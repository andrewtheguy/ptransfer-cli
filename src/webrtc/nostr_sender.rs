//! Nostr Auto Exchange sender compatible with secure-send-web.
//!
//! Handshake: publish a plaintext rendezvous event carrying a blinded SPAKE2
//! element per PIN rotation, finish the PAKE against the first claim that opens
//! under a still-honored generation, publish the sealed confirm (file metadata
//! included) immediately, then park until the operator types the confirmation
//! code the receiver is showing before any WebRTC signal leaves this device.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nostr_sdk::prelude::*;
use rtc::peer_connection::sdp::RTCSessionDescription;

use crate::archive::SendSource;
use crate::crypto::aes;
use crate::crypto::base32::{constant_time_equal, normalize_crockford_base32};
use crate::crypto::chunk::MAX_MESSAGE_SIZE;
use crate::crypto::kdf::{
    ConfirmationCodeBinding, HandshakeSealKeys, NostrSessionKeys, PakeRoot, generate_salt,
};
use crate::crypto::pin::{
    CLAIM_VERIFY_LIMIT, PIN_ROTATION_MS, PIN_WAIT_TIMEOUT_MS, generate_pin, generate_transfer_id,
    is_pin_bucket_active, now_ms, pin_bucket, pin_hint_for_bucket, pin_locator,
};
use crate::crypto::spake2::{PakeIdentities, PakeRole, PakeRun, derive_pake_secret};
use crate::signaling::nostr::{
    self, CandidatePayload, ClaimPayload, ConfirmPayload, HandshakeType, NostrClient,
    RendezvousPayload, Signal, TransferMetadata, addressed_filter, addressed_filter_from_author,
    compute_rendezvous_transcript_hash, compute_transfer_metadata_hash, create_handshake_event,
    create_rendezvous_event, create_signal_event, generate_handshake_nonce, open_handshake_payload,
    parse_handshake_event, parse_signal_event, seal_handshake_payload,
};
use crate::transfer::run_sender;
use crate::ui;
use crate::util::format_bytes;
use crate::webrtc::common::{DcMessenger, WebRtcPeer, open_and_detach};
use crate::webrtc::{add_ice_candidate_safely, advertise_max_message_size, candidate_strings};

/// Total time the sender keeps rotating/waiting before giving up
/// ([`PIN_WAIT_TIMEOUT_MS`]).
const WAIT_FOR_RECEIVER_TIMEOUT: Duration = Duration::from_millis(PIN_WAIT_TIMEOUT_MS);
/// Human confirmation entry window; shorter than the receiver's offer wait, so
/// a slow typist makes the side with a person in front of it report the timeout.
const CONFIRM_CODE_ENTRY_TIMEOUT: Duration = Duration::from_secs(150);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
const OFFER_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// One rotation generation of the displayed PIN: its SPAKE2 run, the rendezvous
/// it published, and the online-guessing budget claims against it may spend.
struct PinGeneration {
    pake: PakeRun,
    nonce: String,
    bucket: u64,
    transcript_hash: String,
    /// Remaining SPAKE2 claim verifications. With a PAKE every verification is
    /// exactly one online PIN guess for whoever authored the claim, so this
    /// budget — not any key stretching — is the online guessing bound.
    verify_budget: u32,
}

/// A verified receiver claim: the transfer is locked to this peer.
struct VerifiedClaim {
    receiver_pubkey: PublicKey,
    payload: ClaimPayload,
    /// Root of the matching SPAKE2 session; every session key hangs off it.
    root: PakeRoot,
    seal_keys: HandshakeSealKeys,
}

pub async fn send_file_nostr(source: &SendSource) -> Result<()> {
    let file_size = source.advertised_size();
    let file_size_exact = source.size_is_exact();
    let file_name = source.file_name.clone();
    let mime_type = source.mime_type.to_string();

    if file_size > MAX_MESSAGE_SIZE || source.estimated_size > MAX_MESSAGE_SIZE {
        bail!(
            "File is {}, which exceeds the {} limit",
            format_bytes(file_size),
            format_bytes(MAX_MESSAGE_SIZE)
        );
    }

    // Per-transfer credentials: the public salt (HKDF input for the session
    // keys) and an ephemeral Nostr identity. The shared secret protecting
    // signaling and content comes from the SPAKE2 run itself — each PIN
    // generation carries fresh ephemeral scalars, so there is no key pair to
    // keep across rotations.
    let step = Instant::now();
    ui::status("Preparing secure keys...");
    let salt = generate_salt()?;
    let transfer_id = generate_transfer_id()?;
    ui::status_timed("Prepared secure keys", step.elapsed());

    // File metadata never touches the rendezvous; it travels inside the sealed
    // confirm and is bound into the confirmation code through its own digest.
    let metadata = TransferMetadata {
        content_type: "file".to_string(),
        file_name: file_name.clone(),
        file_size,
        file_size_exact,
        mime_type,
    };
    let metadata_hash = compute_transfer_metadata_hash(&metadata)?;

    let step = Instant::now();
    ui::status("Connecting to Nostr relays...");
    let client = NostrClient::connect(Keys::generate()).await?;
    let sender_pubkey = client.public_key();
    ui::status_timed(
        &format!(
            "Connected to Nostr relays ({})",
            nostr::DEFAULT_RELAYS.len()
        ),
        step.elapsed(),
    );

    let rendezvous = RendezvousContext {
        client: &client,
        salt: &salt,
        transfer_id: &transfer_id,
        sender_pubkey_hex: client.public_key_hex(),
        file_name: &file_name,
        file_size,
    };

    let claim = wait_for_verified_claim(&client, &rendezvous, &sender_pubkey).await?;

    // First-claim lockout: rotation has stopped and every retained PIN
    // generation is dropped; the PIN is no longer needed for display.
    ui::hide_pin();
    ui::status("Receiver claim verified.");

    // Session keys and the human confirmation code are HKDF derivations off the
    // SPAKE2 root the claim just proved agreement on.
    let session_keys: NostrSessionKeys = claim.root.session_keys(&salt)?;
    let expected_confirmation_code = claim.root.confirmation_code(
        &salt,
        &ConfirmationCodeBinding {
            transfer_id: &transfer_id,
            sender_nonce: &claim.payload.sender_nonce,
            receiver_nonce: &claim.payload.receiver_nonce,
            transcript_hash: &claim.payload.transcript_hash,
            metadata_hash: &metadata_hash,
        },
    )?;

    // Mutual proof plus metadata delivery, sealed under the session's confirm
    // key. It goes out *before* the code gate: the receiver needs it to learn
    // what is being offered and to display the confirmation code at all. The
    // gate guards the WebRTC offer and the file bytes, which is where the harm
    // lives.
    let confirm = ConfirmPayload {
        payload_type: "confirm".to_string(),
        transfer_id: transfer_id.clone(),
        sender_nonce: claim.payload.sender_nonce.clone(),
        receiver_nonce: claim.payload.receiver_nonce.clone(),
        sender_pubkey: client.public_key_hex(),
        receiver_pubkey: claim.receiver_pubkey.to_hex(),
        transcript_hash: claim.payload.transcript_hash.clone(),
        metadata,
    };
    let confirm_event = create_handshake_event(
        &client,
        &claim.receiver_pubkey,
        &transfer_id,
        HandshakeType::Confirm,
        &seal_handshake_payload(&claim.seal_keys.confirm, &confirm)?,
        None,
    )?;
    let step = Instant::now();
    ui::status("Publishing confirmation to Nostr...");
    client.publish(&confirm_event).await?;
    ui::status_timed("Published confirmation to Nostr", step.elapsed());

    wait_for_confirmation_code(&expected_confirmation_code).await?;

    ui::status("Creating P2P connection...");
    let mut peer = WebRtcPeer::new(ICE_GATHER_TIMEOUT).await?;
    let data_channel = peer.create_data_channel("file-transfer").await?;

    let offer = peer.create_offer().await?;
    peer.set_local_description(offer.clone()).await?;

    ui::status("Gathering network candidates...");
    let candidates = peer.gather_ice_candidates().await?;
    let offer_sdp = advertise_max_message_size(offer.sdp);
    let candidates = candidate_strings(candidates)?;

    let signal_filter =
        addressed_filter_from_author(&transfer_id, &sender_pubkey, claim.receiver_pubkey);
    let mut notifications = client.notifications();
    let sub_id = client.subscribe(signal_filter.clone()).await?;

    let step = Instant::now();
    ui::status("Publishing P2P offer to Nostr...");
    publish_offer_and_candidates(
        &client,
        &sender_pubkey,
        &transfer_id,
        &offer_sdp,
        &candidates,
        &session_keys.signals,
    )
    .await?;
    ui::status_timed("Published P2P offer to Nostr", step.elapsed());

    let peer = Arc::new(peer);
    let mut seen = HashSet::new();
    let mut answer_set = false;
    let mut queued_candidates = Vec::new();

    for event in client.fetch(signal_filter.clone()).await? {
        handle_sender_signal(
            &event,
            &mut seen,
            &peer,
            &session_keys.signals,
            &transfer_id,
            claim.receiver_pubkey,
            &mut answer_set,
            &mut queued_candidates,
        )
        .await?;
    }

    ui::status("Waiting for WebRTC answer...");
    tokio::time::timeout(CONNECTION_TIMEOUT, async {
        let mut retry_interval = tokio::time::interval(OFFER_RETRY_INTERVAL);
        retry_interval.tick().await;

        while !answer_set {
            tokio::select! {
                _ = retry_interval.tick() => {
                    let step = Instant::now();
                    ui::status("Republishing P2P offer to Nostr...");
                    publish_offer_and_candidates(
                        &client,
                        &sender_pubkey,
                        &transfer_id,
                        &offer_sdp,
                        &candidates,
                        &session_keys.signals,
                    ).await?;
                    ui::status_timed("Republished P2P offer to Nostr", step.elapsed());
                }
                event = next_event(&mut notifications) => {
                    let event = event?;
                    handle_sender_signal(
                        &event,
                        &mut seen,
                        &peer,
                        &session_keys.signals,
                        &transfer_id,
                        claim.receiver_pubkey,
                        &mut answer_set,
                        &mut queued_candidates,
                    )
                    .await?;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timed out waiting for WebRTC answer"))??;

    ui::status("Waiting for data channel...");
    let open = open_and_detach(data_channel, CONNECTION_TIMEOUT);
    tokio::pin!(open);
    let raw = loop {
        tokio::select! {
            result = &mut open => break result?,
            event = next_event(&mut notifications) => {
                let event = event?;
                handle_sender_signal(
                    &event,
                    &mut seen,
                    &peer,
                    &session_keys.signals,
                    &transfer_id,
                    claim.receiver_pubkey,
                    &mut answer_set,
                    &mut queued_candidates,
                ).await?;
            }
        }
    };
    client.unsubscribe(&sub_id).await;

    let info = peer.get_connection_info().await;
    ui::status(&format!("Connected via {}", info.connection_type));

    let mut messenger = DcMessenger::new(raw);
    let result = run_sender(&mut messenger, &session_keys.content, source).await;

    let _ = peer.close().await;
    client.disconnect().await;
    result?;

    ui::status("File sent successfully.");
    Ok(())
}

async fn wait_for_confirmation_code(expected: &str) -> Result<()> {
    ui::status("Ask the receiver for the confirmation code shown on their screen.");

    let entry = async {
        loop {
            let entered = ui::prompt_confirmation_code().await?;
            let normalized = normalize_crockford_base32(&entered);
            if constant_time_equal(&normalized, expected) {
                return Ok::<(), anyhow::Error>(());
            }
            ui::status("Confirmation code did not match. Check it and try again.");
        }
    };

    tokio::time::timeout(CONFIRM_CODE_ENTRY_TIMEOUT, entry)
        .await
        .map_err(|_| {
            anyhow::anyhow!("Confirmation code was not entered in time. Start a new transfer.")
        })??;
    ui::status("Confirmation code matched.");
    Ok(())
}

/// Everything a rendezvous publication needs; stable across rotations.
struct RendezvousContext<'a> {
    client: &'a NostrClient,
    salt: &'a [u8],
    transfer_id: &'a str,
    sender_pubkey_hex: String,
    file_name: &'a str,
    file_size: u64,
}

impl RendezvousContext<'_> {
    /// Mint a fresh PIN, start a fresh SPAKE2 run, publish its rendezvous
    /// event, and display the PIN. Returns the generation the sender must
    /// retain to verify claims.
    async fn publish_fresh_pin(&self) -> Result<PinGeneration> {
        let pin = generate_pin()?;
        // No key stretching: with a balanced PAKE nothing published can be
        // ground against offline, so stretching would only add latency.
        let pake_secret = derive_pake_secret(&pin);
        let pake = PakeRun::start(PakeRole::Sender, &pake_secret)?;

        let nonce = generate_handshake_nonce()?;
        let bucket = pin_bucket(now_ms());
        let payload = RendezvousPayload {
            payload_type: "rendezvous".to_string(),
            transfer_id: self.transfer_id.to_string(),
            sender_pubkey: self.sender_pubkey_hex.clone(),
            pake_message: STANDARD.encode(pake.message()),
            nonce: nonce.clone(),
            relays: Some(nostr::default_relays_vec()),
        };
        // Hash what we are about to publish, so a claim can be checked against
        // the rendezvous we actually sent rather than the one the claimant says
        // it saw. Per generation, since the nonce and element are fresh on
        // every rotation.
        let transcript_hash = compute_rendezvous_transcript_hash(&payload, self.salt)?;
        let event = create_rendezvous_event(
            self.client,
            &payload,
            self.salt,
            &pin_hint_for_bucket(pin_locator(&pin), bucket),
            bucket,
        )?;
        self.client.publish(&event).await?;

        ui::show_pin(self.file_name, self.file_size, &pin);

        Ok(PinGeneration {
            pake,
            nonce,
            bucket,
            transcript_hash,
            verify_budget: CLAIM_VERIFY_LIMIT,
        })
    }
}

/// Rotate the PIN until a receiver proves knowledge of one of the retained
/// generations, then lock the transfer to that receiver. An on-demand refresh
/// ([`ui::request_pin_refresh`]) drops every retained generation and publishes
/// a fresh PIN immediately.
async fn wait_for_verified_claim(
    client: &NostrClient,
    rendezvous: &RendezvousContext<'_>,
    sender_pubkey: &PublicKey,
) -> Result<VerifiedClaim> {
    // Subscribe before the first publish so a fast claim can never slip past.
    let filter = addressed_filter(rendezvous.transfer_id, sender_pubkey);
    let mut notifications = client.notifications();
    let sub_id = client.subscribe(filter).await?;

    // Newest generation first; inactive wall-clock buckets are discarded.
    let mut generations: Vec<PinGeneration> = Vec::new();
    let mut seen = HashSet::new();
    let refresh = ui::pin_refresh_signal();

    let rotation_period = Duration::from_millis(PIN_ROTATION_MS);
    let mut rotation = tokio::time::interval_at(
        tokio::time::Instant::now() + rotation_period,
        rotation_period,
    );

    let deadline = tokio::time::sleep(WAIT_FOR_RECEIVER_TIMEOUT);
    tokio::pin!(deadline);

    fn register(generations: &mut Vec<PinGeneration>, generation: PinGeneration) {
        generations.insert(0, generation);
        let now = now_ms();
        generations.retain(|candidate| is_pin_bucket_active(candidate.bucket, now));
    }

    register(&mut generations, rendezvous.publish_fresh_pin().await?);
    ui::status("Waiting for receiver...");

    let claim = loop {
        tokio::select! {
            _ = &mut deadline => {
                client.unsubscribe(&sub_id).await;
                bail!("No receiver connected. Please start a new transfer.");
            }

            _ = rotation.tick() => {
                ui::status("Rotating PIN...");
                register(&mut generations, rendezvous.publish_fresh_pin().await?);
                ui::status("Waiting for receiver...");
            }

            _ = refresh.notified() => {
                // Drop every retained generation so previously shown PINs stop
                // authenticating, restart the rotation cadence, and publish a
                // fresh rendezvous.
                ui::status("Refreshing PIN...");
                generations.clear();
                rotation.reset();
                register(&mut generations, rendezvous.publish_fresh_pin().await?);
                ui::status("Waiting for receiver...");
            }

            event = next_event(&mut notifications) => {
                let event = event?;
                if !seen.insert(event.id) {
                    continue;
                }
                if let Some(claim) =
                    verify_claim(
                        &event,
                        &mut generations,
                        rendezvous.transfer_id,
                        rendezvous.salt,
                        sender_pubkey,
                    )
                {
                    break claim;
                }
            }
        }
    };

    client.unsubscribe(&sub_id).await;
    Ok(claim)
}

/// Try every retained, active PIN generation with budget left against a claim
/// event. Invalid claims are ignored, never fatal: transfer tags are public, so
/// aborting here would let anyone deny the transfer — but every attempt burns a
/// unit of the generation's verification budget, which is the online-guessing
/// meter.
fn verify_claim(
    event: &Event,
    generations: &mut [PinGeneration],
    transfer_id: &str,
    salt: &[u8],
    sender_pubkey: &PublicKey,
) -> Option<VerifiedClaim> {
    let handshake = parse_handshake_event(event)?;
    if handshake.handshake_type != HandshakeType::Claim || handshake.transfer_id != transfer_id {
        return None;
    }
    let claim_pake_message = handshake.pake_message?;

    let identities = PakeIdentities {
        transfer_id,
        sender_pubkey: &sender_pubkey.to_hex(),
        receiver_pubkey: &event.pubkey.to_hex(),
    };

    for generation in generations.iter_mut() {
        if !is_pin_bucket_active(generation.bucket, now_ms()) || generation.verify_budget == 0 {
            continue;
        }
        generation.verify_budget -= 1;

        // Finish our side of the SPAKE2 run against the claimant's element,
        // then try the claim seal. A wrong PIN (or a different generation)
        // lands on a different root key and the seal simply refuses to open.
        let Ok(root) = generation.pake.finish(&claim_pake_message, &identities) else {
            continue; // Invalid element
        };
        let Ok(seal_keys) = root.handshake_seal_keys(salt) else {
            continue;
        };
        let Ok(payload) =
            open_handshake_payload::<ClaimPayload>(&seal_keys.claim, &handshake.sealed_payload)
        else {
            continue; // Sealed by a different PAKE session
        };

        // The payload opened under this generation's session key; its contents
        // must bind the proof to this transfer, this rotation's nonce, both
        // identities, and the rendezvous we actually published.
        if payload.payload_type != "claim"
            || payload.transfer_id != transfer_id
            || payload.sender_nonce != generation.nonce
            || payload.receiver_nonce.is_empty()
            || payload.sender_pubkey != sender_pubkey.to_hex()
            || payload.receiver_pubkey != event.pubkey.to_hex()
            || payload.transcript_hash != generation.transcript_hash
            || !is_pin_bucket_active(generation.bucket, now_ms())
        {
            return None;
        }

        return Some(VerifiedClaim {
            receiver_pubkey: event.pubkey,
            payload,
            root,
            seal_keys,
        });
    }

    None
}

async fn publish_offer_and_candidates(
    client: &NostrClient,
    sender_pubkey: &PublicKey,
    transfer_id: &str,
    offer_sdp: &str,
    candidates: &[String],
    key: &[u8; aes::AES_KEY_LEN],
) -> Result<()> {
    let mut signals = vec![Signal::Offer {
        sdp: offer_sdp.to_string(),
    }];
    signals.extend(candidates.iter().map(|candidate| Signal::Candidate {
        candidate: Some(CandidatePayload {
            candidate: candidate.clone(),
            sdp_mid: Some("0".to_string()),
            sdp_m_line_index: Some(0),
        }),
    }));
    publish_signals_concurrently(client, sender_pubkey, transfer_id, signals, key).await
}

/// Publish signaling events concurrently: a slow relay must not serialize the
/// offer/answer and every trickled candidate into a multiple of its latency.
async fn publish_signals_concurrently(
    client: &NostrClient,
    sender_pubkey: &PublicKey,
    transfer_id: &str,
    signals: Vec<Signal>,
    key: &[u8; aes::AES_KEY_LEN],
) -> Result<()> {
    let mut set = tokio::task::JoinSet::new();
    for signal in signals {
        let event = create_signal_event(client, sender_pubkey, transfer_id, signal, key)?;
        let client = client.clone();
        set.spawn(async move { client.publish(&event).await });
    }
    while let Some(result) = set.join_next().await {
        result.context("signal publish task failed")??;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_sender_signal(
    event: &Event,
    seen: &mut HashSet<EventId>,
    peer: &Arc<WebRtcPeer>,
    key: &[u8; aes::AES_KEY_LEN],
    transfer_id: &str,
    receiver_pubkey: PublicKey,
    answer_set: &mut bool,
    queued_candidates: &mut Vec<String>,
) -> Result<()> {
    if !seen.insert(event.id) {
        return Ok(());
    }
    let Some(parsed) = parse_signal_event(event, key, transfer_id) else {
        return Ok(());
    };
    if parsed.pubkey != receiver_pubkey {
        return Ok(());
    }

    match parsed.signal {
        Signal::Answer { sdp } if !*answer_set => {
            let answer = RTCSessionDescription::answer(sdp).context("Invalid answer SDP")?;
            peer.set_remote_description(answer).await?;
            *answer_set = true;
            for candidate in queued_candidates.drain(..) {
                add_ice_candidate_safely(peer, &candidate).await;
            }
        }
        Signal::Candidate {
            candidate: Some(candidate),
        } => {
            if *answer_set {
                add_ice_candidate_safely(peer, &candidate.candidate).await;
            } else {
                queued_candidates.push(candidate.candidate);
            }
        }
        _ => {}
    }

    Ok(())
}

async fn next_event(
    notifications: &mut tokio::sync::broadcast::Receiver<RelayPoolNotification>,
) -> Result<Event> {
    loop {
        match notifications.recv().await {
            Ok(RelayPoolNotification::Event { event, .. }) => return Ok((*event).clone()),
            Ok(RelayPoolNotification::Message { message, .. }) => {
                if let RelayMessage::Event { event, .. } = message {
                    return Ok((*event).clone());
                }
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(e) => bail!("Nostr notification stream closed: {e}"),
        }
    }
}
