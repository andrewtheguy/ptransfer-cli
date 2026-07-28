//! Nostr Auto Exchange sender compatible with secure-send-web.
//!
//! Handshake: publish a rendezvous event per PIN rotation, wait for a
//! receiver's claim sealed with a still-honored PIN generation, lock the
//! transfer to that receiver with a confirm, then derive the ECDH session
//! keys and stream the file over a direct WebRTC data channel.

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
use crate::crypto::chunk::MAX_MESSAGE_SIZE;
use crate::crypto::ecdh::{EcdhKeyPair, NostrSessionKeys, generate_salt};
use crate::crypto::pin::{
    PIN_ROTATION_MS, PIN_WAIT_TIMEOUT_MS, PinRoot, generate_pin, generate_transfer_id,
    is_pin_bucket_active, now_ms, pin_bucket, pin_fingerprint,
};
use crate::signaling::nostr::{
    self, CandidatePayload, ClaimPayload, ConfirmPayload, HandshakeType, NostrClient,
    RendezvousPayload, Signal, addressed_filter, addressed_filter_from_author,
    create_handshake_event, create_rendezvous_event, create_signal_event, generate_handshake_nonce,
    open_handshake_payload, parse_handshake_event, parse_signal_event, seal_handshake_payload,
};
use crate::transfer::run_sender;
use crate::ui;
use crate::util::format_bytes;
use crate::webrtc::common::{DcMessenger, WebRtcPeer, open_and_detach};
use crate::webrtc::{add_ice_candidate_safely, advertise_max_message_size, candidate_strings};

/// Total time the sender keeps rotating/waiting before giving up
/// ([`PIN_WAIT_TIMEOUT_MS`]).
const WAIT_FOR_RECEIVER_TIMEOUT: Duration = Duration::from_millis(PIN_WAIT_TIMEOUT_MS);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
const OFFER_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// One rotation generation of the displayed PIN. Its absolute bucket prevents
/// retained keys from authenticating outside the current or previous bucket.
struct PinGeneration {
    auth_key: [u8; aes::AES_KEY_LEN],
    nonce: String,
    bucket: u64,
}

/// A verified receiver claim: the transfer is locked to this peer.
struct VerifiedClaim {
    receiver_pubkey: PublicKey,
    receiver_ecdh_public_key: Vec<u8>,
    payload: ClaimPayload,
    auth_key: [u8; aes::AES_KEY_LEN],
}

fn decode_ecdh_public_key(b64: &str) -> Option<Vec<u8>> {
    let bytes = STANDARD.decode(b64).ok()?;
    (bytes.len() == 65 && bytes[0] == 0x04).then_some(bytes)
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

    // Per-transfer credentials: public salt (HKDF input for the ECDH session
    // keys), ephemeral Nostr identity, and the ephemeral ECDH key pair whose
    // shared secret will protect signaling and content.
    let step = Instant::now();
    ui::status("Preparing secure keys...");
    let salt = generate_salt()?;
    let transfer_id = generate_transfer_id()?;
    let ecdh = EcdhKeyPair::generate()?;
    let ecdh_public_key_b64 = STANDARD.encode(ecdh.public_key_bytes);
    ui::status_timed("Prepared secure keys", step.elapsed());

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
        ecdh_public_key_b64: &ecdh_public_key_b64,
        file_name: &file_name,
        file_size,
        file_size_exact,
        mime_type: &mime_type,
    };

    let claim = wait_for_verified_claim(&client, &rendezvous, &sender_pubkey).await?;

    // First-claim lockout: rotation has stopped and every retained PIN
    // generation is dropped; the PIN is no longer needed for display.
    ui::hide_pin();
    ui::status("Receiver claim verified.");

    // Mutual proof: confirm under the same PIN-derived auth key that sealed
    // the claim, echoing both nonces and the receiver key we locked onto.
    let confirm = ConfirmPayload {
        payload_type: "confirm".to_string(),
        transfer_id: transfer_id.clone(),
        sender_nonce: claim.payload.sender_nonce.clone(),
        receiver_nonce: claim.payload.receiver_nonce.clone(),
        receiver_ecdh_public_key: claim.payload.receiver_ecdh_public_key.clone(),
    };
    let confirm_event = create_handshake_event(
        &client,
        &claim.receiver_pubkey,
        &transfer_id,
        HandshakeType::Confirm,
        &seal_handshake_payload(&claim.auth_key, &confirm)?,
    )?;
    let step = Instant::now();
    ui::status("Publishing confirmation to Nostr...");
    client.publish(&confirm_event).await?;
    ui::status_timed("Published confirmation to Nostr", step.elapsed());

    // Session keys come from the ephemeral ECDH exchange the PIN just
    // authenticated — the PIN derives no content or signaling keys.
    let session_keys: NostrSessionKeys =
        ecdh.derive_nostr_session_keys(&claim.receiver_ecdh_public_key, &salt)?;

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

/// Everything a rendezvous publication needs; stable across rotations.
struct RendezvousContext<'a> {
    client: &'a NostrClient,
    salt: &'a [u8],
    transfer_id: &'a str,
    sender_pubkey_hex: String,
    ecdh_public_key_b64: &'a str,
    file_name: &'a str,
    file_size: u64,
    file_size_exact: bool,
    mime_type: &'a str,
}

impl RendezvousContext<'_> {
    /// Mint a fresh PIN, publish its rendezvous event, and display it.
    /// Returns the generation the sender must retain to verify claims.
    async fn publish_fresh_pin(&self) -> Result<PinGeneration> {
        let pin = generate_pin()?;
        // The PBKDF2 stretch is CPU-bound (~600k iterations); keep it off the
        // async runtime worker.
        let root = tokio::task::spawn_blocking({
            let pin = pin.clone();
            move || PinRoot::derive(&pin)
        })
        .await
        .context("PIN derivation task failed")?;

        let nonce = generate_handshake_nonce()?;
        let bucket = pin_bucket(now_ms());
        let payload = RendezvousPayload {
            payload_type: "rendezvous".to_string(),
            content_type: "file".to_string(),
            transfer_id: self.transfer_id.to_string(),
            sender_pubkey: self.sender_pubkey_hex.clone(),
            ecdh_public_key: self.ecdh_public_key_b64.to_string(),
            nonce: nonce.clone(),
            relays: Some(nostr::default_relays_vec()),
            file_name: self.file_name.to_string(),
            file_size: self.file_size,
            file_size_exact: self.file_size_exact,
            mime_type: self.mime_type.to_string(),
        };
        let encrypted = aes::encrypt(&root.rendezvous_key(), &serde_json::to_vec(&payload)?)?;
        let event = create_rendezvous_event(
            self.client,
            &encrypted,
            self.salt,
            self.transfer_id,
            &root.hint_for_bucket(bucket),
            bucket,
        )?;
        self.client.publish(&event).await?;

        ui::show_pin(
            self.file_name,
            self.file_size,
            &pin,
            &pin_fingerprint(&pin),
        );

        Ok(PinGeneration {
            auth_key: root.auth_key(),
            nonce,
            bucket,
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
                    verify_claim(&event, &generations, rendezvous.transfer_id, rendezvous.ecdh_public_key_b64)
                {
                    break claim;
                }
            }
        }
    };

    client.unsubscribe(&sub_id).await;
    Ok(claim)
}

/// Try every retained, active PIN generation against a claim event. Invalid
/// claims are ignored, never fatal: transfer tags are public, so aborting here
/// would let anyone deny the transfer.
fn verify_claim(
    event: &Event,
    generations: &[PinGeneration],
    transfer_id: &str,
    sender_ecdh_public_key_b64: &str,
) -> Option<VerifiedClaim> {
    let handshake = parse_handshake_event(event)?;
    if handshake.handshake_type != HandshakeType::Claim || handshake.transfer_id != transfer_id {
        return None;
    }

    for generation in generations {
        if !is_pin_bucket_active(generation.bucket, now_ms()) {
            continue;
        }
        let Ok(payload) =
            open_handshake_payload::<ClaimPayload>(&generation.auth_key, &handshake.sealed_payload)
        else {
            continue; // Sealed with a different PIN/generation
        };

        let receiver_ecdh_public_key = decode_ecdh_public_key(&payload.receiver_ecdh_public_key);

        // The payload opened under this generation's key; its contents must
        // bind the proof to this transfer, this rotation's nonce, and both
        // ECDH public keys (what makes the ECDH session MITM-proof).
        if payload.payload_type != "claim"
            || payload.transfer_id != transfer_id
            || payload.sender_nonce != generation.nonce
            || payload.receiver_nonce.is_empty()
            || payload.sender_ecdh_public_key != sender_ecdh_public_key_b64
            || !is_pin_bucket_active(generation.bucket, now_ms())
        {
            return None;
        }
        let receiver_ecdh_public_key = receiver_ecdh_public_key?;

        return Some(VerifiedClaim {
            receiver_pubkey: event.pubkey,
            receiver_ecdh_public_key,
            payload,
            auth_key: generation.auth_key,
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
