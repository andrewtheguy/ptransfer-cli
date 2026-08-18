//! Nostr Auto Exchange receiver compatible with secure-send-web.
//!
//! Handshake: derive the PIN root, locate the sender's rendezvous event via
//! rotation-bucket hints, claim the transfer with a payload sealed under the
//! PIN auth key, show the ECDH-derived confirmation code, wait for the sender's
//! gated confirm, then receive over a direct WebRTC data channel.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nostr_sdk::prelude::*;
use rtc::peer_connection::sdp::RTCSessionDescription;

use crate::crypto::aes;
use crate::crypto::chunk::MAX_MESSAGE_SIZE;
use crate::crypto::ecdh::{ConfirmationCodeBinding, EcdhKeyPair, NostrSessionKeys};
use crate::crypto::pin::{
    PIN_HINT_LOOKBACK_BUCKETS, PIN_TTL_MS, PinRoot, is_valid_pin, now_ms, pin_bucket,
    pin_hint_for_bucket, pin_locator,
};
use crate::signaling::nostr::{
    CandidatePayload, ClaimPayload, ConfirmPayload, HandshakeType, NostrClient, RendezvousPayload,
    Signal, addressed_filter_from_author, compute_rendezvous_transcript_hash,
    create_handshake_event, create_signal_event, generate_handshake_nonce, open_handshake_payload,
    parse_handshake_event, parse_rendezvous_event, parse_signal_event, rendezvous_filter,
    seal_handshake_payload, signal_filter_from_sender,
};
use crate::transfer::run_receiver;
use crate::ui;
use crate::util::{OnConflict, format_bytes, resolve_destination};
use crate::webrtc::common::{DcMessenger, WebRtcPeer, open_and_detach};
use crate::webrtc::{add_ice_candidate_safely, advertise_max_message_size, candidate_strings};

/// Time to establish the WebRTC data channel after the handshake completes.
/// Mirrors the sender's timeout.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
/// Human-sized window for the sender to receive and type the displayed code.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(180);
/// Backstop poll for a confirm a relay stored before our subscription landed.
const CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(3);
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
const ANSWER_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// A decrypted, validated rendezvous event.
struct RendezvousMatch {
    payload: RendezvousPayload,
    salt: Vec<u8>,
    transfer_id: String,
    sender_pubkey: PublicKey,
    sender_ecdh_public_key: Vec<u8>,
}

fn decode_ecdh_public_key(b64: &str) -> Option<Vec<u8>> {
    let bytes = STANDARD.decode(b64).ok()?;
    (bytes.len() == 65 && bytes[0] == 0x04).then_some(bytes)
}

pub async fn receive_file_nostr(
    pin: &str,
    output_dir: Option<PathBuf>,
    on_conflict: OnConflict,
) -> Result<()> {
    if !is_valid_pin(pin) {
        bail!("Invalid PIN: check for typos and try again");
    }
    let pin = pin.to_string();
    let locator = pin_locator(&pin).to_string();

    // One PBKDF2 stretch per PIN for the sealed-payload keys. Public lookup
    // hints derive separately from the locator segment below.
    let step = Instant::now();
    ui::status("Deriving PIN lookup keys...");
    let root = tokio::task::spawn_blocking(move || PinRoot::derive(&pin))
        .await
        .context("PIN derivation task failed")?;
    // Mirror the sender's rule by deriving the current and previous buckets.
    let current_bucket = pin_bucket(now_ms());
    let hints: Vec<String> = (0..=PIN_HINT_LOOKBACK_BUCKETS)
        .map(|offset| {
            pin_hint_for_bucket(&locator, current_bucket.saturating_sub(offset))
        })
        .collect();
    let rendezvous_key = root.rendezvous_key();
    let auth_key = root.auth_key();
    ui::status_timed("Derived PIN lookup keys", step.elapsed());

    let step = Instant::now();
    ui::status("Connecting to Nostr relays...");
    let client = NostrClient::connect(Keys::generate()).await?;
    ui::status_timed("Connected to Nostr relays", step.elapsed());

    ui::status("Searching for sender...");
    let rendezvous = find_rendezvous_event(&client, &hints, &rendezvous_key).await?;

    let file_name = rendezvous.payload.file_name.clone();
    let file_size = rendezvous.payload.file_size;
    let file_size_exact = rendezvous.payload.file_size_exact;
    let mime_type = rendezvous.payload.mime_type.clone();

    if file_size_exact && file_size == 0 {
        bail!("Transfer describes an empty file");
    }
    if file_size > MAX_MESSAGE_SIZE {
        bail!(
            "Transfer is {}, which exceeds the {} limit",
            format_bytes(file_size),
            format_bytes(MAX_MESSAGE_SIZE)
        );
    }

    ui::incoming(&file_name, file_size, Some(&mime_type));
    let Some(dest) = resolve_destination(output_dir, &file_name, on_conflict).await? else {
        ui::status("Cancelled.");
        client.disconnect().await;
        return Ok(());
    };

    // Claim the transfer: prove PIN knowledge and bind our ephemeral ECDH key
    // (and the sender's) into the sealed payload.
    let ecdh = EcdhKeyPair::generate()?;
    let receiver_ecdh_public_key_b64 = STANDARD.encode(ecdh.public_key_bytes);
    let receiver_nonce = generate_handshake_nonce()?;
    let sender_pubkey = rendezvous.sender_pubkey;
    let transfer_id = rendezvous.transfer_id.clone();
    let receiver_pubkey = client.public_key_hex();
    let transcript_hash =
        compute_rendezvous_transcript_hash(&rendezvous.payload, &rendezvous.salt)?;

    // The authenticated rendezvous already commits us to the sender's ECDH
    // key. Derive and display the human code before publishing the claim; the
    // sender will not confirm or signal until its operator enters this value.
    let confirmation_code = ecdh.derive_confirmation_code(
        &rendezvous.sender_ecdh_public_key,
        &rendezvous.salt,
        &ConfirmationCodeBinding {
            transfer_id: &transfer_id,
            sender_nonce: &rendezvous.payload.nonce,
            receiver_nonce: &receiver_nonce,
            transcript_hash: &transcript_hash,
        },
    )?;

    let claim = ClaimPayload {
        payload_type: "claim".to_string(),
        transfer_id: transfer_id.clone(),
        sender_nonce: rendezvous.payload.nonce.clone(),
        receiver_nonce: receiver_nonce.clone(),
        receiver_ecdh_public_key: receiver_ecdh_public_key_b64.clone(),
        sender_ecdh_public_key: rendezvous.payload.ecdh_public_key.clone(),
        sender_pubkey: sender_pubkey.to_hex(),
        receiver_pubkey: receiver_pubkey.clone(),
        transcript_hash: transcript_hash.clone(),
    };
    let claim_event = create_handshake_event(
        &client,
        &sender_pubkey,
        &transfer_id,
        HandshakeType::Claim,
        &seal_handshake_payload(&auth_key, &claim)?,
    )?;

    ui::show_confirmation_code(&confirmation_code);
    let confirm_result = wait_for_confirm(
        &client,
        claim_event,
        &auth_key,
        &transfer_id,
        &sender_pubkey,
        &rendezvous.payload.nonce,
        &receiver_nonce,
        &receiver_ecdh_public_key_b64,
        &receiver_pubkey,
        &transcript_hash,
    )
    .await;
    ui::hide_confirmation_code();
    confirm_result?;

    // Session keys come from the ephemeral ECDH exchange the PIN just
    // authenticated — the PIN derives no content or signaling keys.
    let session_keys: NostrSessionKeys =
        ecdh.derive_nostr_session_keys(&rendezvous.sender_ecdh_public_key, &rendezvous.salt)?;

    let connection_deadline = Instant::now() + CONNECTION_TIMEOUT;

    ui::status("Waiting for sender P2P offer...");
    let signal_filter = signal_filter_from_sender(&transfer_id, sender_pubkey);
    let mut notifications = client.notifications();
    let sub_id = client.subscribe(signal_filter.clone()).await?;
    let mut seen = HashSet::new();
    let mut queued_candidates = Vec::new();

    let mut offer_sdp = None;
    for event in client.fetch(signal_filter.clone()).await? {
        handle_pre_offer_signal(
            &event,
            &mut seen,
            &session_keys.signals,
            &transfer_id,
            sender_pubkey,
            &mut offer_sdp,
            &mut queued_candidates,
        )?;
        if offer_sdp.is_some() {
            break;
        }
    }

    tokio::time::timeout(remaining_connection_timeout(connection_deadline)?, async {
        while offer_sdp.is_none() {
            let event = next_event(&mut notifications).await?;
            handle_pre_offer_signal(
                &event,
                &mut seen,
                &session_keys.signals,
                &transfer_id,
                sender_pubkey,
                &mut offer_sdp,
                &mut queued_candidates,
            )?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("WebRTC connection timeout"))??;

    let offer_sdp = offer_sdp.context("missing sender offer")?;

    ui::status("Creating P2P answer...");
    let mut peer = WebRtcPeer::new(ICE_GATHER_TIMEOUT).await?;
    let mut data_channel_rx = peer
        .take_data_channel_rx()
        .context("Data channel receiver already taken")?;

    let offer = RTCSessionDescription::offer(offer_sdp).context("Invalid offer SDP")?;
    peer.set_remote_description(offer).await?;
    for candidate in queued_candidates.drain(..) {
        add_ice_candidate_safely(&peer, &candidate).await;
    }

    let answer = peer.create_answer().await?;
    peer.set_local_description(answer.clone()).await?;

    ui::status("Gathering network candidates...");
    let candidates = peer.gather_ice_candidates().await?;
    let answer_sdp = advertise_max_message_size(answer.sdp);
    let candidates = candidate_strings(candidates)?;

    let step = Instant::now();
    ui::status("Publishing P2P answer to Nostr...");
    publish_answer_and_candidates(
        &client,
        &sender_pubkey,
        &transfer_id,
        &answer_sdp,
        &candidates,
        &session_keys.signals,
    )
    .await?;
    ui::status_timed("Published P2P answer to Nostr", step.elapsed());

    let peer = Arc::new(peer);
    let mut answer_retry = tokio::time::interval(ANSWER_RETRY_INTERVAL);
    answer_retry.tick().await;

    ui::status("Waiting for data channel...");
    let data_channel_timeout =
        tokio::time::sleep(remaining_connection_timeout(connection_deadline)?);
    tokio::pin!(data_channel_timeout);
    let data_channel = loop {
        tokio::select! {
            _ = answer_retry.tick() => {
                let step = Instant::now();
                ui::status("Republishing P2P answer to Nostr...");
                publish_answer_and_candidates(
                    &client,
                    &sender_pubkey,
                    &transfer_id,
                    &answer_sdp,
                    &candidates,
                    &session_keys.signals,
                ).await?;
                ui::status_timed("Republished P2P answer to Nostr", step.elapsed());
            }
            maybe_channel = data_channel_rx.recv() => {
                break maybe_channel.context("Sender never opened a data channel")?;
            }
            event = next_event(&mut notifications) => {
                let event = event?;
                handle_receiver_candidate(
                    &event,
                    &mut seen,
                    &peer,
                    &session_keys.signals,
                    &transfer_id,
                    sender_pubkey,
                ).await?;
            }
            _ = &mut data_channel_timeout => {
                bail!("WebRTC connection timeout");
            }
        }
    };

    // The channel arriving means the P2P link is up; opening it is a local
    // SCTP handshake, so give it a fresh window instead of whatever sliver of
    // the signaling deadline is left. Mirrors the web receiver, which clears
    // its pre-open connection timeout the moment the channel opens.
    let open = open_and_detach(data_channel, CONNECTION_TIMEOUT);
    tokio::pin!(open);
    let raw = loop {
        tokio::select! {
            result = &mut open => break result?,
            _ = answer_retry.tick() => {
                let step = Instant::now();
                ui::status("Republishing P2P answer to Nostr...");
                publish_answer_and_candidates(
                    &client,
                    &sender_pubkey,
                    &transfer_id,
                    &answer_sdp,
                    &candidates,
                    &session_keys.signals,
                ).await?;
                ui::status_timed("Republished P2P answer to Nostr", step.elapsed());
            }
            event = next_event(&mut notifications) => {
                let event = event?;
                handle_receiver_candidate(
                    &event,
                    &mut seen,
                    &peer,
                    &session_keys.signals,
                    &transfer_id,
                    sender_pubkey,
                ).await?;
            }
        }
    };
    client.unsubscribe(&sub_id).await;

    let info = peer.get_connection_info().await;
    ui::status(&format!("Connected via {}", info.connection_type));

    let mut messenger = DcMessenger::new(raw);
    let result = run_receiver(
        &mut messenger,
        &session_keys.content,
        &dest,
        file_size_exact.then_some(file_size),
        file_size,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = peer.close().await;
    client.disconnect().await;

    result?;
    ui::status(&format!("Saved to {}", dest.display()));
    Ok(())
}

fn remaining_connection_timeout(deadline: Instant) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("WebRTC connection timeout");
    }
    Ok(remaining)
}

/// Locate and decrypt the sender's rendezvous event.
///
/// Binds the authenticated payload to the plaintext routing data: the payload
/// must name the event's own author and transfer id, so a copied ciphertext
/// republished under another identity is rejected.
async fn find_rendezvous_event(
    client: &NostrClient,
    hints: &[String],
    rendezvous_key: &[u8; aes::AES_KEY_LEN],
) -> Result<RendezvousMatch> {
    let step = Instant::now();
    ui::status("Fetching rendezvous events from Nostr...");
    let mut events = client.fetch(rendezvous_filter(hints)).await?;
    ui::status_timed(
        &format!("Fetched {} candidate rendezvous event(s)", events.len()),
        step.elapsed(),
    );

    if events.is_empty() {
        bail!(
            "No transfer found for this PIN. It may have rotated — check the code currently shown on the sender."
        );
    }

    events.sort_by_key(|event| std::cmp::Reverse(event.created_at.as_secs()));

    ui::status("Decrypting candidate transfer metadata...");
    let decrypt_start = Instant::now();
    let mut saw_expired = false;
    let mut candidates_checked = 0usize;
    for event in events {
        // A rendezvous event is only claimable while the sender still honors
        // its PIN generation.
        let created_at_ms = event.created_at.as_secs() * 1000;
        if now_ms().saturating_sub(created_at_ms) > PIN_TTL_MS {
            saw_expired = true;
            continue;
        }

        let Some((_hint, salt, transfer_id, encrypted_payload)) = parse_rendezvous_event(&event)
        else {
            continue;
        };
        candidates_checked += 1;

        // Not sealed with our PIN (stale event sharing the hint tag)? Try the
        // next candidate.
        let Ok(decrypted) = aes::decrypt(rendezvous_key, &encrypted_payload) else {
            continue;
        };
        let Ok(payload) = serde_json::from_slice::<RendezvousPayload>(&decrypted) else {
            continue;
        };

        let Some(sender_ecdh_public_key) = decode_ecdh_public_key(&payload.ecdh_public_key) else {
            continue;
        };
        if payload.payload_type != "rendezvous"
            || payload.transfer_id != transfer_id
            || payload.sender_pubkey != event.pubkey.to_hex()
            || payload.nonce.is_empty()
        {
            continue;
        }

        ui::status_timed(
            &format!("Matched sender after {candidates_checked} candidate event(s)"),
            decrypt_start.elapsed(),
        );
        return Ok(RendezvousMatch {
            payload,
            salt,
            transfer_id,
            sender_pubkey: event.pubkey,
            sender_ecdh_public_key,
        });
    }

    if saw_expired {
        bail!("This PIN has expired. Enter the code currently shown on the sender.");
    }
    bail!("Could not decrypt transfer. Wrong PIN?");
}

/// Publish the claim and wait for the sender's confirm, verified under the
/// same PIN auth key. Subscribes before publishing so the response cannot
/// slip past, and polls as a backstop for relays that stored the confirm
/// before the subscription landed. The wait includes time for the two humans
/// to exchange the displayed confirmation code.
#[allow(clippy::too_many_arguments)]
async fn wait_for_confirm(
    client: &NostrClient,
    claim_event: Event,
    auth_key: &[u8; aes::AES_KEY_LEN],
    transfer_id: &str,
    sender_pubkey: &PublicKey,
    sender_nonce: &str,
    receiver_nonce: &str,
    receiver_ecdh_public_key_b64: &str,
    receiver_pubkey: &str,
    transcript_hash: &str,
) -> Result<()> {
    let our_pubkey = client.public_key();
    let confirm_filter = addressed_filter_from_author(transfer_id, &our_pubkey, *sender_pubkey);
    let mut notifications = client.notifications();
    let sub_id = client.subscribe(confirm_filter.clone()).await?;

    let step = Instant::now();
    ui::status("Publishing claim to Nostr...");
    client.publish(&claim_event).await?;
    ui::status_timed("Published claim to Nostr", step.elapsed());

    ui::status("Waiting for the sender to enter the confirmation code...");
    let mut seen = HashSet::new();

    let verify = |event: &Event| -> bool {
        let Some(handshake) = parse_handshake_event(event) else {
            return false;
        };
        if handshake.handshake_type != HandshakeType::Confirm
            || handshake.transfer_id != transfer_id
            || handshake.author != *sender_pubkey
        {
            return false;
        }
        let Ok(payload) =
            open_handshake_payload::<ConfirmPayload>(auth_key, &handshake.sealed_payload)
        else {
            return false; // Not sealed with our PIN
        };
        payload.payload_type == "confirm"
            && payload.transfer_id == transfer_id
            && payload.sender_nonce == sender_nonce
            && payload.receiver_nonce == receiver_nonce
            && payload.receiver_ecdh_public_key == receiver_ecdh_public_key_b64
            && payload.sender_pubkey == sender_pubkey.to_hex()
            && payload.receiver_pubkey == receiver_pubkey
            && payload.transcript_hash == transcript_hash
    };

    let mut poll = tokio::time::interval(CONFIRM_POLL_INTERVAL);
    poll.tick().await; // consume the immediate first tick

    let wait = async {
        loop {
            tokio::select! {
                event = next_event(&mut notifications) => {
                    let event = event?;
                    if seen.insert(event.id) && verify(&event) {
                        return Ok::<(), anyhow::Error>(());
                    }
                }
                _ = poll.tick() => {
                    for event in client.fetch(confirm_filter.clone()).await? {
                        if seen.insert(event.id) && verify(&event) {
                            return Ok(());
                        }
                    }
                }
            }
        }
    };

    let result = tokio::time::timeout(CONFIRM_TIMEOUT, wait).await;
    client.unsubscribe(&sub_id).await;
    match result {
        Ok(inner) => inner?,
        Err(_) => bail!(
            "Sender did not confirm. The transfer may have been claimed by another device, or the sender went offline."
        ),
    }

    ui::status("Sender confirmed the claim.");
    Ok(())
}

async fn publish_answer_and_candidates(
    client: &NostrClient,
    sender_pubkey: &PublicKey,
    transfer_id: &str,
    answer_sdp: &str,
    candidates: &[String],
    key: &[u8; aes::AES_KEY_LEN],
) -> Result<()> {
    let mut signals = vec![Signal::Answer {
        sdp: answer_sdp.to_string(),
    }];
    signals.extend(candidates.iter().map(|candidate| Signal::Candidate {
        candidate: Some(CandidatePayload {
            candidate: candidate.clone(),
            sdp_mid: Some("0".to_string()),
            sdp_m_line_index: Some(0),
        }),
    }));

    // Publish concurrently: a slow relay must not serialize the answer and
    // every trickled candidate into a multiple of its latency.
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

fn handle_pre_offer_signal(
    event: &Event,
    seen: &mut HashSet<EventId>,
    key: &[u8; aes::AES_KEY_LEN],
    transfer_id: &str,
    sender_pubkey: PublicKey,
    offer_sdp: &mut Option<String>,
    queued_candidates: &mut Vec<String>,
) -> Result<()> {
    if !seen.insert(event.id) {
        return Ok(());
    }
    let Some(parsed) = parse_signal_event(event, key, transfer_id) else {
        return Ok(());
    };
    if parsed.pubkey != sender_pubkey {
        return Ok(());
    }

    match parsed.signal {
        Signal::Offer { sdp } => {
            *offer_sdp = Some(sdp);
        }
        Signal::Candidate {
            candidate: Some(candidate),
        } => queued_candidates.push(candidate.candidate),
        _ => {}
    }
    Ok(())
}

async fn handle_receiver_candidate(
    event: &Event,
    seen: &mut HashSet<EventId>,
    peer: &Arc<WebRtcPeer>,
    key: &[u8; aes::AES_KEY_LEN],
    transfer_id: &str,
    sender_pubkey: PublicKey,
) -> Result<()> {
    if !seen.insert(event.id) {
        return Ok(());
    }
    let Some(parsed) = parse_signal_event(event, key, transfer_id) else {
        return Ok(());
    };
    if parsed.pubkey != sender_pubkey {
        return Ok(());
    }

    if let Signal::Candidate {
        candidate: Some(candidate),
    } = parsed.signal
    {
        add_ice_candidate_safely(peer, &candidate.candidate).await;
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
