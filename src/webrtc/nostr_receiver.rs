//! Nostr Auto Exchange receiver compatible with secure-send-web.
//!
//! Handshake: reduce the PIN to its SPAKE2 password scalar, locate candidate
//! rendezvous events via rotation-bucket hints, run the receiver side of the
//! PAKE against each candidate and publish one sealed claim per candidate, wait
//! for the confirm that opens under one of those sessions (which delivers the
//! file metadata), display the confirmation code, then receive over a direct
//! WebRTC data channel once the sender's operator has typed it.

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
use crate::crypto::kdf::{ConfirmationCodeBinding, HandshakeSealKeys, NostrSessionKeys, PakeRoot};
use crate::crypto::pin::{
    MAX_CLAIM_CANDIDATES, PIN_HINT_LOOKBACK_BUCKETS, PIN_TTL_MS, is_valid_pin, now_ms, pin_bucket,
    pin_hint_for_bucket, pin_locator,
};
use crate::crypto::spake2::{
    PakeIdentities, PakeRole, PakeRun, derive_pake_secret, is_valid_pake_message,
};
use crate::signaling::nostr::{
    CandidatePayload, ClaimPayload, ConfirmPayload, HandshakeType, NostrClient, RendezvousPayload,
    Signal, TransferMetadata, compute_rendezvous_transcript_hash, compute_transfer_metadata_hash,
    confirm_filter, create_handshake_event, create_signal_event, generate_handshake_nonce,
    open_handshake_payload, parse_handshake_event, parse_rendezvous_event, parse_signal_event,
    rendezvous_filter, seal_handshake_payload, signal_filter_from_sender,
};
use crate::transfer::run_receiver;
use crate::ui;
use crate::util::{OnConflict, format_bytes, resolve_destination};
use crate::webrtc::common::{DcMessenger, WebRtcPeer, open_and_detach};
use crate::webrtc::{add_ice_candidate_safely, advertise_max_message_size, candidate_strings};

/// Time to establish the WebRTC data channel once signaling has started.
/// Mirrors the sender's timeout.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
/// Wait for the sender's confirm after the claims are published. The sender
/// confirms as soon as a claim verifies — no human is in that leg — so this only
/// needs to cover relay latency. It is also where a mistyped-but-checksum-valid
/// PIN surfaces.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(60);
/// Wait for the sender's first WebRTC signal after its confirm. Generous
/// because a human is in the loop: the sender publishes nothing until its
/// operator types the code this side is displaying.
const OFFER_WAIT_TIMEOUT: Duration = Duration::from_secs(180);
/// Backstop poll for a confirm a relay stored before our subscription landed.
const CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(3);
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
const ANSWER_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// A structurally valid rendezvous event, before any PAKE work.
struct RendezvousCandidate {
    payload: RendezvousPayload,
    salt: Vec<u8>,
    sender_pubkey: PublicKey,
    pake_message: Vec<u8>,
}

/// One rendezvous candidate the receiver has run its side of the PAKE against
/// and claimed. The hint is a filter, not an identifier, and the rendezvous is
/// plaintext, so the receiver cannot know which candidate is its sender until a
/// confirm opens under one of these sessions' keys.
struct ClaimCandidate {
    transfer_id: String,
    sender_pubkey: PublicKey,
    sender_nonce: String,
    receiver_nonce: String,
    salt: Vec<u8>,
    transcript_hash: String,
    root: PakeRoot,
    seal_keys: HandshakeSealKeys,
    claim_event: Event,
}

/// The candidate whose sender confirmed, plus the metadata that confirm carried.
struct ConfirmedSession {
    candidate: ClaimCandidate,
    metadata: TransferMetadata,
}

pub async fn receive_file_nostr(
    pin: &str,
    output_dir: Option<PathBuf>,
    on_conflict: OnConflict,
) -> Result<()> {
    if !is_valid_pin(pin) {
        bail!("Invalid PIN: check for typos and try again");
    }
    let locator = pin_locator(pin).to_string();

    // Nothing here waits on a key stretch — with the PAKE there is none. The
    // PIN reduces to its password scalar and derives the public lookup hints
    // from its locator segment.
    let pake_secret = derive_pake_secret(pin);
    // Mirror the sender's acceptance rule by deriving the current and previous
    // buckets.
    let current_bucket = pin_bucket(now_ms());
    let hints: Vec<String> = (0..=PIN_HINT_LOOKBACK_BUCKETS)
        .map(|offset| pin_hint_for_bucket(&locator, current_bucket.saturating_sub(offset)))
        .collect();

    let step = Instant::now();
    ui::status("Connecting to Nostr relays...");
    let client = NostrClient::connect(Keys::generate()).await?;
    ui::status_timed("Connected to Nostr relays", step.elapsed());

    ui::status("Searching for sender...");
    let candidates = find_rendezvous_candidates(&client, &hints).await?;

    // Claim every candidate: run our side of the SPAKE2 exchange against each
    // one's element and seal a claim under the resulting session's claim key.
    // Only the candidate our sender actually published can ever answer with a
    // confirm that opens under its session's confirm key.
    let receiver_pubkey = client.public_key_hex();
    let claims = build_claims(&client, candidates, &pake_secret, &receiver_pubkey)?;
    if claims.is_empty() {
        bail!(
            "No claimable transfer found for this PIN. Check the code currently shown on the sender."
        );
    }

    let session = wait_for_confirm(&client, claims, &receiver_pubkey).await?;
    let metadata = &session.metadata;

    if metadata.content_type != "file" {
        bail!("Transfer describes unsupported content");
    }
    if metadata.file_size_exact && metadata.file_size == 0 {
        bail!("Transfer describes an empty file");
    }
    if metadata.file_size > MAX_MESSAGE_SIZE {
        bail!(
            "Transfer is {}, which exceeds the {} limit",
            format_bytes(metadata.file_size),
            format_bytes(MAX_MESSAGE_SIZE)
        );
    }

    // The confirm proved the sender ran our PAKE session, and its sealed
    // metadata is now on the table. The sender publishes nothing further — no
    // WebRTC offer, no file byte — until its operator types this code. Someone
    // who front-ran us with a stolen PIN holds a different SPAKE2 session, so
    // the code on their screen is not the one the sender is about to be told.
    let candidate = &session.candidate;
    let metadata_hash = compute_transfer_metadata_hash(metadata)?;
    let confirmation_code = candidate.root.confirmation_code(
        &candidate.salt,
        &ConfirmationCodeBinding {
            transfer_id: &candidate.transfer_id,
            sender_nonce: &candidate.sender_nonce,
            receiver_nonce: &candidate.receiver_nonce,
            transcript_hash: &candidate.transcript_hash,
            metadata_hash: &metadata_hash,
        },
    )?;
    ui::show_confirmation_code(&confirmation_code);

    let file_name = metadata.file_name.clone();
    let file_size = metadata.file_size;
    let file_size_exact = metadata.file_size_exact;
    ui::incoming(&file_name, file_size, Some(&metadata.mime_type));
    let dest = match resolve_destination(output_dir, &file_name, on_conflict).await? {
        Some(dest) => dest,
        None => {
            ui::hide_confirmation_code();
            ui::status("Cancelled.");
            client.disconnect().await;
            return Ok(());
        }
    };

    // Session keys are HKDF derivations off the same SPAKE2 root — the PIN
    // authenticated the exchange, and the exchange's fresh ephemeral scalars
    // supply the entropy.
    let session_keys: NostrSessionKeys = candidate.root.session_keys(&candidate.salt)?;
    let transfer_id = candidate.transfer_id.clone();
    let sender_pubkey = candidate.sender_pubkey;

    ui::status("Waiting for the sender to enter the confirmation code...");
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

    // The sender's first signal is what says the operator's code matched.
    let offer_wait = tokio::time::timeout(OFFER_WAIT_TIMEOUT, async {
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
    .await;
    ui::hide_confirmation_code();
    offer_wait.map_err(|_| {
        anyhow::anyhow!("The sender did not enter the confirmation code in time. Start a new transfer.")
    })??;

    let offer_sdp = offer_sdp.context("missing sender offer")?;
    let connection_deadline = Instant::now() + CONNECTION_TIMEOUT;

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

/// Locate structurally valid rendezvous candidates, newest first, one per
/// transfer id and at most [`MAX_CLAIM_CANDIDATES`].
///
/// The rendezvous is plaintext, so nothing here can tell which candidate is our
/// sender — validation is structural only: the payload must name the event's own
/// author and transfer id (so a copied payload republished under another
/// identity is rejected) and carry a valid non-identity curve point.
async fn find_rendezvous_candidates(
    client: &NostrClient,
    hints: &[String],
) -> Result<Vec<RendezvousCandidate>> {
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

    let mut saw_expired = false;
    let mut candidates: Vec<RendezvousCandidate> = Vec::new();

    for event in events {
        if candidates.len() >= MAX_CLAIM_CANDIDATES {
            break;
        }

        // A rendezvous event is only claimable while the sender still honors
        // its PIN generation.
        let created_at_ms = event.created_at.as_secs() * 1000;
        if now_ms().saturating_sub(created_at_ms) > PIN_TTL_MS {
            saw_expired = true;
            continue;
        }

        let Some(parsed) = parse_rendezvous_event(&event) else {
            continue;
        };
        // The sender's current and previous rotation both match our hints and
        // share a transfer id — claim only the newest generation.
        if candidates
            .iter()
            .any(|candidate| candidate.payload.transfer_id == parsed.transfer_id)
        {
            continue;
        }

        let payload = parsed.payload;
        if payload.payload_type != "rendezvous"
            || payload.transfer_id != parsed.transfer_id
            || payload.sender_pubkey != event.pubkey.to_hex()
            || payload.nonce.is_empty()
        {
            continue;
        }
        let Ok(pake_message) = STANDARD.decode(&payload.pake_message) else {
            continue;
        };
        if !is_valid_pake_message(&pake_message) {
            continue;
        }

        candidates.push(RendezvousCandidate {
            payload,
            salt: parsed.salt,
            sender_pubkey: event.pubkey,
            pake_message,
        });
    }

    if candidates.is_empty() {
        if saw_expired {
            bail!("This PIN has expired. Enter the code currently shown on the sender.");
        }
        bail!(
            "No claimable transfer found for this PIN. Check the code currently shown on the sender."
        );
    }

    ui::status(&format!(
        "Claiming {} candidate transfer(s)...",
        candidates.len()
    ));
    Ok(candidates)
}

/// Run the receiver side of the PAKE against every candidate and seal one claim
/// each. Each claim hands whoever authored that candidate one online PIN guess —
/// inherent to any PAKE, bounded here by [`MAX_CLAIM_CANDIDATES`].
fn build_claims(
    client: &NostrClient,
    candidates: Vec<RendezvousCandidate>,
    pake_secret: &[u8; 32],
    receiver_pubkey: &str,
) -> Result<Vec<ClaimCandidate>> {
    let mut claims = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        let sender_pubkey_hex = candidate.sender_pubkey.to_hex();
        let identities = PakeIdentities {
            transfer_id: &candidate.payload.transfer_id,
            sender_pubkey: &sender_pubkey_hex,
            receiver_pubkey,
        };

        // A candidate whose element fails the PAKE is simply skipped.
        let Ok(pake) = PakeRun::start(PakeRole::Receiver, pake_secret) else {
            continue;
        };
        let Ok(root) = pake.finish(&candidate.pake_message, &identities) else {
            continue;
        };
        // Same treatment: the salt rides on an unauthenticated rendezvous event,
        // so a forged one carrying a short salt must cost that candidate, not
        // the whole receive.
        let Ok(seal_keys) = root.handshake_seal_keys(&candidate.salt) else {
            continue;
        };

        // Hash the rendezvous we actually acted on. The sender compares it with
        // the one it published and drops the claim on any difference, so a
        // republished rendezvous with any altered field never reaches the point
        // where the two humans compare codes.
        let transcript_hash =
            compute_rendezvous_transcript_hash(&candidate.payload, &candidate.salt)?;
        let receiver_nonce = generate_handshake_nonce()?;

        let claim = ClaimPayload {
            payload_type: "claim".to_string(),
            transfer_id: candidate.payload.transfer_id.clone(),
            sender_nonce: candidate.payload.nonce.clone(),
            receiver_nonce: receiver_nonce.clone(),
            sender_pubkey: sender_pubkey_hex,
            receiver_pubkey: receiver_pubkey.to_string(),
            transcript_hash: transcript_hash.clone(),
        };
        let claim_event = create_handshake_event(
            client,
            &candidate.sender_pubkey,
            &candidate.payload.transfer_id,
            HandshakeType::Claim,
            &seal_handshake_payload(&seal_keys.claim, &claim)?,
            Some(pake.message()),
        )?;

        claims.push(ClaimCandidate {
            transfer_id: candidate.payload.transfer_id,
            sender_pubkey: candidate.sender_pubkey,
            sender_nonce: candidate.payload.nonce,
            receiver_nonce,
            salt: candidate.salt,
            transcript_hash,
            root,
            seal_keys,
            claim_event,
        });
    }

    Ok(claims)
}

/// Publish every claim and wait for the first confirm that opens under one of
/// the claimed sessions' confirm keys — that is what decides which candidate was
/// real. Subscribes before publishing so the response cannot slip past, and
/// polls as a backstop for relays that stored the confirm before the
/// subscription landed.
async fn wait_for_confirm(
    client: &NostrClient,
    claims: Vec<ClaimCandidate>,
    receiver_pubkey: &str,
) -> Result<ConfirmedSession> {
    let our_pubkey = client.public_key();
    let filter = confirm_filter(
        claims.iter().map(|claim| claim.transfer_id.as_str()),
        &our_pubkey,
        claims.iter().map(|claim| claim.sender_pubkey),
    );
    let mut notifications = client.notifications();
    let sub_id = client.subscribe(filter.clone()).await?;

    let step = Instant::now();
    ui::status("Publishing claim to Nostr...");
    // Most candidates are hint collisions or forgeries; only one can be our
    // sender, and we cannot tell which. A relay refusing any single claim (a
    // burst of up to MAX_CLAIM_CANDIDATES events invites rate limiting) must
    // not strand the rest, so keep going and fail only if none landed.
    let mut published = 0usize;
    let mut last_failure = None;
    for claim in &claims {
        match client.publish(&claim.claim_event).await {
            Ok(()) => published += 1,
            Err(error) => last_failure = Some(error),
        }
    }
    if published == 0 {
        client.unsubscribe(&sub_id).await;
        return Err(last_failure
            .unwrap_or_else(|| anyhow::anyhow!("no claim was published"))
            .context("Failed to publish any claim to Nostr"));
    }
    ui::status_timed("Published claim to Nostr", step.elapsed());

    ui::status("Waiting for the sender to verify...");
    let mut seen = HashSet::new();

    let mut poll = tokio::time::interval(CONFIRM_POLL_INTERVAL);
    poll.tick().await; // consume the immediate first tick

    let wait = async {
        loop {
            tokio::select! {
                event = next_event(&mut notifications) => {
                    let event = event?;
                    if seen.insert(event.id)
                        && let Some(matched) = match_confirm(&event, &claims, receiver_pubkey)
                    {
                        return Ok::<_, anyhow::Error>(matched);
                    }
                }
                _ = poll.tick() => {
                    for event in client.fetch(filter.clone()).await? {
                        if seen.insert(event.id)
                            && let Some(matched) = match_confirm(&event, &claims, receiver_pubkey)
                        {
                            return Ok(matched);
                        }
                    }
                }
            }
        }
    };

    let result = tokio::time::timeout(CONFIRM_TIMEOUT, wait).await;
    client.unsubscribe(&sub_id).await;
    let (index, metadata) = match result {
        Ok(inner) => inner?,
        Err(_) => bail!(
            "Sender did not confirm. The transfer may have been claimed by another device, the sender may have gone offline, or the PIN was mistyped."
        ),
    };

    ui::status("Sender confirmed the claim.");
    let candidate = claims
        .into_iter()
        .nth(index)
        .context("confirmed candidate disappeared")?;
    Ok(ConfirmedSession {
        candidate,
        metadata,
    })
}

/// Try to open a confirm event under each claimed session's confirm key.
/// Returns the index of the winning candidate and the metadata it delivered.
fn match_confirm(
    event: &Event,
    claims: &[ClaimCandidate],
    receiver_pubkey: &str,
) -> Option<(usize, TransferMetadata)> {
    let handshake = parse_handshake_event(event)?;
    if handshake.handshake_type != HandshakeType::Confirm {
        return None;
    }

    let (index, candidate) = claims.iter().enumerate().find(|(_, candidate)| {
        candidate.transfer_id == handshake.transfer_id && candidate.sender_pubkey == event.pubkey
    })?;

    let Ok(payload) = open_handshake_payload::<ConfirmPayload>(
        &candidate.seal_keys.confirm,
        &handshake.sealed_payload,
    ) else {
        return None; // Not sealed by our PAKE peer for this candidate
    };

    if payload.payload_type != "confirm"
        || payload.transfer_id != candidate.transfer_id
        || payload.sender_nonce != candidate.sender_nonce
        || payload.receiver_nonce != candidate.receiver_nonce
        || payload.sender_pubkey != event.pubkey.to_hex()
        || payload.receiver_pubkey != receiver_pubkey
        || payload.transcript_hash != candidate.transcript_hash
    {
        return None;
    }

    Some((index, payload.metadata))
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
