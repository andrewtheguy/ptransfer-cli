//! The receiver's half of the relay fallback.
//!
//! It joins the control channel on the relays the offer named, says `hello` —
//! which is also what tells a sender still trying the direct route that there
//! is nothing to connect to — and waits for the manifest. From then on it
//! follows the sender's announcements: each one carries the whole ring and the
//! whole placement, so every announced piece is fetched from the one relay it
//! was placed on, and whatever could not be fetched is reported back **at the
//! placement that was actually tried**, never the newest announced one. An
//! announcement landing mid-fetch would otherwise blame a relay this cycle
//! never asked, costing a needless re-send and a false strike against a
//! healthy relay.
//!
//! The receiver also runs on its own clock: a piece still missing ten seconds
//! after its last attempt is fetched again from the same placement, so a
//! timed-out or not-yet-propagated copy recovers without costing a re-send,
//! and a lost announcement never strands a piece.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use nostr_sdk::prelude::*;
use tokio::sync::mpsc;

use crate::code::keys::RelaySession;
use crate::crypto::aes::AES_KEY_LEN;
use crate::ui;

use super::codec::{assemble_chunks, chunk_aad, decode_chunk_content, decompress_payload, sha256};
use super::control::{
    ChannelConfig, ControlChannel, ControlRole, ReceiverMessage, SenderMessage, decode_position,
};
use super::events::{chunk_filters, parse_chunk_event};
use super::manifest::NostrFileManifest;
use super::pool::FilePool;
use super::{
    CLOCK_SKEW_TOLERANCE_SEC, LIVE_FETCH_RETRY, LIVE_IDLE_TIMEOUT, RELAY_QUERY_TIMEOUT, now_seconds,
};

/// What the receiver needs beyond the offer it took in.
pub struct ReceiveContext<'a> {
    pub pool: Arc<FilePool>,
    pub session: &'a RelaySession,
    /// The relays the offer named.
    pub control_relays: Vec<String>,
    /// unix seconds: the exchange's own start, so a manifest published before
    /// this side joined is read out of the backlog.
    pub since: u64,
    /// unix seconds: the exchange's deadline, stamped on this side's events.
    pub expires_at: u64,
    /// Whether the sender has yet to be handed the response. Its silence is
    /// then not a fault but a person still carrying a code, so until its first
    /// message only the transfer's own expiry ends the wait.
    pub awaiting_handover: bool,
    /// What the offer said is coming, checked against the manifest.
    pub expected_name: String,
}

/// Everything the receiver keeps while pieces arrive.
struct Download {
    manifest: Option<NostrFileManifest>,
    sender_pubkey: Option<PublicKey>,
    chunks: Vec<Option<Vec<u8>>>,
    /// The placement last tried for a chunk still missing, and when that
    /// attempt finished: after [`LIVE_FETCH_RETRY`] the same placement becomes
    /// worth trying again.
    last_tried: Vec<Option<(usize, u64)>>,
    last_tried_at: Vec<Option<Instant>>,
    ring: Vec<String>,
    /// The ring position of every announced chunk, decoded once from the
    /// announcement's map.
    map: Vec<usize>,
    gens: HashMap<usize, u64>,
    upto: usize,
    chunks_done: usize,
    last_sender_n: u64,
    last_peer_at: Option<Instant>,
    last_cycle_at: Option<Instant>,
}

impl Download {
    fn new() -> Self {
        Self {
            manifest: None,
            sender_pubkey: None,
            chunks: Vec::new(),
            last_tried: Vec::new(),
            last_tried_at: Vec::new(),
            ring: Vec::new(),
            map: Vec::new(),
            gens: HashMap::new(),
            upto: 0,
            chunks_done: 0,
            last_sender_n: 0,
            last_peer_at: None,
            last_cycle_at: None,
        }
    }

    fn total(&self) -> usize {
        self.chunks.len()
    }

    /// The sender is on the control channel, which means it took the response
    /// in: the code has done its job and the screen goes back to reporting the
    /// transfer.
    fn saw_sender(&mut self) {
        if self.last_peer_at.is_none() {
            ui::hide_code();
        }
        self.last_peer_at = Some(Instant::now());
    }

    /// Where the latest announcement says a chunk is: its ring position and
    /// its re-send generation.
    fn placement(&self, index: usize) -> Option<(usize, u64)> {
        let position = *self.map.get(index)?;
        Some((position, self.gens.get(&index).copied().unwrap_or(0)))
    }
}

/// Take the file the sender is relaying, and hand back the verified plaintext.
pub async fn receive_over_relays(context: ReceiveContext<'_>) -> Result<Vec<u8>> {
    let key = context.session.key_bytes;
    let (channel, mut incoming) = ControlChannel::open(
        Arc::clone(&context.pool),
        ChannelConfig {
            relays: &context.control_relays,
            transfer_id: context.session.transfer_id.clone(),
            key: context.session.control_key()?,
            role: ControlRole::Receiver,
            keys: Keys::generate(),
            since: context.since.saturating_sub(CLOCK_SKEW_TOLERANCE_SEC),
            expires_at: context.expires_at,
        },
    )
    .await?;

    let started = Instant::now();
    let mut state = Download::new();
    channel
        .send_receiver(ReceiverMessage::Hello { n: 0 })
        .await
        .context("The sender could not be told the direct route is dead")?;
    ui::status("Waiting for the sender to start relaying the file...");

    let result = run(&context, &channel, &mut incoming, &mut state, key, started).await;
    if result.is_err() {
        // Best effort: let the sender stop re-sending right away.
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            channel.send_receiver(ReceiverMessage::Cancel { n: 0 }),
        )
        .await;
    }
    channel.close().await;
    ui::progress_end();
    result
}

async fn run(
    context: &ReceiveContext<'_>,
    channel: &ControlChannel,
    incoming: &mut mpsc::UnboundedReceiver<(serde_json::Value, PublicKey)>,
    state: &mut Download,
    key: [u8; AES_KEY_LEN],
    started: Instant,
) -> Result<Vec<u8>> {
    let transfer_id = context.session.transfer_id.clone();
    loop {
        let mut fetch_now = false;
        tokio::select! {
            message = incoming.recv() => {
                let Some((value, pubkey)) = message else {
                    bail!("The control channel to the sender closed.");
                };
                match handle(state, value, pubkey, &context.expected_name)? {
                    Handled::Fetch => fetch_now = true,
                    Handled::Nothing => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }

        // Clocks first: a transfer whose window is over cannot be finished by
        // fetching harder.
        let expires_at = state
            .manifest
            .as_ref()
            .map_or(context.expires_at, |manifest| manifest.expires_at);
        if now_seconds() > expires_at {
            bail!(
                "The transfer expired before every piece arrived — relay copies are only kept \
                 for an hour. Ask the sender to start a new transfer."
            );
        }
        let quiet_for = state.last_peer_at.unwrap_or(started).elapsed();
        let sender_due = state.last_peer_at.is_some() || !context.awaiting_handover;
        if sender_due && quiet_for > LIVE_IDLE_TIMEOUT {
            if state.last_peer_at.is_some() {
                bail!("The sender stopped responding. Both sides have to stay open until the transfer completes.");
            }
            bail!("No answer from the sender over the relays. Make sure its transfer is still running.");
        }

        // The retry clock: with announced pieces still missing and no cycle in
        // the last ten seconds, run one anyway.
        let due = state
            .last_cycle_at
            .is_none_or(|last| last.elapsed() >= LIVE_FETCH_RETRY);
        if !state.ring.is_empty()
            && state.upto > state.chunks_done
            && (fetch_now || due)
            && let Some(data) = cycle(context, channel, state, &transfer_id, key).await?
        {
            return Ok(data);
        }
    }
}

#[derive(Debug)]
enum Handled {
    Fetch,
    Nothing,
}

/// Apply one of the sender's messages.
fn handle(
    state: &mut Download,
    value: serde_json::Value,
    pubkey: PublicKey,
    expected_name: &str,
) -> Result<Handled> {
    if state
        .sender_pubkey
        .is_some_and(|pinned| pinned != pubkey)
    {
        return Ok(Handled::Nothing);
    }
    let Ok(message) = serde_json::from_value::<SenderMessage>(value) else {
        return Ok(Handled::Nothing);
    };
    let total = state.manifest.as_ref().map(|_| state.total());
    if message.validate(total).is_err() || message.counter() <= state.last_sender_n {
        return Ok(Handled::Nothing);
    }

    match message {
        SenderMessage::Manifest { n, manifest } => {
            // Exactly one manifest, and only from the identity it names.
            if state.manifest.is_some() || manifest.pubkey != pubkey.to_hex() {
                return Ok(Handled::Nothing);
            }
            manifest.validate()?;
            manifest.check_window(now_seconds())?;
            // The receiver agreed to the file the code described and has no
            // other way to notice being handed a different one. The size may
            // legitimately differ — an offer's size is the selection's, a
            // manifest's is the payload's — but the name is the same value on
            // both sides of every implementation.
            if manifest.file_name != expected_name {
                bail!(
                    "The sender is relaying a file called {:?}, not the {:?} the code described. \
                     Start a new transfer.",
                    manifest.file_name,
                    expected_name
                );
            }
            let total = manifest.total_chunks_usize()?;
            state.chunks = vec![None; total];
            state.last_tried = vec![None; total];
            state.last_tried_at = vec![None; total];
            ui::status(&format!(
                "The sender is relaying the file in {total} pieces through Nostr relays."
            ));
            state.manifest = Some(*manifest);
            state.sender_pubkey = Some(pubkey);
            state.last_sender_n = n;
            state.saw_sender();
            Ok(Handled::Nothing)
        }
        SenderMessage::Avail {
            n,
            upto,
            relays,
            map,
            gens,
        } => {
            if !relays.is_empty() {
                if state.ring.is_empty() {
                    state.ring = relays;
                } else if state.ring != relays {
                    // The sender never changes its ring: a different one is
                    // forged or corrupt, and is dropped without advancing the
                    // counter so the real announcement still lands.
                    return Ok(Handled::Nothing);
                }
            }
            state.last_sender_n = n;
            state.saw_sender();
            state.upto = upto;
            // Validation above proved every character names a position in the
            // ring this message carried, which is the ring in use.
            state.map = map.chars().filter_map(decode_position).collect();
            state.gens = gens.into_iter().collect();
            // An empty-ring announcement is presence only — there is nothing
            // placed yet to fetch.
            Ok(if state.ring.is_empty() || upto == 0 {
                Handled::Nothing
            } else {
                Handled::Fetch
            })
        }
        SenderMessage::Cancel { .. } => bail!("The sender cancelled the transfer."),
    }
}

/// One fetch cycle: take what the latest announcement made available, report
/// the outcome, and — when everything is in — verify and hand over the file.
async fn cycle(
    context: &ReceiveContext<'_>,
    channel: &ControlChannel,
    state: &mut Download,
    transfer_id: &str,
    key: [u8; AES_KEY_LEN],
) -> Result<Option<Vec<u8>>> {
    let manifest = state
        .manifest
        .as_ref()
        .context("a fetch cycle ran before the manifest arrived")?
        .clone();
    state.last_cycle_at = Some(Instant::now());
    let announced = state.last_sender_n;

    let mut by_position: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut tried: HashMap<usize, (usize, u64)> = HashMap::new();
    for index in 0..state.upto {
        if state.chunks[index].is_some() {
            continue;
        }
        let Some((position, generation)) = state.placement(index) else {
            continue;
        };
        // A placement already tried and not yet cooled down is left alone: the
        // sender is being asked for a new one.
        if state.last_tried[index] == Some((position, generation))
            && state.last_tried_at[index]
                .is_some_and(|at| at.elapsed() < LIVE_FETCH_RETRY)
        {
            continue;
        }
        tried.insert(index, (position, generation));
        by_position.entry(position).or_default().push(index);
    }

    let mut fetches = tokio::task::JoinSet::new();
    for (position, indices) in by_position {
        let Some(relay) = state.ring.get(position).cloned() else {
            continue;
        };
        let pool = Arc::clone(&context.pool);
        let manifest = manifest.clone();
        let transfer_id = transfer_id.to_string();
        fetches.spawn(async move {
            fetch_from_relay(&pool, &transfer_id, &manifest, &key, &relay, &indices).await
        });
    }
    while let Some(fetched) = fetches.join_next().await {
        let Ok(fetched) = fetched else { continue };
        for (index, plaintext) in fetched {
            if index < state.chunks.len() && state.chunks[index].is_none() {
                state.chunks[index] = Some(plaintext);
                state.chunks_done += 1;
            }
        }
    }
    report(state, &manifest);

    let now = Instant::now();
    for (index, placement) in tried {
        if state.chunks[index].is_none() {
            state.last_tried[index] = Some(placement);
            state.last_tried_at[index] = Some(now);
        }
    }

    let missing: Vec<(usize, usize, u64)> = (0..state.upto)
        .filter(|index| state.chunks[*index].is_none())
        .filter_map(|index| {
            state.last_tried[index].map(|(position, generation)| (index, position, generation))
        })
        .collect();
    channel
        .send_receiver(ReceiverMessage::Ack {
            n: 0,
            avail: announced,
            have: state.chunks_done,
            missing,
        })
        .await?;

    if state.chunks_done < state.total() {
        return Ok(None);
    }

    // Chunks carry the compressed payload; the hash covers the plaintext, so
    // the payload is inflated first — bounded by the size the manifest
    // promised — and only then verified.
    ui::status("Every piece arrived — verifying the file...");
    // The pieces are taken rather than borrowed, so the assembled payload and
    // the plaintext are the only copies of the file this process holds by the
    // time it verifies them.
    let pieces = std::mem::take(&mut state.chunks);
    let payload = assemble_chunks(&pieces, manifest.payload_size)?;
    drop(pieces);
    let data = decompress_payload(&payload, manifest.compression, manifest.file_size)?;
    drop(payload);
    if BASE64.encode(sha256(&data)) != manifest.file_hash {
        bail!("The relayed file failed its integrity check — it arrived corrupted.");
    }
    // The file is complete and verified: hand it over first, and tell the
    // sender as a courtesy. A `done` no relay would take must not sink a
    // download that already succeeded.
    let _ = channel.send_receiver(ReceiverMessage::Done { n: 0 }).await;
    Ok(Some(data))
}

/// Ask one relay for the pieces placed on it and decrypt what comes back.
///
/// A relay's failure is not the transfer's: what it does not serve simply
/// stays missing, is reported in the next acknowledgement, and is re-sent
/// somewhere else.
async fn fetch_from_relay(
    pool: &FilePool,
    transfer_id: &str,
    manifest: &NostrFileManifest,
    key: &[u8; AES_KEY_LEN],
    relay: &str,
    indices: &[usize],
) -> Vec<(usize, Vec<u8>)> {
    let Ok(pubkey) = PublicKey::parse(&manifest.pubkey) else {
        return Vec::new();
    };
    let total = manifest.total_chunks as usize;
    let mut fetched = Vec::new();
    for filter in chunk_filters(&pubkey, transfer_id, indices) {
        let events = match pool.query(relay, filter, RELAY_QUERY_TIMEOUT).await {
            Ok(events) => events,
            Err(error) => {
                log::debug!("relay {relay} did not answer for pieces: {error:#}");
                continue;
            }
        };
        for event in events {
            let Some((index, content)) = parse_chunk_event(&event, &pubkey, transfer_id) else {
                continue;
            };
            if index >= total || !indices.contains(&index) {
                continue;
            }
            match decode_chunk_content(
                key,
                content,
                &chunk_aad(transfer_id, index, total),
                manifest.chunk_size as usize,
            ) {
                Ok(plaintext) => fetched.push((index, plaintext)),
                // Tampered or corrupt: leave it missing, so it is asked for
                // again somewhere else.
                Err(error) => log::debug!("relay {relay} served an unusable piece: {error:#}"),
            }
        }
    }
    fetched
}

fn report(state: &Download, manifest: &NostrFileManifest) {
    let per_chunk = manifest.file_size.div_ceil(state.total().max(1) as u64);
    let received = (state.chunks_done as u64 * per_chunk).min(manifest.file_size);
    ui::progress(ui::Direction::Receive, received, manifest.file_size);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code::nostr_file::codec::PayloadCompression;

    fn manifest(name: &str) -> NostrFileManifest {
        NostrFileManifest {
            v: super::super::MANIFEST_VERSION,
            file_name: name.to_string(),
            file_size: 100,
            mime_type: "application/pdf".to_string(),
            file_hash: "A".repeat(43) + "=",
            pubkey: "a".repeat(64),
            compression: PayloadCompression::None,
            payload_size: 100,
            chunk_size: 1024,
            total_chunks: 1,
            enc: 2,
            created_at: now_seconds(),
            expires_at: now_seconds() + super::super::NOSTR_FILE_EXPIRATION_SEC,
        }
    }

    fn manifest_message(manifest: NostrFileManifest) -> serde_json::Value {
        serde_json::to_value(SenderMessage::Manifest {
            n: 1,
            manifest: Box::new(manifest),
        })
        .unwrap()
    }

    /// The announcement's ring is adopted once and never replaced: the ring
    /// positions of everything already fetched are indexes into it.
    #[test]
    fn a_second_ring_is_refused_rather_than_adopted() {
        let mut state = Download::new();
        let keys = Keys::generate();
        let mut manifest = manifest("report.pdf");
        manifest.pubkey = keys.public_key().to_hex();
        handle(
            &mut state,
            manifest_message(manifest),
            keys.public_key(),
            "report.pdf",
        )
        .unwrap();

        let announce = |n: u64, relay: &str| {
            serde_json::to_value(SenderMessage::Avail {
                n,
                upto: 1,
                relays: vec![relay.to_string()],
                map: "A".to_string(),
                gens: Vec::new(),
            })
            .unwrap()
        };
        handle(&mut state, announce(2, "wss://one.example"), keys.public_key(), "report.pdf")
            .unwrap();
        assert_eq!(state.ring, vec!["wss://one.example"]);
        handle(&mut state, announce(3, "wss://two.example"), keys.public_key(), "report.pdf")
            .unwrap();
        assert_eq!(state.ring, vec!["wss://one.example"]);
        assert_eq!(state.last_sender_n, 2);
    }

    /// The code is the only description the receiver agreed to, and the name
    /// is the one field both implementations carry identically in the offer
    /// and in the manifest.
    #[test]
    fn a_manifest_for_another_file_is_refused() {
        let mut state = Download::new();
        let keys = Keys::generate();
        let mut manifest = manifest("other.pdf");
        manifest.pubkey = keys.public_key().to_hex();
        let error = handle(
            &mut state,
            manifest_message(manifest),
            keys.public_key(),
            "report.pdf",
        )
        .unwrap_err();
        assert!(error.to_string().contains("not the"), "{error}");
    }

    /// Only the identity the manifest names may speak on the channel from then
    /// on, and only one manifest is ever taken.
    #[test]
    fn a_second_sender_is_ignored_once_one_is_pinned() {
        let mut state = Download::new();
        let keys = Keys::generate();
        let mut first = manifest("report.pdf");
        first.pubkey = keys.public_key().to_hex();
        handle(&mut state, manifest_message(first), keys.public_key(), "report.pdf").unwrap();

        let other = Keys::generate();
        let mut second = manifest("report.pdf");
        second.pubkey = other.public_key().to_hex();
        handle(&mut state, manifest_message(second), other.public_key(), "report.pdf").unwrap();
        assert_eq!(state.sender_pubkey, Some(keys.public_key()));
    }
}
