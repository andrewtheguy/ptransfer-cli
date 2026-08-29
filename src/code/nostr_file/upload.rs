//! The sender's half of the relay fallback.
//!
//! Nothing here runs until the direct route is known to be dead. Then the file
//! is hashed and chunked, the manifest goes out as the first control message —
//! so a receiver that joins late reads it from the backlog before any
//! placement — and each chunk is published **once**, to the one ring relay its
//! position names, while the receiver downloads alongside. Redundancy is
//! created on demand: a piece is re-sent only after the receiver reports it
//! could not fetch it, so the upload costs about one copy of the file plus the
//! pieces that went missing.
//!
//! A relay that acknowledges writes but does not serve them is the failure
//! mode this design has to survive, and it is what demotion is for: after two
//! reported misses new chunks and re-sends skip that relay while any other
//! remains. Without it, a ring holding a few such relays re-sends a third of a
//! large file.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use nostr_sdk::prelude::*;
use tokio::sync::{Notify, mpsc};

use crate::code::keys::RelaySession;
use crate::crypto::aes::AES_KEY_LEN;
use crate::ui;

use super::codec::{
    PayloadCompression, chunk_aad, compress_payload, encode_chunk_content, sha256,
};
use super::control::{
    ChannelConfig, ControlChannel, ControlRole, ReceiverMessage, SenderMessage, encode_position,
};
use super::events::{ChunkEvent, build_chunk_event};
use super::manifest::NostrFileManifest;
use super::pool::FilePool;
use super::relay_pool::PreparedRing;
use super::{
    CLOCK_SKEW_TOLERANCE_SEC, LIVE_BATCH_CHUNKS, LIVE_HEARTBEAT, LIVE_IDLE_TIMEOUT,
    LIVE_MIN_RETRANSMITS_PER_CHUNK, LIVE_RELAY_DEMOTE_GIVEUPS, LIVE_RELAY_DEMOTE_MISSES,
    MANIFEST_VERSION, NOSTR_FILE_CHUNK_SIZE, NOSTR_FILE_EXPIRATION_SEC, PUBLISH_BACKOFF_BASE,
    PUBLISH_BACKOFF_CAP, PUBLISH_BACKOFF_JITTER, PUBLISH_MAX_RETRIES, RELAY_MAX_BYTES, UPLOAD_CHUNK_CONCURRENCY,
    now_seconds,
};

/// What the sender needs beyond the file itself.
pub struct SendContext<'a> {
    pub pool: Arc<FilePool>,
    pub session: &'a RelaySession,
    /// The relays the offer named, which carry only the control channel.
    pub control_relays: Vec<String>,
    /// The storage ring, prepared behind the exchange and adopted here as soon
    /// as it resolves.
    pub ring: PreparedRing,
    pub file_name: String,
    pub mime_type: String,
}

/// What a source becomes on its way to the relays: the plaintext both sides
/// verify against, and the flow-based compression rule the payload follows.
pub struct RelaySource {
    pub data: Vec<u8>,
    pub compression: PayloadCompression,
}

/// Everything the tasks share. Nothing in here is held across an await.
struct Upload {
    total: usize,
    /// Ring position holding each chunk, or `None` while it is unplaced.
    placed: Vec<Option<usize>>,
    /// How many times each chunk has been re-sent.
    generation: Vec<u64>,
    /// Where the next attempt for each chunk starts walking the ring.
    next_offset: Vec<usize>,
    ring: Vec<String>,
    misses: Vec<u32>,
    give_ups: Vec<u32>,
    demoted: HashSet<usize>,
    max_retransmits: u64,
    /// Chunks `[0, upto)` are all placed.
    upto: usize,
    chunks_done: usize,
    resent: u64,
    next_chunk: usize,
    retry_queue: VecDeque<usize>,
    pending_retry: HashSet<usize>,
    receiver_pubkey: Option<PublicKey>,
    receiver_have: usize,
    last_peer_n: u64,
    last_peer_at: Option<Instant>,
    avail_dirty: bool,
    finished: bool,
}

impl Upload {
    fn new(total: usize) -> Self {
        Self {
            total,
            placed: vec![None; total],
            generation: vec![0; total],
            next_offset: vec![0; total],
            ring: Vec::new(),
            misses: Vec::new(),
            give_ups: Vec::new(),
            demoted: HashSet::new(),
            max_retransmits: LIVE_MIN_RETRANSMITS_PER_CHUNK,
            upto: 0,
            chunks_done: 0,
            resent: 0,
            next_chunk: 0,
            retry_queue: VecDeque::new(),
            pending_retry: HashSet::new(),
            receiver_pubkey: None,
            receiver_have: 0,
            last_peer_n: 0,
            last_peer_at: None,
            avail_dirty: false,
            finished: false,
        }
    }

    /// Ring positions to try for a chunk, starting `offset` past its home
    /// position: healthy relays first, demoted ones only as a last resort.
    fn candidates(&self, index: usize, offset: usize) -> Vec<usize> {
        let size = self.ring.len();
        let mut healthy = Vec::with_capacity(size);
        let mut fallback = Vec::new();
        for step in 0..size {
            let position = (index + (offset + step) % size) % size;
            if self.demoted.contains(&position) {
                fallback.push(position);
            } else {
                healthy.push(position);
            }
        }
        healthy.extend(fallback);
        healthy
    }

    /// Stop placing new chunks on a relay that does not serve what it stored —
    /// never all of them, because something has to remain.
    fn demote(&mut self, position: usize) {
        if self.demoted.len() + 1 >= self.ring.len() {
            return;
        }
        if self.demoted.insert(position) {
            log::info!("relay {} is not serving what it stored", self.ring[position]);
        }
    }

    /// The announcement as it stands: the whole ring and the whole placement,
    /// in every message, so a lost one costs nothing.
    fn announcement(&self) -> Result<SenderMessage> {
        let mut map = String::with_capacity(self.upto);
        let mut gens = Vec::new();
        for index in 0..self.upto {
            let position = self.placed[index].context("a placed chunk lost its placement")?;
            map.push(encode_position(position)?);
            if self.generation[index] != 0 {
                gens.push((index, self.generation[index]));
            }
        }
        Ok(SenderMessage::Avail {
            n: 0,
            upto: self.upto,
            relays: self.ring.clone(),
            map,
            gens,
        })
    }
}

/// Serve `source` to the receiver over the relays the offer named.
///
/// Returns when the receiver reports the verified file, and fails when the
/// transfer cannot complete — relays that will not take the pieces, the
/// session's expiry, or a peer that stopped answering.
pub async fn send_over_relays(context: SendContext<'_>, source: RelaySource) -> Result<()> {
    if source.data.is_empty() {
        bail!("There is nothing to send.");
    }
    if source.data.len() as u64 > RELAY_MAX_BYTES {
        bail!(
            "This selection is {}, over the {} the relay fallback allows.",
            crate::util::format_bytes(source.data.len() as u64),
            crate::util::format_bytes(RELAY_MAX_BYTES)
        );
    }

    let file_size = source.data.len() as u64;
    let file_hash = BASE64.encode(sha256(&source.data));
    let payload = compress_payload(source.data, source.compression)?;
    let chunks: Arc<Vec<Vec<u8>>> = Arc::new(
        payload
            .chunks(NOSTR_FILE_CHUNK_SIZE)
            .map(<[u8]>::to_vec)
            .collect(),
    );
    let total = chunks.len();
    let payload_size = payload.len() as u64;
    drop(payload);

    let keys = Keys::generate();
    let created_at = now_seconds();
    let expires_at = created_at + NOSTR_FILE_EXPIRATION_SEC;
    let manifest = NostrFileManifest {
        v: MANIFEST_VERSION,
        file_name: context.file_name.clone(),
        file_size,
        mime_type: context.mime_type.clone(),
        file_hash,
        pubkey: keys.public_key().to_hex(),
        compression: source.compression,
        payload_size,
        chunk_size: NOSTR_FILE_CHUNK_SIZE as u64,
        total_chunks: total as u64,
        enc: 2,
        created_at,
        expires_at,
    };

    let (channel, incoming) = ControlChannel::open(
        Arc::clone(&context.pool),
        ChannelConfig {
            relays: &context.control_relays,
            transfer_id: context.session.transfer_id.clone(),
            key: context.session.control_key()?,
            role: ControlRole::Sender,
            keys: keys.clone(),
            since: created_at.saturating_sub(CLOCK_SKEW_TOLERANCE_SEC),
            expires_at,
        },
    )
    .await?;
    let channel = Arc::new(channel);

    let state = Arc::new(Mutex::new(Upload::new(total)));
    let work = Arc::new(Notify::new());
    let announce = Arc::new(Notify::new());
    let (outcome_tx, mut outcome_rx) = mpsc::unbounded_channel::<Result<()>>();

    // The manifest goes first, before any availability, so a receiver reading
    // the backlog has what sizes its state before the placements arrive.
    channel
        .send_sender(SenderMessage::Manifest {
            n: 0,
            manifest: Box::new(manifest),
        })
        .await
        .context("The relays would not take this transfer's manifest")?;

    let mut tasks = Vec::new();
    tasks.push(tokio::spawn(read_receiver(
        incoming,
        Arc::clone(&state),
        Arc::clone(&work),
        Arc::clone(&announce),
        keys.public_key(),
        file_size,
        outcome_tx.clone(),
    )));
    tasks.push(tokio::spawn(announce_loop(
        Arc::clone(&channel),
        Arc::clone(&state),
        Arc::clone(&announce),
        outcome_tx.clone(),
    )));
    tasks.push(tokio::spawn(watchdog(
        Arc::clone(&state),
        expires_at,
        outcome_tx.clone(),
    )));
    // The first announcement goes out at once: an empty ring tells a receiver
    // the sender is here while storage relays are still being found.
    state.lock().expect("upload state").avail_dirty = true;
    announce.notify_one();

    tasks.push(tokio::spawn(start_workers(
        context.ring,
        Arc::clone(&context.pool),
        Arc::clone(&state),
        Arc::clone(&work),
        Arc::clone(&announce),
        Arc::clone(&chunks),
        UploadIdentity {
            transfer_id: context.session.transfer_id.clone(),
            key: context.session.key_bytes,
            keys: keys.clone(),
            created_at,
            file_size,
        },
        outcome_tx.clone(),
    )));
    drop(outcome_tx);

    let outcome = outcome_rx.recv().await.unwrap_or(Ok(()));
    {
        let mut state = state.lock().expect("upload state");
        state.finished = true;
    }
    work.notify_waiters();
    announce.notify_waiters();
    for task in &tasks {
        task.abort();
    }
    if outcome.is_err() {
        // Best effort: let the receiver stop waiting right away.
        let _ = tokio::time::timeout(
            Duration::from_secs(3),
            channel.send_sender(SenderMessage::Cancel { n: 0 }),
        )
        .await;
    }
    channel.close().await;
    ui::progress_end();
    outcome
}

/// The ephemeral identity and keys every chunk of this transfer is published
/// under.
#[derive(Clone)]
struct UploadIdentity {
    transfer_id: String,
    key: [u8; AES_KEY_LEN],
    keys: Keys,
    created_at: u64,
    file_size: u64,
}

/// Adopt the ring the moment it resolves, then run the upload workers on it.
#[allow(clippy::too_many_arguments)]
async fn start_workers(
    prepared: PreparedRing,
    pool: Arc<FilePool>,
    state: Arc<Mutex<Upload>>,
    work: Arc<Notify>,
    announce: Arc<Notify>,
    chunks: Arc<Vec<Vec<u8>>>,
    identity: UploadIdentity,
    outcome: mpsc::UnboundedSender<Result<()>>,
) {
    let ring = match prepared.ring().await {
        Ok(ring) => ring,
        Err(error) => {
            let _ = outcome.send(Err(error));
            return;
        }
    };
    ui::status(&format!(
        "Relaying the file through {} Nostr relays.",
        ring.len()
    ));
    let workers = {
        let mut state = state.lock().expect("upload state");
        if state.finished {
            return;
        }
        state.misses = vec![0; ring.len()];
        state.give_ups = vec![0; ring.len()];
        state.max_retransmits = (ring.len() as u64).max(LIVE_MIN_RETRANSMITS_PER_CHUNK);
        state.ring = ring;
        state.avail_dirty = true;
        UPLOAD_CHUNK_CONCURRENCY.min(state.total)
    };
    announce.notify_one();

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..workers {
        set.spawn(worker(
            Arc::clone(&pool),
            Arc::clone(&state),
            Arc::clone(&work),
            Arc::clone(&announce),
            Arc::clone(&chunks),
            identity.clone(),
            outcome.clone(),
        ));
    }
    while set.join_next().await.is_some() {}
}

/// One upload worker: take the next chunk (a re-send first), walk the ring
/// until a relay accepts it, and record where it landed.
async fn worker(
    pool: Arc<FilePool>,
    state: Arc<Mutex<Upload>>,
    work: Arc<Notify>,
    announce: Arc<Notify>,
    chunks: Arc<Vec<Vec<u8>>>,
    identity: UploadIdentity,
    outcome: mpsc::UnboundedSender<Result<()>>,
) {
    let total = chunks.len();
    loop {
        let next = {
            let mut state = state.lock().expect("upload state");
            if state.finished {
                return;
            }
            match state.retry_queue.pop_front() {
                Some(index) => Some((index, true)),
                None if state.next_chunk < total => {
                    let index = state.next_chunk;
                    state.next_chunk += 1;
                    Some((index, false))
                }
                None => None,
            }
        };
        let Some((index, is_retry)) = next else {
            // Nothing to do: wait for a re-send to be queued, or for the
            // transfer to end.
            let _ = tokio::time::timeout(Duration::from_secs(1), work.notified()).await;
            continue;
        };

        let aad = chunk_aad(&identity.transfer_id, index, total);
        let event = match encode_chunk_content(&identity.key, &chunks[index], &aad).and_then(
            |content| {
                build_chunk_event(
                    &identity.keys,
                    ChunkEvent {
                        transfer_id: &identity.transfer_id,
                        index,
                        total,
                        content,
                        created_at: identity.created_at,
                    },
                )
            },
        ) {
            Ok(event) => event,
            Err(error) => {
                let _ = outcome.send(Err(error));
                return;
            }
        };

        match place(&pool, &state, index, &event).await {
            Ok(position) => {
                let mut state = state.lock().expect("upload state");
                if state.finished {
                    return;
                }
                state.placed[index] = Some(position);
                if is_retry {
                    state.generation[index] += 1;
                    state.resent += 1;
                    state.pending_retry.remove(&index);
                } else {
                    state.chunks_done += 1;
                }
                let previous = state.upto;
                while state.upto < total && state.placed[state.upto].is_some() {
                    state.upto += 1;
                }
                if state.upto == total && previous != total {
                    // The bar follows the receiver, which has its own fetching
                    // to do, so this is the line that says the sending side is
                    // done and waiting rather than stalled.
                    ui::status("Every piece is on the relays. Waiting for the receiver...");
                }
                if is_retry
                    || state.upto == total
                    || previous / LIVE_BATCH_CHUNKS != state.upto / LIVE_BATCH_CHUNKS
                {
                    state.avail_dirty = true;
                    announce.notify_one();
                }
                report(&state, identity.file_size);
            }
            Err(error) => {
                let _ = outcome.send(Err(error));
                return;
            }
        }
    }
}

/// Walk the ring for one chunk until a relay takes it.
///
/// Candidates are re-ranked before every attempt, so a demotion that lands
/// mid-walk counts, and the walk starts where this chunk's last attempt left
/// off — which is what makes a re-send land somewhere else.
async fn place(
    pool: &FilePool,
    state: &Mutex<Upload>,
    index: usize,
    event: &Event,
) -> Result<usize> {
    let mut tried: HashSet<usize> = HashSet::new();
    loop {
        let (relay, position) = {
            let mut upload = state.lock().expect("upload state");
            if upload.finished {
                bail!("the transfer ended before this piece was placed");
            }
            let size = upload.ring.len();
            if tried.len() >= size {
                break;
            }
            let offset = upload.next_offset[index];
            let Some(position) = upload
                .candidates(index, offset)
                .into_iter()
                .find(|position| !tried.contains(position))
            else {
                break;
            };
            upload.next_offset[index] = ((position + size - index % size) % size + 1) % size;
            (upload.ring[position].clone(), position)
        };
        tried.insert(position);
        if publish_with_retry(pool, &relay, event).await {
            return Ok(position);
        }
        let mut upload = state.lock().expect("upload state");
        upload.give_ups[position] += 1;
        if upload.give_ups[position] >= LIVE_RELAY_DEMOTE_GIVEUPS {
            // Rejected through every retry: stop starting walks here.
            upload.demote(position);
        }
    }
    bail!("A piece of the file could not be saved to any relay — the transfer cannot continue.")
}

/// Publish one event to one relay, with the backoff a busy relay needs.
/// Up to [`PUBLISH_BACKOFF_JITTER`] of spread, off the same source everything
/// else here draws randomness from.
fn jitter() -> Duration {
    let mut byte = [0u8; 1];
    if crate::crypto::chunk::fill_random(&mut byte).is_err() {
        return Duration::ZERO;
    }
    PUBLISH_BACKOFF_JITTER.mul_f64(f64::from(byte[0]) / 255.0)
}

async fn publish_with_retry(pool: &FilePool, relay: &str, event: &Event) -> bool {
    for attempt in 0..=PUBLISH_MAX_RETRIES {
        match pool.publish(relay, event).await {
            Ok(()) => return true,
            Err(error) => {
                log::debug!("relay {relay} refused a piece: {error:#}");
                if attempt < PUBLISH_MAX_RETRIES {
                    let backoff = (PUBLISH_BACKOFF_BASE * (1 << attempt)).min(PUBLISH_BACKOFF_CAP);
                    tokio::time::sleep(backoff + jitter()).await;
                }
            }
        }
    }
    false
}

/// Announce new availability as soon as it exists, and repeat the latest
/// announcement on every heartbeat otherwise.
async fn announce_loop(
    channel: Arc<ControlChannel>,
    state: Arc<Mutex<Upload>>,
    announce: Arc<Notify>,
    outcome: mpsc::UnboundedSender<Result<()>>,
) {
    loop {
        let dirty = {
            let state = state.lock().expect("upload state");
            if state.finished {
                return;
            }
            state.avail_dirty
        };
        if !dirty {
            let _ = tokio::time::timeout(LIVE_HEARTBEAT, announce.notified()).await;
        }
        let message = {
            let mut state = state.lock().expect("upload state");
            if state.finished {
                return;
            }
            state.avail_dirty = false;
            state.announcement()
        };
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                let _ = outcome.send(Err(error));
                return;
            }
        };
        if let Err(error) = channel.send_sender(message).await {
            let _ = outcome.send(Err(error));
            return;
        }
    }
}

/// Read the receiver's half of the channel.
#[allow(clippy::too_many_arguments)]
async fn read_receiver(
    mut incoming: mpsc::UnboundedReceiver<(serde_json::Value, PublicKey)>,
    state: Arc<Mutex<Upload>>,
    work: Arc<Notify>,
    announce: Arc<Notify>,
    own_pubkey: PublicKey,
    file_size: u64,
    outcome: mpsc::UnboundedSender<Result<()>>,
) {
    while let Some((value, pubkey)) = incoming.recv().await {
        if pubkey == own_pubkey {
            continue;
        }
        let Ok(message) = serde_json::from_value::<ReceiverMessage>(value) else {
            continue;
        };
        let mut upload = state.lock().expect("upload state");
        if upload.finished {
            return;
        }
        // The first author whose message opens under this session's key is the
        // receiver, and every other author is ignored from then on: only the
        // holder of the code's secret could have sealed one at all.
        if upload
            .receiver_pubkey
            .is_some_and(|pinned| pinned != pubkey)
        {
            continue;
        }
        if message
            .validate(upload.total, upload.ring.len())
            .inspect_err(|error| log::debug!("the receiver sent something unusable: {error:#}"))
            .is_err()
            || message.counter() <= upload.last_peer_n
        {
            continue;
        }
        upload.last_peer_n = message.counter();
        upload.receiver_pubkey = Some(pubkey);
        upload.last_peer_at = Some(Instant::now());
        match message {
            ReceiverMessage::Hello { .. } => {
                // The receiver just joined: announce what is already placed
                // rather than leaving it until the next heartbeat.
                upload.avail_dirty = true;
                announce.notify_one();
            }
            ReceiverMessage::Ack {
                have, ref missing, ..
            } => {
                upload.receiver_have = upload.receiver_have.max(have);
                let mut queued = false;
                for (index, position, generation) in missing {
                    // A placement this side has already replaced: the receiver
                    // simply has not seen the newer announcement yet.
                    if upload.placed[*index] != Some(*position)
                        || upload.generation[*index] != *generation
                        || upload.pending_retry.contains(index)
                    {
                        continue;
                    }
                    upload.misses[*position] += 1;
                    if upload.misses[*position] >= LIVE_RELAY_DEMOTE_MISSES {
                        upload.demote(*position);
                    }
                    if upload.generation[*index] >= upload.max_retransmits {
                        let _ = outcome.send(Err(anyhow::anyhow!(
                            "Piece {} of {} could not be delivered after {} re-sends — \
                             the transfer cannot continue.",
                            index + 1,
                            upload.total,
                            upload.generation[*index]
                        )));
                        return;
                    }
                    upload.pending_retry.insert(*index);
                    upload.retry_queue.push_back(*index);
                    queued = true;
                }
                if queued {
                    work.notify_waiters();
                }
                report(&upload, file_size);
            }
            ReceiverMessage::Done { .. } => {
                let _ = outcome.send(Ok(()));
                return;
            }
            ReceiverMessage::Cancel { .. } => {
                let _ = outcome.send(Err(anyhow::anyhow!("The receiver cancelled the transfer.")));
                return;
            }
        }
    }
}

/// The clocks that end a transfer nobody is finishing.
async fn watchdog(
    state: Arc<Mutex<Upload>>,
    expires_at: u64,
    outcome: mpsc::UnboundedSender<Result<()>>,
) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let upload = state.lock().expect("upload state");
        if upload.finished {
            return;
        }
        if now_seconds() > expires_at {
            let _ = outcome.send(Err(anyhow::anyhow!(
                "The relay copies expired before the receiver finished. Start a new transfer."
            )));
            return;
        }
        if upload.upto == upload.total
            && let Some(last) = upload.last_peer_at
            && last.elapsed() > LIVE_IDLE_TIMEOUT
        {
            let _ = outcome.send(Err(anyhow::anyhow!(
                "The receiver stopped responding. Both sides have to stay open until the \
                 transfer completes."
            )));
            return;
        }
    }
}

/// What the screen says while the relays carry the file. The receiver's own
/// count is the honest one — a piece is not delivered because it was
/// published — so that is what the progress bar follows.
fn report(upload: &Upload, file_size: u64) {
    let per_chunk = file_size.div_ceil(upload.total.max(1) as u64);
    let received = (upload.receiver_have as u64 * per_chunk).min(file_size);
    ui::progress(ui::Direction::Send, received, file_size);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upload(ring: usize, total: usize) -> Upload {
        let mut upload = Upload::new(total);
        upload.ring = (0..ring).map(|index| format!("wss://r{index}.example")).collect();
        upload.misses = vec![0; ring];
        upload.give_ups = vec![0; ring];
        upload
    }

    /// Chunk `i` starts at `ring[i % N]`, which is what spreads a file evenly
    /// rather than filling one relay first.
    #[test]
    fn a_chunk_starts_at_its_own_ring_position() {
        let upload = upload(4, 16);
        assert_eq!(upload.candidates(0, 0)[0], 0);
        assert_eq!(upload.candidates(5, 0)[0], 1);
        assert_eq!(upload.candidates(5, 1)[0], 2);
    }

    /// A demoted relay is not dropped, it is moved to the back: it is still
    /// somewhere to put a chunk when nothing else will take it.
    #[test]
    fn a_demoted_relay_is_tried_last_rather_than_not_at_all() {
        let mut upload = upload(3, 9);
        upload.demote(0);
        let order = upload.candidates(0, 0);
        assert_eq!(order.len(), 3);
        assert_eq!(order[2], 0);
    }

    /// Something has to stay: demoting the last usable relay would leave a
    /// walk with nowhere to go.
    #[test]
    fn the_ring_is_never_demoted_away_entirely() {
        let mut upload = upload(2, 4);
        upload.demote(0);
        upload.demote(1);
        assert_eq!(upload.demoted.len(), 1);
    }

    /// The announcement is what the receiver fetches from, so it has to carry
    /// the ring, one map character per placed chunk, and the re-sends.
    #[test]
    fn an_announcement_describes_every_placed_chunk() {
        let mut upload = upload(2, 3);
        upload.placed[0] = Some(0);
        upload.placed[1] = Some(1);
        upload.generation[1] = 2;
        upload.upto = 2;
        match upload.announcement().unwrap() {
            SenderMessage::Avail {
                upto,
                relays,
                map,
                gens,
                ..
            } => {
                assert_eq!(upto, 2);
                assert_eq!(relays.len(), 2);
                assert_eq!(map, "AB");
                assert_eq!(gens, vec![(1, 2)]);
            }
            other => panic!("expected an announcement, got {other:?}"),
        }
    }
}
