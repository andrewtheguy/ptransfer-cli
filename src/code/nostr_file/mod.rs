//! The clearnet relay fallback: Code Exchange's data path when the two devices
//! turn out to have no direct route between them.
//!
//! It is the ordinary stand-in for TURN, and the alternative to the anonymous
//! fallback in [`super::relay`]. The sender proves a handful of relays before
//! the code is shown and names them in the offer; if — and only if — the
//! direct WebRTC connection then fails, the file is chunked, encrypted, and
//! published to a ring of storage relays discovered behind the exchange, while
//! the receiver fetches those pieces and acknowledges what it could not.
//! Nothing is uploaded ahead of time: a transfer that connects directly never
//! puts a byte on a relay.
//!
//! The session is **derived, not carried**. The offer/answer exchange already
//! produced an ECDH secret; both sides run the same HKDF over it and arrive at
//! the same transfer id (the public tag namespace) and the same file key. No
//! key or id appears in a code, and no relay ever holds anything but
//! ciphertext.
//!
//! - [`relays`]: what counts as a relay URL, and the seed pool.
//! - [`relay_pool`]: discovery, health probes, the two relay sets, and the
//!   background sweep of the relay population.
//! - [`relay_cache`]: what earlier runs learned, kept between transfers.
//! - [`control`]: the sealed control channel and its message vocabulary.
//! - [`codec`], [`z85`], [`events`], [`manifest`]: what a chunk is on the wire.
//! - [`upload`] / [`download`]: the two halves of the transfer.
//!
//! The wire contract is the web app's `src/lib/nostr-file/`, specified in its
//! `docs/NOSTR_FILE_RELAY.md`.

use std::time::Duration;

pub mod codec;
pub mod control;
pub mod download;
pub mod events;
pub mod manifest;
pub mod pool;
pub mod relay_cache;
pub mod relay_pool;
pub mod relays;
pub mod upload;
pub mod z85;

/// Payload chunk size. Encoded content per event is
/// `z85(chunk + 12 B nonce + 16 B tag)` = 61,475 bytes, just under the ~63 KiB
/// content size the public relay population actually accepts — relays that cap
/// lower fail the full-size health probe instead of rejecting real chunks.
pub const NOSTR_FILE_CHUNK_SIZE: usize = 49_152;

/// NIP-78 addressable kind every event of this mode uses: chunks, probes, and
/// control messages alike.
pub const EVENT_KIND_FILE_CHUNK: u16 = 30078;

/// NIP-40 lifetime stamped on every published event, probes included. The
/// whole point of the mode is that relays never hold the data longer than one
/// transfer window. It is a client-enforced deadline plus a deletion
/// *request*: a compliant relay stops serving and prunes, but nothing
/// guarantees erasure — which costs nothing, because what is left behind is
/// ciphertext under a key that was never published.
pub const NOSTR_FILE_EXPIRATION_SEC: u64 = 3600;

pub const MANIFEST_VERSION: u8 = 7;
pub const NOSTR_FILE_ENCRYPTION_LABEL: &str = "aes-256-gcm";
pub const NOSTR_FILE_AAD_PREFIX: &str = "ptransfer-nostr-file:v1";

/// The cap on a relayed payload: [`crate::crypto::SLOW_TRANSPORT_MAX_BYTES`],
/// the ceiling every transport that carries bytes through third parties
/// shares. Nothing about this path comes from the anonymous one — the two are
/// alternatives, and an offer names one or neither.
pub use crate::crypto::SLOW_TRANSPORT_MAX_BYTES as RELAY_MAX_BYTES;

/// Storage relays a chunk ring is spread across. Chunk `i` starts at
/// `ring[i % N]`, so each relay holds about a sixteenth of the file.
pub const UPLOAD_RELAY_COUNT: usize = 16;
/// Fewer usable storage relays than this and an upload refuses to start.
pub const MIN_UPLOAD_RELAYS: usize = 2;
/// Chunks in flight.
pub const UPLOAD_CHUNK_CONCURRENCY: usize = 16;

pub const PUBLISH_MAX_RETRIES: u32 = 3;
pub const PUBLISH_BACKOFF_BASE: Duration = Duration::from_millis(500);
pub const PUBLISH_BACKOFF_CAP: Duration = Duration::from_secs(5);
/// Spread added to each backoff, so sixteen workers that all bounced off the
/// same relay do not come back at it in step.
pub const PUBLISH_BACKOFF_JITTER: Duration = Duration::from_millis(250);

pub const HEALTH_CHECK_CONCURRENCY: usize = 16;
pub const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(8);

/// Once the ring is full the foreground health check stops, and the rest of
/// the relay population would never be looked at. A background sweep runs
/// behind the transfer instead: it enumerates every relay it can find and
/// probes as far as the transfer lasts, so the next transfer starts from a
/// cache of the whole population. It shares the upload's bandwidth, so it
/// stays well below [`HEALTH_CHECK_CONCURRENCY`].
pub const BACKGROUND_PROBE_CONCURRENCY: usize = 4;
/// Sweep verdicts are written to the cache in batches of this size, plus a
/// final flush, so a transfer that ends mid-sweep still keeps most of the work.
pub const BACKGROUND_PROBE_SAVE_BATCH: usize = 8;

/// Control relays the offer aims to name, and the fewest it may name at all:
/// below this the offer names none and the transfer has no fallback.
pub const CONTROL_RELAY_COUNT: usize = 6;
pub const MIN_CONTROL_RELAYS: usize = 2;
/// A sealed control message is a few hundred bytes, so a size-capped relay
/// that would reject chunks may still carry the channel perfectly.
pub const CONTROL_PROBE_BYTES: usize = 256;
/// Control probes race every seed and the check waits out each one in flight,
/// so a dead seed delays showing the code by this much. Kept short for exactly
/// that reason.
pub const CONTROL_PROBE_TIMEOUT: Duration = Duration::from_secs(4);
/// Relays an offer may name, and the fewest it names when it names any. The
/// control set is what it carries, so these are that set's own bounds.
pub const OFFER_RELAY_COUNT: usize = CONTROL_RELAY_COUNT;
pub const MIN_OFFER_RELAYS: usize = MIN_CONTROL_RELAYS;

/// One page of discovery per listing kind: the foreground pass only has to
/// fill one ring.
pub const DISCOVERY_CANDIDATE_LIMIT: usize = 100;
/// Candidates a single transfer will rank and probe. A bound on the working
/// set, not on what is known: the cache holds far more (see
/// [`RELAY_CACHE_MAX_ENTRIES`]) and the best of it leads this list.
pub const DISCOVERY_CANDIDATE_CAP: usize = 150;
pub const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(8);

/// The sweep enumerates instead of sampling: it pages back through NIP-66 and
/// NIP-65 history by `created_at` until a page turns up nothing new. These
/// bound the paging, not the result.
pub const DISCOVERY_PAGE_LIMIT: usize = 500;
pub const DISCOVERY_MAX_PAGES: usize = 20;
pub const DISCOVERY_PAGE_TIMEOUT: Duration = Duration::from_secs(8);

/// How long a discovery or a failed verdict counts for. A healthy relay is
/// exempt and stays cached until it fails: it is what a start with dead seeds
/// runs on, and it is probed again before it carries anything, so an old
/// verdict costs one probe, never a transfer.
pub const RELAY_CANDIDATE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Relays kept in the cache — everything the sweep has found, proved, or
/// buried. Far above [`DISCOVERY_CANDIDATE_CAP`] on purpose: each transfer
/// draws its working set from here, and capping this at the working-set size
/// would throw the enumeration away.
pub const RELAY_CACHE_MAX_ENTRIES: usize = 2000;

/// Chunk identifiers per fetch filter (~3 MiB of content per query).
pub const D_TAG_FILTER_BATCH: usize = 50;
pub const RELAY_QUERY_TIMEOUT: Duration = Duration::from_secs(15);

/// Chunks per availability announcement (64 x 48 KiB = 3 MiB).
pub const LIVE_BATCH_CHUNKS: usize = 64;
/// How often the sender repeats its latest announcement when nothing changed,
/// so a lost announcement or acknowledgement is recovered on the next beat.
pub const LIVE_HEARTBEAT: Duration = Duration::from_secs(15);
/// How long either side waits on a peer that has gone quiet, once it has been
/// seen at least once.
pub const LIVE_IDLE_TIMEOUT: Duration = Duration::from_secs(3 * 60);
/// Floor on how many times one chunk may be re-sent before the transfer fails.
pub const LIVE_MIN_RETRANSMITS_PER_CHUNK: u64 = 4;
/// A piece still missing this long after its last attempt is fetched again
/// from the same placement — a slow relay or a propagation delay heals without
/// costing a re-send — and the receiver runs a cycle on this clock even when
/// no announcement arrives.
pub const LIVE_FETCH_RETRY: Duration = Duration::from_secs(10);
/// Misses reported against a relay before new chunks stop being placed there:
/// it acknowledged the writes but does not serve them.
pub const LIVE_RELAY_DEMOTE_MISSES: u32 = 2;
/// Publishes a relay may give up on — every retry rejected — before ring walks
/// stop starting there.
pub const LIVE_RELAY_DEMOTE_GIVEUPS: u32 = 3;

/// Decompression bound for one control body. A full map of every chunk in a
/// 100 MiB transfer is well under it.
pub const CONTROL_MESSAGE_MAX_BYTES: u64 = 256 * 1024;

/// Tolerated wall-clock disagreement between the two sides.
pub const CLOCK_SKEW_TOLERANCE_SEC: u64 = 600;

pub fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
