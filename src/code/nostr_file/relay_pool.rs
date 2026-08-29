//! Finding relays that will actually carry this transfer, and proving they do.
//!
//! Two disjoint sets do two different jobs:
//!
//! - **Control relays**, named by the offer: they carry only the sealed
//!   control channel, so a relay that caps event size or rate-limits large
//!   writes — useless for 48 KiB chunks — still serves perfectly here. The
//!   signaling seeds are probed with a control-sized write/read round trip,
//!   and a defunct seed is replaced by a relay proven at full chunk size,
//!   never by a weaker control-sized discovery.
//! - **The storage ring**, discovered and health-checked: it holds the pieces.
//!   It is announced over the control channel rather than named in the offer,
//!   and the seed pool is barred from it, so chunk traffic never competes with
//!   the control channel on a shared relay.
//!
//! Proof is a real write/read round trip at the size the job needs, through
//! the production codec and event shape. A relay whose event-size cap sits
//! below a real chunk therefore fails here rather than by rejecting chunks
//! halfway through an upload.
//!
//! Every verdict goes into the [`RelayCache`], and the candidate list a
//! transfer probes leads with what the cache has already proved. Behind the
//! transfer a sweep enumerates the whole relay population and probes as far
//! as the transfer lasts, so the next one is not limited to what this one
//! happened to need.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use nostr_sdk::prelude::*;

use crate::crypto::aes::AES_KEY_LEN;
use crate::crypto::chunk::fill_random;

use super::codec::{chunk_aad, decode_chunk_content, encode_chunk_content};
use super::events::{build_probe_event, chunk_kind};
use super::pool::FilePool;
use super::relay_cache::{Capability, RelayCache, now_ms};
use super::relays::{SEED_RELAYS, canonical, normalize_relay_url};
use super::{
    BACKGROUND_PROBE_CONCURRENCY, BACKGROUND_PROBE_SAVE_BATCH, CONTROL_PROBE_BYTES,
    CONTROL_PROBE_TIMEOUT, CONTROL_RELAY_COUNT, DISCOVERY_CANDIDATE_CAP,
    DISCOVERY_CANDIDATE_LIMIT, DISCOVERY_MAX_PAGES, DISCOVERY_PAGE_LIMIT,
    DISCOVERY_PAGE_TIMEOUT, DISCOVERY_TIMEOUT, HEALTH_CHECK_CONCURRENCY, HEALTH_CHECK_TIMEOUT,
    MIN_CONTROL_RELAYS, MIN_UPLOAD_RELAYS, NOSTR_FILE_CHUNK_SIZE, UPLOAD_RELAY_COUNT,
    now_seconds,
};

/// NIP-66 relay discovery events.
const KIND_RELAY_DISCOVERY: u16 = 30166;
/// NIP-65 relay lists.
const KIND_RELAY_LIST: u16 = 10002;

pub const NOT_ENOUGH_RELAYS: &str =
    "Not enough working Nostr relays could be found to relay the file. Try again on a network \
     that allows a direct connection.";

#[derive(Debug, Clone)]
pub struct HealthyRelay {
    pub url: String,
    pub rtt: Duration,
}

/// The verdicts one health-check pass produced.
pub struct Probed {
    /// Relays that passed, fastest first, capped at the pass's target.
    pub healthy: Vec<HealthyRelay>,
    /// Every relay that passed, including the ones that came in after the
    /// target had filled — their sockets are closed, but their verdicts are
    /// as good as any other's, and a later pass can take them unprobed.
    pub passed: Vec<HealthyRelay>,
    /// Every relay that got a verdict, passed or failed. What is left of the
    /// candidate list after these is what a later pass has any reason to try.
    pub checked: HashSet<String>,
}

/// What a control backfill's discovery left over.
pub struct Discovered {
    /// Full-size-proven relays the backfill did not need, which the ring can
    /// take without probing them again.
    pub proven: Vec<HealthyRelay>,
    /// Candidates the early stop never reached.
    pub unprobed: Vec<String>,
}

/// What resolving the offer's control relays leaves behind for the ring.
pub struct ControlSelection {
    /// The relays the offer names.
    pub relays: Vec<String>,
    /// The backfill's leftovers — `None` when the seeds filled the control set
    /// on their own, and the ring discovers for itself instead.
    pub discovered: Option<Discovered>,
}

/// Relay candidates from NIP-66 (kind 30166, `d` tag) and NIP-65 (kind 10002,
/// `r` tags) events.
fn parse_candidates(events: &[Event]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for event in events {
        let raw: Vec<&str> = if event.kind == Kind::from_u16(KIND_RELAY_DISCOVERY) {
            event
                .tags
                .iter()
                .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("d"))
                .filter_map(|tag| tag.as_slice().get(1).map(String::as_str))
                .collect()
        } else if event.kind == Kind::from_u16(KIND_RELAY_LIST) {
            event
                .tags
                .iter()
                .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("r"))
                .filter_map(|tag| tag.as_slice().get(1).map(String::as_str))
                .collect()
        } else {
            Vec::new()
        };
        for entry in raw {
            if let Some(url) = normalize_relay_url(entry)
                && seen.insert(url.clone())
            {
                candidates.push(url);
            }
        }
    }
    candidates
}

/// One page of storage-candidate discovery from the seed relays.
///
/// The seeds are queried but never returned: they are the signaling pool and
/// must not carry chunks, so a failed discovery yields nothing — and the
/// fallback then refuses to start — rather than degrading onto them.
async fn discover_page(pool: &FilePool, seeds: &[String]) -> Vec<String> {
    let excluded: HashSet<&String> = seeds.iter().collect();
    // Opened once, before either query names them: two queries that each
    // opened the same seed would race, and the one whose connect lost would
    // drop a relay the other had already counted on.
    let reachable = pool.open_all(seeds).await;
    // The two listing kinds are asked for at once: they are independent
    // queries against the same relays, and one after the other would put a
    // whole second query timeout between a person and their code.
    let ask = |kind: u16| {
        let reachable = &reachable;
        let filter = Filter::new()
            .kind(Kind::from_u16(kind))
            .limit(DISCOVERY_CANDIDATE_LIMIT);
        async move { pool.query_open(reachable, filter, DISCOVERY_TIMEOUT).await }
    };
    let (discovery, lists) =
        tokio::join!(ask(KIND_RELAY_DISCOVERY), ask(KIND_RELAY_LIST));
    let mut events = Vec::new();
    for found in [discovery, lists] {
        match found {
            Ok(found) => events.extend(found),
            Err(error) => log::debug!("a relay discovery query found nothing: {error:#}"),
        }
    }
    parse_candidates(&events)
        .into_iter()
        .filter(|url| !excluded.contains(url))
        .take(DISCOVERY_CANDIDATE_CAP)
        .collect()
}

/// The storage candidates a transfer will probe: one page of fresh discovery
/// merged with what the cache still holds, proven relays first, minus
/// `exclude` (the control relays) and the seeds.
///
/// Discovery opens the seeds; the ones not carrying this transfer's control
/// channel have no further job, so their sockets are dropped here.
pub async fn discover_candidates(
    pool: &FilePool,
    cache: &RelayCache,
    exclude: &[String],
) -> Vec<String> {
    let seeds = canonical(SEED_RELAYS);
    let discovered = discover_page(pool, &seeds).await;
    let control: HashSet<String> = exclude.iter().cloned().collect();
    let done_seeds: Vec<String> = seeds
        .iter()
        .filter(|url| !control.contains(*url))
        .cloned()
        .collect();
    if !done_seeds.is_empty() {
        pool.close(&done_seeds).await;
    }
    let seed_set: HashSet<String> = seeds.into_iter().collect();
    cache
        .update(move |cache| {
            cache.merge_candidates(discovered, &seed_set, Capability::Storage, now_ms())
        })
        .await
        .into_iter()
        .filter(|url| !control.contains(url))
        .collect()
}

/// Enumerate the relay population rather than sampling it: page back through
/// NIP-66 and NIP-65 history by `created_at` until a page returns nothing,
/// stops moving, or the page bound is hit. Uncapped — this is the sweep, and
/// its whole job is to find every relay it can.
///
/// A query that fails ends that kind's paging with what it already collected
/// rather than failing the sweep, and `stopped` is read between pages.
async fn discover_all_candidates(
    pool: &FilePool,
    seeds: &[String],
    stopped: &(dyn Fn() -> bool + Sync),
) -> Vec<String> {
    let seed_set: HashSet<&String> = seeds.iter().collect();
    let reachable = pool.open_all(seeds).await;
    let mut found: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for kind in [KIND_RELAY_DISCOVERY, KIND_RELAY_LIST] {
        let mut until: Option<u64> = None;
        for _ in 0..DISCOVERY_MAX_PAGES {
            if stopped() {
                return found;
            }
            let mut filter = Filter::new()
                .kind(Kind::from_u16(kind))
                .limit(DISCOVERY_PAGE_LIMIT);
            if let Some(until) = until {
                filter = filter.until(Timestamp::from_secs(until));
            }
            let events = match pool
                .query_open(&reachable, filter, DISCOVERY_PAGE_TIMEOUT)
                .await
            {
                Ok(events) => events,
                Err(error) => {
                    log::debug!("the relay sweep's discovery page found nothing: {error:#}");
                    break;
                }
            };
            if events.is_empty() {
                break;
            }
            for url in parse_candidates(&events) {
                if !seed_set.contains(&url) && seen.insert(url.clone()) {
                    found.push(url);
                }
            }
            // Step the cursor past the oldest event this page returned. A
            // cursor that fails to move means the relays are serving the same
            // page again.
            let Some(oldest) = events.iter().map(|event| event.created_at.as_secs()).min()
            else {
                break;
            };
            let next = oldest.saturating_sub(1);
            if until.is_some_and(|until| next >= until) {
                break;
            }
            until = Some(next);
        }
    }
    found
}

/// A real write/read round trip against one relay, in the production event
/// shape and at the size the job needs. `None` when the relay fails any step.
///
/// The write and the read get `timeout` each, the way the web app races them:
/// one budget spanning both would fail a relay that spent most of it accepting
/// a 60 KiB event and would have served it straight back.
async fn probe_relay(
    pool: &FilePool,
    url: &str,
    timeout: Duration,
    probe_bytes: usize,
) -> Option<Duration> {
    let started = Instant::now();
    let mut key = [0u8; AES_KEY_LEN];
    fill_random(&mut key).ok()?;
    let mut payload = vec![0u8; probe_bytes];
    fill_random(&mut payload).ok()?;
    let aad = chunk_aad("probe", 0, 1);
    let content = encode_chunk_content(&key, &payload, &aad).ok()?;
    let keys = Keys::generate();
    let (event, d_tag) = build_probe_event(&keys, content.clone(), now_seconds()).ok()?;

    tokio::time::timeout(timeout, pool.publish(url, &event))
        .await
        .ok()?
        .ok()?;
    let filter = Filter::new()
        .kind(chunk_kind())
        .author(keys.public_key())
        .identifier(d_tag)
        .limit(1);
    let events = pool.query(url, filter, timeout).await.ok()?;
    let fetched = events.first()?;
    // Byte-compared rather than merely present: a relay that truncates or
    // rewrites content passes a "did you store it" check and then serves
    // pieces that will not decrypt.
    if fetched.content != content {
        return None;
    }
    let roundtripped =
        decode_chunk_content(&key, &fetched.content, &aad, NOSTR_FILE_CHUNK_SIZE).ok()?;
    (roundtripped == payload).then(|| started.elapsed())
}

pub struct HealthCheck<'a> {
    pub target: usize,
    pub probe_bytes: usize,
    pub timeout: Duration,
    /// Called with (checked, healthy) after every verdict, so a slow probe run
    /// says what it is doing.
    pub on_progress: &'a (dyn Fn(usize, usize) + Sync),
}

/// Probe candidates with bounded concurrency, stopping once `target` have
/// passed. Fastest first.
///
/// The early stop is the point: only about one public candidate in six passes
/// a full-size probe, and probing the whole list to find that out would cost
/// more than the transfer.
pub async fn health_check(
    pool: &FilePool,
    candidates: &[String],
    opts: HealthCheck<'_>,
) -> Probed {
    struct Progress {
        next: usize,
        checked: HashSet<String>,
        healthy: Vec<HealthyRelay>,
        passed: Vec<HealthyRelay>,
    }
    let state = Mutex::new(Progress {
        next: 0,
        checked: HashSet::new(),
        healthy: Vec::new(),
        passed: Vec::new(),
    });
    let workers = HEALTH_CHECK_CONCURRENCY.min(candidates.len().max(1));
    let run = |_worker: usize| async {
        loop {
            let index = {
                let mut state = state.lock().expect("health check state");
                if state.healthy.len() >= opts.target || state.next >= candidates.len() {
                    return;
                }
                let index = state.next;
                state.next += 1;
                index
            };
            let url = &candidates[index];
            let rtt = probe_relay(pool, url, opts.timeout, opts.probe_bytes).await;
            let (checked, healthy, kept) = {
                let mut state = state.lock().expect("health check state");
                // Every verdict is kept, whether or not the target had room
                // left for it: what this pass cannot use, the next one takes
                // without paying for the probe again.
                if let Some(rtt) = rtt {
                    state.passed.push(HealthyRelay {
                        url: url.clone(),
                        rtt,
                    });
                }
                // Re-checked here: sibling probes may have filled the target
                // while this one was in flight.
                let keep = rtt.is_some() && state.healthy.len() < opts.target;
                if let Some(rtt) = rtt.filter(|_| keep) {
                    state.healthy.push(HealthyRelay {
                        url: url.clone(),
                        rtt,
                    });
                }
                state.checked.insert(url.clone());
                (state.checked.len(), state.healthy.len(), keep)
            };
            // A relay with no further job — it failed, or it passed after the
            // target had filled — keeps no socket: with reconnection on, one
            // left open would retry for the rest of the transfer.
            if !kept {
                pool.close(std::slice::from_ref(url)).await;
            }
            (opts.on_progress)(checked, healthy);
        }
    };
    futures_util::future::join_all((0..workers).map(run)).await;

    let mut state = state.lock().expect("health check state");
    let mut healthy = std::mem::take(&mut state.healthy);
    healthy.sort_by_key(|relay| relay.rtt);
    Probed {
        healthy,
        passed: std::mem::take(&mut state.passed),
        checked: std::mem::take(&mut state.checked),
    }
}

/// Full-size-probe candidates until `target` pass, and record every verdict
/// in the cache: what this pass cannot use, the next run takes without paying
/// for the probe again.
async fn probe_storage_candidates(
    pool: &FilePool,
    cache: &RelayCache,
    candidates: &[String],
    target: usize,
    on_progress: &(dyn Fn(usize, usize) + Sync),
) -> Probed {
    let probed = health_check(
        pool,
        candidates,
        HealthCheck {
            target,
            probe_bytes: NOSTR_FILE_CHUNK_SIZE,
            timeout: HEALTH_CHECK_TIMEOUT,
            on_progress,
        },
    )
    .await;
    record_verdicts(cache, &probed.passed, &probed.checked, Capability::Storage).await;
    probed
}

/// Write one probe pass's verdicts down: `checked` minus `passed` failed.
async fn record_verdicts(
    cache: &RelayCache,
    passed: &[HealthyRelay],
    checked: &HashSet<String>,
    capability: Capability,
) {
    let passed_urls: HashSet<&String> = passed.iter().map(|relay| &relay.url).collect();
    let failed: Vec<String> = checked
        .iter()
        .filter(|url| !passed_urls.contains(url))
        .cloned()
        .collect();
    let healthy = passed.to_vec();
    cache
        .update(move |cache| cache.record_probes(&healthy, &failed, capability, now_ms()))
        .await;
}

/// Resolve the control relays the offer will name, before the code is shown.
///
/// Only what the code needs is done here: the seeds are probed at control
/// size, and if fewer than [`CONTROL_RELAY_COUNT`] pass, discovery fills the
/// gap with relays proven at full chunk size — stopping the moment enough have
/// passed. The storage ring is never built here; the code does not depend on
/// it.
pub async fn resolve_control_relays(
    pool: &FilePool,
    cache: &RelayCache,
    on_progress: &(dyn Fn(usize, usize) + Sync),
) -> Result<ControlSelection> {
    let seeds = canonical(SEED_RELAYS);
    let defaults = health_check(
        pool,
        &seeds,
        HealthCheck {
            target: CONTROL_RELAY_COUNT,
            probe_bytes: CONTROL_PROBE_BYTES,
            timeout: CONTROL_PROBE_TIMEOUT,
            on_progress,
        },
    )
    .await
    .healthy;

    let mut discovered = None;
    let mut backfill = Vec::new();
    let missing = CONTROL_RELAY_COUNT.saturating_sub(defaults.len());
    if missing > 0 {
        let taken: Vec<String> = defaults.iter().map(|relay| relay.url.clone()).collect();
        let candidates = discover_candidates(pool, cache, &taken).await;
        let probed = probe_storage_candidates(pool, cache, &candidates, missing, on_progress).await;
        let chosen: Vec<HealthyRelay> = probed.healthy.into_iter().take(missing).collect();
        let backfilled: HashSet<String> = chosen.iter().map(|relay| relay.url.clone()).collect();
        discovered = Some(Discovered {
            // Everything the probe proved that the control set did not take.
            // The early stop caps what this pass *uses*, not what it learns:
            // a relay that passed once the target was full is a relay the ring
            // can have for nothing.
            proven: probed
                .passed
                .into_iter()
                .filter(|relay| !backfilled.contains(&relay.url))
                .collect(),
            // Only what nobody has tried: a relay that already failed a
            // full-size probe is not a candidate the ring should spend its own
            // budget on again.
            unprobed: candidates
                .iter()
                .filter(|url| !probed.checked.contains(*url))
                .cloned()
                .collect(),
        });
        backfill = chosen;
    }

    let relays: Vec<String> = defaults
        .into_iter()
        .chain(backfill)
        .map(|relay| relay.url)
        .collect();
    if relays.len() < MIN_CONTROL_RELAYS {
        bail!(NOT_ENOUGH_RELAYS);
    }
    Ok(ControlSelection {
        relays,
        discovered,
    })
}

/// A storage ring, and what selecting it left untried.
pub struct Ring {
    /// The relays, in placement order.
    pub relays: Vec<String>,
    /// Candidates the early stop never reached, for the sweep to start from.
    pub unprobed: Vec<String>,
}

/// The storage ring: discovery, full-size probes, and the batch that carries
/// the chunks.
///
/// `discovered` is what control resolution left over when it had to discover —
/// proven relays join the ring without another probe, and only its untried
/// leftovers are probed. Without it the ring discovers here. The control
/// relays and the seed pool never join it either way, so chunk traffic and the
/// control channel never share a relay. The ring is cut from the healthy list
/// at a cursor the cache carries between uploads, so successive transfers
/// rotate through the population instead of all landing on the same few.
pub async fn resolve_storage_ring(
    pool: &FilePool,
    cache: &RelayCache,
    control_relays: &[String],
    discovered: Option<Discovered>,
    on_progress: &(dyn Fn(usize, usize) + Sync),
) -> Result<Ring> {
    let seeds = canonical(SEED_RELAYS);
    let excluded: HashSet<String> = seeds
        .iter()
        .chain(control_relays.iter())
        .cloned()
        .collect();
    let (mut healthy, candidates) = match discovered {
        Some(discovered) => (
            discovered
                .proven
                .into_iter()
                .filter(|relay| !excluded.contains(&relay.url))
                .collect::<Vec<_>>(),
            discovered
                .unprobed
                .into_iter()
                .filter(|url| !excluded.contains(url))
                .collect::<Vec<_>>(),
        ),
        None => (
            Vec::new(),
            discover_candidates(pool, cache, control_relays).await,
        ),
    };
    let probed = probe_storage_candidates(
        pool,
        cache,
        &candidates,
        UPLOAD_RELAY_COUNT.saturating_sub(healthy.len()),
        on_progress,
    )
    .await;
    let unprobed: Vec<String> = candidates
        .iter()
        .filter(|url| !probed.checked.contains(*url))
        .cloned()
        .collect();
    healthy.extend(probed.healthy);
    healthy.sort_by_key(|relay| relay.rtt);
    if healthy.len() < MIN_UPLOAD_RELAYS {
        bail!(NOT_ENOUGH_RELAYS);
    }

    let selection = healthy.clone();
    let relays = cache
        .update(move |cache| cache.take_ring(&selection, UPLOAD_RELAY_COUNT))
        .await;
    let ring_set: HashSet<&String> = relays.iter().collect();
    let unselected: Vec<String> = healthy
        .iter()
        .filter(|relay| !ring_set.contains(&relay.url))
        .map(|relay| relay.url.clone())
        .collect();
    if !unselected.is_empty() {
        pool.close(&unselected).await;
    }
    Ok(Ring { relays, unprobed })
}

/// The background relay pass, run behind a transfer.
///
/// The foreground path samples: one page of discovery, capped, probed only
/// until the ring is full. This does the opposite — it enumerates the whole
/// population, writes the enumeration to the cache at once, and then probes
/// it, longest-unchecked first, so successive runs extend coverage instead of
/// re-probing the same prefix. Sockets are closed as each probe finishes,
/// verdicts are written in batches, and nothing here fails.
///
/// It runs until the pool is shut down, which is how the transfer ends it: a
/// probe still in flight then is abandoned and its verdict discarded, so the
/// teardown is never recorded as relay failures. `exclude` is the relays
/// carrying this transfer, never probed and never closed; the seeds stay out
/// of it exactly as they stay out of a ring.
pub async fn sweep_relay_health(
    pool: &FilePool,
    cache: &RelayCache,
    unprobed: Vec<String>,
    exclude: &[String],
) {
    let stopped = || pool.is_shut_down();
    let seeds = canonical(SEED_RELAYS);
    let transfer_relays: HashSet<String> = canonical(exclude).into_iter().collect();
    let excluded: HashSet<String> = transfer_relays
        .iter()
        .chain(seeds.iter())
        .cloned()
        .collect();

    let discovered = discover_all_candidates(pool, &seeds, &stopped).await;
    if stopped() {
        return;
    }
    // Discovery reopened the seeds; the ones not carrying this transfer are
    // done again.
    let done_seeds: Vec<String> = seeds
        .iter()
        .filter(|url| !transfer_relays.contains(*url))
        .cloned()
        .collect();
    if !done_seeds.is_empty() {
        pool.close(&done_seeds).await;
    }

    let urls: Vec<String> = canonical(unprobed.iter().chain(discovered.iter()))
        .into_iter()
        .filter(|url| !excluded.contains(url))
        .collect();
    if urls.is_empty() {
        return;
    }
    log::debug!("relay sweep: {} relays to probe", urls.len());
    // Written down before a single probe runs: the enumeration is the part
    // the next transfer needs most, and it must survive a teardown that lands
    // long before the probing is done.
    let listed = urls.clone();
    cache
        .update(move |cache| cache.record_discovered(&listed, now_ms()))
        .await;
    if stopped() {
        return;
    }

    let last_checked: HashMap<String, u64> = cache.read().await.last_checked();
    let mut queue = urls;
    queue.sort_by(|a, b| {
        last_checked
            .get(a)
            .cmp(&last_checked.get(b))
            .then_with(|| a.cmp(b))
    });

    struct Progress {
        next: usize,
        healthy: Vec<HealthyRelay>,
        failed: Vec<String>,
        checked: usize,
        passed: usize,
    }
    let state = Mutex::new(Progress {
        next: 0,
        healthy: Vec::new(),
        failed: Vec::new(),
        checked: 0,
        passed: 0,
    });
    let flush = |healthy: Vec<HealthyRelay>, failed: Vec<String>| async move {
        if healthy.is_empty() && failed.is_empty() {
            return;
        }
        cache
            .update(move |cache| {
                cache.record_probes(&healthy, &failed, Capability::Storage, now_ms())
            })
            .await;
    };
    let run = |_worker: usize| async {
        loop {
            if stopped() {
                return;
            }
            let index = {
                let mut state = state.lock().expect("relay sweep state");
                if state.next >= queue.len() {
                    return;
                }
                let index = state.next;
                state.next += 1;
                index
            };
            let url = &queue[index];
            let rtt = probe_relay(pool, url, HEALTH_CHECK_TIMEOUT, NOSTR_FILE_CHUNK_SIZE).await;
            // A probe that outlived the stop raced the transfer tearing the
            // pool down; its verdict says nothing about the relay.
            if stopped() {
                return;
            }
            let batch = {
                let mut state = state.lock().expect("relay sweep state");
                state.checked += 1;
                match rtt {
                    Some(rtt) => {
                        state.passed += 1;
                        state.healthy.push(HealthyRelay {
                            url: url.clone(),
                            rtt,
                        });
                    }
                    None => state.failed.push(url.clone()),
                }
                (state.healthy.len() + state.failed.len() >= BACKGROUND_PROBE_SAVE_BATCH).then(
                    || {
                        (
                            std::mem::take(&mut state.healthy),
                            std::mem::take(&mut state.failed),
                        )
                    },
                )
            };
            pool.close(std::slice::from_ref(url)).await;
            if let Some((healthy, failed)) = batch {
                flush(healthy, failed).await;
            }
        }
    };
    let workers = BACKGROUND_PROBE_CONCURRENCY.min(queue.len());
    futures_util::future::join_all((0..workers).map(run)).await;

    let (healthy, failed, checked, passed) = {
        let mut state = state.lock().expect("relay sweep state");
        (
            std::mem::take(&mut state.healthy),
            std::mem::take(&mut state.failed),
            state.checked,
            state.passed,
        )
    };
    flush(healthy, failed).await;
    log::debug!("relay sweep: {checked} of {} probed, {passed} passed", queue.len());
}

/// The ring being prepared behind the exchange: started as soon as the offer's
/// relays are known, awaited only if the direct route dies.
///
/// Once the ring has resolved, the sweep of the rest of the population runs
/// on from it, on the same pool, for as long as the pool lives — a direct
/// connection leaves the ring unused and the cache warmer for the next
/// transfer; a relayed one keeps the sweep going behind the upload. Shutting
/// the pool down is what ends it.
pub struct PreparedRing {
    task: tokio::task::JoinHandle<Result<Vec<String>>>,
}

impl PreparedRing {
    /// Takes the control relays and the leftovers as the two separate things
    /// they are, rather than a whole [`ControlSelection`] alongside a relay
    /// list a caller could get out of step with it.
    pub fn spawn(
        pool: Arc<FilePool>,
        cache: Arc<RelayCache>,
        control_relays: Vec<String>,
        discovered: Option<Discovered>,
    ) -> Self {
        let task = tokio::spawn(async move {
            let ring =
                resolve_storage_ring(&pool, &cache, &control_relays, discovered, &|_, _| {})
                    .await?;
            let exclude: Vec<String> = control_relays
                .iter()
                .chain(ring.relays.iter())
                .cloned()
                .collect();
            tokio::spawn(async move {
                sweep_relay_health(&pool, &cache, ring.unprobed, &exclude).await;
            });
            Ok(ring.relays)
        });
        Self { task }
    }

    pub async fn ring(self) -> Result<Vec<String>> {
        self.task.await.map_err(|error| anyhow::anyhow!("the relay preparation failed: {error}"))?
    }

    pub fn abort(&self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u16, tags: Vec<Vec<&str>>) -> Event {
        let keys = Keys::generate();
        EventBuilder::new(Kind::from_u16(kind), "")
            .tags(
                tags.into_iter()
                    .map(|tag| Tag::parse(tag.into_iter().map(String::from)).unwrap()),
            )
            .sign_with_keys(&keys)
            .unwrap()
    }

    /// Both listing shapes, and nothing that is not a relay: a discovery event
    /// is written by strangers, so what it names is put through the same URL
    /// rule as everything else.
    #[test]
    fn candidates_come_out_of_both_listing_kinds_and_nothing_else() {
        let events = vec![
            event(KIND_RELAY_DISCOVERY, vec![vec!["d", "wss://one.example/"]]),
            event(
                KIND_RELAY_LIST,
                vec![
                    vec!["r", "wss://two.example"],
                    vec!["r", "ws://plain.example"],
                    vec!["r", "wss://one.example"],
                ],
            ),
            event(1, vec![vec!["r", "wss://note.example"]]),
        ];
        assert_eq!(
            parse_candidates(&events),
            vec!["wss://one.example", "wss://two.example"]
        );
    }
}
