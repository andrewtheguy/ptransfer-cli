//! What earlier runs learned about the relay population, kept between
//! transfers.
//!
//! The web app keeps the same records in IndexedDB (`relay-pool.ts`,
//! `RelayPoolStorage`): one candidate list with a rotating ring cursor, and one
//! health record per relay — when it was last listed, last probed, last
//! passed, its latency, how many probes in a row it has failed, and which of
//! the two probe sizes it has passed. A transfer leads its candidate list with
//! what is proven here, so a warm run reaches its probe target in the first
//! batch instead of sampling the population again.
//!
//! Here the store is one JSON file under the user's cache directory. Several
//! transfers may run on one machine at once — two terminals, or the wizard
//! beside a one-shot command — so every change is a locked read-modify-write:
//! an exclusive advisory lock on a sibling lock file, the file read again under
//! it, the change applied to *that*, and the result renamed into place. A
//! second process therefore adds its verdicts to the first's rather than
//! overwriting them, and a reader never sees a torn file. The lock is on a
//! separate file because the rename replaces the cache file's inode, and a lock
//! on the old one would mean nothing to the next writer.
//!
//! Nothing here can fail a transfer: an unreadable, unwritable, or unparseable
//! cache is an empty one. The cache holds relay URLs and verdicts and nothing
//! about any transfer.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::relay_pool::HealthyRelay;
use super::relays::normalize_relay_url;
use super::{DISCOVERY_CANDIDATE_CAP, RELAY_CACHE_MAX_ENTRIES, RELAY_CANDIDATE_TTL};

/// Bumped when the file's shape changes. An older file is discarded whole,
/// never migrated: the cache is disposable.
pub const CACHE_FILE_VERSION: u32 = 1;
const CACHE_FILE_NAME: &str = "relay-cache.json";
const LOCK_FILE_NAME: &str = "relay-cache.lock";
const CACHE_SUBDIR: &str = "ptransfer";

/// Where the cache lives, or whether it does: a directory path moves it,
/// `off` keeps it in memory for the life of the process.
pub const RELAY_CACHE_ENV: &str = "PTRANSFER_RELAY_CACHE";

/// What a probe proved about a relay. A full-size write proves both — a relay
/// that takes a chunk takes a control message — while a control-sized write
/// says nothing either way about a chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Control,
    Storage,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CachedRelay {
    pub url: String,
    pub last_discovered_at: u64,
    pub last_checked_at: Option<u64>,
    pub last_succeeded_at: Option<u64>,
    pub rtt_ms: Option<u64>,
    pub consecutive_failures: u32,
    pub supports_control: bool,
    pub supports_storage: bool,
}

impl CachedRelay {
    /// A relay discovery has named but no probe has judged yet.
    fn discovered(url: String, now: u64) -> Self {
        Self {
            url,
            last_discovered_at: now,
            last_checked_at: None,
            last_succeeded_at: None,
            rtt_ms: None,
            consecutive_failures: 0,
            supports_control: false,
            supports_storage: false,
        }
    }

    /// When the relay was last known to exist: listed, or proven.
    fn freshness(&self) -> u64 {
        self.last_discovered_at
            .max(self.last_succeeded_at.unwrap_or(0))
    }

    fn is_fresh(&self, now: u64) -> bool {
        is_fresh(self.freshness(), now)
    }
}

/// The candidate list one transfer ranked, and the ring cursor that rotates
/// over the healthy list so successive uploads spread across it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct PoolState {
    pub candidates: Vec<String>,
    pub discovered_at: u64,
    pub cursor: usize,
}

/// Everything the cache holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cache {
    pub state: Option<PoolState>,
    pub relays: Vec<CachedRelay>,
}

/// The on-disk envelope.
#[derive(Serialize, Deserialize)]
struct CacheFile {
    version: u32,
    state: Option<PoolState>,
    relays: Vec<CachedRelay>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn is_fresh(at: u64, now: u64) -> bool {
    at <= now && Duration::from_millis(now - at) < RELAY_CANDIDATE_TTL
}

fn rtt_ms(rtt: Duration) -> u64 {
    rtt.as_millis() as u64
}

impl Cache {
    /// The relays keyed by canonical URL. A file written by hand, or by a
    /// build with a different URL rule, is put through the same rule as
    /// everything else; two entries that collapse to one URL keep the fresher.
    fn by_url(&self) -> HashMap<String, CachedRelay> {
        let mut by_url: HashMap<String, CachedRelay> = HashMap::new();
        for relay in &self.relays {
            let Some(url) = normalize_relay_url(&relay.url) else {
                continue;
            };
            let relay = CachedRelay {
                url: url.clone(),
                ..relay.clone()
            };
            match by_url.get(&url) {
                Some(previous) if previous.freshness() > relay.freshness() => {}
                _ => {
                    by_url.insert(url, relay);
                }
            }
        }
        by_url
    }

    /// Drop expired entries and order the cache by how much a future transfer
    /// wants each relay: proven storage relays first, then fewer failures,
    /// then lower latency, then most recently seen. The cap then sheds
    /// repeatedly failing relays before ones the sweep has yet to reach.
    fn rank(&mut self, now: u64) {
        let mut relays: Vec<CachedRelay> = self
            .by_url()
            .into_values()
            .filter(|relay| relay.is_fresh(now))
            .collect();
        relays.sort_by(|a, b| {
            b.supports_storage
                .cmp(&a.supports_storage)
                .then(a.consecutive_failures.cmp(&b.consecutive_failures))
                .then(
                    a.rtt_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.rtt_ms.unwrap_or(u64::MAX)),
                )
                .then(b.last_discovered_at.cmp(&a.last_discovered_at))
                .then(a.url.cmp(&b.url))
        });
        relays.truncate(RELAY_CACHE_MAX_ENTRIES);
        self.relays = relays;
        if let Some(state) = &mut self.state {
            let mut seen = HashSet::new();
            state.candidates = state
                .candidates
                .iter()
                .filter_map(|url| normalize_relay_url(url))
                .filter(|url| seen.insert(url.clone()))
                .collect();
        }
    }

    /// The candidate list for a transfer: fresh discovery merged with what is
    /// still valid here, proven relays first. Writes the list back as the new
    /// state and refreshes the health records it touched.
    ///
    /// The seeds are barred from every source, the caches included: they are
    /// older than any given seed list, and a relay listed before it became a
    /// seed would otherwise sit in the candidate list forever.
    pub fn merge_candidates(
        &mut self,
        discovered: Vec<String>,
        seeds: &HashSet<String>,
        capability: Capability,
        now: u64,
    ) -> Vec<String> {
        let mut by_url: HashMap<String, CachedRelay> = self
            .by_url()
            .into_iter()
            .filter(|(_, relay)| relay.is_fresh(now))
            .collect();
        let state = self.state.clone();
        let cached: Vec<String> = match &state {
            Some(state) if is_fresh(state.discovered_at, now) => state
                .candidates
                .iter()
                .filter_map(|url| normalize_relay_url(url))
                .filter(|url| !seeds.contains(url))
                .collect(),
            _ => Vec::new(),
        };
        let discovered_at = state.as_ref().map(|state| state.discovered_at).unwrap_or(0);
        for url in &cached {
            by_url
                .entry(url.clone())
                .or_insert_with(|| CachedRelay::discovered(url.clone(), discovered_at));
        }
        for url in &discovered {
            by_url
                .entry(url.clone())
                .or_insert_with(|| CachedRelay::discovered(url.clone(), now))
                .last_discovered_at = now;
        }

        let mut known_working: Vec<&CachedRelay> = by_url
            .values()
            .filter(|relay| {
                !seeds.contains(&relay.url)
                    && match capability {
                        Capability::Storage => relay.supports_storage,
                        Capability::Control => relay.supports_control,
                    }
                    && relay.consecutive_failures == 0
                    && relay
                        .last_succeeded_at
                        .is_some_and(|at| is_fresh(at, now))
            })
            .collect();
        known_working.sort_by(|a, b| {
            a.rtt_ms
                .unwrap_or(u64::MAX)
                .cmp(&b.rtt_ms.unwrap_or(u64::MAX))
                .then(b.last_succeeded_at.cmp(&a.last_succeeded_at))
                .then(a.url.cmp(&b.url))
        });

        let mut ranked: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        for url in discovered.iter().chain(cached.iter()) {
            if seen.insert(url.clone()) {
                ranked.push(url.clone());
            }
        }
        // Failure-ranked, then newest-first; a stable sort keeps discovery
        // order among equals.
        ranked.sort_by(|a, b| {
            let a = by_url.get(a);
            let b = by_url.get(b);
            let failures = |relay: Option<&CachedRelay>| {
                relay.map(|relay| relay.consecutive_failures).unwrap_or(0)
            };
            let listed = |relay: Option<&CachedRelay>| {
                relay.map(|relay| relay.last_discovered_at).unwrap_or(0)
            };
            failures(a)
                .cmp(&failures(b))
                .then(listed(b).cmp(&listed(a)))
        });

        let mut merged: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        for url in known_working
            .iter()
            .map(|relay| relay.url.clone())
            .chain(ranked)
        {
            if seen.insert(url.clone()) {
                merged.push(url);
            }
            if merged.len() >= DISCOVERY_CANDIDATE_CAP {
                break;
            }
        }

        self.state = Some(PoolState {
            candidates: merged.clone(),
            discovered_at: now,
            cursor: state.map(|state| state.cursor).unwrap_or(0),
        });
        // The whole cache is kept, not just `merged`: trimming it to this
        // transfer's working set would throw away everything the sweep
        // enumerated beyond the relays this run happens to rank highest.
        self.relays = by_url.into_values().collect();
        self.rank(now);
        merged
    }

    /// Record probe verdicts under the capability the probe actually proved.
    /// A failure at either size clears both flags but keeps a failure count
    /// for ranking.
    pub fn record_probes(
        &mut self,
        healthy: &[HealthyRelay],
        failed: &[String],
        capability: Capability,
        now: u64,
    ) {
        let mut by_url = self.by_url();
        let mut healthy_rtt: HashMap<String, u64> = HashMap::new();
        for relay in healthy {
            if let Some(url) = normalize_relay_url(&relay.url) {
                let rtt = rtt_ms(relay.rtt);
                healthy_rtt
                    .entry(url)
                    .and_modify(|best| *best = (*best).min(rtt))
                    .or_insert(rtt);
            }
        }
        let failed: Vec<String> = failed
            .iter()
            .filter_map(|url| normalize_relay_url(url))
            .filter(|url| !healthy_rtt.contains_key(url))
            .collect();
        for url in failed {
            let relay = by_url
                .entry(url.clone())
                .or_insert_with(|| CachedRelay::discovered(url, now));
            relay.last_checked_at = Some(now);
            relay.rtt_ms = None;
            relay.consecutive_failures += 1;
            relay.supports_control = false;
            relay.supports_storage = false;
        }
        for (url, rtt) in healthy_rtt {
            let relay = by_url
                .entry(url.clone())
                .or_insert_with(|| CachedRelay::discovered(url, now));
            relay.last_checked_at = Some(now);
            relay.last_succeeded_at = Some(now);
            relay.rtt_ms = Some(rtt);
            relay.consecutive_failures = 0;
            relay.supports_control = true;
            if capability == Capability::Storage {
                relay.supports_storage = true;
            }
        }
        self.relays = by_url.into_values().collect();
        self.rank(now);
    }

    /// Record relays discovery has named, without probing them. The sweep
    /// finds far more relays than one transfer lasts long enough to probe, so
    /// the enumeration is written first and the verdicts fill in behind it.
    pub fn record_discovered(&mut self, urls: &[String], now: u64) {
        let mut by_url = self.by_url();
        for url in urls {
            let Some(url) = normalize_relay_url(url) else {
                continue;
            };
            by_url
                .entry(url.clone())
                .or_insert_with(|| CachedRelay::discovered(url, now))
                .last_discovered_at = now;
        }
        self.relays = by_url.into_values().collect();
        self.rank(now);
    }

    /// When each relay was last probed, for the sweep's longest-unchecked
    /// ordering.
    pub fn last_checked(&self) -> HashMap<String, u64> {
        self.by_url()
            .into_iter()
            .filter_map(|(url, relay)| relay.last_checked_at.map(|at| (url, at)))
            .collect()
    }

    /// Up to `count` relays from `healthy`, starting at the persisted cursor
    /// and advancing it, so successive uploads rotate through the healthy
    /// list instead of all landing on the same fastest few.
    pub fn take_ring(&mut self, healthy: &[HealthyRelay], count: usize) -> Vec<String> {
        if healthy.is_empty() {
            return Vec::new();
        }
        let state = self.state.get_or_insert_with(PoolState::default);
        let cursor = state.cursor % healthy.len();
        let selected: Vec<String> = (0..count.min(healthy.len()))
            .map(|i| healthy[(cursor + i) % healthy.len()].url.clone())
            .collect();
        state.cursor = (cursor + selected.len()) % healthy.len();
        selected
    }
}

enum Store {
    Disk { dir: PathBuf },
    Memory(Mutex<Cache>),
}

/// The cache, wherever it lives.
pub struct RelayCache {
    store: Store,
}

impl RelayCache {
    /// The cache the environment asks for: [`RELAY_CACHE_ENV`] names a
    /// directory or turns it off, and otherwise it is `ptransfer/` under the
    /// platform's cache directory. Without one — no home directory, say — it
    /// is kept in memory.
    pub fn open() -> Self {
        let dir = match std::env::var(RELAY_CACHE_ENV) {
            Ok(value) if value.trim().eq_ignore_ascii_case("off") => None,
            Ok(value) if !value.trim().is_empty() => Some(PathBuf::from(value.trim())),
            _ => dirs::cache_dir().map(|dir| dir.join(CACHE_SUBDIR)),
        };
        match dir {
            Some(dir) => {
                log::debug!("relay cache: {}", dir.display());
                Self {
                    store: Store::Disk { dir },
                }
            }
            None => {
                log::debug!("relay cache: in memory only");
                Self::in_memory()
            }
        }
    }

    pub fn in_memory() -> Self {
        Self {
            store: Store::Memory(Mutex::new(Cache::default())),
        }
    }

    /// The cache as it is now.
    pub async fn read(&self) -> Cache {
        match &self.store {
            Store::Memory(cache) => cache.lock().expect("relay cache").clone(),
            Store::Disk { dir } => {
                let dir = dir.clone();
                tokio::task::spawn_blocking(move || read_locked(&dir))
                    .await
                    .unwrap_or_default()
            }
        }
    }

    /// Apply `change` to the cache and keep the result. On disk this is one
    /// locked read-modify-write, so what `change` sees is what every other
    /// process has written by now, and what it writes is not lost to one.
    pub async fn update<T>(&self, change: impl FnOnce(&mut Cache) -> T + Send + 'static) -> T
    where
        T: Send + 'static,
    {
        match &self.store {
            Store::Memory(cache) => change(&mut cache.lock().expect("relay cache")),
            Store::Disk { dir } => {
                let dir = dir.clone();
                tokio::task::spawn_blocking(move || update_locked(&dir, change))
                    .await
                    // A blocking task is never cancelled, so this is a panic
                    // in `change`, and it stays one.
                    .unwrap_or_else(|error| std::panic::resume_unwind(error.into_panic()))
            }
        }
    }
}

fn change_in_memory<T>(change: impl FnOnce(&mut Cache) -> T) -> T {
    let mut cache = Cache::default();
    change(&mut cache)
}

/// The cache file's contents, or an empty cache when there is nothing usable.
fn parse(bytes: &[u8]) -> Cache {
    match serde_json::from_slice::<CacheFile>(bytes) {
        Ok(file) if file.version == CACHE_FILE_VERSION => Cache {
            state: file.state,
            relays: file.relays,
        },
        Ok(file) => {
            log::debug!(
                "relay cache is version {}, not {CACHE_FILE_VERSION}; starting over",
                file.version
            );
            Cache::default()
        }
        Err(error) => {
            log::debug!("relay cache is unreadable; starting over: {error}");
            Cache::default()
        }
    }
}

fn read_file(dir: &Path) -> Cache {
    match fs::read(dir.join(CACHE_FILE_NAME)) {
        Ok(bytes) => parse(&bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Cache::default(),
        Err(error) => {
            log::debug!("relay cache could not be read: {error}");
            Cache::default()
        }
    }
}

fn lock_file(dir: &Path) -> std::io::Result<File> {
    fs::create_dir_all(dir)?;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(LOCK_FILE_NAME))
}

fn read_locked(dir: &Path) -> Cache {
    let lock = match lock_file(dir) {
        Ok(lock) => lock,
        Err(error) => {
            log::debug!("relay cache lock could not be opened: {error}");
            return read_file(dir);
        }
    };
    if let Err(error) = lock.lock_shared() {
        log::debug!("relay cache could not be locked: {error}");
    }
    read_file(dir)
}

fn update_locked<T>(dir: &Path, change: impl FnOnce(&mut Cache) -> T) -> T {
    let lock = match lock_file(dir) {
        Ok(lock) => lock,
        Err(error) => {
            log::debug!("relay cache lock could not be opened; not persisting: {error}");
            return change_in_memory(change);
        }
    };
    if let Err(error) = lock.lock() {
        log::debug!("relay cache could not be locked; not persisting: {error}");
        return change_in_memory(change);
    }
    let mut cache = read_file(dir);
    let result = change(&mut cache);
    if let Err(error) = write_file(dir, &cache) {
        log::debug!("relay cache could not be written: {error}");
    }
    result
}

/// Serialize into a sibling temporary file and rename it over the cache, so
/// a reader sees the old file or the new one and never a partial write.
fn write_file(dir: &Path, cache: &Cache) -> std::io::Result<()> {
    let file = CacheFile {
        version: CACHE_FILE_VERSION,
        state: cache.state.clone(),
        relays: cache.relays.clone(),
    };
    let bytes = serde_json::to_vec(&file)?;
    let temporary = dir.join(format!("{CACHE_FILE_NAME}.{}.tmp", std::process::id()));
    let written = (|| {
        let mut handle = File::create(&temporary)?;
        handle.write_all(&bytes)?;
        handle.sync_all()?;
        fs::rename(&temporary, dir.join(CACHE_FILE_NAME))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 60 * 60 * 1000;
    const NOW: u64 = 100 * HOUR;

    fn seeds() -> HashSet<String> {
        ["wss://seed.example"].iter().map(|s| s.to_string()).collect()
    }

    fn passed(url: &str, ms: u64) -> HealthyRelay {
        HealthyRelay {
            url: url.to_string(),
            rtt: Duration::from_millis(ms),
        }
    }

    fn find<'a>(cache: &'a Cache, url: &str) -> &'a CachedRelay {
        cache.relays.iter().find(|relay| relay.url == url).unwrap()
    }

    /// A full-size pass proves both capabilities, a control-sized pass only
    /// the small one, and a failure at either size clears both.
    #[test]
    fn a_verdict_is_recorded_under_what_it_proved() {
        let mut cache = Cache::default();
        cache.record_probes(&[passed("wss://big.example", 40)], &[], Capability::Storage, NOW);
        cache.record_probes(&[passed("wss://small.example", 20)], &[], Capability::Control, NOW);
        let big = find(&cache, "wss://big.example");
        assert!(big.supports_storage && big.supports_control);
        assert_eq!(big.rtt_ms, Some(40));
        let small = find(&cache, "wss://small.example");
        assert!(small.supports_control && !small.supports_storage);

        // A control pass leaves an earlier full-size verdict alone.
        cache.record_probes(&[passed("wss://big.example", 30)], &[], Capability::Control, NOW + 1);
        assert!(find(&cache, "wss://big.example").supports_storage);

        cache.record_probes(&[], &["wss://big.example/".to_string()], Capability::Storage, NOW + 2);
        let big = find(&cache, "wss://big.example");
        assert!(!big.supports_storage && !big.supports_control);
        assert_eq!(big.consecutive_failures, 1);
        assert_eq!(big.rtt_ms, None);
        assert_eq!(big.last_succeeded_at, Some(NOW + 1));
    }

    /// Proven relays lead the list, the seeds never appear from any source,
    /// and a stale candidate list is ignored while a fresh one is merged.
    #[test]
    fn candidates_lead_with_what_is_proven_and_never_name_a_seed() {
        let mut cache = Cache::default();
        cache.record_probes(
            &[passed("wss://fast.example", 10), passed("wss://slow.example", 900)],
            &["wss://dead.example".to_string()],
            Capability::Storage,
            NOW - HOUR,
        );
        cache.state = Some(PoolState {
            candidates: vec![
                "wss://seed.example".to_string(),
                "wss://old.example".to_string(),
                "wss://dead.example".to_string(),
            ],
            discovered_at: NOW - 2 * HOUR,
            cursor: 3,
        });
        let merged = cache.merge_candidates(
            vec!["wss://new.example".to_string(), "wss://dead.example".to_string()],
            &seeds(),
            Capability::Storage,
            NOW,
        );
        assert_eq!(
            merged,
            vec![
                "wss://fast.example",
                "wss://slow.example",
                "wss://new.example",
                "wss://old.example",
                "wss://dead.example",
            ]
        );
        let state = cache.state.as_ref().unwrap();
        assert_eq!(state.candidates, merged);
        assert_eq!(state.discovered_at, NOW);
        assert_eq!(state.cursor, 3);
        assert_eq!(find(&cache, "wss://new.example").last_discovered_at, NOW);
        assert_eq!(find(&cache, "wss://old.example").last_discovered_at, NOW - 2 * HOUR);

        // Past the TTL the candidate list is stale and the verdicts expire.
        let mut stale = cache.clone();
        let merged = stale.merge_candidates(Vec::new(), &seeds(), Capability::Storage, NOW + 8 * 24 * HOUR);
        assert!(merged.is_empty());
        assert!(stale.relays.is_empty());
    }

    #[test]
    fn the_ring_cursor_rotates_across_uploads() {
        let mut cache = Cache::default();
        let healthy = vec![
            passed("wss://a.example", 1),
            passed("wss://b.example", 2),
            passed("wss://c.example", 3),
        ];
        assert_eq!(cache.take_ring(&healthy, 2), vec!["wss://a.example", "wss://b.example"]);
        assert_eq!(cache.take_ring(&healthy, 2), vec!["wss://c.example", "wss://a.example"]);
        assert_eq!(cache.state.as_ref().unwrap().cursor, 1);
        assert!(cache.take_ring(&[], 2).is_empty());
    }

    /// Ranking: proven storage first, then fewest failures, then fastest;
    /// the cap sheds the tail; two spellings of one relay are one entry.
    #[test]
    fn the_cache_is_ranked_deduplicated_and_capped() {
        let mut cache = Cache::default();
        for i in 0..(RELAY_CACHE_MAX_ENTRIES + 5) {
            cache.relays.push(CachedRelay::discovered(format!("wss://r{i}.example"), NOW));
        }
        cache.relays.push(CachedRelay {
            rtt_ms: Some(5),
            ..CachedRelay::discovered("wss://Proven.example/".to_string(), NOW)
        });
        cache.relays.push(CachedRelay {
            supports_storage: true,
            supports_control: true,
            rtt_ms: Some(50),
            last_succeeded_at: Some(NOW),
            ..CachedRelay::discovered("wss://proven.example".to_string(), NOW - 1)
        });
        cache.rank(NOW);
        assert_eq!(cache.relays.len(), RELAY_CACHE_MAX_ENTRIES);
        assert_eq!(cache.relays[0].url, "wss://proven.example");
        assert!(cache.relays[0].supports_storage);
        assert_eq!(
            cache.relays.iter().filter(|relay| relay.url == "wss://proven.example").count(),
            1
        );
    }

    /// Writers that each open the lock file for themselves — which is what
    /// separate processes do — add to one another's verdicts rather than
    /// overwriting them.
    #[test]
    fn concurrent_writers_lose_nothing() {
        let dir = std::env::temp_dir().join(format!(
            "ptransfer-relay-cache-writers-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let writers: Vec<_> = (0..8)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    for round in 0..10 {
                        update_locked(&dir, move |cache| {
                            cache.record_probes(
                                &[passed(&format!("wss://w{i}.example"), round + 1)],
                                &[format!("wss://f{i}-{round}.example")],
                                Capability::Storage,
                                NOW,
                            );
                        });
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        let cache = read_locked(&dir);
        assert_eq!(cache.relays.len(), 8 + 80);
        for i in 0..8 {
            assert_eq!(find(&cache, &format!("wss://w{i}.example")).rtt_ms, Some(10));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// The file survives a round trip, a version bump discards it, and
    /// garbage is an empty cache.
    #[test]
    fn the_file_round_trips_and_anything_else_is_empty() {
        let dir = std::env::temp_dir().join(format!("ptransfer-relay-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut cache = Cache::default();
        cache.record_probes(&[passed("wss://a.example", 7)], &[], Capability::Storage, NOW);
        cache.take_ring(&[passed("wss://a.example", 7)], 1);
        write_file(&dir, &cache).unwrap();
        assert_eq!(read_locked(&dir), cache);
        assert!(!dir.read_dir().unwrap().any(|entry| {
            entry.unwrap().path().extension().is_some_and(|ext| ext == "tmp")
        }));

        let result = update_locked(&dir, |cache| {
            cache.record_probes(&[], &["wss://a.example".to_string()], Capability::Storage, NOW + 1);
            cache.relays.len()
        });
        assert_eq!(result, 1);
        assert_eq!(find(&read_locked(&dir), "wss://a.example").consecutive_failures, 1);

        fs::write(dir.join(CACHE_FILE_NAME), br#"{"version":0,"state":null,"relays":[]}"#).unwrap();
        assert_eq!(read_locked(&dir), Cache::default());
        fs::write(dir.join(CACHE_FILE_NAME), b"not json").unwrap();
        assert_eq!(read_locked(&dir), Cache::default());
        let _ = fs::remove_dir_all(&dir);
    }
}
