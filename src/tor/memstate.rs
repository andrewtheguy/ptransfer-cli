//! The Tor client's persistent state, kept in memory instead.
//!
//! Arti asks for persistent state through [`StateMgr`], a small key-value
//! trait over serde values: the guard manager keeps its guard sets there, the
//! vanguard manager its vanguard sets, and the circuit manager its measured
//! build timeouts. Arti's own implementation of the trait writes JSON files
//! under a state directory and takes a lock file over it.
//!
//! Because the trait is public, none of that is forced on us: this is the same
//! store with a `HashMap` behind it. Nothing is written anywhere, so there is
//! no directory to create, no permissions to check, no lock to contend for and
//! nothing left behind when the process dies — including when it is killed
//! outright, which a destructor would not survive. It behaves identically on
//! every platform, which a tmpfs path does not.
//!
//! What we give up by not persisting is only what persistence buys: guards and
//! vanguards are chosen afresh each run rather than being kept across runs.
//! For a one-shot transfer that is the intended behaviour anyway — the process
//! is the session.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tor_persist::{LockStatus, StateMgr};

/// What every method here returns.
///
/// `tor_persist::Result` is private, so this spells out the same thing.
type Result<T> = std::result::Result<T, tor_persist::Error>;

/// Arti's persistent state, held in this process and nowhere else.
///
/// Cloning shares one store: Arti hands copies to the guard, vanguard and
/// circuit managers, and they are all meant to see the same state.
#[derive(Clone, Debug, Default)]
pub struct MemoryStateMgr {
    /// The shared store. Also guards the lock flag, so that "do we hold the
    /// lock" and "what is stored" cannot disagree.
    inner: Arc<Mutex<Inner>>,
}

/// The state behind [`MemoryStateMgr`].
#[derive(Debug)]
struct Inner {
    /// Whether this manager holds the write lock. Always true in practice; see
    /// [`MemoryStateMgr::new`].
    locked: bool,
    /// Stored values, serialized on the way in so that one key can be written
    /// and read as one type without this store having to be generic.
    entries: HashMap<String, serde_json::Value>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            // See `new`: the lock is ours from the start.
            locked: true,
            entries: HashMap::new(),
        }
    }
}

impl MemoryStateMgr {
    /// Create an empty store that already holds its own lock.
    ///
    /// Arti's file-backed manager starts unlocked because a second Arti on the
    /// same machine may hold the state directory; whoever loses the race runs
    /// read-only. This store is private to one client in one process, so there
    /// is nobody to lose the race to, and starting locked means callers that
    /// never call [`StateMgr::try_lock`] can still store state.
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateMgr for MemoryStateMgr {
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned,
    {
        let inner = self.inner.lock().expect("poisoned lock");
        let Some(value) = inner.entries.get(key) else {
            return Ok(None);
        };

        // A stored value that will not deserialize is reported as absent
        // rather than as an error, because `tor_persist::Error` cannot be
        // constructed outside its own crate: `Error::new`, `Action` and
        // `Resource` are all `pub(crate)`. Every method here therefore has to
        // succeed.
        //
        // Treating it as absent is the same thing Arti's own manager does with
        // state it cannot parse — the caller regenerates it — and it cannot
        // happen here regardless: the only writer is `store` below, one key is
        // only ever written as one type, and the value never leaves memory to
        // be corrupted in between.
        match serde_json::from_value(value.clone()) {
            Ok(parsed) => Ok(Some(parsed)),
            Err(error) => {
                log::warn!("discarding unreadable Tor client state at {key:?}: {error}");
                Ok(None)
            }
        }
    }

    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize,
    {
        let mut inner = self.inner.lock().expect("poisoned lock");
        if !inner.locked {
            // Matches the file-backed manager, which refuses to write when
            // another process holds the lock.
            return Ok(());
        }

        // Unreachable for the types Arti stores here: they all round-trip
        // through serde_json in Arti's own on-disk manager, which would fail
        // the same way. See the note in `load` for why this cannot be an error.
        match serde_json::to_value(val) {
            Ok(value) => {
                inner.entries.insert(key.to_owned(), value);
            }
            Err(error) => log::warn!("failed to record Tor client state at {key:?}: {error}"),
        }
        Ok(())
    }

    fn can_store(&self) -> bool {
        self.inner.lock().expect("poisoned lock").locked
    }

    fn try_lock(&self) -> Result<LockStatus> {
        let mut inner = self.inner.lock().expect("poisoned lock");
        if inner.locked {
            Ok(LockStatus::AlreadyHeld)
        } else {
            inner.locked = true;
            Ok(LockStatus::NewlyAcquired)
        }
    }

    fn unlock(&self) -> Result<()> {
        self.inner.lock().expect("poisoned lock").locked = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape Arti actually stores: a struct that round-trips through serde.
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Guards {
        relays: Vec<String>,
    }

    #[test]
    fn a_stored_value_reads_back() {
        let mgr = MemoryStateMgr::new();
        let guards = Guards {
            relays: vec!["one".into(), "two".into()],
        };

        mgr.store("guards", &guards).unwrap();
        assert_eq!(mgr.load::<Guards>("guards").unwrap(), Some(guards));
    }

    #[test]
    fn an_unwritten_key_is_absent() {
        let mgr = MemoryStateMgr::new();
        assert_eq!(mgr.load::<Guards>("guards").unwrap(), None);
    }

    #[test]
    fn storing_again_replaces_the_previous_value() {
        let mgr = MemoryStateMgr::new();
        mgr.store("guards", &Guards { relays: vec![] }).unwrap();
        let replacement = Guards {
            relays: vec!["only".into()],
        };
        mgr.store("guards", &replacement).unwrap();

        assert_eq!(mgr.load::<Guards>("guards").unwrap(), Some(replacement));
    }

    /// Arti clones the manager into the guard, vanguard and circuit managers,
    /// which are all meant to be looking at the same state.
    #[test]
    fn clones_share_one_store() {
        let mgr = MemoryStateMgr::new();
        let clone = mgr.clone();

        clone.store("guards", &Guards { relays: vec![] }).unwrap();
        assert_eq!(
            mgr.load::<Guards>("guards").unwrap(),
            Some(Guards { relays: vec![] })
        );
    }

    /// Nothing else can hold this lock, so it is held from the start and a
    /// caller that never asks for it can still store state.
    #[test]
    fn the_lock_is_held_without_being_asked_for() {
        let mgr = MemoryStateMgr::new();
        assert!(mgr.can_store());
        assert_eq!(mgr.try_lock().unwrap(), LockStatus::AlreadyHeld);
        assert!(mgr.try_lock().unwrap().held());
    }

    #[test]
    fn unlocking_stops_writes_and_relocking_resumes_them() {
        let mgr = MemoryStateMgr::new();
        mgr.unlock().unwrap();
        assert!(!mgr.can_store());

        // Dropped, because the lock is not ours.
        mgr.store("guards", &Guards { relays: vec![] }).unwrap();
        assert_eq!(mgr.load::<Guards>("guards").unwrap(), None);

        assert_eq!(mgr.try_lock().unwrap(), LockStatus::NewlyAcquired);
        mgr.store("guards", &Guards { relays: vec![] }).unwrap();
        assert!(mgr.load::<Guards>("guards").unwrap().is_some());
    }

    /// A value stored as one type and read back as an incompatible one is
    /// reported as absent, because this trait's error type cannot be built
    /// from outside `tor-persist`.
    #[test]
    fn an_unreadable_value_reads_as_absent() {
        let mgr = MemoryStateMgr::new();
        mgr.store("guards", &"not a Guards").unwrap();
        assert_eq!(mgr.load::<Guards>("guards").unwrap(), None);
    }
}
