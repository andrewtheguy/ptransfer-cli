//! Throwaway backing store for an Arti client.
//!
//! Arti keeps three things outside the process: the directory cache (the
//! consensus and the microdescriptors), persistent client state (guards,
//! introduction points), and the keystore. We want none of them to survive the
//! process, and we especially do not want to touch the machine's normal Arti
//! installation under `~/.local/share/arti` — a second `ptransfer` on the same
//! machine would fight it for the state directory lock.
//!
//! The keystore is genuinely in memory: Arti's `ArtiEphemeralKeystore` holds
//! the onion service's ed25519 identity in RAM only, so every run publishes a
//! fresh `.onion` address and the key is gone when the process exits.
//!
//! The directory cache and the state directory are still filesystem paths.
//! `arti-client` has no in-memory `StateMgr` to plug in: fully ephemeral onion
//! services are arti#1186, still unscheduled, and the merge requests that would
//! have exposed a `MemoryStateMgr` (arti!4160, arti!4161) were closed. The next
//! best thing is a private directory on a RAM-backed filesystem, so on Linux we
//! allocate under `/dev/shm` (tmpfs, never written to a disk) and fall back to
//! the platform temp dir elsewhere. Either way the whole tree is removed when
//! [`EphemeralStorage`] is dropped.
//!
//! Because the root is new on every run, the introduction-point manager never
//! finds stale state from a previous identity, which is what produces the
//! "missing previous key, regenerating" errors reported on arti#1186 when an
//! ephemeral keystore is paired with a reused state directory.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// A private, self-deleting directory tree holding one Arti client's state.
#[derive(Debug)]
pub struct EphemeralStorage {
    /// Removed recursively on drop.
    dir: TempDir,
}

impl EphemeralStorage {
    /// Allocate a fresh storage root, preferring RAM-backed storage.
    pub fn new() -> Result<Self> {
        let mut builder = tempfile::Builder::new();
        builder.prefix("ptransfer-tor-");

        // `/dev/shm` and `/tmp` are both world-writable, but they are sticky,
        // which Arti's `fs-mistrust` checks accept for an intermediate
        // directory. Our own directory has to be private.
        #[cfg(unix)]
        builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o700));

        let dir = match ram_backed_root() {
            Some(root) => builder.tempdir_in(root),
            None => builder.tempdir(),
        }
        .context("failed to create a temporary directory for Tor client state")?;

        Ok(Self { dir })
    }

    /// Path for Arti's `storage.state_dir`.
    ///
    /// Arti creates the directory itself, with the permissions it wants.
    pub fn state_dir(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    /// Path for Arti's `storage.cache_dir`.
    pub fn cache_dir(&self) -> PathBuf {
        self.dir.path().join("cache")
    }

    /// The root that gets deleted on drop; useful for logging.
    pub fn root(&self) -> &Path {
        self.dir.path()
    }
}

/// Return a directory that lives in RAM rather than on a disk, if there is one.
fn ram_backed_root() -> Option<PathBuf> {
    // On Linux `/dev/shm` is a tmpfs, so nothing under it is ever written to
    // stable storage. Other platforms have no portable equivalent.
    let shm = Path::new("/dev/shm");
    shm.is_dir().then(|| shm.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_root_is_removed_on_drop() {
        let storage = EphemeralStorage::new().unwrap();
        let root = storage.root().to_path_buf();
        assert!(root.is_dir());
        drop(storage);
        assert!(!root.exists());
    }

    #[test]
    fn state_and_cache_live_under_the_root() {
        let storage = EphemeralStorage::new().unwrap();
        assert!(storage.state_dir().starts_with(storage.root()));
        assert!(storage.cache_dir().starts_with(storage.root()));
        assert_ne!(storage.state_dir(), storage.cache_dir());
    }

    #[cfg(unix)]
    #[test]
    fn storage_root_is_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let storage = EphemeralStorage::new().unwrap();
        let mode = std::fs::metadata(storage.root()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "root is {:o}", mode & 0o777);
    }

    #[test]
    fn two_clients_do_not_share_a_root() {
        let a = EphemeralStorage::new().unwrap();
        let b = EphemeralStorage::new().unwrap();
        assert_ne!(a.root(), b.root());
    }
}
