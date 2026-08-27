//! Experimental CLI-to-CLI transport over a Tor v3 onion service.
//!
//! Enabled by the `tor` cargo feature. The v1 scope is a proof of concept:
//! one instance publishes an ephemeral onion address and echoes lines, the
//! other connects to that address and gets its line back. See [`echo`].
//!
//! The Arti client is deliberately not wired to the machine's Tor setup. It
//! reads no configuration file, and its directory cache, client state and
//! keystore all live in throwaway storage that disappears with the process —
//! see [`storage`] for exactly how in-memory each of those is.

pub mod client;
pub mod echo;
pub mod storage;

pub use client::EphemeralTorClient;
pub use storage::EphemeralStorage;
