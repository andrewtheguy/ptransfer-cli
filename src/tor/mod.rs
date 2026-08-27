//! CLI-to-CLI transport over a Tor v3 onion service.
//!
//! Enabled by the `tor` cargo feature. Two things run over it:
//!
//! - [`echo`], the proof of concept the transport was built against: one
//!   instance publishes an ephemeral onion address and echoes lines, the other
//!   connects and gets its line back.
//! - [`transfer`], the file transfer: the sender publishes an address and a
//!   one-time password, and the receiver needs nothing else to connect,
//!   authenticate, and pull the file.
//!
//! The Arti client is deliberately not wired to the machine's Tor setup. It
//! reads no configuration file, and its directory cache, client state and
//! keystore all live in throwaway storage that disappears with the process —
//! see [`storage`] for exactly how in-memory each of those is.

pub mod client;
pub mod echo;
pub mod handshake;
pub mod service;
pub mod storage;
pub mod transfer;
pub mod wire;

pub use client::EphemeralTorClient;
pub use service::OnionListener;
pub use storage::EphemeralStorage;

use anyhow::{Context, Result};
use safelog::DisplayRedacted as _;
use tor_hsservice::HsId;

/// Virtual port both onion services listen on. Onion services have their own
/// port space, so this collides with nothing on either machine, and a process
/// publishes at most one service at a time.
pub const DEFAULT_PORT: u16 = 9735;

/// Split `address` into a canonical v3 onion host and a port, falling back to
/// `default_port`.
///
/// A port in the address wins over `default_port`, so the line the serving side
/// prints can be pasted straight into the connecting side.
///
/// The host has to be a v3 `.onion` address, checksum and all. Arti would
/// otherwise happily resolve anything else through an exit node, so a typo
/// that drops the suffix would leave the onion network and reach the plain
/// internet from this machine's Tor circuit.
///
/// The host comes back in `HsId`'s canonical spelling, which is what both peers
/// bind their handshake to: two peers that typed the same address in different
/// letter cases still agree on the string.
pub fn split_address(address: &str, default_port: u16) -> Result<(String, u16)> {
    let (host, port) = match address.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse()
                .with_context(|| format!("invalid port in address {address:?}"))?,
        ),
        None => (address, default_port),
    };

    let host: HsId = host
        .parse()
        .with_context(|| format!("invalid v3 onion address {host:?}"))?;
    Ok((host.display_unredacted().to_string(), port))
}

/// Whether an I/O error just means the peer went away.
///
/// A Tor stream never ends with a plain EOF. The far side sends an END cell,
/// whose reason Arti maps to an `ErrorKind` — and the reason depends on how the
/// peer let go: a shut-down writer sends `DONE`, a dropped stream sends `MISC`.
/// So rather than enumerate reasons, treat any END as the end of the
/// conversation. If the stream is already torn down by the time we read, Arti
/// reports `NotConnected` instead and no END cell is involved.
pub fn is_disconnect(err: &std::io::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected};

    if matches!(
        err.kind(),
        NotConnected | ConnectionReset | ConnectionAborted | BrokenPipe
    ) {
        return true;
    }

    err.get_ref()
        .and_then(|source| source.downcast_ref::<tor_proto::Error>())
        .is_some_and(|e| matches!(e, tor_proto::Error::EndReceived(_)))
}

/// Resolve when the process is asked to stop.
///
/// A signal is how a serving command is meant to be stopped, so it unwinds
/// normally: the throwaway storage is only removed by its destructor, which a
/// signal-killed process never runs.
#[cfg(unix)]
pub async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = term.recv() => Ok(()),
    }
}

/// Resolve when the process is asked to stop.
#[cfg(not(unix))]
pub async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real address printed by the serving side, so the checksum is genuine.
    const ONION: &str = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion";

    #[test]
    fn a_bare_address_uses_the_default_port() {
        assert_eq!(
            split_address(ONION, DEFAULT_PORT).unwrap(),
            (ONION.to_owned(), DEFAULT_PORT)
        );
    }

    #[test]
    fn a_port_in_the_address_wins() {
        assert_eq!(
            split_address(&format!("{ONION}:1234"), DEFAULT_PORT).unwrap(),
            (ONION.to_owned(), 1234)
        );
    }

    #[test]
    fn a_non_numeric_port_is_an_error() {
        assert!(split_address(&format!("{ONION}:"), DEFAULT_PORT).is_err());
        assert!(split_address(&format!("{ONION}:http"), DEFAULT_PORT).is_err());
    }

    #[test]
    fn a_non_onion_host_is_an_error() {
        // Without this, Arti would route these out through an exit node.
        assert!(split_address("example.com", DEFAULT_PORT).is_err());
        assert!(split_address("example.com:80", DEFAULT_PORT).is_err());
        assert!(split_address("127.0.0.1:9735", DEFAULT_PORT).is_err());
    }

    #[test]
    fn a_malformed_onion_host_is_an_error() {
        // Too short to be v3, a bad checksum, and a subdomain.
        assert!(split_address("abc.onion", DEFAULT_PORT).is_err());
        let mut wrong = ONION.to_owned();
        wrong.replace_range(0..1, "a");
        assert!(split_address(&wrong, DEFAULT_PORT).is_err());
        assert!(split_address(&format!("www.{ONION}"), DEFAULT_PORT).is_err());
    }

    #[test]
    fn the_host_comes_back_canonicalized() {
        // Both peers bind their handshake to this string, so an address typed
        // in a different case must not produce a different binding.
        assert_eq!(
            split_address(&ONION.to_uppercase(), DEFAULT_PORT).unwrap().0,
            ONION
        );
    }
}
