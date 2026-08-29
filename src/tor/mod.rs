//! CLI-to-CLI transport over a Tor v3 onion service.
//!
//! Enabled by the `tor` cargo feature. What runs over it is [`transfer`], the
//! file transfer: the sender publishes an address and a one-time password, and
//! the receiver needs nothing else to connect, authenticate, and pull the file.
//!
//! The Tor client is deliberately not wired to the machine's Tor setup. It
//! reads no configuration file and shares nothing with a system Tor or an
//! existing `~/.local/share/arti`. It also writes no Tor state: the directory
//! ([`netdir`]), the guard and vanguard state ([`memstate`]), and the
//! onion-service keys ([`service`]) are ordinary values in this process's
//! memory, so they need no cleanup and cannot outlive it. Received transfer
//! output is separate and is written to the operator's chosen destination.

pub mod client;
pub mod config;
pub mod handshake;
pub mod memstate;
pub mod netdir;
pub mod service;
pub mod transfer;
pub mod wire;

pub use client::TorClient;
pub use service::OnionListener;

use anyhow::{Context, Result};
use safelog::DisplayRedacted as _;
use tor_hscrypto::pk::HsId;

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
/// The host has to be a v3 `.onion` address, checksum and all. Nothing else is
/// a thing this transport can reach: it only ever builds onion-service
/// circuits, so a typo that drops the suffix has to be refused here rather
/// than turning into a connection to somewhere else.
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

/// The address as a person is handed it: `<host>.onion`, with the default port
/// left implicit.
///
/// The port is not a choice either side offers, so spelling out 9735 only gives
/// the other side more to retype. A non-default port is spelled out, because
/// [`split_address`] resolves a missing one to the default and would otherwise
/// send the receiver to the wrong port. What the handshake binds is the
/// canonical `<host>.onion:<port>`, always carrying its port — that string is
/// built separately and is never what gets displayed.
pub fn display_address(host: &str, port: u16) -> String {
    if port == DEFAULT_PORT {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
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
/// A signal is how a serving command is meant to be stopped. Nothing has to be
/// cleaned up on the way out — there is no storage to remove — but unwinding
/// normally lets the onion service tell its introduction points it is going
/// away, instead of leaving them to time it out.
pub async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = term.recv() => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real address printed by the serving side, so the checksum is genuine.
    const ONION: &str = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion";

    /// The spec hands over `<host>.onion` and resolves a missing port to the
    /// default, so the two spellings have to round-trip to the same binding.
    #[test]
    fn the_handed_over_address_leaves_the_default_port_implicit() {
        assert_eq!(display_address(ONION, DEFAULT_PORT), ONION);
        assert_eq!(
            split_address(&display_address(ONION, DEFAULT_PORT), DEFAULT_PORT).unwrap(),
            (ONION.to_owned(), DEFAULT_PORT)
        );
    }

    /// A port nobody could guess has to be spelled out, or the receiver
    /// resolves the missing one to 9735 and dials the wrong port.
    #[test]
    fn the_handed_over_address_spells_out_a_non_default_port() {
        assert_eq!(display_address(ONION, 1234), format!("{ONION}:1234"));
        assert_eq!(
            split_address(&display_address(ONION, 1234), DEFAULT_PORT).unwrap(),
            (ONION.to_owned(), 1234)
        );
    }

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
