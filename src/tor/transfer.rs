//! File transfer over a Tor v3 onion service.
//!
//! The sender publishes a throwaway onion service and mints a one-time
//! password. Those two strings are the whole rendezvous: the receiver needs no
//! relay, no account, and nothing else the sender did not hand it. Everything
//! after the connection is the shared choreography in [`crate::transfer`],
//! keyed by the handshake in [`super::handshake`] and framed by
//! [`super::wire`].
//!
//! v1 is CLI to CLI and caps a transfer at [`MAX_TRANSFER_BYTES`]. The cap is
//! deliberate rather than incidental: a Tor circuit is slow enough that a large
//! transfer wants resume support, which this has none of.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::archive::{SendSource, prepare_send_source_with_cap};
use crate::crypto::pin::{generate_pin, is_valid_pin};
use crate::transfer::{run_receiver, run_sender};
use crate::ui;
use crate::util::{OnConflict, format_bytes, resolve_destination};
use crate::wire::TransferMetadata;

use super::client::EphemeralTorClient;
use super::handshake::{
    ClientHandshake, ServiceHandshake, run_client_handshake, run_service_handshake, send_cancel,
    send_ready,
};
use super::service::OnionListener;
use super::wire::TorMessenger;
use super::{shutdown_signal, split_address};

/// Largest payload a Tor transfer carries, measured on the input.
///
/// The spec's number, and the web app spends it on its relayed transfers too:
/// both paths push bytes through third parties at a fraction of a data
/// channel's speed and neither can resume. It is a hard limit because it is
/// the receiver's rule as well as the sender's — a peer that ignored it would
/// only find out after a bootstrap and a handshake.
pub const MAX_TRANSFER_BYTES: u64 = 100 * 1024 * 1024;

/// The size past which a Tor transfer is worth a word to the operator. Advice
/// printed once, never enforced: a circuit's throughput is the luck of the
/// relays it was built from, so the same size can arrive in moments or crawl.
/// A fixed ceiling would refuse transfers that would have finished fine.
pub const SUGGESTED_MAX_BYTES: u64 = 1024 * 1024;

/// Wire allowance for that payload. A single file is deflated on the wire,
/// which grows incompressible input very slightly, and a generated ZIP adds
/// per-entry headers — neither is known until the bytes are produced, so the
/// wire ceiling carries a margin over the payload limit that is enforced on the
/// input. A flat 1 MiB: deflate's worst case is a fraction of a percent, and
/// the rest is headroom for a selection of many small files, whose ZIP headers
/// are what actually add up.
const MAX_WIRE_BYTES: u64 = MAX_TRANSFER_BYTES + 1024 * 1024;

/// Keystore nickname for the transfer service. With the in-memory keystore
/// there is only ever one service per process and no key to look up again
/// later, so the name is fixed.
const NICKNAME: &str = "ptransfer-transfer";

/// How long the sender keeps the service up, from publish to a delivered file.
/// A resource backstop, not a security control: the password is single-use by
/// convention and the address dies with the process either way.
const WAIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// How long an accepted connection may take to authenticate before the sender
/// drops it and goes back to waiting.
///
/// Anyone who has the address can open the port, so an accepted connection is
/// not yet a receiver, and it must not be able to hold the service against the
/// real one. It covers the handshake and the receiver's answer to it — a human
/// at an overwrite prompt is inside that — but not the transfer: once a peer
/// has proved it knows the password it is the receiver, and `run_sender`'s
/// stall window is what polices it from there. A wall clock over the transfer
/// would just be a second, worse size limit, since how long a hundred
/// megabytes takes to crawl down a Tor circuit is not knowable in advance.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How many connections may fail to authenticate before the sender gives up.
///
/// The password is far too long to guess — this bounds a stranger who found
/// the address hammering the service, not a realistic search.
const MAX_FAILED_HANDSHAKES: u32 = 20;

/// Publish an onion service and send `paths` to the first receiver that
/// authenticates with the printed password.
///
/// Prints the address and password to stdout as soon as they exist, then
/// `ready` once the descriptor is published — wait for `ready` before
/// connecting.
pub async fn send(paths: Vec<PathBuf>, port: u16) -> Result<()> {
    // Fail on an oversized selection before spending a minute bootstrapping.
    let source = tokio::task::spawn_blocking(move || {
        prepare_send_source_with_cap(&paths, MAX_TRANSFER_BYTES)
    })
    .await??;
    // Advice, not a gate: the transfer goes ahead either way.
    if source.estimated_size > SUGGESTED_MAX_BYTES {
        ui::status(&format!(
            "{} over Tor: speed depends on the circuit, and a transfer that \
             drops starts over. Sending anyway.",
            format_bytes(source.estimated_size)
        ));
    }
    let password = generate_pin()?;

    let tor = EphemeralTorClient::bootstrap().await?;
    let mut listener = OnionListener::launch(&tor, NICKNAME)?;
    let onion = format!("{}:{}", listener.onion(), port);

    ui::show_tor_address(&source.file_name, source.estimated_size, &onion, &password);
    log::info!("publishing the descriptor; this usually takes under a minute");
    listener.wait_until_published().await?;
    ui::tor_published();

    serve_one_transfer(listener, port, &onion, &password, &source).await
}

/// How one accepted connection ended, once its peer authenticated.
#[derive(Debug)]
enum ServedConnection {
    /// The file was delivered.
    Sent,
    /// The receiver declined after seeing what was on offer.
    Cancelled,
}

/// What the receiver is told it is about to be handed.
fn describe(source: &SendSource) -> TransferMetadata {
    TransferMetadata {
        content_type: "file".to_string(),
        file_name: source.file_name.clone(),
        file_size: source.estimated_size,
        content_encoding: source.wire_encoding,
        mime_type: source.mime_type.to_string(),
    }
}

/// Wait for a receiver that can authenticate, then send it the file.
///
/// The shutdown signal and the deadline wrap the whole wait rather than just
/// the gaps between connections: a peer that opens the port and then says
/// nothing is exactly when this command most needs to still be interruptible.
async fn serve_one_transfer(
    listener: OnionListener,
    port: u16,
    onion: &str,
    password: &str,
    source: &SendSource,
) -> Result<()> {
    ui::status("Waiting for a receiver...");

    tokio::select! {
        // A signal is how this command is meant to be stopped, so unwind
        // normally: the throwaway Tor storage is only removed by its
        // destructor, which a signal-killed process never runs.
        result = shutdown_signal() => {
            result.context("failed to listen for a shutdown signal")?;
            log::info!("shutting down and removing the Tor client state");
            Ok(())
        }
        _ = tokio::time::sleep(WAIT_TIMEOUT) => bail!(
            "No transfer finished within {} minutes. Start a new transfer.",
            WAIT_TIMEOUT.as_secs() / 60
        ),
        result = serve_until_sent(listener, port, onion, password, source) => result,
    }
}

/// Accept connections until one of them takes the file.
async fn serve_until_sent(
    mut listener: OnionListener,
    port: u16,
    onion: &str,
    password: &str,
    source: &SendSource,
) -> Result<()> {
    let metadata = describe(source);
    let mut failures = 0u32;

    loop {
        let Some(stream) = listener.accept(port).await? else {
            bail!("the onion service stopped accepting connections");
        };

        ui::status("A receiver connected; authenticating...");
        let mut messenger = TorMessenger::new(stream);
        let outcome = serve_connection(&mut messenger, password, onion, &metadata, source).await;
        messenger.shutdown().await;

        match outcome {
            Ok(ServedConnection::Sent) => {
                ui::status("Sent.");
                return Ok(());
            }
            Ok(ServedConnection::Cancelled) => {
                ui::status("The receiver cancelled. Still waiting.");
            }
            // A connection that could not authenticate and one that dropped
            // mid-transfer are both just a connection that did not deliver the
            // file: the address and password are untouched either way, so the
            // receiver can come back, and the count bounds a stranger who
            // found the address from hammering it.
            Err(error) => {
                failures += 1;
                log::warn!("connection failed: {error:#}");
                if failures >= MAX_FAILED_HANDSHAKES {
                    bail!("Giving up after {failures} failed connections. Start a new transfer.");
                }
                ui::status(&format!(
                    "A connection failed ({failures}/{MAX_FAILED_HANDSHAKES}). Still waiting."
                ));
            }
        }
    }
}

/// The sender's side of one accepted connection: authenticate the peer, then
/// hand it the file.
///
/// Only the authentication is on a clock, and a peer that stalls through it is
/// reported as a failed connection — which is what it is — so the caller goes
/// back to waiting for the receiver it is actually expecting.
async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin + Send>(
    messenger: &mut TorMessenger<S>,
    password: &str,
    onion: &str,
    metadata: &TransferMetadata,
    source: &SendSource,
) -> Result<ServedConnection> {
    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        run_service_handshake(messenger, password, onion, metadata),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "the peer went quiet for {}s without authenticating",
            HANDSHAKE_TIMEOUT.as_secs()
        )
    })??;

    match handshake {
        ServiceHandshake::Ready(keys) => {
            ui::status("Receiver authenticated; sending...");
            run_sender(messenger, &keys.content, source, MAX_WIRE_BYTES).await?;
            Ok(ServedConnection::Sent)
        }
        ServiceHandshake::Cancelled => Ok(ServedConnection::Cancelled),
    }
}

/// Connect to `address`, authenticate with `password`, and receive the file.
pub async fn receive(
    address: &str,
    port: u16,
    password: &str,
    output: Option<PathBuf>,
    on_conflict: OnConflict,
) -> Result<()> {
    // Validate both inputs before bootstrapping, which otherwise spends tens of
    // seconds fetching a directory only to reject them afterwards.
    let (host, port) = split_address(address, port)?;
    if !is_valid_pin(password) {
        bail!("Invalid password: check for typos and try again");
    }
    // Exactly the string the sender binds its side of the handshake to.
    let onion = format!("{host}:{port}");

    let tor = EphemeralTorClient::bootstrap().await?;
    ui::status(&format!("Connecting to {onion}..."));
    let stream = tor
        .client()
        .connect((host.as_str(), port))
        .await
        .with_context(|| format!("failed to connect to {onion}"))?;

    let mut messenger = TorMessenger::new(stream);
    let result = receive_over(&mut messenger, password, &onion, output, on_conflict).await;
    messenger.shutdown().await;

    match result? {
        Some(dest) => ui::status(&format!("Saved to {}", dest.display())),
        None => ui::status("Cancelled."),
    }
    Ok(())
}

/// The receiver's side of a connected stream. `Ok(None)` means the transfer was
/// declined at the destination prompt.
async fn receive_over<S: AsyncRead + AsyncWrite + Unpin + Send>(
    messenger: &mut TorMessenger<S>,
    password: &str,
    onion: &str,
    output: Option<PathBuf>,
    on_conflict: OnConflict,
) -> Result<Option<PathBuf>> {
    let ClientHandshake { keys, metadata } =
        run_client_handshake(messenger, password, onion).await?;

    // `file_size` is the sender's input size — a progress hint that bounds
    // nothing on the wire, but a sender offering more than the limit is not
    // worth connecting a transfer for.
    if metadata.file_size > MAX_TRANSFER_BYTES {
        bail!(
            "The sender is offering {}, which exceeds the {} limit of the Tor transport",
            format_bytes(metadata.file_size),
            format_bytes(MAX_TRANSFER_BYTES)
        );
    }
    ui::incoming(
        &metadata.file_name,
        metadata.file_size,
        Some(&metadata.mime_type),
    );

    let Some(dest) = resolve_destination(output, &metadata.file_name, on_conflict).await? else {
        send_cancel(messenger).await?;
        report_receipt(messenger.wait_for_close().await, "cancellation");
        return Ok(None);
    };

    send_ready(messenger).await?;
    run_receiver(
        messenger,
        &keys.content,
        &dest,
        metadata.content_encoding,
        metadata.file_size,
        MAX_WIRE_BYTES,
    )
    .await?;
    // `ACK` is the last frame of the conversation, and this process is about to
    // exit — stay until the sender has it.
    report_receipt(messenger.wait_for_close().await, "confirmation");
    Ok(Some(dest))
}

/// Report whether the sender acknowledged the last frame.
///
/// This is deliberately not propagated. By the time the receiver waits for a
/// receipt its own work is finished and verified — the file is on disk, or the
/// transfer was declined — and the only thing in doubt is whether the sender
/// heard about it. Failing here would tell a script the transfer failed when
/// it did not, and hiding it would leave a sender stuck at the far end with
/// nothing on this side saying so, so it is said out loud instead.
fn report_receipt(result: Result<()>, what: &str) {
    if let Err(error) = result {
        log::warn!("the sender did not acknowledge the {what}: {error:#}");
        ui::status(&format!(
            "Warning: the sender never acknowledged the {what}, so it may still be waiting."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write as _;

    use crate::archive::prepare_send_source;

    const ONION: &str = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion:9735";

    /// Run both sides against each other over an in-memory duplex: everything
    /// the real commands do once Arti has produced a stream.
    async fn transfer(
        password: &str,
        client_password: &str,
        payload: &[u8],
        name: &str,
    ) -> (
        Result<ServedConnection>,
        Result<Option<PathBuf>>,
        PathBuf,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join(name);
        std::fs::File::create(&input)
            .unwrap()
            .write_all(payload)
            .unwrap();
        let output = dir.path().join("out");
        std::fs::create_dir(&output).unwrap();

        let source = prepare_send_source(&[input]).unwrap();
        let metadata = describe(&source);

        let (a, b) = tokio::io::duplex(256 * 1024);
        let (mut service, mut client) = (TorMessenger::new(a), TorMessenger::new(b));

        let password = password.to_string();
        let sent = tokio::spawn(async move {
            serve_connection(&mut service, &password, ONION, &metadata, &source).await
        });
        let received = receive_over(
            &mut client,
            client_password,
            ONION,
            Some(output.clone()),
            OnConflict::Fail,
        )
        .await;

        // The directory is returned so it outlives the caller's assertions.
        let dest = output.join(name);
        (sent.await.unwrap(), received, dest, dir)
    }

    #[tokio::test]
    async fn a_file_round_trips_over_the_framed_stream() {
        // Big enough to span several 128 KiB chunks, and compressible, so the
        // deflate-raw wire encoding is exercised in both directions.
        let payload: Vec<u8> = (0..400_000u32).map(|i| (i % 251) as u8).collect();
        let (sent, received, dest, _dir) =
            transfer("ABCDEFGHJKLA", "ABCDEFGHJKLA", &payload, "big.bin").await;

        assert!(matches!(sent.unwrap(), ServedConnection::Sent));
        assert_eq!(received.unwrap().as_deref(), Some(dest.as_path()));
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
    }

    #[tokio::test]
    async fn a_wrong_password_transfers_nothing() {
        let (sent, received, dest, _dir) =
            transfer("ABCDEFGHJKLA", "ABCDEFGHJKLZ", b"secret", "secret.txt").await;

        assert!(sent.is_err());
        assert!(received.is_err());
        assert!(!dest.exists(), "nothing may be written for a failed handshake");
    }

    #[tokio::test(start_paused = true)]
    async fn a_connection_that_says_nothing_is_dropped_rather_than_waited_on() {
        // Anyone with the address can open the port. Holding it open without
        // speaking used to stop the sender forever: nothing counted it as a
        // failure, and no second receiver could get in behind it.
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("held.txt");
        std::fs::write(&input, b"held").unwrap();
        let source = prepare_send_source(&[input]).unwrap();
        let metadata = describe(&source);

        // `_peer` is the silent connection: held open, never written to.
        let (service, _peer) = tokio::io::duplex(1024);
        let mut messenger = TorMessenger::new(service);
        let error = serve_connection(
            &mut messenger,
            "ABCDEFGHJKLA",
            ONION,
            &metadata,
            &source,
        )
        .await
        .expect_err("a silent peer must not hold the sender");
        assert!(
            error.to_string().contains("went quiet"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn a_receiver_checks_its_inputs_before_bootstrapping() {
        // Neither of these should reach the Tor client: both come back fast
        // rather than after a directory fetch.
        let bad_address = receive("example.com", 9735, "ABCDEFGHJKLA", None, OnConflict::Fail);
        assert!(bad_address.await.is_err());

        let onion = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion";
        let bad_password = receive(onion, 9735, "not-a-password", None, OnConflict::Fail);
        assert!(bad_password.await.is_err());
    }
}
