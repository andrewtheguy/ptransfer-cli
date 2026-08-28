//! File transfer over a Tor v3 onion service.
//!
//! The sender publishes a throwaway onion service and mints a one-time
//! password. Those two strings are the whole rendezvous: the receiver needs no
//! signaling relay, no account, and nothing else the sender did not hand it.
//! Tor relays still carry the circuits. Everything after the connection is the
//! shared choreography in [`crate::transfer`],
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
use tokio::time::Instant;

use crate::archive::{SendSource, prepare_send_source_with_cap};
use crate::crypto::pin::{PinKind, classify_pin, generate_pin};
use crate::transfer::{run_receiver, run_sender};
use crate::ui;
use crate::util::{OnConflict, format_bytes, resolve_destination};
use crate::wire::TransferMetadata;

use super::client::TorClient;
use super::handshake::{
    ClientHandshake, ServiceHandshake, run_client_handshake, run_service_handshake, send_cancel,
    send_ready,
};
use tor_proto::client::stream::DataStream;

use super::service::OnionListener;
use super::wire::TorMessenger;
use super::{display_address, shutdown_signal, split_address};

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

/// Name for the transfer service, used only in this process's own logging.
/// There is one service per process and its key is never stored, so nothing
/// ever has to look it up again by name.
const NICKNAME: &str = "ptransfer-transfer";

/// How long the sender waits for a receiver that can authenticate.
///
/// A resource backstop, not a security control: the password is single-use by
/// convention and the address dies with the process either way. It bounds the
/// *wait*, not a transfer — once a peer has proved it knows the password it is
/// the receiver, and cutting its transfer off at an arbitrary minute would be
/// a speed-based size limit in disguise, which this transport deliberately
/// does not have. What polices a transfer is `run_sender`'s stall window.
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
    ui::status("Preparing the files to send...");
    let step = Instant::now();
    let source = tokio::task::spawn_blocking(move || {
        prepare_send_source_with_cap(&paths, MAX_TRANSFER_BYTES)
    })
    .await??;
    ui::status_timed("Prepared the files to send", step.elapsed());
    // A ZIP's headers and entry paths are wire bytes that no file size
    // accounts for, so a selection of many tiny files can pass the input cap
    // and still not fit. Refusing here costs a moment; finding out while
    // producing bytes costs a bootstrap, a handshake, and — with no resume —
    // the whole transfer.
    if source.projected_wire_size > MAX_WIRE_BYTES {
        bail!(
            "This selection needs up to {} on the wire, over the {} the Tor \
             transport allows. Archive overhead grows with the number of \
             files; send fewer of them.",
            format_bytes(source.projected_wire_size),
            format_bytes(MAX_WIRE_BYTES)
        );
    }
    // Advice, not a gate: the transfer goes ahead either way.
    if source.estimated_size > SUGGESTED_MAX_BYTES {
        ui::status(&format!(
            "{} over Tor: speed depends on the circuit, and a transfer that \
             drops starts over. Sending anyway.",
            format_bytes(source.estimated_size)
        ));
    }
    // A PIN's alphabet and checksum, at the ordinary length. The transport's
    // password is not a PIN Exchange PIN and never selects a relay pool, so it
    // is minted — and below, accepted — at exactly one kind rather than either.
    let password = generate_pin(PinKind::Standard)?;

    let tor = TorClient::bootstrap().await?;
    ui::status("Launching the onion service...");
    let mut listener = OnionListener::launch(&tor, NICKNAME)?;
    // Two spellings of one address: the canonical form the handshake binds,
    // and the shorter form the receiver is asked to retype.
    let onion = format!("{}:{}", listener.onion(), port);

    ui::show_tor_address(
        &source.file_name,
        source.estimated_size,
        &display_address(listener.onion(), port),
        &password,
    );
    log::info!("publishing the descriptor; this usually takes under a minute");
    ui::status("Publishing the onion descriptor...");
    let step = Instant::now();
    listener.wait_until_published().await?;
    ui::status_timed("Published the onion descriptor", step.elapsed());
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
/// The shutdown signal wraps everything, transfer included: Ctrl-C is how this
/// command is meant to be stopped, and it has to work while bytes are moving.
/// The deadline does not — it bounds the wait, inside the accept loop, so an
/// authenticated transfer is never cut off by the clock.
async fn serve_one_transfer(
    listener: OnionListener,
    port: u16,
    onion: &str,
    password: &str,
    source: &SendSource,
) -> Result<()> {
    ui::status("Waiting for a receiver...");

    tokio::select! {
        // Unwinding lets the service tell its introduction points it is going
        // away. Nothing has to be cleaned up: the client only ever existed in
        // this process's memory.
        result = shutdown_signal() => {
            result.context("failed to listen for a shutdown signal")?;
            log::info!("shutting down");
            Ok(())
        }
        result = serve_until_sent(listener, port, onion, password, source) => result,
    }
}

/// Where [`serve_until_sent`] gets its streams from.
///
/// A test seam, not an abstraction. The wait deadline lives in the accept loop
/// and must never end up wrapping a transfer — it once did, and the only way
/// to hold that line is to drive the loop without an onion service.
trait StreamSource {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    fn accept(
        &mut self,
        port: u16,
    ) -> impl Future<Output = Result<Option<Self::Stream>>> + Send;
}

impl StreamSource for OnionListener {
    type Stream = DataStream;

    fn accept(
        &mut self,
        port: u16,
    ) -> impl Future<Output = Result<Option<Self::Stream>>> + Send {
        OnionListener::accept(self, port)
    }
}

/// Accept connections until one of them takes the file.
async fn serve_until_sent<L: StreamSource>(
    mut listener: L,
    port: u16,
    onion: &str,
    password: &str,
    source: &SendSource,
) -> Result<()> {
    let metadata = describe(source);
    let mut failures = 0u32;
    let deadline = Instant::now() + WAIT_TIMEOUT;

    loop {
        // The deadline covers waiting for a connection, not only the gaps
        // between them: a service nobody ever reaches is exactly when this
        // most needs to stop on its own. A connection that authenticates
        // leaves it behind — see WAIT_TIMEOUT.
        let accepted = tokio::time::timeout_at(deadline, listener.accept(port))
            .await
            .map_err(|_| {
                anyhow!(
                    "No receiver authenticated within {} minutes. Start a new transfer.",
                    WAIT_TIMEOUT.as_secs() / 60
                )
            })??;
        let Some(stream) = accepted else {
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
    let step = Instant::now();
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
            ui::status_timed("Receiver authenticated", step.elapsed());
            ui::status("Sending...");
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
    if classify_pin(password) != Some(PinKind::Standard) {
        bail!("Invalid password: check for typos and try again");
    }
    // Exactly the string the sender binds its side of the handshake to.
    let onion = format!("{host}:{port}");

    let tor = TorClient::bootstrap().await?;
    ui::status(&format!(
        "Connecting to {}...",
        display_address(&host, port)
    ));
    let step = Instant::now();
    let stream = tor
        .connect(&host, port)
        .await
        .with_context(|| format!("failed to connect to {onion}"))?;
    ui::status_timed("Connected to the onion service", step.elapsed());

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
    ui::status("Authenticating with the sender's password...");
    let step = Instant::now();
    let ClientHandshake { keys, metadata } =
        run_client_handshake(messenger, password, onion).await?;
    ui::status_timed("Authenticated with the sender", step.elapsed());

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

    /// Deterministic bytes that `deflate-raw` cannot shrink.
    ///
    /// Wire chunking is what the round trips below are for, and chunks are
    /// measured on the compressed stream: a counting pattern of this length
    /// deflates to under two kilobytes and arrives as a single chunk, which
    /// exercises none of it. Incompressible input keeps the wire payload the
    /// size of the input, which is several 128 KiB chunks.
    fn incompressible(len: usize) -> Vec<u8> {
        // xorshift64*, from a fixed seed: the same bytes on every run.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        (0..len)
            .map(|_| {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u8
            })
            .collect()
    }

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

    /// The same round trip over a real onion service, which the duplex above
    /// deliberately does not reach: the sender publishes an address and waits
    /// in its accept loop, the receiver builds a rendezvous circuit to it, and
    /// the file arrives having crossed introduction and rendezvous points.
    ///
    /// Ignored by default, like the checks in `tests/tor_network.rs` — this
    /// one talks to the real Tor network:
    ///
    /// ```sh
    /// cargo test -- --ignored --nocapture
    /// ```
    ///
    /// One client plays both roles, which is not how the CLI is used but costs
    /// one directory bootstrap instead of two. Both sides run the production
    /// paths: `serve_until_sent` is the accept loop `tor send` ends in, and
    /// `receive_over` is all of `tor receive` after the connection.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "talks to the real Tor network"]
    async fn a_file_round_trips_over_a_real_onion_service() {
        // The same provider the binary installs. Ignore the error: another
        // test in this process may have got there first.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let port = crate::tor::DEFAULT_PORT;
        // Several 128 KiB chunks on the wire, so chunking and reassembly are
        // exercised over the circuit rather than only in memory.
        let payload = incompressible(400_000);

        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("over-tor.bin");
        std::fs::write(&input, &payload).unwrap();
        let output = dir.path().join("out");
        std::fs::create_dir(&output).unwrap();

        let source = prepare_send_source(&[input]).unwrap();
        let password = generate_pin(PinKind::Standard).unwrap();

        let tor = TorClient::bootstrap()
            .await
            .expect("failed to bootstrap a Tor client");

        let mut listener = OnionListener::launch(&tor, NICKNAME).expect("failed to launch");
        let host = listener.onion().to_owned();
        // The canonical spelling both sides bind their handshake to, built
        // exactly as `send` and `receive` build it.
        let onion = format!("{host}:{port}");
        println!("publishing {onion}");
        listener
            .wait_until_published()
            .await
            .expect("the service never published its descriptor");
        println!("descriptor is up");

        let sender = {
            let (onion, password) = (onion.clone(), password.clone());
            tokio::spawn(async move {
                serve_until_sent(listener, port, &onion, &password, &source).await
            })
        };

        let stream = tor
            .connect(&host, port)
            .await
            .expect("failed to connect to our own onion service");
        let mut messenger = TorMessenger::new(stream);
        let received = receive_over(
            &mut messenger,
            &password,
            &onion,
            Some(output.clone()),
            OnConflict::Fail,
        )
        .await;
        messenger.shutdown().await;

        sender.await.unwrap().expect("the sender failed");
        let dest = received.expect("the receiver failed");
        assert_eq!(dest.as_deref(), Some(output.join("over-tor.bin").as_path()));
        assert_eq!(std::fs::read(dest.unwrap()).unwrap(), payload);
    }

    #[tokio::test]
    async fn a_file_round_trips_over_the_framed_stream() {
        // Big enough to span several 128 KiB chunks on the wire, so chunking
        // and reassembly are exercised in both directions.
        let payload = incompressible(400_000);
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

    /// One stream, then nothing: enough to drive the accept loop once without
    /// an onion service behind it.
    struct OneStream(Option<tokio::io::DuplexStream>);

    impl StreamSource for OneStream {
        type Stream = tokio::io::DuplexStream;

        async fn accept(&mut self, _port: u16) -> Result<Option<Self::Stream>> {
            match self.0.take() {
                Some(stream) => Ok(Some(stream)),
                // The loop must never come back for a second one here: the
                // first connection is the transfer, and it succeeds.
                None => std::future::pending().await,
            }
        }
    }

    /// The wait deadline bounds the wait, never a transfer.
    ///
    /// This is a regression test with a specific history: the deadline once
    /// raced the whole accept loop, so an authenticated transfer still moving
    /// bytes was cancelled 30 minutes after the *wait* began. Virtual time
    /// jumps well past WAIT_TIMEOUT between chunks here while every hand-off
    /// stays inside the stall window, which is the shape that used to fail.
    #[tokio::test(start_paused = true)]
    async fn a_transfer_outlives_the_wait_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("slow.bin");
        // Several chunks, so there are hand-offs to advance the clock between.
        let payload = incompressible(400_000);
        std::fs::write(&input, &payload).unwrap();
        let output = dir.path().join("out");
        std::fs::create_dir(&output).unwrap();
        let source = prepare_send_source(&[input]).unwrap();

        // Roomy enough that the sender's writes never block, so no stall
        // window is ever pending while the clock below jumps.
        let (service_side, client_side) = tokio::io::duplex(4 * 1024 * 1024);

        let received = tokio::spawn(async move {
            let mut client = TorMessenger::new(client_side);
            let ClientHandshake { keys, metadata } =
                run_client_handshake(&mut client, "ABCDEFGHJKLA", ONION)
                    .await
                    .unwrap();
            let dest = output.join(&metadata.file_name);
            send_ready(&mut client).await.unwrap();

            // Authenticated. From here the peer is the receiver, and the wait
            // deadline is no longer anything it has to race — so cross it.
            tokio::time::advance(WAIT_TIMEOUT * 2).await;

            run_receiver(
                &mut client,
                &keys.content,
                &dest,
                metadata.content_encoding,
                metadata.file_size,
                MAX_WIRE_BYTES,
            )
            .await
            .unwrap();
            dest
        });

        let sent = serve_until_sent(
            OneStream(Some(service_side)),
            9735,
            ONION,
            "ABCDEFGHJKLA",
            &source,
        )
        .await;

        sent.expect("the deadline must not cancel an authenticated transfer");
        let dest = received.await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
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
