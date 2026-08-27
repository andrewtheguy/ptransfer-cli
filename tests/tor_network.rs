//! Live-network checks for the Tor transport.
//!
//! Ignored by default: these talk to the real Tor network, take tens of
//! seconds, and fail on a machine with no route to it. Run them deliberately:
//!
//! ```sh
//! cargo test --all-features --test tor_network -- --ignored --nocapture
//! ```

#![cfg(feature = "tor")]

use ptransfer_cli::tor::service::OnionListener;
use ptransfer_cli::tor::{DEFAULT_PORT, TorClient};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tor_netdir::{NetDirProvider as _, Timeliness};

/// Install the same crypto provider the binary installs.
fn install_crypto_provider() {
    // Ignore the error: another test in this process may have got there first.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// The whole point of the rewrite: a client that reaches the network with
/// nothing on disk. If the consensus, the authority certificates and the
/// microdescriptors all check out, this returns a directory big enough to
/// build circuits from.
// Arti's managers run background tasks that expect to make progress while the
// test's own future is blocked on the network, so this needs a real scheduler
// rather than the current-thread runtime `#[tokio::test]` defaults to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "talks to the real Tor network"]
async fn the_client_bootstraps_a_directory_from_the_live_network() {
    install_crypto_provider();

    let tor = TorClient::bootstrap()
        .await
        .expect("failed to bootstrap a Tor client");

    let netdir = tor
        .netdir_provider()
        .netdir(Timeliness::Strict)
        .expect("the freshly downloaded directory should be timely");

    // A live consensus lists thousands of relays; anything in the hundreds
    // means we assembled a real directory rather than a stub.
    let relays = netdir.relays().count();
    println!("directory holds {relays} relays");
    assert!(relays > 500, "only {relays} relays in the directory");

    // The consensus we accepted has to be one we are inside the lifetime of.
    let lifetime = netdir.lifetime();
    let now = std::time::SystemTime::now();
    assert!(lifetime.valid_after() <= now && now <= lifetime.valid_until());
}

/// The onion service end to end: publish an address, then reach it and get
/// bytes back over the rendezvous circuit.
///
/// One client plays both roles. That is not how the CLI is used, but it
/// exercises everything the service side has to get right — introduction
/// points, descriptor signing and upload, the INTRODUCE2/RENDEZVOUS1
/// handshake — without paying for a second directory bootstrap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "talks to the real Tor network"]
async fn a_published_service_answers_a_client() {
    install_crypto_provider();

    let tor = TorClient::bootstrap()
        .await
        .expect("failed to bootstrap a Tor client");

    let mut listener = OnionListener::launch(&tor, "ptransfer-test").expect("failed to launch");
    let address = listener.onion().to_owned();
    println!("published as {address}");
    listener
        .wait_until_published()
        .await
        .expect("the service never published its descriptor");
    println!("descriptor is up");

    // Echo one line back, then let the connection go.
    let service = tokio::spawn(async move {
        let stream = listener
            .accept(DEFAULT_PORT)
            .await
            .expect("failed to accept")
            .expect("the service stopped accepting");
        let (reader, mut writer) = stream.split();
        let mut line = String::new();
        BufReader::new(reader)
            .read_line(&mut line)
            .await
            .expect("failed to read the client's line");
        writer
            .write_all(line.as_bytes())
            .await
            .expect("failed to echo");
        writer.flush().await.expect("failed to flush");
        let _ = writer.shutdown().await;
    });

    let stream = tor
        .connect(&address, DEFAULT_PORT)
        .await
        .expect("failed to connect to our own onion service");
    let (reader, mut writer) = stream.split();
    writer.write_all(b"hello\n").await.expect("failed to send");
    writer.flush().await.expect("failed to flush");

    let mut echoed = String::new();
    BufReader::new(reader)
        .read_line(&mut echoed)
        .await
        .expect("failed to read the echo");
    assert_eq!(echoed, "hello\n");

    service.await.expect("the service task panicked");
}
