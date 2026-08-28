//! Live-network checks for the Tor client and for anonymous signaling.
//!
//! Ignored by default: these talk to the real Tor network, take tens of
//! seconds, and fail on a machine with no route to it. Run them deliberately:
//!
//! ```sh
//! cargo test --all-features --test tor_network -- --ignored --nocapture
//! ```
//!
//! The transfer over a real onion service is ignored the same way, but lives
//! with the code it exercises, in `src/tor/transfer.rs`. `cargo test
//! --all-features -- --ignored` runs both.

#![cfg(feature = "tor")]

use nostr_sdk::prelude::*;
use ptransfer_cli::crypto::pin::{
    PinKind, generate_pin, now_ms, pin_bucket, pin_hint_for_bucket, pin_locator,
};
use ptransfer_cli::signaling::nostr::{
    NostrClient, RendezvousPayload, create_rendezvous_event, generate_handshake_nonce,
    parse_rendezvous_event, rendezvous_filter,
};
use ptransfer_cli::tor::TorClient;
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

/// Anonymous signaling end to end against the real pool: bootstrap Tor, open a
/// WebSocket to an onion-service Nostr relay through it, and round-trip the one
/// event the mode actually depends on.
///
/// Publishing is the point rather than an implementation detail. Answering a
/// `REQ` is not the bar for pool membership — signaling has to *write* under a
/// throwaway key, and most onion relays that serve reads refuse exactly that or
/// accept and silently drop. So this publishes a real rendezvous event, tagged
/// with a hint nothing else will collide with, and reads it back by that tag.
/// The event carries a NIP-40 expiration like every rendezvous, so nothing is
/// left behind that would not have been left by a transfer.
///
/// Expect minutes: a cold directory bootstrap, then a full rendezvous (HSDir
/// descriptor fetch, introduction circuit, rendezvous circuit) per relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "talks to the real Tor network"]
async fn anonymous_signaling_round_trips_a_rendezvous_through_an_onion_relay() {
    install_crypto_provider();

    let client = NostrClient::connect(Keys::generate(), PinKind::Anonymous)
        .await
        .expect("failed to reach an onion Nostr relay through Tor");
    println!("connected to the onion relay pool: {:?}", client.relays());

    // A real PIN, so the hint is derived exactly as a sender's would be. The
    // locator carries ~17.3 bits, so a collision with an unrelated transfer in
    // the same bucket is possible; the transfer id below is what makes the
    // assertion exact.
    let pin = generate_pin(PinKind::Anonymous).expect("failed to mint a PIN");
    assert_eq!(pin.len(), 16);
    let bucket = pin_bucket(now_ms());
    let hint = pin_hint_for_bucket(pin_locator(&pin), bucket);

    let payload = RendezvousPayload {
        payload_type: "rendezvous".to_string(),
        transfer_id: format!("test-{}", client.public_key_hex()),
        sender_pubkey: client.public_key_hex(),
        // Not a real SPAKE2 element: nothing claims this rendezvous, and the
        // relay does not read the payload.
        pake_message: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        nonce: generate_handshake_nonce().expect("failed to mint a nonce"),
        relays: Some(client.relays().to_vec()),
    };
    let event = create_rendezvous_event(&client, &payload, &[7_u8; 16], &hint, bucket)
        .expect("failed to build the rendezvous event");

    client
        .publish(&event)
        .await
        .expect("no onion relay accepted the rendezvous event");
    println!("published a rendezvous under hint {hint}");

    let found = client
        .fetch(rendezvous_filter(std::slice::from_ref(&hint)))
        .await
        .expect("failed to fetch by hint")
        .into_iter()
        .filter_map(|event| parse_rendezvous_event(&event))
        .any(|parsed| parsed.transfer_id == payload.transfer_id);
    assert!(found, "the relay did not serve back the rendezvous it accepted");

    client.disconnect().await;
}
