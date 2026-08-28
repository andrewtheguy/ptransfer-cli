//! End-to-end CLI↔CLI transfer over a real (loopback) WebRTC data channel.
//!
//! Both peers use the `rtc` sans-I/O stack, exactly like two CLIs talking to
//! each other. This guards the large-message transfer that the former
//! `webrtc-sctp` transport could deadlock while queueing.
//!
//! The payload is several MiB across two folders, enough to queue many full
//! chunks against an intermittently-idle write loop. A regression would surface
//! as the overall `timeout` below elapsing (a hang) rather than an assertion
//! failure.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ptransfer_cli::archive::{SendSource, prepare_send_source};
use ptransfer_cli::crypto::chunk::MAX_MESSAGE_SIZE;
use ptransfer_cli::transfer::{run_receiver, run_sender};
use ptransfer_cli::webrtc::common::{DcMessenger, WebRtcPeer, open_and_detach};
use ptransfer_cli::wire::WireEncoding;

use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;
use rtc::peer_connection::transport::RTCIceCandidateInit;

/// Fixed content key for the test. The transfer's crypto is exercised
/// end-to-end; the key exchange itself is covered elsewhere.
const TEST_KEY: [u8; 32] = [0x42; 32];

/// Time budget for gathering local ICE candidates.
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
/// Time budget for the data channel to open once signaling is exchanged.
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Overall budget for connecting and streaming the whole payload. A flow-control
/// stall (the bug this guards against) trips this instead of completing.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(90);

/// Deterministic, poorly-compressible bytes. Deflate barely shrinks them, so
/// the generated archive stays large enough to span many chunks and exercise
/// flow control, and every received byte can be checked against the source.
fn pseudo_random(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state >> 24) as u8);
    }
    out
}

fn write_file(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Mirror production's SDP patch: webrtc-rs omits `a=max-message-size`, so both
/// CLIs inject it (see `webrtc::advertise_max_message_size`). Kept in sync here
/// so the negotiated message size matches a real CLI↔CLI session.
fn advertise_max_message_size(sdp: String) -> String {
    if sdp.contains("max-message-size") {
        return sdp;
    }
    let attr = "a=max-message-size:262144\r\n";
    let mut out = String::with_capacity(sdp.len() + attr.len());
    let mut inserted = false;
    for line in sdp.split_inclusive("\r\n") {
        out.push_str(line);
        if !inserted && line.starts_with("a=sctp-port") {
            out.push_str(attr);
            inserted = true;
        }
    }
    if inserted { out } else { sdp }
}

fn candidate_init(candidate: &str) -> RTCIceCandidateInit {
    RTCIceCandidateInit {
        candidate: candidate.to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
        username_fragment: None,
        url: None,
    }
}

async fn candidate_strings(peer: &mut WebRtcPeer) -> Vec<String> {
    let candidates = peer.gather_ice_candidates().await.unwrap();
    assert!(!candidates.is_empty(), "no ICE candidates gathered");
    candidates
        .iter()
        .map(|c| c.candidate.clone())
        .collect()
}

/// Establish a connected data channel between two webrtc-rs peers over loopback
/// using vanilla (non-trickle) ICE, and return both ends as `DcMessenger`s. The
/// peers are returned so their connections stay alive for the transfer.
async fn connect_pair() -> (Arc<WebRtcPeer>, DcMessenger, Arc<WebRtcPeer>, DcMessenger) {
    let mut sender = WebRtcPeer::new(ICE_GATHER_TIMEOUT).await.unwrap();
    let mut receiver = WebRtcPeer::new(ICE_GATHER_TIMEOUT).await.unwrap();
    let mut incoming_dc = receiver.take_data_channel_rx().unwrap();

    // Sender: offer + local candidates.
    let data_channel = sender.create_data_channel("file-transfer").await.unwrap();
    let offer = sender.create_offer().await.unwrap();
    sender.set_local_description(offer.clone()).await.unwrap();
    let sender_candidates = candidate_strings(&mut sender).await;

    // Receiver: apply offer, answer + local candidates.
    let offer_sdp =
        RTCSessionDescription::offer(advertise_max_message_size(offer.sdp)).unwrap();
    receiver.set_remote_description(offer_sdp).await.unwrap();
    for c in &sender_candidates {
        receiver.add_ice_candidate(candidate_init(c)).await.unwrap();
    }
    let answer = receiver.create_answer().await.unwrap();
    receiver.set_local_description(answer.clone()).await.unwrap();
    let receiver_candidates = candidate_strings(&mut receiver).await;

    // Sender: apply answer + remote candidates.
    let answer_sdp =
        RTCSessionDescription::answer(advertise_max_message_size(answer.sdp)).unwrap();
    sender.set_remote_description(answer_sdp).await.unwrap();
    for c in &receiver_candidates {
        sender.add_ice_candidate(candidate_init(c)).await.unwrap();
    }

    // Open + detach both ends for large-message I/O.
    let sender = Arc::new(sender);
    let receiver = Arc::new(receiver);

    let sender_raw = open_and_detach(data_channel, OPEN_TIMEOUT).await.unwrap();
    let sender_msg = DcMessenger::new(sender_raw);

    let incoming = tokio::time::timeout(OPEN_TIMEOUT, incoming_dc.recv())
        .await
        .expect("receiver never saw a data channel")
        .expect("data channel sender dropped");
    let receiver_raw = open_and_detach(incoming, OPEN_TIMEOUT).await.unwrap();
    let receiver_msg = DcMessenger::new(receiver_raw);

    assert_eq!(
        sender.connection_state(),
        RTCPeerConnectionState::Connected,
        "sender peer did not reach Connected"
    );

    // The channel must be *ordered*. `rtc` derives its data-channel parameters
    // from a plain `Default`, so an omitted `RTCDataChannelInit` silently
    // negotiates reliable-unordered; the answering side's view here is decoded
    // from the DCEP the offerer actually sent, so it catches that on the wire.
    // Loopback never reorders, so nothing else in this test would notice —
    // against a browser it corrupts every transfer that outlives one
    // retransmit.
    assert!(
        sender_msg.is_ordered().await.unwrap(),
        "offered data channel is not ordered"
    );
    assert!(
        receiver_msg.is_ordered().await.unwrap(),
        "answered data channel is not ordered"
    );

    (sender, sender_msg, receiver, receiver_msg)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_folder_zip_streams_cli_to_cli_without_stalling() {
    let _ = env_logger::try_init();
    // The DTLS transport needs a process-level Rustls crypto provider, exactly
    // as `main` installs one. Ignore the error if a prior test already did.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    // Two folders totaling ~12 MiB — ~96 full 131102-byte wire chunks, each one
    // an opportunity to hit the oversized-message pending-queue deadlock.
    let files: &[(&str, u64, usize)] = &[
        ("dir_a/f1.bin", 1, 4 * 1024 * 1024),
        ("dir_a/sub/f2.bin", 2, 3 * 1024 * 1024 + 777),
        ("dir_b/f3.bin", 3, 5 * 1024 * 1024 + 123),
    ];
    let mut expected: Vec<(String, Vec<u8>)> = Vec::new();
    for (rel, seed, len) in files {
        let bytes = pseudo_random(*seed, *len);
        write_file(&src.path().join(rel), &bytes);
        expected.push((rel.to_string(), bytes));
    }

    let inputs: Vec<PathBuf> = vec![src.path().join("dir_a"), src.path().join("dir_b")];
    let source: SendSource = prepare_send_source(&inputs).unwrap();
    // Multiple folders take the lazy-ZIP path: already compressed entry by
    // entry, so the archive travels as-is.
    assert_eq!(source.wire_encoding, WireEncoding::Identity);
    let estimated = source.estimated_size;
    let dest = dst.path().join("received.zip");

    let (sender_peer, mut sender_msg, receiver_peer, mut receiver_msg) = connect_pair().await;

    let send = async { run_sender(&mut sender_msg, &TEST_KEY, &source, MAX_MESSAGE_SIZE).await };
    let recv = async {
        run_receiver(
            &mut receiver_msg,
            &TEST_KEY,
            &dest,
            WireEncoding::Identity,
            estimated,
            MAX_MESSAGE_SIZE,
        )
        .await
    };

    let outcome = tokio::time::timeout(TRANSFER_TIMEOUT, async { tokio::try_join!(send, recv) })
        .await
        .expect("CLI↔CLI transfer stalled: did not finish within the time budget");
    outcome.expect("transfer returned an error");

    let _ = sender_peer.close().await;
    let _ = receiver_peer.close().await;

    // The received archive must unzip to exactly the source files.
    let bytes = std::fs::read(&dest).unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    assert_eq!(archive.len(), expected.len(), "unexpected entry count");

    let mut seen: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let name = entry.name().to_string();
        let mut content = Vec::new();
        entry.read_to_end(&mut content).unwrap();
        seen.push((name, content));
    }
    seen.sort_by(|a, b| a.0.cmp(&b.0));

    let mut want = expected;
    want.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(seen.len(), want.len());
    for ((got_name, got_bytes), (want_name, want_bytes)) in seen.iter().zip(want.iter()) {
        assert_eq!(got_name, want_name, "entry name mismatch");
        assert_eq!(
            got_bytes.len(),
            want_bytes.len(),
            "entry {got_name} length mismatch"
        );
        assert!(got_bytes == want_bytes, "entry {got_name} content mismatch");
    }
}

/// The single-file path: deflated on the wire by the sender, inflated by the
/// receiver, over a real data channel. This is the leg that has to interoperate
/// with the browser's CompressionStream/DecompressionStream, so it is checked
/// end to end rather than only at the codec. That the wire payload really is
/// compressed is covered by `archive::tests::single_file_stream_is_a_raw_deflate_stream`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_file_deflates_on_the_wire_and_inflates_on_receipt() {
    let _ = env_logger::try_init();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let src = tempfile::tempdir().unwrap();
    let dst = tempfile::tempdir().unwrap();

    // Hex text: compressible enough that the wire payload is unmistakably
    // smaller than the file — deflate halves it at best — while keeping enough
    // entropy that the deflated stream still spans dozens of chunks. A payload
    // that merely repeats itself would deflate to a single chunk and exercise
    // none of the flow control this test guards.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut plain = Vec::with_capacity(8 * 1024 * 1024);
    for byte in pseudo_random(4, 4 * 1024 * 1024) {
        plain.push(HEX[usize::from(byte >> 4)]);
        plain.push(HEX[usize::from(byte & 0x0f)]);
    }
    let input = src.path().join("report.log");
    write_file(&input, &plain);

    let source: SendSource = prepare_send_source(&[input]).unwrap();
    // A single file is always deflated, whatever it contains.
    assert_eq!(source.wire_encoding, WireEncoding::DeflateRaw);
    assert_eq!(source.estimated_size, plain.len() as u64);
    let dest = dst.path().join("report.log");

    let (sender_peer, mut sender_msg, receiver_peer, mut receiver_msg) = connect_pair().await;

    let send = async { run_sender(&mut sender_msg, &TEST_KEY, &source, MAX_MESSAGE_SIZE).await };
    let recv = async {
        run_receiver(
            &mut receiver_msg,
            &TEST_KEY,
            &dest,
            WireEncoding::DeflateRaw,
            source.estimated_size,
            MAX_MESSAGE_SIZE,
        )
        .await
    };

    let outcome = tokio::time::timeout(TRANSFER_TIMEOUT, async { tokio::try_join!(send, recv) })
        .await
        .expect("CLI\u{2194}CLI transfer stalled: did not finish within the time budget");
    outcome.expect("transfer returned an error");

    let _ = sender_peer.close().await;
    let _ = receiver_peer.close().await;

    assert_eq!(std::fs::read(&dest).unwrap(), plain, "payload did not survive");
}
