//! WebRTC transport for peer-to-peer file transfer.

pub mod common;
pub mod nostr_receiver;
pub mod nostr_sender;

pub use nostr_receiver::receive_file_nostr;
pub use nostr_sender::send_file_nostr;

use anyhow::Result;
use rtc::peer_connection::transport::RTCIceCandidateInit;

use crate::webrtc::common::WebRtcPeer;

/// Serialize gathered ICE candidates to their SDP `candidate:` strings - the
/// only field pTransfer transmits and reads.
pub(crate) fn candidate_strings(candidates: Vec<RTCIceCandidateInit>) -> Result<Vec<String>> {
    Ok(candidates.into_iter().map(|candidate| candidate.candidate).collect())
}

/// Rebuild an ICE candidate init from a candidate string. pTransfer
/// applies received candidates with `sdpMid:"0"`, `sdpMLineIndex:0` (the single
/// data-channel m-section), so we do the same.
pub(crate) fn candidate_init(candidate: &str) -> RTCIceCandidateInit {
    RTCIceCandidateInit {
        candidate: candidate.to_string(),
        sdp_mid: Some("0".to_string()),
        sdp_mline_index: Some(0),
        username_fragment: None,
        url: None,
    }
}

/// Match pTransfer's candidate handling: malformed, duplicate, or stale
/// candidates should not abort an otherwise viable WebRTC connection attempt.
pub(crate) async fn add_ice_candidate_safely(peer: &WebRtcPeer, candidate: &str) {
    if let Err(err) = peer.add_ice_candidate(candidate_init(candidate)).await {
        log::warn!("Ignoring ICE candidate error: {err:#}");
    }
}

/// Ensure our outgoing SDP advertises a data-channel `max-message-size` large
/// enough for a full 128 KiB content chunk. webrtc-rs omits this attribute,
/// which would otherwise cap a browser peer's sends at the 64 KiB default and
/// break browser-to-CLI transfers. Matches browsers, which advertise 262144.
pub(crate) fn advertise_max_message_size(sdp: String) -> String {
    if sdp.contains("max-message-size") {
        return sdp;
    }
    let attr = "a=max-message-size:262144\r\n";
    let mut out = String::with_capacity(sdp.len() + attr.len());
    let mut inserted = false;
    for line in sdp.split_inclusive("\r\n") {
        out.push_str(line);
        // Insert after the sctp-port attribute so a= lines stay grouped.
        if !inserted && line.starts_with("a=sctp-port") {
            out.push_str(attr);
            inserted = true;
        }
    }
    if inserted { out } else { sdp }
}
