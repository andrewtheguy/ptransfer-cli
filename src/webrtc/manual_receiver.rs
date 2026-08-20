//! Manual-mode receiver: consume the sender's PT01 offer code, hand back an
//! answer code, connect, and receive the encrypted file to disk.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rtc::peer_connection::sdp::RTCSessionDescription;

use crate::crypto::chunk::MAX_MESSAGE_SIZE;
use crate::crypto::ecdh::EcdhKeyPair;
use crate::signaling::manual::{self, SignalingPayload};
use crate::transfer::run_receiver;
use crate::ui;
use crate::util::{OnConflict, resolve_destination};
use crate::webrtc::common::{DcMessenger, WebRtcPeer, open_and_detach};
use crate::webrtc::{advertise_max_message_size, candidate_init, candidate_strings};

const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);
const OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// Receive a single file using manual (copy/paste) signaling.
///
/// `offer_code` is the sender's PT01 offer; `output_dir` defaults to the
/// current directory.
pub async fn receive_file_manual(
    offer_code: &str,
    output_dir: Option<PathBuf>,
    on_conflict: OnConflict,
) -> Result<()> {
    let offer = manual::decode(offer_code)?;
    if offer.payload_type != "offer" {
        bail!("Expected an offer code, but got a response code");
    }
    if manual::is_expired(offer.created_at) {
        bail!("Offer expired. Ask the sender to create a new one.");
    }

    let file_size = offer
        .file_size
        .context("Offer is missing the transfer size")?;
    let file_size_exact = offer
        .file_size_exact
        .context("Offer is missing the exact-size flag")?;
    let file_name = offer
        .file_name
        .clone()
        .context("Offer is missing the file name")?;
    let mime_type = offer
        .mime_type
        .clone()
        .context("Offer is missing the MIME type")?;
    let salt = offer
        .salt
        .clone()
        .context("Offer is missing the encryption salt")?;

    if file_size_exact && file_size == 0 {
        bail!("Offer describes an empty file");
    }
    if file_size > MAX_MESSAGE_SIZE {
        bail!(
            "Transfer is {}, which exceeds the {} limit",
            crate::util::format_bytes(file_size),
            crate::util::format_bytes(MAX_MESSAGE_SIZE)
        );
    }

    ui::incoming(&file_name, file_size, Some(&mime_type));

    // Resolve the destination up front so no stdin prompt blocks the transfer.
    let dest = match resolve_destination(output_dir, &file_name, on_conflict).await? {
        Some(path) => path,
        None => {
            ui::status("Cancelled.");
            return Ok(());
        }
    };

    // Derive the shared content key from the sender's public key.
    let ecdh = EcdhKeyPair::generate()?;
    let key = ecdh.derive_aes_key(&offer.public_key, &salt)?;

    // Set up WebRTC and apply the offer.
    let mut peer = WebRtcPeer::new(ICE_GATHER_TIMEOUT).await?;
    let mut data_channel_rx = peer
        .take_data_channel_rx()
        .context("Data channel receiver already taken")?;

    let offer_sdp = RTCSessionDescription::offer(offer.sdp.clone()).context("Invalid offer SDP")?;
    peer.set_remote_description(offer_sdp).await?;
    for candidate in &offer.candidates {
        peer.add_ice_candidate(candidate_init(candidate)).await?;
    }

    let answer = peer.create_answer().await?;
    peer.set_local_description(answer.clone()).await?;

    ui::status("Gathering network candidates...");
    let candidates = peer.gather_ice_candidates().await?;
    if candidates.is_empty() {
        bail!("No ICE candidates gathered. Check your network connection.");
    }

    // Build and show the PT01 answer code.
    let answer_payload = SignalingPayload::answer(
        advertise_max_message_size(answer.sdp),
        candidate_strings(candidates)?,
        manual::now_ms(),
        ecdh.public_key_bytes,
    );
    let answer_code = manual::encode(&answer_payload)?;
    ui::status("Send this response code back to the sender:");
    ui::show_code("PTRANSFER RESPONSE", &answer_code);

    let peer = Arc::new(peer);

    // Wait for the sender's data channel.
    ui::status("Connecting...");
    let data_channel = tokio::time::timeout(CONNECTION_TIMEOUT, data_channel_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout. NAT traversal may have failed."))?
        .context("Sender never opened a data channel")?;

    let raw = open_and_detach(data_channel, OPEN_TIMEOUT).await?;
    let mut messenger = DcMessenger::new(raw);

    let info = peer.get_connection_info().await;
    ui::status(&format!("Connected via {}", info.connection_type));

    // Receive the file.
    let result = run_receiver(
        &mut messenger,
        &key,
        &dest,
        file_size_exact.then_some(file_size),
        file_size,
    )
    .await;

    // Give the sender a moment to receive the ACK before we tear down.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = peer.close().await;

    result?;
    ui::status(&format!("Saved to {}", dest.display()));
    Ok(())
}
