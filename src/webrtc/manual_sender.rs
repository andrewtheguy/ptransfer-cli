//! Manual-mode sender: create an offer, hand the receiver a PT01 offer code,
//! consume their answer code, connect, and stream the encrypted file.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::RTCPeerConnectionState;

use crate::archive::SendSource;
use crate::crypto::chunk::MAX_MESSAGE_SIZE;
use crate::crypto::ecdh::EcdhKeyPair;
use crate::crypto::kdf::generate_salt;
use crate::signaling::manual::{self, SignalingPayload};
use crate::transfer::run_sender;
use crate::ui;
use crate::webrtc::common::{DcMessenger, WebRtcPeer, open_and_detach};
use crate::webrtc::{advertise_max_message_size, candidate_init, candidate_strings};

/// Time allowed for local ICE gathering before proceeding with what we have.
const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
/// Time allowed for the data channel to open after exchanging codes.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);

/// Send the prepared source using manual (copy/paste) signaling.
pub async fn send_file_manual(source: &SendSource) -> Result<()> {
    let file_size = source.advertised_size();
    let file_size_exact = source.size_is_exact();
    let file_name = source.file_name.clone();
    let mime_type = source.mime_type.to_string();

    if file_size > MAX_MESSAGE_SIZE || source.estimated_size > MAX_MESSAGE_SIZE {
        bail!(
            "File is {}, which exceeds the {} limit",
            crate::util::format_bytes(file_size),
            crate::util::format_bytes(MAX_MESSAGE_SIZE)
        );
    }

    // Generate our ECDH key pair and per-transfer salt.
    let created_at = manual::now_ms();
    let ecdh = EcdhKeyPair::generate()?;
    let salt = generate_salt()?;

    // Set up the WebRTC connection and data channel.
    ui::status("Preparing offer...");
    let mut peer = WebRtcPeer::new(ICE_GATHER_TIMEOUT).await?;
    let data_channel = peer.create_data_channel("file-transfer").await?;

    let offer = peer.create_offer().await?;
    peer.set_local_description(offer.clone()).await?;

    ui::status("Gathering network candidates...");
    let candidates = peer.gather_ice_candidates().await?;
    if candidates.is_empty() {
        bail!("No ICE candidates gathered. Check your network connection.");
    }

    // Build and show the PT01 offer code.
    let offer_payload = SignalingPayload::offer(
        advertise_max_message_size(offer.sdp),
        candidate_strings(candidates)?,
        created_at,
        file_name.clone(),
        file_size,
        file_size_exact,
        mime_type,
        ecdh.public_key_bytes,
        salt,
    );
    let offer_code = manual::encode(&offer_payload)?;
    ui::status(&format!(
        "Ready to send \"{}\" ({} bytes). Give this offer code to the receiver:",
        file_name, file_size
    ));
    ui::show_code("PTRANSFER OFFER", &offer_code);

    // Read the receiver's answer code.
    let answer_code = ui::prompt_code("Paste the receiver's response code:").await?;
    let answer = manual::decode(&answer_code)?;
    if answer.payload_type != "answer" {
        bail!("Expected a response code, but got an offer code");
    }
    if manual::is_expired(created_at) {
        bail!("Session expired. Please start a new transfer.");
    }

    // Derive the shared content key from the receiver's public key.
    let key = ecdh.derive_aes_key(&answer.public_key, &salt)?;

    // Apply the answer.
    let answer_sdp = RTCSessionDescription::answer(answer.sdp).context("Invalid answer SDP")?;
    peer.set_remote_description(answer_sdp).await?;
    for candidate in &answer.candidates {
        peer.add_ice_candidate(candidate_init(candidate)).await?;
    }

    let peer = Arc::new(peer);

    // Wait for the data channel to open, then detach it for large-message I/O.
    ui::status("Connecting...");
    let raw = open_and_detach(data_channel, CONNECTION_TIMEOUT).await?;
    let mut messenger = DcMessenger::new(raw);
    if peer.connection_state() != RTCPeerConnectionState::Connected {
        bail!("Connection failed (state: {:?})", peer.connection_state());
    }

    let info = peer.get_connection_info().await;
    ui::status(&format!("Connected via {}", info.connection_type));

    // Stream the direct file or generate the ZIP into the transfer on demand.
    let result = run_sender(&mut messenger, &key, source).await;

    let _ = peer.close().await;
    result?;

    ui::status("File sent successfully.");
    Ok(())
}
