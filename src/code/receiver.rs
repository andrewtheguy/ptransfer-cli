//! Code Exchange receiver: take an offer in, hand a response back, connect.
//!
//! There is no mode to choose here. What the operator pastes decides
//! everything: the offer says which file is coming, which fallback the sender
//! selected, and — through the public key inside it — what this side agrees a
//! secret with. The response that goes back carries a tag bound to that exact
//! offer and to the response's own fields, which is what lets the sender
//! refuse anything that is not an answer to the code it is showing.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rtc::peer_connection::sdp::RTCSessionDescription;

use crate::crypto::chunk::MAX_MESSAGE_SIZE;
use crate::tor::TorClient;
use crate::transfer::run_receiver;
use crate::ui;
use crate::util::{OnConflict, format_bytes, resolve_destination};
use crate::webrtc::common::{DcMessenger, WebRtcPeer, open_and_detach};
use crate::webrtc::{add_ice_candidate_safely, advertise_max_message_size, candidate_strings};
use crate::wire::TransferMetadata;

use super::control::seconds;
use super::keys::{CodeKeyPair, CodeSecret};
use super::nostr_file::RELAY_MAX_BYTES;
use super::nostr_file::download::{ReceiveContext, receive_over_relays};
use super::nostr_file::pool::FilePool;
use super::payload::{
    self, PayloadKind, SignalingPayload, TRANSFER_EXPIRATION_MS,
};
use super::relay::{FallbackContext, receive_over_anonymous_relay};

/// What the screen says while a simulated dead route waits for the sender,
/// in the web app's words: nothing has begun, and the response is still the
/// only thing that starts it.
const SIMULATED_HOLDING: &str =
    "Simulating no direct connection — waiting for the sender to take in your response.";

const ICE_GATHER_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the direct attempt runs. Longer than the sender's window when a
/// fallback exists, because this side's wait starts before the sender has even
/// been handed the response.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(120);

/// Receive the file an offer code describes.
///
/// `offer_code` is the base64 blob the sender handed over — pasted at a
/// prompt, piped in, or typed into the wizard's receive box.
pub async fn receive_file_code(
    offer_code: &str,
    output_dir: Option<PathBuf>,
    on_conflict: OnConflict,
    simulate_no_direct: bool,
) -> Result<()> {
    let offer = decode_offer(offer_code)?;
    let anonymous = offer.is_anonymous();
    let salt = offer.offer_salt()?;
    let metadata = offer_metadata(&offer)?;
    // The sender's choice, read out of the offer: the relays it named carry
    // the clearnet fallback's control channel, and an offer naming none has no
    // clearnet fallback to run.
    let relays = offer.fallback_relays();
    // Named relays are not enough on their own: past the relay size cap the
    // fallback would refuse the file, so simulating a dead route would kill a
    // working direct connection and leave both sides with nowhere to go.
    if simulate_no_direct
        && !anonymous
        && (relays.is_none() || metadata.file_size > RELAY_MAX_BYTES)
    {
        bail!(
            "This code has no fallback to simulate one into: its sender named no relays \
             this transfer could use and did not select the anonymous option, so a dead \
             direct route ends the transfer."
        );
    }

    // The slow part, started as the offer is taken in rather than once the
    // direct route is known to be dead: by then the sender is already waiting,
    // and a bootstrap is minutes.
    let tor = anonymous.then(|| {
        ui::status("Starting the Tor client for the anonymous fallback...");
        tokio::spawn(async { TorClient::bootstrap().await.map(Arc::new) })
    });

    ui::incoming(
        &metadata.file_name,
        metadata.file_size,
        Some(&metadata.mime_type),
    );
    let Some(dest) = resolve_destination(output_dir, &metadata.file_name, on_conflict).await?
    else {
        if let Some(tor) = tor {
            tor.abort();
        }
        ui::status("Cancelled.");
        return Ok(());
    };

    ui::status("Creating P2P answer...");
    let mut peer = WebRtcPeer::new(ICE_GATHER_TIMEOUT).await?;
    let mut data_channel_rx = peer
        .take_data_channel_rx()
        .context("Data channel receiver already taken")?;

    peer.set_remote_description(
        RTCSessionDescription::offer(offer.sdp.clone()).context("Invalid offer SDP")?,
    )
    .await?;
    for candidate in &offer.candidates {
        add_ice_candidate_safely(&peer, candidate).await;
    }

    let answer = peer.create_answer().await?;
    peer.set_local_description(answer.clone()).await?;
    ui::status("Gathering network candidates...");
    let candidates = candidate_strings(peer.gather_ice_candidates().await?)?;

    // The agreement, and with it every key this transfer uses, comes out of
    // the offer's public key and a key pair minted here.
    //
    // A simulated dead route hands the sender the answer SDP with none of this
    // side's network routes in it: with nothing to connect to and — once the
    // peer connection below is dropped — no agent left here to answer a
    // connectivity check either, the sender's direct attempt fails the way it
    // would behind a hostile NAT, and the fallback runs for real.
    let (response, secret) = build_response(
        &payload::from_clipboard(offer_code)?,
        &offer,
        advertise_max_message_size(answer.sdp),
        if simulate_no_direct {
            Vec::new()
        } else {
            candidates
        },
    )?;

    ui::show_code(
        "Give this response back to the sender:",
        &payload::to_clipboard(&response),
    );

    let opened = if simulate_no_direct {
        ui::status(SIMULATED_HOLDING);
        // Nothing here may answer a connectivity check, or the two sides find
        // each other peer-reflexively and the simulation does not hold.
        let _ = peer.close().await;
        Err(anyhow::anyhow!("the direct route was simulated dead"))
    } else {
        ui::status("Waiting for the sender to take the response in...");
        wait_for_data_channel(&mut data_channel_rx).await
    };

    // The response stays on screen from here until the sender turns up, on
    // whichever route: it is the only thing this transfer is waiting on, and
    // taking it off screen before it has been handed over strands both sides.
    let content_key = secret.content_key(&salt)?;
    match (opened, tor) {
        (Ok(channel), bootstrap) => {
            ui::hide_code();
            if let Some(bootstrap) = bootstrap {
                bootstrap.abort();
            }
            let raw = open_and_detach(channel, CONNECTION_TIMEOUT).await?;
            let info = peer.get_connection_info().await;
            ui::status(&format!("Connected via {}", info.connection_type));
            let mut messenger = DcMessenger::new(raw);
            let result = run_receiver(
                &mut messenger,
                &content_key,
                &dest,
                metadata.content_encoding,
                metadata.file_size,
                MAX_MESSAGE_SIZE,
            )
            .await;
            // Give the sender a moment to read the ACK off the channel before
            // the peer connection goes away underneath it.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = peer.close().await;
            result?;
        }
        (Err(error), None) => {
            log::info!("the direct route did not open: {error:#}");
            let _ = peer.close().await;
            let Some(relays) = relays else {
                ui::hide_code();
                return Err(error);
            };
            if metadata.file_size > RELAY_MAX_BYTES {
                ui::hide_code();
                return Err(error.context(format!(
                    "The file is over {}, so it cannot be relayed through Nostr either.",
                    format_bytes(RELAY_MAX_BYTES)
                )));
            }
            if !simulate_no_direct {
                ui::status(
                    "No direct connection — taking the file through Nostr relays instead. \
                     Hand your response to the sender to start it.",
                );
            }
            let session = secret.relay_session(&salt)?;
            let pool = Arc::new(FilePool::new());
            let received = receive_over_relays(ReceiveContext {
                pool: Arc::clone(&pool),
                session: &session,
                control_relays: relays,
                since: seconds(offer.created_at),
                expires_at: seconds(offer.created_at + TRANSFER_EXPIRATION_MS),
                // The sender may not have been handed the response yet, and a
                // sender that has not been handed it is not silent, it is
                // uninvolved: until its first message only the code's own hour
                // bounds this wait.
                awaiting_handover: true,
                expected_name: metadata.file_name.clone(),
            })
            .await;
            pool.shutdown().await;
            ui::hide_code();
            tokio::fs::write(&dest, received?)
                .await
                .with_context(|| format!("Cannot write {}", dest.display()))?;
        }
        (Err(error), Some(bootstrap)) => {
            log::info!("the direct route did not open: {error:#}");
            let _ = peer.close().await;
            if !simulate_no_direct {
                ui::status(
                    "No direct connection — receiving the file through Tor instead. \
                     Hand your response to the sender to start it.",
                );
            }
            // Announced rather than waited on silently: the bootstrap started
            // behind the direct attempt and is usually done by now, but a cold
            // one is minutes and this is the row that says so.
            let step = ui::status_step("Waiting for the Tor client to finish starting...");
            let tor = bootstrap
                .await
                .context("the Tor client task failed")?
                .context("The anonymous fallback could not reach the Tor network")?;
            step.done("The Tor client is ready");
            let session = secret.relay_session(&salt)?;
            let password = secret.onion_password(&salt)?;
            receive_over_anonymous_relay(
                FallbackContext {
                    tor,
                    session: &session,
                    since: seconds(offer.created_at),
                    expires_at: seconds(offer.created_at + TRANSFER_EXPIRATION_MS),
                },
                &password,
                &metadata,
                &dest,
            )
            .await?;
        }
    }

    ui::status(&format!("Saved to {}", dest.display()));
    Ok(())
}

/// Build the response to an offer, and with it the secret every key of this
/// transfer hangs off.
///
/// The tag has to cover the exact fields being encoded, so the payload is built
/// first, hashed, and only then signed — never signed over values the encoder
/// might not carry, which is what would let the transcript and the encoded
/// response drift apart.
pub(super) fn build_response(
    offer_binary: &[u8],
    offer: &SignalingPayload,
    sdp: String,
    candidates: Vec<String>,
) -> Result<(Vec<u8>, CodeSecret)> {
    let salt = offer.offer_salt()?;
    let keys = CodeKeyPair::generate();
    let public_key = keys.public_key().to_vec();
    let secret = keys.agree(&offer.peer_public_key()?)?;

    let mut response = SignalingPayload {
        kind: PayloadKind::Answer,
        sdp,
        candidates,
        created_at: payload::now_ms(),
        public_key,
        confirm: None,
        file_name: None,
        file_size: None,
        content_encoding: None,
        mime_type: None,
        salt: None,
        relays: None,
        anon: None,
    };
    let tag = secret.answer_confirmation(
        &salt,
        &payload::offer_transcript_hash(offer_binary),
        &payload::answer_transcript_hash(&response)?,
    )?;
    response.confirm = Some(payload::encode_answer_confirmation(&tag));

    Ok((payload::encode(&response)?, secret))
}

/// Wait for the sender to open a data channel, which is the first sign it took
/// the response in at all.
async fn wait_for_data_channel(
    data_channel_rx: &mut tokio::sync::mpsc::Receiver<crate::webrtc::common::RtcDataChannel>,
) -> Result<crate::webrtc::common::RtcDataChannel> {
    tokio::time::timeout(CONNECTION_TIMEOUT, data_channel_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("No direct connection was established"))?
        .context("Sender never opened a data channel")
}

/// Parse and vet a pasted offer before anything is spent on it.
fn decode_offer(offer_code: &str) -> Result<SignalingPayload> {
    let offer = payload::decode(&payload::from_clipboard(offer_code)?)?;
    if offer.kind != PayloadKind::Offer {
        bail!("That is a response code, not a sender's code.");
    }
    payload::check_freshness(offer.created_at)?;
    Ok(offer)
}

/// What the offer says is coming. The anonymous fallback's handshake describes
/// the file a second time, and this is what that description is checked
/// against — the receiver agreed to *this*, and has no other way to notice
/// being handed something else.
fn offer_metadata(offer: &SignalingPayload) -> Result<TransferMetadata> {
    let file_size = offer.file_size.context("the code carries no file size")?;
    if file_size > MAX_MESSAGE_SIZE {
        bail!(
            "Transfer rejected: {} exceeds the {} limit",
            format_bytes(file_size),
            format_bytes(MAX_MESSAGE_SIZE)
        );
    }
    Ok(TransferMetadata {
        content_type: "file".to_string(),
        file_name: offer
            .file_name
            .clone()
            .context("the code names no file")?,
        file_size,
        content_encoding: offer
            .content_encoding
            .context("the code carries no content encoding")?,
        mime_type: offer.mime_type.clone().unwrap_or_default(),
    })
}
