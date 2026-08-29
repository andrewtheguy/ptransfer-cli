//! Code Exchange's anonymous relay fallback: the rendezvous that lets two
//! peers meet on an onion service neither of them could name in advance.
//!
//! The Tor transport ([`crate::tor`]) is used unchanged and unaware. All this
//! module supplies is the two values that transport normally asks a person to
//! carry, without a person:
//!
//! - The **password** is derived from the ECDH secret the offer/answer
//!   exchange already established, on both devices, and never travels.
//!   [`crate::crypto::spake2::derive_pake_secret`] takes an opaque string, so
//!   derived key material drops into the same handshake unchanged.
//! - The **address** cannot be derived — the Tor client mints an ephemeral
//!   service identity — so it is announced over the encrypted control channel
//!   in [`super::control`], sealed under a key from that same secret.
//!
//! The ordering is the security property, and the sender's own act is what
//! enforces it: the shared secret needs the receiver's public key, which
//! exists only inside a response the sender pasted in, so until then there is
//! nothing published, no address to announce, and no password that would open
//! the handshake.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::archive::SendSource;
use crate::tor::handshake::{ClientHandshake, run_client_handshake, send_ready};
use crate::tor::transfer::{MAX_TRANSFER_BYTES, MAX_WIRE_BYTES, publish_transfer_service, serve_source};
use crate::tor::wire::TorMessenger;
use crate::tor::{self, TorClient};
use crate::transfer::run_receiver;
use crate::ui;
use crate::util::format_bytes;
use crate::wire::TransferMetadata;

use super::control::{
    ControlChannel, ControlChannelConfig, ControlMessage, ControlRole, parse_announced_onion,
};
use super::keys::RelaySession;

/// The relay pool this fallback meets on: the same onion-service relays
/// anonymous PIN Exchange uses, and a constant on both sides — which is why an
/// anonymous offer names no relays at all.
use crate::signaling::anonymous::ANONYMOUS_SIGNALING_RELAYS;

/// How long the receiver waits between polls of the control channel while it
/// waits for the sender to publish. Short enough that the announcement is
/// acted on promptly, long enough to cost nothing.
const ANNOUNCE_POLL: Duration = Duration::from_secs(5);

/// What both directions need to open the session's control channel.
pub struct FallbackContext<'a> {
    pub tor: Arc<TorClient>,
    pub session: &'a RelaySession,
    /// unix seconds: the exchange's start, so a message published while this
    /// side was still bootstrapping is read out of the relay's backlog.
    pub since: u64,
    /// unix seconds: the exchange's deadline, stamped on published events.
    pub expires_at: u64,
}

impl FallbackContext<'_> {
    async fn open_channel(&self, role: ControlRole) -> Result<ControlChannel> {
        ControlChannel::open(
            Arc::clone(&self.tor),
            self.session.transfer_id.clone(),
            self.session.control_key()?,
            role,
            ControlChannelConfig {
                relays: ANONYMOUS_SIGNALING_RELAYS,
                since: self.since,
                expires_at: self.expires_at,
            },
        )
        .await
    }
}

/// Publish the onion service, tell the receiver where it is, and serve the
/// file.
///
/// Nothing before this call has published anything: the service is established
/// here, after the sender accepted a response and after the direct route was
/// found dead, which is what makes "the service is unreachable until the
/// sender takes the response in" true rather than merely intended.
pub async fn serve_over_anonymous_relay(
    context: FallbackContext<'_>,
    password: &str,
    source: &SendSource,
) -> Result<()> {
    ui::status("No direct connection — relaying the file through Tor instead.");

    // Two slow, independent steps on one Tor client: a descriptor publication
    // and a rendezvous to each relay. Run together they cost the longer of the
    // two rather than their sum, and neither can start any earlier.
    let (service, mut channel) = tokio::try_join!(
        publish_transfer_service(&context.tor, tor::DEFAULT_PORT),
        context.open_channel(ControlRole::Sender),
    )?;

    ui::status("Telling the receiver where to find the onion service...");
    let announcement = ControlMessage::Onion {
        // The channel stamps the counter.
        n: 0,
        onion: service.onion().to_string(),
    };
    let sent = channel.send(announcement).await;
    channel.close().await;
    sent.context("The onion address could not be announced to the receiver")?;

    ui::status("Waiting for the receiver over Tor...");
    serve_source(service, password, source).await
}

/// Check in on the control channel, wait for the sender's address, and take
/// the file over Tor.
///
/// The `hello` goes out before there is anything to wait for: it is what tells
/// a sender still watching the control relays that the direct route is dead.
pub async fn receive_over_anonymous_relay(
    context: FallbackContext<'_>,
    password: &str,
    expected: &TransferMetadata,
    dest: &Path,
) -> Result<PathBuf> {
    ui::status("Telling the sender the direct route is dead...");
    let mut channel = context.open_channel(ControlRole::Receiver).await?;

    channel
        .send(ControlMessage::hello())
        .await
        .context("The sender could not be told the direct route is dead")?;

    ui::status("Waiting for the sender to publish its onion service...");
    let onion = wait_for_announcement(&mut channel, context.expires_at).await;
    // The sender is on the channel, so it took the response in: the code has
    // done its job and the screen goes back to reporting the transfer.
    ui::hide_code();
    channel.close().await;
    let (host, port) = parse_announced_onion(&onion?, tor::DEFAULT_PORT)?;
    // Exactly the string the sender binds its side of the handshake to.
    let onion = format!("{host}:{port}");

    ui::status(&format!("Building a circuit to {host}..."));
    let stream = context
        .tor
        .connect(&host, port)
        .await
        .with_context(|| format!("failed to connect to {onion}"))?;

    let mut messenger = TorMessenger::new(stream);
    let result = take_the_file(&mut messenger, password, &onion, expected, dest).await;
    messenger.shutdown().await;
    result?;
    Ok(dest.to_path_buf())
}

/// Wait for the sender's announcement, giving up at the session's deadline.
async fn wait_for_announcement(channel: &mut ControlChannel, expires_at: u64) -> Result<String> {
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        if now >= expires_at {
            bail!("The sender never published an onion service. Start a new transfer.");
        }
        match channel.recv_within(ANNOUNCE_POLL).await {
            Some(ControlMessage::Onion { onion, .. }) => return Ok(onion),
            // The sender's channel is one-way here, so anything else is a
            // message from a session that happens to share this relay.
            Some(ControlMessage::Hello { .. }) | None => {}
        }
    }
}

/// Authenticate with the derived password, check that what is on offer is what
/// the code described, and take the file.
async fn take_the_file<S>(
    messenger: &mut TorMessenger<S>,
    password: &str,
    onion: &str,
    expected: &TransferMetadata,
    dest: &Path,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    ui::status("Authenticating with the sender...");
    let ClientHandshake { keys, metadata } =
        run_client_handshake(messenger, password, onion).await?;

    // Whoever completed the handshake is the sender — the password came out of
    // the ECDH secret, so nobody else could have — which is exactly why this is
    // worth checking. The receiver agreed to take the file the code described
    // and has no other way to notice being handed a different one.
    if let Some(field) = first_mismatch(expected, &metadata) {
        bail!(
            "The sender is offering a file with a different {field} than the code said. \
             Start a new transfer."
        );
    }
    if metadata.file_size > MAX_TRANSFER_BYTES {
        bail!(
            "The sender is offering {}, over the {} limit of the Tor transport.",
            format_bytes(metadata.file_size),
            format_bytes(MAX_TRANSFER_BYTES)
        );
    }

    ui::status("Receiving the file over Tor...");
    send_ready(messenger).await?;
    run_receiver(
        messenger,
        &keys.content,
        dest,
        metadata.content_encoding,
        metadata.file_size,
        MAX_WIRE_BYTES,
    )
    .await?;
    // `ACK` is the last frame of the conversation and the sender is waiting on
    // it; a file already written and verified does not become unreceived
    // because the receipt went missing, so this is reported, not propagated.
    if let Err(error) = messenger.wait_for_close().await {
        log::warn!("the sender did not acknowledge the confirmation: {error:#}");
    }
    Ok(())
}

/// The first thing the handshake's metadata says that the code did not, or
/// `None` when the two describe the same file.
fn first_mismatch(expected: &TransferMetadata, offered: &TransferMetadata) -> Option<&'static str> {
    if offered.file_name != expected.file_name {
        return Some("name");
    }
    if offered.file_size != expected.file_size {
        return Some("size");
    }
    if offered.mime_type != expected.mime_type {
        return Some("type");
    }
    if offered.content_encoding != expected.content_encoding {
        return Some("encoding");
    }
    if offered.content_type != expected.content_type {
        return Some("content type");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::WireEncoding;

    fn metadata() -> TransferMetadata {
        TransferMetadata {
            content_type: "file".to_string(),
            file_name: "report.pdf".to_string(),
            file_size: 1024,
            content_encoding: WireEncoding::DeflateRaw,
            mime_type: "application/pdf".to_string(),
        }
    }

    /// The code is the only description the receiver agreed to. A handshake
    /// that describes something else is a different transfer wearing this
    /// one's password, and the mismatch has to name the field so the operator
    /// can tell that from a network failure.
    #[test]
    fn a_handshake_describing_another_file_is_caught_field_by_field() {
        assert_eq!(first_mismatch(&metadata(), &metadata()), None);

        let mut renamed = metadata();
        renamed.file_name = "other.pdf".to_string();
        assert_eq!(first_mismatch(&metadata(), &renamed), Some("name"));

        let mut resized = metadata();
        resized.file_size = 2048;
        assert_eq!(first_mismatch(&metadata(), &resized), Some("size"));

        let mut retyped = metadata();
        retyped.mime_type = "text/plain".to_string();
        assert_eq!(first_mismatch(&metadata(), &retyped), Some("type"));

        let mut recoded = metadata();
        recoded.content_encoding = WireEncoding::Identity;
        assert_eq!(first_mismatch(&metadata(), &recoded), Some("encoding"));
    }
}
