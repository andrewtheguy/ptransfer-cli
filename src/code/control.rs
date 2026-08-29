//! The encrypted control channel the anonymous fallback meets on.
//!
//! When the direct WebRTC route does not exist, the two sides still hold the
//! ECDH secret their offer/answer exchange produced — but nothing to connect
//! to. The onion service the sender is about to publish has an identity the
//! Tor client mints on the spot, so it cannot be derived, which leaves exactly
//! one thing that has to travel: its address. This channel is what carries it.
//!
//! It rides the same onion-service relay pool anonymous PIN Exchange uses,
//! reached through the same Tor client, as **addressable kind-30078 events**:
//!
//! ```text
//! d          <transferId>:ctl:<role>:<n>     unique per message
//! x          <transferId>:ctl                what both sides subscribe to
//! expiration <unix seconds>                  NIP-40, the session's own clock
//! content    base64( AES-GCM( deflate-raw(JSON), aad ) )
//! aad        ptransfer-nostr-file:v1:ctl:<transferId>:<role>
//! ```
//!
//! The transfer id and the key are derived, never carried (see
//! [`super::keys`]), so a relay sees an opaque tag namespace and ciphertext.
//! The AAD binds every message to the transfer *and* to the sending role, so a
//! receiver's message can never be replayed as a sender's.
//!
//! Only two messages cross it here — the receiver's `hello` and the sender's
//! `onion` announcement — because the anonymous fallback puts the file on an
//! onion service rather than on the relays. The clearnet Nostr file relay the
//! web app can fall back to instead carries its whole transfer over a channel
//! of this shape; this CLI does not implement that path.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::crypto::aes::{self, AES_KEY_LEN};
use crate::signaling::nostr::NostrClient;
use crate::tor::TorClient;
use crate::wire::Inflater;

/// NIP-78 addressable event kind the control channel publishes under, shared
/// with the web app's relay file transfer.
const EVENT_KIND_CONTROL: u16 = 30078;
/// AAD prefix. Shared with the web app's relay transfer, whose control channel
/// this is the same shape as.
const AAD_PREFIX: &str = "ptransfer-nostr-file:v1";
/// Decompression bound for one control body. Two tiny messages cross this
/// channel; the bound only stops a relay from making this process allocate.
const MAX_CONTROL_BYTES: u64 = 256 * 1024;

/// Which side of the channel a message came from. It is part of the AAD and of
/// the `d` tag, so the two directions never overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRole {
    Sender,
    Receiver,
}

impl ControlRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Receiver => "receiver",
        }
    }

    fn peer(self) -> Self {
        match self {
            Self::Sender => Self::Receiver,
            Self::Receiver => Self::Sender,
        }
    }
}

/// The messages this channel carries.
///
/// `hello` is the receiver saying it has given up on the direct route — the
/// same signal the web app's clearnet fallback sends, read by the same watch.
/// `onion` is the sender's answer to it, and the one value of the anonymous
/// fallback that cannot be derived on both sides.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum ControlMessage {
    #[serde(rename = "hello")]
    Hello { n: u64 },
    #[serde(rename = "onion")]
    Onion {
        n: u64,
        /// The exact `<host>.onion:<port>` string both sides bind the Tor
        /// handshake's transcript to.
        onion: String,
    },
}

impl ControlMessage {
    /// The `hello` a receiver publishes as it gives up on the direct route.
    pub fn hello() -> Self {
        Self::Hello { n: 0 }
    }

    fn set_counter(&mut self, counter: u64) {
        match self {
            Self::Hello { n } | Self::Onion { n, .. } => *n = counter,
        }
    }
}

/// An open control channel: a subscription to the peer's messages and a way to
/// publish our own.
pub struct ControlChannel {
    client: NostrClient,
    key: [u8; AES_KEY_LEN],
    transfer_id: String,
    role: ControlRole,
    expires_at: u64,
    counter: u64,
    subscription: SubscriptionId,
    incoming: mpsc::UnboundedReceiver<ControlMessage>,
}

/// Everything the channel needs that is not derived from the session.
pub struct ControlChannelConfig<'a> {
    pub relays: &'a [&'static str],
    /// unix seconds: the subscription's lower bound, so a message published
    /// while this side was still bootstrapping is not missed.
    pub since: u64,
    /// unix seconds: stamped on every event this side publishes.
    pub expires_at: u64,
}

impl ControlChannel {
    /// Connect to the onion relay pool on an existing Tor client and subscribe
    /// to the peer's half of this session.
    ///
    /// The Tor client is shared with the onion service the sender publishes:
    /// a bootstrap is the slow part of this whole path, and doing it twice
    /// would double it for nothing.
    pub async fn open(
        tor: Arc<TorClient>,
        transfer_id: String,
        key: [u8; AES_KEY_LEN],
        role: ControlRole,
        config: ControlChannelConfig<'_>,
    ) -> Result<Self> {
        let client = NostrClient::connect_anonymous_with(Keys::generate(), tor, config.relays)
            .await
            .context("The anonymous fallback could not reach its onion relays")?;

        let filter = Filter::new()
            .kind(Kind::from_u16(EVENT_KIND_CONTROL))
            .custom_tag(SingleLetterTag::lowercase(Alphabet::X), channel_tag(&transfer_id))
            .since(Timestamp::from(config.since));
        let mut notifications = client.notifications();
        let subscription = client.subscribe(filter.clone()).await?;

        let (tx, incoming) = mpsc::unbounded_channel();
        // Backlog first: the peer may have published before this side's Tor
        // bootstrap finished, and on an ephemeral-feeling channel of retained
        // events that message is simply sitting there.
        for event in client.fetch(filter).await.unwrap_or_default() {
            if let Some(message) = open_control_event(&event, &key, &transfer_id, role.peer()) {
                let _ = tx.send(message);
            }
        }

        let peer_role = role.peer();
        let key_for_task = key;
        let id_for_task = transfer_id.clone();
        tokio::spawn(async move {
            loop {
                match notifications.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        if let Some(message) =
                            open_control_event(&event, &key_for_task, &id_for_task, peer_role)
                            && tx.send(message).is_err()
                        {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => return,
                }
            }
        });

        Ok(Self {
            client,
            key,
            transfer_id,
            role,
            expires_at: config.expires_at,
            counter: 0,
            subscription,
            incoming,
        })
    }

    /// Seal, sign, and publish one message. The channel stamps the
    /// per-message counter, so a caller cannot number two messages alike.
    pub async fn send(&mut self, mut message: ControlMessage) -> Result<()> {
        self.counter += 1;
        message.set_counter(self.counter);
        let content = seal(&self.key, &self.transfer_id, self.role, &message)?;
        let tags = vec![
            tag("d", format!("{}:ctl:{}:{}", self.transfer_id, self.role.as_str(), self.counter))?,
            tag("x", channel_tag(&self.transfer_id))?,
            tag("expiration", self.expires_at.to_string())?,
        ];
        let event = self.client.sign(
            EventBuilder::new(Kind::from_u16(EVENT_KIND_CONTROL), content).tags(tags),
        )?;
        self.client.publish(&event).await
    }

    /// The next message from the peer, or `None` once the channel is torn
    /// down. Messages that do not open under this session's key are dropped
    /// without a word — on a public relay they are simply someone else's.
    pub async fn recv(&mut self) -> Option<ControlMessage> {
        self.incoming.recv().await
    }

    /// Wait for the peer's message for at most `timeout`.
    pub async fn recv_within(&mut self, timeout: Duration) -> Option<ControlMessage> {
        tokio::time::timeout(timeout, self.recv()).await.ok().flatten()
    }

    pub async fn close(self) {
        self.client.unsubscribe(&self.subscription).await;
        self.client.disconnect().await;
    }
}

/// The public tag both sides subscribe to. Derived, so it names the session
/// without naming either device.
fn channel_tag(transfer_id: &str) -> String {
    format!("{transfer_id}:ctl")
}

fn control_aad(transfer_id: &str, role: ControlRole) -> String {
    format!("{AAD_PREFIX}:ctl:{transfer_id}:{}", role.as_str())
}

/// JSON → deflate-raw → AES-GCM (transfer- and role-bound AAD) → base64.
fn seal(
    key: &[u8; AES_KEY_LEN],
    transfer_id: &str,
    role: ControlRole,
    message: &ControlMessage,
) -> Result<String> {
    use std::io::Write as _;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&serde_json::to_vec(message)?)?;
    let compressed = encoder.finish()?;
    let sealed = aes::encrypt_with_aad(key, &compressed, control_aad(transfer_id, role).as_bytes())?;
    Ok(BASE64.encode(sealed))
}

fn unseal(
    key: &[u8; AES_KEY_LEN],
    transfer_id: &str,
    role: ControlRole,
    content: &str,
) -> Result<ControlMessage> {
    let sealed = BASE64.decode(content).context("control message is not base64")?;
    let compressed =
        aes::decrypt_with_aad(key, &sealed, control_aad(transfer_id, role).as_bytes())?;
    let mut inflater = Inflater::new(MAX_CONTROL_BYTES);
    let mut json = Vec::new();
    json.extend_from_slice(inflater.push(&compressed)?);
    json.extend_from_slice(inflater.finish()?);
    serde_json::from_slice(&json).context("control message is not one this channel carries")
}

/// The message inside an event, or `None` when it is not one of the peer's.
fn open_control_event(
    event: &Event,
    key: &[u8; AES_KEY_LEN],
    transfer_id: &str,
    peer_role: ControlRole,
) -> Option<ControlMessage> {
    if event.kind != Kind::from_u16(EVENT_KIND_CONTROL) {
        return None;
    }
    // The `d` tag says which direction the message went. It carries no
    // authority — the AAD checked below is what does — but routing on it first
    // keeps this side from trying to open its own messages.
    let d_tag = event
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().map(String::as_str) == Some("d"))
        .and_then(|tag| tag.as_slice().get(1))?;
    if !d_tag.starts_with(&format!("{transfer_id}:ctl:{}:", peer_role.as_str())) {
        return None;
    }
    unseal(key, transfer_id, peer_role, &event.content).ok()
}

fn tag(name: &str, value: impl Into<String>) -> Result<Tag> {
    Tag::parse([name.to_string(), value.into()]).context("invalid Nostr tag")
}

/// Unix seconds from a millisecond stamp, the clock every control event's
/// `since` and `expiration` is read on.
pub fn seconds(ms: i64) -> u64 {
    (ms / 1000).max(0) as u64
}

/// Reject an announcement that is not a v3 onion address before a rendezvous
/// circuit is built for it.
///
/// The seal already proves the message came from the peer, so this is not
/// standing between the transfer and a stranger; it stands between the Tor
/// client and a malformed address, which Arti would otherwise route out
/// through an exit node.
pub fn parse_announced_onion(onion: &str, default_port: u16) -> Result<(String, u16)> {
    if onion.len() > 100 {
        bail!("the announced onion address is not one");
    }
    crate::tor::split_address(onion, default_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSFER_ID: &str = "c05587dba544d9543610d42f7b7b640d";

    #[test]
    fn a_message_round_trips_through_its_own_role() {
        let key = [9u8; AES_KEY_LEN];
        let message = ControlMessage::Onion {
            n: 1,
            onion: "abc.onion:9735".to_string(),
        };
        let sealed = seal(&key, TRANSFER_ID, ControlRole::Sender, &message).unwrap();
        let opened = unseal(&key, TRANSFER_ID, ControlRole::Sender, &sealed).unwrap();
        assert!(matches!(opened, ControlMessage::Onion { onion, .. } if onion == "abc.onion:9735"));
    }

    /// The AAD is what makes a direction unforgeable: a message the receiver
    /// sealed must not open as one of the sender's, even to a holder of the
    /// key, or the announcement could be reflected back.
    #[test]
    fn a_message_does_not_open_as_the_other_direction() {
        let key = [9u8; AES_KEY_LEN];
        let sealed = seal(&key, TRANSFER_ID, ControlRole::Receiver, &ControlMessage::hello()).unwrap();
        assert!(unseal(&key, TRANSFER_ID, ControlRole::Sender, &sealed).is_err());
        assert!(unseal(&key, TRANSFER_ID, ControlRole::Receiver, &sealed).is_ok());
    }

    /// The transfer id is in the AAD too, so a message from another session on
    /// the same relay cannot open here even if the keys ever collided.
    #[test]
    fn a_message_does_not_open_under_another_transfer_id() {
        let key = [9u8; AES_KEY_LEN];
        let sealed = seal(&key, TRANSFER_ID, ControlRole::Receiver, &ControlMessage::hello()).unwrap();
        assert!(unseal(&key, &"a".repeat(32), ControlRole::Receiver, &sealed).is_err());
    }

    #[test]
    fn a_message_sealed_under_another_key_is_refused() {
        let sealed = seal(&[1u8; AES_KEY_LEN], TRANSFER_ID, ControlRole::Sender, &ControlMessage::hello()).unwrap();
        assert!(unseal(&[2u8; AES_KEY_LEN], TRANSFER_ID, ControlRole::Sender, &sealed).is_err());
    }

    /// The wire shape the two implementations meet on: the JSON is what the
    /// web app's control channel parses, tag included.
    #[test]
    fn the_message_shape_is_the_web_apps() {
        assert_eq!(
            serde_json::to_string(&ControlMessage::Hello { n: 3 }).unwrap(),
            r#"{"t":"hello","n":3}"#
        );
        assert_eq!(
            serde_json::to_string(&ControlMessage::Onion {
                n: 1,
                onion: "x.onion:9735".to_string()
            })
            .unwrap(),
            r#"{"t":"onion","n":1,"onion":"x.onion:9735"}"#
        );
    }

    /// Only a real v3 address may become a circuit: Arti routes anything else
    /// out through an exit node, off the onion network entirely.
    #[test]
    fn only_a_v3_onion_address_is_accepted_from_the_peer() {
        let onion = "zrmxlosp6cvmkhxwhx7267wkvqyztsrmloqw76eu4fhn2gsbg5zk4kad.onion";
        assert_eq!(
            parse_announced_onion(&format!("{onion}:9735"), 9735).unwrap(),
            (onion.to_string(), 9735)
        );
        assert!(parse_announced_onion("example.com:80", 9735).is_err());
        assert!(parse_announced_onion(&"a".repeat(200), 9735).is_err());
    }
}
