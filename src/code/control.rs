//! The anonymous fallback's control channel: the same sealed kind-30078
//! channel the clearnet fallback runs on, carried to the onion relay pool over
//! Tor.
//!
//! Everything about the events — the tags, the AAD, the counter, the sealing —
//! is [`super::nostr_file::control`]'s, because it is one contract with two
//! transports. What differs here is the transport and the vocabulary: this
//! channel rides the onion-service relay pool anonymous PIN Exchange uses,
//! reached through the same Tor client the sender publishes its service on,
//! and only two messages cross it.
//!
//! The clearnet fallback puts the whole file on relays and needs a manifest,
//! availability, and acknowledgements to do it. This one puts the file on an
//! onion service, so the only thing that has to travel is the address the Tor
//! client mints on the spot — plus the receiver's `hello`, which is the same
//! "the direct route is dead" signal both fallbacks send.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::crypto::aes::AES_KEY_LEN;
use crate::signaling::nostr::NostrClient;
use crate::tor::TorClient;

use super::nostr_file::control::{
    build_control_event, channel_tag, control_kind, is_peer_event, seal, unseal,
};

pub use super::nostr_file::control::ControlRole;

/// The messages this channel carries.
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
            .kind(control_kind())
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
        let event = build_control_event(
            self.client.keys(),
            &self.transfer_id,
            self.role,
            self.counter,
            content,
            self.expires_at,
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

/// The message inside an event, or `None` when it is not one of the peer's.
fn open_control_event(
    event: &Event,
    key: &[u8; AES_KEY_LEN],
    transfer_id: &str,
    peer_role: ControlRole,
) -> Option<ControlMessage> {
    if !is_peer_event(event, transfer_id, peer_role) {
        return None;
    }
    let value = unseal(key, transfer_id, peer_role, &event.content).ok()?;
    serde_json::from_value(value).ok()
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

    fn open(
        key: &[u8; AES_KEY_LEN],
        transfer_id: &str,
        role: ControlRole,
        content: &str,
    ) -> Result<ControlMessage> {
        Ok(serde_json::from_value(unseal(key, transfer_id, role, content)?)?)
    }

    #[test]
    fn a_message_round_trips_through_its_own_role() {
        let key = [9u8; AES_KEY_LEN];
        let message = ControlMessage::Onion {
            n: 1,
            onion: "abc.onion:9735".to_string(),
        };
        let sealed = seal(&key, TRANSFER_ID, ControlRole::Sender, &message).unwrap();
        let opened = open(&key, TRANSFER_ID, ControlRole::Sender, &sealed).unwrap();
        assert!(matches!(opened, ControlMessage::Onion { onion, .. } if onion == "abc.onion:9735"));
    }

    /// The AAD is what makes a direction unforgeable: a message the receiver
    /// sealed must not open as one of the sender's, even to a holder of the
    /// key, or the announcement could be reflected back.
    #[test]
    fn a_message_does_not_open_as_the_other_direction() {
        let key = [9u8; AES_KEY_LEN];
        let sealed =
            seal(&key, TRANSFER_ID, ControlRole::Receiver, &ControlMessage::hello()).unwrap();
        assert!(open(&key, TRANSFER_ID, ControlRole::Sender, &sealed).is_err());
        assert!(open(&key, TRANSFER_ID, ControlRole::Receiver, &sealed).is_ok());
    }

    /// The transfer id is in the AAD too, so a message from another session on
    /// the same relay cannot open here even if the keys ever collided.
    #[test]
    fn a_message_does_not_open_under_another_transfer_id() {
        let key = [9u8; AES_KEY_LEN];
        let sealed =
            seal(&key, TRANSFER_ID, ControlRole::Receiver, &ControlMessage::hello()).unwrap();
        assert!(open(&key, &"a".repeat(32), ControlRole::Receiver, &sealed).is_err());
    }

    #[test]
    fn a_message_sealed_under_another_key_is_refused() {
        let sealed = seal(
            &[1u8; AES_KEY_LEN],
            TRANSFER_ID,
            ControlRole::Sender,
            &ControlMessage::hello(),
        )
        .unwrap();
        assert!(open(&[2u8; AES_KEY_LEN], TRANSFER_ID, ControlRole::Sender, &sealed).is_err());
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
