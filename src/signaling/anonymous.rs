//! Anonymous signaling: the PIN Exchange handshake carried to onion-service
//! Nostr relays through this crate's own Tor client.
//!
//! pTransfer's `docs/ANONYMOUS_SIGNALING.md` is the shared specification. Only
//! the socket changes: the same events, subscriptions, signatures, SPAKE2
//! exchange, and sealed payloads travel over it, and nothing above
//! [`crate::signaling::nostr`] knows the difference. What the option removes is
//! the relay's view of both devices' IP addresses. It does not anonymize the
//! transfer as a whole — file bytes still take the same direct WebRTC data
//! channel, so the peer and STUN still learn an address.
//!
//! The pool this reaches is disjoint from the clearnet one, which is what makes
//! the mode agree end to end without a flag in the protocol for either side to
//! lie about: a PIN of one kind published on the other pool cannot be found.
//! Which pool a transfer uses is decided by the PIN's length alone
//! ([`crate::crypto::pin::PinKind`]).
//!
//! One Tor client is shared by every relay socket in a session, but each socket
//! is its own rendezvous — an HSDir descriptor fetch, an introduction circuit,
//! and a rendezvous circuit — which is why the pool is kept small.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_wsocket::Message;
use async_wsocket::message::CloseFrame;
use futures_util::stream::SplitSink;
use futures_util::{Sink, SinkExt, StreamExt};
use nostr_sdk::Url;
use nostr_sdk::pool::ConnectionMode;
use nostr_sdk::pool::transport::error::TransportError;
use nostr_sdk::pool::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use nostr_sdk::util::BoxedFuture;
use tokio_tungstenite::WebSocketStream as TungsteniteSocket;
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tor_proto::client::stream::DataStream;

use crate::tor::TorClient;

/// Relays used for signaling when the sender turns on anonymous signaling,
/// reached as v3 onion services through the Tor client this crate assembles.
///
/// Candidates come from [`0xtrr/onion-service-nostr-relays`][list]. Answering a
/// `REQ` is not enough: signaling has to *write* — the sender's kind-4243
/// rendezvous and both sides' kind-24243 handshakes — under a throwaway key,
/// and most onion relays that serve reads refuse exactly that (paid admission,
/// whitelists) or answer `OK` and then silently drop the event. These are the
/// ones that accepted both kinds from a fresh key and served the rendezvous
/// back. The list is community-maintained and tracks no uptime, so this is a
/// set of candidates that passed on a given day, not a monitored pool; expect
/// this mode to fail more often than ordinary PIN Exchange. Each relay costs
/// its own rendezvous circuit, so it is kept small.
///
/// It must stay identical to pTransfer's `ANONYMOUS_SIGNALING_RELAYS`: the two
/// sides only ever meet on a relay they both hold.
///
/// [list]: https://github.com/0xtrr/onion-service-nostr-relays
pub const ANONYMOUS_SIGNALING_RELAYS: &[&str] = &[
    "ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion",
    "ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion",
];

/// The port an onion relay URL means when it does not say. Onion services have
/// their own port space, so this is the `ws://` default and not a guess about
/// anything listening on the public internet.
const DEFAULT_ONION_RELAY_PORT: u16 = 80;

/// Largest Nostr message this transport will read off a relay socket.
///
/// pTransfer's WASM client caps a relay message at the same figure, and the
/// events that cross it here are a few kilobytes at most: an SDP offer with its
/// ICE candidates is the largest of them. A cap this far above the real traffic
/// exists to bound what a relay can make this process allocate, not to police
/// the protocol.
const MAX_RELAY_MESSAGE_BYTES: usize = 1024 * 1024;

/// How long one relay socket may take to open.
///
/// A whole rendezvous — an HSDir descriptor fetch, an introduction circuit, and
/// a rendezvous circuit — is minutes on a bad day and still the fastest path
/// available, so it gets its own budget rather than being declared dead on the
/// clearnet clock the relay pool would otherwise apply.
const ONION_RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(180);

/// Canonical onion-service relay URL: the mirror image of what a clearnet
/// relay URL has to be.
///
/// Only `ws://<v3 address>.onion` is accepted. `wss://` is refused along with
/// every clearnet host, and that is not an oversight — an onion circuit is
/// already encrypted and authenticated end to end by the key the address
/// commits to, so TLS on top would add nothing this client could meaningfully
/// verify. Refusing clearnet is the stronger half: it is what guarantees an
/// anonymous-signaling socket can never be opened to a host that would see this
/// device's IP address.
///
/// The address is checked in full, checksum included, because Arti routes
/// anything that is not a v3 onion address through an exit node and off the
/// onion network — a typo that survived to here would reach the plain internet.
pub fn normalize_onion_relay_url(raw: &str) -> Result<String> {
    let url = Url::parse(raw.trim()).with_context(|| format!("invalid relay URL {raw:?}"))?;
    let (host, port) = onion_endpoint(&url)?;
    let path = url.path().trim_end_matches('/');
    let port = if port == DEFAULT_ONION_RELAY_PORT {
        String::new()
    } else {
        format!(":{port}")
    };
    Ok(format!("ws://{host}{port}{path}"))
}

/// Split an onion relay URL into the address and port a Tor stream needs.
fn onion_endpoint(url: &Url) -> Result<(String, u16)> {
    if url.scheme() != "ws" {
        bail!(
            "anonymous signaling only speaks ws:// to an onion service, not {:?}",
            url.scheme()
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("an onion relay URL carries no credentials");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("relay URL {url} has no host"))?;
    // `split_address` is where the v3 address is parsed and its checksum
    // checked; it refuses every non-onion host, which is the guarantee this
    // whole function exists for.
    crate::tor::split_address(host, url.port().unwrap_or(DEFAULT_ONION_RELAY_PORT))
}

/// One bootstrapped Tor client, dressed as the WebSocket transport
/// `nostr-sdk`'s relay pool builds its sockets from.
#[derive(Clone)]
pub struct OnionSignalingTransport {
    tor: Arc<TorClient>,
}

impl OnionSignalingTransport {
    pub fn new(tor: Arc<TorClient>) -> Self {
        Self { tor }
    }
}

impl fmt::Debug for OnionSignalingTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `TorClient` is not `Debug` and has nothing worth printing anyway:
        // the trait needs this only so a relay can name its transport in a log
        // line.
        f.write_str("OnionSignalingTransport")
    }
}

impl WebSocketTransport for OnionSignalingTransport {
    /// The relay pool's ping is a WebSocket ping, not a Nostr message, so it
    /// costs two small cells a minute on a circuit that is already open. It
    /// buys the same liveness check and latency reading every clearnet relay
    /// gets, and it keeps this transport from being a special case in the one
    /// place the pool would otherwise treat it as one.
    fn support_ping(&self) -> bool {
        true
    }

    fn connect<'a>(
        &'a self,
        url: &'a Url,
        _mode: &'a ConnectionMode,
        timeout: Duration,
    ) -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), TransportError>> {
        Box::pin(async move {
            // The pool's own budget is a clearnet one; a rendezvous needs
            // longer than it, never less.
            let deadline = timeout.max(ONION_RELAY_CONNECT_TIMEOUT);
            let socket = tokio::time::timeout(deadline, open(&self.tor, url))
                .await
                .map_err(|_| {
                    backend(anyhow!(
                        "no answer from the onion relay {url} within {} seconds",
                        deadline.as_secs()
                    ))
                })?
                .map_err(backend)?;

            let (tx, rx) = socket.split();
            let sink: WebSocketSink = Box::new(OnionSink(tx));
            let stream: WebSocketStream = Box::pin(rx.map(|message| match message {
                Ok(message) => from_tungstenite(message),
                Err(error) => Err(TransportError::backend(error)),
            }));
            Ok((sink, stream))
        })
    }
}

/// Open one onion stream and run the WebSocket handshake inside it.
async fn open(tor: &TorClient, url: &Url) -> Result<TungsteniteSocket<DataStream>> {
    let (host, port) = onion_endpoint(url)?;
    let stream = tor.connect(&host, port).await?;

    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_RELAY_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_RELAY_MESSAGE_BYTES));
    let (socket, _response) =
        tokio_tungstenite::client_async_with_config(url.as_str(), stream, Some(config))
            .await
            .with_context(|| format!("the onion relay {url} refused a WebSocket connection"))?;
    Ok(socket)
}

/// Wrap an [`anyhow::Error`] as the error type the transport trait returns.
///
/// `TransportError::backend` takes a `std::error::Error`, which `anyhow::Error`
/// deliberately is not; the boxed conversion is the way through.
fn backend(error: anyhow::Error) -> TransportError {
    TransportError::Backend(error.into())
}

/// Translate a frame the relay sent into the pool's message type.
///
/// A binary frame is a protocol error rather than a silent drop: Nostr has no
/// use for one, and treating it as an error is what pTransfer's WASM client
/// does. Returning it here ends the socket, and the pool reconnects.
fn from_tungstenite(message: TungsteniteMessage) -> Result<Message, TransportError> {
    match message {
        TungsteniteMessage::Text(text) => Ok(Message::Text(text.to_string())),
        TungsteniteMessage::Ping(data) => Ok(Message::Ping(data.to_vec())),
        TungsteniteMessage::Pong(data) => Ok(Message::Pong(data.to_vec())),
        TungsteniteMessage::Close(frame) => Ok(Message::Close(frame.map(|frame| CloseFrame {
            code: frame.code.into(),
            reason: frame.reason.to_string(),
        }))),
        TungsteniteMessage::Binary(_) | TungsteniteMessage::Frame(_) => Err(backend(anyhow!(
            "the relay sent a binary message on a Nostr socket"
        ))),
    }
}

/// The write half, with the pool's message type converted on its way out.
struct OnionSink(SplitSink<TungsteniteSocket<DataStream>, TungsteniteMessage>);

impl Sink<Message> for OnionSink {
    type Error = TransportError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready_unpin(cx).map_err(TransportError::backend)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.0
            .start_send_unpin(item.into())
            .map_err(TransportError::backend)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.0.poll_flush_unpin(cx).map_err(TransportError::backend)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.0.poll_close_unpin(cx).map_err(TransportError::backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A relay list written into the source is the one relay list that could
    /// reach the network in a form nothing else compares equal to, so it has to
    /// read exactly as it is used.
    #[test]
    fn the_relay_pool_is_written_in_canonical_form() {
        for relay in ANONYMOUS_SIGNALING_RELAYS {
            assert_eq!(&normalize_onion_relay_url(relay).unwrap(), relay);
        }
    }

    /// The pool is small because each entry costs a rendezvous, and a
    /// duplicate would cost one for nothing.
    #[test]
    fn the_relay_pool_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for relay in ANONYMOUS_SIGNALING_RELAYS {
            assert!(seen.insert(*relay), "duplicate relay {relay}");
        }
    }

    /// The whole privacy property rests on this: no URL that would open a
    /// clearnet socket may pass, whatever it claims to be.
    #[test]
    fn only_a_ws_url_to_a_valid_v3_onion_address_is_accepted() {
        let onion = "oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion";

        assert!(normalize_onion_relay_url(&format!("ws://{onion}")).is_ok());
        // TLS on top of an onion circuit adds nothing this client could check.
        assert!(normalize_onion_relay_url(&format!("wss://{onion}")).is_err());
        // Clearnet, in every spelling.
        assert!(normalize_onion_relay_url("wss://relay.damus.io").is_err());
        assert!(normalize_onion_relay_url("ws://relay.damus.io").is_err());
        assert!(normalize_onion_relay_url("ws://127.0.0.1:7777").is_err());
        assert!(normalize_onion_relay_url("http://example.com").is_err());
        // A bad checksum is a typo that would otherwise leave the onion
        // network through an exit node.
        let mut wrong = onion.to_string();
        wrong.replace_range(0..1, "a");
        assert!(normalize_onion_relay_url(&format!("ws://{wrong}")).is_err());
        // v2 addresses are gone, and a subdomain is not this service.
        assert!(normalize_onion_relay_url("ws://abcdefghijklmnop.onion").is_err());
        assert!(normalize_onion_relay_url(&format!("ws://www.{onion}")).is_err());
        // Credentials have no meaning here and would ride in the clear.
        assert!(normalize_onion_relay_url(&format!("ws://user:pw@{onion}")).is_err());
    }

    /// The port is part of the identity of a socket, so it has to survive
    /// canonicalization — and the default has to stay implicit, or the same
    /// relay would appear twice under two spellings.
    #[test]
    fn canonicalization_keeps_a_non_default_port_and_drops_the_default() {
        let onion = "oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion";
        assert_eq!(
            normalize_onion_relay_url(&format!("ws://{onion}:80/")).unwrap(),
            format!("ws://{onion}")
        );
        assert_eq!(
            normalize_onion_relay_url(&format!("ws://{onion}:8080")).unwrap(),
            format!("ws://{onion}:8080")
        );
        // The address is canonicalized too: a different letter case is the
        // same relay and must not open a second circuit.
        assert_eq!(
            normalize_onion_relay_url(&format!("ws://{}", onion.to_uppercase())).unwrap(),
            format!("ws://{onion}")
        );
    }
}
