//! The encrypted control channel both fallbacks meet on, and the vocabulary
//! the clearnet one speaks over it.
//!
//! Addressable kind-30078 events on the relays the offer named:
//!
//! ```text
//! d          <transferId>:ctl:<role>:<n>     unique per message
//! x          <transferId>:ctl                what both sides subscribe to
//! expiration <unix seconds>                  NIP-40
//! content    base64( AES-GCM( deflate-raw(JSON), aad ) )
//! aad        ptransfer-nostr-file:v1:ctl:<transferId>:<role>
//! ```
//!
//! The key and the transfer id are derived from the exchange's ECDH secret and
//! never travel, so a relay sees an opaque tag namespace and ciphertext. The
//! AAD binds every message to the transfer *and* to the sending role, so a
//! receiver's message can never be replayed as a sender's, and the per-side
//! counter `n` is what refuses a replay within one role.
//!
//! Because the events are stored rather than ephemeral, a side that joins late
//! — or whose socket dropped — reads what it missed out of the backlog through
//! the subscription's `since`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, mpsc};

use crate::crypto::aes::{self, AES_KEY_LEN};
use crate::wire::Inflater;

use super::manifest::NostrFileManifest;
use super::pool::FilePool;
use super::{
    CONTROL_DEMOTE_FAILURE_RATIO, CONTROL_DEMOTE_MIN_PUBLISHES, CONTROL_MESSAGE_MAX_BYTES,
    CONTROL_RELAY_MAX, EVENT_KIND_FILE_CHUNK, NOSTR_FILE_AAD_PREFIX, PUBLISH_BACKOFF_BASE,
    PUBLISH_MAX_RETRIES, UPLOAD_RELAY_COUNT,
};

/// Which side of the channel a message came from. Part of the AAD and of the
/// `d` tag, so the two directions never overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRole {
    Sender,
    Receiver,
}

impl ControlRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sender => "sender",
            Self::Receiver => "receiver",
        }
    }

    pub fn peer(self) -> Self {
        match self {
            Self::Sender => Self::Receiver,
            Self::Receiver => Self::Sender,
        }
    }
}

/// One character per ring position, which is what bounds an announcement's
/// map to 64 relays however many the ring holds.
const POSITION_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode_position(position: usize) -> Result<char> {
    POSITION_ALPHABET
        .get(position)
        .map(|byte| *byte as char)
        .with_context(|| format!("ring position {position} is past what a map can encode"))
}

/// The ring position a map character names, or `None` when it is not one.
pub fn decode_position(character: char) -> Option<usize> {
    POSITION_ALPHABET
        .iter()
        .position(|byte| *byte as char == character)
}

/// Where one chunk was placed: its index, the ring position of the relay
/// holding it, and the re-send generation (0 is the first placement).
pub type ChunkPlacement = (usize, usize, u64);

/// Sender to receiver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum SenderMessage {
    /// First message: what is being relayed. Sized state on the receiving side
    /// hangs off it, so an `avail` that arrives before it is refused.
    Manifest {
        n: u64,
        manifest: Box<NostrFileManifest>,
    },
    /// Chunks `[0, upto)` are uploaded. `relays` is the ring in placement
    /// order — empty while storage discovery is still running, which announces
    /// presence and nothing else — `map` names, per chunk, the position in
    /// *this message's* ring of the relay holding it, and `gens` lists the
    /// chunks that were re-sent with their current generation.
    ///
    /// `ctl` is the sender's current control set: the relays the offer named
    /// minus the ones it has demoted, plus the replacements it promoted in
    /// their place. The receiver takes on whatever of it it does not already
    /// hold, which is how a relay the offer never named reaches it — over the
    /// signaling relays that still work.
    ///
    /// The whole ring, placement, and control set travel in every
    /// announcement, so a lost one costs nothing: a swap the receiver missed
    /// is repeated on the next heartbeat rather than needing an
    /// acknowledgement of its own.
    Avail {
        n: u64,
        upto: usize,
        relays: Vec<String>,
        map: String,
        gens: Vec<(usize, u64)>,
        ctl: Vec<String>,
    },
    Cancel {
        n: u64,
    },
}

/// Receiver to sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ReceiverMessage {
    /// The receiver is online and subscribed, and its own direct attempt is
    /// over — which is what lets a sender still trying cut that attempt short.
    Hello { n: u64 },
    /// The outcome of fetching what one `avail` announced: how many chunks are
    /// held, and which ones were tried at a named placement and not found.
    Ack {
        n: u64,
        avail: u64,
        have: usize,
        missing: Vec<ChunkPlacement>,
    },
    /// The whole file is assembled and its hash verified.
    Done { n: u64 },
    Cancel { n: u64 },
}

impl SenderMessage {
    fn set_counter(&mut self, counter: u64) {
        match self {
            Self::Manifest { n, .. } | Self::Avail { n, .. } | Self::Cancel { n } => *n = counter,
        }
    }

    pub fn counter(&self) -> u64 {
        match self {
            Self::Manifest { n, .. } | Self::Avail { n, .. } | Self::Cancel { n } => *n,
        }
    }

    /// Everything an announcement has to say about itself, checked against the
    /// ring travelling in the same message rather than against anything this
    /// side remembers. `total_chunks` is `None` until the manifest has
    /// arrived, and an announcement before that has nothing to be bounded by.
    pub fn validate(&self, total_chunks: Option<usize>) -> Result<()> {
        let Self::Avail {
            upto,
            relays,
            map,
            gens,
            ctl,
            ..
        } = self
        else {
            return Ok(());
        };
        let Some(total) = total_chunks else {
            bail!("an announcement arrived before the manifest it depends on");
        };
        if relays.len() > UPLOAD_RELAY_COUNT {
            bail!("the announced ring is larger than a ring may be");
        }
        let mut seen = std::collections::HashSet::new();
        for relay in relays {
            let normalized = super::relays::normalize_relay_url(relay)
                .context("the announced ring names something that is not a relay")?;
            // Positions index into this list, so the same relay under two URL
            // forms would make one position mean two things.
            if !seen.insert(normalized) {
                bail!("the announced ring names one relay twice");
            }
        }
        // A control set is never empty: the sender published this very message
        // over it, and its demotion stops at MIN_CONTROL_RELAYS. The cap is
        // what bounds the sockets an announcement can make this side open.
        if ctl.is_empty() || ctl.len() > CONTROL_RELAY_MAX {
            bail!("the announced control set is not a control set");
        }
        let mut seen = std::collections::HashSet::new();
        for relay in ctl {
            let normalized = super::relays::normalize_relay_url(relay)
                .context("the announced control set names something that is not a relay")?;
            if !seen.insert(normalized) {
                bail!("the announced control set names one relay twice");
            }
        }
        if *upto > total {
            bail!("more pieces were announced than the manifest describes");
        }
        if relays.is_empty() && *upto > 0 {
            bail!("pieces were announced with no ring to have placed them on");
        }
        if map.chars().count() != *upto {
            bail!("the announced placement map does not cover what it announces");
        }
        for character in map.chars() {
            match decode_position(character) {
                Some(position) if position < relays.len() => {}
                _ => bail!("the announced placement map names a relay outside the ring"),
            }
        }
        if gens.len() > *upto {
            bail!("more re-sends were announced than there are pieces");
        }
        for (index, generation) in gens {
            if *index >= *upto || *generation < 1 {
                bail!("a re-send was announced for a piece that was not");
            }
        }
        Ok(())
    }
}

impl ReceiverMessage {
    fn set_counter(&mut self, counter: u64) {
        match self {
            Self::Hello { n } | Self::Ack { n, .. } | Self::Done { n } | Self::Cancel { n } => {
                *n = counter
            }
        }
    }

    pub fn counter(&self) -> u64 {
        match self {
            Self::Hello { n } | Self::Ack { n, .. } | Self::Done { n } | Self::Cancel { n } => *n,
        }
    }

    pub fn validate(&self, total_chunks: usize, relay_count: usize) -> Result<()> {
        let Self::Ack { have, missing, .. } = self else {
            return Ok(());
        };
        if *have > total_chunks || missing.len() > total_chunks {
            bail!("the acknowledgement claims more pieces than there are");
        }
        for (index, position, _) in missing {
            if *index >= total_chunks || *position >= relay_count {
                bail!("the acknowledgement names a piece or a relay this transfer has not");
            }
        }
        Ok(())
    }
}

/// The public tag both sides subscribe to. Derived, so it names the session
/// without naming either device.
pub fn channel_tag(transfer_id: &str) -> String {
    format!("{transfer_id}:ctl")
}

fn control_aad(transfer_id: &str, role: ControlRole) -> String {
    format!("{NOSTR_FILE_AAD_PREFIX}:ctl:{transfer_id}:{}", role.as_str())
}

/// JSON -> deflate-raw -> AES-GCM (transfer- and role-bound AAD) -> base64.
pub fn seal<T: Serialize>(
    key: &[u8; AES_KEY_LEN],
    transfer_id: &str,
    role: ControlRole,
    message: &T,
) -> Result<String> {
    use std::io::Write as _;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&serde_json::to_vec(message)?)?;
    let compressed = encoder.finish()?;
    let sealed = aes::encrypt_with_aad(key, &compressed, control_aad(transfer_id, role).as_bytes())?;
    Ok(BASE64.encode(sealed))
}

/// The JSON a sealed message carries, still untyped: what opened under this
/// transfer's key and this role's AAD, bounded on the way out so a relay
/// cannot make this process allocate.
pub fn unseal(
    key: &[u8; AES_KEY_LEN],
    transfer_id: &str,
    role: ControlRole,
    content: &str,
) -> Result<Value> {
    let sealed = BASE64.decode(content).context("control message is not base64")?;
    let compressed =
        aes::decrypt_with_aad(key, &sealed, control_aad(transfer_id, role).as_bytes())?;
    let mut inflater = Inflater::new(CONTROL_MESSAGE_MAX_BYTES);
    let mut json = Vec::new();
    json.extend_from_slice(inflater.push(&compressed)?);
    json.extend_from_slice(inflater.finish()?);
    serde_json::from_slice(&json).context("control message is not JSON")
}

pub fn control_kind() -> Kind {
    Kind::from_u16(EVENT_KIND_FILE_CHUNK)
}

/// The unsigned control event. Signing is the caller's, so an identity that
/// belongs to a client — the Code Exchange channel signs as its signaling
/// client — never has to be handed out to be used here.
pub fn build_control_event(
    transfer_id: &str,
    role: ControlRole,
    counter: u64,
    content: String,
    expires_at: u64,
) -> Result<EventBuilder> {
    let tags = vec![
        control_tag("d", format!("{transfer_id}:ctl:{}:{counter}", role.as_str()))?,
        control_tag("x", channel_tag(transfer_id))?,
        control_tag("expiration", expires_at.to_string())?,
    ];
    Ok(EventBuilder::new(control_kind(), content).tags(tags))
}

/// Whether an event is one of the peer's messages on this channel.
///
/// The `d` tag carries no authority — the AAD checked when it is unsealed is
/// what does — but routing on it first keeps a side from trying to open its
/// own messages.
pub fn is_peer_event(event: &Event, transfer_id: &str, peer_role: ControlRole) -> bool {
    if event.kind != control_kind() {
        return false;
    }
    event
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().map(String::as_str) == Some("d"))
        .and_then(|tag| tag.as_slice().get(1))
        .is_some_and(|d| d.starts_with(&format!("{transfer_id}:ctl:{}:", peer_role.as_str())))
}

fn control_tag(name: &str, value: impl Into<String>) -> Result<Tag> {
    Tag::parse([name.to_string(), value.into()]).context("invalid Nostr tag")
}

/// When a control relay stops being worth publishing to.
///
/// The channel demotes; it never promotes. Each relay it drops is named once
/// on `demoted`, and what — if anything — takes its place is the caller's,
/// handed back through [`ControlChannel::add`]. Leave the whole policy out and
/// nothing is ever demoted.
pub struct ControlDemotion {
    /// Never demote below this many relays still being published to.
    pub min_relays: usize,
    pub demoted: mpsc::UnboundedSender<String>,
}

/// The relays a channel publishes to, and what it has learned about them.
///
/// Two invariants make a swap safe without an acknowledgement. Demotion stops
/// publishing and never listening — `known` only grows, and a demoted relay
/// keeps its subscription — so nothing the peer says on a relay this side gave
/// up on is lost. And it stops at `min_relays`, so the two sides' publish sets
/// can never drift apart entirely.
struct ControlRelaySet {
    /// Published to, in the order they were taken on.
    active: Vec<String>,
    /// Everything ever taken on, subscribed to whether demoted or not.
    known: HashSet<String>,
    /// Publishes that settled per relay: accepted, and given up on.
    settled: HashMap<String, (u64, u64)>,
    policy: Option<ControlDemotion>,
}

impl ControlRelaySet {
    /// Taken as given: every caller hands over canonical URLs already — the
    /// offer's list came through `normalize_relay_url`, and so did anything
    /// discovery proved.
    fn new(relays: &[String], policy: Option<ControlDemotion>) -> Self {
        let mut active = Vec::with_capacity(relays.len());
        let mut known = HashSet::new();
        for relay in relays {
            if known.insert(relay.clone()) {
                active.push(relay.clone());
            }
        }
        Self {
            active,
            known,
            settled: HashMap::new(),
            policy,
        }
    }

    /// A snapshot: one publish walks the set it started with.
    fn snapshot(&self) -> Vec<String> {
        self.active.clone()
    }

    /// Take on the relays of `relays` this set does not already hold, up to
    /// what a channel may ever hold, and report which those were.
    fn accept(&mut self, relays: &[String]) -> Vec<String> {
        let mut fresh = Vec::new();
        for relay in relays {
            if self.known.len() >= CONTROL_RELAY_MAX {
                break;
            }
            let Some(url) = super::relays::normalize_relay_url(relay) else {
                continue;
            };
            if !self.known.insert(url.clone()) {
                continue;
            }
            self.active.push(url.clone());
            fresh.push(url);
        }
        fresh
    }

    fn accepted(&mut self, relay: &str) {
        self.settled.entry(relay.to_string()).or_default().0 += 1;
    }

    /// Every retry rejected. Drops the relay from the publish set once the
    /// share it has thrown away condemns it.
    fn gave_up(&mut self, relay: &str) {
        let tally = self.settled.entry(relay.to_string()).or_default();
        tally.1 += 1;
        let (accepted, given_up) = *tally;
        let Some(policy) = &self.policy else {
            return;
        };
        if self.active.len() <= policy.min_relays {
            return;
        }
        let settled = accepted + given_up;
        if settled < CONTROL_DEMOTE_MIN_PUBLISHES {
            return;
        }
        if (given_up as f64) / (settled as f64) < CONTROL_DEMOTE_FAILURE_RATIO {
            return;
        }
        let Some(at) = self.active.iter().position(|url| url == relay) else {
            return;
        };
        self.active.remove(at);
        log::info!("signaling relay {relay} is throwing away most of what it is handed");
        let _ = policy.demoted.send(relay.to_string());
    }
}

/// What opening a channel needs beyond the session it is derived from.
pub struct ChannelConfig<'a> {
    pub relays: &'a [String],
    pub transfer_id: String,
    pub key: [u8; AES_KEY_LEN],
    pub role: ControlRole,
    /// The ephemeral Nostr identity this side signs with. The sender's is the
    /// one its manifest names and its chunks are signed by, so the receiver
    /// can pin a single author across the control channel and the pieces.
    pub keys: Keys,
    /// unix seconds: the subscription's lower bound, so a message published
    /// while this side was still starting up is read out of the backlog.
    pub since: u64,
    /// unix seconds: stamped on every event this side publishes.
    pub expires_at: u64,
    /// When to stop publishing to a relay. Omitted: never.
    pub demotion: Option<ControlDemotion>,
}

/// An open control channel: a subscription to the peer's half of the session
/// and a way to publish this side's.
///
/// The relay set is live rather than fixed. With a [`ControlDemotion`] policy
/// a relay that keeps giving up publishes stops being published to and the
/// caller is told, so it can [`Self::add`] a replacement; the subscription
/// stays, so nothing the peer sends over it is lost.
pub struct ControlChannel {
    pool: Arc<FilePool>,
    relays: Arc<StdMutex<ControlRelaySet>>,
    /// Kept so a relay taken on later is subscribed to on the same terms.
    filter: Filter,
    keys: Keys,
    key: [u8; AES_KEY_LEN],
    transfer_id: String,
    role: ControlRole,
    expires_at: u64,
    counter: Mutex<u64>,
    subscriptions: Mutex<Vec<SubscriptionId>>,
    closed: Arc<AtomicBool>,
}

impl ControlChannel {
    /// Subscribe to the peer's messages and return the channel plus the stream
    /// of what opens under this session's key.
    ///
    /// Authorization — which author is the peer — is the caller's, exactly as
    /// it is in the web app: a message is delivered here because it opened,
    /// and the engine decides whose it is.
    pub async fn open(
        pool: Arc<FilePool>,
        config: ChannelConfig<'_>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<(Value, PublicKey)>)> {
        let filter = Filter::new()
            .kind(control_kind())
            .custom_tag(
                SingleLetterTag::lowercase(Alphabet::X),
                channel_tag(&config.transfer_id),
            )
            .since(Timestamp::from(config.since));
        // Taken before the subscription exists, so nothing the relays replay
        // out of their backlog lands before there is a listener for it.
        let mut notifications = pool.notifications();
        let (subscription, reachable) = pool.subscribe(config.relays, filter.clone()).await?;

        let (tx, incoming) = mpsc::unbounded_channel();
        let closed = Arc::new(AtomicBool::new(false));
        let peer_role = config.role.peer();
        let key = config.key;
        let transfer_id = config.transfer_id.clone();
        let done = Arc::clone(&closed);

        // The backlog, asked for alongside the subscription rather than waited
        // on: these events are stored, and the one message that is sent
        // exactly once — the manifest — may already be sitting on the relays
        // before this side ever subscribed. A message that arrives twice costs
        // nothing, since a counter that has already been seen is dropped.
        tokio::spawn({
            let pool = Arc::clone(&pool);
            let relays = reachable;
            let filter = filter.clone();
            let transfer_id = transfer_id.clone();
            let tx = tx.clone();
            async move {
                let Ok(events) = pool.query_open(&relays, filter, BACKLOG_TIMEOUT).await else {
                    return;
                };
                for event in events {
                    if is_peer_event(&event, &transfer_id, peer_role)
                        && let Ok(message) = unseal(&key, &transfer_id, peer_role, &event.content)
                        && tx.send((message, event.pubkey)).is_err()
                    {
                        return;
                    }
                }
            }
        });
        tokio::spawn(async move {
            loop {
                match notifications.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) => {
                        if done.load(Ordering::Relaxed) {
                            return;
                        }
                        if !is_peer_event(&event, &transfer_id, peer_role) {
                            continue;
                        }
                        // Anything that does not open under this session's key
                        // is dropped without a word: on a public relay it is
                        // simply someone else's.
                        if let Ok(message) = unseal(&key, &transfer_id, peer_role, &event.content)
                            && tx.send((message, event.pubkey)).is_err()
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

        Ok((
            Self {
                pool,
                relays: Arc::new(StdMutex::new(ControlRelaySet::new(
                    config.relays,
                    config.demotion,
                ))),
                filter,
                keys: config.keys,
                key: config.key,
                transfer_id: config.transfer_id,
                role: config.role,
                expires_at: config.expires_at,
                counter: Mutex::new(0),
                subscriptions: Mutex::new(vec![subscription]),
                closed,
            },
            incoming,
        ))
    }

    /// This side's ephemeral Nostr identity: the author every message it
    /// publishes is signed by, and what the peer pins on.
    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    /// Seal, sign, and publish one message. The channel stamps the per-side
    /// counter, so a caller cannot number two messages alike.
    async fn publish(&self, content: String, counter: u64) -> Result<()> {
        let event = build_control_event(
            &self.transfer_id,
            self.role,
            counter,
            content,
            self.expires_at,
        )?
        .sign_with_keys(&self.keys)
        .context("could not sign a control event")?;
        publish_to_any(Arc::clone(&self.pool), &self.relays, event).await
    }

    /// The relays this side is publishing to, which is what an announcement
    /// carries as its `ctl` set.
    pub fn relays(&self) -> Vec<String> {
        self.relays.lock().expect("control relays").snapshot()
    }

    /// Take on relays this channel does not already hold: subscribe to them,
    /// and start publishing there. Returns the ones actually taken on.
    ///
    /// A promotion opens a second subscription rather than reopening the
    /// first: the relays already connected have no reason to re-serve their
    /// backlog because a new one joined.
    pub async fn add(&self, relays: &[String]) -> Vec<String> {
        if self.closed.load(Ordering::Relaxed) {
            return Vec::new();
        }
        let fresh = self
            .relays
            .lock()
            .expect("control relays")
            .accept(relays);
        if fresh.is_empty() {
            return fresh;
        }
        // A relay that will not answer stays in the set regardless: publishing
        // opens its own socket, and a relay that will not take a message
        // either is what demotion is for.
        match self.pool.subscribe(&fresh, self.filter.clone()).await {
            Ok((subscription, _)) => {
                // The lock is taken before the flag is read, and `close` sets
                // the flag before it takes the same lock: a subscription that
                // opened while the channel was being closed is ended here
                // rather than outliving everything that would have ended it.
                let mut subscriptions = self.subscriptions.lock().await;
                if self.closed.load(Ordering::Relaxed) {
                    drop(subscriptions);
                    self.pool.unsubscribe(&subscription).await;
                } else {
                    subscriptions.push(subscription);
                }
            }
            Err(error) => log::debug!("a promoted signaling relay would not answer: {error:#}"),
        }
        fresh
    }
}

impl ControlChannel {
    pub async fn send_sender(&self, mut message: SenderMessage) -> Result<()> {
        let counter = self.next_counter().await;
        message.set_counter(counter);
        let content = seal(&self.key, &self.transfer_id, self.role, &message)?;
        self.publish(content, counter).await
    }

    pub async fn send_receiver(&self, mut message: ReceiverMessage) -> Result<()> {
        let counter = self.next_counter().await;
        message.set_counter(counter);
        let content = seal(&self.key, &self.transfer_id, self.role, &message)?;
        self.publish(content, counter).await
    }

    async fn next_counter(&self) -> u64 {
        let mut counter = self.counter.lock().await;
        *counter += 1;
        *counter
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        for subscription in self.subscriptions.lock().await.drain(..) {
            self.pool.unsubscribe(&subscription).await;
        }
    }
}

/// Publish to every relay and return as soon as one accepts.
///
/// The rest keep trying in the background rather than being cancelled: a
/// message that only ever reached the one relay that then fails to serve it is
/// a message the peer never sees, and the one that matters most — the manifest
/// — is sent exactly once.
async fn publish_to_any(
    pool: Arc<FilePool>,
    set: &Arc<StdMutex<ControlRelaySet>>,
    event: Event,
) -> Result<()> {
    let relays = set.lock().expect("control relays").snapshot();
    if relays.is_empty() {
        bail!("this transfer has no control relays left to reach the other side on");
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    for relay in &relays {
        let pool = Arc::clone(&pool);
        let set = Arc::clone(set);
        let relay = relay.clone();
        let event = event.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            for attempt in 0..=PUBLISH_MAX_RETRIES {
                match pool.publish(&relay, &event).await {
                    Ok(()) => {
                        set.lock().expect("control relays").accepted(&relay);
                        let _ = tx.send(true);
                        return;
                    }
                    Err(error) => {
                        log::debug!("control relay {relay} refused a message: {error:#}");
                        if attempt < PUBLISH_MAX_RETRIES {
                            tokio::time::sleep(PUBLISH_BACKOFF_BASE * (1 << attempt)).await;
                        }
                    }
                }
            }
            // The teardown is not the relay's fault: a pool being shut down
            // fails every publish still in flight.
            if !pool.is_shut_down() {
                set.lock().expect("control relays").gave_up(&relay);
            }
            let _ = tx.send(false);
        });
    }
    drop(tx);

    let mut failures = 0;
    while let Some(accepted) = rx.recv().await {
        if accepted {
            return Ok(());
        }
        failures += 1;
        if failures == relays.len() {
            break;
        }
    }
    bail!("lost contact with the relays — the control message could not be delivered")
}

/// How long the backlog query waits on the relays. It runs behind the live
/// subscription rather than in front of it, so this bounds a background task
/// and never the moment a channel opens.
const BACKLOG_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSFER_ID: &str = "c05587dba544d9543610d42f7b7b640d";

    /// The wire shape the two implementations meet on: these are the exact
    /// objects the web app's parser reads, tag and field names included.
    #[test]
    fn the_message_shapes_are_the_web_apps() {
        assert_eq!(
            serde_json::to_string(&ReceiverMessage::Hello { n: 1 }).unwrap(),
            r#"{"t":"hello","n":1}"#
        );
        assert_eq!(
            serde_json::to_string(&ReceiverMessage::Ack {
                n: 2,
                avail: 3,
                have: 4,
                missing: vec![(1, 2, 3)],
            })
            .unwrap(),
            r#"{"t":"ack","n":2,"avail":3,"have":4,"missing":[[1,2,3]]}"#
        );
        assert_eq!(
            serde_json::to_string(&SenderMessage::Avail {
                n: 5,
                upto: 2,
                relays: vec!["wss://relay.example".to_string()],
                map: "AA".to_string(),
                gens: vec![(1, 2)],
                ctl: vec!["wss://ctl.example".to_string()],
            })
            .unwrap(),
            r#"{"t":"avail","n":5,"upto":2,"relays":["wss://relay.example"],"map":"AA","gens":[[1,2]],"ctl":["wss://ctl.example"]}"#
        );
    }

    #[test]
    fn a_message_round_trips_through_its_own_role() {
        let key = [9u8; AES_KEY_LEN];
        let sealed = seal(
            &key,
            TRANSFER_ID,
            ControlRole::Receiver,
            &ReceiverMessage::Done { n: 7 },
        )
        .unwrap();
        let opened = unseal(&key, TRANSFER_ID, ControlRole::Receiver, &sealed).unwrap();
        let message: ReceiverMessage = serde_json::from_value(opened).unwrap();
        assert!(matches!(message, ReceiverMessage::Done { n: 7 }));
    }

    /// The AAD is what makes a direction unforgeable: a receiver's message
    /// must not open as a sender's even to a holder of the key.
    #[test]
    fn a_message_does_not_open_as_the_other_direction_or_another_transfer() {
        let key = [9u8; AES_KEY_LEN];
        let sealed = seal(
            &key,
            TRANSFER_ID,
            ControlRole::Receiver,
            &ReceiverMessage::Hello { n: 1 },
        )
        .unwrap();
        assert!(unseal(&key, TRANSFER_ID, ControlRole::Sender, &sealed).is_err());
        assert!(unseal(&key, &"a".repeat(32), ControlRole::Receiver, &sealed).is_err());
        assert!(unseal(&[8u8; AES_KEY_LEN], TRANSFER_ID, ControlRole::Receiver, &sealed).is_err());
    }

    /// An announcement is read against the ring travelling with it, so the
    /// state a receiver builds from it cannot name a relay or a piece that
    /// message never described.
    #[test]
    fn an_announcement_that_does_not_describe_itself_is_refused() {
        let good = SenderMessage::Avail {
            n: 1,
            upto: 2,
            relays: vec![
                "wss://one.example".to_string(),
                "wss://two.example".to_string(),
            ],
            map: "AB".to_string(),
            gens: vec![(1, 1)],
            ctl: vec!["wss://ctl.example".to_string()],
        };
        good.validate(Some(4)).unwrap();
        // Nothing to size it against yet.
        assert!(good.validate(None).is_err());

        let ctl = || vec!["wss://ctl.example".to_string()];
        let cases = [
            SenderMessage::Avail {
                n: 1,
                upto: 5,
                relays: vec!["wss://one.example".to_string()],
                map: "AAAAA".to_string(),
                gens: Vec::new(),
                ctl: ctl(),
            },
            SenderMessage::Avail {
                n: 1,
                upto: 2,
                relays: vec!["wss://one.example".to_string()],
                map: "AB".to_string(),
                gens: Vec::new(),
                ctl: ctl(),
            },
            SenderMessage::Avail {
                n: 1,
                upto: 2,
                relays: vec!["wss://one.example".to_string()],
                map: "A".to_string(),
                gens: Vec::new(),
                ctl: ctl(),
            },
            SenderMessage::Avail {
                n: 1,
                upto: 1,
                relays: vec![
                    "wss://one.example".to_string(),
                    "wss://one.example/".to_string(),
                ],
                map: "A".to_string(),
                gens: Vec::new(),
                ctl: ctl(),
            },
            SenderMessage::Avail {
                n: 1,
                upto: 1,
                relays: vec!["ws://one.example".to_string()],
                map: "A".to_string(),
                gens: Vec::new(),
                ctl: ctl(),
            },
        ];
        for case in cases {
            assert!(case.validate(Some(4)).is_err(), "{case:?} should be refused");
        }
    }

    /// The control set is what this side is told to open sockets to, so it is
    /// bounded and checked exactly as the ring is — and it is never empty: the
    /// sender published the very message carrying it over that set.
    #[test]
    fn an_announcement_whose_control_set_is_not_one_is_refused() {
        let avail = |ctl: Vec<String>| SenderMessage::Avail {
            n: 1,
            upto: 1,
            relays: vec!["wss://one.example".to_string()],
            map: "A".to_string(),
            gens: Vec::new(),
            ctl,
        };
        avail(vec!["wss://ctl.example".to_string()])
            .validate(Some(4))
            .unwrap();
        let cases = [
            Vec::new(),
            vec!["wss://ctl.example".to_string(); CONTROL_RELAY_MAX + 1],
            vec![
                "wss://ctl.example".to_string(),
                "wss://ctl.example/".to_string(),
            ],
            vec!["ws://ctl.example".to_string()],
        ];
        for case in cases {
            let message = avail(case);
            assert!(
                message.validate(Some(4)).is_err(),
                "{message:?} should be refused"
            );
        }
    }

    #[test]
    fn an_acknowledgement_naming_what_this_transfer_has_not_is_refused() {
        let good = ReceiverMessage::Ack {
            n: 1,
            avail: 1,
            have: 2,
            missing: vec![(1, 0, 0)],
        };
        good.validate(4, 2).unwrap();
        assert!(
            ReceiverMessage::Ack {
                n: 1,
                avail: 1,
                have: 9,
                missing: Vec::new()
            }
            .validate(4, 2)
            .is_err()
        );
        assert!(
            ReceiverMessage::Ack {
                n: 1,
                avail: 1,
                have: 1,
                missing: vec![(9, 0, 0)]
            }
            .validate(4, 2)
            .is_err()
        );
        assert!(
            ReceiverMessage::Ack {
                n: 1,
                avail: 1,
                have: 1,
                missing: vec![(1, 5, 0)]
            }
            .validate(4, 2)
            .is_err()
        );
    }

    #[test]
    fn ring_positions_encode_and_decode_as_one_alphabet() {
        for position in 0..POSITION_ALPHABET.len() {
            let character = encode_position(position).unwrap();
            assert_eq!(decode_position(character), Some(position));
        }
        assert!(encode_position(POSITION_ALPHABET.len()).is_err());
        assert_eq!(decode_position('*'), None);
    }
}
