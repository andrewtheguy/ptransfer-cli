//! Nostr signaling compatible with secure-send-web's Auto Exchange mode.
//!
//! Three event shapes, mirroring `src/lib/nostr/events.ts`:
//!
//! - **Rendezvous** (kind 24243, `type=rendezvous`): published by the sender
//!   once per PIN rotation, tagged with the rotation-bucket-scoped PIN hint
//!   (`#h`). The payload is **plaintext JSON**: the SPAKE2 element it carries is
//!   password-blinded, so nothing in it can confirm a PIN guess offline, and
//!   encrypting it under a PIN-derived key would reintroduce exactly the offline
//!   target the PAKE removes. File metadata is deliberately absent.
//! - **Handshake** (kind 24242, `type=claim|confirm`): the receiver claims the
//!   transfer, the sender confirms and delivers the file metadata. The content
//!   is a JSON envelope carrying the sealed body plus — for claims — the
//!   receiver's SPAKE2 element in plaintext, since the sender must finish its
//!   side of the PAKE before it can derive the key that opens the seal.
//! - **Signal** (kind 24242, `type=signal`): WebRTC offer/answer/candidates,
//!   encrypted with the PAKE-derived session signaling key.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nostr_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::aes;
use crate::crypto::chunk::fill_random;
use crate::crypto::pin::{PIN_ACTIVE_BUCKETS, PIN_ROTATION_MS};

pub const DEFAULT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.primal.net",
    "wss://nostr.rocks",
    "wss://relay.nostr.pub",
    "wss://relay.snort.social",
];

const EVENT_KIND_DATA_TRANSFER: u16 = 24242;
const EVENT_KIND_RENDEZVOUS: u16 = 24243;
const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const PUBLISH_RETRIES: usize = 3;

/// Rendezvous payload, published as plaintext JSON inside the kind-24243 event.
/// Republished with a fresh PIN, hint, nonce, and SPAKE2 element on every
/// rotation; `transfer_id` and `sender_pubkey` stay stable for the transfer's
/// lifetime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RendezvousPayload {
    /// Always `"rendezvous"`.
    #[serde(rename = "type")]
    pub payload_type: String,
    pub transfer_id: String,
    /// Nostr pubkey of the sender; must equal the rendezvous event author.
    pub sender_pubkey: String,
    /// Sender's SPAKE2 element pA (base64, 33-byte compressed P-256 point).
    pub pake_message: String,
    /// Sender handshake nonce (base64), fresh per rotation; echoed in the claim.
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,
}

/// File metadata delivered inside the sender's sealed confirm — after the
/// handshake, never on the public rendezvous. Both sides hash it into the
/// confirmation code, so the code the humans compare attests to what is being
/// transferred.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferMetadata {
    /// Always `"file"`.
    pub content_type: String,
    pub file_name: String,
    pub file_size: u64,
    /// False when `file_size` is an input-size estimate for a streamed ZIP.
    pub file_size_exact: bool,
    pub mime_type: String,
}

/// Claim payload (receiver -> sender), sealed with the claim key derived from
/// the receiver's SPAKE2 run against the rendezvous element. Opening it is the
/// sender's proof that the claimant knows the PIN: the seal key exists only on
/// the two ends of a matching PAKE session.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimPayload {
    /// Always `"claim"`.
    #[serde(rename = "type")]
    pub payload_type: String,
    pub transfer_id: String,
    /// Echo of the rendezvous nonce for the PIN generation the receiver used.
    pub sender_nonce: String,
    /// Fresh receiver handshake nonce (base64); echoed back in the confirm.
    pub receiver_nonce: String,
    /// Sender identity from the rendezvous event author.
    pub sender_pubkey: String,
    /// Receiver identity, which must match the claim event author.
    pub receiver_pubkey: String,
    /// SHA-256 digest of the canonical rendezvous transcript.
    pub transcript_hash: String,
}

/// Confirm payload (sender -> receiver), sealed with the confirm key from the
/// same SPAKE2 session that verified the claim. Published as soon as the claim
/// verifies — the confirmation-code gate guards the WebRTC offer and the file
/// bytes, not this event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmPayload {
    /// Always `"confirm"`.
    #[serde(rename = "type")]
    pub payload_type: String,
    pub transfer_id: String,
    pub sender_nonce: String,
    pub receiver_nonce: String,
    /// Sender identity, which must match the confirm event author.
    pub sender_pubkey: String,
    /// Receiver identity the sender locked onto.
    pub receiver_pubkey: String,
    /// Echo of the agreed rendezvous transcript digest.
    pub transcript_hash: String,
    /// File metadata, delivered post-handshake and bound into the code.
    pub metadata: TransferMetadata,
}

/// Compute secure-send-web's versioned canonical rendezvous transcript digest.
///
/// The SPAKE2 transcript already keys the session by both identities, both
/// elements, and the transfer id. This digest extends the agreement to the rest
/// of the plaintext record — the salt and the relay hints — and to the exact
/// wire encoding of the fields the PAKE covers only semantically.
///
/// A JSON array fixes field order and JSON escaping prevents field-boundary
/// ambiguity. `relays` is canonicalized to an empty array when absent.
pub fn compute_rendezvous_transcript_hash(
    payload: &RendezvousPayload,
    salt: &[u8],
) -> Result<String> {
    const TRANSCRIPT_LABEL: &str = "secure-send:nostr-rendezvous-transcript:v3";

    let canonical = serde_json::to_vec(&serde_json::json!([
        TRANSCRIPT_LABEL,
        payload.payload_type,
        payload.transfer_id,
        payload.sender_pubkey,
        payload.pake_message,
        payload.nonce,
        payload.relays.as_deref().unwrap_or(&[]),
        hex_lower(salt),
    ]))?;

    Ok(hex_lower(&Sha256::digest(canonical)))
}

/// Compute secure-send-web's versioned canonical file-metadata digest.
///
/// Metadata travels inside the sealed confirm, so it cannot ride the rendezvous
/// transcript (the receiver commits to that digest in its claim, before it has
/// seen any metadata). This digest is bound into the confirmation-code KDF
/// instead.
pub fn compute_transfer_metadata_hash(metadata: &TransferMetadata) -> Result<String> {
    const METADATA_LABEL: &str = "secure-send:nostr-metadata-transcript:v1";

    let canonical = serde_json::to_vec(&serde_json::json!([
        METADATA_LABEL,
        metadata.content_type,
        metadata.file_name,
        metadata.file_size,
        metadata.file_size_exact,
        metadata.mime_type,
    ]))?;

    Ok(hex_lower(&Sha256::digest(canonical)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    Claim,
    Confirm,
}

impl HandshakeType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Confirm => "confirm",
        }
    }
}

/// A parsed (but not yet opened) rendezvous event.
#[derive(Debug, Clone)]
pub struct ParsedRendezvousEvent {
    pub salt: Vec<u8>,
    pub transfer_id: String,
    pub payload: RendezvousPayload,
}

/// A parsed (but not yet opened) handshake event.
#[derive(Debug, Clone)]
pub struct ParsedHandshakeEvent {
    pub event_id: EventId,
    pub author: PublicKey,
    pub handshake_type: HandshakeType,
    pub transfer_id: String,
    pub sealed_payload: Vec<u8>,
    /// The claimant's SPAKE2 element, when the envelope carries one.
    pub pake_message: Option<Vec<u8>>,
}

/// Content envelope of a handshake event: the sealed body, plus the claimant's
/// plaintext SPAKE2 element on claims.
#[derive(Debug, Serialize, Deserialize)]
struct HandshakeEnvelope {
    sealed: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pake: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidatePayload {
    pub candidate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_m_line_index: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Signal {
    #[serde(rename = "offer")]
    Offer { sdp: String },
    #[serde(rename = "answer")]
    Answer { sdp: String },
    #[serde(rename = "candidate")]
    Candidate {
        #[serde(skip_serializing_if = "Option::is_none")]
        candidate: Option<CandidatePayload>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct SignalEnvelope {
    #[serde(rename = "type")]
    payload_type: String,
    signal: Signal,
}

#[derive(Debug, Clone)]
pub struct ParsedSignalEvent {
    pub event_id: EventId,
    pub pubkey: PublicKey,
    pub signal: Signal,
}

#[derive(Clone)]
pub struct NostrClient {
    client: Client,
    keys: Keys,
}

impl NostrClient {
    pub async fn connect(keys: Keys) -> Result<Self> {
        let client = Client::new(keys.clone());
        for relay in DEFAULT_RELAYS {
            client
                .add_relay(*relay)
                .await
                .with_context(|| format!("Failed to add relay {relay}"))?;
        }
        client.connect().await;
        client.wait_for_connection(RELAY_CONNECT_TIMEOUT).await;
        Ok(Self { client, keys })
    }

    pub fn public_key(&self) -> PublicKey {
        self.keys.public_key()
    }

    pub fn public_key_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }

    pub async fn publish(&self, event: &Event) -> Result<()> {
        let mut last_failure = String::from("no relay accepted the event");
        for attempt in 0..PUBLISH_RETRIES {
            log::debug!(
                "Publishing Nostr event kind {:?}, attempt {}/{}",
                event.kind,
                attempt + 1,
                PUBLISH_RETRIES
            );
            let output = self
                .client
                .send_event(event)
                .await
                .context("Failed to publish Nostr event")?;

            if !output.success.is_empty() {
                log::debug!(
                    "Nostr publish accepted by {} relay(s), failed on {} relay(s)",
                    output.success.len(),
                    output.failed.len()
                );
                return Ok(());
            }

            last_failure = if output.failed.is_empty() {
                String::from("no relay accepted the event")
            } else {
                output
                    .failed
                    .iter()
                    .map(|(relay, err)| format!("{relay}: {err}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            log::warn!(
                "Nostr publish attempt {}/{} was not accepted by any relay: {}",
                attempt + 1,
                PUBLISH_RETRIES,
                last_failure
            );

            if attempt + 1 < PUBLISH_RETRIES {
                tokio::time::sleep(Duration::from_millis(500 * (1_u64 << attempt))).await;
            }
        }

        bail!(
            "Failed to publish Nostr event to any relay after {PUBLISH_RETRIES} attempts: {last_failure}"
        );
    }

    pub async fn subscribe(&self, filter: Filter) -> Result<SubscriptionId> {
        Ok(self
            .client
            .subscribe(filter, None)
            .await
            .context("Failed to subscribe to Nostr events")?
            .val)
    }

    pub async fn unsubscribe(&self, id: &SubscriptionId) {
        self.client.unsubscribe(id).await;
    }

    pub fn notifications(&self) -> tokio::sync::broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    pub async fn fetch(&self, filter: Filter) -> Result<Vec<Event>> {
        let events = self
            .client
            .fetch_events(filter, FETCH_TIMEOUT)
            .await
            .context("Failed to fetch Nostr events")?;
        Ok(events.into_iter().collect())
    }

    pub async fn disconnect(&self) {
        self.client.disconnect().await;
    }

    pub fn sign(&self, builder: EventBuilder) -> Result<Event> {
        builder
            .sign_with_keys(&self.keys)
            .context("Failed to sign Nostr event")
    }
}

pub fn data_kind() -> Kind {
    Kind::from_u16(EVENT_KIND_DATA_TRANSFER)
}

pub fn rendezvous_kind() -> Kind {
    Kind::from_u16(EVENT_KIND_RENDEZVOUS)
}

pub fn default_relays_vec() -> Vec<String> {
    DEFAULT_RELAYS
        .iter()
        .map(|relay| (*relay).to_string())
        .collect()
}

/// Generate a random handshake nonce (16 bytes, base64). The sender mints one
/// per rendezvous publication; the receiver mints one per claim. Echoing them
/// inside the sealed claim/confirm payloads prevents replay across rotations,
/// transfers, and handshake directions.
pub fn generate_handshake_nonce() -> Result<String> {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes)?;
    Ok(STANDARD.encode(bytes))
}

/// Create a rendezvous event (kind 24243) carrying the plaintext payload.
///
/// The NIP-40 `expiration` tag is the end of the PIN's immediately following
/// bucket, matching the sender's current-or-previous acceptance rule.
pub fn create_rendezvous_event(
    client: &NostrClient,
    payload: &RendezvousPayload,
    salt: &[u8],
    hint: &str,
    pin_bucket: u64,
) -> Result<Event> {
    let expiration = (pin_bucket + PIN_ACTIVE_BUCKETS) * PIN_ROTATION_MS / 1000;
    let tags = vec![
        tag("h", hint)?,
        tag("s", STANDARD.encode(salt))?,
        tag("t", payload.transfer_id.as_str())?,
        tag("type", "rendezvous")?,
        tag("expiration", expiration.to_string())?,
    ];

    client.sign(EventBuilder::new(rendezvous_kind(), serde_json::to_string(payload)?).tags(tags))
}

/// Parse a rendezvous event: tags plus the plaintext JSON payload. Only shape
/// is checked here; field validation (author binding, element validity,
/// freshness) is the caller's job.
pub fn parse_rendezvous_event(event: &Event) -> Option<ParsedRendezvousEvent> {
    if event.kind != rendezvous_kind() {
        return None;
    }

    // The `h` tag must be present for the event to be routable at all, but its
    // value carries no authority and is not used past relay filtering.
    tag_value(event, "h")?;
    let salt = STANDARD.decode(tag_value(event, "s")?).ok()?;
    let transfer_id = tag_value(event, "t")?.to_string();
    let payload: RendezvousPayload = serde_json::from_str(&event.content).ok()?;

    Some(ParsedRendezvousEvent {
        salt,
        transfer_id,
        payload,
    })
}

/// Seal a handshake payload (claim/confirm) with the session's seal key, an
/// HKDF derivation off the SPAKE2 root. AES-GCM's authentication tag is the
/// PAKE's key-confirmation step: only a peer that ran the same session — same
/// PIN, elements, identities, and transfer — can produce or verify it.
pub fn seal_handshake_payload<T: Serialize>(
    seal_key: &[u8; aes::AES_KEY_LEN],
    payload: &T,
) -> Result<Vec<u8>> {
    aes::encrypt(seal_key, &serde_json::to_vec(payload)?)
}

/// Open a sealed handshake payload. Fails if the payload was not sealed with
/// this session's key (i.e. the author ran a different PAKE session — wrong
/// PIN, wrong generation, or tampered elements) or is not valid JSON. Field
/// validation is the caller's job.
pub fn open_handshake_payload<T: for<'de> Deserialize<'de>>(
    seal_key: &[u8; aes::AES_KEY_LEN],
    sealed_payload: &[u8],
) -> Result<T> {
    let decrypted = aes::decrypt(seal_key, sealed_payload)?;
    serde_json::from_slice(&decrypted).context("invalid handshake payload JSON")
}

/// Create a handshake event (kind 24242, `type=claim|confirm`).
///
/// Tags stay plaintext so relays can route by transfer and recipient, but
/// neither they nor the element carry authority: the sealed body must decrypt
/// under the session's seal key and repeat the transfer/nonces before either
/// side acts on it.
pub fn create_handshake_event(
    client: &NostrClient,
    recipient_pubkey: &PublicKey,
    transfer_id: &str,
    handshake_type: HandshakeType,
    sealed_payload: &[u8],
    pake_message: Option<&[u8]>,
) -> Result<Event> {
    let envelope = HandshakeEnvelope {
        sealed: STANDARD.encode(sealed_payload),
        pake: pake_message.map(|message| STANDARD.encode(message)),
    };
    let tags = vec![
        tag("p", recipient_pubkey.to_hex())?,
        tag("t", transfer_id)?,
        tag("type", handshake_type.as_str())?,
    ];

    client.sign(EventBuilder::new(data_kind(), serde_json::to_string(&envelope)?).tags(tags))
}

/// Parse a handshake event (claim or confirm).
pub fn parse_handshake_event(event: &Event) -> Option<ParsedHandshakeEvent> {
    if event.kind != data_kind() {
        return None;
    }
    let handshake_type = match tag_value(event, "type")? {
        "claim" => HandshakeType::Claim,
        "confirm" => HandshakeType::Confirm,
        _ => return None,
    };

    let envelope: HandshakeEnvelope = serde_json::from_str(&event.content).ok()?;
    let pake_message = match envelope.pake {
        Some(pake) => Some(STANDARD.decode(pake).ok()?),
        None => None,
    };

    Some(ParsedHandshakeEvent {
        event_id: event.id,
        author: event.pubkey,
        handshake_type,
        transfer_id: tag_value(event, "t")?.to_string(),
        sealed_payload: STANDARD.decode(envelope.sealed).ok()?,
        pake_message,
    })
}

pub fn create_signal_event(
    client: &NostrClient,
    sender_pubkey: &PublicKey,
    transfer_id: &str,
    signal: Signal,
    key: &[u8; aes::AES_KEY_LEN],
) -> Result<Event> {
    let envelope = SignalEnvelope {
        payload_type: "signal".to_string(),
        signal,
    };
    let encrypted = aes::encrypt(key, &serde_json::to_vec(&envelope)?)?;
    let tags = vec![
        tag("t", transfer_id)?,
        tag("p", sender_pubkey.to_hex())?,
        tag("type", "signal")?,
    ];

    client.sign(
        EventBuilder::new(data_kind(), STANDARD.encode(encrypted))
            .tags(tags)
            .allow_self_tagging(),
    )
}

pub fn parse_signal_event(
    event: &Event,
    key: &[u8; aes::AES_KEY_LEN],
    expected_transfer_id: &str,
) -> Option<ParsedSignalEvent> {
    if event.kind != data_kind() || tag_value(event, "type")? != "signal" {
        return None;
    }
    if tag_value(event, "t")? != expected_transfer_id {
        return None;
    }

    let encrypted = STANDARD.decode(&event.content).ok()?;
    let decrypted = aes::decrypt(key, &encrypted).ok()?;
    let envelope: SignalEnvelope = serde_json::from_slice(&decrypted).ok()?;
    if envelope.payload_type != "signal" {
        return None;
    }

    Some(ParsedSignalEvent {
        event_id: event.id,
        pubkey: event.pubkey,
        signal: envelope.signal,
    })
}

/// Rendezvous lookup: kind 24243 events carrying any of the receiver's
/// derived PIN hints. The limit leaves headroom for hint collisions, which are
/// expected rather than exotic (the hint carries ~17.3 bits).
pub fn rendezvous_filter(hints: &[String]) -> Filter {
    Filter::new()
        .kind(rendezvous_kind())
        .custom_tags(
            SingleLetterTag::lowercase(Alphabet::H),
            hints.iter().cloned(),
        )
        .limit(50)
}

/// Kind-24242 events addressed to `recipient` for this transfer. The sender
/// uses it for incoming claims (and later, receiver signals); the receiver
/// narrows it by author for the sender's confirm.
pub fn addressed_filter(transfer_id: &str, recipient: &PublicKey) -> Filter {
    Filter::new()
        .kind(data_kind())
        .custom_tag(SingleLetterTag::lowercase(Alphabet::T), transfer_id)
        .custom_tag(SingleLetterTag::lowercase(Alphabet::P), recipient.to_hex())
}

pub fn addressed_filter_from_author(
    transfer_id: &str,
    recipient: &PublicKey,
    author: PublicKey,
) -> Filter {
    addressed_filter(transfer_id, recipient).author(author)
}

/// Kind-24242 events addressed to `recipient` by any of the claimed
/// candidates' senders. The receiver cannot tell which rendezvous candidate is
/// its sender until a confirm opens under one of the claimed sessions' keys, so
/// it watches all of them at once.
pub fn confirm_filter<'a>(
    transfer_ids: impl IntoIterator<Item = &'a str>,
    recipient: &PublicKey,
    authors: impl IntoIterator<Item = PublicKey>,
) -> Filter {
    Filter::new()
        .kind(data_kind())
        .custom_tags(
            SingleLetterTag::lowercase(Alphabet::T),
            transfer_ids.into_iter().map(str::to_string),
        )
        .custom_tag(SingleLetterTag::lowercase(Alphabet::P), recipient.to_hex())
        .authors(authors)
}

/// Kind-24242 events authored by the sender for this transfer, regardless of
/// `#p` tag — matches the shape secure-send-web's receiver subscribes with.
pub fn signal_filter_from_sender(transfer_id: &str, sender_pubkey: PublicKey) -> Filter {
    Filter::new()
        .kind(data_kind())
        .custom_tag(SingleLetterTag::lowercase(Alphabet::T), transfer_id)
        .author(sender_pubkey)
}

fn tag(name: &str, value: impl Into<String>) -> Result<Tag> {
    Tag::parse([name.to_string(), value.into()]).context("invalid Nostr tag")
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|tag| tag.as_slice().first().is_some_and(|k| k == name))
        .and_then(|tag| tag.content())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> (NostrClient, Keys) {
        let keys = Keys::generate();
        (
            NostrClient {
                client: Client::new(keys.clone()),
                keys: keys.clone(),
            },
            keys,
        )
    }

    fn sample_rendezvous() -> RendezvousPayload {
        RendezvousPayload {
            payload_type: "rendezvous".to_string(),
            transfer_id: "a1b2c3d4e5f60718".to_string(),
            sender_pubkey: "a".repeat(64),
            pake_message: "ApAkEeLeMeNtBase64==".to_string(),
            nonce: "c2VuZGVyLW5vbmNlLTAwMDAwMDA=".to_string(),
            relays: Some(vec![
                "wss://relay.one".to_string(),
                "wss://relay.two".to_string(),
            ]),
        }
    }

    fn sample_metadata() -> TransferMetadata {
        TransferMetadata {
            content_type: "file".to_string(),
            file_name: "quarterly-report.pdf".to_string(),
            file_size: 1_048_576,
            file_size_exact: true,
            mime_type: "application/pdf".to_string(),
        }
    }

    #[test]
    fn signal_event_preserves_sender_self_p_tag() {
        let (client, keys) = test_client();
        let key = [7_u8; aes::AES_KEY_LEN];
        let event = create_signal_event(
            &client,
            &keys.public_key(),
            "transfer-id",
            Signal::Offer {
                sdp: "v=0\r\n".to_string(),
            },
            &key,
        )
        .expect("signal event");

        let sender = keys.public_key().to_hex();
        assert_eq!(tag_value(&event, "p"), Some(sender.as_str()));
        assert!(parse_signal_event(&event, &key, "transfer-id").is_some());
    }

    #[test]
    fn sender_offer_filter_matches_web_receiver_shape() {
        let sender = Keys::generate().public_key();
        let value = serde_json::to_value(signal_filter_from_sender("transfer-id", sender))
            .expect("filter json");

        assert_eq!(
            value["kinds"],
            serde_json::json!([EVENT_KIND_DATA_TRANSFER])
        );
        assert_eq!(value["#t"], serde_json::json!(["transfer-id"]));
        assert_eq!(value["authors"], serde_json::json!([sender.to_hex()]));
        assert!(value.get("#p").is_none());
    }

    #[test]
    fn confirm_filter_watches_every_claimed_candidate() {
        let recipient = Keys::generate().public_key();
        let first = Keys::generate().public_key();
        let second = Keys::generate().public_key();
        let value =
            serde_json::to_value(confirm_filter(["one", "two"], &recipient, [first, second]))
                .expect("filter json");

        let transfer_ids = value["#t"].as_array().expect("#t array");
        assert_eq!(transfer_ids.len(), 2);
        assert_eq!(value["#p"], serde_json::json!([recipient.to_hex()]));
        assert_eq!(value["authors"].as_array().expect("authors").len(), 2);
    }

    #[test]
    fn rendezvous_event_round_trips_as_plaintext_json() {
        let (client, _) = test_client();
        let salt = [9u8; 16];
        let pin_bucket = 123;
        let payload = sample_rendezvous();
        let event =
            create_rendezvous_event(&client, &payload, &salt, "aabbccdd", pin_bucket)
                .expect("rendezvous event");

        assert_eq!(event.kind.as_u16(), EVENT_KIND_RENDEZVOUS);
        assert_eq!(tag_value(&event, "type"), Some("rendezvous"));
        assert_eq!(tag_value(&event, "h"), Some("aabbccdd"));
        let expiration: u64 = tag_value(&event, "expiration").unwrap().parse().unwrap();
        assert_eq!(
            expiration,
            (pin_bucket + PIN_ACTIVE_BUCKETS) * PIN_ROTATION_MS / 1000
        );

        // Plaintext by design: the element is password-blinded, so nothing here
        // is PIN-testable and there is no ciphertext to grind.
        let wire: serde_json::Value = serde_json::from_str(&event.content).expect("plaintext json");
        assert_eq!(wire["type"], "rendezvous");
        assert_eq!(wire["pakeMessage"], payload.pake_message);
        assert!(wire.get("fileName").is_none());

        let parsed = parse_rendezvous_event(&event).expect("parses");
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.transfer_id, payload.transfer_id);
        assert_eq!(parsed.payload.pake_message, payload.pake_message);
        assert_eq!(parsed.payload.nonce, payload.nonce);
    }

    #[test]
    fn handshake_payloads_round_trip_with_camel_case() {
        let key = [3u8; aes::AES_KEY_LEN];
        let claim = ClaimPayload {
            payload_type: "claim".to_string(),
            transfer_id: "tid".to_string(),
            sender_nonce: "sn".to_string(),
            receiver_nonce: "rn".to_string(),
            sender_pubkey: "spk".to_string(),
            receiver_pubkey: "rpk".to_string(),
            transcript_hash: "th".to_string(),
        };
        let sealed = seal_handshake_payload(&key, &claim).unwrap();
        let opened: ClaimPayload = open_handshake_payload(&key, &sealed).unwrap();
        assert_eq!(opened.sender_nonce, "sn");

        // Wire JSON uses secure-send-web's camelCase field names.
        let json = serde_json::to_value(&claim).unwrap();
        assert_eq!(json["type"], "claim");
        assert!(json.get("receiverNonce").is_some());
        assert_eq!(json["receiverPubkey"], "rpk");
        assert_eq!(json["transcriptHash"], "th");

        // Wrong key must fail to open.
        let wrong = [4u8; aes::AES_KEY_LEN];
        assert!(open_handshake_payload::<ClaimPayload>(&wrong, &sealed).is_err());
    }

    #[test]
    fn confirm_payload_carries_camel_case_metadata() {
        let confirm = ConfirmPayload {
            payload_type: "confirm".to_string(),
            transfer_id: "tid".to_string(),
            sender_nonce: "sn".to_string(),
            receiver_nonce: "rn".to_string(),
            sender_pubkey: "spk".to_string(),
            receiver_pubkey: "rpk".to_string(),
            transcript_hash: "th".to_string(),
            metadata: sample_metadata(),
        };
        let json = serde_json::to_value(&confirm).unwrap();
        assert_eq!(json["type"], "confirm");
        assert_eq!(json["metadata"]["contentType"], "file");
        assert_eq!(json["metadata"]["fileName"], "quarterly-report.pdf");
        assert_eq!(json["metadata"]["fileSize"], 1_048_576);
        assert_eq!(json["metadata"]["fileSizeExact"], true);
        assert_eq!(json["metadata"]["mimeType"], "application/pdf");
    }

    #[test]
    fn claim_event_carries_the_pake_element_and_confirm_does_not() {
        let (client, _) = test_client();
        let recipient = Keys::generate().public_key();
        let element = [2u8; 33];

        let claim = create_handshake_event(
            &client,
            &recipient,
            "transfer-id",
            HandshakeType::Claim,
            b"sealed",
            Some(&element),
        )
        .expect("claim event");

        assert_eq!(claim.kind.as_u16(), EVENT_KIND_DATA_TRANSFER);
        assert_eq!(tag_value(&claim, "type"), Some("claim"));
        assert_eq!(tag_value(&claim, "p"), Some(recipient.to_hex().as_str()));

        let parsed = parse_handshake_event(&claim).expect("parses");
        assert_eq!(parsed.handshake_type, HandshakeType::Claim);
        assert_eq!(parsed.transfer_id, "transfer-id");
        assert_eq!(parsed.sealed_payload, b"sealed");
        assert_eq!(parsed.pake_message.as_deref(), Some(&element[..]));

        let confirm = create_handshake_event(
            &client,
            &recipient,
            "transfer-id",
            HandshakeType::Confirm,
            b"sealed",
            None,
        )
        .expect("confirm event");
        let wire: serde_json::Value = serde_json::from_str(&confirm.content).expect("envelope");
        assert!(wire.get("pake").is_none());
        assert!(
            parse_handshake_event(&confirm)
                .expect("parses")
                .pake_message
                .is_none()
        );
    }

    /// Drive a complete PIN handshake through the real event encodings: the
    /// plaintext rendezvous, the claim envelope carrying `pB`, and the sealed
    /// confirm carrying the metadata. Both sides must land on the same session
    /// keys and the same confirmation code without ever touching a relay.
    #[test]
    fn pake_handshake_round_trips_through_the_wire_format() {
        use crate::crypto::kdf::{ConfirmationCodeBinding, generate_salt};
        use crate::crypto::spake2::{
            PakeIdentities, PakeRole, PakeRun, derive_pake_secret, is_valid_pake_message,
        };

        let (sender_client, sender_keys) = test_client();
        let (receiver_client, receiver_keys) = test_client();
        let sender_hex = sender_keys.public_key().to_hex();
        let receiver_hex = receiver_keys.public_key().to_hex();

        let pin = "ABCDEFGHJKLA";
        let pake_secret = derive_pake_secret(pin);
        let salt = generate_salt().unwrap();
        let transfer_id = "a1b2c3d4e5f60718";

        // Sender: fresh SPAKE2 run, plaintext rendezvous.
        let sender_pake = PakeRun::start(PakeRole::Sender, &pake_secret).unwrap();
        let rendezvous = RendezvousPayload {
            payload_type: "rendezvous".to_string(),
            transfer_id: transfer_id.to_string(),
            sender_pubkey: sender_hex.clone(),
            pake_message: STANDARD.encode(sender_pake.message()),
            nonce: generate_handshake_nonce().unwrap(),
            relays: Some(default_relays_vec()),
        };
        let sender_transcript = compute_rendezvous_transcript_hash(&rendezvous, &salt).unwrap();
        let rendezvous_event =
            create_rendezvous_event(&sender_client, &rendezvous, &salt, "aabbccdd", 123).unwrap();

        // Receiver: parse, run its side of the PAKE, seal a claim.
        let parsed = parse_rendezvous_event(&rendezvous_event).expect("parses");
        let peer_element = STANDARD.decode(&parsed.payload.pake_message).unwrap();
        assert!(is_valid_pake_message(&peer_element));

        let identities = PakeIdentities {
            transfer_id,
            sender_pubkey: &sender_hex,
            receiver_pubkey: &receiver_hex,
        };
        let receiver_pake = PakeRun::start(PakeRole::Receiver, &pake_secret).unwrap();
        let receiver_root = receiver_pake.finish(&peer_element, &identities).unwrap();
        let receiver_seals = receiver_root.handshake_seal_keys(&parsed.salt).unwrap();
        let receiver_transcript =
            compute_rendezvous_transcript_hash(&parsed.payload, &parsed.salt).unwrap();
        assert_eq!(receiver_transcript, sender_transcript);

        let receiver_nonce = generate_handshake_nonce().unwrap();
        let claim = ClaimPayload {
            payload_type: "claim".to_string(),
            transfer_id: transfer_id.to_string(),
            sender_nonce: parsed.payload.nonce.clone(),
            receiver_nonce: receiver_nonce.clone(),
            sender_pubkey: sender_hex.clone(),
            receiver_pubkey: receiver_hex.clone(),
            transcript_hash: receiver_transcript.clone(),
        };
        let claim_event = create_handshake_event(
            &receiver_client,
            &sender_keys.public_key(),
            transfer_id,
            HandshakeType::Claim,
            &seal_handshake_payload(&receiver_seals.claim, &claim).unwrap(),
            Some(receiver_pake.message()),
        )
        .unwrap();

        // Sender: finish against the claimant's element and open the seal.
        let parsed_claim = parse_handshake_event(&claim_event).expect("parses");
        let claim_element = parsed_claim.pake_message.expect("claims carry an element");
        let sender_root = sender_pake.finish(&claim_element, &identities).unwrap();
        let sender_seals = sender_root.handshake_seal_keys(&salt).unwrap();
        let opened: ClaimPayload =
            open_handshake_payload(&sender_seals.claim, &parsed_claim.sealed_payload).unwrap();
        assert_eq!(opened.sender_nonce, rendezvous.nonce);
        assert_eq!(opened.transcript_hash, sender_transcript);

        // Sender: confirm, sealed with the confirm key, carrying the metadata.
        let metadata = sample_metadata();
        let metadata_hash = compute_transfer_metadata_hash(&metadata).unwrap();
        let confirm = ConfirmPayload {
            payload_type: "confirm".to_string(),
            transfer_id: transfer_id.to_string(),
            sender_nonce: rendezvous.nonce.clone(),
            receiver_nonce: receiver_nonce.clone(),
            sender_pubkey: sender_hex.clone(),
            receiver_pubkey: receiver_hex.clone(),
            transcript_hash: sender_transcript.clone(),
            metadata,
        };
        let confirm_event = create_handshake_event(
            &sender_client,
            &receiver_keys.public_key(),
            transfer_id,
            HandshakeType::Confirm,
            &seal_handshake_payload(&sender_seals.confirm, &confirm).unwrap(),
            None,
        )
        .unwrap();

        let parsed_confirm = parse_handshake_event(&confirm_event).expect("parses");
        let opened_confirm: ConfirmPayload =
            open_handshake_payload(&receiver_seals.confirm, &parsed_confirm.sealed_payload).unwrap();
        assert_eq!(opened_confirm.receiver_nonce, receiver_nonce);
        assert_eq!(
            compute_transfer_metadata_hash(&opened_confirm.metadata).unwrap(),
            metadata_hash
        );

        // Both sides agree on the code the humans compare and on the keys the
        // transfer runs under.
        let binding = ConfirmationCodeBinding {
            transfer_id,
            sender_nonce: &rendezvous.nonce,
            receiver_nonce: &receiver_nonce,
            transcript_hash: &sender_transcript,
            metadata_hash: &metadata_hash,
        };
        let sender_code = sender_root.confirmation_code(&salt, &binding).unwrap();
        assert_eq!(sender_code.len(), 8);
        assert_eq!(
            sender_code,
            receiver_root.confirmation_code(&parsed.salt, &binding).unwrap()
        );
        assert_eq!(
            sender_root.session_keys(&salt).unwrap().content,
            receiver_root.session_keys(&parsed.salt).unwrap().content
        );

        // A wrong PIN never opens the claim: the seal is the key confirmation.
        let wrong = PakeRun::start(PakeRole::Sender, &derive_pake_secret("ABCDEFGHJKLZ")).unwrap();
        let wrong_root = wrong.finish(&claim_element, &identities).unwrap();
        let wrong_seals = wrong_root.handshake_seal_keys(&salt).unwrap();
        assert!(
            open_handshake_payload::<ClaimPayload>(
                &wrong_seals.claim,
                &parsed_claim.sealed_payload
            )
            .is_err()
        );
    }

    #[test]
    fn rendezvous_transcript_matches_web_fixed_vector() {
        assert_eq!(
            compute_rendezvous_transcript_hash(&sample_rendezvous(), &[7_u8; 32]).unwrap(),
            "614d33304b183901aa0a9dae42add9b0b8b843b76b3b22f1f1e890a0d08e7643"
        );
    }

    #[test]
    fn metadata_transcript_matches_web_fixed_vector() {
        assert_eq!(
            compute_transfer_metadata_hash(&sample_metadata()).unwrap(),
            "4e81dd4145657c1786a5a7109907cc70b1492cd17a8dcf1cfeeccf81c92aee26"
        );
    }
}
