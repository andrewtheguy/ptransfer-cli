//! Nostr signaling compatible with secure-send-web's Auto Exchange mode.
//!
//! Three event shapes, mirroring `src/lib/nostr/events.ts`:
//!
//! - **Rendezvous** (kind 24243, `type=rendezvous`): published by the sender
//!   once per PIN rotation, tagged with the rotation-bucket-scoped PIN hint
//!   (`#h`). The payload is sealed with the PIN-derived rendezvous key.
//! - **Handshake** (kind 24242, `type=claim|confirm`): the receiver claims the
//!   transfer, the sender confirms. Payloads are sealed with the PIN-derived
//!   auth key; the echoed identities, rendezvous transcript, nonces, and ECDH
//!   public keys bind the handshake to exactly what each peer accepted.
//! - **Signal** (kind 24242, `type=signal`): WebRTC offer/answer/candidates,
//!   sealed with the ECDH-derived session signaling key.

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

/// Rendezvous payload, sealed with the PIN-derived rendezvous key inside the
/// kind-24243 event. Republished with a fresh PIN, hint, and nonce on every
/// rotation; `transfer_id`, `sender_pubkey`, and `ecdh_public_key` stay stable
/// for the transfer's lifetime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RendezvousPayload {
    /// Always `"rendezvous"`.
    #[serde(rename = "type")]
    pub payload_type: String,
    pub content_type: String,
    pub transfer_id: String,
    /// Nostr pubkey of the sender; must equal the rendezvous event author.
    pub sender_pubkey: String,
    /// Sender's ephemeral ECDH public key (base64, 65-byte uncompressed P-256).
    pub ecdh_public_key: String,
    /// Sender handshake nonce (base64), fresh per rotation; echoed in the claim.
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,
    pub file_name: String,
    pub file_size: u64,
    /// False when `file_size` is an input-size estimate for a streamed ZIP.
    pub file_size_exact: bool,
    pub mime_type: String,
}

/// Claim payload (receiver -> sender), sealed with the PIN-derived auth key.
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
    /// Receiver's ephemeral ECDH public key (base64, 65-byte uncompressed P-256).
    pub receiver_ecdh_public_key: String,
    /// Echo of the sender's ECDH public key the receiver will run ECDH against.
    pub sender_ecdh_public_key: String,
    /// Sender identity from the rendezvous event author.
    pub sender_pubkey: String,
    /// Receiver identity, which must match the claim event author.
    pub receiver_pubkey: String,
    /// SHA-256 digest of the canonical rendezvous transcript.
    pub transcript_hash: String,
}

/// Confirm payload (sender -> receiver), sealed with the same PIN-derived auth
/// key that verified the claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmPayload {
    /// Always `"confirm"`.
    #[serde(rename = "type")]
    pub payload_type: String,
    pub transfer_id: String,
    pub sender_nonce: String,
    pub receiver_nonce: String,
    /// Echo of the receiver ECDH public key the sender locked the transfer to.
    pub receiver_ecdh_public_key: String,
    /// Sender identity, which must match the confirm event author.
    pub sender_pubkey: String,
    /// Receiver identity the sender locked onto.
    pub receiver_pubkey: String,
    /// Echo of the agreed rendezvous transcript digest.
    pub transcript_hash: String,
}

/// Compute secure-send-web's versioned canonical rendezvous transcript digest.
///
/// A JSON array fixes field order and JSON escaping prevents field-boundary
/// ambiguity. `relays` is canonicalized to an empty array when absent.
pub fn compute_rendezvous_transcript_hash(
    payload: &RendezvousPayload,
    salt: &[u8],
) -> Result<String> {
    const TRANSCRIPT_LABEL: &str = "secure-send:nostr-rendezvous-transcript:v1";

    let canonical = serde_json::to_vec(&serde_json::json!([
        TRANSCRIPT_LABEL,
        payload.payload_type,
        payload.content_type,
        payload.transfer_id,
        payload.sender_pubkey,
        payload.ecdh_public_key,
        payload.nonce,
        payload.relays.as_deref().unwrap_or(&[]),
        payload.file_name,
        payload.file_size,
        payload.file_size_exact,
        payload.mime_type,
        hex_lower(salt),
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

/// A parsed (but not yet opened) handshake event.
#[derive(Debug, Clone)]
pub struct ParsedHandshakeEvent {
    pub event_id: EventId,
    pub author: PublicKey,
    pub handshake_type: HandshakeType,
    pub transfer_id: String,
    pub sealed_payload: Vec<u8>,
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

/// Create a rendezvous event (kind 24243).
///
/// The NIP-40 `expiration` tag is the end of the PIN's immediately following
/// bucket, matching the sender's current-or-previous acceptance rule.
pub fn create_rendezvous_event(
    client: &NostrClient,
    encrypted_payload: &[u8],
    salt: &[u8],
    transfer_id: &str,
    hint: &str,
    pin_bucket: u64,
) -> Result<Event> {
    let expiration = (pin_bucket + PIN_ACTIVE_BUCKETS) * PIN_ROTATION_MS / 1000;
    let tags = vec![
        tag("h", hint)?,
        tag("s", STANDARD.encode(salt))?,
        tag("t", transfer_id)?,
        tag("type", "rendezvous")?,
        tag("expiration", expiration.to_string())?,
    ];

    client.sign(EventBuilder::new(rendezvous_kind(), STANDARD.encode(encrypted_payload)).tags(tags))
}

/// Parse a rendezvous event into `(hint, salt, transfer_id, encrypted_payload)`.
pub fn parse_rendezvous_event(event: &Event) -> Option<(String, Vec<u8>, String, Vec<u8>)> {
    if event.kind != rendezvous_kind() {
        return None;
    }

    let hint = tag_value(event, "h")?.to_string();
    let salt = STANDARD.decode(tag_value(event, "s")?).ok()?;
    let transfer_id = tag_value(event, "t")?.to_string();
    let encrypted_payload = STANDARD.decode(&event.content).ok()?;
    Some((hint, salt, transfer_id, encrypted_payload))
}

/// Seal a handshake payload (claim/confirm) with the PIN-derived auth key.
/// AES-GCM's authentication tag is what makes a wrong-PIN proof unverifiable.
pub fn seal_handshake_payload<T: Serialize>(
    auth_key: &[u8; aes::AES_KEY_LEN],
    payload: &T,
) -> Result<Vec<u8>> {
    aes::encrypt(auth_key, &serde_json::to_vec(payload)?)
}

/// Open a sealed handshake payload. Fails if the payload was not sealed with
/// this auth key (i.e. the author used a different PIN) or is not valid JSON.
/// Field validation is the caller's job.
pub fn open_handshake_payload<T: for<'de> Deserialize<'de>>(
    auth_key: &[u8; aes::AES_KEY_LEN],
    sealed_payload: &[u8],
) -> Result<T> {
    let decrypted = aes::decrypt(auth_key, sealed_payload)?;
    serde_json::from_slice(&decrypted).context("invalid handshake payload JSON")
}

/// Create a handshake event (kind 24242, `type=claim|confirm`).
///
/// Tags stay plaintext so relays can route by transfer and recipient, but they
/// carry no authority: the sealed body must decrypt under the PIN-derived auth
/// key and repeat the transfer/nonces before either side acts on it.
pub fn create_handshake_event(
    client: &NostrClient,
    recipient_pubkey: &PublicKey,
    transfer_id: &str,
    handshake_type: HandshakeType,
    sealed_payload: &[u8],
) -> Result<Event> {
    let tags = vec![
        tag("p", recipient_pubkey.to_hex())?,
        tag("t", transfer_id)?,
        tag("type", handshake_type.as_str())?,
    ];

    client.sign(EventBuilder::new(data_kind(), STANDARD.encode(sealed_payload)).tags(tags))
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

    Some(ParsedHandshakeEvent {
        event_id: event.id,
        author: event.pubkey,
        handshake_type,
        transfer_id: tag_value(event, "t")?.to_string(),
        sealed_payload: STANDARD.decode(&event.content).ok()?,
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
/// derived PIN hints.
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
    fn rendezvous_event_round_trips_and_matches_web_shape() {
        let (client, _) = test_client();
        let salt = [9u8; 16];
        let pin_bucket = 123;
        let event = create_rendezvous_event(
            &client,
            b"sealed",
            &salt,
            "transfer-id",
            "aabbccdd",
            pin_bucket,
        )
        .expect("rendezvous event");

        assert_eq!(event.kind.as_u16(), EVENT_KIND_RENDEZVOUS);
        assert_eq!(tag_value(&event, "type"), Some("rendezvous"));
        let expiration: u64 = tag_value(&event, "expiration").unwrap().parse().unwrap();
        assert_eq!(
            expiration,
            (pin_bucket + PIN_ACTIVE_BUCKETS) * PIN_ROTATION_MS / 1000
        );

        let (hint, parsed_salt, transfer_id, sealed) =
            parse_rendezvous_event(&event).expect("parses");
        assert_eq!(hint, "aabbccdd");
        assert_eq!(parsed_salt, salt);
        assert_eq!(transfer_id, "transfer-id");
        assert_eq!(sealed, b"sealed");
    }

    #[test]
    fn handshake_payloads_round_trip_with_camel_case() {
        let key = [3u8; aes::AES_KEY_LEN];
        let claim = ClaimPayload {
            payload_type: "claim".to_string(),
            transfer_id: "tid".to_string(),
            sender_nonce: "sn".to_string(),
            receiver_nonce: "rn".to_string(),
            receiver_ecdh_public_key: "rk".to_string(),
            sender_ecdh_public_key: "sk".to_string(),
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
        assert!(json.get("senderEcdhPublicKey").is_some());
        assert!(json.get("receiverNonce").is_some());
        assert_eq!(json["receiverPubkey"], "rpk");
        assert_eq!(json["transcriptHash"], "th");

        // Wrong key must fail to open.
        let wrong = [4u8; aes::AES_KEY_LEN];
        assert!(open_handshake_payload::<ClaimPayload>(&wrong, &sealed).is_err());
    }

    #[test]
    fn handshake_event_round_trips() {
        let (client, _) = test_client();
        let recipient = Keys::generate().public_key();
        let event = create_handshake_event(
            &client,
            &recipient,
            "transfer-id",
            HandshakeType::Claim,
            b"sealed",
        )
        .expect("handshake event");

        assert_eq!(event.kind.as_u16(), EVENT_KIND_DATA_TRANSFER);
        assert_eq!(tag_value(&event, "type"), Some("claim"));
        assert_eq!(tag_value(&event, "p"), Some(recipient.to_hex().as_str()));

        let parsed = parse_handshake_event(&event).expect("parses");
        assert_eq!(parsed.handshake_type, HandshakeType::Claim);
        assert_eq!(parsed.transfer_id, "transfer-id");
        assert_eq!(parsed.sealed_payload, b"sealed");
    }

    #[test]
    fn rendezvous_payload_serializes_like_web() {
        let payload = RendezvousPayload {
            payload_type: "rendezvous".to_string(),
            content_type: "file".to_string(),
            transfer_id: "tid".to_string(),
            sender_pubkey: "pk".to_string(),
            ecdh_public_key: "ek".to_string(),
            nonce: "n".to_string(),
            relays: Some(vec!["wss://r".to_string()]),
            file_name: "a.txt".to_string(),
            file_size: 42,
            file_size_exact: true,
            mime_type: "text/plain".to_string(),
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["type"], "rendezvous");
        assert_eq!(json["contentType"], "file");
        assert_eq!(json["ecdhPublicKey"], "ek");
        assert_eq!(json["fileSize"], 42);
        assert_eq!(json["fileSizeExact"], true);
    }

    #[test]
    fn rendezvous_transcript_matches_web_fixed_vector() {
        let payload = RendezvousPayload {
            payload_type: "rendezvous".to_string(),
            content_type: "file".to_string(),
            transfer_id: "a1b2c3d4e5f60718".to_string(),
            sender_pubkey: "a".repeat(64),
            ecdh_public_key: "BApublicKeyBase64==".to_string(),
            nonce: "c2VuZGVyLW5vbmNlLTAwMDAwMDA=".to_string(),
            relays: Some(vec![
                "wss://relay.one".to_string(),
                "wss://relay.two".to_string(),
            ]),
            file_name: "quarterly-report.pdf".to_string(),
            file_size: 1_048_576,
            file_size_exact: true,
            mime_type: "application/pdf".to_string(),
        };

        assert_eq!(
            compute_rendezvous_transcript_hash(&payload, &[7_u8; 32]).unwrap(),
            "87c2371953bb20ab03e79edc083f0033b6b739550155de7639d793ea48a3e818"
        );
    }
}
