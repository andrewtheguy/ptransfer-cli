//! The PT01 container Code Exchange hands from one device to the other.
//!
//! Code Exchange has no signaling server: the sender's offer and the
//! receiver's answer are both carried by a person. The web app can carry them
//! as QR codes or as base64 text; this CLI carries them as **base64 text
//! only** today. Drawing the offer as a QR grid is on the roadmap; reading a
//! code back is not, since there is no camera at a terminal.
//!
//! What travels is the same container either way:
//!
//! ```text
//! [ "PT01" ][ xorObfuscate( [ "mag!" ][ deflate-raw(JSON) ], hourly seed ) ]
//! ```
//!
//! The obfuscation is not encryption and is not treated as any: it exists so a
//! blob that lands in a chat log does not read as an SDP offer, and its hourly
//! seed bucket keeps a stale code from being decoded weeks later. Everything
//! that actually protects the transfer is downstream — the ECDH agreement in
//! [`super::keys`], and the answer confirmation tag the sender checks before
//! it acts on a response at all.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use flate2::Compression;
use flate2::write::DeflateEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::wire::{Inflater, WireEncoding};

/// Plaintext container header: "PT01", the Code Exchange signaling format
/// version. Outside the obfuscated area so a reader can tell what it is
/// holding without guessing a seed.
const MAGIC_HEADER: [u8; 4] = *b"PT01";
/// Inside the obfuscated area: the marker that says a candidate seed was the
/// right one, checked before the rest of the buffer is touched.
const INNER_MAGIC: [u8; 4] = *b"mag!";
/// Obfuscation seed bucket, in seconds.
const BUCKET_SEC: i64 = 3600;
/// Seed mixer's starting constant.
const BASE_SEED: u32 = 0x9e37_79b9;

/// How long a code may be acted on, from the moment the offer was made.
/// The web app's `TRANSFER_EXPIRATION_MS`.
pub const TRANSFER_EXPIRATION_MS: i64 = 60 * 60 * 1000;

/// The key-confirmation tag an answer carries (`ANSWER_CONFIRMATION_BYTES`).
pub const ANSWER_CONFIRMATION_LEN: usize = 16;

/// Salt carried by an offer, and the HKDF salt of every Code Exchange
/// derivation.
pub const CODE_SALT_LEN: usize = 16;

/// Uncompressed SEC1 P-256 public key, as the payload carries it.
pub const PUBLIC_KEY_LEN: usize = 65;

/// The widest `createdAt` a payload may carry: milliseconds since the epoch,
/// through the end of year 9999.
///
/// A hand-carried payload's stamp is an arbitrary number until something says
/// otherwise, and everything this side does with it is arithmetic — the age
/// against now, the session deadline a TTL past it. Bounding it here is what
/// keeps that arithmetic from overflowing on a value nobody could mean, which
/// in a release build would come out the other side looking fresh.
const MAX_CREATED_AT_MS: i64 = 253_402_300_799_999;

/// A payload's own bound on decompressed size. An offer is a couple of
/// kilobytes; this only stops a hand-carried blob from being a deflate bomb.
const MAX_PAYLOAD_BYTES: u64 = 512 * 1024;

/// Which half of the exchange a payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadKind {
    Offer,
    Answer,
}

/// The hand-carried signaling payload, in the web app's `SignalingPayload`
/// shape. Offer-only and answer-only fields are optional here and checked by
/// [`SignalingPayload::validate`], which is where "offer-only" is enforced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalingPayload {
    #[serde(rename = "type")]
    pub kind: PayloadKind,
    pub sdp: String,
    /// ICE candidates as their SDP `candidate:` strings.
    pub candidates: Vec<String>,
    /// Milliseconds since the epoch; the TTL both sides enforce runs from it.
    pub created_at: i64,
    /// Uncompressed P-256 ECDH public key (65 bytes).
    pub public_key: Vec<u8>,
    /// Answer-only and mandatory there: the key-confirmation tag, base64.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<WireEncoding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Offer-only: the HKDF salt of every derivation off the ECDH secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<Vec<u8>>,
    /// Offer-only: the control relays of the clearnet Nostr file-relay
    /// fallback, proven before the code was shown. An offer that names them
    /// promises a receiver that path; one that names none has no clearnet
    /// fallback at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relays: Option<Vec<String>>,
    /// Offer-only, and only ever `true`: this transfer's fallback runs inside
    /// Tor. The sender's switch, and the only thing that decides it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anon: Option<bool>,
}

impl SignalingPayload {
    /// Whether this offer asks for the Tor fallback rather than the clearnet
    /// one. Always false on an answer.
    pub fn is_anonymous(&self) -> bool {
        self.kind == PayloadKind::Offer && self.anon == Some(true)
    }

    /// Structural validation, matching `isValidSignalingPayload`.
    ///
    /// The offer-only/answer-only rules are not tidiness: an answer carrying a
    /// relay list, or an offer carrying a confirmation tag, is a payload
    /// nothing on either side produces, so it is refused rather than read
    /// selectively.
    fn validate(&self) -> Result<()> {
        if self.public_key.len() != PUBLIC_KEY_LEN {
            bail!("signaling payload carries a malformed public key");
        }
        if !(0..=MAX_CREATED_AT_MS).contains(&self.created_at) {
            bail!("signaling payload carries a timestamp that is not a time");
        }
        match self.kind {
            PayloadKind::Offer => {
                // Nothing earlier exists for an offer's tag to be bound to.
                if self.confirm.is_some() {
                    bail!("an offer may not carry a confirmation tag");
                }
                if self.anon.is_some_and(|anon| !anon) {
                    bail!("an offer's anonymous flag is only ever true");
                }
                // The two fallbacks are alternatives, and only the clearnet one
                // names its relays: an offer carrying both asks the receiver to
                // pick, which no implementation does.
                if self.relays.is_some() && self.anon.is_some() {
                    bail!("an offer names relays or asks for Tor, never both");
                }
                // A relay list that is not one invalidates the whole offer
                // rather than being trimmed to what parses: it is covered by
                // the offer digest the answer's confirmation tag is bound to,
                // so a list neither side would have written is not an offer
                // either side made.
                if let Some(relays) = self.relays.as_ref() {
                    self.fallback_relays_from(relays)?;
                }
                let Some(salt) = self.salt.as_ref() else {
                    bail!("an offer must carry a salt");
                };
                if salt.len() != CODE_SALT_LEN {
                    bail!("an offer's salt must be {CODE_SALT_LEN} bytes");
                }
                if self.file_name.as_ref().is_none_or(String::is_empty) {
                    bail!("an offer must name the file it is offering");
                }
                if self.file_size.is_none() {
                    bail!("an offer must carry the file size");
                }
                if self.content_encoding.is_none() {
                    bail!("an offer must carry a content encoding");
                }
            }
            PayloadKind::Answer => {
                // Every offer-only field, not just the three that steer a
                // fallback: none of them is covered by the answer transcript
                // the confirmation tag is computed over, so one carried here
                // would be a correctly tagged field nothing agreed on — the
                // file's own name and size among them.
                if self.salt.is_some()
                    || self.relays.is_some()
                    || self.anon.is_some()
                    || self.file_name.is_some()
                    || self.file_size.is_some()
                    || self.content_encoding.is_some()
                    || self.mime_type.is_some()
                {
                    bail!("an answer carries no offer-only fields");
                }
                let Some(confirm) = self.confirm.as_deref() else {
                    bail!("an answer must carry a confirmation tag");
                };
                if decode_answer_confirmation(confirm).is_none() {
                    bail!("an answer's confirmation tag is malformed");
                }
            }
        }
        Ok(())
    }

    /// The clearnet fallback's control relays, in canonical form, or `None`
    /// when this offer has no clearnet fallback.
    pub fn fallback_relays(&self) -> Option<Vec<String>> {
        if self.kind != PayloadKind::Offer || self.is_anonymous() {
            return None;
        }
        self.relays
            .as_ref()
            .and_then(|relays| self.fallback_relays_from(relays).ok())
    }

    fn fallback_relays_from(&self, relays: &[String]) -> Result<Vec<String>> {
        crate::code::nostr_file::relays::offer_relays(
            relays,
            crate::code::nostr_file::OFFER_RELAY_COUNT,
            crate::code::nostr_file::MIN_OFFER_RELAYS,
        )
    }

    /// The tag as raw bytes. Only ever `Some` on a payload that validated as
    /// an answer.
    pub fn confirmation_tag(&self) -> Option<[u8; ANSWER_CONFIRMATION_LEN]> {
        decode_answer_confirmation(self.confirm.as_deref()?)
    }

    /// The offer's salt, which validation guarantees is present and sized.
    pub fn offer_salt(&self) -> Result<[u8; CODE_SALT_LEN]> {
        let salt = self.salt.as_ref().context("payload carries no salt")?;
        let mut out = [0u8; CODE_SALT_LEN];
        if salt.len() != CODE_SALT_LEN {
            bail!("payload salt is not {CODE_SALT_LEN} bytes");
        }
        out.copy_from_slice(salt);
        Ok(out)
    }

    /// The peer's ECDH public key, sized.
    pub fn peer_public_key(&self) -> Result<[u8; PUBLIC_KEY_LEN]> {
        let mut out = [0u8; PUBLIC_KEY_LEN];
        if self.public_key.len() != PUBLIC_KEY_LEN {
            bail!("payload public key is not {PUBLIC_KEY_LEN} bytes");
        }
        out.copy_from_slice(&self.public_key);
        Ok(out)
    }
}

/// Milliseconds since the epoch, the clock every `createdAt` is stamped from.
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// The obfuscation seed for one hourly bucket. A 32-bit MurmurHash3 finalizer
/// over the bucket index; `Math.imul` in the web app is a wrapping 32-bit
/// multiply, which is what `wrapping_mul` is here.
fn seed_for_bucket(bucket_epoch: i64) -> u32 {
    let mut h = BASE_SEED ^ (bucket_epoch as i32 as u32);
    h = (h ^ (h >> 16)).wrapping_mul(0x85eb_ca6b);
    h = (h ^ (h >> 13)).wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

fn xorshift32(mut state: u32) -> u32 {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    state
}

/// XOR a buffer against the keystream of the bucket seed, in place.
///
/// Its own inverse, which is why one function covers both directions.
fn xor_obfuscate(data: &mut [u8], seed: u32) {
    let mut state = seed;
    for byte in data {
        state = xorshift32(state);
        *byte ^= (state & 0xff) as u8;
    }
}

fn deflate_raw(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write as _;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn inflate_raw(data: &[u8]) -> Result<Vec<u8>> {
    let mut inflater = Inflater::new(MAX_PAYLOAD_BYTES);
    let mut out = Vec::new();
    out.extend_from_slice(inflater.push(data)?);
    out.extend_from_slice(inflater.finish()?);
    Ok(out)
}

/// Encode a payload into the PT01 container, stamped with the current hourly
/// seed bucket.
pub fn encode(payload: &SignalingPayload) -> Result<Vec<u8>> {
    let compressed = deflate_raw(&serde_json::to_vec(payload)?)?;

    let mut inner = Vec::with_capacity(INNER_MAGIC.len() + compressed.len());
    inner.extend_from_slice(&INNER_MAGIC);
    inner.extend_from_slice(&compressed);
    xor_obfuscate(&mut inner, seed_for_bucket(now_ms() / 1000 / BUCKET_SEC));

    let mut out = Vec::with_capacity(MAGIC_HEADER.len() + inner.len());
    out.extend_from_slice(&MAGIC_HEADER);
    out.extend_from_slice(&inner);
    Ok(out)
}

/// Whether these bytes are a PT01 container at all. Cheap enough to run over
/// anything a person pasted, which is what tells one mode's code from
/// another's.
pub fn is_code_payload(binary: &[u8]) -> bool {
    binary.len() >= 8 && binary[..4] == MAGIC_HEADER
}

/// Decode a PT01 container and validate the payload inside it.
///
/// The seed is tried for the current and the immediately previous hourly
/// bucket — a two-hour window that tolerates a sender whose clock sits in the
/// receiver's previous bucket. It is not the session TTL: a payload that
/// decodes may still be expired, which is [`check_freshness`]'s job.
pub fn decode(binary: &[u8]) -> Result<SignalingPayload> {
    if !is_code_payload(binary) {
        bail!("that does not look like a pTransfer code");
    }
    let obfuscated = &binary[4..];
    let current = now_ms() / 1000 / BUCKET_SEC;

    for bucket in [current, current - 1] {
        let seed = seed_for_bucket(bucket);
        // De-obfuscate the marker alone first: a wrong seed is the common case
        // while walking the window, and it costs four bytes to rule out.
        let mut head = [0u8; 4];
        head.copy_from_slice(&obfuscated[..4]);
        xor_obfuscate(&mut head, seed);
        if head != INNER_MAGIC {
            continue;
        }
        let mut inner = obfuscated.to_vec();
        xor_obfuscate(&mut inner, seed);
        let json = inflate_raw(&inner[4..]).context("the code's payload could not be read")?;
        let payload: SignalingPayload =
            serde_json::from_slice(&json).context("the code carries an unreadable payload")?;
        payload.validate()?;
        return Ok(payload);
    }

    bail!("that code is not from the last hour or two — ask for a fresh one")
}

/// Reject a code whose session has run out. The clock starts at the offer's
/// `createdAt` on both sides, so an answer is judged against the offer it
/// answers rather than against its own stamp.
pub fn check_freshness(created_at: i64) -> Result<()> {
    // Saturating, not wrapping: validation bounds the stamp, and this is the
    // one place that arithmetic is reached from, so the two together are what
    // makes a stamp nobody could mean report as stale rather than as fresh.
    let age = now_ms().saturating_sub(created_at);
    if age > TRANSFER_EXPIRATION_MS {
        bail!("This code has expired. Ask for a fresh one.");
    }
    Ok(())
}

/// Base64 of the container, as it travels through a clipboard.
pub fn to_clipboard(binary: &[u8]) -> String {
    BASE64.encode(binary)
}

/// The container behind pasted base64, whitespace and line wrapping ignored.
pub fn from_clipboard(text: &str) -> Result<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64
        .decode(compact.as_bytes())
        .context("that is not a pTransfer code — check that the whole thing was copied")
}

/// Digest of the exact offer container both sides must agree on.
///
/// The bytes themselves, not a re-serialization of the parsed fields: the
/// container is handed over unmodified, so hashing it commits to everything it
/// carried — including any field a reader would not know to canonicalize.
pub fn offer_transcript_hash(offer_binary: &[u8]) -> String {
    hex_lower(&Sha256::digest(offer_binary))
}

const ANSWER_TRANSCRIPT_LABEL: &str = "ptransfer:code-exchange-answer-transcript:v1";

/// Digest of an answer's own contents: every field the sender acts on, and
/// only those.
///
/// Unlike the offer digest this cannot hash the container, because the tag
/// bound to it lives inside that container. A canonical JSON array fixes
/// element order here instead of leaving it to key ordering, and JSON escaping
/// keeps one field's value from forging a delimiter into the next.
pub fn answer_transcript_hash(payload: &SignalingPayload) -> Result<String> {
    let canonical = serde_json::to_vec(&serde_json::json!([
        ANSWER_TRANSCRIPT_LABEL,
        payload.kind,
        payload.sdp,
        payload.candidates,
        payload.created_at,
        hex_lower(&payload.public_key),
    ]))?;
    Ok(hex_lower(&Sha256::digest(canonical)))
}

/// The raw tag behind an answer's base64 `confirm`, or `None` when the field
/// is not one.
fn decode_answer_confirmation(value: &str) -> Option<[u8; ANSWER_CONFIRMATION_LEN]> {
    // 16 bytes is 22 base64 characters plus "==". A different length is not a
    // tag whatever it decodes to.
    if value.len() != ANSWER_CONFIRMATION_LEN.div_ceil(3) * 4 {
        return None;
    }
    let bytes = BASE64.decode(value).ok()?;
    let mut tag = [0u8; ANSWER_CONFIRMATION_LEN];
    if bytes.len() != ANSWER_CONFIRMATION_LEN {
        return None;
    }
    tag.copy_from_slice(&bytes);
    Some(tag)
}

/// Base64 of a raw tag, as it travels in an answer.
pub fn encode_answer_confirmation(tag: &[u8; ANSWER_CONFIRMATION_LEN]) -> String {
    BASE64.encode(tag)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> SignalingPayload {
        SignalingPayload {
            kind: PayloadKind::Offer,
            sdp: "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n".to_string(),
            candidates: vec!["candidate:1 1 udp 2130706431 10.0.0.1 5000 typ host".to_string()],
            created_at: now_ms(),
            public_key: vec![4u8; PUBLIC_KEY_LEN],
            confirm: None,
            file_name: Some("report.pdf".to_string()),
            file_size: Some(1024),
            content_encoding: Some(WireEncoding::DeflateRaw),
            mime_type: Some("application/pdf".to_string()),
            salt: Some(vec![7u8; CODE_SALT_LEN]),
            relays: None,
            anon: None,
        }
    }

    fn answer() -> SignalingPayload {
        SignalingPayload {
            kind: PayloadKind::Answer,
            sdp: "v=0\r\n".to_string(),
            candidates: vec![],
            created_at: now_ms(),
            public_key: vec![4u8; PUBLIC_KEY_LEN],
            confirm: Some(encode_answer_confirmation(&[3u8; ANSWER_CONFIRMATION_LEN])),
            file_name: None,
            file_size: None,
            content_encoding: None,
            mime_type: None,
            salt: None,
            relays: None,
            anon: None,
        }
    }

    /// The seed derivation is the one thing a second implementation cannot
    /// discover by experiment: a wrong mixer decodes nothing and says only
    /// that the code is stale. These are the web app's values.
    #[test]
    fn the_seed_mixer_matches_the_web_app() {
        assert_eq!(seed_for_bucket(0), 0x92ca_2f0e);
        assert_eq!(seed_for_bucket(1), 0x36de_b503);
        assert_eq!(seed_for_bucket(485_000), 0xd0d4_437a);
    }

    /// The keystream itself, not only the seed: a xorshift whose shifts drift
    /// still produces plausible-looking noise, and the failure would read as
    /// "that code is not from the last hour or two" on the other side.
    #[test]
    fn the_keystream_matches_the_web_app() {
        let mut bytes = [0u8; 8];
        xor_obfuscate(&mut bytes, seed_for_bucket(0));
        assert_eq!(bytes, [251, 137, 246, 139, 171, 163, 130, 141]);
    }

    #[test]
    fn a_container_round_trips() {
        let encoded = encode(&offer()).unwrap();
        assert!(is_code_payload(&encoded));
        assert_eq!(&encoded[..4], b"PT01");
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.file_name.as_deref(), Some("report.pdf"));
        assert_eq!(decoded.salt.unwrap().len(), CODE_SALT_LEN);
    }

    #[test]
    fn clipboard_text_round_trips_through_whitespace() {
        let encoded = encode(&answer()).unwrap();
        let text = to_clipboard(&encoded);
        let wrapped = format!("  {}\n{}  \n", &text[..10], &text[10..]);
        assert_eq!(from_clipboard(&wrapped).unwrap(), encoded);
    }

    /// The obfuscation is not a control, but a container that came out
    /// readable would mean the seed was never applied at all.
    #[test]
    fn the_payload_is_not_readable_in_the_clear() {
        let encoded = encode(&offer()).unwrap();
        assert!(!encoded.windows(4).any(|window| window == b"mag!"));
    }

    /// Offer-only means every offer-only field. None of them is covered by
    /// the answer transcript the confirmation tag is computed over, so an
    /// answer carrying one would be a correctly tagged claim about a file that
    /// nothing agreed to — the sender's own metadata, overwritten on the way
    /// back.
    #[test]
    fn an_answer_carrying_any_offer_only_field_is_refused() {
        /// One offer-only field set on an answer.
        type Mutation = fn(&mut SignalingPayload);
        let mutations: [(&str, Mutation); 7] = [
            ("salt", |p| p.salt = Some(vec![7u8; CODE_SALT_LEN])),
            ("relays", |p| p.relays = Some(vec!["wss://relay".to_string()])),
            ("anon", |p| p.anon = Some(true)),
            ("fileName", |p| p.file_name = Some("other.pdf".to_string())),
            ("fileSize", |p| p.file_size = Some(1)),
            ("contentEncoding", |p| {
                p.content_encoding = Some(WireEncoding::Identity)
            }),
            ("mimeType", |p| p.mime_type = Some("text/plain".to_string())),
        ];
        for (field, mutate) in mutations {
            let mut payload = answer();
            mutate(&mut payload);
            let encoded = encode(&payload).unwrap();
            assert!(
                decode(&encoded).is_err(),
                "an answer carrying {field} should be refused"
            );
        }
        // And the answer they were derived from is still accepted.
        assert!(decode(&encode(&answer()).unwrap()).is_ok());
    }

    /// A stamp is an arbitrary number carried by hand until something bounds
    /// it, and every use of it here is arithmetic. Out of range it is refused;
    /// were it not, the age of `i64::MIN` would wrap in a release build and
    /// come out looking like a code minted moments ago.
    #[test]
    fn a_timestamp_nothing_could_mean_is_refused() {
        for stamp in [i64::MIN, -1, MAX_CREATED_AT_MS + 1, i64::MAX] {
            let mut payload = offer();
            payload.created_at = stamp;
            let encoded = encode(&payload).unwrap();
            assert!(decode(&encoded).is_err(), "{stamp} is not a time");
        }

        // Nothing before validation can be relied on to have run, so the check
        // that reads a stamp does not overflow on one either.
        assert!(check_freshness(i64::MIN).is_err());
        assert!(check_freshness(i64::MAX).is_ok());
    }

    #[test]
    fn an_offer_without_a_salt_is_refused() {
        let mut payload = offer();
        payload.salt = None;
        let encoded = encode(&payload).unwrap();
        assert!(decode(&encoded).is_err());
    }

    /// An answer is the only thing that carries a tag, and it must carry one:
    /// without it there is nothing for the sender to check the response
    /// against, which is the whole confirmation step.
    #[test]
    fn the_confirmation_tag_is_answer_only_and_mandatory() {
        let mut without = answer();
        without.confirm = None;
        assert!(decode(&encode(&without).unwrap()).is_err());

        let mut on_an_offer = offer();
        on_an_offer.confirm = Some(encode_answer_confirmation(&[1u8; ANSWER_CONFIRMATION_LEN]));
        assert!(decode(&encode(&on_an_offer).unwrap()).is_err());

        let mut malformed = answer();
        malformed.confirm = Some("not-a-tag".to_string());
        assert!(decode(&encode(&malformed).unwrap()).is_err());
    }

    /// The flag says which fallback to spend a Tor bootstrap on, so `false`
    /// would be an offer describing the fallback it is not.
    #[test]
    fn the_anonymous_flag_is_offer_only_and_only_true() {
        let mut anonymous = offer();
        anonymous.anon = Some(true);
        assert!(decode(&encode(&anonymous).unwrap()).unwrap().is_anonymous());

        let mut falsy = offer();
        falsy.anon = Some(false);
        assert!(decode(&encode(&falsy).unwrap()).is_err());

        let mut both = offer();
        both.anon = Some(true);
        both.relays = Some(vec!["wss://relay.example".to_string()]);
        assert!(decode(&encode(&both).unwrap()).is_err());

        let mut on_an_answer = answer();
        on_an_answer.anon = Some(true);
        assert!(decode(&encode(&on_an_answer).unwrap()).is_err());
    }

    #[test]
    fn a_stale_code_is_refused_by_its_own_stamp() {
        assert!(check_freshness(now_ms()).is_ok());
        assert!(check_freshness(now_ms() - TRANSFER_EXPIRATION_MS + 5_000).is_ok());
        assert!(check_freshness(now_ms() - TRANSFER_EXPIRATION_MS - 1).is_err());
    }

    /// Anything that is not a container has to be rejected as one rather than
    /// parsed, because the receive box takes a PIN and an onion address too.
    #[test]
    fn foreign_text_is_not_a_code() {
        assert!(!is_code_payload(b"PT02abcd"));
        assert!(!is_code_payload(b"PT01"));
        assert!(decode(b"PT01\x00\x00\x00\x00").is_err());
    }

    /// The digest is over the container's bytes, so any edit anywhere in the
    /// offer changes it — that is what the answer's tag is bound to.
    #[test]
    fn the_offer_digest_covers_every_byte() {
        let encoded = encode(&offer()).unwrap();
        let mut edited = encoded.clone();
        let last = edited.len() - 1;
        edited[last] ^= 0x01;
        assert_ne!(offer_transcript_hash(&encoded), offer_transcript_hash(&edited));
    }

    /// The answer digest covers exactly the fields the sender acts on, and the
    /// tag it carries is not one of them.
    #[test]
    fn the_answer_digest_ignores_the_tag_and_covers_the_rest() {
        let base = answer();
        let mut other_tag = base.clone();
        other_tag.confirm = Some(encode_answer_confirmation(&[9u8; ANSWER_CONFIRMATION_LEN]));
        assert_eq!(
            answer_transcript_hash(&base).unwrap(),
            answer_transcript_hash(&other_tag).unwrap()
        );

        let mut edited = base.clone();
        edited.candidates.push("candidate:2 1 udp 1 10.0.0.2 5001 typ host".to_string());
        assert_ne!(
            answer_transcript_hash(&base).unwrap(),
            answer_transcript_hash(&edited).unwrap()
        );
    }

    /// A frozen digest, so the field order, the label, and the JSON escaping
    /// cannot drift from the web app's without a test saying so.
    #[test]
    fn the_answer_digest_matches_a_frozen_vector() {
        let payload = SignalingPayload {
            kind: PayloadKind::Answer,
            sdp: "v=0\r\na=answer\r\n".to_string(),
            candidates: vec!["candidate:1 1 udp 2130706431 192.0.2.1 5000 typ host".to_string()],
            created_at: 1_700_000_000_000,
            public_key: (0..PUBLIC_KEY_LEN as u8).collect(),
            confirm: Some(encode_answer_confirmation(&[0u8; ANSWER_CONFIRMATION_LEN])),
            file_name: None,
            file_size: None,
            content_encoding: None,
            mime_type: None,
            salt: None,
            relays: None,
            anon: None,
        };
        assert_eq!(
            answer_transcript_hash(&payload).unwrap(),
            "1e1498e7af0eefe6d37a4e2691302990d3fa68e7e80b0d2edc67198b828c2e21"
        );
    }
}
