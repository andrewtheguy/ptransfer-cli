//! Manual (copy/paste) signaling - the "PT01" payload format, byte-for-byte
//! compatible with pTransfer's `src/lib/manual-signaling.ts`.
//!
//! Wire pipeline (offer and answer are identical apart from the JSON body):
//!
//! ```text
//! JSON -> raw DEFLATE -> ["mag!" || compressed] -> XOR-obfuscate
//!      -> ["PT01" || obfuscated] -> standard base64
//! ```
//!
//! The XOR layer is obfuscation, not encryption (secrecy comes from ECDH); it
//! only deters casual inspection and is keyed by a 1-hour time bucket.

use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use serde::{Deserialize, Serialize};

use crate::crypto::ecdh::PUBLIC_KEY_LEN;

/// Outer magic: "PT01" (pTransfer manual-signaling format version 1).
const MAGIC_HEADER: [u8; 4] = [0x50, 0x54, 0x30, 0x31];
/// Inner magic: "mag!" - inside the obfuscated area to verify the XOR seed.
const INNER_MAGIC: [u8; 4] = [0x6d, 0x61, 0x67, 0x21];
const BUCKET_SEC: u64 = 3600;
const BASE_SEED: u32 = 0x9e37_79b9;
/// Transfer expiration (`TRANSFER_EXPIRATION_MS` = 1 hour), in milliseconds.
pub const TRANSFER_EXPIRATION_MS: u64 = 3_600_000;

/// Method-agnostic manual-exchange signaling payload (mirrors the web's
/// `SignalingPayload` interface). Serializes to the exact JSON field names.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalingPayload {
    #[serde(rename = "type")]
    pub payload_type: String,
    pub sdp: String,
    /// ICE candidates as raw SDP `candidate:` strings.
    pub candidates: Vec<String>,
    /// Milliseconds since the Unix epoch when this payload was generated.
    pub created_at: u64,
    /// ECDH public key (65 bytes, P-256 uncompressed) as a JSON number array.
    pub public_key: Vec<u8>,

    // Offer-only fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size_exact: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<Vec<u8>>,
}

impl SignalingPayload {
    /// Build an offer payload carrying file metadata, salt, and public key.
    #[allow(clippy::too_many_arguments)]
    pub fn offer(
        sdp: String,
        candidates: Vec<String>,
        created_at: u64,
        file_name: String,
        file_size: u64,
        file_size_exact: bool,
        mime_type: String,
        public_key: [u8; PUBLIC_KEY_LEN],
        salt: [u8; 16],
    ) -> Self {
        Self {
            payload_type: "offer".to_string(),
            sdp,
            candidates,
            created_at,
            public_key: public_key.to_vec(),
            file_name: Some(file_name),
            file_size: Some(file_size),
            file_size_exact: Some(file_size_exact),
            mime_type: Some(mime_type),
            salt: Some(salt.to_vec()),
        }
    }

    /// Build an answer payload carrying only the public key (no metadata/salt).
    pub fn answer(
        sdp: String,
        candidates: Vec<String>,
        created_at: u64,
        public_key: [u8; PUBLIC_KEY_LEN],
    ) -> Self {
        Self {
            payload_type: "answer".to_string(),
            sdp,
            candidates,
            created_at,
            public_key: public_key.to_vec(),
            file_name: None,
            file_size: None,
            file_size_exact: None,
            mime_type: None,
            salt: None,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.payload_type != "offer" && self.payload_type != "answer" {
            bail!(
                "invalid signaling payload: unknown type {:?}",
                self.payload_type
            );
        }
        if self.public_key.len() != PUBLIC_KEY_LEN {
            bail!(
                "invalid signaling payload: public key must be {PUBLIC_KEY_LEN} bytes, got {}",
                self.public_key.len()
            );
        }
        Ok(())
    }
}

/// Current time in milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64
}

/// True if a payload's `created_at` (ms) is older than the transfer TTL.
pub fn is_expired(created_at_ms: u64) -> bool {
    now_ms().saturating_sub(created_at_ms) > TRANSFER_EXPIRATION_MS
}

fn current_bucket() -> u32 {
    (now_ms() / 1000 / BUCKET_SEC) as u32
}

/// MurmurHash3-style finalizer of `BASE_SEED ^ bucket`, using 32-bit wrapping
/// arithmetic to match JavaScript's `Math.imul` / `>>> 0` semantics.
fn seed_for_bucket(bucket: u32) -> u32 {
    let mut h = BASE_SEED ^ bucket;
    h = (h ^ (h >> 16)).wrapping_mul(0x85eb_ca6b);
    h = (h ^ (h >> 13)).wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

fn xorshift32(mut s: u32) -> u32 {
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    s
}

/// XOR each byte with the next `xorshift32` keystream byte. The first output
/// byte uses `xorshift32(seed)` (the seed itself is never applied directly).
fn xor_obfuscate(data: &[u8], seed: u32) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        state = xorshift32(state);
        out.push(b ^ (state & 0xff) as u8);
    }
    out
}

fn deflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn inflate(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

/// Encode a payload to the base64 PT01 clipboard string (uses the current time
/// bucket for obfuscation, matching the web app).
pub fn encode(payload: &SignalingPayload) -> Result<String> {
    let json = serde_json::to_vec(payload)?;
    let compressed = deflate(&json)?;

    let mut inner = Vec::with_capacity(INNER_MAGIC.len() + compressed.len());
    inner.extend_from_slice(&INNER_MAGIC);
    inner.extend_from_slice(&compressed);

    let obfuscated = xor_obfuscate(&inner, seed_for_bucket(current_bucket()));

    let mut binary = Vec::with_capacity(MAGIC_HEADER.len() + obfuscated.len());
    binary.extend_from_slice(&MAGIC_HEADER);
    binary.extend_from_slice(&obfuscated);

    Ok(STANDARD.encode(&binary))
}

/// Decode a base64 PT01 clipboard string back into a payload. Tries the current
/// and previous time bucket (a ~2-hour window), mirroring the web app.
pub fn decode(input: &str) -> Result<SignalingPayload> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let binary = STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid base64: {e}"))?;

    if binary.len() < 8 || binary[..4] != MAGIC_HEADER {
        bail!("not a valid PT01 payload (bad magic header)");
    }
    let obfuscated_inner = &binary[4..];
    let bucket = current_bucket();

    for i in 0..=1u32 {
        let seed = seed_for_bucket(bucket.saturating_sub(i));

        // Cheap check: de-obfuscate only the 4 inner-magic bytes first.
        let head = xor_obfuscate(&obfuscated_inner[..4], seed);
        if head != INNER_MAGIC {
            continue;
        }

        let deobfuscated = xor_obfuscate(obfuscated_inner, seed);
        let compressed = &deobfuscated[4..];
        let Ok(json) = inflate(compressed) else {
            continue;
        };
        let Ok(payload) = serde_json::from_slice::<SignalingPayload>(&json) else {
            continue;
        };
        payload.validate()?;
        return Ok(payload);
    }

    bail!("could not decode PT01 payload (expired or corrupted)");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_offer() -> SignalingPayload {
        SignalingPayload::offer(
            "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\n".to_string(),
            vec!["candidate:1 1 udp 1 1.2.3.4 5000 typ host".to_string()],
            now_ms(),
            "photo.jpg".to_string(),
            42,
            true,
            "image/jpeg".to_string(),
            [4u8; PUBLIC_KEY_LEN],
            [9u8; 16],
        )
    }

    #[test]
    fn offer_round_trip() {
        let offer = sample_offer();
        let encoded = encode(&offer).unwrap();
        let binary = STANDARD.decode(&encoded).unwrap();
        assert_eq!(&binary[..4], b"PT01");

        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.payload_type, "offer");
        assert_eq!(decoded.sdp, offer.sdp);
        assert_eq!(decoded.candidates, offer.candidates);
        assert_eq!(decoded.file_name.as_deref(), Some("photo.jpg"));
        assert_eq!(decoded.file_size_exact, Some(true));
        assert_eq!(decoded.salt, Some(vec![9u8; 16]));
        assert_eq!(decoded.public_key.len(), PUBLIC_KEY_LEN);
    }

    #[test]
    fn answer_omits_offer_fields() {
        let answer = SignalingPayload::answer(
            "v=0\r\n".to_string(),
            vec![],
            now_ms(),
            [4u8; PUBLIC_KEY_LEN],
        );
        let json = serde_json::to_string(&answer).unwrap();
        assert!(!json.contains("fileName"));
        assert!(!json.contains("fileSizeExact"));
        assert!(!json.contains("salt"));
        let decoded = decode(&encode(&answer).unwrap()).unwrap();
        assert_eq!(decoded.payload_type, "answer");
        assert!(decoded.salt.is_none());
    }

    #[test]
    fn tolerates_whitespace_in_base64() {
        let encoded = encode(&sample_offer()).unwrap();
        let mut wrapped = String::new();
        for (i, c) in encoded.chars().enumerate() {
            if i > 0 && i % 40 == 0 {
                wrapped.push('\n');
            }
            wrapped.push(c);
        }
        assert!(decode(&wrapped).is_ok());
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode("not base64 PT01!").is_err());
        assert!(decode(&STANDARD.encode(b"XXXX....")).is_err());
    }
}
