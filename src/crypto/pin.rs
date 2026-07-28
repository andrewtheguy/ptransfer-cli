//! Rotating short PIN and PIN-root key derivation for secure-send-web's
//! Nostr "Auto Exchange" mode.
//!
//! The PIN is 12 case-sensitive characters (11 data + 1 checksum). The sender
//! mints a fresh PIN every [`PIN_ROTATION_MS`] and honors PINs minted in the
//! current or immediately previous wall-clock bucket, so any single PIN is
//! valid for roughly 5–10 minutes.
//!
//! Every wire-exposed PIN-scoped value is an HKDF derivation off a single
//! PBKDF2-SHA-256 stretch of the PIN (the "PIN root"), domain-separated by
//! info label: `hint:<bucket>` (rendezvous event lookup tag), `auth`
//! (claim/confirm sealing key), and `rendezvous` (rendezvous payload key).
//! The on-screen [`pin_fingerprint`] is never transmitted, so it uses its own
//! deliberately light stretch. The PIN derives no content-encryption keys —
//! those come from the ephemeral ECDH exchange the PIN authenticates (see
//! [`crate::crypto::ecdh`]). Mirrors secure-send-web's `src/lib/crypto/pin.ts`.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use super::aes::AES_KEY_LEN;
use super::chunk::fill_random;

/// Total PIN length, including the trailing checksum character.
pub const PIN_LENGTH: usize = 12;
const PIN_CHECKSUM_LENGTH: usize = 1;

/// Case-sensitive alphabet excluding ambiguous `0`, `1`, `I`, `O`, `i`, `l`,
/// and `o`, with symbols available on the iOS "123" keyboard. Matches
/// secure-send-web's `PIN_CHARSET`.
const PIN_CHARSET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789-/:;()$&@?!.,\"";

/// How often the sender mints and publishes a fresh PIN.
pub const PIN_ROTATION_MS: u64 = 300_000;
/// Total time the sender keeps rotating/waiting before giving up. A resource
/// backstop, not a security control: rotation already caps any single PIN's
/// exposure at [`PIN_TTL_MS`], so waiting longer is not less safe. Mirrors
/// secure-send-web's `PIN_WAIT_TIMEOUT_MS`.
pub const PIN_WAIT_TIMEOUT_MS: u64 = 30 * 60 * 1000;
/// How many wall-clock buckets may authenticate a claim: the current bucket
/// and the immediately previous one.
pub const PIN_ACTIVE_BUCKETS: u64 = 2;
/// Maximum possible age of an active PIN. Exact expiry is the end of its
/// immediately following bucket.
pub const PIN_TTL_MS: u64 = PIN_ROTATION_MS * PIN_ACTIVE_BUCKETS;
/// How many earlier rotation buckets the receiver derives hints for. This
/// mirrors the sender's exact current-or-previous-bucket acceptance rule.
pub const PIN_HINT_LOOKBACK_BUCKETS: u64 = PIN_ACTIVE_BUCKETS - 1;

const PBKDF2_ITERATIONS: u32 = 600_000;
/// Domain-separation salt for the PBKDF2 PIN-root derivation (public).
const PIN_ROOT_SALT: &str = "secure-send:pin-root:v2";
/// HKDF salt shared by every derivation off the PIN root; each purpose is
/// domain-separated by its HKDF info label.
const PIN_HKDF_SALT: &str = "secure-send:pin:v2";

/// PIN hint length in hex characters (64 bits): the Nostr `#h` filter tag.
const PIN_HINT_LENGTH: usize = 16;
/// PIN fingerprint length in lowercase hex characters (48 bits, local-only).
const PIN_FINGERPRINT_LENGTH: usize = 12;
/// The fingerprint is never transmitted — it exists only for on-screen human
/// comparison — so it uses a deliberately light stretch instead of the full
/// PIN-root work factor.
const PIN_FINGERPRINT_ITERATIONS: u32 = 1_000;
/// Domain-separation salt for the fingerprint derivation (public).
const PIN_FINGERPRINT_SALT: &str = "secure-send:pin-fingerprint:v2";

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis() as u64
}

pub fn now_sec() -> u64 {
    now_ms() / 1000
}

/// Compute the checksum character using a position-weighted sum.
///
/// Each character's alphabet index is weighted by its one-based position.
/// Mirrors secure-send-web's `computeChecksum`.
fn compute_checksum(data: &[u8]) -> u8 {
    let mut sum = 0usize;
    for (i, byte) in data.iter().enumerate() {
        let Some(index) = PIN_CHARSET.iter().position(|c| c == byte) else {
            return PIN_CHARSET[0];
        };
        sum += index * (i + 1);
    }
    PIN_CHARSET[sum % PIN_CHARSET.len()]
}

/// Generate a random PIN: 11 data characters drawn with rejection sampling
/// (no modulo bias) plus the checksum character.
pub fn generate_pin() -> Result<String> {
    let data_len = PIN_LENGTH - PIN_CHECKSUM_LENGTH;
    let charset_len = PIN_CHARSET.len();
    let max_multiple = (256 / charset_len) * charset_len;
    let mut data = Vec::with_capacity(PIN_LENGTH);
    let mut buf = vec![0u8; data_len * 2];

    while data.len() < data_len {
        fill_random(&mut buf)?;
        for byte in &buf {
            let n = *byte as usize;
            if n < max_multiple {
                data.push(PIN_CHARSET[n % charset_len]);
                if data.len() == data_len {
                    break;
                }
            }
        }
    }

    data.push(compute_checksum(&data));
    String::from_utf8(data).map_err(|e| anyhow::anyhow!("generated invalid PIN: {e}"))
}

/// Accept one typed character for interactive PIN entry without changing its
/// case. Unsupported characters are filtered out.
pub fn pin_char(c: char) -> Option<char> {
    c.is_ascii()
        .then_some(c)
        .filter(|candidate| PIN_CHARSET.contains(&(*candidate as u8)))
}

/// Validate the exact case-sensitive PIN format and checksum.
pub fn is_valid_pin(pin: &str) -> bool {
    let bytes = pin.as_bytes();
    if bytes.len() != PIN_LENGTH {
        return false;
    }
    if !bytes.iter().all(|byte| PIN_CHARSET.contains(byte)) {
        return false;
    }

    let data = &bytes[..PIN_LENGTH - PIN_CHECKSUM_LENGTH];
    compute_checksum(data) == bytes[PIN_LENGTH - PIN_CHECKSUM_LENGTH]
}

pub fn generate_transfer_id() -> Result<String> {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes)?;
    Ok(hex_lower(&bytes))
}

/// The PIN root: the PBKDF2-SHA-256 stretch of the PIN, ready for cheap HKDF
/// expansions. The expensive stretch runs exactly once per PIN; brute-forcing
/// any derived value still costs the full PBKDF2 work factor per PIN guess.
///
/// CPU-bound (~600k PBKDF2 iterations): call [`PinRoot::derive`] from
/// `spawn_blocking` in async contexts.
pub struct PinRoot {
    hkdf: Hkdf<Sha256>,
}

impl PinRoot {
    pub fn derive(pin: &str) -> Self {
        let mut root = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            pin.as_bytes(),
            PIN_ROOT_SALT.as_bytes(),
            PBKDF2_ITERATIONS,
            &mut root,
        );
        Self {
            hkdf: Hkdf::new(Some(PIN_HKDF_SALT.as_bytes()), &root),
        }
    }

    fn expand(&self, info: &str, out: &mut [u8]) {
        self.hkdf
            .expand(info.as_bytes(), out)
            .expect("HKDF output length is always valid here");
    }

    fn aes_key(&self, info: &str) -> [u8; AES_KEY_LEN] {
        let mut key = [0u8; AES_KEY_LEN];
        self.expand(info, &mut key);
        key
    }

    /// The PIN hint (16 hex chars) for an absolute rotation bucket. Published
    /// as the Nostr `#h` tag so the receiver can locate the rendezvous event
    /// without revealing the PIN; bucket scoping keeps the tag from being a
    /// stable cross-transfer correlator.
    pub fn hint_for_bucket(&self, bucket: u64) -> String {
        let mut bytes = [0u8; PIN_HINT_LENGTH / 2];
        self.expand(&format!("hint:{bucket}"), &mut bytes);
        hex_lower(&bytes)
    }

    /// The AES-GCM key that seals the claim/confirm handshake payloads. A
    /// payload that decrypts under this key proves the author knows the PIN.
    pub fn auth_key(&self) -> [u8; AES_KEY_LEN] {
        self.aes_key("auth")
    }

    /// The AES-GCM key for the rendezvous event payload (transfer id, sender
    /// ECDH public key, handshake nonce, file metadata).
    pub fn rendezvous_key(&self) -> [u8; AES_KEY_LEN] {
        self.aes_key("rendezvous")
    }
}

/// The PIN fingerprint: a stable one-way derivation displayed to both sides
/// so two humans can visually confirm they entered the same PIN. Never
/// published to relays, so it carries no rotation-bucket scoping and only a
/// light stretch ([`PIN_FINGERPRINT_ITERATIONS`]) — cheap enough to show the
/// moment the PIN is typed.
///
/// Encoded as 12 lowercase hex chars, displayed as-is (no grouping).
pub fn pin_fingerprint(pin: &str) -> String {
    let mut bytes = [0u8; PIN_FINGERPRINT_LENGTH.div_ceil(2)];
    pbkdf2_hmac::<Sha256>(
        pin.as_bytes(),
        PIN_FINGERPRINT_SALT.as_bytes(),
        PIN_FINGERPRINT_ITERATIONS,
        &mut bytes,
    );
    hex_lower(&bytes)[..PIN_FINGERPRINT_LENGTH].to_string()
}

/// The wall-clock PIN bucket at `now_ms`.
pub fn pin_bucket(now_ms: u64) -> u64 {
    now_ms / PIN_ROTATION_MS
}

/// Whether a PIN minted in `bucket` is active at `now_ms`.
pub fn is_pin_bucket_active(bucket: u64, now_ms: u64) -> bool {
    let current = pin_bucket(now_ms);
    bucket == current || bucket.checked_add(1) == Some(current)
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

    #[test]
    fn generated_pin_validates() {
        let pin = generate_pin().unwrap();
        assert_eq!(pin.len(), PIN_LENGTH);
        assert!(is_valid_pin(&pin));
        assert!(pin.bytes().all(|b| PIN_CHARSET.contains(&b)));
    }

    #[test]
    fn checksum_rejects_typo_and_transposition() {
        // Fixed vector: checksum of "ABCDEFGHJKL" is 'c',
        // verified against secure-send-web's computeChecksum.
        assert!(is_valid_pin("ABCDEFGHJKLc"));
        assert!(!is_valid_pin("ABCDefGHJKLc")); // substitution
        assert!(!is_valid_pin("BACDEFGHJKLc")); // transposition
        assert!(!is_valid_pin("ABCDEFGHJKL")); // too short
    }

    #[test]
    fn validation_is_case_sensitive() {
        assert!(is_valid_pin("AbCDefGHJKL&"));
        assert!(!is_valid_pin("ABCDEFGHJKL&"));
    }

    #[test]
    fn pin_char_preserves_supported_characters() {
        assert_eq!(pin_char('a'), Some('a'));
        assert_eq!(pin_char('A'), Some('A'));
        assert_eq!(pin_char('-'), Some('-'));
        assert_eq!(pin_char('"'), Some('"'));
        assert_eq!(pin_char('0'), None);
        assert_eq!(pin_char('o'), None);
        assert_eq!(pin_char('*'), None);
    }

    #[test]
    fn pin_root_matches_web_vectors() {
        // Parity with secure-send-web's importPinRoot + HKDF derivations,
        // verified against the Web Crypto API (PBKDF2-SHA-256, 600k
        // iterations, salt "secure-send:pin-root:v2"; HKDF-SHA-256, salt
        // "secure-send:pin:v2").
        let root = PinRoot::derive("ABCDEFGHJKLc");
        assert_eq!(root.hint_for_bucket(14778858), "1d5c44a599863be2");
        assert_eq!(
            hex_lower(&root.auth_key()),
            "65528de3152b27ac4282046a042074e9bc595422338b2815eec855ee38669db0"
        );
        assert_eq!(
            hex_lower(&root.rendezvous_key()),
            "dbb7e0aaf348bdfa69967e0d2cad4dea985f709c9c07234c836f2aba541cb6e4"
        );
    }

    #[test]
    fn fingerprint_matches_web_vector() {
        // Parity with secure-send-web's computePinFingerprint
        // (PBKDF2-SHA-256, 1k iterations, salt
        // "secure-send:pin-fingerprint:v2"), verified independently.
        assert_eq!(pin_fingerprint("A/B:C;D(E)F"), "2e700e579152");
        assert_ne!(
            pin_fingerprint("A/B:C;D(E)F"),
            pin_fingerprint("A/B:C;D(E)G")
        );
    }

    #[test]
    fn only_current_and_previous_pin_buckets_are_active() {
        let now = 10 * PIN_ROTATION_MS + 1;
        assert!(is_pin_bucket_active(10, now));
        assert!(is_pin_bucket_active(9, now));
        assert!(!is_pin_bucket_active(8, now));
        assert!(!is_pin_bucket_active(11, now));
    }
}
