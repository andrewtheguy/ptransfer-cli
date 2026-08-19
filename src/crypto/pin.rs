//! Rotating short PIN for secure-send-web's Nostr "Auto Exchange" mode.
//!
//! The PIN is 12 case-sensitive characters (11 data + 1 checksum). The sender
//! mints a fresh PIN every [`PIN_ROTATION_MS`] and honors PINs minted in the
//! current or immediately previous wall-clock bucket, so any single PIN is
//! valid for roughly 2–4 minutes.
//!
//! The PIN has exactly two jobs: its leading three-character locator derives
//! the public rendezvous hint, and the whole PIN reduces to the SPAKE2 password
//! scalar that authenticates the key exchange (see [`crate::crypto::spake2`]).
//! It derives no content or signaling keys — those are HKDF derivations off the
//! PAKE root, which requires ephemeral scalars both peers discard. There is
//! deliberately no key stretching: stretching only helps when something permits
//! offline guessing, and with a balanced PAKE nothing does.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use hkdf::Hkdf;
use sha2::Sha256;

use super::chunk::fill_random;

/// Total PIN length, including the trailing checksum character.
pub const PIN_LENGTH: usize = 12;
const PIN_CHECKSUM_LENGTH: usize = 1;
/// Leading characters used to derive the public rendezvous lookup hint. They
/// are public by construction: a hint has at most `PIN_CHARSET.len() ** 3`
/// preimages per rotation bucket, so anyone can enumerate locator -> hint and
/// read the locator straight off a relay event. The remaining data characters
/// are the only entropy the SPAKE2 handshake rests on.
pub const PIN_LOCATOR_LENGTH: usize = 3;

/// Case-sensitive alphabet of letters and digits excluding ambiguous `0`, `1`,
/// `I`, `O`, `i`, `l`, and `o`. 55 characters, no symbols, so the PIN types
/// cleanly on any mobile keyboard. Matches secure-send-web's `PIN_CHARSET`.
const PIN_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";

/// How often the sender mints and publishes a fresh PIN.
pub const PIN_ROTATION_MS: u64 = 120_000;
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

/// How many SPAKE2 claim verifications the sender runs per PIN generation.
/// With a balanced PAKE the only way to test a PIN guess is to publish a claim
/// and have the sender try to verify it, so this cap — not any key stretching —
/// is the online guessing bound. Exhausting it stalls that generation; rotation
/// mints a fresh budget with the next PIN.
pub const CLAIM_VERIFY_LIMIT: u32 = 100;

/// How many rendezvous candidates the receiver claims per attempt. The hint is
/// keyed by the public locator alone, so unrelated transfers collide on it and
/// a plaintext rendezvous cannot be told apart locally. Each claim hands
/// whoever published that candidate one online guess at our PIN, so the cap
/// also bounds what a flood of forged rendezvous events can extract.
pub const MAX_CLAIM_CANDIDATES: usize = 8;

/// HKDF salt for the locator-keyed rendezvous hint derivation. A public
/// constant for domain separation only: the hint is keyed by the public locator
/// segment and never by any PIN secret.
const PIN_HINT_HKDF_SALT: &str = "secure-send:pin:v3";

/// PIN hint length in hex characters: the Nostr `#h` filter tag. It carries at
/// most log2(55³) ≈ 17.3 bits regardless of width, because it is a function of
/// the locator alone.
const PIN_HINT_LENGTH: usize = 8;

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

/// Return the PIN's public three-character locator segment.
pub fn pin_locator(pin: &str) -> &str {
    pin.get(..PIN_LOCATOR_LENGTH).unwrap_or(pin)
}

/// Compute the public, per-bucket rendezvous hint from the locator segment.
///
/// The locator is intentionally the only input key material: publishing a value
/// derived from the full PIN would hand an attacker a cheap oracle for
/// confirming guesses at its secret characters — the one offline foothold the
/// SPAKE2 handshake otherwise eliminates.
///
/// With roughly 17.3 bits behind it the hint is a filter, not an identifier.
/// Unrelated transfers in the same bucket do collide, and callers must be
/// prepared to walk several candidates.
pub fn pin_hint_for_bucket(locator: &str, bucket: u64) -> String {
    let hkdf = Hkdf::<Sha256>::new(Some(PIN_HINT_HKDF_SALT.as_bytes()), locator.as_bytes());
    let mut bytes = [0_u8; PIN_HINT_LENGTH / 2];
    hkdf.expand(format!("hint:{bucket}").as_bytes(), &mut bytes)
        .expect("HKDF output length is always valid here");
    hex_lower(&bytes)
}

pub fn generate_transfer_id() -> Result<String> {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes)?;
    Ok(hex_lower(&bytes))
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
    fn charset_carries_no_symbols_or_ambiguous_characters() {
        assert_eq!(PIN_CHARSET.len(), 55);
        assert!(
            PIN_CHARSET
                .iter()
                .all(|b| b.is_ascii_alphanumeric() && !b"01".contains(b))
        );
        for ambiguous in b"01IOilo" {
            assert!(!PIN_CHARSET.contains(ambiguous));
        }
    }

    #[test]
    fn checksum_rejects_typo_and_transposition() {
        // Fixed vector: checksum of "ABCDEFGHJKL" is 'A',
        // verified against secure-send-web's computeChecksum.
        assert!(is_valid_pin("ABCDEFGHJKLA"));
        assert!(!is_valid_pin("ABCDefGHJKLA")); // substitution
        assert!(!is_valid_pin("BACDEFGHJKLA")); // transposition
        assert!(!is_valid_pin("ABCDEFGHJKL")); // too short
    }

    #[test]
    fn validation_is_case_sensitive() {
        assert!(is_valid_pin("AbCDefGhjkmQ"));
        assert!(!is_valid_pin("ABCDEFGHJKMQ"));
    }

    #[test]
    fn pin_char_preserves_supported_characters() {
        assert_eq!(pin_char('a'), Some('a'));
        assert_eq!(pin_char('A'), Some('A'));
        assert_eq!(pin_char('9'), Some('9'));
        assert_eq!(pin_char('0'), None);
        assert_eq!(pin_char('o'), None);
        assert_eq!(pin_char('-'), None);
        assert_eq!(pin_char('*'), None);
    }

    #[test]
    fn locator_hint_depends_only_on_locator_and_bucket() {
        // Fixed vector from secure-send-web's computePinHintFromLocator.
        let bucket = 36_947_145;
        assert_eq!(pin_locator("ABCDEFGHJKLA"), "ABC");
        assert_eq!(pin_hint_for_bucket("ABC", bucket), "a77b01bb");
        assert_eq!(
            pin_hint_for_bucket("ABC", bucket),
            pin_hint_for_bucket(pin_locator("ABCzzzzzzzzQ"), bucket)
        );
        assert_ne!(
            pin_hint_for_bucket("ABC", bucket),
            pin_hint_for_bucket("ABD", bucket)
        );
        assert_ne!(
            pin_hint_for_bucket("ABC", bucket),
            pin_hint_for_bucket("ABC", bucket - 1)
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
