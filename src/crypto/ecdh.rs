//! ECDH P-256 key agreement + HKDF-SHA256 key derivation, byte-for-byte
//! compatible with secure-send-web's `src/lib/crypto/ecdh.ts` and `kdf.ts`.
//!
//! Manual mode derives one AES content key:
//! `HKDF-SHA256(ikm = ECDH shared X coordinate, salt = 16-byte transfer salt,
//!  info = "secure-send-mutual", len = 32)`.
//!
//! Nostr (Auto Exchange) mode derives two session keys and a human confirmation
//! code off the same shared secret with distinct info labels.

use anyhow::{Result, bail};
use hkdf::Hkdf;
use p256::PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;

use super::base32::{CONFIRMATION_CODE_BYTES, encode_crockford_base32};
use super::chunk::fill_random;

/// HKDF `info` string for the mutual (manual-mode) content key.
const HKDF_INFO_MUTUAL: &[u8] = b"secure-send-mutual";
/// HKDF `info` string for the Nostr-mode signaling key (`kdf.ts`).
const HKDF_INFO_NOSTR_SIGNALS: &[u8] = b"secure-send:nostr-session:v2:signals";
/// HKDF `info` string for the Nostr-mode content key (`kdf.ts`).
const HKDF_INFO_NOSTR_CONTENT: &[u8] = b"secure-send:nostr-session:v2:content";
/// Prefix of the transcript-bound Nostr confirmation-code info string.
const HKDF_INFO_NOSTR_CONFIRMATION: &str = "secure-send:nostr-session:v2:confirmation";
/// Transfer salt length (`SALT_LENGTH`).
pub const SALT_LEN: usize = 16;
/// Uncompressed P-256 public key length (`0x04 || X || Y`).
pub const PUBLIC_KEY_LEN: usize = 65;

/// Session keys for Nostr (Auto Exchange) mode, derived from the ephemeral
/// ECDH shared secret established during the PIN-authenticated handshake.
/// Mirrors secure-send-web's `NostrSessionKeys` (`kdf.ts`).
pub struct NostrSessionKeys {
    /// Encrypts relay-carried WebRTC signaling (offer/answer/candidates).
    pub signals: [u8; 32],
    /// Encrypts P2P file content chunks on the data channel.
    pub content: [u8; 32],
}

/// Handshake values bound into the ECDH confirmation code.
pub struct ConfirmationCodeBinding<'a> {
    pub transfer_id: &'a str,
    pub sender_nonce: &'a str,
    pub receiver_nonce: &'a str,
    pub transcript_hash: &'a str,
}

/// An ephemeral ECDH key pair. The secret scalar never leaves this struct.
pub struct EcdhKeyPair {
    secret: p256::SecretKey,
    /// 65-byte uncompressed public key (`0x04 || X(32) || Y(32)`).
    pub public_key_bytes: [u8; PUBLIC_KEY_LEN],
}

impl EcdhKeyPair {
    /// Generate a fresh ephemeral P-256 key pair.
    pub fn generate() -> Result<Self> {
        // Rejection-sample a valid non-zero scalar < curve order. A random
        // 32-byte string is out of range with probability ~2^-32, so this
        // effectively never loops.
        let secret = loop {
            let mut bytes = [0u8; 32];
            fill_random(&mut bytes)?;
            if let Ok(sk) = p256::SecretKey::from_slice(&bytes) {
                break sk;
            }
        };

        let encoded = secret.public_key().to_encoded_point(false);
        let mut public_key_bytes = [0u8; PUBLIC_KEY_LEN];
        public_key_bytes.copy_from_slice(encoded.as_bytes());

        Ok(Self {
            secret,
            public_key_bytes,
        })
    }

    /// Derive the manual-mode shared AES-256 content key from the peer's
    /// public key and the per-transfer salt.
    pub fn derive_aes_key(&self, peer_public_key: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
        let hk = self.shared_secret_hkdf(peer_public_key, salt)?;
        expand_key(&hk, HKDF_INFO_MUTUAL)
    }

    /// Derive the Nostr-mode session keys (signaling + content) from the
    /// peer's public key and the public per-transfer salt. Mirrors
    /// secure-send-web's `deriveNostrSessionKeys`.
    pub fn derive_nostr_session_keys(
        &self,
        peer_public_key: &[u8],
        salt: &[u8],
    ) -> Result<NostrSessionKeys> {
        let hk = self.shared_secret_hkdf(peer_public_key, salt)?;
        Ok(NostrSessionKeys {
            signals: expand_key(&hk, HKDF_INFO_NOSTR_SIGNALS)?,
            content: expand_key(&hk, HKDF_INFO_NOSTR_CONTENT)?,
        })
    }

    /// Derive the eight-character confirmation code the receiver reads to the
    /// sender before the sender publishes its confirm event.
    pub fn derive_confirmation_code(
        &self,
        peer_public_key: &[u8],
        salt: &[u8],
        binding: &ConfirmationCodeBinding<'_>,
    ) -> Result<String> {
        let hk = self.shared_secret_hkdf(peer_public_key, salt)?;
        derive_confirmation_code_from_hkdf(&hk, binding)
    }

    /// Run ECDH against the peer's public key and prepare the salted HKDF the
    /// per-purpose keys expand from.
    fn shared_secret_hkdf(&self, peer_public_key: &[u8], salt: &[u8]) -> Result<Hkdf<Sha256>> {
        if salt.len() < SALT_LEN {
            bail!(
                "salt too short: expected at least {SALT_LEN} bytes, got {}",
                salt.len()
            );
        }
        let peer = import_public_key(peer_public_key)?;

        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        // secure-send-web's Web Crypto ECDH yields the X coordinate as the HKDF
        // input keying material; `raw_secret_bytes()` is exactly that X coordinate.
        Ok(Hkdf::<Sha256>::new(Some(salt), shared.raw_secret_bytes()))
    }
}

fn derive_confirmation_code_from_hkdf(
    hkdf: &Hkdf<Sha256>,
    binding: &ConfirmationCodeBinding<'_>,
) -> Result<String> {
    let info = format!(
        "{HKDF_INFO_NOSTR_CONFIRMATION}|{}|{}|{}|{}",
        binding.transfer_id,
        binding.sender_nonce,
        binding.receiver_nonce,
        binding.transcript_hash
    );
    let mut bytes = [0_u8; CONFIRMATION_CODE_BYTES];
    hkdf.expand(info.as_bytes(), &mut bytes)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(encode_crockford_base32(&bytes))
}

fn expand_key(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<[u8; 32]> {
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

/// Import a peer's 65-byte uncompressed P-256 public key, validating format and
/// that the point is on the curve.
pub fn import_public_key(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != PUBLIC_KEY_LEN {
        bail!(
            "invalid ECDH public key: expected {PUBLIC_KEY_LEN}-byte uncompressed key, got {}",
            bytes.len()
        );
    }
    if bytes[0] != 0x04 {
        bail!("invalid ECDH public key: missing uncompressed point prefix (0x04)");
    }
    PublicKey::from_sec1_bytes(bytes)
        .map_err(|_| anyhow::anyhow!("invalid ECDH public key: point not on curve"))
}

/// Generate a fresh 16-byte transfer salt.
pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_same_key() {
        let alice = EcdhKeyPair::generate().unwrap();
        let bob = EcdhKeyPair::generate().unwrap();
        let salt = generate_salt().unwrap();

        let ka = alice.derive_aes_key(&bob.public_key_bytes, &salt).unwrap();
        let kb = bob.derive_aes_key(&alice.public_key_bytes, &salt).unwrap();
        assert_eq!(ka, kb);
    }

    #[test]
    fn different_salt_differs() {
        let alice = EcdhKeyPair::generate().unwrap();
        let bob = EcdhKeyPair::generate().unwrap();
        let k1 = alice
            .derive_aes_key(&bob.public_key_bytes, &[9u8; 16])
            .unwrap();
        let k2 = alice
            .derive_aes_key(&bob.public_key_bytes, &[8u8; 16])
            .unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn both_sides_derive_same_nostr_session_keys() {
        let alice = EcdhKeyPair::generate().unwrap();
        let bob = EcdhKeyPair::generate().unwrap();
        let salt = generate_salt().unwrap();

        let ka = alice
            .derive_nostr_session_keys(&bob.public_key_bytes, &salt)
            .unwrap();
        let kb = bob
            .derive_nostr_session_keys(&alice.public_key_bytes, &salt)
            .unwrap();
        assert_eq!(ka.signals, kb.signals);
        assert_eq!(ka.content, kb.content);
        assert_ne!(ka.signals, ka.content);
    }

    #[test]
    fn both_sides_derive_same_confirmation_code() {
        let sender = EcdhKeyPair::generate().unwrap();
        let receiver = EcdhKeyPair::generate().unwrap();
        let salt = generate_salt().unwrap();
        let binding = ConfirmationCodeBinding {
            transfer_id: "a1b2c3d4e5f60718",
            sender_nonce: "c2VuZGVyLW5vbmNlLTAwMDAwMDA=",
            receiver_nonce: "cmVjZWl2ZXItbm9uY2UtMDAwMDA=",
            transcript_hash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        };

        let sender_code = sender
            .derive_confirmation_code(&receiver.public_key_bytes, &salt, &binding)
            .unwrap();
        let receiver_code = receiver
            .derive_confirmation_code(&sender.public_key_bytes, &salt, &binding)
            .unwrap();

        assert_eq!(sender_code, receiver_code);
        assert_eq!(sender_code.len(), 8);
    }

    #[test]
    fn confirmation_code_matches_fixed_hkdf_vector() {
        let ikm: Vec<u8> = (0_u8..32).collect();
        let hkdf = Hkdf::<Sha256>::new(Some(&[7_u8; 16]), &ikm);
        let binding = ConfirmationCodeBinding {
            transfer_id: "a1b2c3d4e5f60718",
            sender_nonce: "c2VuZGVyLW5vbmNlLTAwMDAwMDA=",
            receiver_nonce: "cmVjZWl2ZXItbm9uY2UtMDAwMDA=",
            transcript_hash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        };

        assert_eq!(
            derive_confirmation_code_from_hkdf(&hkdf, &binding).unwrap(),
            "S9MP3G4D"
        );
    }

    #[test]
    fn nostr_session_labels_match_web_vectors() {
        // HKDF-SHA256(ikm = 0x00..0x1f, salt = 16×0x07) with the kdf.ts info
        // labels, verified against an independent HKDF implementation.
        let ikm: Vec<u8> = (0u8..32).collect();
        let hk = Hkdf::<Sha256>::new(Some(&[7u8; 16]), &ikm);
        let signals = expand_key(&hk, HKDF_INFO_NOSTR_SIGNALS).unwrap();
        let content = expand_key(&hk, HKDF_INFO_NOSTR_CONTENT).unwrap();
        assert_eq!(
            signals.to_vec(),
            hex_bytes("71822edb65d5e2a2482a3e9924c99ca2a1d84edefb5566ccd5327f5061704992")
        );
        assert_eq!(
            content.to_vec(),
            hex_bytes("181adc4ffbe81a7c1c4806b9197b9f10129ffcf7559f224ee6b744ff234214a4")
        );
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rejects_bad_public_key() {
        assert!(import_public_key(&[0u8; 10]).is_err());
        assert!(import_public_key(&[0u8; 65]).is_err()); // prefix != 0x04
    }
}
