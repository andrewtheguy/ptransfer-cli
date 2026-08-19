//! Key derivation off the SPAKE2 root established by the PIN handshake,
//! byte-for-byte compatible with secure-send-web's `src/lib/crypto/kdf.ts`.
//!
//! The root already mixes fresh ephemeral scalars from both sides, so it is the
//! transfer's ephemeral shared secret — there is no ECDH exchange in Nostr
//! mode. Everything fans out from it with the public per-transfer salt and
//! distinct HKDF info labels.

use anyhow::{Result, bail};
use hkdf::Hkdf;
use sha2::Sha256;

use super::aes::AES_KEY_LEN;
use super::base32::{CONFIRMATION_CODE_BYTES, encode_crockford_base32};
use super::chunk::fill_random;

/// Transfer salt length (`SALT_LENGTH`).
pub const SALT_LEN: usize = 16;

const LABEL_SIGNALS: &str = "secure-send:nostr-session:v4:signals";
const LABEL_CONTENT: &str = "secure-send:nostr-session:v4:content";
const LABEL_CLAIM: &str = "secure-send:nostr-session:v4:claim";
const LABEL_CONFIRM: &str = "secure-send:nostr-session:v4:confirm";
const LABEL_CONFIRMATION: &str = "secure-send:nostr-session:v4:confirmation";

/// Session keys for Nostr (Auto Exchange) mode. Distinct HKDF info labels
/// guarantee signaling and content never reuse the same AES-GCM key.
pub struct NostrSessionKeys {
    /// Encrypts relay-carried WebRTC signaling (offer/answer/candidates).
    pub signals: [u8; AES_KEY_LEN],
    /// Encrypts P2P file content chunks on the data channel.
    pub content: [u8; AES_KEY_LEN],
}

/// The AES-GCM keys that seal the two handshake payloads. Successfully sealing
/// or opening under either one is the key-confirmation step of the PAKE: only a
/// peer that ran this exact SPAKE2 session — same PIN, same elements, same
/// identities, same transfer — holds them. Distinct labels per direction (plus
/// the `type` field inside each payload) rule out reflecting one side's sealed
/// payload back as the other's.
pub struct HandshakeSealKeys {
    /// Seals the receiver's claim payload (receiver -> sender).
    pub claim: [u8; AES_KEY_LEN],
    /// Seals the sender's confirm payload, metadata included (sender -> receiver).
    pub confirm: [u8; AES_KEY_LEN],
}

/// The handshake values a confirmation code is bound to, so that a code proves
/// agreement on *this* claim rather than merely on a shared secret.
pub struct ConfirmationCodeBinding<'a> {
    pub transfer_id: &'a str,
    /// Sender's per-rotation nonce, from the rendezvous payload.
    pub sender_nonce: &'a str,
    /// Receiver's per-claim nonce.
    pub receiver_nonce: &'a str,
    /// Digest of the rendezvous both peers believe they are acting on. The
    /// SPAKE2 transcript already keys the root by identities and elements; this
    /// extends the agreement to every plaintext rendezvous field.
    pub transcript_hash: &'a str,
    /// Digest of the file metadata the sender delivered inside its sealed
    /// confirm. Metadata travels after the handshake rather than in the
    /// rendezvous, so it is bound here — the code the humans compare attests to
    /// *what* is being transferred, not only to the key exchange.
    pub metadata_hash: &'a str,
}

/// The SPAKE2 session root: the transcript digest returned by
/// [`crate::crypto::spake2::PakeRun::finish`], ready for HKDF expansion.
pub struct PakeRoot {
    ikm: [u8; 32],
}

impl Drop for PakeRoot {
    fn drop(&mut self) {
        self.ikm.fill(0);
    }
}

impl PakeRoot {
    pub(crate) fn from_digest(ikm: [u8; 32]) -> Self {
        Self { ikm }
    }

    /// The raw transcript digest. Test-only: production code derives through
    /// the methods below so no caller can reuse the root as a key directly.
    #[cfg(test)]
    pub(crate) fn ikm(&self) -> &[u8; 32] {
        &self.ikm
    }

    fn hkdf(&self, salt: &[u8]) -> Result<Hkdf<Sha256>> {
        if salt.len() < SALT_LEN {
            bail!(
                "salt too short: expected at least {SALT_LEN} bytes, got {}",
                salt.len()
            );
        }
        Ok(Hkdf::<Sha256>::new(Some(salt), &self.ikm))
    }

    /// Derive the session keys (signaling + content) from the public
    /// per-transfer salt.
    pub fn session_keys(&self, salt: &[u8]) -> Result<NostrSessionKeys> {
        let hkdf = self.hkdf(salt)?;
        Ok(NostrSessionKeys {
            signals: expand_key(&hkdf, LABEL_SIGNALS)?,
            content: expand_key(&hkdf, LABEL_CONTENT)?,
        })
    }

    /// Derive the claim/confirm seal keys.
    pub fn handshake_seal_keys(&self, salt: &[u8]) -> Result<HandshakeSealKeys> {
        let hkdf = self.hkdf(salt)?;
        Ok(HandshakeSealKeys {
            claim: expand_key(&hkdf, LABEL_CLAIM)?,
            confirm: expand_key(&hkdf, LABEL_CONFIRM)?,
        })
    }

    /// Derive the confirmation code both peers show to their humans: a short
    /// authentication string over the SPAKE2 root.
    ///
    /// The receiver computes it once the sender's confirm verifies and displays
    /// it. The sender computes the same value from the claim it locked onto and
    /// publishes no WebRTC signaling, and no file byte, until its operator types
    /// a match. Since the code is keyed by the shared secret, only the peer
    /// holding the matching session can produce it, so someone who front-ran the
    /// intended receiver with a stolen PIN wins the claim race and then has
    /// nothing to say when the sender asks for the code.
    pub fn confirmation_code(
        &self,
        salt: &[u8],
        binding: &ConfirmationCodeBinding<'_>,
    ) -> Result<String> {
        let hkdf = self.hkdf(salt)?;
        // transferId and both hashes are hex and both nonces are fixed-length
        // base64, so '|' cannot appear inside a field and the join is
        // unambiguous.
        let info = format!(
            "{LABEL_CONFIRMATION}|{}|{}|{}|{}|{}",
            binding.transfer_id,
            binding.sender_nonce,
            binding.receiver_nonce,
            binding.transcript_hash,
            binding.metadata_hash
        );
        let mut bytes = [0u8; CONFIRMATION_CODE_BYTES];
        hkdf.expand(info.as_bytes(), &mut bytes)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(encode_crockford_base32(&bytes))
    }
}

fn expand_key(hkdf: &Hkdf<Sha256>, info: &str) -> Result<[u8; AES_KEY_LEN]> {
    let mut key = [0u8; AES_KEY_LEN];
    hkdf.expand(info.as_bytes(), &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(key)
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

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixed_root() -> PakeRoot {
        let mut ikm = [0u8; 32];
        for (index, byte) in ikm.iter_mut().enumerate() {
            *byte = index as u8;
        }
        PakeRoot::from_digest(ikm)
    }

    #[test]
    fn session_and_seal_labels_match_web_vectors() {
        // HKDF-SHA256(ikm = 0x00..0x1f, salt = 16 x 0x07) with the kdf.ts info
        // labels, verified against secure-send-web's Web Crypto derivations.
        let root = fixed_root();
        let salt = [7u8; SALT_LEN];
        let session = root.session_keys(&salt).unwrap();
        let seals = root.handshake_seal_keys(&salt).unwrap();

        assert_eq!(
            hex_lower(&session.signals),
            "6d418e6543fd2d99f8d7587a84884b90e1b765ff03e752bc7b265d6e21f10ab1"
        );
        assert_eq!(
            hex_lower(&session.content),
            "f7e6eb8471d0e274ce7f979d5b35d05742ec85e61a831e9ade6f4811a62bbb1d"
        );
        assert_eq!(
            hex_lower(&seals.claim),
            "b5be97d4f23fd9105f32692c71d5964276ce01c997154fa31c124cc6ddb83e22"
        );
        assert_eq!(
            hex_lower(&seals.confirm),
            "581475ee363698d069426c1b36805072573080556f8869f75f3dfc0417252357"
        );
    }

    #[test]
    fn confirmation_code_matches_web_vector() {
        let transcript_hash = "f".repeat(64);
        let metadata_hash = "e".repeat(64);
        let binding = ConfirmationCodeBinding {
            transfer_id: "a1b2c3d4e5f60718",
            sender_nonce: "c2VuZGVyLW5vbmNlLTAwMDAwMDA=",
            receiver_nonce: "cmVjZWl2ZXItbm9uY2UtMDAwMDA=",
            transcript_hash: &transcript_hash,
            metadata_hash: &metadata_hash,
        };

        // HKDF bits 98c41f6f50 over the fixed root, Crockford Base32 encoded.
        assert_eq!(
            fixed_root().confirmation_code(&[7u8; SALT_LEN], &binding).unwrap(),
            encode_crockford_base32(&[0x98, 0xc4, 0x1f, 0x6f, 0x50])
        );
    }

    #[test]
    fn code_is_bound_to_every_handshake_value() {
        let transcript_hash = "f".repeat(64);
        let metadata_hash = "e".repeat(64);
        let base_binding = || ConfirmationCodeBinding {
            transfer_id: "a1b2c3d4e5f60718",
            sender_nonce: "c2VuZGVyLW5vbmNlLTAwMDAwMDA=",
            receiver_nonce: "cmVjZWl2ZXItbm9uY2UtMDAwMDA=",
            transcript_hash: &transcript_hash,
            metadata_hash: &metadata_hash,
        };
        let root = fixed_root();
        let salt = [7u8; SALT_LEN];
        let base = root.confirmation_code(&salt, &base_binding()).unwrap();

        let other_transcript = format!("{}e", "f".repeat(63));
        let other_metadata = format!("{}f", "e".repeat(63));
        let variants = [
            ConfirmationCodeBinding {
                transfer_id: "0000000000000000",
                ..base_binding()
            },
            ConfirmationCodeBinding {
                sender_nonce: "b3RoZXItc2VuZGVyLW5vbmNlLTA=",
                ..base_binding()
            },
            ConfirmationCodeBinding {
                receiver_nonce: "b3RoZXItcmVjZWl2ZXItbm9uY2U=",
                ..base_binding()
            },
            ConfirmationCodeBinding {
                transcript_hash: &other_transcript,
                ..base_binding()
            },
            ConfirmationCodeBinding {
                metadata_hash: &other_metadata,
                ..base_binding()
            },
        ];
        for variant in &variants {
            assert_ne!(root.confirmation_code(&salt, variant).unwrap(), base);
        }
        // A different transfer salt separates it too.
        assert_ne!(
            root.confirmation_code(&[8u8; SALT_LEN], &base_binding())
                .unwrap(),
            base
        );
    }

    #[test]
    fn rejects_a_short_salt() {
        assert!(fixed_root().session_keys(&[0u8; 8]).is_err());
    }
}
