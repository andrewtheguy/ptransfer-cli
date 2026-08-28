//! The key schedule Code Exchange hangs off one ECDH agreement.
//!
//! There is no PAKE here and no relay-carried handshake: the offer is carried
//! by a person, and its authenticity is what the whole mode rests on. Both
//! sides mint an ephemeral P-256 key pair, the offer and the answer carry the
//! two public keys, and everything below comes out of the shared secret with
//! the offer's salt as the HKDF salt and a distinct info label each:
//!
//! | Derivation | Label | Used by |
//! | --- | --- | --- |
//! | Content key | `ptransfer-mutual` | the direct data channel |
//! | Answer confirmation tag | `ptransfer:code-exchange:v1:answer-confirm|…` | the sender, before it acts on a response |
//! | Relay session | `ptransfer-nostr-file:v1:session` | the fallback's control channel |
//! | Onion password | `ptransfer-code-exchange:v1:onion-password` | the anonymous fallback's Tor handshake |
//!
//! The last two are what let the anonymous fallback happen with nothing extra
//! handed over: the password the Tor transport would otherwise ask a person to
//! carry is derived on both devices instead, and the control channel that
//! announces the onion address is keyed from the same secret.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::{EncodedPoint, PublicKey};
use sha2::Sha256;

use crate::crypto::aes::AES_KEY_LEN;

use super::payload::{ANSWER_CONFIRMATION_LEN, CODE_SALT_LEN, PUBLIC_KEY_LEN};

/// HKDF info label for the direct path's content key.
const CONTENT_INFO: &str = "ptransfer-mutual";
/// HKDF info label prefix for the answer's key-confirmation tag.
const ANSWER_CONFIRM_INFO: &str = "ptransfer:code-exchange:v1:answer-confirm";
/// HKDF info label for the relay session both sides derive for the fallback.
const RELAY_SESSION_INFO: &str = "ptransfer-nostr-file:v1:session";
/// HKDF info label for the control-channel key, derived from the session key.
const CONTROL_KEY_INFO: &str = "ptransfer-nostr-file:v1:control";
/// HKDF info label for the onion-service password of the anonymous fallback.
const ONION_PASSWORD_INFO: &str = "ptransfer-code-exchange:v1:onion-password";

/// Bytes of the relay session's public transfer id, before hex.
const RELAY_TRANSFER_ID_BYTES: usize = 16;
/// Bytes behind the derived onion password. Never read, typed, or compared by
/// a person, so it is sized as key material rather than as something to say
/// out loud — the online-guessing bounds a human-length password needs simply
/// do not apply to it.
const ONION_PASSWORD_BYTES: usize = 32;

/// One side's ephemeral ECDH key pair. The secret is consumed by the agreement
/// and never leaves this process.
pub struct CodeKeyPair {
    secret: EphemeralSecret,
    public_key: [u8; PUBLIC_KEY_LEN],
}

impl CodeKeyPair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut rand_core_compat::OsRng);
        let point = EncodedPoint::from(secret.public_key());
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(point.as_bytes());
        Self { secret, public_key }
    }

    /// The uncompressed SEC1 point the code carries.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// Agree with the peer's public key.
    ///
    /// Takes `&self` rather than consuming: the sender's public key is inside
    /// the code it is showing, so the same pair has to serve every response
    /// pasted against that code — including the refused ones. The pair is
    /// still ephemeral, minted per exchange and dropped with it.
    pub fn agree(&self, peer_public_key: &[u8; PUBLIC_KEY_LEN]) -> Result<CodeSecret> {
        if peer_public_key[0] != 0x04 {
            bail!("the peer's key is not an uncompressed P-256 point");
        }
        let peer = PublicKey::from_sec1_bytes(peer_public_key)
            .context("the peer's key is not a valid P-256 point")?;
        let shared = self.secret.diffie_hellman(&peer);
        let mut ikm = [0u8; 32];
        ikm.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(CodeSecret { ikm })
    }
}

/// The ECDH shared secret: the x coordinate of the agreed point, which is what
/// Web Crypto's `deriveBits`/`deriveKey` hands the web app as HKDF input.
pub struct CodeSecret {
    ikm: [u8; 32],
}

impl Drop for CodeSecret {
    fn drop(&mut self) {
        self.ikm.fill(0);
    }
}

/// The relay-fallback session both sides derive rather than carry.
///
/// Nothing about it travels in a code: the id is the public tag namespace the
/// control channel lives under, and the key is what seals it.
pub struct RelaySession {
    /// 32 lowercase hex characters.
    pub transfer_id: String,
    pub key_bytes: [u8; AES_KEY_LEN],
}

impl Drop for RelaySession {
    fn drop(&mut self) {
        self.key_bytes.fill(0);
    }
}

impl CodeSecret {
    fn hkdf(&self, salt: &[u8; CODE_SALT_LEN]) -> Hkdf<Sha256> {
        Hkdf::<Sha256>::new(Some(salt), &self.ikm)
    }

    /// The AES-256-GCM key the direct data channel's chunks are sealed with.
    pub fn content_key(&self, salt: &[u8; CODE_SALT_LEN]) -> Result<[u8; AES_KEY_LEN]> {
        let mut key = [0u8; AES_KEY_LEN];
        self.hkdf(salt)
            .expand(CONTENT_INFO.as_bytes(), &mut key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(key)
    }

    /// The tag the receiver folds into its answer and the sender recomputes
    /// before it acts on that answer at all.
    ///
    /// Producing one takes having held this offer, having completed the
    /// agreement against the key inside it, *and* having sent exactly the
    /// answer that was signed — so an answer from another transfer, a replayed
    /// answer, and an answer whose SDP or candidates were edited on the way
    /// back are all refused outright instead of turning into a connection that
    /// never opens.
    pub fn answer_confirmation(
        &self,
        salt: &[u8; CODE_SALT_LEN],
        offer_transcript_hash: &str,
        answer_transcript_hash: &str,
    ) -> Result<[u8; ANSWER_CONFIRMATION_LEN]> {
        // Both transcripts are fixed-length hex, so '|' cannot appear inside a
        // field and the join is unambiguous.
        let info =
            format!("{ANSWER_CONFIRM_INFO}|{offer_transcript_hash}|{answer_transcript_hash}");
        let mut tag = [0u8; ANSWER_CONFIRMATION_LEN];
        self.hkdf(salt)
            .expand(info.as_bytes(), &mut tag)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(tag)
    }

    /// The fallback's transfer id and key, from the same secret and salt under
    /// a label of their own.
    pub fn relay_session(&self, salt: &[u8; CODE_SALT_LEN]) -> Result<RelaySession> {
        let mut bits = [0u8; RELAY_TRANSFER_ID_BYTES + AES_KEY_LEN];
        self.hkdf(salt)
            .expand(RELAY_SESSION_INFO.as_bytes(), &mut bits)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        let transfer_id = bits[..RELAY_TRANSFER_ID_BYTES]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut key_bytes = [0u8; AES_KEY_LEN];
        key_bytes.copy_from_slice(&bits[RELAY_TRANSFER_ID_BYTES..]);
        bits.fill(0);
        Ok(RelaySession {
            transfer_id,
            key_bytes,
        })
    }

    /// The password the anonymous fallback's Tor handshake runs on, in place
    /// of the one the Tor transfer mode asks a person to carry.
    ///
    /// It is never transmitted: both sides arrive at it from the secret the
    /// offer/answer exchange already established. The sender cannot reach it
    /// before it holds the receiver's public key, which exists only inside a
    /// response the sender itself took in — which is what keeps the service
    /// unreachable until then.
    pub fn onion_password(&self, salt: &[u8; CODE_SALT_LEN]) -> Result<String> {
        let mut bits = [0u8; ONION_PASSWORD_BYTES];
        self.hkdf(salt)
            .expand(ONION_PASSWORD_INFO.as_bytes(), &mut bits)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        let password = BASE64.encode(bits);
        bits.fill(0);
        Ok(password)
    }
}

impl RelaySession {
    /// The AES-256-GCM key every control message on this session is sealed
    /// with, derived from the session key with the transfer id as salt.
    pub fn control_key(&self) -> Result<[u8; AES_KEY_LEN]> {
        let hkdf = Hkdf::<Sha256>::new(Some(self.transfer_id.as_bytes()), &self.key_bytes);
        let mut key = [0u8; AES_KEY_LEN];
        hkdf.expand(CONTROL_KEY_INFO.as_bytes(), &mut key)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        Ok(key)
    }
}

/// `p256` 0.13 is built against `rand_core` 0.6, while the rest of this crate
/// draws randomness from `getrandom` and `rand` 0.10. Rather than pull a
/// second RNG stack in, hand it the one `getrandom` already provides.
mod rand_core_compat {
    pub use p256::elliptic_curve::rand_core::OsRng;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// A fixed secret, so every label below is pinned against the web app's
    /// Web Crypto derivations rather than against itself.
    fn fixed_secret() -> CodeSecret {
        let mut ikm = [0u8; 32];
        for (index, byte) in ikm.iter_mut().enumerate() {
            *byte = index as u8;
        }
        CodeSecret { ikm }
    }

    #[test]
    fn both_sides_of_an_agreement_reach_the_same_secret() {
        let sender = CodeKeyPair::generate();
        let receiver = CodeKeyPair::generate();
        let sender_public = *sender.public_key();
        let receiver_public = *receiver.public_key();

        let salt = [7u8; CODE_SALT_LEN];
        let from_sender = sender.agree(&receiver_public).unwrap();
        let from_receiver = receiver.agree(&sender_public).unwrap();
        assert_eq!(
            from_sender.content_key(&salt).unwrap(),
            from_receiver.content_key(&salt).unwrap()
        );
    }

    #[test]
    fn a_public_key_is_an_uncompressed_point() {
        let pair = CodeKeyPair::generate();
        assert_eq!(pair.public_key()[0], 0x04);
        assert_eq!(pair.public_key().len(), PUBLIC_KEY_LEN);
    }

    #[test]
    fn a_malformed_peer_key_is_refused_rather_than_agreed_with() {
        let pair = CodeKeyPair::generate();
        assert!(pair.agree(&[0u8; PUBLIC_KEY_LEN]).is_err());
        let pair = CodeKeyPair::generate();
        let mut not_on_the_curve = [4u8; PUBLIC_KEY_LEN];
        not_on_the_curve[0] = 0x04;
        assert!(pair.agree(&not_on_the_curve).is_err());
    }

    /// HKDF-SHA256(ikm = 0x00..0x1f, salt = 16 x 0x07) with each label, checked
    /// against the web app. A label that drifts lands the two sides on
    /// different keys, and nothing on the wire announces which one was used.
    #[test]
    fn every_label_matches_the_web_app() {
        let secret = fixed_secret();
        let salt = [7u8; CODE_SALT_LEN];

        assert_eq!(
            hex_lower(&secret.content_key(&salt).unwrap()),
            "bdf9708e97a719ea15bc3e19e4ec6e2092a04a3b9cd375a7bd796764c5d91e77"
        );
        let session = secret.relay_session(&salt).unwrap();
        assert_eq!(session.transfer_id, "c05587dba544d9543610d42f7b7b640d");
        assert_eq!(
            hex_lower(&session.key_bytes),
            "9ff98dad3dff5e42b0ca21a7cdabc2e135b8d50da09f0dc42c6fe31edef7f6e2"
        );
        assert_eq!(
            hex_lower(&session.control_key().unwrap()),
            "e62e943897153bd50efa915d454c71ca1a71b01e3441129e981551c7a430698b"
        );
        assert_eq!(
            secret.onion_password(&salt).unwrap(),
            "qwqg1Up94u8ObvUaqx7s1a9x7rGNS4rQANrbp5WQBCc="
        );
        assert_eq!(
            hex_lower(
                &secret
                    .answer_confirmation(&salt, &"aa".repeat(32), &"bb".repeat(32))
                    .unwrap()
            ),
            "ca43435529678169b0aed77536d8734a"
        );
    }
}
