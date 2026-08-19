//! SPAKE2 (RFC 9382) over P-256, byte-for-byte compatible with
//! secure-send-web's `src/lib/crypto/spake2.ts`.
//!
//! A balanced PAKE is what removes the offline attack surface the previous
//! PBKDF2-sealed handshake had to out-muscle: both published elements are
//! password-blinded group elements, so a relay transcript provides no efficient
//! offline PIN verifier. The only way to test a guess is a live protocol run,
//! which the sender counts and caps ([`crate::crypto::pin::CLAIM_VERIFY_LIMIT`]).
//!
//! Roles are fixed: the transfer sender is SPAKE2's A (blinds with `M`), the
//! receiver is B (blinds with `N`).

use std::sync::OnceLock;

use anyhow::{Result, bail};
use hkdf::Hkdf;
use p256::elliptic_curve::Curve;
use p256::elliptic_curve::bigint::{Encoding, NonZero, U384};
use p256::elliptic_curve::group::Group;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{NistP256, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, SecretKey};
use sha2::{Digest, Sha256};

use super::chunk::fill_random;
use super::kdf::PakeRoot;

/// Compressed SEC1 point size — the wire size of every SPAKE2 element.
pub const PAKE_MESSAGE_LEN: usize = 33;
/// Width of the SPAKE2 password scalar `w` on the wire (big-endian).
pub const PAKE_SECRET_LEN: usize = 32;

/// Versioned domain separators. Bump with any change to the transcript layout.
const PAKE_CONTEXT: &str = "secure-send:spake2-p256:v3";
const PAKE_SECRET_SALT: &str = "secure-send:spake2-w:v3";

/// RFC 9382 nothing-up-my-sleeve constant `M` for P-256 (compressed SEC1).
const M_BYTES: [u8; PAKE_MESSAGE_LEN] = [
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];
/// RFC 9382 nothing-up-my-sleeve constant `N` for P-256 (compressed SEC1).
const N_BYTES: [u8; PAKE_MESSAGE_LEN] = [
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];

/// Which side of the exchange this peer is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PakeRole {
    /// The transfer sender: blinds with `M`, unblinds the peer with `N`.
    Sender,
    /// The transfer receiver: blinds with `N`, unblinds the peer with `M`.
    Receiver,
}

impl PakeRole {
    /// The constant this side blinds its own ephemeral element with.
    fn own_constant(self) -> ProjectivePoint {
        match self {
            Self::Sender => *pake_m(),
            Self::Receiver => *pake_n(),
        }
    }

    /// The constant the peer's element must be unblinded against.
    fn peer_constant(self) -> ProjectivePoint {
        match self {
            Self::Sender => *pake_n(),
            Self::Receiver => *pake_m(),
        }
    }
}

fn decompress(bytes: &[u8; PAKE_MESSAGE_LEN]) -> ProjectivePoint {
    PublicKey::from_sec1_bytes(bytes)
        .expect("RFC 9382 constant is a valid P-256 point")
        .to_projective()
}

fn pake_m() -> &'static ProjectivePoint {
    static M: OnceLock<ProjectivePoint> = OnceLock::new();
    M.get_or_init(|| decompress(&M_BYTES))
}

fn pake_n() -> &'static ProjectivePoint {
    static N: OnceLock<ProjectivePoint> = OnceLock::new();
    N.get_or_init(|| decompress(&N_BYTES))
}

/// The group order widened to 384 bits, for reducing the HKDF output for `w`.
fn wide_group_order() -> NonZero<U384> {
    let mut wide = [0u8; 48];
    wide[16..].copy_from_slice(&NistP256::ORDER.to_be_bytes());
    NonZero::new(U384::from_be_slice(&wide)).unwrap()
}

/// Derive the SPAKE2 password scalar `w` from the PIN: HKDF-SHA256 stretched to
/// 384 bits and reduced mod the group order, returned as 32 big-endian bytes.
///
/// There is deliberately no expensive KDF. Password hardening only helps when
/// some artifact permits offline guessing, and the whole point of the PAKE is
/// that none does. The 384-bit intermediate makes the mod-n reduction bias
/// negligible.
///
/// The whole PIN goes in, locator included. The locator is public (it is
/// recoverable from the published hint), so it adds no strength, but it costs
/// nothing and keeps a wrong locator from producing a working handshake.
pub fn derive_pake_secret(pin: &str) -> [u8; PAKE_SECRET_LEN] {
    let hkdf = Hkdf::<Sha256>::new(Some(PAKE_SECRET_SALT.as_bytes()), pin.as_bytes());
    let mut wide = [0u8; 48];
    hkdf.expand(b"w", &mut wide)
        .expect("HKDF output length is always valid here");

    let reduced = (U384::from_be_slice(&wide) % wide_group_order()).to_be_bytes();
    wide.fill(0);

    let mut secret = [0u8; PAKE_SECRET_LEN];
    secret.copy_from_slice(&reduced[16..]);
    // w = 0 has probability ~2^-384; map it to a valid scalar anyway so the
    // function is total.
    if secret == [0u8; PAKE_SECRET_LEN] {
        secret[PAKE_SECRET_LEN - 1] = 1;
    }
    secret
}

fn read_pake_scalar(pake_secret: &[u8; PAKE_SECRET_LEN]) -> Result<Scalar> {
    // SecretKey::from_slice enforces exactly the RFC's requirement on w:
    // a reduced, nonzero group scalar.
    let Ok(secret) = SecretKey::from_slice(pake_secret) else {
        bail!("invalid PAKE secret: not a reduced nonzero group scalar");
    };
    Ok(*secret.to_nonzero_scalar())
}

/// The values the SPAKE2 transcript binds beyond the group elements. Keying the
/// transcript by both Nostr identities and the transfer id means a relay (or a
/// live-PIN attacker) that republishes either side's element under a different
/// identity or transfer derives a *different* root key, and every seal keyed
/// off it then fails.
pub struct PakeIdentities<'a> {
    pub transfer_id: &'a str,
    /// Nostr pubkey of the transfer sender (SPAKE2 A).
    pub sender_pubkey: &'a str,
    /// Nostr pubkey of the claiming receiver (SPAKE2 B).
    pub receiver_pubkey: &'a str,
}

/// One side of one SPAKE2 run: an ephemeral scalar, its blinded element, and
/// the password scalar the run is authenticated by.
///
/// The receiver starts one per rendezvous candidate it claims, so its `y` and
/// `pB` really are single-use. The sender starts one per PIN generation and
/// [`PakeRun::finish`]es it against *every* claim that generation sees, so its
/// `x` and `pA` are reused up to
/// [`crate::crypto::pin::CLAIM_VERIFY_LIMIT`] times inside one rotation
/// bucket. `finish` takes `&self` for exactly that reason.
///
/// That reuse is a deliberate deviation from RFC 9382 §7 ("Randomly generated
/// values, e.g., x and y, MUST NOT be reused"). It is forced by the rendezvous
/// shape: `pA` is published before any claimant exists, and each claim is
/// sealed under a transcript committing to the `pA` its author saw, so a fresh
/// scalar per claim would need a third round trip. See "SPAKE2 scalar reuse"
/// in `docs/ARCHITECTURE.md` for why it does not hand an attacker more than
/// the metered one guess per claim — and for the limits of that argument.
pub struct PakeRun {
    role: PakeRole,
    secret: [u8; PAKE_SECRET_LEN],
    ephemeral: NonZeroScalar,
    message: [u8; PAKE_MESSAGE_LEN],
}

impl Drop for PakeRun {
    fn drop(&mut self) {
        // Best-effort hygiene, mirroring secure-send-web's wipe of the PAKE
        // secret when a generation is retired. Every secret here is
        // transfer-scoped and dead within minutes either way.
        self.secret.fill(0);
    }
}

impl PakeRun {
    /// Start a run: pick a fresh ephemeral scalar and produce this side's
    /// blinded element (`pA = x·G + w·M` for the sender, `pB = y·G + w·N` for
    /// the receiver).
    pub fn start(role: PakeRole, pake_secret: &[u8; PAKE_SECRET_LEN]) -> Result<Self> {
        let w = read_pake_scalar(pake_secret)?;

        // Rejection-sample a valid nonzero scalar < the group order. A random
        // 32-byte string is out of range with probability ~2^-32, so this
        // effectively never loops.
        let ephemeral = loop {
            let mut bytes = [0u8; 32];
            fill_random(&mut bytes)?;
            let candidate = SecretKey::from_slice(&bytes);
            bytes.fill(0);
            if let Ok(secret) = candidate {
                break secret.to_nonzero_scalar();
            }
        };

        let blinded = ProjectivePoint::GENERATOR * *ephemeral + role.own_constant() * w;
        Ok(Self {
            role,
            secret: *pake_secret,
            ephemeral,
            message: compress(&blinded)?,
        })
    }

    /// This side's blinded element, published on the wire.
    pub fn message(&self) -> &[u8; PAKE_MESSAGE_LEN] {
        &self.message
    }

    /// Finish the run: unblind the peer's element, compute the shared element
    /// `K`, and hash the RFC 9382 transcript
    /// `TT = len‖Context ‖ len‖idA ‖ len‖idB ‖ len‖pA ‖ len‖pB ‖ len‖K ‖ len‖w`
    /// into the session root key.
    ///
    /// Fails on any invalid peer element (wrong length, not on the curve, or
    /// one whose unblinding lands on the identity). A wrong PIN does *not*
    /// fail here — both sides simply derive different roots, and the mismatch
    /// surfaces when a sealed claim or confirm refuses to open.
    pub fn finish(
        &self,
        peer_message: &[u8],
        identities: &PakeIdentities<'_>,
    ) -> Result<PakeRoot> {
        let w = read_pake_scalar(&self.secret)?;

        if peer_message.len() != PAKE_MESSAGE_LEN {
            bail!("invalid PAKE message length");
        }
        // from_sec1_bytes validates the point is on the curve; P-256 has
        // cofactor 1, so on-curve and non-identity is the full subgroup check.
        let Ok(peer) = PublicKey::from_sec1_bytes(peer_message) else {
            bail!("invalid PAKE message: point not on curve");
        };

        let unblinded = peer.to_projective() - self.role.peer_constant() * w;
        if bool::from(unblinded.is_identity()) {
            bail!("invalid PAKE message: unblinds to the identity");
        }
        let mut shared = compress(&(unblinded * *self.ephemeral))?;

        let (pa, pb) = match self.role {
            PakeRole::Sender => (&self.message[..], peer_message),
            PakeRole::Receiver => (peer_message, &self.message[..]),
        };

        // Hash incrementally instead of buffering: the transcript's last two
        // fields are the shared element K and the password scalar w, and a
        // growing Vec copies them into successively larger allocations, leaving
        // both in freed heap blocks that the final wipe cannot reach.
        let mut transcript = Sha256::new();
        push_framed(
            &mut transcript,
            format!("{PAKE_CONTEXT}|{}", identities.transfer_id).as_bytes(),
        );
        push_framed(&mut transcript, identities.sender_pubkey.as_bytes());
        push_framed(&mut transcript, identities.receiver_pubkey.as_bytes());
        push_framed(&mut transcript, pa);
        push_framed(&mut transcript, pb);
        push_framed(&mut transcript, &shared);
        push_framed(&mut transcript, &self.secret);

        let digest = transcript.finalize();
        shared.fill(0);
        Ok(PakeRoot::from_digest(digest.into()))
    }
}

/// Absorb one transcript field with RFC 9382's 8-byte little-endian length
/// framing, so no field can shift bytes into a neighbor.
fn push_framed(out: &mut Sha256, data: &[u8]) {
    out.update((data.len() as u64).to_le_bytes());
    out.update(data);
}

fn compress(point: &ProjectivePoint) -> Result<[u8; PAKE_MESSAGE_LEN]> {
    let encoded = point.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != PAKE_MESSAGE_LEN {
        bail!("PAKE element did not encode to a compressed point");
    }
    let mut out = [0u8; PAKE_MESSAGE_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Cheap structural check for an incoming wire element, before committing to
/// the heavier [`PakeRun::finish`] work: correct length and a valid
/// non-identity curve point.
pub fn is_valid_pake_message(message: &[u8]) -> bool {
    message.len() == PAKE_MESSAGE_LEN && PublicKey::from_sec1_bytes(message).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::{ConfirmationCodeBinding, generate_salt};

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn identities<'a>() -> PakeIdentities<'a> {
        PakeIdentities {
            transfer_id: "a1b2c3d4e5f60718",
            sender_pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            receiver_pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }
    }

    #[test]
    fn uses_the_rfc_9382_p256_constants() {
        // Known-answer vectors from RFC 9382 §6. An edited or home-grown
        // constant breaks the security argument (an attacker who knows
        // dlog(M)/dlog(N) can unblind an element), so pin the exact encodings.
        assert_eq!(
            hex_lower(&M_BYTES),
            "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
        );
        assert_eq!(
            hex_lower(&N_BYTES),
            "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
        );
    }

    #[test]
    fn pake_secret_matches_web_vector() {
        // secure-send-web's derivePakeSecret("ABCDEFGHJKLA").
        assert_eq!(
            hex_lower(&derive_pake_secret("ABCDEFGHJKLA")),
            "a225404eecf6539849b7bc7c69290489d50c99cf8baa4d46f0ee1485ff555b2b"
        );
        // Deterministic across the two peers entering the same PIN.
        assert_eq!(
            derive_pake_secret("AbCDefG23hjk"),
            derive_pake_secret("AbCDefG23hjk")
        );
    }

    /// A fully deterministic run against secure-send-web: fixed `w` (from the
    /// PIN above) and fixed ephemeral scalars x = 0x11.., y = 0x22.., so the
    /// published elements, the shared element K, and the transcript digest can
    /// all be pinned as known answers.
    #[test]
    fn transcript_matches_web_fixed_vector() {
        let w = derive_pake_secret("ABCDEFGHJKLA");
        let w_scalar = read_pake_scalar(&w).unwrap();

        let fixed = |byte: u8| {
            *SecretKey::from_slice(&[byte; 32])
                .unwrap()
                .to_nonzero_scalar()
        };
        let (x, y) = (fixed(0x11), fixed(0x22));

        let sender = PakeRun {
            role: PakeRole::Sender,
            secret: w,
            ephemeral: NonZeroScalar::new(x).unwrap(),
            message: compress(&(ProjectivePoint::GENERATOR * x + *pake_m() * w_scalar)).unwrap(),
        };
        let receiver = PakeRun {
            role: PakeRole::Receiver,
            secret: w,
            ephemeral: NonZeroScalar::new(y).unwrap(),
            message: compress(&(ProjectivePoint::GENERATOR * y + *pake_n() * w_scalar)).unwrap(),
        };

        assert_eq!(
            hex_lower(sender.message()),
            "02da2c0682f872084a64f331a946a607caff3ccef9c1e1ef0e2e73037cd8f6df19"
        );
        assert_eq!(
            hex_lower(receiver.message()),
            "020b00a820bc8c8e2cbb52af2282998d090036f3abd4ccb09b52b8c4e83367d4f9"
        );

        let root = sender.finish(receiver.message(), &identities()).unwrap();
        assert_eq!(
            hex_lower(root.ikm()),
            "7ac9af6119570923bff87cad72b536e6aee2e4c5f11ff01d0e1c34682840ad1f"
        );
        // Both roles land on the same root from opposite sides of the wire.
        let mirrored = receiver.finish(sender.message(), &identities()).unwrap();
        assert_eq!(mirrored.ikm(), root.ikm());
    }

    #[test]
    fn both_peers_derive_the_same_root_from_the_same_pin() {
        let w = derive_pake_secret("ABCDEFGHJKLA");
        let sender = PakeRun::start(PakeRole::Sender, &w).unwrap();
        let receiver = PakeRun::start(PakeRole::Receiver, &w).unwrap();

        let a = sender.finish(receiver.message(), &identities()).unwrap();
        let b = receiver.finish(sender.message(), &identities()).unwrap();
        assert_eq!(a.ikm(), b.ikm());
    }

    #[test]
    fn published_elements_are_single_use() {
        let w = derive_pake_secret("ABCDEFGHJKLA");
        let first = PakeRun::start(PakeRole::Sender, &w).unwrap();
        let second = PakeRun::start(PakeRole::Sender, &w).unwrap();
        assert_ne!(first.message(), second.message());
    }

    #[test]
    fn a_wrong_pin_lands_on_a_different_root() {
        // The online-guess property: nothing fails here, the roots simply
        // disagree, and the mismatch surfaces when a seal refuses to open.
        let sender = PakeRun::start(PakeRole::Sender, &derive_pake_secret("ABCDEFGHJKLA")).unwrap();
        let receiver =
            PakeRun::start(PakeRole::Receiver, &derive_pake_secret("ABCDEFGHJKLZ")).unwrap();

        let a = sender.finish(receiver.message(), &identities()).unwrap();
        let b = receiver.finish(sender.message(), &identities()).unwrap();
        assert_ne!(a.ikm(), b.ikm());
    }

    #[test]
    fn root_is_bound_to_the_transfer_id_and_both_identities() {
        let w = derive_pake_secret("ABCDEFGHJKLA");
        let sender = PakeRun::start(PakeRole::Sender, &w).unwrap();
        let receiver = PakeRun::start(PakeRole::Receiver, &w).unwrap();
        let base = sender.finish(receiver.message(), &identities()).unwrap();

        let changed = [
            PakeIdentities {
                transfer_id: "0000000000000000",
                ..identities()
            },
            PakeIdentities {
                sender_pubkey: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                ..identities()
            },
            PakeIdentities {
                receiver_pubkey: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                ..identities()
            },
        ];
        for variant in changed {
            let other = receiver.finish(sender.message(), &variant).unwrap();
            assert_ne!(base.ikm(), other.ikm());
        }
    }

    #[test]
    fn a_tampered_element_breaks_agreement_under_the_right_pin() {
        // A relay that swaps an element for its own (without the PIN) must not
        // share a key with either side.
        let w = derive_pake_secret("ABCDEFGHJKLA");
        let sender = PakeRun::start(PakeRole::Sender, &w).unwrap();
        let receiver = PakeRun::start(PakeRole::Receiver, &w).unwrap();
        let attacker =
            PakeRun::start(PakeRole::Receiver, &derive_pake_secret("ABCDEFGHJKLZ")).unwrap();

        let a = sender.finish(attacker.message(), &identities()).unwrap();
        let b = receiver.finish(sender.message(), &identities()).unwrap();
        assert_ne!(a.ikm(), b.ikm());
    }

    #[test]
    fn rejects_malformed_and_invalid_peer_elements() {
        let w = derive_pake_secret("ABCDEFGHJKLA");
        let sender = PakeRun::start(PakeRole::Sender, &w).unwrap();

        assert!(sender.finish(&[0u8; 32], &identities()).is_err());
        let mut junk = [0xffu8; PAKE_MESSAGE_LEN];
        junk[0] = 0x02;
        assert!(sender.finish(&junk, &identities()).is_err());
        // Its own element unblinds to the identity for the peer role only, so
        // check the explicit identity guard with w·N reflected back.
        let reflected = compress(&(*pake_n() * read_pake_scalar(&w).unwrap())).unwrap();
        assert!(sender.finish(&reflected, &identities()).is_err());
    }

    #[test]
    fn screens_wire_elements() {
        let w = derive_pake_secret("ABCDEFGHJKLA");
        let run = PakeRun::start(PakeRole::Receiver, &w).unwrap();
        assert!(is_valid_pake_message(run.message()));
        assert!(!is_valid_pake_message(&run.message()[1..]));
        let mut junk = [0xffu8; PAKE_MESSAGE_LEN];
        junk[0] = 0x03;
        assert!(!is_valid_pake_message(&junk));
    }

    #[test]
    fn peers_agree_on_the_confirmation_code_and_session_keys() {
        let w = derive_pake_secret("ABCDEFGHJKLA");
        let sender = PakeRun::start(PakeRole::Sender, &w).unwrap();
        let receiver = PakeRun::start(PakeRole::Receiver, &w).unwrap();
        let salt = generate_salt().unwrap();

        let a = sender.finish(receiver.message(), &identities()).unwrap();
        let b = receiver.finish(sender.message(), &identities()).unwrap();

        let transcript_hash = "f".repeat(64);
        let metadata_hash = "e".repeat(64);
        let binding = ConfirmationCodeBinding {
            transfer_id: "a1b2c3d4e5f60718",
            sender_nonce: "c2VuZGVyLW5vbmNlLTAwMDAwMDA=",
            receiver_nonce: "cmVjZWl2ZXItbm9uY2UtMDAwMDA=",
            transcript_hash: &transcript_hash,
            metadata_hash: &metadata_hash,
        };
        assert_eq!(
            a.confirmation_code(&salt, &binding).unwrap(),
            b.confirmation_code(&salt, &binding).unwrap()
        );
        assert_eq!(
            a.session_keys(&salt).unwrap().content,
            b.session_keys(&salt).unwrap().content
        );
    }
}
