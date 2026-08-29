//! Cryptography compatible with pTransfer (Web Crypto API).
//!
//! - [`base32`]: Crockford Base32 encoding and normalization for confirmation
//!   codes.
//! - [`chunk`]: AES-256-GCM streaming chunk format with the 2-byte chunk index
//!   as additional authenticated data.
//! - [`kdf`]: session, handshake-seal, and confirmation-code derivations off
//!   the SPAKE2 root.
//! - [`pin`]: rotating PIN generation, validation, and the public rendezvous
//!   hint.
//! - [`spake2`]: the SPAKE2 (RFC 9382) password-authenticated key exchange the
//!   PIN drives.

pub mod aes;
pub mod base32;
pub mod chunk;
pub mod kdf;
pub mod pin;
pub mod spake2;

/// Cap on a transfer that does not run over a direct WebRTC data channel: the
/// Nostr file relay and the Tor onion transport.
///
/// Both push bytes through third parties at a fraction of a data channel's
/// speed, and neither can resume, so a transfer that dies two thirds of the
/// way through starts over. [`chunk::MAX_MESSAGE_SIZE`] stops meaning anything
/// on them long before it is reached.
///
/// It is one constant rather than one per transport because a receiver
/// enforces the sender's ceiling as its own: two numbers that drifted apart
/// would show up as a transfer refused mid-handshake for no reason a user
/// could act on. It lives here, with neither transport, for the same reason —
/// the relay path and the onion path are alternatives, and neither is the
/// other's source of truth.
pub const SLOW_TRANSPORT_MAX_BYTES: u64 = 100 * 1024 * 1024;
