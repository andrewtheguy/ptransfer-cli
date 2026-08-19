//! Cryptography compatible with secure-send-web (Web Crypto API).
//!
//! - [`base32`]: Crockford Base32 encoding and normalization for confirmation
//!   codes.
//! - [`chunk`]: AES-256-GCM streaming chunk format with the 2-byte chunk index
//!   as additional authenticated data.
//! - [`ecdh`]: P-256 ECDH key agreement + HKDF-SHA256 content-key derivation
//!   used by manual (copy/paste) mode.
//! - [`kdf`]: session, handshake-seal, and confirmation-code derivations off
//!   the SPAKE2 root used by Nostr mode.
//! - [`pin`]: rotating PIN generation, validation, and the public rendezvous
//!   hint used by Nostr mode.
//! - [`spake2`]: the SPAKE2 (RFC 9382) password-authenticated key exchange the
//!   PIN drives in Nostr mode.

pub mod aes;
pub mod base32;
pub mod chunk;
pub mod ecdh;
pub mod kdf;
pub mod pin;
pub mod spake2;
