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
