//! Cryptography compatible with secure-send-web (Web Crypto API).
//!
//! - [`base32`]: Crockford Base32 encoding and normalization for confirmation
//!   codes.
//! - [`chunk`]: AES-256-GCM streaming chunk format with the 2-byte chunk index
//!   as additional authenticated data.
//! - [`ecdh`]: P-256 ECDH key agreement + HKDF-SHA256 content-key derivation
//!   used by manual (copy/paste) mode.
//! - [`pin`]: PIN generation and PBKDF2 key derivation used by Nostr mode.

pub mod aes;
pub mod base32;
pub mod chunk;
pub mod ecdh;
pub mod pin;
