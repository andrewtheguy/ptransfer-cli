//! AES-256-GCM helpers compatible with pTransfer's `aes-gcm.ts`.
//!
//! Format for Nostr metadata/signaling ciphertexts:
//! `12-byte nonce || ciphertext || 16-byte GCM tag`.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use anyhow::{Context, Result, bail};

use super::chunk::fill_random;

pub const AES_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

fn cipher(key: &[u8; AES_KEY_LEN]) -> Aes256Gcm {
    Aes256Gcm::new(GenericArray::from_slice(key))
}

pub fn encrypt(key: &[u8; AES_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_with_aad(key, plaintext, &[])
}

/// As [`encrypt`], binding `aad` into the authentication tag. Decryption then
/// requires the identical additional data, which is how a message sealed for
/// one transfer and direction cannot be replayed as another's.
pub fn encrypt_with_aad(
    key: &[u8; AES_KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let ciphertext = cipher(key)
        .encrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt(key: &[u8; AES_KEY_LEN], encrypted: &[u8]) -> Result<Vec<u8>> {
    decrypt_with_aad(key, encrypted, &[])
}

/// As [`decrypt`], requiring the same `aad` the sealer bound in.
pub fn decrypt_with_aad(
    key: &[u8; AES_KEY_LEN],
    encrypted: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        bail!(
            "encrypted data too short: expected at least {} bytes, got {}",
            NONCE_LEN + TAG_LEN,
            encrypted.len()
        );
    }

    let (nonce, ciphertext) = encrypted.split_at(NONCE_LEN);
    cipher(key)
        .decrypt(
            GenericArray::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .context("AES-GCM decryption/authentication failed")
}
