//! AES-256-GCM helpers compatible with pTransfer's `aes-gcm.ts`.
//!
//! Format for Nostr metadata/signaling ciphertexts:
//! `12-byte nonce || ciphertext || 16-byte GCM tag`.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use anyhow::{Context, Result, bail};

use super::chunk::fill_random;

pub const AES_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

fn cipher(key: &[u8; AES_KEY_LEN]) -> Aes256Gcm {
    Aes256Gcm::new(GenericArray::from_slice(key))
}

pub fn encrypt(key: &[u8; AES_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let ciphertext = cipher(key)
        .encrypt(GenericArray::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt(key: &[u8; AES_KEY_LEN], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        bail!(
            "encrypted data too short: expected at least {} bytes, got {}",
            NONCE_LEN + TAG_LEN,
            encrypted.len()
        );
    }

    let (nonce, ciphertext) = encrypted.split_at(NONCE_LEN);
    cipher(key)
        .decrypt(GenericArray::from_slice(nonce), ciphertext)
        .context("AES-GCM decryption/authentication failed")
}
