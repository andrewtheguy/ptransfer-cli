//! Streaming chunk encryption, byte-for-byte compatible with pTransfer's
//! `src/lib/crypto/stream-crypto.ts`.
//!
//! Each chunk is one discrete WebRTC data-channel message with the wire format:
//!
//! ```text
//! [2-byte chunk index (big-endian)][12-byte nonce][ciphertext][16-byte GCM tag]
//! ```
//!
//! The 2-byte big-endian chunk index is also fed to AES-256-GCM as additional
//! authenticated data (AAD), making each chunk's write position tamper-evident.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use anyhow::{Context, Result, bail};

/// Plaintext chunk size (`ENCRYPTION_CHUNK_SIZE` in pTransfer).
pub const ENCRYPTION_CHUNK_SIZE: usize = 128 * 1024;
/// AES-GCM nonce length (`AES_NONCE_LENGTH`).
pub const NONCE_LEN: usize = 12;
/// AES-GCM tag length (`AES_TAG_LENGTH`).
pub const TAG_LEN: usize = 16;
/// Length of the big-endian chunk-index prefix.
pub const CHUNK_INDEX_SIZE: usize = 2;
/// Per-chunk wire overhead: index + nonce + tag (`ENCRYPTED_CHUNK_OVERHEAD` = 30).
pub const OVERHEAD_PER_CHUNK: usize = CHUNK_INDEX_SIZE + NONCE_LEN + TAG_LEN;
/// Maximum transferred payload size (`MAX_MESSAGE_SIZE` = 2 GiB). Both sides
/// stream chunk by chunk, so this is an application bound rather than a RAM
/// bound; generated ZIPs enforce it against their actual output while sending.
pub const MAX_MESSAGE_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Fill `buf` with cryptographically secure random bytes from the OS.
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| anyhow::anyhow!("OS RNG failure: {e}"))
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(GenericArray::from_slice(key))
}

/// Encrypt one chunk, producing `[index(2)][nonce(12)][ciphertext][tag(16)]`.
pub fn encrypt_chunk(key: &[u8; 32], plaintext: &[u8], index: u16) -> Result<Vec<u8>> {
    let index_bytes = index.to_be_bytes();

    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let ciphertext = cipher(key)
        .encrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &index_bytes,
            },
        )
        .map_err(|_| anyhow::anyhow!("chunk encryption failed"))?;

    let mut out = Vec::with_capacity(CHUNK_INDEX_SIZE + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&index_bytes);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Split a received chunk message into `(index, encrypted_data)` where
/// `encrypted_data` is `[nonce][ciphertext][tag]`.
pub fn parse_chunk_message(data: &[u8]) -> Result<(u16, &[u8])> {
    if data.len() < OVERHEAD_PER_CHUNK {
        bail!(
            "chunk message too short: {} bytes, need at least {}",
            data.len(),
            OVERHEAD_PER_CHUNK
        );
    }
    let index = u16::from_be_bytes([data[0], data[1]]);
    Ok((index, &data[CHUNK_INDEX_SIZE..]))
}

/// Decrypt `encrypted_data` (`[nonce][ciphertext][tag]`) for the given index.
/// The index is verified as AAD, so a mismatched index fails authentication.
pub fn decrypt_chunk(key: &[u8; 32], encrypted_data: &[u8], index: u16) -> Result<Vec<u8>> {
    if encrypted_data.len() < NONCE_LEN + TAG_LEN {
        bail!("encrypted chunk too short: {} bytes", encrypted_data.len());
    }
    let index_bytes = index.to_be_bytes();
    let (nonce, ciphertext) = encrypted_data.split_at(NONCE_LEN);

    cipher(key)
        .decrypt(
            GenericArray::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &index_bytes,
            },
        )
        .context("chunk decryption/authentication failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [7u8; 32];
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let msg = encrypt_chunk(&key, plaintext, 3).unwrap();
        // wire layout: index(2) + nonce(12) + ct + tag(16)
        assert_eq!(
            msg.len(),
            CHUNK_INDEX_SIZE + NONCE_LEN + plaintext.len() + TAG_LEN
        );
        let (idx, enc) = parse_chunk_message(&msg).unwrap();
        assert_eq!(idx, 3);
        let out = decrypt_chunk(&key, enc, idx).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn wrong_index_fails_auth() {
        let key = [1u8; 32];
        let msg = encrypt_chunk(&key, b"hello", 5).unwrap();
        let (_, enc) = parse_chunk_message(&msg).unwrap();
        // Decrypting with a different index must fail because the index is AAD.
        assert!(decrypt_chunk(&key, enc, 6).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let msg = encrypt_chunk(&[1u8; 32], b"hello", 0).unwrap();
        let (idx, enc) = parse_chunk_message(&msg).unwrap();
        assert!(decrypt_chunk(&[2u8; 32], enc, idx).is_err());
    }
}
