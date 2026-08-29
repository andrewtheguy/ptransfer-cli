//! What a chunk is on the wire, and what a payload is before it is chunked.
//!
//! ```text
//! [ whole-payload deflate for a single file | identity for a generated ZIP ]
//!     -> chunk -> AES-256-GCM (nonce || ciphertext || tag) -> Z85
//! ```
//!
//! Compressing once over the whole payload rather than per chunk is what lets
//! a compressible file collapse into a few events instead of one per 48 KiB of
//! plaintext; a generated ZIP is already deflated entry by entry and is never
//! recompressed, which is the same flow-based rule the direct path's wire
//! encoding follows.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::aes::{self, AES_KEY_LEN};
use crate::wire::{Inflater, WireEncoding};

use super::{NOSTR_FILE_AAD_PREFIX, NOSTR_FILE_CHUNK_SIZE};

/// Whole-payload compression applied before chunking, as the manifest names
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadCompression {
    Deflate,
    None,
}

impl PayloadCompression {
    /// The compression a source's wire encoding implies. The two vocabularies
    /// describe the same flow-based decision — a single file is deflated once,
    /// a generated ZIP travels as it is — so neither side ever has to sniff
    /// content to agree.
    pub fn of(encoding: WireEncoding) -> Self {
        match encoding {
            WireEncoding::DeflateRaw => Self::Deflate,
            WireEncoding::Identity => Self::None,
        }
    }
}

/// Compress the whole payload once, before chunking.
///
/// Takes the plaintext by value: an already-compressed payload *is* the
/// payload, and copying a hundred megabytes to say so would be the largest
/// allocation this path makes.
pub fn compress_payload(data: Vec<u8>, compression: PayloadCompression) -> Result<Vec<u8>> {
    match compression {
        PayloadCompression::None => Ok(data),
        PayloadCompression::Deflate => {
            use std::io::Write as _;
            let mut encoder = flate2::write::DeflateEncoder::new(
                Vec::with_capacity(data.len() / 2),
                flate2::Compression::default(),
            );
            encoder.write_all(&data)?;
            encoder.finish().context("could not deflate the payload")
        }
    }
}

/// Reverse [`compress_payload`] on the assembled payload.
///
/// `file_size` is the exact plaintext size the manifest promised: it bounds
/// the inflate output, and anything but an exact match is refused — a payload
/// that decompresses to something else is not the file the manifest described,
/// whether by a bomb or by corruption.
pub fn decompress_payload(
    payload: &[u8],
    compression: PayloadCompression,
    file_size: u64,
) -> Result<Vec<u8>> {
    if compression == PayloadCompression::None {
        if payload.len() as u64 != file_size {
            bail!("the relayed payload is not the size the manifest promised");
        }
        return Ok(payload.to_vec());
    }
    let mut inflater = Inflater::new(file_size);
    let mut plaintext = Vec::with_capacity(file_size as usize);
    plaintext.extend_from_slice(inflater.push(payload)?);
    plaintext.extend_from_slice(inflater.finish()?);
    if plaintext.len() as u64 != file_size {
        bail!("the relayed payload did not decompress to the size the manifest promised");
    }
    Ok(plaintext)
}

/// Additional authenticated data binding a chunk to its transfer, index, and
/// total count, so a chunk moved to another position — or another transfer —
/// fails its GCM tag instead of being assembled.
pub fn chunk_aad(transfer_id: &str, index: usize, total: usize) -> String {
    format!("{NOSTR_FILE_AAD_PREFIX}:{transfer_id}:{index}:{total}")
}

/// Payload chunk -> event content.
pub fn encode_chunk_content(
    key: &[u8; AES_KEY_LEN],
    chunk: &[u8],
    aad: &str,
) -> Result<String> {
    Ok(super::z85::encode(&aes::encrypt_with_aad(
        key,
        chunk,
        aad.as_bytes(),
    )?))
}

/// Event content -> payload chunk. Fails on tampering (the GCM tag), on the
/// wrong AAD, and on a chunk larger than the manifest's own chunk size.
pub fn decode_chunk_content(
    key: &[u8; AES_KEY_LEN],
    content: &str,
    aad: &str,
    max_size: usize,
) -> Result<Vec<u8>> {
    if content.len() > encoded_len_bound(max_size) {
        bail!("chunk content is longer than a chunk could encode to");
    }
    let chunk = aes::decrypt_with_aad(key, &super::z85::decode(content)?, aad.as_bytes())?;
    if chunk.len() > max_size {
        bail!("chunk exceeds the chunk size");
    }
    Ok(chunk)
}

/// The most Z85 can make of a sealed chunk of `max_size` bytes: the nonce and
/// the tag on top of it, then five characters for every four bytes. Checked
/// before decoding so a relay cannot make this process allocate by answering
/// with something enormous.
fn encoded_len_bound(max_size: usize) -> usize {
    (max_size + aes::NONCE_LEN + aes::TAG_LEN).div_ceil(4) * 5
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Assemble downloaded chunks back into the payload.
pub fn assemble_chunks(chunks: &[Option<Vec<u8>>], payload_size: u64) -> Result<Vec<u8>> {
    let payload_size = usize::try_from(payload_size).context("payload size out of range")?;
    let mut payload = Vec::with_capacity(payload_size);
    for (index, chunk) in chunks.iter().enumerate() {
        let chunk = chunk
            .as_ref()
            .with_context(|| format!("piece {} of {} is missing", index + 1, chunks.len()))?;
        if payload.len() + chunk.len() > payload_size {
            bail!("the assembled pieces are larger than the manifest said");
        }
        payload.extend_from_slice(chunk);
    }
    if payload.len() != payload_size {
        bail!("the assembled pieces are not the size the manifest said");
    }
    Ok(payload)
}

/// How many chunks a payload of this size becomes.
pub fn chunk_count(payload_size: usize) -> usize {
    payload_size.div_ceil(NOSTR_FILE_CHUNK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSFER_ID: &str = "c05587dba544d9543610d42f7b7b640d";

    #[test]
    fn a_chunk_round_trips_under_its_own_additional_data() {
        let key = [3u8; AES_KEY_LEN];
        let chunk = vec![7u8; 4096];
        let aad = chunk_aad(TRANSFER_ID, 2, 9);
        let content = encode_chunk_content(&key, &chunk, &aad).unwrap();
        assert_eq!(
            decode_chunk_content(&key, &content, &aad, NOSTR_FILE_CHUNK_SIZE).unwrap(),
            chunk
        );
    }

    /// The AAD is what makes a chunk's position part of what was sealed: a
    /// relay that serves piece 3 in answer to a query for piece 2 has to fail
    /// the tag rather than be assembled in the wrong place.
    #[test]
    fn a_chunk_does_not_open_at_another_position_or_in_another_transfer() {
        let key = [3u8; AES_KEY_LEN];
        let content = encode_chunk_content(&key, b"payload", &chunk_aad(TRANSFER_ID, 2, 9)).unwrap();
        for aad in [
            chunk_aad(TRANSFER_ID, 3, 9),
            chunk_aad(TRANSFER_ID, 2, 10),
            chunk_aad(&"a".repeat(32), 2, 9),
        ] {
            assert!(decode_chunk_content(&key, &content, &aad, NOSTR_FILE_CHUNK_SIZE).is_err());
        }
    }

    /// A relay is not trusted for the size of what it serves: content that
    /// would decode past the manifest's chunk size is refused before it is
    /// decoded at all.
    #[test]
    fn content_too_long_to_be_a_chunk_is_refused_before_it_is_decoded() {
        let key = [3u8; AES_KEY_LEN];
        let aad = chunk_aad(TRANSFER_ID, 0, 1);
        let content = "0".repeat(encoded_len_bound(1024) + 5);
        assert!(decode_chunk_content(&key, &content, &aad, 1024).is_err());
    }

    #[test]
    fn a_payload_deflates_and_comes_back_exactly() {
        let data = b"the same bytes, over and over, ".repeat(500);
        let payload = compress_payload(data.clone(), PayloadCompression::Deflate).unwrap();
        assert!(payload.len() < data.len());
        assert_eq!(
            decompress_payload(&payload, PayloadCompression::Deflate, data.len() as u64).unwrap(),
            data
        );
    }

    /// The manifest's `fileSize` is the bound, so a payload that inflates to
    /// anything else is refused rather than truncated or ballooned.
    #[test]
    fn a_payload_that_is_not_the_promised_size_is_refused() {
        let data = vec![1u8; 2048];
        let payload = compress_payload(data.clone(), PayloadCompression::Deflate).unwrap();
        assert!(decompress_payload(&payload, PayloadCompression::Deflate, 2047).is_err());
        assert!(decompress_payload(&payload, PayloadCompression::Deflate, 2049).is_err());
        assert!(decompress_payload(&data, PayloadCompression::None, 2047).is_err());
    }

    #[test]
    fn assembly_refuses_anything_but_the_promised_pieces() {
        let chunks = vec![Some(vec![1u8; 4]), Some(vec![2u8; 4])];
        assert_eq!(assemble_chunks(&chunks, 8).unwrap().len(), 8);
        assert!(assemble_chunks(&chunks, 9).is_err());
        assert!(assemble_chunks(&chunks, 7).is_err());
        assert!(assemble_chunks(&[Some(vec![1u8; 4]), None], 8).is_err());
    }
}
