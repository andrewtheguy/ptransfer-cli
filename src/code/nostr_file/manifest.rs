//! What is being relayed: the first control message the sender publishes, and
//! everything the receiver needs to fetch and verify the pieces.
//!
//! It never appears in a code and relays only ever see it sealed. The transfer
//! id and the control relays are session-level — the id is derived from the
//! exchange's ECDH secret, the relays are the ones the offer named — so
//! neither is repeated here, and chunk `d` tags are derived from the id and
//! the index, so there are no per-chunk pointers either. Integrity comes from
//! the per-chunk GCM tags plus the whole-file hash; authenticity from the
//! Nostr signatures under `pubkey`.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use super::codec::PayloadCompression;
use super::{
    CLOCK_SKEW_TOLERANCE_SEC, MANIFEST_VERSION, NOSTR_FILE_EXPIRATION_SEC, RELAY_MAX_BYTES,
};

/// Codec version: whole-payload deflate, then AES-256-GCM and Z85 per chunk.
const CODEC_VERSION: u8 = 2;
/// The chunk sizes a manifest may name. The receiver allocates against this,
/// and the upper bound is what a relay's event-content ceiling allows.
const MIN_CHUNK_SIZE: u64 = 1024;
const MAX_CHUNK_SIZE: u64 = 65_408;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NostrFileManifest {
    pub v: u8,
    pub file_name: String,
    pub file_size: u64,
    pub mime_type: String,
    /// base64 of the SHA-256 of the plaintext, verified after assembly.
    pub file_hash: String,
    /// 64 hex characters: the ephemeral Nostr identity every chunk of this
    /// transfer is signed by, and the only author the receiver accepts.
    pub pubkey: String,
    pub compression: PayloadCompression,
    /// The byte count actually chunked onto relays: the deflate output, or the
    /// file size when nothing was compressed.
    pub payload_size: u64,
    pub chunk_size: u64,
    pub total_chunks: u64,
    pub enc: u8,
    /// unix seconds.
    pub created_at: u64,
    /// unix seconds; `created_at + NOSTR_FILE_EXPIRATION_SEC`.
    pub expires_at: u64,
}

impl NostrFileManifest {
    /// Everything a manifest has to say about itself before a single relay is
    /// asked for a piece.
    ///
    /// The receiver sizes its whole state from these fields — the chunk array,
    /// the assembly buffer, the inflate bound — so they are checked against
    /// each other here rather than trusted one at a time as they are used.
    pub fn validate(&self) -> Result<()> {
        if self.v != MANIFEST_VERSION {
            bail!("the sender's manifest is version {}, not {MANIFEST_VERSION}", self.v);
        }
        if self.enc != CODEC_VERSION {
            bail!("the sender's manifest names a codec this build does not have");
        }
        if self.file_name.is_empty() {
            bail!("the manifest names no file");
        }
        if self.file_size == 0 || self.file_size > RELAY_MAX_BYTES {
            bail!("the manifest describes a file the relay fallback cannot carry");
        }
        let bound = match self.compression {
            // An already-compressed payload is chunked exactly as it is.
            PayloadCompression::None => self.file_size,
            // Deflate can grow input it cannot compress, but never past raw
            // DEFLATE's own worst case of five bytes of stored-block framing
            // per 64 KiB, plus slack.
            PayloadCompression::Deflate => {
                self.file_size + self.file_size.div_ceil(65_535) * 5 + 64
            }
        };
        if self.payload_size == 0
            || self.payload_size > bound
            || (self.compression == PayloadCompression::None && self.payload_size != self.file_size)
        {
            bail!("the manifest's payload size does not match the file it describes");
        }
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size) {
            bail!("the manifest names a chunk size no relay would carry");
        }
        if self.total_chunks != self.payload_size.div_ceil(self.chunk_size) {
            bail!("the manifest's piece count does not match its payload size");
        }
        if !is_base64_sha256(&self.file_hash) {
            bail!("the manifest's file hash is malformed");
        }
        if self.pubkey.len() != 64 || !self.pubkey.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("the manifest names no usable sender identity");
        }
        // Checked rather than added: `created_at` is a number a peer chose,
        // and one near the end of the range would overflow the sum — which is
        // a panic in a debug build and a wrapped comparison in a release one.
        // A window that cannot even be computed is not this mode's window.
        if self.created_at.checked_add(NOSTR_FILE_EXPIRATION_SEC) != Some(self.expires_at) {
            bail!("the manifest's window is not the one this mode gives a transfer");
        }
        Ok(())
    }

    /// Refuse a manifest whose window is over, or has not begun on a clock
    /// this far out. Relay copies live an hour; a manifest outside that is
    /// pointing at pieces that are already gone.
    pub fn check_window(&self, now: u64) -> Result<()> {
        if now > self.expires_at.saturating_add(CLOCK_SKEW_TOLERANCE_SEC) {
            bail!(
                "This transfer has expired — relay copies are only kept for an hour. \
                 Ask the sender to start a new one."
            );
        }
        if self.created_at > now.saturating_add(CLOCK_SKEW_TOLERANCE_SEC) {
            bail!(
                "The sender's transfer is dated in the future — check that this device's \
                 clock is right."
            );
        }
        Ok(())
    }

    pub fn total_chunks_usize(&self) -> Result<usize> {
        usize::try_from(self.total_chunks).map_err(|_| anyhow::anyhow!("piece count out of range"))
    }
}

/// base64 of exactly 32 bytes: 43 characters and one `=`.
fn is_base64_sha256(text: &str) -> bool {
    text.len() == 44
        && text.ends_with('=')
        && text[..43]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> NostrFileManifest {
        NostrFileManifest {
            v: MANIFEST_VERSION,
            file_name: "report.pdf".to_string(),
            file_size: 100_000,
            mime_type: "application/pdf".to_string(),
            file_hash: "A".repeat(43) + "=",
            pubkey: "a".repeat(64),
            compression: PayloadCompression::Deflate,
            payload_size: 90_000,
            chunk_size: super::super::NOSTR_FILE_CHUNK_SIZE as u64,
            total_chunks: 2,
            enc: CODEC_VERSION,
            created_at: 1_700_000_000,
            expires_at: 1_700_000_000 + NOSTR_FILE_EXPIRATION_SEC,
        }
    }

    #[test]
    fn a_manifest_the_sender_would_build_is_accepted() {
        manifest().validate().unwrap();
    }

    /// The receiver allocates from these fields, so every one of them that
    /// could make it allocate — or assemble — something other than the file
    /// described has to be refused here.
    #[test]
    fn a_manifest_that_does_not_describe_itself_is_refused() {
        type Mutation = fn(&mut NostrFileManifest);
        let cases: [(&str, Mutation); 10] = [
            ("version", |m| m.v = 6),
            ("codec", |m| m.enc = 1),
            ("no name", |m| m.file_name.clear()),
            ("over the cap", |m| m.file_size = RELAY_MAX_BYTES + 1),
            ("payload larger than deflate's worst case", |m| {
                m.payload_size = m.file_size * 2
            }),
            ("identity payload of another size", |m| {
                m.compression = PayloadCompression::None;
                m.payload_size = m.file_size - 1;
            }),
            ("piece count", |m| m.total_chunks = 3),
            ("hash", |m| m.file_hash = "not base64".to_string()),
            ("window", |m| m.expires_at = m.created_at + 1),
            ("a window whose end cannot be computed", |m| {
                m.created_at = u64::MAX;
                m.expires_at = u64::MAX;
            }),
        ];
        for (name, mutate) in cases {
            let mut subject = manifest();
            mutate(&mut subject);
            assert!(subject.validate().is_err(), "{name} should have been refused");
        }
    }

    /// The chunk count is what the receiver's array is sized from, and it is
    /// checked against the payload size rather than believed.
    #[test]
    fn the_piece_count_has_to_follow_from_the_payload_size() {
        let mut subject = manifest();
        subject.compression = PayloadCompression::None;
        subject.payload_size = subject.file_size;
        subject.total_chunks = subject.file_size.div_ceil(subject.chunk_size);
        subject.validate().unwrap();
    }

    #[test]
    fn a_window_that_is_over_or_impossibly_early_is_refused() {
        let subject = manifest();
        subject.check_window(subject.created_at).unwrap();
        assert!(subject.check_window(subject.expires_at + CLOCK_SKEW_TOLERANCE_SEC + 1).is_err());
        assert!(subject.check_window(subject.created_at - CLOCK_SKEW_TOLERANCE_SEC - 1).is_err());
    }

    /// `check_window` is public and takes both ends from the manifest, so a
    /// clock comparison against a peer's numbers must not be able to overflow.
    #[test]
    fn a_window_at_the_end_of_the_range_compares_rather_than_overflows() {
        let mut subject = manifest();
        subject.created_at = u64::MAX;
        subject.expires_at = u64::MAX;
        subject.check_window(u64::MAX).unwrap();
        assert!(subject.check_window(0).is_err());
    }
}
