//! How payload bytes travel between peers, and the receiver's inflater.
//!
//! The rule is pTransfer's `wireEncodingFor` (`src/lib/transfer-source.ts`),
//! and it is **flow-based, never content-sniffed**: a payload the multi-file
//! flow already compressed (a ZIP whose entries are deflated) travels as-is,
//! and everything else — that is, a single file — is deflated on the wire and
//! restored on receipt. Either way the final wire length is unknown during
//! signaling, which is why the advertised file size is only a progress hint and
//! the `DONE:<chunks>:<bytes>` trailer carries the authoritative count.

use anyhow::{Result, bail};
use flate2::{Decompress, FlushDecompress, Status};
use serde::{Deserialize, Serialize};

/// How payload bytes travel on the wire between peers.
///
/// Serializes as pTransfer's `contentEncoding` metadata field. The enum is
/// closed, so an unknown encoding fails deserialization — which *is* the
/// receiver-side validation the web app spells out by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WireEncoding {
    /// Raw DEFLATE (RFC 1951, no zlib or gzip wrapper), matching the browser's
    /// `CompressionStream('deflate-raw')`.
    DeflateRaw,
    /// The bytes travel unchanged.
    Identity,
}

/// What the receiver is about to be handed: the payload's name, its input
/// size, and how its bytes travel.
///
/// Delivered inside the sender's authenticated handshake payload — never in
/// the clear before the peers have a shared key — on both transports: the
/// sealed confirm of PIN Exchange, and the sealed confirm of the Tor onion
/// handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferMetadata {
    /// Always `"file"`.
    pub content_type: String,
    pub file_name: String,
    /// Input size of the payload: a progress hint, never the wire length.
    pub file_size: u64,
    /// How the payload travels; `deflate-raw` payloads are inflated by the
    /// receiver after decryption.
    pub content_encoding: WireEncoding,
    pub mime_type: String,
}

/// Grow the scratch buffer in 128 KiB steps: one wire chunk of highly
/// compressible input can inflate to far more than its own length, so a single
/// `push` may need several passes.
const INFLATE_BUF_STEP: usize = 128 * 1024;

/// Streaming raw-DEFLATE inflater with a hard cap on produced bytes.
///
/// The cap is the decompression-bomb guard, mirroring the bound pTransfer's
/// `createInflatingAppendSink` applies: a small wire payload must not be able
/// to make the receiver write an unbounded file.
pub struct Inflater {
    decoder: Decompress,
    out: Vec<u8>,
    max_output: u64,
    stream_ended: bool,
}

impl Inflater {
    pub fn new(max_output: u64) -> Self {
        Self {
            // `false` = raw deflate, no zlib header. Getting this wrong is
            // silent: the stream simply never inflates against the web app.
            decoder: Decompress::new(false),
            out: Vec::with_capacity(INFLATE_BUF_STEP),
            max_output,
            stream_ended: false,
        }
    }

    /// Inflate one decrypted wire chunk, returning the plaintext it produced.
    pub fn push(&mut self, input: &[u8]) -> Result<&[u8]> {
        self.run(input, FlushDecompress::None)
    }

    /// Flush at end of stream, returning any remaining plaintext.
    ///
    /// A stream that has not reached its end by now was truncated — something
    /// the `DONE` chunk and byte counts cannot detect on their own, because
    /// every wire byte the sender claimed to send did arrive.
    pub fn finish(&mut self) -> Result<&[u8]> {
        self.run(&[], FlushDecompress::Finish)?;
        if !self.stream_ended {
            bail!("Transfer ended in the middle of a compressed stream");
        }
        Ok(&self.out)
    }

    fn run(&mut self, input: &[u8], flush: FlushDecompress) -> Result<&[u8]> {
        self.out.clear();
        let mut consumed = 0usize;

        loop {
            if self.out.len() == self.out.capacity() {
                self.out.reserve(INFLATE_BUF_STEP);
            }

            let before_in = self.decoder.total_in();
            let before_out = self.decoder.total_out();
            let status = self
                .decoder
                .decompress_vec(&input[consumed..], &mut self.out, flush)?;
            let read = (self.decoder.total_in() - before_in) as usize;
            let produced = self.decoder.total_out() - before_out;
            consumed += read;

            if self.decoder.total_out() > self.max_output {
                bail!("Decompressed transfer exceeds the size limit");
            }

            if status == Status::StreamEnd {
                self.stream_ended = true;
                if consumed < input.len() {
                    bail!("Trailing data after the end of the compressed stream");
                }
                break;
            }

            // No progress on either side: the decoder wants more input, which
            // will only arrive in a later chunk.
            if read == 0 && produced == 0 {
                break;
            }
        }

        Ok(&self.out)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    use super::*;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn content_encoding_matches_ptransfer_spelling() {
        assert_eq!(
            serde_json::to_value(WireEncoding::DeflateRaw).unwrap(),
            serde_json::json!("deflate-raw")
        );
        assert_eq!(
            serde_json::to_value(WireEncoding::Identity).unwrap(),
            serde_json::json!("identity")
        );
        assert_eq!(
            serde_json::from_value::<WireEncoding>(serde_json::json!("deflate-raw")).unwrap(),
            WireEncoding::DeflateRaw
        );
        // An encoding neither side implements must be rejected, not guessed at.
        assert!(serde_json::from_value::<WireEncoding>(serde_json::json!("gzip")).is_err());
    }

    #[test]
    fn round_trips_a_stream_split_across_chunks() {
        let plain: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let compressed = deflate(&plain);

        let mut inflater = Inflater::new(u64::MAX);
        let mut restored = Vec::new();
        for piece in compressed.chunks(1024) {
            restored.extend_from_slice(inflater.push(piece).unwrap());
        }
        restored.extend_from_slice(inflater.finish().unwrap());

        assert_eq!(restored, plain);
    }

    #[test]
    fn round_trips_an_empty_payload() {
        let compressed = deflate(b"");
        let mut inflater = Inflater::new(u64::MAX);
        let mut restored = Vec::new();
        restored.extend_from_slice(inflater.push(&compressed).unwrap());
        restored.extend_from_slice(inflater.finish().unwrap());
        assert!(restored.is_empty());
    }

    #[test]
    fn rejects_a_truncated_stream() {
        let compressed = deflate(&vec![b'x'; 200_000]);
        let mut inflater = Inflater::new(u64::MAX);
        inflater
            .push(&compressed[..compressed.len() - 5])
            .unwrap();

        let error = inflater.finish().unwrap_err().to_string();
        assert!(error.contains("middle of a compressed stream"), "{error}");
    }

    #[test]
    fn rejects_trailing_data_after_the_stream_ends() {
        let mut compressed = deflate(b"hello");
        compressed.extend_from_slice(b"junk");

        let mut inflater = Inflater::new(u64::MAX);
        let error = inflater.push(&compressed).unwrap_err().to_string();
        assert!(error.contains("Trailing data"), "{error}");
    }

    #[test]
    fn caps_the_inflated_output() {
        // 4 MiB of zeros deflates to a few KiB: exactly the shape a malicious
        // sender would use to make a receiver write far more than it received.
        let compressed = deflate(&vec![0u8; 4 * 1024 * 1024]);
        assert!(compressed.len() < 64 * 1024);

        let mut inflater = Inflater::new(1024);
        let error = inflater.push(&compressed).unwrap_err().to_string();
        assert!(error.contains("exceeds the size limit"), "{error}");
    }
}
