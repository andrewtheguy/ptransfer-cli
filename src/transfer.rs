//! Message-oriented file transfer over a WebRTC data channel, matching
//! pTransfer's transfer choreography:
//!
//! - Sender: consume a lazy source in 128 KiB plaintext chunks, send each as
//!   an encrypted binary message (index 0..N-1), then send the text message
//!   `DONE:N:B` with the final chunk and byte counts and await `ACK`.
//! - Receiver: exact-size files are written by chunk offset; streamed ZIPs
//!   whose final size was unknown during signaling are validated in reliable
//!   wire order and appended. `DONE:N:B` seals both forms before `ACK`.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::archive::SendSource;
use crate::crypto::chunk::{
    ENCRYPTION_CHUNK_SIZE, MAX_MESSAGE_SIZE, NONCE_LEN, TAG_LEN, decrypt_chunk, encrypt_chunk,
    parse_chunk_message,
};
use crate::ui::{self, Direction};
use crate::webrtc::common::DcMessenger;

/// How long the sender waits for the receiver's `ACK` after `DONE`.
const ACK_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle/stall window for active P2P transfer activity.
const STALL_TIMEOUT: Duration = Duration::from_secs(60);
/// SCTP send-buffer high-water mark for backpressure (matches web's 1 MiB).
const MAX_BUFFERED: usize = 1024 * 1024;
/// The chunk index is a 2-byte big-endian field, so valid totals are 0..=65536.
const MAX_CHUNKS: u64 = 0x10000;

/// Number of 128 KiB chunks needed for `total_bytes`.
fn chunk_count(total_bytes: u64) -> u64 {
    total_bytes.div_ceil(ENCRYPTION_CHUNK_SIZE as u64)
}

/// Plaintext length of chunk `index` given the total size.
fn plaintext_len(index: u64, total_bytes: u64) -> usize {
    let start = index * ENCRYPTION_CHUNK_SIZE as u64;
    (total_bytes - start).min(ENCRYPTION_CHUNK_SIZE as u64) as usize
}

/// Consume `source`, encrypt it chunk by chunk, and send it over `messenger`.
/// ZIP generation begins only when the source is opened here.
pub async fn run_sender(
    messenger: &mut DcMessenger,
    key: &[u8; 32],
    source: &SendSource,
) -> Result<()> {
    let exact_size = source.file_size;
    let progress_total = source.advertised_size();
    let mut stream = source.open().await?;
    let mut chunks_sent = 0u64;
    let mut sent = 0u64;

    while let Some(chunk) = stream.next_chunk().await? {
        if chunk.is_empty() || chunk.len() > ENCRYPTION_CHUNK_SIZE {
            bail!("transfer source produced an invalid chunk size");
        }
        if chunks_sent >= MAX_CHUNKS {
            bail!("generated payload exceeds the transfer chunk-index range");
        }

        let next_sent = sent
            .checked_add(chunk.len() as u64)
            .context("generated payload size exceeds the supported range")?;
        if next_sent > MAX_MESSAGE_SIZE {
            bail!("Generated payload exceeds the transfer size limit");
        }
        if let Some(expected) = exact_size
            && next_sent > expected
        {
            bail!(
                "Transfer source size changed: expected {expected} bytes, got more than {expected}"
            );
        }

        let index = chunks_sent as u16;
        let encrypted = encrypt_chunk(key, &chunk, index)?;
        match tokio::time::timeout(
            STALL_TIMEOUT,
            send_binary_with_backpressure(messenger, Bytes::from(encrypted)),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => bail!(
                "Transfer stalled: receiver stopped accepting data within {}s",
                STALL_TIMEOUT.as_secs()
            ),
        }

        sent = next_sent;
        chunks_sent += 1;
        ui::progress(Direction::Send, sent, progress_total);
    }

    if let Some(expected) = exact_size
        && sent != expected
    {
        bail!("Transfer source size changed: expected {expected} bytes, got {sent}");
    }

    // Replace an estimate with the authenticated final byte count at EOF.
    ui::progress(Direction::Send, sent, sent);
    ui::progress_end();
    messenger
        .send_text(format!("DONE:{chunks_sent}:{sent}"))
        .await?;
    ui::status("Waiting for receiver acknowledgment...");

    wait_for_ack(messenger).await
}

async fn send_binary_with_backpressure(messenger: &DcMessenger, data: Bytes) -> Result<()> {
    while messenger.buffered_amount() > MAX_BUFFERED {
        if messenger.is_closed() {
            bail!("data channel closed during transfer");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    messenger.send_binary(data).await
}

async fn wait_for_ack(messenger: &mut DcMessenger) -> Result<()> {
    let recv_ack = async {
        loop {
            match messenger.recv().await {
                Some(msg) if msg.is_string => {
                    if msg.data.as_ref() == b"ACK" {
                        return Ok(());
                    }
                    // Ignore any other control strings.
                }
                Some(_) => {} // Ignore stray binary messages.
                None => bail!("data channel closed before acknowledgment"),
            }
        }
    };

    tokio::time::timeout(ACK_TIMEOUT, recv_ack)
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for receiver acknowledgment"))?
}

/// Receive into `dest`, decrypting with `key`.
///
/// `total_bytes` is `Some` for an exact-size direct file and `None` for a ZIP
/// generated during transfer. `estimated_bytes` is only a progress hint in
/// the latter case. Writes go to `<dest>.part` and are atomically renamed on
/// success.
pub async fn run_receiver(
    messenger: &mut DcMessenger,
    key: &[u8; 32],
    dest: &Path,
    total_bytes: Option<u64>,
    estimated_bytes: u64,
) -> Result<()> {
    let expected_chunks = total_bytes.map(chunk_count);
    if let Some(expected) = expected_chunks
        && expected > MAX_CHUNKS
    {
        bail!("transfer size exceeds the supported chunk-index range");
    }

    let part_path = dest.with_extension(match dest.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.part"),
        None => "part".to_string(),
    });
    let mut out = File::create(&part_path)
        .await
        .with_context(|| format!("Failed to create {}", part_path.display()))?;
    if let Some(total_bytes) = total_bytes {
        out.set_len(total_bytes).await?;
    }

    let mut received = expected_chunks.map(|count| vec![false; count as usize]);
    let mut received_count = 0u64;
    let mut received_bytes = 0u64;
    let mut previous_streamed_chunk_len = None;
    let mut done = None;
    let progress_total = total_bytes.unwrap_or(estimated_bytes);

    let result = async {
        loop {
            let msg = match tokio::time::timeout(STALL_TIMEOUT, messenger.recv()).await {
                Ok(Some(msg)) => msg,
                Ok(None) => break,
                Err(_) => bail!(
                    "Transfer stalled: no data received within {}s",
                    STALL_TIMEOUT.as_secs()
                ),
            };

            if msg.is_string {
                let text = String::from_utf8_lossy(&msg.data);
                let (final_chunks, final_bytes) =
                    parse_done(&text).with_context(|| format!("invalid DONE message: {text:?}"))?;
                if final_chunks != received_count {
                    bail!(
                        "sender reported {final_chunks} chunks after {received_count} were received"
                    );
                }
                if let Some(expected) = expected_chunks
                    && final_chunks != expected
                {
                    bail!("sender reported {final_chunks} chunks, expected {expected}");
                }
                if let Some(expected) = total_bytes
                    && final_bytes != expected
                {
                    bail!("sender reported {final_bytes} bytes, expected {expected}");
                }
                if final_bytes != received_bytes {
                    bail!(
                        "sender reported {final_bytes} bytes after {received_bytes} were received"
                    );
                }
                done = Some((final_chunks, final_bytes));
                ui::progress(Direction::Receive, final_bytes, final_bytes);
                break;
            }

            // Binary message: one encrypted chunk.
            let (index, encrypted) = parse_chunk_message(&msg.data)?;
            let index_u64 = index as u64;
            let expect_plain = if let Some(expected_chunks) = expected_chunks {
                if index_u64 >= expected_chunks {
                    bail!("chunk index {index} out of range (expected < {expected_chunks})");
                }
                let received = received.as_mut().context("missing exact-size index set")?;
                if received[index as usize] {
                    bail!("duplicate chunk index {index}");
                }
                plaintext_len(
                    index_u64,
                    total_bytes.context("missing exact transfer size")?,
                )
            } else {
                // Unknown-size transfers append, so require the reliable data
                // channel's default ordering and full chunks before the last.
                if index_u64 != received_count {
                    bail!("unexpected streamed chunk index {index}");
                }
                if let Some(previous) = previous_streamed_chunk_len
                    && previous != ENCRYPTION_CHUNK_SIZE
                {
                    bail!("only the final streamed chunk may be short");
                }
                let length = encrypted
                    .len()
                    .checked_sub(NONCE_LEN + TAG_LEN)
                    .context("streamed chunk is shorter than its encryption overhead")?;
                if length == 0 || length > ENCRYPTION_CHUNK_SIZE {
                    bail!("invalid streamed chunk {index} length");
                }
                previous_streamed_chunk_len = Some(length);
                length
            };

            let expect_encrypted = expect_plain + NONCE_LEN + TAG_LEN;
            if encrypted.len() != expect_encrypted {
                bail!(
                    "chunk {index}: expected {expect_encrypted} encrypted bytes, got {}",
                    encrypted.len()
                );
            }
            let next_received_bytes = received_bytes
                .checked_add(expect_plain as u64)
                .context("transfer size exceeds the supported range")?;
            if next_received_bytes > MAX_MESSAGE_SIZE {
                bail!("Transfer exceeds the supported size limit");
            }

            let plaintext = decrypt_chunk(key, encrypted, index)?;
            if plaintext.len() != expect_plain {
                bail!(
                    "chunk {index}: expected {expect_plain} plaintext bytes, got {}",
                    plaintext.len()
                );
            }

            if total_bytes.is_some() {
                let offset = index_u64 * ENCRYPTION_CHUNK_SIZE as u64;
                out.seek(std::io::SeekFrom::Start(offset)).await?;
                received.as_mut().context("missing exact-size index set")?[index as usize] = true;
            }
            out.write_all(&plaintext).await?;

            received_count += 1;
            received_bytes = next_received_bytes;
            ui::progress(Direction::Receive, received_bytes, progress_total);
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    ui::progress_end();

    // Clean up the partial file on any failure path.
    let cleanup = || {
        let _ = std::fs::remove_file(&part_path);
    };

    if let Err(error) = result {
        drop(out);
        cleanup();
        return Err(error);
    }

    let Some((final_chunks, final_bytes)) = done else {
        drop(out);
        cleanup();
        bail!("data channel closed before transfer completed");
    };
    if received_count != final_chunks || received_bytes != final_bytes {
        drop(out);
        cleanup();
        bail!(
            "incomplete transfer: got {received_count}/{final_chunks} chunks, \
             {received_bytes}/{final_bytes} bytes"
        );
    }

    out.flush().await?;
    out.sync_all().await?;
    drop(out);

    tokio::fs::rename(&part_path, dest)
        .await
        .with_context(|| format!("Failed to move into place: {}", dest.display()))?;

    // Only acknowledge after the file is fully authenticated and persisted.
    messenger.send_text("ACK").await?;
    Ok(())
}

fn parse_done(message: &str) -> Result<(u64, u64)> {
    let values = message
        .strip_prefix("DONE:")
        .context("missing DONE prefix")?;
    let (chunks, bytes) = values.split_once(':').context("missing final byte count")?;
    if chunks.is_empty()
        || bytes.is_empty()
        || !chunks.bytes().all(|byte| byte.is_ascii_digit())
        || !bytes.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("DONE values must contain digits only");
    }
    let chunks: u64 = chunks.parse().context("chunk count out of range")?;
    let bytes: u64 = bytes.parse().context("byte count out of range")?;
    if chunks > MAX_CHUNKS || bytes > MAX_MESSAGE_SIZE {
        bail!("DONE values exceed the supported transfer limits");
    }
    Ok((chunks, bytes))
}

#[cfg(test)]
mod tests {
    use super::parse_done;

    #[test]
    fn done_accepts_final_chunk_and_byte_counts() {
        assert_eq!(parse_done("DONE:0:0").unwrap(), (0, 0));
        assert_eq!(parse_done("DONE:42:123456").unwrap(), (42, 123456));
    }

    #[test]
    fn done_rejects_legacy_or_malformed_values() {
        assert!(parse_done("DONE:42").is_err());
        assert!(parse_done("DONE:42:1:2").is_err());
        assert!(parse_done("DONE::42").is_err());
        assert!(parse_done("DONE:42: 1").is_err());
        assert!(parse_done("DONE:42x:1").is_err());
        assert!(parse_done("ACK").is_err());
    }
}
