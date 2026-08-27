//! Message framing over a Tor stream.
//!
//! A Tor stream is a byte stream, and the transfer choreography
//! ([`crate::transfer`]) needs discrete messages that keep the binary/text
//! distinction a WebRTC data channel gives for free. Each message travels as
//!
//! ```text
//! [1-byte kind][4-byte big-endian payload length][payload]
//! ```
//!
//! with kind `0` for a binary content chunk and `1` for a control string. The
//! length is capped at one full encrypted chunk, so a peer cannot make this
//! side allocate more than the transfer itself would.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::chunk::{ENCRYPTION_CHUNK_SIZE, OVERHEAD_PER_CHUNK};
use crate::transfer::{Messenger, TransferMessage};

use super::is_disconnect;

const HEADER_LEN: usize = 5;
const KIND_BINARY: u8 = 0;
const KIND_TEXT: u8 = 1;

/// Largest payload one frame may carry: exactly one encrypted content chunk.
/// Handshake frames are orders of magnitude smaller.
pub const MAX_FRAME_BYTES: usize = ENCRYPTION_CHUNK_SIZE + OVERHEAD_PER_CHUNK;

/// How long [`TorMessenger::wait_for_close`] waits for the peer to hang up.
/// Only a peer that has stopped answering ever reaches it.
const LINGER_TIMEOUT: Duration = Duration::from_secs(30);

/// Framed message transport over one Tor stream.
///
/// Sends and receives are `&mut self` because the protocol on top is strictly
/// turn-taking — handshake ping-pong, then chunks out and `ACK` back — so there
/// is never a read and a write in flight at once.
pub struct TorMessenger<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> TorMessenger<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Send one control string as a text frame.
    pub async fn send_string(&mut self, text: &str) -> Result<()> {
        self.send_frame(KIND_TEXT, text.as_bytes()).await
    }

    /// Read the next frame, requiring it to be a text frame.
    ///
    /// The handshake speaks only text frames, and a peer that sends anything
    /// else there is not running this protocol.
    pub async fn recv_string(&mut self) -> Result<String> {
        let Some(message) = self.recv_frame().await? else {
            bail!("the peer closed the connection during the handshake");
        };
        if !message.is_string {
            bail!("expected a handshake message, got a binary frame");
        }
        String::from_utf8(message.data.to_vec()).context("handshake message is not valid UTF-8")
    }

    /// Close the write half, so the peer sees a clean end rather than an
    /// abrupt drop.
    pub async fn shutdown(&mut self) {
        let _ = self.stream.shutdown().await;
    }

    /// Block until the peer closes its end, which is the receipt for the last
    /// frame sent.
    ///
    /// Whoever sends the *last* message of a conversation has to call this
    /// before exiting. Arti hands bytes to the circuit from background tasks,
    /// so a process that writes its final frame and exits takes that frame with
    /// it: the stream dies before the cell is transmitted, and the peer sees a
    /// closed connection where its `ACK` should have been. The peer closes as
    /// soon as it has acted on that frame, so its close is the delivery
    /// receipt.
    ///
    /// Only an actual close is that receipt, so anything else — a read error,
    /// or a peer that goes quiet past [`LINGER_TIMEOUT`] — is an error here.
    /// It says the last frame may not have arrived, which is not the same
    /// thing as the local work having failed: the caller decides what that is
    /// worth.
    pub async fn wait_for_close(&mut self) -> Result<()> {
        let mut scratch = [0u8; 64];
        let closed = async {
            loop {
                match self.stream.read(&mut scratch).await {
                    Ok(0) => return Ok(()),
                    // Nothing should follow the last frame; drain and keep
                    // waiting rather than guess at what it meant.
                    Ok(_) => {}
                    Err(error) if is_disconnect(&error) => return Ok(()),
                    Err(error) => {
                        return Err(error).context("failed to wait for the peer to close");
                    }
                }
            }
        };

        tokio::time::timeout(LINGER_TIMEOUT, closed)
            .await
            .with_context(|| {
                format!(
                    "the peer did not close the stream within {}s",
                    LINGER_TIMEOUT.as_secs()
                )
            })?
    }

    async fn send_frame(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_FRAME_BYTES {
            bail!(
                "frame of {} bytes exceeds the {MAX_FRAME_BYTES}-byte limit",
                payload.len()
            );
        }

        // One write for header and payload together: a Tor stream pays for
        // every flush, and a 5-byte write of its own would ride its own cell.
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.push(kind);
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);

        self.stream
            .write_all(&frame)
            .await
            .context("failed to write a frame")?;
        self.stream
            .flush()
            .await
            .context("failed to flush a frame")?;
        Ok(())
    }

    /// Read one frame. `Ok(None)` is a clean end of the conversation — the peer
    /// closed *between* frames rather than in the middle of one.
    async fn recv_frame(&mut self) -> Result<Option<TransferMessage>> {
        let Some(header) = self.read_header().await? else {
            return Ok(None);
        };

        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if len > MAX_FRAME_BYTES {
            bail!("peer announced a {len}-byte frame, over the {MAX_FRAME_BYTES}-byte limit");
        }
        let is_string = match header[0] {
            KIND_BINARY => false,
            KIND_TEXT => true,
            other => bail!("unknown frame kind {other}"),
        };

        let mut payload = vec![0u8; len];
        self.stream
            .read_exact(&mut payload)
            .await
            .context("failed to read a frame payload")?;

        Ok(Some(TransferMessage {
            is_string,
            data: Bytes::from(payload),
        }))
    }

    /// Read a frame header, distinguishing a close between frames from one in
    /// the middle of a header. `read_exact` cannot tell those apart, because it
    /// reports the same error either way.
    async fn read_header(&mut self) -> Result<Option<[u8; HEADER_LEN]>> {
        let mut header = [0u8; HEADER_LEN];
        let mut filled = 0;

        while filled < HEADER_LEN {
            match self.stream.read(&mut header[filled..]).await {
                // Nothing of a frame had arrived, so the peer hung up cleanly.
                // Over Tor that is an END cell rather than an EOF, which is why
                // a disconnect error lands here too.
                Ok(0) if filled == 0 => return Ok(None),
                Err(error) if is_disconnect(&error) && filled == 0 => return Ok(None),
                Ok(0) => bail!("the peer closed the connection mid-frame"),
                Ok(read) => filled += read,
                Err(error) if is_disconnect(&error) => bail!("the peer disconnected mid-frame"),
                Err(error) => return Err(error).context("failed to read a frame header"),
            }
        }

        Ok(Some(header))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> Messenger for TorMessenger<S> {
    async fn recv(&mut self) -> Option<TransferMessage> {
        match self.recv_frame().await {
            Ok(message) => message,
            // The choreography treats a closed transport as the end of the
            // conversation and reports it in its own terms, so the reason a
            // malformed frame ended it goes to the log.
            Err(error) => {
                log::warn!("dropping the Tor stream: {error:#}");
                None
            }
        }
    }

    async fn send_binary(&mut self, data: Bytes) -> Result<()> {
        self.send_frame(KIND_BINARY, &data).await
    }

    async fn send_text(&mut self, text: String) -> Result<()> {
        self.send_frame(KIND_TEXT, text.as_bytes()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both ends of an in-memory duplex, which is all the framing needs: it
    /// only ever sees `AsyncRead + AsyncWrite`.
    fn pair() -> (
        TorMessenger<tokio::io::DuplexStream>,
        TorMessenger<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (TorMessenger::new(a), TorMessenger::new(b))
    }

    #[tokio::test]
    async fn round_trips_binary_and_text_frames() {
        let (mut a, mut b) = pair();

        a.send_binary(Bytes::from_static(b"\x00\x01chunk")).await.unwrap();
        a.send_text("DONE:1:2".to_string()).await.unwrap();

        let binary = b.recv().await.unwrap();
        assert!(!binary.is_string);
        assert_eq!(binary.data.as_ref(), b"\x00\x01chunk");

        let text = b.recv().await.unwrap();
        assert!(text.is_string);
        assert_eq!(text.data.as_ref(), b"DONE:1:2");
    }

    #[tokio::test]
    async fn a_full_size_chunk_fits_in_one_frame() {
        let (mut a, mut b) = pair();
        let chunk = Bytes::from(vec![7u8; MAX_FRAME_BYTES]);

        let send = tokio::spawn(async move { a.send_binary(chunk).await });
        let received = b.recv().await.unwrap();
        send.await.unwrap().unwrap();

        assert_eq!(received.data.len(), MAX_FRAME_BYTES);
    }

    #[tokio::test]
    async fn refuses_to_send_more_than_one_chunk_per_frame() {
        let (mut a, _b) = pair();
        let too_big = Bytes::from(vec![0u8; MAX_FRAME_BYTES + 1]);
        assert!(a.send_binary(too_big).await.is_err());
    }

    #[tokio::test]
    async fn a_close_between_frames_ends_the_conversation() {
        let (mut a, mut b) = pair();
        a.send_text("DONE:0:0".to_string()).await.unwrap();
        drop(a);

        assert!(b.recv().await.is_some());
        assert!(b.recv().await.is_none());
    }

    #[tokio::test]
    async fn an_oversized_announced_length_is_refused_before_allocating() {
        let (mut raw, other) = tokio::io::duplex(64);
        let mut framed = TorMessenger::new(other);

        let mut header = vec![KIND_BINARY];
        header.extend_from_slice(&u32::MAX.to_be_bytes());
        raw.write_all(&header).await.unwrap();

        assert!(framed.recv_frame().await.is_err());
    }

    #[tokio::test]
    async fn a_truncated_header_is_an_error_not_a_clean_end() {
        let (mut raw, other) = tokio::io::duplex(64);
        let mut framed = TorMessenger::new(other);

        raw.write_all(&[KIND_TEXT, 0, 0]).await.unwrap();
        drop(raw);

        assert!(framed.recv_frame().await.is_err());
    }

    #[tokio::test]
    async fn waiting_for_a_close_returns_when_the_peer_hangs_up() {
        let (mut a, mut b) = pair();
        a.send_text("ACK".to_string()).await.unwrap();

        let waiting = tokio::spawn(async move { a.wait_for_close().await });
        assert_eq!(b.recv().await.unwrap().data.as_ref(), b"ACK");
        drop(b);

        // The close is the receipt for `ACK`, so it is the success case.
        waiting.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_for_a_close_fails_when_the_peer_never_hangs_up() {
        // A peer holding the stream open past the linger timeout never
        // acknowledged the last frame, and saying otherwise would report a
        // delivery that may not have happened.
        let (mut a, _b) = pair();
        a.send_text("ACK".to_string()).await.unwrap();
        assert!(a.wait_for_close().await.is_err());
    }

    #[tokio::test]
    async fn the_handshake_refuses_a_binary_frame() {
        let (mut a, mut b) = pair();
        a.send_binary(Bytes::from_static(b"nope")).await.unwrap();
        assert!(b.recv_string().await.is_err());
    }
}
