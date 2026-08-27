//! Minimal echo service over a Tor v3 onion service.
//!
//! This is the proof of concept the transport was built against: instance A
//! runs [`serve`], which prints an ephemeral `.onion` address; instance B runs
//! [`connect`] with that address and a line of text, and gets the same text
//! back over the rendezvous circuit. Nothing here is part of the file transfer
//! — see [`super::transfer`] for that — it exists to prove the onion service
//! comes up, publishes, and carries bytes both ways.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt as _, AsyncWriteExt, BufReader};
use arti_client::DataStream;

use super::client::EphemeralTorClient;
use super::service::OnionListener;
use super::{is_disconnect, shutdown_signal, split_address};

/// Keystore nickname for the echo service.
const NICKNAME: &str = "ptransfer-poc";

/// Total bytes either side will read from one connection. A cap keeps a peer
/// from growing our buffers without bound; anything past it reads as EOF.
const MAX_CONNECTION_BYTES: u64 = 64 * 1024;

/// Run the echo service until the process is interrupted.
///
/// Prints the `.onion` address to stdout as soon as it is known, then a
/// readiness line once the descriptor is published; progress goes to the log.
pub async fn serve(port: u16) -> Result<()> {
    let tor = EphemeralTorClient::bootstrap().await?;
    let mut listener = OnionListener::launch(&tor, NICKNAME)?;

    println!("{}:{port}", listener.onion());
    log::info!(
        "publishing descriptor for {}; this usually takes under a minute",
        listener.onion()
    );
    listener.wait_until_published().await?;
    println!("ready");

    loop {
        let stream = tokio::select! {
            // A signal is how this command is meant to be stopped, so unwind
            // normally: the throwaway storage is only removed by its
            // destructor, which a signal-killed process never runs.
            result = shutdown_signal() => {
                result.context("failed to listen for a shutdown signal")?;
                log::info!("shutting down and removing the Tor client state");
                return Ok(());
            }
            accepted = listener.accept(port) => match accepted? {
                Some(stream) => stream,
                None => bail!("the onion service stopped accepting requests"),
            },
        };

        tokio::spawn(async move {
            if let Err(e) = handle_stream(stream).await {
                log::warn!("echo connection failed: {e:#}");
            }
        });
    }
}

/// Answer one accepted stream, echoing every line back to the client.
async fn handle_stream(stream: DataStream) -> Result<()> {
    log::info!("echo connection open");

    let (reader, mut writer) = stream.split();
    let mut lines = BufReader::new(reader.take(MAX_CONNECTION_BYTES)).lines();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => break,
            // The client hanging up is how a connection normally ends here,
            // and Tor reports it as an END cell rather than a clean EOF.
            Err(e) if is_disconnect(&e) => {
                log::debug!("client disconnected: {e}");
                break;
            }
            Err(e) => return Err(e).context("failed to read a line"),
        };

        log::info!("echoing {} byte(s)", line.len());
        writer
            .write_all(format!("{line}\n").as_bytes())
            .await
            .context("failed to write the echo")?;
        writer.flush().await.context("failed to flush the echo")?;
    }

    // Sends an END with reason DONE, so the client sees a clean close.
    let _ = writer.shutdown().await;
    log::info!("echo connection closed");
    Ok(())
}

/// Connect to `address`, send `message` as one line, and return the echo.
pub async fn connect(address: &str, port: u16, message: &str) -> Result<String> {
    if message.contains('\n') {
        bail!("the message must be a single line");
    }

    // `serve` prints `<address>:<port>`, so accept that verbatim. Validate it
    // before bootstrapping, which otherwise spends tens of seconds fetching a
    // directory only to reject the address afterwards.
    let (host, port) = split_address(address, port)?;
    let tor = EphemeralTorClient::bootstrap().await?;

    log::info!("connecting to {host}:{port}");
    let stream = tor
        .client()
        .connect((host.as_str(), port))
        .await
        .with_context(|| format!("failed to connect to {host}:{port}"))?;

    let (reader, mut writer) = stream.split();
    writer
        .write_all(format!("{message}\n").as_bytes())
        .await
        .context("failed to send the message")?;
    writer.flush().await.context("failed to flush the message")?;

    let mut reply = String::new();
    match BufReader::new(reader.take(MAX_CONNECTION_BYTES))
        .read_line(&mut reply)
        .await
    {
        // Nothing read at all: the service hung up before echoing. An empty
        // echo is not this case — it arrives as the one byte `\n`.
        Ok(0) => bail!("the service closed the stream without echoing anything"),
        Ok(_) => {}
        // A partial line is discarded by `read_line`, so this is the same
        // truncation as above, just reported as an END cell instead of an EOF.
        Err(e) if is_disconnect(&e) => {
            log::debug!("service disconnected: {e}");
            bail!("the service closed the stream without echoing a full line");
        }
        Err(e) => return Err(e).context("failed to read the echo"),
    }

    // Sends an END with reason DONE rather than letting the drop look abrupt.
    let _ = writer.shutdown().await;

    Ok(reply.trim_end_matches('\n').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tor_hsservice::HsNickname;

    #[test]
    fn the_nickname_is_a_valid_slug() {
        HsNickname::new(NICKNAME.to_owned()).unwrap();
    }
}
