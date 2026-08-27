//! Minimal echo service over a Tor v3 onion service.
//!
//! This is the proof of concept for CLI-to-CLI transport over Tor: instance A
//! runs [`serve`], which prints an ephemeral `.onion` address; instance B runs
//! [`connect`] with that address and a line of text, and gets the same text
//! back over the rendezvous circuit. Nothing here is part of the pTransfer file
//! transfer protocol yet — it exists to prove the onion service comes up,
//! publishes, and carries bytes both ways.

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt;
use safelog::DisplayRedacted as _;
use tokio::io::{AsyncBufReadExt, AsyncReadExt as _, AsyncWriteExt, BufReader};
use tor_cell::relaycell::msg::{Connected, End};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::status::State;
use tor_hsservice::{HsNickname, StreamRequest, handle_rend_requests};
use tor_proto::stream::IncomingStreamRequest;

use super::client::EphemeralTorClient;

/// Virtual port the echo service listens on. Onion services have their own port
/// space, so this collides with nothing on either machine.
pub const DEFAULT_PORT: u16 = 9735;

/// Keystore nickname for the service.
///
/// With the in-memory keystore there is only ever one service per process and
/// no key to look up again later, so the name is fixed.
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

    let svc_config = OnionServiceConfigBuilder::default()
        .nickname(HsNickname::new(NICKNAME.to_owned()).expect("nickname is a valid slug"))
        .build()
        .context("failed to build the onion service configuration")?;

    let (service, rend_requests) = tor
        .client()
        .launch_onion_service(svc_config)
        .context("failed to launch the onion service")?
        .ok_or_else(|| anyhow!("the onion service is disabled in the configuration"))?;

    let onion = service
        .onion_address()
        .ok_or_else(|| anyhow!("the onion service has no address"))?
        .display_unredacted()
        .to_string();
    println!("{onion}:{port}");
    log::info!("publishing descriptor for {onion}; this usually takes under a minute");

    let mut status_events = service.status_events();
    let mut announced = false;
    let mut stream_requests = Box::pin(handle_rend_requests(rend_requests));

    loop {
        tokio::select! {
            // A signal is how this command is meant to be stopped, so unwind
            // normally: the throwaway storage is only removed by its
            // destructor, which a signal-killed process never runs.
            result = shutdown_signal() => {
                result.context("failed to listen for a shutdown signal")?;
                log::info!("shutting down and removing the Tor client state");
                return Ok(());
            }

            Some(status) = status_events.next() => {
                match status.state() {
                    State::Running if !announced => {
                        announced = true;
                        println!("ready");
                    }
                    state => log::info!("onion service state: {state:?}"),
                }
            }

            request = stream_requests.next() => {
                let Some(request) = request else {
                    bail!("the onion service stopped accepting requests");
                };
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(request, port).await {
                        log::warn!("echo connection failed: {e:#}");
                    }
                });
            }
        }
    }
}

/// Resolve when the process is asked to stop.
#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = term.recv() => Ok(()),
    }
}

/// Resolve when the process is asked to stop.
#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

/// Answer one incoming stream, echoing every line back to the client.
async fn handle_stream(request: StreamRequest, port: u16) -> Result<()> {
    match request.request() {
        IncomingStreamRequest::Begin(begin) if begin.port() == port => {}
        other => {
            log::debug!("rejecting stream request: {other:?}");
            request
                .reject(End::new_misc())
                .await
                .context("failed to reject a stream")?;
            return Ok(());
        }
    }

    let stream = request
        .accept(Connected::new_empty())
        .await
        .context("failed to accept a stream")?;
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

/// Whether an I/O error just means the peer went away.
///
/// A Tor stream never ends with a plain EOF. The far side sends an END cell,
/// whose reason Arti maps to an `ErrorKind` — and the reason depends on how the
/// peer let go: a shut-down writer sends `DONE`, a dropped stream sends `MISC`.
/// So rather than enumerate reasons, treat any END as the end of the
/// conversation. If the stream is already torn down by the time we read, Arti
/// reports `NotConnected` instead and no END cell is involved.
fn is_disconnect(err: &std::io::Error) -> bool {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, NotConnected};

    if matches!(
        err.kind(),
        NotConnected | ConnectionReset | ConnectionAborted | BrokenPipe
    ) {
        return true;
    }

    err.get_ref()
        .and_then(|source| source.downcast_ref::<tor_proto::Error>())
        .is_some_and(|e| matches!(e, tor_proto::Error::EndReceived(_)))
}

/// Split `address` into a host and a port, falling back to `default_port`.
///
/// A port in the address wins over `default_port`, so the line `serve` prints
/// can be pasted straight into `connect`.
fn split_address(address: &str, default_port: u16) -> Result<(&str, u16)> {
    let Some((host, port)) = address.rsplit_once(':') else {
        return Ok((address, default_port));
    };

    let port = port
        .parse()
        .with_context(|| format!("invalid port in address {address:?}"))?;
    Ok((host, port))
}

/// Connect to `address`, send `message` as one line, and return the echo.
pub async fn connect(address: &str, port: u16, message: &str) -> Result<String> {
    if message.contains('\n') {
        bail!("the message must be a single line");
    }

    // `serve` prints `<address>:<port>`, so accept that verbatim.
    let (host, port) = split_address(address, port)?;
    let tor = EphemeralTorClient::bootstrap().await?;

    log::info!("connecting to {host}:{port}");
    let stream = tor
        .client()
        .connect((host, port))
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
        Ok(_) => {}
        Err(e) if is_disconnect(&e) => log::debug!("service disconnected: {e}"),
        Err(e) => return Err(e).context("failed to read the echo"),
    }

    // Sends an END with reason DONE rather than letting the drop look abrupt.
    let _ = writer.shutdown().await;

    let reply = reply.trim_end_matches('\n').to_owned();
    if reply.is_empty() {
        bail!("the service closed the stream without echoing anything");
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_address_uses_the_default_port() {
        assert_eq!(
            split_address("abc.onion", DEFAULT_PORT).unwrap(),
            ("abc.onion", DEFAULT_PORT)
        );
    }

    #[test]
    fn a_port_in_the_address_wins() {
        assert_eq!(
            split_address("abc.onion:1234", DEFAULT_PORT).unwrap(),
            ("abc.onion", 1234)
        );
    }

    #[test]
    fn a_non_numeric_port_is_an_error() {
        assert!(split_address("abc.onion:", DEFAULT_PORT).is_err());
        assert!(split_address("abc.onion:http", DEFAULT_PORT).is_err());
    }

    #[test]
    fn the_nickname_is_a_valid_slug() {
        HsNickname::new(NICKNAME.to_owned()).unwrap();
    }
}
