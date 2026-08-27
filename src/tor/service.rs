//! Publishing an ephemeral v3 onion service and accepting streams on it.
//!
//! Shared by the echo proof of concept and the file transfer: both publish a
//! throwaway address, wait for the descriptor to go up, and then answer
//! incoming streams on one virtual port.

use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{Stream, StreamExt};
use safelog::DisplayRedacted as _;
use tor_cell::relaycell::msg::{Connected, End};
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::status::State;
use tor_hsservice::{HsNickname, RunningOnionService, StreamRequest, handle_rend_requests};
use arti_client::DataStream;
use tor_proto::stream::IncomingStreamRequest;

use super::client::EphemeralTorClient;

/// A published onion service and its queue of incoming streams.
///
/// Dropping this unpublishes the service.
pub struct OnionListener {
    service: Arc<RunningOnionService>,
    onion: String,
    streams: Pin<Box<dyn Stream<Item = StreamRequest> + Send>>,
}

impl OnionListener {
    /// Publish a fresh service under `nickname`.
    ///
    /// Returns as soon as the identity key exists, which is well before the
    /// descriptor is reachable — call [`Self::wait_until_published`] for that.
    pub fn launch(tor: &EphemeralTorClient, nickname: &str) -> Result<Self> {
        let config = OnionServiceConfigBuilder::default()
            .nickname(
                HsNickname::new(nickname.to_owned())
                    .with_context(|| format!("invalid onion service nickname {nickname:?}"))?,
            )
            .build()
            .context("failed to build the onion service configuration")?;

        let (service, rend_requests) = tor
            .client()
            .launch_onion_service(config)
            .context("failed to launch the onion service")?
            .ok_or_else(|| anyhow!("the onion service is disabled in the configuration"))?;

        let onion = service
            .onion_address()
            .ok_or_else(|| anyhow!("the onion service has no address"))?
            .display_unredacted()
            .to_string();

        Ok(Self {
            service,
            onion,
            streams: Box::pin(handle_rend_requests(rend_requests)),
        })
    }

    /// The `.onion` address this service publishes.
    pub fn onion(&self) -> &str {
        &self.onion
    }

    /// Resolve once the descriptor is published and the service is reachable.
    ///
    /// This usually takes well under a minute, but there is no useful timeout
    /// to apply: a service that is slow to publish is still going to publish,
    /// and the operator can interrupt.
    pub async fn wait_until_published(&mut self) -> Result<()> {
        // A watch stream, so the current state arrives first.
        let mut events = self.service.status_events();
        while let Some(status) = events.next().await {
            match status.state() {
                State::Running => return Ok(()),
                state => log::info!("onion service state: {state:?}"),
            }
        }
        bail!("the onion service stopped reporting status")
    }

    /// Accept the next incoming stream on `port`, rejecting any other port.
    ///
    /// `Ok(None)` means the service stopped accepting requests. Cancel-safe up
    /// to the point a request has been taken off the queue: dropping this
    /// future mid-accept drops that one connection, nothing else.
    pub async fn accept(&mut self, port: u16) -> Result<Option<DataStream>> {
        loop {
            let Some(request) = self.streams.next().await else {
                return Ok(None);
            };

            match request.request() {
                IncomingStreamRequest::Begin(begin) if begin.port() == port => {}
                other => {
                    log::debug!("rejecting stream request: {other:?}");
                    // A stream we did not want is not worth the listener over.
                    // Whoever is waiting here is waiting for one specific peer,
                    // and anyone can open a stream to a published address, so
                    // failing to refuse an unwanted one must not end the wait.
                    if let Err(error) = request.reject(End::new_misc()).await {
                        log::warn!("failed to reject a stream: {error}");
                    }
                    continue;
                }
            }

            return Ok(Some(
                request
                    .accept(Connected::new_empty())
                    .await
                    .context("failed to accept a stream")?,
            ));
        }
    }
}
