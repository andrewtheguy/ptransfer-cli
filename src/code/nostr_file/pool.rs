//! One relay pool for the whole fallback: sockets opened on demand, addressed
//! one relay at a time.
//!
//! Everything this mode does is per-relay. A chunk is published to *the* relay
//! its ring position names and fetched back from that one; a health probe is a
//! write and a read against a single relay, and its whole point is that the
//! answer came from there. So this wraps `nostr-sdk`'s client rather than
//! using its pool-wide operations, and every call names its relay.
//!
//! Sockets are dropped as soon as a relay has no further job — a failed probe,
//! a candidate the ring did not need — because with reconnection enabled a
//! lingering dead socket retries for the rest of the transfer.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nostr_sdk::prelude::*;
use tokio::sync::Mutex;

/// How long a relay has to open its socket before an operation on it is
/// declared failed. A relay this slow to answer is not one to place a chunk
/// on.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// How many notifications the pool keeps behind it.
///
/// The pool's broadcast is a ring buffer: every event this mode receives sits
/// in it until newer ones push it out, and a fetched chunk is ~60 KiB. The
/// default of a few thousand slots would therefore hold a large part of the
/// file in memory a second time, for no one — only the control channel listens
/// here, and it drops everything else on sight.
const NOTIFICATION_BUFFER: usize = 256;

impl Default for FilePool {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FilePool {
    client: Client,
    /// Relays a socket has already been asked for, so a publish or a query
    /// does not re-enter the connect path on every call.
    opened: Mutex<HashSet<String>>,
}

impl FilePool {
    pub fn new() -> Self {
        Self {
            // No signer: every event this mode publishes is signed with the
            // ephemeral identity its own engine minted, never with a pool-wide
            // one.
            client: Client::builder()
                .opts(ClientOptions::new().pool(
                    RelayPoolOptions::default().notification_channel_size(NOTIFICATION_BUFFER),
                ))
                .build(),
            opened: Mutex::new(HashSet::new()),
        }
    }

    /// Open a socket to one relay, or report that it would not open.
    pub async fn ensure(&self, url: &str) -> Result<()> {
        {
            let opened = self.opened.lock().await;
            if opened.contains(url) {
                return Ok(());
            }
        }
        self.client
            .add_relay(url)
            .await
            .with_context(|| format!("unusable relay URL {url}"))?;
        if let Err(error) = self.client.try_connect_relay(url, CONNECT_TIMEOUT).await {
            // Dropped rather than left registered: a relay that did not answer
            // would otherwise keep a reconnect loop running for the rest of the
            // transfer, for a socket nothing is waiting on.
            let _ = self.client.force_remove_relay(url).await;
            return Err(error).with_context(|| format!("relay {url} did not answer"));
        }
        self.opened.lock().await.insert(url.to_string());
        Ok(())
    }

    /// Publish one event to one relay, waiting for that relay's own `OK`.
    pub async fn publish(&self, url: &str, event: &Event) -> Result<()> {
        self.ensure(url).await?;
        let output = self
            .client
            .send_event_to(vec![url.to_string()], event)
            .await
            .with_context(|| format!("relay {url} refused the event"))?;
        if output.success.is_empty() {
            bail!(
                "relay {url} did not accept the event: {}",
                output
                    .failed
                    .values()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "no reason given".to_string())
            );
        }
        Ok(())
    }

    /// Ask one relay for what a filter names.
    pub async fn query(&self, url: &str, filter: Filter, timeout: Duration) -> Result<Vec<Event>> {
        self.ensure(url).await?;
        Ok(self
            .client
            .fetch_events_from(vec![url.to_string()], filter, timeout)
            .await
            .with_context(|| format!("relay {url} answered nothing usable"))?
            .into_iter()
            .collect())
    }

    /// Open sockets to as many of `urls` as will answer, and report which did.
    ///
    /// Opening is separated from asking because two operations that named the
    /// same relay and opened it themselves would race: the one whose connect
    /// failed drops the relay out of the pool, and the one that had already
    /// counted it reachable then loses its whole query to `relay not found`.
    /// Everything that asks several relays at once opens them here first.
    pub async fn open_all(&self, urls: &[String]) -> Vec<String> {
        let mut reachable = Vec::new();
        for url in urls {
            match self.ensure(url).await {
                Ok(()) => reachable.push(url.clone()),
                Err(error) => log::debug!("relay {url} is not usable: {error:#}"),
            }
        }
        reachable
    }

    /// Ask relays already opened by [`Self::open_all`] and take whatever any of
    /// them answers. Used where the relays are interchangeable sources of the
    /// same public events.
    pub async fn query_open(
        &self,
        urls: &[String],
        filter: Filter,
        timeout: Duration,
    ) -> Result<Vec<Event>> {
        if urls.is_empty() {
            bail!("no relay of the pool answered");
        }
        Ok(self
            .client
            .fetch_events_from(urls.to_vec(), filter, timeout)
            .await
            .context("the relays answered nothing usable")?
            .into_iter()
            .collect())
    }

    /// Subscribe to the given relays, live and with their stored backlog.
    ///
    /// The relays that answered come back with the subscription, so a caller
    /// that also has to query them — the control channel asks for its backlog
    /// alongside the live feed — asks the ones already open rather than
    /// opening them a second time.
    pub async fn subscribe(
        &self,
        urls: &[String],
        filter: Filter,
    ) -> Result<(SubscriptionId, Vec<String>)> {
        let reachable = self.open_all(urls).await;
        if reachable.is_empty() {
            bail!("none of the relays this transfer named could be reached");
        }
        let subscription = self
            .client
            .subscribe_to(reachable.clone(), filter, None)
            .await
            .context("could not subscribe to the control channel")?
            .val;
        Ok((subscription, reachable))
    }

    pub async fn unsubscribe(&self, id: &SubscriptionId) {
        self.client.unsubscribe(id).await;
    }

    pub fn notifications(&self) -> tokio::sync::broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    /// Drop the sockets to relays that have no further job, so no reconnect
    /// loop outlives what it was opened for.
    pub async fn close(&self, urls: &[String]) {
        let mut opened = self.opened.lock().await;
        for url in urls {
            opened.remove(url);
            let _ = self.client.force_remove_relay(url.as_str()).await;
        }
    }

    pub async fn shutdown(&self) {
        self.client.shutdown().await;
        self.opened.lock().await.clear();
    }
}
