//! Bootstrapping an Arti client that leaves nothing behind.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arti_client::TorClient;
use arti_client::config::{CfgPath, TorClientConfig};
use arti_client::status::BootstrapStatus;
use futures_util::StreamExt as _;
use tor_config::ExplicitOrAuto;
use tor_keymgr::config::ArtiKeystoreKind;
use tor_rtcompat::PreferredRuntime;

use crate::ui;

use super::storage::EphemeralStorage;

/// Shortest gap between two bootstrap progress lines.
///
/// Arti's status stream coalesces to the most recent value but still ticks
/// several times a second while microdescriptors download. In the TUI each
/// update replaces the line before it, so the rate costs nothing there; without
/// a sink every update is its own line on stderr, and an unthrottled bootstrap
/// would bury everything printed before it.
const REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// A bootstrapped Arti client plus the throwaway storage it is using.
///
/// The storage must outlive the client, so the two are kept together and
/// dropped together.
pub struct EphemeralTorClient {
    /// The bootstrapped client.
    client: Arc<TorClient<PreferredRuntime>>,
    /// Deleted when this struct is dropped; the client borrows nothing from it,
    /// but reads and writes the paths it hands out.
    _storage: EphemeralStorage,
}

impl EphemeralTorClient {
    /// Build a client on fresh throwaway storage and bootstrap it.
    ///
    /// This talks to the real Tor network and typically takes a few tens of
    /// seconds, because nothing is cached: the directory has to be fetched from
    /// scratch every time.
    ///
    /// That wait is the longest unexplained pause in a Tor transfer, so it is
    /// bootstrapped in two steps rather than with `create_bootstrapped`: an
    /// unbootstrapped client first, so its status stream can be read while the
    /// bootstrap it belongs to runs.
    pub async fn bootstrap() -> Result<Self> {
        let storage = EphemeralStorage::new()?;
        log::info!("Tor client state: {} (removed on exit)", storage.root().display());

        let config = ephemeral_config(&storage)?;
        let client = TorClient::builder()
            .config(config)
            .create_unbootstrapped()
            .context("failed to create the Tor client")?;

        ui::status("Bootstrapping the Tor client; this usually takes under a minute...");
        let started = Instant::now();
        bootstrap_reporting_progress(&client)
            .await
            .context("failed to bootstrap the Tor client")?;
        ui::status_timed("Bootstrapped the Tor client", started.elapsed());

        Ok(Self {
            client,
            _storage: storage,
        })
    }

    /// The underlying Arti client.
    pub fn client(&self) -> &TorClient<PreferredRuntime> {
        &self.client
    }
}

/// Bootstrap `client`, reporting Arti's own progress as it goes.
///
/// The bootstrap future is what decides the outcome; the status stream is only
/// read alongside it. If Arti stops reporting, the bootstrap is still awaited
/// to completion — losing the commentary is not a failure.
async fn bootstrap_reporting_progress(client: &TorClient<PreferredRuntime>) -> Result<()> {
    let mut bootstrapping = std::pin::pin!(client.bootstrap());
    let mut events = client.bootstrap_events();
    let mut reporter = ProgressReporter::default();

    loop {
        tokio::select! {
            result = &mut bootstrapping => return Ok(result?),
            status = events.next() => match status {
                Some(status) => reporter.report(&status),
                None => return Ok(bootstrapping.await?),
            },
        }
    }
}

/// Throttles bootstrap status lines to something a person can read.
#[derive(Default)]
struct ProgressReporter {
    last: Option<Instant>,
    /// The line most recently shown. Arti re-reports an unchanged status while
    /// it waits on a slow step, and repeating it says nothing new.
    line: String,
    /// Whether the last line said the client was stuck. A blockage appearing or
    /// clearing is news at any moment: it is the difference between "slow" and
    /// "this machine cannot reach Tor at all", which is the one thing worth
    /// interrupting a long silence for.
    blocked: bool,
}

impl ProgressReporter {
    fn report(&mut self, status: &BootstrapStatus) {
        // Arti's own wording, which names the phase it is in and counts the
        // microdescriptors it is still fetching.
        let line = format!("Tor bootstrap: {status}");
        self.emit(status.blocked().is_some(), line, Instant::now());
    }

    /// Show `line`, unless it repeats the last one or follows it too closely.
    ///
    /// Returns whether it was shown.
    fn emit(&mut self, blocked: bool, line: String, now: Instant) -> bool {
        let due = blocked != self.blocked
            || self
                .last
                .is_none_or(|last| now.duration_since(last) >= REPORT_INTERVAL);
        if !due || line == self.line {
            return false;
        }

        self.last = Some(now);
        self.blocked = blocked;
        self.line = line;
        ui::status_update(&self.line);
        true
    }
}

/// Build a `TorClientConfig` that uses `storage` and an in-memory keystore.
///
/// Everything else is Arti's default, which means the real Tor network, the
/// built-in directory authorities and no bridges. Notably this does *not* read
/// `arti.toml` or any other configuration file, so a machine-wide Arti or
/// C Tor setup cannot change what this client does.
fn ephemeral_config(storage: &EphemeralStorage) -> Result<TorClientConfig> {
    let mut builder = TorClientConfig::builder();

    builder
        .storage()
        .state_dir(CfgPath::new_literal(storage.state_dir()))
        .cache_dir(CfgPath::new_literal(storage.cache_dir()));

    // The onion service identity key is generated on first launch and only
    // ever exists in this process's memory.
    builder
        .storage()
        .keystore()
        .primary()
        .kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));

    builder
        .build()
        .context("failed to build the Tor client configuration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_progress_is_throttled_but_a_blockage_is_not() {
        let now = Instant::now();
        let mut reporter = ProgressReporter::default();

        // Nothing said yet: the first status always earns a line, so the wait
        // is never silent at the start.
        assert!(reporter.emit(false, "15%".to_string(), now));
        // Too soon, and then far enough apart to be worth another line.
        assert!(!reporter.emit(false, "20%".to_string(), now + REPORT_INTERVAL / 2));
        assert!(reporter.emit(false, "20%".to_string(), now + REPORT_INTERVAL));
        // Arti re-reporting the same status is not news at any distance.
        assert!(!reporter.emit(false, "20%".to_string(), now + REPORT_INTERVAL * 10));

        // "This machine cannot reach Tor at all" is the one thing worth
        // breaking the throttle for: it is the difference between slow and
        // stuck, and only one of those is worth waiting out.
        assert!(reporter.emit(true, "stuck at 20%".to_string(), now + REPORT_INTERVAL * 10));
    }

    #[test]
    fn config_builds_from_ephemeral_storage() {
        let storage = EphemeralStorage::new().unwrap();
        // `state_dir`/`cache_dir` are not readable back off `TorClientConfig`,
        // so all this can check is that the paths are accepted at all. The
        // storage tests cover where those paths point.
        ephemeral_config(&storage).unwrap();
    }

    #[test]
    fn config_selects_the_in_memory_keystore() {
        let storage = EphemeralStorage::new().unwrap();
        let config = ephemeral_config(&storage).unwrap();

        assert_eq!(
            config.keystore().primary_kind(),
            Some(ArtiKeystoreKind::Ephemeral)
        );
    }
}
