//! Bootstrapping an Arti client that leaves nothing behind.

use anyhow::{Context, Result};
use arti_client::TorClient;
use arti_client::config::{CfgPath, TorClientConfig};
use std::sync::Arc;
use tor_config::ExplicitOrAuto;
use tor_keymgr::config::ArtiKeystoreKind;
use tor_rtcompat::PreferredRuntime;

use super::storage::EphemeralStorage;

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
    pub async fn bootstrap() -> Result<Self> {
        let storage = EphemeralStorage::new()?;
        log::info!("Tor client state: {} (removed on exit)", storage.root().display());

        let config = ephemeral_config(&storage)?;
        let client = TorClient::create_bootstrapped(config)
            .await
            .context("failed to bootstrap the Tor client")?;

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
