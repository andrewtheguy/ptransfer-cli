//! Configuration for the Tor client this crate assembles.
//!
//! Arti's managers do not take a single configuration object; each one takes a
//! trait describing only the settings it reads ([`GuardMgrConfig`],
//! [`CircMgrConfig`], [`HsClientConnectorConfig`]). `arti-client` satisfies
//! them all with its `TorClientConfig`, which is also what reads `arti.toml`.
//! This crate has no configuration file and no settings to expose, so it
//! satisfies them with one small struct of Arti's own defaults instead.
//!
//! The one value that is not a `Default` is the fallback directory list:
//! `FallbackList` derives `Default`, which is *empty*, while the built-in list
//! shipped with Arti comes from the builder. An empty list would leave the
//! client with no way into the network on a first run, so [`TorConfig::new`]
//! goes through the builder.

use anyhow::{Context, Result};
use tor_circmgr::{CircuitTiming, PathConfig, PreemptiveCircuitConfig};
use tor_dircommon::authority::AuthorityContacts;
use tor_dircommon::fallback::{FallbackList, FallbackListBuilder};
use tor_guardmgr::VanguardConfig;
use tor_guardmgr::bridge::BridgeConfig;

/// Settings for every Arti manager this crate drives.
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// Relays to bootstrap from when we have no directory yet.
    fallbacks: FallbackList,
    /// The directory authorities: their identities are the trust anchors the
    /// consensus is checked against, and their addresses are where a
    /// certificate we are missing gets fetched from.
    authorities: AuthorityContacts,
    /// How paths through the network may be built.
    paths: PathConfig,
    /// Onion-service circuit protection. On by default in Arti, and left on.
    vanguards: VanguardConfig,
    /// Circuit build and expiry timing.
    timing: CircuitTiming,
    /// How many circuits to build ahead of being asked.
    preemptive: PreemptiveCircuitConfig,
}

impl TorConfig {
    /// Build the configuration from Arti's own defaults.
    pub fn new() -> Result<Self> {
        Ok(Self {
            fallbacks: FallbackListBuilder::default()
                .build()
                .context("failed to build the built-in fallback directory list")?,
            authorities: AuthorityContacts::builder()
                .build()
                .context("failed to build the built-in directory authority list")?,
            paths: PathConfig::default(),
            vanguards: VanguardConfig::default(),
            timing: CircuitTiming::default(),
            preemptive: PreemptiveCircuitConfig::default(),
        })
    }

    /// The directory authorities, whose identities anchor consensus validation.
    pub fn authorities(&self) -> &AuthorityContacts {
        &self.authorities
    }

    /// The relays to bootstrap the directory from.
    pub fn fallbacks(&self) -> &FallbackList {
        &self.fallbacks
    }
}

impl AsRef<FallbackList> for TorConfig {
    fn as_ref(&self) -> &FallbackList {
        &self.fallbacks
    }
}

impl AsRef<[BridgeConfig]> for TorConfig {
    fn as_ref(&self) -> &[BridgeConfig] {
        // Without the `bridge-client` feature `BridgeConfig` is uninhabited,
        // so this is the only value this can take. We reach the network
        // directly; a censored client is not a case this transport handles.
        &[]
    }
}

impl AsRef<PathConfig> for TorConfig {
    fn as_ref(&self) -> &PathConfig {
        &self.paths
    }
}

impl AsRef<VanguardConfig> for TorConfig {
    fn as_ref(&self) -> &VanguardConfig {
        &self.vanguards
    }
}

impl AsRef<CircuitTiming> for TorConfig {
    fn as_ref(&self) -> &CircuitTiming {
        &self.timing
    }
}

impl AsRef<PreemptiveCircuitConfig> for TorConfig {
    fn as_ref(&self) -> &PreemptiveCircuitConfig {
        &self.preemptive
    }
}

impl tor_guardmgr::GuardMgrConfig for TorConfig {
    fn bridges_enabled(&self) -> bool {
        false
    }
}

impl tor_circmgr::CircMgrConfig for TorConfig {}

impl tor_hsclient::HsClientConnectorConfig for TorConfig {}

#[cfg(test)]
mod tests {
    use super::*;

    /// `FallbackList::default()` is empty; the built-in list is only reachable
    /// through the builder. Getting this wrong leaves a first run with no way
    /// into the network, and nothing else would notice.
    #[test]
    fn the_fallback_list_is_the_built_in_one() {
        let config = TorConfig::new().unwrap();
        assert!(!config.fallbacks().is_empty());
        assert!(FallbackList::default().is_empty());
    }

    /// These identities are what the consensus signatures are checked against.
    #[test]
    fn the_authorities_are_the_built_in_ones() {
        let config = TorConfig::new().unwrap();
        // Tor has had nine directory authorities for years; assert only that
        // we got a plausible set rather than pinning the exact count.
        assert!(config.authorities().v3idents().len() >= 5);
        assert!(!config.authorities().downloads().is_empty());
    }
}
