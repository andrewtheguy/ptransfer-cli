//! The Tor network directory, fetched into memory and never written down.
//!
//! This is what replaces `tor-dirmgr`. Arti's directory manager keeps the
//! consensus and the microdescriptors in a SQLite database plus a `dir_blobs/`
//! directory so that a later run can start from a warm cache; its `Store`
//! trait is `pub(crate)`, so the storage cannot be swapped out from outside.
//! Everything that *reads* the directory, though, goes through the public
//! [`NetDirProvider`] trait — so we skip the manager, download the directory
//! ourselves, and hand it out from an `RwLock`. A session is one process, so
//! there is no second run for a cache to help.
//!
//! # What is checked
//!
//! The download follows the same sequence Arti's own directory manager uses,
//! and none of the checks are optional:
//!
//! 1. The consensus is parsed and must be **timely** — within its own
//!    `valid-after`/`valid-until` interval, per our clock.
//! 2. It must claim signatures from **authorities we recognize**, and enough of
//!    them: the identities come from Arti's built-in list (see
//!    [`TorConfig::authorities`]), not from anything the network told us.
//! 3. Every authority certificate is checked for a **valid signature** and for
//!    **timeliness** before it is allowed to vouch for anything, and only
//!    certificates belonging to recognized authorities are fetched at all.
//! 4. The consensus signatures are then verified against those certificates.
//! 5. Each microdescriptor is accepted only if its **digest is one the
//!    consensus asked for** — [`MdReceiver::add_microdesc`] rejects the rest.
//!
//! `tor-netdoc` offers `dangerously_assume_timely` and
//! `dangerously_assume_wellsigned` to skip steps 1 and 4. They are not used
//! here, and must not be: they are exactly the "skip verify" this transport
//! cannot afford, because the consensus is what tells us which relay keys to
//! trust for everything afterwards.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::stream::{BoxStream, StreamExt as _};
use tor_checkable::{ExternallySigned, SelfSigned, TimeBound};
use tor_circmgr::{CircMgr, DirInfo};
use tor_dirclient::request::{AuthCertRequest, ConsensusRequest, MicrodescRequest};
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdir::params::NetParameters;
use tor_netdir::{DirEvent, MdReceiver, NetDir, NetDirProvider, PartialNetDir, Timeliness};
use tor_netdoc::AllowAnnotations;
use tor_netdoc::doc::authcert::{AuthCert, AuthCertKeyIds};
use tor_netdoc::doc::microdesc::{MdDigest, MicrodescReader};
use tor_netdoc::doc::netstatus::{ConsensusFlavor, MdConsensus};
use tor_rtcompat::{Runtime, SleepProviderExt as _};

use super::config::TorConfig;

/// Microdescriptors to ask for in one request.
///
/// The directory caches cap how much they will return for one request, and a
/// consensus lists several thousand relays, so this is a batch size rather
/// than a limit: whatever is still missing is asked for again.
const MICRODESCS_PER_REQUEST: usize = 500;

/// How long before the consensus expires to start fetching its replacement.
///
/// A download takes tens of seconds; this leaves room for several attempts
/// before the directory in hand stops being usable, which matters for `serve`,
/// the one command that can outlive a consensus.
const REFRESH_MARGIN: Duration = Duration::from_secs(45 * 60);

/// How long to wait before retrying a refresh that failed.
const REFRESH_RETRY_DELAY: Duration = Duration::from_secs(60);

/// How long to give one directory request before trying somewhere else.
///
/// Without this a single unresponsive directory cache stalls the whole
/// bootstrap: `get_resource` waits on the circuit it built and has no deadline
/// of its own.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// How many directory caches to try for one document before giving up.
const REQUEST_ATTEMPTS: usize = 4;

/// The network directory, held in memory for as long as the process runs.
///
/// This is the whole of the directory storage: no cache, no state directory,
/// nothing on disk.
#[derive(Debug)]
pub struct MemoryNetDirProvider {
    /// The directory we are currently handing out, once one has been
    /// downloaded and validated.
    current: RwLock<Option<Arc<NetDir>>>,
    /// Publishes a tick whenever `current` changes. Arti's managers subscribe
    /// to this to notice a new consensus.
    events: std::sync::Mutex<postage::watch::Sender<DirEvent>>,
}

impl MemoryNetDirProvider {
    /// Create a provider that has no directory yet.
    pub fn new() -> Self {
        // Deliberately not `NewConsensus`. A `watch` receiver is handed the
        // current value the moment it subscribes, and Arti's vanguard manager
        // responds to `NewConsensus` by calling `netdir(Timeliness::Timely)`
        // and treating an error as fatal — it logs "Vanguard manager crashed"
        // and stops for good. It subscribes before the first directory has
        // been downloaded, so an initial `NewConsensus` kills it before the
        // client can build a single onion-service circuit. `NewDescriptors`
        // is ignored by that code, so the first real event a subscriber acts
        // on is the one `publish` sends.
        let (tx, _rx) = postage::watch::channel_with(DirEvent::NewDescriptors);
        Self {
            current: RwLock::new(None),
            events: std::sync::Mutex::new(tx),
        }
    }

    /// Install `netdir` as the directory this provider hands out.
    pub fn publish(&self, netdir: Arc<NetDir>) {
        *self.current.write().expect("poisoned lock") = Some(netdir);
        // Wakes `wait_for_netdir` and prompts the managers to re-read.
        let _ = postage::sink::Sink::try_send(
            &mut *self.events.lock().expect("poisoned lock"),
            DirEvent::NewConsensus,
        );
    }

    /// The directory we hold, if any, without checking how old it is.
    fn peek(&self) -> Option<Arc<NetDir>> {
        self.current.read().expect("poisoned lock").clone()
    }
}

impl Default for MemoryNetDirProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NetDirProvider for MemoryNetDirProvider {
    fn netdir(&self, timeliness: Timeliness) -> tor_netdir::Result<Arc<NetDir>> {
        let netdir = self.peek().ok_or(tor_netdir::Error::NoInfo)?;

        // `Unchecked` is for callers that would rather have a stale directory
        // than none — reporting relay information for a circuit that is
        // already open, say. The other two are held to the consensus's own
        // lifetime rather than to a tolerance, because the refresh task
        // replaces the directory well before it expires: if we are outside
        // the interval at all, something is wrong, and saying so beats
        // building circuits from a directory we cannot vouch for.
        match timeliness {
            Timeliness::Unchecked => return Ok(netdir),
            Timeliness::Timely | Timeliness::Strict => {}
        }

        let now = SystemTime::now();
        let lifetime = netdir.lifetime();
        if now < lifetime.valid_after() {
            // Almost always a wrong local clock rather than a bad directory.
            Err(tor_netdir::Error::DirNotYetValid)
        } else if now > lifetime.valid_until() {
            Err(tor_netdir::Error::DirExpired)
        } else {
            Ok(netdir)
        }
    }

    fn events(&self) -> BoxStream<'static, DirEvent> {
        let rx = self.events.lock().expect("poisoned lock").subscribe();
        // A `watch` receiver yields the current value immediately, so a
        // subscriber sees one event before anything has changed. That is why
        // the initial value is `NewDescriptors` rather than `NewConsensus`;
        // see `new`.
        rx.boxed()
    }

    fn params(&self) -> Arc<dyn AsRef<NetParameters>> {
        match self.peek() {
            Some(netdir) => netdir,
            // Arti's own defaults, which is what it uses before bootstrapping.
            None => Arc::new(NetParameters::default()),
        }
    }

    fn protocol_statuses(
        &self,
    ) -> Option<(SystemTime, Arc<tor_netdoc::doc::netstatus::ProtoStatuses>)> {
        // Arti's directory manager reads these out of the consensus to warn
        // that the running software is too old for the network. We do not
        // surface that, and the trait allows saying so.
        None
    }
}

/// Download, validate and assemble a complete network directory.
///
/// Talks to the network: a consensus, the authority certificates that sign it,
/// and a microdescriptor for every relay we intend to be able to use.
pub async fn download<R: Runtime>(
    runtime: &R,
    circmgr: &Arc<CircMgr<R>>,
    config: &TorConfig,
    netdir: Option<&NetDir>,
) -> Result<NetDir> {
    let consensus = fetch_consensus(runtime, circmgr, config, netdir).await?;

    let mut partial = PartialNetDir::new(consensus, None);
    fetch_microdescs(runtime, circmgr, config, netdir, &mut partial).await?;

    partial.unwrap_if_sufficient().map_err(|partial| {
        anyhow!(
            "the directory is missing too many relays to build circuits ({} still missing)",
            partial.missing_microdescs().count()
        )
    })
}

/// Fetch a consensus and verify it against the built-in directory authorities.
async fn fetch_consensus<R: Runtime>(
    runtime: &R,
    circmgr: &Arc<CircMgr<R>>,
    config: &TorConfig,
    netdir: Option<&NetDir>,
) -> Result<MdConsensus> {
    let authority_ids = config.authorities().v3idents();

    let mut request = ConsensusRequest::new(ConsensusFlavor::Microdesc);
    // Ask only for signatures from authorities we would accept anyway.
    for id in authority_ids {
        request.push_authority_id(*id);
    }

    let text = fetch(runtime, circmgr, config, netdir, &request)
        .await
        .context("failed to fetch the Tor consensus")?;

    let (_signed, _remainder, parsed) =
        MdConsensus::parse(&text).context("failed to parse the Tor consensus")?;

    // (1) Timeliness. `dangerously_assume_timely` would skip this.
    let now = runtime.wallclock();
    let timely = parsed
        .if_valid_at(&now)
        .context("the Tor consensus is not valid at the current time; check this machine's clock")?;

    // (2) Signed by enough authorities that we recognize. The identities come
    // from the built-in list, so a consensus signed by a full set of
    // authorities we have never heard of is rejected here.
    let unvalidated = timely.set_n_authorities(authority_ids.len());
    let id_refs: Vec<&RsaIdentity> = authority_ids.iter().collect();
    if !unvalidated.authorities_are_correct(&id_refs) {
        bail!("the Tor consensus is not signed by enough recognized directory authorities");
    }

    // (3) Fetch only the certificates of recognized authorities, and check
    // each one's signature and lifetime before it is allowed to vouch.
    let wanted: HashSet<AuthCertKeyIds> = unvalidated
        .signing_cert_ids()
        .filter(|ids| authority_ids.contains(&ids.id_fingerprint))
        .collect();
    let certs = fetch_certs(runtime, circmgr, config, netdir, &wanted).await?;

    // (4) The signatures themselves. `dangerously_assume_wellsigned` would
    // skip this.
    unvalidated
        .key_is_correct(&certs)
        .map_err(|missing| anyhow!("missing {} authority certificate(s)", missing.len()))?;
    unvalidated
        .check_signature(&certs)
        .context("the Tor consensus signatures did not verify")
}

/// Fetch and check the authority certificates identified by `wanted`.
async fn fetch_certs<R: Runtime>(
    runtime: &R,
    circmgr: &Arc<CircMgr<R>>,
    config: &TorConfig,
    netdir: Option<&NetDir>,
    wanted: &HashSet<AuthCertKeyIds>,
) -> Result<Vec<AuthCert>> {
    if wanted.is_empty() {
        return Ok(Vec::new());
    }

    let mut request = AuthCertRequest::new();
    for ids in wanted {
        request.push(*ids);
    }

    let text = fetch(runtime, circmgr, config, netdir, &request)
        .await
        .context("failed to fetch the directory authority certificates")?;

    let now = runtime.wallclock();
    let mut certs = Vec::new();
    for parsed in AuthCert::parse_multiple(&text)
        .context("failed to parse the directory authority certificates")?
    {
        let cert = match parsed {
            Ok(cert) => cert,
            Err(error) => {
                // One bad certificate in the batch is not fatal: the consensus
                // check below fails if what is left is not enough.
                log::warn!("discarding an unparsable authority certificate: {error}");
                continue;
            }
        };

        // Signature first, then lifetime: an expired certificate and a forged
        // one are both refused, and neither is allowed to vouch for anything.
        let cert = match cert.check_signature() {
            Ok(wellsigned) => wellsigned,
            Err(error) => {
                log::warn!("discarding an incorrectly signed authority certificate: {error}");
                continue;
            }
        };
        let cert = match cert.if_valid_at(&now) {
            Ok(timely) => timely,
            Err(error) => {
                log::warn!("discarding an untimely authority certificate: {error}");
                continue;
            }
        };

        // A cache is free to send certificates we did not ask for.
        if wanted.contains(&cert.key_ids()) {
            certs.push(cert);
        } else {
            log::warn!("discarding an authority certificate we did not ask for");
        }
    }

    Ok(certs)
}

/// Fetch microdescriptors until `partial` has everything the consensus listed.
async fn fetch_microdescs<R: Runtime>(
    runtime: &R,
    circmgr: &Arc<CircMgr<R>>,
    config: &TorConfig,
    netdir: Option<&NetDir>,
    partial: &mut PartialNetDir,
) -> Result<()> {
    loop {
        let missing: Vec<MdDigest> = partial.missing_microdescs().copied().collect();
        if missing.is_empty() {
            return Ok(());
        }

        let mut added = 0;
        for batch in missing.chunks(MICRODESCS_PER_REQUEST) {
            let mut request = MicrodescRequest::new();
            for digest in batch {
                request.push(*digest);
            }

            let text = match fetch(runtime, circmgr, config, netdir, &request).await {
                Ok(text) => text,
                Err(error) => {
                    // Try the rest of the batches; a directory cache that
                    // fails one request often serves the next.
                    log::warn!("failed to fetch a batch of microdescriptors: {error:#}");
                    continue;
                }
            };

            let reader = match MicrodescReader::new(&text, &AllowAnnotations::AnnotationsNotAllowed)
            {
                Ok(reader) => reader,
                Err(error) => {
                    log::warn!("failed to parse a batch of microdescriptors: {error}");
                    continue;
                }
            };

            for parsed in reader {
                match parsed {
                    // (5) `add_microdesc` returns false for a descriptor whose
                    // digest the consensus did not list, which is what binds
                    // these documents to the consensus we verified. A cache
                    // cannot slip in a relay of its own choosing.
                    Ok(annotated) => {
                        if partial.add_microdesc(annotated.into_microdesc()) {
                            added += 1;
                        } else {
                            log::debug!("ignoring a microdescriptor we did not ask for");
                        }
                    }
                    Err(error) => log::warn!("ignoring an unparsable microdescriptor: {error}"),
                }
            }
        }

        // Every relay the consensus lists is worth having, but a few are
        // routinely unavailable from any cache. Stop as soon as we have enough
        // to build circuits, and give up if a whole pass added nothing.
        if partial.have_enough_paths() {
            return Ok(());
        }
        if added == 0 {
            bail!("no directory cache would serve the microdescriptors this consensus lists");
        }
    }
}

/// Send one directory request and return the document it produced.
///
/// Before the first consensus arrives there is no directory to pick a path
/// from, so the request goes to one of the built-in fallback directories over
/// a one-hop circuit — which is how every Tor client starts, and why the
/// documents it returns are all independently verified above.
async fn fetch<R: Runtime, Q: tor_dirclient::request::Requestable + ?Sized>(
    runtime: &R,
    circmgr: &Arc<CircMgr<R>>,
    config: &TorConfig,
    netdir: Option<&NetDir>,
    request: &Q,
) -> Result<String> {
    let dirinfo = match netdir {
        Some(netdir) => DirInfo::Directory(netdir),
        None => DirInfo::Fallbacks(config.fallbacks()),
    };

    let mut last_error = None;
    for attempt in 1..=REQUEST_ATTEMPTS {
        // Each attempt goes through `get_resource` again, which picks a
        // directory cache and builds a circuit to it, so a retry is a retry
        // somewhere else rather than the same dead end again.
        let outcome = runtime
            .timeout(
                REQUEST_TIMEOUT,
                tor_dirclient::get_resource(request, dirinfo, runtime, Arc::clone(circmgr)),
            )
            .await;

        let error = match outcome {
            Ok(Ok(response)) => match response.into_output_string() {
                Ok(text) => return Ok(text),
                Err(error) => anyhow::Error::new(error)
                    .context("the directory cache returned a partial or failed response"),
            },
            Ok(Err(error)) => anyhow::Error::new(error).context("the directory request failed"),
            Err(_) => anyhow!("the directory cache did not answer in {REQUEST_TIMEOUT:?}"),
        };
        log::debug!("directory request attempt {attempt} of {REQUEST_ATTEMPTS} failed: {error:#}");
        last_error = Some(error);
    }

    Err(last_error
        .unwrap_or_else(|| anyhow!("no directory cache answered"))
        .context(format!("giving up after {REQUEST_ATTEMPTS} directory caches")))
}

/// Keep `provider` supplied with a directory for as long as the process runs.
///
/// The consensus we bootstrapped with expires; `serve` can outlive it. This
/// re-downloads shortly before that happens, using the directory in hand to
/// pick the path rather than going back to the fallbacks.
pub async fn keep_current<R: Runtime>(
    runtime: R,
    circmgr: Arc<CircMgr<R>>,
    config: Arc<TorConfig>,
    provider: Arc<MemoryNetDirProvider>,
) {
    loop {
        let Some(netdir) = provider.netdir(Timeliness::Unchecked).ok() else {
            // Nothing to refresh yet; the bootstrap publishes the first one.
            runtime.sleep(REFRESH_RETRY_DELAY).await;
            continue;
        };

        let expires = netdir.lifetime().valid_until();
        let renew_at = expires
            .checked_sub(REFRESH_MARGIN)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if let Ok(wait) = renew_at.duration_since(SystemTime::now()) {
            runtime.sleep(wait).await;
        }

        log::info!("refreshing the Tor directory before it expires");
        match download(&runtime, &circmgr, &config, Some(netdir.as_ref())).await {
            Ok(fresh) => {
                log::info!("refreshed the Tor directory");
                provider.publish(Arc::new(fresh));
            }
            Err(error) => {
                log::warn!("failed to refresh the Tor directory: {error:#}");
                runtime.sleep(REFRESH_RETRY_DELAY).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_provider_with_no_directory_reports_that() {
        let provider = MemoryNetDirProvider::new();
        assert!(matches!(
            provider.netdir(Timeliness::Unchecked),
            Err(tor_netdir::Error::NoInfo)
        ));
        assert!(matches!(
            provider.netdir(Timeliness::Strict),
            Err(tor_netdir::Error::NoInfo)
        ));
    }

    /// Before a directory exists, callers still ask for network parameters;
    /// they must get Arti's defaults rather than a panic.
    #[test]
    fn parameters_fall_back_to_the_defaults() {
        let provider = MemoryNetDirProvider::new();
        let params = provider.params();
        let params: &NetParameters = params.as_ref().as_ref();
        assert_eq!(
            params.min_circuit_path_threshold,
            NetParameters::default().min_circuit_path_threshold
        );
    }
}
