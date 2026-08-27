//! A Tor client assembled from Arti's managers, with nothing on disk.
//!
//! `arti-client` would do all of this for us, but it reaches the network
//! through `tor-dirmgr` and stores onion-service state through
//! `tor-hsservice`, and those two are the only parts of Arti that require a
//! filesystem. So this module does what `arti-client` does — channel manager,
//! guard manager, circuit manager, onion-service circuit pool, onion-service
//! client — and supplies the two missing pieces from memory instead:
//! [`MemoryStateMgr`] for the guard and vanguard state, and
//! [`MemoryNetDirProvider`] for the directory.
//!
//! Everything below the directory is still Arti's, deliberately. In
//! particular the channel manager owns the TLS connection to each relay and
//! the link handshake that authenticates it: Tor relays present self-signed
//! certificates and are identified by the CERTS cell instead, so replacing
//! that layer would mean writing a certificate verifier that accepts anything
//! and re-implementing the check that makes it safe. This way that check
//! remains Arti's.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt as _;
use futures_util::stream::BoxStream;
use tor_chanmgr::{ChanMgr, ChanMgrConfig, ChannelConfig, Dormancy};
use tor_circmgr::CircMgr;
use tor_circmgr::hspool::HsCircPool;
use tor_guardmgr::GuardMgr;
use tor_hsclient::{HsClientConnector, HsClientSecretKeys};
use tor_hscrypto::pk::HsId;
use tor_circmgr::isolation::StreamIsolation;
use tor_netdir::params::NetParameters;
use tor_netdir::{DirEvent, NetDirProvider as _, Timeliness, UpcastArcNetDirProvider as _};
use tor_proto::client::stream::{DataStream, StreamParameters};
use tor_memquota::MemoryQuotaTracker;
use tor_rtcompat::PreferredRuntime;

use crate::ui;

use super::config::TorConfig;
use super::memstate::MemoryStateMgr;
use super::netdir::{self, MemoryNetDirProvider};

/// How long to wait for a service to answer a `BEGIN`.
///
/// Arti's own stream timeout is ten seconds. This is longer because the peer
/// on the other end is one CLI serving one transfer: it answers a second
/// connection only when it comes back round to accepting, which can be after
/// it has finished with somebody else.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Arti's default memory quota, sized from this machine's memory.
fn memory_quota(runtime: &PreferredRuntime) -> Result<Arc<MemoryQuotaTracker>> {
    let config = tor_memquota::Config::builder()
        .build()
        .context("failed to work out how much memory the Tor client may use")?;
    MemoryQuotaTracker::new(runtime, config).context("failed to set up memory accounting")
}

/// A bootstrapped Tor client that exists only in this process.
///
/// There is no storage to clean up: when this is dropped, or when the process
/// dies for any reason including being killed outright, everything it knew —
/// the directory, the guards, the onion-service keys — goes with it.
pub struct TorClient {
    /// The async runtime everything runs on.
    runtime: PreferredRuntime,
    /// The directory, held in memory. Also the thing every manager reads the
    /// network's shape from.
    netdir: Arc<MemoryNetDirProvider>,
    /// Builds and reuses circuits. Held so the manager outlives every circuit
    /// taken from it, including the ones inside the onion-service pool.
    _circmgr: Arc<CircMgr<PreferredRuntime>>,
    /// Circuits for onion-service use, kept separate from ordinary ones.
    hs_pool: Arc<HsCircPool<PreferredRuntime>>,
    /// Connects to onion services.
    hsclient: HsClientConnector<PreferredRuntime>,
    /// Settings, shared with the directory refresh task.
    config: Arc<TorConfig>,
    /// Background tasks stop when their handles drop, so they are kept here
    /// for as long as the client lives.
    _tasks: Vec<tor_rtcompat::scheduler::TaskHandle>,
}

impl TorClient {
    /// Build a client and fetch a directory for it.
    ///
    /// This talks to the real Tor network and takes a few tens of seconds:
    /// there is no cached directory to start from, by design, so the consensus
    /// and every microdescriptor are downloaded each run.
    pub async fn bootstrap() -> Result<Self> {
        let runtime = PreferredRuntime::current()
            .context("failed to find the async runtime the Tor client should use")?;
        let config = Arc::new(TorConfig::new()?);
        let statemgr = MemoryStateMgr::new();
        let netdir = Arc::new(MemoryNetDirProvider::new(config.tolerance().clone()));

        let chanmgr = Arc::new(
            ChanMgr::new(
                runtime.clone(),
                ChanMgrConfig::new(ChannelConfig::default()),
                Dormancy::Active,
                &NetParameters::default(),
                // Arti's own default quota, sized from the machine's memory.
                // A published onion service takes introductions from anyone
                // who has the address, so the queues behind those circuits are
                // reachable by a stranger; leaving them unaccounted is how a
                // stranger turns them into all of this machine's memory.
                memory_quota(&runtime)?,
            )
            .context("failed to set up the Tor channel manager")?,
        );

        let guardmgr = GuardMgr::new(runtime.clone(), statemgr.clone(), config.as_ref())
            .context("failed to set up the Tor guard manager")?;

        let circmgr = Arc::new(
            CircMgr::new(
                config.as_ref(),
                statemgr.clone(),
                &runtime,
                Arc::clone(&chanmgr),
                &guardmgr,
            )
            .context("failed to set up the Tor circuit manager")?,
        );

        let mut tasks = circmgr
            .launch_background_tasks(&runtime, &netdir, statemgr.clone())
            .context("failed to start the circuit manager's background tasks")?;
        tasks.extend(
            chanmgr
                .launch_background_tasks(&runtime, Arc::clone(&netdir).upcast_arc())
                .context("failed to start the channel manager's background tasks")?,
        );

        let hs_pool = Arc::new(HsCircPool::new(&circmgr));
        tasks.extend(
            hs_pool
                .launch_background_tasks(&runtime, &Arc::clone(&netdir).upcast_arc())
                .context("failed to start the onion-service circuit pool")?,
        );

        // Nothing above can build a multi-hop circuit until this lands: the
        // managers are all waiting on a directory that only arrives here.
        ui::status("Fetching the Tor directory; this usually takes under a minute...");
        let started = Instant::now();
        let directory = netdir::download(&runtime, &circmgr, &config, None)
            .await
            .context("failed to fetch the Tor directory")?;
        netdir.publish(directory);
        ui::status_timed("Fetched the Tor directory", started.elapsed());

        // The consensus expires; `serve` can outlive it.
        tokio::spawn(netdir::keep_current(
            runtime.clone(),
            Arc::clone(&circmgr),
            Arc::clone(&config),
            Arc::clone(&netdir),
        ));

        let hsclient = HsClientConnector::new(
            runtime.clone(),
            Arc::clone(&hs_pool),
            config.as_ref(),
            housekeeping(&netdir),
        )
        .context("failed to set up the onion-service client")?;

        Ok(Self {
            runtime,
            netdir,
            _circmgr: circmgr,
            hs_pool,
            hsclient,
            config,
            _tasks: tasks,
        })
    }

    /// Open a stream to `port` on the onion service at `host`.
    ///
    /// `host` must already be a canonical `.onion` address; [`super::split_address`]
    /// is what turns typed input into one.
    pub async fn connect(&self, host: &str, port: u16) -> Result<DataStream> {
        let hsid: HsId = host
            .parse()
            .with_context(|| format!("invalid v3 onion address {host:?}"))?;

        let netdir = self
            .netdir
            .netdir(Timeliness::Timely)
            .context("no usable Tor directory")?;

        let tunnel = self
            .hsclient
            .get_or_launch_tunnel(
                &netdir,
                hsid,
                HsClientSecretKeys::default(),
                // One client, one purpose: every stream this process opens is
                // part of the same transfer, so there is nothing to isolate
                // from anything else.
                StreamIsolation::no_isolation(),
            )
            .await
            .with_context(|| format!("failed to reach the onion service at {host}"))?;

        // The service already knows which service it is, and telling it the
        // hostname again leaks nothing useful; Arti suppresses it, so we do.
        let mut params = StreamParameters::default();
        params
            .suppress_hostname()
            .suppress_begin_flags()
            .optimistic(false);

        // `begin_stream` waits for the service to answer BEGIN and has no
        // deadline of its own, so a service that takes the stream and says
        // nothing would hang the command for good. Generous, because a service
        // that is busy with another transfer answers only when it comes back
        // round to accepting.
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            tunnel.begin_stream("", port, Some(params)),
        )
        .await
        .map_err(|_| {
            anyhow!("the onion service at {host}:{port} accepted a stream but never answered")
        })?
        .with_context(|| format!("failed to open a stream to {host}:{port}"))
    }

    /// The async runtime this client runs on.
    pub fn runtime(&self) -> &PreferredRuntime {
        &self.runtime
    }

    /// The circuit pool onion services build their circuits from.
    pub fn hs_pool(&self) -> &Arc<HsCircPool<PreferredRuntime>> {
        &self.hs_pool
    }

    /// The directory, for callers that need to pick relays themselves.
    pub fn netdir_provider(&self) -> &Arc<MemoryNetDirProvider> {
        &self.netdir
    }

    /// The settings this client was built with.
    pub fn config(&self) -> &Arc<TorConfig> {
        &self.config
    }
}

/// A stream that ticks whenever a new consensus arrives.
///
/// The onion-service client uses this to expire cached descriptors: a new
/// consensus is a moment when it is already doing work, so it is a good moment
/// to do a little more.
fn housekeeping(netdir: &Arc<MemoryNetDirProvider>) -> BoxStream<'static, ()> {
    netdir
        .events()
        .filter_map(|event| async move {
            match event {
                DirEvent::NewConsensus => Some(()),
                _ => None,
            }
        })
        .boxed()
}
