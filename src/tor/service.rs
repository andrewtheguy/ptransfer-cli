//! Publishing an ephemeral v3 onion service and accepting streams on it.
//!
//! The file transfer publishes a throwaway address here, waits for the
//! descriptor to go up, and then answers incoming streams on one virtual port.
//!
//! This is the second half of what `arti-client` would have provided.
//! `tor-hsservice` cannot be used here because it keeps its state through
//! `tor_persist::StateDirectory`, a concrete filesystem type: the
//! introduction-point records are files, and the replay log it keeps per
//! introduction point is a file it appends to and re-reads. So the service is
//! built here instead, on `tor-proto`, and its state — the identity key, the
//! introduction points, the replay set — is ordinary process memory.
//!
//! The sequence is the one in rend-spec-v3:
//!
//! 1. generate an identity keypair, whose public half *is* the `.onion`
//!    address, and blind it for each time period we publish in;
//! 2. build a circuit to each of a few relays and send `ESTABLISH_INTRO`, so
//!    they become introduction points for this service;
//! 3. sign a descriptor naming those introduction points and upload it to the
//!    HSDirs the hash ring makes responsible for the blinded identity;
//! 4. for every `INTRODUCE2` forwarded by an introduction point, finish the
//!    hs-ntor handshake as responder, build a circuit to the rendezvous point
//!    the client named, add the virtual hop and answer with `RENDEZVOUS1`;
//! 5. hand every `BEGIN` that arrives on that virtual hop to [`OnionListener::accept`].

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::StreamExt as _;
use futures_channel::{mpsc, oneshot};
use safelog::DisplayRedacted as _;
use tokio::task::JoinHandle;
use tor_cell::chancell::msg::HandshakeType;
use tor_cell::relaycell::hs::est_intro::EstablishIntroDetails;
use tor_cell::relaycell::hs::intro_payload::{IntroduceHandshakePayload, OnionKey};
use tor_cell::relaycell::hs::{Introduce2, Rendezvous1};
use tor_cell::relaycell::msg::{AnyRelayMsg, Connected, End, Unrecognized};
use tor_cell::relaycell::{RelayCmd, RelayMsg as _};
use tor_circmgr::build::onion_circparams_from_netparams;
use tor_circmgr::hspool::HsCircPool;
use tor_dirclient::request::HsDescUploadRequest;
use tor_hscrypto::ope::AesOpeKey;
use tor_hscrypto::pk::{
    HsBlindId, HsId, HsIdKey, HsIdKeypair, HsIntroPtSessionIdKey, HsIntroPtSessionIdKeypair,
    HsSvcNtorKeypair,
};
use tor_hscrypto::time::TimePeriod;
use tor_hscrypto::{RevisionCounter, Subcredential};
use tor_linkspec::verbatim::VerbatimLinkSpecCircTarget;
use tor_linkspec::decode::Strictness;
use tor_linkspec::{
    CircTarget, EncodedLinkSpec, HasRelayIds as _, OwnedChanTargetBuilder, OwnedCircTarget,
};
use tor_llcrypto::pk::ed25519;
use tor_netdir::{NetDir, NetDirProvider as _, Timeliness, WeightRole};
use tor_netdoc::NetdocBuilder as _;
use tor_netdoc::doc::hsdesc::{HsDescBuilder, IntroPointDesc, create_desc_sign_key_cert};
use tor_proto::client::circuit::handshake::{HandshakeRole, RelayProtocol, hs_ntor};
use tor_proto::client::stream::DataStream;
use tor_proto::stream::{
    IncomingStream, IncomingStreamRequest, IncomingStreamRequestContext,
    IncomingStreamRequestDisposition, IncomingStreamRequestFilter,
};
use tor_proto::{MetaCellDisposition, MsgHandler, TargetHop};
use tor_rtcompat::PreferredRuntime;

use super::client::TorClient;
use super::netdir::MemoryNetDirProvider;

/// How many introduction points a service establishes. Three is what C tor and
/// Arti both use.
const INTRO_POINTS: usize = 3;
/// How long a published descriptor claims to be good for.
const DESCRIPTOR_LIFETIME: Duration = Duration::from_secs(3 * 60 * 60);
/// Lifetime of the certificates inside the descriptor. C tor uses 54 hours: a
/// descriptor can live 48, plus room for a consensus that turns over late.
const CERT_LIFETIME: Duration = Duration::from_secs(54 * 60 * 60);
/// The CREATE handshake a client may use on the rendezvous circuit.
const CREATE2_FORMATS: &[HandshakeType] = &[HandshakeType::NTOR];
/// How long between republications of the descriptor.
///
/// A descriptor expires, and the rings it sits on rotate with the time period,
/// so a service that uploads once stops being reachable a few hours later
/// while still looking healthy from the inside.
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// How long to wait before trying again when a republication failed.
///
/// Shorter than [`REPUBLISH_INTERVAL`]: a descriptor that did not go up is the
/// case where waiting an hour actually costs reachability.
const REPUBLISH_RETRY_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// How often the service checks that its introduction points are still up.
///
/// A relay that drops the circuit stops forwarding introductions, and the
/// published descriptor still names it, so a client that picks it waits for an
/// answer that cannot arrive. This bounds how long that lasts.
const INTRO_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Time limit on establishing one introduction point.
const ESTABLISH_INTRO_TIMEOUT: Duration = Duration::from_secs(90);
/// How long to keep trying to establish the first introduction point.
///
/// Arti's vanguard manager builds its vanguard sets from the directory in a
/// background task, so for a moment after the directory lands there is no
/// vanguard to route an onion-service circuit through and every attempt fails
/// with "unbootstrapped vanguard manager". It clears itself in about a second;
/// only retrying makes it invisible.
const ESTABLISH_INTRO_DEADLINE: Duration = Duration::from_secs(180);
/// How long to wait between those attempts.
const ESTABLISH_INTRO_RETRY_DELAY: Duration = Duration::from_secs(2);
/// Time limit on storing the descriptor at one HSDir.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// Time limit on answering one client at its rendezvous point.
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(90);
/// Streams one client circuit may have open at once.
const MAX_CONCURRENT_STREAMS: usize = 16;
/// Depth of the queues between the circuit reactors and the service task.
const CHANNEL_DEPTH: usize = 8;
/// How many clients may be in the middle of an introduction at once.
///
/// Each one is a rendezvous circuit built on somebody else's say-so: anyone who
/// has the address can send `INTRODUCE2`, and none of them has authenticated
/// yet. Without a bound they are as many circuits as a stranger cares to ask
/// for. Introductions past the bound wait, and are dropped once the queue
/// behind them fills, which is what a busy service is supposed to do.
const MAX_CONCURRENT_INTRODUCTIONS: usize = 8;
/// How many introductions to remember for replay detection.
///
/// Each entry is 32 bytes, so even the cap is trivial; it exists only so that
/// a service left running for weeks cannot grow this without bound.
const REPLAY_CAPACITY: usize = 64 * 1024;

/// A published onion service and its queue of incoming streams.
///
/// Dropping this unpublishes the service: the tasks that hold the
/// introduction-point circuits stop, so the introduction points drop them too,
/// and the descriptor expires on the HSDirs without being renewed.
pub struct OnionListener {
    /// The `.onion` address this service publishes.
    onion: String,
    /// `BEGIN` requests from every client circuit, still unaccepted so that
    /// [`Self::accept`] can refuse the wrong port.
    requests: mpsc::Receiver<IncomingStream>,
    /// Resolves once the descriptor has been stored somewhere.
    published: Option<oneshot::Receiver<Result<()>>>,
    /// Aborted on drop, which is what unpublishes the service.
    task: JoinHandle<()>,
}

impl Drop for OnionListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl OnionListener {
    /// Publish a fresh service.
    ///
    /// Returns as soon as the address is known — which is immediately, because
    /// the address is derived from a key we generate here — and well before
    /// the descriptor is reachable. Call [`Self::wait_until_published`] for
    /// that.
    pub fn launch(tor: &TorClient, nickname: &str) -> Result<Self> {
        let mut rng = rand::rng();
        let identity = HsIdKeypair::from(ed25519::ExpandedKeypair::from(
            &ed25519::Keypair::generate(&mut rng),
        ));
        let hsid: HsId = HsIdKey::from(*identity.as_ref().public()).id();
        let onion = hsid.display_unredacted().to_string();
        log::info!("onion service {nickname} will publish as {onion}");

        let (request_tx, request_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (published_tx, published_rx) = oneshot::channel();

        let service = Service {
            runtime: tor.runtime().clone(),
            hs_pool: Arc::clone(tor.hs_pool()),
            netdir: Arc::clone(tor.netdir_provider()),
            identity: Arc::new(identity),
            subcredentials: Mutex::new(Vec::new()),
            seen: Mutex::new(HashSet::new()),
            requests: request_tx,
        };

        let task = tokio::spawn(async move {
            let service = Arc::new(service);
            if let Err(error) = service.run(published_tx).await {
                log::error!("the onion service stopped: {error:#}");
            }
        });

        Ok(Self {
            onion,
            requests: request_rx,
            published: Some(published_rx),
            task,
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
        let Some(published) = self.published.take() else {
            // Already waited once; the service has been up since then.
            return Ok(());
        };
        published
            .await
            .map_err(|_| anyhow!("the onion service stopped before publishing"))?
    }

    /// Accept the next incoming stream on `port`, rejecting any other port.
    ///
    /// `Ok(None)` means the service stopped accepting requests. Cancel-safe up
    /// to the point a request has been taken off the queue: dropping this
    /// future mid-accept drops that one connection, nothing else.
    pub async fn accept(&mut self, port: u16) -> Result<Option<DataStream>> {
        loop {
            let Some(request) = self.requests.next().await else {
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
                    .accept_data(Connected::new_empty())
                    .await
                    .context("failed to accept a stream")?,
            ));
        }
    }
}

/// Everything the running service needs, shared by its tasks.
struct Service {
    /// The runtime its tasks run on.
    runtime: PreferredRuntime,
    /// Where its circuits come from.
    hs_pool: Arc<HsCircPool<PreferredRuntime>>,
    /// The directory it picks relays and HSDirs from.
    netdir: Arc<MemoryNetDirProvider>,
    /// The service identity. Its public half is the `.onion` address, and it
    /// exists only here: there is no keystore, and it is never written down.
    identity: Arc<HsIdKeypair>,
    /// One subcredential per time period we have published for, which is what
    /// an `INTRODUCE2` is decrypted against. A client that found an older
    /// descriptor still has to be able to reach us.
    subcredentials: Mutex<Vec<(TimePeriod, Subcredential)>>,
    /// Introductions already answered, so a recorded `INTRODUCE2` replayed at
    /// us does not open a second rendezvous.
    ///
    /// This is what `tor-hsservice` keeps in an on-disk replay log per
    /// introduction point. In memory it is the same defence with a shorter
    /// horizon: it is forgotten when the process exits, and so are the
    /// introduction points and the identity key it protects, so there is
    /// nothing left for a recorded introduction to be replayed against.
    seen: Mutex<HashSet<[u8; 32]>>,
    /// Where accepted `BEGIN` requests are handed to [`OnionListener::accept`].
    requests: mpsc::Sender<IncomingStream>,
}

impl Service {
    /// Establish introduction points, publish, and keep both up.
    async fn run(self: &Arc<Self>, published: oneshot::Sender<Result<()>>) -> Result<()> {
        let (introduce_tx, mut introduce_rx) = mpsc::channel(CHANNEL_DEPTH);

        let mut intro_points = self
            .establish_intro_points_with_retry(introduce_tx.clone())
            .await
            .context("failed to establish any introduction point")?;

        let first = self.publish(&descriptors_of(&intro_points)).await;
        let ok = first.is_ok();
        let _ = published.send(first);
        if !ok {
            bail!("failed to publish the descriptor");
        }

        // Keep the introduction points and the descriptor up for as long as we
        // run, and answer clients meanwhile. This owns `intro_points`, so the
        // circuits live exactly as long as this loop does: dropping one tells
        // its introduction point we are gone.
        let maintain = {
            let service = Arc::clone(self);
            async move {
                let mut next_republish = tokio::time::Instant::now() + REPUBLISH_INTERVAL;
                loop {
                    tokio::time::sleep(INTRO_CHECK_INTERVAL).await;

                    // An introduction point whose circuit has closed is not
                    // one any more, however healthy the descriptor naming it
                    // looks. Drop it, replace it, and publish the new list.
                    let before = intro_points.len();
                    intro_points.retain(|point| !point.tunnel.is_closed());
                    let mut changed = intro_points.len() < before;
                    if changed {
                        log::warn!(
                            "{} introduction point(s) closed; re-establishing",
                            before - intro_points.len()
                        );
                    }

                    if intro_points.len() < INTRO_POINTS {
                        let live: HashSet<ed25519::Ed25519Identity> =
                            intro_points.iter().map(|point| point.relay).collect();
                        let wanted = INTRO_POINTS - intro_points.len();
                        match service
                            .establish_intro_points(introduce_tx.clone(), wanted, &live)
                            .await
                        {
                            Ok(fresh) => {
                                changed = true;
                                intro_points.extend(fresh);
                            }
                            // Not fatal while any introduction point is left:
                            // the service is still reachable through the rest,
                            // and the next pass tries again.
                            Err(error) => {
                                log::warn!("failed to replace an introduction point: {error:#}");
                            }
                        }
                    }

                    if intro_points.is_empty() {
                        return Err(anyhow!(
                            "every introduction point closed and none could be replaced; \
                             the service is no longer reachable"
                        ));
                    }

                    if !changed && tokio::time::Instant::now() < next_republish {
                        continue;
                    }
                    next_republish = match service.publish(&descriptors_of(&intro_points)).await {
                        Ok(()) => tokio::time::Instant::now() + REPUBLISH_INTERVAL,
                        Err(error) => {
                            log::warn!("failed to republish the descriptor: {error:#}");
                            tokio::time::Instant::now() + REPUBLISH_RETRY_INTERVAL
                        }
                    };
                }
            }
        };

        let answer = async {
            let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_INTRODUCTIONS));
            while let Some((keys, message)) = introduce_rx.next().await {
                let permit = Arc::clone(&permits)
                    .acquire_owned()
                    .await
                    .expect("the introduction semaphore is never closed");
                let service = Arc::clone(self);
                tokio::spawn(async move {
                    // Held for the whole introduction, rendezvous circuit and
                    // client streams included.
                    let _permit = permit;
                    if let Err(error) = service.serve_introduction(&keys, message).await {
                        log::warn!("an introduction from a client failed: {error:#}");
                    }
                });
            }
        };

        tokio::select! {
            // Returns only when the service has no introduction point left,
            // which leaves the address published but unreachable. Say so
            // rather than exiting quietly as though the work were done.
            result = maintain => result,
            // Cannot finish while the loop above holds a sender to re-establish
            // introduction points with; it is here because selecting on it is
            // what drives the introductions clients send us.
            _ = answer => Ok(()),
        }
    }

    /// Keep trying to establish introduction points until some are up.
    ///
    /// The first attempts land before the vanguard manager has built its sets
    /// from the directory, which fails in a way that fixes itself; see
    /// [`ESTABLISH_INTRO_DEADLINE`].
    async fn establish_intro_points_with_retry(
        self: &Arc<Self>,
        introduce: mpsc::Sender<(Arc<IntroPointKeys>, Introduce2)>,
    ) -> Result<Vec<EstablishedIntroPoint>> {
        let deadline = tokio::time::Instant::now() + ESTABLISH_INTRO_DEADLINE;
        let last_error;
        loop {
            match self
                .establish_intro_points(introduce.clone(), INTRO_POINTS, &HashSet::new())
                .await
            {
                Ok(points) => return Ok(points),
                Err(error) => log::debug!("no introduction point yet: {error:#}"),
            }
            if tokio::time::Instant::now() >= deadline {
                last_error = anyhow!("no relay would act as an introduction point in time");
                break;
            }
            tokio::time::sleep(ESTABLISH_INTRO_RETRY_DELAY).await;
        }
        Err(last_error)
    }

    /// Build a circuit to `wanted` relays and ask each to be an introduction
    /// point, picking none of the relays in `avoid`.
    ///
    /// `avoid` is how a replacement is kept off a relay that is already an
    /// introduction point for this service.
    async fn establish_intro_points(
        self: &Arc<Self>,
        introduce: mpsc::Sender<(Arc<IntroPointKeys>, Introduce2)>,
        wanted: usize,
        avoid: &HashSet<ed25519::Ed25519Identity>,
    ) -> Result<Vec<EstablishedIntroPoint>> {
        let netdir = self.timely_netdir()?;

        let mut established = Vec::new();
        let mut used: HashSet<ed25519::Ed25519Identity> = avoid.clone();
        let mut last_error = None;

        for _ in 0..wanted {
            let target = {
                let mut rng = rand::rng();
                let relay = netdir.pick_relay(&mut rng, WeightRole::HsIntro, |relay| {
                    relay.low_level_details().is_flagged_stable()
                        && relay.low_level_details().is_flagged_fast()
                        && !used.contains(relay.id())
                });
                match relay {
                    Some(relay) => {
                        used.insert(*relay.id());
                        OwnedCircTarget::from_circ_target(&relay)
                    }
                    None => break,
                }
            };

            let attempt = tokio::time::timeout(
                ESTABLISH_INTRO_TIMEOUT,
                self.establish_intro_point(&netdir, &target, introduce.clone()),
            )
            .await;

            match attempt {
                Ok(Ok(point)) => {
                    log::info!("introduction point established");
                    established.push(point);
                }
                Ok(Err(error)) => {
                    log::warn!("a relay would not be an introduction point: {error:#}");
                    last_error = Some(error);
                }
                Err(_) => log::warn!("a relay took too long to become an introduction point"),
            }
        }

        if established.is_empty() {
            return Err(last_error
                .unwrap_or_else(|| anyhow!("no relay would act as an introduction point")));
        }
        Ok(established)
    }

    /// One introduction point: a circuit, an `ESTABLISH_INTRO` signed with a
    /// fresh session key, and a handler that forwards every `INTRODUCE2`.
    async fn establish_intro_point(
        self: &Arc<Self>,
        netdir: &Arc<NetDir>,
        target: &OwnedCircTarget,
        introduce: mpsc::Sender<(Arc<IntroPointKeys>, Introduce2)>,
    ) -> Result<EstablishedIntroPoint> {
        // Scoped, because `ThreadRng` is not `Send` and this task is spawned:
        // the generator must be gone before the first await below.
        let keys = Arc::new({
            let mut rng = rand::rng();
            let session_id = HsIntroPtSessionIdKeypair::from(ed25519::Keypair::generate(&mut rng));
            let session_id_key = HsIntroPtSessionIdKey::from(session_id.as_ref().verifying_key());
            let ntor = HsSvcNtorKeypair::generate(&mut rng);
            IntroPointKeys {
                session_id,
                session_id_key,
                ntor,
            }
        });

        let tunnel = Arc::new(
            self.hs_pool
                .get_or_launch_svc_intro(netdir, target.clone())
                .await
                .context("failed to build a circuit to the introduction point")?,
        );

        // The ESTABLISH_INTRO signature covers the circuit's binding key,
        // which is what stops it being replayed onto another circuit.
        let binding = tunnel
            .binding_key(TargetHop::LastHop)
            .await
            .context("the introduction circuit has no state")?
            .ok_or_else(|| anyhow!("the introduction circuit has no binding key"))?;

        let body = EstablishIntroDetails::new(ed25519::Ed25519Identity::from(
            keys.session_id.as_ref().verifying_key(),
        ))
        .sign_and_encode(keys.session_id.as_ref(), binding.hs_mac())
        .context("failed to sign ESTABLISH_INTRO")?;

        let (established_tx, established) = oneshot::channel();
        tunnel
            .start_conversation(
                Some(AnyRelayMsg::Unrecognized(Unrecognized::new(
                    RelayCmd::ESTABLISH_INTRO,
                    body,
                ))),
                IntroPointHandler {
                    established: Some(established_tx),
                    keys: Arc::clone(&keys),
                    introduce,
                },
                TargetHop::LastHop,
            )
            .await
            .context("failed to send ESTABLISH_INTRO")?;
        established
            .await
            .map_err(|_| anyhow!("the introduction point closed the circuit without acknowledging"))?;

        let descriptor = IntroPointDesc::builder()
            .link_specifiers(
                target
                    .linkspecs()
                    .map_err(|e| anyhow!("failed to encode the introduction point: {e}"))?,
            )
            .ipt_kp_ntor(*target.ntor_onion_key())
            .kp_hs_ipt_sid(keys.session_id_key.clone())
            .kp_hss_ntor(keys.ntor.public().clone())
            .build()
            .map_err(|e| anyhow!("failed to describe the introduction point: {e}"))?;

        Ok(EstablishedIntroPoint {
            // Always present: the target came from the directory, which
            // does not list a relay without an Ed25519 identity.
            relay: *target
                .ed_identity()
                .ok_or_else(|| anyhow!("the introduction point has no Ed25519 identity"))?,
            tunnel,
            descriptor,
        })
    }

    /// Sign a descriptor for every live time period and store it on the HSDirs
    /// responsible for it.
    async fn publish(self: &Arc<Self>, intro_points: &[IntroPointDesc]) -> Result<()> {
        let netdir = self.timely_netdir()?;
        let now = SystemTime::now();
        // The ring a client searches right now. The others are the rollover
        // ones a service publishes to in advance, or has just come off; a
        // descriptor on those alone is one nobody looks for.
        let current_period = netdir.hs_time_period();
        let mut stored_on_current_ring = false;
        let mut last_error = None;
        let mut published = Vec::new();

        for params in netdir.hs_all_time_periods() {
            let period = params.time_period();
            let (blind_key, blind_keypair, subcredential) = self
                .identity
                .compute_blinded_key(period)
                .map_err(|e| anyhow!("failed to blind the service key: {e}"))?;

            self.remember_subcredential(period, subcredential);
            published.push(period);

            let descriptor = {
                let mut rng = rand::rng();
                build_descriptor(
                    &blind_key,
                    &blind_keypair,
                    &subcredential,
                    intro_points,
                    &params,
                    now,
                    &mut rng,
                )
            };
            // One unusable time period must not cost us the others: the ring
            // that matters is `current_period`, and the loop is still to reach
            // it or has already passed it.
            let descriptor = match descriptor {
                Ok(descriptor) => descriptor,
                Err(error) => {
                    log::warn!("failed to build a descriptor for {period:?}: {error:#}");
                    if period == current_period {
                        last_error = Some(error);
                    }
                    continue;
                }
            };

            let blind_id: HsBlindId = blind_key.id();
            match self.upload(&netdir, blind_id, period, &descriptor).await {
                Ok(()) => stored_on_current_ring |= period == current_period,
                Err(error) => {
                    log::warn!("failed to publish for time period {period:?}: {error:#}");
                    if period == current_period {
                        last_error = Some(error);
                    }
                }
            }
        }

        self.forget_stale_subcredentials(&published);

        if stored_on_current_ring {
            Ok(())
        } else {
            Err(last_error
                .unwrap_or_else(|| anyhow!("no HSDir accepted the descriptor"))
                .context(
                    "the descriptor did not reach the hash ring clients are searching now",
                ))
        }
    }

    /// Store one descriptor on every HSDir responsible for `blind_id`.
    ///
    /// A client asks the relays of one replica after another until one serves
    /// the descriptor, so a single HSDir accepting it already makes the
    /// address reachable; the rest are what a client falls back on.
    async fn upload(
        self: &Arc<Self>,
        netdir: &Arc<NetDir>,
        blind_id: HsBlindId,
        period: TimePeriod,
        descriptor: &str,
    ) -> Result<()> {
        let hsdirs: Vec<OwnedCircTarget> = netdir
            .hs_dirs_upload(blind_id, period)
            .map_err(|e| anyhow!("failed to work out which HSDirs to use: {e}"))?
            .map(|relay| OwnedCircTarget::from_circ_target(&relay))
            .collect();
        if hsdirs.is_empty() {
            bail!("the directory lists no HSDirs for this service");
        }

        // All at once, and resolve on the first success. One HSDir holding the
        // descriptor already makes the address reachable, and the rest are
        // only a fallback for when that one has forgotten it — so making the
        // caller wait for all of them would put the slowest HSDir on the path
        // to `ready`, twice over, once per time period. The uploads that are
        // still running when this returns carry on in the background.
        let total = hsdirs.len();
        let (result_tx, mut results) = mpsc::channel(total);
        for hsdir in hsdirs {
            let service = Arc::clone(self);
            let netdir = Arc::clone(netdir);
            let descriptor = descriptor.to_owned();
            let mut result_tx = result_tx.clone();
            tokio::spawn(async move {
                let outcome = tokio::time::timeout(
                    UPLOAD_TIMEOUT,
                    service.upload_to(&netdir, &hsdir, &descriptor),
                )
                .await;
                let outcome = match outcome {
                    Ok(result) => result,
                    Err(_) => Err(anyhow!("the HSDir did not answer in {UPLOAD_TIMEOUT:?}")),
                };
                if let Err(error) = &outcome {
                    log::debug!("an HSDir did not store the descriptor: {error:#}");
                }
                // Fails once publishing has moved on without this upload,
                // which is the point of running it out here.
                let _ = futures_util::SinkExt::send(&mut result_tx, outcome).await;
            });
        }
        // Otherwise the loop below would never see the end of the uploads.
        drop(result_tx);

        let mut refused = 0;
        let mut last_error = None;
        while let Some(outcome) = results.next().await {
            match outcome {
                Ok(()) => {
                    log::info!("descriptor stored on an HSDir; {total} were asked");
                    return Ok(());
                }
                Err(error) => {
                    refused += 1;
                    last_error = Some(error);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| anyhow!("no HSDir accepted the descriptor"))
            .context(format!("all {refused} HSDirs refused the descriptor")))
    }

    /// Store the descriptor on one HSDir.
    async fn upload_to(
        self: &Arc<Self>,
        netdir: &Arc<NetDir>,
        hsdir: &OwnedCircTarget,
        descriptor: &str,
    ) -> Result<()> {
        let tunnel = self
            .hs_pool
            .get_or_launch_svc_dir(netdir, hsdir.clone())
            .await
            .context("failed to build a circuit to the HSDir")?;
        let mut stream = tunnel
            .begin_dir_stream()
            .await
            .context("failed to open a directory stream to the HSDir")?;

        let request = HsDescUploadRequest::new(descriptor.into());
        let response = tor_dirclient::send_request(&self.runtime, &request, &mut stream, None)
            .await
            .context("the HSDir did not accept the descriptor")?;
        response
            .into_output_string()
            .context("the HSDir returned an error for the descriptor")?;
        Ok(())
    }

    /// Finish one client's handshake: answer at its rendezvous point and hand
    /// on every stream it opens.
    async fn serve_introduction(
        self: &Arc<Self>,
        keys: &IntroPointKeys,
        message: Introduce2,
    ) -> Result<()> {
        // An INTRODUCE2 we have already answered is a replay; answering it
        // again would open a second rendezvous circuit on somebody else's say-so.
        if !self.first_time_seen(&message) {
            bail!("ignoring a replayed introduction");
        }

        let subcredentials: Vec<Subcredential> = self
            .subcredentials
            .lock()
            .expect("poisoned lock")
            .iter()
            .map(|(_, subcredential)| *subcredential)
            .collect();

        let (keygen, rendezvous1_body, payload) = hs_ntor::server_receive_intro(
            &mut rand::rng(),
            &keys.ntor,
            &keys.session_id_key,
            &subcredentials,
            message.encoded_header(),
            message.encrypted_body(),
        )
        .map_err(|e| anyhow!("the hs-ntor handshake failed: {e}"))?;

        let payload: IntroduceHandshakePayload = {
            let mut reader = tor_bytes::Reader::from_slice(&payload);
            // Not `should_be_exhausted`: the payload is padded to hide its size.
            reader
                .extract()
                .map_err(|e| anyhow!("the INTRODUCE2 payload could not be parsed: {e}"))?
        };
        let OnionKey::NtorOnionKey(ntor_key) = payload.onion_key() else {
            bail!("the client named a rendezvous point with an unsupported onion key");
        };
        let rendezvous_point = verbatim_target(payload.link_specifiers(), ntor_key)
            .context("the client named an unusable rendezvous point")?;

        let netdir = self.timely_netdir()?;
        let tunnel = Arc::new(
            tokio::time::timeout(
                RENDEZVOUS_TIMEOUT,
                self.hs_pool
                    .get_or_launch_svc_rend(&netdir, rendezvous_point),
            )
            .await
            .map_err(|_| anyhow!("building the rendezvous circuit timed out"))?
            .context("failed to build a circuit to the rendezvous point")?,
        );

        let rendezvous_hop = tunnel
            .last_hop()
            .map_err(|e| anyhow!("the rendezvous circuit has no hop: {e}"))?;
        let params = onion_circparams_from_netparams(netdir.params())
            .map_err(|e| anyhow!("failed to build circuit parameters: {e}"))?;
        tunnel
            .extend_virtual(
                RelayProtocol::HsV3,
                HandshakeRole::Responder,
                keygen,
                params,
                &Default::default(),
            )
            .await
            .context("failed to add the client hop")?;
        let client_hop = tunnel
            .last_hop()
            .map_err(|e| anyhow!("the rendezvous circuit has no virtual hop: {e}"))?;

        // Ask for BEGIN before RENDEZVOUS1 goes out, so the client's first
        // request cannot arrive before anything is listening for it.
        let mut requests = tunnel
            .allow_stream_requests(
                &[RelayCmd::BEGIN],
                client_hop,
                AcceptBegin {
                    max_streams: MAX_CONCURRENT_STREAMS,
                },
            )
            .await
            .context("failed to accept client streams")?
            .boxed();

        tunnel
            .send_raw_msg(
                Rendezvous1::new(*payload.cookie(), rendezvous1_body).into(),
                rendezvous_hop,
            )
            .await
            .context("failed to send RENDEZVOUS1")?;
        log::info!("a client circuit is open");

        let mut sender = self.requests.clone();
        while let Some(request) = requests.next().await {
            if futures_util::SinkExt::send(&mut sender, request).await.is_err() {
                // Nobody is accepting any more; the service is closing.
                break;
            }
        }
        Ok(())
    }

    /// The current directory, or an error saying we have none.
    fn timely_netdir(&self) -> Result<Arc<NetDir>> {
        self.netdir
            .netdir(Timeliness::Timely)
            .context("no usable Tor directory")
    }

    /// Record `subcredential` as one we will decrypt introductions against.
    ///
    /// Called before the descriptor naming it is stored, never after: a client
    /// that finds a descriptor must not be turned away because this side is
    /// not yet willing to decrypt what it sends.
    fn remember_subcredential(&self, period: TimePeriod, subcredential: Subcredential) {
        let mut held = self.subcredentials.lock().expect("poisoned lock");
        if !held.iter().any(|(known, _)| *known == period) {
            held.push((period, subcredential));
        }
    }

    /// Forget the subcredentials for periods that are now too old to be used.
    ///
    /// `published` is every period this round published for. A client can
    /// still be working from the period before the earliest of those — it may
    /// hold a descriptor fetched just before the rotation — so that one is
    /// kept and anything older is dropped.
    fn forget_stale_subcredentials(&self, published: &[TimePeriod]) {
        let Some(earliest) = published.iter().map(|p| p.interval_num()).min() else {
            return;
        };
        // Saturating: at interval zero there is nothing older to keep anyway.
        let oldest = earliest.saturating_sub(1);
        self.subcredentials
            .lock()
            .expect("poisoned lock")
            .retain(|(period, _)| period.interval_num() >= oldest);
    }

    /// Whether this introduction is one we have not answered before.
    fn first_time_seen(&self, message: &Introduce2) -> bool {
        use sha2::{Digest as _, Sha256};

        // The whole cell, so that a replay of a recorded INTRODUCE2 — the
        // thing this defends against — hashes to what we already hold, while
        // two genuine clients never collide.
        let mut hasher = Sha256::new();
        hasher.update(message.encoded_header());
        hasher.update(message.encrypted_body());
        let digest: [u8; 32] = hasher.finalize().into();

        let mut seen = self.seen.lock().expect("poisoned lock");
        if seen.len() >= REPLAY_CAPACITY {
            // Far beyond what a real transfer produces. Forgetting everything
            // is safe in the direction that matters: a client whose
            // introduction is forgotten simply gets served again.
            log::warn!("the introduction replay set is full; clearing it");
            seen.clear();
        }
        seen.insert(digest)
    }
}

/// How `intro_points` are named in the descriptor.
fn descriptors_of(intro_points: &[EstablishedIntroPoint]) -> Vec<IntroPointDesc> {
    intro_points
        .iter()
        .map(|point| point.descriptor.clone())
        .collect()
}

/// The keys that identify this service at one introduction point.
struct IntroPointKeys {
    /// Signs `ESTABLISH_INTRO`, and identifies us to that relay.
    session_id: HsIntroPtSessionIdKeypair,
    /// The public half, which also goes in the descriptor.
    session_id_key: HsIntroPtSessionIdKey,
    /// The key a client encrypts its `INTRODUCE1` to.
    ntor: HsSvcNtorKeypair,
}

/// An introduction point that has acknowledged `ESTABLISH_INTRO`.
struct EstablishedIntroPoint {
    /// Which relay this is, so that a replacement for some other introduction
    /// point is not established at the same one.
    relay: ed25519::Ed25519Identity,
    /// Held open for as long as the service runs: dropping it retires the
    /// introduction point.
    tunnel: Arc<tor_circmgr::ServiceOnionServiceIntroTunnel>,
    /// How this introduction point is described in the descriptor.
    descriptor: IntroPointDesc,
}

/// Encode and sign the descriptor that advertises `intro_points`.
#[allow(clippy::too_many_arguments)]
fn build_descriptor<R: rand::Rng + rand::CryptoRng>(
    blind_key: &tor_hscrypto::pk::HsBlindIdKey,
    blind_keypair: &tor_hscrypto::pk::HsBlindIdKeypair,
    subcredential: &Subcredential,
    intro_points: &[IntroPointDesc],
    params: &tor_netdir::HsDirParams,
    now: SystemTime,
    rng: &mut R,
) -> Result<String> {
    let signing_key = ed25519::Keypair::generate(rng);
    let certificate =
        create_desc_sign_key_cert(&signing_key.verifying_key(), blind_keypair, now + CERT_LIFETIME)
            .map_err(|e| anyhow!("failed to certify the descriptor signing key: {e}"))?;

    // Descriptors for the same blinded identity are ordered by this counter,
    // and an HSDir keeps the copy it already holds unless a new one raises it,
    // so it has to grow across every republication.
    //
    // rend-spec-v3 does not let it be the plain time: an HSDir that could read
    // the clock inside it would learn this host's clock skew, which is a
    // fingerprint that survives across otherwise unrelated services. The
    // "encrypted time in period" scheme keeps the ordering while hiding the
    // offset it was made from, and it is order-preserving so that the same
    // service run twice still produces comparable counters. The key is the
    // blinded identity's secret, exactly as `tor-hsservice` derives it.
    let ope_key = AesOpeKey::from_secret(&blind_keypair.as_ref().to_secret_key_bytes()[0..32]);
    let offset = params.offset_within_srv_period(now).ok_or_else(|| {
        anyhow!("the clock is before the start of this time period's shared random value")
    })?;
    let revision = ope_key.encrypt(offset);

    HsDescBuilder::default()
        .blinded_id(blind_key)
        .hs_desc_sign(&signing_key)
        .hs_desc_sign_cert(certificate)
        .create2_formats(CREATE2_FORMATS)
        .auth_required(None)
        .is_single_onion_service(false)
        .intro_points(intro_points)
        .intro_auth_key_cert_expiry(now + CERT_LIFETIME)
        .intro_enc_key_cert_expiry(now + CERT_LIFETIME)
        .lifetime(((DESCRIPTOR_LIFETIME.as_secs() / 60) as u16).into())
        .revision_counter(RevisionCounter::from(revision))
        .subcredential(*subcredential)
        .auth_clients(None)
        .build_sign(rng)
        .map_err(|e| anyhow!("failed to sign the descriptor: {e}"))
}

/// Build a circuit target from the link specifiers a client sent verbatim.
///
/// The rendezvous point has to be reached exactly as the client described it,
/// including any link specifier we do not understand: rewriting the list from
/// our own directory would produce a different EXTEND and the client would
/// never see us arrive.
fn verbatim_target(
    link_specifiers: &[EncodedLinkSpec],
    ntor_onion_key: &tor_llcrypto::pk::curve25519::PublicKey,
) -> Result<VerbatimLinkSpecCircTarget<OwnedCircTarget>> {
    let chan_target =
        OwnedChanTargetBuilder::from_encoded_linkspecs(Strictness::Standard, link_specifiers)
            .map_err(|e| anyhow!("not a valid target: {e}"))?;
    let mut builder = OwnedCircTarget::builder();
    *builder.chan_target() = chan_target;
    builder
        .ntor_onion_key(*ntor_onion_key)
        .protocols(tor_protover::Protocols::default());
    let target = builder
        .build()
        .map_err(|e| anyhow!("not a valid target: {e}"))?;
    Ok(VerbatimLinkSpecCircTarget::new(
        target,
        link_specifiers.to_vec(),
    ))
}

/// Accepts `BEGIN` until a client has too many streams open at once.
#[derive(Clone, Debug)]
struct AcceptBegin {
    /// The cap.
    max_streams: usize,
}

impl IncomingStreamRequestFilter for AcceptBegin {
    fn disposition(
        &mut self,
        _context: &IncomingStreamRequestContext<'_>,
        circuit: &tor_proto::circuit::CircHopSyncView<'_>,
    ) -> tor_proto::Result<IncomingStreamRequestDisposition> {
        if circuit.n_open_streams() >= self.max_streams {
            Ok(IncomingStreamRequestDisposition::CloseCircuit)
        } else {
            Ok(IncomingStreamRequestDisposition::Accept)
        }
    }
}

/// Handles what an introduction point sends back: one `INTRO_ESTABLISHED`,
/// then an `INTRODUCE2` for every client that asks for us there.
struct IntroPointHandler {
    /// Fired once, when the introduction point acknowledges us.
    established: Option<oneshot::Sender<()>>,
    /// The keys this introduction point knows us by.
    keys: Arc<IntroPointKeys>,
    /// Where introductions are handed to the service task.
    introduce: mpsc::Sender<(Arc<IntroPointKeys>, Introduce2)>,
}

impl MsgHandler for IntroPointHandler {
    fn handle_msg(&mut self, msg: AnyRelayMsg) -> tor_proto::Result<MetaCellDisposition> {
        match msg {
            AnyRelayMsg::IntroEstablished(_) => match self.established.take() {
                Some(sender) => {
                    let _ = sender.send(());
                    Ok(MetaCellDisposition::Consumed)
                }
                None => Err(tor_proto::Error::CircProto(
                    "duplicate INTRO_ESTABLISHED".to_string(),
                )),
            },
            AnyRelayMsg::Introduce2(message) => {
                if self.established.is_some() {
                    return Err(tor_proto::Error::CircProto(
                        "INTRODUCE2 before INTRO_ESTABLISHED".to_string(),
                    ));
                }
                match self.introduce.try_send((Arc::clone(&self.keys), message)) {
                    Ok(()) => Ok(MetaCellDisposition::Consumed),
                    // A full queue means the service is already busy; dropping
                    // the introduction leaves the client to retry, which is
                    // what it does anyway when a service is overloaded.
                    Err(error) if error.is_full() => {
                        log::warn!("dropped an INTRODUCE2: the service is busy");
                        Ok(MetaCellDisposition::Consumed)
                    }
                    Err(_) => Ok(MetaCellDisposition::CloseCirc),
                }
            }
            other => Err(tor_proto::Error::CircProto(format!(
                "unexpected {} on an introduction circuit",
                other.cmd()
            ))),
        }
    }
}
