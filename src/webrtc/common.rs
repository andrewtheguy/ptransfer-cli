//! Sans-I/O WebRTC peer and data-channel adapter.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use bytes::{Bytes, BytesMut};
use rtc::data_channel::{RTCDataChannelId, RTCDataChannelInit};
use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::setting_engine::{SctpMaxMessageSize, SettingEngine};
use rtc::peer_connection::event::{RTCDataChannelEvent, RTCPeerConnectionEvent};
use rtc::peer_connection::message::RTCMessage;
use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::state::{RTCIceConnectionState, RTCPeerConnectionState};
use rtc::peer_connection::transport::{
    CandidateConfig, CandidateHostConfig, CandidateServerReflexiveConfig, RTCIceCandidate,
    RTCIceCandidateInit,
};
use rtc::sansio::Protocol;
use rtc::shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc, oneshot, watch};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
const DATAGRAM_BUFFER_SIZE: usize = 65_536;
const BUFFERED_AMOUNT_LOW: u32 = 512 * 1024;
const BUFFERED_AMOUNT_HIGH: u32 = 1024 * 1024;
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

enum PeerCommand {
    CreateDataChannel {
        label: String,
        response: oneshot::Sender<std::result::Result<ChannelParts, String>>,
    },
    CreateOffer(oneshot::Sender<std::result::Result<RTCSessionDescription, String>>),
    CreateAnswer(oneshot::Sender<std::result::Result<RTCSessionDescription, String>>),
    SetLocal {
        description: RTCSessionDescription,
        response: oneshot::Sender<std::result::Result<(), String>>,
    },
    SetRemote {
        description: RTCSessionDescription,
        response: oneshot::Sender<std::result::Result<(), String>>,
    },
    AddRemoteCandidate {
        candidate: RTCIceCandidateInit,
        response: oneshot::Sender<std::result::Result<(), String>>,
    },
    Send {
        channel_id: RTCDataChannelId,
        data: Bytes,
        is_string: bool,
        response: oneshot::Sender<std::result::Result<(), String>>,
    },
    /// Whether a channel negotiated ordered delivery. On the answering side
    /// this reflects the DCEP the offerer sent, which is what makes it worth
    /// asking: both receivers append in wire order and reject an out-of-order
    /// index, so an unordered channel corrupts every multi-chunk transfer on a
    /// path that ever retransmits.
    IsOrdered {
        channel_id: RTCDataChannelId,
        response: oneshot::Sender<std::result::Result<bool, String>>,
    },
    Close(oneshot::Sender<std::result::Result<(), String>>),
}

struct ChannelParts {
    id: RTCDataChannelId,
    label: String,
    message_rx: mpsc::UnboundedReceiver<DcMessage>,
    opened_rx: watch::Receiver<bool>,
    closed: Arc<AtomicBool>,
    send_allowed: Arc<AtomicBool>,
    send_ready: Arc<Notify>,
}

struct WorkerChannel {
    message_tx: mpsc::UnboundedSender<DcMessage>,
    opened_tx: watch::Sender<bool>,
    closed: Arc<AtomicBool>,
    send_allowed: Arc<AtomicBool>,
    send_ready: Arc<Notify>,
}

struct WorkerContext {
    command_tx: mpsc::Sender<PeerCommand>,
    data_channel_tx: mpsc::Sender<RtcDataChannel>,
    connection_state: Arc<RwLock<RTCPeerConnectionState>>,
    ice_connection_state: Arc<RwLock<RTCIceConnectionState>>,
    connection_info: Arc<RwLock<WebRtcConnectionInfo>>,
}

struct InboundDatagram {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    message: BytesMut,
}

struct PeerNetwork {
    sockets: Vec<Arc<UdpSocket>>,
    routes: HashMap<SocketAddr, usize>,
    inbound_rx: mpsc::Receiver<InboundDatagram>,
    readers: Vec<tokio::task::JoinHandle<()>>,
}

fn new_channel_parts(
    id: RTCDataChannelId,
    label: String,
) -> (ChannelParts, WorkerChannel) {
    let (message_tx, message_rx) = mpsc::unbounded_channel();
    let (opened_tx, opened_rx) = watch::channel(false);
    let closed = Arc::new(AtomicBool::new(false));
    let send_allowed = Arc::new(AtomicBool::new(true));
    let send_ready = Arc::new(Notify::new());
    (
        ChannelParts {
            id,
            label: label.clone(),
            message_rx,
            opened_rx,
            closed: closed.clone(),
            send_allowed: send_allowed.clone(),
            send_ready: send_ready.clone(),
        },
        WorkerChannel {
            message_tx,
            opened_tx,
            closed,
            send_allowed,
            send_ready,
        },
    )
}

/// WebRTC peer connection driven by a Tokio UDP event loop.
pub struct WebRtcPeer {
    command_tx: mpsc::Sender<PeerCommand>,
    candidates: Vec<RTCIceCandidateInit>,
    data_channel_rx: Option<mpsc::Receiver<RtcDataChannel>>,
    connection_state: Arc<RwLock<RTCPeerConnectionState>>,
    ice_connection_state: Arc<RwLock<RTCIceConnectionState>>,
    connection_info: Arc<RwLock<WebRtcConnectionInfo>>,
}

impl WebRtcPeer {
    pub async fn new(ice_gather_timeout: Duration) -> Result<Self> {
        let ice_deadline = Instant::now() + ice_gather_timeout;
        let sockets = bind_candidate_sockets().await?;
        let mut routes = HashMap::new();
        let mut candidates = Vec::new();
        for (socket_index, socket) in sockets.iter().enumerate() {
            let local_addr = socket.local_addr()?;
            routes.insert(local_addr, socket_index);

            let host_candidate = CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "udp".to_owned(),
                    address: local_addr.ip().to_string(),
                    port: local_addr.port(),
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()
            .context("Failed to create local ICE candidate")?;
            candidates.push(
                RTCIceCandidate::from(&host_candidate)
                    .to_json()
                    .context("Failed to serialize local ICE candidate")?,
            );

            for (mapped_addr, stun_server) in
                gather_server_reflexive_candidates(socket, ice_deadline).await
            {
                routes.insert(mapped_addr, socket_index);
                let candidate = CandidateServerReflexiveConfig {
                    base_config: CandidateConfig {
                        network: "udp".to_owned(),
                        address: mapped_addr.ip().to_string(),
                        port: mapped_addr.port(),
                        component: 1,
                        ..Default::default()
                    },
                    rel_addr: local_addr.ip().to_string(),
                    rel_port: local_addr.port(),
                    url: Some(format!("stun:{stun_server}")),
                }
                .new_candidate_server_reflexive()
                .context("Failed to create server-reflexive ICE candidate")?;
                let mut candidate = RTCIceCandidate::from(&candidate)
                    .to_json()
                    .context("Failed to serialize server-reflexive ICE candidate")?;
                candidate.url = Some(format!("stun:{stun_server}"));
                if !candidates
                    .iter()
                    .any(|existing| existing.candidate == candidate.candidate)
                {
                    candidates.push(candidate);
                }
            }
        }

        let mut setting_engine = SettingEngine::default();
        setting_engine.set_sctp_max_message_size(SctpMaxMessageSize::Unbounded);
        let mut peer_connection = RTCPeerConnectionBuilder::new()
            .with_setting_engine(setting_engine)
            .build()
            .context("Failed to create peer connection")?;
        for candidate in &candidates {
            peer_connection
                .add_local_candidate(candidate.clone())
                .context("Failed to add local ICE candidate")?;
        }

        let (command_tx, command_rx) = mpsc::channel(32);
        let (data_channel_tx, data_channel_rx) = mpsc::channel(1);
        let connection_state = Arc::new(RwLock::new(RTCPeerConnectionState::New));
        let ice_connection_state = Arc::new(RwLock::new(RTCIceConnectionState::New));
        let local_addr = sockets[0].local_addr()?;
        let connection_info = Arc::new(RwLock::new(WebRtcConnectionInfo {
            connection_type: "Unknown".to_owned(),
            local_address: Some(local_addr.to_string()),
            remote_address: None,
        }));

        let network = start_peer_network(sockets, routes);
        tokio::spawn(run_peer(peer_connection, network, command_rx, WorkerContext {
            command_tx: command_tx.clone(),
            data_channel_tx,
            connection_state: connection_state.clone(),
            ice_connection_state: ice_connection_state.clone(),
            connection_info: connection_info.clone(),
        }));

        Ok(Self {
            command_tx,
            candidates,
            data_channel_rx: Some(data_channel_rx),
            connection_state,
            ice_connection_state,
            connection_info,
        })
    }

    pub fn take_data_channel_rx(&mut self) -> Option<mpsc::Receiver<RtcDataChannel>> {
        self.data_channel_rx.take()
    }

    pub async fn gather_ice_candidates(&mut self) -> Result<Vec<RTCIceCandidateInit>> {
        let public_candidate = self
            .candidates
            .iter()
            .any(|candidate| candidate.candidate.contains(" typ srflx"));
        crate::ui::status(&format!(
            "Gathered {} network candidate(s){}.",
            self.candidates.len(),
            if public_candidate {
                ", including a public address"
            } else {
                "; public-address discovery failed"
            }
        ));
        Ok(self.candidates.clone())
    }

    pub async fn create_data_channel(&self, label: &str) -> Result<RtcDataChannel> {
        let (response, rx) = oneshot::channel();
        self.command_tx
            .send(PeerCommand::CreateDataChannel {
                label: label.to_owned(),
                response,
            })
            .await
            .context("Peer connection closed")?;
        let parts = receive_response(rx, "create data channel").await?;
        eprintln!("Created data channel: {label}");
        Ok(RtcDataChannel::new(parts, self.command_tx.clone()))
    }

    pub async fn create_offer(&self) -> Result<RTCSessionDescription> {
        let (tx, rx) = oneshot::channel();
        self.command_tx.send(PeerCommand::CreateOffer(tx)).await?;
        receive_response(rx, "create offer").await
    }

    pub async fn create_answer(&self) -> Result<RTCSessionDescription> {
        let (tx, rx) = oneshot::channel();
        self.command_tx.send(PeerCommand::CreateAnswer(tx)).await?;
        receive_response(rx, "create answer").await
    }

    pub async fn set_local_description(&self, description: RTCSessionDescription) -> Result<()> {
        let (response, rx) = oneshot::channel();
        self.command_tx
            .send(PeerCommand::SetLocal {
                description,
                response,
            })
            .await?;
        receive_response(rx, "set local description").await
    }

    pub async fn set_remote_description(&self, description: RTCSessionDescription) -> Result<()> {
        let (response, rx) = oneshot::channel();
        self.command_tx
            .send(PeerCommand::SetRemote {
                description,
                response,
            })
            .await?;
        receive_response(rx, "set remote description").await
    }

    pub async fn add_ice_candidate(&self, candidate: RTCIceCandidateInit) -> Result<()> {
        let (response, rx) = oneshot::channel();
        self.command_tx
            .send(PeerCommand::AddRemoteCandidate {
                candidate,
                response,
            })
            .await?;
        receive_response(rx, "add ICE candidate").await
    }

    pub fn connection_state(&self) -> RTCPeerConnectionState {
        *self.connection_state.read().expect("connection state poisoned")
    }

    #[allow(dead_code)]
    pub fn ice_connection_state(&self) -> RTCIceConnectionState {
        *self
            .ice_connection_state
            .read()
            .expect("ICE connection state poisoned")
    }

    pub async fn get_connection_info(&self) -> WebRtcConnectionInfo {
        self.connection_info
            .read()
            .expect("connection info poisoned")
            .clone()
    }

    pub async fn close(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        if self.command_tx.send(PeerCommand::Close(tx)).await.is_err() {
            return Ok(());
        }
        receive_response(rx, "close peer connection").await
    }
}

async fn receive_response<T>(
    rx: oneshot::Receiver<std::result::Result<T, String>>,
    operation: &str,
) -> Result<T> {
    rx.await
        .with_context(|| format!("Peer connection stopped while trying to {operation}"))?
        .map_err(anyhow::Error::msg)
}

async fn run_peer(
    mut peer: rtc::peer_connection::RTCPeerConnection,
    mut network: PeerNetwork,
    mut command_rx: mpsc::Receiver<PeerCommand>,
    context: WorkerContext,
) {
    let mut channels = HashMap::<RTCDataChannelId, WorkerChannel>::new();

    'event_loop: loop {
        while let Some(transmit) = peer.poll_write() {
            let socket_index = network
                .routes
                .get(&transmit.transport.local_addr)
                .copied()
                .or_else(|| {
                    network.sockets.iter().position(|socket| {
                        socket
                            .local_addr()
                            .is_ok_and(|addr| addr.is_ipv4() == transmit.transport.peer_addr.is_ipv4())
                    })
                })
                .unwrap_or(0);
            if let Err(error) = network.sockets[socket_index]
                .send_to(&transmit.message, transmit.transport.peer_addr)
                .await
            {
                log::warn!("WebRTC UDP write failed: {error}");
            }
        }

        while let Some(event) = peer.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnConnectionStateChangeEvent(state) => {
                    *context.connection_state.write().expect("connection state poisoned") = state;
                    match state {
                        RTCPeerConnectionState::Connected => {
                            crate::ui::status("WebRTC connection established!");
                        }
                        RTCPeerConnectionState::Disconnected => {
                            crate::ui::status("WebRTC connection disconnected");
                        }
                        RTCPeerConnectionState::Failed => log::error!("WebRTC connection failed"),
                        RTCPeerConnectionState::Closed => {
                            crate::ui::status("WebRTC connection closed");
                        }
                        _ => {}
                    }
                }
                RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) => {
                    *context.ice_connection_state
                        .write()
                        .expect("ICE connection state poisoned") = state;
                    match state {
                        RTCIceConnectionState::Checking => {
                            crate::ui::status("Checking direct network routes...");
                        }
                        RTCIceConnectionState::Failed => {
                            log::error!("ICE failed: no direct network route reached the peer");
                        }
                        _ => {}
                    }
                }
                RTCPeerConnectionEvent::OnDataChannel(channel_event) => match channel_event {
                    RTCDataChannelEvent::OnOpen(id) => {
                        if let Some(channel) = channels.get(&id) {
                            let _ = channel.opened_tx.send(true);
                        } else if let Some(mut dc) = peer.data_channel(id) {
                            let label = dc.label().to_owned();
                            dc.set_buffered_amount_low_threshold(BUFFERED_AMOUNT_LOW);
                            dc.set_buffered_amount_high_threshold(BUFFERED_AMOUNT_HIGH);
                            let (parts, worker) = new_channel_parts(id, label);
                            let _ = worker.opened_tx.send(true);
                            channels.insert(id, worker);
                            if context.data_channel_tx
                                .send(RtcDataChannel::new(parts, context.command_tx.clone()))
                                .await
                                .is_err()
                            {
                                log::trace!("Incoming data-channel receiver closed");
                            }
                        }
                    }
                    RTCDataChannelEvent::OnClose(id) | RTCDataChannelEvent::OnError(id) => {
                        if let Some(channel) = channels.get(&id) {
                            channel.closed.store(true, Ordering::SeqCst);
                            channel.send_ready.notify_waiters();
                        }
                    }
                    RTCDataChannelEvent::OnBufferedAmountHigh(id) => {
                        if let Some(channel) = channels.get(&id) {
                            channel.send_allowed.store(false, Ordering::SeqCst);
                        }
                    }
                    RTCDataChannelEvent::OnBufferedAmountLow(id) => {
                        if let Some(channel) = channels.get(&id) {
                            channel.send_allowed.store(true, Ordering::SeqCst);
                            channel.send_ready.notify_waiters();
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        while let Some(message) = peer.poll_read() {
            if let RTCMessage::DataChannelMessage(id, message) = message
                && let Some(channel) = channels.get(&id)
            {
                let _ = channel.message_tx.send(DcMessage {
                    is_string: message.is_string,
                    data: message.data.freeze(),
                });
            }
        }

        let timeout = peer
            .poll_timeout()
            .unwrap_or_else(|| Instant::now() + DEFAULT_TIMEOUT);
        let delay = timeout.saturating_duration_since(Instant::now());
        if delay.is_zero() {
            if let Err(error) = peer.handle_timeout(Instant::now()) {
                log::error!("WebRTC timer failed: {error}");
                break;
            }
            continue;
        }
        let timer = tokio::time::sleep(delay);
        tokio::pin!(timer);

        tokio::select! {
            command = command_rx.recv() => {
                let Some(command) = command else { break };
                match command {
                    PeerCommand::CreateDataChannel { label, response } => {
                        // `ordered` MUST be set explicitly. `rtc` builds its
                        // parameters from a derived `Default`, so passing
                        // `None` here yields `ordered: false` — a *reliable
                        // unordered* channel, despite the crate's own doc
                        // claiming the default is ordered. Every message still
                        // arrives, but SCTP hands each one up the moment it
                        // reassembles, so a single retransmit lets a later
                        // chunk overtake an earlier one. Both receivers append
                        // in wire order and reject an out-of-order index, so
                        // that surfaces as "Unexpected streamed chunk index"
                        // mid-transfer on any lossy path. Loopback never
                        // reorders, which is why CLI-to-CLI never caught it.
                        let init = RTCDataChannelInit {
                            ordered: true,
                            ..Default::default()
                        };
                        let result = peer.create_data_channel(&label, Some(init))
                            .map(|mut dc| {
                                dc.set_buffered_amount_low_threshold(BUFFERED_AMOUNT_LOW);
                                dc.set_buffered_amount_high_threshold(BUFFERED_AMOUNT_HIGH);
                                (dc.id(), dc.label().to_owned())
                            })
                            .map_err(|error| error.to_string())
                            .map(|(id, label)| {
                                let (parts, worker) = new_channel_parts(id, label);
                                channels.insert(id, worker);
                                parts
                            });
                        let _ = response.send(result);
                    }
                    PeerCommand::CreateOffer(response) => {
                        let _ = response.send(peer.create_offer(None).map_err(|e| e.to_string()));
                    }
                    PeerCommand::CreateAnswer(response) => {
                        let _ = response.send(peer.create_answer(None).map_err(|e| e.to_string()));
                    }
                    PeerCommand::SetLocal { description, response } => {
                        let _ = response.send(peer.set_local_description(description).map_err(|e| e.to_string()));
                    }
                    PeerCommand::SetRemote { description, response } => {
                        let _ = response.send(peer.set_remote_description(description).map_err(|e| e.to_string()));
                    }
                    PeerCommand::AddRemoteCandidate { candidate, response } => {
                        let _ = response.send(peer.add_remote_candidate(candidate).map_err(|e| e.to_string()));
                    }
                    PeerCommand::Send { channel_id, data, is_string, response } => {
                        let result = peer.data_channel(channel_id)
                            .ok_or_else(|| "data channel is closed".to_owned())
                            .and_then(|mut dc| {
                                if is_string {
                                    let text = String::from_utf8(data.to_vec())
                                        .map_err(|e| e.to_string())?;
                                    dc.send_text(text).map_err(|e| e.to_string())
                                } else {
                                    dc.send(BytesMut::from(data.as_ref())).map_err(|e| e.to_string())
                                }
                            });
                        let _ = response.send(result);
                    }
                    PeerCommand::IsOrdered { channel_id, response } => {
                        let result = peer.data_channel(channel_id)
                            .map(|dc| dc.ordered())
                            .ok_or_else(|| "data channel is closed".to_owned());
                        let _ = response.send(result);
                    }
                    PeerCommand::Close(response) => {
                        let result = peer.close().map_err(|e| e.to_string());
                        let _ = response.send(result);
                        break 'event_loop;
                    }
                }
            }
            datagram = network.inbound_rx.recv() => {
                match datagram {
                    Some(datagram) => {
                        {
                            let mut info = context.connection_info.write().expect("connection info poisoned");
                            info.connection_type = "Direct (Host)".to_owned();
                            info.local_address = Some(datagram.local_addr.to_string());
                            info.remote_address = Some(datagram.remote_addr.to_string());
                        }
                        if let Err(error) = peer.handle_read(TaggedBytesMut {
                            now: Instant::now(),
                            transport: TransportContext {
                                local_addr: datagram.local_addr,
                                peer_addr: datagram.remote_addr,
                                ecn: None,
                                transport_protocol: TransportProtocol::UDP,
                            },
                            message: datagram.message,
                        }) {
                            log::debug!("Ignoring invalid WebRTC datagram: {error}");
                        }
                    }
                    None => {
                        log::error!("All WebRTC UDP readers stopped");
                        break;
                    }
                }
            }
            _ = timer.as_mut() => {
                if let Err(error) = peer.handle_timeout(Instant::now()) {
                    log::error!("WebRTC timer failed: {error}");
                    break;
                }
            }
        }
    }

    for channel in channels.values() {
        channel.closed.store(true, Ordering::SeqCst);
        channel.send_ready.notify_waiters();
    }
    for reader in network.readers {
        reader.abort();
    }
}

/// The address the OS would route to the internet over, one per IP family.
///
/// This is an ordering hint only: [`bind_candidate_sockets`] appends every
/// other usable address from `if_addrs`, so coverage never depends on it. It
/// exists so a host with several interfaces (VPN, container bridge, WSL) leads
/// with the one that actually reaches the internet.
///
/// Both families are probed because a host may route over only one of them, and
/// an unroutable family must contribute nothing rather than a placeholder — a
/// fabricated loopback address would be published to the peer as a host
/// candidate that can never connect. An empty result is fine: `if_addrs` still
/// supplies the addresses, and `bind_candidate_sockets` has its own last-resort
/// loopback bind for a host with no usable interface at all.
///
/// No packets are sent. `connect` on a UDP socket is a local route lookup, so
/// this stays safe offline.
fn discover_local_ips() -> Vec<IpAddr> {
    const PROBES: [(IpAddr, IpAddr); 2] = [
        (
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ),
        (
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
        ),
    ];

    PROBES
        .iter()
        .filter_map(|(bind_addr, probe_addr)| {
            let socket = std::net::UdpSocket::bind(SocketAddr::new(*bind_addr, 0)).ok()?;
            socket.connect(SocketAddr::new(*probe_addr, 3478)).ok()?;
            socket.local_addr().ok().map(|addr| addr.ip())
        })
        // A host that blackholes the probe address over `lo` would otherwise
        // hand back a loopback address, which is the one thing this must never
        // contribute.
        .filter(|ip| !ip.is_loopback())
        .collect()
}

async fn bind_candidate_sockets() -> Result<Vec<Arc<UdpSocket>>> {
    let mut ips = discover_local_ips();
    match if_addrs::get_if_addrs() {
        Ok(interfaces) => {
            for interface in interfaces {
                let ip = interface.ip();
                if interface.is_loopback()
                    || interface.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ips.contains(&ip)
                {
                    continue;
                }
                ips.push(ip);
            }
        }
        Err(error) => log::warn!("Failed to enumerate network interfaces: {error}"),
    }

    let mut sockets = Vec::new();
    for ip in ips {
        match UdpSocket::bind(SocketAddr::new(ip, 0)).await {
            Ok(socket) => sockets.push(Arc::new(socket)),
            Err(error) => log::debug!("Skipping unusable WebRTC interface {ip}: {error}"),
        }
    }
    if sockets.is_empty() {
        sockets.push(Arc::new(
            UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .context("Failed to bind any WebRTC UDP socket")?,
        ));
    }
    Ok(sockets)
}

fn start_peer_network(
    sockets: Vec<Arc<UdpSocket>>,
    routes: HashMap<SocketAddr, usize>,
) -> PeerNetwork {
    let (inbound_tx, inbound_rx) = mpsc::channel(256);
    let mut readers = Vec::with_capacity(sockets.len());
    for socket in &sockets {
        let socket = socket.clone();
        let inbound_tx = inbound_tx.clone();
        readers.push(tokio::spawn(async move {
            let Ok(local_addr) = socket.local_addr() else {
                return;
            };
            let mut buffer = vec![0; DATAGRAM_BUFFER_SIZE];
            loop {
                match socket.recv_from(&mut buffer).await {
                    Ok((size, remote_addr)) => {
                        if inbound_tx
                            .send(InboundDatagram {
                                local_addr,
                                remote_addr,
                                message: BytesMut::from(&buffer[..size]),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(error) => {
                        log::warn!("WebRTC UDP read failed on {local_addr}: {error}");
                        break;
                    }
                }
            }
        }));
    }
    drop(inbound_tx);
    PeerNetwork {
        sockets,
        routes,
        inbound_rx,
        readers,
    }
}

async fn gather_server_reflexive_candidates(
    socket: &UdpSocket,
    ice_deadline: Instant,
) -> Vec<(SocketAddr, String)> {
    let Ok(local_addr) = socket.local_addr() else {
        return Vec::new();
    };
    let local_is_ipv4 = local_addr.is_ipv4();
    let mut candidates = Vec::new();
    for server in STUN_SERVERS {
        let remaining = ice_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let Ok(Ok(resolved)) = tokio::time::timeout(
            remaining.min(Duration::from_millis(500)),
            tokio::net::lookup_host(*server),
        )
        .await
        else {
            continue;
        };
        let Some(server_addr) = resolved
            .into_iter()
            .find(|addr| addr.is_ipv4() == local_is_ipv4)
        else {
            continue;
        };

        let mut transaction_id = [0u8; 12];
        if getrandom::getrandom(&mut transaction_id).is_err() {
            return candidates;
        }
        let mut request = [0u8; 20];
        request[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
        request[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
        request[8..20].copy_from_slice(&transaction_id);
        if socket.send_to(&request, server_addr).await.is_err() {
            continue;
        }

        let mut response = [0u8; 1500];
        let probe_deadline = ice_deadline.min(Instant::now() + Duration::from_millis(700));
        loop {
            let remaining = probe_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let received = tokio::time::timeout(remaining, socket.recv_from(&mut response)).await;
            let Ok(Ok((length, source))) = received else {
                break;
            };
            if source != server_addr {
                continue;
            }
            let Some(mapped_addr) =
                parse_stun_binding_response(&response[..length], &transaction_id)
            else {
                continue;
            };
            if !candidates
                .iter()
                .any(|(existing, _)| *existing == mapped_addr)
            {
                candidates.push((mapped_addr, (*server).to_owned()));
            }
            break;
        }
    }
    candidates
}

fn parse_stun_binding_response(packet: &[u8], transaction_id: &[u8; 12]) -> Option<SocketAddr> {
    const MAGIC_COOKIE: u32 = 0x2112_A442;
    if packet.len() < 20
        || u16::from_be_bytes([packet[0], packet[1]]) != 0x0101
        || packet[4..8] != MAGIC_COOKIE.to_be_bytes()
        || packet[8..20] != transaction_id[..]
    {
        return None;
    }

    let attributes_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let end = 20usize.checked_add(attributes_length)?.min(packet.len());
    let mut offset: usize = 20;
    while offset.checked_add(4)? <= end {
        let attribute_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let length = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start.checked_add(length)?;
        if value_end > end {
            return None;
        }
        if attribute_type == 0x0020 && length >= 8 {
            let value = &packet[value_start..value_end];
            let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
            return match value[1] {
                0x01 if length >= 8 => {
                    let encoded = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                    Some(SocketAddr::new(IpAddr::V4((encoded ^ MAGIC_COOKIE).into()), port))
                }
                0x02 if length >= 20 => {
                    let mut mask = [0u8; 16];
                    mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                    mask[4..].copy_from_slice(transaction_id);
                    let mut address = [0u8; 16];
                    for (index, byte) in address.iter_mut().enumerate() {
                        *byte = value[4 + index] ^ mask[index];
                    }
                    Some(SocketAddr::new(IpAddr::V6(address.into()), port))
                }
                _ => None,
            };
        }
        offset = value_start + length.div_ceil(4) * 4;
    }
    None
}

#[derive(Debug, Clone)]
pub struct WebRtcConnectionInfo {
    pub connection_type: String,
    pub local_address: Option<String>,
    pub remote_address: Option<String>,
}

/// Handle for one `rtc` data channel.
pub struct RtcDataChannel {
    id: RTCDataChannelId,
    #[allow(dead_code)]
    label: String,
    command_tx: mpsc::Sender<PeerCommand>,
    message_rx: mpsc::UnboundedReceiver<DcMessage>,
    opened_rx: watch::Receiver<bool>,
    closed: Arc<AtomicBool>,
    send_allowed: Arc<AtomicBool>,
    send_ready: Arc<Notify>,
}

impl RtcDataChannel {
    fn new(parts: ChannelParts, command_tx: mpsc::Sender<PeerCommand>) -> Self {
        Self {
            id: parts.id,
            label: parts.label,
            command_tx,
            message_rx: parts.message_rx,
            opened_rx: parts.opened_rx,
            closed: parts.closed,
            send_allowed: parts.send_allowed,
            send_ready: parts.send_ready,
        }
    }

    async fn send(&self, data: Bytes, is_string: bool) -> Result<()> {
        loop {
            let notified = self.send_ready.notified();
            if self.closed.load(Ordering::SeqCst) {
                bail!("data channel is closed");
            }
            if self.send_allowed.load(Ordering::SeqCst) {
                break;
            }
            notified.await;
        }
        let (response, rx) = oneshot::channel();
        self.command_tx
            .send(PeerCommand::Send {
                channel_id: self.id,
                data,
                is_string,
                response,
            })
            .await
            .context("Peer connection closed")?;
        receive_response(rx, "send data-channel message").await
    }
}

#[derive(Debug, Clone)]
pub struct DcMessage {
    pub is_string: bool,
    pub data: Bytes,
}

/// Message-oriented transfer adapter over an `rtc` data channel.
pub struct DcMessenger {
    channel: RtcDataChannel,
}

impl DcMessenger {
    pub fn new(channel: RtcDataChannel) -> Self {
        Self { channel }
    }

    pub async fn recv(&mut self) -> Option<DcMessage> {
        self.channel.message_rx.recv().await
    }

    pub async fn send_binary(&self, data: Bytes) -> Result<()> {
        self.channel.send(data, false).await
    }

    pub async fn send_text(&self, text: impl Into<String>) -> Result<()> {
        self.channel
            .send(Bytes::from(text.into().into_bytes()), true)
            .await
    }

    pub fn buffered_amount(&self) -> usize {
        0
    }

    /// Whether the channel negotiated ordered delivery.
    pub async fn is_ordered(&self) -> Result<bool> {
        let (response, rx) = oneshot::channel();
        self.channel
            .command_tx
            .send(PeerCommand::IsOrdered {
                channel_id: self.channel.id,
                response,
            })
            .await
            .context("Peer connection closed")?;
        receive_response(rx, "query data-channel ordering").await
    }

    pub fn is_closed(&self) -> bool {
        self.channel.closed.load(Ordering::SeqCst)
    }
}

/// Wait until the sans-I/O worker reports that a channel is open.
pub async fn open_and_detach(
    mut data_channel: RtcDataChannel,
    timeout: Duration,
) -> Result<RtcDataChannel> {
    if *data_channel.opened_rx.borrow() {
        return Ok(data_channel);
    }

    tokio::time::timeout(timeout, async {
        loop {
            if data_channel.opened_rx.changed().await.is_err() {
                bail!("Data channel open signal was cancelled");
            }
            if *data_channel.opened_rx.borrow() {
                return Ok(data_channel);
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("Timed out waiting for the data channel to open"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe is an ordering hint, so an offline or single-stack host must
    /// simply contribute fewer addresses — never a placeholder. A loopback or
    /// duplicated entry here would be published to the peer as a host candidate
    /// that can never connect.
    #[test]
    fn discovered_ips_are_routable_and_one_per_family() {
        let ips = discover_local_ips();

        assert!(ips.len() <= 2, "at most one address per IP family");
        assert!(ips.iter().all(|ip| !ip.is_loopback()));
        assert!(ips.iter().all(|ip| !ip.is_unspecified()));
        assert!(ips.iter().filter(|ip| ip.is_ipv4()).count() <= 1);
        assert!(ips.iter().filter(|ip| ip.is_ipv6()).count() <= 1);
    }

    /// Every address the probe returns must be bindable, since
    /// `bind_candidate_sockets` turns each one into a UDP socket and a host
    /// candidate.
    #[tokio::test]
    async fn discovered_ips_are_bindable() {
        for ip in discover_local_ips() {
            UdpSocket::bind(SocketAddr::new(ip, 0))
                .await
                .unwrap_or_else(|error| panic!("probe returned unbindable {ip}: {error}"));
        }
    }
}
