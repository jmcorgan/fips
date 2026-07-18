//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

pub(crate) mod acl;
mod bloom;
pub(crate) mod context;
mod dataplane;
#[cfg(unix)]
pub(crate) mod decrypt_worker;
#[cfg(unix)]
pub(crate) mod encrypt_worker;
mod handlers;
mod lifecycle;
pub(crate) mod metrics;
mod peering;
mod rate_limit;
pub(crate) mod reject;
mod reloadable;
pub(crate) mod session;
pub(crate) mod stats;
pub(crate) mod stats_history;
#[cfg(test)]
mod tests;
mod tree;

use self::rate_limit::HandshakeRateLimiter;
use self::reloadable::Reloadable;

/// Half-range of the symmetric jitter applied to the per-session rekey timer.
/// Each session draws an offset uniformly from `[-REKEY_JITTER_SECS,
/// +REKEY_JITTER_SECS]` seconds at construction. Desynchronizes
/// dual-initiation in symmetric-start meshes; the configured
/// `node.rekey.after_secs` remains the nominal interval (mean preserved).
pub(crate) const REKEY_JITTER_SECS: i64 = 15;
use crate::cache::CoordCache;
use crate::node::session::SessionEntry;
use crate::peer::machine::{PeerMachine, TimerKind};
use crate::peer::{ActivePeer, PeerConnection};
use crate::proto::bloom::{BloomFilter, BloomState};
use crate::proto::fmp::Fmp;
use crate::proto::fmp::wire::{
    ESTABLISHED_HEADER_SIZE, FLAG_CE, FLAG_KEY_EPOCH, FLAG_SP, build_encrypted,
    build_established_header, prepend_inner_header,
};
use crate::proto::fsp::Fsp;
use crate::proto::lookup::{Lookup, LookupBackoff, LookupForwardRateLimiter};
use crate::proto::mmp::Mmp;
use crate::proto::routing::{self, Router, RoutingErrorRateLimiter};
use crate::proto::stp::TreeState;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::transport::ethernet::EthernetTransport;
use crate::transport::nym::NymTransport;
use crate::transport::tcp::TcpTransport;
use crate::transport::tor::TorTransport;
use crate::transport::udp::UdpTransport;
use crate::transport::{
    ConnectionState, Link, LinkId, PacketRx, PacketTx, TransportAddr, TransportError,
    TransportHandle, TransportId,
};
use crate::upper::hosts::HostMap;
use crate::upper::icmp_rate_limit::IcmpRateLimiter;
use crate::upper::tun::{TunError, TunOutboundTx, TunState, TunTx};
use crate::utils::index::IndexAllocator;
use crate::{Config, ConfigError, Identity, IdentityError, NodeAddr, PeerIdentity, TreeCoordinate};
use rand::Rng;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

/// Errors related to node operations.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("node not started")]
    NotStarted,

    #[error("node already started")]
    AlreadyStarted,

    #[error("node already stopped")]
    AlreadyStopped,

    #[error("transport not found: {0}")]
    TransportNotFound(TransportId),

    #[error("no transport available for type: {0}")]
    NoTransportForType(String),

    #[error("link not found: {0}")]
    LinkNotFound(LinkId),

    #[error("connection not found: {0}")]
    ConnectionNotFound(LinkId),

    #[error("peer not found: {0:?}")]
    PeerNotFound(NodeAddr),

    #[error("peer already exists: {0:?}")]
    PeerAlreadyExists(NodeAddr),

    #[error("connection already exists for link: {0}")]
    ConnectionAlreadyExists(LinkId),

    #[error("invalid peer npub '{npub}': {reason}")]
    InvalidPeerNpub { npub: String, reason: String },

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("max connections exceeded: {max}")]
    MaxConnectionsExceeded { max: usize },

    #[error("max peers exceeded: {max}")]
    MaxPeersExceeded { max: usize },

    #[error("max links exceeded: {max}")]
    MaxLinksExceeded { max: usize },

    #[error("handshake incomplete for link {0}")]
    HandshakeIncomplete(LinkId),

    #[error("no session available for link {0}")]
    NoSession(LinkId),

    #[error("promotion failed for link {link_id}: {reason}")]
    PromotionFailed { link_id: LinkId, reason: String },

    #[error("send failed to {node_addr}: {reason}")]
    SendFailed { node_addr: NodeAddr, reason: String },

    #[error("mtu exceeded forwarding to {node_addr}: packet {packet_size} > mtu {mtu}")]
    MtuExceeded {
        node_addr: NodeAddr,
        packet_size: usize,
        mtu: u16,
    },

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("TUN error: {0}")]
    Tun(#[from] TunError),

    #[error("index allocation failed: {0}")]
    IndexAllocationFailed(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("transport error: {0}")]
    TransportError(String),

    #[error("bootstrap handoff failed: {0}")]
    BootstrapHandoff(String),

    #[error("node start failed: no operational transports")]
    NoOperationalTransports,
}

/// Node operational state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeState {
    /// Created but not started.
    Created,
    /// Starting up (initializing transports).
    Starting,
    /// Fully operational — every configured child came up.
    Running,
    /// Operational but degraded: ≥1 transport is up and the
    /// node is serving, but one or more configured optional children (a
    /// transport beyond the first, Nostr, mDNS, TUN, DNS, or a worker pool)
    /// failed to start. Still operational — a degraded node serves traffic.
    Degraded,
    /// Bounded graceful drain in progress: a shutdown
    /// `Disconnect` has been broadcast and the node is waiting for peers to
    /// clear (bounded by `node.drain_timeout_secs`) before teardown. Not
    /// operational; the daemon drain path advances to `Stopping` via the
    /// supervisor's `DrainDeadlineElapsed`, never through `stop()`.
    Draining,
    /// Start failed fatally: zero transports came up. The
    /// driver tears down any children that did come up and `start()` returns
    /// an error. Not operational and not restartable in-process.
    Failed,
    /// Shutting down.
    Stopping,
    /// Stopped.
    Stopped,
}

impl NodeState {
    /// Check if node is operational. A `Degraded` node is operational — it is
    /// serving, just missing an optional child.
    pub fn is_operational(&self) -> bool {
        matches!(self, NodeState::Running | NodeState::Degraded)
    }

    /// Check if node can be started. A `Failed` node is not restartable
    /// in-process — only a fresh `Created` or a cleanly
    /// `Stopped` node can start.
    pub fn can_start(&self) -> bool {
        matches!(self, NodeState::Created | NodeState::Stopped)
    }

    /// Check if node can be stopped. Both `Running` and `Degraded` nodes are
    /// operational and can be stopped or drained.
    pub fn can_stop(&self) -> bool {
        matches!(self, NodeState::Running | NodeState::Degraded)
    }
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NodeState::Created => "created",
            NodeState::Starting => "starting",
            NodeState::Running => "running",
            NodeState::Degraded => "degraded",
            NodeState::Draining => "draining",
            NodeState::Failed => "failed",
            NodeState::Stopping => "stopping",
            NodeState::Stopped => "stopped",
        };
        write!(f, "{}", s)
    }
}

/// Reports what changed when replacing the runtime peer list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdatePeersOutcome {
    /// Peers present in the new list but not the previous list.
    pub added: usize,
    /// Peers removed from the previous list.
    pub removed: usize,
    /// Existing peers whose configured behavior changed.
    pub updated: usize,
    /// Existing peers whose comparable config did not change.
    pub unchanged: usize,
}

/// Key for addr_to_link reverse lookup.
type AddrKey = (TransportId, TransportAddr);

/// Per-transport kernel drop tracking for congestion detection.
///
/// Sampled every tick (1s). The `dropping` flag indicates whether new
/// kernel drops were observed since the previous sample.
#[derive(Debug, Default)]
struct TransportDropState {
    /// Previous `recv_drops` sample (cumulative counter).
    prev_drops: u64,
    /// True if drops increased since the last sample.
    dropping: bool,
}

/// State for a link waiting for transport-level connection establishment.
///
/// For connection-oriented transports (TCP, Tor), the transport connect runs
/// asynchronously. This struct holds the data needed to complete the handshake
/// once the connection is ready.
struct PendingConnect {
    /// The link that was created for this connection.
    link_id: LinkId,
    /// Which transport is being used.
    transport_id: TransportId,
    /// The remote address being connected to.
    remote_addr: TransportAddr,
    /// The peer identity (for handshake initiation).
    peer_identity: PeerIdentity,
}

/// A running FIPS node instance.
///
/// This is the top-level container holding all node state.
///
/// ## Peer Lifecycle
///
/// Peers go through two phases:
/// 1. **Connection phase**: Handshake in progress; the pending connection is
///    carried by its per-peer control machine (`peer_machines`), indexed by LinkId
/// 2. **Active phase** (`peers`): Authenticated, indexed by NodeAddr
///
/// The `addr_to_link` map enables dispatching incoming packets to the right
/// connection before authentication completes.
// Discovery lookup constants moved to config: node.lookup.attempt_timeouts_secs, node.lookup.ttl
pub struct Node {
    // === Immutable Context ===
    /// Shared immutable context bundle: the single source of truth for the
    /// node's effectively-immutable state (config/identity/startup_epoch/
    /// started_at/is_leaf_only/max_*). Mutated only by whole-`Arc` replacement
    /// via `replace_context` at the constructors, `leaf_only`, and
    /// `update_peers`; readers reach it through the accessors.
    context: Arc<context::NodeContext>,

    // === Lifecycle Supervisor ===
    /// Owner of the lifecycle-managed substrate handles (packet-send channel,
    /// TUN plumbing, DNS task, Nostr/LAN rendezvous, encrypt/decrypt worker
    /// pools) plus the published `NodeState` and the sans-IO supervisor FSM
    /// that authors their spawn/teardown ordering. Reached via
    /// `self.supervisor.*`.
    supervisor: lifecycle::supervisor::Supervisor,

    // === Spanning Tree ===
    /// Local spanning tree state.
    tree_state: TreeState,

    // === Bloom Filter ===
    /// Local Bloom filter state.
    bloom_state: BloomState,

    // === Routing ===
    /// Address -> coordinates cache (from session setup and discovery).
    coord_cache: CoordCache,
    /// Per-destination path MTU lookup, keyed by FipsAddress (mirrors
    /// `coord_cache.entries[*].path_mtu`). Sync read-only access from
    /// the TUN reader/writer threads at TCP MSS clamp time so the
    /// SYN/SYN-ACK clamp can use the smaller of the local-egress floor
    /// and the learned per-destination path MTU.
    path_mtu_lookup: Arc<std::sync::RwLock<HashMap<crate::FipsAddress, u16>>>,

    // === Transports & Links ===
    /// Active transports (owned by Node).
    transports: HashMap<TransportId, TransportHandle>,
    /// Per-transport kernel drop tracking for congestion detection.
    transport_drops: HashMap<TransportId, TransportDropState>,
    /// Active links.
    links: HashMap<LinkId, Link>,
    /// Reverse lookup: (transport_id, remote_addr) -> link_id.
    addr_to_link: HashMap<AddrKey, LinkId>,

    // === Packet Channel ===
    /// Packet receiver (for event loop).
    packet_rx: Option<PacketRx>,

    // === Child Exit Channel ===
    /// Sender half of the runtime child-liveness channel. Cloned into each
    /// directly-observable child (the TUN reader/writer threads, the DNS task,
    /// and the mDNS/Nostr liveness monitor) so a child self-reports its
    /// [`Child`](crate::node::lifecycle::supervisor::Child) when it exits. Held
    /// on `self` for the rx_loop's lifetime as the keep-alive sender so the
    /// receiver never observes a spuriously-closed channel.
    child_exit_tx: Option<tokio::sync::mpsc::Sender<crate::node::lifecycle::supervisor::Child>>,
    /// Receiver half of the runtime child-liveness channel, `take()`-en by the
    /// rx_loop select arm that feeds `Event::ChildExited` to the supervisor FSM.
    child_exit_rx: Option<tokio::sync::mpsc::Receiver<crate::node::lifecycle::supervisor::Child>>,

    // === Per-Peer Control Machines ===
    /// Per-peer lifecycle control FSMs, keyed by the stable `LinkId` that spans
    /// the handshake→active lifetime. Each machine owns its pending handshake
    /// connection (the `PeerConnection` leg) while the handshake is in
    /// progress — the single LinkId-keyed per-peer map on `Node`; `peers`
    /// stays byte-unchanged (hot path pristine).
    /// Machines are inserted at dial and inbound msg1, and stepped in production
    /// by the handshake handlers, the rekey-cadence and liveness-reap routers,
    /// and the lifecycle paths, with the executor (`dataplane/peer_actions.rs`)
    /// performing the returned actions. Timer FIRING decisions remain
    /// shell-side: `PeerEvent::Timeout` is never dispatched in production.
    peer_machines: HashMap<LinkId, PeerMachine>,

    /// Per-peer timer store, keyed by `LinkId` then `TimerKind`, holding each
    /// armed timer's absolute deadline (ms). The sans-IO time-as-input backing
    /// for `PeerEvent::Timeout`: populated/cleared by the machine's
    /// `SetTimer`/`CancelTimer` actions (`dataplane/peer_actions.rs`) and dropped
    /// alongside the machine through the `remove_peer_machine` choke-point. The
    /// `HandshakeRetransmit`/`HandshakeTimeout` kinds are driven by
    /// `drive_peer_timers` (the retransmit fires on the stored deadline; the
    /// timeout reap keys on the timer's presence, with the threshold read from
    /// config); the rekey/liveness kinds are still SHADOWS of their
    /// own shell drivers, and the machine's `on_timeout` handlers stay dormant
    /// (`PeerEvent::Timeout` is never dispatched in production).
    peer_timers: HashMap<LinkId, HashMap<TimerKind, u64>>,

    // === Peers (Active Phase) ===
    /// Authenticated peers.
    /// Indexed by NodeAddr (verified identity).
    peers: HashMap<NodeAddr, ActivePeer>,

    // === End-to-End Sessions ===
    /// Session table for end-to-end encrypted sessions.
    /// Keyed by remote NodeAddr.
    sessions: HashMap<NodeAddr, SessionEntry>,

    // === Identity Cache ===
    /// Maps FipsAddress prefix bytes (bytes 1-15) to (NodeAddr, PublicKey).
    /// Enables reverse lookup from IPv6 destination to session/routing identity.
    identity_cache: HashMap<[u8; 15], (NodeAddr, secp256k1::PublicKey, u64)>,

    // === Pending TUN Packets ===
    /// Packets queued while waiting for session establishment.
    /// Keyed by destination NodeAddr, bounded per-dest and total.
    pending_tun_packets: HashMap<NodeAddr, VecDeque<Vec<u8>>>,

    // === Discovery ===
    /// Discovery-subsystem state: recent-request dedup cache, in-flight
    /// lookups, originator-side backoff, and transit-side forward limiter.
    lookup: Lookup,

    // === Counters ===
    /// Next link ID to allocate.
    next_link_id: u64,
    /// Next transport ID to allocate.
    next_transport_id: u32,

    // === Node Statistics ===
    /// Routing, forwarding, discovery, and error signal counters.
    stats: stats::NodeStats,

    /// Lock-free atomic metric counters. Shadows `stats` during the
    /// counter migration; bumped alongside it with a parity check.
    metrics: std::sync::Arc<metrics::MetricsRegistry>,

    /// Time-series history of node-level metrics (1s/1m rings).
    stats_history: stats_history::StatsHistory,

    /// Read-side snapshot of `stats_history` plus the scalar gauges/counts
    /// `show_status` reports, published from the tick (the natural mutator)
    /// so those queries serve off the rx_loop. The dual-ring read copy: the
    /// live mutable `stats_history` above stays on the tick.
    stats_snapshot: std::sync::Arc<arc_swap::ArcSwap<crate::control::snapshot::StatsSnapshot>>,

    /// Read-side snapshot of the Category-D derived/routing/cache subsystems
    /// (tree / bloom / coord cache / identity cache + F-queue scalars) that the
    /// `show_tree` / `show_bloom` / `show_cache` / `show_routing` /
    /// `show_identity_cache` queries render off the rx_loop. Published from the
    /// tick (see [`Self::publish_routing_snapshot`] for the Q1 rationale).
    routing_snapshot: std::sync::Arc<arc_swap::ArcSwap<crate::control::snapshot::RoutingSnapshot>>,

    /// Read-side snapshot of the Category-E per-entity tables (peers / sessions
    /// / links / connections / transports + mmp) that the `show_peers` /
    /// `show_sessions` / `show_links` / `show_connections` / `show_transports`
    /// / `show_mmp` queries render off the rx_loop. Published from the tick with
    /// `Vec<Arc<Row>>` structural sharing (unchanged rows reused by pointer);
    /// see [`Self::publish_entities_snapshot`] for the Q1 rationale.
    entities_snapshot: std::sync::Arc<arc_swap::ArcSwap<crate::control::snapshot::EntitySnapshot>>,

    // === TUN Interface ===
    /// TUN device state.
    tun_state: TunState,
    /// TUN interface name (for cleanup).
    tun_name: Option<String>,

    // === Index-Based Session Dispatch ===
    /// Allocator for session indices.
    index_allocator: IndexAllocator,
    /// O(1) lookup: (transport_id, our_index) → NodeAddr.
    /// This maps our session index to the peer that uses it.
    peers_by_index: HashMap<(TransportId, u32), NodeAddr>,
    /// Pending outbound handshakes by our sender_idx.
    /// Tracks which LinkId corresponds to which session index.
    pending_outbound: HashMap<(TransportId, u32), LinkId>,

    // === Rate Limiting ===
    /// Rate limiter for msg1 processing (DoS protection).
    msg1_rate_limiter: HandshakeRateLimiter,
    /// Rate limiter for ICMP Packet Too Big messages.
    icmp_rate_limiter: IcmpRateLimiter,
    /// Routing-subsystem state (routing error-signal rate limiter).
    routing: Router,
    /// FMP connection-lifecycle decision anchor (stateless; drives the
    /// tick-poll maintain/teardown decisions).
    fmp: Fmp,
    /// FSP session-lifecycle decision anchor (stateless; drives the rekey /
    /// epoch-reaction decisions).
    fsp: Fsp,
    /// MMP reporting decision anchor (stateless; drives the report-fan-out /
    /// liveness / heartbeat decisions).
    mmp: Mmp,
    /// Rate limiter for source-side CoordsRequired/PathBroken responses.
    coords_response_rate_limiter: RoutingErrorRateLimiter,

    // === Peering Homeostasis ===
    /// Owner of the peering-reconciler state relocated off `Node`: the sans-IO
    /// retry-schedule core (`peering.reconciler.retry_pending`) and the pending
    /// transport connects (`peering.pending_connects`) awaiting transport-level
    /// connection establishment before handshake msg1 (for connection-oriented
    /// transports the transport connect runs in the background; the tick handler
    /// polls connection_state() and initiates the handshake when connected). The
    /// retry entries are created when a handshake times out or fails, and removed
    /// on successful promotion or when max retries are exhausted. Still driven by
    /// the imperative methods; the reconciler core is unwired until the driver
    /// cutover.
    peering: peering::reconcile::Peering,

    // === Periodic Parent Re-evaluation ===
    /// Timestamp of last periodic parent re-evaluation (for pacing).
    last_parent_reeval: Option<std::time::Instant>,

    // === Congestion Logging ===
    /// Timestamp of last congestion detection log (rate-limited to 5s).
    last_congestion_log: Option<std::time::Instant>,

    // === Mesh Size Estimate ===
    /// Cached estimated mesh size (computed once per tick from bloom filters).
    estimated_mesh_size: Option<u64>,
    /// Timestamp of last mesh size log emission.
    last_mesh_size_log: Option<std::time::Instant>,

    // === Bloom Self-Plausibility ===
    /// Rate-limit state for the self-plausibility WARN. Fires at most
    /// once per 60s globally when our own outgoing FilterAnnounce has
    /// an FPR above `node.bloom.max_inbound_fpr`, signalling either
    /// aggregation drift or an ingress bypass.
    last_self_warn: Option<std::time::Instant>,

    // === Display Names ===
    /// Human-readable names for configured peers (alias or short npub).
    /// Populated at startup from peer config.
    peer_aliases: HashMap<NodeAddr, String>,

    /// Reloadable peer ACL state from standard allow/deny files.
    peer_acl: acl::PeerAclReloader,

    // === Host Map ===
    /// Static hostname → npub mapping for DNS resolution.
    /// Built at construction from peer aliases and /etc/fips/hosts, and
    /// published through a lock-free snapshot for the display path.
    host_map: reloadable::HostMapReloadable,

    /// Sessions whose recv cipher + replay window have been handed
    /// off to a decrypt shard worker. Lookup gate on the hot receive
    /// path: if the cache-key is in here, dispatch to worker; else
    /// fall through to the legacy synchronous decrypt (test mode +
    /// not-yet-registered first packets).
    #[cfg(unix)]
    pub(crate) decrypt_registered_sessions: std::collections::HashSet<(TransportId, u32)>,

    /// Decrypt worker fallback channel: workers bounce
    /// authenticated-FMP-plaintext back here for the rx_loop to
    /// finish the per-peer side-effects (stats, MMP, ECN
    /// propagation, dispatch_link_message). `Option` so the receive
    /// end can be `take()`-en by the rx_loop arm.
    #[cfg(unix)]
    pub(crate) decrypt_fallback_rx:
        Option<tokio::sync::mpsc::UnboundedReceiver<decrypt_worker::DecryptWorkerEvent>>,
    #[cfg(unix)]
    pub(crate) decrypt_fallback_tx:
        tokio::sync::mpsc::UnboundedSender<decrypt_worker::DecryptWorkerEvent>,
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(config: Config) -> Result<Self, NodeError> {
        config.validate()?;
        let identity = config.create_identity()?;
        let node_addr = *identity.node_addr();
        let is_leaf_only = config.is_leaf_only();

        let mut startup_epoch = [0u8; 8];
        rand::rng().fill_bytes(&mut startup_epoch);

        let mut bloom_state = if is_leaf_only {
            BloomState::leaf_only(node_addr)
        } else {
            BloomState::new(node_addr)
        };
        bloom_state.set_update_debounce_ms(config.node.bloom.update_debounce_ms);

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let tree_now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut tree_state = TreeState::new(node_addr, tree_now_secs);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree::sign_declaration(tree_state.my_declaration_mut(), &identity)
            .expect("signing own declaration should never fail");

        let coord_cache = CoordCache::new(
            config.node.cache.coord_size,
            config.node.cache.coord_ttl_secs * 1000,
        );
        let rl = &config.node.rate_limit;
        let msg1_rate_limiter = HandshakeRateLimiter::with_params(
            rate_limit::TokenBucket::with_params(rl.handshake_burst, rl.handshake_rate),
            config.node.limits.max_pending_inbound,
        );

        let max_connections = config.node.limits.max_connections;
        let max_peers = config.node.limits.max_peers;
        let max_links = config.node.limits.max_links;
        let coords_response_interval_ms = config.node.session.coords_response_interval_ms;
        let backoff_base_secs = config.node.lookup.backoff_base_secs;
        let backoff_max_secs = config.node.lookup.backoff_max_secs;
        let forward_min_interval_secs = config.node.lookup.forward_min_interval_secs;

        let base_host_map = HostMap::from_peer_configs(config.peers());
        let hosts_path = std::path::PathBuf::from(crate::upper::hosts::DEFAULT_HOSTS_PATH);
        let host_map =
            reloadable::HostMapReloadable::new(base_host_map.clone(), hosts_path.clone());
        let peer_acl = acl::PeerAclReloader::with_alias_sources(
            std::path::PathBuf::from(acl::DEFAULT_PEERS_ALLOW_PATH),
            std::path::PathBuf::from(acl::DEFAULT_PEERS_DENY_PATH),
            base_host_map,
            hosts_path,
        );

        #[cfg(unix)]
        let (decrypt_fallback_tx, decrypt_fallback_rx) =
            tokio::sync::mpsc::unbounded_channel::<decrypt_worker::DecryptWorkerEvent>();

        let started_at = std::time::Instant::now();
        let context = Arc::new(context::NodeContext::new(
            Arc::new(config.clone()),
            identity.clone(),
            startup_epoch,
            started_at,
            is_leaf_only,
            max_connections,
            max_peers,
            max_links,
        ));

        Ok(Self {
            context,
            supervisor: lifecycle::supervisor::Supervisor::new(),
            tree_state,
            bloom_state,
            coord_cache,
            transports: HashMap::new(),
            transport_drops: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_rx: None,
            child_exit_tx: None,
            child_exit_rx: None,
            peer_machines: HashMap::new(),
            peer_timers: HashMap::new(),
            peers: HashMap::new(),
            sessions: HashMap::new(),
            identity_cache: HashMap::new(),
            pending_tun_packets: HashMap::new(),
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            metrics: std::sync::Arc::new(metrics::MetricsRegistry::new()),
            stats_history: stats_history::StatsHistory::new(),
            stats_snapshot: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::control::snapshot::StatsSnapshot::empty(),
            )),
            routing_snapshot: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::control::snapshot::RoutingSnapshot::empty(),
            )),
            entities_snapshot: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::control::snapshot::EntitySnapshot::empty(),
            )),
            tun_state,
            tun_name: None,
            index_allocator: IndexAllocator::new(),
            peers_by_index: HashMap::new(),
            pending_outbound: HashMap::new(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing: Router::new(),
            fmp: Fmp::new(),
            fsp: Fsp::new(),
            mmp: Mmp::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval_ms(
                coords_response_interval_ms,
            ),
            lookup: Lookup::new(
                LookupBackoff::with_params(backoff_base_secs, backoff_max_secs),
                LookupForwardRateLimiter::with_interval_ms(forward_min_interval_secs * 1000),
            ),
            peering: peering::reconcile::Peering::new(),
            last_parent_reeval: None,
            last_congestion_log: None,
            estimated_mesh_size: None,
            last_mesh_size_log: None,
            last_self_warn: None,
            peer_aliases: HashMap::new(),
            peer_acl,
            host_map,
            path_mtu_lookup: Arc::new(std::sync::RwLock::new(HashMap::new())),
            #[cfg(unix)]
            decrypt_registered_sessions: std::collections::HashSet::new(),
            #[cfg(unix)]
            decrypt_fallback_rx: Some(decrypt_fallback_rx),
            #[cfg(unix)]
            decrypt_fallback_tx,
        })
    }

    /// Create a node with a specific identity.
    ///
    /// This constructor validates cross-field config invariants before
    /// constructing the node, same as [`Node::new`].
    pub fn with_identity(identity: Identity, config: Config) -> Result<Self, NodeError> {
        config.validate()?;
        let node_addr = *identity.node_addr();

        let mut startup_epoch = [0u8; 8];
        rand::rng().fill_bytes(&mut startup_epoch);

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let tree_now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut tree_state = TreeState::new(node_addr, tree_now_secs);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree::sign_declaration(tree_state.my_declaration_mut(), &identity)
            .expect("signing own declaration should never fail");

        let mut bloom_state = BloomState::new(node_addr);
        bloom_state.set_update_debounce_ms(config.node.bloom.update_debounce_ms);

        let coord_cache = CoordCache::new(
            config.node.cache.coord_size,
            config.node.cache.coord_ttl_secs * 1000,
        );
        let rl = &config.node.rate_limit;
        let msg1_rate_limiter = HandshakeRateLimiter::with_params(
            rate_limit::TokenBucket::with_params(rl.handshake_burst, rl.handshake_rate),
            config.node.limits.max_pending_inbound,
        );

        let max_connections = config.node.limits.max_connections;
        let max_peers = config.node.limits.max_peers;
        let max_links = config.node.limits.max_links;
        let coords_response_interval_ms = config.node.session.coords_response_interval_ms;

        let base_host_map = HostMap::from_peer_configs(config.peers());
        let hosts_path = std::path::PathBuf::from(crate::upper::hosts::DEFAULT_HOSTS_PATH);
        let host_map =
            reloadable::HostMapReloadable::new(base_host_map.clone(), hosts_path.clone());
        let peer_acl = acl::PeerAclReloader::with_alias_sources(
            std::path::PathBuf::from(acl::DEFAULT_PEERS_ALLOW_PATH),
            std::path::PathBuf::from(acl::DEFAULT_PEERS_DENY_PATH),
            base_host_map,
            hosts_path,
        );

        #[cfg(unix)]
        let (decrypt_fallback_tx, decrypt_fallback_rx) =
            tokio::sync::mpsc::unbounded_channel::<decrypt_worker::DecryptWorkerEvent>();

        let started_at = std::time::Instant::now();
        let context = Arc::new(context::NodeContext::new(
            Arc::new(config.clone()),
            identity.clone(),
            startup_epoch,
            started_at,
            false,
            max_connections,
            max_peers,
            max_links,
        ));

        Ok(Self {
            context,
            supervisor: lifecycle::supervisor::Supervisor::new(),
            tree_state,
            bloom_state,
            coord_cache,
            transports: HashMap::new(),
            transport_drops: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_rx: None,
            child_exit_tx: None,
            child_exit_rx: None,
            peer_machines: HashMap::new(),
            peer_timers: HashMap::new(),
            peers: HashMap::new(),
            sessions: HashMap::new(),
            identity_cache: HashMap::new(),
            pending_tun_packets: HashMap::new(),
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            metrics: std::sync::Arc::new(metrics::MetricsRegistry::new()),
            stats_history: stats_history::StatsHistory::new(),
            stats_snapshot: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::control::snapshot::StatsSnapshot::empty(),
            )),
            routing_snapshot: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::control::snapshot::RoutingSnapshot::empty(),
            )),
            entities_snapshot: std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                crate::control::snapshot::EntitySnapshot::empty(),
            )),
            tun_state,
            tun_name: None,
            index_allocator: IndexAllocator::new(),
            peers_by_index: HashMap::new(),
            pending_outbound: HashMap::new(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing: Router::new(),
            fmp: Fmp::new(),
            fsp: Fsp::new(),
            mmp: Mmp::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval_ms(
                coords_response_interval_ms,
            ),
            lookup: Lookup::new(LookupBackoff::new(), LookupForwardRateLimiter::new()),
            peering: peering::reconcile::Peering::new(),
            last_parent_reeval: None,
            last_congestion_log: None,
            estimated_mesh_size: None,
            last_mesh_size_log: None,
            last_self_warn: None,
            peer_aliases: HashMap::new(),
            peer_acl,
            host_map,
            path_mtu_lookup: Arc::new(std::sync::RwLock::new(HashMap::new())),
            #[cfg(unix)]
            decrypt_registered_sessions: std::collections::HashSet::new(),
            #[cfg(unix)]
            decrypt_fallback_rx: Some(decrypt_fallback_rx),
            #[cfg(unix)]
            decrypt_fallback_tx,
        })
    }

    /// Create a leaf-only node (simplified state).
    pub fn leaf_only(config: Config) -> Result<Self, NodeError> {
        let mut node = Self::new(config)?;
        node.bloom_state = BloomState::leaf_only(*node.node_addr());
        node.replace_context(|ctx| ctx.is_leaf_only = true);
        Ok(node)
    }

    /// Create transport instances from configuration.
    ///
    /// Returns a vector of TransportHandles for all configured transports.
    async fn create_transports(&mut self, packet_tx: &PacketTx) -> Vec<TransportHandle> {
        let mut transports = Vec::new();

        // Collect UDP configs with optional names to avoid borrow conflicts
        let udp_instances: Vec<_> = self
            .config()
            .transports
            .udp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        // Create UDP transport instances
        for (name, udp_config) in udp_instances {
            let transport_id = self.allocate_transport_id();
            let udp = UdpTransport::new(transport_id, name, udp_config, packet_tx.clone());
            transports.push(TransportHandle::Udp(udp));
        }

        // Create Ethernet transport instances (Unix only — requires raw sockets)
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let eth_instances: Vec<_> = self
                .config()
                .transports
                .ethernet
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();
            let xonly = self.identity().pubkey();
            for (name, eth_config) in eth_instances {
                let transport_id = self.allocate_transport_id();
                let mut eth =
                    EthernetTransport::new(transport_id, name, eth_config, packet_tx.clone());
                eth.set_local_pubkey(xonly);
                transports.push(TransportHandle::Ethernet(eth));
            }
        }

        // Create TCP transport instances
        let tcp_instances: Vec<_> = self
            .config()
            .transports
            .tcp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        // Node-wide connection budget — used as the TCP inbound-cap fallback
        // when a TCP instance has no explicit `max_inbound_connections`, so
        // raising `node.limits.max_connections` actually raises the inbound
        // ceiling rather than being silently capped at the transport default.
        let node_max_connections = self.config().node.limits.max_connections;
        for (name, tcp_config) in tcp_instances {
            let transport_id = self.allocate_transport_id();
            let mut tcp = TcpTransport::new(transport_id, name, tcp_config, packet_tx.clone());
            tcp.set_node_max_connections(node_max_connections);
            transports.push(TransportHandle::Tcp(tcp));
        }

        // Create Tor transport instances
        let tor_instances: Vec<_> = self
            .config()
            .transports
            .tor
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        for (name, tor_config) in tor_instances {
            let transport_id = self.allocate_transport_id();
            let tor = TorTransport::new(transport_id, name, tor_config, packet_tx.clone());
            transports.push(TransportHandle::Tor(tor));
        }

        // Create Nym transport instances
        let nym_instances: Vec<_> = self
            .config()
            .transports
            .nym
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        for (name, nym_config) in nym_instances {
            let transport_id = self.allocate_transport_id();
            let nym = NymTransport::new(transport_id, name, nym_config, packet_tx.clone());
            transports.push(TransportHandle::Nym(nym));
        }

        // Create BLE transport instances
        #[cfg(bluer_available)]
        {
            let ble_instances: Vec<_> = self
                .config()
                .transports
                .ble
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();

            #[cfg(all(bluer_available, not(test)))]
            for (name, ble_config) in ble_instances {
                let transport_id = self.allocate_transport_id();
                let adapter = ble_config.adapter().to_string();
                let mtu = ble_config.mtu();
                match crate::transport::ble::io::BluerIo::new(&adapter, mtu).await {
                    Ok(io) => {
                        let mut ble = crate::transport::ble::BleTransport::new(
                            transport_id,
                            name,
                            ble_config,
                            io,
                            packet_tx.clone(),
                        );
                        ble.set_local_pubkey(self.identity().pubkey().serialize());
                        transports.push(TransportHandle::Ble(ble));
                    }
                    Err(e) => {
                        tracing::warn!(adapter = %adapter, error = %e, "failed to initialize BLE adapter");
                    }
                }
            }

            #[cfg(any(not(bluer_available), test))]
            if !ble_instances.is_empty() {
                #[cfg(not(test))]
                tracing::warn!("BLE transport configured but this build lacks BlueZ support");
            }
        }

        transports
    }

    /// Find an operational transport that matches the given transport type name.
    fn find_transport_for_type(&self, transport_type: &str) -> Option<TransportId> {
        self.transports
            .iter()
            .find(|(_, handle)| {
                handle.transport_type().name == transport_type && handle.is_operational()
            })
            .map(|(id, _)| *id)
    }

    /// Resolve an Ethernet peer address ("interface/mac") to a transport ID
    /// and binary TransportAddr.
    ///
    /// Finds the Ethernet transport instance bound to the named interface
    /// and parses the MAC portion into a 6-byte TransportAddr.
    #[allow(unused_variables)]
    fn resolve_ethernet_addr(
        &self,
        addr_str: &str,
    ) -> Result<(TransportId, TransportAddr), NodeError> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let (iface, mac_str) = addr_str.split_once('/').ok_or_else(|| {
                NodeError::NoTransportForType(format!(
                    "invalid Ethernet address format '{}': expected 'interface/mac'",
                    addr_str
                ))
            })?;

            // Find the Ethernet transport bound to this interface
            let transport_id = self
                .transports
                .iter()
                .find(|(_, handle)| {
                    handle.transport_type().name == "ethernet"
                        && handle.is_operational()
                        && handle.interface_name() == Some(iface)
                })
                .map(|(id, _)| *id)
                .ok_or_else(|| {
                    NodeError::NoTransportForType(format!(
                        "no operational Ethernet transport for interface '{}'",
                        iface
                    ))
                })?;

            let mac = crate::transport::ethernet::parse_mac_string(mac_str).map_err(|e| {
                NodeError::NoTransportForType(format!("invalid MAC in '{}': {}", addr_str, e))
            })?;

            Ok((transport_id, TransportAddr::from_bytes(&mac)))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(NodeError::NoTransportForType(
                "Ethernet transport is not supported on this platform".to_string(),
            ))
        }
    }

    /// Resolve a BLE address string (`"adapter/AA:BB:CC:DD:EE:FF"`) to a
    /// (TransportId, TransportAddr) pair by finding the BLE transport
    /// instance matching the adapter name.
    #[cfg(bluer_available)]
    fn resolve_ble_addr(&self, addr_str: &str) -> Result<(TransportId, TransportAddr), NodeError> {
        let ta = TransportAddr::from_string(addr_str);
        let adapter = crate::transport::ble::addr::adapter_from_addr(&ta).ok_or_else(|| {
            NodeError::NoTransportForType(format!(
                "invalid BLE address format '{}': expected 'adapter/mac'",
                addr_str
            ))
        })?;

        // Find the BLE transport for this adapter
        let transport_id = self
            .transports
            .iter()
            .find(|(_, handle)| handle.transport_type().name == "ble" && handle.is_operational())
            .map(|(id, _)| *id)
            .ok_or_else(|| {
                NodeError::NoTransportForType(format!(
                    "no operational BLE transport for adapter '{}'",
                    adapter
                ))
            })?;

        // Validate the address format
        crate::transport::ble::addr::BleAddr::parse(addr_str).map_err(|e| {
            NodeError::NoTransportForType(format!("invalid BLE address '{}': {}", addr_str, e))
        })?;

        Ok((transport_id, TransportAddr::from_string(addr_str)))
    }

    // === Identity Accessors ===

    /// Get this node's identity.
    pub fn identity(&self) -> &Identity {
        &self.context.identity
    }

    /// Get this node's NodeAddr.
    pub fn node_addr(&self) -> &NodeAddr {
        self.context.identity.node_addr()
    }

    /// Get this node's npub.
    pub fn npub(&self) -> String {
        self.context.identity.npub()
    }

    /// Get this node's startup epoch (random per-boot tag for restart detection).
    pub fn startup_epoch(&self) -> [u8; 8] {
        self.context.startup_epoch
    }

    /// Reload the host map if the backing `/etc/fips/hosts` file changed.
    ///
    /// Returns `true` if a new snapshot was published.
    pub(crate) async fn reload_host_map(&mut self) -> bool {
        self.host_map.reload().await
    }

    /// Return a human-readable display name for a NodeAddr.
    ///
    /// Lookup order:
    /// 1. Host map hostname (from peer aliases + /etc/fips/hosts)
    /// 2. Configured peer alias or short npub (from startup map)
    /// 3. Active peer's short npub (e.g., inbound peer not in config)
    /// 4. Session endpoint's short npub (end-to-end, may not be direct peer)
    /// 5. Truncated NodeAddr hex (unknown address)
    pub(crate) fn peer_display_name(&self, addr: &NodeAddr) -> String {
        let hosts = self.host_map.load();
        if let Some(hostname) = hosts.lookup_hostname(addr) {
            return hostname.to_string();
        }
        if let Some(name) = self.peer_aliases.get(addr) {
            return name.clone();
        }
        if let Some(peer) = self.peers.get(addr) {
            return peer.identity().short_npub();
        }
        if let Some(entry) = self.sessions.get(addr) {
            let (xonly, _) = entry.remote_pubkey().x_only_public_key();
            return PeerIdentity::from_pubkey(xonly).short_npub();
        }
        addr.short_hex()
    }

    // === Configuration ===

    /// Get the configuration.
    pub fn config(&self) -> &Config {
        self.context.config.as_ref()
    }

    /// Mutate the shared immutable context by building a fresh
    /// [`context::NodeContext`] and swapping the whole `Arc`. The per-instance
    /// context is never interior-mutated; this clone-edit-swap is the sole
    /// runtime mutation path for the bundle (the constructors,
    /// [`leaf_only`](Self::leaf_only), and [`update_peers`](Self::update_peers)).
    /// Cheap — the only deep copy is the (rare) `Config` clone behind its `Arc`.
    fn replace_context(&mut self, f: impl FnOnce(&mut context::NodeContext)) {
        let mut ctx = (*self.context).clone();
        f(&mut ctx);
        self.context = Arc::new(ctx);
    }

    /// Calculate the effective IPv6 MTU that can be sent over FIPS.
    ///
    /// Delegates to `upper::icmp::effective_ipv6_mtu()` with this node's
    /// transport MTU. Returns the maximum IPv6 packet size (including
    /// IPv6 header) that can be transmitted through the FIPS mesh.
    pub fn effective_ipv6_mtu(&self) -> u16 {
        crate::upper::icmp::effective_ipv6_mtu(self.transport_mtu())
    }

    /// Get the transport MTU governing the global TUN-boundary MSS clamp.
    ///
    /// Returns the **minimum** MTU across all operational transports, or
    /// 1280 (IPv6 minimum) as fallback. Used for initial TUN configuration
    /// where a specific egress transport isn't yet known: the resulting
    /// `effective_ipv6_mtu` (transport_mtu - 77) and `max_mss`
    /// (effective_mtu - 60) form a conservative ceiling that fits ANY
    /// configured-transport's egress, eliminating PMTU-D black holes that
    /// would otherwise occur when a flow's actual egress is smaller than
    /// the clamp ceiling assumed at TUN init.
    ///
    /// Returning the smallest (rather than the first-iterated, which used
    /// to vary across HashMap iteration order + async-startup race) makes
    /// the clamp deterministic across daemon restarts.
    ///
    /// See `ISSUE-2026-0011` for the empirical investigation.
    pub fn transport_mtu(&self) -> u16 {
        let min_operational = self
            .transports
            .values()
            .filter(|h| h.is_operational())
            .map(|h| h.mtu())
            .min();
        if let Some(mtu) = min_operational {
            return mtu;
        }
        // Fallback to config: try UDP first, then Ethernet
        if let Some((_, cfg)) = self.config().transports.udp.iter().next() {
            return cfg.mtu();
        }
        1280
    }

    // === State ===

    /// Get the node state.
    pub fn state(&self) -> NodeState {
        self.supervisor.state
    }

    /// Get the node uptime.
    pub fn uptime(&self) -> std::time::Duration {
        self.context.started_at.elapsed()
    }

    /// Check if node is operational.
    pub fn is_running(&self) -> bool {
        self.supervisor.state.is_operational()
    }

    /// Check if this is a leaf-only node.
    pub fn is_leaf_only(&self) -> bool {
        self.context.is_leaf_only
    }

    // === Tree State ===

    /// Get the tree state.
    pub fn tree_state(&self) -> &TreeState {
        &self.tree_state
    }

    /// Get mutable tree state.
    pub fn tree_state_mut(&mut self) -> &mut TreeState {
        &mut self.tree_state
    }

    // === Bloom State ===

    /// Get the Bloom filter state.
    pub fn bloom_state(&self) -> &BloomState {
        &self.bloom_state
    }

    /// Get mutable Bloom filter state.
    pub fn bloom_state_mut(&mut self) -> &mut BloomState {
        &mut self.bloom_state
    }

    // === Mesh Size Estimate ===

    /// Get the cached estimated mesh size.
    pub fn estimated_mesh_size(&self) -> Option<u64> {
        self.estimated_mesh_size
    }

    /// Compute and cache the estimated mesh size from bloom filters.
    ///
    /// Builds an OR-union of self plus every connected peer's inbound filter
    /// and estimates its cardinality once. Unioning (rather than summing
    /// per-peer counts) deduplicates the overlap between the split-horizon
    /// filters, each of which approximates "the whole mesh minus my subtree".
    /// See the body for why all routing peers contribute, not just the tree
    /// neighborhood.
    pub(crate) fn compute_mesh_size(&mut self) {
        let my_addr = *self.tree_state.my_node_addr();

        let max_fpr = self.config().node.bloom.max_inbound_fpr;
        let mut contributor_count: u32 = 0;

        // OR-union of the contributing filters. Summing per-filter
        // cardinalities over-counts whenever the filters overlap (a stale
        // or oversized parent filter, a topology loop); OR is idempotent,
        // so unioning and estimating once deduplicates the overlap.
        //
        // Membership is self + every connected peer's inbound_filter. We
        // deliberately fold in *all* peers, not just the spanning-tree
        // neighborhood (parent + children). Filter propagation is
        // split-horizon (BloomState::compute_outgoing_filter excludes the
        // peer it routes back to), so every routing peer — including
        // cross-links — advertises a near-complete "whole mesh minus my
        // subtree" view. Unioning all of them yields the same set as the
        // tree-only union in steady state (OR-union dedups overlap, and
        // each filter is a subset of the mesh so it cannot over-count) while
        // damping the node-count flap on a parent switch: dropping the
        // parent leaves the cross-links still carrying the upward coverage.
        // It also removes the dependency on tree-declaration cache freshness.
        let mut union: Option<BloomFilter> = None;

        // Helper: fold a contributing filter into the union, starting it
        // from a clone of the first filter (already the right size class).
        // BloomFilter::new() uses default size params that may not match
        // the stored peer filters, so we must not seed from a fresh filter.
        let add_to_union = |union: &mut Option<BloomFilter>, filter: &BloomFilter| match union {
            None => *union = Some(filter.clone()),
            Some(existing) => {
                // Size-class mismatch is skipped rather than fatal.
                let _ = existing.merge(filter);
            }
        };

        // Every connected peer's filter contributes. Honest peers are pure
        // redundancy (overlapping bits dedup under OR); cross-links carry
        // the upward coverage that would otherwise hinge on the parent alone.
        for peer in self.peers.values() {
            if let Some(filter) = peer.inbound_filter() {
                contributor_count += 1;
                add_to_union(&mut union, filter);
            }
        }

        // No contributing filter at all -> refuse to estimate (matches
        // the prior `!has_data` early return).
        let Some(mut union) = union else {
            self.estimated_mesh_size = None;
            return;
        };

        // Count self in the union (idempotent).
        union.insert(&my_addr);

        // Estimate once. If the union is saturated or above the FPR cap,
        // refuse to estimate (matches the prior per-filter None behavior).
        // Node.estimated_mesh_size is already Option<u64> and consumers
        // (control socket, fipstop, periodic debug log) handle None.
        let Some(union_estimate) = union.estimated_count(max_fpr) else {
            self.estimated_mesh_size = None;
            return;
        };

        let union_size = union_estimate.round() as u64;
        self.estimated_mesh_size = Some(union_size);

        // Periodic logging (reuse MMP default interval: 30s)
        let now = std::time::Instant::now();
        let should_log = match self.last_mesh_size_log {
            None => true,
            Some(last) => {
                now.duration_since(last)
                    >= std::time::Duration::from_secs(self.config().node.mmp.log_interval_secs)
            }
        };
        if should_log {
            tracing::debug!(
                estimated_mesh_size = union_size,
                peers = self.peers.len(),
                contributors = contributor_count,
                "Mesh size estimate"
            );
            self.last_mesh_size_log = Some(now);
        }
    }

    // === Coord Cache ===

    /// Get the coordinate cache.
    pub fn coord_cache(&self) -> &CoordCache {
        &self.coord_cache
    }

    /// Get mutable coordinate cache.
    pub fn coord_cache_mut(&mut self) -> &mut CoordCache {
        &mut self.coord_cache
    }

    // === Node Statistics ===

    /// Get the node statistics.
    pub fn stats(&self) -> &stats::NodeStats {
        &self.stats
    }

    /// Get mutable node statistics.
    pub(crate) fn stats_mut(&mut self) -> &mut stats::NodeStats {
        &mut self.stats
    }

    /// Get the atomic metric registry.
    pub(crate) fn metrics(&self) -> &metrics::MetricsRegistry {
        &self.metrics
    }

    /// Build a [`ControlReadHandle`](crate::control::read_handle::ControlReadHandle)
    /// over this node's already-shared `NodeContext` and `MetricsRegistry`.
    ///
    /// Used at control-socket spawn time so pure-snapshot `show_*` queries
    /// render off the rx_loop. Cloneable; cheap (all `Arc` clones).
    pub(crate) fn control_read_handle(&self) -> crate::control::read_handle::ControlReadHandle {
        crate::control::read_handle::ControlReadHandle::new(
            self.context.clone(),
            self.metrics.clone(),
            self.stats_snapshot.clone(),
            self.routing_snapshot.clone(),
            self.entities_snapshot.clone(),
        )
    }

    /// Get the stats history collector.
    pub fn stats_history(&self) -> &stats_history::StatsHistory {
        &self.stats_history
    }

    /// Sample the current node state into the stats history ring.
    /// Called once per tick from the RX loop.
    pub(crate) fn record_stats_history(&mut self) {
        let fwd = &self.metrics.forwarding;
        let peers_with_mmp: Vec<f64> = self
            .peers
            .values()
            .filter_map(|p| p.mmp().map(|m| m.metrics.loss_rate()))
            .collect();
        let loss_rate = if peers_with_mmp.is_empty() {
            0.0
        } else {
            peers_with_mmp.iter().sum::<f64>() / peers_with_mmp.len() as f64
        };

        let snap = stats_history::Snapshot {
            mesh_size: self.estimated_mesh_size,
            tree_depth: self.tree_state.my_coords().depth() as u32,
            peer_count: self.peers.len() as u64,
            parent_switches_total: self.metrics.tree.parent_switches.get(),
            bytes_in_total: fwd.received_bytes.get(),
            bytes_out_total: fwd.forwarded_bytes.get() + fwd.originated_bytes.get(),
            packets_in_total: fwd.received_packets.get(),
            packets_out_total: fwd.forwarded_packets.get() + fwd.originated_packets.get(),
            loss_rate,
            active_sessions: self.sessions.len() as u64,
        };

        let now = std::time::Instant::now();
        let peer_snaps: Vec<stats_history::PeerSnapshot> = self
            .peers
            .values()
            .map(|p| {
                let stats = p.link_stats();
                let (srtt_ms, loss_rate, ecn_ce) = match p.mmp() {
                    Some(m) => (
                        m.metrics.srtt_ms(),
                        Some(m.metrics.loss_rate()),
                        m.receiver.ecn_ce_count() as u64,
                    ),
                    None => (None, None, 0),
                };
                stats_history::PeerSnapshot {
                    node_addr: *p.node_addr(),
                    last_seen: now,
                    srtt_ms,
                    loss_rate,
                    bytes_in_total: stats.bytes_recv,
                    bytes_out_total: stats.bytes_sent,
                    packets_in_total: stats.packets_recv,
                    packets_out_total: stats.packets_sent,
                    ecn_ce_total: ecn_ce,
                }
            })
            .collect();

        self.stats_history.tick(now, &snap, &peer_snaps);

        // Publish the read-side snapshot (R2 dual-ring, Q1-b). The tick is the
        // natural and sole mutator of `stats_history`, so publishing here can
        // never produce false staleness: the snapshot and the underlying data
        // advance together. This is data, not a rendered response (Q1-d), and
        // it is published only here, not in a monolithic per-tick rebuild of
        // every query (Q1-c). It also is not gated behind any slow I/O on the
        // tick the way the abandoned 2edc8a1 republish was.
        // Per-stats-history-peer metadata (R5). `show_stats_peers` /
        // `show_stats_history_all_peers` need each tracked peer's live
        // membership (`is_active`), resolved npub, and display name — all
        // cross-subsystem reads against the live peer table and host map,
        // available only here with `&self`. The lifecycle timestamps and
        // metric rings the renderers also read live in `history` (the dual-ring
        // read copy above), so this map carries only the resolved fields.
        let peer_meta: HashMap<NodeAddr, crate::control::snapshot::StatsPeerMeta> = self
            .stats_history
            .peer_addrs()
            .copied()
            .map(|addr| {
                let live = self.peers.get(&addr);
                let meta = crate::control::snapshot::StatsPeerMeta {
                    is_active: live.is_some(),
                    npub: live
                        .map(|p| p.npub())
                        .unwrap_or_else(|| hex::encode(addr.as_bytes())),
                    display_name: self.peer_display_name(&addr),
                };
                (addr, meta)
            })
            .collect();

        // Per-configured-transport-type peer counts (`show_status`). Seed every
        // configured transport type at 0 so an idle-but-configured type stays
        // visible, then tally the peers whose active link rides that type.
        let mut transport_peer_counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for id in self.transport_ids() {
            if let Some(handle) = self.get_transport(id) {
                transport_peer_counts
                    .entry(handle.transport_type().name.to_string())
                    .or_insert(0);
            }
        }
        for peer in self.peers() {
            if let Some(link) = self.get_link(&peer.link_id())
                && let Some(handle) = self.get_transport(&link.transport_id())
            {
                *transport_peer_counts
                    .entry(handle.transport_type().name.to_string())
                    .or_insert(0) += 1;
            }
        }

        let tree = self.tree_state();
        let snapshot = crate::control::snapshot::StatsSnapshot {
            history: std::sync::Arc::new(self.stats_history.clone()),
            estimated_mesh_size: self.estimated_mesh_size,
            state: self.supervisor.state,
            tun_state: self.tun_state,
            tun_name: self.tun_name.clone(),
            effective_ipv6_mtu: self.effective_ipv6_mtu(),
            connection_count: self.connection_count(),
            peer_count: self.peers.len(),
            link_count: self.links.len(),
            transport_count: self.transports.len(),
            session_count: self.sessions.len(),
            root: *tree.root(),
            is_root: tree.is_root(),
            transport_peer_counts,
            peer_aliases: std::sync::Arc::new(self.peer_aliases.clone()),
            acl_status: self.peer_acl_status(),
            peer_meta: std::sync::Arc::new(peer_meta),
        };
        self.stats_snapshot.store(std::sync::Arc::new(snapshot));

        // Publish the Category-D routing read view alongside the stats
        // snapshot, from the same tick.
        self.publish_routing_snapshot();

        // Publish the Category-E per-entity read view from the same tick, with
        // `Vec<Arc<Row>>` structural sharing against the previous snapshot.
        self.publish_entities_snapshot();
    }

    /// Resolve the npub of the spanning-tree root for `show_tree`'s `root_npub`.
    ///
    /// Resolution order: this node when it is root, then the root as a live
    /// authenticated peer (cryptographically attested npub), then the
    /// identity-cache, else `None`.
    pub(crate) fn resolve_root_npub(&self, tree: &crate::proto::stp::TreeState) -> Option<String> {
        if tree.is_root() {
            return Some(self.npub());
        }
        let root_addr = tree.root();
        if let Some(peer) = self.get_peer(root_addr) {
            return Some(peer.npub());
        }
        for (addr, pubkey, _last_seen) in self.identity_cache_iter() {
            if addr == root_addr {
                let (xonly, _parity) = pubkey.x_only_public_key();
                return Some(crate::identity::encode_npub(&xonly));
            }
        }
        None
    }

    /// Project the Category-D derived/routing/cache state into a
    /// [`RoutingSnapshot`](crate::control::snapshot::RoutingSnapshot) and
    /// publish it via `ArcSwap`, so `show_tree` / `show_bloom` / `show_cache`
    /// / `show_routing` / `show_identity_cache` render off the rx_loop.
    ///
    /// **Q1 publisher placement.** The four projected subsystems (tree / bloom
    /// / coord cache / identity cache) mutate at dozens of scattered handler
    /// sites, and every projected row carries a *display name* resolved against
    /// the live peer/session tables and host map — state reachable only with
    /// `&Node`. Per-mutator on-change publication (Q1-a) would therefore be
    /// large, error-prone surgery, and each call would still need `&Node` to
    /// resolve names across subsystem boundaries. So this projection is
    /// published from the tick — the documented acceptable interim (the spec's
    /// "publish from the tick" allowance, mirroring R2's stats publish). The
    /// tick is the one site with coherent `&Node` access to resolve every
    /// display name together. A single combined cell is the natural shape
    /// because there is exactly one publisher, so the multi-mutator
    /// whole-snapshot-rebuild hazard Q1-c warns against does not arise.
    ///
    /// The snapshot holds typed rows + scalars (Q1-d data, not rendered
    /// responses); the counter-family `stats` blocks the queries also emit are
    /// served from the `MetricsRegistry` (already `Arc`-shared) at render time.
    fn publish_routing_snapshot(&self) {
        use crate::control::snapshot as snap;

        let now = Self::now_ms();

        // --- tree (show_tree) ---
        let tree = self.tree_state();
        let my_coords = tree.my_coords();
        let tree_peers: Vec<snap::TreePeerRow> = tree
            .peer_ids()
            .map(|peer_id| {
                let coords = tree
                    .peer_coords(peer_id)
                    .map(|coords| snap::TreePeerCoords {
                        depth: coords.depth(),
                        root: *coords.root_id(),
                        coord_path: coords.entries().iter().map(|e| e.node_addr).collect(),
                        distance_to_us: my_coords.distance_to(coords),
                    });
                snap::TreePeerRow {
                    node_addr: *peer_id,
                    display_name: self.peer_display_name(peer_id),
                    coords,
                }
            })
            .collect();
        let parent_addr = my_coords.parent_id();
        let root_npub = self.resolve_root_npub(tree);
        let tree_view = snap::TreeView {
            my_node_addr: *tree.my_node_addr(),
            root: *tree.root(),
            root_npub,
            is_root: tree.is_root(),
            depth: my_coords.depth(),
            my_coords: my_coords.entries().iter().map(|e| e.node_addr).collect(),
            parent: *parent_addr,
            parent_display_name: self.peer_display_name(parent_addr),
            declaration_sequence: tree.my_declaration().sequence(),
            declaration_signed: tree.my_declaration().is_signed(),
            peer_tree_count: tree.peer_count(),
            peers: tree_peers,
        };

        // --- bloom (show_bloom) ---
        let bloom = self.bloom_state();
        let max_inbound_fpr = self.config().node.bloom.max_inbound_fpr;
        let bloom_peers: Vec<snap::BloomPeerRow> = self
            .peers()
            .map(|peer| {
                let addr = *peer.node_addr();
                let filter = peer.inbound_filter().map(|f| snap::BloomPeerFilter {
                    estimated_count: f.estimated_count(max_inbound_fpr),
                    set_bits: f.count_ones(),
                    fill_ratio: f.fill_ratio(),
                });
                snap::BloomPeerRow {
                    peer: addr,
                    display_name: self.peer_display_name(&addr),
                    has_filter: peer.filter_sequence() > 0,
                    filter_sequence: peer.filter_sequence(),
                    filter,
                }
            })
            .collect();
        // Uptree filter metrics: the last filter actually sent to the tree
        // parent (`record_sent_filter`), which is what the parent currently
        // holds for us. `None` for a root node (nothing sent uptree) or before
        // the first announce. The estimate is this node's whole subtree
        // (split-horizon), not the mesh.
        let (uptree_fill_ratio, uptree_estimated_count) = if tree.is_root() {
            (None, None)
        } else {
            match bloom.last_sent_filter(parent_addr) {
                Some(filter) => (
                    Some(filter.fill_ratio()),
                    filter.estimated_count(max_inbound_fpr),
                ),
                None => (None, None),
            }
        };
        let bloom_view = snap::BloomView {
            own_node_addr: *self.node_addr(),
            is_leaf_only: self.is_leaf_only(),
            sequence: bloom.sequence(),
            leaf_dependents: bloom.leaf_dependents().iter().copied().collect(),
            peer_filters: bloom_peers,
            uptree_fill_ratio,
            uptree_estimated_count,
        };

        // --- coord cache (show_cache, show_routing) ---
        let cache = self.coord_cache();
        let cache_stats = cache.stats(now);
        let cache_entries: Vec<snap::CacheEntryRow> = cache
            .iter(now)
            .map(|(addr, entry)| snap::CacheEntryRow {
                node_addr: *addr,
                display_name: self.peer_display_name(addr),
                depth: entry.coords().depth(),
                coord_path: entry
                    .coords()
                    .entries()
                    .iter()
                    .map(|e| e.node_addr)
                    .collect(),
                created_at: entry.created_at(),
                last_used_ms: entry.last_used(),
                path_mtu: entry.path_mtu(),
            })
            .collect();
        let cache_view = snap::CacheView {
            count: cache_stats.entries,
            max_entries: cache_stats.max_entries,
            fill_ratio: cache_stats.fill_ratio(),
            default_ttl_ms: cache.default_ttl_ms(),
            expired: cache_stats.expired,
            avg_age_ms: cache_stats.avg_age_ms,
            entries: cache_entries,
        };

        // --- F-queue / discovery routing scalars (show_routing) ---
        let pending_lookups: Vec<snap::PendingLookupRow> = self
            .pending_lookups_iter()
            .map(|(addr, lookup)| snap::PendingLookupRow {
                target: *addr,
                display_name: self.peer_display_name(addr),
                initiated_ms: lookup.initiated_ms,
                last_sent_ms: lookup.last_sent_ms,
                attempt: lookup.attempt,
            })
            .collect();
        let retries: Vec<snap::RetryRow> = self
            .retry_state_iter()
            .map(|(addr, state)| snap::RetryRow {
                node_addr: *addr,
                display_name: self.peer_display_name(addr),
                retry_count: state.retry_count,
                retry_after_ms: state.retry_after_ms,
                auto_reconnect: state.reconnect,
            })
            .collect();
        let routing_view = snap::RoutingView {
            pending_lookups,
            pending_tun_destinations: self.pending_tun_destinations(),
            pending_tun_packets: self.pending_tun_total_packets(),
            recent_requests: self.recent_request_count(),
            retries,
        };

        // --- identity cache (show_identity_cache, show_routing) ---
        let identity_entries: Vec<snap::IdentityRow> = self
            .identity_cache_iter()
            .map(|(node_addr, pubkey, last_seen_ms)| {
                let (xonly, _parity) = pubkey.x_only_public_key();
                let fips_addr = crate::identity::FipsAddress::from_node_addr(node_addr);
                snap::IdentityRow {
                    node_addr: *node_addr,
                    npub: crate::identity::encode_npub(&xonly),
                    display_name: self.peer_display_name(node_addr),
                    ipv6_addr: format!("{}", fips_addr),
                    last_seen_ms,
                }
            })
            .collect();
        let identity_view = snap::IdentityView {
            entries: identity_entries,
            max_entries: self.identity_cache_max(),
        };

        let snapshot = snap::RoutingSnapshot {
            tree: tree_view,
            bloom: bloom_view,
            cache: cache_view,
            routing: routing_view,
            identity: identity_view,
        };
        self.routing_snapshot.store(std::sync::Arc::new(snapshot));
    }

    /// Project the Category-E per-entity tables (peers / sessions / links /
    /// connections / transports + mmp) into an
    /// [`EntitySnapshot`](crate::control::snapshot::EntitySnapshot) and publish
    /// it via `ArcSwap`, so `show_peers` / `show_sessions` / `show_links` /
    /// `show_connections` / `show_transports` / `show_mmp` render off the
    /// rx_loop.
    ///
    /// **Q1 publisher placement (tick, like R3).** Every projected row needs a
    /// display name resolved against the live peer/session tables and host map
    /// (`&Node`); `show_peers` additionally needs the live tree state to derive
    /// `is_parent` / `is_child` plus the Nostr-discovery failure-state map —
    /// cross-subsystem reads available only with `&Node`. And most fields
    /// (link/session traffic counters, MMP metrics, `last_seen`, noise counters)
    /// mutate continuously on the data plane, not at the discrete entity
    /// lifecycle mutators, so per-lifecycle-mutator publication (Q1-a) would not
    /// capture their freshness anyway. The tick is the natural cadence with
    /// coherent `&Node` access.
    ///
    /// **Structural sharing (the R4 umbrella mandate).** Each table is a
    /// `Vec<Arc<Row>>`. The freshly-projected rows are reconciled against the
    /// previously published snapshot via
    /// [`reconcile_rows`](crate::control::snapshot::reconcile_rows): a row's
    /// `Arc` is reused (kept by pointer) whenever it matches the prior row by
    /// identity and compares equal by value, so a tick in which only one
    /// peer/session changed re-allocates only that one row, not the whole table.
    /// This is what keeps the publish cost off the hot path at scale (the exact
    /// thing the umbrella warns a naive per-tick rebuild would violate).
    fn publish_entities_snapshot(&self) {
        use crate::control::snapshot as snap;

        let prev = self.entities_snapshot.load();

        // --- peers (show_peers) ---
        let tree = self.tree_state();
        let my_addr = *tree.my_node_addr();
        let parent_id = *tree.my_declaration().parent_id();
        let is_root = tree.is_root();

        // Per-npub Nostr-traversal failure-state, indexed by npub for O(1)
        // per-peer lookup (empty when Nostr discovery is disabled).
        let nostr_state: std::collections::HashMap<String, _> = self
            .nostr_rendezvous_handle()
            .map(|d| {
                d.failure_state_snapshot()
                    .into_iter()
                    .map(|view| (view.npub.clone(), view))
                    .collect()
            })
            .unwrap_or_default();

        // Cold-start gate for effective_depth, mirroring `evaluate_parent`:
        // if any peer has an SRTT measurement, unmeasured peers are excluded
        // (their effective_depth is `None`); during cold start (no peer has
        // SRTT) every peer falls back to the default link cost of 1.0.
        let any_peer_has_srtt = self.peers().any(|p| p.has_srtt());

        let peer_rows: Vec<snap::PeerRow> = self
            .peers()
            .map(|peer| {
                let node_addr = *peer.node_addr();
                let is_parent = !is_root && node_addr == parent_id;
                let is_child = tree
                    .peer_declaration(&node_addr)
                    .is_some_and(|decl| *decl.parent_id() == my_addr);

                let link_info = self.get_link(&peer.link_id()).map(|link| {
                    let transport_type = self
                        .get_transport(&link.transport_id())
                        .map(|h| h.transport_type().name.to_string());
                    snap::PeerLinkInfo {
                        direction: format!("{}", link.direction()),
                        transport_type,
                    }
                });

                let stats = peer.link_stats();
                let nostr = nostr_state.get(&peer.npub());
                let nostr_traversal = snap::PeerNostrState {
                    consecutive_failures: nostr.map(|s| s.consecutive_failures).unwrap_or(0),
                    cooldown_until_ms: nostr.and_then(|s| s.cooldown_until_ms),
                    last_observed_skew_ms: nostr.and_then(|s| s.last_observed_skew_ms),
                };

                let noise = peer.noise_session().map(|session| snap::PeerNoiseCounters {
                    send_counter: session.current_send_counter(),
                    highest_recv_counter: session.highest_received_counter(),
                });

                let mmp = peer
                    .mmp()
                    .map(|mmp| project_entity_mmp(&mmp.metrics, format!("{}", mmp.mode()), None));

                // effective_depth = tree_depth + link_cost, the value
                // `evaluate_parent` ranks on. Computed only when the peer has
                // coords and passes the cold-start measurement gate.
                let effective_depth = peer.coords().and_then(|coords| {
                    if any_peer_has_srtt && !peer.has_srtt() {
                        None
                    } else {
                        Some(coords.depth() as f64 + peer.link_cost())
                    }
                });

                snap::PeerRow {
                    node_addr,
                    npub: peer.npub(),
                    display_name: self.peer_display_name(&node_addr),
                    ipv6_addr: format!("{}", peer.address()),
                    connectivity: format!("{}", peer.connectivity()),
                    link_id: peer.link_id().as_u64(),
                    authenticated_at_ms: peer.authenticated_at(),
                    last_seen_ms: peer.last_seen(),
                    has_tree_position: peer.has_tree_position(),
                    has_bloom_filter: peer.filter_sequence() > 0,
                    filter_sequence: peer.filter_sequence(),
                    is_parent,
                    is_child,
                    transport_addr: peer.current_addr().map(|a| format!("{}", a)),
                    link_info,
                    tree_depth: peer.coords().map(|c| c.depth()),
                    effective_depth,
                    stats: snap::PeerLinkStats {
                        packets_sent: stats.packets_sent,
                        packets_recv: stats.packets_recv,
                        bytes_sent: stats.bytes_sent,
                        bytes_recv: stats.bytes_recv,
                    },
                    replay_suppressed: peer.replay_suppressed_count(),
                    consecutive_decrypt_failures: peer.consecutive_decrypt_failures(),
                    nostr_traversal,
                    noise,
                    our_session_index: peer.our_index().map(|idx| idx.as_u32()),
                    rekey_in_progress: peer.rekey_in_progress(),
                    rekey_draining: peer.is_draining(),
                    current_k_bit: peer.current_k_bit(),
                    mmp,
                }
            })
            .collect();

        // --- sessions (show_sessions) ---
        let session_rows: Vec<snap::SessionRow> = self
            .session_entries()
            .map(|(addr, entry)| {
                let state = if entry.is_established() {
                    "established"
                } else if entry.is_initiating() {
                    "initiating"
                } else if entry.is_awaiting_msg3() {
                    "awaiting_msg3"
                } else {
                    "unknown"
                };
                let (xonly, _parity) = entry.remote_pubkey().x_only_public_key();
                let (pkts_tx, pkts_rx, bytes_tx, bytes_rx) = entry.traffic_counters();

                let resend_count = (!entry.is_established()).then(|| entry.resend_count());
                let established = entry.is_established().then(|| snap::SessionEstablished {
                    session_start_ms: entry.session_start_ms(),
                    current_k_bit: entry.current_k_bit(),
                    coords_warmup_remaining: entry.coords_warmup_remaining(),
                    is_draining: entry.is_draining(),
                });
                let mmp = entry.mmp().map(|mmp| {
                    project_entity_mmp(
                        &mmp.metrics,
                        format!("{}", mmp.mode()),
                        Some(mmp.path_mtu.current_mtu()),
                    )
                });

                snap::SessionRow {
                    remote_addr: *addr,
                    display_name: self.peer_display_name(addr),
                    state,
                    is_initiator: entry.is_initiator(),
                    last_activity_ms: entry.last_activity(),
                    npub: crate::identity::encode_npub(&xonly),
                    stats: snap::SessionStats {
                        packets_sent: pkts_tx,
                        packets_recv: pkts_rx,
                        bytes_sent: bytes_tx,
                        bytes_recv: bytes_rx,
                    },
                    resend_count,
                    established,
                    mmp,
                }
            })
            .collect();

        // --- links (show_links) ---
        let link_rows: Vec<snap::LinkRow> = self
            .links()
            .map(|link| {
                let stats = link.stats();
                snap::LinkRow {
                    link_id: link.link_id().as_u64(),
                    transport_id: link.transport_id().as_u32(),
                    remote_addr: format!("{}", link.remote_addr()),
                    direction: format!("{}", link.direction()),
                    state: format!("{}", link.state()),
                    created_at_ms: link.created_at(),
                    stats: snap::LinkStats {
                        packets_sent: stats.packets_sent,
                        packets_recv: stats.packets_recv,
                        bytes_sent: stats.bytes_sent,
                        bytes_recv: stats.bytes_recv,
                        last_recv_ms: stats.last_recv_ms,
                    },
                }
            })
            .collect();

        // --- connections (show_connections) ---
        let connection_rows: Vec<snap::ConnectionRow> = self
            .connections()
            .map(|(_, machine)| snap::ConnectionRow {
                link_id: machine.link_id().as_u64(),
                direction: format!("{}", machine.conn_direction()),
                handshake_state: self
                    .connection_handshake_state(machine.link_id())
                    .to_string(),
                started_at_ms: self.connection_started_at(machine.link_id()),
                last_activity_ms: self.connection_last_activity(machine.link_id()),
                resend_count: self.connection_resend_count(machine.link_id()),
                expected_peer: self
                    .connection_expected_identity(machine.link_id())
                    .map(|id| id.npub()),
            })
            .collect();

        // --- transports (show_transports) ---
        let transport_rows: Vec<snap::TransportRow> = self
            .transport_ids()
            .map(|id| {
                let handle = self.get_transport(id).unwrap();
                snap::TransportRow {
                    transport_id: id.as_u32(),
                    transport_type: handle.transport_type().name.to_string(),
                    state: format!("{}", handle.state()),
                    mtu: handle.mtu(),
                    name: handle.name().map(|s| s.to_string()),
                    local_addr: handle.local_addr().map(|a| format!("{}", a)),
                    tor_mode: handle.tor_mode().map(|s| s.to_string()),
                    onion_address: handle.onion_address().map(|s| s.to_string()),
                    tor_monitoring: handle
                        .tor_monitoring()
                        .map(|m| serde_json::to_value(&m).unwrap_or_default()),
                    stats: handle.transport_stats(),
                }
            })
            .collect();

        // --- mmp peers (show_mmp link-layer) ---
        let mmp_peer_rows: Vec<snap::MmpPeerRow> = self
            .peers()
            .filter_map(|peer| {
                let mmp = peer.mmp()?;
                let addr = *peer.node_addr();
                let metrics = &mmp.metrics;
                let srtt_ms = metrics.srtt_ms();
                let smoothed_etx = metrics.smoothed_etx();
                let lqi = match (srtt_ms, smoothed_etx) {
                    (Some(srtt), Some(setx)) => Some(setx * (1.0 + srtt / 100.0)),
                    _ => None,
                };
                let trend = |dual: &crate::proto::mmp::DualEwma| {
                    dual.initialized()
                        .then(|| crate::control::queries::trend_label(dual.short(), dual.long()))
                };
                Some(snap::MmpPeerRow {
                    peer: addr,
                    display_name: self.peer_display_name(&addr),
                    mode: format!("{}", mmp.mode()),
                    loss_rate: metrics.loss_rate(),
                    etx: metrics.etx,
                    goodput_bps: metrics.goodput_bps,
                    spin_bit_initiator: mmp.spin_bit.is_initiator(),
                    smoothed_loss: metrics.smoothed_loss(),
                    smoothed_etx,
                    srtt_ms,
                    lqi,
                    trends: snap::MmpTrends {
                        rtt_trend: trend(&metrics.rtt_trend),
                        loss_trend: trend(&metrics.loss_trend),
                        goodput_trend: trend(&metrics.goodput_trend),
                        jitter_trend: trend(&metrics.jitter_trend),
                    },
                    delivery_ratio_forward: metrics.delivery_ratio_forward,
                    delivery_ratio_reverse: metrics.delivery_ratio_reverse,
                    ecn_ce_count: metrics.last_ecn_ce_count(),
                })
            })
            .collect();

        // --- mmp sessions (show_mmp session-layer) ---
        let mmp_session_rows: Vec<snap::MmpSessionRow> = self
            .session_entries()
            .filter_map(|(addr, entry)| {
                let mmp = entry.mmp()?;
                let metrics = &mmp.metrics;
                let srtt_ms = metrics.srtt_ms();
                let smoothed_etx = metrics.smoothed_etx();
                let sqi = match (srtt_ms, smoothed_etx) {
                    (Some(srtt), Some(setx)) => Some(setx * (1.0 + srtt / 100.0)),
                    _ => None,
                };
                let trend = |dual: &crate::proto::mmp::DualEwma| {
                    dual.initialized()
                        .then(|| crate::control::queries::trend_label(dual.short(), dual.long()))
                };
                Some(snap::MmpSessionRow {
                    remote: *addr,
                    display_name: self.peer_display_name(addr),
                    mode: format!("{}", mmp.mode()),
                    loss_rate: metrics.loss_rate(),
                    etx: metrics.etx,
                    path_mtu: mmp.path_mtu.current_mtu(),
                    smoothed_loss: metrics.smoothed_loss(),
                    smoothed_etx,
                    srtt_ms,
                    sqi,
                    trends: snap::MmpSessionTrends {
                        rtt_trend: trend(&metrics.rtt_trend),
                        loss_trend: trend(&metrics.loss_trend),
                        etx_trend: trend(&metrics.etx_trend),
                    },
                })
            })
            .collect();

        let snapshot = snap::EntitySnapshot {
            peers: snap::reconcile_rows(&prev.peers, peer_rows, |r| r.node_addr),
            sessions: snap::reconcile_rows(&prev.sessions, session_rows, |r| r.remote_addr),
            links: snap::reconcile_rows(&prev.links, link_rows, |r| r.link_id),
            connections: snap::reconcile_rows(&prev.connections, connection_rows, |r| r.link_id),
            transports: snap::reconcile_rows(&prev.transports, transport_rows, |r| r.transport_id),
            mmp_peers: snap::reconcile_rows(&prev.mmp_peers, mmp_peer_rows, |r| r.peer),
            mmp_sessions: snap::reconcile_rows(&prev.mmp_sessions, mmp_session_rows, |r| r.remote),
        };
        self.entities_snapshot.store(std::sync::Arc::new(snapshot));
    }

    // === TUN Interface ===

    /// Get the TUN state.
    pub fn tun_state(&self) -> TunState {
        self.tun_state
    }

    /// Get the TUN interface name, if active.
    pub fn tun_name(&self) -> Option<&str> {
        self.tun_name.as_deref()
    }

    // === Resource Limits ===

    /// Maximum connections (handshake phase); 0 = unlimited.
    pub fn max_connections(&self) -> usize {
        self.context.max_connections
    }

    /// Maximum authenticated peers; 0 = unlimited.
    pub fn max_peers(&self) -> usize {
        self.context.max_peers
    }

    /// Maximum links; 0 = unlimited.
    pub fn max_links(&self) -> usize {
        self.context.max_links
    }

    /// Returns false when we are at or above the configured `max_peers`
    /// cap, suppressing outbound connection-initiation. `max_peers == 0`
    /// is the "no cap" sentinel and always returns true. The inbound
    /// msg1 gate in `handshake.rs` is the authoritative cap; this helper
    /// keeps the four outbound initiation paths (auto-reconnect retries,
    /// Nostr-discovery `Established` adoption, and both sides of the
    /// Nostr-mediated NAT-traversal punch) from doing pointless work
    /// when saturated.
    pub(crate) fn outbound_admission_check(&self) -> bool {
        let max_peers = self.context.max_peers;
        max_peers == 0 || self.peers.len() < max_peers
    }

    // === Counts ===

    /// Number of pending connections (handshake in progress).
    pub fn connection_count(&self) -> usize {
        self.peer_machines
            .values()
            .filter(|machine| machine.leg().is_some())
            .count()
    }

    /// Number of authenticated peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of active links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Number of active transports.
    pub fn transport_count(&self) -> usize {
        self.transports.len()
    }

    // === Transport Management ===

    /// Allocate a new transport ID.
    pub fn allocate_transport_id(&mut self) -> TransportId {
        let id = TransportId::new(self.next_transport_id);
        self.next_transport_id += 1;
        id
    }

    /// Get a transport by ID.
    pub fn get_transport(&self, id: &TransportId) -> Option<&TransportHandle> {
        self.transports.get(id)
    }

    /// Get mutable transport by ID.
    pub fn get_transport_mut(&mut self, id: &TransportId) -> Option<&mut TransportHandle> {
        self.transports.get_mut(id)
    }

    /// Iterate over transport IDs.
    pub fn transport_ids(&self) -> impl Iterator<Item = &TransportId> {
        self.transports.keys()
    }

    /// Get the packet receiver for the event loop.
    pub fn packet_rx(&mut self) -> Option<&mut PacketRx> {
        self.packet_rx.as_mut()
    }

    // === Link Management ===

    /// Allocate a new link ID.
    pub fn allocate_link_id(&mut self) -> LinkId {
        let id = LinkId::new(self.next_link_id);
        self.next_link_id += 1;
        id
    }

    /// Add a link.
    pub fn add_link(&mut self, link: Link) -> Result<(), NodeError> {
        if self.max_links() > 0 && self.links.len() >= self.max_links() {
            return Err(NodeError::MaxLinksExceeded {
                max: self.max_links(),
            });
        }
        let link_id = link.link_id();
        let transport_id = link.transport_id();
        let remote_addr = link.remote_addr().clone();

        self.links.insert(link_id, link);
        self.addr_to_link
            .insert((transport_id, remote_addr), link_id);
        Ok(())
    }

    /// Get a link by ID.
    pub fn get_link(&self, link_id: &LinkId) -> Option<&Link> {
        self.links.get(link_id)
    }

    /// Get a mutable link by ID.
    pub fn get_link_mut(&mut self, link_id: &LinkId) -> Option<&mut Link> {
        self.links.get_mut(link_id)
    }

    /// Find link ID by transport address.
    pub fn find_link_by_addr(
        &self,
        transport_id: TransportId,
        addr: &TransportAddr,
    ) -> Option<LinkId> {
        self.addr_to_link
            .get(&(transport_id, addr.clone()))
            .copied()
    }

    /// Remove a link.
    ///
    /// Only removes the addr_to_link reverse lookup if it still points to this
    /// link. In cross-connection scenarios, a newer link may have replaced the
    /// entry for the same address.
    pub fn remove_link(&mut self, link_id: &LinkId) -> Option<Link> {
        if let Some(link) = self.links.remove(link_id) {
            // Clean up reverse lookup only if it still maps to this link
            let key = (link.transport_id(), link.remote_addr().clone());
            if self.addr_to_link.get(&key) == Some(link_id) {
                self.addr_to_link.remove(&key);
            }
            Some(link)
        } else {
            None
        }
    }

    /// Single choke-point for dropping a per-peer control machine. Also drops the
    /// machine's timer store so no armed `SetTimer` outlives it (the store and the
    /// machine share the `LinkId` lifetime). Every teardown path routes machine
    /// removal here rather than calling `peer_machines.remove` directly.
    pub(in crate::node) fn remove_peer_machine(&mut self, link: LinkId) {
        self.peer_machines.remove(&link);
        self.peer_timers.remove(&link);
    }

    /// Debug-build coherence sweep over the peer-lifecycle maps, run once per
    /// rx-loop tick and invoked directly by unit tests.
    ///
    /// Machine→carrier: every `peer_machines` entry must have a live carrier —
    /// its own embedded pending connection, an active peer on its link, or a
    /// pending connect still resolving toward it. A machine with none of these
    /// is unreachable by every teardown path and has leaked. (The pending
    /// connection lives inside the machine, so no separate connection→machine
    /// direction exists to check.)
    #[cfg(debug_assertions)]
    pub(in crate::node) fn debug_assert_peer_maps_coherent(&self) {
        for (link, machine) in &self.peer_machines {
            let has_carrier = machine.leg().is_some()
                || self.peers.values().any(|peer| peer.link_id() == *link)
                || self
                    .peering
                    .pending_connects
                    .iter()
                    .any(|pending| pending.link_id == *link);
            assert!(
                has_carrier,
                "control machine for link {link} has no live carrier \
                 (no pending connection, active peer, or pending connect)"
            );
        }
    }

    /// Operator-visible msg1 resend count for a pending handshake `link`, read
    /// from the per-peer machine (the counter's home once the resend drive moved
    /// off the shell connection). A link with no machine reports 0, and inbound
    /// machines never resend, matching what the shell connection reported
    /// before the counter moved.
    pub(crate) fn connection_resend_count(&self, link: LinkId) -> u32 {
        self.peer_machines
            .get(&link)
            .map_or(0, |machine| machine.resend_count())
    }

    /// Operator-visible connection-start timestamp for a pending handshake
    /// `link`, read from the per-peer machine carrier (the timing's home now
    /// that the leg no longer projects it). A link with no machine reports 0;
    /// every leg surfaced by `connections()` is embedded in a machine, so the
    /// lookup resolves.
    pub(crate) fn connection_started_at(&self, link: LinkId) -> u64 {
        self.peer_machines
            .get(&link)
            .map_or(0, |machine| machine.conn_started_at())
    }

    /// Operator-visible last-activity timestamp for a pending handshake `link`,
    /// read from the per-peer machine carrier. A link with no machine reports 0;
    /// every leg surfaced by `connections()` is embedded in a machine, so the
    /// lookup resolves.
    pub(crate) fn connection_last_activity(&self, link: LinkId) -> u64 {
        self.peer_machines
            .get(&link)
            .map_or(0, |machine| machine.conn_last_activity())
    }

    /// Operator-visible expected peer identity for a pending handshake `link`,
    /// read from the per-peer machine carrier (the identity's telemetry home now
    /// that the leg no longer projects it). A link with no machine reports
    /// `None`; every leg surfaced by `connections()` is embedded in a machine, so
    /// the lookup resolves.
    pub(crate) fn connection_expected_identity(&self, link: LinkId) -> Option<PeerIdentity> {
        self.peer_machines
            .get(&link)
            .and_then(|machine| machine.conn_expected_identity().copied())
    }

    /// Operator-visible handshake-state string for a pending handshake `link`,
    /// derived from the per-peer control machine (the phase's home now that the
    /// leg no longer carries it). Every leg surfaced by `connections()` is
    /// embedded in a machine, so the lookup resolves; the `"initial"` default is
    /// unreachable in that view and only guards a missing machine.
    pub(crate) fn connection_handshake_state(&self, link: LinkId) -> &'static str {
        self.peer_machines
            .get(&link)
            .map_or("initial", |machine| machine.displayed_handshake_state())
    }

    pub(crate) fn cleanup_bootstrap_transport_if_unused(&mut self, transport_id: TransportId) {
        if !self
            .supervisor
            .nostr_rendezvous
            .is_bootstrap_transport(&transport_id)
        {
            return;
        }

        let transport_in_use = self
            .links
            .values()
            .any(|link| link.transport_id() == transport_id)
            || self.peer_machines.values().any(|machine| {
                machine.leg().is_some() && machine.conn_transport_id() == Some(transport_id)
            })
            || self
                .peers
                .values()
                .any(|peer| peer.transport_id() == Some(transport_id))
            || self
                .peering
                .pending_connects
                .iter()
                .any(|pending| pending.transport_id == transport_id);

        if transport_in_use {
            return;
        }

        tracing::debug!(
            transport_id = %transport_id,
            "bootstrap transport has no remaining references; dropping"
        );

        self.supervisor
            .nostr_rendezvous
            .remove_bootstrap_transport(&transport_id);
        self.transport_drops.remove(&transport_id);
        self.transports.remove(&transport_id);
    }

    /// Iterate over all links.
    pub fn links(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    // === Connection Management (Handshake Phase) ===

    /// The pending connection for `link_id`, read through the control machine
    /// that carries it.
    fn leg(&self, link_id: &LinkId) -> Option<&PeerConnection> {
        self.peer_machines
            .get(link_id)
            .and_then(|machine| machine.leg())
    }

    /// Mutable access to the pending connection for `link_id`.
    fn leg_mut(&mut self, link_id: &LinkId) -> Option<&mut PeerConnection> {
        self.peer_machines
            .get_mut(link_id)
            .and_then(|machine| machine.leg_mut())
    }

    /// Add a pending connection.
    ///
    /// Seeds a control machine for the leg when none exists yet and embeds the
    /// connection on it, for callers that insert a connection directly rather
    /// than through the dial or inbound-msg1 paths, which build the machine
    /// themselves.
    pub fn add_connection(&mut self, connection: PeerConnection) -> Result<(), NodeError> {
        let link_id = connection.state().link_id();

        if self
            .peer_machines
            .get(&link_id)
            .is_some_and(|machine| machine.leg().is_some())
        {
            return Err(NodeError::ConnectionAlreadyExists(link_id));
        }

        if self.max_connections() > 0 && self.connection_count() >= self.max_connections() {
            return Err(NodeError::MaxConnectionsExceeded {
                max: self.max_connections(),
            });
        }

        let machine = self.peer_machines.entry(link_id).or_insert_with(|| {
            let now = connection.started_at();
            match connection.state().expected_identity() {
                Some(identity) if connection.state().is_outbound() => {
                    PeerMachine::new_outbound(link_id, *identity, now)
                }
                _ => PeerMachine::new_inbound(link_id, now),
            }
        });
        // Seed the surviving carrier's peer index and transport from the
        // pre-built leg so the promotion hand-off reads them from the machine,
        // matching the establish paths that write them on the machine directly.
        if let Some(their) = connection.their_index() {
            machine.set_conn_their_index(their);
        }
        if let Some(tid) = connection.transport_id() {
            machine.set_conn_transport_id(tid);
        }
        if let Some(addr) = connection.state().source_addr() {
            machine.set_conn_source_addr(addr.clone());
        }
        machine.set_leg(connection);
        Ok(())
    }

    /// Test-support: seed a control machine for `seed.link_id` the way
    /// [`Node::add_connection`] does, without the caller having to build a
    /// free-standing leg first.
    ///
    /// The carrier seeding below is a verbatim copy of `add_connection`'s: the
    /// two conditional writes (`their_index`, `transport_id`) and `set_leg`,
    /// built through the same `entry(..).or_insert_with(..)` so an existing
    /// leg-less machine keeps its constructor-side fields. Nothing else is
    /// written to the carrier — `our_index`, `source_addr`, post-construction
    /// `started_at`, and the stored handshake bytes stay leg-only, exactly as
    /// they do for a test that goes through `add_connection` today.
    ///
    /// The duplication is deliberate: keeping the carrier writes visible here
    /// is what lets each later step of the leg dissolution revise them at a
    /// single reviewable site. The two bodies must stay in sync until
    /// `add_connection` itself is removed; any drift surfaces as a test
    /// failure while both paths still exist.
    #[cfg(test)]
    pub(crate) fn seed_handshake_machine(&mut self, seed: HandshakeSeed) -> Result<(), NodeError> {
        let link_id = seed.link_id;

        let mut connection = match seed.expected_identity {
            Some(identity) => PeerConnection::outbound(link_id, identity, seed.started_at_ms),
            None => PeerConnection::inbound(link_id, seed.started_at_ms),
        };
        if let Some(id) = seed.transport_id {
            connection.set_transport_id(id);
        }
        let seeded_source_addr = seed.source_addr.clone();
        if let Some(index) = seed.our_index {
            connection.set_our_index(index);
        }
        if let Some(index) = seed.their_index {
            connection.set_their_index(index);
        }

        if self
            .peer_machines
            .get(&link_id)
            .is_some_and(|machine| machine.leg().is_some())
        {
            return Err(NodeError::ConnectionAlreadyExists(link_id));
        }

        if self.max_connections() > 0 && self.connection_count() >= self.max_connections() {
            return Err(NodeError::MaxConnectionsExceeded {
                max: self.max_connections(),
            });
        }

        let machine = self.peer_machines.entry(link_id).or_insert_with(|| {
            let now = connection.started_at();
            match connection.state().expected_identity() {
                Some(identity) if connection.state().is_outbound() => {
                    PeerMachine::new_outbound(link_id, *identity, now)
                }
                _ => PeerMachine::new_inbound(link_id, now),
            }
        });
        if let Some(their) = connection.their_index() {
            machine.set_conn_their_index(their);
        }
        if let Some(tid) = connection.transport_id() {
            machine.set_conn_transport_id(tid);
        }
        if let Some(addr) = seeded_source_addr {
            machine.set_conn_source_addr(addr);
        }
        machine.set_leg(connection);
        Ok(())
    }

    /// Get a connection by LinkId.
    pub fn get_connection(&self, link_id: &LinkId) -> Option<&PeerConnection> {
        self.leg(link_id)
    }

    /// Get a mutable connection by LinkId.
    pub fn get_connection_mut(&mut self, link_id: &LinkId) -> Option<&mut PeerConnection> {
        self.leg_mut(link_id)
    }

    /// Remove a connection, disposing its control machine alongside
    /// (the disposal complement of `add_connection`'s machine seeding). The
    /// connection is taken off the machine BEFORE the machine is dropped, so
    /// the caller still receives it.
    pub fn remove_connection(&mut self, link_id: &LinkId) -> Option<PeerConnection> {
        let connection = self
            .peer_machines
            .get_mut(link_id)
            .and_then(|machine| machine.take_leg());
        self.remove_peer_machine(*link_id);
        connection
    }

    /// Iterate over the control machines that carry a pending connection.
    ///
    /// Carrying a pending connection is what makes a machine handshake-phase,
    /// so the filter below is the membership rule. It is the same predicate
    /// that `connection_count` applies, and the one the stale-connection sweep
    /// narrows further.
    ///
    /// Internal to the crate: this yields the control machine, which is not
    /// part of the published surface. Callers outside the crate that need a
    /// view of the pending handshakes go through the operator queries.
    pub(crate) fn connections(&self) -> impl Iterator<Item = (&LinkId, &PeerMachine)> {
        self.peer_machines
            .iter()
            .filter(|(_, machine)| machine.leg().is_some())
    }

    // === Peer Management (Active Phase) ===

    /// Get a peer by NodeAddr.
    pub fn get_peer(&self, node_addr: &NodeAddr) -> Option<&ActivePeer> {
        self.peers.get(node_addr)
    }

    /// Get a mutable peer by NodeAddr.
    pub fn get_peer_mut(&mut self, node_addr: &NodeAddr) -> Option<&mut ActivePeer> {
        self.peers.get_mut(node_addr)
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, node_addr: &NodeAddr) -> Option<ActivePeer> {
        self.peers.remove(node_addr)
    }

    /// Iterate over all peers.
    pub fn peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values()
    }

    /// Reference to the Nostr discovery handle if discovery is enabled.
    /// Used by control queries (`show_peers` per-peer Nostr-traversal
    /// state) to read failure-state without taking shared ownership.
    pub fn nostr_rendezvous_handle(&self) -> Option<&crate::nostr::NostrRendezvous> {
        self.supervisor.nostr_rendezvous.engine()
    }

    /// Iterate over all peer node IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NodeAddr> {
        self.peers.keys()
    }

    /// Iterate over peers that can send traffic.
    pub fn sendable_peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values().filter(|p| p.can_send())
    }

    /// Number of peers that can send traffic.
    pub fn sendable_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.can_send()).count()
    }

    // === End-to-End Sessions ===

    /// Get a session by remote NodeAddr.
    /// Disable the discovery forward rate limiter (for tests).
    #[cfg(test)]
    pub(crate) fn disable_discovery_forward_rate_limit(&mut self) {
        self.lookup.forward_limiter.set_interval_ms(0);
    }

    #[cfg(test)]
    pub(crate) fn get_session(&self, remote: &NodeAddr) -> Option<&SessionEntry> {
        self.sessions.get(remote)
    }

    /// Get a mutable session by remote NodeAddr.
    #[cfg(test)]
    pub(crate) fn get_session_mut(&mut self, remote: &NodeAddr) -> Option<&mut SessionEntry> {
        self.sessions.get_mut(remote)
    }

    /// Remove a session.
    #[cfg(test)]
    pub(crate) fn remove_session(&mut self, remote: &NodeAddr) -> Option<SessionEntry> {
        self.sessions.remove(remote)
    }

    /// Read the path_mtu_lookup entry for a destination FipsAddress.
    #[cfg(test)]
    pub(crate) fn path_mtu_lookup_get(&self, fips_addr: &crate::FipsAddress) -> Option<u16> {
        self.path_mtu_lookup
            .read()
            .ok()
            .and_then(|map| map.get(fips_addr).copied())
    }

    /// Write a path_mtu_lookup entry directly (for tests that pre-seed the map).
    #[cfg(test)]
    pub(crate) fn path_mtu_lookup_insert(&self, fips_addr: crate::FipsAddress, mtu: u16) {
        if let Ok(mut map) = self.path_mtu_lookup.write() {
            map.insert(fips_addr, mtu);
        }
    }

    /// Number of end-to-end sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Iterate over all session entries (for control queries).
    pub(crate) fn session_entries(&self) -> impl Iterator<Item = (&NodeAddr, &SessionEntry)> {
        self.sessions.iter()
    }

    // === Identity Cache ===

    /// Register a node in the identity cache for FipsAddress → NodeAddr lookup.
    pub(crate) fn register_identity(&mut self, node_addr: NodeAddr, pubkey: secp256k1::PublicKey) {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&node_addr.as_bytes()[0..15]);
        self.identity_cache
            .insert(prefix, (node_addr, pubkey, Self::now_ms()));
        // LRU eviction
        let max = self.config().node.cache.identity_size;
        if self.identity_cache.len() > max
            && let Some(oldest_key) = self
                .identity_cache
                .iter()
                .min_by_key(|(_, (_, _, ts))| *ts)
                .map(|(k, _)| *k)
        {
            self.identity_cache.remove(&oldest_key);
        }
    }

    /// Look up a destination by FipsAddress prefix (bytes 1-15 of the IPv6 address).
    pub(crate) fn lookup_by_fips_prefix(
        &mut self,
        prefix: &[u8; 15],
    ) -> Option<(NodeAddr, secp256k1::PublicKey)> {
        if let Some(entry) = self.identity_cache.get_mut(prefix) {
            entry.2 = Self::now_ms(); // LRU touch
            Some((entry.0, entry.1))
        } else {
            None
        }
    }

    /// Check if a node's identity is in the cache (without LRU touch).
    pub(crate) fn has_cached_identity(&self, addr: &NodeAddr) -> bool {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&addr.as_bytes()[0..15]);
        self.identity_cache.contains_key(&prefix)
    }

    /// Number of identity cache entries.
    pub fn identity_cache_len(&self) -> usize {
        self.identity_cache.len()
    }

    /// Iterate over identity cache entries.
    ///
    /// Returns `(NodeAddr, PublicKey, last_seen_ms)` for each cached identity.
    /// Used by the `show_identity_cache` control query.
    pub fn identity_cache_iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &secp256k1::PublicKey, u64)> {
        self.identity_cache
            .values()
            .map(|(addr, pk, ts)| (addr, pk, *ts))
    }

    /// Configured maximum identity cache size.
    pub fn identity_cache_max(&self) -> usize {
        self.config().node.cache.identity_size
    }

    /// Number of pending discovery lookups.
    pub fn pending_lookup_count(&self) -> usize {
        self.lookup.pending_lookups.len()
    }

    /// Iterate over pending discovery lookups for diagnostics.
    pub fn pending_lookups_iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &crate::proto::lookup::PendingLookup)> {
        self.lookup.pending_lookups.iter()
    }

    /// Number of recent discovery requests tracked.
    pub fn recent_request_count(&self) -> usize {
        self.lookup.recent_requests.len()
    }

    /// Count of destinations with queued TUN packets awaiting session setup.
    pub fn pending_tun_destinations(&self) -> usize {
        self.pending_tun_packets.len()
    }

    /// Total TUN packets queued across all destinations.
    pub fn pending_tun_total_packets(&self) -> usize {
        self.pending_tun_packets.values().map(|q| q.len()).sum()
    }

    /// Iterate over retry state for diagnostics.
    pub fn retry_state_iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &peering::retry::RetryState)> {
        self.peering.reconciler.retry_pending.iter()
    }

    // === Routing ===

    /// Check if a peer is a tree neighbor (parent or child in the spanning tree).
    ///
    /// Returns true if the peer is our current tree parent, or if the peer
    /// has declared us as their parent (making them our child).
    pub(crate) fn is_tree_peer(&self, peer_addr: &NodeAddr) -> bool {
        // Peer is our parent
        if !self.tree_state.is_root() && self.tree_state.my_declaration().parent_id() == peer_addr {
            return true;
        }
        // Peer is our child (their declaration names us as parent)
        if let Some(decl) = self.tree_state.peer_declaration(peer_addr)
            && decl.parent_id() == self.node_addr()
        {
            return true;
        }
        false
    }

    /// Find next hop for a destination node address.
    ///
    /// Routing priority:
    /// 1. Destination is self → `None` (local delivery)
    /// 2. Destination is a direct peer → that peer
    /// 3. Bloom filter candidates with cached dest coords → among peers whose
    ///    bloom filter contains the destination, pick the one that minimizes
    ///    tree distance to the destination, with
    ///    `(link_cost, tree_distance_to_dest, node_addr)` tie-breaking.
    ///    The self-distance check ensures only peers strictly closer to the
    ///    destination than us are considered (prevents routing loops).
    /// 4. Greedy tree routing fallback (requires cached dest coords)
    /// 5. No route → `None`
    ///
    /// Both the bloom filter and tree routing paths require cached destination
    /// coordinates (checked in `coord_cache`). Without coordinates, the node
    /// cannot make loop-free forwarding decisions. The caller should signal
    /// `CoordsRequired` back to the source when `None` is returned for a
    /// non-local destination.
    pub fn find_next_hop(&mut self, dest_node_addr: &NodeAddr) -> Option<&ActivePeer> {
        // 1. Local delivery
        if dest_node_addr == self.node_addr() {
            return None;
        }

        // 2. Direct peer
        if let Some(peer) = self.peers.get(dest_node_addr)
            && peer.can_send()
        {
            return Some(peer);
        }

        // Look up cached destination coordinates (required by both bloom and tree paths).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let dest_coords = self
            .coord_cache
            .get_and_touch(dest_node_addr, now_ms)?
            .clone();

        // 3. Bloom filter candidates — requires dest_coords for loop-free selection.
        //    If no candidate is strictly closer, fall through to tree routing.
        //    The sans-IO core assembles the candidate snapshot over the
        //    `RoutingView` seam (enumerate peers, apply the bloom `may_reach`
        //    filter, snapshot each), then picks the winner; the shell supplies
        //    only the raw per-peer reads.
        let candidates = {
            let view = NodeRoutingView {
                coord_cache: &self.coord_cache,
                peers: &self.peers,
                tree_state: &self.tree_state,
                congested: false,
            };
            routing::routing_candidates(&view, dest_node_addr)
        };
        if !candidates.is_empty()
            && let Some(next_hop) = routing::select_best_candidate(
                &candidates,
                &dest_coords,
                self.tree_state.my_coords(),
            )
        {
            return self.peers.get(&next_hop);
        }

        // 4. Greedy tree routing fallback. No peers are excluded from transit
        //    on this branch; the non-full/leaf skip is a next-only refinement.
        let next_hop_id = self
            .tree_state
            .find_next_hop(&dest_coords, &BTreeSet::new())?;

        self.peers.get(&next_hop_id).filter(|p| p.can_send())
    }

    /// Classify a transit forward by route class from tree coordinates.
    ///
    /// Thin shell adapter over the pure [`routing::classify_forward`]: it
    /// pre-resolves the destination coordinates from the coord cache (the
    /// sole impurity — a read-only lookup, no LRU touch) and reads our own
    /// and the chosen peer's coordinates from tree state, then defers the
    /// six-way classification to the sans-IO routing core.
    pub(crate) fn classify_forward(
        &self,
        dest: &NodeAddr,
        chosen_peer: &NodeAddr,
    ) -> metrics::RouteClass {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let dest_coords = self.coord_cache.get(dest, now_ms).cloned();
        routing::classify_forward(
            dest,
            chosen_peer,
            self.node_addr(),
            self.tree_state.my_coords(),
            dest_coords.as_ref(),
            self.tree_state.peer_coords(chosen_peer),
        )
    }

    /// Get the TUN packet sender channel.
    ///
    /// Returns None if TUN is not active or the node hasn't been started.
    pub fn tun_tx(&self) -> Option<&TunTx> {
        self.supervisor.tun_tx.as_ref()
    }

    /// Set up an **app-owned TUN**: rather than FIPS creating a system TUN
    /// device, the embedder (e.g. an Android `VpnService`) owns the fd and
    /// exchanges IPv6 packet bytes with FIPS over the returned channels. Call
    /// this after [`Node::new`] and **before** [`Self::start`] — and before
    /// moving the node into a background task.
    ///
    /// Returns `(app_outbound_tx, app_inbound_rx)`:
    /// - push IPv6 packets read from the app's TUN fd into `app_outbound_tx`
    ///   (app → mesh); FIPS routes them to the destination node.
    /// - pull IPv6 packets destined for the app's TUN fd from `app_inbound_rx`
    ///   (mesh → app) and write them to the fd (`recv_timeout` for clean stop).
    ///
    /// With this set, [`Self::start`] skips system-TUN creation (it gates on
    /// `tun_tx` being unset). Packets pushed into `app_outbound_tx` bypass the
    /// system-TUN reader's `handle_tun_packet`, so the embedder must do what that
    /// path otherwise would: push only `fd::/8`-destined IPv6 packets — FIPS no
    /// longer filters the destination or emits ICMPv6 unreachable for off-mesh
    /// dests — and clamp TCP MSS on outbound SYNs.
    pub fn enable_app_owned_tun(&mut self) -> (TunOutboundTx, std::sync::mpsc::Receiver<Vec<u8>>) {
        let tun_channel_size = self.config().node.buffers.tun_channel;
        // app → mesh: the app pushes; `run_rx_loop` drains `tun_outbound_rx`.
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(tun_channel_size);
        // mesh → app: the node writes inbound packets to `tun_tx`; the app pulls.
        let (tun_tx, tun_rx) = std::sync::mpsc::channel();
        self.supervisor.tun_tx = Some(tun_tx);
        self.supervisor.tun_outbound_rx = Some(outbound_rx);
        self.tun_state = TunState::Active;
        (outbound_tx, tun_rx)
    }

    // === Sending ===

    /// Encrypt and send a link-layer message to an authenticated peer.
    ///
    /// The plaintext should include the message type byte followed by the
    /// message-specific payload (e.g., `[0x50, reason]` for Disconnect).
    ///
    /// The send path prepends a 4-byte session-relative timestamp (inner
    /// header) before encryption. The full 16-byte outer header is used
    /// as AAD for the AEAD construction.
    ///
    /// This is the standard path for sending any link-layer control message
    /// to a peer over their encrypted Noise session.
    pub(super) async fn send_encrypted_link_message(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
    ) -> Result<(), NodeError> {
        self.send_encrypted_link_message_with_ce(node_addr, plaintext, false)
            .await
    }

    /// Like `send_encrypted_link_message` but allows setting the FMP CE flag.
    ///
    /// Used by the forwarding path to relay congestion signals hop-by-hop.
    pub(super) async fn send_encrypted_link_message_with_ce(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
    ) -> Result<(), NodeError> {
        let peer = self
            .peers
            .get_mut(node_addr)
            .ok_or(NodeError::PeerNotFound(*node_addr))?;

        let their_index = peer.their_index().ok_or_else(|| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: "no their_index".into(),
        })?;
        let transport_id = peer.transport_id().ok_or_else(|| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: "no transport_id".into(),
        })?;
        let remote_addr = peer
            .current_addr()
            .cloned()
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "no current_addr".into(),
            })?;

        // Prepend 4-byte session-relative timestamp (inner header)
        let timestamp_ms = peer.session_elapsed_ms();

        // MMP: read spin bit value before entering session borrow
        let sp_flag = peer.mmp().map(|mmp| mmp.spin_bit.tx_bit()).unwrap_or(false);
        let mut flags = if sp_flag { FLAG_SP } else { 0 };
        if ce_flag {
            flags |= FLAG_CE;
        }
        if peer.current_k_bit() {
            flags |= FLAG_KEY_EPOCH;
        }

        // Snapshot the per-peer connect()-ed UDP socket BEFORE the
        // session borrow so the encrypt-worker dispatch can refcount-
        // clone the Arc without re-borrowing self.peers later.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let connected_socket = peer.connected_udp();

        let session = peer
            .noise_session_mut()
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *node_addr,
                reason: "no noise session".into(),
            })?;

        // ── Off-task encrypt + sendmmsg/GSO fast path (unix + UDP) ──
        // Build the wire buffer directly as
        // `[16-byte header][4-byte timestamp][plaintext]` with
        // TAG_SIZE trailing capacity for the AEAD tag — one alloc,
        // one extend, no intermediate `inner_plaintext` Vec. The
        // worker `seal_in_place_separate_tag`s on `wire_buf[16..]`
        // and appends the tag — buffer IS the wire packet.
        const INNER_TS_LEN: usize = 4;
        let inner_len = INNER_TS_LEN + plaintext.len();
        let payload_len = inner_len as u16;

        #[cfg(unix)]
        {
            let send_cipher_opt = session.send_cipher_clone();
            if let Some(fmp_cipher) = send_cipher_opt
                && let Some(workers) = self.supervisor.encrypt_workers.as_ref().cloned()
                && let Some(transport) = self.transports.get(&transport_id)
                && let TransportHandle::Udp(udp) = transport
                && let Some(socket) = udp.async_socket()
            {
                // Skip per-packet DNS resolve on the steady-state path
                // when the connected socket already knows the peer
                // address (kernel 5-tuple cache wins over re-parsing
                // the configured TransportAddr).
                let socket_addr_opt = {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    {
                        match connected_socket.as_ref() {
                            Some(s) => Some(s.peer_addr()),
                            None => udp.resolve_for_off_task(&remote_addr).await.ok(),
                        }
                    }
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    {
                        udp.resolve_for_off_task(&remote_addr).await.ok()
                    }
                };
                if let Some(dest_socket_addr) = socket_addr_opt {
                    let counter =
                        session
                            .take_send_counter()
                            .map_err(|e| NodeError::SendFailed {
                                node_addr: *node_addr,
                                reason: format!("counter reservation failed: {}", e),
                            })?;
                    let header = build_established_header(their_index, counter, flags, payload_len);
                    let wire_capacity =
                        ESTABLISHED_HEADER_SIZE + inner_len + crate::noise::TAG_SIZE;
                    let mut wire_buf = Vec::with_capacity(wire_capacity);
                    wire_buf.extend_from_slice(&header);
                    wire_buf.extend_from_slice(&timestamp_ms.to_le_bytes());
                    wire_buf.extend_from_slice(plaintext);

                    let predicted_bytes = wire_capacity;
                    // Drop bulk endpoint data on UDP backpressure to
                    // keep the queue moving; control frames retry.
                    let drop_on_backpressure = plaintext.first().is_some_and(|t| *t == 0x00);
                    workers.dispatch(crate::node::encrypt_worker::FmpSendJob {
                        cipher: fmp_cipher,
                        counter,
                        wire_buf,
                        fsp_seal: None,
                        socket,
                        dest_addr: dest_socket_addr,
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        connected_socket,
                        drop_on_backpressure,
                        queued_at: None,
                    });

                    if let Some(peer) = self.peers.get_mut(node_addr) {
                        peer.link_stats_mut().record_sent(predicted_bytes);
                        if let Some(mmp) = peer.mmp_mut() {
                            mmp.sender
                                .record_sent(counter, timestamp_ms, predicted_bytes);
                        }
                    }
                    return Ok(());
                }
            }
        }

        // Legacy inline path: only reached for non-UDP transports or
        // unit-test mode (no worker pool spawned). Materialise the
        // inner plaintext lazily here so the worker path above
        // avoids the alloc.
        let inner_plaintext = prepend_inner_header(timestamp_ms, plaintext);

        // Build 16-byte outer header (used as AAD for AEAD)
        let counter = session.current_send_counter();
        let header = build_established_header(their_index, counter, flags, payload_len);

        // Encrypt with AAD binding to the outer header
        let ciphertext = session
            .encrypt_with_aad(&inner_plaintext, &header)
            .map_err(|e| NodeError::SendFailed {
                node_addr: *node_addr,
                reason: format!("encryption failed: {}", e),
            })?;

        let wire_packet = build_encrypted(&header, &ciphertext);

        // Re-borrow peer for stats update after sending
        let transport = self
            .transports
            .get(&transport_id)
            .ok_or(NodeError::TransportNotFound(transport_id))?;

        // Gate: don't drive connect-on-send from the tick path. If the
        // transport's connection isn't ready, kick off a non-blocking
        // background connect (no-op if already in flight or pooled) and
        // fail this send fast. A subsequent tick will retry once the
        // pool entry exists. The historical connect-on-send wedged the
        // rx_loop tick body for up to `connect_timeout_ms` (5 s default)
        // per unreachable peer, which under convergence-phase mesh
        // pressure cascaded into multi-tick stalls and control-RPC HOL.
        match transport.connection_state(&remote_addr) {
            ConnectionState::Connected => {}
            other => {
                if matches!(other, ConnectionState::None) {
                    let _ = transport.connect(&remote_addr).await;
                }
                return Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!("transport connection not ready: {:?}", other),
                });
            }
        }

        let bytes_sent = transport
            .send(&remote_addr, &wire_packet)
            .await
            .map_err(|e| match e {
                TransportError::MtuExceeded { packet_size, mtu } => NodeError::MtuExceeded {
                    node_addr: *node_addr,
                    packet_size,
                    mtu,
                },
                other => NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!("transport send: {}", other),
                },
            })?;

        // Update send statistics
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.link_stats_mut().record_sent(bytes_sent);
            // MMP: record sent frame for sender report generation
            if let Some(mmp) = peer.mmp_mut() {
                mmp.sender.record_sent(counter, timestamp_ms, bytes_sent);
            }
        }

        Ok(())
    }
}

/// Shell-side [`routing::RoutingView`] seam over live `Node` state — the sole
/// routing read adapter the shell retains. It hands the sans-IO routing core
/// raw per-peer reads (enumeration plus `may_reach` / `can_send` / `link_cost`
/// / `coords`) so the candidate assembly, selection, and error synthesis all
/// live in `proto::routing::core`; no routing decision or assembly logic
/// remains here.
///
/// Field-narrowed to `coord_cache` + `peers` + `tree_state` (never `&Node`
/// whole) so it borrows disjointly from `&mut self.routing` on the
/// forward/synth path, where the handler also holds the mutable `Router`.
///
/// Two call sites:
/// - `find_next_hop` builds it to assemble bloom candidates via the `peer_*`
///   reads; it never queries `is_congested`, so it leaves `congested` false.
/// - `handle_session_datagram` builds it for `Router::route` / `synth_*`,
///   which read `is_congested` (precomputed once for the resolved next hop)
///   and `cached_coords`.
pub(in crate::node) struct NodeRoutingView<'a> {
    pub(in crate::node) coord_cache: &'a CoordCache,
    pub(in crate::node) peers: &'a HashMap<NodeAddr, ActivePeer>,
    pub(in crate::node) tree_state: &'a TreeState,
    pub(in crate::node) congested: bool,
}

impl routing::RoutingView for NodeRoutingView<'_> {
    fn is_congested(&self, _next_hop: &NodeAddr) -> bool {
        self.congested
    }

    fn cached_coords(&self, dest: &NodeAddr, now_ms: u64) -> Option<TreeCoordinate> {
        self.coord_cache.get(dest, now_ms).cloned()
    }

    fn peer_addrs(&self) -> Vec<NodeAddr> {
        self.peers.keys().copied().collect()
    }

    fn peer_may_reach(&self, peer: &NodeAddr, dest: &NodeAddr) -> bool {
        self.peers.get(peer).is_some_and(|p| p.may_reach(dest))
    }

    fn peer_can_send(&self, peer: &NodeAddr) -> bool {
        self.peers.get(peer).is_some_and(|p| p.can_send())
    }

    fn peer_link_cost(&self, peer: &NodeAddr) -> f64 {
        self.peers
            .get(peer)
            .map_or(f64::INFINITY, |p| p.link_cost())
    }

    fn peer_coords(&self, peer: &NodeAddr) -> Option<TreeCoordinate> {
        self.tree_state.peer_coords(peer).cloned()
    }
}

/// Project an MMP metrics block into the snapshot
/// [`EntityMmp`](crate::control::snapshot::EntityMmp) shared by `show_peers`
/// (link-layer, `path_mtu = None`) and `show_sessions` (session-layer,
/// `path_mtu = Some`). `quality_index` (`lqi` for peers / `sqi` for sessions)
/// is precomputed here exactly as the on-loop queries do, so the render is a
/// plain field emit.
fn project_entity_mmp(
    metrics: &crate::proto::mmp::MmpMetrics,
    mode: String,
    path_mtu: Option<u16>,
) -> crate::control::snapshot::EntityMmp {
    let srtt_ms = metrics.srtt_ms();
    let smoothed_etx = metrics.smoothed_etx();
    let quality_index = match (srtt_ms, smoothed_etx) {
        (Some(srtt), Some(setx)) => Some(setx * (1.0 + srtt / 100.0)),
        _ => None,
    };
    crate::control::snapshot::EntityMmp {
        mode,
        srtt_ms,
        loss_rate: metrics.loss_rate(),
        etx: metrics.etx,
        goodput_bps: metrics.goodput_bps,
        delivery_ratio_forward: metrics.delivery_ratio_forward,
        delivery_ratio_reverse: metrics.delivery_ratio_reverse,
        smoothed_loss: metrics.smoothed_loss(),
        smoothed_etx,
        quality_index,
        path_mtu,
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("node_addr", self.node_addr())
            .field("state", &self.supervisor.state)
            .field("is_leaf_only", &self.is_leaf_only())
            .field("connections", &self.connection_count())
            .field("peers", &self.peer_count())
            .field("links", &self.link_count())
            .field("transports", &self.transport_count())
            .finish()
    }
}

/// Test-support seed spec for [`Node::seed_handshake_machine`].
///
/// Mirrors the leg constructors plus the setters tests apply to a connection
/// *before* handing it to `add_connection`. Only fields that exist on the leg
/// at add time belong here; crypto is run afterwards through
/// `get_connection_mut`, which `add_connection` never reads.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct HandshakeSeed {
    link_id: LinkId,
    expected_identity: Option<PeerIdentity>,
    started_at_ms: u64,
    transport_id: Option<TransportId>,
    source_addr: Option<TransportAddr>,
    our_index: Option<crate::utils::index::SessionIndex>,
    their_index: Option<crate::utils::index::SessionIndex>,
}

#[cfg(test)]
impl HandshakeSeed {
    /// Outbound leg: we know who we are dialing.
    pub(crate) fn outbound(
        link_id: LinkId,
        expected_identity: PeerIdentity,
        started_at_ms: u64,
    ) -> Self {
        Self {
            link_id,
            expected_identity: Some(expected_identity),
            started_at_ms,
            transport_id: None,
            source_addr: None,
            our_index: None,
            their_index: None,
        }
    }

    /// Inbound leg: identity is unknown until msg1 decrypts.
    pub(crate) fn inbound(link_id: LinkId, started_at_ms: u64) -> Self {
        Self {
            link_id,
            expected_identity: None,
            started_at_ms,
            transport_id: None,
            source_addr: None,
            our_index: None,
            their_index: None,
        }
    }

    pub(crate) fn with_transport_id(mut self, transport_id: TransportId) -> Self {
        self.transport_id = Some(transport_id);
        self
    }

    pub(crate) fn with_source_addr(mut self, source_addr: TransportAddr) -> Self {
        self.source_addr = Some(source_addr);
        self
    }

    pub(crate) fn with_our_index(mut self, index: crate::utils::index::SessionIndex) -> Self {
        self.our_index = Some(index);
        self
    }

    pub(crate) fn with_their_index(mut self, index: crate::utils::index::SessionIndex) -> Self {
        self.their_index = Some(index);
        self
    }
}
