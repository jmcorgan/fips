//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

mod bloom;
mod handlers;
mod lifecycle;
mod retry;
mod rate_limit;
mod routing_error_rate_limit;
pub(crate) mod session;
pub(crate) mod session_wire;
pub(crate) mod wire;
pub(crate) mod stats;
mod tree;
#[cfg(test)]
mod tests;

use crate::bloom::BloomState;
use crate::cache::CoordCache;
use crate::utils::index::IndexAllocator;
use crate::node::session::SessionEntry;
use crate::peer::{ActivePeer, PeerConnection};
use self::rate_limit::HandshakeRateLimiter;
use self::routing_error_rate_limit::RoutingErrorRateLimiter;
use crate::transport::{
    Link, LinkId, PacketRx, PacketTx, TransportAddr, TransportError, TransportHandle, TransportId,
};
use crate::transport::udp::UdpTransport;
use crate::transport::tcp::TcpTransport;
#[cfg(target_os = "linux")]
use crate::transport::ethernet::EthernetTransport;
use crate::tree::TreeState;
use crate::upper::icmp_rate_limit::IcmpRateLimiter;
use crate::upper::tun::{TunError, TunOutboundRx, TunState, TunTx};
use self::wire::{build_encrypted, build_established_header, prepend_inner_header, FLAG_SP};
use crate::{Config, ConfigError, Identity, IdentityError, NodeAddr, PeerIdentity};
use rand::Rng;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::thread::JoinHandle;
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
    MtuExceeded { node_addr: NodeAddr, packet_size: usize, mtu: u16 },

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
}

/// Node operational state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeState {
    /// Created but not started.
    Created,
    /// Starting up (initializing transports).
    Starting,
    /// Fully operational.
    Running,
    /// Shutting down.
    Stopping,
    /// Stopped.
    Stopped,
}

impl NodeState {
    /// Check if node is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, NodeState::Running)
    }

    /// Check if node can be started.
    pub fn can_start(&self) -> bool {
        matches!(self, NodeState::Created | NodeState::Stopped)
    }

    /// Check if node can be stopped.
    pub fn can_stop(&self) -> bool {
        matches!(self, NodeState::Running)
    }
}

impl fmt::Display for NodeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            NodeState::Created => "created",
            NodeState::Starting => "starting",
            NodeState::Running => "running",
            NodeState::Stopping => "stopping",
            NodeState::Stopped => "stopped",
        };
        write!(f, "{}", s)
    }
}

/// Recent request tracking for dedup and reverse-path forwarding.
///
/// When a LookupRequest is forwarded through a node, the node stores the
/// request_id and which peer sent it. When the corresponding LookupResponse
/// arrives, it's forwarded back to that peer (reverse-path forwarding).
#[derive(Clone, Debug)]
pub(crate) struct RecentRequest {
    /// The peer who sent this request to us.
    pub(crate) from_peer: NodeAddr,
    /// When we received this request (Unix milliseconds).
    pub(crate) timestamp_ms: u64,
}

impl RecentRequest {
    pub(crate) fn new(from_peer: NodeAddr, timestamp_ms: u64) -> Self {
        Self {
            from_peer,
            timestamp_ms,
        }
    }

    /// Check if this entry has expired (older than expiry_ms).
    pub(crate) fn is_expired(&self, current_time_ms: u64, expiry_ms: u64) -> bool {
        current_time_ms.saturating_sub(self.timestamp_ms) > expiry_ms
    }
}

/// Key for addr_to_link reverse lookup.
type AddrKey = (TransportId, TransportAddr);

/// A running FIPS node instance.
///
/// This is the top-level container holding all node state.
///
/// ## Peer Lifecycle
///
/// Peers go through two phases:
/// 1. **Connection phase** (`connections`): Handshake in progress, indexed by LinkId
/// 2. **Active phase** (`peers`): Authenticated, indexed by NodeAddr
///
/// The `addr_to_link` map enables dispatching incoming packets to the right
/// connection before authentication completes.
// Discovery lookup constants moved to config: node.discovery.timeout_secs, node.discovery.ttl
pub struct Node {
    // === Identity ===
    /// This node's cryptographic identity.
    identity: Identity,

    /// Random epoch generated at startup for peer restart detection.
    /// Exchanged inside Noise handshake messages so peers can detect restarts.
    startup_epoch: [u8; 8],

    // === Configuration ===
    /// Loaded configuration.
    config: Config,

    // === State ===
    /// Node operational state.
    state: NodeState,

    /// Whether this is a leaf-only node.
    is_leaf_only: bool,

    // === Spanning Tree ===
    /// Local spanning tree state.
    tree_state: TreeState,

    // === Bloom Filter ===
    /// Local Bloom filter state.
    bloom_state: BloomState,

    // === Routing ===
    /// Address -> coordinates cache (from session setup and discovery).
    coord_cache: CoordCache,
    /// Recent discovery requests (dedup + reverse-path forwarding).
    /// Maps request_id → RecentRequest.
    recent_requests: HashMap<u64, RecentRequest>,

    // === Transports & Links ===
    /// Active transports (owned by Node).
    transports: HashMap<TransportId, TransportHandle>,
    /// Active links.
    links: HashMap<LinkId, Link>,
    /// Reverse lookup: (transport_id, remote_addr) -> link_id.
    addr_to_link: HashMap<AddrKey, LinkId>,

    // === Packet Channel ===
    /// Packet sender for transports.
    packet_tx: Option<PacketTx>,
    /// Packet receiver (for event loop).
    packet_rx: Option<PacketRx>,

    // === Connections (Handshake Phase) ===
    /// Pending connections (handshake in progress).
    /// Indexed by LinkId since we don't know the peer's identity yet.
    connections: HashMap<LinkId, PeerConnection>,

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

    // === Pending Discovery Lookups ===
    /// Tracks in-flight discovery lookups. Maps target NodeAddr to the
    /// initiation timestamp (Unix ms). Prevents duplicate flood queries.
    pending_lookups: HashMap<NodeAddr, u64>,

    // === Resource Limits ===
    /// Maximum connections (0 = unlimited).
    max_connections: usize,
    /// Maximum peers (0 = unlimited).
    max_peers: usize,
    /// Maximum links (0 = unlimited).
    max_links: usize,

    // === Counters ===
    /// Next link ID to allocate.
    next_link_id: u64,
    /// Next transport ID to allocate.
    next_transport_id: u32,

    // === Node Statistics ===
    /// Routing, forwarding, discovery, and error signal counters.
    stats: stats::NodeStats,

    // === TUN Interface ===
    /// TUN device state.
    tun_state: TunState,
    /// TUN interface name (for cleanup).
    tun_name: Option<String>,
    /// TUN packet sender channel.
    tun_tx: Option<TunTx>,
    /// Receiver for outbound packets from the TUN reader.
    tun_outbound_rx: Option<TunOutboundRx>,
    /// TUN reader thread handle.
    tun_reader_handle: Option<JoinHandle<()>>,
    /// TUN writer thread handle.
    tun_writer_handle: Option<JoinHandle<()>>,

    // === DNS Responder ===
    /// Receiver for resolved identities from the DNS responder.
    dns_identity_rx: Option<crate::upper::dns::DnsIdentityRx>,
    /// DNS responder task handle.
    dns_task: Option<tokio::task::JoinHandle<()>>,

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
    /// Rate limiter for routing error signals (CoordsRequired / PathBroken).
    routing_error_rate_limiter: RoutingErrorRateLimiter,
    /// Rate limiter for source-side CoordsRequired/PathBroken responses.
    coords_response_rate_limiter: RoutingErrorRateLimiter,

    // === Connection Retry ===
    /// Retry state for peers whose outbound connections have failed.
    /// Keyed by NodeAddr. Entries are created when a handshake times out
    /// or fails, and removed on successful promotion or when max retries
    /// are exhausted.
    retry_pending: HashMap<NodeAddr, retry::RetryState>,

    // === Periodic Parent Re-evaluation ===
    /// Timestamp of last periodic parent re-evaluation (for pacing).
    last_parent_reeval: Option<std::time::Instant>,

    // === Display Names ===
    /// Human-readable names for configured peers (alias or short npub).
    /// Populated at startup from peer config.
    peer_aliases: HashMap<NodeAddr, String>,
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(config: Config) -> Result<Self, NodeError> {
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
        let mut tree_state = TreeState::new(node_addr);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree_state
            .sign_declaration(&identity)
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

        Ok(Self {
            identity,
            startup_epoch,
            config,
            state: NodeState::Created,
            is_leaf_only,
            tree_state,
            bloom_state,
            coord_cache,
            recent_requests: HashMap::new(),
            transports: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_tx: None,
            packet_rx: None,
            connections: HashMap::new(),
            peers: HashMap::new(),
            sessions: HashMap::new(),
            identity_cache: HashMap::new(),
            pending_tun_packets: HashMap::new(),
            pending_lookups: HashMap::new(),
            max_connections,
            max_peers,
            max_links,
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_outbound_rx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
            dns_identity_rx: None,
            dns_task: None,
            index_allocator: IndexAllocator::new(),
            peers_by_index: HashMap::new(),
            pending_outbound: HashMap::new(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing_error_rate_limiter: RoutingErrorRateLimiter::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval(
                std::time::Duration::from_millis(coords_response_interval_ms),
            ),
            retry_pending: HashMap::new(),
            last_parent_reeval: None,
            peer_aliases: HashMap::new(),
        })
    }

    /// Create a node with a specific identity.
    pub fn with_identity(identity: Identity, config: Config) -> Self {
        let node_addr = *identity.node_addr();

        let mut startup_epoch = [0u8; 8];
        rand::rng().fill_bytes(&mut startup_epoch);

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_addr);
        tree_state.set_parent_hysteresis(config.node.tree.parent_hysteresis);
        tree_state.set_hold_down(config.node.tree.hold_down_secs);
        tree_state.set_flap_dampening(
            config.node.tree.flap_threshold,
            config.node.tree.flap_window_secs,
            config.node.tree.flap_dampening_secs,
        );
        tree_state
            .sign_declaration(&identity)
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

        Self {
            identity,
            startup_epoch,
            config,
            state: NodeState::Created,
            is_leaf_only: false,
            tree_state,
            bloom_state,
            coord_cache,
            recent_requests: HashMap::new(),
            transports: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_tx: None,
            packet_rx: None,
            connections: HashMap::new(),
            peers: HashMap::new(),
            sessions: HashMap::new(),
            identity_cache: HashMap::new(),
            pending_tun_packets: HashMap::new(),
            pending_lookups: HashMap::new(),
            max_connections,
            max_peers,
            max_links,
            next_link_id: 1,
            next_transport_id: 1,
            stats: stats::NodeStats::new(),
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_outbound_rx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
            dns_identity_rx: None,
            dns_task: None,
            index_allocator: IndexAllocator::new(),
            peers_by_index: HashMap::new(),
            pending_outbound: HashMap::new(),
            msg1_rate_limiter,
            icmp_rate_limiter: IcmpRateLimiter::new(),
            routing_error_rate_limiter: RoutingErrorRateLimiter::new(),
            coords_response_rate_limiter: RoutingErrorRateLimiter::with_interval(
                std::time::Duration::from_millis(coords_response_interval_ms),
            ),
            retry_pending: HashMap::new(),
            last_parent_reeval: None,
            peer_aliases: HashMap::new(),
        }
    }

    /// Create a leaf-only node (simplified state).
    pub fn leaf_only(config: Config) -> Result<Self, NodeError> {
        let mut node = Self::new(config)?;
        node.is_leaf_only = true;
        node.bloom_state = BloomState::leaf_only(*node.identity.node_addr());
        Ok(node)
    }

    /// Create transport instances from configuration.
    ///
    /// Returns a vector of TransportHandles for all configured transports.
    fn create_transports(&mut self, packet_tx: &PacketTx) -> Vec<TransportHandle> {
        let mut transports = Vec::new();

        // Collect UDP configs with optional names to avoid borrow conflicts
        let udp_instances: Vec<_> = self
            .config
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

        // Create Ethernet transport instances
        #[cfg(target_os = "linux")]
        {
            let eth_instances: Vec<_> = self
                .config
                .transports
                .ethernet
                .iter()
                .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
                .collect();

            let xonly = self.identity.pubkey();
            for (name, eth_config) in eth_instances {
                let transport_id = self.allocate_transport_id();
                let mut eth = EthernetTransport::new(transport_id, name, eth_config, packet_tx.clone());
                eth.set_local_pubkey(xonly);
                transports.push(TransportHandle::Ethernet(eth));
            }
        }

        // Create TCP transport instances
        let tcp_instances: Vec<_> = self
            .config
            .transports
            .tcp
            .iter()
            .map(|(name, config)| (name.map(|s| s.to_string()), config.clone()))
            .collect();

        for (name, tcp_config) in tcp_instances {
            let transport_id = self.allocate_transport_id();
            let tcp = TcpTransport::new(transport_id, name, tcp_config, packet_tx.clone());
            transports.push(TransportHandle::Tcp(tcp));
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
    fn resolve_ethernet_addr(
        &self,
        addr_str: &str,
    ) -> Result<(TransportId, TransportAddr), NodeError> {
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

        // Parse the MAC address
        #[cfg(target_os = "linux")]
        let mac = crate::transport::ethernet::parse_mac_string(mac_str).map_err(|e| {
            NodeError::NoTransportForType(format!("invalid MAC in '{}': {}", addr_str, e))
        })?;
        #[cfg(not(target_os = "linux"))]
        let mac: [u8; 6] = {
            let _ = mac_str;
            return Err(NodeError::NoTransportForType(
                "Ethernet transport not available on this platform".into(),
            ));
        };

        Ok((transport_id, TransportAddr::from_bytes(&mac)))
    }

    // === Identity Accessors ===

    /// Get this node's identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get this node's NodeAddr.
    pub fn node_addr(&self) -> &NodeAddr {
        self.identity.node_addr()
    }

    /// Get this node's npub.
    pub fn npub(&self) -> String {
        self.identity.npub()
    }

    /// Return a human-readable display name for a NodeAddr.
    ///
    /// Lookup order:
    /// 1. Configured peer alias or short npub (from startup map)
    /// 2. Active peer's short npub (e.g., inbound peer not in config)
    /// 3. Session endpoint's short npub (end-to-end, may not be direct peer)
    /// 4. Truncated NodeAddr hex (unknown address)
    pub(crate) fn peer_display_name(&self, addr: &NodeAddr) -> String {
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
        &self.config
    }

    /// Calculate the effective IPv6 MTU that can be sent over FIPS.
    ///
    /// Delegates to `upper::icmp::effective_ipv6_mtu()` with this node's
    /// transport MTU. Returns the maximum IPv6 packet size (including
    /// IPv6 header) that can be transmitted through the FIPS mesh.
    pub fn effective_ipv6_mtu(&self) -> u16 {
        crate::upper::icmp::effective_ipv6_mtu(self.transport_mtu())
    }

    /// Get the transport MTU for a specific transport.
    ///
    /// When called without a specific transport context, returns the MTU
    /// of the first operational transport, or 1280 (IPv6 minimum) as
    /// fallback. This is used for initial TUN configuration where a
    /// specific transport isn't yet known.
    pub fn transport_mtu(&self) -> u16 {
        // Prefer the MTU from the first operational transport
        for handle in self.transports.values() {
            if handle.is_operational() {
                return handle.mtu();
            }
        }
        // Fallback to config: try UDP first, then Ethernet
        if let Some((_, cfg)) = self.config.transports.udp.iter().next() {
            return cfg.mtu();
        }
        1280
    }

    // === State ===

    /// Get the node state.
    pub fn state(&self) -> NodeState {
        self.state
    }

    /// Check if node is operational.
    pub fn is_running(&self) -> bool {
        self.state.is_operational()
    }

    /// Check if this is a leaf-only node.
    pub fn is_leaf_only(&self) -> bool {
        self.is_leaf_only
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

    // === TUN Interface ===

    /// Get the TUN state.
    pub fn tun_state(&self) -> TunState {
        self.tun_state
    }


    // === Resource Limits ===

    /// Set the maximum number of connections (handshake phase).
    pub fn set_max_connections(&mut self, max: usize) {
        self.max_connections = max;
    }

    /// Set the maximum number of peers (authenticated).
    pub fn set_max_peers(&mut self, max: usize) {
        self.max_peers = max;
    }

    /// Set the maximum number of links.
    pub fn set_max_links(&mut self, max: usize) {
        self.max_links = max;
    }

    // === Counts ===

    /// Number of pending connections (handshake in progress).
    pub fn connection_count(&self) -> usize {
        self.connections.len()
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
        if self.max_links > 0 && self.links.len() >= self.max_links {
            return Err(NodeError::MaxLinksExceeded { max: self.max_links });
        }
        let link_id = link.link_id();
        let transport_id = link.transport_id();
        let remote_addr = link.remote_addr().clone();

        self.links.insert(link_id, link);
        self.addr_to_link.insert((transport_id, remote_addr), link_id);
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
    pub fn find_link_by_addr(&self, transport_id: TransportId, addr: &TransportAddr) -> Option<LinkId> {
        self.addr_to_link.get(&(transport_id, addr.clone())).copied()
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

    /// Iterate over all links.
    pub fn links(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    // === Connection Management (Handshake Phase) ===

    /// Add a pending connection.
    pub fn add_connection(&mut self, connection: PeerConnection) -> Result<(), NodeError> {
        let link_id = connection.link_id();

        if self.connections.contains_key(&link_id) {
            return Err(NodeError::ConnectionAlreadyExists(link_id));
        }

        if self.max_connections > 0 && self.connections.len() >= self.max_connections {
            return Err(NodeError::MaxConnectionsExceeded {
                max: self.max_connections,
            });
        }

        self.connections.insert(link_id, connection);
        Ok(())
    }

    /// Get a connection by LinkId.
    pub fn get_connection(&self, link_id: &LinkId) -> Option<&PeerConnection> {
        self.connections.get(link_id)
    }

    /// Get a mutable connection by LinkId.
    pub fn get_connection_mut(&mut self, link_id: &LinkId) -> Option<&mut PeerConnection> {
        self.connections.get_mut(link_id)
    }

    /// Remove a connection.
    pub fn remove_connection(&mut self, link_id: &LinkId) -> Option<PeerConnection> {
        self.connections.remove(link_id)
    }

    /// Iterate over all connections.
    pub fn connections(&self) -> impl Iterator<Item = &PeerConnection> {
        self.connections.values()
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
    #[cfg(test)]
    pub(crate) fn get_session(&self, remote: &NodeAddr) -> Option<&SessionEntry> {
        self.sessions.get(remote)
    }

    /// Remove a session.
    #[cfg(test)]
    pub(crate) fn remove_session(&mut self, remote: &NodeAddr) -> Option<SessionEntry> {
        self.sessions.remove(remote)
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
        self.identity_cache.insert(prefix, (node_addr, pubkey, Self::now_ms()));
        // LRU eviction
        let max = self.config.node.cache.identity_size;
        if self.identity_cache.len() > max
            && let Some(oldest_key) = self.identity_cache.iter()
                .min_by_key(|(_, (_, _, ts))| *ts)
                .map(|(k, _)| *k)
        {
            self.identity_cache.remove(&oldest_key);
        }
    }

    /// Look up a destination by FipsAddress prefix (bytes 1-15 of the IPv6 address).
    pub(crate) fn lookup_by_fips_prefix(&mut self, prefix: &[u8; 15]) -> Option<(NodeAddr, secp256k1::PublicKey)> {
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

    /// Number of pending discovery lookups.
    pub fn pending_lookup_count(&self) -> usize {
        self.pending_lookups.len()
    }

    /// Number of recent discovery requests tracked.
    pub fn recent_request_count(&self) -> usize {
        self.recent_requests.len()
    }

    // === Routing ===

    /// Check if a peer is a tree neighbor (parent or child in the spanning tree).
    ///
    /// Returns true if the peer is our current tree parent, or if the peer
    /// has declared us as their parent (making them our child).
    pub(crate) fn is_tree_peer(&self, peer_addr: &NodeAddr) -> bool {
        // Peer is our parent
        if !self.tree_state.is_root()
            && self.tree_state.my_declaration().parent_id() == peer_addr
        {
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
        let dest_coords = self.coord_cache.get_and_touch(dest_node_addr, now_ms)?.clone();

        // 3. Bloom filter candidates — requires dest_coords for loop-free selection
        let candidates: Vec<&ActivePeer> = self.destination_in_filters(dest_node_addr);
        if !candidates.is_empty() {
            return self.select_best_candidate(&candidates, &dest_coords);
        }

        // 4. Greedy tree routing fallback
        let next_hop_id = self.tree_state.find_next_hop(&dest_coords)?;

        self.peers.get(&next_hop_id).filter(|p| p.can_send())
    }

    /// Select the best peer from a set of bloom filter candidates.
    ///
    /// Uses distance from each candidate's tree coordinates to the destination
    /// as the primary metric (after link_cost). Only selects peers that are
    /// strictly closer to the destination than we are (self-distance check
    /// prevents routing loops).
    ///
    /// Ordering: `(link_cost, distance_to_dest, node_addr)`.
    fn select_best_candidate<'a>(
        &'a self,
        candidates: &[&'a ActivePeer],
        dest_coords: &crate::tree::TreeCoordinate,
    ) -> Option<&'a ActivePeer> {
        let my_distance = self.tree_state.my_coords().distance_to(dest_coords);

        let mut best: Option<(&ActivePeer, f64, usize)> = None;

        for &candidate in candidates {
            if !candidate.can_send() {
                continue;
            }

            let cost = candidate.link_cost();

            let dist = self
                .tree_state
                .peer_coords(candidate.node_addr())
                .map(|pc| pc.distance_to(dest_coords))
                .unwrap_or(usize::MAX);

            // Self-distance check: only consider peers strictly closer
            // to the destination than we are (prevents routing loops)
            if dist >= my_distance {
                continue;
            }

            let dominated = match &best {
                None => true,
                Some((_, best_cost, best_dist)) => {
                    cost < *best_cost
                        || (cost == *best_cost && dist < *best_dist)
                        || (cost == *best_cost
                            && dist == *best_dist
                            && candidate.node_addr() < best.as_ref().unwrap().0.node_addr())
                }
            };

            if dominated {
                best = Some((candidate, cost, dist));
            }
        }

        best.map(|(peer, _, _)| peer)
    }

    /// Check if a destination is in any peer's bloom filter.
    pub fn destination_in_filters(&self, dest: &NodeAddr) -> Vec<&ActivePeer> {
        self.peers.values().filter(|p| p.may_reach(dest)).collect()
    }

    /// Get the TUN packet sender channel.
    ///
    /// Returns None if TUN is not active or the node hasn't been started.
    pub fn tun_tx(&self) -> Option<&TunTx> {
        self.tun_tx.as_ref()
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
        let peer = self.peers.get_mut(node_addr)
            .ok_or(NodeError::PeerNotFound(*node_addr))?;

        let their_index = peer.their_index().ok_or_else(|| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: "no their_index".into(),
        })?;
        let transport_id = peer.transport_id().ok_or_else(|| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: "no transport_id".into(),
        })?;
        let remote_addr = peer.current_addr().cloned().ok_or_else(|| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: "no current_addr".into(),
        })?;

        // Prepend 4-byte session-relative timestamp (inner header)
        let timestamp_ms = peer.session_elapsed_ms();

        // MMP: read spin bit value before entering session borrow
        let sp_flag = peer.mmp()
            .map(|mmp| mmp.spin_bit.tx_bit())
            .unwrap_or(false);
        let flags = if sp_flag { FLAG_SP } else { 0 };

        let session = peer.noise_session_mut().ok_or_else(|| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: "no noise session".into(),
        })?;

        // Inner plaintext: [timestamp:4 LE][msg_type][payload...]
        let inner_plaintext = prepend_inner_header(timestamp_ms, plaintext);

        // Build 16-byte outer header (used as AAD for AEAD)
        let counter = session.current_send_counter();
        let payload_len = inner_plaintext.len() as u16;
        let header = build_established_header(their_index, counter, flags, payload_len);

        // Encrypt with AAD binding to the outer header
        let ciphertext = session.encrypt_with_aad(&inner_plaintext, &header).map_err(|e| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: format!("encryption failed: {}", e),
        })?;

        let wire_packet = build_encrypted(&header, &ciphertext);

        // Re-borrow peer for stats update after sending
        let transport = self.transports.get(&transport_id)
            .ok_or(NodeError::TransportNotFound(transport_id))?;

        let bytes_sent = transport.send(&remote_addr, &wire_packet).await
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

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("node_addr", self.node_addr())
            .field("state", &self.state)
            .field("is_leaf_only", &self.is_leaf_only)
            .field("connections", &self.connection_count())
            .field("peers", &self.peer_count())
            .field("links", &self.link_count())
            .field("transports", &self.transport_count())
            .finish()
    }
}
