//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

mod bloom;
mod handlers;
mod lifecycle;
mod retry;
mod tree;
#[cfg(test)]
mod tests;

use crate::bloom::BloomState;
use crate::cache::CoordCache;
use crate::index::IndexAllocator;
use crate::peer::{ActivePeer, PeerConnection};
use crate::rate_limit::HandshakeRateLimiter;
use crate::transport::{
    Link, LinkId, PacketRx, PacketTx, TransportAddr, TransportHandle, TransportId,
};
use crate::transport::udp::UdpTransport;
use crate::tree::TreeState;
use crate::tun::{TunError, TunState, TunTx};
use crate::wire::build_encrypted;
use crate::{Config, ConfigError, Identity, IdentityError, NodeAddr};
use std::collections::HashMap;
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

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("TUN error: {0}")]
    Tun(#[from] TunError),
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
pub struct Node {
    // === Identity ===
    /// This node's cryptographic identity.
    identity: Identity,

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
    /// Address -> coordinates cache.
    coord_cache: CoordCache,

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

    // === TUN Interface ===
    /// TUN device state.
    tun_state: TunState,
    /// TUN interface name (for cleanup).
    tun_name: Option<String>,
    /// TUN packet sender channel.
    tun_tx: Option<TunTx>,
    /// TUN reader thread handle.
    tun_reader_handle: Option<JoinHandle<()>>,
    /// TUN writer thread handle.
    tun_writer_handle: Option<JoinHandle<()>>,

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

    // === Tree Announce Timing ===
    /// Last time we refreshed our root announcement (Unix seconds).
    last_root_refresh_secs: u64,

    // === Connection Retry ===
    /// Retry state for peers whose outbound connections have failed.
    /// Keyed by NodeAddr. Entries are created when a handshake times out
    /// or fails, and removed on successful promotion or when max retries
    /// are exhausted.
    retry_pending: HashMap<NodeAddr, retry::RetryState>,
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(config: Config) -> Result<Self, NodeError> {
        let identity = config.create_identity()?;
        let node_addr = *identity.node_addr();
        let is_leaf_only = config.is_leaf_only();

        let bloom_state = if is_leaf_only {
            BloomState::leaf_only(node_addr)
        } else {
            BloomState::new(node_addr)
        };

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_addr);
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        Ok(Self {
            identity,
            config,
            state: NodeState::Created,
            is_leaf_only,
            tree_state,
            bloom_state,
            coord_cache: CoordCache::with_defaults(),
            transports: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_tx: None,
            packet_rx: None,
            connections: HashMap::new(),
            peers: HashMap::new(),
            max_connections: 256,
            max_peers: 128,
            max_links: 256,
            next_link_id: 1,
            next_transport_id: 1,
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
            index_allocator: IndexAllocator::new(),
            peers_by_index: HashMap::new(),
            pending_outbound: HashMap::new(),
            msg1_rate_limiter: HandshakeRateLimiter::new(),
            last_root_refresh_secs: 0,
            retry_pending: HashMap::new(),
        })
    }

    /// Create a node with a specific identity.
    pub fn with_identity(identity: Identity, config: Config) -> Self {
        let node_addr = *identity.node_addr();
        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_addr);
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        Self {
            identity,
            config,
            state: NodeState::Created,
            is_leaf_only: false,
            tree_state,
            bloom_state: BloomState::new(node_addr),
            coord_cache: CoordCache::with_defaults(),
            transports: HashMap::new(),
            links: HashMap::new(),
            addr_to_link: HashMap::new(),
            packet_tx: None,
            packet_rx: None,
            connections: HashMap::new(),
            peers: HashMap::new(),
            max_connections: 256,
            max_peers: 128,
            max_links: 256,
            next_link_id: 1,
            next_transport_id: 1,
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
            index_allocator: IndexAllocator::new(),
            peers_by_index: HashMap::new(),
            pending_outbound: HashMap::new(),
            msg1_rate_limiter: HandshakeRateLimiter::new(),
            last_root_refresh_secs: 0,
            retry_pending: HashMap::new(),
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

        // Future transports follow same pattern:
        // for (name, tcp_config) in self.config.transports.tcp.iter() { ... }

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

    // === Configuration ===

    /// Get the configuration.
    pub fn config(&self) -> &Config {
        &self.config
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

    // === Routing ===

    /// Find next hop for a destination node address.
    ///
    /// Routing priority:
    /// 1. Destination is self → `None` (local delivery)
    /// 2. Destination is a direct peer → that peer
    /// 3. Bloom filter candidates + greedy tree routing → among peers whose
    ///    bloom filter contains the destination, pick the one that minimizes
    ///    tree distance to the destination (if dest coords are cached), with
    ///    `(link_cost, tree_distance_to_dest, node_addr)` tie-breaking.
    ///    Falls back to greedy tree routing if no bloom filter hits.
    /// 4. No route → `None`
    ///
    /// The self-distance check from greedy routing also applies to bloom
    /// filter candidates: a peer is only selected if it is strictly closer
    /// to the destination than we are (prevents routing loops).
    pub fn find_next_hop(&self, dest_node_addr: &NodeAddr) -> Option<&ActivePeer> {
        // 1. Local delivery
        if dest_node_addr == self.node_addr() {
            return None;
        }

        // 2. Direct peer
        if let Some(peer) = self.peers.get(dest_node_addr) {
            if peer.can_send() {
                return Some(peer);
            }
        }

        // Look up destination coords (used by both bloom and tree paths)
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let dest_coords = self.coord_cache.get(dest_node_addr, now_ms);

        // 3. Bloom filter candidates, scored by tree distance to dest
        let candidates: Vec<&ActivePeer> = self.destination_in_filters(dest_node_addr);
        if !candidates.is_empty() {
            return self.select_best_candidate(&candidates, dest_coords);
        }

        // 4. Greedy tree routing fallback
        let dest_coords = dest_coords?;
        let next_hop_id = self.tree_state.find_next_hop(dest_coords)?;

        self.peers.get(&next_hop_id).filter(|p| p.can_send())
    }

    /// Select the best peer from a set of bloom filter candidates.
    ///
    /// When dest_coords are available, uses distance from each candidate's
    /// coordinates to the destination as the primary metric (after link_cost).
    /// Only selects peers that are strictly closer to the destination than
    /// we are (self-distance check prevents loops).
    ///
    /// When dest_coords are not available, falls back to distance from us
    /// to the candidate peer (a weaker heuristic — prefers closer peers on
    /// the theory that shorter paths are better).
    ///
    /// Ordering: `(link_cost, distance_to_dest, node_addr)`.
    fn select_best_candidate<'a>(
        &'a self,
        candidates: &[&'a ActivePeer],
        dest_coords: Option<&crate::tree::TreeCoordinate>,
    ) -> Option<&'a ActivePeer> {
        let my_distance = dest_coords.map(|dc| self.tree_state.my_coords().distance_to(dc));

        let mut best: Option<(&ActivePeer, f64, usize)> = None;

        for &candidate in candidates {
            if !candidate.can_send() {
                continue;
            }

            let cost = candidate.link_cost();

            // Compute distance: peer→dest if coords available, else us→peer
            let dist = match dest_coords {
                Some(dc) => self
                    .tree_state
                    .peer_coords(candidate.node_addr())
                    .map(|pc| pc.distance_to(dc))
                    .unwrap_or(usize::MAX),
                None => self
                    .tree_state
                    .distance_to_peer(candidate.node_addr())
                    .unwrap_or(usize::MAX),
            };

            // Self-distance check: when dest coords are available,
            // only consider peers that are strictly closer than us
            if let Some(my_dist) = my_distance {
                if dist >= my_dist {
                    continue;
                }
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

        let session = peer.noise_session_mut().ok_or_else(|| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: "no noise session".into(),
        })?;

        // Get counter before encrypt (encrypt increments it)
        let counter = session.current_send_counter();
        let ciphertext = session.encrypt(plaintext).map_err(|e| NodeError::SendFailed {
            node_addr: *node_addr,
            reason: format!("encryption failed: {}", e),
        })?;

        let wire_packet = build_encrypted(their_index, counter, &ciphertext);

        // Re-borrow peer for stats update after sending
        let transport = self.transports.get(&transport_id)
            .ok_or(NodeError::TransportNotFound(transport_id))?;

        let bytes_sent = transport.send(&remote_addr, &wire_packet).await
            .map_err(|e| NodeError::SendFailed {
                node_addr: *node_addr,
                reason: format!("transport send: {}", e),
            })?;

        // Update send statistics
        if let Some(peer) = self.peers.get_mut(node_addr) {
            peer.link_stats_mut().record_sent(bytes_sent);
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
