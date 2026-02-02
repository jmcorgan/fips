//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

use crate::bloom::BloomState;
use crate::cache::CoordCache;
use crate::config::PeerConfig;
use crate::index::IndexAllocator;
use crate::peer::{
    cross_connection_winner, ActivePeer, PeerConnection, PromotionResult,
};
use crate::rate_limit::HandshakeRateLimiter;
use crate::transport::{
    packet_channel, Link, LinkDirection, LinkId, PacketRx, PacketTx, ReceivedPacket,
    TransportAddr, TransportHandle, TransportId,
};
use crate::transport::udp::UdpTransport;
use crate::tree::TreeState;
use crate::tun::{run_tun_reader, shutdown_tun_interface, TunDevice, TunError, TunState, TunTx};
use crate::wire::{
    build_msg1, build_msg2, EncryptedHeader, Msg1Header, Msg2Header,
    DISCRIMINATOR_ENCRYPTED, DISCRIMINATOR_MSG1, DISCRIMINATOR_MSG2,
};
use crate::{Config, ConfigError, Identity, IdentityError, NodeId, PeerIdentity};
use std::collections::HashMap;
use std::fmt;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

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
    PeerNotFound(NodeId),

    #[error("peer already exists: {0:?}")]
    PeerAlreadyExists(NodeId),

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
/// 2. **Active phase** (`peers`): Authenticated, indexed by NodeId
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
    /// Indexed by NodeId (verified identity).
    peers: HashMap<NodeId, ActivePeer>,

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
    /// O(1) lookup: (transport_id, our_index) → NodeId.
    /// This maps our session index to the peer that uses it.
    peers_by_index: HashMap<(TransportId, u32), NodeId>,
    /// Pending outbound handshakes by our sender_idx.
    /// Tracks which LinkId corresponds to which session index.
    pending_outbound: HashMap<(TransportId, u32), LinkId>,

    // === Rate Limiting ===
    /// Rate limiter for msg1 processing (DoS protection).
    msg1_rate_limiter: HandshakeRateLimiter,
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(config: Config) -> Result<Self, NodeError> {
        let identity = config.create_identity()?;
        let node_id = *identity.node_id();
        let is_leaf_only = config.is_leaf_only();

        let bloom_state = if is_leaf_only {
            BloomState::leaf_only(node_id)
        } else {
            BloomState::new(node_id)
        };

        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_id);
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
        })
    }

    /// Create a node with a specific identity.
    pub fn with_identity(identity: Identity, config: Config) -> Self {
        let node_id = *identity.node_id();
        let tun_state = if config.tun.enabled {
            TunState::Configured
        } else {
            TunState::Disabled
        };

        // Initialize tree state with signed self-declaration
        let mut tree_state = TreeState::new(node_id);
        tree_state
            .sign_declaration(&identity)
            .expect("signing own declaration should never fail");

        Self {
            identity,
            config,
            state: NodeState::Created,
            is_leaf_only: false,
            tree_state,
            bloom_state: BloomState::new(node_id),
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
        }
    }

    /// Create a leaf-only node (simplified state).
    pub fn leaf_only(config: Config) -> Result<Self, NodeError> {
        let mut node = Self::new(config)?;
        node.is_leaf_only = true;
        node.bloom_state = BloomState::leaf_only(*node.identity.node_id());
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

    /// Initiate connections to configured static peers.
    ///
    /// For each peer configured with AutoConnect policy, creates a link and
    /// peer entry, then starts the Noise handshake by sending the first message.
    async fn initiate_peer_connections(&mut self) {
        // Collect peer configs to avoid borrow conflicts
        let peer_configs: Vec<_> = self.config.auto_connect_peers().cloned().collect();

        if peer_configs.is_empty() {
            debug!("No static peers configured");
            return;
        }

        info!(count = peer_configs.len(), "Initiating static peer connections");

        for peer_config in peer_configs {
            if let Err(e) = self.initiate_peer_connection(&peer_config).await {
                warn!(
                    npub = %peer_config.npub,
                    alias = ?peer_config.alias,
                    error = %e,
                    "Failed to initiate peer connection"
                );
            }
        }
    }

    /// Initiate a connection to a single peer.
    ///
    /// Creates a link, starts the Noise handshake, and sends the first message.
    async fn initiate_peer_connection(&mut self, peer_config: &PeerConfig) -> Result<(), NodeError> {
        // Parse the peer's npub to get their identity
        let peer_identity = PeerIdentity::from_npub(&peer_config.npub).map_err(|e| {
            NodeError::InvalidPeerNpub {
                npub: peer_config.npub.clone(),
                reason: e.to_string(),
            }
        })?;

        let peer_node_id = *peer_identity.node_id();

        // Check if peer already exists (fully authenticated)
        if self.peers.contains_key(&peer_node_id) {
            debug!(
                npub = %peer_config.npub,
                "Peer already exists, skipping"
            );
            return Ok(());
        }

        // Check if connection already in progress to this peer
        let already_connecting = self.connections.values().any(|conn| {
            conn.expected_identity()
                .map(|id| id.node_id() == &peer_node_id)
                .unwrap_or(false)
        });
        if already_connecting {
            debug!(
                npub = %peer_config.npub,
                "Connection already in progress, skipping"
            );
            return Ok(());
        }

        // Try addresses in priority order until one works
        for addr in peer_config.addresses_by_priority() {
            // Find a transport matching this address type
            let transport_id = match self.find_transport_for_type(&addr.transport) {
                Some(id) => id,
                None => {
                    debug!(
                        transport = %addr.transport,
                        addr = %addr.addr,
                        "No operational transport for address type"
                    );
                    continue;
                }
            };

            // Allocate link ID and create link
            let link_id = self.allocate_link_id();
            let remote_addr = TransportAddr::from_string(&addr.addr);

            // For UDP, links are immediately "connected" (connectionless)
            // TODO: For connection-oriented transports, state would be Connecting
            let link = Link::connectionless(
                link_id,
                transport_id,
                remote_addr.clone(),
                LinkDirection::Outbound,
                Duration::from_millis(100), // Base RTT estimate for UDP
            );

            self.links.insert(link_id, link);

            // Add reverse lookup for packet dispatch
            self.addr_to_link
                .insert((transport_id, remote_addr.clone()), link_id);

            // Create connection in handshake phase (outbound knows expected identity)
            let current_time_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let mut connection = PeerConnection::outbound(link_id, peer_identity.clone(), current_time_ms);

            // Allocate a session index for this handshake
            let our_index = match self.index_allocator.allocate() {
                Ok(idx) => idx,
                Err(e) => {
                    warn!(
                        npub = %peer_config.npub,
                        error = %e,
                        "Failed to allocate session index"
                    );
                    // Clean up the link we just created
                    self.links.remove(&link_id);
                    self.addr_to_link.remove(&(transport_id, remote_addr));
                    continue;
                }
            };

            // Start the Noise handshake and get message 1
            let our_keypair = self.identity.keypair();
            let noise_msg1 = match connection.start_handshake(our_keypair, current_time_ms) {
                Ok(msg) => msg,
                Err(e) => {
                    warn!(
                        npub = %peer_config.npub,
                        error = %e,
                        "Failed to start handshake"
                    );
                    // Clean up the index and link
                    let _ = self.index_allocator.free(our_index);
                    self.links.remove(&link_id);
                    self.addr_to_link.remove(&(transport_id, remote_addr));
                    continue;
                }
            };

            // Set index and transport info on the connection
            connection.set_our_index(our_index);
            connection.set_transport_id(transport_id);
            connection.set_source_addr(remote_addr.clone());

            // Build wire format msg1: [0x01][sender_idx:4 LE][noise_msg1:82]
            let wire_msg1 = build_msg1(our_index, &noise_msg1);

            let alias_display = peer_config
                .alias
                .as_deref()
                .map(|a| format!(" ({})", a))
                .unwrap_or_default();

            info!("Peer connection initiated{}", alias_display);
            info!("  npub: {}", peer_config.npub);
            info!("  node_id: {}", peer_node_id);
            info!("  transport: {}", addr.transport);
            info!("  addr: {}", addr.addr);
            info!("  link_id: {}", link_id);
            info!("  our_index: {}", our_index);

            // Track in pending_outbound for msg2 dispatch
            self.pending_outbound.insert((transport_id, our_index.as_u32()), link_id);
            self.connections.insert(link_id, connection);

            // Send the wire format handshake message
            if let Some(transport) = self.transports.get(&transport_id) {
                match transport.send(&remote_addr, &wire_msg1).await {
                    Ok(bytes) => {
                        debug!(
                            link_id = %link_id,
                            our_index = %our_index,
                            bytes,
                            "Sent Noise handshake message 1 (wire format)"
                        );
                    }
                    Err(e) => {
                        warn!(
                            link_id = %link_id,
                            error = %e,
                            "Failed to send handshake message"
                        );
                        // Mark connection as failed but don't remove it yet
                        // The event loop can handle retry logic
                        if let Some(conn) = self.connections.get_mut(&link_id) {
                            conn.mark_failed();
                        }
                    }
                }
            }

            // Successfully initiated connection via this address
            return Ok(());
        }

        // No address worked
        Err(NodeError::NoTransportForType(format!(
            "no operational transport for any of {}'s addresses",
            peer_config.npub
        )))
    }

    // === Identity Accessors ===

    /// Get this node's identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get this node's NodeId.
    pub fn node_id(&self) -> &NodeId {
        self.identity.node_id()
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
    pub fn remove_link(&mut self, link_id: &LinkId) -> Option<Link> {
        if let Some(link) = self.links.remove(link_id) {
            // Clean up reverse lookup
            let key = (link.transport_id(), link.remote_addr().clone());
            self.addr_to_link.remove(&key);
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

    /// Promote a connection to active peer after successful authentication.
    ///
    /// Handles cross-connection detection and resolution using tie-breaker rules.
    pub fn promote_connection(
        &mut self,
        link_id: LinkId,
        verified_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Result<PromotionResult, NodeError> {
        // Remove the connection from pending
        let connection = self
            .connections
            .remove(&link_id)
            .ok_or(NodeError::ConnectionNotFound(link_id))?;

        let peer_node_id = *verified_identity.node_id();
        let is_outbound = connection.is_outbound();

        // Check for cross-connection
        if let Some(existing_peer) = self.peers.get(&peer_node_id) {
            let existing_link_id = existing_peer.link_id();

            // Determine which connection wins
            let this_wins = cross_connection_winner(
                self.identity.node_id(),
                &peer_node_id,
                is_outbound,
            );

            if this_wins {
                // This connection wins, replace the existing peer
                let old_peer = self.peers.remove(&peer_node_id).unwrap();
                let loser_link_id = old_peer.link_id();

                // Create new active peer with stats from handshake
                let new_peer = ActivePeer::with_stats(
                    verified_identity,
                    link_id,
                    current_time_ms,
                    connection.link_stats().clone(),
                );

                self.peers.insert(peer_node_id, new_peer);

                info!(
                    node_id = %peer_node_id,
                    winner_link = %link_id,
                    loser_link = %loser_link_id,
                    "Cross-connection resolved: this connection won"
                );

                Ok(PromotionResult::CrossConnectionWon {
                    loser_link_id,
                    node_id: peer_node_id,
                })
            } else {
                // This connection loses, keep existing
                info!(
                    node_id = %peer_node_id,
                    winner_link = %existing_link_id,
                    loser_link = %link_id,
                    "Cross-connection resolved: this connection lost"
                );

                Ok(PromotionResult::CrossConnectionLost {
                    winner_link_id: existing_link_id,
                })
            }
        } else {
            // No cross-connection, normal promotion
            if self.max_peers > 0 && self.peers.len() >= self.max_peers {
                return Err(NodeError::MaxPeersExceeded { max: self.max_peers });
            }

            let new_peer = ActivePeer::with_stats(
                verified_identity,
                link_id,
                current_time_ms,
                connection.link_stats().clone(),
            );

            self.peers.insert(peer_node_id, new_peer);

            info!(
                node_id = %peer_node_id,
                link_id = %link_id,
                "Connection promoted to active peer"
            );

            Ok(PromotionResult::Promoted(peer_node_id))
        }
    }

    // === Peer Management (Active Phase) ===

    /// Get a peer by NodeId.
    pub fn get_peer(&self, node_id: &NodeId) -> Option<&ActivePeer> {
        self.peers.get(node_id)
    }

    /// Get a mutable peer by NodeId.
    pub fn get_peer_mut(&mut self, node_id: &NodeId) -> Option<&mut ActivePeer> {
        self.peers.get_mut(node_id)
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, node_id: &NodeId) -> Option<ActivePeer> {
        self.peers.remove(node_id)
    }

    /// Iterate over all peers.
    pub fn peers(&self) -> impl Iterator<Item = &ActivePeer> {
        self.peers.values()
    }

    /// Iterate over all peer node IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NodeId> {
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

    // === Routing (stubs) ===

    /// Find next hop for a destination (stub).
    ///
    /// Returns the peer that minimizes tree distance to the destination.
    pub fn find_next_hop(&self, _dest_node_id: &NodeId) -> Option<&ActivePeer> {
        // Stub: would implement greedy tree routing
        None
    }

    /// Check if a destination is in any peer's bloom filter.
    pub fn destination_in_filters(&self, dest: &NodeId) -> Vec<&ActivePeer> {
        self.peers.values().filter(|p| p.may_reach(dest)).collect()
    }

    // === State Transitions ===

    /// Start the node.
    ///
    /// Initializes the TUN interface (if configured), spawns I/O threads,
    /// and transitions to the Running state.
    pub async fn start(&mut self) -> Result<(), NodeError> {
        if !self.state.can_start() {
            return Err(NodeError::AlreadyStarted);
        }
        self.state = NodeState::Starting;

        // Create packet channel for transport -> Node communication
        const PACKET_BUFFER_SIZE: usize = 1024;
        let (packet_tx, packet_rx) = packet_channel(PACKET_BUFFER_SIZE);
        self.packet_tx = Some(packet_tx.clone());
        self.packet_rx = Some(packet_rx);

        // Initialize transports first (before TUN)
        let transport_handles = self.create_transports(&packet_tx);

        for mut handle in transport_handles {
            let transport_id = handle.transport_id();
            let transport_type = handle.transport_type().name;
            let name = handle.name().map(|s| s.to_string());

            match handle.start().await {
                Ok(()) => {
                    self.transports.insert(transport_id, handle);
                }
                Err(e) => {
                    if let Some(ref n) = name {
                        warn!(transport_type, name = %n, error = %e, "Transport failed to start");
                    } else {
                        warn!(transport_type, error = %e, "Transport failed to start");
                    }
                }
            }
        }

        if !self.transports.is_empty() {
            info!(count = self.transports.len(), "Transports initialized");
        }

        // Connect to static peers before TUN is active
        // This allows handshake messages to be sent before we start accepting packets
        self.initiate_peer_connections().await;

        // Initialize TUN interface last, after transports and peers are ready
        if self.config.tun.enabled {
            let address = *self.identity.address();
            match TunDevice::create(&self.config.tun, address).await {
                Ok(device) => {
                    let mtu = device.mtu();
                    let name = device.name().to_string();
                    let our_addr = *device.address();

                    info!("TUN device active:");
                    info!("     name: {}", name);
                    info!("  address: {}", device.address());
                    info!("      mtu: {}", mtu);

                    // Create writer (dups the fd for independent write access)
                    let (writer, tun_tx) = device.create_writer()?;

                    // Spawn writer thread
                    let writer_handle = thread::spawn(move || {
                        writer.run();
                    });

                    // Clone tun_tx for the reader
                    let reader_tun_tx = tun_tx.clone();

                    // Spawn reader thread
                    let reader_handle = thread::spawn(move || {
                        run_tun_reader(device, mtu, our_addr, reader_tun_tx);
                    });

                    self.tun_state = TunState::Active;
                    self.tun_name = Some(name);
                    self.tun_tx = Some(tun_tx);
                    self.tun_reader_handle = Some(reader_handle);
                    self.tun_writer_handle = Some(writer_handle);
                }
                Err(e) => {
                    self.tun_state = TunState::Failed;
                    warn!(error = %e, "Failed to initialize TUN, continuing without it");
                }
            }
        }

        self.state = NodeState::Running;
        info!("Node started:");
        info!("       state: {}", self.state);
        info!("  transports: {}", self.transports.len());
        info!(" connections: {}", self.connections.len());
        Ok(())
    }

    // === RX Event Loop ===

    /// Run the receive event loop.
    ///
    /// Processes packets from all transports, dispatching based on
    /// the discriminator byte in the wire protocol:
    /// - 0x00: Encrypted frame (session data)
    /// - 0x01: Handshake message 1 (initiator -> responder)
    /// - 0x02: Handshake message 2 (responder -> initiator)
    ///
    /// This method takes ownership of the packet_rx channel and runs
    /// until the channel is closed (typically when stop() is called).
    pub async fn run_rx_loop(&mut self) -> Result<(), NodeError> {
        let mut packet_rx = self.packet_rx.take()
            .ok_or(NodeError::NotStarted)?;

        info!("RX event loop started");

        while let Some(packet) = packet_rx.recv().await {
            self.process_packet(packet).await;
        }

        info!("RX event loop stopped (channel closed)");
        Ok(())
    }

    /// Process a single received packet.
    ///
    /// Dispatches based on the discriminator byte.
    async fn process_packet(&mut self, packet: ReceivedPacket) {
        if packet.data.is_empty() {
            return; // Drop empty packets
        }

        let discriminator = packet.data[0];
        match discriminator {
            DISCRIMINATOR_ENCRYPTED => {
                self.handle_encrypted_frame(packet).await;
            }
            DISCRIMINATOR_MSG1 => {
                self.handle_msg1(packet).await;
            }
            DISCRIMINATOR_MSG2 => {
                self.handle_msg2(packet).await;
            }
            _ => {
                // Unknown discriminator, drop silently
                debug!(
                    discriminator = discriminator,
                    transport_id = %packet.transport_id,
                    "Unknown packet discriminator, dropping"
                );
            }
        }
    }

    /// Handle an encrypted frame (discriminator 0x00).
    ///
    /// This is the hot path for established sessions. We use O(1)
    /// index-based lookup to find the session, then decrypt.
    async fn handle_encrypted_frame(&mut self, packet: ReceivedPacket) {
        // Parse header (fail fast)
        let header = match EncryptedHeader::parse(&packet.data) {
            Some(h) => h,
            None => return, // Malformed, drop silently
        };

        // O(1) session lookup by our receiver index
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let node_id = match self.peers_by_index.get(&key) {
            Some(id) => *id,
            None => {
                // Unknown index - could be stale session or attack
                debug!(
                    receiver_idx = %header.receiver_idx,
                    transport_id = %packet.transport_id,
                    "Unknown session index, dropping"
                );
                return;
            }
        };

        let peer = match self.peers.get_mut(&node_id) {
            Some(p) => p,
            None => {
                // Peer removed but index not cleaned up - fix it
                self.peers_by_index.remove(&key);
                return;
            }
        };

        // Get the session (peer must have one for index-based lookup)
        let session = match peer.noise_session_mut() {
            Some(s) => s,
            None => {
                warn!(
                    node_id = %node_id,
                    "Peer in index map has no session"
                );
                return;
            }
        };

        // Decrypt with replay check (this is the expensive part)
        let ciphertext = &packet.data[header.ciphertext_offset..];
        let plaintext = match session.decrypt_with_replay_check(ciphertext, header.counter) {
            Ok(p) => p,
            Err(e) => {
                debug!(
                    node_id = %node_id,
                    counter = header.counter,
                    error = %e,
                    "Decryption failed"
                );
                return;
            }
        };

        // === PACKET IS AUTHENTIC ===

        // Update address for roaming support
        peer.set_current_addr(packet.transport_id, packet.remote_addr.clone());

        // Update statistics
        peer.link_stats_mut().record_recv(packet.data.len(), packet.timestamp_ms);
        peer.touch(packet.timestamp_ms);

        // Dispatch to link message handler
        self.dispatch_link_message(&node_id, &plaintext).await;
    }

    /// Handle handshake message 1 (discriminator 0x01).
    ///
    /// This creates a new inbound connection. Rate limiting is applied
    /// before any expensive crypto operations.
    async fn handle_msg1(&mut self, packet: ReceivedPacket) {
        // === RATE LIMITING (before any processing) ===
        if !self.msg1_rate_limiter.start_handshake() {
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                "Msg1 rate limited"
            );
            return;
        }

        // Parse header
        let header = match Msg1Header::parse(&packet.data) {
            Some(h) => h,
            None => {
                self.msg1_rate_limiter.complete_handshake();
                debug!("Invalid msg1 header");
                return;
            }
        };

        // Check for existing connection from this address
        let addr_key = (packet.transport_id, packet.remote_addr.clone());
        if self.addr_to_link.contains_key(&addr_key) {
            self.msg1_rate_limiter.complete_handshake();
            debug!(
                transport_id = %packet.transport_id,
                remote_addr = %packet.remote_addr,
                "Already have connection from this address"
            );
            return;
        }

        // === CRYPTO COST PAID HERE ===
        let link_id = self.allocate_link_id();
        let mut conn = PeerConnection::inbound_with_transport(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            packet.timestamp_ms,
        );

        let our_keypair = self.identity.keypair();
        let noise_msg1 = &packet.data[header.noise_msg1_offset..];
        let msg2_response = match conn.receive_handshake_init(our_keypair, noise_msg1, packet.timestamp_ms) {
            Ok(m) => m,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                debug!(
                    error = %e,
                    "Failed to process msg1"
                );
                return;
            }
        };

        // Learn peer identity from msg1
        let peer_identity = match conn.expected_identity() {
            Some(id) => id.clone(),
            None => {
                self.msg1_rate_limiter.complete_handshake();
                warn!("Identity not learned from msg1");
                return;
            }
        };
        let peer_node_id = *peer_identity.node_id();

        // Check if this peer is already connected
        if self.peers.contains_key(&peer_node_id) {
            // TODO: Handle reconnection case (future: session replacement)
            self.msg1_rate_limiter.complete_handshake();
            debug!(
                node_id = %peer_node_id,
                "Peer already connected, ignoring msg1"
            );
            return;
        }

        // Allocate our session index
        let our_index = match self.index_allocator.allocate() {
            Ok(idx) => idx,
            Err(e) => {
                self.msg1_rate_limiter.complete_handshake();
                warn!(error = %e, "Failed to allocate session index for inbound");
                return;
            }
        };

        conn.set_our_index(our_index);
        conn.set_their_index(header.sender_idx);

        // Create link
        let link = Link::connectionless(
            link_id,
            packet.transport_id,
            packet.remote_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(100),
        );

        self.links.insert(link_id, link);
        self.addr_to_link.insert(addr_key, link_id);
        self.connections.insert(link_id, conn);

        // Build and send msg2 response
        let wire_msg2 = build_msg2(our_index, header.sender_idx, &msg2_response);

        if let Some(transport) = self.transports.get(&packet.transport_id) {
            match transport.send(&packet.remote_addr, &wire_msg2).await {
                Ok(bytes) => {
                    debug!(
                        link_id = %link_id,
                        our_index = %our_index,
                        their_index = %header.sender_idx,
                        bytes,
                        "Sent msg2 response"
                    );
                }
                Err(e) => {
                    warn!(
                        link_id = %link_id,
                        error = %e,
                        "Failed to send msg2"
                    );
                    // Clean up on failure
                    self.connections.remove(&link_id);
                    self.links.remove(&link_id);
                    self.addr_to_link.remove(&(packet.transport_id, packet.remote_addr));
                    let _ = self.index_allocator.free(our_index);
                    self.msg1_rate_limiter.complete_handshake();
                    return;
                }
            }
        }

        info!(
            node_id = %peer_node_id,
            link_id = %link_id,
            our_index = %our_index,
            "Inbound handshake initiated"
        );

        // Note: rate limiter completed when handshake completes or times out
    }

    /// Handle handshake message 2 (discriminator 0x02).
    ///
    /// This completes an outbound handshake we initiated.
    async fn handle_msg2(&mut self, packet: ReceivedPacket) {
        // Parse header
        let header = match Msg2Header::parse(&packet.data) {
            Some(h) => h,
            None => {
                debug!("Invalid msg2 header");
                return;
            }
        };

        // Look up our pending handshake by our sender_idx (receiver_idx in msg2)
        let key = (packet.transport_id, header.receiver_idx.as_u32());
        let link_id = match self.pending_outbound.get(&key) {
            Some(id) => *id,
            None => {
                debug!(
                    receiver_idx = %header.receiver_idx,
                    "No pending outbound handshake for index"
                );
                return;
            }
        };

        let conn = match self.connections.get_mut(&link_id) {
            Some(c) => c,
            None => {
                // Connection removed, clean up pending_outbound
                self.pending_outbound.remove(&key);
                return;
            }
        };

        // Process Noise msg2
        let noise_msg2 = &packet.data[header.noise_msg2_offset..];
        if let Err(e) = conn.complete_handshake(noise_msg2, packet.timestamp_ms) {
            warn!(
                link_id = %link_id,
                error = %e,
                "Handshake completion failed"
            );
            conn.mark_failed();
            return;
        }

        // Store their index
        conn.set_their_index(header.sender_idx);
        conn.set_source_addr(packet.remote_addr.clone());

        // Get peer identity for promotion
        let peer_identity = match conn.expected_identity() {
            Some(id) => id.clone(),
            None => {
                warn!(link_id = %link_id, "No identity after handshake");
                return;
            }
        };

        info!(
            node_id = %peer_identity.node_id(),
            link_id = %link_id,
            their_index = %header.sender_idx,
            "Outbound handshake completed"
        );

        // Promote to active peer (TODO: implement with session transfer)
        // For now, just use the existing promote_connection
        match self.promote_connection(link_id, peer_identity.clone(), packet.timestamp_ms) {
            Ok(result) => {
                // Clean up pending_outbound
                self.pending_outbound.remove(&key);

                match result {
                    PromotionResult::Promoted(node_id) => {
                        info!(
                            node_id = %node_id,
                            "Peer promoted to active"
                        );
                    }
                    PromotionResult::CrossConnectionWon { loser_link_id, node_id } => {
                        info!(
                            node_id = %node_id,
                            loser_link_id = %loser_link_id,
                            "Cross-connection won"
                        );
                    }
                    PromotionResult::CrossConnectionLost { winner_link_id } => {
                        info!(
                            winner_link_id = %winner_link_id,
                            "Cross-connection lost"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    link_id = %link_id,
                    error = %e,
                    "Failed to promote connection"
                );
            }
        }
    }

    /// Dispatch a decrypted link message to the appropriate handler.
    ///
    /// Link messages are protocol messages exchanged between authenticated peers.
    async fn dispatch_link_message(&mut self, _from: &NodeId, plaintext: &[u8]) {
        if plaintext.is_empty() {
            return;
        }

        let msg_type = plaintext[0];
        let _payload = &plaintext[1..];

        // TODO: Implement link message handlers
        match msg_type {
            0x10 => {
                // TreeAnnounce
                debug!("Received TreeAnnounce (not yet implemented)");
            }
            0x20 => {
                // FilterAnnounce
                debug!("Received FilterAnnounce (not yet implemented)");
            }
            0x30 => {
                // LookupRequest
                debug!("Received LookupRequest (not yet implemented)");
            }
            0x31 => {
                // LookupResponse
                debug!("Received LookupResponse (not yet implemented)");
            }
            0x40 => {
                // SessionDatagram
                debug!("Received SessionDatagram (not yet implemented)");
            }
            _ => {
                debug!(msg_type = msg_type, "Unknown link message type");
            }
        }
    }

    /// Stop the node.
    ///
    /// Shuts down TUN interface, stops I/O threads, and transitions to
    /// the Stopped state.
    pub async fn stop(&mut self) -> Result<(), NodeError> {
        if !self.state.can_stop() {
            return Err(NodeError::NotStarted);
        }
        self.state = NodeState::Stopping;
        info!(state = %self.state, "Node stopping");

        // Shutdown transports first (they're packet producers)
        let transport_ids: Vec<_> = self.transports.keys().cloned().collect();
        for transport_id in transport_ids {
            if let Some(mut handle) = self.transports.remove(&transport_id) {
                let transport_type = handle.transport_type().name;
                match handle.stop().await {
                    Ok(()) => {
                        info!(transport_id = %transport_id, transport_type, "Transport stopped");
                    }
                    Err(e) => {
                        warn!(
                            transport_id = %transport_id,
                            transport_type,
                            error = %e,
                            "Transport stop failed"
                        );
                    }
                }
            }
        }

        // Drop packet channels
        self.packet_tx.take();
        self.packet_rx.take();

        // Shutdown TUN interface
        if let Some(name) = self.tun_name.take() {
            info!(name = %name, "Shutting down TUN interface");

            // Drop the tun_tx to signal the writer to stop
            self.tun_tx.take();

            // Delete the interface (causes reader to get EFAULT)
            if let Err(e) = shutdown_tun_interface(&name).await {
                warn!(name = %name, error = %e, "Failed to shutdown TUN interface");
            }

            // Wait for threads to finish
            if let Some(handle) = self.tun_reader_handle.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.tun_writer_handle.take() {
                let _ = handle.join();
            }

            self.tun_state = TunState::Disabled;
        }

        self.state = NodeState::Stopped;
        info!(state = %self.state, "Node stopped");
        Ok(())
    }

    /// Get the TUN packet sender channel.
    ///
    /// Returns None if TUN is not active or the node hasn't been started.
    pub fn tun_tx(&self) -> Option<&TunTx> {
        self.tun_tx.as_ref()
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("node_id", self.node_id())
            .field("state", &self.state)
            .field("is_leaf_only", &self.is_leaf_only)
            .field("connections", &self.connection_count())
            .field("peers", &self.peer_count())
            .field("links", &self.link_count())
            .field("transports", &self.transport_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{LinkDirection, TransportAddr};
    use std::time::Duration;

    fn make_node() -> Node {
        let config = Config::new();
        Node::new(config).unwrap()
    }

    #[allow(dead_code)]
    fn make_node_id(val: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        NodeId::from_bytes(bytes)
    }

    fn make_peer_identity() -> PeerIdentity {
        let identity = Identity::generate();
        PeerIdentity::from_pubkey(identity.pubkey())
    }

    #[test]
    fn test_node_creation() {
        let node = make_node();

        assert_eq!(node.state(), NodeState::Created);
        assert_eq!(node.peer_count(), 0);
        assert_eq!(node.connection_count(), 0);
        assert_eq!(node.link_count(), 0);
        assert!(!node.is_leaf_only());
    }

    #[test]
    fn test_node_with_identity() {
        let identity = Identity::generate();
        let expected_node_id = *identity.node_id();
        let config = Config::new();

        let node = Node::with_identity(identity, config);

        assert_eq!(node.node_id(), &expected_node_id);
    }

    #[test]
    fn test_node_leaf_only() {
        let config = Config::new();
        let node = Node::leaf_only(config).unwrap();

        assert!(node.is_leaf_only());
        assert!(node.bloom_state().is_leaf_only());
    }

    #[tokio::test]
    async fn test_node_state_transitions() {
        let mut node = make_node();

        assert!(!node.is_running());
        assert!(node.state().can_start());

        node.start().await.unwrap();
        assert!(node.is_running());
        assert!(!node.state().can_start());

        node.stop().await.unwrap();
        assert!(!node.is_running());
        assert_eq!(node.state(), NodeState::Stopped);
    }

    #[tokio::test]
    async fn test_node_double_start() {
        let mut node = make_node();
        node.start().await.unwrap();

        let result = node.start().await;
        assert!(matches!(result, Err(NodeError::AlreadyStarted)));

        // Clean up
        node.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_node_stop_not_started() {
        let mut node = make_node();

        let result = node.stop().await;
        assert!(matches!(result, Err(NodeError::NotStarted)));
    }

    #[test]
    fn test_node_link_management() {
        let mut node = make_node();

        let link_id = node.allocate_link_id();
        let link = Link::connectionless(
            link_id,
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        node.add_link(link).unwrap();
        assert_eq!(node.link_count(), 1);

        assert!(node.get_link(&link_id).is_some());

        // Test addr_to_link lookup
        assert_eq!(
            node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")),
            Some(link_id)
        );

        node.remove_link(&link_id);
        assert_eq!(node.link_count(), 0);

        // Lookup should be gone
        assert!(node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")).is_none());
    }

    #[test]
    fn test_node_link_limit() {
        let mut node = make_node();
        node.set_max_links(2);

        for i in 0..2 {
            let link_id = node.allocate_link_id();
            let link = Link::connectionless(
                link_id,
                TransportId::new(1),
                TransportAddr::from_string(&format!("test{}", i)),
                LinkDirection::Outbound,
                Duration::from_millis(50),
            );
            node.add_link(link).unwrap();
        }

        let link_id = node.allocate_link_id();
        let link = Link::connectionless(
            link_id,
            TransportId::new(1),
            TransportAddr::from_string("test_extra"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        let result = node.add_link(link);
        assert!(matches!(result, Err(NodeError::MaxLinksExceeded { .. })));
    }

    #[test]
    fn test_node_connection_management() {
        let mut node = make_node();

        let identity = make_peer_identity();
        let link_id = LinkId::new(1);
        let conn = PeerConnection::outbound(link_id, identity, 1000);

        node.add_connection(conn).unwrap();
        assert_eq!(node.connection_count(), 1);

        assert!(node.get_connection(&link_id).is_some());

        node.remove_connection(&link_id);
        assert_eq!(node.connection_count(), 0);
    }

    #[test]
    fn test_node_connection_duplicate() {
        let mut node = make_node();

        let identity = make_peer_identity();
        let link_id = LinkId::new(1);
        let conn1 = PeerConnection::outbound(link_id, identity.clone(), 1000);
        let conn2 = PeerConnection::outbound(link_id, identity, 2000);

        node.add_connection(conn1).unwrap();
        let result = node.add_connection(conn2);

        assert!(matches!(result, Err(NodeError::ConnectionAlreadyExists(_))));
    }

    #[test]
    fn test_node_promote_connection() {
        let mut node = make_node();

        let identity = make_peer_identity();
        let node_id = *identity.node_id();
        let link_id = LinkId::new(1);
        let conn = PeerConnection::outbound(link_id, identity.clone(), 1000);

        node.add_connection(conn).unwrap();
        assert_eq!(node.connection_count(), 1);
        assert_eq!(node.peer_count(), 0);

        let result = node.promote_connection(link_id, identity, 2000).unwrap();

        assert!(matches!(result, PromotionResult::Promoted(_)));
        assert_eq!(node.connection_count(), 0);
        assert_eq!(node.peer_count(), 1);

        let peer = node.get_peer(&node_id).unwrap();
        assert_eq!(peer.authenticated_at(), 2000);
    }

    #[test]
    fn test_node_cross_connection_resolution() {
        let mut node = make_node();

        // First connection and promotion (becomes active peer)
        let identity = make_peer_identity();
        let node_id = *identity.node_id();
        let link_id1 = LinkId::new(1);
        let conn1 = PeerConnection::outbound(link_id1, identity.clone(), 1000);

        node.add_connection(conn1).unwrap();
        node.promote_connection(link_id1, identity.clone(), 1500).unwrap();

        assert_eq!(node.peer_count(), 1);
        assert_eq!(node.get_peer(&node_id).unwrap().link_id(), link_id1);

        // Second connection (simulates cross-connection scenario)
        let link_id2 = LinkId::new(2);
        let conn2 = PeerConnection::inbound(link_id2, 2000);

        node.add_connection(conn2).unwrap();

        // Promote second connection - tie-breaker determines outcome
        let result = node.promote_connection(link_id2, identity, 2500).unwrap();

        // One connection should win, one should lose
        match result {
            PromotionResult::CrossConnectionWon { loser_link_id, .. } => {
                assert_eq!(loser_link_id, link_id1);
                assert_eq!(node.get_peer(&node_id).unwrap().link_id(), link_id2);
            }
            PromotionResult::CrossConnectionLost { winner_link_id } => {
                assert_eq!(winner_link_id, link_id1);
                assert_eq!(node.get_peer(&node_id).unwrap().link_id(), link_id1);
            }
            PromotionResult::Promoted(_) => {
                panic!("Expected cross-connection, got normal promotion");
            }
        }

        // Still only one peer
        assert_eq!(node.peer_count(), 1);
    }

    #[test]
    fn test_node_peer_limit() {
        let mut node = make_node();
        node.set_max_peers(2);

        // Add two peers via promotion
        for i in 0..2 {
            let identity = make_peer_identity();
            let link_id = LinkId::new(i as u64 + 1);
            let conn = PeerConnection::outbound(link_id, identity.clone(), 1000);
            node.add_connection(conn).unwrap();
            node.promote_connection(link_id, identity, 2000).unwrap();
        }

        assert_eq!(node.peer_count(), 2);

        // Third should fail
        let identity = make_peer_identity();
        let link_id = LinkId::new(3);
        let conn = PeerConnection::outbound(link_id, identity.clone(), 3000);
        node.add_connection(conn).unwrap();

        let result = node.promote_connection(link_id, identity, 4000);
        assert!(matches!(result, Err(NodeError::MaxPeersExceeded { .. })));
    }

    #[test]
    fn test_node_link_id_allocation() {
        let mut node = make_node();

        let id1 = node.allocate_link_id();
        let id2 = node.allocate_link_id();
        let id3 = node.allocate_link_id();

        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_eq!(id1.as_u64(), 1);
        assert_eq!(id2.as_u64(), 2);
        assert_eq!(id3.as_u64(), 3);
    }

    #[test]
    fn test_node_transport_management() {
        let mut node = make_node();

        // Initially no transports (transports are created during start())
        assert_eq!(node.transport_count(), 0);

        // Allocating IDs still works
        let id1 = node.allocate_transport_id();
        let id2 = node.allocate_transport_id();
        assert_ne!(id1, id2);

        // get_transport returns None when transport doesn't exist
        assert!(node.get_transport(&id1).is_none());
        assert!(node.get_transport(&id2).is_none());

        // transport_ids() iterator is empty
        assert_eq!(node.transport_ids().count(), 0);
    }

    #[test]
    fn test_node_sendable_peers() {
        let mut node = make_node();

        // Add a healthy peer
        let identity1 = make_peer_identity();
        let node_id1 = *identity1.node_id();
        let link_id1 = LinkId::new(1);
        let conn1 = PeerConnection::outbound(link_id1, identity1.clone(), 1000);
        node.add_connection(conn1).unwrap();
        node.promote_connection(link_id1, identity1, 2000).unwrap();

        // Add another peer and mark it stale (still sendable)
        let identity2 = make_peer_identity();
        let link_id2 = LinkId::new(2);
        let conn2 = PeerConnection::outbound(link_id2, identity2.clone(), 1000);
        node.add_connection(conn2).unwrap();
        node.promote_connection(link_id2, identity2, 2000).unwrap();

        // Add a third peer and mark it disconnected (not sendable)
        let identity3 = make_peer_identity();
        let node_id3 = *identity3.node_id();
        let link_id3 = LinkId::new(3);
        let conn3 = PeerConnection::outbound(link_id3, identity3.clone(), 1000);
        node.add_connection(conn3).unwrap();
        node.promote_connection(link_id3, identity3, 2000).unwrap();
        node.get_peer_mut(&node_id3).unwrap().mark_disconnected();

        assert_eq!(node.peer_count(), 3);
        assert_eq!(node.sendable_peer_count(), 2);

        let sendable: Vec<_> = node.sendable_peers().collect();
        assert_eq!(sendable.len(), 2);
        assert!(sendable.iter().any(|p| p.node_id() == &node_id1));
    }

    // === RX Loop Tests ===

    #[test]
    fn test_node_index_allocator_initialized() {
        let node = make_node();
        // Index allocator should be empty on creation
        assert_eq!(node.index_allocator.count(), 0);
    }

    #[test]
    fn test_node_pending_outbound_tracking() {
        let mut node = make_node();
        let transport_id = TransportId::new(1);
        let link_id = LinkId::new(1);

        // Allocate an index
        let index = node.index_allocator.allocate().unwrap();

        // Track in pending_outbound
        node.pending_outbound.insert((transport_id, index.as_u32()), link_id);

        // Verify we can look it up
        let found = node.pending_outbound.get(&(transport_id, index.as_u32()));
        assert_eq!(found, Some(&link_id));

        // Clean up
        node.pending_outbound.remove(&(transport_id, index.as_u32()));
        let _ = node.index_allocator.free(index);

        assert_eq!(node.index_allocator.count(), 0);
        assert!(node.pending_outbound.is_empty());
    }

    #[test]
    fn test_node_peers_by_index_tracking() {
        let mut node = make_node();
        let transport_id = TransportId::new(1);
        let node_id = make_node_id(42);

        // Allocate an index
        let index = node.index_allocator.allocate().unwrap();

        // Track in peers_by_index
        node.peers_by_index.insert((transport_id, index.as_u32()), node_id);

        // Verify lookup
        let found = node.peers_by_index.get(&(transport_id, index.as_u32()));
        assert_eq!(found, Some(&node_id));

        // Clean up
        node.peers_by_index.remove(&(transport_id, index.as_u32()));
        let _ = node.index_allocator.free(index);

        assert!(node.peers_by_index.is_empty());
    }

    #[tokio::test]
    async fn test_node_rx_loop_requires_start() {
        let mut node = make_node();

        // RX loop should fail if node not started (no packet_rx)
        let result = node.run_rx_loop().await;
        assert!(matches!(result, Err(NodeError::NotStarted)));
    }

    #[tokio::test]
    async fn test_node_rx_loop_takes_channel() {
        let mut node = make_node();
        node.start().await.unwrap();

        // packet_rx should be available after start
        assert!(node.packet_rx.is_some());

        // After run_rx_loop takes ownership, it should be None
        // We can't actually run the loop (it blocks), but we can test the take
        let rx = node.packet_rx.take();
        assert!(rx.is_some());
        assert!(node.packet_rx.is_none());

        node.stop().await.unwrap();
    }

    #[test]
    fn test_rate_limiter_initialized() {
        let mut node = make_node();

        // Rate limiter should allow handshakes initially
        assert!(node.msg1_rate_limiter.can_start_handshake());

        // Start a handshake
        assert!(node.msg1_rate_limiter.start_handshake());
        assert_eq!(node.msg1_rate_limiter.pending_count(), 1);

        // Complete it
        node.msg1_rate_limiter.complete_handshake();
        assert_eq!(node.msg1_rate_limiter.pending_count(), 0);
    }
}
