//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

use crate::bloom::BloomState;
use crate::cache::CoordCache;
use crate::config::PeerConfig;
use crate::peer::Peer;
use crate::transport::{
    packet_channel, Link, LinkDirection, LinkId, PacketRx, PacketTx, TransportAddr,
    TransportHandle, TransportId,
};
use crate::transport::udp::UdpTransport;
use crate::tree::TreeState;
use crate::tun::{run_tun_reader, shutdown_tun_interface, TunDevice, TunError, TunState, TunTx};
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

    #[error("peer not found: {0:?}")]
    PeerNotFound(NodeId),

    #[error("peer already exists: {0:?}")]
    PeerAlreadyExists(NodeId),

    #[error("invalid peer npub '{npub}': {reason}")]
    InvalidPeerNpub { npub: String, reason: String },

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

/// A running FIPS node instance.
///
/// This is the top-level container holding all node state.
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

    // === Packet Channel ===
    /// Packet sender for transports.
    packet_tx: Option<PacketTx>,
    /// Packet receiver (for event loop).
    packet_rx: Option<PacketRx>,

    // === Peers ===
    /// Authenticated peers.
    peers: HashMap<NodeId, Peer>,

    // === Resource Limits ===
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

        info!(
            node_id = %node_id,
            address = %identity.address(),
            "Node initialized as root"
        );

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
            packet_tx: None,
            packet_rx: None,
            peers: HashMap::new(),
            max_peers: 128,
            max_links: 256,
            next_link_id: 1,
            next_transport_id: 1,
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
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

        info!(
            node_id = %node_id,
            address = %identity.address(),
            "Node initialized as root"
        );

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
            packet_tx: None,
            packet_rx: None,
            peers: HashMap::new(),
            max_peers: 128,
            max_links: 256,
            next_link_id: 1,
            next_transport_id: 1,
            tun_state,
            tun_name: None,
            tun_tx: None,
            tun_reader_handle: None,
            tun_writer_handle: None,
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
    /// peer entry. The peer starts in Connecting state; authentication
    /// handshake will be handled by the event loop.
    fn initiate_peer_connections(&mut self) {
        // Collect peer configs to avoid borrow conflicts
        let peer_configs: Vec<_> = self.config.auto_connect_peers().cloned().collect();

        if peer_configs.is_empty() {
            debug!("No static peers configured");
            return;
        }

        info!(count = peer_configs.len(), "Initiating static peer connections");

        for peer_config in peer_configs {
            if let Err(e) = self.initiate_peer_connection(&peer_config) {
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
    fn initiate_peer_connection(&mut self, peer_config: &PeerConfig) -> Result<(), NodeError> {
        // Parse the peer's npub to get their identity
        let peer_identity = PeerIdentity::from_npub(&peer_config.npub).map_err(|e| {
            NodeError::InvalidPeerNpub {
                npub: peer_config.npub.clone(),
                reason: e.to_string(),
            }
        })?;

        let peer_node_id = *peer_identity.node_id();

        // Check if peer already exists
        if self.peers.contains_key(&peer_node_id) {
            debug!(
                npub = %peer_config.npub,
                "Peer already exists, skipping"
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
                remote_addr,
                LinkDirection::Outbound,
                Duration::from_millis(100), // Base RTT estimate for UDP
            );

            self.links.insert(link_id, link);

            // Create peer in Connecting state
            let mut peer = Peer::discovered(peer_identity.clone(), link_id);
            peer.set_connecting();

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

            self.peers.insert(peer_node_id, peer);

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

    /// Set the maximum number of peers.
    pub fn set_max_peers(&mut self, max: usize) {
        self.max_peers = max;
    }

    /// Set the maximum number of links.
    pub fn set_max_links(&mut self, max: usize) {
        self.max_links = max;
    }

    // === Counts ===

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
        self.links.insert(link.link_id(), link);
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

    /// Remove a link.
    pub fn remove_link(&mut self, link_id: &LinkId) -> Option<Link> {
        self.links.remove(link_id)
    }

    /// Iterate over all links.
    pub fn links(&self) -> impl Iterator<Item = &Link> {
        self.links.values()
    }

    // === Peer Management ===

    /// Add an authenticated peer.
    pub fn add_peer(&mut self, peer: Peer) -> Result<(), NodeError> {
        let node_id = *peer.node_id();

        if self.peers.contains_key(&node_id) {
            return Err(NodeError::PeerAlreadyExists(node_id));
        }

        if self.max_peers > 0 && self.peers.len() >= self.max_peers {
            return Err(NodeError::MaxPeersExceeded { max: self.max_peers });
        }

        self.peers.insert(node_id, peer);
        Ok(())
    }

    /// Get a peer by NodeId.
    pub fn get_peer(&self, node_id: &NodeId) -> Option<&Peer> {
        self.peers.get(node_id)
    }

    /// Get a mutable peer by NodeId.
    pub fn get_peer_mut(&mut self, node_id: &NodeId) -> Option<&mut Peer> {
        self.peers.get_mut(node_id)
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, node_id: &NodeId) -> Option<Peer> {
        self.peers.remove(node_id)
    }

    /// Iterate over all peers.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    /// Iterate over all peer node IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.peers.keys()
    }

    /// Iterate over all active peers.
    pub fn active_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values().filter(|p| p.state().is_active())
    }

    /// Number of active peers.
    pub fn active_peer_count(&self) -> usize {
        self.peers.values().filter(|p| p.state().is_active()).count()
    }

    // === Routing (stubs) ===

    /// Find next hop for a destination (stub).
    ///
    /// Returns the peer that minimizes tree distance to the destination.
    pub fn find_next_hop(&self, _dest_node_id: &NodeId) -> Option<&Peer> {
        // Stub: would implement greedy tree routing
        None
    }

    /// Check if a destination is in any peer's bloom filter.
    pub fn destination_in_filters(&self, dest: &NodeId) -> Vec<&Peer> {
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

        // Initialize TUN interface if configured
        if self.config.tun.enabled {
            let address = *self.identity.address();
            match TunDevice::create(&self.config.tun, address).await {
                Ok(device) => {
                    let mtu = device.mtu();
                    let name = device.name().to_string();
                    let our_addr = *device.address();

                    info!(
                        name = %name,
                        mtu,
                        address = %device.address(),
                        "TUN device active"
                    );

                    // Create writer (dups the fd for independent write access)
                    let (writer, tun_tx) = device.create_writer()?;

                    info!(mtu, name = %name, "Starting TUN reader and writer");

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

        // Connect to static peers (step 5 per architecture doc)
        self.initiate_peer_connections();

        self.state = NodeState::Running;
        info!(
            state = %self.state,
            transports = self.transports.len(),
            peers = self.peers.len(),
            "Node started"
        );
        Ok(())
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

    #[test]
    fn test_node_creation() {
        let node = make_node();

        assert_eq!(node.state(), NodeState::Created);
        assert_eq!(node.peer_count(), 0);
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

        node.remove_link(&link_id);
        assert_eq!(node.link_count(), 0);
    }

    #[test]
    fn test_node_link_limit() {
        let mut node = make_node();
        node.set_max_links(2);

        for _ in 0..2 {
            let link_id = node.allocate_link_id();
            let link = Link::connectionless(
                link_id,
                TransportId::new(1),
                TransportAddr::from_string("test"),
                LinkDirection::Outbound,
                Duration::from_millis(50),
            );
            node.add_link(link).unwrap();
        }

        let link_id = node.allocate_link_id();
        let link = Link::connectionless(
            link_id,
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        let result = node.add_link(link);
        assert!(matches!(result, Err(NodeError::MaxLinksExceeded { .. })));
    }

    #[test]
    fn test_node_peer_management() {
        let mut node = make_node();

        let peer_identity = Identity::generate();
        let peer_pub = crate::PeerIdentity::from_pubkey(peer_identity.pubkey());
        let peer = Peer::discovered(peer_pub, LinkId::new(1));
        let peer_node_id = *peer.node_id();

        node.add_peer(peer).unwrap();
        assert_eq!(node.peer_count(), 1);

        assert!(node.get_peer(&peer_node_id).is_some());

        node.remove_peer(&peer_node_id);
        assert_eq!(node.peer_count(), 0);
    }

    #[test]
    fn test_node_peer_duplicate() {
        let mut node = make_node();

        let peer_identity = Identity::generate();
        let peer_pub = crate::PeerIdentity::from_pubkey(peer_identity.pubkey());
        let peer1 = Peer::discovered(peer_pub, LinkId::new(1));
        let peer2 = Peer::discovered(peer_pub, LinkId::new(2));

        node.add_peer(peer1).unwrap();
        let result = node.add_peer(peer2);

        assert!(matches!(result, Err(NodeError::PeerAlreadyExists(_))));
    }

    #[test]
    fn test_node_peer_limit() {
        let mut node = make_node();
        node.set_max_peers(2);

        for _ in 0..2 {
            let peer_identity = Identity::generate();
            let peer_pub = crate::PeerIdentity::from_pubkey(peer_identity.pubkey());
            let peer = Peer::discovered(peer_pub, LinkId::new(1));
            node.add_peer(peer).unwrap();
        }

        let peer_identity = Identity::generate();
        let peer_pub = crate::PeerIdentity::from_pubkey(peer_identity.pubkey());
        let peer = Peer::discovered(peer_pub, LinkId::new(1));

        let result = node.add_peer(peer);
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
    fn test_node_active_peers() {
        let mut node = make_node();

        // Add a discovered peer
        let peer_identity1 = Identity::generate();
        let peer_pub1 = crate::PeerIdentity::from_pubkey(peer_identity1.pubkey());
        let peer1 = Peer::discovered(peer_pub1, LinkId::new(1));
        node.add_peer(peer1).unwrap();

        // Add an active peer
        let peer_identity2 = Identity::generate();
        let peer_pub2 = crate::PeerIdentity::from_pubkey(peer_identity2.pubkey());
        let mut peer2 = Peer::discovered(peer_pub2, LinkId::new(2));
        peer2.set_active(1000);
        let peer2_id = *peer2.node_id();
        node.add_peer(peer2).unwrap();

        assert_eq!(node.peer_count(), 2);
        assert_eq!(node.active_peer_count(), 1);

        let active: Vec<_> = node.active_peers().collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].node_id(), &peer2_id);
    }
}
