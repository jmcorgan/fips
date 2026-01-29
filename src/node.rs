//! FIPS Node Entity
//!
//! Top-level structure representing a running FIPS instance. The Node
//! holds all state required for mesh routing: identity, tree state,
//! Bloom filters, coordinate caches, transports, links, and peers.

use crate::bloom::BloomState;
use crate::cache::CoordCache;
use crate::peer::Peer;
use crate::transport::{Link, LinkId, TransportId};
use crate::tree::TreeState;
use crate::{Config, ConfigError, Identity, IdentityError, NodeId};
use std::collections::HashMap;
use std::fmt;
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

    #[error("link not found: {0}")]
    LinkNotFound(LinkId),

    #[error("peer not found: {0:?}")]
    PeerNotFound(NodeId),

    #[error("peer already exists: {0:?}")]
    PeerAlreadyExists(NodeId),

    #[error("max peers exceeded: {max}")]
    MaxPeersExceeded { max: usize },

    #[error("max links exceeded: {max}")]
    MaxLinksExceeded { max: usize },

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
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
    /// Active transport IDs.
    transport_ids: Vec<TransportId>,
    /// Active links.
    links: HashMap<LinkId, Link>,

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
}

impl Node {
    /// Create a new node from configuration.
    pub fn new(config: Config) -> Result<Self, NodeError> {
        let identity = config.create_identity()?;
        let node_id = *identity.node_id();

        Ok(Self {
            identity,
            config,
            state: NodeState::Created,
            is_leaf_only: false,
            tree_state: TreeState::new(node_id),
            bloom_state: BloomState::new(node_id),
            coord_cache: CoordCache::with_defaults(),
            transport_ids: Vec::new(),
            links: HashMap::new(),
            peers: HashMap::new(),
            max_peers: 128,
            max_links: 256,
            next_link_id: 1,
            next_transport_id: 1,
        })
    }

    /// Create a node with a specific identity.
    pub fn with_identity(identity: Identity, config: Config) -> Self {
        let node_id = *identity.node_id();
        Self {
            identity,
            config,
            state: NodeState::Created,
            is_leaf_only: false,
            tree_state: TreeState::new(node_id),
            bloom_state: BloomState::new(node_id),
            coord_cache: CoordCache::with_defaults(),
            transport_ids: Vec::new(),
            links: HashMap::new(),
            peers: HashMap::new(),
            max_peers: 128,
            max_links: 256,
            next_link_id: 1,
            next_transport_id: 1,
        }
    }

    /// Create a leaf-only node (simplified state).
    pub fn leaf_only(config: Config) -> Result<Self, NodeError> {
        let mut node = Self::new(config)?;
        node.is_leaf_only = true;
        node.bloom_state = BloomState::leaf_only(*node.identity.node_id());
        Ok(node)
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

    /// Number of transports.
    pub fn transport_count(&self) -> usize {
        self.transport_ids.len()
    }

    // === Transport Management ===

    /// Allocate a new transport ID.
    pub fn allocate_transport_id(&mut self) -> TransportId {
        let id = TransportId::new(self.next_transport_id);
        self.next_transport_id += 1;
        id
    }

    /// Register a transport.
    pub fn add_transport(&mut self, transport_id: TransportId) {
        if !self.transport_ids.contains(&transport_id) {
            self.transport_ids.push(transport_id);
        }
    }

    /// Unregister a transport.
    pub fn remove_transport(&mut self, transport_id: &TransportId) {
        self.transport_ids.retain(|id| id != transport_id);
    }

    /// Get all transport IDs.
    pub fn transport_ids(&self) -> &[TransportId] {
        &self.transport_ids
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

    /// Start the node (stub).
    ///
    /// In a full implementation, this would:
    /// - Initialize transports
    /// - Bind TUN interface
    /// - Start event loop
    pub fn start(&mut self) -> Result<(), NodeError> {
        if !self.state.can_start() {
            return Err(NodeError::AlreadyStarted);
        }
        self.state = NodeState::Starting;
        // Actual startup would initialize transports, TUN, etc.
        self.state = NodeState::Running;
        Ok(())
    }

    /// Stop the node (stub).
    ///
    /// In a full implementation, this would:
    /// - Close all peers
    /// - Close all links
    /// - Stop all transports
    /// - Unbind TUN interface
    pub fn stop(&mut self) -> Result<(), NodeError> {
        if !self.state.can_stop() {
            return Err(NodeError::NotStarted);
        }
        self.state = NodeState::Stopping;
        // Actual shutdown would close transports, links, etc.
        self.state = NodeState::Stopped;
        Ok(())
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

    #[test]
    fn test_node_state_transitions() {
        let mut node = make_node();

        assert!(!node.is_running());
        assert!(node.state().can_start());

        node.start().unwrap();
        assert!(node.is_running());
        assert!(!node.state().can_start());

        node.stop().unwrap();
        assert!(!node.is_running());
        assert_eq!(node.state(), NodeState::Stopped);
    }

    #[test]
    fn test_node_double_start() {
        let mut node = make_node();
        node.start().unwrap();

        let result = node.start();
        assert!(matches!(result, Err(NodeError::AlreadyStarted)));
    }

    #[test]
    fn test_node_stop_not_started() {
        let mut node = make_node();

        let result = node.stop();
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

        let id1 = node.allocate_transport_id();
        let id2 = node.allocate_transport_id();

        node.add_transport(id1);
        node.add_transport(id2);
        assert_eq!(node.transport_count(), 2);

        // Adding same ID again doesn't duplicate
        node.add_transport(id1);
        assert_eq!(node.transport_count(), 2);

        node.remove_transport(&id1);
        assert_eq!(node.transport_count(), 1);
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
