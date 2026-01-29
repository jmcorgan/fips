//! Peer Management Entities
//!
//! Structures for tracking authenticated remote FIPS nodes. A Peer
//! represents an authenticated connection to another node in the mesh.

use crate::bloom::BloomFilter;
use crate::transport::{LinkId, LinkStats};
use crate::tree::{ParentDeclaration, TreeCoordinate};
use crate::{FipsAddress, NodeId, PeerIdentity};
use secp256k1::XOnlyPublicKey;
use std::fmt;
use thiserror::Error;

/// Errors related to peer operations.
#[derive(Debug, Error)]
pub enum PeerError {
    #[error("peer not authenticated")]
    NotAuthenticated,

    #[error("peer not found: {0:?}")]
    NotFound(NodeId),

    #[error("peer already exists: {0:?}")]
    AlreadyExists(NodeId),

    #[error("peer state invalid for operation: expected {expected}, got {actual}")]
    InvalidState { expected: &'static str, actual: PeerState },

    #[error("peer disconnected")]
    Disconnected,
}

/// Peer lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Known via discovery or config, no link yet.
    Discovered,
    /// Link establishment in progress (connection-oriented transports).
    Connecting,
    /// FIPS authentication handshake in progress.
    Authenticating,
    /// Fully integrated peer.
    Active,
    /// Was active, now disconnected.
    Disconnected,
}

impl PeerState {
    /// Check if the peer is fully operational.
    pub fn is_active(&self) -> bool {
        matches!(self, PeerState::Active)
    }

    /// Check if peer can receive data.
    pub fn can_send(&self) -> bool {
        matches!(self, PeerState::Active)
    }

    /// Check if this is a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, PeerState::Disconnected)
    }

    /// Check if the peer is in the process of connecting.
    pub fn is_connecting(&self) -> bool {
        matches!(self, PeerState::Connecting | PeerState::Authenticating)
    }
}

impl fmt::Display for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PeerState::Discovered => "discovered",
            PeerState::Connecting => "connecting",
            PeerState::Authenticating => "authenticating",
            PeerState::Active => "active",
            PeerState::Disconnected => "disconnected",
        };
        write!(f, "{}", s)
    }
}

/// An authenticated remote FIPS node.
#[derive(Clone, Debug)]
pub struct Peer {
    // === Identity ===
    /// Cryptographic identity (includes pubkey, node_id, address).
    identity: PeerIdentity,

    // === Connection ===
    /// Link used to reach this peer.
    link_id: LinkId,
    /// Current lifecycle state.
    state: PeerState,

    // === Spanning Tree ===
    /// Their latest parent declaration.
    declaration: Option<ParentDeclaration>,
    /// Their path to root.
    ancestry: Option<TreeCoordinate>,

    // === Bloom Filter ===
    /// What's reachable through them (inbound filter).
    inbound_filter: Option<BloomFilter>,
    /// Their filter's sequence number.
    filter_sequence: u64,
    /// Remaining propagation hops on their filter.
    filter_ttl: u8,
    /// When we received their last filter (Unix milliseconds).
    filter_received_at: u64,
    /// Whether we owe them a filter update.
    pending_filter_update: bool,

    // === Statistics ===
    /// Link statistics.
    link_stats: LinkStats,
    /// When this peer was first connected (Unix milliseconds).
    connected_at: Option<u64>,
    /// When this peer was last seen (any activity, Unix milliseconds).
    last_seen: u64,
}

impl Peer {
    /// Create a new peer in Discovered state.
    pub fn discovered(identity: PeerIdentity, link_id: LinkId) -> Self {
        Self {
            identity,
            link_id,
            state: PeerState::Discovered,
            declaration: None,
            ancestry: None,
            inbound_filter: None,
            filter_sequence: 0,
            filter_ttl: 0,
            filter_received_at: 0,
            pending_filter_update: false,
            link_stats: LinkStats::new(),
            connected_at: None,
            last_seen: 0,
        }
    }

    /// Create a new peer from a public key.
    pub fn from_pubkey(pubkey: XOnlyPublicKey, link_id: LinkId) -> Self {
        Self::discovered(PeerIdentity::from_pubkey(pubkey), link_id)
    }

    // === Identity Accessors ===

    /// Get the peer's identity.
    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Get the peer's NodeId.
    pub fn node_id(&self) -> &NodeId {
        self.identity.node_id()
    }

    /// Get the peer's FIPS address.
    pub fn address(&self) -> &FipsAddress {
        self.identity.address()
    }

    /// Get the peer's public key.
    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.identity.pubkey()
    }

    /// Get the peer's npub string.
    pub fn npub(&self) -> String {
        self.identity.npub()
    }

    // === Connection Accessors ===

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.link_id
    }

    /// Get the current state.
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Check if the peer is active.
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Check if the peer can receive data.
    pub fn can_send(&self) -> bool {
        self.state.can_send()
    }

    // === Tree Accessors ===

    /// Get the peer's tree coordinates, if known.
    pub fn coords(&self) -> Option<&TreeCoordinate> {
        self.ancestry.as_ref()
    }

    /// Get the peer's parent declaration, if known.
    pub fn declaration(&self) -> Option<&ParentDeclaration> {
        self.declaration.as_ref()
    }

    /// Check if this peer has a known tree position.
    pub fn has_tree_position(&self) -> bool {
        self.declaration.is_some() && self.ancestry.is_some()
    }

    // === Filter Accessors ===

    /// Get the peer's inbound filter, if known.
    pub fn inbound_filter(&self) -> Option<&BloomFilter> {
        self.inbound_filter.as_ref()
    }

    /// Get the filter sequence number.
    pub fn filter_sequence(&self) -> u64 {
        self.filter_sequence
    }

    /// Get the filter TTL.
    pub fn filter_ttl(&self) -> u8 {
        self.filter_ttl
    }

    /// Check if this peer's filter is stale.
    pub fn filter_is_stale(&self, current_time_ms: u64, stale_threshold_ms: u64) -> bool {
        if self.filter_received_at == 0 {
            return true;
        }
        current_time_ms.saturating_sub(self.filter_received_at) > stale_threshold_ms
    }

    /// Check if a destination might be reachable through this peer.
    pub fn may_reach(&self, node_id: &NodeId) -> bool {
        match &self.inbound_filter {
            Some(filter) => filter.contains(node_id),
            None => false,
        }
    }

    /// Check if we need to send this peer a filter update.
    pub fn needs_filter_update(&self) -> bool {
        self.pending_filter_update
    }

    // === Statistics Accessors ===

    /// Get link statistics.
    pub fn link_stats(&self) -> &LinkStats {
        &self.link_stats
    }

    /// Get mutable link statistics.
    pub fn link_stats_mut(&mut self) -> &mut LinkStats {
        &mut self.link_stats
    }

    /// Get when this peer was connected.
    pub fn connected_at(&self) -> Option<u64> {
        self.connected_at
    }

    /// Get when this peer was last seen.
    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        if self.last_seen == 0 {
            return u64::MAX;
        }
        current_time_ms.saturating_sub(self.last_seen)
    }

    /// Connection duration.
    pub fn connection_duration(&self, current_time_ms: u64) -> Option<u64> {
        self.connected_at
            .map(|t| current_time_ms.saturating_sub(t))
    }

    // === State Transitions ===

    /// Transition to Connecting state.
    pub fn set_connecting(&mut self) {
        self.state = PeerState::Connecting;
    }

    /// Transition to Authenticating state.
    pub fn set_authenticating(&mut self) {
        self.state = PeerState::Authenticating;
    }

    /// Transition to Active state.
    pub fn set_active(&mut self, current_time_ms: u64) {
        self.state = PeerState::Active;
        self.connected_at = Some(current_time_ms);
        self.last_seen = current_time_ms;
    }

    /// Transition to Disconnected state.
    pub fn set_disconnected(&mut self) {
        self.state = PeerState::Disconnected;
    }

    /// Update last seen timestamp.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.last_seen = current_time_ms;
    }

    // === Tree Updates ===

    /// Update peer's tree position.
    pub fn update_tree_position(
        &mut self,
        declaration: ParentDeclaration,
        ancestry: TreeCoordinate,
        current_time_ms: u64,
    ) {
        self.declaration = Some(declaration);
        self.ancestry = Some(ancestry);
        self.last_seen = current_time_ms;
    }

    /// Clear peer's tree position.
    pub fn clear_tree_position(&mut self) {
        self.declaration = None;
        self.ancestry = None;
    }

    // === Filter Updates ===

    /// Update peer's inbound filter.
    pub fn update_filter(
        &mut self,
        filter: BloomFilter,
        sequence: u64,
        ttl: u8,
        current_time_ms: u64,
    ) {
        self.inbound_filter = Some(filter);
        self.filter_sequence = sequence;
        self.filter_ttl = ttl;
        self.filter_received_at = current_time_ms;
        self.last_seen = current_time_ms;
    }

    /// Clear peer's inbound filter.
    pub fn clear_filter(&mut self) {
        self.inbound_filter = None;
        self.filter_sequence = 0;
        self.filter_ttl = 0;
        self.filter_received_at = 0;
    }

    /// Mark that we need to send this peer a filter update.
    pub fn mark_filter_update_needed(&mut self) {
        self.pending_filter_update = true;
    }

    /// Clear the pending filter update flag.
    pub fn clear_filter_update_needed(&mut self) {
        self.pending_filter_update = false;
    }

    // === Link Updates ===

    /// Update the link ID (e.g., on reconnect).
    pub fn set_link_id(&mut self, link_id: LinkId) {
        self.link_id = link_id;
    }
}

/// Simplified peer for leaf-only nodes.
///
/// Leaf-only nodes maintain a single upstream peer without tree state
/// or Bloom filter management.
#[derive(Clone, Debug)]
pub struct UpstreamPeer {
    /// Peer identity.
    identity: PeerIdentity,
    /// Link to upstream.
    link_id: LinkId,
    /// Lifecycle state (auth lifecycle only).
    state: PeerState,
    /// Link statistics.
    link_stats: LinkStats,
    /// When connected.
    connected_at: Option<u64>,
    /// Last activity.
    last_seen: u64,
}

impl UpstreamPeer {
    /// Create a new upstream peer.
    pub fn new(identity: PeerIdentity, link_id: LinkId) -> Self {
        Self {
            identity,
            link_id,
            state: PeerState::Discovered,
            link_stats: LinkStats::new(),
            connected_at: None,
            last_seen: 0,
        }
    }

    /// Create from public key.
    pub fn from_pubkey(pubkey: XOnlyPublicKey, link_id: LinkId) -> Self {
        Self::new(PeerIdentity::from_pubkey(pubkey), link_id)
    }

    /// Get the identity.
    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Get the node ID.
    pub fn node_id(&self) -> &NodeId {
        self.identity.node_id()
    }

    /// Get the FIPS address.
    pub fn address(&self) -> &FipsAddress {
        self.identity.address()
    }

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.link_id
    }

    /// Get the state.
    pub fn state(&self) -> PeerState {
        self.state
    }

    /// Check if active.
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Get link statistics.
    pub fn link_stats(&self) -> &LinkStats {
        &self.link_stats
    }

    /// Get mutable link statistics.
    pub fn link_stats_mut(&mut self) -> &mut LinkStats {
        &mut self.link_stats
    }

    /// Set connecting state.
    pub fn set_connecting(&mut self) {
        self.state = PeerState::Connecting;
    }

    /// Set authenticating state.
    pub fn set_authenticating(&mut self) {
        self.state = PeerState::Authenticating;
    }

    /// Set active state.
    pub fn set_active(&mut self, current_time_ms: u64) {
        self.state = PeerState::Active;
        self.connected_at = Some(current_time_ms);
        self.last_seen = current_time_ms;
    }

    /// Set disconnected state.
    pub fn set_disconnected(&mut self) {
        self.state = PeerState::Disconnected;
    }

    /// Update last seen.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.last_seen = current_time_ms;
    }

    /// Get connected timestamp.
    pub fn connected_at(&self) -> Option<u64> {
        self.connected_at
    }

    /// Get last seen timestamp.
    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }

    /// Set link ID.
    pub fn set_link_id(&mut self, link_id: LinkId) {
        self.link_id = link_id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn make_peer() -> Peer {
        let identity = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey(identity.pubkey());
        Peer::discovered(peer_identity, LinkId::new(1))
    }

    fn make_node_id(val: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        NodeId::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::new(ids.iter().map(|&v| make_node_id(v)).collect()).unwrap()
    }

    // ===== PeerState Tests =====

    #[test]
    fn test_peer_state_properties() {
        assert!(!PeerState::Discovered.is_active());
        assert!(!PeerState::Connecting.is_active());
        assert!(!PeerState::Authenticating.is_active());
        assert!(PeerState::Active.is_active());
        assert!(!PeerState::Disconnected.is_active());

        assert!(PeerState::Connecting.is_connecting());
        assert!(PeerState::Authenticating.is_connecting());
        assert!(!PeerState::Active.is_connecting());

        assert!(PeerState::Disconnected.is_terminal());
        assert!(!PeerState::Active.is_terminal());
    }

    // ===== Peer Tests =====

    #[test]
    fn test_peer_state_transitions() {
        let mut peer = make_peer();

        assert_eq!(peer.state(), PeerState::Discovered);
        assert!(!peer.is_active());

        peer.set_connecting();
        assert_eq!(peer.state(), PeerState::Connecting);

        peer.set_authenticating();
        assert_eq!(peer.state(), PeerState::Authenticating);

        peer.set_active(1000);
        assert_eq!(peer.state(), PeerState::Active);
        assert!(peer.is_active());
        assert_eq!(peer.connected_at(), Some(1000));

        peer.set_disconnected();
        assert_eq!(peer.state(), PeerState::Disconnected);
        assert!(peer.state().is_terminal());
    }

    #[test]
    fn test_peer_filter_stale() {
        let mut peer = make_peer();

        // No filter received yet
        assert!(peer.filter_is_stale(1000, 500));

        // Update filter
        peer.update_filter(BloomFilter::new(), 1, 2, 1000);

        // Not stale yet
        assert!(!peer.filter_is_stale(1200, 500));

        // Stale after threshold
        assert!(peer.filter_is_stale(1600, 500));
    }

    #[test]
    fn test_peer_may_reach() {
        let mut peer = make_peer();
        let target = make_node_id(42);

        // No filter yet
        assert!(!peer.may_reach(&target));

        // Add filter with target
        let mut filter = BloomFilter::new();
        filter.insert(&target);
        peer.update_filter(filter, 1, 2, 0);

        assert!(peer.may_reach(&target));
    }

    #[test]
    fn test_peer_tree_position() {
        let mut peer = make_peer();

        assert!(!peer.has_tree_position());
        assert!(peer.coords().is_none());
        assert!(peer.declaration().is_none());

        let node = make_node_id(1);
        let parent = make_node_id(2);
        let decl = ParentDeclaration::new(node, parent, 1, 1000);
        let coords = make_coords(&[1, 2, 0]);

        peer.update_tree_position(decl, coords, 2000);

        assert!(peer.has_tree_position());
        assert!(peer.coords().is_some());
        assert!(peer.declaration().is_some());
        assert_eq!(peer.last_seen(), 2000);
    }

    #[test]
    fn test_peer_filter_update_flag() {
        let mut peer = make_peer();

        assert!(!peer.needs_filter_update());

        peer.mark_filter_update_needed();
        assert!(peer.needs_filter_update());

        peer.clear_filter_update_needed();
        assert!(!peer.needs_filter_update());
    }

    #[test]
    fn test_peer_idle_time() {
        let mut peer = make_peer();

        // No activity yet
        assert_eq!(peer.idle_time(1000), u64::MAX);

        peer.touch(500);
        assert_eq!(peer.idle_time(1000), 500);
        assert_eq!(peer.idle_time(500), 0);
    }

    #[test]
    fn test_peer_connection_duration() {
        let mut peer = make_peer();

        // Not connected
        assert!(peer.connection_duration(1000).is_none());

        peer.set_active(500);
        assert_eq!(peer.connection_duration(1000), Some(500));
    }

    // ===== UpstreamPeer Tests =====

    #[test]
    fn test_upstream_peer_state_transitions() {
        let identity = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey(identity.pubkey());
        let mut upstream = UpstreamPeer::new(peer_identity, LinkId::new(1));

        assert!(!upstream.is_active());
        assert_eq!(upstream.state(), PeerState::Discovered);

        upstream.set_connecting();
        assert_eq!(upstream.state(), PeerState::Connecting);

        upstream.set_authenticating();
        assert_eq!(upstream.state(), PeerState::Authenticating);

        upstream.set_active(1000);
        assert!(upstream.is_active());
        assert_eq!(upstream.connected_at(), Some(1000));

        upstream.set_disconnected();
        assert!(!upstream.is_active());
    }

    #[test]
    fn test_upstream_peer_touch() {
        let identity = Identity::generate();
        let peer_identity = PeerIdentity::from_pubkey(identity.pubkey());
        let mut upstream = UpstreamPeer::new(peer_identity, LinkId::new(1));

        assert_eq!(upstream.last_seen(), 0);

        upstream.touch(1000);
        assert_eq!(upstream.last_seen(), 1000);
    }
}
