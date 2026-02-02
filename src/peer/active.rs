//! Active Peer (Authenticated Phase)
//!
//! Represents a fully authenticated peer after successful Noise handshake.
//! ActivePeer holds tree state, Bloom filter, and routing information.

use crate::bloom::BloomFilter;
use crate::index::SessionIndex;
use crate::noise::NoiseSession;
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::tree::{ParentDeclaration, TreeCoordinate};
use crate::{FipsAddress, NodeId, PeerIdentity};
use secp256k1::XOnlyPublicKey;
use std::fmt;

/// Connectivity state for an active peer.
///
/// This is simpler than the full PeerState since authentication is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectivityState {
    /// Peer is fully connected and responsive.
    Connected,
    /// Peer hasn't been heard from recently (potential timeout).
    Stale,
    /// Connection lost, attempting to reconnect.
    Reconnecting,
    /// Peer has been explicitly disconnected.
    Disconnected,
}

impl ConnectivityState {
    /// Check if the peer is usable for sending traffic.
    pub fn can_send(&self) -> bool {
        matches!(self, ConnectivityState::Connected | ConnectivityState::Stale)
    }

    /// Check if this is a terminal state requiring cleanup.
    pub fn is_terminal(&self) -> bool {
        matches!(self, ConnectivityState::Disconnected)
    }

    /// Check if peer is fully healthy.
    pub fn is_healthy(&self) -> bool {
        matches!(self, ConnectivityState::Connected)
    }
}

impl fmt::Display for ConnectivityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ConnectivityState::Connected => "connected",
            ConnectivityState::Stale => "stale",
            ConnectivityState::Reconnecting => "reconnecting",
            ConnectivityState::Disconnected => "disconnected",
        };
        write!(f, "{}", s)
    }
}

/// A fully authenticated remote FIPS node.
///
/// Created only after successful Noise KK handshake. The identity is
/// cryptographically verified at this point.
///
/// Note: ActivePeer intentionally does not implement Clone because it
/// contains NoiseSession, which cannot be safely cloned (cloning would
/// risk nonce reuse, a catastrophic security failure).
#[derive(Debug)]
pub struct ActivePeer {
    // === Identity (Verified) ===
    /// Cryptographic identity (verified via handshake).
    identity: PeerIdentity,

    // === Connection ===
    /// Link used to reach this peer.
    link_id: LinkId,
    /// Current connectivity state.
    connectivity: ConnectivityState,

    // === Session (Wire Protocol) ===
    /// Noise session for encryption/decryption (None if legacy peer).
    noise_session: Option<NoiseSession>,
    /// Our session index (they include this when sending TO us).
    our_index: Option<SessionIndex>,
    /// Their session index (we include this when sending TO them).
    their_index: Option<SessionIndex>,
    /// Transport ID for this peer's link.
    transport_id: Option<TransportId>,
    /// Current transport address (for roaming support).
    current_addr: Option<TransportAddr>,

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
    /// When this peer was authenticated (Unix milliseconds).
    authenticated_at: u64,
    /// When this peer was last seen (any activity, Unix milliseconds).
    last_seen: u64,
}

impl ActivePeer {
    /// Create a new active peer from verified identity.
    ///
    /// Called after successful authentication handshake.
    /// For peers with Noise sessions, use `with_session` instead.
    pub fn new(identity: PeerIdentity, link_id: LinkId, authenticated_at: u64) -> Self {
        Self {
            identity,
            link_id,
            connectivity: ConnectivityState::Connected,
            noise_session: None,
            our_index: None,
            their_index: None,
            transport_id: None,
            current_addr: None,
            declaration: None,
            ancestry: None,
            inbound_filter: None,
            filter_sequence: 0,
            filter_ttl: 0,
            filter_received_at: 0,
            pending_filter_update: true, // Send filter on new connection
            link_stats: LinkStats::new(),
            authenticated_at,
            last_seen: authenticated_at,
        }
    }

    /// Create from verified identity with existing link stats.
    ///
    /// Used when promoting from PeerConnection, preserving handshake stats.
    /// For peers with Noise sessions, use `with_session` instead.
    pub fn with_stats(
        identity: PeerIdentity,
        link_id: LinkId,
        authenticated_at: u64,
        link_stats: LinkStats,
    ) -> Self {
        let mut peer = Self::new(identity, link_id, authenticated_at);
        peer.link_stats = link_stats;
        peer
    }

    /// Create from verified identity with Noise session and index tracking.
    ///
    /// This is the primary constructor for the wire protocol path.
    /// The NoiseSession provides encryption/decryption and replay protection.
    #[allow(clippy::too_many_arguments)]
    pub fn with_session(
        identity: PeerIdentity,
        link_id: LinkId,
        authenticated_at: u64,
        noise_session: NoiseSession,
        our_index: SessionIndex,
        their_index: SessionIndex,
        transport_id: TransportId,
        current_addr: TransportAddr,
        link_stats: LinkStats,
    ) -> Self {
        Self {
            identity,
            link_id,
            connectivity: ConnectivityState::Connected,
            noise_session: Some(noise_session),
            our_index: Some(our_index),
            their_index: Some(their_index),
            transport_id: Some(transport_id),
            current_addr: Some(current_addr),
            declaration: None,
            ancestry: None,
            inbound_filter: None,
            filter_sequence: 0,
            filter_ttl: 0,
            filter_received_at: 0,
            pending_filter_update: true,
            link_stats,
            authenticated_at,
            last_seen: authenticated_at,
        }
    }

    // === Identity Accessors ===

    /// Get the peer's verified identity.
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

    /// Get the connectivity state.
    pub fn connectivity(&self) -> ConnectivityState {
        self.connectivity
    }

    /// Check if peer can receive traffic.
    pub fn can_send(&self) -> bool {
        self.connectivity.can_send()
    }

    /// Check if peer is fully healthy.
    pub fn is_healthy(&self) -> bool {
        self.connectivity.is_healthy()
    }

    /// Check if peer is disconnected.
    pub fn is_disconnected(&self) -> bool {
        self.connectivity.is_terminal()
    }

    // === Session Accessors ===

    /// Check if this peer has a Noise session.
    pub fn has_session(&self) -> bool {
        self.noise_session.is_some()
    }

    /// Get the Noise session, if present.
    pub fn noise_session(&self) -> Option<&NoiseSession> {
        self.noise_session.as_ref()
    }

    /// Get mutable access to the Noise session.
    pub fn noise_session_mut(&mut self) -> Option<&mut NoiseSession> {
        self.noise_session.as_mut()
    }

    /// Get our session index (they use this to send TO us).
    pub fn our_index(&self) -> Option<SessionIndex> {
        self.our_index
    }

    /// Get their session index (we use this to send TO them).
    pub fn their_index(&self) -> Option<SessionIndex> {
        self.their_index
    }

    /// Get the transport ID for this peer.
    pub fn transport_id(&self) -> Option<TransportId> {
        self.transport_id
    }

    /// Get the current transport address.
    pub fn current_addr(&self) -> Option<&TransportAddr> {
        self.current_addr.as_ref()
    }

    /// Update the current address (for roaming support).
    ///
    /// Called when we receive a valid authenticated packet from a new address.
    pub fn set_current_addr(&mut self, transport_id: TransportId, addr: TransportAddr) {
        self.transport_id = Some(transport_id);
        self.current_addr = Some(addr);
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

    /// When this peer was authenticated.
    pub fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }

    /// When this peer was last seen.
    pub fn last_seen(&self) -> u64 {
        self.last_seen
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.last_seen)
    }

    /// Connection duration since authentication.
    pub fn connection_duration(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.authenticated_at)
    }

    // === State Updates ===

    /// Update last seen timestamp.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.last_seen = current_time_ms;
        // If we were stale, receiving traffic makes us connected again
        if self.connectivity == ConnectivityState::Stale {
            self.connectivity = ConnectivityState::Connected;
        }
    }

    /// Mark peer as stale (no recent traffic).
    pub fn mark_stale(&mut self) {
        if self.connectivity == ConnectivityState::Connected {
            self.connectivity = ConnectivityState::Stale;
        }
    }

    /// Mark peer as reconnecting.
    pub fn mark_reconnecting(&mut self) {
        self.connectivity = ConnectivityState::Reconnecting;
    }

    /// Mark peer as disconnected.
    pub fn mark_disconnected(&mut self) {
        self.connectivity = ConnectivityState::Disconnected;
    }

    /// Mark peer as connected (e.g., after successful reconnect).
    pub fn mark_connected(&mut self, current_time_ms: u64) {
        self.connectivity = ConnectivityState::Connected;
        self.last_seen = current_time_ms;
    }

    /// Update the link ID (e.g., on reconnect).
    pub fn set_link_id(&mut self, link_id: LinkId) {
        self.link_id = link_id;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn make_peer_identity() -> PeerIdentity {
        let identity = Identity::generate();
        PeerIdentity::from_pubkey(identity.pubkey())
    }

    fn make_node_id(val: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        NodeId::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::new(ids.iter().map(|&v| make_node_id(v)).collect()).unwrap()
    }

    #[test]
    fn test_connectivity_state_properties() {
        assert!(ConnectivityState::Connected.can_send());
        assert!(ConnectivityState::Stale.can_send());
        assert!(!ConnectivityState::Reconnecting.can_send());
        assert!(!ConnectivityState::Disconnected.can_send());

        assert!(ConnectivityState::Connected.is_healthy());
        assert!(!ConnectivityState::Stale.is_healthy());

        assert!(ConnectivityState::Disconnected.is_terminal());
        assert!(!ConnectivityState::Connected.is_terminal());
    }

    #[test]
    fn test_active_peer_creation() {
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity.clone(), LinkId::new(1), 1000);

        assert_eq!(peer.identity().node_id(), identity.node_id());
        assert_eq!(peer.link_id(), LinkId::new(1));
        assert!(peer.is_healthy());
        assert!(peer.can_send());
        assert_eq!(peer.authenticated_at(), 1000);
        assert!(peer.needs_filter_update()); // New peers need filter
    }

    #[test]
    fn test_connectivity_transitions() {
        let identity = make_peer_identity();
        let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        assert!(peer.is_healthy());

        peer.mark_stale();
        assert_eq!(peer.connectivity(), ConnectivityState::Stale);
        assert!(peer.can_send()); // Stale can still send

        // Traffic received brings back to connected
        peer.touch(2000);
        assert!(peer.is_healthy());

        peer.mark_reconnecting();
        assert!(!peer.can_send());

        peer.mark_connected(3000);
        assert!(peer.is_healthy());

        peer.mark_disconnected();
        assert!(peer.is_disconnected());
        assert!(!peer.can_send());
    }

    #[test]
    fn test_tree_position() {
        let identity = make_peer_identity();
        let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        assert!(!peer.has_tree_position());
        assert!(peer.coords().is_none());

        let node = make_node_id(1);
        let parent = make_node_id(2);
        let decl = ParentDeclaration::new(node, parent, 1, 1000);
        let coords = make_coords(&[1, 2, 0]);

        peer.update_tree_position(decl, coords, 2000);

        assert!(peer.has_tree_position());
        assert!(peer.coords().is_some());
        assert_eq!(peer.last_seen(), 2000);
    }

    #[test]
    fn test_bloom_filter() {
        let identity = make_peer_identity();
        let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);
        let target = make_node_id(42);

        assert!(!peer.may_reach(&target));
        assert!(peer.filter_is_stale(2000, 500));

        let mut filter = BloomFilter::new();
        filter.insert(&target);
        peer.update_filter(filter, 1, 2, 1500);

        assert!(peer.may_reach(&target));
        assert!(!peer.filter_is_stale(1800, 500));
        assert!(peer.filter_is_stale(2500, 500));
    }

    #[test]
    fn test_timing() {
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        assert_eq!(peer.connection_duration(2000), 1000);
        assert_eq!(peer.idle_time(2000), 1000);
    }

    #[test]
    fn test_filter_update_flag() {
        let identity = make_peer_identity();
        let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        assert!(peer.needs_filter_update()); // New peer

        peer.clear_filter_update_needed();
        assert!(!peer.needs_filter_update());

        peer.mark_filter_update_needed();
        assert!(peer.needs_filter_update());
    }

    #[test]
    fn test_with_stats() {
        let identity = make_peer_identity();
        let mut stats = LinkStats::new();
        stats.record_sent(100);
        stats.record_recv(200, 500);

        let peer = ActivePeer::with_stats(identity, LinkId::new(1), 1000, stats);

        assert_eq!(peer.link_stats().packets_sent, 1);
        assert_eq!(peer.link_stats().packets_recv, 1);
    }
}
