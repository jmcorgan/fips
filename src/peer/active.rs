//! Active Peer (Authenticated Phase)
//!
//! Represents a fully authenticated peer after successful Noise handshake.
//! ActivePeer holds tree state, Bloom filter, and routing information.

use crate::bloom::BloomFilter;
use crate::mmp::{MmpConfig, MmpPeerState};
use crate::noise::{HandshakeState as NoiseHandshakeState, NoiseError, NoiseSession};
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::tree::{ParentDeclaration, TreeCoordinate};
use crate::utils::index::SessionIndex;
use crate::{FipsAddress, NodeAddr, PeerIdentity};
use secp256k1::XOnlyPublicKey;
use std::fmt;
use std::time::Instant;

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
        matches!(
            self,
            ConnectivityState::Connected | ConnectivityState::Stale
        )
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

    // === Tree Announce Rate Limiting ===
    /// Minimum interval between TreeAnnounce messages (milliseconds).
    tree_announce_min_interval_ms: u64,
    /// Last time we sent a TreeAnnounce to this peer (Unix milliseconds).
    last_tree_announce_sent_ms: u64,
    /// Whether a tree announce is pending (deferred due to rate limit).
    pending_tree_announce: bool,

    // === Bloom Filter ===
    /// What's reachable through them (inbound filter).
    inbound_filter: Option<BloomFilter>,
    /// Their filter's sequence number.
    filter_sequence: u64,
    /// When we received their last filter (Unix milliseconds).
    filter_received_at: u64,
    /// Whether we owe them a filter update.
    pending_filter_update: bool,

    // === Timing ===
    /// Session start time for computing session-relative timestamps.
    /// Used as the epoch for the 4-byte inner header timestamp field.
    session_start: Instant,

    // === Statistics ===
    /// Link statistics.
    link_stats: LinkStats,
    /// When this peer was authenticated (Unix milliseconds).
    authenticated_at: u64,
    /// When this peer was last seen (any activity, Unix milliseconds).
    last_seen: u64,

    // === Epoch (Restart Detection) ===
    /// Remote peer's startup epoch (from handshake). Used to detect restarts.
    remote_epoch: Option<[u8; 8]>,

    // === MMP ===
    /// Per-peer MMP state (None for legacy peers without Noise sessions).
    mmp: Option<MmpPeerState>,

    // === Heartbeat ===
    /// When we last sent a heartbeat to this peer.
    last_heartbeat_sent: Option<Instant>,

    // === Handshake Resend ===
    /// Wire-format msg2 for resend on duplicate msg1 (responder only).
    /// Cleared after the handshake timeout window.
    handshake_msg2: Option<Vec<u8>>,

    // === Replay Detection Suppression ===
    /// Number of replay detections suppressed since last session reset.
    replay_suppressed_count: u32,
    /// Consecutive decryption failures (reset on any successful decrypt).
    consecutive_decrypt_failures: u32,

    // === Rekey (Key Rotation) ===
    /// When the current Noise session was established (for rekey timer).
    session_established_at: Instant,
    /// Current K-bit epoch value (alternates each rekey).
    current_k_bit: bool,
    /// Previous session kept alive during drain window after cutover.
    previous_session: Option<NoiseSession>,
    /// Previous session's our_index (for peers_by_index cleanup on drain expiry).
    previous_our_index: Option<SessionIndex>,
    /// When the drain window started (None = no drain in progress).
    drain_started: Option<Instant>,
    /// Pending new session from completed rekey (before K-bit cutover).
    pending_new_session: Option<NoiseSession>,
    /// Pending new session's our_index.
    pending_our_index: Option<SessionIndex>,
    /// Pending new session's their_index.
    pending_their_index: Option<SessionIndex>,
    /// Whether a rekey is currently in progress (handshake sent, not yet complete).
    rekey_in_progress: bool,
    /// When we last received a rekey msg1 from this peer (dampening).
    last_peer_rekey: Option<Instant>,
    /// In-progress rekey: Noise handshake state (initiator only).
    rekey_handshake: Option<NoiseHandshakeState>,
    /// In-progress rekey: our new session index.
    rekey_our_index: Option<SessionIndex>,
    /// In-progress rekey: wire-format msg1 for resend.
    rekey_msg1: Option<Vec<u8>>,
    /// In-progress rekey: next resend timestamp (Unix ms).
    rekey_msg1_next_resend: u64,
}

impl ActivePeer {
    /// Create a new active peer from verified identity.
    ///
    /// Called after successful authentication handshake.
    /// For peers with Noise sessions, use `with_session` instead.
    pub fn new(identity: PeerIdentity, link_id: LinkId, authenticated_at: u64) -> Self {
        let now = Instant::now();
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
            tree_announce_min_interval_ms: 500,
            last_tree_announce_sent_ms: 0,
            pending_tree_announce: false,
            inbound_filter: None,
            filter_sequence: 0,
            filter_received_at: 0,
            pending_filter_update: true, // Send filter on new connection
            session_start: now,
            link_stats: LinkStats::new(),
            authenticated_at,
            last_seen: authenticated_at,
            remote_epoch: None,
            mmp: None,
            last_heartbeat_sent: None,
            handshake_msg2: None,
            replay_suppressed_count: 0,
            consecutive_decrypt_failures: 0,
            session_established_at: now,
            current_k_bit: false,
            previous_session: None,
            previous_our_index: None,
            drain_started: None,
            pending_new_session: None,
            pending_our_index: None,
            pending_their_index: None,
            rekey_in_progress: false,
            last_peer_rekey: None,
            rekey_handshake: None,
            rekey_our_index: None,
            rekey_msg1: None,
            rekey_msg1_next_resend: 0,
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
        is_initiator: bool,
        mmp_config: &MmpConfig,
        remote_epoch: Option<[u8; 8]>,
    ) -> Self {
        let now = Instant::now();
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
            tree_announce_min_interval_ms: 500,
            last_tree_announce_sent_ms: 0,
            pending_tree_announce: false,
            inbound_filter: None,
            filter_sequence: 0,
            filter_received_at: 0,
            pending_filter_update: true,
            session_start: now,
            link_stats,
            authenticated_at,
            last_seen: authenticated_at,
            remote_epoch,
            mmp: Some(MmpPeerState::new(mmp_config, is_initiator)),
            last_heartbeat_sent: None,
            handshake_msg2: None,
            replay_suppressed_count: 0,
            consecutive_decrypt_failures: 0,
            session_established_at: now,
            current_k_bit: false,
            previous_session: None,
            previous_our_index: None,
            drain_started: None,
            pending_new_session: None,
            pending_our_index: None,
            pending_their_index: None,
            rekey_in_progress: false,
            last_peer_rekey: None,
            rekey_handshake: None,
            rekey_our_index: None,
            rekey_msg1: None,
            rekey_msg1_next_resend: 0,
        }
    }

    // === Identity Accessors ===

    /// Get the peer's verified identity.
    pub fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Get the peer's NodeAddr.
    pub fn node_addr(&self) -> &NodeAddr {
        self.identity.node_addr()
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

    /// Update their session index (used during cross-connection resolution
    /// when the losing node keeps its inbound session but needs the peer's
    /// outbound index).
    pub fn set_their_index(&mut self, index: SessionIndex) {
        self.their_index = Some(index);
    }

    /// Replace the Noise session and indices during cross-connection resolution.
    ///
    /// When both nodes simultaneously initiate, each promotes its inbound
    /// handshake first. When the peer's msg2 arrives, we learn the correct
    /// session — the outbound handshake that pairs with the peer's inbound.
    /// This replaces the entire session so both nodes use matching keys.
    ///
    /// Returns the old our_index so the caller can update peers_by_index.
    /// Also resets the replay suppression counter since the session changed.
    pub fn replace_session(
        &mut self,
        new_session: NoiseSession,
        new_our_index: SessionIndex,
        new_their_index: SessionIndex,
    ) -> Option<SessionIndex> {
        self.reset_replay_suppressed();
        let old_our_index = self.our_index;
        self.noise_session = Some(new_session);
        self.our_index = Some(new_our_index);
        self.their_index = Some(new_their_index);
        old_our_index
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

    // === Handshake Resend ===

    /// Store wire-format msg2 for resend on duplicate msg1.
    pub fn set_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.handshake_msg2 = Some(msg2);
    }

    /// Get stored msg2 bytes for resend.
    pub fn handshake_msg2(&self) -> Option<&[u8]> {
        self.handshake_msg2.as_deref()
    }

    /// Clear stored msg2 (no longer needed after handshake window).
    pub fn clear_handshake_msg2(&mut self) {
        self.handshake_msg2 = None;
    }

    // === Replay Detection Suppression ===

    /// Increment replay suppression counter. Returns the new count.
    pub fn increment_replay_suppressed(&mut self) -> u32 {
        self.replay_suppressed_count += 1;
        self.replay_suppressed_count
    }

    /// Reset replay suppression counter, returning previous count.
    pub fn reset_replay_suppressed(&mut self) -> u32 {
        let count = self.replay_suppressed_count;
        self.replay_suppressed_count = 0;
        count
    }

    /// Current replay suppression count.
    pub fn replay_suppressed_count(&self) -> u32 {
        self.replay_suppressed_count
    }

    // === Decryption Failure Tracking ===

    /// Increment consecutive decryption failure counter, returning new count.
    pub fn increment_decrypt_failures(&mut self) -> u32 {
        self.consecutive_decrypt_failures += 1;
        self.consecutive_decrypt_failures
    }

    /// Reset consecutive decryption failure counter.
    pub fn reset_decrypt_failures(&mut self) {
        self.consecutive_decrypt_failures = 0;
    }

    /// Current consecutive decryption failure count.
    pub fn consecutive_decrypt_failures(&self) -> u32 {
        self.consecutive_decrypt_failures
    }

    // === Epoch Accessors ===

    /// Get the remote peer's startup epoch (from handshake).
    pub fn remote_epoch(&self) -> Option<[u8; 8]> {
        self.remote_epoch
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

    /// Check if this peer's filter is stale.
    pub fn filter_is_stale(&self, current_time_ms: u64, stale_threshold_ms: u64) -> bool {
        if self.filter_received_at == 0 {
            return true;
        }
        current_time_ms.saturating_sub(self.filter_received_at) > stale_threshold_ms
    }

    /// Check if a destination might be reachable through this peer.
    pub fn may_reach(&self, node_addr: &NodeAddr) -> bool {
        match &self.inbound_filter {
            Some(filter) => filter.contains(node_addr),
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

    // === MMP Accessors ===

    /// Get MMP state (None for legacy peers without sessions).
    pub fn mmp(&self) -> Option<&MmpPeerState> {
        self.mmp.as_ref()
    }

    /// Get mutable MMP state.
    pub fn mmp_mut(&mut self) -> Option<&mut MmpPeerState> {
        self.mmp.as_mut()
    }

    /// Link cost for routing decisions.
    ///
    /// Returns a scalar cost where lower is better (1.0 = ideal).
    /// Computed as RTT-weighted ETX: `etx * (1.0 + srtt_ms / 100.0)`.
    ///
    /// Returns 1.0 (optimistic default) when MMP metrics are not yet
    /// available, matching depth-only parent selection behavior.
    pub fn link_cost(&self) -> f64 {
        match self.mmp() {
            Some(mmp) => {
                let etx = mmp.metrics.etx;
                match mmp.metrics.srtt_ms() {
                    Some(srtt_ms) => etx * (1.0 + srtt_ms / 100.0),
                    None => 1.0,
                }
            }
            None => 1.0,
        }
    }

    /// Whether this peer has at least one MMP RTT measurement.
    pub fn has_srtt(&self) -> bool {
        self.mmp()
            .is_some_and(|mmp| mmp.metrics.srtt_ms().is_some())
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

    /// Session-relative elapsed time in milliseconds (for inner header timestamp).
    ///
    /// Returns milliseconds since session establishment, truncated to u32.
    /// Wraps at ~49.7 days which is acceptable for session-relative timing.
    pub fn session_elapsed_ms(&self) -> u32 {
        self.session_start.elapsed().as_millis() as u32
    }

    /// When this peer's session started (for link-dead fallback timing).
    pub fn session_start(&self) -> Instant {
        self.session_start
    }

    // === Heartbeat ===

    /// When we last sent a heartbeat to this peer.
    pub fn last_heartbeat_sent(&self) -> Option<Instant> {
        self.last_heartbeat_sent
    }

    /// Record that we sent a heartbeat.
    pub fn mark_heartbeat_sent(&mut self, now: Instant) {
        self.last_heartbeat_sent = Some(now);
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

    // === Tree Announce Rate Limiting ===

    /// Set the minimum interval between TreeAnnounce messages (milliseconds).
    pub fn set_tree_announce_min_interval_ms(&mut self, ms: u64) {
        self.tree_announce_min_interval_ms = ms;
    }

    /// Get the last tree announce send timestamp (for carrying across reconnection).
    pub fn last_tree_announce_sent_ms(&self) -> u64 {
        self.last_tree_announce_sent_ms
    }

    /// Set the last tree announce send timestamp (to preserve rate limit across reconnection).
    pub fn set_last_tree_announce_sent_ms(&mut self, ms: u64) {
        self.last_tree_announce_sent_ms = ms;
    }

    /// Check if we can send a TreeAnnounce now (rate limiting).
    pub fn can_send_tree_announce(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_tree_announce_sent_ms) >= self.tree_announce_min_interval_ms
    }

    /// Record that we sent a TreeAnnounce to this peer.
    pub fn record_tree_announce_sent(&mut self, now_ms: u64) {
        self.last_tree_announce_sent_ms = now_ms;
        self.pending_tree_announce = false;
    }

    /// Mark that a tree announce is pending (deferred due to rate limit).
    pub fn mark_tree_announce_pending(&mut self) {
        self.pending_tree_announce = true;
    }

    /// Check if a deferred tree announce is waiting to be sent.
    pub fn has_pending_tree_announce(&self) -> bool {
        self.pending_tree_announce
    }

    // === Filter Updates ===

    /// Update peer's inbound filter.
    pub fn update_filter(&mut self, filter: BloomFilter, sequence: u64, current_time_ms: u64) {
        self.inbound_filter = Some(filter);
        self.filter_sequence = sequence;
        self.filter_received_at = current_time_ms;
        self.last_seen = current_time_ms;
    }

    /// Clear peer's inbound filter.
    pub fn clear_filter(&mut self) {
        self.inbound_filter = None;
        self.filter_sequence = 0;
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

    // === Rekey (Key Rotation) ===

    /// When the current Noise session was established.
    pub fn session_established_at(&self) -> Instant {
        self.session_established_at
    }

    /// Current K-bit epoch value.
    pub fn current_k_bit(&self) -> bool {
        self.current_k_bit
    }

    /// Whether a rekey is currently in progress.
    pub fn rekey_in_progress(&self) -> bool {
        self.rekey_in_progress
    }

    /// Mark that a rekey has been initiated.
    pub fn set_rekey_in_progress(&mut self) {
        self.rekey_in_progress = true;
    }

    /// Check if rekey initiation is dampened (peer recently sent us msg1).
    pub fn is_rekey_dampened(&self, dampening_secs: u64) -> bool {
        match self.last_peer_rekey {
            Some(t) => t.elapsed().as_secs() < dampening_secs,
            None => false,
        }
    }

    /// Record that the peer initiated a rekey (for dampening).
    pub fn record_peer_rekey(&mut self) {
        self.last_peer_rekey = Some(Instant::now());
    }

    /// Get the pending new session's our_index.
    pub fn pending_our_index(&self) -> Option<SessionIndex> {
        self.pending_our_index
    }

    /// Get the pending new session's their_index.
    pub fn pending_their_index(&self) -> Option<SessionIndex> {
        self.pending_their_index
    }

    /// Get the previous session's our_index (during drain).
    pub fn previous_our_index(&self) -> Option<SessionIndex> {
        self.previous_our_index
    }

    /// Get the previous session for decryption fallback.
    pub fn previous_session(&self) -> Option<&NoiseSession> {
        self.previous_session.as_ref()
    }

    /// Get mutable access to the previous session for decryption.
    pub fn previous_session_mut(&mut self) -> Option<&mut NoiseSession> {
        self.previous_session.as_mut()
    }

    /// Get the pending new session (completed rekey, not yet cut over).
    pub fn pending_new_session(&self) -> Option<&NoiseSession> {
        self.pending_new_session.as_ref()
    }

    /// Store a completed rekey session and its indices.
    ///
    /// Called when the rekey handshake completes. The session is held
    /// as pending until the initiator flips the K-bit on the next outbound packet.
    pub fn set_pending_session(
        &mut self,
        session: NoiseSession,
        our_index: SessionIndex,
        their_index: SessionIndex,
    ) {
        self.pending_new_session = Some(session);
        self.pending_our_index = Some(our_index);
        self.pending_their_index = Some(their_index);
        self.rekey_in_progress = false;
        // Clear initiator handshake state (index now lives in pending_our_index)
        self.rekey_our_index = None;
        self.rekey_handshake = None;
        self.rekey_msg1 = None;
        self.rekey_msg1_next_resend = 0;
    }

    /// Cut over to the pending new session (initiator side).
    ///
    /// Moves current session to previous (for drain), promotes pending to current,
    /// flips the K-bit. Returns the old our_index that should remain in peers_by_index
    /// during the drain window.
    pub fn cutover_to_new_session(&mut self) -> Option<SessionIndex> {
        let new_session = self.pending_new_session.take()?;
        let new_our_index = self.pending_our_index.take();
        let new_their_index = self.pending_their_index.take();

        // Demote current to previous
        self.previous_session = self.noise_session.take();
        self.previous_our_index = self.our_index;
        self.drain_started = Some(Instant::now());

        // Promote pending to current
        self.noise_session = Some(new_session);
        self.our_index = new_our_index;
        self.their_index = new_their_index;

        // Flip K-bit and reset timing
        self.current_k_bit = !self.current_k_bit;
        self.session_established_at = Instant::now();
        self.session_start = Instant::now();
        self.rekey_in_progress = false;
        self.reset_replay_suppressed();

        // Reset MMP counters to avoid metric discontinuity
        let now = Instant::now();
        if let Some(mmp) = &mut self.mmp {
            mmp.reset_for_rekey(now);
        }

        self.previous_our_index
    }

    /// Handle receiving a K-bit flip from the peer (responder side).
    ///
    /// Promotes pending_new_session to current, demotes current to previous.
    /// Returns the old our_index for drain tracking.
    pub fn handle_peer_kbit_flip(&mut self) -> Option<SessionIndex> {
        let new_session = self.pending_new_session.take()?;
        let new_our_index = self.pending_our_index.take();
        let new_their_index = self.pending_their_index.take();

        // Demote current to previous
        self.previous_session = self.noise_session.take();
        self.previous_our_index = self.our_index;
        self.drain_started = Some(Instant::now());

        // Promote pending to current
        self.noise_session = Some(new_session);
        self.our_index = new_our_index;
        self.their_index = new_their_index;

        // Match peer's K-bit
        self.current_k_bit = !self.current_k_bit;
        self.session_established_at = Instant::now();
        self.session_start = Instant::now();
        self.rekey_in_progress = false;
        self.reset_replay_suppressed();

        // Reset MMP counters to avoid metric discontinuity
        let now = Instant::now();
        if let Some(mmp) = &mut self.mmp {
            mmp.reset_for_rekey(now);
        }

        self.previous_our_index
    }

    /// Check if the drain window has expired.
    pub fn drain_expired(&self, drain_secs: u64) -> bool {
        match self.drain_started {
            Some(t) => t.elapsed().as_secs() >= drain_secs,
            None => false,
        }
    }

    /// Whether a drain is in progress.
    pub fn is_draining(&self) -> bool {
        self.drain_started.is_some()
    }

    /// Complete the drain: drop previous session and free its index.
    ///
    /// Returns the previous our_index so the caller can remove it from
    /// peers_by_index and free it from the IndexAllocator.
    pub fn complete_drain(&mut self) -> Option<SessionIndex> {
        self.previous_session = None;
        self.drain_started = None;
        self.previous_our_index.take()
    }

    /// Abandon an in-progress rekey.
    ///
    /// Returns the rekey our_index so the caller can free it.
    /// Also clears any pending session state if the handshake was completed
    /// but not yet cut over.
    pub fn abandon_rekey(&mut self) -> Option<SessionIndex> {
        self.rekey_handshake = None;
        self.rekey_msg1 = None;
        self.rekey_msg1_next_resend = 0;
        self.rekey_in_progress = false;
        // Return whichever index needs freeing
        self.rekey_our_index.take().or_else(|| {
            self.pending_new_session = None;
            self.pending_their_index = None;
            self.pending_our_index.take()
        })
    }

    // === Rekey Handshake State (Initiator) ===

    /// Store rekey handshake state after sending msg1.
    pub fn set_rekey_state(
        &mut self,
        handshake: NoiseHandshakeState,
        our_index: SessionIndex,
        wire_msg1: Vec<u8>,
        next_resend_ms: u64,
    ) {
        self.rekey_handshake = Some(handshake);
        self.rekey_our_index = Some(our_index);
        self.rekey_msg1 = Some(wire_msg1);
        self.rekey_msg1_next_resend = next_resend_ms;
        self.rekey_in_progress = true;
    }

    /// Get the rekey our_index (for msg2 dispatch lookup).
    pub fn rekey_our_index(&self) -> Option<SessionIndex> {
        self.rekey_our_index
    }

    /// Complete the rekey by processing msg2 (initiator side).
    ///
    /// Takes the stored handshake state, reads msg2, and returns the
    /// completed NoiseSession. Clears the handshake-related fields but
    /// leaves rekey_our_index for set_pending_session to use.
    pub fn complete_rekey_msg2(&mut self, msg2_bytes: &[u8]) -> Result<NoiseSession, NoiseError> {
        let mut hs = self
            .rekey_handshake
            .take()
            .ok_or_else(|| NoiseError::WrongState {
                expected: "rekey handshake in progress".to_string(),
                got: "no handshake state".to_string(),
            })?;

        hs.read_message_2(msg2_bytes)?;
        let session = hs.into_session()?;

        // Clear msg1 resend state
        self.rekey_msg1 = None;
        self.rekey_msg1_next_resend = 0;

        Ok(session)
    }

    /// Check if msg1 needs resending.
    pub fn needs_msg1_resend(&self, now_ms: u64) -> bool {
        self.rekey_in_progress && self.rekey_msg1.is_some() && now_ms >= self.rekey_msg1_next_resend
    }

    /// Get msg1 bytes for resend (without consuming).
    pub fn rekey_msg1(&self) -> Option<&[u8]> {
        self.rekey_msg1.as_deref()
    }

    /// Update next resend timestamp.
    pub fn set_msg1_next_resend(&mut self, next_ms: u64) {
        self.rekey_msg1_next_resend = next_ms;
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

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
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
        let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        assert_eq!(peer.identity().node_addr(), identity.node_addr());
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

        let node = make_node_addr(1);
        let parent = make_node_addr(2);
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
        let target = make_node_addr(42);

        assert!(!peer.may_reach(&target));
        assert!(peer.filter_is_stale(2000, 500));

        let mut filter = BloomFilter::new();
        filter.insert(&target);
        peer.update_filter(filter, 1, 1500);

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

    #[test]
    fn test_replay_suppression_counter() {
        let identity = make_peer_identity();
        let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        // Initial count is zero
        assert_eq!(peer.replay_suppressed_count(), 0);

        // Increment returns new count
        assert_eq!(peer.increment_replay_suppressed(), 1);
        assert_eq!(peer.increment_replay_suppressed(), 2);
        assert_eq!(peer.increment_replay_suppressed(), 3);
        assert_eq!(peer.replay_suppressed_count(), 3);

        // Reset returns previous count and zeroes it
        assert_eq!(peer.reset_replay_suppressed(), 3);
        assert_eq!(peer.replay_suppressed_count(), 0);

        // Can increment again after reset
        assert_eq!(peer.increment_replay_suppressed(), 1);
        assert_eq!(peer.replay_suppressed_count(), 1);

        // Reset when zero returns zero
        peer.reset_replay_suppressed();
        assert_eq!(peer.reset_replay_suppressed(), 0);
    }
}
