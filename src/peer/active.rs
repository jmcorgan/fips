//! Active Peer (Authenticated Phase)
//!
//! Represents a fully authenticated peer after successful Noise handshake.
//! ActivePeer holds tree state, Bloom filter, and routing information.

use crate::config::MmpConfig;
use crate::node::REKEY_JITTER_SECS;
use crate::node::diag::HsLineCounts;
use crate::noise::{HandshakeState as NoiseHandshakeState, NoiseError, NoiseSession};
use crate::proto::bloom::BloomFilter;
use crate::proto::fmp::{AnsweredMsg1s, EphemeralDigest, Msg1Digest, RekeyAnswer, RekeyRole};
use crate::proto::mmp::MmpPeerState;
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{Ipv6Address, NodeAddr, PeerIdentity};
use rand::RngExt;
use secp256k1::XOnlyPublicKey;
use std::fmt;
use std::time::{Duration, Instant};

/// Draw a fresh per-session rekey jitter from `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]`.
fn draw_rekey_jitter() -> i64 {
    rand::rng().random_range(-REKEY_JITTER_SECS..=REKEY_JITTER_SECS)
}

/// Connectivity of an active peer, as the control socket reports it.
///
/// Not stored on the peer: the node derives it from how long the peer has
/// been silent, compared with the configured heartbeat interval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectivityState {
    /// Heard from within the heartbeat interval.
    Connected,
    /// Silent for longer than the heartbeat interval.
    Stale,
}

impl ConnectivityState {
    /// Check if this is a terminal state requiring cleanup.
    ///
    /// Always false: neither derived state is terminal.
    pub fn is_terminal(&self) -> bool {
        false
    }
}

impl fmt::Display for ConnectivityState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ConnectivityState::Connected => "connected",
            ConnectivityState::Stale => "stale",
        };
        write!(f, "{}", s)
    }
}

/// Published active-send-state for a peer (the two-tier boundary).
///
/// This is the send-critical subset of an `ActivePeer` that the data plane
/// reads (and, on roam/responder-cutover, writes) directly by plain borrow
/// with no FSM dispatch: the three epoch slots (current / previous-draining /
/// pending), the K-bit + session-relative time base, the transport target,
/// the connected-UDP handles, and the hot per-packet counters. Grouping these
/// draws the control/published-send-state boundary inside the peer entry.
///
/// Co-located, not behind `Arc`/`ArcSwap` — the data plane is not sharded, so
/// the hot path reads this by plain borrow. Publishing behind `Arc`/`ArcSwap`
/// is later-increment plumbing for a sharded data plane.
///
/// Like `ActivePeer`, this does not implement `Clone` because it contains
/// `NoiseSession`, which cannot be safely cloned (cloning would risk nonce
/// reuse, a catastrophic security failure).
#[derive(Debug)]
struct PeerSendState {
    // === Current epoch slot ===
    /// Noise session for encryption/decryption (None if legacy peer).
    noise_session: Option<NoiseSession>,
    /// Our session index (they include this when sending TO us).
    our_index: Option<SessionIndex>,
    /// Their session index (we include this when sending TO them).
    their_index: Option<SessionIndex>,

    // === Previous / draining epoch slot ===
    /// Previous session kept alive during drain window after cutover.
    previous_session: Option<NoiseSession>,
    /// Previous session's our_index (for peers_by_index cleanup on drain expiry).
    previous_our_index: Option<SessionIndex>,
    /// When the drain window started (None = no drain in progress).
    drain_started: Option<Instant>,
    /// When the last cutover happened, in either role. Kept after the drain
    /// completes, so a later removal can say how long ago it was.
    last_cutover: Option<Instant>,

    // === Pending epoch slot ===
    /// Pending new session from completed rekey (before K-bit cutover).
    pending_new_session: Option<NoiseSession>,
    /// Pending new session's our_index.
    pending_our_index: Option<SessionIndex>,
    /// Pending new session's their_index.
    pending_their_index: Option<SessionIndex>,

    // === Epoch bit + session-relative time base ===
    /// Current K-bit epoch value (alternates each rekey).
    current_k_bit: bool,
    /// Session start time for computing session-relative timestamps.
    /// Used as the epoch for the 4-byte inner header timestamp field.
    session_start: Instant,

    // === Transport target ===
    /// Transport ID for this peer's link.
    transport_id: Option<TransportId>,
    /// Current transport address (for roaming support).
    current_addr: Option<TransportAddr>,
    /// Link used to reach this peer.
    link_id: LinkId,

    // === Connected-UDP handles ===
    /// Unix UDP fast-path: per-peer `connect()`-ed socket (paired with
    /// the listen socket via `SO_REUSEPORT`). The kernel demux prefers
    /// the connected 5-tuple, so inbound packets land here; the
    /// encrypt-worker send path sends with `msg_name = NULL`, skipping
    /// per-packet sockaddr handling + route lookup. Behind an `Arc` so
    /// in-flight worker jobs survive rekey/address-change rotations.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_udp: Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>>,

    /// Per-peer recv drain thread. Always paired with `connected_udp`:
    /// the kernel routes inbound packets from this peer to the
    /// connected socket, so it *must* be drained or the kernel recv
    /// buffer fills. Drop signals shutdown via self-pipe.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    peer_recv_drain: Option<crate::transport::udp::PeerRecvDrain>,

    // === Hot counters ===
    /// Link statistics.
    link_stats: LinkStats,
    /// When this peer was last seen (any activity, Unix milliseconds).
    last_seen: u64,
    /// Whether an authenticated frame from this peer has arrived since it was
    /// promoted. Kept beside `last_seen` because `touch` writes both.
    heard: bool,
    /// Number of replay detections suppressed since last session reset.
    replay_suppressed_count: u32,
    /// Consecutive decryption failures (reset on any successful decrypt).
    consecutive_decrypt_failures: u32,
    /// Frames authenticated on the previous session since the last cutover.
    prev_frames: u64,
    /// The receiver index of the last frame that failed to decrypt.
    failed_idx: Option<SessionIndex>,
    /// Per-peer MMP state (None for legacy peers without Noise sessions).
    mmp: Option<MmpPeerState>,
}

impl PeerSendState {
    /// Empty send-state for a peer with no Noise session yet. Mirrors the
    /// send-critical portion of `ActivePeer::new`.
    fn new(link_id: LinkId, session_start: Instant, last_seen: u64) -> Self {
        Self {
            noise_session: None,
            our_index: None,
            their_index: None,
            previous_session: None,
            previous_our_index: None,
            drain_started: None,
            last_cutover: None,
            pending_new_session: None,
            pending_our_index: None,
            pending_their_index: None,
            current_k_bit: false,
            session_start,
            transport_id: None,
            current_addr: None,
            link_id,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_udp: None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            peer_recv_drain: None,
            link_stats: LinkStats::new(),
            last_seen,
            heard: false,
            replay_suppressed_count: 0,
            consecutive_decrypt_failures: 0,
            prev_frames: 0,
            failed_idx: None,
            mmp: None,
        }
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
    /// Bech32 npub, derived once at construction.
    ///
    /// The npub is a pure function of `identity`'s public key, and
    /// `identity` is never mutated after construction, so this can never
    /// go stale. Deriving it costs a bech32 encode, which the per-tick
    /// stats snapshot was paying once per peer per tick.
    npub: String,
    /// Shortened npub for log/UI display, derived once at construction.
    /// Immutable for the same reason as [`ActivePeer::npub`].
    short_npub: String,

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

    // === Statistics ===
    /// When this peer was authenticated (Unix milliseconds).
    authenticated_at: u64,

    // === Epoch (Restart Detection) ===
    /// Remote peer's startup epoch (from handshake). Used to detect restarts.
    remote_epoch: Option<[u8; 8]>,

    // === Heartbeat ===
    /// When a heartbeat to this peer last *succeeded*. A send that failed does
    /// not move this: it told the peer nothing, and treating it as if it had
    /// would leave the peer un-heartbeated for a full interval on the strength
    /// of a send that never landed.
    last_heartbeat_sent: Option<Instant>,
    /// When a heartbeat to this peer was last *attempted*, whatever came of it.
    /// Paired with the above so a peer whose send failed is retried sooner than
    /// the heartbeat interval without being retried on every tick — see
    /// `HEARTBEAT_RETRY_INTERVAL`.
    last_heartbeat_attempt: Option<Instant>,

    // === Handshake Resend ===
    /// Wire-format msg2 for resend on duplicate msg1 (responder only).
    /// Cleared after the handshake timeout window.
    handshake_msg2: Option<Vec<u8>>,
    /// Digest of the link-setup msg1 the peering was promoted from, which
    /// `handshake_msg2` answers. Only a resend of that msg1 draws it.
    setup_msg1: Option<Msg1Digest>,
    /// Digest of the ephemeral in that msg1, by which the silent-session
    /// record counts a session once however a copy's header was rewritten.
    setup_ephemeral: Option<EphemeralDigest>,

    // === Rekey (Key Rotation) ===
    /// When the current Noise session was established (for rekey timer).
    session_established_at: Instant,
    /// When this peering's link came up: set at promotion, and again when a
    /// pending session whose msg2 revealed a peer restart leaves the slot.
    /// A rekey cutover, an adoption or a cross-connection swap does not
    /// move it.
    link_established_at: Instant,
    /// Per-session symmetric jitter applied to the rekey timer trigger.
    /// Drawn once at construction (and at each cutover) uniformly from
    /// `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]`. Desynchronizes
    /// dual-initiation in symmetric-start meshes; mean interval is
    /// preserved.
    rekey_jitter_secs: i64,
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
    /// In-progress rekey: number of msg1 retransmissions performed so far.
    rekey_msg1_resend_count: u32,
    /// Which side installed the pending session (`None` when no pending is
    /// held). Set with the pending slot and cleared with it.
    pending_role: Option<RekeyRole>,
    /// When the pending session was installed, for the responder hold.
    pending_since: Option<Instant>,
    /// The pending session completed a rekey msg2 that revealed a peer
    /// restart: the restarted peer promoted our msg1 as a fresh link at
    /// K-bit 0. Set with the pending slot and cleared with it.
    pending_restart: bool,
    /// The rekey msg1s this node answered for this peer as the responder: the
    /// whole answer that armed a pending it holds, so a resend of that msg1
    /// can be answered again, and the digests of ended cycles, so a copy of
    /// one is refused. Not cycle state: it outlives every pending.
    answered: AnsweredMsg1s,
    /// Repeated handshake lines logged for this peer, by kind, so a peer
    /// repeating one msg1 outcome logs it a bounded number of times.
    hs_lines: HsLineCounts,
    /// Test-only: hold this peer entry on the K-bit-only pending trial, as a
    /// peer running the earlier gate would.
    #[cfg(test)]
    old_gate: bool,
    /// Whether this peering has given any evidence that its peer is present
    /// now: an authenticated frame on its session, or, for a peering this
    /// node initiated, the msg2 that answered our fresh ephemeral. A
    /// responder promotion is not such evidence, because the msg1 it was
    /// promoted from carries nothing fresh and may be a replayed capture.
    heard: bool,

    // === Published active-send-state (two-tier boundary) ===
    /// The send-critical subset read (and, on roam/responder-cutover, written)
    /// directly by the data plane. See `PeerSendState`.
    send: PeerSendState,
}

impl ActivePeer {
    /// Create a new active peer from verified identity.
    ///
    /// Called after successful authentication handshake.
    /// For peers with Noise sessions, use `with_session` instead.
    pub fn new(identity: PeerIdentity, link_id: LinkId, authenticated_at: u64) -> Self {
        let now = Instant::now();
        Self {
            npub: identity.npub(),
            short_npub: identity.short_npub(),
            identity,
            declaration: None,
            ancestry: None,
            tree_announce_min_interval_ms: 500,
            last_tree_announce_sent_ms: 0,
            pending_tree_announce: false,
            inbound_filter: None,
            filter_sequence: 0,
            filter_received_at: 0,
            pending_filter_update: true, // Send filter on new connection
            authenticated_at,
            remote_epoch: None,
            last_heartbeat_sent: None,
            last_heartbeat_attempt: None,
            handshake_msg2: None,
            setup_msg1: None,
            setup_ephemeral: None,
            session_established_at: now,
            link_established_at: now,
            rekey_jitter_secs: draw_rekey_jitter(),
            rekey_in_progress: false,
            last_peer_rekey: None,
            rekey_handshake: None,
            rekey_our_index: None,
            rekey_msg1: None,
            rekey_msg1_next_resend: 0,
            rekey_msg1_resend_count: 0,
            pending_role: None,
            pending_since: None,
            pending_restart: false,
            answered: AnsweredMsg1s::default(),
            hs_lines: HsLineCounts::default(),
            #[cfg(test)]
            old_gate: false,
            heard: true,
            send: PeerSendState::new(link_id, now, authenticated_at),
        }
    }

    /// Create from verified identity with existing link stats.
    ///
    /// Used when promoting a completed handshake, preserving its link stats.
    /// For peers with Noise sessions, use `with_session` instead.
    pub fn with_stats(
        identity: PeerIdentity,
        link_id: LinkId,
        authenticated_at: u64,
        link_stats: LinkStats,
    ) -> Self {
        let mut peer = Self::new(identity, link_id, authenticated_at);
        peer.send.link_stats = link_stats;
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
        let mut send = PeerSendState::new(link_id, now, authenticated_at);
        send.noise_session = Some(noise_session);
        send.our_index = Some(our_index);
        send.their_index = Some(their_index);
        send.transport_id = Some(transport_id);
        send.current_addr = Some(current_addr);
        send.link_stats = link_stats;
        send.mmp = Some(MmpPeerState::new(
            mmp_config.mode,
            mmp_config.log_interval_secs,
            mmp_config.owd_window_size,
            is_initiator,
        ));
        Self {
            npub: identity.npub(),
            short_npub: identity.short_npub(),
            identity,
            declaration: None,
            ancestry: None,
            tree_announce_min_interval_ms: 500,
            last_tree_announce_sent_ms: 0,
            pending_tree_announce: false,
            inbound_filter: None,
            filter_sequence: 0,
            filter_received_at: 0,
            pending_filter_update: true,
            authenticated_at,
            remote_epoch,
            last_heartbeat_sent: None,
            last_heartbeat_attempt: None,
            handshake_msg2: None,
            setup_msg1: None,
            setup_ephemeral: None,
            session_established_at: now,
            link_established_at: now,
            rekey_jitter_secs: draw_rekey_jitter(),
            rekey_in_progress: false,
            last_peer_rekey: None,
            rekey_handshake: None,
            rekey_our_index: None,
            rekey_msg1: None,
            rekey_msg1_next_resend: 0,
            rekey_msg1_resend_count: 0,
            pending_role: None,
            pending_since: None,
            pending_restart: false,
            answered: AnsweredMsg1s::default(),
            hs_lines: HsLineCounts::default(),
            #[cfg(test)]
            old_gate: false,
            heard: is_initiator,
            send,
        }
    }

    // === Connected-UDP fast path ===

    /// Refcount the per-peer `connect()`-ed UDP socket if installed.
    /// Encrypt-worker send path uses this to bypass the wildcard
    /// listen socket's per-packet sockaddr handling.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn connected_udp(
        &self,
    ) -> Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>> {
        self.send.connected_udp.clone()
    }

    /// Install a per-peer `connect()`-ed UDP socket with its paired
    /// recv drain thread. The two own each other's lifetime: the drain
    /// is the only consumer of packets on this socket.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn set_connected_udp(
        &mut self,
        socket: std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>,
        drain: crate::transport::udp::PeerRecvDrain,
    ) {
        // Drop the old drain BEFORE the old socket so its last fd
        // reference is released cleanly.
        self.send.peer_recv_drain = None;
        self.send.connected_udp = None;
        self.send.connected_udp = Some(socket);
        self.send.peer_recv_drain = Some(drain);
    }

    /// Clear the per-peer connected UDP socket + drain. The drain
    /// exits via self-pipe signal; the kernel fd closes on last `Arc`
    /// drop (any in-flight worker jobs holding the old `Arc` stay
    /// valid until they complete).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(dead_code)] // called from session-deregister + rekey follow-up
    pub(crate) fn clear_connected_udp(&mut self) {
        self.send.peer_recv_drain = None;
        self.send.connected_udp = None;
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

    /// Get the peer's IPv6 address.
    pub fn address(&self) -> &Ipv6Address {
        self.identity.address()
    }

    /// Get the peer's public key.
    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.identity.pubkey()
    }

    /// Get the peer's npub string.
    ///
    /// Returns a clone of the value cached at construction; the bech32
    /// encode is not repeated.
    pub fn npub(&self) -> String {
        self.npub.clone()
    }

    /// Borrow the peer's cached npub without allocating.
    pub fn npub_str(&self) -> &str {
        &self.npub
    }

    /// Borrow the peer's cached shortened npub (e.g. `npub1abcd...wxyz`).
    pub fn short_npub(&self) -> &str {
        &self.short_npub
    }

    // === Connection Accessors ===

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.send.link_id
    }

    /// Check if peer is disconnected.
    ///
    /// Always false: the peer stores no connectivity state, and a peer that
    /// goes away is removed from the node rather than marked.
    pub fn is_disconnected(&self) -> bool {
        false
    }

    // === Session Accessors ===

    /// Check if this peer has a Noise session.
    pub fn has_session(&self) -> bool {
        self.send.noise_session.is_some()
    }

    /// Get the Noise session, if present.
    pub fn noise_session(&self) -> Option<&NoiseSession> {
        self.send.noise_session.as_ref()
    }

    /// Get mutable access to the Noise session.
    pub fn noise_session_mut(&mut self) -> Option<&mut NoiseSession> {
        self.send.noise_session.as_mut()
    }

    /// Get our session index (they use this to send TO us).
    pub fn our_index(&self) -> Option<SessionIndex> {
        self.send.our_index
    }

    /// Get their session index (we use this to send TO them).
    pub fn their_index(&self) -> Option<SessionIndex> {
        self.send.their_index
    }

    /// Update their session index (used during cross-connection resolution
    /// when the losing node keeps its inbound session but needs the peer's
    /// outbound index).
    pub fn set_their_index(&mut self, index: SessionIndex) {
        self.send.their_index = Some(index);
    }

    /// Replace the Noise session and indices during cross-connection resolution.
    ///
    /// When both nodes simultaneously initiate, each promotes its inbound
    /// handshake first. When the peer's msg2 arrives, we learn the correct
    /// session — the outbound handshake that pairs with the peer's inbound.
    /// This replaces the entire session so both nodes use matching keys.
    ///
    /// Returns the old our_index so the caller can update peers_by_index.
    /// Also resets the replay suppression counter and the repeated handshake
    /// line counts since the session changed.
    pub fn replace_session(
        &mut self,
        new_session: NoiseSession,
        new_our_index: SessionIndex,
        new_their_index: SessionIndex,
    ) -> Option<SessionIndex> {
        self.reset_replay_suppressed();
        self.hs_lines.roll();
        let old_our_index = self.send.our_index;
        self.send.noise_session = Some(new_session);
        self.send.our_index = Some(new_our_index);
        self.send.their_index = Some(new_their_index);
        old_our_index
    }

    /// Get the transport ID for this peer.
    pub fn transport_id(&self) -> Option<TransportId> {
        self.send.transport_id
    }

    /// Get the current transport address.
    pub fn current_addr(&self) -> Option<&TransportAddr> {
        self.send.current_addr.as_ref()
    }

    /// Update the current address (for roaming support).
    ///
    /// Called when we receive a valid authenticated packet from a new address.
    /// Returns `true` if `(transport_id, addr)` actually changed — callers
    /// use this to invalidate per-peer `connect(2)`-ed UDP sockets whose
    /// 5-tuple just went stale.
    pub fn set_current_addr(&mut self, transport_id: TransportId, addr: TransportAddr) -> bool {
        let changed = self.send.transport_id != Some(transport_id)
            || self.send.current_addr.as_ref() != Some(&addr);
        self.send.transport_id = Some(transport_id);
        self.send.current_addr = Some(addr);
        changed
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
        self.setup_msg1 = None;
    }

    // === Replay Detection Suppression ===

    /// Increment replay suppression counter. Returns the new count.
    pub fn increment_replay_suppressed(&mut self) -> u32 {
        self.send.replay_suppressed_count += 1;
        self.send.replay_suppressed_count
    }

    /// Reset replay suppression counter, returning previous count.
    pub fn reset_replay_suppressed(&mut self) -> u32 {
        let count = self.send.replay_suppressed_count;
        self.send.replay_suppressed_count = 0;
        count
    }

    /// Current replay suppression count.
    pub fn replay_suppressed_count(&self) -> u32 {
        self.send.replay_suppressed_count
    }

    // === Repeated Handshake Lines ===

    /// This peer's repeated handshake line counts.
    pub(crate) fn hs_lines(&self) -> &HsLineCounts {
        &self.hs_lines
    }

    /// This peer's repeated handshake line counts, to count a line.
    pub(crate) fn hs_lines_mut(&mut self) -> &mut HsLineCounts {
        &mut self.hs_lines
    }

    // === Decryption Failure Tracking ===

    /// Increment consecutive decryption failure counter, returning new count.
    /// Saturates at `u32::MAX`, since only an authenticated frame resets it.
    pub fn increment_decrypt_failures(&mut self) -> u32 {
        self.send.consecutive_decrypt_failures =
            self.send.consecutive_decrypt_failures.saturating_add(1);
        self.send.consecutive_decrypt_failures
    }

    /// Reset consecutive decryption failure counter.
    pub fn reset_decrypt_failures(&mut self) {
        self.send.consecutive_decrypt_failures = 0;
    }

    /// Current consecutive decryption failure count.
    pub fn consecutive_decrypt_failures(&self) -> u32 {
        self.send.consecutive_decrypt_failures
    }

    /// Record the receiver index of a frame that failed to decrypt.
    pub(crate) fn record_failed(&mut self, idx: SessionIndex) {
        self.send.failed_idx = Some(idx);
    }

    /// The receiver index of the last frame that failed to decrypt.
    pub(crate) fn last_failed(&self) -> Option<SessionIndex> {
        self.send.failed_idx
    }

    /// Count one frame authenticated on the previous session.
    pub(crate) fn count_previous(&mut self) {
        self.send.prev_frames = self.send.prev_frames.saturating_add(1);
    }

    /// Frames authenticated on the previous session since the last cutover.
    pub(crate) fn prev_frames(&self) -> u64 {
        self.send.prev_frames
    }

    /// How long ago the last cutover happened; `None` if there has been none.
    pub(crate) fn since_cutover(&self) -> Option<Duration> {
        self.send.last_cutover.map(|t| t.elapsed())
    }

    // === Epoch Accessors ===

    /// Get the remote peer's startup epoch (from handshake).
    pub fn remote_epoch(&self) -> Option<[u8; 8]> {
        self.remote_epoch
    }

    /// Update the remote peer's startup epoch after a successful in-place
    /// rekey. Initial handshakes set this through `with_session`, but recovery
    /// rekeys also exchange epochs and must keep restart detection current.
    pub(crate) fn set_remote_epoch(&mut self, remote_epoch: Option<[u8; 8]>) {
        self.remote_epoch = remote_epoch;
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
        &self.send.link_stats
    }

    /// Get mutable link statistics.
    pub fn link_stats_mut(&mut self) -> &mut LinkStats {
        &mut self.send.link_stats
    }

    // === MMP Accessors ===

    /// Get MMP state (None for legacy peers without sessions).
    pub fn mmp(&self) -> Option<&MmpPeerState> {
        self.send.mmp.as_ref()
    }

    /// Get mutable MMP state.
    pub fn mmp_mut(&mut self) -> Option<&mut MmpPeerState> {
        self.send.mmp.as_mut()
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
        self.send.last_seen
    }

    /// Whether an authenticated frame from this peer has arrived since it was
    /// promoted.
    pub(crate) fn heard(&self) -> bool {
        self.send.heard
    }

    /// Whether this peering has been heard from: an authenticated frame
    /// arrived on its session, or this node initiated it. A peering promoted
    /// on a received msg1 is unheard until its first authenticated frame.
    pub fn is_heard(&self) -> bool {
        self.heard
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.send.last_seen)
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
        self.send.session_start.elapsed().as_millis() as u32
    }

    /// When this peer's session started (for link-dead fallback timing).
    pub fn session_start(&self) -> Instant {
        self.send.session_start
    }

    // === Heartbeat ===

    /// When a heartbeat to this peer last succeeded.
    pub fn last_heartbeat_sent(&self) -> Option<Instant> {
        self.last_heartbeat_sent
    }

    /// Record that a heartbeat reached the transport without error.
    ///
    /// Call this *after* the send, and only when it returned cleanly. Marking
    /// before the send makes a failed heartbeat indistinguishable from a
    /// delivered one, which then suppresses the next attempt for a full
    /// `heartbeat_interval_secs` although the peer has heard nothing.
    pub fn mark_heartbeat_sent(&mut self, now: Instant) {
        self.last_heartbeat_sent = Some(now);
        self.last_heartbeat_attempt = Some(now);
    }

    /// When a heartbeat to this peer was last attempted, whatever came of it.
    pub(crate) fn last_heartbeat_attempt(&self) -> Option<Instant> {
        self.last_heartbeat_attempt
    }

    /// Record that a heartbeat send was attempted.
    ///
    /// Call this *before* the send, so an attempt that fails, or one that never
    /// returns, still spaces the next one out.
    pub(crate) fn mark_heartbeat_attempt(&mut self, now: Instant) {
        self.last_heartbeat_attempt = Some(now);
    }

    // === State Updates ===

    /// Record an authenticated frame from this peer: refresh the last-seen
    /// time and mark the peer, and the peering, heard.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.heard = true;
        self.send.last_seen = current_time_ms;
        self.send.heard = true;
    }

    /// Set the last-seen time without marking the peer heard, as for a
    /// session that has carried no authenticated frame and gone idle.
    #[cfg(test)]
    pub(crate) fn test_set_last_seen(&mut self, current_time_ms: u64) {
        self.send.last_seen = current_time_ms;
    }

    /// Set when the peering was authenticated, as for one promoted that long
    /// ago. A peering not yet heard from is aged from here.
    #[cfg(test)]
    pub(crate) fn test_set_authenticated_at(&mut self, authenticated_at: u64) {
        self.authenticated_at = authenticated_at;
    }

    /// Update the link ID (e.g., on reconnect).
    pub fn set_link_id(&mut self, link_id: LinkId) {
        self.send.link_id = link_id;
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
        self.send.last_seen = current_time_ms;
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

    /// Mark that a tree announce is pending (deferred by the rate limit or by
    /// a failed link send).
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
        self.send.last_seen = current_time_ms;
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

    /// When this peering's link came up: at promotion, or when a pending
    /// session that revealed a peer restart left the slot. Unlike
    /// [`session_established_at`](Self::session_established_at), a rekey
    /// cutover does not move it.
    pub fn link_established_at(&self) -> Instant {
        self.link_established_at
    }

    /// Test-only seam: backdate the session-established instant so a test can
    /// construct a session that reads as `age`-old. The link instant is moved
    /// back with it when it would otherwise be the younger of the two, since
    /// a link is never younger than its session. This only shifts the private
    /// timestamp fields; it changes no decision logic, no threshold, and is
    /// compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_session_established(&mut self, age: std::time::Duration) {
        self.session_established_at = self
            .session_established_at
            .checked_sub(age)
            .unwrap_or_else(Instant::now);
        self.link_established_at = self.link_established_at.min(self.session_established_at);
    }

    /// Test-only seam: backdate the start of the drain a cutover began, so a
    /// test can stand up a drain window that has passed but that no rekey
    /// tick has completed yet. A no-op when no drain is in progress. Compiled
    /// out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_drain_started(&mut self, age: Duration) {
        self.send.drain_started = self
            .send
            .drain_started
            .map(|t| t.checked_sub(age).unwrap_or_else(Instant::now));
    }

    /// Test-only seam: backdate the pending session's install time so a test
    /// can make the responder hold read as passed. Shifts only the private
    /// timestamp; compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn backdate_pending(&mut self, age: Duration) {
        self.pending_since = self
            .pending_since
            .map(|t| t.checked_sub(age).unwrap_or_else(Instant::now));
    }

    /// Test-only seam: backdate the last peer-initiated rekey so a test can
    /// move past the rekey dampening window without waiting it out. Shifts
    /// only the private timestamp; compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn backdate_dampener(&mut self, age: Duration) {
        self.last_peer_rekey = self
            .last_peer_rekey
            .map(|t| t.checked_sub(age).unwrap_or_else(Instant::now));
    }

    /// Test-only seam: set the K-bit this node sends with, to stand up the
    /// out-of-step K-bits that a peer restart or a cross-connection swap
    /// leaves behind. Compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn force_kbit(&mut self, kbit: bool) {
        self.send.current_k_bit = kbit;
    }

    /// Test-only seam: try the pending session only on a K-bit that differs
    /// from ours, as a peer running the earlier gate does. Compiled out of
    /// release builds.
    #[cfg(test)]
    pub(crate) fn set_oldgate(&mut self) {
        self.old_gate = true;
    }

    /// Test-only: whether [`set_oldgate`](Self::set_oldgate) was called.
    #[cfg(test)]
    pub(crate) fn old_gate(&self) -> bool {
        self.old_gate
    }

    /// Test-only seam: install link-layer MMP state with a chosen operating
    /// mode on a peer that was constructed without a Noise session (the bare
    /// `new` constructor leaves `mmp` as `None`). This only attaches the same
    /// `MmpPeerState::new` the session path installs; it changes no decision
    /// logic and no threshold, and is compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_init_mmp(&mut self, mode: crate::proto::mmp::MmpMode) {
        let config = MmpConfig {
            mode,
            ..MmpConfig::default()
        };
        self.send.mmp = Some(MmpPeerState::new(
            config.mode,
            config.log_interval_secs,
            config.owd_window_size,
            true,
        ));
    }

    /// Test-only seam: backdate the session-start instant so a test can make
    /// `session_elapsed_ms()` read as `age`-old (needed to synthesize a
    /// positive RTT sample from a crafted ReceiverReport). This only shifts the
    /// private timestamp field; it changes no decision logic, no threshold, and
    /// is compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_session_start(&mut self, age: std::time::Duration) {
        self.send.session_start = self
            .send
            .session_start
            .checked_sub(age)
            .unwrap_or_else(Instant::now);
    }

    /// Per-session symmetric rekey-timer jitter offset (seconds).
    ///
    /// Drawn at session construction and at each rekey cutover; uniform
    /// over `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]`. Callers add this
    /// to the configured `node.rekey.after_secs` to obtain the effective
    /// trigger interval for this session.
    pub fn rekey_jitter_secs(&self) -> i64 {
        self.rekey_jitter_secs
    }

    /// Current K-bit epoch value.
    pub fn current_k_bit(&self) -> bool {
        self.send.current_k_bit
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
        self.send.pending_our_index
    }

    /// Get the pending new session's their_index.
    pub fn pending_their_index(&self) -> Option<SessionIndex> {
        self.send.pending_their_index
    }

    /// Get the previous session's our_index (during drain).
    pub fn previous_our_index(&self) -> Option<SessionIndex> {
        self.send.previous_our_index
    }

    /// Get the previous session for decryption fallback.
    pub fn previous_session(&self) -> Option<&NoiseSession> {
        self.send.previous_session.as_ref()
    }

    /// Get mutable access to the previous session for decryption.
    pub fn previous_session_mut(&mut self) -> Option<&mut NoiseSession> {
        self.send.previous_session.as_mut()
    }

    /// Get the pending new session (completed rekey, not yet cut over).
    pub fn pending_new_session(&self) -> Option<&NoiseSession> {
        self.send.pending_new_session.as_ref()
    }

    /// Mutable access to the pending new session, for trial-decrypt of an
    /// inbound frame before promoting it on a peer K-bit flip.
    pub fn pending_new_session_mut(&mut self) -> Option<&mut NoiseSession> {
        self.send.pending_new_session.as_mut()
    }

    /// Which side of the rekey handshake produced the pending session; `None`
    /// when no pending session is held.
    pub(crate) fn pending_role(&self) -> Option<RekeyRole> {
        self.pending_role
    }

    /// The answer that armed the pending session, when this node holds it as
    /// the rekey responder; `None` otherwise.
    pub(crate) fn rekey_answer(&self) -> Option<&RekeyAnswer> {
        self.answered.held()
    }

    /// Whether `msg1` armed a responder cycle with this peer that has ended,
    /// or is the link-setup msg1 the peering was promoted from.
    pub(crate) fn answered_before(&self, msg1: &Msg1Digest) -> bool {
        self.answered.ended(msg1)
    }

    /// Whether `msg1` is the link-setup msg1 this peering was promoted from,
    /// the one the stored msg2 answers.
    pub(crate) fn is_setup(&self, msg1: &Msg1Digest) -> bool {
        self.setup_msg1.as_ref() == Some(msg1)
    }

    /// Record `msg1`, the link-setup msg1 this peering was promoted from, so
    /// a resend of it draws the stored msg2 while the session is too young
    /// to rekey, and a copy of it is refused once the session is old enough.
    pub(crate) fn note_setup(&mut self, msg1: Msg1Digest) {
        self.setup_msg1 = Some(msg1);
        self.answered.end_setup(msg1);
    }

    /// Record the ephemeral digest of the link-setup msg1 this peering was
    /// promoted from (`None` if the msg1 was too short to carry one).
    pub(crate) fn note_setup_ephemeral(&mut self, ephemeral: Option<EphemeralDigest>) {
        self.setup_ephemeral = ephemeral;
    }

    /// The ephemeral digest of the link-setup msg1 this peering was promoted
    /// from, or `None` for a peering this node dialled.
    pub(crate) fn setup_ephemeral(&self) -> Option<EphemeralDigest> {
        self.setup_ephemeral
    }

    /// Check whether the pending session has been held for at least `hold`
    /// since it was installed. False when no pending session is held.
    pub(crate) fn pending_expired(&self, hold: Duration) -> bool {
        self.pending_since.is_some_and(|t| t.elapsed() >= hold)
    }

    /// How long the pending session has been held since it was installed;
    /// `None` when no pending session is held.
    pub(crate) fn pending_age(&self) -> Option<Duration> {
        self.pending_since.map(|t| t.elapsed())
    }

    /// Store a completed rekey session and its indices.
    ///
    /// Called when the rekey handshake completes. The session is held
    /// as pending until the initiator flips the K-bit on the next outbound packet.
    /// Records this node as the initiator; a pending session answered for the
    /// peer is stored with [`answer_rekey`](Self::answer_rekey).
    pub fn set_pending_session(
        &mut self,
        session: NoiseSession,
        our_index: SessionIndex,
        their_index: SessionIndex,
    ) {
        self.install_pending(session, our_index, their_index, RekeyRole::Initiator);
        self.answered.end();
    }

    /// Record that the msg2 which completed the held initiator pending
    /// revealed a peer restart. The restarted peer promoted our msg1 as a
    /// fresh link and sends at K-bit 0, so the cutover to this pending takes
    /// K-bit 0 instead of toggling ours.
    pub(crate) fn note_restart(&mut self) {
        debug_assert_eq!(
            self.pending_role,
            Some(RekeyRole::Initiator),
            "note_restart: no initiator pending is held"
        );
        self.pending_restart = true;
    }

    /// Store the session this node produced by answering the peer's rekey
    /// msg1, with the answer it sent. It is held until a frame on the new
    /// epoch from the peer authenticates against it
    /// ([`handle_peer_kbit_flip`](Self::handle_peer_kbit_flip)), or until the
    /// responder hold passes and the node retires it
    /// ([`retire_pending`](Self::retire_pending)); it is never cut over on this
    /// node's own schedule.
    pub(crate) fn answer_rekey(
        &mut self,
        session: NoiseSession,
        our_index: SessionIndex,
        their_index: SessionIndex,
        answer: RekeyAnswer,
    ) {
        self.install_pending(session, our_index, their_index, RekeyRole::Responder);
        self.answered.arm(answer);
    }

    /// Clear what is recorded beside the pending slot: its role and install
    /// time, and the answer that armed it, of which only the msg1 digest is
    /// kept, as an ended cycle. Every path that empties the slot calls this.
    ///
    /// A pending whose msg2 revealed a peer restart
    /// ([`note_restart`](Self::note_restart)) restarts the link's age as it
    /// leaves: the restarted peer promoted our msg1 as a fresh link, so its
    /// dials may cross ours for the next 30 s. While it is held, the old
    /// link age stands and a msg1 from that peer is refused as arriving
    /// with a pending held.
    fn release_pending(&mut self) {
        if self.pending_restart {
            self.link_established_at = Instant::now();
        }
        self.pending_role = None;
        self.pending_since = None;
        self.pending_restart = false;
        self.answered.end();
    }

    /// Store a pending session with the role that produced it and the time it
    /// was installed; the one writer that fills the pending slot.
    fn install_pending(
        &mut self,
        session: NoiseSession,
        our_index: SessionIndex,
        their_index: SessionIndex,
        role: RekeyRole,
    ) {
        self.send.pending_new_session = Some(session);
        self.send.pending_our_index = Some(our_index);
        self.send.pending_their_index = Some(their_index);
        self.pending_role = Some(role);
        self.pending_since = Some(Instant::now());
        self.pending_restart = false;
        self.rekey_in_progress = false;
        // Clear initiator handshake state (index now lives in pending_our_index)
        self.rekey_our_index = None;
        self.rekey_handshake = None;
        self.rekey_msg1 = None;
        self.rekey_msg1_next_resend = 0;
        self.rekey_msg1_resend_count = 0;
        debug_assert_eq!(
            self.pending_role.is_some(),
            self.send.pending_new_session.is_some(),
            "install_pending: pending role out of step with the pending slot"
        );
    }

    /// Cut over to the pending new session (initiator side).
    ///
    /// Moves current session to previous (for drain), promotes pending to current,
    /// flips the K-bit, or sets it to 0 when the pending's msg2 revealed a peer
    /// restart ([`note_restart`](Self::note_restart)). Returns the old our_index
    /// that should remain in peers_by_index during the drain window.
    pub fn cutover_to_new_session(&mut self) -> Option<SessionIndex> {
        let new_session = self.send.pending_new_session.take()?;
        let new_our_index = self.send.pending_our_index.take();
        let new_their_index = self.send.pending_their_index.take();
        let restarted = self.pending_restart;
        self.release_pending();

        // Demote current to previous
        self.send.previous_session = self.send.noise_session.take();
        self.send.previous_our_index = self.send.our_index;
        self.send.drain_started = Some(Instant::now());
        self.send.last_cutover = self.send.drain_started;
        self.send.prev_frames = 0;

        // Promote pending to current
        self.send.noise_session = Some(new_session);
        self.send.our_index = new_our_index;
        self.send.their_index = new_their_index;

        // Flip the K-bit and reset timing. A peer that restarted promoted our
        // msg1 as a fresh link at K-bit 0 and did not flip, so match it.
        self.send.current_k_bit = if restarted {
            false
        } else {
            !self.send.current_k_bit
        };
        self.session_established_at = Instant::now();
        self.send.session_start = Instant::now();
        self.rekey_in_progress = false;
        self.rekey_msg1_resend_count = 0;
        self.rekey_jitter_secs = draw_rekey_jitter();
        self.reset_replay_suppressed();
        self.hs_lines.roll();

        // Reset MMP counters to avoid metric discontinuity
        let now_ms = crate::time::mono_ms();
        if let Some(mmp) = &mut self.send.mmp {
            mmp.reset_for_rekey(now_ms);
        }

        debug_assert_eq!(
            self.pending_role.is_some(),
            self.send.pending_new_session.is_some(),
            "cutover_to_new_session: pending role out of step with the pending slot"
        );
        self.send.previous_our_index
    }

    /// Handle receiving a K-bit flip from the peer (responder side).
    ///
    /// Promotes pending_new_session to current, demotes current to previous.
    /// Returns the old our_index for drain tracking.
    pub fn handle_peer_kbit_flip(&mut self) -> Option<SessionIndex> {
        let new_session = self.send.pending_new_session.take()?;
        let new_our_index = self.send.pending_our_index.take();
        let new_their_index = self.send.pending_their_index.take();
        self.release_pending();

        // Demote current to previous
        self.send.previous_session = self.send.noise_session.take();
        self.send.previous_our_index = self.send.our_index;
        self.send.drain_started = Some(Instant::now());
        self.send.last_cutover = self.send.drain_started;
        self.send.prev_frames = 0;

        // Promote pending to current
        self.send.noise_session = Some(new_session);
        self.send.our_index = new_our_index;
        self.send.their_index = new_their_index;

        // Match peer's K-bit
        self.send.current_k_bit = !self.send.current_k_bit;
        self.session_established_at = Instant::now();
        self.send.session_start = Instant::now();
        self.rekey_in_progress = false;
        self.rekey_msg1_resend_count = 0;
        self.rekey_jitter_secs = draw_rekey_jitter();
        self.reset_replay_suppressed();
        self.hs_lines.roll();

        // Reset MMP counters to avoid metric discontinuity
        let now_ms = crate::time::mono_ms();
        if let Some(mmp) = &mut self.send.mmp {
            mmp.reset_for_rekey(now_ms);
        }

        debug_assert_eq!(
            self.pending_role.is_some(),
            self.send.pending_new_session.is_some(),
            "handle_peer_kbit_flip: pending role out of step with the pending slot"
        );
        self.send.previous_our_index
    }

    /// Promote the pending session on a peer frame that authenticated
    /// against it, and take the K-bit from that frame rather than toggling
    /// ours: the two ends' bits may have been out of step, and the frame's
    /// bit is the one the peer sends with.
    pub(crate) fn adopt_pending(&mut self, frame_kbit: bool) -> Option<SessionIndex> {
        let held = self.send.pending_new_session.is_some();
        let old = self.handle_peer_kbit_flip();
        if held {
            self.send.current_k_bit = frame_kbit;
        }
        old
    }

    /// Check if the drain window has expired.
    pub fn drain_expired(&self, drain_secs: u64) -> bool {
        match self.send.drain_started {
            Some(t) => t.elapsed().as_secs() >= drain_secs,
            None => false,
        }
    }

    /// Whether a drain is in progress.
    pub fn is_draining(&self) -> bool {
        self.send.drain_started.is_some()
    }

    /// Complete the drain: drop previous session and free its index.
    ///
    /// Returns the previous our_index so the caller can remove it from
    /// peers_by_index and free it from the IndexAllocator.
    pub fn complete_drain(&mut self) -> Option<SessionIndex> {
        self.send.previous_session = None;
        self.send.drain_started = None;
        self.send.previous_our_index.take()
    }

    /// Drop a pending session this node did not initiate, which the
    /// initiator never adopted. Returns its index so the caller can
    /// unregister and free it; `None` if no such pending is held. A pending
    /// this node initiated is left alone: that one is cut over, not retired.
    pub(crate) fn retire_pending(&mut self) -> Option<SessionIndex> {
        if self.pending_role == Some(RekeyRole::Initiator) {
            return None;
        }
        self.send.pending_new_session.take()?;
        self.send.pending_their_index = None;
        self.release_pending();
        debug_assert_eq!(
            self.pending_role.is_some(),
            self.send.pending_new_session.is_some(),
            "retire_pending: pending role out of step with the pending slot"
        );
        self.send.pending_our_index.take()
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
        self.rekey_msg1_resend_count = 0;
        self.rekey_in_progress = false;
        // Return whichever index needs freeing
        let freed = self.rekey_our_index.take().or_else(|| {
            self.send.pending_new_session = None;
            self.send.pending_their_index = None;
            self.release_pending();
            self.send.pending_our_index.take()
        });
        debug_assert_eq!(
            self.pending_role.is_some(),
            self.send.pending_new_session.is_some(),
            "abandon_rekey: pending role out of step with the pending slot"
        );
        freed
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
        self.rekey_msg1_resend_count = 0;
        self.rekey_in_progress = true;
    }

    /// Get the rekey our_index (for msg2 dispatch lookup).
    pub fn rekey_our_index(&self) -> Option<SessionIndex> {
        self.rekey_our_index
    }

    /// Whether this peer still holds its rekey initiator handshake, waiting
    /// on msg2.
    ///
    /// [`complete_rekey_msg2`](Self::complete_rekey_msg2) keeps the handshake
    /// when a msg2 fails to authenticate, so after a failed call this tells
    /// the caller the cycle is still intact.
    pub fn awaits_msg2(&self) -> bool {
        self.rekey_handshake.is_some()
    }

    /// Complete the rekey by processing msg2 (initiator side).
    ///
    /// Reads msg2 against the stored handshake state and returns the
    /// completed NoiseSession. Clears the handshake-related fields but
    /// leaves rekey_our_index for set_pending_session to use.
    ///
    /// A msg2 that fails the read changes nothing: the handshake goes back
    /// in its pre-read state, and the msg1 resend schedule stays as it was.
    /// Nothing authenticates a msg2 before this read, so the message may be a
    /// forgery naming our rekey index, and the responder's genuine msg2 has
    /// to remain readable when it arrives.
    pub fn complete_rekey_msg2(
        &mut self,
        msg2_bytes: &[u8],
    ) -> Result<(NoiseSession, Option<[u8; 8]>), NoiseError> {
        let mut hs = self
            .rekey_handshake
            .take()
            .ok_or_else(|| NoiseError::WrongState {
                expected: "rekey handshake in progress".to_string(),
                got: "no handshake state".to_string(),
            })?;

        if let Err(e) = hs.try_read_message_2(msg2_bytes) {
            self.rekey_handshake = Some(hs);
            return Err(e);
        }
        let remote_epoch = hs.remote_epoch();
        let session = hs.into_session()?;

        // Clear msg1 resend state
        self.rekey_msg1 = None;
        self.rekey_msg1_next_resend = 0;
        self.rekey_msg1_resend_count = 0;

        Ok((session, remote_epoch))
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

    /// Number of rekey msg1 retransmissions performed so far.
    pub fn rekey_msg1_resend_count(&self) -> u32 {
        self.rekey_msg1_resend_count
    }

    /// Record a rekey msg1 retransmission and schedule the next one.
    pub fn record_rekey_msg1_resend(&mut self, next_ms: u64) {
        self.rekey_msg1_resend_count += 1;
        self.rekey_msg1_next_resend = next_ms;
    }
}

#[cfg(test)]
#[path = "tests/active.rs"]
mod tests;
