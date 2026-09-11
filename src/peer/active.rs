//! Active Peer (Authenticated Phase)
//!
//! Represents a fully authenticated peer after successful Noise handshake.
//! ActivePeer holds tree state, Bloom filter, and routing information.

use crate::config::MmpConfig;
use crate::node::REKEY_JITTER_SECS;
use crate::noise::{HandshakeState as NoiseHandshakeState, NoiseError, NoiseSession};
use crate::proto::bloom::BloomFilter;
use crate::proto::fmp::RekeyRole;
use crate::proto::mmp::MmpPeerState;
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{FipsAddress, NodeAddr, PeerIdentity};
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

/// One transport-level path to a peer.
///
/// Path identity is the transport instance: one transport holds at most one
/// path to a given peer, and an address roams *inside* a path. Everything
/// that is per session (Noise slots, K-bit, indices, rekey state) stays on
/// the peer; a path carries only what is bound to the medium it runs over.
/// See `docs/design/fips-multi-path-switchover.md` §1–2.
///
/// Today a peer holds at most one path, added at promotion. The probe
/// exchange that adds further paths under the existing session is the next
/// step of that design; nothing here assumes a single path.
#[derive(Debug)]
pub struct PeerPath {
    /// The transport instance this path runs over.
    transport_id: TransportId,
    /// The peer's current address on that transport (roams).
    addr: TransportAddr,

    /// Unix UDP fast-path: per-path `connect()`-ed socket (paired with
    /// the listen socket via `SO_REUSEPORT`). The kernel demux prefers
    /// the connected 5-tuple, so inbound packets land here; the
    /// encrypt-worker send path sends with `msg_name = NULL`, skipping
    /// per-packet sockaddr handling + route lookup. Behind an `Arc` so
    /// in-flight worker jobs survive rekey/address-change rotations.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    connected_udp: Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>>,

    /// Recv drain thread for `connected_udp`. Always paired with it: the
    /// kernel routes inbound packets from this peer to the connected
    /// socket, so it *must* be drained or the kernel recv buffer fills.
    /// Drop signals shutdown via self-pipe.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    peer_recv_drain: Option<crate::transport::udp::PeerRecvDrain>,
}

impl PeerPath {
    fn new(transport_id: TransportId, addr: TransportAddr) -> Self {
        Self {
            transport_id,
            addr,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_udp: None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            peer_recv_drain: None,
        }
    }

    /// The transport instance this path runs over.
    pub fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    /// The peer's current address on this path.
    pub fn addr(&self) -> &TransportAddr {
        &self.addr
    }

    /// Drop the connected socket and its drain. The drain goes first so
    /// its last fd reference is released cleanly; the kernel fd closes on
    /// the last `Arc` drop, so in-flight worker jobs holding the old `Arc`
    /// stay valid until they complete.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn clear_connected_udp(&mut self) {
        self.peer_recv_drain = None;
        self.connected_udp = None;
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
    /// The paths this peer is reachable over, one per transport instance.
    /// Empty for a peer that has not been bound to a transport yet.
    paths: Vec<PeerPath>,
    /// Index into `paths` of the path *our* frames go out on. `None` only
    /// while `paths` is empty.
    active: Option<usize>,
    /// Link used to reach this peer.
    link_id: LinkId,

    // === Hot counters ===
    /// Link statistics.
    link_stats: LinkStats,
    /// When this peer was last seen (any activity, Unix milliseconds).
    last_seen: u64,
    /// Number of replay detections suppressed since last session reset.
    replay_suppressed_count: u32,
    /// Consecutive decryption failures (reset on any successful decrypt).
    consecutive_decrypt_failures: u32,
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
            pending_new_session: None,
            pending_our_index: None,
            pending_their_index: None,
            current_k_bit: false,
            session_start,
            paths: Vec::new(),
            active: None,
            link_id,
            link_stats: LinkStats::new(),
            last_seen,
            replay_suppressed_count: 0,
            consecutive_decrypt_failures: 0,
            mmp: None,
        }
    }

    /// The path our frames go out on, if any.
    fn active_path(&self) -> Option<&PeerPath> {
        self.active.and_then(|i| self.paths.get(i))
    }

    fn active_path_mut(&mut self) -> Option<&mut PeerPath> {
        self.active.and_then(|i| self.paths.get_mut(i))
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

    // === Rekey (Key Rotation) ===
    /// When the current Noise session was established (for rekey timer).
    session_established_at: Instant,
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
            session_established_at: now,
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
        send.paths.push(PeerPath::new(transport_id, current_addr));
        send.active = Some(0);
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
            session_established_at: now,
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
            send,
        }
    }

    // === Connected-UDP fast path ===

    /// Refcount the active path's `connect()`-ed UDP socket if installed.
    /// Encrypt-worker send path uses this to bypass the wildcard
    /// listen socket's per-packet sockaddr handling.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn connected_udp(
        &self,
    ) -> Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>> {
        self.send
            .active_path()
            .and_then(|path| path.connected_udp.clone())
    }

    /// Install a `connect()`-ed UDP socket with its paired recv drain
    /// thread on the active path. The two own each other's lifetime: the
    /// drain is the only consumer of packets on this socket. A no-op on a
    /// peer with no path: there is no address to have connected to.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn set_connected_udp(
        &mut self,
        socket: std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>,
        drain: crate::transport::udp::PeerRecvDrain,
    ) {
        let Some(path) = self.send.active_path_mut() else {
            return;
        };
        // Drop the old drain BEFORE the old socket so its last fd
        // reference is released cleanly.
        path.clear_connected_udp();
        path.connected_udp = Some(socket);
        path.peer_recv_drain = Some(drain);
    }

    /// Clear the active path's connected UDP socket + drain. The drain
    /// exits via self-pipe signal; the kernel fd closes on last `Arc`
    /// drop (any in-flight worker jobs holding the old `Arc` stay
    /// valid until they complete).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[allow(dead_code)] // called from session-deregister + rekey follow-up
    pub(crate) fn clear_connected_udp(&mut self) {
        if let Some(path) = self.send.active_path_mut() {
            path.clear_connected_udp();
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
    /// Also resets the replay suppression counter since the session changed.
    pub fn replace_session(
        &mut self,
        new_session: NoiseSession,
        new_our_index: SessionIndex,
        new_their_index: SessionIndex,
    ) -> Option<SessionIndex> {
        self.reset_replay_suppressed();
        let old_our_index = self.send.our_index;
        self.send.noise_session = Some(new_session);
        self.send.our_index = Some(new_our_index);
        self.send.their_index = Some(new_their_index);
        old_our_index
    }

    /// The transport our frames to this peer go out on: the active path's.
    pub fn transport_id(&self) -> Option<TransportId> {
        self.send.active_path().map(|path| path.transport_id)
    }

    /// The address our frames to this peer go to: the active path's.
    pub fn current_addr(&self) -> Option<&TransportAddr> {
        self.send.active_path().map(|path| &path.addr)
    }

    /// Every path this peer is reachable over. The active one is
    /// [`active_path`](Self::active_path).
    pub fn paths(&self) -> &[PeerPath] {
        &self.send.paths
    }

    /// The path our frames go out on, if the peer has one.
    pub fn active_path(&self) -> Option<&PeerPath> {
        self.send.active_path()
    }

    /// Update the current address (for roaming support).
    ///
    /// Called when we receive a valid authenticated packet from a new address.
    /// An address roams only *inside* a path: the frame updates the address
    /// of the path on `transport_id` if the peer has one. A frame that
    /// arrives on a transport the peer has no path on is still delivered
    /// (the demux is by index alone) but creates nothing and moves nothing:
    /// an authentic frame proves the peer produced it, not that it came from
    /// where it claims, so an on-path relay rewriting the source (a rogue
    /// AP, anyone on a shared L2) could otherwise move the whole send side
    /// onto another transport, undamped and unprobed. A peer with no path
    /// at all is bound by its first authentic frame, as before. Only a
    /// deliberate [`rebind_transport`](Self::rebind_transport) changes which
    /// transport the peer sends on.
    ///
    /// Returns `true` if the *active* path's address changed — callers use
    /// this to invalidate the `connect(2)`-ed UDP socket whose 5-tuple just
    /// went stale. A roam on a standby path clears that path's own socket
    /// here and returns `false`; a frame refused for being on an unknown
    /// transport returns `false` too: nothing moved.
    pub fn set_current_addr(&mut self, transport_id: TransportId, addr: TransportAddr) -> bool {
        if self.send.paths.is_empty() {
            return self.rebind_transport(transport_id, addr);
        }
        let Some(idx) = self
            .send
            .paths
            .iter()
            .position(|path| path.transport_id == transport_id)
        else {
            return false;
        };
        let path = &mut self.send.paths[idx];
        if path.addr == addr {
            return false;
        }
        path.addr = addr;
        let on_active = self.send.active == Some(idx);
        // A standby's connected socket is its own to drop; the active one
        // is the caller's, on the `true` return.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if !on_active {
            path.clear_connected_udp();
        }
        on_active
    }

    /// Bind the peer's send side to `(transport_id, addr)` outright.
    ///
    /// The deliberate counterpart of [`set_current_addr`](Self::set_current_addr):
    /// that one is the roaming rule and never crosses transports; this one
    /// is a path change. If the peer already has a path on `transport_id`
    /// it becomes the active one at `addr`; otherwise the active path is
    /// re-pointed at the new transport, or created if there was none.
    /// Returns `true` if either the active transport or its address changed.
    pub fn rebind_transport(&mut self, transport_id: TransportId, addr: TransportAddr) -> bool {
        let changed =
            self.transport_id() != Some(transport_id) || self.current_addr() != Some(&addr);
        if !changed {
            return false;
        }
        if let Some(idx) = self
            .send
            .paths
            .iter()
            .position(|path| path.transport_id == transport_id)
        {
            self.send.paths[idx].addr = addr;
            self.send.active = Some(idx);
        } else if let Some(path) = self.send.active_path_mut() {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            path.clear_connected_udp();
            path.transport_id = transport_id;
            path.addr = addr;
        } else {
            self.send.paths.push(PeerPath::new(transport_id, addr));
            self.send.active = Some(0);
        }
        true
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

    // === Decryption Failure Tracking ===

    /// Increment consecutive decryption failure counter, returning new count.
    pub fn increment_decrypt_failures(&mut self) -> u32 {
        self.send.consecutive_decrypt_failures += 1;
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
    /// The [`quality_index`](crate::proto::mmp::quality_index) of the link's
    /// ETX and smoothed RTT.
    ///
    /// Returns 1.0 (optimistic default) when MMP metrics are not yet
    /// available, matching depth-only parent selection behavior.
    pub fn link_cost(&self) -> f64 {
        match self.mmp() {
            Some(mmp) => {
                let etx = mmp.metrics.etx;
                match mmp.metrics.srtt_ms() {
                    Some(srtt_ms) => crate::proto::mmp::quality_index(etx, srtt_ms),
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

    /// Update last seen timestamp.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.send.last_seen = current_time_ms;
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

    /// Test-only seam: backdate the session-established instant so a test can
    /// construct a session that reads as `age`-old. This only shifts the
    /// private timestamp field; it changes no decision logic, no threshold, and
    /// is compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_session_established(&mut self, age: std::time::Duration) {
        self.session_established_at = self
            .session_established_at
            .checked_sub(age)
            .unwrap_or_else(Instant::now);
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

    /// Check whether the pending session has been held for at least `hold`
    /// since it was installed. False when no pending session is held.
    pub(crate) fn pending_expired(&self, hold: Duration) -> bool {
        self.pending_since.is_some_and(|t| t.elapsed() >= hold)
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
    }

    /// Store the session this node produced by answering the peer's rekey
    /// msg1. It is held until a frame on the new epoch from the peer
    /// authenticates against it ([`handle_peer_kbit_flip`](Self::handle_peer_kbit_flip)),
    /// or until the responder hold passes and the node retires it
    /// ([`retire_pending`](Self::retire_pending)); it is never cut over on this
    /// node's own schedule.
    pub(crate) fn answer_rekey(
        &mut self,
        session: NoiseSession,
        our_index: SessionIndex,
        their_index: SessionIndex,
    ) {
        self.install_pending(session, our_index, their_index, RekeyRole::Responder);
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
    /// flips the K-bit. Returns the old our_index that should remain in peers_by_index
    /// during the drain window.
    pub fn cutover_to_new_session(&mut self) -> Option<SessionIndex> {
        let new_session = self.send.pending_new_session.take()?;
        let new_our_index = self.send.pending_our_index.take();
        let new_their_index = self.send.pending_their_index.take();
        self.pending_role = None;
        self.pending_since = None;

        // Demote current to previous
        self.send.previous_session = self.send.noise_session.take();
        self.send.previous_our_index = self.send.our_index;
        self.send.drain_started = Some(Instant::now());

        // Promote pending to current
        self.send.noise_session = Some(new_session);
        self.send.our_index = new_our_index;
        self.send.their_index = new_their_index;

        // Flip K-bit and reset timing
        self.send.current_k_bit = !self.send.current_k_bit;
        self.session_established_at = Instant::now();
        self.send.session_start = Instant::now();
        self.rekey_in_progress = false;
        self.rekey_msg1_resend_count = 0;
        self.rekey_jitter_secs = draw_rekey_jitter();
        self.reset_replay_suppressed();

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
        self.pending_role = None;
        self.pending_since = None;

        // Demote current to previous
        self.send.previous_session = self.send.noise_session.take();
        self.send.previous_our_index = self.send.our_index;
        self.send.drain_started = Some(Instant::now());

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
        self.pending_role = None;
        self.pending_since = None;
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
            self.pending_role = None;
            self.pending_since = None;
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
        assert!(!ConnectivityState::Connected.is_terminal());
        assert!(!ConnectivityState::Stale.is_terminal());
    }

    #[test]
    fn test_active_peer_creation() {
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        assert_eq!(peer.identity().node_addr(), identity.node_addr());
        assert_eq!(peer.link_id(), LinkId::new(1));
        assert!(!peer.is_disconnected());
        assert_eq!(peer.authenticated_at(), 1000);
        assert!(peer.needs_filter_update()); // New peers need filter
    }

    #[test]
    fn test_npub_cache_matches_identity() {
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        assert_eq!(peer.npub(), identity.npub());
        assert_eq!(peer.npub_str(), identity.npub());
        assert_eq!(peer.short_npub(), identity.short_npub());
    }

    #[test]
    fn test_npub_cache_matches_identity_with_session() {
        // `with_session` builds its own struct literal, so it needs its
        // own check that the cache is populated from the same identity.
        let identity = make_peer_identity();
        let (session, _peer_session) = ik_session_pair();

        let peer = ActivePeer::with_session(
            identity,
            LinkId::new(1),
            1000,
            session,
            SessionIndex::new(1),
            SessionIndex::new(2),
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:9000"),
            LinkStats::new(),
            true,
            &MmpConfig::default(),
            None,
        );

        assert_eq!(peer.npub(), identity.npub());
        assert_eq!(peer.short_npub(), identity.short_npub());
    }

    #[test]
    fn test_npub_is_memoized_not_rederived() {
        // The whole point of the fix: the strings are stored on the peer,
        // not recomputed per call. A stored string keeps one heap buffer,
        // so repeated borrows have a stable address. A per-call bech32
        // encode would hand back a fresh allocation each time.
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        let first = peer.npub_str().as_ptr();
        let second = peer.npub_str().as_ptr();
        assert_eq!(first, second);

        let short_first = peer.short_npub().as_ptr();
        let short_second = peer.short_npub().as_ptr();
        assert_eq!(short_first, short_second);
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

    #[test]
    fn test_increment_decrypt_failures_monotonic() {
        let identity = make_peer_identity();
        let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        // Initial count is zero
        assert_eq!(peer.consecutive_decrypt_failures(), 0);

        // Each call returns a strictly increasing count
        let mut prev = 0u32;
        for expected in 1..=25u32 {
            let count = peer.increment_decrypt_failures();
            assert_eq!(count, expected, "increment must return monotonic count");
            assert!(count > prev, "count must strictly increase");
            assert_eq!(peer.consecutive_decrypt_failures(), count);
            prev = count;
        }
    }

    #[test]
    fn test_reset_decrypt_failures_zeroes_counter() {
        let identity = make_peer_identity();
        let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

        // Drive counter up
        for _ in 0..7 {
            peer.increment_decrypt_failures();
        }
        assert_eq!(peer.consecutive_decrypt_failures(), 7);

        // Reset zeroes it
        peer.reset_decrypt_failures();
        assert_eq!(peer.consecutive_decrypt_failures(), 0);

        // Reset on zero is a no-op (still zero, no panic)
        peer.reset_decrypt_failures();
        assert_eq!(peer.consecutive_decrypt_failures(), 0);

        // Counter resumes at 1 after reset
        assert_eq!(peer.increment_decrypt_failures(), 1);
        assert_eq!(peer.consecutive_decrypt_failures(), 1);
    }

    #[test]
    fn test_rekey_jitter_in_range() {
        // Every newly constructed peer's jitter must lie in the
        // symmetric range [-REKEY_JITTER_SECS, +REKEY_JITTER_SECS].
        for _ in 0..100 {
            let identity = make_peer_identity();
            let peer = ActivePeer::new(identity, LinkId::new(1), 1000);
            let j = peer.rekey_jitter_secs();
            assert!(
                (-REKEY_JITTER_SECS..=REKEY_JITTER_SECS).contains(&j),
                "jitter {} outside [-{}, +{}]",
                j,
                REKEY_JITTER_SECS,
                REKEY_JITTER_SECS
            );
        }
    }

    #[test]
    fn test_rekey_jitter_mean_near_zero() {
        // Sanity check that the distribution is roughly symmetric and
        // not stuck at one extreme. With N=200 draws from a uniform
        // ~30-second-wide range, the empirical mean should be well
        // under 5 in absolute value with overwhelming probability.
        let mut sum: i64 = 0;
        let n: i64 = 200;
        for _ in 0..n {
            let identity = make_peer_identity();
            let peer = ActivePeer::new(identity, LinkId::new(1), 1000);
            sum += peer.rekey_jitter_secs();
        }
        let mean = sum / n;
        assert!(
            mean.abs() < 5,
            "empirical mean {} not within 5 of 0 over {} samples",
            mean,
            n
        );
    }

    /// Put a peer into a rekey-in-progress state with a real (initiator)
    /// handshake so the msg1 resend budget can be exercised.
    fn arm_rekey(peer: &mut ActivePeer) {
        let remote = Identity::generate();
        let local = Identity::generate();
        let hs = NoiseHandshakeState::new_initiator(local.keypair(), remote.pubkey_full());
        peer.set_rekey_state(hs, SessionIndex::new(7), vec![0xAB; 64], 0);
    }

    #[test]
    fn rekey_msg1_resend_count_increments_and_caps() {
        let identity = make_peer_identity();
        let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);
        arm_rekey(&mut peer);

        assert!(peer.rekey_in_progress());
        assert_eq!(peer.rekey_msg1_resend_count(), 0);
        assert!(peer.rekey_msg1().is_some());

        // The driver records one resend per call; the count tracks them.
        let max_resends: u32 = 5;
        for i in 0..max_resends {
            peer.record_rekey_msg1_resend(1000 + i as u64 * 100);
            assert_eq!(peer.rekey_msg1_resend_count(), i + 1);
        }
        assert_eq!(peer.rekey_msg1_resend_count(), max_resends);
    }

    #[test]
    fn rekey_msg1_budget_exhaustion_abandons_cleanly() {
        let identity = make_peer_identity();
        let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);
        arm_rekey(&mut peer);

        // Simulate the driver exhausting its budget.
        let max_resends: u32 = 5;
        for i in 0..max_resends {
            peer.record_rekey_msg1_resend(1000 + i as u64 * 100);
        }
        assert_eq!(peer.rekey_msg1_resend_count(), max_resends);

        // Budget exhausted -> abandon: state clears and the counter resets.
        peer.abandon_rekey();
        assert!(!peer.rekey_in_progress());
        assert!(peer.rekey_msg1().is_none());
        assert_eq!(peer.rekey_msg1_resend_count(), 0);
    }

    // === FMP rekey cutover: authenticate-before-promote ===
    //
    // IK-adapted analogue of the FSP trial-decrypt tests
    // (node/session/mod.rs `trial_decrypt_picks_pending_and_promotes` /
    // `trial_decrypt_failed_slot_leaves_replay_window_intact`). The FMP
    // cutover is gated on an authenticated decrypt against `pending`, not
    // the bare header K-bit. These tests exercise that primitive:
    // `pending_new_session_mut()` trial-decrypt followed by
    // `handle_peer_kbit_flip()` promotion.

    /// Complete an IK handshake and return the (sender, receiver) session
    /// pair. The receiver decrypts what the sender seals.
    fn ik_session_pair() -> (NoiseSession, NoiseSession) {
        let initiator_id = Identity::generate();
        let responder_id = Identity::generate();
        let mut initiator =
            NoiseHandshakeState::new_initiator(initiator_id.keypair(), responder_id.pubkey_full());
        initiator.set_local_epoch([0xA1, 0xB2, 0xC3, 0xD4, 0x11, 0x22, 0x33, 0x44]);
        let mut responder = NoiseHandshakeState::new_responder(responder_id.keypair());
        responder.set_local_epoch([0xD4, 0xC3, 0xB2, 0xA1, 0x44, 0x33, 0x22, 0x11]);

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let msg2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&msg2).unwrap();

        (
            initiator.into_session().unwrap(),
            responder.into_session().unwrap(),
        )
    }

    /// Seal an FMP frame the way the send path does: returns
    /// `(ciphertext, counter, header_bytes)` for the given K-bit.
    fn seal_fmp(
        sender: &mut NoiseSession,
        receiver_idx: SessionIndex,
        plaintext: &[u8],
        k_bit: bool,
    ) -> (Vec<u8>, u64, [u8; 16]) {
        use crate::proto::fmp::wire::{FLAG_KEY_EPOCH, build_established_header};
        let counter = sender.current_send_counter();
        let flags = if k_bit { FLAG_KEY_EPOCH } else { 0 };
        let header = build_established_header(receiver_idx, counter, flags, plaintext.len() as u16);
        let ciphertext = sender.encrypt_with_aad(plaintext, &header).unwrap();
        (ciphertext, counter, header)
    }

    /// Build a peer whose `current` slot is `current_recv`.
    fn peer_with_current(current_recv: NoiseSession) -> ActivePeer {
        let identity = make_peer_identity();
        ActivePeer::with_session(
            identity,
            LinkId::new(1),
            1_000,
            current_recv,
            SessionIndex::new(1),
            SessionIndex::new(2),
            TransportId::new(1),
            TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:01"),
            LinkStats::new(),
            true,
            &MmpConfig::default(),
            None,
        )
    }

    // A genuine new-epoch frame authenticates against `pending` and the
    // peer promotes: pending -> current, K-bit flips, plaintext delivered.
    #[test]
    fn cutover_pending_authenticates_and_promotes() {
        let (_cur_send, cur_recv) = ik_session_pair();
        let (mut pend_send, pend_recv) = ik_session_pair();

        let mut peer = peer_with_current(cur_recv);
        let k_before = peer.current_k_bit();
        peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));

        // Peer sealed in the new epoch with the flipped K-bit.
        let (ct, counter, hdr) = seal_fmp(
            &mut pend_send,
            SessionIndex::new(3),
            b"new-epoch",
            !k_before,
        );

        // Trial-decrypt against pending succeeds (the cutover signal).
        let plaintext = peer
            .pending_new_session_mut()
            .and_then(|p| p.decrypt_with_replay_check_and_aad(&ct, counter, &hdr).ok())
            .expect("new-epoch frame must authenticate against pending");
        assert_eq!(plaintext, b"new-epoch");

        // Promotion moves pending -> current and flips the K-bit.
        assert!(peer.handle_peer_kbit_flip().is_some());
        assert!(peer.pending_new_session().is_none());
        assert_eq!(peer.current_k_bit(), !k_before);
        assert!(peer.previous_session().is_some());
    }

    // A stale/mismatched frame on a K-bit flip does NOT authenticate
    // against `pending`: no promotion, `pending` preserved with its replay
    // window intact, and the genuine current session still decrypts a
    // subsequent steady-state frame.
    #[test]
    fn cutover_stale_frame_does_not_promote() {
        let (mut cur_send, cur_recv) = ik_session_pair();
        let (_pend_send, pend_recv) = ik_session_pair();
        // A third, unrelated session whose ciphertext will NOT authenticate
        // against `pending` (wrong keys) — simulates a flip belonging to a
        // different rekey epoch.
        let (mut stale_send, _stale_recv) = ik_session_pair();

        let mut peer = peer_with_current(cur_recv);
        let k_before = peer.current_k_bit();
        peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));

        // Frame carries the flipped K-bit but is sealed in an unrelated
        // session: it must fail to authenticate against `pending`.
        let (ct, counter, hdr) =
            seal_fmp(&mut stale_send, SessionIndex::new(3), b"stale", !k_before);
        let result = peer
            .pending_new_session_mut()
            .and_then(|p| p.decrypt_with_replay_check_and_aad(&ct, counter, &hdr).ok());
        assert!(
            result.is_none(),
            "stale frame must not authenticate against pending"
        );

        // No promotion happened: pending preserved, K-bit unchanged.
        assert!(peer.pending_new_session().is_some());
        assert_eq!(peer.current_k_bit(), k_before);

        // The trial-decrypt left pending's replay window untouched, and the
        // genuine current session still decrypts steady-state traffic — the
        // fall-through path the handler takes on a non-authenticating flip.
        let (ct2, counter2, hdr2) =
            seal_fmp(&mut cur_send, SessionIndex::new(1), b"steady", k_before);
        let cur_pt = peer.noise_session_mut().and_then(|s| {
            s.decrypt_with_replay_check_and_aad(&ct2, counter2, &hdr2)
                .ok()
        });
        assert_eq!(cur_pt.as_deref(), Some(&b"steady"[..]));
    }

    /// Retiring a pending session this node answered hands back its index for
    /// the caller to free, empties the pending slot and its role, and leaves
    /// the current session alone.
    #[test]
    fn retiring_an_answered_pending_returns_its_index_and_empties_the_slot() {
        let (_cur_send, cur_recv) = ik_session_pair();
        let (_pend_send, pend_recv) = ik_session_pair();
        let mut peer = peer_with_current(cur_recv);
        peer.answer_rekey(pend_recv, SessionIndex::new(3), SessionIndex::new(4));
        assert_eq!(peer.pending_role(), Some(RekeyRole::Responder));

        assert_eq!(peer.retire_pending(), Some(SessionIndex::new(3)));
        assert!(peer.pending_new_session().is_none());
        assert_eq!(peer.pending_role(), None);
        assert_eq!(peer.pending_their_index(), None);
        assert_eq!(peer.pending_our_index(), None);
        assert!(peer.noise_session().is_some());
        assert_eq!(peer.our_index(), Some(SessionIndex::new(1)));
    }

    /// Retirement leaves a pending session this node initiated in place: that
    /// one is cut over on this node's schedule, never retired.
    #[test]
    fn retire_leaves_a_pending_this_node_initiated_in_place() {
        let (_cur_send, cur_recv) = ik_session_pair();
        let (_pend_send, pend_recv) = ik_session_pair();
        let mut peer = peer_with_current(cur_recv);
        peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));
        assert_eq!(peer.pending_role(), Some(RekeyRole::Initiator));

        assert_eq!(peer.retire_pending(), None);
        assert!(peer.pending_new_session().is_some());
        assert_eq!(peer.pending_role(), Some(RekeyRole::Initiator));
    }

    /// Promoting an answered pending session on the peer's first new-epoch
    /// frame clears its role and install time with the slot.
    #[test]
    fn promotion_on_the_peers_new_epoch_frame_clears_the_pending_role() {
        let (_cur_send, cur_recv) = ik_session_pair();
        let (_pend_send, pend_recv) = ik_session_pair();
        let mut peer = peer_with_current(cur_recv);
        peer.answer_rekey(pend_recv, SessionIndex::new(3), SessionIndex::new(4));

        assert!(peer.handle_peer_kbit_flip().is_some());
        assert_eq!(peer.pending_role(), None);
        assert!(!peer.pending_expired(Duration::ZERO));
    }

    /// The pending hold is measured from the install time: not expired inside
    /// the hold, expired once the install time is older than it.
    #[test]
    fn pending_expiry_reads_the_install_time_against_the_hold() {
        let (_cur_send, cur_recv) = ik_session_pair();
        let (_pend_send, pend_recv) = ik_session_pair();
        let mut peer = peer_with_current(cur_recv);
        peer.answer_rekey(pend_recv, SessionIndex::new(3), SessionIndex::new(4));

        assert!(!peer.pending_expired(Duration::from_secs(60)));
        peer.backdate_pending(Duration::from_secs(61));
        assert!(peer.pending_expired(Duration::from_secs(60)));
    }
}
