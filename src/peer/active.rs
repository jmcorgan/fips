//! Active Peer (Authenticated Phase)
//!
//! Represents a fully authenticated peer after successful Noise handshake.
//! ActivePeer holds tree state, Bloom filter, and routing information.

use crate::config::{MmpConfig, TransportRole};
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
use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

/// How often a full-size (MTU-padded) probe goes out on a proven path.
const FULL_SIZE_PROBE_INTERVAL_MS: u64 = 60_000;

/// Fold one probe outcome into a path's ETX: the long EWMA (α = 1/32) of
/// the delivery ratio, inverted and clamped like the link ETX. Per report a
/// raw value is a flap generator on a lightly loaded link; the long average
/// is what selection reads.
fn smooth_etx(etx: f64, delivered: bool) -> f64 {
    let alpha = crate::proto::mmp::EWMA_LONG_ALPHA;
    let ratio = (1.0 / etx).clamp(0.01, 1.0);
    let sample = if delivered { 1.0 } else { 0.0 };
    let next = ratio + alpha * (sample - ratio);
    (1.0 / next.max(0.01)).clamp(1.0, 100.0)
}

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

/// Where a path is in its life. See `docs/design/fips-multi-path-switchover.md` §4, §7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathState {
    /// Added, probe outstanding or never answered. Never eligible to carry
    /// traffic: an unmeasured path is not assumed good.
    Probing,
    /// The peer has acknowledged a probe on this path: both directions work.
    Live,
    /// A hard signal (carrier, send error, failed ack) says the path may be
    /// gone. Selection acts on this at once because the standby is warm.
    Suspect,
    /// Confirmed gone. Kept with its history so a returning transport does
    /// not start from scratch.
    Dead,
}

/// Probe bookkeeping for one path: what is outstanding, and when the next
/// one may go.
#[derive(Clone, Copy, Debug, Default)]
struct ProbeState {
    /// The next `probe_id` to use. Per path, both directions.
    next_id: u32,
    /// `(probe_id, sent_at_ms)` of the probe awaiting its ack.
    outstanding: Option<(u32, u64)>,
    /// `(probe_id, sent_at_ms)` of the last probe whose echo timed out.
    /// Its ack is still an ack: on a medium whose round trip exceeds the
    /// timeout floor (Tor, Nym, satellite) the first echo is always late,
    /// and discarding it would leave the path unmeasured, so the timeout
    /// never stretches and the path never proves itself.
    timed_out: Option<(u32, u64)>,
    /// Probes sent since the last ack, for the backoff.
    unanswered: u32,
    /// Earliest monotonic ms at which another probe may be sent.
    next_at_ms: u64,
}

/// The knobs selection is bounded by. Built from `node.path.*`.
#[derive(Clone, Copy, Debug)]
pub struct PathPolicy {
    /// Discretionary switch margin `K`.
    pub margin: f64,
    /// Discretionary switch dwell `D`, ms.
    pub dwell_ms: u64,
    /// RTT samples `N` a path needs before it is selectable.
    pub min_samples: u32,
    /// The min-RTT window, ms. At least `N` standby heartbeat intervals,
    /// otherwise a standby never accumulates a min.
    pub rtt_window_ms: u64,
}

impl PathPolicy {
    /// Everything selectable at once; for tests.
    pub const PERMISSIVE: Self = Self {
        margin: 1.5,
        dwell_ms: 0,
        min_samples: 0,
        rtt_window_ms: u64::MAX,
    };
}

/// A post-switch hold on the link cost the tree sees.
#[derive(Clone, Copy, Debug)]
struct CostHold {
    /// The cost as it was at the switch.
    cost: f64,
    /// Monotonic ms the dwell runs to.
    until_ms: u64,
    /// Receiver reports still to arrive before the hold may release: the
    /// one that spans the switch, and the one that replaces its ETX.
    reports_pending: u8,
}

/// Why selection moved the active path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchReason {
    /// The active path was not `tx_live`: switched at once, no margin.
    Mandatory,
    /// The active path scored worse than the best standby by the margin,
    /// for the dwell.
    Discretionary,
    /// The operator pinned another path.
    Pinned,
}

/// The intervals [`ActivePeer::plan_heartbeats`] runs on, all in ms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeartbeatTiming {
    /// Interval on a path either side sends on.
    pub fast_ms: u64,
    /// Interval on a standby.
    pub slow_ms: u64,
    /// Echo timeout floor; stretched per path by its round trip.
    pub timeout_ms: u64,
    /// Ceiling on the discovery backoff of a path the peer has never
    /// acknowledged: an old node, or a medium the peer cannot hear us on.
    /// Every such probe is full-size, so this bounds a permanent cost.
    pub discovery_cap_ms: u64,
}

/// One heartbeat probe to put on the wire, from
/// [`ActivePeer::plan_heartbeats`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeartbeatSend {
    pub transport_id: TransportId,
    pub addr: TransportAddr,
    pub probe_id: u32,
    /// Whether this is the path we send on.
    pub remote_active: bool,
    /// Our identifier for the path.
    pub path_id: u32,
    /// Pad this probe to the link MTU: the first probe on a path, and one a
    /// minute after, so a medium that forwards small frames and drops large
    /// ones never proves itself.
    pub full_size: bool,
}

/// What one pass of [`ActivePeer::plan_heartbeats`] decided.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeartbeatPlan {
    /// Probes to send now.
    pub sends: Vec<HeartbeatSend>,
    /// Paths whose outstanding probe timed out and went `Suspect`.
    pub suspects: Vec<TransportId>,
}

/// Selection moved the active path from `from` to `to`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathSwitch {
    pub from: (TransportId, TransportAddr),
    pub to: (TransportId, TransportAddr),
    pub reason: SwitchReason,
}

/// What withdrawing a path did to the peer's send side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathWithdrawal {
    /// The peer had no path on that transport.
    NoPath,
    /// A standby went `Dead`; traffic was never on it.
    Standby,
    /// The active path went `Dead` and an eligible path took over.
    Switched {
        from: (TransportId, TransportAddr),
        to: (TransportId, TransportAddr),
    },
    /// The active path went `Dead` and nothing eligible remains: the peer
    /// is unreachable and the caller reaps it.
    NoAlternative,
}

/// One transport-level path to a peer.
///
/// Path identity is the transport instance: one transport holds at most one
/// path to a given peer, and an address roams *inside* a path. Everything
/// that is per session (Noise slots, K-bit, indices, rekey state) stays on
/// the peer; a path carries only what is bound to the medium it runs over.
/// See `docs/design/fips-multi-path-switchover.md` §1–2.
///
/// The first path is added at promotion, proven by the handshake. Further
/// ones are added by the probe exchange under the existing session (§4).
#[derive(Debug)]
pub struct PeerPath {
    /// The transport instance this path runs over.
    transport_id: TransportId,
    /// The peer's current address on that transport (roams).
    addr: TransportAddr,
    state: PathState,
    /// Monotonic ms of the last authentic frame heard on this path. Free:
    /// any authentic frame proves the peer can reach us here.
    rx_live_at_ms: Option<u64>,
    /// Monotonic ms of the last ack proving the peer hears us here. Needs
    /// the echo: hearing the peer is a hint, not proof our direction works.
    tx_live_at_ms: Option<u64>,
    /// The peer's last word on whether this is the path it sends on.
    remote_active: bool,
    /// Most recent probe round trip on this path, ms.
    last_rtt_ms: Option<u64>,
    /// When the path went `Dead`, for the history grace period.
    dead_since_ms: Option<u64>,
    probe: ProbeState,
    /// `(sampled_at_ms, rtt_ms)` probe round trips inside the min-RTT
    /// window. Min, not smoothed: srtt inflates under load (wifi
    /// bufferbloat) while an idle standby looks pristine, which is a
    /// ping-pong generator; min RTT is a property of the medium.
    rtt_window: VecDeque<(u64, u64)>,
    /// Per-path expected transmission count, from the probe/heartbeat ack
    /// ratio, long-EWMA smoothed. 1.0 until measured.
    etx: f64,
    /// Whether the peer has ever acknowledged a probe on this path. Gates
    /// the failed-echo signal: a peer that never answers probes is an old
    /// node, not a dead path.
    acked_once: bool,
    /// From the transport's config: a `Backup` path never carries traffic
    /// while a `Normal` one is eligible.
    role: TransportRole,
    /// Our identifier for this path, carried in every probe and ack we
    /// send on it, so the peer can name it in a `PathClose`.
    local_id: u32,
    /// The peer's identifier for its side of this path, learned from its
    /// probes and acks.
    remote_id: Option<u32>,
    /// When a full-size probe last went out on this path.
    last_full_probe_ms: Option<u64>,
    /// Operator override: wins selection while it is `tx_live`.
    pinned: bool,

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
    fn new(transport_id: TransportId, addr: TransportAddr, state: PathState) -> Self {
        Self {
            transport_id,
            addr,
            state,
            rx_live_at_ms: None,
            tx_live_at_ms: None,
            remote_active: false,
            last_rtt_ms: None,
            dead_since_ms: None,
            probe: ProbeState::default(),
            rtt_window: VecDeque::new(),
            etx: 1.0,
            acked_once: false,
            role: TransportRole::Normal,
            local_id: rand::rng().random::<u32>(),
            remote_id: None,
            last_full_probe_ms: None,
            pinned: false,
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

    /// Where the path is in its life.
    pub fn state(&self) -> PathState {
        self.state
    }

    /// Monotonic ms of the last authentic frame heard on this path.
    pub fn rx_live_at_ms(&self) -> Option<u64> {
        self.rx_live_at_ms
    }

    /// Monotonic ms of the last ack proving the peer hears us here.
    pub fn tx_live_at_ms(&self) -> Option<u64> {
        self.tx_live_at_ms
    }

    /// Whether the peer last said it sends on this path.
    pub fn remote_active(&self) -> bool {
        self.remote_active
    }

    /// Most recent probe round trip on this path, ms.
    pub fn last_rtt_ms(&self) -> Option<u64> {
        self.last_rtt_ms
    }

    /// Whether the path may carry our traffic: `Live`, and the peer has
    /// acknowledged hearing us on it.
    pub fn is_eligible(&self) -> bool {
        self.state == PathState::Live && self.tx_live_at_ms.is_some()
    }

    /// The transport's role, from its config.
    pub fn role(&self) -> TransportRole {
        self.role
    }

    /// Record the transport's role.
    pub fn set_role(&mut self, role: TransportRole) {
        self.role = role;
    }

    /// Whether the operator pinned traffic to this path.
    pub fn pinned(&self) -> bool {
        self.pinned
    }

    /// Whether the peer has ever acknowledged a probe here.
    pub fn acked_once(&self) -> bool {
        self.acked_once
    }

    /// Our identifier for this path on the wire.
    pub fn local_id(&self) -> u32 {
        self.local_id
    }

    /// The peer's identifier for its side of this path, once heard.
    pub fn remote_id(&self) -> Option<u32> {
        self.remote_id
    }

    /// Minimum probe round trip inside the window, ms.
    pub fn min_rtt_ms(&self) -> Option<u64> {
        self.rtt_window.iter().map(|(_, rtt)| *rtt).min()
    }

    /// RTT samples inside the window.
    pub fn rtt_samples(&self) -> u32 {
        self.rtt_window.len() as u32
    }

    /// Per-path expected transmission count, smoothed.
    pub fn etx(&self) -> f64 {
        self.etx
    }

    /// The path's quality index, [`quality_index`](crate::proto::mmp::quality_index)
    /// of its ETX and min RTT, lower is better. `None` until an RTT has been
    /// measured.
    pub fn score(&self) -> Option<f64> {
        self.min_rtt_ms()
            .map(|rtt| crate::proto::mmp::quality_index(self.etx, rtt as f64))
    }

    /// Whether selection may pick this path: eligible, with enough samples,
    /// per `policy`.
    pub fn is_selectable(&self, policy: &PathPolicy) -> bool {
        self.is_eligible() && self.rtt_samples() >= policy.min_samples
    }

    fn record_rtt(&mut self, now_ms: u64, rtt_ms: u64, window_ms: u64) {
        self.rtt_window.push_back((now_ms, rtt_ms));
        while let Some((at, _)) = self.rtt_window.front() {
            if now_ms.saturating_sub(*at) > window_ms {
                self.rtt_window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Whether a probe may be sent now, per the backoff.
    pub fn probe_due(&self, now_ms: u64) -> bool {
        now_ms >= self.probe.next_at_ms
    }

    /// Reset the probe backoff so the next tick may probe at once. Called
    /// when the transport's presence cycles: the medium has changed, so what
    /// went unanswered before says nothing about now.
    pub fn reset_probe_backoff(&mut self) {
        self.probe.unanswered = 0;
        self.probe.next_at_ms = 0;
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
    /// When the active path first scored worse than the best standby by
    /// the margin; the discretionary dwell counts from here.
    discretionary_since_ms: Option<u64>,
    /// The link cost reported to the tree is held at its pre-switch value
    /// after a switch, so a short switch (cable flap, replug) does not
    /// ripple mesh-wide (design §10). Released once the dwell has passed
    /// *and* the receiver reports that span the switch have been replaced:
    /// the first report after a switch counts every frame in flight on the
    /// old path as lost and spikes the per-report ETX for one interval,
    /// and that spike must not reach parent selection.
    cost_hold: Option<CostHold>,
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
            discretionary_since_ms: None,
            cost_hold: None,
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
        let mut path = PeerPath::new(transport_id, current_addr, PathState::Live);
        let now_ms = crate::time::mono_ms();
        path.rx_live_at_ms = Some(now_ms);
        path.tx_live_at_ms = Some(now_ms);
        send.paths.push(path);
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
            self.send
                .paths
                .push(PeerPath::new(transport_id, addr, PathState::Live));
            self.send.active = Some(0);
        }
        true
    }

    // === Path set ===

    /// The path on `transport_id`, if the peer has one.
    pub fn path_on(&self, transport_id: TransportId) -> Option<&PeerPath> {
        self.send
            .paths
            .iter()
            .find(|path| path.transport_id == transport_id)
    }

    fn path_on_mut(&mut self, transport_id: TransportId) -> Option<&mut PeerPath> {
        self.send
            .paths
            .iter_mut()
            .find(|path| path.transport_id == transport_id)
    }

    /// Add a `Probing` path on `transport_id` at `addr`, or return the one
    /// already there. The only way a path is created after promotion: both
    /// ends of the probe exchange call this, the prober before it sends and
    /// the receiver when a probe arrives.
    pub fn add_path(&mut self, transport_id: TransportId, addr: TransportAddr) -> &mut PeerPath {
        let idx = match self
            .send
            .paths
            .iter()
            .position(|path| path.transport_id == transport_id)
        {
            Some(idx) => idx,
            None => {
                self.send
                    .paths
                    .push(PeerPath::new(transport_id, addr, PathState::Probing));
                self.send.paths.len() - 1
            }
        };
        &mut self.send.paths[idx]
    }

    /// An authentic frame arrived on `transport_id`: the path there, if any,
    /// is `rx_live` as of `now_ms`.
    pub fn note_path_rx(&mut self, transport_id: TransportId, now_ms: u64) {
        if let Some(path) = self.path_on_mut(transport_id) {
            path.rx_live_at_ms = Some(now_ms);
        }
    }

    /// Take the next probe to send on `transport_id`: its `probe_id`, and
    /// whether the path is the one we send on. Records it as outstanding and
    /// advances the backoff; `None` if the peer has no path there or the
    /// backoff has not expired. `backoff_cap_ms` bounds the retry interval,
    /// which doubles from `base_ms` per unanswered probe.
    ///
    /// Tests only. In production [`plan_heartbeats`](Self::plan_heartbeats)
    /// is the one issuer of probes, so no two writers race for
    /// `probe.outstanding`.
    #[cfg(test)]
    pub fn take_probe(
        &mut self,
        transport_id: TransportId,
        now_ms: u64,
        base_ms: u64,
        backoff_cap_ms: u64,
    ) -> Option<(u32, bool, u32)> {
        let active = self.transport_id() == Some(transport_id);
        let path = self.path_on_mut(transport_id)?;
        if !path.probe_due(now_ms) {
            return None;
        }
        let id = path.probe.next_id;
        path.probe.next_id = path.probe.next_id.wrapping_add(1);
        path.probe.outstanding = Some((id, now_ms));
        let shift = path.probe.unanswered.min(16);
        let delay = base_ms.saturating_mul(1u64 << shift).min(backoff_cap_ms);
        path.probe.next_at_ms = now_ms.saturating_add(delay.max(1));
        path.probe.unanswered = path.probe.unanswered.saturating_add(1);
        let path_id = path.local_id;
        Some((id, active, path_id))
    }

    /// A `PathProbe` arrived on `transport_id` from `addr`. Adds the path if
    /// it is new, roams its address if not, marks it `rx_live` and records
    /// what the peer said about sending here.
    pub fn note_path_probe(
        &mut self,
        transport_id: TransportId,
        addr: TransportAddr,
        remote_active: bool,
        remote_id: u32,
        now_ms: u64,
    ) {
        let path = self.add_path(transport_id, addr.clone());
        if path.addr != addr {
            path.addr = addr;
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            path.clear_connected_udp();
        }
        path.remote_id = Some(remote_id);
        if path.state == PathState::Dead {
            // The peer is probing a path we had given up on: it is back,
            // unproven in our direction until its ack.
            path.state = PathState::Probing;
            path.dead_since_ms = None;
        }
        path.rx_live_at_ms = Some(now_ms);
        if path.remote_active && !remote_active {
            // The peer stopped sending here. It may have stopped hearing us
            // here too: a hint, so probe now, never `Suspect` (design §7).
            path.probe.next_at_ms = 0;
        }
        path.remote_active = remote_active;
    }

    /// A `PathAck` arrived on `transport_id`. If it answers the outstanding
    /// probe, or the one whose echo last timed out, the path is `tx_live`
    /// and `Live`, the backoff is cleared and the round trip is sampled.
    /// Returns the RTT sample in ms, or `None` if the ack matched nothing
    /// (a stale or duplicate ack is ignored).
    pub fn note_path_ack(
        &mut self,
        transport_id: TransportId,
        probe_id: u32,
        remote_active: bool,
        remote_id: u32,
        now_ms: u64,
        rtt_window_ms: u64,
    ) -> Option<u64> {
        let path = self.path_on_mut(transport_id)?;
        path.remote_id = Some(remote_id);
        let sent_at_ms = match (path.probe.outstanding, path.probe.timed_out) {
            (Some((id, at)), _) if id == probe_id => {
                path.probe.outstanding = None;
                at
            }
            (_, Some((id, at))) if id == probe_id => {
                path.probe.timed_out = None;
                at
            }
            _ => return None,
        };
        path.probe.unanswered = 0;
        let rtt_ms = now_ms.saturating_sub(sent_at_ms);
        path.last_rtt_ms = Some(rtt_ms);
        path.record_rtt(now_ms, rtt_ms, rtt_window_ms);
        path.acked_once = true;
        path.etx = smooth_etx(path.etx, true);
        path.rx_live_at_ms = Some(now_ms);
        path.tx_live_at_ms = Some(now_ms);
        path.remote_active = remote_active;
        path.state = PathState::Live;
        path.dead_since_ms = None;
        Some(rtt_ms)
    }

    /// Whether the peer has a path on `transport_id` at `addr`, whichever
    /// path it is. The msg1 classifier asks this: a rekey from the peer
    /// arrives on the path *the peer* sends on, which need not be ours.
    pub fn is_reachable_at(&self, transport_id: TransportId, addr: &TransportAddr) -> bool {
        self.path_on(transport_id)
            .is_some_and(|path| path.addr == *addr)
    }

    /// The transport `transport_id` went away: the path on it is `Dead`.
    ///
    /// The path keeps its history (RTT, liveness marks) so a returning
    /// transport is re-probed rather than re-measured from nothing; the
    /// history expires with [`prune_dead_paths`](Self::prune_dead_paths).
    /// If the withdrawn path was the active one, the best eligible path takes
    /// over: `Live` and `tx_live`, lowest last RTT first. With no eligible
    /// path the active index is left where it was, the path is `Suspect`
    /// rather than `Dead` so it keeps being probed, and the caller decides;
    /// a `Probing` path is never promoted, because nothing has proven it
    /// carries anything.
    pub fn withdraw_path(
        &mut self,
        transport_id: TransportId,
        now_ms: u64,
        policy: &PathPolicy,
    ) -> PathWithdrawal {
        let Some(idx) = self
            .send
            .paths
            .iter()
            .position(|path| path.transport_id == transport_id)
        else {
            return PathWithdrawal::NoPath;
        };
        {
            let path = &mut self.send.paths[idx];
            path.state = PathState::Dead;
            path.dead_since_ms = Some(now_ms);
            path.probe.outstanding = None;
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            path.clear_connected_udp();
        }
        if self.send.active != Some(idx) {
            return PathWithdrawal::Standby;
        }
        let from = {
            let path = &self.send.paths[idx];
            (path.transport_id, path.addr.clone())
        };
        match self.best_alternative(idx, policy) {
            Some(next) => {
                self.hold_link_cost(now_ms, policy.dwell_ms);
                self.send.active = Some(next);
                let path = &self.send.paths[next];
                PathWithdrawal::Switched {
                    from,
                    to: (path.transport_id, path.addr.clone()),
                }
            }
            None => {
                // Nothing to move to. The caller either reaps the peer
                // (transport gone) or keeps it (advisory close): in the
                // latter case the path must stay probed, and only a
                // non-`Dead` path is, so it is `Suspect`, not `Dead`.
                let path = &mut self.send.paths[idx];
                path.state = PathState::Suspect;
                path.dead_since_ms = None;
                PathWithdrawal::NoAlternative
            }
        }
    }

    /// The best selectable path other than `exclude`, with its score:
    /// `Normal` before `Backup`, then lowest score; a selectable path with
    /// no score yet ranks last. The one rule both selection and withdrawal
    /// pick by. A `Backup` is offered only while no selectable `Normal`
    /// path exists at all, `exclude` included: a `Normal` active path is
    /// never left for a `Backup`, however it scores.
    fn best_selectable(&self, exclude: usize, policy: &PathPolicy) -> Option<(usize, Option<f64>)> {
        let any_normal = self
            .send
            .paths
            .iter()
            .any(|p| p.is_selectable(policy) && p.role == TransportRole::Normal);
        self.send
            .paths
            .iter()
            .enumerate()
            .filter(|(i, p)| *i != exclude && p.is_selectable(policy))
            .filter(|(_, p)| p.role == TransportRole::Normal || !any_normal)
            .min_by(|(_, a), (_, b)| {
                a.score()
                    .unwrap_or(f64::MAX)
                    .total_cmp(&b.score().unwrap_or(f64::MAX))
            })
            .map(|(i, p)| (i, p.score()))
    }

    /// The best path other than `exclude` to move traffic to, if any.
    ///
    /// Selectable paths first ([`best_selectable`](Self::best_selectable));
    /// failing that, any eligible path by last RTT: a `Live` path with
    /// fewer than `N` samples beats no path. A `Probing` path is never
    /// returned.
    fn best_alternative(&self, exclude: usize, policy: &PathPolicy) -> Option<usize> {
        if let Some((i, _)) = self.best_selectable(exclude, policy) {
            return Some(i);
        }
        let candidates = || {
            self.send
                .paths
                .iter()
                .enumerate()
                .filter(move |(i, p)| *i != exclude && p.is_eligible())
        };
        let any_normal = candidates().any(|(_, p)| p.role == TransportRole::Normal);
        candidates()
            .filter(|(_, p)| p.role == TransportRole::Normal || !any_normal)
            .min_by_key(|(_, p)| p.last_rtt_ms.unwrap_or(u64::MAX))
            .map(|(i, _)| i)
    }

    /// Run selection over the path set (design §8). Returns the switch if
    /// the active path changed.
    ///
    /// - **Pinned:** a pinned path wins while it is `tx_live`.
    /// - **Mandatory:** active path not `tx_live` (`Suspect`/`Dead`) →
    ///   best alternative now, no margin, no dwell.
    /// - **Discretionary:** `active.score > best.score × K`, sustained for
    ///   the dwell → switch. Only selectable paths compete here, and only
    ///   when the active path itself has a score.
    /// - Ties keep the current path.
    pub fn select_path(&mut self, now_ms: u64, policy: &PathPolicy) -> Option<PathSwitch> {
        let active = self.send.active?;
        let pinned = self
            .send
            .paths
            .iter()
            .position(|p| p.pinned && p.is_eligible());
        if let Some(pin) = pinned {
            if pin == active {
                self.send.discretionary_since_ms = None;
                return None;
            }
            self.hold_link_cost(now_ms, policy.dwell_ms);
            return Some(self.switch_to(active, pin, SwitchReason::Pinned));
        }
        if !self.send.paths[active].is_eligible() {
            let next = self.best_alternative(active, policy)?;
            self.hold_link_cost(now_ms, policy.dwell_ms);
            return Some(self.switch_to(active, next, SwitchReason::Mandatory));
        }
        let Some(active_score) = self.send.paths[active].score() else {
            self.send.discretionary_since_ms = None;
            return None;
        };
        let Some((next, Some(best_score))) = self.best_selectable(active, policy) else {
            self.send.discretionary_since_ms = None;
            return None;
        };
        // A `Backup` active path yields to a selectable `Normal` one outright:
        // its role says it should not be carrying traffic at all.
        let active_is_backup_yielding = self.send.paths[active].role == TransportRole::Backup
            && self.send.paths[next].role == TransportRole::Normal;
        if !active_is_backup_yielding && active_score <= best_score * policy.margin {
            self.send.discretionary_since_ms = None;
            return None;
        }
        let since = *self.send.discretionary_since_ms.get_or_insert(now_ms);
        if !active_is_backup_yielding && now_ms.saturating_sub(since) < policy.dwell_ms {
            return None;
        }
        self.hold_link_cost(now_ms, policy.dwell_ms);
        Some(self.switch_to(active, next, SwitchReason::Discretionary))
    }

    /// Whether a post-switch cost hold is in force at `now_ms`.
    pub fn link_cost_held(&self, now_ms: u64) -> bool {
        self.send
            .cost_hold
            .is_some_and(|hold| now_ms < hold.until_ms || hold.reports_pending > 0)
    }

    /// A receiver report arrived: one fewer to wait for before a
    /// post-switch cost hold may release.
    pub fn note_receiver_report(&mut self) {
        if let Some(hold) = self.send.cost_hold.as_mut() {
            hold.reports_pending = hold.reports_pending.saturating_sub(1);
        }
    }

    fn switch_to(&mut self, from: usize, to: usize, reason: SwitchReason) -> PathSwitch {
        self.send.discretionary_since_ms = None;
        let from_path = &self.send.paths[from];
        let from_key = (from_path.transport_id, from_path.addr.clone());
        self.send.active = Some(to);
        let to_path = &self.send.paths[to];
        PathSwitch {
            from: from_key,
            to: (to_path.transport_id, to_path.addr.clone()),
            reason,
        }
    }

    /// Pin traffic to the path on `transport_id`. Returns `false` if the
    /// peer has no path there. Selection honours the pin on its next run.
    pub fn pin_path(&mut self, transport_id: TransportId) -> bool {
        let Some(idx) = self
            .send
            .paths
            .iter()
            .position(|p| p.transport_id == transport_id)
        else {
            return false;
        };
        for (i, p) in self.send.paths.iter_mut().enumerate() {
            p.pinned = i == idx;
        }
        true
    }

    /// Clear any pin.
    pub fn unpin_paths(&mut self) {
        for p in self.send.paths.iter_mut() {
            p.pinned = false;
        }
    }

    /// Record the transport's role on the path over `transport_id`.
    pub fn set_path_role(&mut self, transport_id: TransportId, role: TransportRole) {
        if let Some(path) = self.path_on_mut(transport_id) {
            path.role = role;
        }
    }

    /// A hard signal (carrier lost, unreachable on send) says the path on
    /// `transport_id` may be gone: `Suspect`, so selection leaves it now
    /// and a later ack restores it. Only a `Live` path can become suspect.
    pub fn mark_path_suspect(&mut self, transport_id: TransportId) -> bool {
        match self.path_on_mut(transport_id) {
            Some(path) if path.state == PathState::Live => {
                path.state = PathState::Suspect;
                true
            }
            _ => false,
        }
    }

    /// Decide this tick's per-path heartbeats (design §7).
    ///
    /// Every path that is not `Dead` is heartbeated with a `PathProbe`
    /// whose `probe_id` is the path's sequence: fast (`fast_ms`) on a path
    /// that either side sends on, slow (`slow_ms`) on a standby, one probe
    /// in flight per path. A probe unanswered for `timeout_ms` is a failed
    /// echo: on a path the peer has acknowledged before, that is a hard
    /// signal and the path goes `Suspect` (a never-acknowledged path is an
    /// old node, not a dead path; it keeps the discovery backoff instead,
    /// capped at `discovery_cap_ms`). The timed-out probe is remembered so
    /// its late ack still samples the round trip: until a path has one,
    /// its timeout cannot stretch.
    /// Each timeout is one lost sample for the path's ETX, and a verdict
    /// only if the peer has also been silent on the path for the timeout:
    /// a late echo on a path still carrying the peer's frames is load, not
    /// death. Both the interval
    /// and the timeout stretch with the path's measured round trip, so a
    /// circuit whose round trip exceeds `fast_ms` is neither flooded nor
    /// declared dead every round trip: interval is at least the min RTT,
    /// timeout at least three times the last RTT.
    ///
    /// The silence hint: our active path silent for two of the peer's
    /// intervals on it while a standby hears the peer triggers a probe now,
    /// never `Suspect` (see §7 for the loop that would otherwise follow).
    pub fn plan_heartbeats(&mut self, now_ms: u64, timing: &HeartbeatTiming) -> HeartbeatPlan {
        let HeartbeatTiming {
            fast_ms,
            slow_ms,
            timeout_ms,
            discovery_cap_ms,
        } = *timing;
        let mut plan = HeartbeatPlan::default();
        let active = self.send.active;
        let newest_rx = self.send.paths.iter().filter_map(|p| p.rx_live_at_ms).max();
        for (i, path) in self.send.paths.iter_mut().enumerate() {
            if path.state == PathState::Dead {
                continue;
            }
            let ours = active == Some(i);
            let interval = if ours || path.remote_active {
                fast_ms.max(path.min_rtt_ms().unwrap_or(0))
            } else {
                slow_ms
            };
            let timeout_ms = timeout_ms.max(path.last_rtt_ms.unwrap_or(0).saturating_mul(3));

            if let Some((id, sent_at)) = path.probe.outstanding
                && now_ms.saturating_sub(sent_at) >= timeout_ms
            {
                path.probe.outstanding = None;
                path.probe.timed_out = Some((id, sent_at));
                if path.acked_once {
                    // Loss is sampled while the path is Live. Once it is
                    // Suspect the state already says it is down, and every
                    // further timeout is the same outage, not a lossier
                    // medium; counting them would keep a returning cable
                    // scoring like a bad link for the next minute and stall
                    // the fail-back.
                    if path.state == PathState::Live {
                        path.etx = smooth_etx(path.etx, false);
                    }
                    // A late echo on a path we are still hearing the peer on
                    // is a loss sample, not a verdict: under load the echo
                    // queues behind data and comes back late while the path
                    // is plainly carrying traffic. Only a path silent in
                    // both directions for the timeout goes Suspect.
                    let heard_recently = path
                        .rx_live_at_ms
                        .is_some_and(|rx| now_ms.saturating_sub(rx) < timeout_ms);
                    if path.state == PathState::Live && !heard_recently {
                        path.state = PathState::Suspect;
                        plan.suspects.push(path.transport_id);
                    }
                    path.probe.next_at_ms = 0;
                } else {
                    path.probe.unanswered = path.probe.unanswered.saturating_add(1);
                }
            }

            // Silence hint on our active path.
            if ours
                && let Some(last_rx) = path.rx_live_at_ms
                && let Some(newest) = newest_rx
            {
                let peer_interval = if path.remote_active { fast_ms } else { slow_ms };
                if newest > last_rx && now_ms.saturating_sub(last_rx) >= 2 * peer_interval {
                    path.probe.next_at_ms = 0;
                }
            }

            if path.probe.outstanding.is_some() || now_ms < path.probe.next_at_ms {
                continue;
            }
            let id = path.probe.next_id;
            path.probe.next_id = path.probe.next_id.wrapping_add(1);
            path.probe.outstanding = Some((id, now_ms));
            let delay = if path.acked_once {
                interval
            } else {
                // Discovery backoff: doubles per unanswered probe, capped at
                // `discovery_cap_ms`. Every one of these is full-size, and
                // an old node never answers, so the cap is a permanent
                // per-path cost.
                let shift = path.probe.unanswered.min(16);
                interval
                    .saturating_mul(1u64 << shift)
                    .min(discovery_cap_ms.max(interval))
            };
            path.probe.next_at_ms = now_ms.saturating_add(delay.max(1));
            let full_size = !path.acked_once
                || path
                    .last_full_probe_ms
                    .is_none_or(|t| now_ms.saturating_sub(t) >= FULL_SIZE_PROBE_INTERVAL_MS);
            if full_size {
                path.last_full_probe_ms = Some(now_ms);
            }
            plan.sends.push(HeartbeatSend {
                transport_id: path.transport_id,
                addr: path.addr.clone(),
                probe_id: id,
                remote_active: ours,
                path_id: path.local_id,
                full_size,
            });
        }
        plan
    }

    /// The peer closed the path we call `local_id` (a `PathClose` names
    /// the receiver's id). Same as losing the transport under it: `Dead`
    /// with history, traffic moved if it was there. Returns the transport
    /// it was on alongside the outcome.
    pub fn withdraw_path_by_local_id(
        &mut self,
        local_id: u32,
        now_ms: u64,
        policy: &PathPolicy,
    ) -> Option<(TransportId, PathWithdrawal)> {
        let transport_id = self
            .send
            .paths
            .iter()
            .find(|p| p.local_id == local_id)?
            .transport_id;
        Some((
            transport_id,
            self.withdraw_path(transport_id, now_ms, policy),
        ))
    }

    /// Forget `Dead` paths older than `grace_ms`. The active path is never
    /// pruned, whatever its state: the peer is reaped, not trimmed.
    pub fn prune_dead_paths(&mut self, now_ms: u64, grace_ms: u64) {
        let Some(active) = self.send.active else {
            return;
        };
        let keep: Vec<bool> = self
            .send
            .paths
            .iter()
            .enumerate()
            .map(|(i, path)| {
                i == active
                    || path.state != PathState::Dead
                    || path
                        .dead_since_ms
                        .is_none_or(|since| now_ms.saturating_sub(since) < grace_ms)
            })
            .collect();
        if keep.iter().all(|k| *k) {
            return;
        }
        let mut i = 0;
        let mut new_active = active;
        self.send.paths.retain(|_| {
            let k = keep[i];
            if !k && i < active {
                new_active -= 1;
            }
            i += 1;
            k
        });
        self.send.active = Some(new_active);
    }

    /// Clear the probe backoff on every path over `transport_id`.
    pub fn reset_probe_backoff_on(&mut self, transport_id: TransportId) {
        if let Some(path) = self.path_on_mut(transport_id) {
            path.reset_probe_backoff();
        }
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
    ///
    /// Reads the smoothed (long EWMA) ETX rather than the per-report value:
    /// after a path switch the next report spans the gap and produces one
    /// ETX spike, which must not reach the tree. While a cost hold is in
    /// force after a switch the pre-switch cost is returned instead.
    pub fn link_cost(&self, now_ms: u64) -> f64 {
        if let Some(hold) = self.send.cost_hold
            && self.link_cost_held(now_ms)
        {
            return hold.cost;
        }
        self.raw_link_cost()
    }

    /// The per-report quality index, as the tree has always read it.
    fn raw_link_cost(&self) -> f64 {
        match self.mmp() {
            Some(mmp) => match mmp.metrics.srtt_ms() {
                Some(srtt_ms) => crate::proto::mmp::quality_index(mmp.metrics.etx, srtt_ms),
                None => 1.0,
            },
            None => 1.0,
        }
    }

    /// Hold the reported link cost at its current value: for `hold_ms`,
    /// and until the two receiver reports after the switch have arrived
    /// (the one that spans it, whose ETX carries the frames lost in flight,
    /// and the one that replaces that ETX).
    fn hold_link_cost(&mut self, now_ms: u64, hold_ms: u64) {
        if hold_ms == 0 {
            return;
        }
        let cost = self.link_cost(now_ms);
        self.send.cost_hold = Some(CostHold {
            cost,
            until_ms: now_ms.saturating_add(hold_ms),
            reports_pending: 2,
        });
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
