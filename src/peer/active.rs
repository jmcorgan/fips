//! Active Peer (Authenticated Phase)
//!
//! Represents a fully authenticated peer after successful Noise handshake.
//! ActivePeer holds tree state, Bloom filter, and routing information.

use super::{
    LinkCaps, LinkOutput, LinkOutputs, LinkProfile, LinkRekey, PeerInstant, peer_now, since,
};
use crate::config::{MmpConfig, TransportRole};
use crate::node::diag::HsLineCounts;
use crate::node::session::{ThreadJitter, with_tags};
use crate::noise::NoiseSession;
use crate::proto::bloom::BloomFilter;
use crate::proto::fmp::{EphemeralDigest, Msg1Digest};
use crate::proto::mmp::MmpPeerState;
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};
use crate::transport::{LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{Ipv6Address, NodeAddr, PeerIdentity};
use fips_core::proto::fmp::rekey::ik::{LinkKeys, setup_record};
use fips_core::proto::rekey::{
    Bond, Close, Completed, CycleView, Env, Identity, Ids, IndexLease, Input, PeerKey, Record,
    Role, SealRefusal, Sealed, SendCopy, SetupFacts, Slot,
};
use rand::RngExt;
use secp256k1::XOnlyPublicKey;
use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

/// How often a full-size (MTU-padded) probe goes out on a proven path.
const FULL_SIZE_PROBE_INTERVAL_MS: u64 = 60_000;

/// Discovery probes a never-acknowledged standby path gets before it is
/// given up as `Dead`. At the doubling backoff from the fast interval,
/// capped at the heartbeat interval, that is about half a minute. An
/// address we were told about but the peer never answers on — an old
/// node's transport, a replayed handshake source, a beacon from a NIC the
/// peer no longer sends on — is then no longer probed, and no longer
/// counts as a transport the peer is on. `prune_dead_paths` forgets it
/// after the grace; a fresh candidate starts the count over.
pub const MAX_DISCOVERY_PROBES: u32 = 8;

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

/// The rekey machine of a link whose session is `session`, bonded to
/// `bond`: its first epoch is `session` under this node's `ours` and the
/// peer's `theirs`, bound on `transport`, with the key-epoch bit, starts and
/// record `facts` gives, offered to the decrypt workers at once when
/// `caps` says a pool runs. Returns the machine and the binding of `ours`. Hands the lease back,
/// building nothing, when `session` authenticated another key than `bond`.
fn link_machine(
    bond: PeerKey,
    session: NoiseSession,
    ours: IndexLease,
    theirs: SessionIndex,
    transport: TransportId,
    facts: SetupFacts<PeerInstant>,
    caps: &mut LinkCaps<'_>,
) -> Result<(LinkRekey, LinkOutputs), IndexLease> {
    let bond = Bond::Key(bond);
    let epoch = facts.peer_epoch.unwrap_or_default();
    let Ok(first) = bond.check(completed(session, epoch, theirs)) else {
        return Err(ours);
    };
    let ids = Ids::new(ours, theirs.as_u32(), transport);
    let mut scratch = Vec::new();
    Ok(with_tags(|tags| {
        let mut env = Env {
            indices: &mut *caps.indices,
            transport,
            tags,
            workers: caps.workers,
            jitter: &mut ThreadJitter,
            local: caps.local,
            scratch: &mut scratch,
        };
        LinkRekey::established(
            caps.params,
            bond,
            caps.me,
            first,
            ids,
            facts,
            peer_now(),
            &mut env,
        )
    }))
}

/// What link setup tells a new link's rekey machine: key-epoch bit 0, the
/// session and the link starting now, nothing seen from the peer yet, the
/// peer's startup epoch `peer_epoch`, if the setup carried one, and the
/// replay record `record` an earlier link with the peer at that epoch left.
fn setup_facts(peer_epoch: Option<[u8; 8]>, record: Record) -> SetupFacts<PeerInstant> {
    let now = peer_now();
    SetupFacts {
        peer_epoch,
        k: false,
        link_since: now,
        started: now,
        peer_k: None,
        record,
    }
}

/// A completed handshake's `session` as a link's rekey machine takes it: the
/// key it authenticated, the peer's startup `epoch` it carried (zero when
/// unknown) and the peer's index `theirs`.
fn completed(
    session: NoiseSession,
    epoch: [u8; 8],
    theirs: SessionIndex,
) -> Completed<LinkProfile> {
    Completed {
        remote: PeerKey::from_xonly(&session.remote_static_xonly()),
        session: Box::new(LinkKeys::new(session)),
        epoch,
        theirs: Some(theirs.as_u32()),
    }
}

/// What a link's rekey machine keeps across a cross-connection move, as a
/// test reads it (test builds only).
#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LinkAnchors {
    /// The current session's key-epoch bit.
    pub(crate) k: bool,
    /// When the current session started.
    pub(crate) started: PeerInstant,
    /// The current session's inner-header timestamp base.
    pub(crate) base: Option<PeerInstant>,
    /// When the link came up.
    pub(crate) link_since: PeerInstant,
    /// The peer's startup epoch.
    pub(crate) peer_epoch: Option<[u8; 8]>,
    /// The key-epoch bit last seen on the peer's frames.
    pub(crate) peer_k: Option<bool>,
    /// The replay record.
    pub(crate) record: Record,
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

impl PathState {
    /// The control-socket spelling: `probing`, `live`, `suspect`, `dead`.
    /// A fixed string per variant, so a rename here cannot silently change
    /// what `show_peers` and `path_show` emit and what fipstop matches.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Probing => "probing",
            Self::Live => "live",
            Self::Suspect => "suspect",
            Self::Dead => "dead",
        }
    }
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
    /// per `bounds`.
    pub fn is_selectable(&self, bounds: &PathPolicy) -> bool {
        self.is_eligible() && self.rtt_samples() >= bounds.min_samples
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
/// reads (and, on roam, writes) directly by plain borrow with no FSM
/// dispatch: the transport target, the connected-UDP handles, and the hot
/// per-packet counters. The epochs, their keys, indices and key-epoch bits
/// and the session-relative time base live in the peer's link rekey machine.
///
/// Co-located, not behind `Arc`/`ArcSwap` — the data plane is not sharded, so
/// the hot path reads this by plain borrow. Publishing behind `Arc`/`ArcSwap`
/// is later-increment plumbing for a sharded data plane.
#[derive(Debug)]
struct PeerSendState {
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
    fn new(link_id: LinkId, last_seen: u64) -> Self {
        Self {
            paths: Vec::new(),
            active: None,
            discretionary_since_ms: None,
            cost_hold: None,
            link_id,
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
/// Created only after successful Noise IK handshake. The identity is
/// cryptographically verified at this point.
///
/// Note: ActivePeer intentionally does not implement Clone because its link
/// rekey machine holds Noise sessions, which cannot be safely cloned
/// (cloning would risk nonce reuse, a catastrophic security failure).
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
    /// Kept for the life of the peering: nothing clears it.
    handshake_msg2: Option<Vec<u8>>,
    /// Digest of the ephemeral in the link-setup msg1 the peering was
    /// promoted from, by which the silent-session record counts a session
    /// once however a copy's header was rewritten.
    setup_ephemeral: Option<EphemeralDigest>,

    // === Rekey (Key Rotation) ===
    /// The link's rekey machine: its epochs and their keys, indices and
    /// key-epoch bits, this node's own rekey handshake in flight, the
    /// drain, the pending session with the role that made it and its
    /// install time, the peer's startup epoch, dampening, the link's age,
    /// the rekey jitter and the record of answered msg1s. `None` for a peer
    /// built without a Noise session.
    rekey: Option<LinkRekey>,
    /// Repeated handshake lines logged for this peer, by kind, so a peer
    /// repeating one msg1 outcome logs it a bounded number of times.
    hs_lines: HsLineCounts,
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
            last_heartbeat_sent: None,
            last_heartbeat_attempt: None,
            handshake_msg2: None,
            setup_ephemeral: None,
            rekey: None,
            hs_lines: HsLineCounts::default(),
            heard: true,
            send: PeerSendState::new(link_id, authenticated_at),
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
    /// This is the primary constructor for the wire protocol path. The
    /// session becomes the first epoch of the peer's link rekey machine,
    /// under `our_index`, the lease link setup took, and the peer's
    /// `their_index`, bound on `transport_id`; the machine is bonded to the
    /// identity's key. Returns the outputs the node executes, the binding of
    /// `our_index` among them. Hands the lease back, building nothing, when
    /// the session authenticated another key than `identity`'s, which a
    /// completed handshake never does.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_session(
        identity: PeerIdentity,
        link_id: LinkId,
        authenticated_at: u64,
        noise_session: NoiseSession,
        our_index: IndexLease,
        their_index: SessionIndex,
        transport_id: TransportId,
        current_addr: TransportAddr,
        link_stats: LinkStats,
        is_initiator: bool,
        mmp_config: &MmpConfig,
        remote_epoch: Option<[u8; 8]>,
        caps: &mut LinkCaps<'_>,
    ) -> Result<(Self, LinkOutputs), IndexLease> {
        let bond = PeerKey::from_xonly(&identity.pubkey());
        let facts = setup_facts(remote_epoch, std::mem::take(&mut caps.record));
        let (rekey, out) = link_machine(
            bond,
            noise_session,
            our_index,
            their_index,
            transport_id,
            facts,
            caps,
        )?;
        let mut send = PeerSendState::new(link_id, authenticated_at);
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
        let peer = Self {
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
            last_heartbeat_sent: None,
            last_heartbeat_attempt: None,
            handshake_msg2: None,
            setup_ephemeral: None,
            rekey: Some(rekey),
            hs_lines: HsLineCounts::default(),
            heard: is_initiator,
            send,
        };
        Ok((peer, out))
    }

    /// [`with_session`](Self::with_session) for a test that needs a keyed
    /// peer without running link setup: `our_index` is leased outside any
    /// allocator, and the machine is bonded to the key the session
    /// authenticated, which a test's `identity` need not be. The outputs (the
    /// index binding) are dropped, as the test has no node.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_test_session(
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
        let local =
            fips_core::proto::rekey::NodeKeys::new(crate::Identity::generate().keypair(), [0; 8]);
        let mut indices = crate::utils::index::IndexAllocator::new();
        let mut caps = LinkCaps {
            indices: &mut indices,
            local: &local,
            me: *identity.node_addr(),
            params: super::test_link_params(),
            record: Record::new(),
            workers: false,
        };
        let bond = PeerKey::from_xonly(&noise_session.remote_static_xonly());
        let (rekey, _) = link_machine(
            bond,
            noise_session,
            IndexLease::for_test(our_index.as_u32()),
            their_index,
            transport_id,
            setup_facts(remote_epoch, Record::new()),
            &mut caps,
        )
        .unwrap_or_else(|_| unreachable!("a machine bonds to its own session's key"));
        let mut peer = Self::with_stats(identity, link_id, authenticated_at, link_stats);
        let mut path = PeerPath::new(transport_id, current_addr, PathState::Live);
        let now_ms = crate::time::mono_ms();
        path.rx_live_at_ms = Some(now_ms);
        path.tx_live_at_ms = Some(now_ms);
        peer.send.paths.push(path);
        peer.send.active = Some(0);
        peer.send.mmp = Some(MmpPeerState::new(
            mmp_config.mode,
            mmp_config.log_interval_secs,
            mmp_config.owd_window_size,
            is_initiator,
        ));
        peer.heard = is_initiator;
        peer.rekey = Some(rekey);
        peer
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
    pub(crate) fn has_session(&self) -> bool {
        self.rekey.is_some()
    }

    /// The Noise session of the epoch in `slot`, read-only.
    fn keys(&self, slot: Slot) -> Option<&NoiseSession> {
        self.rekey
            .as_ref()?
            .keys(slot)
            .map(fips_core::proto::rekey::NoiseKeys::session)
    }

    /// Our session index of the epoch in `slot`.
    fn index(&self, slot: Slot) -> Option<SessionIndex> {
        self.rekey.as_ref()?.ours(slot).map(SessionIndex::new)
    }

    /// The tag of the epoch in `slot`, by which the link's rekey machine
    /// is told of a frame a decrypt worker opened under it.
    pub(crate) fn epoch_tag(&self, slot: Slot) -> Option<fips_core::proto::rekey::EpochTag> {
        self.rekey.as_ref()?.tag(slot)
    }

    /// The transport this peer's indices are bound on: the one it is
    /// reached over. A peer with a session always has one.
    fn bound_transport(&self) -> TransportId {
        self.transport_id().unwrap_or(TransportId::new(0))
    }

    /// Get the Noise session, if present.
    pub(crate) fn noise_session(&self) -> Option<&NoiseSession> {
        self.keys(Slot::Current)
    }

    /// Reserve a counter under the current session at `now` for one
    /// frame, with the send key, the peer's index, the key-epoch bit and
    /// the inner-header timestamp that session fixes.
    pub(crate) fn seal(&mut self, now: PeerInstant) -> Result<Sealed<SendCopy>, SealRefusal> {
        match self.rekey.as_mut() {
            Some(rekey) => rekey.seal(now),
            None => Err(SealRefusal::NotEstablished),
        }
    }

    /// Get our session index (they use this to send TO us).
    pub(crate) fn our_index(&self) -> Option<SessionIndex> {
        self.index(Slot::Current)
    }

    /// Get their session index (we use this to send TO them).
    pub(crate) fn their_index(&self) -> Option<SessionIndex> {
        self.rekey
            .as_ref()?
            .theirs(Slot::Current)
            .map(SessionIndex::new)
    }

    /// Move this peer onto `session`, the winning handshake of a crossed
    /// dial, under this node's `ours` and the peer's `theirs`.
    ///
    /// When both nodes dial each other at once, each promotes the handshake
    /// the other started; the smaller node's outbound handshake wins, and it
    /// moves to that session when the peer's msg2 arrives. The link's rekey
    /// machine is closed, which abandons its own rekey in flight, ends a
    /// responder pending and the drain of the previous session, and releases
    /// every index they held, and a new one is built on `session` from what
    /// the closed one hands back: the moved session keeps the replaced one's
    /// key-epoch bit and start (so its rekey age and inner-header timestamps
    /// carry on), the link's age, the key-epoch bit last seen from the peer
    /// and the replay record. `caps` lends the index allocator and keys, the
    /// parameters the new machine is built with and whether a decrypt-worker
    /// pool runs, to which the new session is offered at once; its record is
    /// not read.
    ///
    /// Returns the outputs that unbind, revoke and release what the closed
    /// machine held and bind (and offer) the new session. Hands `ours` back
    /// in a release, changing nothing, when `session` authenticated another
    /// key than the peer's. Also resets the replay suppression counter and
    /// the repeated handshake line counts since the session changed.
    pub(crate) fn move_session(
        &mut self,
        session: NoiseSession,
        ours: IndexLease,
        theirs: SessionIndex,
        caps: &mut LinkCaps<'_>,
    ) -> LinkOutputs {
        self.reset_replay_suppressed();
        self.hs_lines.roll();
        let transport = self.bound_transport();
        let Some(old) = self.rekey.take() else {
            return vec![LinkOutput::Release(ours)];
        };
        let remote = PeerKey::from_xonly(&session.remote_static_xonly());
        let view = old.view();
        let held = match view.identity {
            Identity::Proven(key) if key == remote => Some(key),
            Identity::Proven(_) | Identity::Claimed(_) => None,
        };
        let Some(bond) = held else {
            self.rekey = Some(old);
            return vec![LinkOutput::Release(ours)];
        };
        let (mut out, carry) = old.close(Close::CrossConnectionMove);
        let Some(carry) = carry else {
            out.push(LinkOutput::Release(ours));
            return out;
        };
        match link_machine(bond, session, ours, theirs, transport, carry.into(), caps) {
            Ok((rekey, built)) => {
                out.extend(built);
                self.rekey = Some(rekey);
            }
            Err(lease) => out.push(LinkOutput::Release(lease)),
        }
        out
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

    /// The peer's address on `transport_id` is `addr` now. Roams the path
    /// there, if any, without touching its state; a `Dead` path brought back
    /// at a new address is `Probing` again. Returns whether anything changed.
    /// Nothing happens for a transport the peer has no path on — that is
    /// [`add_path`](Self::add_path)'s job — nor for the same address.
    ///
    /// A peer's address on a transport does change under it: a Wi-Fi Aware
    /// data path that re-forms comes up with a new link-local, and an
    /// address that has moved is not one a probe can reach. Without this the
    /// path kept the dead address for as long as it lived.
    pub fn refresh_path_addr(&mut self, transport_id: TransportId, addr: TransportAddr) -> bool {
        let Some(path) = self.path_on_mut(transport_id) else {
            return false;
        };
        if path.addr == addr {
            return false;
        }
        path.addr = addr;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        path.clear_connected_udp();
        if path.state == PathState::Dead {
            path.state = PathState::Probing;
            path.dead_since_ms = None;
        }
        path.probe.next_at_ms = 0;
        true
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
    /// Unit-test sampler for the selection tests, which need a path fed a
    /// chosen round trip without driving a whole heartbeat schedule. Every
    /// node-level test goes through [`plan_heartbeats`](Self::plan_heartbeats),
    /// the one issuer of probes in production.
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
        self.add_path(transport_id, addr.clone());
        self.refresh_path_addr(transport_id, addr);
        let path = self
            .path_on_mut(transport_id)
            .expect("path added just above");
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
        bounds: &PathPolicy,
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
        match self.best_alternative(idx, bounds) {
            Some(next) => {
                self.hold_link_cost(now_ms, bounds.dwell_ms);
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
    fn best_selectable(&self, exclude: usize, bounds: &PathPolicy) -> Option<(usize, Option<f64>)> {
        let any_normal = self
            .send
            .paths
            .iter()
            .any(|p| p.is_selectable(bounds) && p.role == TransportRole::Normal);
        self.send
            .paths
            .iter()
            .enumerate()
            .filter(|(i, p)| *i != exclude && p.is_selectable(bounds))
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
    fn best_alternative(&self, exclude: usize, bounds: &PathPolicy) -> Option<usize> {
        if let Some((i, _)) = self.best_selectable(exclude, bounds) {
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
    pub fn select_path(&mut self, now_ms: u64, bounds: &PathPolicy) -> Option<PathSwitch> {
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
            self.hold_link_cost(now_ms, bounds.dwell_ms);
            return Some(self.switch_to(active, pin, SwitchReason::Pinned));
        }
        if !self.send.paths[active].is_eligible() {
            let next = self.best_alternative(active, bounds)?;
            self.hold_link_cost(now_ms, bounds.dwell_ms);
            return Some(self.switch_to(active, next, SwitchReason::Mandatory));
        }
        let Some(active_score) = self.send.paths[active].score() else {
            self.send.discretionary_since_ms = None;
            return None;
        };
        let Some((next, Some(best_score))) = self.best_selectable(active, bounds) else {
            self.send.discretionary_since_ms = None;
            return None;
        };
        // A `Backup` active path yields to a selectable `Normal` one outright:
        // its role says it should not be carrying traffic at all.
        let active_is_backup_yielding = self.send.paths[active].role == TransportRole::Backup
            && self.send.paths[next].role == TransportRole::Normal;
        if !active_is_backup_yielding && active_score <= best_score * bounds.margin {
            self.send.discretionary_since_ms = None;
            return None;
        }
        let since = *self.send.discretionary_since_ms.get_or_insert(now_ms);
        if !active_is_backup_yielding && now_ms.saturating_sub(since) < bounds.dwell_ms {
            return None;
        }
        self.hold_link_cost(now_ms, bounds.dwell_ms);
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
    ///
    /// A peer with one `Live` path is not heartbeated here at all.
    /// Selection has nothing to move to, so a `Suspect` mark on it changes
    /// nothing, and the link heartbeat already keeps its liveness; five
    /// probes a second on every single-path link would be cost without a
    /// decision behind it. Probes start the moment a second path — a
    /// candidate included — exists, which is when a verdict can act; and a
    /// lone path that is `Suspect` (the peer closed it, nowhere to go) is
    /// probed so its ack can bring it back.
    pub fn plan_heartbeats(&mut self, now_ms: u64, timing: &HeartbeatTiming) -> HeartbeatPlan {
        let HeartbeatTiming {
            fast_ms,
            slow_ms,
            timeout_ms,
            discovery_cap_ms,
        } = *timing;
        let mut plan = HeartbeatPlan::default();
        let active = self.send.active;
        let alone_and_live = self
            .send
            .paths
            .iter()
            .filter(|p| p.state != PathState::Dead)
            .count()
            < 2
            && active
                .and_then(|i| self.send.paths.get(i))
                .is_some_and(|p| p.state == PathState::Live);
        if alone_and_live {
            for path in self.send.paths.iter_mut() {
                path.probe.outstanding = None;
                path.probe.timed_out = None;
            }
            return plan;
        }
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
                    // A standby the peer has never answered on is given up
                    // after the discovery budget. Never the active path:
                    // an old node answers no probe there either, and the
                    // handshake proved it.
                    if !ours && path.probe.unanswered >= MAX_DISCOVERY_PROBES {
                        path.state = PathState::Dead;
                        path.dead_since_ms = Some(now_ms);
                        path.probe.timed_out = None;
                        continue;
                    }
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
            // Discovery probes are full-size so a medium that passes small
            // frames and drops large ones never proves itself — except on
            // the active path, which the handshake proved and whose MTU it
            // seeded; there the once-a-minute full-size probe is enough.
            let full_size = (!path.acked_once && !ours)
                || match path.last_full_probe_ms {
                    Some(t) => now_ms.saturating_sub(t) >= FULL_SIZE_PROBE_INTERVAL_MS,
                    None => !ours,
                };
            if full_size || path.last_full_probe_ms.is_none() {
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
        bounds: &PathPolicy,
    ) -> Option<(TransportId, PathWithdrawal)> {
        let transport_id = self
            .send
            .paths
            .iter()
            .find(|p| p.local_id == local_id)?
            .transport_id;
        Some((
            transport_id,
            self.withdraw_path(transport_id, now_ms, bounds),
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

    /// The transport `transport_id` is back: clear the probe backoff on
    /// its path, and a path given up as `Dead` while it was gone is
    /// `Probing` again, its RTT window and ETX intact, so the next
    /// heartbeat tick re-proves it rather than measuring it from nothing.
    /// Returns whether a `Dead` path was revived.
    pub fn reset_probe_backoff_on(&mut self, transport_id: TransportId) -> bool {
        let Some(path) = self.path_on_mut(transport_id) else {
            return false;
        };
        path.reset_probe_backoff();
        if path.state == PathState::Dead {
            path.state = PathState::Probing;
            path.dead_since_ms = None;
            path.probe.outstanding = None;
            path.probe.timed_out = None;
            return true;
        }
        false
    }

    // === Handshake Resend ===

    /// Store wire-format msg2 for resend on duplicate msg1.
    pub(crate) fn set_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.handshake_msg2 = Some(msg2);
    }

    /// Get stored msg2 bytes for resend.
    pub(crate) fn handshake_msg2(&self) -> Option<&[u8]> {
        self.handshake_msg2.as_deref()
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

    // === Epoch Accessors ===

    /// Get the remote peer's startup epoch (from handshake).
    pub(crate) fn remote_epoch(&self) -> Option<[u8; 8]> {
        self.rekey.as_ref()?.view().peer_epoch
    }

    /// Update the remote peer's startup epoch after a successful in-place
    /// rekey. Initial handshakes set this through `with_session`, but recovery
    /// rekeys also exchange epochs and must keep restart detection current.
    #[cfg(test)]
    pub(crate) fn set_remote_epoch(&mut self, remote_epoch: Option<[u8; 8]>) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.force_peer_epoch(remote_epoch);
        }
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
    /// Returns milliseconds since the current session's timestamp base, its
    /// cutover, truncated to u32. Wraps at ~49.7 days which is acceptable
    /// for session-relative timing. Zero for a peer without a session.
    pub(crate) fn session_elapsed_ms(&self) -> u32 {
        self.rekey
            .as_ref()
            .and_then(LinkRekey::base)
            .map_or(0, |base| since(base).as_millis() as u32)
    }

    /// When the link's rekey machine last heard the peer: the last frame
    /// that authenticated under any session the link holds, the previous
    /// one during a drain included. `None` before the first.
    pub(crate) fn last_heard(&self) -> Option<PeerInstant> {
        self.rekey.as_ref()?.view().last_rx
    }

    /// How long ago this peer's current session started (for link-dead
    /// fallback timing): the time since the current session's timestamp
    /// base on the peer clock, the clock the link's MMP receiver reads, or
    /// zero for a peer without a session.
    pub(crate) fn session_age(&self) -> Duration {
        self.rekey
            .as_ref()
            .and_then(LinkRekey::base)
            .map_or(Duration::ZERO, since)
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

    /// When the current Noise session was established; `None` without a
    /// session.
    pub(crate) fn session_established_at(&self) -> Option<PeerInstant> {
        self.rekey.as_ref()?.started(Slot::Current)
    }

    /// When this peering's link came up: at promotion, or when a pending
    /// session that revealed a peer restart left the slot. Unlike
    /// [`session_established_at`](Self::session_established_at), a rekey
    /// cutover does not move it. `None` without a session.
    #[cfg(test)]
    pub(crate) fn link_established_at(&self) -> Option<PeerInstant> {
        Some(self.rekey.as_ref()?.view().link_since)
    }

    /// Test-only seam: backdate the session-established instant so a test can
    /// construct a session that reads as `age`-old. The link instant is moved
    /// back with it when it would otherwise be the younger of the two, since
    /// a link is never younger than its session. This only shifts the
    /// machine's stamps; it changes no decision logic, no threshold, and is
    /// compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_session_established(&mut self, age: std::time::Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_started(age);
        }
    }

    /// Test-only seam: backdate the start of the drain a cutover began, so a
    /// test can stand up a drain window that has passed but that no rekey
    /// tick has completed yet. A no-op when no drain is in progress. Compiled
    /// out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_drain_started(&mut self, age: Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_drain(age);
        }
    }

    /// Test-only seam: backdate the pending session's install time so a test
    /// can make the responder hold read as passed. Shifts only the machine's
    /// stamp; compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn backdate_pending(&mut self, age: Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_pending(age);
        }
    }

    /// Test-only seam: backdate the last peer-initiated rekey so a test can
    /// move past the rekey dampening window without waiting it out. Shifts
    /// only the machine's stamp; compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn backdate_dampener(&mut self, age: Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_dampening(age);
        }
    }

    /// Test-only seam: set the K-bit this node sends with, to stand up the
    /// out-of-step K-bits that a peer restart or a cross-connection swap
    /// leaves behind. Compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn force_kbit(&mut self, kbit: bool) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.force_k(kbit);
        }
    }

    /// Test-only seam: seal `plaintext` under this peer's session in `slot`
    /// for `receiver_idx` with header flags `flags`, as the inline send path
    /// seals a frame, and return the framed wire bytes. A test forges with it
    /// what the peer holding the other half of that session would send.
    #[cfg(test)]
    pub(crate) fn seal_test_frame(
        &mut self,
        slot: Slot,
        receiver_idx: SessionIndex,
        flags: u8,
        plaintext: &[u8],
    ) -> Vec<u8> {
        use crate::proto::fmp::wire::{build_encrypted, build_established_header};
        let (counter, key) = self
            .rekey
            .as_mut()
            .and_then(|rekey| rekey.reserve_slot(slot))
            .expect("the peer holds a session in the slot");
        let header = build_established_header(receiver_idx, counter, flags, plaintext.len() as u16);
        let ciphertext = fips_core::noise::seal(key.key(), counter, &header, plaintext)
            .expect("the session seals");
        build_encrypted(&header, &ciphertext)
    }

    /// Test-only: what this peer's link rekey machine would hand a
    /// successor: the key-epoch bits of its current session and of the
    /// peer's last frame, its current session's start and timestamp base,
    /// the link's age, the peer's startup epoch and the replay record.
    #[cfg(test)]
    pub(crate) fn link_anchors(&self) -> Option<LinkAnchors> {
        let rekey = self.rekey.as_ref()?;
        let view = rekey.view();
        let cur = view.current.as_ref()?;
        let (peer_k, record) = rekey.memory();
        Some(LinkAnchors {
            k: cur.k,
            started: cur.started,
            base: cur.base,
            link_since: view.link_since,
            peer_epoch: view.peer_epoch,
            peer_k,
            record: record.clone(),
        })
    }

    /// Test-only: every index this peer's link rekey machine binds, with
    /// whether a decrypt worker
    /// holds that session's receive half, for the audit of the node's index
    /// map and worker table against the machine.
    #[cfg(test)]
    pub(crate) fn link_bindings(&self) -> Vec<(u32, bool)> {
        use fips_core::proto::rekey::{Purpose, RecvHome};
        let Some(rekey) = self.rekey.as_ref() else {
            return Vec::new();
        };
        let view = rekey.view();
        rekey
            .bindings()
            .into_iter()
            .map(|b| {
                let ep = match b.purpose {
                    Purpose::Current => view.current.as_ref(),
                    Purpose::Previous => view.previous.as_ref(),
                    Purpose::Pending => view.pending.as_ref(),
                    Purpose::Attempt => None,
                };
                let on_worker = ep.is_some_and(|e| e.recv == RecvHome::Delegated);
                (b.index, on_worker)
            })
            .collect()
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

    /// Test-only seam: backdate the session's timestamp base so a test can
    /// make `session_elapsed_ms()` read as `age`-old (needed to synthesize a
    /// positive RTT sample from a crafted ReceiverReport). This only shifts the
    /// machine's stamp; it changes no decision logic, no threshold, and is
    /// compiled out of release builds.
    #[cfg(test)]
    pub(crate) fn test_backdate_session_start(&mut self, age: std::time::Duration) {
        if let Some(rekey) = self.rekey.as_mut() {
            rekey.backdate_base(age);
        }
    }

    /// Per-session symmetric rekey-timer jitter offset (seconds).
    ///
    /// Drawn at session construction and at each rekey cutover; uniform
    /// over `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]`. Callers add this
    /// to the configured `node.rekey.after_secs` to obtain the effective
    /// trigger interval for this session. Zero without a session.
    #[cfg(test)]
    pub(crate) fn rekey_jitter_secs(&self) -> i64 {
        self.rekey
            .as_ref()
            .map_or(0, |rekey| i64::from(rekey.jitter_secs()))
    }

    /// Current K-bit epoch value.
    pub(crate) fn current_k_bit(&self) -> bool {
        self.rekey.as_ref().is_some_and(LinkRekey::k)
    }

    /// Whether this node's own rekey handshake is in flight: its msg1 sent
    /// and the peer's msg2 not yet read.
    pub(crate) fn rekey_in_progress(&self) -> bool {
        self.rekey
            .as_ref()
            .is_some_and(|rekey| rekey.view().cycle == CycleView::Init)
    }

    /// Whether dampening, opened when this node last answered the peer's
    /// rekey, still holds back this node's own.
    #[cfg(test)]
    pub(crate) fn dampened(&self) -> bool {
        self.rekey
            .as_ref()
            .is_some_and(|rekey| rekey.dampened(peer_now()))
    }

    /// Get the pending new session's our_index.
    pub(crate) fn pending_our_index(&self) -> Option<SessionIndex> {
        self.index(Slot::Pending)
    }

    /// Get the pending new session's their_index.
    #[cfg(test)]
    pub(crate) fn pending_their_index(&self) -> Option<SessionIndex> {
        self.rekey
            .as_ref()?
            .theirs(Slot::Pending)
            .map(SessionIndex::new)
    }

    /// Get the previous session's our_index (during drain).
    pub(crate) fn previous_our_index(&self) -> Option<SessionIndex> {
        self.index(Slot::Previous)
    }

    /// Get the previous session for decryption fallback.
    pub(crate) fn previous_session(&self) -> Option<&NoiseSession> {
        self.keys(Slot::Previous)
    }

    /// Get the pending new session (completed rekey, not yet cut over).
    pub(crate) fn pending_new_session(&self) -> Option<&NoiseSession> {
        self.keys(Slot::Pending)
    }

    /// Which side of the rekey handshake produced the pending session; `None`
    /// when no pending session is held.
    pub(crate) fn pending_role(&self) -> Option<Role> {
        match self.rekey.as_ref()?.view().cycle {
            CycleView::PendI(_) => Some(Role::Initiator),
            CycleView::PendR => Some(Role::Responder),
            CycleView::Idle | CycleView::Init => None,
        }
    }

    /// The digest of the msg1 whose answer armed the pending session, and
    /// the msg2 that answered it, when this node holds it as the rekey
    /// responder; `None` otherwise.
    pub(crate) fn rekey_answer(&self) -> Option<(Msg1Digest, Vec<u8>)> {
        let (msg1, msg2) = self.rekey.as_ref()?.rekey_answer()?;
        Some((msg1.into(), msg2.clone()))
    }

    /// Record `msg1`, the framed link-setup msg1 this peering was promoted
    /// from, and `msg2`, the msg2 that answered it: a resend of the msg1
    /// draws the msg2 again while the session is too young to rekey, and a
    /// copy of it, under any header, is refused once the session is old
    /// enough. Nothing is recorded for a msg1 too short to frame one.
    pub(crate) fn note_setup(&mut self, msg1: &[u8], msg2: &[u8]) {
        if let Some(rekey) = self.rekey.as_mut()
            && let Some(record) = setup_record(msg1, Some(msg2))
        {
            rekey.note_setup(record);
        }
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

    /// How long the pending session has been held since it was installed;
    /// `None` when no pending session is held.
    pub(crate) fn pending_age(&self) -> Option<Duration> {
        self.rekey.as_ref()?.started(Slot::Pending).map(since)
    }

    /// Step this peer's link rekey machine with `input` at `now`, lending
    /// it the node's index allocator `indices`, its keys `local` and
    /// whether a decrypt-worker pool exists, and return what the node must
    /// carry out, front to back. Empty for a peer without a session. Its
    /// index bindings are made on the transport the peer is reached over
    /// now.
    pub(crate) fn step_link(
        &mut self,
        now: PeerInstant,
        input: Input<'_, LinkProfile>,
        indices: &mut crate::utils::index::IndexAllocator,
        local: &fips_core::proto::rekey::NodeKeys,
        workers: bool,
    ) -> LinkOutputs {
        let transport = self.bound_transport();
        let Some(rekey) = self.rekey.as_mut() else {
            return LinkOutputs::new();
        };
        let mut scratch = Vec::new();
        with_tags(|tags| {
            let mut env = Env {
                indices,
                transport,
                tags,
                workers,
                jitter: &mut ThreadJitter,
                local,
                scratch: &mut scratch,
            };
            rekey.step(now, input, &mut env)
        })
    }

    /// Test-only: start this node's own rekey at `now` as a trigger that has
    /// come would, whatever the link's age, lending the machine `indices`
    /// and `local`. Returns the outputs (the attempt index's binding and the
    /// msg1); empty when a rekey or a pending session is already held.
    #[cfg(test)]
    pub(crate) fn start_rekey_now(
        &mut self,
        now: PeerInstant,
        indices: &mut crate::utils::index::IndexAllocator,
        local: &fips_core::proto::rekey::NodeKeys,
    ) -> LinkOutputs {
        let transport = self.bound_transport();
        let Some(rekey) = self.rekey.as_mut() else {
            return LinkOutputs::new();
        };
        let mut scratch = Vec::new();
        with_tags(|tags| {
            let mut env = Env {
                indices,
                transport,
                tags,
                workers: false,
                jitter: &mut ThreadJitter,
                local,
                scratch: &mut scratch,
            };
            rekey.start_now(now, &mut env)
        })
    }

    /// Test-only: the index of this node's own rekey in flight, which a msg2
    /// names; `None` with no attempt in flight.
    #[cfg(test)]
    pub(crate) fn rekey_our_index(&self) -> Option<SessionIndex> {
        self.rekey
            .as_ref()?
            .bindings()
            .into_iter()
            .find(|b| b.purpose == fips_core::proto::rekey::Purpose::Attempt)
            .map(|b| SessionIndex::new(b.index))
    }

    /// Seal the link prompt under this peer's session `tag` at `now`.
    pub(crate) fn seal_prompt(
        &mut self,
        now: PeerInstant,
        tag: fips_core::proto::rekey::EpochTag,
    ) -> Result<fips_core::proto::rekey::SealedPrompt<LinkProfile>, SealRefusal> {
        match self.rekey.as_mut() {
            Some(rekey) => rekey.seal_prompt(now, tag),
            None => Err(SealRefusal::NotEstablished),
        }
    }

    /// Reset what a cutover resets beside the machine: the replay
    /// suppression and handshake line counts, the frames counted on the
    /// previous session, and the link MMP counters. The node runs it for
    /// each cutover the link machine reports.
    pub(crate) fn after_cutover(&mut self) {
        self.send.prev_frames = 0;
        self.reset_replay_suppressed();
        self.hs_lines.roll();

        // Reset MMP counters to avoid metric discontinuity
        let now_ms = crate::time::mono_ms();
        if let Some(mmp) = &mut self.send.mmp {
            mmp.reset_for_rekey(now_ms);
        }
    }

    /// Whether a drain is in progress.
    pub(crate) fn is_draining(&self) -> bool {
        self.rekey
            .as_ref()
            .is_some_and(|rekey| rekey.drain_deadline().is_some())
    }

    /// How long ago the last cutover happened; `None` if there has been none.
    pub(crate) fn since_cutover(&self) -> Option<Duration> {
        self.rekey.as_ref()?.last_cutover().map(since)
    }

    /// Test-only: offer the current session's receive half to the decrypt
    /// workers, as a poll does while no worker holds it, for a test that
    /// starts the worker pool after the link was promoted.
    #[cfg(test)]
    pub(crate) fn offer_to_workers(&self) -> LinkOutputs {
        self.rekey
            .as_ref()
            .map(LinkRekey::offer_held)
            .unwrap_or_default()
    }

    /// End the link's rekey machine as the peer is removed, returning the
    /// outputs that unbind, revoke and release every index it held (its
    /// sessions' and its own rekey handshake's), and the peer's startup
    /// epoch with the replay record the machine kept, for the node to hand
    /// to a later link with the peer at that epoch. Empty outputs and no
    /// record for a peer without a session.
    pub(crate) fn close(&mut self) -> (LinkOutputs, Option<([u8; 8], Record)>) {
        // The reason only labels an own rekey handshake the machine
        // abandons, which the node counts nowhere.
        let Some(rekey) = self.rekey.take() else {
            return (LinkOutputs::new(), None);
        };
        let (out, carry) = rekey.close(fips_core::proto::rekey::Close::Admin);
        (
            out,
            carry.map(|c| (c.peer_epoch.unwrap_or_default(), c.record)),
        )
    }
}

#[cfg(test)]
#[path = "tests/active.rs"]
mod tests;
