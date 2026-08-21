//! Plain data for the probe stage machine: stage identity, per-stage verdicts
//! and their machine-stable discriminators, the coordinate-derived path facts,
//! and the preflight/report snapshots the shell exchanges with the core.
//!
//! Every enum carries a `const fn name()` returning the exact string the
//! control-socket JSON publishes, so the wire vocabulary has one home.

use crate::NodeAddr;
use crate::proto::routing::RouteClass;

/// The five stages, in order, plus the terminal drain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Does any peer's announced filter claim the target, and did a request
    /// therefore go out? Separate from `Discovery` because the two fail for
    /// unrelated reasons: nobody claims the address, against nobody answers
    /// for it.
    Bloom,
    /// Waiting for a LookupResponse to put coordinates in the cache.
    Discovery,
    Path,
    Session,
    Rtt,
    /// Stages are done; teardown (if owed) and `Finish` remain.
    Terminal,
}

/// Per-stage answer. `Pending` means the stage has not been reached.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum StageVerdict {
    Pending,
    Running,
    Ok,
    Skipped,
    Failed,
}

impl StageVerdict {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            StageVerdict::Pending => "pending",
            StageVerdict::Running => "running",
            StageVerdict::Ok => "ok",
            StageVerdict::Skipped => "skipped",
            StageVerdict::Failed => "failed",
        }
    }
}

/// Machine-stable failure or skip discriminator.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum FailKind {
    /// bloom and discovery skipped: coordinates already cached.
    Cached,
    /// bloom and discovery skipped: the target is a send-ready direct peer.
    DirectPeer,
    /// bloom: no peer's filter holds the target, so no request was sent.
    BloomMiss,
    /// bloom: this node is in post-failure lookup backoff.
    BackoffSuppressed,
    /// discovery: joined an in-flight lookup, which then failed.
    AlreadyPending,
    /// bloom: the gate proceeded but the fanout was zero.
    NoTreePeers,
    /// discovery: the attempt ladder was exhausted, or the budget expired.
    NoResponse,
    /// path: the two coordinates have different spanning-tree roots.
    DisjointTrees,
    /// path: no send-ready peer is strictly closer to the target.
    NoNextHop,
    /// session skipped: an entry already existed at action time.
    Preexisting,
    /// session: `initiate_session` returned an error.
    SendError,
    /// session: the budget expired with the handshake incomplete.
    HandshakeTimeout,
    /// rtt: no receiver report of any kind arrived.
    NoReport,
    /// rtt: reports arrived, none carried a usable timestamp echo.
    NoEcho,
    /// rtt: echoes arrived and every sample truncated to 0 ms.
    SubMillisecond,
    /// rtt: echo arithmetic failed — a real anomaly.
    BadTimestampEcho,
    /// the stage was skipped because an earlier stage failed.
    NotReached,
}

impl FailKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            FailKind::Cached => "cached",
            FailKind::DirectPeer => "direct_peer",
            FailKind::BloomMiss => "bloom_miss",
            FailKind::BackoffSuppressed => "backoff_suppressed",
            FailKind::AlreadyPending => "already_pending",
            FailKind::NoTreePeers => "no_tree_peers",
            FailKind::NoResponse => "no_response",
            FailKind::DisjointTrees => "disjoint_trees",
            FailKind::NoNextHop => "no_next_hop",
            FailKind::Preexisting => "preexisting",
            FailKind::SendError => "send_error",
            FailKind::HandshakeTimeout => "handshake_timeout",
            FailKind::NoReport => "no_report",
            FailKind::NoEcho => "no_echo",
            FailKind::SubMillisecond => "sub_millisecond",
            FailKind::BadTimestampEcho => "bad_timestamp_echo",
            FailKind::NotReached => "not_reached",
        }
    }
}

/// Where the target's coordinates came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolveSource {
    Cache,
    Lookup,
    DirectPeer,
}

impl ResolveSource {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            ResolveSource::Cache => "cache",
            ResolveSource::Lookup => "lookup",
            ResolveSource::DirectPeer => "direct_peer",
        }
    }
}

/// One stage's record. `elapsed_ms` is filled when the stage leaves `Running`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StageRecord {
    pub(crate) verdict: StageVerdict,
    pub(crate) reason: Option<FailKind>,
    /// Free text for the one case carrying a real message: the error string
    /// out of `initiate_session`.
    pub(crate) detail: Option<String>,
    pub(crate) elapsed_ms: Option<u64>,
}

impl StageRecord {
    pub(crate) fn pending() -> Self {
        Self {
            verdict: StageVerdict::Pending,
            reason: None,
            detail: None,
            elapsed_ms: None,
        }
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.verdict == StageVerdict::Failed
    }
}

/// The probe's overall answer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Overall {
    Running,
    Ok,
    Partial,
    Failed,
    Cancelled,
}

impl Overall {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            // A job still in flight publishes its stages, not a verdict.
            Overall::Running => "running",
            Overall::Ok => "ok",
            Overall::Partial => "partial",
            Overall::Failed => "failed",
            Overall::Cancelled => "cancelled",
        }
    }
}

/// Coordinate-derived path facts. Purely local arithmetic over two
/// coordinates — nothing here was observed on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PathFacts {
    /// Self → root, as `TreeCoordinate` stores them.
    pub(crate) our_coords: Vec<NodeAddr>,
    pub(crate) their_coords: Vec<NodeAddr>,
    pub(crate) our_depth: usize,
    pub(crate) their_depth: usize,
    pub(crate) same_root: bool,
    pub(crate) lca: Option<NodeAddr>,
    /// Root-relative: 0 is the root.
    pub(crate) lca_depth: Option<usize>,
    /// Tree metric, not a predicted hop count.
    pub(crate) tree_hops_up: Option<usize>,
    pub(crate) tree_hops_down: Option<usize>,
    /// Upper bound on the real hop count: selection requires only strict
    /// progress, so a crosslink cut-through routinely delivers in fewer hops.
    pub(crate) tree_distance: Option<usize>,
}

/// The first hop this node would select right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NextHopFacts {
    pub(crate) node_addr: NodeAddr,
    pub(crate) class: RouteClass,
    pub(crate) direct_peer: bool,
    /// True when the class is a crosslink form: the first hop leaves the
    /// up-then-down walk `tree_hops_*` describes.
    pub(crate) leaves_tree_walk: bool,
}

/// Why no next hop could be named.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum NoHopReason {
    Local,
    NoCoords,
    DisjointTrees,
    NoCloserPeer,
    HopNotSendReady,
}

impl NoHopReason {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            NoHopReason::Local => "local",
            NoHopReason::NoCoords => "no_coords",
            NoHopReason::DisjointTrees => "disjoint_trees",
            NoHopReason::NoCloserPeer => "no_closer_peer",
            NoHopReason::HopNotSendReady => "hop_not_send_ready",
        }
    }
}

/// What the gated lookup entry point decided, flattened for the core.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum LookupOutcomeKind {
    BloomMiss,
    Suppressed,
    Deduplicated,
    /// The gate proceeded but the request reached zero peers.
    ZeroFanout,
    /// The gate proceeded and the request went to at least one peer.
    Sent,
}

/// Live state read once, at `probe_start`, before any stage runs.
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct Preflight {
    pub(crate) session_present: bool,
    pub(crate) coords_cached: bool,
    pub(crate) identity_cached: bool,
    /// Another probe already holds this target's ownership claim.
    pub(crate) target_claimed: bool,
}

/// The four MMP report counters, sampled together.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RttCounters {
    pub(crate) reports_seen: u64,
    pub(crate) samples: u64,
    pub(crate) zero: u64,
    pub(crate) arith_fail: u64,
}

impl RttCounters {
    /// Per-field saturating difference, so a rekey or a wrap cannot produce a
    /// negative delta that reads as "nothing happened".
    pub(crate) fn delta(self, base: RttCounters) -> RttCounters {
        RttCounters {
            reports_seen: self.reports_seen.saturating_sub(base.reports_seen),
            samples: self.samples.saturating_sub(base.samples),
            zero: self.zero.saturating_sub(base.zero),
            arith_fail: self.arith_fail.saturating_sub(base.arith_fail),
        }
    }
}

/// Why a session the probe touched was left in place.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum LeftIntact {
    Preexisting,
    AdoptedByTraffic,
    Replaced,
}

impl LeftIntact {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            LeftIntact::Preexisting => "preexisting",
            LeftIntact::AdoptedByTraffic => "adopted_by_traffic",
            LeftIntact::Replaced => "replaced",
        }
    }
}

/// Everything the control-socket projection needs from the core, as plain
/// data. The core hands one of these out; it never serializes anything itself.
#[derive(Clone, Debug)]
pub(crate) struct ProbeSnapshot {
    pub(crate) overall: Overall,
    pub(crate) tick_ms: u64,
    pub(crate) bloom: StageRecord,
    pub(crate) discovery: StageRecord,
    pub(crate) path: StageRecord,
    pub(crate) session: StageRecord,
    pub(crate) rtt: StageRecord,
    pub(crate) resolve_source: Option<ResolveSource>,
    pub(crate) lookup_fanout: Option<usize>,
    pub(crate) path_facts: Option<PathFacts>,
    pub(crate) next_hop: Option<NextHopFacts>,
    pub(crate) no_hop_reason: Option<NoHopReason>,
    pub(crate) session_preexisting: bool,
    pub(crate) session_established: bool,
    pub(crate) path_mtu: Option<u32>,
    pub(crate) rtt_ms: Option<u32>,
    pub(crate) srtt_ms: Option<f64>,
    pub(crate) counters: RttCounters,
    pub(crate) torn_down: bool,
    pub(crate) left_intact: Option<LeftIntact>,
    pub(crate) lookup_issued: bool,
    pub(crate) coords_were_cached: bool,
    pub(crate) identity_was_cached: bool,
    pub(crate) warmups_sent: u8,
}
