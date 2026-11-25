//! Plain data for the probe stage machine: stage identity, per-stage verdicts
//! and their machine-stable discriminators, the coordinate-derived path facts,
//! and the preflight/report snapshots the shell exchanges with the core.
//!
//! Every enum carries a `const fn name()` returning the exact string the
//! control-socket JSON publishes, so the wire vocabulary has one home.

use crate::identity::NodeAddr;
use crate::proto::routing::RouteClass;
use alloc::string::String;
use alloc::vec::Vec;

/// The five stages, in order, plus the terminal drain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Stage {
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
pub enum StageVerdict {
    Pending,
    Running,
    Ok,
    Skipped,
    Failed,
}

impl StageVerdict {
    pub const fn name(self) -> &'static str {
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
pub enum FailKind {
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
    /// discovery: the gate proceeded on a peer filter's claim and the lookup
    /// was never answered, so the claim was never confirmed. Distinct from
    /// `NoResponse` because the reason a request went out at all is part of
    /// the finding: a filter cannot miss a key that is present, so on an
    /// absent key this is that filter false-positiving.
    BloomUnconfirmed,
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
    pub const fn name(self) -> &'static str {
        match self {
            FailKind::Cached => "cached",
            FailKind::DirectPeer => "direct_peer",
            FailKind::BloomMiss => "bloom_miss",
            FailKind::BackoffSuppressed => "backoff_suppressed",
            FailKind::AlreadyPending => "already_pending",
            FailKind::NoTreePeers => "no_tree_peers",
            FailKind::NoResponse => "no_response",
            FailKind::BloomUnconfirmed => "bloom_unconfirmed",
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
pub enum ResolveSource {
    Cache,
    Lookup,
    DirectPeer,
}

impl ResolveSource {
    pub const fn name(self) -> &'static str {
        match self {
            ResolveSource::Cache => "cache",
            ResolveSource::Lookup => "lookup",
            ResolveSource::DirectPeer => "direct_peer",
        }
    }
}

/// One stage's record. `elapsed_ms` is filled when the stage leaves `Running`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageRecord {
    pub verdict: StageVerdict,
    pub reason: Option<FailKind>,
    /// Free text for the one case carrying a real message: the error string
    /// out of `initiate_session`.
    pub detail: Option<String>,
    pub elapsed_ms: Option<u64>,
}

impl StageRecord {
    pub fn pending() -> Self {
        Self {
            verdict: StageVerdict::Pending,
            reason: None,
            detail: None,
            elapsed_ms: None,
        }
    }

    pub fn is_failed(&self) -> bool {
        self.verdict == StageVerdict::Failed
    }
}

/// The probe's overall answer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Overall {
    Running,
    Ok,
    Partial,
    Failed,
    Cancelled,
}

impl Overall {
    pub const fn name(self) -> &'static str {
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
pub struct PathFacts {
    /// Self → root, as `TreeCoordinate` stores them.
    pub our_coords: Vec<NodeAddr>,
    pub their_coords: Vec<NodeAddr>,
    pub our_depth: usize,
    pub their_depth: usize,
    pub same_root: bool,
    pub lca: Option<NodeAddr>,
    /// Root-relative: 0 is the root.
    pub lca_depth: Option<usize>,
    /// Tree metric, not a predicted hop count.
    pub tree_hops_up: Option<usize>,
    pub tree_hops_down: Option<usize>,
    /// Upper bound on the real hop count: selection requires only strict
    /// progress, so a crosslink cut-through routinely delivers in fewer hops.
    pub tree_distance: Option<usize>,
}

/// The first hop this node would select right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextHopFacts {
    pub node_addr: NodeAddr,
    pub class: RouteClass,
    pub direct_peer: bool,
    /// True when the class is a crosslink form: the first hop leaves the
    /// up-then-down walk `tree_hops_*` describes.
    pub leaves_tree_walk: bool,
}

/// Why no next hop could be named.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NoHopReason {
    Local,
    NoCoords,
    DisjointTrees,
    NoCloserPeer,
    HopNotSendReady,
}

impl NoHopReason {
    pub const fn name(self) -> &'static str {
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
pub enum LookupOutcomeKind {
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
pub struct Preflight {
    pub session_present: bool,
    pub coords_cached: bool,
    pub identity_cached: bool,
    /// Another probe already holds this target's ownership claim.
    pub target_claimed: bool,
}

/// The four MMP report counters, sampled together.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RttCounters {
    pub reports_seen: u64,
    pub samples: u64,
    pub zero: u64,
    pub arith_fail: u64,
}

impl RttCounters {
    /// Per-field saturating difference, so a rekey or a wrap cannot produce a
    /// negative delta that reads as "nothing happened".
    pub fn delta(self, base: RttCounters) -> RttCounters {
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
pub enum LeftIntact {
    Preexisting,
    AdoptedByTraffic,
    /// The entry is no longer the probe's: replaced, taken over by the peer,
    /// or holding the peer's handshake, which completes it in place of the
    /// probe's own.
    Replaced,
    /// The probe opened it and it is established: it is left for the idle
    /// timeout to close on both ends.
    IdleTimeout,
}

impl LeftIntact {
    pub const fn name(self) -> &'static str {
        match self {
            LeftIntact::Preexisting => "preexisting",
            LeftIntact::AdoptedByTraffic => "adopted_by_traffic",
            LeftIntact::Replaced => "replaced",
            LeftIntact::IdleTimeout => "idle_timeout",
        }
    }
}

/// Everything the control-socket projection needs from the core, as plain
/// data. The core hands one of these out; it never serializes anything itself.
#[derive(Clone, Debug)]
pub struct ProbeSnapshot {
    pub overall: Overall,
    pub tick_ms: u64,
    pub bloom: StageRecord,
    pub discovery: StageRecord,
    pub path: StageRecord,
    pub session: StageRecord,
    pub rtt: StageRecord,
    pub resolve_source: Option<ResolveSource>,
    pub lookup_fanout: Option<usize>,
    pub path_facts: Option<PathFacts>,
    pub next_hop: Option<NextHopFacts>,
    pub no_hop_reason: Option<NoHopReason>,
    pub session_preexisting: bool,
    pub session_established: bool,
    pub path_mtu: Option<u32>,
    pub rtt_ms: Option<u32>,
    pub srtt_ms: Option<f64>,
    pub counters: RttCounters,
    pub torn_down: bool,
    pub left_intact: Option<LeftIntact>,
    pub lookup_issued: bool,
    pub coords_were_cached: bool,
    pub identity_was_cached: bool,
    pub warmups_sent: u8,
}
