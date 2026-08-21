//! Control-socket projection of a probe report.
//!
//! Plain serde structs mirroring the sans-IO core's stage records. Only
//! `rtt_ms`, `srtt_ms` and `path_mtu` vanish when unmeasured; every other key
//! is always present so a script need not guard. The `path` block is
//! deliberately explicit that it is a local computation: `computed_locally` is
//! always true and `observed` always false, so a machine reader cannot mistake
//! it for a traceroute.

use serde::Serialize;

use crate::node::Node;
use crate::node::ProbeJob;
use crate::proto::probe::{ProbeSnapshot, StageRecord};

/// Common to every stage. `verdict` is the per-stage answer.
#[derive(Serialize)]
pub struct StageStatus {
    /// "pending" | "running" | "ok" | "skipped" | "failed"
    pub verdict: &'static str,
    /// Machine-stable failure or skip discriminator; `null` when the stage is
    /// ok, pending or running.
    pub reason: Option<&'static str>,
    /// Free text for the one case carrying a real message: the error string
    /// out of session initiation.
    pub detail: Option<String>,
    pub elapsed_ms: Option<u64>,
}

impl From<&StageRecord> for StageStatus {
    fn from(record: &StageRecord) -> Self {
        Self {
            verdict: record.verdict.name(),
            reason: record.reason.map(|r| r.name()),
            detail: record.detail.clone(),
            elapsed_ms: record.elapsed_ms,
        }
    }
}

#[derive(Serialize)]
pub struct TargetInfo {
    pub npub: String,
    pub node_addr: String,
    pub display_name: String,
    pub ipv6_addr: String,
}

/// Whether any peer's announced filter claims the target, which decides
/// whether a LookupRequest is sent at all.
#[derive(Serialize)]
pub struct BloomStage {
    #[serde(flatten)]
    pub status: StageStatus,
    /// Peers the LookupRequest actually reached; null when none was issued.
    pub fanout: Option<usize>,
}

/// Waiting for a LookupResponse to answer with coordinates.
#[derive(Serialize)]
pub struct DiscoveryStage {
    #[serde(flatten)]
    pub status: StageStatus,
    /// "cache" | "lookup" | "direct_peer" | null
    pub source: Option<&'static str>,
    /// The attempt in flight, or the last one tried. Counts from 1.
    pub attempts: Option<u8>,
    /// This node's lookup ladder: the timeout of each attempt, in order. It
    /// is configuration rather than measurement, and is published so a client
    /// can say how long each attempt was given without guessing.
    pub attempt_timeouts_secs: Vec<u64>,
}

#[derive(Serialize)]
pub struct NextHopInfo {
    pub node_addr: String,
    pub display_name: String,
    pub class: &'static str,
    pub direct_peer: bool,
    /// True when the first hop leaves the up-then-down tree walk that
    /// `tree_hops_*` describes.
    pub leaves_tree_walk: bool,
}

#[derive(Serialize)]
pub struct PathStage {
    #[serde(flatten)]
    pub status: StageStatus,
    /// Always true: these facts are computed here from coordinates.
    pub computed_locally: bool,
    /// Always false: no hop beyond the first was contacted.
    pub observed: bool,
    /// False when no coordinates were available, in which case every field
    /// below that describes the tree is null rather than a computed value. A
    /// resolve failure and a fresh direct peer both land here, and neither
    /// justifies a claim about the spanning tree.
    pub coords_known: bool,
    pub our_coords: Vec<String>,
    pub their_coords: Vec<String>,
    pub our_depth: Option<usize>,
    pub their_depth: Option<usize>,
    pub same_root: Option<bool>,
    pub lca: Option<String>,
    pub lca_depth: Option<usize>,
    /// Tree metric, not a predicted hop count.
    pub tree_hops_up: Option<usize>,
    pub tree_hops_down: Option<usize>,
    /// Upper bound on the real hop count; a crosslink cut-through shortens it.
    pub tree_distance: Option<usize>,
    pub next_hop: Option<NextHopInfo>,
    pub no_hop_reason: Option<&'static str>,
}

#[derive(Serialize)]
pub struct SessionStage {
    #[serde(flatten)]
    pub status: StageStatus,
    /// An entry existed at the moment the probe would have opened one, so the
    /// probe neither opened nor closed it.
    pub preexisting: bool,
    pub established: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_mtu: Option<u32>,
}

#[derive(Serialize)]
pub struct RttStage {
    #[serde(flatten)]
    pub status: StageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srtt_ms: Option<f64>,
    /// Deltas measured across the probe.
    pub reports_seen: u64,
    pub samples: u64,
    pub zero_samples: u64,
    pub arith_failures: u64,
}

#[derive(Serialize)]
pub struct CleanupInfo {
    pub session_created_and_torn_down: bool,
    pub session_left_intact: bool,
    /// "preexisting" | "adopted_by_traffic" | "replaced" | null
    pub left_intact_reason: Option<&'static str>,
    pub lookup_issued: bool,
    /// The coord-cache and identity-cache entries a lookup produced are
    /// deliberately not evicted; these say what was already there.
    pub coords_were_cached: bool,
    pub identity_was_cached: bool,
    pub warmups_sent: u8,
}

#[derive(Serialize)]
pub struct ProbeReport {
    pub probe_id: u64,
    pub target: TargetInfo,
    /// "running" | "ok" | "partial" | "failed" | "cancelled"
    pub overall: &'static str,
    pub elapsed_ms: u64,
    /// Tick period in ms. Every stage duration is quantized to this.
    pub tick_ms: u64,
    pub bloom: BloomStage,
    pub discovery: DiscoveryStage,
    pub path: PathStage,
    pub session: SessionStage,
    pub rtt: RttStage,
    pub cleanup: CleanupInfo,
}

impl ProbeReport {
    /// Project a live job into its report. `now_ms` is monotonic, used only
    /// for the elapsed figure of a job that has not finished.
    pub(crate) fn build(node: &Node, job: &ProbeJob, now_ms: u64) -> Self {
        let snap = job.probe().snapshot();
        let target = *job.target();
        Self {
            probe_id: job.id(),
            target: TargetInfo {
                npub: job.npub().to_string(),
                node_addr: target.to_string(),
                display_name: node.peer_display_name(&target),
                ipv6_addr: crate::FipsAddress::from_node_addr(&target).to_string(),
            },
            overall: snap.overall.name(),
            elapsed_ms: job.probe().elapsed_ms(now_ms),
            tick_ms: snap.tick_ms,
            bloom: BloomStage {
                status: (&snap.bloom).into(),
                fanout: snap.lookup_fanout,
            },
            discovery: DiscoveryStage {
                status: (&snap.discovery).into(),
                source: snap.resolve_source.map(|s| s.name()),
                attempts: job.lookup_attempts(),
                attempt_timeouts_secs: node.config().node.lookup.attempt_timeouts_secs.clone(),
            },
            path: path_stage(node, &snap),
            session: SessionStage {
                status: (&snap.session).into(),
                preexisting: snap.session_preexisting,
                established: snap.session_established,
                path_mtu: snap.path_mtu,
            },
            rtt: RttStage {
                status: (&snap.rtt).into(),
                rtt_ms: snap.rtt_ms,
                srtt_ms: snap.srtt_ms,
                reports_seen: snap.counters.reports_seen,
                samples: snap.counters.samples,
                zero_samples: snap.counters.zero,
                arith_failures: snap.counters.arith_fail,
            },
            cleanup: cleanup_info(job, &snap),
        }
    }
}

fn path_stage(node: &Node, snap: &ProbeSnapshot) -> PathStage {
    let facts = snap.path_facts.as_ref();
    PathStage {
        status: (&snap.path).into(),
        computed_locally: true,
        observed: false,
        coords_known: facts.is_some(),
        our_coords: facts.map_or_else(Vec::new, |f| {
            f.our_coords.iter().map(|a| a.to_string()).collect()
        }),
        their_coords: facts.map_or_else(Vec::new, |f| {
            f.their_coords.iter().map(|a| a.to_string()).collect()
        }),
        our_depth: facts.map(|f| f.our_depth),
        their_depth: facts.map(|f| f.their_depth),
        same_root: facts.map(|f| f.same_root),
        lca: facts.and_then(|f| f.lca.map(|a| a.to_string())),
        lca_depth: facts.and_then(|f| f.lca_depth),
        tree_hops_up: facts.and_then(|f| f.tree_hops_up),
        tree_hops_down: facts.and_then(|f| f.tree_hops_down),
        tree_distance: facts.and_then(|f| f.tree_distance),
        next_hop: snap.next_hop.as_ref().map(|h| NextHopInfo {
            node_addr: h.node_addr.to_string(),
            display_name: node.peer_display_name(&h.node_addr),
            class: h.class.name(),
            direct_peer: h.direct_peer,
            leaves_tree_walk: h.leaves_tree_walk,
        }),
        no_hop_reason: snap.no_hop_reason.map(|r| r.name()),
    }
}

fn cleanup_info(job: &ProbeJob, snap: &ProbeSnapshot) -> CleanupInfo {
    // A drive-time refusal overrides the core's decision: the action was
    // emitted but the guard declined, so the session is still there.
    let refused = job.teardown_refused();
    let torn_down = snap.torn_down && refused.is_none();
    let left_intact = refused.or(snap.left_intact);
    CleanupInfo {
        session_created_and_torn_down: torn_down,
        session_left_intact: left_intact.is_some(),
        left_intact_reason: left_intact.map(|r| r.name()),
        lookup_issued: snap.lookup_issued,
        coords_were_cached: snap.coords_were_cached,
        identity_was_cached: snap.identity_was_cached,
        warmups_sent: snap.warmups_sent,
    }
}
