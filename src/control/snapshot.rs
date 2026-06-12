//! Read-side state snapshots published from the node's natural mutators so
//! pure-snapshot `show_*` queries render off the rx_loop hot path.
//!
//! [`StatsSnapshot`] is the R2 reference implementation of the canonical
//! snapshot pattern (see `design/fast-path-refactoring-r0-read-handle.md`): a
//! read-only data bundle published via `ArcSwap` from the tick after
//! `StatsHistory::tick()`. It carries
//!
//! - the `stats_history` read-side rings (the "dual-ring": the live mutable
//!   ring stays on the tick; this is the cloned read copy), and
//! - the cheap scalar gauges `show_status` needs (`estimated_mesh_size`,
//!   node `state`, `tun_state`, `tun_name`, `effective_ipv6_mtu`, and the
//!   peer / session / link / connection / transport counts), plus
//!   `peer_aliases` (effectively immutable after construction).
//!
//! The snapshot holds *data*, not rendered `Response` envelopes (Q1-d):
//! rendering happens in the control task off the rx_loop. Staleness is bounded
//! by the tick interval and is never staler than the underlying data, which
//! also advances only on the tick (Q1-b).

use std::collections::HashMap;
use std::sync::Arc;

use crate::identity::NodeAddr;
use crate::node::NodeState;
use crate::node::acl::PeerAclStatus;
use crate::node::stats_history::StatsHistory;
use crate::upper::tun::TunState;

/// Read-only snapshot of the stats-history rings plus the scalar gauges and
/// counts `show_status` reports. Published from the tick (Q1-b).
#[derive(Clone)]
pub(crate) struct StatsSnapshot {
    /// Cloned read copy of the history rings (the dual-ring read side).
    pub history: Arc<StatsHistory>,
    /// Cached estimated mesh size, or `None` when no estimate is available.
    pub estimated_mesh_size: Option<u64>,
    /// Node operational state.
    pub state: NodeState,
    /// TUN device state.
    pub tun_state: TunState,
    /// TUN interface name, if active.
    pub tun_name: Option<String>,
    /// Effective IPv6 MTU over the mesh.
    pub effective_ipv6_mtu: u16,
    /// Number of pending connections (handshake in progress).
    pub connection_count: usize,
    /// Number of authenticated peers.
    pub peer_count: usize,
    /// Number of active links.
    pub link_count: usize,
    /// Number of active transports.
    pub transport_count: usize,
    /// Number of active sessions.
    pub session_count: usize,
    /// Current spanning-tree root `NodeAddr` (rendered as hex by `show_status`).
    pub root: NodeAddr,
    /// Whether this node is the spanning-tree root.
    pub is_root: bool,
    /// Per-configured-transport-type count of peers whose active link rides that
    /// transport type. Configured-but-idle types appear with a zero count.
    /// Keyed by the transport type name (`"udp"`, `"tcp"`, `"tor"`, ...).
    pub transport_peer_counts: std::collections::BTreeMap<String, usize>,
    /// Configured peer aliases, keyed by `NodeAddr`. Effectively immutable
    /// after construction; shared to avoid a per-tick map clone.
    pub peer_aliases: Arc<HashMap<NodeAddr, String>>,
    /// Loaded peer-ACL status (`show_acl`). The ACL itself is an
    /// `arc_swap::ArcSwap<PeerAcl>` mutated only by the tick's `reload_peer_acl`;
    /// the human-readable status is a cheap projection of it (R5).
    pub acl_status: PeerAclStatus,
    /// Per-stats-history-peer metadata resolved against the live peer/session
    /// tables and host map at publish time (`show_stats_peers` /
    /// `show_stats_history_all_peers`), keyed by `NodeAddr`. The lifecycle
    /// timestamps and per-peer metric rings stay in `history`; this map carries
    /// only the cross-subsystem fields a renderer can't derive from the rings
    /// alone (`is_active`, resolved `npub`, resolved `display_name`) (R5).
    pub peer_meta: Arc<HashMap<NodeAddr, StatsPeerMeta>>,
}

/// Cross-subsystem metadata for one peer tracked in the stats-history rings,
/// resolved at publish time. Joined against `StatsSnapshot::history`'s rings
/// (lifecycle timestamps + metric series) by the off-loop `show_stats_peers` /
/// `show_stats_history_all_peers` renderers.
#[derive(Clone)]
pub(crate) struct StatsPeerMeta {
    /// Whether this peer is currently in the live authenticated-peer table.
    pub is_active: bool,
    /// Resolved npub (live peer npub, or `node_addr` hex when not a live peer),
    /// matching the on-loop `show_stats_peers` fallback.
    pub npub: String,
    /// Display name resolved via `Node::peer_display_name` at publish time.
    pub display_name: String,
}

impl StatsSnapshot {
    /// Build an empty snapshot for seeding the `ArcSwap` cell at construction,
    /// before the first tick has published real state.
    pub(crate) fn empty() -> Self {
        Self {
            history: Arc::new(StatsHistory::new()),
            estimated_mesh_size: None,
            state: NodeState::Created,
            tun_state: TunState::Disabled,
            tun_name: None,
            effective_ipv6_mtu: 0,
            connection_count: 0,
            peer_count: 0,
            link_count: 0,
            transport_count: 0,
            session_count: 0,
            root: zero_addr(),
            is_root: false,
            transport_peer_counts: std::collections::BTreeMap::new(),
            peer_aliases: Arc::new(HashMap::new()),
            acl_status: empty_acl_status(),
            peer_meta: Arc::new(HashMap::new()),
        }
    }
}

/// An empty/default [`PeerAclStatus`] for seeding the snapshot before the first
/// tick publishes the real ACL status. `PeerAclStatus` does not derive
/// `Default`, so this spells out the inert "no ACL loaded" shape.
fn empty_acl_status() -> PeerAclStatus {
    PeerAclStatus {
        allow_file: String::new(),
        deny_file: String::new(),
        enforcement_active: false,
        effective_mode: String::new(),
        default_decision: String::new(),
        allow_all: false,
        deny_all: false,
        allow_file_entries: Vec::new(),
        deny_file_entries: Vec::new(),
        allow_entries: Vec::new(),
        deny_entries: Vec::new(),
    }
}

// =====================================================================
// RoutingSnapshot (R3 — Category-D derived/routing/cache read view)
// =====================================================================

/// Read-only snapshot of the Category-D derived/routing/cache subsystems that
/// the pure-snapshot `show_tree` / `show_bloom` / `show_cache` / `show_routing`
/// / `show_identity_cache` queries render. Published via `ArcSwap`.
///
/// The R0 stub (`design/fast-path-refactoring-r0-read-handle.md`) names a
/// single combined `ArcSwap<RoutingSnapshot>` for R3. This is that cell: one
/// cohesive routing view holding the four subsystems (tree / bloom / coord
/// cache / identity cache) plus the F-queue summary scalars.
///
/// **Publisher placement (Q1).** The four subsystems mutate at many scattered
/// handler sites (28 `coord_cache_mut` call sites, 16 `tree_state_mut`, ~32
/// identity-cache touches), and every projected row needs a *display name*
/// resolved against the live peer/session tables and host map — Category-E
/// state reachable only with `&Node`. Wiring an on-change `publish_*` at each
/// mutation site would be large, error-prone surgery, and each call would still
/// need `&Node` to resolve names across subsystem boundaries. So this snapshot
/// is published from the **tick** (Q1-b acceptable-at-mutator / the documented
/// interim the spec permits, mirroring R2's stats publish): the tick is the one
/// site with coherent `&Node` access to resolve all display names together. A
/// single combined cell is the natural shape because there is exactly one
/// publisher — the multi-mutator "rebuild the whole snapshot N times" hazard
/// that Q1-c warns against does not arise.
///
/// The snapshot holds *data* (typed rows + scalars), not rendered `Response`
/// envelopes (Q1-d); rendering happens off the rx_loop in the control task. The
/// counter-family `stats` blocks the queries also emit come from the
/// `MetricsRegistry` (already `Arc`-shared in the handle) at render time, not
/// from this snapshot.
///
/// Time-relative fields (`age_ms`, `idle_ms`) are derived at render time from
/// the captured absolute timestamps, so the rendered age stays fresh relative
/// to the read, exactly as the on-loop queries computed it.
///
/// Forward-compat: when step 5 structurally extracts the Category-D subsystems
/// into typed types, these projections become thin views over them without
/// changing the read-handle interface or this publisher placement.
#[derive(Clone)]
pub(crate) struct RoutingSnapshot {
    /// Spanning-tree read view (`show_tree`).
    pub tree: TreeView,
    /// Bloom-filter read view (`show_bloom`).
    pub bloom: BloomView,
    /// Coordinate-cache read view (`show_cache`, `show_routing`).
    pub cache: CacheView,
    /// F-queue / discovery routing scalars + rows (`show_routing`).
    pub routing: RoutingView,
    /// Identity-cache read view (`show_identity_cache`, `show_routing`).
    pub identity: IdentityView,
}

impl RoutingSnapshot {
    /// Build an empty snapshot for seeding the `ArcSwap` cell at construction,
    /// before the first tick has published real state.
    pub(crate) fn empty() -> Self {
        Self {
            tree: TreeView::default(),
            bloom: BloomView::default(),
            cache: CacheView::default(),
            routing: RoutingView::default(),
            identity: IdentityView::default(),
        }
    }
}

/// Zero `NodeAddr` for empty/seed views (all-zero 16 bytes).
fn zero_addr() -> NodeAddr {
    NodeAddr::from_bytes([0u8; 16])
}

/// Spanning-tree read view for `show_tree`.
#[derive(Clone)]
pub(crate) struct TreeView {
    pub my_node_addr: NodeAddr,
    pub root: NodeAddr,
    /// Resolved npub of the root node, when discoverable (self when root, a live
    /// peer's attested npub, or an identity-cache hit); `None` otherwise.
    pub root_npub: Option<String>,
    pub is_root: bool,
    pub depth: usize,
    /// `my_coords` entries as `NodeAddr`s (rendered as hex).
    pub my_coords: Vec<NodeAddr>,
    pub parent: NodeAddr,
    pub parent_display_name: String,
    pub declaration_sequence: u64,
    pub declaration_signed: bool,
    pub peer_tree_count: usize,
    pub peers: Vec<TreePeerRow>,
}

impl Default for TreeView {
    fn default() -> Self {
        Self {
            my_node_addr: zero_addr(),
            root: zero_addr(),
            root_npub: None,
            is_root: false,
            depth: 0,
            my_coords: Vec::new(),
            parent: zero_addr(),
            parent_display_name: String::new(),
            declaration_sequence: 0,
            declaration_signed: false,
            peer_tree_count: 0,
            peers: Vec::new(),
        }
    }
}

/// One peer's tree position in `show_tree`.
#[derive(Clone)]
pub(crate) struct TreePeerRow {
    pub node_addr: NodeAddr,
    pub display_name: String,
    /// Present only when the peer's coordinates are known.
    pub coords: Option<TreePeerCoords>,
}

/// Coordinate detail for a tree peer (present only when known).
#[derive(Clone)]
pub(crate) struct TreePeerCoords {
    pub depth: usize,
    pub root: NodeAddr,
    pub coord_path: Vec<NodeAddr>,
    pub distance_to_us: usize,
}

/// Bloom-filter read view for `show_bloom`.
#[derive(Clone)]
pub(crate) struct BloomView {
    pub own_node_addr: NodeAddr,
    pub is_leaf_only: bool,
    pub sequence: u64,
    pub leaf_dependents: Vec<NodeAddr>,
    pub peer_filters: Vec<BloomPeerRow>,
    /// Fill ratio of the last filter actually sent uptree (to the tree parent).
    /// `None` for a root node (nothing sent uptree) or before the first
    /// announce has been sent.
    pub uptree_fill_ratio: Option<f64>,
    /// Estimated cardinality of the last filter sent uptree — this node's whole
    /// subtree (self + tree-descendants, parent excluded), since bloom is
    /// split-horizon. `None` for root, pre-first-announce, or when the estimate
    /// is undefined for the saturation.
    pub uptree_estimated_count: Option<f64>,
}

impl Default for BloomView {
    fn default() -> Self {
        Self {
            own_node_addr: zero_addr(),
            is_leaf_only: false,
            sequence: 0,
            leaf_dependents: Vec::new(),
            peer_filters: Vec::new(),
            uptree_fill_ratio: None,
            uptree_estimated_count: None,
        }
    }
}

/// One peer's bloom-filter state in `show_bloom`.
#[derive(Clone)]
pub(crate) struct BloomPeerRow {
    pub peer: NodeAddr,
    pub display_name: String,
    pub has_filter: bool,
    pub filter_sequence: u64,
    /// Present only when the peer has supplied an inbound filter.
    pub filter: Option<BloomPeerFilter>,
}

/// Inbound-filter statistics for a bloom peer (present only when known).
#[derive(Clone)]
pub(crate) struct BloomPeerFilter {
    /// Estimated cardinality (`None` when undefined for the saturation),
    /// matching `BloomFilter::estimated_count`'s `Option<f64>`.
    pub estimated_count: Option<f64>,
    pub set_bits: usize,
    pub fill_ratio: f64,
}

/// Coordinate-cache read view for `show_cache` (and the cache scalars in
/// `show_routing`).
#[derive(Clone, Default)]
pub(crate) struct CacheView {
    pub count: usize,
    pub max_entries: usize,
    pub fill_ratio: f64,
    pub default_ttl_ms: u64,
    pub expired: usize,
    pub avg_age_ms: u64,
    pub entries: Vec<CacheEntryRow>,
}

/// One coordinate-cache entry in `show_cache`.
#[derive(Clone)]
pub(crate) struct CacheEntryRow {
    pub node_addr: NodeAddr,
    pub display_name: String,
    pub depth: usize,
    pub coord_path: Vec<NodeAddr>,
    /// Absolute creation time (Unix ms); `age_ms` derived at render time.
    pub created_at: u64,
    pub last_used_ms: u64,
    pub path_mtu: Option<u16>,
}

/// F-queue / discovery routing read view for `show_routing`.
#[derive(Clone, Default)]
pub(crate) struct RoutingView {
    pub pending_lookups: Vec<PendingLookupRow>,
    pub pending_tun_destinations: usize,
    pub pending_tun_packets: usize,
    pub recent_requests: usize,
    pub retries: Vec<RetryRow>,
}

/// One in-flight discovery lookup in `show_routing`.
#[derive(Clone)]
pub(crate) struct PendingLookupRow {
    pub target: NodeAddr,
    pub display_name: String,
    /// Absolute initiation time (Unix ms); `age_ms` derived at render time.
    pub initiated_ms: u64,
    pub last_sent_ms: u64,
    pub attempt: u8,
}

/// One connection-retry entry in `show_routing`.
#[derive(Clone)]
pub(crate) struct RetryRow {
    pub node_addr: NodeAddr,
    pub display_name: String,
    pub retry_count: u32,
    pub retry_after_ms: u64,
    pub auto_reconnect: bool,
}

/// Identity-cache read view for `show_identity_cache` (and the
/// `identity_cache_entries` scalar in `show_routing`).
#[derive(Clone, Default)]
pub(crate) struct IdentityView {
    pub entries: Vec<IdentityRow>,
    pub max_entries: usize,
}

/// One identity-cache entry in `show_identity_cache`.
#[derive(Clone)]
pub(crate) struct IdentityRow {
    pub node_addr: NodeAddr,
    pub npub: String,
    pub display_name: String,
    pub ipv6_addr: String,
    pub last_seen_ms: u64,
}

// =====================================================================
// EntitySnapshot (R4 — Category-E per-entity table read views)
// =====================================================================

/// Read-only snapshot of the Category-E per-entity tables that the
/// pure-snapshot `show_peers` / `show_sessions` / `show_links` /
/// `show_connections` / `show_transports` / `show_mmp` queries render.
/// Published via `ArcSwap`.
///
/// The R0 stub (`design/fast-path-refactoring-r0-read-handle.md`) pre-scopes
/// R4 as `entities — ArcSwap<EntitySnapshot>: peers / sessions / links /
/// connections / transports, published per-entity with `Vec<Arc<Row>>`
/// structural sharing`. This is that cell.
///
/// **Structural sharing (the umbrella mandate).** Every entity table is a
/// `Vec<Arc<Row>>`, so a republish in which only one row changed re-allocates
/// only that one `Arc<Row>` — the unchanged rows are reused by pointer from the
/// previous snapshot (`Arc::ptr_eq`-stable). The publisher diffs each freshly
/// projected row against the prior published row by value (`PartialEq`) and
/// keeps the old `Arc` when they are equal. A clone of the snapshot for each
/// accepted control connection is then a vector of cheap pointer clones, not a
/// deep table copy. This is what keeps the per-tick publish cost off the hot
/// path at scale, as the umbrella requires for R4.
///
/// **Publisher placement (Q1).** Like R3, this is published from the **tick**,
/// not per-mutator. Two reasons, both stronger than for R3:
///
/// 1. Every projected row needs a *display name* resolved against the live
///    peer/session tables and host map (`&Node`), and `show_peers` additionally
///    needs the live tree state to derive `is_parent` / `is_child` and the
///    Nostr-discovery failure-state map — cross-subsystem reads available only
///    with `&Node`.
/// 2. Most of the projected fields (link/session traffic counters, MMP
///    metrics, `last_seen`, noise counters, replay/decrypt counters) are
///    mutated continuously on the **data plane / rx_loop**, not at the discrete
///    peer/session/link lifecycle mutators. Per-lifecycle-mutator publication
///    (Q1-a) would therefore not even capture freshness for those fields; the
///    tick is the natural cadence at which this read view advances.
///
/// The diff-and-reuse therefore satisfies the structural-sharing goal the
/// umbrella mandates (only changed rows re-allocate) while keeping a single
/// coherent `&Node` publisher — the "no monolithic per-tick *re-allocation* of
/// every row" warning is honored because unchanged rows are reused, not rebuilt.
/// This is the documented acceptable interim (the spec's tick-publish-with-
/// Arc-reuse fallback), consistent with R3.
///
/// The snapshot holds typed rows (Q1-d data, not rendered `Response`
/// envelopes). Time-relative fields (`idle_ms`) are derived at render time from
/// captured absolute timestamps, so the rendered age stays fresh relative to
/// the read, exactly as the on-loop queries computed it.
///
/// Forward-compat: step 10 later extracts the session table into a typed
/// `(transport_id, our_index)`-indexed type; these projections then become thin
/// views over it without changing the read-handle interface or this publisher
/// placement.
#[derive(Clone)]
pub(crate) struct EntitySnapshot {
    /// `show_peers` rows.
    pub peers: Vec<Arc<PeerRow>>,
    /// `show_sessions` rows.
    pub sessions: Vec<Arc<SessionRow>>,
    /// `show_links` rows.
    pub links: Vec<Arc<LinkRow>>,
    /// `show_connections` rows.
    pub connections: Vec<Arc<ConnectionRow>>,
    /// `show_transports` rows.
    pub transports: Vec<Arc<TransportRow>>,
    /// `show_mmp` link-layer rows (peers with an MMP instance).
    pub mmp_peers: Vec<Arc<MmpPeerRow>>,
    /// `show_mmp` session-layer rows (sessions with an MMP instance).
    pub mmp_sessions: Vec<Arc<MmpSessionRow>>,
}

impl EntitySnapshot {
    /// Build an empty snapshot for seeding the `ArcSwap` cell at construction,
    /// before the first tick has published real state.
    pub(crate) fn empty() -> Self {
        Self {
            peers: Vec::new(),
            sessions: Vec::new(),
            links: Vec::new(),
            connections: Vec::new(),
            transports: Vec::new(),
            mmp_peers: Vec::new(),
            mmp_sessions: Vec::new(),
        }
    }
}

/// Per-peer link/transport/connectivity fields for `show_peers` derived from a
/// peer's resolved link (present only when the link is found).
#[derive(Clone, PartialEq)]
pub(crate) struct PeerLinkInfo {
    pub direction: String,
    /// Transport type name, present only when the transport handle is found.
    pub transport_type: Option<String>,
}

/// Nostr-traversal failure-state for a peer's npub in `show_peers`. Always
/// emitted (the on-loop query emits a default object even when absent); the
/// `present` flag distinguishes "seen by Nostr discovery" from the default.
#[derive(Clone, PartialEq)]
pub(crate) struct PeerNostrState {
    pub consecutive_failures: u32,
    pub cooldown_until_ms: Option<u64>,
    pub last_observed_skew_ms: Option<i64>,
}

/// Noise session counters surfaced in `show_peers` (present when the peer has a
/// Noise session).
#[derive(Clone, PartialEq)]
pub(crate) struct PeerNoiseCounters {
    pub send_counter: u64,
    pub highest_recv_counter: u64,
}

/// Link/session MMP metrics surfaced inline in `show_peers` (and the
/// per-session block in `show_sessions`). Fields mirror the on-loop projection;
/// `Option` fields are emitted only when present.
#[derive(Clone, PartialEq)]
pub(crate) struct EntityMmp {
    pub mode: String,
    pub srtt_ms: Option<f64>,
    pub loss_rate: f64,
    pub etx: f64,
    pub goodput_bps: f64,
    pub delivery_ratio_forward: f64,
    pub delivery_ratio_reverse: f64,
    pub smoothed_loss: Option<f64>,
    pub smoothed_etx: Option<f64>,
    /// `lqi` (peers) / `sqi` (sessions): present only when both `srtt_ms` and
    /// `smoothed_etx` are present. Precomputed so the render is a plain emit.
    pub quality_index: Option<f64>,
    /// Session-only: path MTU (`show_sessions`). `None` for peer rows.
    pub path_mtu: Option<u16>,
}

/// Link-layer stat counters for a peer in `show_peers`.
#[derive(Clone, PartialEq)]
pub(crate) struct PeerLinkStats {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// One authenticated peer in `show_peers`. Holds every field the on-loop
/// `show_peers` emits; `Option` fields gate the conditionally-emitted keys.
#[derive(Clone, PartialEq)]
pub(crate) struct PeerRow {
    pub node_addr: NodeAddr,
    pub npub: String,
    pub display_name: String,
    pub ipv6_addr: String,
    pub connectivity: String,
    pub link_id: u64,
    pub authenticated_at_ms: u64,
    pub last_seen_ms: u64,
    pub has_tree_position: bool,
    pub has_bloom_filter: bool,
    pub filter_sequence: u64,
    pub is_parent: bool,
    pub is_child: bool,
    pub transport_addr: Option<String>,
    pub link_info: Option<PeerLinkInfo>,
    pub tree_depth: Option<usize>,
    /// `effective_depth = tree_depth + link_cost` — the same quantity
    /// `evaluate_parent` ranks parent candidates on. `None` when the peer is
    /// unmeasured (no SRTT while other peers have it) or has no coords,
    /// mirroring the candidacy/cold-start rules. Pre-computed daemon-side so
    /// fipstop never recomputes it.
    pub effective_depth: Option<f64>,
    pub stats: PeerLinkStats,
    pub replay_suppressed: u32,
    pub consecutive_decrypt_failures: u32,
    pub nostr_traversal: PeerNostrState,
    pub noise: Option<PeerNoiseCounters>,
    pub our_session_index: Option<u32>,
    pub rekey_in_progress: bool,
    pub rekey_draining: bool,
    pub current_k_bit: bool,
    pub mmp: Option<EntityMmp>,
}

/// Traffic counters for a session in `show_sessions`.
#[derive(Clone, PartialEq)]
pub(crate) struct SessionStats {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// One end-to-end session in `show_sessions`.
#[derive(Clone, PartialEq)]
pub(crate) struct SessionRow {
    pub remote_addr: NodeAddr,
    pub display_name: String,
    pub state: &'static str,
    pub is_initiator: bool,
    pub last_activity_ms: u64,
    pub npub: String,
    pub stats: SessionStats,
    /// Handshake resend count, emitted only while not established.
    pub resend_count: Option<u32>,
    /// Established-only health block (session_start_ms, current_k_bit,
    /// coords_warmup_remaining, is_draining). `None` while handshaking.
    pub established: Option<SessionEstablished>,
    pub mmp: Option<EntityMmp>,
}

/// Established-session health fields in `show_sessions` (emitted only when the
/// session is established).
#[derive(Clone, PartialEq)]
pub(crate) struct SessionEstablished {
    pub session_start_ms: u64,
    pub current_k_bit: bool,
    pub coords_warmup_remaining: u8,
    pub is_draining: bool,
}

/// Stat counters for a link in `show_links`.
#[derive(Clone, PartialEq)]
pub(crate) struct LinkStats {
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub last_recv_ms: u64,
}

/// One active link in `show_links`.
#[derive(Clone, PartialEq)]
pub(crate) struct LinkRow {
    pub link_id: u64,
    pub transport_id: u32,
    pub remote_addr: String,
    pub direction: String,
    pub state: String,
    pub created_at_ms: u64,
    pub stats: LinkStats,
}

/// One pending handshake in `show_connections`. `idle_ms` is derived at render
/// time from the captured `last_activity_ms`.
#[derive(Clone, PartialEq)]
pub(crate) struct ConnectionRow {
    pub link_id: u64,
    pub direction: String,
    pub handshake_state: String,
    pub started_at_ms: u64,
    /// Absolute last-activity time (Unix ms); `idle_ms` derived at render time.
    pub last_activity_ms: u64,
    pub resend_count: u32,
    /// Expected peer npub, emitted only when the connection has an expected
    /// identity.
    pub expected_peer: Option<String>,
}

/// One transport instance in `show_transports`. The `stats` and
/// `tor_monitoring` fields are stored as already-projected `serde_json::Value`
/// (data, produced by the transport handle), not as rendered `Response`
/// envelopes.
#[derive(Clone, PartialEq)]
pub(crate) struct TransportRow {
    pub transport_id: u32,
    pub transport_type: String,
    pub state: String,
    pub mtu: u16,
    pub name: Option<String>,
    pub local_addr: Option<String>,
    pub tor_mode: Option<String>,
    pub onion_address: Option<String>,
    pub tor_monitoring: Option<serde_json::Value>,
    pub stats: serde_json::Value,
}

/// MMP trend labels for a peer's link-layer block in `show_mmp` (each present
/// only when the corresponding trend is initialized).
#[derive(Clone, PartialEq)]
pub(crate) struct MmpTrends {
    pub rtt_trend: Option<&'static str>,
    pub loss_trend: Option<&'static str>,
    pub goodput_trend: Option<&'static str>,
    pub jitter_trend: Option<&'static str>,
}

/// One peer's link-layer MMP block in `show_mmp`.
#[derive(Clone, PartialEq)]
pub(crate) struct MmpPeerRow {
    pub peer: NodeAddr,
    pub display_name: String,
    pub mode: String,
    pub loss_rate: f64,
    pub etx: f64,
    pub goodput_bps: f64,
    pub spin_bit_initiator: bool,
    pub smoothed_loss: Option<f64>,
    pub smoothed_etx: Option<f64>,
    pub srtt_ms: Option<f64>,
    /// `lqi`: present only when both `srtt_ms` and `smoothed_etx` are present.
    pub lqi: Option<f64>,
    pub trends: MmpTrends,
    pub delivery_ratio_forward: f64,
    pub delivery_ratio_reverse: f64,
    pub ecn_ce_count: u32,
}

/// MMP trend labels for a session's session-layer block in `show_mmp` (each
/// present only when the corresponding trend is initialized). Mirrors the
/// link-layer [`MmpTrends`] arrow semantics on the session columns: srtt
/// (`rtt_trend`), loss (`loss_trend`), etx (`etx_trend`).
#[derive(Clone, PartialEq)]
pub(crate) struct MmpSessionTrends {
    pub rtt_trend: Option<&'static str>,
    pub loss_trend: Option<&'static str>,
    pub etx_trend: Option<&'static str>,
}

/// One session's session-layer MMP block in `show_mmp`.
#[derive(Clone, PartialEq)]
pub(crate) struct MmpSessionRow {
    pub remote: NodeAddr,
    pub display_name: String,
    pub mode: String,
    pub loss_rate: f64,
    pub etx: f64,
    pub path_mtu: u16,
    pub smoothed_loss: Option<f64>,
    pub smoothed_etx: Option<f64>,
    pub srtt_ms: Option<f64>,
    /// `sqi`: present only when both `srtt_ms` and `smoothed_etx` are present.
    pub sqi: Option<f64>,
    pub trends: MmpSessionTrends,
}

/// Reconcile a freshly-projected entity table against the previously published
/// one, preserving structural sharing: an `Arc<Row>` from `prev` is reused
/// (kept by pointer) whenever a new row matches an old row by identity `key`
/// **and** compares equal by value, so only changed/new rows allocate a fresh
/// `Arc`. This is the `Vec<Arc<Row>>` discipline the R4 umbrella mandates — a
/// single-row change re-allocates one row, not the whole table, keeping the
/// per-tick publish cost off the hot path at scale.
///
/// `key` extracts a stable, hashable identity (e.g. `node_addr`, `link_id`) so
/// matching is order-independent across the source table's iteration order.
pub(crate) fn reconcile_rows<R, K, F>(prev: &[Arc<R>], new_rows: Vec<R>, key: F) -> Vec<Arc<R>>
where
    R: PartialEq,
    K: std::hash::Hash + Eq,
    F: Fn(&R) -> K,
{
    let index: HashMap<K, &Arc<R>> = prev.iter().map(|arc| (key(arc), arc)).collect();
    new_rows
        .into_iter()
        .map(|row| match index.get(&key(&row)) {
            Some(old) if ***old == row => Arc::clone(old),
            _ => Arc::new(row),
        })
        .collect()
}
