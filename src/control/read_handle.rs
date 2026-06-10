//! Read-only handle the control accept loop holds, so pure-snapshot `show_*`
//! queries can render off the rx_loop hot path instead of round-tripping the
//! mpsc → rx_loop oneshot.
//!
//! This is the stable seam of the control read-isolation milestone
//! (TASK-2026-0152, phase R0). The handle bundles the state that is already
//! independently shareable, and grows one `ArcSwap` snapshot cell per phase as
//! each subsystem's read state is published from its natural mutator:
//!
//! - `context` / `metrics` — already `Arc`-shared (refactor steps B/C).
//! - `stats` (R2) — `ArcSwap<StatsSnapshot>`: stats_history dual-ring + the
//!   scalar gauges `show_status` needs, published from the tick.
//! - `routing` (R3) — `ArcSwap<RoutingSnapshot>`: tree / bloom / coord /
//!   identity, published from their announce / discovery mutators.
//! - `entities` (R4) — `ArcSwap<EntitySnapshot>`: peers / sessions / links /
//!   connections / transports, published per-entity with `Vec<Arc<Row>>`
//!   structural sharing.
//!
//! Publisher placement follows the Q1 rules in
//! `design/fast-path-refactoring-r0-read-handle.md`: every snapshot is
//! published at its state's natural mutation site (on-change), never by the
//! contended rx_loop task it is meant to bypass.
//!
//! R0 ships only the type and the dispatch seam ([`snapshot_dispatch`]); no
//! query reads the handle yet. Cutover begins in R1.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::node::context::NodeContext;
use crate::node::metrics::MetricsRegistry;

use super::protocol::{Request, Response};
use super::snapshot::{EntitySnapshot, RoutingSnapshot, StatsSnapshot};

/// Cloneable read-only view of node state for off-loop control serving.
///
/// All fields are `Arc` / `ArcSwap` handles, so cloning is cheap and a clone
/// can be held by every accepted control connection. Fields are consumed
/// starting R1 as `show_*` queries cut over to off-loop rendering; until then
/// they are wired but unread.
#[derive(Clone)]
pub(crate) struct ControlReadHandle {
    /// Effectively-immutable node context (config, identity, limits).
    context: Arc<NodeContext>,
    /// Metrics registry (counters / gauges) for `show_stats_*`.
    metrics: Arc<MetricsRegistry>,
    /// stats_history dual-ring read copy + the scalar gauges/counts
    /// `show_status` needs, published from the tick (R2, Q1-b).
    stats: Arc<ArcSwap<StatsSnapshot>>,
    /// Category-D derived/routing/cache read view (tree / bloom / coord /
    /// identity + F-queue scalars), published from the tick (R3).
    routing: Arc<ArcSwap<RoutingSnapshot>>,
    /// Category-E per-entity table read view (peers / sessions / links /
    /// connections / transports + mmp), published from the tick with
    /// `Vec<Arc<Row>>` structural sharing (R4).
    entities: Arc<ArcSwap<EntitySnapshot>>,
}

impl ControlReadHandle {
    /// Build the handle from the node's already-shared state. Called once at
    /// control-socket spawn time; the result is cloned per connection. The
    /// `stats` cell is the same `Arc` the tick publishes into, so every clone
    /// observes fresh snapshots.
    pub(crate) fn new(
        context: Arc<NodeContext>,
        metrics: Arc<MetricsRegistry>,
        stats: Arc<ArcSwap<StatsSnapshot>>,
        routing: Arc<ArcSwap<RoutingSnapshot>>,
        entities: Arc<ArcSwap<EntitySnapshot>>,
    ) -> Self {
        Self {
            context,
            metrics,
            stats,
            routing,
            entities,
        }
    }

    /// Borrow the effectively-immutable node context.
    pub(crate) fn context(&self) -> &NodeContext {
        &self.context
    }

    /// Borrow the metrics registry.
    pub(crate) fn metrics(&self) -> &MetricsRegistry {
        &self.metrics
    }

    /// Load the latest published stats snapshot (the freshest available by
    /// construction; no IO_TIMEOUT staleness gate, per Q1-e).
    pub(crate) fn stats(&self) -> arc_swap::Guard<Arc<StatsSnapshot>> {
        self.stats.load()
    }

    /// Load the latest published Category-D routing snapshot (freshest
    /// available by construction; no staleness gate, per Q1-e).
    pub(crate) fn routing(&self) -> arc_swap::Guard<Arc<RoutingSnapshot>> {
        self.routing.load()
    }

    /// Load the latest published Category-E entity snapshot (freshest available
    /// by construction; no staleness gate, per Q1-e).
    pub(crate) fn entities(&self) -> arc_swap::Guard<Arc<EntitySnapshot>> {
        self.entities.load()
    }
}

/// Attempt to serve a request entirely from the read handle, off the rx_loop.
///
/// Returns `Some(response)` when the command is a pure-snapshot query that has
/// been cut over to off-loop rendering, or `None` when it must take the
/// mpsc → rx_loop path (parameterized queries, mutations, and any query not
/// yet cut over).
///
/// Cutover queries (R1) read only `NodeContext` / `MetricsRegistry` (the state
/// the read handle already bundles) plus host-OS facts (`/proc`, nftables), so
/// they render entirely in the control task without touching `Node`.
pub(crate) fn snapshot_dispatch(request: &Request, handle: &ControlReadHandle) -> Option<Response> {
    use crate::control::queries;

    match request.command.as_str() {
        "show_listening_sockets" => Some(Response::ok(
            queries::show_listening_sockets_from_handle(handle),
        )),
        "show_stats_list" => Some(Response::ok(queries::show_stats_list())),
        "show_metrics" => Some(Response::ok(queries::show_metrics_from_handle(handle))),
        // R5: peer-ACL status, served from the tick-published `StatsSnapshot`.
        // The ACL is an `arc_swap::ArcSwap<PeerAcl>` reloaded only on the tick;
        // its status projection is captured at the same tick.
        "show_acl" => Some(Response::ok(queries::show_acl_from_handle(handle))),
        // R2: served from the tick-published `StatsSnapshot` (rings + scalar
        // gauges/counts). `show_status` and the two node-level/per-peer series
        // queries carry enough data in the snapshot to render faithfully
        // off-loop, including the parameterized series selectors (the snapshot
        // holds the full rings, so any metric / window / granularity is
        // satisfiable).
        //
        // R5 closes out the per-peer stats queries: `show_stats_peers` and
        // `show_stats_history_all_peers` now read the snapshot's per-peer
        // `peer_meta` (live `is_active`, resolved npub / display name, captured
        // at publish time) joined against the `history` rings, so they no longer
        // need live `&Node` and render off-loop too.
        "show_status" => Some(Response::ok(queries::show_status_from_handle(handle))),
        "show_stats_history" => Some(queries::show_stats_history_from_handle(
            handle,
            request.params.as_ref(),
        )),
        "show_stats_all_history" => Some(queries::show_stats_all_history_from_handle(
            handle,
            request.params.as_ref(),
        )),
        "show_stats_peers" => Some(Response::ok(queries::show_stats_peers_from_handle(handle))),
        "show_stats_history_all_peers" => Some(queries::show_stats_history_all_peers_from_handle(
            handle,
            request.params.as_ref(),
        )),
        // R3: served from the tick-published `RoutingSnapshot` (tree / bloom /
        // coord cache / identity cache + F-queue scalars). Display names are
        // resolved at publish time, so these render entirely off-loop. The
        // counter-family `stats` blocks come from the `MetricsRegistry` (also
        // in the handle). All five are parameterless.
        "show_tree" => Some(Response::ok(queries::show_tree_from_handle(handle))),
        "show_bloom" => Some(Response::ok(queries::show_bloom_from_handle(handle))),
        "show_cache" => Some(Response::ok(queries::show_cache_from_handle(handle))),
        "show_routing" => Some(Response::ok(queries::show_routing_from_handle(handle))),
        "show_identity_cache" => Some(Response::ok(queries::show_identity_cache_from_handle(
            handle,
        ))),
        // R4: served from the tick-published `EntitySnapshot` (per-entity
        // `Vec<Arc<Row>>` tables with structural sharing). Display names,
        // tree-relationship flags, and Nostr-traversal state are resolved at
        // publish time, so these render entirely off-loop. All six are
        // parameterless.
        "show_peers" => Some(Response::ok(queries::show_peers_from_handle(handle))),
        "show_sessions" => Some(Response::ok(queries::show_sessions_from_handle(handle))),
        "show_links" => Some(Response::ok(queries::show_links_from_handle(handle))),
        "show_connections" => Some(Response::ok(queries::show_connections_from_handle(handle))),
        "show_transports" => Some(Response::ok(queries::show_transports_from_handle(handle))),
        "show_mmp" => Some(Response::ok(queries::show_mmp_from_handle(handle))),
        _ => None,
    }
}
