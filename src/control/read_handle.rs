//! Read-only handle the control accept loop holds, so pure-snapshot `show_*`
//! queries can render off the rx_loop hot path instead of round-tripping the
//! mpsc → rx_loop oneshot.
//!
//! The handle bundles the node state that is independently shareable, plus one
//! `ArcSwap` snapshot cell per read subsystem:
//!
//! - `context` / `metrics` — already `Arc`-shared.
//! - `stats` — `ArcSwap<StatsSnapshot>`: stats_history dual-ring + the scalar
//!   gauges `show_status` needs, published from the tick.
//! - `routing` — `ArcSwap<RoutingSnapshot>`: tree / bloom / coord / identity,
//!   published from the tick.
//! - `entities` — `ArcSwap<EntitySnapshot>`: peers / sessions / links /
//!   connections / transports, published from the tick with `Vec<Arc<Row>>`
//!   structural sharing.
//!
//! Publisher placement: all three snapshot cells are published from the
//! periodic tick, which runs as one arm of the rx_loop's `select!`. Publishing
//! therefore costs the rx_loop; what the handle removes is the read-side round
//! trip out to the rx_loop and back, not the cost of publishing. The
//! `publish_routing_snapshot` and `publish_entities_snapshot` doc comments on
//! `Node` carry the reasoning for the two projections that need coherent
//! `&Node` access across subsystems.
//!
//! A projection is a point-in-time copy, not a live view. The entity tables in
//! particular are mutated on the packet path between ticks, so a reader sees
//! the state as of the last publish.
//!
//! [`snapshot_dispatch`] is the seam: it serves the commands in its match arms
//! directly from the handle and returns `None` for everything else, so the
//! caller falls back to the mpsc → rx_loop path.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::node::context::NodeContext;
use crate::node::metrics::MetricsRegistry;

use super::protocol::{Request, Response};
use super::snapshot::{EntitySnapshot, RoutingSnapshot, StatsSnapshot};

/// Cloneable read-only view of node state for off-loop control serving.
///
/// All fields are `Arc` / `ArcSwap` handles, so cloning is cheap and a clone
/// can be held by every accepted control connection. The snapshot cells are
/// read by the `*_from_handle` query functions that [`snapshot_dispatch`]
/// routes to.
#[derive(Clone)]
pub(crate) struct ControlReadHandle {
    /// Effectively-immutable node context (config, identity, limits).
    context: Arc<NodeContext>,
    /// Metrics registry (counters / gauges) for `show_stats_*`.
    metrics: Arc<MetricsRegistry>,
    /// stats_history dual-ring read copy + the scalar gauges/counts
    /// `show_status` needs, published from the tick.
    stats: Arc<ArcSwap<StatsSnapshot>>,
    /// Derived/routing/cache read view (tree / bloom / coord /
    /// identity + F-queue scalars), published from the tick.
    routing: Arc<ArcSwap<RoutingSnapshot>>,
    /// Per-entity table read view (peers / sessions / links /
    /// connections / transports + mmp), published from the tick with
    /// `Vec<Arc<Row>>` structural sharing.
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
    /// construction; no IO_TIMEOUT staleness gate).
    pub(crate) fn stats(&self) -> arc_swap::Guard<Arc<StatsSnapshot>> {
        self.stats.load()
    }

    /// Load the latest published routing snapshot (freshest
    /// available by construction; no staleness gate).
    pub(crate) fn routing(&self) -> arc_swap::Guard<Arc<RoutingSnapshot>> {
        self.routing.load()
    }

    /// Load the latest published entity snapshot (freshest available
    /// by construction; no staleness gate).
    pub(crate) fn entities(&self) -> arc_swap::Guard<Arc<EntitySnapshot>> {
        self.entities.load()
    }
}

/// Attempt to serve a request entirely from the read handle, off the rx_loop.
///
/// Returns `Some(response)` when the command can be rendered from the bundled
/// snapshot cells, or `None` when it must take the mpsc → rx_loop path.
///
/// The queries served here read any of the cells the handle bundles —
/// `context`, `metrics`, `stats`, `routing`, `entities` — plus host-OS facts
/// gathered in [`super::listening`] and [`super::firewall_state`], so they
/// render in the control task without touching `Node`. Taking a parameter is
/// not what decides it: `show_stats_history` is parameterized and is served
/// here. What falls back is a query needing live `Node` state the snapshot does
/// not carry, and every mutation.
///
/// **It now also carries mutating commands**, namely the `profile_tick_*`
/// family under the `profiling` feature. They are served here rather than on
/// the rx_loop deliberately: all of their state is process statics, they need
/// no `&mut Node`, and routing them through the loop would make the toggle
/// queue behind the very behavior it exists to measure.
pub(crate) fn snapshot_dispatch(request: &Request, handle: &ControlReadHandle) -> Option<Response> {
    use crate::control::queries;

    match request.command.as_str() {
        // Tick-body profiler toggle. Present only in a `--features profiling`
        // build; otherwise these fall through to the rx_loop dispatch, which
        // reports them as unknown commands.
        #[cfg(feature = "profiling")]
        "profile_tick_on" => {
            let dir = request
                .params
                .as_ref()
                .and_then(|p| p.get("dir"))
                .and_then(|v| v.as_str());
            let context = handle.context();
            let npub = context.identity.npub();
            let period = context.config.node.tick_interval_secs;
            Some(match crate::instr::capture::start(dir, &npub, period) {
                Ok(value) => Response::ok(value),
                Err(e) => Response::error(e),
            })
        }
        #[cfg(feature = "profiling")]
        "profile_tick_off" => Some(match crate::instr::capture::stop() {
            Ok(value) => Response::ok(value),
            Err(e) => Response::error(e),
        }),
        #[cfg(feature = "profiling")]
        "profile_tick_status" => Some(Response::ok(crate::instr::capture::status())),
        "show_listening_sockets" => Some(Response::ok(
            queries::show_listening_sockets_from_handle(handle),
        )),
        "show_stats_list" => Some(Response::ok(queries::show_stats_list())),
        "show_metrics" => Some(Response::ok(queries::show_metrics_from_handle(handle))),
        // Peer-ACL status, served from the tick-published `StatsSnapshot`.
        // The ACL is an `arc_swap::ArcSwap<PeerAcl>` reloaded only on the tick;
        // its status projection is captured at the same tick.
        "show_acl" => Some(Response::ok(queries::show_acl_from_handle(handle))),
        // Served from the tick-published `StatsSnapshot` (rings + scalar
        // gauges/counts). `show_status` and the two node-level/per-peer series
        // queries carry enough data in the snapshot to render faithfully
        // off-loop, including the parameterized series selectors (the snapshot
        // holds the full rings, so any metric / window / granularity is
        // satisfiable).
        //
        // The per-peer stats queries: `show_stats_peers` and
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
        // Served from the tick-published `RoutingSnapshot` (tree / bloom /
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
        // Served from the tick-published `EntitySnapshot` (per-entity
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
