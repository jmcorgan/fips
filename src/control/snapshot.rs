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
    /// Configured peer aliases, keyed by `NodeAddr`. Effectively immutable
    /// after construction; shared to avoid a per-tick map clone.
    pub peer_aliases: Arc<HashMap<NodeAddr, String>>,
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
            peer_aliases: Arc::new(HashMap::new()),
        }
    }
}
