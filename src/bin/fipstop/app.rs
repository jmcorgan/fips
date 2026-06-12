use ratatui::widgets::TableState;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Tab {
    Node,
    Peers,
    Links,
    Sessions,
    Tree,
    Bloom,
    Mmp,
    Cache,
    Transports,
    Routing,
    Gateway,
    Graphs,
}

impl Tab {
    pub const ALL: [Tab; 10] = [
        Tab::Node,
        Tab::Peers,
        Tab::Transports,
        Tab::Sessions,
        Tab::Tree,
        Tab::Bloom,
        Tab::Mmp,
        Tab::Routing,
        Tab::Graphs,
        Tab::Gateway,
    ];

    /// Tab group index: 0 = Node, 1 = Connectivity, 2 = Internals, 3 = Gateway.
    pub fn group(&self) -> usize {
        match self {
            Tab::Node => 0,
            Tab::Peers | Tab::Transports => 1,
            Tab::Gateway => 3,
            Tab::Graphs => 2,
            _ => 2,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Node => "Node",
            Tab::Peers => "Peers",
            Tab::Links => "Links",
            Tab::Sessions => "Sessions",
            Tab::Tree => "Tree",
            Tab::Bloom => "Filters",
            Tab::Mmp => "Performance",
            Tab::Cache => "Cache",
            Tab::Transports => "Transports",
            Tab::Routing => "Routing",
            Tab::Gateway => "Gateway",
            Tab::Graphs => "Graphs",
        }
    }

    pub fn command(&self) -> &'static str {
        match self {
            Tab::Node => "show_status",
            Tab::Peers => "show_peers",
            Tab::Links => "show_links",
            Tab::Sessions => "show_sessions",
            Tab::Tree => "show_tree",
            Tab::Bloom => "show_bloom",
            Tab::Mmp => "show_mmp",
            Tab::Cache => "show_cache",
            Tab::Transports => "show_transports",
            Tab::Routing => "show_routing",
            Tab::Gateway => "show_gateway",
            // Graphs uses show_stats_history with params; fetched via a
            // dedicated path in main.rs rather than the generic command()
            // dispatcher.
            Tab::Graphs => "show_stats_history",
        }
    }

    pub fn index(&self) -> usize {
        Tab::ALL.iter().position(|t| t == self).unwrap()
    }

    pub fn next(&self) -> Tab {
        let i = self.index();
        Tab::ALL[(i + 1) % Tab::ALL.len()]
    }

    pub fn prev(&self) -> Tab {
        let i = self.index();
        Tab::ALL[(i + Tab::ALL.len() - 1) % Tab::ALL.len()]
    }

    /// The JSON key containing the data array for this tab's response.
    pub fn command_data_key(&self) -> &'static str {
        match self {
            Tab::Peers => "peers",
            Tab::Links => "links",
            Tab::Sessions => "sessions",
            Tab::Transports => "transports",
            Tab::Gateway => "mappings",
            _ => "",
        }
    }

    /// Whether this tab has a table view with row selection.
    pub fn has_table(&self) -> bool {
        matches!(
            self,
            Tab::Peers | Tab::Sessions | Tab::Transports | Tab::Gateway
        )
    }

    /// Number of focusable, independently-scrollable panes on this tab, for the
    /// multi-pane focus/scroll model. Returns 0 for tabs that don't participate
    /// (they use table selection or their own scroll instead). The Tree, Bloom
    /// (Filters), and Routing tabs each lay out three stacked panes; the
    /// Performance (Mmp) tab lays out two (Link MMP, Session MMP).
    pub fn scroll_pane_count(&self) -> usize {
        match self {
            Tab::Tree | Tab::Bloom | Tab::Routing => 3,
            Tab::Mmp => 2,
            _ => 0,
        }
    }
}

#[derive(Clone)]
pub enum ConnectionState {
    Connected,
    Disconnected(String),
}

pub struct DetailView {
    pub scroll: u16,
}

/// A pending Del-disconnect confirmation against a selected peer. Holds the
/// peer's npub (for the control command) and a human-readable label plus a
/// reconnect note tailored to the peer kind (or a generic line when the
/// connect-policy is not surfaced).
#[derive(Clone)]
pub struct ConfirmDisconnect {
    pub npub: String,
    pub display_name: String,
    pub reconnect_note: String,
}

#[derive(Clone, Copy)]
pub enum SelectedTreeItem {
    None,
    Transport(u64),
    Link,
}

/// Per-view column-sort state: the active sort column index and direction.
/// `s` cycles the column; `S` toggles direction. Default is column 0 ascending,
/// which for the name-first column layouts is an alphabetical-by-name order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SortState {
    pub col: usize,
    pub descending: bool,
}

impl SortState {
    /// Cycle to the next sort column (wrapping over `n` columns), resetting to
    /// ascending on a column change so a fresh column starts predictably.
    pub fn cycle_col(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        self.col = (self.col + 1) % n;
        self.descending = false;
    }

    /// Toggle the sort direction on the current column.
    pub fn toggle_dir(&mut self) {
        self.descending = !self.descending;
    }
}

/// Sortable column labels for the Link MMP table (sort key order matches the
/// rendered column order). Column 0 is the peer name.
pub const MMP_LINK_SORT_LABELS: &[&str] = &["name", "srtt", "loss", "etx", "lqi", "gp"];
pub const MMP_LINK_SORT_COLS: usize = MMP_LINK_SORT_LABELS.len();

/// Sortable column labels for the Session MMP table.
pub const MMP_SESSION_SORT_LABELS: &[&str] = &["name", "srtt", "loss", "etx", "sqi", "mtu"];
pub const MMP_SESSION_SORT_COLS: usize = MMP_SESSION_SORT_LABELS.len();

/// Sortable column labels for the Graphs by-peer summary list.
pub const GRAPHS_PEER_SORT_LABELS: &[&str] = &["name", "min", "max", "last", "n"];
pub const GRAPHS_PEER_SORT_COLS: usize = GRAPHS_PEER_SORT_LABELS.len();

/// Options for the Graphs tab window selector.
pub const GRAPHS_WINDOWS: &[(&str, &str)] =
    &[("1m", "1s"), ("10m", "1s"), ("1h", "1s"), ("24h", "1m")];

/// Node-level metric display order for Graphs tab Node mode. Must
/// match names returned by `show_stats_all_history` (no `peer` param).
pub const GRAPHS_METRICS: &[&str] = &[
    "mesh_size",
    "tree_depth",
    "peer_count",
    "parent_switches",
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    "loss_rate",
    "active_sessions",
];

/// Per-peer metric display order for Graphs tab PeerByMetric mode and
/// MetricByPeer selector. Must match names returned by
/// `show_stats_all_history` with a `peer` param.
pub const PEER_GRAPHS_METRICS: &[&str] = &[
    "srtt_ms",
    "loss_rate",
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    "ecn_ce",
];

/// Which variety of plot the Graphs tab shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphsMode {
    /// Stacked node-level metrics (the original view).
    Node,
    /// Grid: one metric, small-multiples across peers.
    MetricByPeer,
    /// Stacked per-peer metrics for one selected peer.
    PeerByMetric,
}

impl GraphsMode {
    pub fn next(self) -> Self {
        match self {
            GraphsMode::Node => GraphsMode::MetricByPeer,
            GraphsMode::MetricByPeer => GraphsMode::PeerByMetric,
            GraphsMode::PeerByMetric => GraphsMode::Node,
        }
    }
}

/// Cached peer summary for Graphs-tab selector (peer-list population
/// is independent of the per-tick metric data).
#[derive(Clone, Debug)]
pub struct GraphsPeer {
    pub npub: String,
    pub display_name: String,
}

pub struct App {
    pub active_tab: Tab,
    pub should_quit: bool,
    pub connection_state: ConnectionState,
    pub refresh_interval: Duration,
    pub data: HashMap<Tab, serde_json::Value>,
    pub table_states: HashMap<Tab, TableState>,
    pub detail_view: Option<DetailView>,
    /// Whether the `?` help overlay is currently shown.
    pub show_help: bool,
    /// A pending Del-disconnect confirmation, if the modal is open.
    pub confirm_disconnect: Option<ConfirmDisconnect>,
    /// Per-tab focused pane index for multi-pane tabs, generalizing the
    /// one-off peers `TableState`. Absent entry means pane 0. The accessors
    /// below are the general focus/scroll model the interaction consumers
    /// (multi-pane focus, Graphs by-peer) build on.
    pub focused_pane: HashMap<Tab, usize>,
    /// Per-(tab, pane) scroll offset (rows), generalizing the one-off detail
    /// and graphs scroll state.
    pub scroll_offsets: HashMap<(Tab, usize), u16>,
    pub last_fetch: Instant,
    pub last_error: Option<(Instant, String)>,
    pub expanded_transports: HashSet<u64>,
    pub tree_row_count: usize,
    pub selected_tree_item: SelectedTreeItem,
    /// Whether the gateway control socket is reachable.
    pub gateway_running: bool,
    /// Mappings data fetched from the gateway (separate from summary).
    pub gateway_mappings: Option<serde_json::Value>,
    /// `show_listening_sockets` payload for the Node-tab "Listening on
    /// fips0" panel; refreshed each tick alongside `show_status`.
    pub listening_sockets: Option<serde_json::Value>,
    /// Scroll offset (rows) for the stacked Graphs tab.
    pub graphs_scroll: u16,
    /// Selected (window, granularity) index for the Graphs tab.
    pub graphs_window_idx: usize,
    /// Current Graphs-tab view mode.
    pub graphs_mode: GraphsMode,
    /// Selected metric index for MetricByPeer mode (into
    /// `PEER_GRAPHS_METRICS`).
    pub graphs_peer_metric_idx: usize,
    /// Selected peer index for PeerByMetric mode (into `graphs_peers`).
    pub graphs_peer_idx: usize,
    /// Cached peer list from `show_stats_peers`, populated when the
    /// Graphs tab is active in a non-Node mode.
    pub graphs_peers: Vec<GraphsPeer>,
    /// Column-sort state for the Link MMP table.
    pub mmp_link_sort: SortState,
    /// Column-sort state for the Session MMP table.
    pub mmp_session_sort: SortState,
    /// Column-sort state for the Graphs by-peer summary list.
    pub graphs_peer_sort: SortState,
}

impl App {
    pub fn new(refresh_interval: Duration) -> Self {
        Self {
            active_tab: Tab::Node,
            should_quit: false,
            connection_state: ConnectionState::Disconnected("Not yet connected".into()),
            refresh_interval,
            data: HashMap::new(),
            table_states: HashMap::new(),
            detail_view: None,
            show_help: false,
            confirm_disconnect: None,
            focused_pane: HashMap::new(),
            scroll_offsets: HashMap::new(),
            last_fetch: Instant::now(),
            last_error: None,
            expanded_transports: HashSet::new(),
            tree_row_count: 0,
            selected_tree_item: SelectedTreeItem::None,
            gateway_running: false,
            gateway_mappings: None,
            listening_sockets: None,
            graphs_scroll: 0,
            graphs_window_idx: 1, // default 10m
            graphs_mode: GraphsMode::Node,
            graphs_peer_metric_idx: 0,
            graphs_peer_idx: 0,
            graphs_peers: Vec::new(),
            mmp_link_sort: SortState::default(),
            mmp_session_sort: SortState::default(),
            graphs_peer_sort: SortState::default(),
        }
    }

    /// Cycle the sort column for the active view (Link/Session MMP or Graphs
    /// by-peer), passing the view's column count. On the Performance tab the
    /// sort acts on the focused pane only (pane 0 Link MMP, pane 1 Session MMP),
    /// so each pane keeps its own sort state.
    pub fn cycle_sort_col(&mut self) {
        match self.active_tab {
            Tab::Mmp => {
                if self.focused_pane() == 1 {
                    self.mmp_session_sort.cycle_col(MMP_SESSION_SORT_COLS);
                } else {
                    self.mmp_link_sort.cycle_col(MMP_LINK_SORT_COLS);
                }
            }
            Tab::Graphs => self.graphs_peer_sort.cycle_col(GRAPHS_PEER_SORT_COLS),
            _ => {}
        }
    }

    /// Toggle the sort direction for the active view (the focused pane on the
    /// Performance tab).
    pub fn toggle_sort_dir(&mut self) {
        match self.active_tab {
            Tab::Mmp => {
                if self.focused_pane() == 1 {
                    self.mmp_session_sort.toggle_dir();
                } else {
                    self.mmp_link_sort.toggle_dir();
                }
            }
            Tab::Graphs => self.graphs_peer_sort.toggle_dir(),
            _ => {}
        }
    }

    /// Cycle the Graphs-tab view mode. Closes any open by-peer detail, which
    /// only applies to the MetricByPeer mode.
    pub fn graphs_next_mode(&mut self) {
        self.graphs_mode = self.graphs_mode.next();
        self.graphs_scroll = 0;
        self.detail_view = None;
    }

    /// Advance the mode-specific selector (metric or peer).
    pub fn graphs_next_selector(&mut self) {
        match self.graphs_mode {
            GraphsMode::Node => {}
            GraphsMode::MetricByPeer => {
                let n = PEER_GRAPHS_METRICS.len();
                self.graphs_peer_metric_idx = (self.graphs_peer_metric_idx + 1) % n;
            }
            GraphsMode::PeerByMetric => {
                let n = self.graphs_peers.len();
                if n > 0 {
                    self.graphs_peer_idx = (self.graphs_peer_idx + 1) % n;
                }
            }
        }
    }

    /// Reverse the mode-specific selector.
    pub fn graphs_prev_selector(&mut self) {
        match self.graphs_mode {
            GraphsMode::Node => {}
            GraphsMode::MetricByPeer => {
                let n = PEER_GRAPHS_METRICS.len();
                self.graphs_peer_metric_idx = (self.graphs_peer_metric_idx + n - 1) % n;
            }
            GraphsMode::PeerByMetric => {
                let n = self.graphs_peers.len();
                if n > 0 {
                    self.graphs_peer_idx = (self.graphs_peer_idx + n - 1) % n;
                }
            }
        }
    }

    /// Current per-peer metric name for MetricByPeer mode.
    pub fn graphs_selected_peer_metric(&self) -> &'static str {
        PEER_GRAPHS_METRICS[self.graphs_peer_metric_idx % PEER_GRAPHS_METRICS.len()]
    }

    /// Current selected peer for PeerByMetric mode, if any.
    pub fn graphs_selected_peer(&self) -> Option<&GraphsPeer> {
        if self.graphs_peers.is_empty() {
            return None;
        }
        let idx = self.graphs_peer_idx % self.graphs_peers.len();
        Some(&self.graphs_peers[idx])
    }

    /// Number of peers in the current Graphs by-peer (MetricByPeer) payload.
    /// The MetricByPeer view lists one summary line per peer carried in the
    /// `peers` array of the fetched `show_stats_history_all_peers` response.
    pub fn graphs_metric_peer_count(&self) -> usize {
        self.data
            .get(&Tab::Graphs)
            .and_then(|d| d.get("peers"))
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    }

    /// Move the by-peer list / detail cursor to the next peer (wrapping).
    /// Shared by the MetricByPeer summary list (Up/Down select) and the
    /// open by-peer detail (Up/Down follow the selection, re-rendering the
    /// plot for the newly selected peer).
    pub fn graphs_peer_select_next(&mut self) {
        let n = self.graphs_metric_peer_count();
        if n > 0 {
            self.graphs_peer_idx = (self.graphs_peer_idx + 1) % n;
        }
    }

    /// Move the by-peer list / detail cursor to the previous peer (wrapping).
    pub fn graphs_peer_select_prev(&mut self) {
        let n = self.graphs_metric_peer_count();
        if n > 0 {
            self.graphs_peer_idx = (self.graphs_peer_idx + n - 1) % n;
        }
    }

    /// Open the Graphs by-peer detail (full-pane btop plot) for the currently
    /// selected peer. No-op unless the by-peer list has at least one peer.
    pub fn graphs_open_peer_detail(&mut self) {
        if self.graphs_metric_peer_count() > 0 {
            if self.graphs_peer_idx >= self.graphs_metric_peer_count() {
                self.graphs_peer_idx = 0;
            }
            self.detail_view = Some(DetailView { scroll: 0 });
        }
    }

    /// Current Graphs-tab (window, granularity) pair.
    pub fn graphs_window(&self) -> (&'static str, &'static str) {
        GRAPHS_WINDOWS[self.graphs_window_idx % GRAPHS_WINDOWS.len()]
    }

    pub fn graphs_scroll_up(&mut self) {
        self.graphs_scroll = self.graphs_scroll.saturating_sub(1);
    }

    pub fn graphs_scroll_down(&mut self) {
        self.graphs_scroll = self.graphs_scroll.saturating_add(1);
    }

    pub fn graphs_next_window(&mut self) {
        self.graphs_window_idx = (self.graphs_window_idx + 1) % GRAPHS_WINDOWS.len();
    }

    pub fn graphs_prev_window(&mut self) {
        self.graphs_window_idx =
            (self.graphs_window_idx + GRAPHS_WINDOWS.len() - 1) % GRAPHS_WINDOWS.len();
    }

    /// Number of rows in the active tab's data array.
    pub fn row_count(&self) -> usize {
        if self.active_tab == Tab::Transports {
            return self.tree_row_count;
        }
        if self.active_tab == Tab::Gateway {
            return self
                .gateway_mappings
                .as_ref()
                .and_then(|v| v.get("mappings"))
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
        }
        let key = self.active_tab.command_data_key();
        self.data
            .get(&self.active_tab)
            .and_then(|v| v.get(key))
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0)
    }

    /// Move table selection down by one row.
    pub fn select_next(&mut self) {
        let count = self.row_count();
        if count == 0 {
            return;
        }
        let state = self.table_states.entry(self.active_tab).or_default();
        let i = state
            .selected()
            .map(|s| (s + 1).min(count - 1))
            .unwrap_or(0);
        state.select(Some(i));
    }

    /// Move table selection up by one row.
    pub fn select_prev(&mut self) {
        let count = self.row_count();
        if count == 0 {
            return;
        }
        let state = self.table_states.entry(self.active_tab).or_default();
        let i = state.selected().map(|s| s.saturating_sub(1)).unwrap_or(0);
        state.select(Some(i));
    }

    /// Open detail view for the currently selected row.
    pub fn open_detail(&mut self) {
        let state = self.table_states.get(&self.active_tab);
        if state.and_then(|s| s.selected()).is_some() {
            self.detail_view = Some(DetailView { scroll: 0 });
        }
    }

    /// Close detail view.
    pub fn close_detail(&mut self) {
        self.detail_view = None;
    }

    /// Toggle the `?` help overlay.
    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    /// Open a disconnect confirmation for the currently selected Peers row.
    /// No-op unless the Peers tab is active with a selected row that carries an
    /// npub. The reconnect note states that the peer stays disconnected until
    /// it is manually reconnected; a manual disconnect suppresses
    /// auto-reconnect for all peer kinds, so there is no per-direction
    /// tailoring.
    pub fn request_disconnect_confirm(&mut self) {
        if self.active_tab != Tab::Peers {
            return;
        }
        let Some(selected) = self
            .table_states
            .get(&Tab::Peers)
            .and_then(|s| s.selected())
        else {
            return;
        };
        // The displayed order is the role-grouped sort (peers.rs); mirror it so
        // the confirm names the same peer the cursor is on.
        let mut peers = self
            .data
            .get(&Tab::Peers)
            .and_then(|v| v.get("peers"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        peers.sort_by(|a, b| {
            let rank = |p: &serde_json::Value| -> u8 {
                let parent = p
                    .get("is_parent")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let child = p.get("is_child").and_then(|v| v.as_bool()).unwrap_or(false);
                if parent {
                    0
                } else if child {
                    1
                } else {
                    2
                }
            };
            rank(a).cmp(&rank(b)).then_with(|| {
                let lqi = |p: &serde_json::Value| {
                    p.get("mmp")
                        .and_then(|m| m.get("lqi"))
                        .and_then(|v| v.as_f64())
                };
                match (lqi(a), lqi(b)) {
                    (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            })
        });
        let Some(peer) = peers.get(selected) else {
            return;
        };
        let npub = peer.get("npub").and_then(|v| v.as_str()).unwrap_or("");
        if npub.is_empty() {
            return;
        }
        let display_name = peer
            .get("display_name")
            .and_then(|v| v.as_str())
            .unwrap_or(npub)
            .to_string();
        let reconnect_note = "It stays disconnected until you manually reconnect it.".to_string();
        self.confirm_disconnect = Some(ConfirmDisconnect {
            npub: npub.to_string(),
            display_name,
            reconnect_note,
        });
    }

    /// Cancel a pending disconnect confirmation.
    pub fn cancel_disconnect(&mut self) {
        self.confirm_disconnect = None;
    }

    /// Take the pending disconnect target, clearing the confirmation. Returns
    /// the npub to disconnect when one was confirmed.
    pub fn take_disconnect_target(&mut self) -> Option<String> {
        self.confirm_disconnect.take().map(|c| c.npub)
    }

    /// Deselect the active tab's table row (return to the overview state).
    /// No-op when the active tab has no selection.
    pub fn deselect_row(&mut self) {
        if let Some(state) = self.table_states.get_mut(&self.active_tab) {
            state.select(None);
        }
    }

    // The focus/scroll model below is the shared substrate the interaction
    // consumers (multi-pane focus, Graphs by-peer detail) build on; some
    // accessors land ahead of their first consumer, mirroring the test-kit's
    // not-yet-used-helper allowance.
    /// Currently focused pane index on the active tab (0 if unset). The general
    /// focus model the multi-pane and Graphs-by-peer consumers read.
    #[allow(dead_code)]
    pub fn focused_pane(&self) -> usize {
        self.focused_pane
            .get(&self.active_tab)
            .copied()
            .unwrap_or(0)
    }

    /// Cycle pane focus forward across `pane_count` panes on the active tab.
    #[allow(dead_code)]
    pub fn focus_next_pane(&mut self, pane_count: usize) {
        if pane_count == 0 {
            return;
        }
        let cur = self.focused_pane();
        self.focused_pane
            .insert(self.active_tab, (cur + 1) % pane_count);
    }

    /// Scroll offset for a given pane on the active tab.
    pub fn pane_scroll(&self, pane: usize) -> u16 {
        self.scroll_offsets
            .get(&(self.active_tab, pane))
            .copied()
            .unwrap_or(0)
    }

    /// Scroll the focused pane on the active tab by `delta` rows (saturating),
    /// generalizing the one-off detail/graphs scroll counters.
    #[allow(dead_code)]
    pub fn scroll_focused_pane(&mut self, delta: i16) {
        let pane = self.focused_pane();
        let entry = self
            .scroll_offsets
            .entry((self.active_tab, pane))
            .or_insert(0);
        *entry = if delta >= 0 {
            entry.saturating_add(delta as u16)
        } else {
            entry.saturating_sub((-delta) as u16)
        };
    }

    /// Set the focused pane's scroll offset directly (used by Home/End). End
    /// passes a large value the renderer clamps to the pane's content height.
    pub fn set_focused_pane_scroll(&mut self, offset: u16) {
        let pane = self.focused_pane();
        self.scroll_offsets.insert((self.active_tab, pane), offset);
    }

    /// Scroll detail view down.
    pub fn scroll_detail_down(&mut self) {
        if let Some(ref mut dv) = self.detail_view {
            dv.scroll = dv.scroll.saturating_add(1);
        }
    }

    /// Scroll detail view up.
    pub fn scroll_detail_up(&mut self) {
        if let Some(ref mut dv) = self.detail_view {
            dv.scroll = dv.scroll.saturating_sub(1);
        }
    }
}
