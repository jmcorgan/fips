use ratatui::widgets::TableState;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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
}

#[derive(Clone)]
pub enum ConnectionState {
    Connected,
    Disconnected(String),
}

pub struct DetailView {
    pub scroll: u16,
}

#[derive(Clone, Copy)]
pub enum SelectedTreeItem {
    None,
    Transport(u64),
    Link,
}

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
    pub last_fetch: Instant,
    pub last_error: Option<(Instant, String)>,
    pub expanded_transports: HashSet<u64>,
    pub tree_row_count: usize,
    pub selected_tree_item: SelectedTreeItem,
    /// Whether the gateway control socket is reachable.
    pub gateway_running: bool,
    /// Mappings data fetched from the gateway (separate from summary).
    pub gateway_mappings: Option<serde_json::Value>,
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
            last_fetch: Instant::now(),
            last_error: None,
            expanded_transports: HashSet::new(),
            tree_row_count: 0,
            selected_tree_item: SelectedTreeItem::None,
            gateway_running: false,
            gateway_mappings: None,
            graphs_scroll: 0,
            graphs_window_idx: 1, // default 10m
            graphs_mode: GraphsMode::Node,
            graphs_peer_metric_idx: 0,
            graphs_peer_idx: 0,
            graphs_peers: Vec::new(),
        }
    }

    /// Cycle the Graphs-tab view mode.
    pub fn graphs_next_mode(&mut self) {
        self.graphs_mode = self.graphs_mode.next();
        self.graphs_scroll = 0;
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
