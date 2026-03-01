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
}

impl Tab {
    pub const ALL: [Tab; 8] = [
        Tab::Node,
        Tab::Peers,
        Tab::Transports,
        Tab::Sessions,
        Tab::Tree,
        Tab::Bloom,
        Tab::Mmp,
        Tab::Routing,
    ];

    /// Tab group index: 0 = Node, 1 = Connectivity, 2 = Internals.
    pub fn group(&self) -> usize {
        match self {
            Tab::Node => 0,
            Tab::Peers | Tab::Transports => 1,
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
            _ => "",
        }
    }

    /// Whether this tab has a table view with row selection.
    pub fn has_table(&self) -> bool {
        matches!(
            self,
            Tab::Peers | Tab::Sessions | Tab::Transports
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
        }
    }

    /// Number of rows in the active tab's data array.
    pub fn row_count(&self) -> usize {
        if self.active_tab == Tab::Transports {
            return self.tree_row_count;
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
        let i = state.selected().map(|s| (s + 1).min(count - 1)).unwrap_or(0);
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
