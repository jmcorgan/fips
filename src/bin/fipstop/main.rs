mod app;
mod client;
mod event;
mod ui;

use app::{App, ConnectionState, SelectedTreeItem, Tab};
use clap::Parser;
use client::ControlClient;
use event::{Event, EventHandler};
use fips::version;
use ratatui::crossterm::event::{KeyCode, KeyModifiers};
use std::path::PathBuf;
use std::time::Duration;

/// FIPS mesh monitoring TUI
#[derive(Parser, Debug)]
#[command(
    name = "fipstop",
    version = version::short_version(),
    long_version = version::long_version(),
    about = "Monitor a running FIPS daemon"
)]
struct Cli {
    /// Control socket path override
    #[arg(short = 's', long)]
    socket: Option<PathBuf>,

    /// Gateway control socket path override
    #[arg(long)]
    gateway_socket: Option<PathBuf>,

    /// Refresh interval in seconds
    #[arg(short = 'r', long, default_value = "2")]
    refresh: u64,
}

fn default_socket_path() -> PathBuf {
    fips::config::default_control_path()
}

fn default_gateway_socket_path() -> PathBuf {
    fips::config::default_gateway_path()
}

fn restore_terminal() {
    ratatui::restore();
}

fn fetch_data(
    rt: &tokio::runtime::Runtime,
    client: &ControlClient,
    gateway_client: &ControlClient,
    app: &mut App,
) {
    // Always fetch status for the status bar
    match rt.block_on(client.query("show_status")) {
        Ok(data) => {
            app.data.insert(Tab::Node, data);
            app.connection_state = ConnectionState::Connected;
        }
        Err(e) => {
            app.connection_state = ConnectionState::Disconnected(e.clone());
            app.last_error = Some((std::time::Instant::now(), e));
            return;
        }
    }

    // Listening-on-fips0 panel — fetched only while the Node tab is
    // active (it's the only place the data is rendered). Errors are
    // non-fatal: an old daemon without the query just leaves the
    // payload at None and the panel hides.
    if app.active_tab == Tab::Node {
        match rt.block_on(client.query("show_listening_sockets")) {
            Ok(data) => app.listening_sockets = Some(data),
            Err(_) => app.listening_sockets = None,
        }
    }

    // Gateway tab uses a separate socket
    if app.active_tab == Tab::Gateway {
        match rt.block_on(gateway_client.query("show_gateway")) {
            Ok(data) => {
                app.data.insert(Tab::Gateway, data);
                app.gateway_running = true;
            }
            Err(_) => {
                app.data.remove(&Tab::Gateway);
                app.gateway_running = false;
                app.gateway_mappings = None;
            }
        }
        // Also fetch mappings for the detail table
        if app.gateway_running {
            match rt.block_on(gateway_client.query("show_mappings")) {
                Ok(data) => {
                    app.gateway_mappings = Some(data);
                }
                Err(_) => {
                    app.gateway_mappings = None;
                }
            }
        }
        app.last_fetch = std::time::Instant::now();
        return;
    }

    // Fetch active tab data (if not Dashboard, which we already fetched)
    if app.active_tab != Tab::Node {
        // Graphs tab pulls all metrics in one round trip via
        // show_stats_all_history; all other tabs use the generic
        // command() path.
        if app.active_tab == Tab::Graphs {
            let (window, granularity) = app.graphs_window();

            // Always refresh the peer list on Graphs-tab fetches so
            // selector indices stay current across peer churn.
            if let Ok(data) = rt.block_on(client.query("show_stats_peers")) {
                app.graphs_peers = data
                    .get("peers")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|p| crate::app::GraphsPeer {
                                npub: p
                                    .get("npub")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                display_name: p
                                    .get("display_name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                if app.graphs_peer_idx >= app.graphs_peers.len().max(1) {
                    app.graphs_peer_idx = 0;
                }
            }

            let (command, params) = match app.graphs_mode {
                crate::app::GraphsMode::Node => (
                    "show_stats_all_history",
                    serde_json::json!({
                        "window": window,
                        "granularity": granularity,
                    }),
                ),
                crate::app::GraphsMode::MetricByPeer => (
                    "show_stats_history_all_peers",
                    serde_json::json!({
                        "metric": app.graphs_selected_peer_metric(),
                        "window": window,
                        "granularity": granularity,
                    }),
                ),
                crate::app::GraphsMode::PeerByMetric => {
                    let npub = app
                        .graphs_selected_peer()
                        .map(|p| p.npub.clone())
                        .unwrap_or_default();
                    (
                        "show_stats_all_history",
                        serde_json::json!({
                            "peer": npub,
                            "window": window,
                            "granularity": granularity,
                        }),
                    )
                }
            };

            // Only issue the per-peer query if there is a peer to query.
            let should_query = match app.graphs_mode {
                crate::app::GraphsMode::PeerByMetric => !app.graphs_peers.is_empty(),
                _ => true,
            };
            if should_query {
                match rt.block_on(client.query_with_params(command, params)) {
                    Ok(data) => {
                        app.data.insert(Tab::Graphs, data);
                    }
                    Err(e) => {
                        app.last_error = Some((std::time::Instant::now(), e));
                    }
                }
            } else {
                app.data.insert(Tab::Graphs, serde_json::json!({}));
            }
        } else {
            match rt.block_on(client.query(app.active_tab.command())) {
                Ok(data) => {
                    app.data.insert(app.active_tab, data);
                }
                Err(e) => {
                    app.last_error = Some((std::time::Instant::now(), e));
                }
            }
        }
    }

    // Cross-reference fetches for detail views
    if app.active_tab == Tab::Peers {
        if let Ok(data) = rt.block_on(client.query("show_links")) {
            app.data.insert(Tab::Links, data);
        }
        if let Ok(data) = rt.block_on(client.query("show_transports")) {
            app.data.insert(Tab::Transports, data);
        }
    }
    if app.active_tab == Tab::Transports {
        if let Ok(data) = rt.block_on(client.query("show_links")) {
            app.data.insert(Tab::Links, data);
        }
        if let Ok(data) = rt.block_on(client.query("show_peers")) {
            app.data.insert(Tab::Peers, data);
        }
    }
    if app.active_tab == Tab::Routing
        && let Ok(data) = rt.block_on(client.query("show_cache"))
    {
        app.data.insert(Tab::Cache, data);
    }
    // The Tree and Filters views carry no parent/child role flags in their own
    // daemon responses, so cross-fetch the peers view and join by node address
    // to group their peer lists the same way the Peers tab does. Non-fatal: on
    // error the grouping falls back to placing every peer under Other.
    if (app.active_tab == Tab::Tree || app.active_tab == Tab::Bloom)
        && let Ok(data) = rt.block_on(client.query("show_peers"))
    {
        app.data.insert(Tab::Peers, data);
    }

    app.last_fetch = std::time::Instant::now();
}

/// Down-arrow behaviour on the Graphs tab. The by-peer detail follows the
/// selection (next peer); the by-peer list moves its cursor; the stacked
/// node/peer modes scroll the content.
fn graphs_down(app: &mut App) {
    match app.graphs_mode {
        crate::app::GraphsMode::MetricByPeer => app.graphs_peer_select_next(),
        _ if app.detail_view.is_some() => app.scroll_detail_down(),
        _ => app.graphs_scroll_down(),
    }
}

/// Up-arrow behaviour on the Graphs tab (mirror of `graphs_down`).
fn graphs_up(app: &mut App) {
    match app.graphs_mode {
        crate::app::GraphsMode::MetricByPeer => app.graphs_peer_select_prev(),
        _ if app.detail_view.is_some() => app.scroll_detail_up(),
        _ => app.graphs_scroll_up(),
    }
}

fn main() {
    let cli = Cli::parse();

    let socket_path = cli.socket.unwrap_or_else(default_socket_path);
    let gateway_socket_path = cli
        .gateway_socket
        .unwrap_or_else(default_gateway_socket_path);
    let refresh = Duration::from_secs(cli.refresh);

    // Install panic hook that restores terminal before printing panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        original_hook(info);
    }));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    let client = ControlClient::new(&socket_path);
    let gateway_client = ControlClient::new(&gateway_socket_path);
    let mut terminal = ratatui::try_init().unwrap_or_else(|e| {
        eprintln!("fipstop: failed to initialize terminal: {e}");
        std::process::exit(1);
    });
    // Force a full repaint of a known-blank screen before the first draw.
    // try_init enters the alternate screen but does not clear it, and the
    // first draw only emits cells that differ from an assumed-blank buffer;
    // on terminals that don't hand back a cleared alternate buffer (notably
    // tmux, and over SSH) that leaves stale content showing through.
    let _ = terminal.clear();
    let mut app = App::new(refresh);
    let mut events = EventHandler::new(refresh);

    // Initial fetch
    fetch_data(&rt, &client, &gateway_client, &mut app);

    // Main loop
    loop {
        terminal
            .draw(|frame| ui::draw(frame, &mut app))
            .expect("failed to draw frame");

        match events.next() {
            Ok(Event::Key(key)) => {
                // Ignore key release events
                if key.kind != ratatui::crossterm::event::KeyEventKind::Press {
                    continue;
                }
                // The disconnect confirmation is modal: while open, only Y
                // (confirm), N/Esc (cancel), and quit are honored.
                if app.confirm_disconnect.is_some() {
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }
                        (KeyCode::Char('y'), _) | (KeyCode::Char('Y'), _) => {
                            if let Some(npub) = app.take_disconnect_target() {
                                let params = serde_json::json!({ "npub": npub });
                                if let Err(e) =
                                    rt.block_on(client.query_with_params("disconnect", params))
                                {
                                    app.last_error = Some((std::time::Instant::now(), e));
                                }
                                fetch_data(&rt, &client, &gateway_client, &mut app);
                            }
                        }
                        (KeyCode::Char('n'), _) | (KeyCode::Char('N'), _) | (KeyCode::Esc, _) => {
                            app.cancel_disconnect();
                        }
                        _ => {}
                    }
                    if app.should_quit {
                        break;
                    }
                    continue;
                }
                // The `?` overlay is modal: while open, only `?`/Esc (close)
                // and quit are honored, so navigation keys don't act behind it.
                if app.show_help {
                    match (key.code, key.modifiers) {
                        (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }
                        (KeyCode::Char('?'), _) | (KeyCode::Esc, _) => {
                            app.show_help = false;
                        }
                        _ => {}
                    }
                    if app.should_quit {
                        break;
                    }
                    continue;
                }
                match (key.code, key.modifiers) {
                    (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    (KeyCode::Char('?'), _) => {
                        app.toggle_help();
                    }
                    (KeyCode::Delete, _) => {
                        // Del on a selected Peers row opens the disconnect
                        // confirmation (the only state-mutating action).
                        if app.active_tab == Tab::Peers && app.detail_view.is_none() {
                            app.request_disconnect_confirm();
                        }
                    }
                    (KeyCode::Tab, KeyModifiers::NONE) => {
                        app.close_detail();
                        app.active_tab = app.active_tab.next();
                        fetch_data(&rt, &client, &gateway_client, &mut app);
                    }
                    (KeyCode::BackTab, _) => {
                        app.close_detail();
                        app.active_tab = app.active_tab.prev();
                        fetch_data(&rt, &client, &gateway_client, &mut app);
                    }
                    (KeyCode::Down, _) => {
                        if app.active_tab == Tab::Graphs {
                            graphs_down(&mut app);
                        } else if app.detail_view.is_some() {
                            app.scroll_detail_down();
                        } else if app.active_tab.has_table() {
                            app.select_next();
                        } else if app.active_tab.scroll_pane_count() > 0 {
                            app.scroll_focused_pane(1);
                        }
                    }
                    (KeyCode::Up, _) => {
                        if app.active_tab == Tab::Graphs {
                            graphs_up(&mut app);
                        } else if app.detail_view.is_some() {
                            app.scroll_detail_up();
                        } else if app.active_tab.has_table() {
                            app.select_prev();
                        } else if app.active_tab.scroll_pane_count() > 0 {
                            app.scroll_focused_pane(-1);
                        }
                    }
                    (KeyCode::PageDown, _) => {
                        if app.active_tab.scroll_pane_count() > 0 {
                            app.scroll_focused_pane(10);
                        }
                    }
                    (KeyCode::PageUp, _) => {
                        if app.active_tab.scroll_pane_count() > 0 {
                            app.scroll_focused_pane(-10);
                        }
                    }
                    (KeyCode::Home, _) => {
                        if app.active_tab.scroll_pane_count() > 0 {
                            app.set_focused_pane_scroll(0);
                        }
                    }
                    (KeyCode::End, _) => {
                        if app.active_tab.scroll_pane_count() > 0 {
                            // A large offset the renderer clamps to content.
                            app.set_focused_pane_scroll(u16::MAX);
                        }
                    }
                    (KeyCode::Char('f'), KeyModifiers::NONE) => {
                        // Cycle pane focus on the multi-pane scrollable tabs.
                        let panes = app.active_tab.scroll_pane_count();
                        if panes > 0 {
                            app.focus_next_pane(panes);
                        }
                    }
                    (KeyCode::Enter, _) => {
                        if app.active_tab == Tab::Graphs
                            && app.detail_view.is_none()
                            && app.graphs_mode == crate::app::GraphsMode::MetricByPeer
                        {
                            // Expand the selected by-peer summary line into a
                            // full-pane btop plot.
                            app.graphs_open_peer_detail();
                        } else if app.active_tab.has_table() && app.detail_view.is_none() {
                            app.open_detail();
                        }
                    }
                    (KeyCode::Char(' '), _) | (KeyCode::Right, _) => {
                        if app.active_tab == Tab::Graphs && app.detail_view.is_none() {
                            app.graphs_next_window();
                            fetch_data(&rt, &client, &gateway_client, &mut app);
                        } else if app.active_tab == Tab::Transports
                            && app.detail_view.is_none()
                            && let SelectedTreeItem::Transport(tid) = app.selected_tree_item
                        {
                            if app.expanded_transports.contains(&tid) {
                                app.expanded_transports.remove(&tid);
                            } else {
                                app.expanded_transports.insert(tid);
                            }
                        }
                    }
                    (KeyCode::Char('m'), KeyModifiers::NONE) if app.active_tab == Tab::Graphs => {
                        // `m` cycles the broader Graphs mode, even from inside
                        // the by-peer detail (which then closes, since the
                        // detail only applies to the by-peer mode).
                        app.graphs_next_mode();
                        fetch_data(&rt, &client, &gateway_client, &mut app);
                    }
                    (KeyCode::Char('n'), KeyModifiers::NONE) if app.active_tab == Tab::Graphs => {
                        // `n` switches the statistic, for both the by-peer list
                        // and the open by-peer detail (which re-renders).
                        app.graphs_next_selector();
                        fetch_data(&rt, &client, &gateway_client, &mut app);
                    }
                    (KeyCode::Char('N'), KeyModifiers::SHIFT) if app.active_tab == Tab::Graphs => {
                        app.graphs_prev_selector();
                        fetch_data(&rt, &client, &gateway_client, &mut app);
                    }
                    (KeyCode::Left, _) => {
                        if app.active_tab == Tab::Graphs && app.detail_view.is_none() {
                            app.graphs_prev_window();
                            fetch_data(&rt, &client, &gateway_client, &mut app);
                        } else if app.active_tab == Tab::Transports
                            && app.detail_view.is_none()
                            && let SelectedTreeItem::Transport(tid) = app.selected_tree_item
                        {
                            app.expanded_transports.remove(&tid);
                        }
                    }
                    (KeyCode::Esc, _) => {
                        // Priority: close an open detail first, otherwise
                        // deselect the active table row (return to overview).
                        if app.detail_view.is_some() {
                            app.close_detail();
                        } else if app.active_tab.has_table() {
                            app.deselect_row();
                        }
                    }
                    (KeyCode::Char('e'), KeyModifiers::NONE) => {
                        if app.active_tab == Tab::Transports
                            && let Some(data) = app.data.get(&Tab::Transports)
                            && let Some(arr) = data.get("transports").and_then(|v| v.as_array())
                        {
                            for t in arr {
                                if let Some(tid) = t.get("transport_id").and_then(|v| v.as_u64()) {
                                    app.expanded_transports.insert(tid);
                                }
                            }
                        }
                    }
                    (KeyCode::Char('c'), KeyModifiers::NONE) => {
                        if app.active_tab == Tab::Transports {
                            app.expanded_transports.clear();
                        }
                    }
                    (KeyCode::Char('g'), KeyModifiers::NONE) => {
                        app.close_detail();
                        app.active_tab = Tab::Graphs;
                        app.graphs_scroll = 0;
                        fetch_data(&rt, &client, &gateway_client, &mut app);
                    }
                    (KeyCode::Char('s'), KeyModifiers::NONE) => {
                        // `s` cycles the active sort column on the MMP and
                        // Graphs by-peer tables (no-op on other tabs).
                        app.cycle_sort_col();
                    }
                    (KeyCode::Char('S'), _) => {
                        // `S` toggles the sort direction on those same tables.
                        app.toggle_sort_dir();
                    }
                    _ => {}
                }
            }
            Ok(Event::Resize) => {
                // Redraw happens at top of loop
            }
            Ok(Event::Tick) => {
                fetch_data(&rt, &client, &gateway_client, &mut app);
            }
            Err(_) => {
                app.should_quit = true;
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Stop the input thread before restoring the terminal so it is not
    // still reading stdin once raw mode is disabled (stray bytes would
    // otherwise echo onto the restored screen).
    events.stop();
    restore_terminal();
}
