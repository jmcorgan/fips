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

    app.last_fetch = std::time::Instant::now();
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
    let mut app = App::new(refresh);
    let events = EventHandler::new(refresh);

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
                match (key.code, key.modifiers) {
                    (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                        app.should_quit = true;
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
                        if app.detail_view.is_some() {
                            app.scroll_detail_down();
                        } else if app.active_tab == Tab::Graphs {
                            app.graphs_scroll_down();
                        } else if app.active_tab.has_table() {
                            app.select_next();
                        }
                    }
                    (KeyCode::Up, _) => {
                        if app.detail_view.is_some() {
                            app.scroll_detail_up();
                        } else if app.active_tab == Tab::Graphs {
                            app.graphs_scroll_up();
                        } else if app.active_tab.has_table() {
                            app.select_prev();
                        }
                    }
                    (KeyCode::Enter, _) => {
                        if app.active_tab.has_table() && app.detail_view.is_none() {
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
                    (KeyCode::Char('m'), KeyModifiers::NONE)
                        if app.active_tab == Tab::Graphs && app.detail_view.is_none() =>
                    {
                        app.graphs_next_mode();
                        fetch_data(&rt, &client, &gateway_client, &mut app);
                    }
                    (KeyCode::Char('n'), KeyModifiers::NONE)
                        if app.active_tab == Tab::Graphs && app.detail_view.is_none() =>
                    {
                        app.graphs_next_selector();
                        fetch_data(&rt, &client, &gateway_client, &mut app);
                    }
                    (KeyCode::Char('N'), KeyModifiers::SHIFT)
                        if app.active_tab == Tab::Graphs && app.detail_view.is_none() =>
                    {
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
                        if app.detail_view.is_some() {
                            app.close_detail();
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

    restore_terminal();
}
