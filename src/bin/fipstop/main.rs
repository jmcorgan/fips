mod app;
mod client;
mod event;
mod ui;

use app::{App, ConnectionState, SelectedTreeItem, Tab};
use clap::Parser;
use client::ControlClient;
use event::{Event, EventHandler};
use ratatui::crossterm::event::{KeyCode, KeyModifiers};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// FIPS mesh monitoring TUI
#[derive(Parser, Debug)]
#[command(name = "fipstop", version, about = "Monitor a running FIPS daemon")]
struct Cli {
    /// Control socket path override
    #[arg(short = 's', long)]
    socket: Option<PathBuf>,

    /// Refresh interval in seconds
    #[arg(short = 'r', long, default_value = "2")]
    refresh: u64,
}

fn default_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(format!("{runtime_dir}/fips/control.sock"))
    } else if Path::new("/run/fips/control.sock").exists() {
        PathBuf::from("/run/fips/control.sock")
    } else {
        PathBuf::from("/tmp/fips-control.sock")
    }
}

fn restore_terminal() {
    ratatui::restore();
}

fn fetch_data(rt: &tokio::runtime::Runtime, client: &ControlClient, app: &mut App) {
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

    // Fetch active tab data (if not Dashboard, which we already fetched)
    if app.active_tab != Tab::Node {
        match rt.block_on(client.query(app.active_tab.command())) {
            Ok(data) => {
                app.data.insert(app.active_tab, data);
            }
            Err(e) => {
                app.last_error = Some((std::time::Instant::now(), e));
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
    let mut terminal = ratatui::init();
    let mut app = App::new(refresh);
    let events = EventHandler::new(refresh);

    // Initial fetch
    fetch_data(&rt, &client, &mut app);

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
                        fetch_data(&rt, &client, &mut app);
                    }
                    (KeyCode::BackTab, _) => {
                        app.close_detail();
                        app.active_tab = app.active_tab.prev();
                        fetch_data(&rt, &client, &mut app);
                    }
                    (KeyCode::Down, _) => {
                        if app.detail_view.is_some() {
                            app.scroll_detail_down();
                        } else if app.active_tab.has_table() {
                            app.select_next();
                        }
                    }
                    (KeyCode::Up, _) => {
                        if app.detail_view.is_some() {
                            app.scroll_detail_up();
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
                        if app.active_tab == Tab::Transports
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
                    (KeyCode::Left, _) => {
                        if app.active_tab == Tab::Transports
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
                    _ => {}
                }
            }
            Ok(Event::Resize) => {
                // Redraw happens at top of loop
            }
            Ok(Event::Tick) => {
                fetch_data(&rt, &client, &mut app);
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
