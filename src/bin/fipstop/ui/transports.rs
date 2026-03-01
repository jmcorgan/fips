use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};

use crate::app::{App, SelectedTreeItem, Tab};

use super::helpers;

/// A single visible row in the tree view — either a transport or a nested link.
enum TreeRow {
    Transport {
        index: usize,
        transport_id: u64,
        link_count: usize,
    },
    Link {
        index: usize,
        is_last: bool,
    },
}

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let transports = get_transports(app);
    let links = get_links(app);
    let tree_rows = build_tree_rows(&transports, &links, app);

    // Update app state for navigation
    app.tree_row_count = tree_rows.len();
    update_selected_tree_item(app, &tree_rows);

    if app.detail_view.is_some() {
        let chunks = Layout::horizontal([
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .split(area);

        draw_table(frame, app, chunks[0], &transports, &links, &tree_rows);
        draw_detail(frame, app, chunks[1], &transports, &links, &tree_rows);
    } else {
        draw_table(frame, app, area, &transports, &links, &tree_rows);
    }
}

fn get_transports(app: &App) -> Vec<serde_json::Value> {
    app.data
        .get(&Tab::Transports)
        .and_then(|v| v.get("transports"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn get_links(app: &App) -> Vec<serde_json::Value> {
    app.data
        .get(&Tab::Links)
        .and_then(|v| v.get("links"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn build_tree_rows(
    transports: &[serde_json::Value],
    links: &[serde_json::Value],
    app: &App,
) -> Vec<TreeRow> {
    let mut rows = Vec::new();
    for (t_idx, transport) in transports.iter().enumerate() {
        let tid = transport
            .get("transport_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Gather links belonging to this transport
        let transport_links: Vec<(usize, &serde_json::Value)> = links
            .iter()
            .enumerate()
            .filter(|(_, l)| l.get("transport_id").and_then(|v| v.as_u64()) == Some(tid))
            .collect();

        rows.push(TreeRow::Transport {
            index: t_idx,
            transport_id: tid,
            link_count: transport_links.len(),
        });

        if app.expanded_transports.contains(&tid) {
            let last_idx = transport_links.len().saturating_sub(1);
            for (pos, (l_idx, _)) in transport_links.iter().enumerate() {
                rows.push(TreeRow::Link {
                    index: *l_idx,
                    is_last: pos == last_idx,
                });
            }
        }
    }
    rows
}

fn update_selected_tree_item(app: &mut App, tree_rows: &[TreeRow]) {
    let selected = app
        .table_states
        .get(&Tab::Transports)
        .and_then(|s| s.selected())
        .unwrap_or(0);

    app.selected_tree_item = match tree_rows.get(selected) {
        Some(TreeRow::Transport { transport_id, .. }) => {
            SelectedTreeItem::Transport(*transport_id)
        }
        Some(TreeRow::Link { .. }) => SelectedTreeItem::Link,
        None => SelectedTreeItem::None,
    };
}

fn draw_table(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    transports: &[serde_json::Value],
    links: &[serde_json::Value],
    tree_rows: &[TreeRow],
) {
    let header = Row::new(vec![
        Cell::from("Transport / Link"),
        Cell::from("State"),
        Cell::from("Peer"),
        Cell::from("Tx"),
        Cell::from("Rx"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = tree_rows
        .iter()
        .map(|tree_row| match tree_row {
            TreeRow::Transport {
                index,
                transport_id,
                link_count,
            } => {
                let t = &transports[*index];
                let indicator = if *link_count == 0 {
                    "  "
                } else if app.expanded_transports.contains(transport_id) {
                    "\u{25BC} " // ▼
                } else {
                    "\u{25B6} " // ▶
                };
                let typ = helpers::str_field(t, "type");
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let addr = t.get("local_addr").and_then(|v| v.as_str()).unwrap_or("");
                let label = if !name.is_empty() {
                    format!("{indicator}{typ} {name}")
                } else if !addr.is_empty() {
                    format!("{indicator}{typ} {addr}")
                } else {
                    format!("{indicator}{typ} #{transport_id}")
                };

                let state = helpers::str_field(t, "state");
                let tx = t
                    .get("stats")
                    .and_then(|s| s.get("packets_sent").or_else(|| s.get("frames_sent")))
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into());
                let rx = t
                    .get("stats")
                    .and_then(|s| s.get("packets_recv").or_else(|| s.get("frames_recv")))
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into());

                Row::new(vec![
                    Cell::from(label),
                    Cell::from(state.to_string()),
                    Cell::from(""),
                    Cell::from(tx),
                    Cell::from(rx),
                ])
                .style(Style::default().fg(Color::White))
            }
            TreeRow::Link { index, is_last } => {
                let link = &links[*index];
                let tree_char = if *is_last { "\u{2514}\u{2500}" } else { "\u{251C}\u{2500}" }; // └─ or ├─
                let dir = helpers::str_field(link, "direction");
                let dir_short = match dir {
                    "Outbound" => "Out",
                    "Inbound" => "In",
                    other => other,
                };
                let addr = helpers::truncate_hex(helpers::str_field(link, "remote_addr"), 16);
                let label = format!("  {tree_char} {dir_short} {addr}");

                let state = helpers::str_field(link, "state");
                let peer_name = lookup_peer_for_link(app, link)
                    .map(|p| helpers::str_field(&p, "display_name").to_string())
                    .unwrap_or_default();

                Row::new(vec![
                    Cell::from(Span::styled(
                        label,
                        Style::default().fg(if dir == "Outbound" {
                            Color::Cyan
                        } else {
                            Color::Green
                        }),
                    )),
                    Cell::from(state.to_string()),
                    Cell::from(peer_name),
                    Cell::from(""),
                    Cell::from(""),
                ])
            }
        })
        .collect();

    let transport_count = transports.len();
    let link_count: usize = tree_rows
        .iter()
        .filter(|r| matches!(r, TreeRow::Link { .. }))
        .count();
    let title = if link_count > 0 {
        format!(" Transports ({transport_count}) Links ({link_count}) ")
    } else {
        format!(" Transports ({transport_count}) ")
    };

    let widths = [
        Constraint::Min(28),
        Constraint::Length(12),
        Constraint::Length(14),
        Constraint::Length(9),
        Constraint::Length(9),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25B8} "); // ▸

    let row_count = tree_rows.len();
    let state = app.table_states.entry(Tab::Transports).or_default();
    frame.render_stateful_widget(table, area, state);

    if row_count > 0 {
        let selected = state.selected().unwrap_or(0);
        let mut scrollbar_state = ScrollbarState::new(row_count).position(selected);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            area,
            &mut scrollbar_state,
        );
    }
}

fn draw_detail(
    frame: &mut Frame,
    app: &App,
    area: Rect,
    transports: &[serde_json::Value],
    links: &[serde_json::Value],
    tree_rows: &[TreeRow],
) {
    let selected = app
        .table_states
        .get(&Tab::Transports)
        .and_then(|s| s.selected())
        .unwrap_or(0);

    let Some(tree_row) = tree_rows.get(selected) else {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Detail ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let msg = Paragraph::new("  No item selected")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    };

    match tree_row {
        TreeRow::Transport { index, .. } => {
            draw_transport_detail(frame, app, area, &transports[*index]);
        }
        TreeRow::Link { index, .. } => {
            draw_link_detail(frame, app, area, &links[*index]);
        }
    }
}

fn draw_transport_detail(frame: &mut Frame, app: &App, area: Rect, t: &serde_json::Value) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Transport Detail ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = vec![
        helpers::section_header("Transport Info"),
        helpers::kv_line("Transport ID", &helpers::u64_field(t, "transport_id")),
        helpers::kv_line("Type", helpers::str_field(t, "type")),
        helpers::kv_line("State", helpers::str_field(t, "state")),
        helpers::kv_line("MTU", &helpers::u64_field(t, "mtu")),
    ];

    if let Some(name) = t.get("name").and_then(|v| v.as_str()) {
        lines.push(helpers::kv_line("Name", name));
    }
    if let Some(addr) = t.get("local_addr").and_then(|v| v.as_str()) {
        lines.push(helpers::kv_line("Local Addr", addr));
    }

    // Transport stats
    if let Some(stats) = t.get("stats") {
        let typ = helpers::str_field(t, "type");
        lines.push(Line::from(""));
        lines.push(helpers::section_header("Traffic"));

        match typ {
            "ethernet" => {
                lines.push(helpers::kv_line(
                    "Frames Sent",
                    &helpers::nested_u64(t, "stats", "frames_sent"),
                ));
                lines.push(helpers::kv_line(
                    "Frames Recv",
                    &helpers::nested_u64(t, "stats", "frames_recv"),
                ));
            }
            _ => {
                lines.push(helpers::kv_line(
                    "Pkts Sent",
                    &helpers::nested_u64(t, "stats", "packets_sent"),
                ));
                lines.push(helpers::kv_line(
                    "Pkts Recv",
                    &helpers::nested_u64(t, "stats", "packets_recv"),
                ));
            }
        }

        let bytes_sent = stats
            .get("bytes_sent")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let bytes_recv = stats
            .get("bytes_recv")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        lines.push(helpers::kv_line(
            "Bytes Sent",
            &helpers::format_bytes(bytes_sent),
        ));
        lines.push(helpers::kv_line(
            "Bytes Recv",
            &helpers::format_bytes(bytes_recv),
        ));

        lines.push(Line::from(""));
        lines.push(helpers::section_header("Errors"));
        lines.push(helpers::kv_line(
            "Send Errors",
            &helpers::nested_u64(t, "stats", "send_errors"),
        ));
        lines.push(helpers::kv_line(
            "Recv Errors",
            &helpers::nested_u64(t, "stats", "recv_errors"),
        ));

        match typ {
            "udp" => {
                lines.push(helpers::kv_line(
                    "MTU Exceeded",
                    &helpers::nested_u64(t, "stats", "mtu_exceeded"),
                ));
                lines.push(helpers::kv_line(
                    "Kernel Drops",
                    &helpers::nested_u64(t, "stats", "kernel_drops"),
                ));
            }
            "tcp" => {
                lines.push(helpers::kv_line(
                    "MTU Exceeded",
                    &helpers::nested_u64(t, "stats", "mtu_exceeded"),
                ));
                lines.push(Line::from(""));
                lines.push(helpers::section_header("Connections"));
                lines.push(helpers::kv_line(
                    "Established",
                    &helpers::nested_u64(t, "stats", "connections_established"),
                ));
                lines.push(helpers::kv_line(
                    "Accepted",
                    &helpers::nested_u64(t, "stats", "connections_accepted"),
                ));
                lines.push(helpers::kv_line(
                    "Rejected",
                    &helpers::nested_u64(t, "stats", "connections_rejected"),
                ));
                lines.push(helpers::kv_line(
                    "Timeouts",
                    &helpers::nested_u64(t, "stats", "connect_timeouts"),
                ));
                lines.push(helpers::kv_line(
                    "Refused",
                    &helpers::nested_u64(t, "stats", "connect_refused"),
                ));
            }
            "ethernet" => {
                lines.push(Line::from(""));
                lines.push(helpers::section_header("Beacons"));
                lines.push(helpers::kv_line(
                    "Beacons Sent",
                    &helpers::nested_u64(t, "stats", "beacons_sent"),
                ));
                lines.push(helpers::kv_line(
                    "Beacons Recv",
                    &helpers::nested_u64(t, "stats", "beacons_recv"),
                ));
                lines.push(Line::from(""));
                lines.push(helpers::section_header("Frame Errors"));
                lines.push(helpers::kv_line(
                    "Too Short",
                    &helpers::nested_u64(t, "stats", "frames_too_short"),
                ));
                lines.push(helpers::kv_line(
                    "Too Long",
                    &helpers::nested_u64(t, "stats", "frames_too_long"),
                ));
            }
            _ => {}
        }
    }

    let detail_scroll = app.detail_view.as_ref().map(|d| d.scroll).unwrap_or(0);
    let paragraph = Paragraph::new(lines).scroll((detail_scroll, 0));
    frame.render_widget(paragraph, inner);
}

fn draw_link_detail(frame: &mut Frame, app: &App, area: Rect, link: &serde_json::Value) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Link Detail ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = vec![
        helpers::section_header("Link Info"),
        helpers::kv_line("Link ID", &helpers::u64_field(link, "link_id")),
        helpers::kv_line("Direction", helpers::str_field(link, "direction")),
        helpers::kv_line("State", helpers::str_field(link, "state")),
        helpers::kv_line("Remote Addr", helpers::str_field(link, "remote_addr")),
        helpers::kv_line(
            "Created",
            &helpers::format_elapsed_ms(
                link.get("created_at_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ),
        Line::from(""),
    ];

    // Transport cross-reference
    if let Some(transport) = lookup_transport(app, link) {
        lines.push(helpers::section_header("Transport"));
        lines.push(helpers::kv_line(
            "Transport ID",
            &helpers::u64_field(link, "transport_id"),
        ));
        lines.push(helpers::kv_line(
            "Type",
            helpers::str_field(&transport, "type"),
        ));
        if let Some(name) = transport.get("name").and_then(|v| v.as_str()) {
            lines.push(helpers::kv_line("Name", name));
        }
        lines.push(helpers::kv_line(
            "MTU",
            &helpers::u64_field(&transport, "mtu"),
        ));
        if let Some(addr) = transport.get("local_addr").and_then(|v| v.as_str()) {
            lines.push(helpers::kv_line("Local Addr", addr));
        }
        lines.push(helpers::kv_line(
            "State",
            helpers::str_field(&transport, "state"),
        ));
        lines.push(Line::from(""));
    }

    // Peer cross-reference
    if let Some(peer) = lookup_peer_for_link(app, link) {
        lines.push(helpers::section_header("Peer"));
        lines.push(helpers::kv_line(
            "Name",
            helpers::str_field(&peer, "display_name"),
        ));
        lines.push(helpers::kv_line(
            "Connectivity",
            helpers::str_field(&peer, "connectivity"),
        ));
        lines.push(helpers::kv_line(
            "Last Seen",
            &helpers::format_elapsed_ms(
                peer.get("last_seen_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ));
        lines.push(Line::from(""));
        lines.push(helpers::section_header("Peer Stats"));
        lines.push(helpers::kv_line(
            "Pkts Sent",
            &helpers::nested_u64(&peer, "stats", "packets_sent"),
        ));
        lines.push(helpers::kv_line(
            "Pkts Recv",
            &helpers::nested_u64(&peer, "stats", "packets_recv"),
        ));
        lines.push(helpers::kv_line(
            "Bytes Sent",
            &helpers::format_bytes(
                peer.get("stats")
                    .and_then(|s| s.get("bytes_sent"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ));
        lines.push(helpers::kv_line(
            "Bytes Recv",
            &helpers::format_bytes(
                peer.get("stats")
                    .and_then(|s| s.get("bytes_recv"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ));
        if peer.get("mmp").is_some() {
            lines.push(Line::from(""));
            lines.push(helpers::section_header("MMP Metrics"));
            lines.push(helpers::kv_line(
                "SRTT",
                &format!("{}ms", helpers::nested_f64(&peer, "mmp", "srtt_ms", 1)),
            ));
            lines.push(helpers::kv_line(
                "Loss Rate",
                &helpers::nested_f64_prefer(&peer, "mmp", "smoothed_loss", "loss_rate", 4),
            ));
            lines.push(helpers::kv_line(
                "ETX",
                &helpers::nested_f64_prefer(&peer, "mmp", "smoothed_etx", "etx", 2),
            ));
            lines.push(helpers::kv_line(
                "LQI",
                &helpers::nested_f64(&peer, "mmp", "lqi", 2),
            ));
        }
    }

    let detail_scroll = app.detail_view.as_ref().map(|d| d.scroll).unwrap_or(0);
    let paragraph = Paragraph::new(lines).scroll((detail_scroll, 0));
    frame.render_widget(paragraph, inner);
}

/// Look up the peer associated with a link by matching link_id.
fn lookup_peer_for_link(app: &App, link: &serde_json::Value) -> Option<serde_json::Value> {
    let link_id = link.get("link_id").and_then(|v| v.as_u64())?;
    let peers = app.data.get(&Tab::Peers)?;
    peers
        .get("peers")?
        .as_array()?
        .iter()
        .find(|p| p.get("link_id").and_then(|v| v.as_u64()) == Some(link_id))
        .cloned()
}

fn lookup_transport(app: &App, link: &serde_json::Value) -> Option<serde_json::Value> {
    let transport_id = link.get("transport_id").and_then(|v| v.as_u64())?;
    let transports = app.data.get(&Tab::Transports)?;
    transports
        .get("transports")?
        .as_array()?
        .iter()
        .find(|t| t.get("transport_id").and_then(|v| v.as_u64()) == Some(transport_id))
        .cloned()
}
