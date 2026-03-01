use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table};

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let peers = get_peers(app);
    let row_count = peers.len();

    if app.detail_view.is_some() {
        // Split: left 40% table, right 60% detail
        let chunks = Layout::horizontal([
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .split(area);

        draw_table(frame, app, chunks[0], &peers, row_count);
        draw_detail(frame, app, chunks[1], &peers);
    } else {
        draw_table(frame, app, area, &peers, row_count);
    }
}

fn get_peers(app: &App) -> Vec<serde_json::Value> {
    app.data
        .get(&Tab::Peers)
        .and_then(|v| v.get("peers"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn draw_table(frame: &mut Frame, app: &mut App, area: Rect, peers: &[serde_json::Value], row_count: usize) {
    let header = Row::new(vec![
        Cell::from("Name"),
        Cell::from("Address"),
        Cell::from("Conn"),
        Cell::from("Depth"),
        Cell::from("SRTT"),
        Cell::from("Loss"),
        Cell::from("LQI"),
        Cell::from("Pkts Tx"),
        Cell::from("Pkts Rx"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = peers
        .iter()
        .map(|peer| {
            let name = helpers::str_field(peer, "display_name");
            let addr = helpers::truncate_hex(helpers::str_field(peer, "ipv6_addr"), 10);
            let conn = helpers::str_field(peer, "connectivity");
            let depth = peer
                .get("tree_depth")
                .and_then(|v| v.as_u64())
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into());
            let srtt = helpers::nested_f64(peer, "mmp", "srtt_ms", 1);
            let loss = helpers::nested_f64_prefer(peer, "mmp", "smoothed_loss", "loss_rate", 3);
            let lqi = helpers::nested_f64(peer, "mmp", "lqi", 2);
            let pkts_tx = helpers::nested_u64(peer, "stats", "packets_sent");
            let pkts_rx = helpers::nested_u64(peer, "stats", "packets_recv");

            Row::new(vec![
                Cell::from(name.to_string()),
                Cell::from(addr),
                Cell::from(connectivity_styled(conn)),
                Cell::from(depth),
                Cell::from(srtt),
                Cell::from(loss),
                Cell::from(lqi),
                Cell::from(pkts_tx),
                Cell::from(pkts_rx),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(12),
        Constraint::Length(13),
        Constraint::Length(8),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Length(9),
        Constraint::Length(9),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Peers ({}) ", row_count)),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let state = app.table_states.entry(Tab::Peers).or_default();
    frame.render_stateful_widget(table, area, state);

    // Scrollbar
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

fn draw_detail(frame: &mut Frame, app: &App, area: Rect, peers: &[serde_json::Value]) {
    let state = app.table_states.get(&Tab::Peers);
    let selected = state.and_then(|s| s.selected()).unwrap_or(0);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Peer Detail ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(peer) = peers.get(selected) else {
        let msg = Paragraph::new("  No peer selected").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    };

    let has_tree = peer.get("has_tree_position").and_then(|v| v.as_bool()).unwrap_or(false);
    let has_bloom = peer.get("has_bloom_filter").and_then(|v| v.as_bool()).unwrap_or(false);

    let mut lines: Vec<Line> = vec![
        // Identity
        helpers::section_header("Identity"),
        helpers::kv_line("Name", helpers::str_field(peer, "display_name")),
        helpers::kv_line("Node Addr", helpers::str_field(peer, "node_addr")),
        helpers::kv_line("Npub", helpers::str_field(peer, "npub")),
        helpers::kv_line("IPv6 Addr", helpers::str_field(peer, "ipv6_addr")),
        Line::from(""),
        // Connection
        helpers::section_header("Connection"),
        helpers::kv_line("Connectivity", helpers::str_field(peer, "connectivity")),
        helpers::kv_line("Link ID", &helpers::u64_field(peer, "link_id")),
    ];
    if let Some(addr) = peer.get("transport_addr").and_then(|v| v.as_str()) {
        lines.push(helpers::kv_line("Transport Addr", addr));
    }
    // Link details (cross-referenced)
    let link_id = peer.get("link_id").and_then(|v| v.as_u64());
    let link = lookup_link(app, link_id);
    if let Some(ref link) = link {
        lines.push(helpers::kv_line("Direction", helpers::str_field(link, "direction")));
        lines.push(helpers::kv_line("Link State", helpers::str_field(link, "state")));
    }
    lines.extend([
        helpers::kv_line("Authenticated", &helpers::format_elapsed_ms(
            peer.get("authenticated_at_ms").and_then(|v| v.as_u64()).unwrap_or(0),
        )),
        helpers::kv_line("Last Seen", &helpers::format_elapsed_ms(
            peer.get("last_seen_ms").and_then(|v| v.as_u64()).unwrap_or(0),
        )),
        Line::from(""),
    ]);

    // Transport info (cross-referenced from link → transport)
    if let Some(transport) = link.as_ref().and_then(|l| lookup_transport(app, l)) {
        lines.push(helpers::section_header("Transport"));
        lines.push(helpers::kv_line("Type", helpers::str_field(&transport, "type")));
        if let Some(name) = transport.get("name").and_then(|v| v.as_str()) {
            lines.push(helpers::kv_line("Name", name));
        }
        lines.push(helpers::kv_line("MTU", &helpers::u64_field(&transport, "mtu")));
        if let Some(addr) = transport.get("local_addr").and_then(|v| v.as_str()) {
            lines.push(helpers::kv_line("Local Addr", addr));
        }
        lines.push(helpers::kv_line("State", helpers::str_field(&transport, "state")));
        lines.push(Line::from(""));
    }

    lines.extend([
        // Tree & Bloom
        helpers::section_header("Tree / Bloom"),
        helpers::kv_line("Tree Position", if has_tree { "yes" } else { "no" }),
    ]);
    if let Some(depth) = peer.get("tree_depth").and_then(|v| v.as_u64()) {
        lines.push(helpers::kv_line("Tree Depth", &depth.to_string()));
    }
    lines.extend([
        helpers::kv_line("Bloom Filter", if has_bloom { "yes" } else { "no" }),
        helpers::kv_line("Filter Seq", &helpers::u64_field(peer, "filter_sequence")),
        Line::from(""),
        // Stats
        helpers::section_header("Link Stats"),
        helpers::kv_line("Pkts Sent", &helpers::nested_u64(peer, "stats", "packets_sent")),
        helpers::kv_line("Pkts Recv", &helpers::nested_u64(peer, "stats", "packets_recv")),
        helpers::kv_line("Bytes Sent", &helpers::format_bytes(
            peer.get("stats").and_then(|s| s.get("bytes_sent")).and_then(|v| v.as_u64()).unwrap_or(0),
        )),
        helpers::kv_line("Bytes Recv", &helpers::format_bytes(
            peer.get("stats").and_then(|s| s.get("bytes_recv")).and_then(|v| v.as_u64()).unwrap_or(0),
        )),
        Line::from(""),
    ]);

    // MMP (if present)
    if peer.get("mmp").is_some() {
        lines.push(helpers::section_header("MMP Metrics"));
        lines.push(helpers::kv_line("Mode", &helpers::nested_str(peer, "mmp", "mode")));
        lines.push(helpers::kv_line("SRTT", &format!("{}ms", helpers::nested_f64(peer, "mmp", "srtt_ms", 1))));
        lines.push(helpers::kv_line("Loss Rate", &helpers::nested_f64_prefer(peer, "mmp", "smoothed_loss", "loss_rate", 4)));
        lines.push(helpers::kv_line("ETX", &helpers::nested_f64_prefer(peer, "mmp", "smoothed_etx", "etx", 2)));
        lines.push(helpers::kv_line("LQI", &helpers::nested_f64(peer, "mmp", "lqi", 2)));
        lines.push(helpers::kv_line("Goodput", &helpers::nested_throughput(peer, "mmp", "goodput_bps")));
        lines.push(helpers::kv_line("Delivery Fwd", &helpers::nested_f64(peer, "mmp", "delivery_ratio_forward", 3)));
        lines.push(helpers::kv_line("Delivery Rev", &helpers::nested_f64(peer, "mmp", "delivery_ratio_reverse", 3)));
    }

    let detail_scroll = app.detail_view.as_ref().map(|d| d.scroll).unwrap_or(0);
    let paragraph = Paragraph::new(lines).scroll((detail_scroll, 0));
    frame.render_widget(paragraph, inner);
}

/// Look up the link for a peer by link_id.
fn lookup_link(app: &App, link_id: Option<u64>) -> Option<serde_json::Value> {
    let link_id = link_id?;
    let links = app.data.get(&Tab::Links)?;
    links
        .get("links")?
        .as_array()?
        .iter()
        .find(|l| l.get("link_id").and_then(|v| v.as_u64()) == Some(link_id))
        .cloned()
}

/// Look up transport info by chaining: link → transport_id → transport.
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

fn connectivity_styled(conn: &str) -> Span<'static> {
    let color = match conn {
        "Full" => Color::Green,
        "Partial" => Color::Yellow,
        _ => Color::Red,
    };
    Span::styled(conn.to_string(), Style::default().fg(color))
}

