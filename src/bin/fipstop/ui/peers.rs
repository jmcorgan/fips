use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let peers = get_peers_sorted(app);
    let row_count = peers.len();

    if app.detail_view.is_some() {
        // Split: left 40% table, right 60% detail
        let chunks = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        draw_table(frame, app, chunks[0], &peers, row_count);
        draw_detail(frame, app, chunks[1], &peers);
    } else {
        draw_table(frame, app, area, &peers, row_count);
    }
}

/// Get peers sorted by LQI ascending (best first). Peers without LQI sort last.
fn get_peers_sorted(app: &App) -> Vec<serde_json::Value> {
    let mut peers = app
        .data
        .get(&Tab::Peers)
        .and_then(|v| v.get("peers"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    peers.sort_by(|a, b| {
        let lqi_a = a
            .get("mmp")
            .and_then(|m| m.get("lqi"))
            .and_then(|v| v.as_f64());
        let lqi_b = b
            .get("mmp")
            .and_then(|m| m.get("lqi"))
            .and_then(|v| v.as_f64());
        match (lqi_a, lqi_b) {
            (Some(a), Some(b)) => a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });

    peers
}

fn draw_table(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    peers: &[serde_json::Value],
    row_count: usize,
) {
    let header = Row::new(vec![
        Cell::from("Name"),
        Cell::from("Npub"),
        Cell::from("Transport"),
        Cell::from("Dir"),
        Cell::from("SRTT"),
        Cell::from("Loss"),
        Cell::from("LQI"),
        Cell::from("Goodput"),
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
            let npub = helpers::str_field(peer, "npub");
            let is_parent = peer
                .get("is_parent")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let is_child = peer
                .get("is_child")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Transport: "type addr" (e.g., "udp 1.2.3.4:2121")
            let transport = {
                let t_type = peer
                    .get("transport_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let t_addr = peer
                    .get("transport_addr")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if t_type.is_empty() && t_addr.is_empty() {
                    "-".to_string()
                } else if t_type.is_empty() {
                    t_addr.to_string()
                } else if t_addr.is_empty() {
                    t_type.to_string()
                } else {
                    format!("{t_type}/{t_addr}")
                }
            };

            let dir = peer
                .get("direction")
                .and_then(|v| v.as_str())
                .map(|d| match d {
                    "inbound" => "in",
                    "outbound" => "out",
                    other => other,
                })
                .unwrap_or("-");
            let srtt = helpers::nested_f64(peer, "mmp", "srtt_ms", 1);
            let loss = helpers::nested_f64_prefer(peer, "mmp", "smoothed_loss", "loss_rate", 3);
            let lqi = helpers::nested_f64(peer, "mmp", "lqi", 2);
            let goodput = helpers::nested_throughput(peer, "mmp", "goodput_bps");
            let pkts_tx = helpers::nested_u64(peer, "stats", "packets_sent");
            let pkts_rx = helpers::nested_u64(peer, "stats", "packets_recv");

            // Tree role colorization
            let row_style = if is_parent {
                Style::default().fg(Color::Magenta)
            } else if is_child {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(name.to_string()),
                Cell::from(npub.to_string()),
                Cell::from(transport),
                Cell::from(dir.to_string()),
                Cell::from(srtt),
                Cell::from(loss),
                Cell::from(lqi),
                Cell::from(goodput),
                Cell::from(pkts_tx),
                Cell::from(pkts_rx),
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Min(12),    // Name
        Constraint::Length(67), // Npub (full bech32)
        Constraint::Min(20),    // Transport
        Constraint::Length(4),  // Dir
        Constraint::Length(8),  // SRTT
        Constraint::Length(7),  // Loss
        Constraint::Length(6),  // LQI
        Constraint::Length(10), // Goodput
        Constraint::Length(9),  // Pkts Tx
        Constraint::Length(9),  // Pkts Rx
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

    let has_tree = peer
        .get("has_tree_position")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let has_bloom = peer
        .get("has_bloom_filter")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_parent = peer
        .get("is_parent")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_child = peer
        .get("is_child")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let tree_role = if is_parent {
        "parent"
    } else if is_child {
        "child"
    } else {
        "peer"
    };

    let mut lines: Vec<Line> = vec![
        // Identity
        helpers::section_header("Identity"),
        helpers::kv_line("Name", helpers::str_field(peer, "display_name")),
        helpers::kv_line("Node Addr", helpers::str_field(peer, "node_addr")),
        helpers::kv_line("Npub", helpers::str_field(peer, "npub")),
        helpers::kv_line("IPv6 Addr", helpers::str_field(peer, "ipv6_addr")),
        helpers::kv_line("Tree Role", tree_role),
        Line::from(""),
        // Connection
        helpers::section_header("Connection"),
        helpers::kv_line("Connectivity", helpers::str_field(peer, "connectivity")),
        helpers::kv_line("Link ID", &helpers::u64_field(peer, "link_id")),
        helpers::kv_line(
            "Direction",
            peer.get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("-"),
        ),
    ];
    if let Some(addr) = peer.get("transport_addr").and_then(|v| v.as_str()) {
        lines.push(helpers::kv_line("Transport Addr", addr));
    }
    if let Some(t_type) = peer.get("transport_type").and_then(|v| v.as_str()) {
        lines.push(helpers::kv_line("Transport Type", t_type));
    }
    // Link details (cross-referenced)
    let link_id = peer.get("link_id").and_then(|v| v.as_u64());
    let link = lookup_link(app, link_id);
    if let Some(ref link) = link {
        lines.push(helpers::kv_line(
            "Link State",
            helpers::str_field(link, "state"),
        ));
    }
    lines.extend([
        helpers::kv_line(
            "Authenticated",
            &helpers::format_elapsed_ms(
                peer.get("authenticated_at_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ),
        helpers::kv_line(
            "Last Seen",
            &helpers::format_elapsed_ms(
                peer.get("last_seen_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ),
        Line::from(""),
    ]);

    // Transport info (cross-referenced from link -> transport)
    if let Some(transport) = link.as_ref().and_then(|l| lookup_transport(app, l)) {
        lines.push(helpers::section_header("Transport"));
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
        helpers::kv_line(
            "Pkts Sent",
            &helpers::nested_u64(peer, "stats", "packets_sent"),
        ),
        helpers::kv_line(
            "Pkts Recv",
            &helpers::nested_u64(peer, "stats", "packets_recv"),
        ),
        helpers::kv_line(
            "Bytes Sent",
            &helpers::format_bytes(
                peer.get("stats")
                    .and_then(|s| s.get("bytes_sent"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ),
        helpers::kv_line(
            "Bytes Recv",
            &helpers::format_bytes(
                peer.get("stats")
                    .and_then(|s| s.get("bytes_recv"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ),
        Line::from(""),
    ]);

    // MMP (if present)
    if peer.get("mmp").is_some() {
        lines.push(helpers::section_header("MMP Metrics"));
        lines.push(helpers::kv_line(
            "Mode",
            &helpers::nested_str(peer, "mmp", "mode"),
        ));
        lines.push(helpers::kv_line(
            "SRTT",
            &format!("{}ms", helpers::nested_f64(peer, "mmp", "srtt_ms", 1)),
        ));
        lines.push(helpers::kv_line(
            "Loss Rate",
            &helpers::nested_f64_prefer(peer, "mmp", "smoothed_loss", "loss_rate", 4),
        ));
        lines.push(helpers::kv_line(
            "ETX",
            &helpers::nested_f64_prefer(peer, "mmp", "smoothed_etx", "etx", 2),
        ));
        lines.push(helpers::kv_line(
            "LQI",
            &helpers::nested_f64(peer, "mmp", "lqi", 2),
        ));
        lines.push(helpers::kv_line(
            "Goodput",
            &helpers::nested_throughput(peer, "mmp", "goodput_bps"),
        ));
        lines.push(helpers::kv_line(
            "Delivery Fwd",
            &helpers::nested_f64(peer, "mmp", "delivery_ratio_forward", 3),
        ));
        lines.push(helpers::kv_line(
            "Delivery Rev",
            &helpers::nested_f64(peer, "mmp", "delivery_ratio_reverse", 3),
        ));
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

/// Look up transport info by chaining: link -> transport_id -> transport.
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
