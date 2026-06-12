use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;

use super::helpers;
use super::listening;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&crate::app::Tab::Node) {
        Some(d) => d,
        None => {
            let msg =
                Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(7), // Runtime
        Constraint::Length(7), // Identity
        Constraint::Length(8), // State (root egg + transports + sparkline rows)
        Constraint::Length(9), // Traffic + Listening on fips0 (side-by-side)
        Constraint::Min(0),    // remaining
    ])
    .split(area);

    draw_runtime(frame, data, chunks[0]);
    draw_identity(frame, data, chunks[1]);
    draw_state(frame, data, chunks[2]);

    // Traffic on the left, listening-on-fips0 on the right. The split
    // is 50/50 with a sane minimum width for each half so very narrow
    // terminals still produce readable columns.
    let traffic_chunks =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[3]);
    draw_node_stats(frame, data, traffic_chunks[0]);
    listening::draw(frame, app.listening_sockets.as_ref(), traffic_chunks[1]);
}

fn draw_runtime(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Runtime ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let version = helpers::str_field(data, "version");
    let pid = helpers::u64_field(data, "pid");
    let exe = helpers::str_field(data, "exe_path");
    let uptime_secs = data
        .get("uptime_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let uptime = format_uptime(uptime_secs);
    let socket = helpers::str_field(data, "control_socket");
    let tun_name = helpers::str_field(data, "tun_name");

    let label = Style::default().fg(Color::DarkGray);

    let lines = vec![
        Line::from(vec![
            Span::styled(" ver: ", label),
            Span::raw(version.to_string()),
            Span::styled("  pid: ", label),
            Span::raw(pid),
            Span::styled("  uptime: ", label),
            Span::raw(uptime),
        ]),
        Line::from(vec![
            Span::styled(" exe: ", label),
            Span::raw(exe.to_string()),
        ]),
        Line::from(vec![
            Span::styled(" ctl: ", label),
            Span::raw(socket.to_string()),
        ]),
        Line::from(vec![
            Span::styled(" tun: ", label),
            Span::raw(tun_name.to_string()),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_identity(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Identity ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let npub = helpers::str_field(data, "npub");
    let node_addr = helpers::str_field(data, "node_addr");
    let ipv6_addr = helpers::str_field(data, "ipv6_addr");
    // Effective persistence: whether this identity survives a restart.
    let mode = match data.get("persistent").and_then(|v| v.as_bool()) {
        Some(true) => "persistent",
        Some(false) => "ephemeral",
        None => "-",
    };

    let label = Style::default().fg(Color::DarkGray);

    let lines = vec![
        Line::from(vec![
            Span::styled(" npub:      ", label),
            Span::raw(npub.to_string()),
        ]),
        Line::from(vec![
            Span::styled(" node_addr: ", label),
            Span::raw(node_addr.to_string()),
        ]),
        Line::from(vec![
            Span::styled(" ipv6:      ", label),
            Span::raw(ipv6_addr.to_string()),
        ]),
        Line::from(vec![
            Span::styled(" identity:  ", label),
            Span::raw(mode.to_string()),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_state(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" State ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let state = helpers::str_field(data, "state");
    let tun = helpers::str_field(data, "tun_state");
    let mtu = helpers::u64_field(data, "effective_ipv6_mtu");
    let leaf = helpers::bool_field(data, "is_leaf_only");

    let label = Style::default().fg(Color::DarkGray);
    let count = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);

    let peers = helpers::u64_field(data, "peer_count");
    let sessions = helpers::u64_field(data, "session_count");
    let links = helpers::u64_field(data, "link_count");
    let transports = helpers::u64_field(data, "transport_count");
    let connections = helpers::u64_field(data, "connection_count");
    let mesh_size = data
        .get("estimated_mesh_size")
        .and_then(|v| v.as_u64())
        .map(|n| format!("~{n}"))
        .unwrap_or_else(|| "-".into());

    let mesh_spark =
        helpers::sparkline(&helpers::nested_f64_array(data, "sparklines", "mesh_size"));
    let peer_spark =
        helpers::sparkline(&helpers::nested_f64_array(data, "sparklines", "peer_count"));
    let spark_style = Style::default().fg(Color::DarkGray);

    // Root: an Easter-egg marker when this node IS the root, otherwise the
    // truncated root hex. The full root address + npub live on the Tree tab.
    let is_root = data
        .get("is_root")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let root_display = if is_root {
        "I am the one who roots".to_string()
    } else {
        let root_hex = helpers::str_field(data, "root");
        let head: String = root_hex.chars().take(16).collect();
        format!("{head}\u{2026}")
    };

    // Configured transport types each with their peer count, e.g.
    // "udp (5), tcp (2), tor (0)". Idle-but-configured types stay visible at 0.
    let transports_by_type = format_transport_peer_counts(data);

    let lines = vec![
        Line::from(vec![
            Span::styled(" state: ", label),
            Span::raw(state.to_string()),
            Span::styled("  tun: ", label),
            Span::raw(tun.to_string()),
            Span::styled("  mtu: ", label),
            Span::raw(mtu),
            Span::styled("  leaf: ", label),
            Span::raw(leaf.to_string()),
        ]),
        Line::from(vec![
            Span::styled(" peers: ", label),
            Span::styled(peers, count),
            Span::styled("  sessions: ", label),
            Span::styled(sessions, count),
            Span::styled("  links: ", label),
            Span::styled(links, count),
            Span::styled("  transports: ", label),
            Span::styled(transports, count),
            Span::styled("  connections: ", label),
            Span::styled(connections, count),
        ]),
        // The mesh size is a bloom-cardinality estimate, not an exact count;
        // it gets its own line so the longer "approx. mesh estimate:" label
        // does not overflow the counts line at narrow widths.
        Line::from(vec![
            Span::styled(" approx. mesh estimate: ", label),
            Span::styled(mesh_size, count),
        ]),
        Line::from(vec![
            Span::styled(" root: ", label),
            Span::raw(root_display),
        ]),
        Line::from(vec![
            Span::styled(" transports: ", label),
            Span::raw(transports_by_type),
        ]),
        Line::from(vec![
            Span::styled(" peers:  ", label),
            Span::styled(peer_spark, spark_style),
            Span::styled("   mesh: ", label),
            Span::styled(mesh_spark, spark_style),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

/// Format the `transport_peer_counts` map as `type (count)` joined with
/// commas, e.g. `udp (5), tcp (2), tor (0)`. Keys are rendered in sorted
/// order (the daemon emits a sorted map). Returns `-` when absent or empty.
fn format_transport_peer_counts(data: &serde_json::Value) -> String {
    let Some(map) = data
        .get("transport_peer_counts")
        .and_then(|v| v.as_object())
    else {
        return "-".into();
    };
    if map.is_empty() {
        return "-".into();
    }
    map.iter()
        .map(|(ty, count)| format!("{ty} ({})", count.as_u64().unwrap_or(0)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn draw_node_stats(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" Traffic ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let spark_style = Style::default().fg(Color::DarkGray);
    let label = Style::default().fg(Color::DarkGray);
    let bytes_in_spark =
        helpers::sparkline(&helpers::nested_f64_array(data, "sparklines", "bytes_in"));
    let bytes_out_spark =
        helpers::sparkline(&helpers::nested_f64_array(data, "sparklines", "bytes_out"));

    let lines = vec![
        helpers::section_header("TUN (IPv6)"),
        fwd_line(data, "Tx", "delivered_packets", "delivered_bytes"),
        fwd_line(data, "Rx", "originated_packets", "originated_bytes"),
        Line::from(""),
        helpers::section_header("Forwarded (transit)"),
        fwd_line(data, "Packets", "forwarded_packets", "forwarded_bytes"),
        Line::from(vec![
            Span::styled("    rate in:  ", label),
            Span::styled(bytes_in_spark, spark_style),
            Span::styled("   rate out: ", label),
            Span::styled(bytes_out_spark, spark_style),
        ]),
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

/// Format a forwarding counter as "N pkts (formatted_bytes)".
fn fwd_line(data: &serde_json::Value, label: &str, pkt_key: &str, byte_key: &str) -> Line<'static> {
    let pkts = data
        .get("forwarding")
        .and_then(|f| f.get(pkt_key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let bytes = data
        .get("forwarding")
        .and_then(|f| f.get(byte_key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    helpers::kv_line(
        label,
        &format!("{} pkts ({})", pkts, helpers::format_bytes(bytes)),
    )
}

/// Format seconds as human-readable uptime (e.g., "3d 2h 15m 4s").
fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {mins}m {s}s")
    } else if hours > 0 {
        format!("{hours}h {mins}m {s}s")
    } else if mins > 0 {
        format!("{mins}m {s}s")
    } else {
        format!("{s}s")
    }
}
