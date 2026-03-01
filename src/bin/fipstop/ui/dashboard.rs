use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;

use super::helpers;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&crate::app::Tab::Node) {
        Some(d) => d,
        None => {
            let msg = Paragraph::new("  Waiting for data...")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(7),  // Runtime
        Constraint::Length(7),  // Identity
        Constraint::Length(5),  // State
        Constraint::Length(9),  // Traffic
        Constraint::Min(0),    // remaining
    ])
    .split(area);

    draw_runtime(frame, data, chunks[0]);
    draw_identity(frame, data, chunks[1]);
    draw_state(frame, data, chunks[2]);
    draw_node_stats(frame, data, chunks[3]);
}

fn draw_runtime(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Runtime ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let pid = helpers::u64_field(data, "pid");
    let exe = helpers::str_field(data, "exe_path");
    let uptime_secs = data.get("uptime_secs").and_then(|v| v.as_u64()).unwrap_or(0);
    let uptime = format_uptime(uptime_secs);
    let socket = helpers::str_field(data, "control_socket");
    let tun_name = helpers::str_field(data, "tun_name");

    let label = Style::default().fg(Color::DarkGray);

    let lines = vec![
        Line::from(vec![
            Span::styled(" pid: ", label),
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
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Identity ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let npub = helpers::str_field(data, "npub");
    let node_addr = helpers::str_field(data, "node_addr");
    let ipv6_addr = helpers::str_field(data, "ipv6_addr");

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
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_state(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" State ");
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
    ];

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_node_stats(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Traffic ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        helpers::section_header("TUN (IPv6)"),
        fwd_line(data, "Tx", "delivered_packets", "delivered_bytes"),
        fwd_line(data, "Rx", "originated_packets", "originated_bytes"),
        Line::from(""),
        helpers::section_header("Forwarded (transit)"),
        fwd_line(data, "Packets", "forwarded_packets", "forwarded_bytes"),
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
    helpers::kv_line(label, &format!("{} pkts ({})", pkts, helpers::format_bytes(bytes)))
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
