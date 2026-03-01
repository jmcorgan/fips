use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Routing) {
        Some(d) => d,
        None => {
            let msg = Paragraph::new("  Waiting for data...")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(7),  // Routing State
        Constraint::Length(8),  // Coordinate Cache
        Constraint::Min(3),    // Routing Statistics
    ])
    .split(area);

    draw_routing_state(frame, data, chunks[0]);
    draw_coord_cache(frame, app, chunks[1]);
    draw_routing_stats(frame, data, chunks[2]);
}

fn draw_routing_state(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let lines = vec![
        helpers::kv_line("Coord Cache", &helpers::u64_field(data, "coord_cache_entries")),
        helpers::kv_line(
            "Identity Cache",
            &helpers::u64_field(data, "identity_cache_entries"),
        ),
        helpers::kv_line(
            "Pending Lookups",
            &helpers::u64_field(data, "pending_lookups"),
        ),
        helpers::kv_line(
            "Recent Requests",
            &helpers::u64_field(data, "recent_requests"),
        ),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Routing State ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
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

fn draw_routing_stats(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Routing Statistics ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = vec![
        helpers::section_header("Forwarding"),
        fwd_line(data, "Received", "received_packets", "received_bytes"),
        fwd_line(data, "Delivered", "delivered_packets", "delivered_bytes"),
        fwd_line(data, "Forwarded", "forwarded_packets", "forwarded_bytes"),
        fwd_line(data, "Originated", "originated_packets", "originated_bytes"),
        fwd_line(data, "Decode Error", "decode_error_packets", "decode_error_bytes"),
        fwd_line(data, "TTL Exhausted", "ttl_exhausted_packets", "ttl_exhausted_bytes"),
        fwd_line(data, "No Route", "drop_no_route_packets", "drop_no_route_bytes"),
        fwd_line(data, "MTU Exceeded", "drop_mtu_exceeded_packets", "drop_mtu_exceeded_bytes"),
        fwd_line(data, "Send Error", "drop_send_error_packets", "drop_send_error_bytes"),
        Line::from(""),
        helpers::section_header("Discovery Requests"),
        helpers::kv_line("Received", &helpers::nested_u64(data, "discovery", "req_received")),
        helpers::kv_line("Forwarded", &helpers::nested_u64(data, "discovery", "req_forwarded")),
        helpers::kv_line("Initiated", &helpers::nested_u64(data, "discovery", "req_initiated")),
        helpers::kv_line("Deduplicated", &helpers::nested_u64(data, "discovery", "req_deduplicated")),
        helpers::kv_line("Target Is Us", &helpers::nested_u64(data, "discovery", "req_target_is_us")),
        helpers::kv_line("Duplicate", &helpers::nested_u64(data, "discovery", "req_duplicate")),
        helpers::kv_line("Already Visited", &helpers::nested_u64(data, "discovery", "req_already_visited")),
        helpers::kv_line("TTL Exhausted", &helpers::nested_u64(data, "discovery", "req_ttl_exhausted")),
        helpers::kv_line("Decode Error", &helpers::nested_u64(data, "discovery", "req_decode_error")),
        Line::from(""),
        helpers::section_header("Discovery Responses"),
        helpers::kv_line("Received", &helpers::nested_u64(data, "discovery", "resp_received")),
        helpers::kv_line("Accepted", &helpers::nested_u64(data, "discovery", "resp_accepted")),
        helpers::kv_line("Forwarded", &helpers::nested_u64(data, "discovery", "resp_forwarded")),
        helpers::kv_line("Timed Out", &helpers::nested_u64(data, "discovery", "resp_timed_out")),
        helpers::kv_line("Identity Miss", &helpers::nested_u64(data, "discovery", "resp_identity_miss")),
        helpers::kv_line("Proof Failed", &helpers::nested_u64(data, "discovery", "resp_proof_failed")),
        helpers::kv_line("Decode Error", &helpers::nested_u64(data, "discovery", "resp_decode_error")),
        Line::from(""),
        helpers::section_header("Error Signals"),
        helpers::kv_line("Coords Required", &helpers::nested_u64(data, "error_signals", "coords_required")),
        helpers::kv_line("Path Broken", &helpers::nested_u64(data, "error_signals", "path_broken")),
        helpers::kv_line("MTU Exceeded", &helpers::nested_u64(data, "error_signals", "mtu_exceeded")),
    ];

    let max_lines = inner.height as usize;
    lines.truncate(max_lines);

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_coord_cache(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Cache) {
        Some(d) => d,
        None => {
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" Coordinate Cache ");
            let inner = block.inner(area);
            frame.render_widget(block, area);
            let msg =
                Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, inner);
            return;
        }
    };

    let entries = helpers::u64_field(data, "entries");
    let max_entries = helpers::u64_field(data, "max_entries");
    let fill_pct = data
        .get("fill_ratio")
        .and_then(|v| v.as_f64())
        .map(|r| format!("{:.1}%", r * 100.0))
        .unwrap_or_else(|| "-".into());
    let ttl = data
        .get("default_ttl_ms")
        .and_then(|v| v.as_u64())
        .map(helpers::format_duration_ms)
        .unwrap_or_else(|| "-".into());
    let expired = helpers::u64_field(data, "expired");
    let avg_age = data
        .get("avg_age_ms")
        .and_then(|v| v.as_u64())
        .map(helpers::format_duration_ms)
        .unwrap_or_else(|| "-".into());

    let lines = vec![
        helpers::kv_line("Entries", &format!("{entries} / {max_entries}")),
        helpers::kv_line("Fill Ratio", &fill_pct),
        helpers::kv_line("Default TTL", &ttl),
        helpers::kv_line("Expired", &expired),
        helpers::kv_line("Avg Age", &avg_age),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Coordinate Cache ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines), inner);
}
