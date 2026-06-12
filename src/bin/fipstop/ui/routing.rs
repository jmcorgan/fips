use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Routing) {
        Some(d) => d,
        None => {
            let msg =
                Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(7), // Routing State
        Constraint::Length(8), // Coordinate Cache
        Constraint::Min(3),    // Routing Statistics
    ])
    .split(area);

    let focused = app.focused_pane();
    draw_routing_state(frame, data, app.pane_scroll(0), focused == 0, chunks[0]);
    draw_coord_cache(frame, app, app.pane_scroll(1), focused == 1, chunks[1]);
    draw_routing_stats(frame, data, app.pane_scroll(2), focused == 2, chunks[2]);
}

fn draw_routing_state(
    frame: &mut Frame,
    data: &serde_json::Value,
    scroll: u16,
    focused: bool,
    area: Rect,
) {
    let lines = helpers::kv_lines(&[
        (
            "Coord Cache",
            helpers::u64_field(data, "coord_cache_entries"),
        ),
        (
            "Identity Cache",
            helpers::u64_field(data, "identity_cache_entries"),
        ),
        (
            "Pending Lookups",
            data.get("pending_lookups")
                .and_then(|v| v.as_array())
                .map(|a| a.len().to_string())
                .unwrap_or_else(|| "0".into()),
        ),
        (
            "Recent Requests",
            helpers::u64_field(data, "recent_requests"),
        ),
    ]);

    let block = helpers::pane_block(" Routing State ", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

/// Format a forwarding counter as "N pkts (formatted_bytes)".
fn fwd_value(data: &serde_json::Value, pkt_key: &str, byte_key: &str) -> String {
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
    format!("{} pkts ({})", pkts, helpers::format_bytes(bytes))
}

/// Build a section: a styled header line followed by the kv pairs rendered
/// through the group helper so the section's values share a left edge.
fn section(title: &str, pairs: &[(&str, String)]) -> Vec<Line<'static>> {
    let mut out = vec![helpers::section_header(title)];
    out.extend(helpers::kv_lines(pairs));
    out
}

fn draw_routing_stats(
    frame: &mut Frame,
    data: &serde_json::Value,
    scroll: u16,
    focused: bool,
    area: Rect,
) {
    let block = helpers::pane_block(" Routing Statistics ", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let cols =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(inner);

    // Shorthand for a nested counter value (e.g. discovery.req_received).
    let disc = |key: &str| helpers::nested_u64(data, "discovery", key);
    let err = |key: &str| helpers::nested_u64(data, "error_signals", key);
    let cong = |key: &str| helpers::nested_u64(data, "congestion", key);

    // Left column: Forwarding + Discovery. Each section's values share a left
    // edge via the kv_lines group helper.
    let mut left = section(
        "Forwarding",
        &[
            (
                "Received",
                fwd_value(data, "received_packets", "received_bytes"),
            ),
            (
                "Delivered",
                fwd_value(data, "delivered_packets", "delivered_bytes"),
            ),
            (
                "Forwarded",
                fwd_value(data, "forwarded_packets", "forwarded_bytes"),
            ),
            (
                "Originated",
                fwd_value(data, "originated_packets", "originated_bytes"),
            ),
            (
                "Decode Error",
                fwd_value(data, "decode_error_packets", "decode_error_bytes"),
            ),
            (
                "TTL Exhausted",
                fwd_value(data, "ttl_exhausted_packets", "ttl_exhausted_bytes"),
            ),
            (
                "No Route",
                fwd_value(data, "drop_no_route_packets", "drop_no_route_bytes"),
            ),
            (
                "MTU Exceeded",
                fwd_value(data, "drop_mtu_exceeded_packets", "drop_mtu_exceeded_bytes"),
            ),
            (
                "Send Error",
                fwd_value(data, "drop_send_error_packets", "drop_send_error_bytes"),
            ),
        ],
    );
    left.push(Line::from(""));
    left.extend(section(
        "Discovery Requests",
        &[
            ("Received", disc("req_received")),
            ("Forwarded", disc("req_forwarded")),
            ("Initiated", disc("req_initiated")),
            ("Deduplicated", disc("req_deduplicated")),
            ("Target Is Us", disc("req_target_is_us")),
            ("Duplicate", disc("req_duplicate")),
            ("Bloom Miss", disc("req_bloom_miss")),
            ("Backoff Suppressed", disc("req_backoff_suppressed")),
            ("Fwd Rate Limited", disc("req_forward_rate_limited")),
            ("TTL Exhausted", disc("req_ttl_exhausted")),
            ("Decode Error", disc("req_decode_error")),
        ],
    ));
    left.push(Line::from(""));
    left.extend(section(
        "Discovery Responses",
        &[
            ("Received", disc("resp_received")),
            ("Accepted", disc("resp_accepted")),
            ("Forwarded", disc("resp_forwarded")),
            ("Timed Out", disc("resp_timed_out")),
            ("Identity Miss", disc("resp_identity_miss")),
            ("Proof Failed", disc("resp_proof_failed")),
            ("Decode Error", disc("resp_decode_error")),
        ],
    ));

    // Right column: Error Signals + Congestion
    let mut right = section(
        "Error Signals",
        &[
            ("Coords Required", err("coords_required")),
            ("Path Broken", err("path_broken")),
            ("MTU Exceeded", err("mtu_exceeded")),
        ],
    );
    right.push(Line::from(""));
    right.extend(section(
        "Congestion",
        &[
            ("CE Forwarded", cong("ce_forwarded")),
            ("CE Received", cong("ce_received")),
            ("Congestion Detected", cong("congestion_detected")),
            ("Kernel Drops", cong("kernel_drop_events")),
        ],
    ));

    // Both columns scroll together under the focused-pane offset, clamped to
    // the taller column so neither over-scrolls past its content.
    let visible = cols[0].height as usize;
    let content = left.len().max(right.len());
    let scroll = helpers::clamp_scroll(scroll, content, visible);

    frame.render_widget(Paragraph::new(left).scroll((scroll, 0)), cols[0]);
    frame.render_widget(Paragraph::new(right).scroll((scroll, 0)), cols[1]);
}

fn draw_coord_cache(frame: &mut Frame, app: &App, scroll: u16, focused: bool, area: Rect) {
    let data = match app.data.get(&Tab::Cache) {
        Some(d) => d,
        None => {
            let block = helpers::pane_block(" Coordinate Cache ", focused);
            let inner = block.inner(area);
            frame.render_widget(block, area);
            let msg =
                Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, inner);
            return;
        }
    };

    let entries = helpers::u64_field(data, "count");
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

    let lines = helpers::kv_lines(&[
        ("Entries", format!("{entries} / {max_entries}")),
        ("Fill Ratio", fill_pct),
        ("Default TTL", ttl),
        ("Expired", expired),
        ("Avg Age", avg_age),
    ]);

    let block = helpers::pane_block(" Coordinate Cache ", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}
