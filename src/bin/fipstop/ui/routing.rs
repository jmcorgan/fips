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

/// Read a raw forwarding counter as a u64 (0 if missing), for arithmetic
/// (percentages, derived totals) that the string-returning helpers can't do.
fn fwd_count(data: &serde_json::Value, key: &str) -> u64 {
    data.get("forwarding")
        .and_then(|f| f.get(key))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

/// Total mesh egress = locally-originated + transit-forwarded, formatted as
/// "N pkts (B)". There is no single daemon counter for everything this node
/// transmits to peers, so it is derived from its two contributors.
fn mesh_tx_value(data: &serde_json::Value) -> String {
    let pkts = fwd_count(data, "originated_packets") + fwd_count(data, "forwarded_packets");
    let bytes = fwd_count(data, "originated_bytes") + fwd_count(data, "forwarded_bytes");
    format!("{} pkts ({})", pkts, helpers::format_bytes(bytes))
}

/// Format a route-class count as "N (xx.x%)" where the percentage is the class's
/// share of total forwarded (transit) packets. Zero forwarded yields "0.0%".
fn route_class_value(count: u64, total_forwarded: u64) -> String {
    let pct = if total_forwarded > 0 {
        count as f64 / total_forwarded as f64 * 100.0
    } else {
        0.0
    };
    format!("{count} ({pct:.1}%)")
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

    // Shorthand for a nested counter value (e.g. lookup.req_received).
    let lookup = |key: &str| helpers::nested_u64(data, "lookup", key);
    let err = |key: &str| helpers::nested_u64(data, "error_signals", key);
    let cong = |key: &str| helpers::nested_u64(data, "congestion", key);

    // The node is an interface adapter between the local host stack and the
    // mesh; the left column reads each side as a Transmitted/Received pair.
    //
    // Local Stack — traffic crossing the TUN / local-origination boundary:
    // Transmitted is what the host injects into the mesh (originated), Received
    // is what the mesh hands up to the host (delivered).
    let mut left = section(
        "Local Stack",
        &[
            (
                "Transmitted",
                fwd_value(data, "originated_packets", "originated_bytes"),
            ),
            (
                "Received",
                fwd_value(data, "delivered_packets", "delivered_bytes"),
            ),
        ],
    );
    left.push(Line::from(""));
    // Mesh — traffic crossing the peer-link boundary: Transmitted is everything
    // this node puts on the wire (originated + forwarded, derived), Received is
    // the ingress aggregate from peers (own-delivered + transit + drops).
    left.extend(section(
        "Mesh",
        &[
            ("Transmitted", mesh_tx_value(data)),
            (
                "Received",
                fwd_value(data, "received_packets", "received_bytes"),
            ),
        ],
    ));
    left.push(Line::from(""));
    left.extend(section(
        "Lookup Requests",
        &[
            ("Received", lookup("req_received")),
            ("Forwarded", lookup("req_forwarded")),
            ("Initiated", lookup("req_initiated")),
            ("Deduplicated", lookup("req_deduplicated")),
            ("Target Is Us", lookup("req_target_is_us")),
            ("Duplicate", lookup("req_duplicate")),
            ("Bloom Miss", lookup("req_bloom_miss")),
            ("Backoff Suppressed", lookup("req_backoff_suppressed")),
            ("Fwd Rate Limited", lookup("req_forward_rate_limited")),
            ("TTL Exhausted", lookup("req_ttl_exhausted")),
            ("Decode Error", lookup("req_decode_error")),
        ],
    ));
    left.push(Line::from(""));
    left.extend(section(
        "Lookup Responses",
        &[
            ("Received", lookup("resp_received")),
            ("Accepted", lookup("resp_accepted")),
            ("Forwarded", lookup("resp_forwarded")),
            ("Timed Out", lookup("resp_timed_out")),
            ("Identity Miss", lookup("resp_identity_miss")),
            ("Proof Failed", lookup("resp_proof_failed")),
            ("Decode Error", lookup("resp_decode_error")),
        ],
    ));

    // Right column — "Forwarded" (transit / routed through this node).
    // Forwarded total, then the route-class breakdown (a percentage partition
    // of the total), then the transit-path drop reasons.
    let fwd_total = fwd_count(data, "forwarded_packets");
    let mut right = section(
        "Forwarded",
        &[(
            "Forwarded",
            fwd_value(data, "forwarded_packets", "forwarded_bytes"),
        )],
    );
    // Blank separator after the Forwarded total, matching the spacing between
    // every other section pair; the total and its route-class breakdown read
    // as two distinct groups.
    right.push(Line::from(""));
    // Route-class breakdown: a partition of Forwarded, each line annotated with
    // its share of the total. Tree-down cross — the dive-to-tree-child
    // cut-through — is the last class; Tree-down + Tree-down cross sum to the
    // pre-split tree-down total.
    right.extend(section(
        "Route Class",
        &[
            (
                "Direct Peer",
                route_class_value(fwd_count(data, "route_direct_peer"), fwd_total),
            ),
            (
                "Tree-down",
                route_class_value(fwd_count(data, "route_tree_down"), fwd_total),
            ),
            (
                "Tree-up",
                route_class_value(fwd_count(data, "route_tree_up"), fwd_total),
            ),
            (
                "Cross-link descend",
                route_class_value(fwd_count(data, "route_crosslink_descend"), fwd_total),
            ),
            (
                "Cross-link ascend",
                route_class_value(fwd_count(data, "route_crosslink_ascend"), fwd_total),
            ),
            (
                "Tree-down cross",
                route_class_value(fwd_count(data, "route_tree_down_cross"), fwd_total),
            ),
        ],
    ));
    right.push(Line::from(""));
    right.extend(section(
        "Dropped",
        &[
            (
                "No Route",
                fwd_value(data, "drop_no_route_packets", "drop_no_route_bytes"),
            ),
            (
                "TTL Exhausted",
                fwd_value(data, "ttl_exhausted_packets", "ttl_exhausted_bytes"),
            ),
            (
                "Decode Error",
                fwd_value(data, "decode_error_packets", "decode_error_bytes"),
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
    ));
    right.push(Line::from(""));
    right.extend(section(
        "Error Signals",
        &[
            ("Coords Required", err("coords_required")),
            ("Path Broken", err("path_broken")),
            ("MTU Exceeded", err("mtu_exceeded")),
        ],
    ));
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
