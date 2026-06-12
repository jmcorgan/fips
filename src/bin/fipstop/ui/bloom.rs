use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Bloom) {
        Some(d) => d,
        None => {
            let msg =
                Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(8),  // Bloom Filter State
        Constraint::Length(15), // Bloom Announce Stats
        Constraint::Min(3),     // Peer Filters
    ])
    .split(area);

    let focused = app.focused_pane();
    draw_state(
        frame,
        app,
        data,
        app.pane_scroll(0),
        focused == 0,
        chunks[0],
    );
    draw_stats(frame, data, app.pane_scroll(1), focused == 1, chunks[1]);
    draw_peer_filters(
        frame,
        app,
        data,
        app.pane_scroll(2),
        focused == 2,
        chunks[2],
    );
}

fn draw_state(
    frame: &mut Frame,
    app: &App,
    data: &serde_json::Value,
    scroll: u16,
    focused: bool,
    area: Rect,
) {
    // is_root determines whether the uptree filter renders as "n/a (root)";
    // read it from the dashboard (State) surface, which carries it.
    let is_root = app
        .data
        .get(&Tab::Node)
        .and_then(|d| d.get("is_root"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Uptree filter (what we last sent to the tree parent): "n/a (root)" for a
    // root node, an em-dash before the first announce, else the value.
    let uptree_fill = if is_root {
        "n/a (root)".to_string()
    } else {
        match data.get("uptree_fill_ratio").and_then(|v| v.as_f64()) {
            Some(r) => format!("{:.1}%", r * 100.0),
            None => "\u{2014}".into(),
        }
    };
    let subtree_est = if is_root {
        "n/a (root)".to_string()
    } else {
        match data.get("uptree_estimated_count").and_then(|v| v.as_f64()) {
            Some(n) => format!("{:.0}", n),
            None => "\u{2014}".into(),
        }
    };

    let lines = helpers::kv_lines(&[
        (
            "Node Addr",
            helpers::truncate_hex(helpers::str_field(data, "own_node_addr"), 16),
        ),
        (
            "Leaf Only",
            helpers::bool_field(data, "is_leaf_only").into(),
        ),
        ("Sequence", helpers::u64_field(data, "sequence")),
        (
            "Leaf Deps",
            helpers::u64_field(data, "leaf_dependent_count"),
        ),
        ("Fill (sent uptree)", uptree_fill),
        ("Subtree est", subtree_est),
    ]);

    let block = helpers::pane_block(" Bloom Filter State ", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

fn draw_stats(frame: &mut Frame, data: &serde_json::Value, scroll: u16, focused: bool, area: Rect) {
    let block = helpers::pane_block(" Bloom Announce Stats ", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let lines = vec![
        helpers::section_header("Inbound"),
        helpers::kv_line("Received", &helpers::nested_u64(data, "stats", "received")),
        helpers::kv_line("Accepted", &helpers::nested_u64(data, "stats", "accepted")),
        helpers::kv_line(
            "Decode Error",
            &helpers::nested_u64(data, "stats", "decode_error"),
        ),
        helpers::kv_line("Invalid", &helpers::nested_u64(data, "stats", "invalid")),
        helpers::kv_line("Non-V1", &helpers::nested_u64(data, "stats", "non_v1")),
        helpers::kv_line(
            "Unknown Peer",
            &helpers::nested_u64(data, "stats", "unknown_peer"),
        ),
        helpers::kv_line("Stale", &helpers::nested_u64(data, "stats", "stale")),
        Line::from(""),
        helpers::section_header("Outbound"),
        helpers::kv_line("Sent", &helpers::nested_u64(data, "stats", "sent")),
        helpers::kv_line(
            "Debounce Suppressed",
            &helpers::nested_u64(data, "stats", "debounce_suppressed"),
        ),
        helpers::kv_line(
            "Send Failed",
            &helpers::nested_u64(data, "stats", "send_failed"),
        ),
    ];

    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

fn draw_peer_filters(
    frame: &mut Frame,
    app: &App,
    data: &serde_json::Value,
    scroll: u16,
    focused: bool,
    area: Rect,
) {
    let filters = data
        .get("peer_filters")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let count = filters.len();
    let block = helpers::pane_block(&format!(" Peer Filters ({count}) "), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if filters.is_empty() {
        let msg = Paragraph::new("  No peers").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    }

    // The bloom response carries no role flags; recover them from the peers view
    // (cross-fetched on this tab) by joining each filter's `peer` hex address,
    // then group by tree role (parent -> STP children -> other) to match the
    // Peers and Tree tabs so the same peer sits under the same heading.
    let role_map = helpers::peer_role_map(app.data.get(&Tab::Peers));
    let mut filters: Vec<serde_json::Value> = filters
        .into_iter()
        .map(|f| helpers::enrich_role(f, &role_map, "peer"))
        .collect();
    helpers::sort_by_group(&mut filters);

    let lines = helpers::grouped_peer_lines(&filters, peer_filter_line);

    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

/// Render one Bloom-tab peer-filter line: name, filter sequence, and either the
/// fill/estimate columns (when the peer has a filter) or a "none" marker.
fn peer_filter_line(f: &serde_json::Value) -> Line<'static> {
    let name = helpers::str_field(f, "display_name");
    let seq = helpers::u64_field(f, "filter_sequence");
    let has = f
        .get("has_filter")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Right-justify each numeric into a fixed field wide enough for
    // realistic data, with a guaranteed trailing separator so a
    // wider-than-expected value can never touch the next label, and
    // the digit columns line up across rows.
    let mut spans = vec![
        Span::styled(
            format!("    {} ", helpers::truncate_name(name, 16)),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled("seq: ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{seq:>9}  ")),
    ];

    if has {
        let fill = f
            .get("fill_ratio")
            .and_then(|v| v.as_f64())
            .map(|r| format!("{:.1}%", r * 100.0))
            .unwrap_or_else(|| "-".into());
        let est = f
            .get("estimated_count")
            .and_then(|v| v.as_f64())
            .map(|n| format!("{:.0}", n))
            .unwrap_or_else(|| "-".into());
        spans.push(Span::styled("fill: ", Style::default().fg(Color::DarkGray)));
        spans.push(Span::raw(format!("{fill:>6}  ")));
        spans.push(Span::styled("est: ", Style::default().fg(Color::DarkGray)));
        spans.push(Span::raw(format!("{est:>6}  ")));
        spans.push(Span::styled("ok", Style::default().fg(Color::Green)));
    } else {
        spans.push(Span::styled("none", Style::default().fg(Color::Red)));
    }

    Line::from(spans)
}
