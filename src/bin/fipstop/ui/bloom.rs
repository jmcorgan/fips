use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Bloom) {
        Some(d) => d,
        None => {
            let msg = Paragraph::new("  Waiting for data...")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(7),  // Bloom Filter State
        Constraint::Length(15), // Bloom Announce Stats
        Constraint::Min(3),    // Peer Filters
    ])
    .split(area);

    draw_state(frame, data, chunks[0]);
    draw_stats(frame, data, chunks[1]);
    draw_peer_filters(frame, data, chunks[2]);
}

fn draw_state(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let lines = vec![
        helpers::kv_line(
            "Node Addr",
            &helpers::truncate_hex(helpers::str_field(data, "own_node_addr"), 16),
        ),
        helpers::kv_line("Leaf Only", helpers::bool_field(data, "is_leaf_only")),
        helpers::kv_line("Sequence", &helpers::u64_field(data, "sequence")),
        helpers::kv_line(
            "Leaf Deps",
            &helpers::u64_field(data, "leaf_dependent_count"),
        ),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Bloom Filter State ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_stats(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Bloom Announce Stats ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = vec![
        helpers::section_header("Inbound"),
        helpers::kv_line("Received", &helpers::nested_u64(data, "stats", "received")),
        helpers::kv_line("Accepted", &helpers::nested_u64(data, "stats", "accepted")),
        helpers::kv_line("Decode Error", &helpers::nested_u64(data, "stats", "decode_error")),
        helpers::kv_line("Invalid", &helpers::nested_u64(data, "stats", "invalid")),
        helpers::kv_line("Non-V1", &helpers::nested_u64(data, "stats", "non_v1")),
        helpers::kv_line("Unknown Peer", &helpers::nested_u64(data, "stats", "unknown_peer")),
        helpers::kv_line("Stale", &helpers::nested_u64(data, "stats", "stale")),
        Line::from(""),
        helpers::section_header("Outbound"),
        helpers::kv_line("Sent", &helpers::nested_u64(data, "stats", "sent")),
        helpers::kv_line("Debounce Suppressed", &helpers::nested_u64(data, "stats", "debounce_suppressed")),
        helpers::kv_line("Send Failed", &helpers::nested_u64(data, "stats", "send_failed")),
    ];

    let max_lines = inner.height as usize;
    lines.truncate(max_lines);

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_peer_filters(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let filters = data
        .get("peer_filters")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let count = filters.len();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Peer Filters ({count}) "));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if filters.is_empty() {
        let msg =
            Paragraph::new("  No peers").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    }

    let lines: Vec<Line> = filters
        .iter()
        .map(|f| {
            let name = helpers::str_field(f, "display_name");
            let seq = helpers::u64_field(f, "filter_sequence");
            let has = f
                .get("has_filter")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let mut spans = vec![
                Span::styled(
                    format!("    {name:<16}"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled("seq: ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{seq:<6}")),
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
                spans.push(Span::raw(format!("{fill:<8}")));
                spans.push(Span::styled("est: ", Style::default().fg(Color::DarkGray)));
                spans.push(Span::raw(format!("{est:<6}")));
                spans.push(Span::styled("ok", Style::default().fg(Color::Green)));
            } else {
                spans.push(Span::styled("none", Style::default().fg(Color::Red)));
            }

            Line::from(spans)
        })
        .collect();

    frame.render_widget(Paragraph::new(lines), inner);
}
