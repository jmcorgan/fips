use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Tree) {
        Some(d) => d,
        None => {
            let msg = Paragraph::new("  Waiting for data...")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(10), // Tree Position
        Constraint::Length(22), // Tree Announce Stats
        Constraint::Min(3),    // Tree Peers
    ])
    .split(area);

    draw_position(frame, data, chunks[0]);
    draw_stats(frame, data, chunks[1]);
    draw_peers(frame, data, chunks[2]);
}

fn draw_position(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let root_hex = helpers::str_field(data, "root");
    let is_root = data
        .get("is_root")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let depth = helpers::u64_field(data, "depth");
    let parent_name = helpers::str_field(data, "parent_display_name");
    let decl_seq = helpers::u64_field(data, "declaration_sequence");
    let decl_signed = helpers::bool_field(data, "declaration_signed");

    let root_display = if is_root {
        format!("{} (self)", helpers::truncate_hex(root_hex, 16))
    } else {
        helpers::truncate_hex(root_hex, 16)
    };

    let parent_display = if is_root {
        "self (root)".to_string()
    } else {
        parent_name.to_string()
    };

    let mut lines = vec![
        helpers::kv_line("Root", &root_display),
        helpers::kv_line("Depth", &depth),
        helpers::kv_line("Parent", &parent_display),
        helpers::kv_line("Declaration", &format!("seq {decl_seq}, {decl_signed}")),
        Line::from(""),
    ];

    // Coordinate path: my_coords array is self→root, render root→self
    if let Some(coords) = data.get("my_coords").and_then(|v| v.as_array()) {
        let mut path_parts: Vec<Span> = vec![Span::styled(
            "    Path: ",
            Style::default().fg(Color::DarkGray),
        )];

        if coords.is_empty() {
            path_parts.push(Span::styled(
                "[root]",
                Style::default().fg(Color::Yellow),
            ));
        } else {
            // Reverse: root first, self last
            for (i, entry) in coords.iter().rev().enumerate() {
                if i > 0 {
                    path_parts
                        .push(Span::styled(" > ", Style::default().fg(Color::DarkGray)));
                }
                let hex = entry.as_str().unwrap_or("-");
                let color = if i == 0 {
                    Color::Yellow // root
                } else {
                    Color::White
                };
                path_parts
                    .push(Span::styled(helpers::truncate_hex(hex, 8), Style::default().fg(color)));
            }
            path_parts.push(Span::styled(" > ", Style::default().fg(Color::DarkGray)));
            path_parts.push(Span::styled(
                "[self]",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ));
        }

        lines.push(Line::from(path_parts));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tree Position ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_stats(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Tree Announce Stats ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines = vec![
        helpers::section_header("Inbound"),
        helpers::kv_line("Received", &helpers::nested_u64(data, "stats", "received")),
        helpers::kv_line("Accepted", &helpers::nested_u64(data, "stats", "accepted")),
        helpers::kv_line("Decode Error", &helpers::nested_u64(data, "stats", "decode_error")),
        helpers::kv_line("Unknown Peer", &helpers::nested_u64(data, "stats", "unknown_peer")),
        helpers::kv_line("Addr Mismatch", &helpers::nested_u64(data, "stats", "addr_mismatch")),
        helpers::kv_line("Sig Failed", &helpers::nested_u64(data, "stats", "sig_failed")),
        helpers::kv_line("Stale", &helpers::nested_u64(data, "stats", "stale")),
        helpers::kv_line("Parent Switched", &helpers::nested_u64(data, "stats", "parent_switched")),
        helpers::kv_line("Loop Detected", &helpers::nested_u64(data, "stats", "loop_detected")),
        helpers::kv_line("Ancestry Changed", &helpers::nested_u64(data, "stats", "ancestry_changed")),
        Line::from(""),
        helpers::section_header("Outbound"),
        helpers::kv_line("Sent", &helpers::nested_u64(data, "stats", "sent")),
        helpers::kv_line("Rate Limited", &helpers::nested_u64(data, "stats", "rate_limited")),
        helpers::kv_line("Send Failed", &helpers::nested_u64(data, "stats", "send_failed")),
        Line::from(""),
        helpers::section_header("Cumulative"),
        helpers::kv_line("Parent Switches", &helpers::nested_u64(data, "stats", "parent_switches")),
        helpers::kv_line("Parent Losses", &helpers::nested_u64(data, "stats", "parent_losses")),
        helpers::kv_line("Flap Dampened", &helpers::nested_u64(data, "stats", "flap_dampened")),
    ];

    // Trim to fit available height
    let max_lines = inner.height as usize;
    lines.truncate(max_lines);

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_peers(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let peers = data
        .get("peers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let my_root = helpers::str_field(data, "root");

    let count = peers.len();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Tree Peers ({count}) "));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if peers.is_empty() {
        let msg =
            Paragraph::new("  No peers").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    }

    let lines: Vec<Line> = peers
        .iter()
        .map(|p| {
            let name = helpers::str_field(p, "display_name");
            let has_depth = p.get("depth").is_some();

            if !has_depth {
                return Line::from(vec![
                    Span::styled(
                        format!("    {name:<16}"),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled("(no position)", Style::default().fg(Color::DarkGray)),
                ]);
            }

            let depth = helpers::u64_field(p, "depth");
            let dist = helpers::u64_field(p, "distance_to_us");
            let peer_root = helpers::str_field(p, "root");
            let (root_ind, root_color) = if peer_root == my_root {
                ("same root", Color::Green)
            } else {
                ("diff root", Color::Red)
            };

            Line::from(vec![
                Span::styled(
                    format!("    {name:<16}"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled("depth: ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{depth:<4}")),
                Span::styled("dist: ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{dist:<4}")),
                Span::styled(root_ind, Style::default().fg(root_color)),
            ])
        })
        .collect();

    frame.render_widget(Paragraph::new(lines), inner);
}
