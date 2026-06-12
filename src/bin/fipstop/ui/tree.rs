use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Tree) {
        Some(d) => d,
        None => {
            let msg =
                Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(10), // Tree Position
        Constraint::Length(22), // Tree Announce Stats
        Constraint::Min(3),     // Tree Peers
    ])
    .split(area);

    let focused = app.focused_pane();
    draw_position(frame, data, app.pane_scroll(0), focused == 0, chunks[0]);
    draw_stats(frame, data, app.pane_scroll(1), focused == 1, chunks[1]);
    draw_peers(
        frame,
        app,
        data,
        app.pane_scroll(2),
        focused == 2,
        chunks[2],
    );
}

/// Look up a peer's daemon-computed `effective_depth` from the Peers tab data
/// by node_addr, formatted, or an em-dash when unavailable/unmeasured. The
/// value is a single daemon derivation (`show_peers`); the Tree tab reads it
/// back rather than recomputing, so the surfaces cannot drift.
fn peer_effective_depth(app: &App, node_addr: &str) -> String {
    app.data
        .get(&Tab::Peers)
        .and_then(|v| v.get("peers"))
        .and_then(|v| v.as_array())
        .and_then(|peers| {
            peers
                .iter()
                .find(|p| p.get("node_addr").and_then(|v| v.as_str()) == Some(node_addr))
        })
        .map(|p| helpers::opt_f64_field(p, "effective_depth", 2))
        .unwrap_or_else(|| "\u{2014}".into())
}

fn draw_position(
    frame: &mut Frame,
    data: &serde_json::Value,
    scroll: u16,
    focused: bool,
    area: Rect,
) {
    let root_hex = helpers::str_field(data, "root");
    let is_root = data
        .get("is_root")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let depth = helpers::u64_field(data, "depth");
    let parent_name = helpers::str_field(data, "parent_display_name");
    let decl_seq = helpers::u64_field(data, "declaration_sequence");
    let decl_signed = helpers::bool_field(data, "declaration_signed");

    // Full root hex (no truncation) so it can be correlated against logs and
    // configs; the npub line below resolves the root's identity when known.
    let root_display = if is_root {
        format!("{root_hex} (self)")
    } else {
        root_hex.to_string()
    };
    let root_npub = helpers::str_field(data, "root_npub");
    let npub_display = if root_npub == "-" {
        "<unknown>".to_string()
    } else {
        root_npub.to_string()
    };

    let parent_display = if is_root {
        "self (root)".to_string()
    } else {
        parent_name.to_string()
    };

    let mut lines = vec![
        helpers::kv_line("Root", &root_display),
        helpers::kv_line("Npub", &npub_display),
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
            path_parts.push(Span::styled("[root]", Style::default().fg(Color::Yellow)));
        } else {
            // Reverse: root first, self last
            for (i, entry) in coords.iter().rev().enumerate() {
                if i > 0 {
                    path_parts.push(Span::styled(" > ", Style::default().fg(Color::DarkGray)));
                }
                let hex = entry.as_str().unwrap_or("-");
                let color = if i == 0 {
                    Color::Yellow // root
                } else {
                    Color::White
                };
                path_parts.push(Span::styled(
                    helpers::truncate_hex(hex, 8),
                    Style::default().fg(color),
                ));
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

    let block = helpers::pane_block(" Tree Position ", focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

fn draw_stats(frame: &mut Frame, data: &serde_json::Value, scroll: u16, focused: bool, area: Rect) {
    let block = helpers::pane_block(" Tree Announce Stats ", focused);
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
        helpers::kv_line(
            "Unknown Peer",
            &helpers::nested_u64(data, "stats", "unknown_peer"),
        ),
        helpers::kv_line(
            "Addr Mismatch",
            &helpers::nested_u64(data, "stats", "addr_mismatch"),
        ),
        helpers::kv_line(
            "Sig Failed",
            &helpers::nested_u64(data, "stats", "sig_failed"),
        ),
        helpers::kv_line("Stale", &helpers::nested_u64(data, "stats", "stale")),
        helpers::kv_line(
            "Parent Switched",
            &helpers::nested_u64(data, "stats", "parent_switched"),
        ),
        helpers::kv_line(
            "Loop Detected",
            &helpers::nested_u64(data, "stats", "loop_detected"),
        ),
        helpers::kv_line(
            "Ancestry Changed",
            &helpers::nested_u64(data, "stats", "ancestry_changed"),
        ),
        Line::from(""),
        helpers::section_header("Outbound"),
        helpers::kv_line("Sent", &helpers::nested_u64(data, "stats", "sent")),
        helpers::kv_line(
            "Rate Limited",
            &helpers::nested_u64(data, "stats", "rate_limited"),
        ),
        helpers::kv_line(
            "Send Failed",
            &helpers::nested_u64(data, "stats", "send_failed"),
        ),
        Line::from(""),
        helpers::section_header("Cumulative"),
        helpers::kv_line(
            "Parent Switches",
            &helpers::nested_u64(data, "stats", "parent_switches"),
        ),
        helpers::kv_line(
            "Parent Losses",
            &helpers::nested_u64(data, "stats", "parent_losses"),
        ),
        helpers::kv_line(
            "Flap Dampened",
            &helpers::nested_u64(data, "stats", "flap_dampened"),
        ),
    ];

    // Apply the focused-pane scroll instead of truncating, so over-full stats
    // can be revealed by scrolling.
    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

fn draw_peers(
    frame: &mut Frame,
    app: &App,
    data: &serde_json::Value,
    scroll: u16,
    focused: bool,
    area: Rect,
) {
    let peers = data
        .get("peers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let my_root = helpers::str_field(data, "root").to_string();

    let count = peers.len();
    let block = helpers::pane_block(&format!(" Tree Peers ({count}) "), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if peers.is_empty() {
        let msg = Paragraph::new("  No peers").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    }

    // The tree response carries no role flags; recover them from the peers view
    // (cross-fetched on this tab) by joining on the hex node address, then group
    // by tree role (parent -> STP children -> other) like the Peers tab so the
    // same peer sits under the same heading on every surface.
    let role_map = helpers::peer_role_map(app.data.get(&Tab::Peers));
    let mut peers: Vec<serde_json::Value> = peers
        .into_iter()
        .map(|p| helpers::enrich_role(p, &role_map, "node_addr"))
        .collect();
    helpers::sort_by_group(&mut peers);

    let lines = helpers::grouped_peer_lines(&peers, |p| tree_peer_line(app, &my_root, p));

    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

/// Render one Tree-tab peer line: name plus depth/dist/eff columns and a
/// same-root/diff-root indicator, or a "(no position)" note for a peer with no
/// tree depth yet.
fn tree_peer_line(app: &App, my_root: &str, p: &serde_json::Value) -> Line<'static> {
    let name = helpers::str_field(p, "display_name");
    let has_depth = p.get("depth").is_some();

    if !has_depth {
        return Line::from(vec![
            Span::styled(
                format!("    {} ", helpers::truncate_name(name, 16)),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled("(no position)", Style::default().fg(Color::DarkGray)),
        ]);
    }

    let depth = helpers::u64_field(p, "depth");
    let dist = helpers::u64_field(p, "distance_to_us");
    let peer_root = helpers::str_field(p, "root");
    let node_addr = helpers::str_field(p, "node_addr");
    let eff = peer_effective_depth(app, node_addr);
    let (root_ind, root_color) = if peer_root == my_root {
        ("same root", Color::Green)
    } else {
        ("diff root", Color::Red)
    };

    Line::from(vec![
        Span::styled(
            format!("    {} ", helpers::truncate_name(name, 16)),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled("depth: ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{depth:<4}")),
        Span::styled("dist: ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{dist:<4}")),
        Span::styled("eff: ", Style::default().fg(Color::DarkGray)),
        Span::raw(format!("{eff:<7}")),
        Span::styled(root_ind, Style::default().fg(root_color)),
    ])
}
