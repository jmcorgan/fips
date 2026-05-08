//! "Listening on fips0" panel — right-half of the Node tab's Traffic block.
//!
//! Renders the daemon's `show_listening_sockets` payload as a table:
//!
//! ```text
//! ┌─ Listening on fips0 ──────────┐
//! │ Proto Port  Process    State  │
//! │ tcp   22    sshd       OPEN   │
//! │ tcp   8443  fips       OPEN   │
//! │ tcp   9100  prometheus filt   │
//! │ udp   5353  systemd-r* filt   │
//! └───────────────────────────────┘
//! ```
//!
//! Style rules per row's `filter` value:
//! - `accept` → default White (mesh-reachable).
//! - `drop` → DarkGray (less prominent).
//! - `unknown` → DarkGray with `?` suffix in State.
//! - `no_firewall` → default White; a yellow banner is rendered above
//!   the table in place of the title to alert the operator.
//!
//! A `*` after the process name marks wildcard binds (`local_addr ==
//! ::`) — the bind is not fips0-specific, so the operator sees it
//! exposed to the mesh perhaps unintentionally.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use serde_json::Value;

/// Render the listening-sockets panel into `area`. `payload` is the
/// raw `show_listening_sockets` response, or `None` if the daemon
/// couldn't be queried (old daemon, or the panel is rendering before
/// the first fetch).
pub fn draw(frame: &mut Frame, payload: Option<&Value>, area: Rect) {
    let payload = match payload {
        Some(p) => p,
        None => {
            let block = Block::default()
                .borders(Borders::ALL)
                .title(" Listening on fips0 ");
            let inner = block.inner(area);
            frame.render_widget(block, area);
            let msg = Paragraph::new(Span::styled(
                "  loading...",
                Style::default().fg(Color::DarkGray),
            ));
            frame.render_widget(msg, inner);
            return;
        }
    };

    let firewall_active = payload
        .get("firewall_active")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let sockets = payload
        .get("sockets")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Title — yellow banner replaces the plain title when the
    // baseline filter is not active.
    let title: Span<'static> = if firewall_active {
        Span::raw(" Listening on fips0 ")
    } else {
        Span::styled(
            " Listening on fips0  fips-firewall.service inactive — all listeners exposed ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    };

    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if sockets.is_empty() {
        let msg = Paragraph::new(Span::styled(
            "  no listeners reachable from fips0",
            Style::default().fg(Color::DarkGray),
        ));
        frame.render_widget(msg, inner);
        return;
    }

    let header = Row::new(vec![
        Cell::from("Proto"),
        Cell::from("Port"),
        Cell::from("Process"),
        Cell::from("State"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = sockets.iter().map(|s| build_row(s)).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),  // Proto
            Constraint::Length(6),  // Port
            Constraint::Min(8),     // Process (variable)
            Constraint::Length(11), // State (e.g., "filt? *" pad)
        ],
    )
    .header(header)
    .column_spacing(1);

    frame.render_widget(table, inner);
}

fn build_row(s: &Value) -> Row<'static> {
    let proto = s
        .get("proto")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let port = s.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
    let pid = s.get("pid").and_then(|v| v.as_u64());
    let process_name = s.get("process").and_then(|v| v.as_str());
    let wildcard = s
        .get("wildcard_bind")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let filter = s.get("filter").and_then(|v| v.as_str()).unwrap_or("drop");

    let process_label = match (pid, process_name) {
        (Some(p), Some(n)) => format!("{n}({p})"),
        (Some(p), None) => format!("?({p})"),
        _ => "?".to_string(),
    };
    let process_label = if wildcard && pid.is_some() {
        format!("{process_label} *")
    } else {
        process_label
    };

    let (state_text, row_style): (String, Style) = match filter {
        "accept" => ("OPEN".into(), Style::default()),
        "drop" => ("filt".into(), Style::default().fg(Color::DarkGray)),
        "unknown" => ("filt?".into(), Style::default().fg(Color::DarkGray)),
        "no_firewall" => ("OPEN".into(), Style::default()),
        _ => ("?".into(), Style::default().fg(Color::DarkGray)),
    };

    Row::new(vec![
        Cell::from(format!(" {proto}")),
        Cell::from(port.to_string()),
        Cell::from(process_label),
        Cell::from(state_text),
    ])
    .style(row_style)
}
