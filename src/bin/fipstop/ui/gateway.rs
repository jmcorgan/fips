use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Gauge, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Table,
};

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    if !app.gateway_running {
        let msg = Paragraph::new("  Gateway not running")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::ALL).title(" Gateway "));
        frame.render_widget(msg, area);
        return;
    }

    let chunks = Layout::vertical([
        Constraint::Length(12), // summary
        Constraint::Min(1),     // mappings table
    ])
    .split(area);

    draw_summary(frame, app, chunks[0]);
    draw_mappings(frame, app, chunks[1]);
}

fn draw_summary(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Gateway) {
        Some(d) => d,
        None => {
            let msg =
                Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Length(7), // pool + config + info
        Constraint::Length(3), // gauge
        Constraint::Min(0),
    ])
    .split(area);

    // Pool and info section
    let block = Block::default().borders(Borders::ALL).title(" Gateway ");
    let inner = block.inner(chunks[0]);
    frame.render_widget(block, chunks[0]);

    let total = data.get("pool_total").and_then(|v| v.as_u64()).unwrap_or(0);
    let allocated = data
        .get("pool_allocated")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let active = data
        .get("pool_active")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let draining = data
        .get("pool_draining")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let free = data.get("pool_free").and_then(|v| v.as_u64()).unwrap_or(0);
    let nat = data
        .get("nat_mappings")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let dns = helpers::str_field(data, "dns_listen");
    let uptime_secs = data
        .get("uptime_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let pool_cidr = helpers::str_field(data, "pool_cidr");
    let lan_iface = helpers::str_field(data, "lan_interface");
    let dns_upstream = helpers::str_field(data, "dns_upstream");
    let dns_ttl = data.get("dns_ttl").and_then(|v| v.as_u64()).unwrap_or(0);
    let grace = data
        .get("pool_grace_period")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let label = Style::default().fg(Color::DarkGray);
    let count = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let val = Style::default().fg(Color::White);

    let lines = vec![
        Line::from(vec![
            Span::styled(" pool: ", label),
            Span::styled(pool_cidr.to_string(), val),
            Span::styled("  iface: ", label),
            Span::styled(lan_iface.to_string(), val),
            Span::styled("  dns: ", label),
            Span::styled(format!("{dns} → {dns_upstream}"), val),
            Span::styled("  ttl: ", label),
            Span::styled(format!("{dns_ttl}s"), val),
            Span::styled("  grace: ", label),
            Span::styled(format!("{grace}s"), val),
        ]),
        Line::from(vec![
            Span::styled(" total: ", label),
            Span::styled(total.to_string(), count),
            Span::styled("  allocated: ", label),
            Span::styled(allocated.to_string(), count),
            Span::styled("  active: ", label),
            Span::styled(active.to_string(), count),
            Span::styled("  draining: ", label),
            Span::styled(draining.to_string(), count),
            Span::styled("  free: ", label),
            Span::styled(free.to_string(), count),
        ]),
        Line::from(vec![
            Span::styled(" NAT mappings: ", label),
            Span::styled(nat.to_string(), count),
            Span::styled("  uptime: ", label),
            Span::raw(format_uptime(uptime_secs)),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);

    // Pool utilization gauge
    let ratio = if total > 0 {
        allocated as f64 / total as f64
    } else {
        0.0
    };
    let pct = (ratio * 100.0).min(100.0);
    let gauge_label = format!("{allocated}/{total} allocated ({pct:.1}%)");
    let gauge_color = if pct > 90.0 {
        Color::Red
    } else if pct > 70.0 {
        Color::Yellow
    } else {
        Color::Green
    };
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Pool Utilization "),
        )
        .gauge_style(Style::default().fg(gauge_color))
        .ratio(ratio.min(1.0))
        .label(gauge_label);
    frame.render_widget(gauge, chunks[1]);
}

fn draw_mappings(frame: &mut Frame, app: &mut App, area: Rect) {
    let mappings = app
        .gateway_mappings
        .as_ref()
        .and_then(|v| v.get("mappings"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let row_count = mappings.len();

    let header = Row::new(vec![
        Cell::from("Virtual IP"),
        Cell::from("DNS Name"),
        Cell::from("Mesh Addr"),
        Cell::from("State"),
        Cell::from("Sessions"),
        Cell::from("Age"),
        Cell::from("Last Ref"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = mappings
        .iter()
        .map(|m| {
            let vip = helpers::str_field(m, "virtual_ip");
            let dns_name = helpers::str_field(m, "dns_name");
            let mesh = helpers::truncate_hex(helpers::str_field(m, "mesh_addr"), 24);
            let state = helpers::str_field(m, "state");
            let sessions = helpers::u64_field(m, "sessions");
            let age = m
                .get("age_secs")
                .and_then(|v| v.as_u64())
                .map(format_duration_secs)
                .unwrap_or_else(|| "-".into());
            let last_ref = m
                .get("last_ref_secs")
                .and_then(|v| v.as_u64())
                .map(|s| format!("{s}s ago"))
                .unwrap_or_else(|| "-".into());

            let row_style = match state {
                "Active" => Style::default().fg(Color::Green),
                "Draining" => Style::default().fg(Color::Yellow),
                _ => Style::default(),
            };

            Row::new(vec![
                Cell::from(vip.to_string()),
                Cell::from(dns_name.to_string()),
                Cell::from(mesh),
                Cell::from(state.to_string()),
                Cell::from(sessions),
                Cell::from(age),
                Cell::from(last_ref),
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Min(18),    // Virtual IP
        Constraint::Min(30),    // DNS Name
        Constraint::Min(26),    // Mesh Addr
        Constraint::Length(10), // State
        Constraint::Length(10), // Sessions
        Constraint::Length(10), // Age
        Constraint::Length(12), // Last Ref
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" NAT Mappings ({row_count}) ")),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let state = app.table_states.entry(Tab::Gateway).or_default();
    frame.render_stateful_widget(table, area, state);

    if row_count > 0 {
        let selected = state.selected().unwrap_or(0);
        let mut scrollbar_state = ScrollbarState::new(row_count).position(selected);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(None)
                .end_symbol(None),
            area,
            &mut scrollbar_state,
        );
    }
}

/// Format seconds as compact duration (e.g., "3d 2h", "15m 4s").
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

/// Format seconds as compact duration for table cells.
fn format_duration_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}
