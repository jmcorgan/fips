use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let sessions = get_sessions(app);
    let row_count = sessions.len();

    if app.detail_view.is_some() {
        let chunks = Layout::horizontal([
            Constraint::Percentage(40),
            Constraint::Percentage(60),
        ])
        .split(area);

        draw_table(frame, app, chunks[0], &sessions, row_count);
        draw_detail(frame, app, chunks[1], &sessions);
    } else {
        draw_table(frame, app, area, &sessions, row_count);
    }
}

fn get_sessions(app: &App) -> Vec<serde_json::Value> {
    app.data
        .get(&Tab::Sessions)
        .and_then(|v| v.get("sessions"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn draw_table(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    sessions: &[serde_json::Value],
    row_count: usize,
) {
    let header = Row::new(vec![
        Cell::from("Name"),
        Cell::from("Remote Addr"),
        Cell::from("State"),
        Cell::from("Role"),
        Cell::from("SRTT"),
        Cell::from("Loss"),
        Cell::from("SQI"),
        Cell::from("Path MTU"),
        Cell::from("Last Activity"),
    ])
    .style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = sessions
        .iter()
        .map(|session| {
            let name = helpers::str_field(session, "display_name");
            let addr = helpers::truncate_hex(helpers::str_field(session, "remote_addr"), 10);
            let state = helpers::str_field(session, "state");
            let role = session
                .get("is_initiator")
                .and_then(|v| v.as_bool())
                .map(|b| if b { "init" } else { "resp" })
                .unwrap_or("-");
            let srtt = helpers::nested_f64(session, "mmp", "srtt_ms", 1);
            let loss = helpers::nested_f64_prefer(session, "mmp", "smoothed_loss", "loss_rate", 3);
            let sqi = helpers::nested_f64(session, "mmp", "sqi", 2);
            let path_mtu = helpers::nested_u64(session, "mmp", "path_mtu");
            let activity = helpers::format_elapsed_ms(
                session
                    .get("last_activity_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            );

            Row::new(vec![
                Cell::from(name.to_string()),
                Cell::from(addr),
                Cell::from(state_styled(state)),
                Cell::from(role.to_string()),
                Cell::from(srtt),
                Cell::from(loss),
                Cell::from(sqi),
                Cell::from(path_mtu),
                Cell::from(activity),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(12),
        Constraint::Length(13),
        Constraint::Length(13),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Length(9),
        Constraint::Length(14),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Sessions ({}) ", row_count)),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let state = app.table_states.entry(Tab::Sessions).or_default();
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

fn draw_detail(frame: &mut Frame, app: &App, area: Rect, sessions: &[serde_json::Value]) {
    let state = app.table_states.get(&Tab::Sessions);
    let selected = state.and_then(|s| s.selected()).unwrap_or(0);

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Session Detail ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(session) = sessions.get(selected) else {
        let msg =
            Paragraph::new("  No session selected").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    };

    let role = session
        .get("is_initiator")
        .and_then(|v| v.as_bool())
        .map(|b| if b { "Initiator" } else { "Responder" })
        .unwrap_or("-");

    let mut lines: Vec<Line> = vec![
        helpers::section_header("Identity"),
        helpers::kv_line("Name", helpers::str_field(session, "display_name")),
        helpers::kv_line("Npub", helpers::str_field(session, "npub")),
        helpers::kv_line("Remote Addr", helpers::str_field(session, "remote_addr")),
        Line::from(""),
        helpers::section_header("Session"),
        helpers::kv_line("State", helpers::str_field(session, "state")),
        helpers::kv_line("Role", role),
        helpers::kv_line(
            "Last Activity",
            &helpers::format_elapsed_ms(
                session
                    .get("last_activity_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ),
        Line::from(""),
    ];

    // Traffic stats
    lines.push(helpers::section_header("Traffic"));
    lines.push(helpers::kv_line(
        "Pkts Sent",
        &helpers::nested_u64(session, "stats", "packets_sent"),
    ));
    lines.push(helpers::kv_line(
        "Pkts Recv",
        &helpers::nested_u64(session, "stats", "packets_recv"),
    ));
    lines.push(helpers::kv_line(
        "Bytes Sent",
        &helpers::format_bytes(
            session
                .get("stats")
                .and_then(|s| s.get("bytes_sent"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        ),
    ));
    lines.push(helpers::kv_line(
        "Bytes Recv",
        &helpers::format_bytes(
            session
                .get("stats")
                .and_then(|s| s.get("bytes_recv"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        ),
    ));
    lines.push(Line::from(""));

    if session.get("mmp").is_some() {
        lines.push(helpers::section_header("MMP Metrics"));
        lines.push(helpers::kv_line(
            "Mode",
            &helpers::nested_str(session, "mmp", "mode"),
        ));
        lines.push(helpers::kv_line(
            "SRTT",
            &format!(
                "{}ms",
                helpers::nested_f64(session, "mmp", "srtt_ms", 1)
            ),
        ));
        lines.push(helpers::kv_line(
            "Loss Rate",
            &helpers::nested_f64_prefer(session, "mmp", "smoothed_loss", "loss_rate", 4),
        ));
        lines.push(helpers::kv_line(
            "ETX",
            &helpers::nested_f64_prefer(session, "mmp", "smoothed_etx", "etx", 2),
        ));
        lines.push(helpers::kv_line(
            "SQI",
            &helpers::nested_f64(session, "mmp", "sqi", 2),
        ));
        lines.push(helpers::kv_line(
            "Goodput",
            &helpers::nested_throughput(session, "mmp", "goodput_bps"),
        ));
        lines.push(helpers::kv_line(
            "Delivery Fwd",
            &helpers::nested_f64(session, "mmp", "delivery_ratio_forward", 3),
        ));
        lines.push(helpers::kv_line(
            "Delivery Rev",
            &helpers::nested_f64(session, "mmp", "delivery_ratio_reverse", 3),
        ));
        lines.push(helpers::kv_line(
            "Path MTU",
            &helpers::nested_u64(session, "mmp", "path_mtu"),
        ));
    }

    let detail_scroll = app.detail_view.as_ref().map(|d| d.scroll).unwrap_or(0);
    let paragraph = Paragraph::new(lines).scroll((detail_scroll, 0));
    frame.render_widget(paragraph, inner);
}

fn state_styled(state: &str) -> Span<'static> {
    let color = match state {
        "established" => Color::Green,
        "initiating" | "awaiting_msg3" => Color::Yellow,
        _ => Color::Red,
    };
    Span::styled(state.to_string(), Style::default().fg(color))
}

