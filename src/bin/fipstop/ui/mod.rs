mod bloom;
mod dashboard;
mod helpers;
mod mmp;
mod peers;
mod routing;
mod sessions;
mod transports;
mod tree;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{App, ConnectionState, Tab};

pub fn draw(frame: &mut Frame, app: &mut App) {
    let chunks = Layout::vertical([
        Constraint::Length(3), // tab bar
        Constraint::Min(1),   // content
        Constraint::Length(1), // status bar
    ])
    .split(frame.area());

    draw_tab_bar(frame, app, chunks[0]);
    draw_content(frame, app, chunks[1]);
    draw_status_bar(frame, app, chunks[2]);
}

fn draw_tab_bar(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title(" fipstop ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let highlight = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let normal = Style::default().fg(Color::White);
    let divider = Style::default().fg(Color::DarkGray);
    let group_sep = Style::default().fg(Color::DarkGray);

    let mut spans: Vec<Span> = Vec::new();
    for (i, tab) in Tab::ALL.iter().enumerate() {
        if i > 0 {
            if tab.group() != Tab::ALL[i - 1].group() {
                spans.push(Span::styled(" \u{2502} ", group_sep));
            } else {
                spans.push(Span::styled(" | ", divider));
            }
        }
        let style = if *tab == app.active_tab { highlight } else { normal };
        spans.push(Span::styled(tab.label(), style));
    }

    let line = Line::from(spans);
    frame.render_widget(Paragraph::new(line), inner);
}

fn draw_content(frame: &mut Frame, app: &mut App, area: Rect) {
    match app.active_tab {
        Tab::Node => dashboard::draw(frame, app, area),
        Tab::Peers => peers::draw(frame, app, area),
        Tab::Sessions => sessions::draw(frame, app, area),
        Tab::Transports => transports::draw(frame, app, area),
        Tab::Tree => tree::draw(frame, app, area),
        Tab::Bloom => bloom::draw(frame, app, area),
        Tab::Mmp => mmp::draw(frame, app, area),
        Tab::Cache => {} // data stored for Routing tab cross-reference
        Tab::Routing => routing::draw(frame, app, area),
        Tab::Links => {} // not a navigable tab; data stored for cross-references
    }
}

fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let conn = match &app.connection_state {
        ConnectionState::Connected => {
            Span::styled(" Connected ", Style::default().fg(Color::Green))
        }
        ConnectionState::Disconnected(msg) => Span::styled(
            format!(" Disconnected: {} ", msg),
            Style::default().fg(Color::Red),
        ),
    };

    let elapsed = app.last_fetch.elapsed();
    let timing = Span::raw(format!(
        "| Refresh: {}s | Updated: {:.1}s ago ",
        app.refresh_interval.as_secs(),
        elapsed.as_secs_f64()
    ));

    let help = Span::styled("[?] Help ", Style::default().fg(Color::DarkGray));

    let line = Line::from(vec![conn, timing, help]);
    let bar = Paragraph::new(line);
    frame.render_widget(bar, area);
}
