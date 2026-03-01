use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::{App, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Mmp) {
        Some(d) => d,
        None => {
            let msg = Paragraph::new("  Waiting for data...")
                .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks = Layout::vertical([
        Constraint::Percentage(60),
        Constraint::Percentage(40),
    ])
    .split(area);

    draw_link_mmp(frame, data, chunks[0]);
    draw_session_mmp(frame, data, chunks[1]);
}

fn draw_link_mmp(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let peers = data
        .get("peers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let count = peers.len();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Link MMP ({count} peers) "));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if peers.is_empty() {
        let msg =
            Paragraph::new("  No peers").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    }

    let mut lines: Vec<Line> = Vec::new();
    for peer in &peers {
        let name = helpers::str_field(peer, "display_name");
        let ll = peer.get("link_layer");

        let srtt = ll
            .and_then(|l| l.get("srtt_ms"))
            .and_then(|v| v.as_f64())
            .map(|v| format!("{:.1}ms", v))
            .unwrap_or_else(|| "-".into());
        let loss = ll
            .and_then(|l| l.get("smoothed_loss").or_else(|| l.get("loss_rate")))
            .and_then(|v| v.as_f64())
            .map(|v| format!("{:.4}", v))
            .unwrap_or_else(|| "-".into());
        let etx = ll
            .and_then(|l| l.get("smoothed_etx").or_else(|| l.get("etx")))
            .and_then(|v| v.as_f64())
            .map(|v| format!("{:.2}", v))
            .unwrap_or_else(|| "-".into());
        let lqi = ll
            .and_then(|l| l.get("lqi"))
            .and_then(|v| v.as_f64())
            .map(|v| format!("{:.2}", v))
            .unwrap_or_else(|| "-".into());
        let goodput = ll
            .and_then(|l| l.get("goodput_bps"))
            .and_then(|v| v.as_f64())
            .map(helpers::format_throughput)
            .unwrap_or_else(|| "-".into());

        // Line 1: primary metrics
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {name:<16}"),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("srtt: ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{srtt:<10}")),
            Span::styled("loss: ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{loss:<8}")),
            Span::styled("etx: ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{etx:<6}")),
            Span::styled("lqi: ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{lqi:<8}")),
            Span::styled("gp: ", Style::default().fg(Color::DarkGray)),
            Span::raw(goodput),
        ]));

        // Line 2: trends
        if let Some(ll_val) = ll {
            let mut trend_spans: Vec<Span> = vec![Span::raw("    ")];
            let mut has_trends = false;

            for (label, key, bad_rising) in [
                ("rtt", "rtt_trend", true),
                ("loss", "loss_trend", true),
                ("goodput", "goodput_trend", false),
                ("jitter", "jitter_trend", true),
            ] {
                if let Some(trend) = ll_val.get(key).and_then(|v| v.as_str()) {
                    if has_trends {
                        trend_spans.push(Span::raw("  "));
                    }
                    trend_spans.push(Span::styled(
                        format!("{label}: "),
                        Style::default().fg(Color::DarkGray),
                    ));
                    trend_spans.push(Span::styled(
                        trend.to_string(),
                        Style::default().fg(trend_color(trend, bad_rising)),
                    ));
                    has_trends = true;
                }
            }

            if has_trends {
                lines.push(Line::from(trend_spans));
            }
        }
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_session_mmp(frame: &mut Frame, data: &serde_json::Value, area: Rect) {
    let sessions = data
        .get("sessions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let count = sessions.len();
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Session MMP ({count} sessions) "));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if sessions.is_empty() {
        let msg = Paragraph::new("  No sessions")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    }

    let lines: Vec<Line> = sessions
        .iter()
        .map(|s| {
            let name = helpers::str_field(s, "display_name");
            let sl = s.get("session_layer");

            let srtt = sl
                .and_then(|l| l.get("srtt_ms"))
                .and_then(|v| v.as_f64())
                .map(|v| format!("{:.1}ms", v))
                .unwrap_or_else(|| "-".into());
            let loss = sl
                .and_then(|l| l.get("smoothed_loss").or_else(|| l.get("loss_rate")))
                .and_then(|v| v.as_f64())
                .map(|v| format!("{:.4}", v))
                .unwrap_or_else(|| "-".into());
            let etx = sl
                .and_then(|l| l.get("smoothed_etx").or_else(|| l.get("etx")))
                .and_then(|v| v.as_f64())
                .map(|v| format!("{:.2}", v))
                .unwrap_or_else(|| "-".into());
            let sqi = sl
                .and_then(|l| l.get("sqi"))
                .and_then(|v| v.as_f64())
                .map(|v| format!("{:.2}", v))
                .unwrap_or_else(|| "-".into());
            let mtu = sl
                .and_then(|l| l.get("path_mtu"))
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into());

            Line::from(vec![
                Span::styled(
                    format!("  {name:<16}"),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("srtt: ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{srtt:<10}")),
                Span::styled("loss: ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{loss:<8}")),
                Span::styled("etx: ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{etx:<6}")),
                Span::styled("sqi: ", Style::default().fg(Color::DarkGray)),
                Span::raw(format!("{sqi:<8}")),
                Span::styled("mtu: ", Style::default().fg(Color::DarkGray)),
                Span::raw(mtu),
            ])
        })
        .collect();

    frame.render_widget(Paragraph::new(lines), inner);
}

/// Color a trend value based on whether "rising" is bad or good for this metric.
fn trend_color(trend: &str, bad_rising: bool) -> Color {
    match trend {
        "rising" => {
            if bad_rising {
                Color::Red
            } else {
                Color::Green
            }
        }
        "falling" => {
            if bad_rising {
                Color::Green
            } else {
                Color::Red
            }
        }
        _ => Color::DarkGray, // "stable"
    }
}

