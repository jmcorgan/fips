use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, MMP_LINK_SORT_LABELS, MMP_SESSION_SORT_LABELS, SortState, Tab};

use super::helpers;

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let data = match app.data.get(&Tab::Mmp) {
        Some(d) => d,
        None => {
            let msg =
                Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray));
            frame.render_widget(msg, area);
            return;
        }
    };

    let chunks =
        Layout::vertical([Constraint::Percentage(60), Constraint::Percentage(40)]).split(area);

    let focused = app.focused_pane();
    draw_link_mmp(
        frame,
        data,
        app.mmp_link_sort,
        app.pane_scroll(0),
        focused == 0,
        chunks[0],
    );
    draw_session_mmp(
        frame,
        data,
        app.mmp_session_sort,
        app.pane_scroll(1),
        focused == 1,
        chunks[1],
    );
}

/// A numeric sort key for a metric value from a layer object, with absent
/// values sorting last under an ascending sort by mapping them to +infinity.
fn metric_key(layer: Option<&serde_json::Value>, prefer: &str, fallback: Option<&str>) -> f64 {
    layer
        .and_then(|l| l.get(prefer).or_else(|| fallback.and_then(|f| l.get(f))))
        .and_then(|v| v.as_f64())
        .unwrap_or(f64::INFINITY)
}

/// Render the sortable-column header line: each column label, with the active
/// sort column highlighted and carrying a direction arrow.
fn sort_header(labels: &[&str], sort: SortState) -> Line<'static> {
    let active = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let idle = Style::default().fg(Color::DarkGray);
    // Solid triangles for the sort direction, distinct from the line-arrow
    // glyphs the MMP trend columns use, so the two never collide visually or
    // in tests.
    let arrow = if sort.descending {
        "\u{25bc}"
    } else {
        "\u{25b2}"
    };
    let mut spans: Vec<Span<'static>> = vec![Span::styled("  sort: ", idle)];
    for (i, label) in labels.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" ", idle));
        }
        if i == sort.col {
            spans.push(Span::styled(format!("{label}{arrow}"), active));
        } else {
            spans.push(Span::styled(label.to_string(), idle));
        }
    }
    Line::from(spans)
}

/// Apply the sort state to `peers` in place. Column 0 sorts by display name;
/// the remaining columns sort by the corresponding metric from `layer_key`
/// (the `link_layer` / `session_layer` object). Descending reverses the order.
fn sort_peers(peers: &mut [serde_json::Value], sort: SortState, layer_key: &str) {
    peers.sort_by(|a, b| {
        let ord = if sort.col == 0 {
            let na = a.get("display_name").and_then(|v| v.as_str()).unwrap_or("");
            let nb = b.get("display_name").and_then(|v| v.as_str()).unwrap_or("");
            na.cmp(nb)
        } else {
            let la = a.get(layer_key);
            let lb = b.get(layer_key);
            let (ka, kb) = metric_pair(la, lb, layer_key, sort.col);
            ka.partial_cmp(&kb).unwrap_or(std::cmp::Ordering::Equal)
        };
        if sort.descending { ord.reverse() } else { ord }
    });
}

/// Compute the numeric sort keys for two peers on the given column, dispatching
/// to the correct metric for the Link vs Session layer.
fn metric_pair(
    la: Option<&serde_json::Value>,
    lb: Option<&serde_json::Value>,
    layer_key: &str,
    col: usize,
) -> (f64, f64) {
    let (prefer, fallback): (&str, Option<&str>) = if layer_key == "link_layer" {
        match col {
            1 => ("srtt_ms", None),
            2 => ("smoothed_loss", Some("loss_rate")),
            3 => ("smoothed_etx", Some("etx")),
            4 => ("lqi", None),
            _ => ("goodput_bps", None),
        }
    } else {
        match col {
            1 => ("srtt_ms", None),
            2 => ("smoothed_loss", Some("loss_rate")),
            3 => ("smoothed_etx", Some("etx")),
            4 => ("sqi", None),
            _ => ("path_mtu", None),
        }
    };
    (
        metric_key(la, prefer, fallback),
        metric_key(lb, prefer, fallback),
    )
}

fn draw_link_mmp(
    frame: &mut Frame,
    data: &serde_json::Value,
    sort: SortState,
    scroll: u16,
    focused: bool,
    area: Rect,
) {
    let mut peers = data
        .get("peers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let count = peers.len();
    let block = helpers::pane_block(&format!(" Link MMP ({count} peers) "), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if peers.is_empty() {
        let msg = Paragraph::new("  No peers").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    }

    sort_peers(&mut peers, sort, "link_layer");

    let mut lines: Vec<Line> = vec![sort_header(MMP_LINK_SORT_LABELS, sort)];
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

        // Trend arrows sit inline, immediately after the value they
        // describe: rtt -> srtt, loss -> loss, goodput -> gp. etx and lqi
        // carry no trend; jitter has no numeric column and is dropped. Each
        // tracked value reserves a fixed 1-char arrow slot (a space when
        // stable) so the columns stay aligned regardless of trend state.
        let label = Style::default().fg(Color::DarkGray);
        let srtt_arrow = trend_arrow(ll, "rtt_trend", true);
        let loss_arrow = trend_arrow(ll, "loss_trend", true);
        let gp_arrow = trend_arrow(ll, "goodput_trend", false);

        lines.push(Line::from(vec![
            Span::styled(
                format!("  {} ", helpers::truncate_name(name, 16)),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("srtt: ", label),
            Span::raw(format!("{srtt:<10}")),
            srtt_arrow,
            Span::styled(" loss: ", label),
            Span::raw(format!("{loss:<8}")),
            loss_arrow,
            Span::styled(" etx: ", label),
            Span::raw(format!("{etx:<6}")),
            Span::styled("lqi: ", label),
            Span::raw(format!("{lqi:<8}")),
            Span::styled("gp: ", label),
            Span::raw(goodput),
            gp_arrow,
        ]));
    }

    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

fn draw_session_mmp(
    frame: &mut Frame,
    data: &serde_json::Value,
    sort: SortState,
    scroll: u16,
    focused: bool,
    area: Rect,
) {
    let mut sessions = data
        .get("sessions")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let count = sessions.len();
    let block = helpers::pane_block(&format!(" Session MMP ({count} sessions) "), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if sessions.is_empty() {
        let msg = Paragraph::new("  No sessions").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    }

    sort_peers(&mut sessions, sort, "session_layer");

    let mut lines: Vec<Line> = vec![sort_header(MMP_SESSION_SORT_LABELS, sort)];
    lines.extend(sessions.iter().map(|s| {
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

        // Inline trend arrows mirror the Link MMP pane: srtt -> rtt_trend,
        // loss -> loss_trend, etx -> etx_trend, each with a fixed 1-char
        // slot (blank when stable) so the value columns stay aligned.
        let label = Style::default().fg(Color::DarkGray);
        let srtt_arrow = trend_arrow(sl, "rtt_trend", true);
        let loss_arrow = trend_arrow(sl, "loss_trend", true);
        let etx_arrow = trend_arrow(sl, "etx_trend", true);

        Line::from(vec![
            Span::styled(
                format!("  {} ", helpers::truncate_name(name, 16)),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("srtt: ", label),
            Span::raw(format!("{srtt:<10}")),
            srtt_arrow,
            Span::styled(" loss: ", label),
            Span::raw(format!("{loss:<8}")),
            loss_arrow,
            Span::styled(" etx: ", label),
            Span::raw(format!("{etx:<6}")),
            etx_arrow,
            Span::styled(" sqi: ", label),
            Span::raw(format!("{sqi:<8}")),
            Span::styled("mtu: ", label),
            Span::raw(mtu),
        ])
    }));

    let scroll = helpers::clamp_scroll(scroll, lines.len(), inner.height as usize);
    frame.render_widget(Paragraph::new(lines).scroll((scroll, 0)), inner);
}

/// Build the inline trend arrow span for a metric: a colored `↑`/`↓` for a
/// rising/falling trend, or a single blank space when stable or absent.
/// The slot is always one cell wide so value columns stay aligned. `layer`
/// is the `link_layer` / `session_layer` object carrying the `*_trend` key.
fn trend_arrow(layer: Option<&serde_json::Value>, key: &str, bad_rising: bool) -> Span<'static> {
    let trend = layer.and_then(|l| l.get(key)).and_then(|v| v.as_str());
    match trend {
        Some("rising") => Span::styled(
            "\u{2191}",
            Style::default().fg(trend_color("rising", bad_rising)),
        ),
        Some("falling") => Span::styled(
            "\u{2193}",
            Style::default().fg(trend_color("falling", bad_rising)),
        ),
        // Stable or no trend: a blank reserved slot.
        _ => Span::raw(" "),
    }
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
