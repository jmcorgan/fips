//! Graphs tab — stack of per-metric mini plots, btop-style.
//!
//! All node-level history metrics render as independent mini-graphs
//! stacked vertically: each has its own title line, its own
//! autoscaled min/max, and its own braille 2×4 filled-area plot
//! colored per-row on a green → yellow → red gradient. Content
//! scrolls with Up/Down; Left/Right cycles the (window, granularity)
//! pair which applies to the whole stack.
//!
//! Rendering follows btop's algorithm: 25-entry braille lookup table
//! `BRAILLE[left_level][right_level]` where each level is 0..=4, two
//! time samples per character cell, row-position-keyed gradient
//! coloring for the characteristic btop "vertical bands" look.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};

use crate::app::{App, GRAPHS_METRICS, GraphsMode, PEER_GRAPHS_METRICS, Tab};

/// 5×5 braille lookup table indexed by (left fill 0..=4, right fill
/// 0..=4). Direct transcription of btop's `braille_up` glyph set.
const BRAILLE: [[char; 5]; 5] = [
    [' ', '⢀', '⢠', '⢰', '⢸'],
    ['⡀', '⣀', '⣠', '⣰', '⣸'],
    ['⡄', '⣄', '⣤', '⣴', '⣼'],
    ['⡆', '⣆', '⣦', '⣶', '⣾'],
    ['⡇', '⣇', '⣧', '⣷', '⣿'],
];

/// Height in rows of each per-metric mini block (title row plus plot).
const METRIC_TITLE_ROWS: u16 = 1;
const METRIC_PLOT_ROWS: u16 = 4;
const METRIC_SEPARATOR_ROWS: u16 = 1;
const METRIC_BLOCK_ROWS: u16 = METRIC_TITLE_ROWS + METRIC_PLOT_ROWS + METRIC_SEPARATOR_ROWS;

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Length(2), // selector strip
        Constraint::Min(5),    // scrollable stack
    ])
    .split(area);

    draw_selector(frame, app, chunks[0]);
    draw_stack(frame, app, chunks[1]);
}

fn draw_selector(frame: &mut Frame, app: &App, area: Rect) {
    let label = Style::default().fg(Color::DarkGray);
    let dim = Style::default().fg(Color::White);
    let emph = Style::default().fg(Color::Cyan);

    let (window, granularity) = app.graphs_window();

    let mode_str = match app.graphs_mode {
        GraphsMode::Node => "node".to_string(),
        GraphsMode::MetricByPeer => {
            format!("metric-by-peer [{}]", app.graphs_selected_peer_metric())
        }
        GraphsMode::PeerByMetric => {
            let name = app
                .graphs_selected_peer()
                .map(|p| p.display_name.clone())
                .unwrap_or_else(|| "(no peers)".into());
            format!("peer-by-metric [{}]", name)
        }
    };

    let line1 = Line::from(vec![
        Span::styled("  mode: ", label),
        Span::styled(mode_str, emph),
        Span::styled("   window: ", label),
        Span::styled(window.to_string(), dim),
        Span::styled("   granularity: ", label),
        Span::styled(granularity.to_string(), dim),
        Span::styled("   scroll: ", label),
        Span::styled(format!("{}", app.graphs_scroll), dim),
    ]);
    let line2 = Line::from(Span::styled(
        "  [↑/↓] scroll   [←/→] window   [m] mode   [n/N] cycle   [g] graphs   [q] quit",
        label,
    ));

    frame.render_widget(Paragraph::new(vec![line1, line2]), area);
}

fn draw_stack(frame: &mut Frame, app: &mut App, area: Rect) {
    let title = match app.graphs_mode {
        GraphsMode::Node => " Graphs — Node ".to_string(),
        GraphsMode::MetricByPeer => {
            format!(" Graphs — {} by peer ", app.graphs_selected_peer_metric())
        }
        GraphsMode::PeerByMetric => {
            let name = app
                .graphs_selected_peer()
                .map(|p| p.display_name.clone())
                .unwrap_or_else(|| "(no peers)".into());
            format!(" Graphs — peer {} ", name)
        }
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    match app.graphs_mode {
        GraphsMode::Node | GraphsMode::PeerByMetric => draw_stacked(frame, app, inner),
        GraphsMode::MetricByPeer => draw_metric_by_peer(frame, app, inner),
    }
}

/// Parse `data.series` into `[(name, values)]` for stacked views.
fn series_from_data(data: &serde_json::Value) -> Vec<(String, Vec<f64>)> {
    data.get("series")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|s| {
                    let name = s
                        .get("metric")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let values: Vec<f64> = s
                        .get("values")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().map(|v| v.as_f64().unwrap_or(f64::NAN)).collect())
                        .unwrap_or_default();
                    (name, values)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn draw_stacked(frame: &mut Frame, app: &mut App, inner: Rect) {
    let data = app.data.get(&Tab::Graphs);
    let all_series = match data {
        Some(d) => series_from_data(d),
        None => Vec::new(),
    };

    if all_series.is_empty() {
        frame.render_widget(
            Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    // Pick metric list by mode.
    let metrics: &[&str] = match app.graphs_mode {
        GraphsMode::Node => GRAPHS_METRICS,
        GraphsMode::PeerByMetric => PEER_GRAPHS_METRICS,
        _ => unreachable!("draw_stacked only renders Node or PeerByMetric modes"),
    };

    let mut lines: Vec<Line<'static>> = Vec::new();
    for metric_name in metrics {
        let series = all_series
            .iter()
            .find(|(n, _)| n == metric_name)
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[]);
        lines.extend(render_metric_block(metric_name, series, inner.width));
    }

    let total_rows = lines.len() as u16;
    let visible = inner.height;
    let max_scroll = total_rows.saturating_sub(visible);
    if app.graphs_scroll > max_scroll {
        app.graphs_scroll = max_scroll;
    }

    let paragraph = Paragraph::new(lines).scroll((app.graphs_scroll, 0));
    frame.render_widget(paragraph, inner);
}

fn draw_metric_by_peer(frame: &mut Frame, app: &mut App, inner: Rect) {
    let data = match app.data.get(&Tab::Graphs) {
        Some(d) => d,
        None => {
            frame.render_widget(
                Paragraph::new("  Waiting for data...").style(Style::default().fg(Color::DarkGray)),
                inner,
            );
            return;
        }
    };

    let metric_name = app.graphs_selected_peer_metric();
    let peers = data.get("peers").and_then(|v| v.as_array());
    let peer_series: Vec<(String, Vec<f64>)> = peers
        .map(|arr| {
            arr.iter()
                .map(|p| {
                    let name = p
                        .get("display_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                        .to_string();
                    let values: Vec<f64> = p
                        .get("values")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().map(|v| v.as_f64().unwrap_or(f64::NAN)).collect())
                        .unwrap_or_default();
                    (name, values)
                })
                .collect()
        })
        .unwrap_or_default();

    if peer_series.is_empty() {
        frame.render_widget(
            Paragraph::new("  No peers tracked yet in stats history.")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    // Pick a column count that keeps each cell wide enough for a
    // readable braille plot. Each cell needs ~30 columns minimum.
    let cols = if inner.width < 40 {
        1
    } else if inner.width < 100 {
        2
    } else {
        3
    };
    let rows = peer_series.len().div_ceil(cols);

    // Stack of cell-rows; each row is a horizontal split of cell cells.
    let row_constraints: Vec<Constraint> = (0..rows)
        .map(|_| Constraint::Length(METRIC_BLOCK_ROWS))
        .collect();
    let row_areas = Layout::vertical(row_constraints).split(inner);

    for row_idx in 0..rows {
        let col_constraints: Vec<Constraint> = (0..cols)
            .map(|_| Constraint::Ratio(1, cols as u32))
            .collect();
        let col_areas = Layout::horizontal(col_constraints).split(row_areas[row_idx]);

        for col_idx in 0..cols {
            let peer_idx = row_idx * cols + col_idx;
            if peer_idx >= peer_series.len() {
                break;
            }
            let (peer_name, values) = &peer_series[peer_idx];
            let cell_lines = render_metric_block_labeled(
                metric_name,
                peer_name,
                values,
                col_areas[col_idx].width,
            );
            frame.render_widget(Paragraph::new(cell_lines), col_areas[col_idx]);
        }
    }
}

/// Variant of `render_metric_block` that labels the block with the
/// peer name in addition to the metric. Used by the metric-by-peer grid.
fn render_metric_block_labeled(
    metric: &str,
    peer_name: &str,
    values: &[f64],
    width: u16,
) -> Vec<Line<'static>> {
    let unit = metric_unit(metric);
    let mut out: Vec<Line<'static>> = Vec::with_capacity(METRIC_BLOCK_ROWS as usize);

    let (min, max, last, n) = summarize(values);
    let title_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let label = Style::default().fg(Color::DarkGray);
    let title = Line::from(vec![
        Span::styled(format!("  {peer_name}"), title_style),
        Span::styled(format!("  [{unit}]"), label),
        Span::styled("    max ", label),
        Span::raw(format_value(max)),
        Span::styled("   last ", label),
        Span::raw(format_value(last)),
        Span::styled("   n=", label),
        Span::raw(format!("{n}")),
    ]);
    out.push(title);

    let gutter = 2u16;
    let plot_cols = width.saturating_sub(gutter) as usize;

    if plot_cols == 0 || values.is_empty() {
        for _ in 0..METRIC_PLOT_ROWS {
            out.push(Line::from(Span::styled(
                "  (no samples)",
                Style::default().fg(Color::DarkGray),
            )));
        }
        out.push(Line::from(""));
        return out;
    }

    let sampled = resample(values, plot_cols * 2);
    let rows = METRIC_PLOT_ROWS as usize;
    let plot_lines = render_btop_graph(&sampled, rows, min, max, gutter as usize);
    out.extend(plot_lines);
    out.push(Line::from(""));
    out
}

/// Render a single metric's mini block: one title row, four plot rows,
/// one separator row. The plot is autoscaled against its own min/max
/// so every metric uses the full vertical resolution regardless of
/// its unit.
fn render_metric_block(metric: &str, values: &[f64], width: u16) -> Vec<Line<'static>> {
    let unit = metric_unit(metric);
    let mut out: Vec<Line<'static>> = Vec::with_capacity(METRIC_BLOCK_ROWS as usize);

    // Title row.
    let (min, max, last, n) = summarize(values);
    let title_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let label = Style::default().fg(Color::DarkGray);
    let title = Line::from(vec![
        Span::styled(format!("  {metric}"), title_style),
        Span::styled(format!("  [{unit}]"), label),
        Span::styled("    max ", label),
        Span::raw(format_value(max)),
        Span::styled("   last ", label),
        Span::raw(format_value(last)),
        Span::styled("   samples ", label),
        Span::raw(format!("{n}")),
    ]);
    out.push(title);

    // Plot rows. Width budget: leave the first two columns for a tiny
    // left gutter so titles and plots align consistently.
    let gutter = 2u16;
    let plot_cols = width.saturating_sub(gutter) as usize;

    if plot_cols == 0 || values.is_empty() {
        for _ in 0..METRIC_PLOT_ROWS {
            out.push(Line::from(Span::styled(
                "  (no samples)",
                Style::default().fg(Color::DarkGray),
            )));
        }
        out.push(Line::from(""));
        return out;
    }

    let sampled = resample(values, plot_cols * 2);
    let rows = METRIC_PLOT_ROWS as usize;
    let plot_lines = render_btop_graph(&sampled, rows, min, max, gutter as usize);
    out.extend(plot_lines);

    // Blank separator.
    out.push(Line::from(""));
    out
}

fn summarize(values: &[f64]) -> (f64, f64, f64, usize) {
    if values.is_empty() {
        return (0.0, 0.0, 0.0, 0);
    }
    let (min, max) = values
        .iter()
        .filter(|v| !v.is_nan())
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &v| {
            (lo.min(v), hi.max(v))
        });
    let (min, max) = if min.is_finite() {
        (min, max)
    } else {
        (0.0, 0.0)
    };
    let last = values
        .iter()
        .rev()
        .find(|v| !v.is_nan())
        .copied()
        .unwrap_or(f64::NAN);
    (min, max, last, values.len())
}

/// Down- or up-sample to exactly `target` points using linear
/// interpolation across the source index space. Returns empty on
/// empty input.
fn resample(values: &[f64], target: usize) -> Vec<f64> {
    if values.is_empty() || target == 0 {
        return Vec::new();
    }
    if values.len() == target {
        return values.to_vec();
    }
    if values.len() == 1 {
        return vec![values[0]; target];
    }
    let mut out = Vec::with_capacity(target);
    let last_src = (values.len() - 1) as f64;
    let last_dst = (target - 1).max(1) as f64;
    for i in 0..target {
        let src = i as f64 * last_src / last_dst;
        let lo = src.floor() as usize;
        let hi = (src.ceil() as usize).min(values.len() - 1);
        let frac = src - lo as f64;
        out.push(values[lo] * (1.0 - frac) + values[hi] * frac);
    }
    out
}

/// Render a filled-area graph using btop's braille algorithm.
///
/// - Normalize values to 0..=100 against the visible min/max.
/// - For each row `horizon` (0 = top), compute the percent band it
///   covers; each sample's fill level is 0..=4 based on where the
///   sample falls within that band (+0.1 modulus bias so small
///   non-zero values still draw).
/// - Two samples per character cell via the 25-entry BRAILLE table.
/// - Per-row gradient color keyed by row position: top rows hot, bottom
///   rows cool. This matches btop's "vertical color bands" look.
fn render_btop_graph(
    values: &[f64],
    rows: usize,
    min: f64,
    max: f64,
    gutter: usize,
) -> Vec<Line<'static>> {
    if rows == 0 || values.is_empty() {
        return Vec::new();
    }

    let range = max - min;
    // NaN samples pass through normalize as NaN so the cell loop below
    // can blank them. Non-NaN samples are clamped into 0..=100.
    let normalized: Vec<f64> = values
        .iter()
        .map(|&v| {
            if v.is_nan() {
                f64::NAN
            } else if !range.is_finite() || range <= 0.0 {
                50.0
            } else {
                ((v - min) / range * 100.0).clamp(0.0, 100.0)
            }
        })
        .collect();

    let clamp_min = 0i32;
    let mod_bias = 0.1f64;
    let gutter_str: String = " ".repeat(gutter);

    let mut lines: Vec<Line<'static>> = Vec::with_capacity(rows);

    for horizon in 0..rows {
        let cur_high = ((rows - horizon) as f64 * 100.0 / rows as f64).round() as i32;
        let cur_low = ((rows - horizon - 1) as f64 * 100.0 / rows as f64).round() as i32;
        let color = row_gradient(horizon, rows);
        let style = Style::default().fg(color);

        let mut chars = String::with_capacity(values.len() / 2 + 1);
        let mut i = 0;
        while i + 1 < normalized.len() {
            let l = normalized[i];
            let r = normalized[i + 1];
            let c = if l.is_nan() || r.is_nan() {
                ' '
            } else {
                let level_l = sample_level(l, cur_low, cur_high, clamp_min, mod_bias);
                let level_r = sample_level(r, cur_low, cur_high, clamp_min, mod_bias);
                BRAILLE[level_l as usize][level_r as usize]
            };
            chars.push(c);
            i += 2;
        }
        if i < normalized.len() {
            let l = normalized[i];
            let c = if l.is_nan() {
                ' '
            } else {
                let level_l = sample_level(l, cur_low, cur_high, clamp_min, mod_bias);
                BRAILLE[level_l as usize][0]
            };
            chars.push(c);
        }

        lines.push(Line::from(vec![
            Span::raw(gutter_str.clone()),
            Span::styled(chars, style),
        ]));
    }

    lines
}

fn sample_level(value: f64, cur_low: i32, cur_high: i32, clamp_min: i32, mod_bias: f64) -> i32 {
    let v = value.round() as i32;
    if v >= cur_high {
        4
    } else if v <= cur_low {
        clamp_min
    } else {
        let span = (cur_high - cur_low).max(1) as f64;
        let scaled = ((value - cur_low as f64) * 4.0 / span + mod_bias).round() as i32;
        scaled.clamp(clamp_min, 4)
    }
}

fn row_gradient(horizon: usize, rows: usize) -> Color {
    let t = 1.0 - (horizon as f64 / rows.max(1) as f64);
    gradient_rgb(t)
}

fn gradient_rgb(t: f64) -> Color {
    let t = t.clamp(0.0, 1.0);
    let (sr, sg, sb) = (0.0, 200.0, 0.0);
    let (mr, mg, mb) = (240.0, 200.0, 0.0);
    let (er, eg, eb) = (240.0, 40.0, 40.0);
    let (r, g, b) = if t < 0.5 {
        let k = t * 2.0;
        (lerp(sr, mr, k), lerp(sg, mg, k), lerp(sb, mb, k))
    } else {
        let k = (t - 0.5) * 2.0;
        (lerp(mr, er, k), lerp(mg, eg, k), lerp(mb, eb, k))
    };
    Color::Rgb(r as u8, g as u8, b as u8)
}

fn lerp(a: f64, b: f64, t: f64) -> f64 {
    a + (b - a) * t
}

fn format_value(v: f64) -> String {
    if v.is_nan() {
        return "-".to_string();
    }
    if v.abs() < 10.0 {
        format!("{:.2}", v)
    } else if v.abs() < 1000.0 {
        format!("{:.1}", v)
    } else if v.abs() < 1_000_000.0 {
        format!("{:.1}K", v / 1000.0)
    } else {
        format!("{:.1}M", v / 1_000_000.0)
    }
}

fn metric_unit(name: &str) -> &'static str {
    match name {
        "mesh_size" => "nodes",
        "tree_depth" => "hops",
        "peer_count" => "peers",
        "parent_switches" => "events/s",
        "bytes_in" | "bytes_out" => "bytes/s",
        "packets_in" | "packets_out" => "packets/s",
        "loss_rate" => "fraction",
        "active_sessions" => "sessions",
        "srtt_ms" => "ms",
        "ecn_ce" => "events/s",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resample_identity_when_length_matches() {
        let v = vec![1.0, 2.0, 3.0];
        assert_eq!(resample(&v, 3), v);
    }

    #[test]
    fn resample_returns_requested_length() {
        let v = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let out = resample(&v, 10);
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn braille_table_corners() {
        assert_eq!(BRAILLE[0][0], ' ');
        assert_eq!(BRAILLE[4][4], '⣿');
        assert_eq!(BRAILLE[4][0], '⡇');
        assert_eq!(BRAILLE[0][4], '⢸');
    }

    #[test]
    fn sample_level_boundaries() {
        assert_eq!(sample_level(0.0, 0, 25, 0, 0.1), 0);
        assert_eq!(sample_level(25.0, 0, 25, 0, 0.1), 4);
    }

    #[test]
    fn metric_block_has_expected_rows() {
        let v = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let lines = render_metric_block("mesh_size", &v, 40);
        assert_eq!(lines.len(), METRIC_BLOCK_ROWS as usize);
    }

    #[test]
    fn metric_block_handles_empty() {
        let lines = render_metric_block("mesh_size", &[], 40);
        assert_eq!(lines.len(), METRIC_BLOCK_ROWS as usize);
    }

    #[test]
    fn gradient_spans_stops() {
        if let Color::Rgb(r, g, _) = gradient_rgb(0.0) {
            assert!(g > r, "bottom of gradient is greener than it is red");
        } else {
            panic!("expected RGB");
        }
        if let Color::Rgb(r, g, _) = gradient_rgb(1.0) {
            assert!(r > g, "top of gradient is redder than it is green");
        } else {
            panic!("expected RGB");
        }
    }
}
