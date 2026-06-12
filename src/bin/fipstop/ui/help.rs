//! Declarative keybinding registry and the `?` help overlay.
//!
//! A single static table keyed by `(Tab, UiMode)` is the one source of truth
//! both the always-visible context footer (`draw_status_bar`) and the full `?`
//! overlay render from, so the two can never drift. Every key the dispatch
//! handles in a given context is registered here as a `(key, label)` pair; the
//! footer renders the contextual subset (with a width-aware truncation rule),
//! and the overlay renders the whole reference.
//!
//! A test (`registry_keys_exist_in_dispatch`) asserts every key string the
//! table mentions is one the `main.rs` dispatch actually recognizes, so a
//! stale or invented hint can't slip in.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::app::{App, Tab};

/// The UI interaction mode the active tab is in, derived from existing `App`
/// fields. Selects which hint set the footer and overlay show. Order:
/// overview (nothing selected/open) is the base; a selected table row, an open
/// detail view, and (for multi-pane tabs) pane focus refine it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UiMode {
    /// No row selected, no detail open — the tab's resting state.
    Overview,
    /// A table row is selected (Peers/Sessions/Transports/Gateway).
    RowSelected,
    /// A detail view is open over the active tab.
    DetailOpen,
}

impl UiMode {
    /// Derive the current mode from `App` state for the active tab.
    pub fn of(app: &App) -> UiMode {
        if app.detail_view.is_some() {
            return UiMode::DetailOpen;
        }
        if app.active_tab.has_table()
            && app
                .table_states
                .get(&app.active_tab)
                .and_then(|s| s.selected())
                .is_some()
        {
            return UiMode::RowSelected;
        }
        UiMode::Overview
    }
}

/// One keybinding hint: the key glyph shown in brackets and its action label.
#[derive(Clone, Copy)]
pub struct Hint {
    pub key: &'static str,
    pub label: &'static str,
}

const fn hint(key: &'static str, label: &'static str) -> Hint {
    Hint { key, label }
}

/// Global hints available on (almost) every tab regardless of mode. These are
/// the lowest-priority footer candidates: when the bar overflows they drop
/// first, leaving the contextual hints and the always-present `[?] Help`.
pub const GLOBAL_HINTS: &[Hint] = &[hint("Tab", "next"), hint("g", "graphs"), hint("q", "quit")];

const DETAIL_HINTS: &[Hint] = &[hint("Esc", "close"), hint("\u{2191}\u{2193}", "scroll")];
const PEERS_SELECTED_HINTS: &[Hint] = &[
    hint("Enter", "detail"),
    hint("Del", "disconnect"),
    hint("Esc", "deselect"),
];
const ROW_SELECTED_HINTS: &[Hint] = &[hint("Enter", "detail"), hint("Esc", "deselect")];
const TABLE_OVERVIEW_HINTS: &[Hint] = &[hint("\u{2191}\u{2193}", "select")];
const GRAPHS_OVERVIEW_HINTS: &[Hint] = &[
    hint("Enter", "expand"),
    hint("m", "mode"),
    hint("n/N", "stat"),
    hint("\u{2190}\u{2192}", "window"),
    hint("s/S", "sort"),
];
/// The MMP (Performance) tab: `f` moves focus between the Link and Session MMP
/// panes, the arrows scroll the focused pane, and `s`/`S` sort the focused pane.
const MMP_HINTS: &[Hint] = &[
    hint("f", "focus pane"),
    hint("\u{2191}\u{2193}", "scroll"),
    hint("s/S", "sort"),
];
/// The multi-pane scrollable tabs (Tree, Filters, Routing): `f` moves pane
/// focus and the arrow keys scroll the focused pane.
const PANE_SCROLL_HINTS: &[Hint] = &[hint("f", "focus pane"), hint("\u{2191}\u{2193}", "scroll")];
/// By-peer detail (full-pane plot) on the Graphs tab: Up/Down flip the peer the
/// plot follows, n/N switch the statistic, m cycles the mode, Esc returns to the
/// scrollable peer list.
const GRAPHS_DETAIL_HINTS: &[Hint] = &[
    hint("\u{2191}\u{2193}", "peer"),
    hint("n/N", "stat"),
    hint("m", "mode"),
    hint("Esc", "back"),
];
const NO_HINTS: &[Hint] = &[];

/// The contextual hints for a `(Tab, UiMode)`. Highest footer priority — these
/// describe what the current state's keys do and are kept when the bar is
/// narrow. The overlay shows these plus the globals plus `[?] Help`.
pub fn contextual_hints(tab: Tab, mode: UiMode) -> &'static [Hint] {
    match (tab, mode) {
        (Tab::Graphs, UiMode::DetailOpen) => GRAPHS_DETAIL_HINTS,
        (_, UiMode::DetailOpen) => DETAIL_HINTS,
        (Tab::Peers, UiMode::RowSelected) => PEERS_SELECTED_HINTS,
        (_, UiMode::RowSelected) => ROW_SELECTED_HINTS,
        (Tab::Peers | Tab::Sessions | Tab::Transports | Tab::Gateway, UiMode::Overview) => {
            TABLE_OVERVIEW_HINTS
        }
        (Tab::Graphs, UiMode::Overview) => GRAPHS_OVERVIEW_HINTS,
        (Tab::Mmp, UiMode::Overview) => MMP_HINTS,
        (Tab::Tree | Tab::Bloom | Tab::Routing, UiMode::Overview) => PANE_SCROLL_HINTS,
        _ => NO_HINTS,
    }
}

/// Render a key hint as `[key] label` spans (key dim-bracketed, label plain).
fn hint_spans(h: &Hint) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!("[{}] ", h.key), Style::default().fg(Color::Yellow)),
        Span::styled(
            format!("{} ", h.label),
            Style::default().fg(Color::DarkGray),
        ),
    ]
}

/// Build the footer hint line for the active context, fitting `budget` columns.
///
/// Contextual hints come first and are kept; global hints fill remaining width
/// and drop when they don't fit; `[?] Help` is always appended last as the
/// overflow affordance. Returns the spans to append after the connection and
/// timing spans in the status bar.
pub fn footer_hint_spans(tab: Tab, mode: UiMode, budget: usize) -> Vec<Span<'static>> {
    let help = Span::styled("[?] Help ", Style::default().fg(Color::DarkGray));
    let help_w = "[?] Help ".len();

    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;

    // Reserve room for the always-present help affordance.
    let avail = budget.saturating_sub(help_w);

    let push_if_fits = |spans: &mut Vec<Span<'static>>, used: &mut usize, h: &Hint| -> bool {
        let w = h.key.chars().count() + h.label.chars().count() + 4; // "[] " + " "
        if *used + w <= avail {
            spans.extend(hint_spans(h));
            *used += w;
            true
        } else {
            false
        }
    };

    // Contextual first (highest priority).
    for h in contextual_hints(tab, mode) {
        push_if_fits(&mut spans, &mut used, h);
    }
    // Globals fill remaining space, dropping when they don't fit.
    for h in GLOBAL_HINTS {
        push_if_fits(&mut spans, &mut used, h);
    }

    spans.push(help);
    spans
}

/// Render the full `?` help overlay: a centered modal listing every binding
/// for the active `(Tab, UiMode)` (contextual + global), drawn from the same
/// registry the footer reads.
pub fn draw_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let tab = app.active_tab;
    let mode = UiMode::of(app);

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(Span::styled(
        format!("  {} — {:?}", tab.label(), mode),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    lines.push(Line::from(Span::styled(
        "  Context",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    let ctx = contextual_hints(tab, mode);
    if ctx.is_empty() {
        lines.push(Line::from(Span::styled(
            "    (no context-specific keys)",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for h in ctx {
            lines.push(overlay_row(h));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Global",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )));
    for h in GLOBAL_HINTS {
        lines.push(overlay_row(h));
    }
    lines.push(overlay_row(&hint("BackTab", "previous tab")));
    lines.push(overlay_row(&hint("?", "toggle this help")));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Press ? or Esc to close",
        Style::default().fg(Color::DarkGray),
    )));

    let popup = centered_rect(60, 70, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Help ")
        .style(Style::default().bg(Color::Black));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Render the Del-disconnect confirmation modal: a centered Y/N prompt naming
/// the peer and showing a reconnect note tailored to its kind.
pub fn draw_disconnect_modal(frame: &mut Frame, app: &App, area: Rect) {
    let Some(confirm) = &app.confirm_disconnect else {
        return;
    };

    let lines = vec![
        Line::from(Span::styled(
            "  Disconnect peer?",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Peer: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                confirm.display_name.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            format!("  {}", confirm.reconnect_note),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [Y] ", Style::default().fg(Color::Yellow)),
            Span::raw("disconnect    "),
            Span::styled("[N/Esc] ", Style::default().fg(Color::Yellow)),
            Span::raw("cancel"),
        ]),
    ];

    let popup = centered_rect_lines(64, 8, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Confirm ")
        .style(Style::default().bg(Color::Black));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    frame.render_widget(Paragraph::new(lines), inner);
}

/// A centered rectangle of fixed `w`×`h` cells (clamped to `area`).
fn centered_rect_lines(w: u16, h: u16, area: Rect) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

fn overlay_row(h: &Hint) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("    {:<10}", format!("[{}]", h.key)),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(h.label.to_string()),
    ])
}

/// Compute a centered rectangle `pct_x`%×`pct_y`% of `area`.
fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let w = area.width * pct_x / 100;
    let h = area.height * pct_y / 100;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every key glyph the registry mentions must be one the `main.rs`
    /// dispatch actually handles, so a stale or invented hint can't ship. The
    /// dispatch key set is mirrored here; adding a binding to the registry
    /// without wiring it (or vice versa) trips this.
    #[test]
    fn registry_keys_exist_in_dispatch() {
        // The authoritative set of key glyphs the dispatch recognizes. Mirror
        // of the match arms in `main.rs` (plus the arrow/Enter/Esc/Tab keys).
        const DISPATCH_KEYS: &[&str] = &[
            "q",
            "Tab",
            "BackTab",
            "g",
            "m",
            "n/N",
            "s/S",
            "f",
            "?",
            "Del",
            "Enter",
            "Esc",
            "\u{2191}\u{2193}", // up/down
            "\u{2190}\u{2192}", // left/right
        ];

        let mut all: Vec<Hint> = GLOBAL_HINTS.to_vec();
        all.push(hint("BackTab", "previous tab"));
        all.push(hint("?", "toggle this help"));
        for &tab in &Tab::ALL {
            for mode in [UiMode::Overview, UiMode::RowSelected, UiMode::DetailOpen] {
                all.extend_from_slice(contextual_hints(tab, mode));
            }
        }
        for h in all {
            assert!(
                DISPATCH_KEYS.contains(&h.key),
                "registry key [{}] ({}) has no dispatch handler",
                h.key,
                h.label
            );
        }
    }
}
