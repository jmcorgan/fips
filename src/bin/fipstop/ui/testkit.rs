//! Render-snapshot test harness for fipstop's `ui::draw_*` functions.
//!
//! Renders a draw function into an in-memory `ratatui` `TestBackend`
//! `Buffer` from a fixed area and canned JSON, then exposes the result as
//! a text grid plus per-cell style lookups. This makes layout, columns,
//! alignment, labels, grouping order, and per-cell colour machine-checkable
//! under `cargo test`, with no operator eyes.

#![cfg(test)]
// This is a test toolkit: some accessors (grid/find/fg_at) are consumed by
// snapshot cases added as render items land, so allow not-yet-used helpers.
#![allow(dead_code)]

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Color;

use crate::app::{App, Tab};

/// Build an `App` with `data` registered under `tab` and that tab active.
pub fn app_with(tab: Tab, data: serde_json::Value) -> App {
    let mut app = App::new(std::time::Duration::from_secs(2));
    app.active_tab = tab;
    app.connection_state = crate::app::ConnectionState::Connected;
    app.data.insert(tab, data);
    app
}

/// Render a draw closure into a `w`x`h` `TestBackend` and return the buffer.
pub fn render<F>(w: u16, h: u16, draw: F) -> Buffer
where
    F: FnOnce(&mut ratatui::Frame, Rect),
{
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| {
            let area = frame.area();
            draw(frame, area);
        })
        .expect("draw");
    terminal.backend().buffer().clone()
}

/// Dump a buffer as a vector of trimmed-right text rows.
pub fn lines(buf: &Buffer) -> Vec<String> {
    let w = buf.area.width as usize;
    let h = buf.area.height as usize;
    let mut out = Vec::with_capacity(h);
    for y in 0..h {
        let mut row = String::new();
        for x in 0..w {
            if let Some(cell) = buf.cell((x as u16, y as u16)) {
                row.push_str(cell.symbol());
            }
        }
        out.push(row.trim_end().to_string());
    }
    out
}

/// The full buffer as a single newline-joined string (for eyeball diffs).
pub fn grid(buf: &Buffer) -> String {
    lines(buf).join("\n")
}

/// Return true if any row, after trimming, contains `needle`.
pub fn contains_row(buf: &Buffer, needle: &str) -> bool {
    lines(buf).iter().any(|r| r.contains(needle))
}

/// Find the first (x, y) of `needle` in the rendered grid, if present.
///
/// The returned `x` is the cell column (not a byte offset), so it can be
/// used directly with `buf.cell`. `needle` is matched against the running
/// concatenation of cell symbols; the column reported is the cell at which
/// the match begins.
pub fn find(buf: &Buffer, needle: &str) -> Option<(u16, u16)> {
    let w = buf.area.width as usize;
    let h = buf.area.height as usize;
    for y in 0..h {
        // Per-cell symbols paired with their column, so a byte match maps
        // back to the originating cell column even with multibyte glyphs.
        let mut row = String::new();
        let mut starts: Vec<usize> = Vec::new();
        for x in 0..w {
            if let Some(cell) = buf.cell((x as u16, y as u16)) {
                starts.push(row.len());
                row.push_str(cell.symbol());
            }
        }
        if let Some(byte_off) = row.find(needle) {
            // Map the byte offset back to the cell column.
            let col = starts
                .iter()
                .position(|&s| s == byte_off)
                .unwrap_or(byte_off);
            return Some((col as u16, y as u16));
        }
    }
    None
}

/// Foreground colour of the cell at the first column where `needle` starts.
pub fn fg_at(buf: &Buffer, needle: &str) -> Option<Color> {
    let (x, y) = find(buf, needle)?;
    buf.cell((x, y)).map(|c| c.fg)
}
