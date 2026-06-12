use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders};
use serde_json::Value;

/// A bordered pane block with a title that highlights its border (cyan, bold
/// title) when `focused`, so the multi-pane focus model has a clear visual
/// indicator of which pane the scroll keys act on.
pub fn pane_block(title: &str, focused: bool) -> Block<'static> {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_string());
    if focused {
        block
            .border_style(Style::default().fg(Color::Cyan))
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
    } else {
        block
    }
}

/// Clamp a desired scroll offset to a pane's content so an over-scroll (e.g.
/// from End, which passes `u16::MAX`) rests at the last full screen rather than
/// scrolling past the content. `content_rows` is the total rendered line count
/// and `visible_rows` the pane's inner height.
pub fn clamp_scroll(offset: u16, content_rows: usize, visible_rows: usize) -> u16 {
    let max = content_rows.saturating_sub(visible_rows) as u16;
    offset.min(max)
}

/// Extract a string field from JSON, returning "-" if missing.
pub fn str_field<'a>(data: &'a Value, key: &str) -> &'a str {
    data.get(key).and_then(|v| v.as_str()).unwrap_or("-")
}

/// Extract a u64 field from JSON, returning "-" if missing.
pub fn u64_field(data: &Value, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".into())
}

/// Truncate a hex string to the given length, adding "..." if truncated.
pub fn truncate_hex(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Truncate a display name to a fixed visible width, appending an ellipsis when
/// it overflows, then pad to exactly `width` columns. Unlike a bare `{:<width}`
/// format this guarantees the field never exceeds `width`, so a long npub-style
/// name can't push past its column and butt against the next label. Counts and
/// pads by `char`, which is correct for the ASCII/BMP names the daemon emits.
pub fn truncate_name(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len <= width {
        format!("{s:<width$}")
    } else if width <= 1 {
        "\u{2026}".chars().take(width).collect()
    } else {
        let head: String = s.chars().take(width - 1).collect();
        format!("{head}\u{2026}")
    }
}

/// Format bytes-per-second with engineering units (B/s, KB/s, MB/s, GB/s) and 3 significant digits.
pub fn format_throughput(bytes_per_sec: f64) -> String {
    if bytes_per_sec < 0.0 {
        return "0 B/s".into();
    }
    let (scaled, unit) = if bytes_per_sec < 1_000.0 {
        (bytes_per_sec, "B/s")
    } else if bytes_per_sec < 1_000_000.0 {
        (bytes_per_sec / 1_000.0, "KB/s")
    } else if bytes_per_sec < 1_000_000_000.0 {
        (bytes_per_sec / 1_000_000.0, "MB/s")
    } else {
        (bytes_per_sec / 1_000_000_000.0, "GB/s")
    };
    let decimals = if scaled >= 100.0 {
        0
    } else if scaled >= 10.0 {
        1
    } else {
        2
    };
    format!("{:.prec$} {unit}", scaled, prec = decimals)
}

/// Extract a nested f64 field and format as engineering-unit throughput.
pub fn nested_throughput(data: &Value, outer: &str, inner: &str) -> String {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_f64())
        .map(format_throughput)
        .unwrap_or_else(|| "-".into())
}

/// Format a byte count as human-readable (B, KB, MB, GB).
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Format millisecond timestamp as relative duration from now (e.g., "3.2s ago").
pub fn format_elapsed_ms(ms: u64) -> String {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    if ms == 0 || ms > now_ms {
        return "-".into();
    }
    let elapsed = now_ms - ms;
    if elapsed < 1000 {
        format!("{elapsed}ms")
    } else if elapsed < 60_000 {
        format!("{:.1}s", elapsed as f64 / 1000.0)
    } else if elapsed < 3_600_000 {
        format!("{:.1}m", elapsed as f64 / 60_000.0)
    } else {
        format!("{:.1}h", elapsed as f64 / 3_600_000.0)
    }
}

/// Get a nested string field.
pub fn nested_str(data: &Value, outer: &str, inner: &str) -> String {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

/// Get a nested field value (e.g., "stats.packets_sent").
pub fn nested_u64(data: &Value, outer: &str, inner: &str) -> String {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_u64())
        .map(|n| n.to_string())
        .unwrap_or_else(|| "-".into())
}

/// Get a nested f64 field formatted to given decimal places.
pub fn nested_f64(data: &Value, outer: &str, inner: &str, decimals: usize) -> String {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_f64())
        .map(|n| format!("{:.prec$}", n, prec = decimals))
        .unwrap_or_else(|| "-".into())
}

/// Get a nested f64 field, preferring `preferred` key with fallback to `fallback` key.
pub fn nested_f64_prefer(
    data: &Value,
    outer: &str,
    preferred: &str,
    fallback: &str,
    decimals: usize,
) -> String {
    data.get(outer)
        .and_then(|o| o.get(preferred).or_else(|| o.get(fallback)))
        .and_then(|v| v.as_f64())
        .map(|n| format!("{:.prec$}", n, prec = decimals))
        .unwrap_or_else(|| "-".into())
}

/// Format an optional numeric field as a fixed-precision number, or an em-dash
/// placeholder when the value is JSON `null` or the key is absent. Used for
/// daemon-emitted `Option<f64>` fields (e.g. `effective_depth`) so an
/// unmeasured value renders distinctly from a real zero.
pub fn opt_f64_field(data: &Value, key: &str, decimals: usize) -> String {
    match data.get(key).and_then(|v| v.as_f64()) {
        Some(n) => format!("{:.prec$}", n, prec = decimals),
        None => "\u{2014}".into(),
    }
}

/// Extract a bool field from JSON, returning "yes"/"no" or "-" if missing.
pub fn bool_field(data: &Value, key: &str) -> &'static str {
    data.get(key)
        .and_then(|v| v.as_bool())
        .map(|b| if b { "yes" } else { "no" })
        .unwrap_or("-")
}

/// Format a duration in milliseconds as compact string (e.g., "42ms", "3.2s", "5.0m").
pub fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else {
        format!("{:.1}h", ms as f64 / 3_600_000.0)
    }
}

/// Section header line for detail views.
pub fn section_header(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("  {title}"),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ))
}

/// Key-value line for detail views.
pub fn kv_line(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("    {key}: "), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
}

/// Render a group of key-value pairs with the keys padded to a common
/// width so the values share a single left edge. Alignment is computed
/// once over the whole group rather than padded per call site, keeping
/// the convention (one aligned value column per stack) in one place.
pub fn kv_lines(pairs: &[(&str, String)]) -> Vec<Line<'static>> {
    let key_width = pairs.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    pairs
        .iter()
        .map(|(key, value)| {
            Line::from(vec![
                Span::styled(
                    format!("    {key:<key_width$}: "),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(value.clone()),
            ])
        })
        .collect()
}

/// Build a node-address -> (is_parent, is_child) map from the peers view's
/// `peers` array. Only the peers view carries the tree-role flags, so the Tree
/// and Bloom surfaces join their own peer lists against this map by node address
/// to recover each peer's role. A missing or malformed payload yields an empty
/// map (every peer then falls back to the Other group).
pub fn peer_role_map(
    peers_data: Option<&Value>,
) -> std::collections::HashMap<String, (bool, bool)> {
    let mut map = std::collections::HashMap::new();
    if let Some(arr) = peers_data
        .and_then(|d| d.get("peers"))
        .and_then(|v| v.as_array())
    {
        for p in arr {
            if let Some(addr) = p.get("node_addr").and_then(|v| v.as_str()) {
                let is_parent = p
                    .get("is_parent")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let is_child = p.get("is_child").and_then(|v| v.as_bool()).unwrap_or(false);
                map.insert(addr.to_string(), (is_parent, is_child));
            }
        }
    }
    map
}

/// Enrich a tree/bloom peer Value with `is_parent`/`is_child` looked up in the
/// peers role map by `addr_key` (the peer's node-address field, which differs
/// per surface: `node_addr` on Tree, `peer` on Bloom). A peer not found in the
/// map is left without role flags, so `group_rank` places it under Other.
pub fn enrich_role(
    mut peer: Value,
    role_map: &std::collections::HashMap<String, (bool, bool)>,
    addr_key: &str,
) -> Value {
    let addr = peer
        .get(addr_key)
        .and_then(|v| v.as_str())
        .map(String::from);
    if let Some(addr) = addr
        && let Some(&(is_parent, is_child)) = role_map.get(&addr)
        && let Some(obj) = peer.as_object_mut()
    {
        obj.insert("is_parent".into(), Value::Bool(is_parent));
        obj.insert("is_child".into(), Value::Bool(is_child));
    }
    peer
}

/// Tree-role group rank for a peer JSON object: parent first (0), then STP
/// children (1), then everything else (2). A node with no parent simply has
/// an empty group 0; a leaf with no children an empty group 1. Shared by the
/// Peers, Tree, and Bloom surfaces so they group peers identically.
pub fn group_rank(peer: &Value) -> u8 {
    let is_parent = peer
        .get("is_parent")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_child = peer
        .get("is_child")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if is_parent {
        0
    } else if is_child {
        1
    } else {
        2
    }
}

/// The section label for a tree-role group rank, matching the Peers tab's
/// box-drawing labels so all three surfaces read consistently.
pub fn group_label(rank: u8) -> &'static str {
    match rank {
        0 => "\u{2500}\u{2500} Parent \u{2500}\u{2500}",
        1 => "\u{2500}\u{2500} STP Children \u{2500}\u{2500}",
        _ => "\u{2500}\u{2500} Other \u{2500}\u{2500}",
    }
}

/// Stable-sort `peers` in place by tree-role group rank, preserving the input
/// order within each group. Callers that want a finer secondary key (e.g. LQI)
/// should sort by that key first, then call this for the group partition, or
/// supply their own comparator keyed off `group_rank`.
pub fn sort_by_group(peers: &mut [Value]) {
    peers.sort_by_key(group_rank);
}

/// Render a group of peers as `Paragraph` lines: a styled section label before
/// each non-empty group (in parent -> children -> other order), a blank
/// separator between groups, and each peer rendered by `render_peer`. Empty
/// groups are omitted (no label). `peers` is expected to already be grouped by
/// `group_rank` (callers sort first). This is the Paragraph-of-Lines analogue
/// of the Peers tab's grouped table, shared by the Tree and Bloom peer lists.
pub fn grouped_peer_lines<F>(peers: &[Value], render_peer: F) -> Vec<Line<'static>>
where
    F: Fn(&Value) -> Line<'static>,
{
    let label_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut last_group: Option<u8> = None;
    for peer in peers {
        let g = group_rank(peer);
        if last_group != Some(g) {
            if last_group.is_some() {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                format!("  {}", group_label(g)),
                label_style,
            )));
            last_group = Some(g);
        }
        lines.push(render_peer(peer));
    }
    lines
}

/// Render a sequence of values as Unicode block characters.
///
/// Returns an empty string for empty input. Constant series render as a
/// mid-level row. Used inline beside metric values in the dashboard and
/// as the per-column renderer for the Graphs tab.
pub fn sparkline(values: &[f64]) -> String {
    const BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if values.is_empty() {
        return String::new();
    }
    let (min, max) = values
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &v| {
            (lo.min(v), hi.max(v))
        });
    let range = max - min;
    values
        .iter()
        .map(|&v| {
            if !range.is_finite() || range <= 0.0 {
                BLOCKS[3]
            } else {
                let norm = ((v - min) / range).clamp(0.0, 1.0);
                let idx = (norm * (BLOCKS.len() as f64 - 1.0)).round() as usize;
                BLOCKS[idx.min(BLOCKS.len() - 1)]
            }
        })
        .collect()
}

/// Extract a `Vec<f64>` from a nested JSON array (e.g., `sparklines.mesh_size`).
pub fn nested_f64_array(data: &Value, outer: &str, inner: &str) -> Vec<f64> {
    data.get(outer)
        .and_then(|o| o.get(inner))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_f64()).collect())
        .unwrap_or_default()
}
