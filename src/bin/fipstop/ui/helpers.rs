use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use serde_json::Value;

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
pub fn nested_f64_prefer(data: &Value, outer: &str, preferred: &str, fallback: &str, decimals: usize) -> String {
    data.get(outer)
        .and_then(|o| o.get(preferred).or_else(|| o.get(fallback)))
        .and_then(|v| v.as_f64())
        .map(|n| format!("{:.prec$}", n, prec = decimals))
        .unwrap_or_else(|| "-".into())
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
        Span::styled(
            format!("    {key}: "),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(value.to_string()),
    ])
}

