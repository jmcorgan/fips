use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};

use crate::app::{App, SelectedTreeItem, Tab};

use super::helpers;

/// A single visible row in the tree view — either a transport or a nested link.
enum TreeRow {
    Transport {
        index: usize,
        transport_id: u64,
        link_count: usize,
    },
    Link {
        index: usize,
        is_last: bool,
    },
}

/// Below this width the table drops its byte counters and keeps its
/// identifying columns.
///
/// The full layout's fixed columns sum to 90, plus six single-column gaps —
/// 96 against the ~77 usable inside an 80-column terminal's border and
/// scrollbar. Ratatui resolves an over-subscribed layout by shrinking every
/// column, so the overflow does not clip the rightmost column, it clips *all*
/// of them: `mesh0 (optional)` becomes `mesh0 (optio`, losing the one marker
/// on the row worth reading.
const NARROW_TABLE_WIDTH: u16 = 100;

/// Below this width the detail view stacks above/below the table instead of
/// beside it.
const SIDE_BY_SIDE_MIN_WIDTH: u16 = 110;

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let transports = get_transports(app);
    let links = get_links(app);
    let tree_rows = build_tree_rows(&transports, &links, app);

    // Update app state for navigation
    app.tree_row_count = tree_rows.len();
    update_selected_tree_item(app, &tree_rows);

    if app.detail_view.is_some() {
        // Side by side only where the table half can still show its
        // identifying columns. At 80 columns — the OpenWrt serial console, and
        // the xterm/tmux default — a 40% split leaves the table 32 columns for
        // a layout that needs 65 even in its narrow form, and ratatui resolves
        // that by giving the trailing columns everything and rendering
        // Transport, Instance, Bound-to and State at width zero. Stacking
        // keeps both panes readable instead of keeping both unreadable.
        let chunks = if area.width < SIDE_BY_SIDE_MIN_WIDTH {
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area)
        } else {
            Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).split(area)
        };

        draw_table(frame, app, chunks[0], &transports, &links, &tree_rows);
        draw_detail(frame, app, chunks[1], &transports, &links, &tree_rows);
    } else {
        draw_table(frame, app, area, &transports, &links, &tree_rows);
    }
}

fn get_transports(app: &App) -> Vec<serde_json::Value> {
    app.data
        .get(&Tab::Transports)
        .and_then(|v| v.get("transports"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn get_links(app: &App) -> Vec<serde_json::Value> {
    app.data
        .get(&Tab::Links)
        .and_then(|v| v.get("links"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn build_tree_rows(
    transports: &[serde_json::Value],
    links: &[serde_json::Value],
    app: &App,
) -> Vec<TreeRow> {
    let mut rows = Vec::new();
    for (t_idx, transport) in transports.iter().enumerate() {
        let tid = transport
            .get("transport_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Gather links belonging to this transport
        let transport_links: Vec<(usize, &serde_json::Value)> = links
            .iter()
            .enumerate()
            .filter(|(_, l)| l.get("transport_id").and_then(|v| v.as_u64()) == Some(tid))
            .collect();

        rows.push(TreeRow::Transport {
            index: t_idx,
            transport_id: tid,
            link_count: transport_links.len(),
        });

        if app.expanded_transports.contains(&tid) {
            let last_idx = transport_links.len().saturating_sub(1);
            for (pos, (l_idx, _)) in transport_links.iter().enumerate() {
                rows.push(TreeRow::Link {
                    index: *l_idx,
                    is_last: pos == last_idx,
                });
            }
        }
    }
    rows
}

fn update_selected_tree_item(app: &mut App, tree_rows: &[TreeRow]) {
    let selected = app
        .table_states
        .get(&Tab::Transports)
        .and_then(|s| s.selected())
        .unwrap_or(0);

    app.selected_tree_item = match tree_rows.get(selected) {
        Some(TreeRow::Transport { transport_id, .. }) => SelectedTreeItem::Transport(*transport_id),
        Some(TreeRow::Link { .. }) => SelectedTreeItem::Link,
        None => SelectedTreeItem::None,
    };
}

/// Build a row, dropping the trailing byte counters in the narrow layout.
///
/// Both row shapes carry the same seven cells in the same order, so the
/// narrow variant is the same list with its tail cut — keeping one place
/// where the column count is decided, rather than two that must agree.
fn table_row<'a>(cells: Vec<Cell<'a>>, narrow: bool) -> Row<'a> {
    let mut cells = cells;
    if narrow {
        cells.truncate(5);
    }
    Row::new(cells)
}

fn draw_table(
    frame: &mut Frame,
    app: &mut App,
    area: Rect,
    transports: &[serde_json::Value],
    links: &[serde_json::Value],
    tree_rows: &[TreeRow],
) {
    // Tx/Rx are the first thing to go when width is short: they are the only
    // columns whose absence costs nothing an operator is scanning this table
    // to find, and the detail pane carries them in full.
    let narrow = area.width < NARROW_TABLE_WIDTH;

    let mut header_cells = vec![
        Cell::from("Transport / Link"),
        Cell::from("Instance"),
        Cell::from("Bound to"),
        Cell::from(Line::from("State").alignment(Alignment::Right)),
        Cell::from("Peer"),
        Cell::from("Tx"),
        Cell::from("Rx"),
    ];
    if narrow {
        header_cells.truncate(5);
    }
    let header = Row::new(header_cells).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = tree_rows
        .iter()
        .map(|tree_row| match tree_row {
            TreeRow::Transport {
                index,
                transport_id,
                link_count,
            } => {
                let t = &transports[*index];
                let indicator = if *link_count == 0 {
                    "  "
                } else if app.expanded_transports.contains(transport_id) {
                    "\u{25BC} " // ▼
                } else {
                    "\u{25B6} " // ▶
                };
                let typ = helpers::str_field(t, "type");
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let addr = t.get("local_addr").and_then(|v| v.as_str()).unwrap_or("");
                // An interface-bound transport is identified by the netdev it
                // names, not by its instance label: "ethernet lan" tells an
                // operator nothing, "ethernet lan br-lan" tells them where to
                // look. The presence marker is what makes the row honest —
                // `state` reads `up` from the moment the transport starts,
                // whether or not it is bound to anything.
                let iface = t.get("interface");
                let iface_name = iface
                    .and_then(|i| i.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let presence = iface
                    .and_then(|i| i.get("presence"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let policy = iface
                    .and_then(|i| i.get("policy"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Three cells, not one packed string. The instance name and
                // the thing the transport is bound to are separate facts about
                // separate columns of a table, and running them together left
                // the netdev names ragged down the list — the column an
                // operator scans to find the interface they are looking for.
                let label = if typ == "tor" {
                    let mode = t
                        .get("tor_mode")
                        .and_then(|v| v.as_str())
                        .unwrap_or("socks5");
                    format!("{indicator}tor({mode})")
                } else {
                    format!("{indicator}{typ}")
                };

                // What this transport is attached to: a netdev for the
                // interface-bound ones, the bound socket address for IP
                // transports, an onion for tor. Different answers, one
                // question, so one column.
                let bound_to = if !iface_name.is_empty() {
                    iface_name.to_string()
                } else if typ == "tor" {
                    t.get("onion_address")
                        .and_then(|v| v.as_str())
                        .map(|a| {
                            let short = if a.len() > 16 { &a[..16] } else { a };
                            format!("{short}..")
                        })
                        .unwrap_or_default()
                } else if !addr.is_empty() {
                    addr.to_string()
                } else {
                    format!("#{transport_id}")
                };

                // The State column carries presence for an interface-bound
                // transport, not the lifecycle state. `up` is true from the
                // moment the transport starts and stays true while its
                // interface is missing, so it is precisely the wrong answer in
                // the one case an operator is scanning this column for. There
                // is no room to show both, and only one of them is news.
                let state = if presence.is_empty() || presence == "present" {
                    helpers::str_field(t, "state")
                } else {
                    presence
                };
                let tx = t
                    .get("stats")
                    .and_then(|s| s.get("packets_sent").or_else(|| s.get("frames_sent")))
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into());
                let rx = t
                    .get("stats")
                    .and_then(|s| s.get("packets_recv").or_else(|| s.get("frames_recv")))
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into());

                // Colour follows bindability, not lifecycle: an absent
                // interface is the case the operator most needs to spot, and
                // it is precisely the one `state` cannot show. Severity then
                // follows the absence policy, because that is what the policy
                // means — a dock adapter that is not plugged in is a warning,
                // an interface the config says to expect is an error. Same
                // split the daemon makes between `Degraded` and silence.
                let row_style = match presence {
                    "" | "present" => Style::default().fg(Color::White),
                    "binding" => Style::default().fg(Color::Yellow),
                    _ if policy == "optional" => Style::default().fg(Color::Yellow),
                    _ => Style::default().fg(Color::Red),
                };

                // Policy rides with the instance name rather than owning a
                // column: `required` is the default and appears on nearly
                // every row, so a column of it is a column of noise. Only the
                // exception is worth printing, and its absence then means the
                // rule.
                let instance = match (name.is_empty(), policy == "optional") {
                    (true, true) => "(optional)".to_string(),
                    (true, false) => String::new(),
                    (false, true) => format!("{name} (optional)"),
                    (false, false) => name.to_string(),
                };

                table_row(
                    vec![
                        Cell::from(label),
                        Cell::from(instance),
                        Cell::from(bound_to),
                        Cell::from(Line::from(state.to_string()).alignment(Alignment::Right)),
                        Cell::from(""),
                        Cell::from(tx),
                        Cell::from(rx),
                    ],
                    narrow,
                )
                .style(row_style)
            }
            TreeRow::Link { index, is_last } => {
                let link = &links[*index];
                let tree_char = if *is_last {
                    "\u{2514}\u{2500}"
                } else {
                    "\u{251C}\u{2500}"
                }; // └─ or ├─
                let dir = helpers::str_field(link, "direction");
                let dir_short = match dir {
                    "Outbound" => "Out",
                    "Inbound" => "In",
                    other => other,
                };
                // Wide enough to render a full MAC (~17) or `hci0/MAC`
                // (~22) without chopping mid-octet; the link detail view
                // shows the untruncated address.
                // The remote address goes in `Bound to`, not in the label. A
                // link is bound to a remote endpoint exactly as a transport is
                // bound to a netdev or a socket — same question, same column —
                // and keeping a full MAC out of the first column is what lets
                // the three left columns sit against the left edge instead of
                // being pushed right by the widest link row.
                let addr = helpers::truncate_hex(helpers::str_field(link, "remote_addr"), 24);
                let label = format!("  {tree_char} {dir_short}");

                let state = helpers::str_field(link, "state");
                let peer_name = lookup_peer_for_link(app, link)
                    .map(|p| helpers::str_field(&p, "display_name").to_string())
                    .unwrap_or_default();

                table_row(
                    vec![
                        Cell::from(Span::styled(
                            label,
                            Style::default().fg(if dir == "Outbound" {
                                Color::Cyan
                            } else {
                                Color::Green
                            }),
                        )),
                        // A link has no instance name of its own — it inherits its
                        // parent transport's, shown one row up — and no absence
                        // policy, which is a property of an interface.
                        Cell::from(""),
                        Cell::from(addr),
                        Cell::from(Line::from(state.to_string()).alignment(Alignment::Right)),
                        Cell::from(peer_name),
                        Cell::from(""),
                        Cell::from(""),
                    ],
                    narrow,
                )
            }
        })
        .collect();

    let transport_count = transports.len();
    let link_count: usize = tree_rows
        .iter()
        .filter(|r| matches!(r, TreeRow::Link { .. }))
        .count();
    let title = if link_count > 0 {
        format!(" Transports ({transport_count}) Links ({link_count}) ")
    } else {
        format!(" Transports ({transport_count}) ")
    };

    // Every identifying column is fixed-width and packed against the left
    // edge; `Peer` takes the slack. The first column used to be `Min`, which
    // meant it absorbed all spare width and shoved Instance and Bound-to into
    // the middle of the terminal, away from the names an operator is scanning.
    //
    // It is sized for the widest label that lives in it — a link's
    // `  └─ Out` — rather than for a full MAC, because the address moved to
    // `Bound to` where it belongs. `Bound to` is sized for a MAC (17), which
    // also covers every netdev name and socket address that shares it.
    // Narrow: the same columns, sized down to what still reads. Instance keeps
    // 18 because `mesh0 (optional)` is 16 and the marker is the point; `Bound
    // to` keeps 17 because that is a full MAC.
    let widths: &[Constraint] = if narrow {
        &[
            Constraint::Length(12), // Transport / Link
            Constraint::Length(18), // Instance, plus "(optional)"
            Constraint::Length(17), // Bound to: a full MAC
            Constraint::Length(9),  // State, right-aligned
            Constraint::Min(6),     // Peer — takes the slack
        ]
    } else {
        &FULL_WIDTHS
    };

    const FULL_WIDTHS: [Constraint; 7] = [
        Constraint::Length(18), // Transport / Link
        Constraint::Length(20), // Instance, plus "(optional)" where it applies
        Constraint::Length(18), // Bound to: netdev, socket addr, onion, MAC
        // Wide enough for the longest value that lands here — `connected` (9)
        // and `binding` — because a right-aligned cell clips from the LEFT,
        // so an overflow reads as `onnected` rather than as a truncation.
        Constraint::Length(10), // State, right-aligned
        Constraint::Min(10),    // Peer — takes the slack
        Constraint::Length(7),  // Tx
        Constraint::Length(7),  // Rx
    ];

    let table = Table::new(rows, widths.to_vec())
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("\u{25B8} "); // ▸

    let row_count = tree_rows.len();
    let state = app.table_states.entry(Tab::Transports).or_default();
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

fn draw_detail(
    frame: &mut Frame,
    app: &App,
    area: Rect,
    transports: &[serde_json::Value],
    links: &[serde_json::Value],
    tree_rows: &[TreeRow],
) {
    let selected = app
        .table_states
        .get(&Tab::Transports)
        .and_then(|s| s.selected())
        .unwrap_or(0);

    let Some(tree_row) = tree_rows.get(selected) else {
        let block = Block::default().borders(Borders::ALL).title(" Detail ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let msg = Paragraph::new("  No item selected").style(Style::default().fg(Color::DarkGray));
        frame.render_widget(msg, inner);
        return;
    };

    match tree_row {
        TreeRow::Transport { index, .. } => {
            draw_transport_detail(frame, app, area, &transports[*index]);
        }
        TreeRow::Link { index, .. } => {
            draw_link_detail(frame, app, area, &links[*index]);
        }
    }
}

fn draw_transport_detail(frame: &mut Frame, app: &App, area: Rect, t: &serde_json::Value) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Transport Detail ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = vec![
        helpers::section_header("Transport Info"),
        helpers::kv_line("Transport ID", &helpers::u64_field(t, "transport_id")),
        helpers::kv_line("Type", helpers::str_field(t, "type")),
        helpers::kv_line("State", helpers::str_field(t, "state")),
        helpers::kv_line("MTU", &helpers::u64_field(t, "mtu")),
    ];

    if let Some(name) = t.get("name").and_then(|v| v.as_str()) {
        lines.push(helpers::kv_line("Name", name));
    }
    if let Some(addr) = t.get("local_addr").and_then(|v| v.as_str()) {
        lines.push(helpers::kv_line("Local Addr", addr));
    }

    // Interface presence, for the transports that are bound to a netdev.
    //
    // `State` above answers a lifecycle question — was this transport started
    // — and reads `up` for an interface that has never existed. That gap is
    // the whole reason interface binding is observable at all: the original
    // OpenWrt bug was expensive because the 802.11s link formed regardless, so
    // nothing an operator could see said the node was deaf. This is where they
    // see it.
    if let Some(iface) = t.get("interface") {
        lines.push(Line::from(""));
        lines.push(helpers::section_header("Interface"));
        lines.push(helpers::kv_line(
            "Interface",
            helpers::str_field(iface, "name"),
        ));

        let presence = helpers::str_field(iface, "presence");
        let since = iface
            .get("since_secs")
            .and_then(|v| v.as_u64())
            .map(|secs| helpers::format_duration_ms(secs.saturating_mul(1000)))
            .unwrap_or_else(|| "-".into());
        lines.push(helpers::kv_line(
            "Presence",
            &format!("{presence} for {since}"),
        ));

        // Carrier is reported, never acted on: presence is IFF_UP, so a bound
        // interface with no carrier is normal (a bridge with nothing plugged
        // into it) rather than a fault. Saying so beats an operator inferring
        // it from silence.
        let carrier = iface
            .get("carrier")
            .and_then(|v| v.as_bool())
            .map(|c| if c { "yes" } else { "no" })
            .unwrap_or("-");
        lines.push(helpers::kv_line("Carrier", carrier));

        // The list marks only the exception, `(optional)`, beside the
        // instance name. The detail pane has room to spell out both, as the
        // consequence rather than the config key: `optional` is a statement
        // about what absence *means*, and someone who has opened this pane
        // wants the meaning.
        let policy = helpers::str_field(iface, "policy");
        let absence = if policy == "optional" {
            "optional (absence is normal)"
        } else {
            "required (absence degrades the node)"
        };
        lines.push(helpers::kv_line("On absence", absence));

        // Binds past the first are rebinds, and a climbing failed-attempt
        // count is an interface that is there and refusing — a different
        // problem from one that is missing, and invisible without this.
        let binds = iface.get("binds").and_then(|v| v.as_u64()).unwrap_or(0);
        if binds > 1 {
            lines.push(helpers::kv_line("Binds", &format!("{binds} (rebound)")));
        } else {
            lines.push(helpers::kv_line("Binds", &binds.to_string()));
        }
        if let Some(failed) = iface.get("failed_attempts").and_then(|v| v.as_u64())
            && failed > 0
        {
            lines.push(helpers::kv_line("Failed binds", &failed.to_string()));
        }
    }

    // Tor-specific info
    if let Some(mode) = t.get("tor_mode").and_then(|v| v.as_str()) {
        lines.push(helpers::kv_line("Tor Mode", mode));
    }
    if let Some(onion) = t.get("onion_address").and_then(|v| v.as_str()) {
        lines.push(helpers::kv_line("Onion Address", onion));
    }

    // Transport stats
    if let Some(stats) = t.get("stats") {
        let typ = helpers::str_field(t, "type");
        lines.push(Line::from(""));
        lines.push(helpers::section_header("Traffic"));

        match typ {
            "ethernet" => {
                lines.push(helpers::kv_line(
                    "Frames Sent",
                    &helpers::nested_u64(t, "stats", "frames_sent"),
                ));
                lines.push(helpers::kv_line(
                    "Frames Recv",
                    &helpers::nested_u64(t, "stats", "frames_recv"),
                ));
            }
            _ => {
                lines.push(helpers::kv_line(
                    "Pkts Sent",
                    &helpers::nested_u64(t, "stats", "packets_sent"),
                ));
                lines.push(helpers::kv_line(
                    "Pkts Recv",
                    &helpers::nested_u64(t, "stats", "packets_recv"),
                ));
            }
        }

        let bytes_sent = stats
            .get("bytes_sent")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let bytes_recv = stats
            .get("bytes_recv")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        lines.push(helpers::kv_line(
            "Bytes Sent",
            &helpers::format_bytes(bytes_sent),
        ));
        lines.push(helpers::kv_line(
            "Bytes Recv",
            &helpers::format_bytes(bytes_recv),
        ));

        lines.push(Line::from(""));
        lines.push(helpers::section_header("Errors"));
        lines.push(helpers::kv_line(
            "Send Errors",
            &helpers::nested_u64(t, "stats", "send_errors"),
        ));
        lines.push(helpers::kv_line(
            "Recv Errors",
            &helpers::nested_u64(t, "stats", "recv_errors"),
        ));

        match typ {
            "udp" => {
                lines.push(helpers::kv_line(
                    "MTU Exceeded",
                    &helpers::nested_u64(t, "stats", "mtu_exceeded"),
                ));
                lines.push(helpers::kv_line(
                    "Kernel Drops",
                    &helpers::nested_u64(t, "stats", "kernel_drops"),
                ));
            }
            "tcp" => {
                lines.push(helpers::kv_line(
                    "MTU Exceeded",
                    &helpers::nested_u64(t, "stats", "mtu_exceeded"),
                ));
                lines.push(Line::from(""));
                lines.push(helpers::section_header("Connections"));
                lines.push(helpers::kv_line(
                    "Established",
                    &helpers::nested_u64(t, "stats", "connections_established"),
                ));
                lines.push(helpers::kv_line(
                    "Accepted",
                    &helpers::nested_u64(t, "stats", "connections_accepted"),
                ));
                lines.push(helpers::kv_line(
                    "Rejected",
                    &helpers::nested_u64(t, "stats", "connections_rejected"),
                ));
                lines.push(helpers::kv_line(
                    "Timeouts",
                    &helpers::nested_u64(t, "stats", "connect_timeouts"),
                ));
                lines.push(helpers::kv_line(
                    "Refused",
                    &helpers::nested_u64(t, "stats", "connect_refused"),
                ));
            }
            "tor" => {
                lines.push(helpers::kv_line(
                    "MTU Exceeded",
                    &helpers::nested_u64(t, "stats", "mtu_exceeded"),
                ));
                lines.push(helpers::kv_line(
                    "SOCKS5 Errors",
                    &helpers::nested_u64(t, "stats", "socks5_errors"),
                ));
                lines.push(helpers::kv_line(
                    "Control Errors",
                    &helpers::nested_u64(t, "stats", "control_errors"),
                ));
                lines.push(Line::from(""));
                lines.push(helpers::section_header("Connections"));
                lines.push(helpers::kv_line(
                    "Established",
                    &helpers::nested_u64(t, "stats", "connections_established"),
                ));
                lines.push(helpers::kv_line(
                    "Accepted",
                    &helpers::nested_u64(t, "stats", "connections_accepted"),
                ));
                lines.push(helpers::kv_line(
                    "Rejected",
                    &helpers::nested_u64(t, "stats", "connections_rejected"),
                ));
                lines.push(helpers::kv_line(
                    "Timeouts",
                    &helpers::nested_u64(t, "stats", "connect_timeouts"),
                ));
                lines.push(helpers::kv_line(
                    "Refused",
                    &helpers::nested_u64(t, "stats", "connect_refused"),
                ));
            }
            "nym" => {
                lines.push(helpers::kv_line(
                    "MTU Exceeded",
                    &helpers::nested_u64(t, "stats", "mtu_exceeded"),
                ));
                lines.push(helpers::kv_line(
                    "SOCKS5 Errors",
                    &helpers::nested_u64(t, "stats", "socks5_errors"),
                ));
                lines.push(Line::from(""));
                lines.push(helpers::section_header("Connections"));
                lines.push(helpers::kv_line(
                    "Established",
                    &helpers::nested_u64(t, "stats", "connections_established"),
                ));
                lines.push(helpers::kv_line(
                    "Timeouts",
                    &helpers::nested_u64(t, "stats", "connect_timeouts"),
                ));
            }
            "ethernet" => {
                lines.push(Line::from(""));
                lines.push(helpers::section_header("Beacons"));
                lines.push(helpers::kv_line(
                    "Beacons Sent",
                    &helpers::nested_u64(t, "stats", "beacons_sent"),
                ));
                lines.push(helpers::kv_line(
                    "Beacons Recv",
                    &helpers::nested_u64(t, "stats", "beacons_recv"),
                ));
                lines.push(Line::from(""));
                lines.push(helpers::section_header("Frame Errors"));
                lines.push(helpers::kv_line(
                    "Too Short",
                    &helpers::nested_u64(t, "stats", "frames_too_short"),
                ));
                lines.push(helpers::kv_line(
                    "Too Long",
                    &helpers::nested_u64(t, "stats", "frames_too_long"),
                ));
            }
            _ => {}
        }

        // Tor daemon monitoring (when control port data is available)
        if let Some(mon) = t.get("tor_monitoring") {
            lines.push(Line::from(""));
            lines.push(helpers::section_header("Tor Daemon"));
            lines.push(helpers::kv_line(
                "Bootstrap",
                &format!("{}%", helpers::nested_u64(t, "tor_monitoring", "bootstrap")),
            ));
            lines.push(helpers::kv_line(
                "Circuit",
                if mon
                    .get("circuit_established")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    "established"
                } else {
                    "none"
                },
            ));
            lines.push(helpers::kv_line(
                "Version",
                &helpers::nested_str(t, "tor_monitoring", "version"),
            ));
            lines.push(helpers::kv_line(
                "Network",
                &helpers::nested_str(t, "tor_monitoring", "network_liveness"),
            ));
            lines.push(helpers::kv_line(
                "Dormant",
                helpers::bool_field(mon, "dormant"),
            ));

            let tor_read = mon
                .get("traffic_read")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let tor_written = mon
                .get("traffic_written")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            lines.push(helpers::kv_line(
                "Tor Read",
                &helpers::format_bytes(tor_read),
            ));
            lines.push(helpers::kv_line(
                "Tor Written",
                &helpers::format_bytes(tor_written),
            ));
        }
    }

    let detail_scroll = app.detail_view.as_ref().map(|d| d.scroll).unwrap_or(0);
    let paragraph = Paragraph::new(lines).scroll((detail_scroll, 0));
    frame.render_widget(paragraph, inner);
}

fn draw_link_detail(frame: &mut Frame, app: &App, area: Rect, link: &serde_json::Value) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Link Detail ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = vec![
        helpers::section_header("Link Info"),
        helpers::kv_line("Link ID", &helpers::u64_field(link, "link_id")),
        helpers::kv_line("Direction", helpers::str_field(link, "direction")),
        helpers::kv_line("State", helpers::str_field(link, "state")),
        helpers::kv_line("Remote Addr", helpers::str_field(link, "remote_addr")),
        helpers::kv_line(
            "Created",
            &helpers::format_elapsed_ms(
                link.get("created_at_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ),
        Line::from(""),
    ];

    // Transport cross-reference
    if let Some(transport) = lookup_transport(app, link) {
        lines.push(helpers::section_header("Transport"));
        lines.push(helpers::kv_line(
            "Transport ID",
            &helpers::u64_field(link, "transport_id"),
        ));
        lines.push(helpers::kv_line(
            "Type",
            helpers::str_field(&transport, "type"),
        ));
        if let Some(name) = transport.get("name").and_then(|v| v.as_str()) {
            lines.push(helpers::kv_line("Name", name));
        }
        lines.push(helpers::kv_line(
            "MTU",
            &helpers::u64_field(&transport, "mtu"),
        ));
        if let Some(addr) = transport.get("local_addr").and_then(|v| v.as_str()) {
            lines.push(helpers::kv_line("Local Addr", addr));
        }
        lines.push(helpers::kv_line(
            "State",
            helpers::str_field(&transport, "state"),
        ));
        lines.push(Line::from(""));
    }

    // Peer cross-reference
    if let Some(peer) = lookup_peer_for_link(app, link) {
        lines.push(helpers::section_header("Peer"));
        lines.push(helpers::kv_line(
            "Name",
            helpers::str_field(&peer, "display_name"),
        ));
        lines.push(helpers::kv_line(
            "Connectivity",
            helpers::str_field(&peer, "connectivity"),
        ));
        lines.push(helpers::kv_line(
            "Last Seen",
            &helpers::format_elapsed_ms(
                peer.get("last_seen_ms")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ));
        lines.push(Line::from(""));
        lines.push(helpers::section_header("Peer Stats"));
        lines.push(helpers::kv_line(
            "Pkts Sent",
            &helpers::nested_u64(&peer, "stats", "packets_sent"),
        ));
        lines.push(helpers::kv_line(
            "Pkts Recv",
            &helpers::nested_u64(&peer, "stats", "packets_recv"),
        ));
        lines.push(helpers::kv_line(
            "Bytes Sent",
            &helpers::format_bytes(
                peer.get("stats")
                    .and_then(|s| s.get("bytes_sent"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ));
        lines.push(helpers::kv_line(
            "Bytes Recv",
            &helpers::format_bytes(
                peer.get("stats")
                    .and_then(|s| s.get("bytes_recv"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            ),
        ));
        if peer.get("mmp").is_some() {
            lines.push(Line::from(""));
            lines.push(helpers::section_header("MMP Metrics"));
            lines.push(helpers::kv_line(
                "SRTT",
                &format!("{}ms", helpers::nested_f64(&peer, "mmp", "srtt_ms", 1)),
            ));
            lines.push(helpers::kv_line(
                "Loss Rate",
                &helpers::nested_f64_prefer(&peer, "mmp", "smoothed_loss", "loss_rate", 4),
            ));
            lines.push(helpers::kv_line(
                "ETX",
                &helpers::nested_f64_prefer(&peer, "mmp", "smoothed_etx", "etx", 2),
            ));
            lines.push(helpers::kv_line(
                "LQI",
                &helpers::nested_f64(&peer, "mmp", "lqi", 2),
            ));
        }
    }

    let detail_scroll = app.detail_view.as_ref().map(|d| d.scroll).unwrap_or(0);
    let paragraph = Paragraph::new(lines).scroll((detail_scroll, 0));
    frame.render_widget(paragraph, inner);
}

/// Look up the peer associated with a link by matching link_id.
fn lookup_peer_for_link(app: &App, link: &serde_json::Value) -> Option<serde_json::Value> {
    let link_id = link.get("link_id").and_then(|v| v.as_u64())?;
    let peers = app.data.get(&Tab::Peers)?;
    peers
        .get("peers")?
        .as_array()?
        .iter()
        .find(|p| p.get("link_id").and_then(|v| v.as_u64()) == Some(link_id))
        .cloned()
}

fn lookup_transport(app: &App, link: &serde_json::Value) -> Option<serde_json::Value> {
    let transport_id = link.get("transport_id").and_then(|v| v.as_u64())?;
    let transports = app.data.get(&Tab::Transports)?;
    transports
        .get("transports")?
        .as_array()?
        .iter()
        .find(|t| t.get("transport_id").and_then(|v| v.as_u64()) == Some(transport_id))
        .cloned()
}
