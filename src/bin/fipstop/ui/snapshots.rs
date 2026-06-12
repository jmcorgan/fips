//! Render snapshots for the `ui::draw_*` functions the TUI overhaul touches.
//!
//! Each test renders a draw function into a fixed-size `TestBackend` from a
//! canned `show_*` payload (the inner `data` object the control client hands
//! `App`) and asserts on the resulting text grid plus, for colour-bearing
//! items, per-cell style. These double as regression tests; when a render
//! item lands, its snapshot asserts the new structure here.

#![cfg(test)]

use serde_json::json;

use super::testkit::{self, app_with};
use crate::app::Tab;

/// Baseline harness check: the Bloom tab renders its three pane titles and
/// the peer-filter rows from canned data.
#[test]
fn bloom_panes_render() {
    let data = json!({
        "is_leaf_only": false,
        "leaf_dependent_count": 3,
        "own_node_addr": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "sequence": 42,
        "peer_filters": [
            {
                "display_name": "alice",
                "filter_sequence": 50677047u64,
                "has_filter": true,
                "fill_ratio": 0.139,
                "estimated_count": 1182.0
            },
            {
                "display_name": "bob",
                "filter_sequence": 7u64,
                "has_filter": false
            }
        ],
        "stats": {
            "received": 1, "accepted": 1, "decode_error": 0, "invalid": 0,
            "non_v1": 0, "unknown_peer": 0, "stale": 0,
            "sent": 5, "debounce_suppressed": 0, "send_failed": 0
        }
    });
    let app = app_with(Tab::Bloom, data);
    let buf = testkit::render(80, 30, |frame, area| {
        super::bloom::draw(frame, &app, area);
    });

    assert!(testkit::contains_row(&buf, "Bloom Filter State"));
    assert!(testkit::contains_row(&buf, "Bloom Announce Stats"));
    assert!(testkit::contains_row(&buf, "Peer Filters (2)"));
    assert!(testkit::contains_row(&buf, "alice"));
    assert!(testkit::contains_row(&buf, "bob"));
}

/// Peer Filters: the right-justified seq field keeps a separator before
/// `fill:` even for a long sequence, and the `fill:`/`est:` labels start at
/// the same column across rows so the numeric columns align.
#[test]
fn bloom_peer_filters_alignment() {
    let data = json!({
        "is_leaf_only": false,
        "leaf_dependent_count": 0,
        "own_node_addr": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "sequence": 0,
        "peer_filters": [
            {
                "display_name": "alice",
                "filter_sequence": 50677047u64,
                "has_filter": true,
                "fill_ratio": 0.139,
                "estimated_count": 1182.0
            },
            {
                "display_name": "bob",
                "filter_sequence": 7u64,
                "has_filter": true,
                "fill_ratio": 0.5,
                "estimated_count": 12.0
            }
        ],
        "stats": {
            "received": 0, "accepted": 0, "decode_error": 0, "invalid": 0,
            "non_v1": 0, "unknown_peer": 0, "stale": 0,
            "sent": 0, "debounce_suppressed": 0, "send_failed": 0
        }
    });
    let app = app_with(Tab::Bloom, data);
    let buf = testkit::render(90, 30, |frame, area| {
        super::bloom::draw(frame, &app, area);
    });

    // Long seq never butts against the fill label.
    assert!(!testkit::contains_row(&buf, "50677047fill"));
    // The fill: label starts at the same column on both peer rows (the
    // rows are ASCII so byte offset equals cell column here).
    let alice_row = testkit::find(&buf, "alice").map(|(_, y)| y).unwrap();
    let bob_row = testkit::find(&buf, "bob").map(|(_, y)| y).unwrap();
    let cols: Vec<usize> = testkit::lines(&buf)
        .iter()
        .enumerate()
        .filter_map(|(y, r)| {
            if y as u16 == alice_row || y as u16 == bob_row {
                r.find("fill:")
            } else {
                None
            }
        })
        .collect();
    assert_eq!(cols.len(), 2, "both peer rows show a fill: label");
    assert_eq!(cols[0], cols[1], "fill: columns align across rows");
}

/// Peers group-sort: the comparator orders parent before STP children
/// before other peers, regardless of LQI, while preserving within-group
/// LQI order.
#[test]
fn peers_group_sort_order() {
    // Deliberately list out-of-order: an "other" peer with the best LQI
    // first, then the parent, then a child. The group sort must reorder.
    let data = json!({
        "peers": [
            { "display_name": "zeta_other", "npub": "npub1other", "is_parent": false, "is_child": false, "mmp": { "lqi": 1.0 } },
            { "display_name": "papa_parent", "npub": "npub1parent", "is_parent": true, "is_child": false, "mmp": { "lqi": 9.0 } },
            { "display_name": "kidd_child", "npub": "npub1child", "is_parent": false, "is_child": true, "mmp": { "lqi": 5.0 } }
        ]
    });
    let mut app = app_with(Tab::Peers, data);
    let buf = testkit::render(120, 20, |frame, area| {
        super::peers::draw(frame, &mut app, area);
    });

    let y_parent = testkit::find(&buf, "papa_parent").map(|(_, y)| y).unwrap();
    let y_child = testkit::find(&buf, "kidd_child").map(|(_, y)| y).unwrap();
    let y_other = testkit::find(&buf, "zeta_other").map(|(_, y)| y).unwrap();
    assert!(y_parent < y_child, "parent renders above child");
    assert!(y_child < y_other, "child renders above other");
}

/// Peers grouped view: styled group labels precede each non-empty group, the
/// groups are ordered parent -> children -> other, and a selected peer's row
/// is highlighted (the cursor never sits on a label or blank row).
#[test]
fn peers_grouped_view_labels_and_cursor() {
    use ratatui::widgets::TableState;
    let data = json!({
        "peers": [
            { "display_name": "zeta_other", "npub": "npub1o", "is_parent": false, "is_child": false, "mmp": { "lqi": 1.0 } },
            { "display_name": "papa_parent", "npub": "npub1p", "is_parent": true, "is_child": false, "mmp": { "lqi": 9.0 } },
            { "display_name": "kidd_child", "npub": "npub1c", "is_parent": false, "is_child": true, "mmp": { "lqi": 5.0 } }
        ]
    });
    let mut app = app_with(Tab::Peers, data);
    // Select peer index 0 (papa, the parent — first in grouped order).
    let mut st = TableState::default();
    st.select(Some(0));
    app.table_states.insert(Tab::Peers, st);
    let buf = testkit::render(140, 24, |frame, area| {
        super::peers::draw(frame, &mut app, area);
    });

    // Group labels render and are ordered.
    let y_parent_lbl = testkit::find(&buf, "Parent").map(|(_, y)| y).unwrap();
    let y_children_lbl = testkit::find(&buf, "STP Children").map(|(_, y)| y).unwrap();
    let y_other_lbl = testkit::find(&buf, "Other").map(|(_, y)| y).unwrap();
    assert!(y_parent_lbl < y_children_lbl, "Parent label above Children");
    assert!(y_children_lbl < y_other_lbl, "Children label above Other");

    // The selected peer (papa) is highlighted with the cursor symbol on its
    // row, not on a label.
    let cursor_row = testkit::find(&buf, "\u{25b6}").map(|(_, y)| y);
    let papa_row = testkit::find(&buf, "papa_parent").map(|(_, y)| y);
    assert_eq!(cursor_row, papa_row, "cursor sits on the selected peer row");
}

/// Link MMP: trend arrows render inline after the value (rising srtt is a
/// red up-arrow), there is no separate trend line, and a stable metric
/// leaves a blank slot rather than a glyph.
#[test]
fn mmp_link_trend_arrows() {
    use ratatui::style::Color;
    let data = json!({
        "peers": [
            {
                "display_name": "alice",
                "link_layer": {
                    "srtt_ms": 42.0,
                    "smoothed_loss": 0.01,
                    "smoothed_etx": 1.2,
                    "lqi": 3.4,
                    "goodput_bps": 1000.0,
                    "rtt_trend": "rising",
                    "loss_trend": "stable",
                    "goodput_trend": "falling",
                    "jitter_trend": "rising"
                }
            }
        ],
        "sessions": []
    });
    let app = app_with(Tab::Mmp, data);
    let buf = testkit::render(120, 20, |frame, area| {
        super::mmp::draw(frame, &app, area);
    });

    // No separate "rtt:"/"jitter:" trend line survives.
    assert!(!testkit::contains_row(&buf, "jitter:"));
    // A rising srtt (bad) shows a red up-arrow somewhere on the row.
    assert_eq!(testkit::fg_at(&buf, "\u{2191}"), Some(Color::Red));
    // A falling goodput (bad) shows a red down-arrow.
    assert_eq!(testkit::fg_at(&buf, "\u{2193}"), Some(Color::Red));
}

/// MMP peer names: a full-length npub used as the display name (no friendly
/// name) is truncated to its fixed column with an ellipsis, so it never butts
/// against the following `srtt:` label, in both the Link and Session panes.
#[test]
fn mmp_long_peer_name_truncated() {
    let npub = "npub1sx42mj99aql52aklsg70y2jmr95u7uz2p40k769aw46ppjv302kqkhmu5r";
    let data = json!({
        "peers": [
            {
                "display_name": npub,
                "link_layer": { "srtt_ms": 42.0, "lqi": 3.4 }
            }
        ],
        "sessions": [
            {
                "display_name": npub,
                "session_layer": { "srtt_ms": 42.0, "sqi": 3.4, "path_mtu": 1280 }
            }
        ]
    });
    let app = app_with(Tab::Mmp, data);
    let buf = testkit::render(120, 24, |frame, area| {
        super::mmp::draw(frame, &app, area);
    });

    // The full npub must not appear (it is truncated with an ellipsis).
    assert!(!testkit::contains_row(&buf, npub));
    // A truncated name carries the ellipsis glyph.
    assert!(
        testkit::find(&buf, "\u{2026}").is_some(),
        "name is truncated"
    );
    // The truncated name never runs directly into the srtt label: the npub
    // prefix is not immediately followed by "srtt:".
    assert!(
        !testkit::contains_row(&buf, "\u{2026}srtt:"),
        "truncated name keeps a separator before srtt:"
    );
    // Both panes still render the srtt label for the peer.
    assert!(testkit::contains_row(&buf, "srtt:"));
}

/// Dashboard Identity panel surfaces effective persistence as
/// persistent/ephemeral.
#[test]
fn dashboard_identity_persistence() {
    let base = json!({
        "version": "v", "npub": "npub1abc", "node_addr": "00112233",
        "ipv6_addr": "fd00::1", "state": "Running", "is_leaf_only": false,
        "peer_count": 0, "session_count": 0, "link_count": 0,
        "transport_count": 0, "connection_count": 0, "tun_state": "Up",
        "tun_name": "fips0", "effective_ipv6_mtu": 1280, "control_socket": "/x",
        "pid": 1, "exe_path": "/x", "uptime_secs": 1, "estimated_mesh_size": 1,
        "forwarding": {}, "sparklines": {},
        "persistent": true
    });
    let app = app_with(Tab::Node, base);
    let buf = testkit::render(100, 40, |frame, area| {
        super::dashboard::draw(frame, &app, area);
    });
    assert!(testkit::contains_row(&buf, "identity:"));
    assert!(testkit::contains_row(&buf, "persistent"));
}

/// Build a Dashboard `show_status` payload with the given root fields.
fn dashboard_status(extra: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "version": "v", "npub": "npub1abc", "node_addr": "00112233",
        "ipv6_addr": "fd00::1", "state": "Running", "is_leaf_only": false,
        "peer_count": 0, "session_count": 0, "link_count": 0,
        "transport_count": 0, "connection_count": 0, "tun_state": "Up",
        "tun_name": "fips0", "effective_ipv6_mtu": 1280, "control_socket": "/x",
        "pid": 1, "exe_path": "/x", "uptime_secs": 1, "estimated_mesh_size": 1,
        "forwarding": {}, "sparklines": {}, "persistent": true
    });
    let obj = base.as_object_mut().unwrap();
    for (k, v) in extra.as_object().unwrap() {
        obj.insert(k.clone(), v.clone());
    }
    base
}

/// Dashboard State panel: when this node is root, the root line shows the
/// Easter-egg marker rather than an address.
#[test]
fn dashboard_root_egg_when_root() {
    let data = dashboard_status(json!({
        "is_root": true,
        "root": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "transport_peer_counts": { "udp": 5, "tcp": 2, "tor": 0 }
    }));
    let app = app_with(Tab::Node, data);
    let buf = testkit::render(100, 40, |frame, area| {
        super::dashboard::draw(frame, &app, area);
    });
    assert!(testkit::contains_row(&buf, "I am the one who roots"));
    // Transports enumerated by type with per-type peer counts, sorted.
    assert!(testkit::contains_row(&buf, "tcp (2)"));
    assert!(testkit::contains_row(&buf, "udp (5)"));
    assert!(testkit::contains_row(&buf, "tor (0)"));
}

/// Dashboard State panel: the mesh size renders under the
/// "approx. mesh estimate:" label, making clear it is a bloom-cardinality
/// estimate rather than an exact count.
#[test]
fn dashboard_mesh_estimate_label() {
    let data = dashboard_status(json!({
        "is_root": false,
        "root": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "estimated_mesh_size": 17,
        "transport_peer_counts": { "udp": 1 }
    }));
    let app = app_with(Tab::Node, data);
    // Render at 80 columns to confirm the label fits on its own line.
    let buf = testkit::render(80, 40, |frame, area| {
        super::dashboard::draw(frame, &app, area);
    });
    assert!(testkit::contains_row(&buf, "approx. mesh estimate:"));
    // The estimate value renders alongside the label.
    let row = testkit::lines(&buf)
        .into_iter()
        .find(|r| r.contains("approx. mesh estimate:"))
        .unwrap();
    assert!(
        row.contains("~17"),
        "mesh estimate value on its line: {row}"
    );
}

/// Dashboard State panel: when not root, the root line shows a truncated hex
/// (16 chars + ellipsis), not the egg.
#[test]
fn dashboard_root_truncated_when_not_root() {
    let data = dashboard_status(json!({
        "is_root": false,
        "root": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "transport_peer_counts": { "udp": 1 }
    }));
    let app = app_with(Tab::Node, data);
    let buf = testkit::render(100, 40, |frame, area| {
        super::dashboard::draw(frame, &app, area);
    });
    assert!(!testkit::contains_row(&buf, "I am the one who roots"));
    assert!(testkit::contains_row(&buf, "1b4788b7ab7a436a\u{2026}"));
}

/// Tree Position: full (un-truncated) root hex plus an `Npub:` line; when the
/// daemon can't resolve the root npub the slot reads `<unknown>`.
#[test]
fn tree_full_root_and_npub() {
    let data = json!({
        "root": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "root_npub": "npub1sx42mj99aql52aklsg70y2jmr95u7uz2p40k769aw46ppjv302kqkhmu5r",
        "is_root": true,
        "depth": 0,
        "parent_display_name": "self",
        "declaration_sequence": 1,
        "declaration_signed": true,
        "my_coords": [],
        "peers": [],
        "stats": {}
    });
    let app = app_with(Tab::Tree, data);
    let buf = testkit::render(100, 40, |frame, area| {
        super::tree::draw(frame, &app, area);
    });
    // Full 32-char hex appears (with the self marker), not the 16-char form.
    assert!(testkit::contains_row(
        &buf,
        "1b4788b7ab7a436a611fc59fb1e34c6e (self)"
    ));
    assert!(testkit::contains_row(&buf, "npub1sx42mj99aql52"));
}

/// Tree Position: a null root_npub renders the `<unknown>` placeholder.
#[test]
fn tree_root_npub_unknown() {
    let data = json!({
        "root": "aabbccddeeff00112233445566778899",
        "root_npub": serde_json::Value::Null,
        "is_root": false,
        "depth": 2,
        "parent_display_name": "alice",
        "declaration_sequence": 7,
        "declaration_signed": true,
        "my_coords": [],
        "peers": [],
        "stats": {}
    });
    let app = app_with(Tab::Tree, data);
    let buf = testkit::render(100, 40, |frame, area| {
        super::tree::draw(frame, &app, area);
    });
    assert!(testkit::contains_row(&buf, "<unknown>"));
}

/// Tree peers line: the daemon-computed effective_depth (read back from the
/// Peers tab by node_addr) appears after `dist:`, and an unmeasured peer shows
/// an em-dash rather than a misleading number.
#[test]
fn tree_peer_effective_depth() {
    let tree = json!({
        "root": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "root_npub": serde_json::Value::Null,
        "is_root": false,
        "depth": 1,
        "parent_display_name": "alice",
        "declaration_sequence": 1,
        "declaration_signed": true,
        "my_coords": [],
        "peers": [
            {
                "display_name": "alice",
                "node_addr": "aa00",
                "depth": 0,
                "distance_to_us": 1,
                "root": "1b4788b7ab7a436a611fc59fb1e34c6e"
            },
            {
                "display_name": "bob",
                "node_addr": "bb00",
                "depth": 2,
                "distance_to_us": 3,
                "root": "1b4788b7ab7a436a611fc59fb1e34c6e"
            }
        ],
        "stats": {}
    });
    let peers = json!({
        "peers": [
            { "node_addr": "aa00", "display_name": "alice", "effective_depth": 1.25 },
            { "node_addr": "bb00", "display_name": "bob", "effective_depth": serde_json::Value::Null }
        ]
    });
    let mut app = app_with(Tab::Tree, tree);
    app.data.insert(Tab::Peers, peers);
    let buf = testkit::render(120, 40, |frame, area| {
        super::tree::draw(frame, &app, area);
    });
    assert!(testkit::contains_row(&buf, "eff: 1.25"));
    // bob's effective_depth is null -> em-dash.
    let bob_row = testkit::lines(&buf)
        .into_iter()
        .find(|r| r.contains("bob"))
        .unwrap();
    assert!(
        bob_row.contains("eff: \u{2014}"),
        "bob shows eff em-dash: {bob_row}"
    );
}

/// Tree Peers list groups by tree role with the same section labels as the
/// Peers tab (parent -> STP children -> other), ordered, and omits a label for
/// an empty group (here there is no parent among the tree peers).
#[test]
fn tree_peers_grouped_by_role() {
    let tree = json!({
        "root": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "root_npub": serde_json::Value::Null,
        "is_root": false,
        "depth": 1,
        "parent_display_name": "alice",
        "declaration_sequence": 1,
        "declaration_signed": true,
        "my_coords": [],
        "peers": [
            { "display_name": "other_peer", "node_addr": "cc00", "depth": 3, "distance_to_us": 4, "root": "1b4788b7ab7a436a611fc59fb1e34c6e" },
            { "display_name": "parent_peer", "node_addr": "aa00", "depth": 0, "distance_to_us": 1, "root": "1b4788b7ab7a436a611fc59fb1e34c6e" },
            { "display_name": "child_peer", "node_addr": "bb00", "depth": 2, "distance_to_us": 3, "root": "1b4788b7ab7a436a611fc59fb1e34c6e" }
        ],
        "stats": {}
    });
    // The role flags live only in the peers view; the tree tab joins them in by
    // node address.
    let peers = json!({
        "peers": [
            { "node_addr": "aa00", "is_parent": true, "is_child": false },
            { "node_addr": "bb00", "is_parent": false, "is_child": true },
            { "node_addr": "cc00", "is_parent": false, "is_child": false }
        ]
    });
    let mut app = app_with(Tab::Tree, tree);
    app.data.insert(Tab::Peers, peers);
    // Tall enough that the Tree Peers pane (below the 10+22-row Position and
    // Stats panes) has room for all three groups and their separators.
    let buf = testkit::render(120, 50, |frame, area| {
        super::tree::draw(frame, &app, area);
    });

    // Match the box-drawing group labels specifically so the Tree Position
    // pane's "Parent:" kv label is not mistaken for the group heading.
    let y_parent = testkit::find(&buf, "\u{2500}\u{2500} Parent")
        .map(|(_, y)| y)
        .unwrap();
    let y_children = testkit::find(&buf, "STP Children").map(|(_, y)| y).unwrap();
    let y_other = testkit::find(&buf, "\u{2500}\u{2500} Other")
        .map(|(_, y)| y)
        .unwrap();
    assert!(y_parent < y_children, "Parent label above Children");
    assert!(y_children < y_other, "Children label above Other");
    // The grouped order also places the peers under their headings.
    let y_parent_peer = testkit::find(&buf, "parent_peer").map(|(_, y)| y).unwrap();
    let y_child_peer = testkit::find(&buf, "child_peer").map(|(_, y)| y).unwrap();
    let y_other_peer = testkit::find(&buf, "other_peer").map(|(_, y)| y).unwrap();
    assert!(y_parent_peer < y_child_peer && y_child_peer < y_other_peer);
}

/// Tree Peers list with no parent among the peers omits the Parent label
/// entirely (empty groups render no heading).
#[test]
fn tree_peers_omit_empty_group() {
    let tree = json!({
        "root": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "root_npub": serde_json::Value::Null,
        "is_root": true,
        "depth": 0,
        "parent_display_name": "self",
        "declaration_sequence": 1,
        "declaration_signed": true,
        "my_coords": [],
        "peers": [
            { "display_name": "child_peer", "node_addr": "bb00", "depth": 1, "distance_to_us": 1, "root": "1b4788b7ab7a436a611fc59fb1e34c6e" }
        ],
        "stats": {}
    });
    let peers = json!({
        "peers": [
            { "node_addr": "bb00", "is_parent": false, "is_child": true }
        ]
    });
    let mut app = app_with(Tab::Tree, tree);
    app.data.insert(Tab::Peers, peers);
    let buf = testkit::render(120, 40, |frame, area| {
        super::tree::draw(frame, &app, area);
    });
    assert!(testkit::contains_row(&buf, "STP Children"));
    assert!(
        !testkit::contains_row(&buf, "\u{2500}\u{2500} Parent"),
        "no Parent heading when no parent peer is present"
    );
}

/// Bloom Peer Filters list groups by tree role with the same labels as the
/// Peers and Tree tabs.
#[test]
fn bloom_peer_filters_grouped_by_role() {
    let data = json!({
        "is_leaf_only": false,
        "leaf_dependent_count": 0,
        "own_node_addr": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "sequence": 0,
        "peer_filters": [
            { "display_name": "other_peer", "peer": "cc00", "filter_sequence": 1u64, "has_filter": true, "fill_ratio": 0.1, "estimated_count": 5.0 },
            { "display_name": "parent_peer", "peer": "aa00", "filter_sequence": 2u64, "has_filter": true, "fill_ratio": 0.2, "estimated_count": 6.0 },
            { "display_name": "child_peer", "peer": "bb00", "filter_sequence": 3u64, "has_filter": false }
        ],
        "stats": {
            "received": 0, "accepted": 0, "decode_error": 0, "invalid": 0,
            "non_v1": 0, "unknown_peer": 0, "stale": 0,
            "sent": 0, "debounce_suppressed": 0, "send_failed": 0
        }
    });
    // Role flags come from the peers view, joined by the filter's `peer` address.
    let peers = json!({
        "peers": [
            { "node_addr": "aa00", "is_parent": true, "is_child": false },
            { "node_addr": "bb00", "is_parent": false, "is_child": true },
            { "node_addr": "cc00", "is_parent": false, "is_child": false }
        ]
    });
    let mut app = app_with(Tab::Bloom, data);
    app.data.insert(Tab::Peers, peers);
    let buf = testkit::render(100, 40, |frame, area| {
        super::bloom::draw(frame, &app, area);
    });

    let y_parent = testkit::find(&buf, "Parent").map(|(_, y)| y).unwrap();
    let y_children = testkit::find(&buf, "STP Children").map(|(_, y)| y).unwrap();
    let y_other = testkit::find(&buf, "Other").map(|(_, y)| y).unwrap();
    assert!(y_parent < y_children, "Parent label above Children");
    assert!(y_children < y_other, "Children label above Other");
    let y_parent_peer = testkit::find(&buf, "parent_peer").map(|(_, y)| y).unwrap();
    let y_child_peer = testkit::find(&buf, "child_peer").map(|(_, y)| y).unwrap();
    let y_other_peer = testkit::find(&buf, "other_peer").map(|(_, y)| y).unwrap();
    assert!(y_parent_peer < y_child_peer && y_child_peer < y_other_peer);
}

/// Peers table + detail: effective_depth renders as a column (em-dash when
/// null) and as a detail kv_line.
#[test]
fn peers_effective_depth_column_and_detail() {
    let data = json!({
        "peers": [
            {
                "display_name": "alice", "npub": "npub1a", "node_addr": "aa00",
                "ipv6_addr": "fd00::a", "connectivity": "direct", "link_id": 1,
                "is_parent": false, "is_child": false,
                "has_tree_position": true, "tree_depth": 1,
                "effective_depth": 2.5,
                "mmp": { "lqi": 3.0 },
                "stats": {}
            }
        ]
    });
    let mut app = app_with(Tab::Peers, data);
    let buf = testkit::render(140, 20, |frame, area| {
        super::peers::draw(frame, &mut app, area);
    });
    assert!(testkit::contains_row(&buf, "EffD"));
    assert!(testkit::contains_row(&buf, "2.50"));
}

/// Bloom Filter State: the uptree fill/subtree-est lines render the values for
/// a non-root node, and `n/a (root)` when this node is root.
#[test]
fn bloom_uptree_render() {
    let bloom = json!({
        "is_leaf_only": false, "leaf_dependent_count": 0,
        "own_node_addr": "1b4788b7ab7a436a611fc59fb1e34c6e", "sequence": 4,
        "peer_filters": [],
        "uptree_fill_ratio": 0.514, "uptree_estimated_count": 1182.0,
        "stats": {}
    });
    // Non-root node (State surface says is_root false).
    let mut app = app_with(Tab::Bloom, bloom);
    app.data.insert(Tab::Node, json!({ "is_root": false }));
    let buf = testkit::render(90, 30, |frame, area| {
        super::bloom::draw(frame, &app, area);
    });
    assert!(testkit::contains_row(&buf, "Fill (sent uptree)"));
    assert!(testkit::contains_row(&buf, "51.4%"));
    assert!(testkit::contains_row(&buf, "Subtree est"));
    assert!(testkit::contains_row(&buf, "1182"));

    // Root node -> n/a (root).
    let bloom_root = json!({
        "is_leaf_only": false, "leaf_dependent_count": 0,
        "own_node_addr": "1b4788b7ab7a436a611fc59fb1e34c6e", "sequence": 0,
        "peer_filters": [],
        "uptree_fill_ratio": serde_json::Value::Null,
        "uptree_estimated_count": serde_json::Value::Null,
        "stats": {}
    });
    let mut app2 = app_with(Tab::Bloom, bloom_root);
    app2.data.insert(Tab::Node, json!({ "is_root": true }));
    let buf2 = testkit::render(90, 30, |frame, area| {
        super::bloom::draw(frame, &app2, area);
    });
    assert!(testkit::contains_row(&buf2, "n/a (root)"));
}

/// Session MMP: trend arrows render inline on the session values (a rising
/// srtt is a red up-arrow), mirroring the Link MMP pane.
#[test]
fn mmp_session_trend_arrows() {
    use ratatui::style::Color;
    let data = json!({
        "peers": [],
        "sessions": [
            {
                "display_name": "alice",
                "session_layer": {
                    "srtt_ms": 42.0,
                    "smoothed_loss": 0.01,
                    "smoothed_etx": 1.2,
                    "sqi": 3.4,
                    "path_mtu": 1280,
                    "rtt_trend": "rising",
                    "loss_trend": "stable",
                    "etx_trend": "falling"
                }
            }
        ]
    });
    let app = app_with(Tab::Mmp, data);
    let buf = testkit::render(120, 20, |frame, area| {
        super::mmp::draw(frame, &app, area);
    });
    // Rising srtt (bad) -> red up-arrow; falling etx (good) -> green down-arrow.
    assert_eq!(testkit::fg_at(&buf, "\u{2191}"), Some(Color::Red));
    assert_eq!(testkit::fg_at(&buf, "\u{2193}"), Some(Color::Green));
}

/// Help registry: the contextual hint set differs per `(Tab, UiMode)`. A
/// selected Peers row surfaces disconnect/deselect; a detail-open state
/// surfaces close/scroll.
#[test]
fn footer_hints_per_mode() {
    use super::help::{UiMode, contextual_hints};

    let peers_sel = contextual_hints(Tab::Peers, UiMode::RowSelected);
    assert!(peers_sel.iter().any(|h| h.label == "disconnect"));
    assert!(peers_sel.iter().any(|h| h.label == "deselect"));

    let detail = contextual_hints(Tab::Peers, UiMode::DetailOpen);
    assert!(detail.iter().any(|h| h.label == "close"));

    let graphs = contextual_hints(Tab::Graphs, UiMode::Overview);
    assert!(graphs.iter().any(|h| h.label == "mode"));
    assert!(graphs.iter().any(|h| h.label == "expand"));

    // The Graphs by-peer detail has its own hint set: peer nav, stat switch,
    // mode cycle, and back (distinct from the generic detail scroll hints).
    let graphs_detail = contextual_hints(Tab::Graphs, UiMode::DetailOpen);
    assert!(graphs_detail.iter().any(|h| h.label == "peer"));
    assert!(graphs_detail.iter().any(|h| h.label == "stat"));
    assert!(graphs_detail.iter().any(|h| h.label == "back"));
}

/// Footer truncation: contextual hints are kept and `[?] Help` is always
/// present even when the budget is too small for the globals.
#[test]
fn footer_truncation_keeps_context_and_help() {
    use super::help::{UiMode, footer_hint_spans};

    // A wide budget shows contextual hints plus the globals.
    let wide = footer_hint_spans(Tab::Peers, UiMode::RowSelected, 120);
    let wide_text: String = wide.iter().map(|s| s.content.as_ref()).collect();
    assert!(wide_text.contains("disconnect"));
    assert!(wide_text.contains("quit"));
    assert!(wide_text.contains("[?] Help"));

    // A narrow budget drops globals but keeps `[?] Help`.
    let narrow = footer_hint_spans(Tab::Peers, UiMode::RowSelected, 14);
    let narrow_text: String = narrow.iter().map(|s| s.content.as_ref()).collect();
    assert!(narrow_text.contains("[?] Help"));
    assert!(
        !narrow_text.contains("quit"),
        "globals drop first: {narrow_text}"
    );
}

/// Del-disconnect modal: the confirmation names the peer, shows a reconnect
/// note, and offers Y/N.
#[test]
fn disconnect_modal_render() {
    let mut app = app_with(Tab::Peers, json!({ "peers": [] }));
    app.confirm_disconnect = Some(crate::app::ConfirmDisconnect {
        npub: "npub1alice".to_string(),
        display_name: "alice".to_string(),
        reconnect_note: "It stays disconnected until you manually reconnect it.".to_string(),
    });
    let buf = testkit::render(100, 30, |frame, area| {
        super::help::draw_disconnect_modal(frame, &app, area);
    });
    assert!(testkit::contains_row(&buf, "Disconnect peer?"));
    assert!(testkit::contains_row(&buf, "alice"));
    assert!(testkit::contains_row(
        &buf,
        "stays disconnected until you manually reconnect"
    ));
    assert!(testkit::contains_row(&buf, "[Y]"));
    assert!(testkit::contains_row(&buf, "[N/Esc]"));
}

/// Del-disconnect selection: request_disconnect_confirm picks the peer under
/// the cursor in the grouped display order and sets the fixed reconnect note
/// for every peer kind.
#[test]
fn disconnect_confirm_picks_selected_peer() {
    use ratatui::widgets::TableState;
    let data = json!({
        "peers": [
            { "display_name": "zeta", "npub": "npub1z", "is_parent": false, "is_child": false, "direction": "inbound", "mmp": { "lqi": 1.0 } },
            { "display_name": "papa", "npub": "npub1p", "is_parent": true, "is_child": false, "direction": "outbound", "mmp": { "lqi": 9.0 } }
        ]
    });
    let mut app = app_with(Tab::Peers, data);
    // Select row 0 in the *displayed* order — parent (papa) sorts first.
    let mut st = TableState::default();
    st.select(Some(0));
    app.table_states.insert(Tab::Peers, st);
    app.request_disconnect_confirm();
    let c = app.confirm_disconnect.as_ref().unwrap();
    assert_eq!(c.display_name, "papa");
    assert_eq!(c.npub, "npub1p");
    assert_eq!(
        c.reconnect_note,
        "It stays disconnected until you manually reconnect it."
    );
}

/// Build a Graphs by-peer (`show_stats_history_all_peers`) payload: a `peers`
/// array of `{display_name, values}`.
fn graphs_by_peer_data() -> serde_json::Value {
    json!({
        "metric": "srtt_ms",
        "peers": [
            { "display_name": "alice", "values": [10.0, 20.0, 30.0, 25.0, 40.0] },
            { "display_name": "bob", "values": [5.0, 5.0, 6.0, 7.0, 8.0] },
            { "display_name": "carol", "values": [100.0, 90.0, 80.0, 70.0, 60.0] }
        ]
    })
}

/// Graphs by-peer list: the resting MetricByPeer state renders one scrollable
/// summary line per peer (name + min/max/last/n), with a cursor marker on the
/// selected peer (never the grid that was deleted).
#[test]
fn graphs_by_peer_list_state() {
    let mut app = app_with(Tab::Graphs, graphs_by_peer_data());
    app.graphs_mode = crate::app::GraphsMode::MetricByPeer;
    app.graphs_peer_idx = 1; // select bob
    let buf = testkit::render(120, 24, |frame, area| {
        super::graphs::draw(frame, &mut app, area);
    });

    // Every peer appears as a summary line.
    assert!(testkit::contains_row(&buf, "alice"));
    assert!(testkit::contains_row(&buf, "bob"));
    assert!(testkit::contains_row(&buf, "carol"));
    // Summary scalars are present (min/max/last/n labels).
    assert!(testkit::contains_row(&buf, "min"));
    assert!(testkit::contains_row(&buf, "last"));
    // The cursor marker sits on the selected peer's row (bob).
    let cursor_row = testkit::find(&buf, "\u{25b6}").map(|(_, y)| y);
    let bob_row = testkit::find(&buf, "bob").map(|(_, y)| y);
    assert_eq!(cursor_row, bob_row, "cursor on the selected peer row");
}

/// Graphs by-peer detail: selecting a peer (detail_view open) swaps to a
/// full-pane btop plot headed by that peer's name and the metric, with summary
/// scalars; the grid is gone.
#[test]
fn graphs_by_peer_detail_state() {
    let mut app = app_with(Tab::Graphs, graphs_by_peer_data());
    app.graphs_mode = crate::app::GraphsMode::MetricByPeer;
    app.graphs_peer_idx = 2; // carol
    app.detail_view = Some(crate::app::DetailView { scroll: 0 });
    let buf = testkit::render(120, 24, |frame, area| {
        super::graphs::draw(frame, &mut app, area);
    });

    // The detail header names the selected peer and metric.
    assert!(testkit::contains_row(&buf, "carol"));
    assert!(testkit::contains_row(&buf, "srtt_ms"));
    // Summary scalars in the header.
    assert!(testkit::contains_row(&buf, "min"));
    assert!(testkit::contains_row(&buf, "samples"));
    // The other peers' summary lines are NOT shown in the full-pane detail.
    assert!(!testkit::contains_row(&buf, "alice"));
}

/// Tree peer line with a long npub-style name: the name field is truncated to
/// a fixed width with a guaranteed trailing space, so it never butts against
/// the `depth:` label.
#[test]
fn tree_long_peer_name_truncated() {
    let tree = json!({
        "root": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "root_npub": serde_json::Value::Null,
        "is_root": false,
        "depth": 1,
        "parent_display_name": "alice",
        "declaration_sequence": 1,
        "declaration_signed": true,
        "my_coords": [],
        "peers": [
            {
                "display_name": "npub1verylongnamethatoverflows",
                "node_addr": "aa00",
                "depth": 0,
                "distance_to_us": 1,
                "root": "1b4788b7ab7a436a611fc59fb1e34c6e"
            }
        ],
        "stats": {}
    });
    let app = app_with(Tab::Tree, tree);
    let buf = testkit::render(120, 40, |frame, area| {
        super::tree::draw(frame, &app, area);
    });
    // The full name must not appear (it is truncated with an ellipsis), and the
    // name must never run directly into the depth label.
    assert!(!testkit::contains_row(
        &buf,
        "npub1verylongnamethatoverflows"
    ));
    assert!(
        !testkit::contains_row(&buf, "overflowsdepth:"),
        "truncated name keeps a separator before depth:"
    );
    assert!(testkit::contains_row(&buf, "depth:"));
}

/// Routing State pane: with the values rendered through the kv_lines group
/// helper, the key column is padded to a common width so all values begin at
/// the same column.
#[test]
fn routing_state_values_aligned() {
    let data = json!({
        "coord_cache_entries": 3,
        "identity_cache_entries": 5,
        "pending_lookups": [],
        "recent_requests": 7,
        "forwarding": {},
        "discovery": {},
        "error_signals": {},
        "congestion": {}
    });
    let mut app = app_with(Tab::Routing, data);
    app.data.insert(Tab::Cache, json!({}));
    let buf = testkit::render(100, 30, |frame, area| {
        super::routing::draw(frame, &app, area);
    });

    // Locate the value column for two state keys; they must match. The keys are
    // padded to a common width, so the value's leading char shares a column.
    let lines = testkit::lines(&buf);
    let coord = lines.iter().find(|r| r.contains("Coord Cache")).unwrap();
    let ident = lines.iter().find(|r| r.contains("Identity Cache")).unwrap();
    // After the padded key the value follows ": "; both rows have the value at
    // the same column because the key field is a fixed width.
    let coord_val = coord.rfind(": ").map(|i| i + 2).unwrap();
    let ident_val = ident.rfind(": ").map(|i| i + 2).unwrap();
    assert_eq!(
        coord_val, ident_val,
        "routing state values share a column: {coord:?} vs {ident:?}"
    );
}

/// Graphs by-peer summary list: the min/max/last numeric columns are
/// right-justified into fixed-width fields so they align across rows of
/// differing magnitude.
#[test]
fn graphs_by_peer_columns_right_justified() {
    // Peers whose values differ in width (single vs triple digit).
    let data = json!({
        "metric": "srtt_ms",
        "peers": [
            { "display_name": "alice", "values": [1.0, 2.0, 3.0] },
            { "display_name": "bob", "values": [100.0, 200.0, 300.0] }
        ]
    });
    let mut app = app_with(Tab::Graphs, data);
    app.graphs_mode = crate::app::GraphsMode::MetricByPeer;
    let buf = testkit::render(120, 24, |frame, area| {
        super::graphs::draw(frame, &mut app, area);
    });

    let lines = testkit::lines(&buf);
    let alice = lines.iter().find(|r| r.contains("alice")).unwrap();
    let bob = lines.iter().find(|r| r.contains("bob")).unwrap();
    // The selected row carries a multibyte cursor glyph that shifts byte
    // offsets, so compare the byte distance between the "min " and "max "
    // labels on each row (both labels and the field between them are ASCII).
    // Because the min value is right-justified into a fixed-width field, this
    // distance is identical regardless of the value's own width.
    let alice_span = alice.find("max ").unwrap() - alice.find("min ").unwrap();
    let bob_span = bob.find("max ").unwrap() - bob.find("min ").unwrap();
    assert_eq!(
        alice_span, bob_span,
        "min->max spacing is constant despite differing value widths: {alice:?} vs {bob:?}"
    );
}

/// Link MMP column sort: with the sort column set to srtt descending, the
/// higher-srtt peer renders above the lower-srtt peer, and the sortable-column
/// header marks srtt as active.
#[test]
fn mmp_link_sort_reorders() {
    let data = json!({
        "peers": [
            { "display_name": "low", "link_layer": { "srtt_ms": 10.0, "lqi": 1.0 } },
            { "display_name": "high", "link_layer": { "srtt_ms": 99.0, "lqi": 2.0 } }
        ],
        "sessions": []
    });
    let mut app = app_with(Tab::Mmp, data);
    // Sort by srtt (column index 1) descending.
    app.mmp_link_sort = crate::app::SortState {
        col: 1,
        descending: true,
    };
    let buf = testkit::render(120, 24, |frame, area| {
        super::mmp::draw(frame, &app, area);
    });

    let y_high = testkit::find(&buf, "high").map(|(_, y)| y).unwrap();
    let y_low = testkit::find(&buf, "low").map(|(_, y)| y).unwrap();
    assert!(
        y_high < y_low,
        "higher srtt sorts above lower under descending sort"
    );
    // The sortable-column header is present and names the columns.
    assert!(testkit::contains_row(&buf, "sort:"));
    assert!(testkit::contains_row(&buf, "srtt"));
}

/// Graphs by-peer column sort: sorting by max descending reorders the summary
/// list so the peer with the larger maximum renders first, while the cursor
/// stays on the originally selected peer.
#[test]
fn graphs_by_peer_sort_reorders() {
    let data = json!({
        "metric": "srtt_ms",
        "peers": [
            { "display_name": "small", "values": [1.0, 2.0, 3.0] },
            { "display_name": "large", "values": [50.0, 60.0, 70.0] }
        ]
    });
    let mut app = app_with(Tab::Graphs, data);
    app.graphs_mode = crate::app::GraphsMode::MetricByPeer;
    // Cursor on "small" (payload index 0).
    app.graphs_peer_idx = 0;
    // Sort by max (column index 2) descending.
    app.graphs_peer_sort = crate::app::SortState {
        col: 2,
        descending: true,
    };
    let buf = testkit::render(120, 24, |frame, area| {
        super::graphs::draw(frame, &mut app, area);
    });

    let y_large = testkit::find(&buf, "large").map(|(_, y)| y).unwrap();
    let y_small = testkit::find(&buf, "small").map(|(_, y)| y).unwrap();
    assert!(
        y_large < y_small,
        "larger max sorts above smaller under descending sort"
    );
    // The cursor stays on the originally selected peer (small), now lower.
    let cursor_row = testkit::find(&buf, "\u{25b6}").map(|(_, y)| y);
    assert_eq!(
        cursor_row,
        Some(y_small),
        "cursor follows the selected peer"
    );
    // The sort header is present.
    assert!(testkit::contains_row(&buf, "sort:"));
}

/// Sort hint registration: the MMP tab and the Graphs by-peer overview both
/// advertise the column-sort key in the contextual hint set.
#[test]
fn sort_hint_registered() {
    use super::help::{UiMode, contextual_hints};

    let mmp = contextual_hints(Tab::Mmp, UiMode::Overview);
    assert!(
        mmp.iter().any(|h| h.label == "sort" && h.key == "s/S"),
        "MMP tab advertises the sort key"
    );

    let graphs = contextual_hints(Tab::Graphs, UiMode::Overview);
    assert!(
        graphs.iter().any(|h| h.label == "sort" && h.key == "s/S"),
        "Graphs overview advertises the sort key"
    );
}

/// Build a minimal Tree payload for the focus/scroll tests.
fn tree_scroll_data() -> serde_json::Value {
    json!({
        "root": "1b4788b7ab7a436a611fc59fb1e34c6e",
        "root_npub": serde_json::Value::Null,
        "is_root": false,
        "depth": 1,
        "parent_display_name": "alice",
        "declaration_sequence": 1,
        "declaration_signed": true,
        "my_coords": [],
        "peers": [],
        "stats": {}
    })
}

/// Tree tab focus/scroll: with the Tree Announce Stats pane focused and a short
/// terminal that clips it, a late stat row ("Flap Dampened") is not visible at
/// offset 0 but is revealed after scrolling the focused pane.
#[test]
fn tree_focused_pane_scrolls() {
    // Height 16: Position pane takes 10, leaving ~6 for the clipped Stats pane.
    // The Stats pane (index 1) is focused.
    let mut app0 = app_with(Tab::Tree, tree_scroll_data());
    app0.focused_pane.insert(Tab::Tree, 1);
    let buf0 = testkit::render(100, 16, |frame, area| {
        super::tree::draw(frame, &app0, area);
    });
    assert!(
        !testkit::contains_row(&buf0, "Flap Dampened"),
        "late stat row is clipped at offset 0"
    );

    // Same layout, but the focused stats pane is scrolled down.
    let mut app1 = app_with(Tab::Tree, tree_scroll_data());
    app1.focused_pane.insert(Tab::Tree, 1);
    app1.scroll_offsets.insert((Tab::Tree, 1), 17);
    let buf1 = testkit::render(100, 16, |frame, area| {
        super::tree::draw(frame, &app1, area);
    });
    assert!(
        testkit::contains_row(&buf1, "Flap Dampened"),
        "scrolling the focused pane reveals the previously-clipped row"
    );
}

/// Routing tab focus/scroll: with the Routing Statistics pane focused and a
/// short terminal, a late stat row ("Congestion") is revealed only after
/// scrolling.
#[test]
fn routing_focused_pane_scrolls() {
    let data = json!({
        "coord_cache_entries": 0, "identity_cache_entries": 0,
        "pending_lookups": [], "recent_requests": 0,
        "forwarding": {}, "discovery": {}, "error_signals": {}, "congestion": {}
    });
    // Routing State (7) + Coord Cache (8) leave the Stats pane (index 2) short.
    let mut app0 = app_with(Tab::Routing, data.clone());
    app0.data.insert(Tab::Cache, json!({}));
    app0.focused_pane.insert(Tab::Routing, 2);
    let buf0 = testkit::render(100, 20, |frame, area| {
        super::routing::draw(frame, &app0, area);
    });
    assert!(
        !testkit::contains_row(&buf0, "Congestion"),
        "Congestion section is clipped at offset 0"
    );

    let mut app1 = app_with(Tab::Routing, data);
    app1.data.insert(Tab::Cache, json!({}));
    app1.focused_pane.insert(Tab::Routing, 2);
    app1.scroll_offsets.insert((Tab::Routing, 2), 6);
    let buf1 = testkit::render(100, 20, |frame, area| {
        super::routing::draw(frame, &app1, area);
    });
    assert!(
        testkit::contains_row(&buf1, "Congestion"),
        "scrolling the focused Routing Statistics pane reveals the section"
    );
}

/// Focus/scroll hint registration: the Tree, Filters, and Routing tabs all
/// advertise the pane-focus key and the scroll keys in their hint set.
#[test]
fn pane_scroll_hints_registered() {
    use super::help::{UiMode, contextual_hints};
    for tab in [Tab::Tree, Tab::Bloom, Tab::Routing] {
        let hints = contextual_hints(tab, UiMode::Overview);
        assert!(
            hints
                .iter()
                .any(|h| h.label == "focus pane" && h.key == "f"),
            "{tab:?} advertises the pane-focus key"
        );
        assert!(
            hints.iter().any(|h| h.label == "scroll"),
            "{tab:?} advertises the scroll keys"
        );
    }
}

/// MMP pane focus: focusing the second pane (Session MMP) highlights its title
/// cyan, while the unfocused Link MMP title stays plain.
#[test]
fn mmp_focused_pane_indicator() {
    use ratatui::style::Color;
    let data = json!({
        "peers": [
            { "display_name": "alice", "link_layer": { "srtt_ms": 10.0, "lqi": 1.0 } }
        ],
        "sessions": [
            { "display_name": "alice", "session_layer": { "srtt_ms": 10.0, "sqi": 1.0, "path_mtu": 1280 } }
        ]
    });
    let mut app = app_with(Tab::Mmp, data);
    app.focused_pane.insert(Tab::Mmp, 1);
    let buf = testkit::render(120, 24, |frame, area| {
        super::mmp::draw(frame, &app, area);
    });
    // The focused Session MMP title is cyan; the unfocused Link MMP title is not.
    assert_eq!(testkit::fg_at(&buf, "Session MMP"), Some(Color::Cyan));
    assert_ne!(testkit::fg_at(&buf, "Link MMP"), Some(Color::Cyan));
}

/// MMP per-pane sort: sorting the focused Session MMP pane by srtt descending
/// reorders only that pane, leaving the unfocused Link MMP pane in its default
/// (name-ascending) order.
#[test]
fn mmp_focused_pane_sort_targets_one_pane() {
    let data = json!({
        "peers": [
            { "display_name": "aaa", "link_layer": { "srtt_ms": 10.0, "lqi": 1.0 } },
            { "display_name": "zzz", "link_layer": { "srtt_ms": 99.0, "lqi": 2.0 } }
        ],
        "sessions": [
            { "display_name": "aaa", "session_layer": { "srtt_ms": 10.0, "sqi": 1.0, "path_mtu": 1280 } },
            { "display_name": "zzz", "session_layer": { "srtt_ms": 99.0, "sqi": 2.0, "path_mtu": 1280 } }
        ]
    });
    let mut app = app_with(Tab::Mmp, data);
    // Focus the Session pane and sort it by srtt descending.
    app.focused_pane.insert(Tab::Mmp, 1);
    app.mmp_session_sort = crate::app::SortState {
        col: 1,
        descending: true,
    };
    let buf = testkit::render(120, 24, |frame, area| {
        super::mmp::draw(frame, &app, area);
    });

    // In the Session MMP pane the high-srtt peer (zzz) sorts above the low one.
    // In the Link MMP pane the default name-ascending order keeps aaa above zzz.
    // The two panes are stacked, Link on top; find the pane boundary by the
    // Session MMP title row, then compare the peer rows within each pane.
    let session_title = testkit::find(&buf, "Session MMP").map(|(_, y)| y).unwrap();
    let lines = testkit::lines(&buf);
    let row_of = |name: &str, above: bool| -> u16 {
        lines
            .iter()
            .enumerate()
            .filter_map(|(y, r)| {
                let y = y as u16;
                let in_pane = if above {
                    y < session_title
                } else {
                    y > session_title
                };
                if in_pane && r.contains(name) {
                    Some(y)
                } else {
                    None
                }
            })
            .next()
            .unwrap()
    };
    // Link pane (above the Session title): default order, aaa before zzz.
    assert!(
        row_of("aaa", true) < row_of("zzz", true),
        "Link pane keeps default name order"
    );
    // Session pane (below the Session title): srtt-descending, zzz before aaa.
    assert!(
        row_of("zzz", false) < row_of("aaa", false),
        "Session pane sorted by srtt descending"
    );
}

/// MMP focus/scroll hint registration: the Performance tab advertises the
/// pane-focus key, the scroll keys, and the sort key.
#[test]
fn mmp_focus_hints_registered() {
    use super::help::{UiMode, contextual_hints};
    let hints = contextual_hints(Tab::Mmp, UiMode::Overview);
    assert!(
        hints
            .iter()
            .any(|h| h.label == "focus pane" && h.key == "f"),
        "MMP tab advertises the pane-focus key"
    );
    assert!(
        hints.iter().any(|h| h.label == "scroll"),
        "MMP tab advertises the scroll keys"
    );
    assert!(
        hints.iter().any(|h| h.label == "sort" && h.key == "s/S"),
        "MMP tab advertises the sort key"
    );
}

/// Help overlay: the `?` modal lists the active context and global keys.
#[test]
fn help_overlay_lists_keys() {
    let mut app = app_with(Tab::Peers, json!({ "peers": [] }));
    app.show_help = true;
    let buf = testkit::render(100, 40, |frame, area| {
        super::help::draw_overlay(frame, &app, area);
    });
    assert!(testkit::contains_row(&buf, "Help"));
    assert!(testkit::contains_row(&buf, "Global"));
    assert!(testkit::contains_row(&buf, "Context"));
    assert!(testkit::contains_row(&buf, "quit"));
    assert!(testkit::contains_row(&buf, "Press ? or Esc to close"));
}
