//! The census of the node's state, and the scan that keeps a peer's record
//! closed.
//!
//! Every field of `Node` and of the path driver is listed here with what holds
//! it: one of this module's per-peer map wrappers, the facets of the transition
//! table whose rows it holds, or an exemption with its reason. The list is read
//! against the struct's source, so a field added with no line, or a line left
//! for a field that is gone, fails whatever the field's type. That catches what
//! a scan for types naming a peer cannot: a per-peer map inside a new struct,
//! or behind a type alias. What it still cannot catch is a field put on the
//! exempt list wrongly; the reason beside it is what a reader checks.
//!
//! The scans read the source as rustfmt leaves it: a struct's fields and an
//! impl's methods one indent in, and a top-level item closed by a `}` alone on
//! its line. Each source is read with its line endings made LF, so a checkout
//! that ends lines with CRLF reads the same.

use std::sync::LazyLock;

use crate::node::settle::table::Facet;
use crate::testutil::with_lf;

/// What holds a field.
#[derive(Clone, Copy, Debug)]
enum Held {
    /// One of the per-peer map wrappers of `node::settle`.
    Table,
    /// The state the table's rows name by these facets.
    Facets(&'static [Facet]),
    /// No change to a held peer writes it, for the reason given.
    Exempt(&'static str),
}

use Held::{Exempt, Facets, Table};

const NODE_WIDE: &str = "node-wide: it holds nothing per peer";
const CHANNEL: &str = "a channel end: it carries events, not state";
const LATCH: &str = "a node-wide log latch or budget";
const COUNTS: &str = "node-wide counters, which a peer's changes add to and never reset";
const SNAPSHOT: &str = "a read copy the tick republishes from the live state";
const PACING: &str = "a node-wide pacing stamp";
const ANCHOR: &str = "a stateless decision anchor";
const TEST: &str = "a test's override of a clock or a tick";
const BY_DEST: &str =
    "keyed by a destination, a link peer or not; no change to a held peer writes it";
const BUDGET: &str = "a rate budget that refills on its own clock; no change to a peer clears it";
const HELD: &str = "held for the destination's next session, which a removal keeps";
const FROM_FILES: &str = "loaded from the configuration and its files, not from a peering";

/// Every field of `Node`, with what holds it.
const NODE: &[(&str, Held)] = &[
    ("context", Exempt(NODE_WIDE)),
    ("supervisor", Facets(&[Facet::Bootstrap])),
    ("tree_state", Facets(&[Facet::Tree])),
    ("bloom_state", Facets(&[Facet::Bloom])),
    ("coord_cache", Exempt(BY_DEST)),
    ("path_mtu_lookup", Facets(&[Facet::PathMtu])),
    ("node_mtu", Exempt(NODE_WIDE)),
    ("path_mtu_seeded_by", Facets(&[Facet::PathMtu])),
    ("netmon_trigger", Exempt(NODE_WIDE)),
    ("transports", Facets(&[Facet::Verified, Facet::Connection])),
    ("transport_drops", Exempt("keyed by transport, not by peer")),
    ("links", Table),
    ("packet_rx", Exempt(CHANNEL)),
    ("child_exit_tx", Exempt(CHANNEL)),
    ("child_exit_rx", Exempt(CHANNEL)),
    ("transport_presence_tx", Exempt(CHANNEL)),
    ("transport_presence_rx", Exempt(CHANNEL)),
    ("peer_machines", Table),
    ("peers", Table),
    ("sessions", Facets(&[Facet::Session])),
    ("identity_cache", Facets(&[Facet::Identity])),
    ("pending_tun_packets", Exempt(HELD)),
    ("pending_tun_since", Exempt(HELD)),
    ("routing_hold", Exempt(NODE_WIDE)),
    ("pending_tun_bound_log", Exempt(LATCH)),
    ("native", Exempt(NODE_WIDE)),
    ("pending_native", Exempt(HELD)),
    ("lookup", Facets(&[Facet::LookupBackoff])),
    ("discovery_sign_limiter", Exempt(BUDGET)),
    ("backoff_bound_log", Exempt(LATCH)),
    ("forward_bound_log", Exempt(LATCH)),
    ("probes", Exempt(BY_DEST)),
    ("next_link_id", Exempt("an allocator's next value")),
    ("next_transport_id", Exempt("an allocator's next value")),
    ("stats", Exempt(COUNTS)),
    ("metrics", Exempt(COUNTS)),
    ("stats_history", Exempt(COUNTS)),
    ("stats_snapshot", Exempt(SNAPSHOT)),
    ("routing_snapshot", Exempt(SNAPSHOT)),
    ("entities_snapshot", Exempt(SNAPSHOT)),
    ("native_snapshot", Exempt(SNAPSHOT)),
    ("ble_radio", Exempt(NODE_WIDE)),
    (
        "index_allocator",
        Exempt("allocates the indices the rekey machine holds, whose row says when they go"),
    ),
    ("peers_by_index", Table),
    ("index_budget", Exempt(LATCH)),
    ("version_budget", Exempt(LATCH)),
    ("length_budget", Exempt(LATCH)),
    ("msgtype_budget", Exempt(LATCH)),
    ("pending_outbound", Table),
    ("restart_dampener", Facets(&[Facet::Dampener])),
    ("silent_sessions", Facets(&[Facet::Silent])),
    ("replayed_msg1s", Facets(&[Facet::Replayed])),
    ("link_records", Facets(&[Facet::Records])),
    (
        "paths",
        Facets(&[
            Facet::PathConnects,
            Facet::PathCloses,
            Facet::PathListings,
            Facet::PathCarrier,
        ]),
    ),
    ("msg1_rate_limiter", Exempt(BUDGET)),
    ("setup_rate_limiter", Exempt(BUDGET)),
    ("setup_clock", Exempt(TEST)),
    ("test_tick", Exempt(TEST)),
    ("peer_error_budget", Exempt(BUDGET)),
    ("coord_hint_budget", Exempt(BUDGET)),
    ("routing", Exempt(BY_DEST)),
    ("fmp", Exempt(ANCHOR)),
    ("fsp", Exempt(ANCHOR)),
    ("mmp", Exempt(ANCHOR)),
    ("coords_response_rate_limiter", Exempt(BY_DEST)),
    ("path_mtu_release_limiter", Exempt(BY_DEST)),
    ("broken_quorum", Exempt(BY_DEST)),
    ("peering", Facets(&[Facet::Reconnect])),
    ("last_parent_reeval", Exempt(PACING)),
    ("last_congestion_log", Exempt(PACING)),
    ("estimated_mesh_size", Exempt(NODE_WIDE)),
    ("last_mesh_size_log", Exempt(PACING)),
    ("seq_origin", Exempt(NODE_WIDE)),
    ("peer_aliases", Exempt(FROM_FILES)),
    ("peer_acl", Exempt(FROM_FILES)),
    ("host_map", Exempt(FROM_FILES)),
    (
        "decrypt_registered_sessions",
        Exempt(
            "follows the rekey machine's indices: registered as a worker takes a \
             session, dropped at its revoke",
        ),
    ),
    ("decrypt_fallback_rx", Exempt(CHANNEL)),
    ("decrypt_fallback_tx", Exempt(CHANNEL)),
];

/// Every field of the path driver, with what holds it.
const PATH_DRIVER: &[(&str, Held)] = &[
    ("connecting", Facets(&[Facet::PathConnects])),
    ("closing", Facets(&[Facet::PathCloses])),
    (
        "wake",
        Exempt("a deadline the tick takes again from the machines' own wakes"),
    ),
    ("polls", Exempt(TEST)),
    ("carrier", Facets(&[Facet::PathCarrier])),
    ("reports", Exempt(CHANNEL)),
    ("listings", Facets(&[Facet::PathListings])),
];

/// The setters `ActivePeer` has, the last three only under `cfg(test)`. A
/// peer's state changes by the event that changes it, not by a setter, so a
/// new setter takes a line here only with a reason its state has no event.
/// `set_past_feed` writes no state of the peer's: it puts back the test's
/// mark that the live audit's `links-mirror` reads, around the frame's
/// accounting.
const SETTERS: &[&str] = &[
    "set_connected_udp",
    "set_handshake_msg2",
    "set_tree_announce_min_interval_ms",
    "set_last_tree_announce_sent_ms",
    "set_link_id",
    "set_current_addr",
    "set_remote_epoch",
    "set_past_feed",
];

static NODE_SOURCE: LazyLock<String> = LazyLock::new(|| with_lf(include_str!("../../mod.rs")));
static PATH_SOURCE: LazyLock<String> =
    LazyLock::new(|| with_lf(include_str!("../../handlers/path.rs")));
static ACTIVE_SOURCE: LazyLock<String> =
    LazyLock::new(|| with_lf(include_str!("../../../peer/active.rs")));
static DATA_SOURCE: LazyLock<String> =
    LazyLock::new(|| with_lf(include_str!("../../../peer/data.rs")));

/// The lines of the top-level item whose opening line ends with `header`, up
/// to the `}` that closes it, or `None` if `source` has no such item.
fn item<'a>(source: &'a str, header: &str) -> Option<Vec<&'a str>> {
    let mut lines = source.lines();
    lines.find(|line| !line.starts_with(' ') && line.ends_with(header))?;
    Some(lines.take_while(|line| *line != "}").collect())
}

/// A line one indent in, past its visibility: the visibility and the rest,
/// or `None` for a line at another depth, a comment or an attribute.
fn member(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("    ")?;
    if rest.starts_with([' ', '/', '#']) {
        return None;
    }
    let after = if rest.starts_with("pub(") {
        rest.find(") ").map(|end| end + 2)
    } else if rest.starts_with("pub ") {
        Some(4)
    } else {
        Some(0)
    }?;
    Some((rest[..after].trim_end(), &rest[after..]))
}

/// Each field of `name`'s struct in `source`, with its visibility (empty for
/// a private field) and its type as far as the line holds it.
fn fields<'a>(source: &'a str, name: &str) -> Vec<(&'a str, &'a str, &'a str)> {
    let lines = item(source, &format!("struct {name} {{"))
        .unwrap_or_else(|| panic!("precondition: no struct {name} in the source"));
    lines
        .into_iter()
        .filter_map(member)
        .filter_map(|(vis, rest)| {
            let (field, ty) = rest.split_once(':')?;
            let named = !field.is_empty()
                && field.starts_with(|c: char| c.is_ascii_lowercase())
                && field
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            (named && !ty.starts_with(':')).then(|| (vis, field, ty.trim().trim_end_matches(',')))
        })
        .collect()
}

/// What the census gets wrong for `name`'s struct: each field with no line,
/// each line with no field, and each name with more than one line.
fn gaps(source: &str, name: &str, census: &[(&str, Held)]) -> Vec<String> {
    let found: Vec<&str> = fields(source, name).iter().map(|(_, f, _)| *f).collect();
    let mut wrong = Vec::new();
    for field in &found {
        if !census.iter().any(|(listed, _)| listed == field) {
            wrong.push(format!("{name}.{field} has no line"));
        }
    }
    for (index, (listed, _)) in census.iter().enumerate() {
        if !found.contains(listed) {
            wrong.push(format!("{name}.{listed} is listed and is not a field"));
        }
        if census[..index].iter().any(|(earlier, _)| earlier == listed) {
            wrong.push(format!("{name}.{listed} is listed twice"));
        }
    }
    wrong
}

/// `source` with `line` added as the first field of `name`'s struct.
fn plant(source: &str, name: &str, line: &str) -> String {
    let header = format!("struct {name} {{\n");
    assert!(
        source.contains(&header),
        "precondition: the struct {name} to plant in"
    );
    source.replacen(&header, &format!("{header}{line}\n"), 1)
}

/// `source` without its line declaring `field`.
fn without(source: &str, field: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let gone: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| member(line).is_none_or(|(_, rest)| !rest.starts_with(&format!("{field}:"))))
        .collect();
    assert_eq!(
        gone.len() + 1,
        lines.len(),
        "precondition: one line declares {field}"
    );
    gone.join("\n")
}

#[test]
fn every_node_field_has_an_owner_and_the_scan_finds_a_planted_one() {
    assert_eq!(
        gaps(&NODE_SOURCE, "Node", NODE),
        Vec::<String>::new(),
        "defect: the census of Node"
    );

    let planted = plant(&NODE_SOURCE, "Node", "    by_peer: HashMap<NodeAddr, u64>,");
    assert_eq!(
        gaps(&planted, "Node", NODE),
        ["Node.by_peer has no line"],
        "defect: a planted per-peer map is not found"
    );
    let planted = plant(&NODE_SOURCE, "Node", "    pub(crate) msg1_x: u64,");
    assert_eq!(
        gaps(&planted, "Node", NODE),
        ["Node.msg1_x has no line"],
        "defect: a planted field with a digit in its name is not found"
    );
    let planted = plant(&NODE_SOURCE, "Node", "    wrapped_x:\n        Option<u64>,");
    assert_eq!(
        gaps(&planted, "Node", NODE),
        ["Node.wrapped_x has no line"],
        "defect: a planted field whose type wraps is not found"
    );
    let planted = plant(
        &NODE_SOURCE,
        "Node",
        "    /// doc_x: a comment.\n    #[cfg(test)]\n    nested_x: HashMap<\n\
         \x20       inner_x: u64,\n    >,",
    );
    assert_eq!(
        gaps(&planted, "Node", NODE),
        ["Node.nested_x has no line"],
        "defect: a comment or a continuation line is read as a field"
    );
    assert_eq!(
        gaps(&without(&NODE_SOURCE, "next_link_id"), "Node", NODE),
        ["Node.next_link_id is listed and is not a field"],
        "defect: a removed field still listed is not found"
    );
}

#[test]
fn a_source_checked_out_with_crlf_line_endings_is_read_and_planted_in_as_its_lf_text() {
    let crlf = NODE_SOURCE.replace('\n', "\r\n");
    assert!(
        crlf.contains("struct Node {\r\n"),
        "precondition: a copy of the source with CRLF line endings"
    );
    let source = with_lf(&crlf);
    assert_eq!(
        gaps(&source, "Node", NODE),
        Vec::<String>::new(),
        "defect: the census of Node read from a CRLF checkout"
    );
    let planted = plant(&source, "Node", "    by_peer: HashMap<NodeAddr, u64>,");
    assert_eq!(
        gaps(&planted, "Node", NODE),
        ["Node.by_peer has no line"],
        "defect: a field planted in a CRLF checkout's source is not found"
    );
}

#[test]
fn every_path_driver_field_has_an_owner() {
    assert_eq!(
        gaps(&PATH_SOURCE, "PathDriver", PATH_DRIVER),
        Vec::<String>::new(),
        "defect: the census of the path driver"
    );

    let planted = plant(
        &PATH_SOURCE,
        "PathDriver",
        "    by_peer: HashMap<NodeAddr, u64>,",
    );
    assert_eq!(
        gaps(&planted, "PathDriver", PATH_DRIVER),
        ["PathDriver.by_peer has no line"],
        "defect: a planted per-peer map is not found"
    );
    let planted = plant(&PATH_SOURCE, "PathDriver", "    msg1_x: u64,");
    assert_eq!(
        gaps(&planted, "PathDriver", PATH_DRIVER),
        ["PathDriver.msg1_x has no line"],
        "defect: a planted field with a digit in its name is not found"
    );
    assert_eq!(
        gaps(&without(&PATH_SOURCE, "wake"), "PathDriver", PATH_DRIVER),
        ["PathDriver.wake is listed and is not a field"],
        "defect: a removed field still listed is not found"
    );
}

#[test]
fn every_exemption_has_a_reason_every_facet_a_field_and_every_map_wrapper_the_table() {
    for (field, held) in NODE.iter().chain(PATH_DRIVER) {
        if let Exempt(reason) = held {
            assert!(
                !reason.trim().is_empty(),
                "defect: {field} is exempt with no reason"
            );
        }
    }

    for facet in Facet::ALL {
        assert!(
            NODE.iter()
                .any(|(_, held)| matches!(held, Facets(facets) if facets.contains(facet))),
            "defect: {facet:?} is held by no field of Node"
        );
    }

    let Some((_, Facets(paths))) = NODE.iter().find(|(field, _)| *field == "paths") else {
        panic!("defect: Node.paths holds no facets");
    };
    for (field, held) in PATH_DRIVER {
        if let Facets(facets) = held {
            for facet in *facets {
                assert!(
                    paths.contains(facet),
                    "defect: PathDriver.{field} holds {facet:?}, which Node.paths does not list"
                );
            }
        }
    }
    for facet in *paths {
        assert!(
            PATH_DRIVER
                .iter()
                .any(|(_, held)| matches!(held, Facets(facets) if facets.contains(facet))),
            "defect: Node.paths lists {facet:?}, which no field of PathDriver holds"
        );
    }

    for (_, field, ty) in fields(&NODE_SOURCE, "Node") {
        let listed = NODE.iter().find(|(f, _)| *f == field).map(|(_, held)| held);
        let wrapper = ty.starts_with("settle::");
        assert_eq!(
            wrapper,
            matches!(listed, Some(Table)),
            "defect: Node.{field}, of type {ty}, is a map wrapper of this module \
             exactly when the census says the table holds it"
        );
    }
}

/// The name of each `fn set_` method in `ActivePeer`'s impl in `source`.
fn setters(source: &str) -> Vec<&str> {
    item(source, "impl ActivePeer {")
        .expect("precondition: an impl ActivePeer in the source")
        .into_iter()
        .filter_map(member)
        .filter_map(|(_, rest)| rest.strip_prefix("fn "))
        .filter(|rest| rest.starts_with("set_"))
        .map(|rest| rest.split(['(', '<']).next().unwrap_or_default())
        .collect()
}

/// Each field of `PeerData` in `source` that is not `pub(super)`, with its
/// visibility.
fn opened(source: &str) -> Vec<String> {
    fields(source, "PeerData")
        .into_iter()
        .filter(|(vis, _, _)| *vis != "pub(super)")
        .map(|(vis, field, _)| format!("{vis} {field}").trim().to_string())
        .collect()
}

#[test]
fn no_setter_beyond_the_list_and_the_scan_finds_a_planted_one() {
    let mut found = setters(&ACTIVE_SOURCE);
    found.sort_unstable();
    let mut listed = SETTERS.to_vec();
    listed.sort_unstable();
    assert_eq!(
        found, listed,
        "defect: ActivePeer's setters are not the listed ones"
    );

    let planted = ACTIVE_SOURCE.replacen(
        "impl ActivePeer {\n",
        "impl ActivePeer {\n    /// fn set_y is a comment.\n\
         \x20   pub(crate) fn set_x(&mut self) {}\n",
        1,
    );
    assert_ne!(
        planted, *ACTIVE_SOURCE,
        "precondition: the impl to plant in"
    );
    assert!(
        setters(&planted).contains(&"set_x"),
        "defect: a planted setter is not found"
    );
    assert!(
        !setters(&planted).contains(&"set_y"),
        "defect: a comment is read as a setter"
    );

    assert_eq!(
        opened(&DATA_SOURCE),
        Vec::<String>::new(),
        "defect: a field of PeerData is open beyond the peer module"
    );
    assert!(
        fields(&DATA_SOURCE, "PeerData").len() > 1,
        "precondition: the scan reads PeerData's fields"
    );
    let planted = plant(
        &DATA_SOURCE,
        "PeerData",
        "    pub(crate) wide_x: u64,\n    pub open_x: u64,",
    );
    assert_eq!(
        opened(&planted),
        ["pub(crate) wide_x", "pub open_x"],
        "defect: a planted open field of PeerData is not found"
    );
    let planted = format!(
        "{}\npub(crate) struct Departed {{\n    pub heard: bool,\n\
         \x20   pub frame_heard: bool,\n}}\n",
        *DATA_SOURCE
    );
    assert_eq!(
        opened(&planted),
        Vec::<String>::new(),
        "defect: the open fields of what a removal hands over are read as the record's"
    );
}
