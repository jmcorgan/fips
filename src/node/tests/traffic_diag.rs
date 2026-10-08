//! Framing drops, unknown link types, filter announces and forwarded lookups
//! carry the fields that say where they came from and what they carried.
//!
//! Each test drives the condition a line reports through the real handler,
//! finds the line by its exact message, and checks the discriminating fields
//! against values derived independently: addresses and bytes from the packet
//! the test built, digests and overlaps from the filter bits the test hashed
//! and counted itself, tree roles from `show_peers`, and names from the peers
//! the test chose.

use super::discovery::{flood_requests, lookup_request_payload, register_peers, unexpiring_node};
use super::link_setup_diag::{expect_line, field};
use super::spanning_tree::{TestNode, cleanup_nodes, run_tree_test};
use super::*;
use crate::proto::bloom::{BloomFilter, FilterAnnounce};
use crate::proto::fmp::wire::{COMMON_PREFIX_SIZE, MSG1_WIRE_SIZE};
use crate::proto::lookup::{LookupRequest, LookupResponse};
use crate::proto::stp::TreeCoordinate;
use crate::testutil::{LogCapture, capture_logs_scoped, log_field};
use sha2::{Digest, Sha256};
use std::time::Instant;

/// Whether `line`'s message is exactly `message`.
fn has_message(line: &str, message: &str) -> bool {
    let needle = format!(" message={message}");
    line.match_indices(&needle).any(|(at, _)| {
        let rest = &line[at + needle.len()..];
        rest.is_empty()
            || rest
                .strip_prefix(' ')
                .and_then(|r| r.split(' ').next())
                .is_some_and(|t| t.contains('='))
    })
}

/// Every captured line whose message is exactly `message`.
fn lines_with(logs: &LogCapture, message: &str) -> Vec<String> {
    logs.lines()
        .into_iter()
        .filter(|l| has_message(l, message))
        .collect()
}

/// `bytes` as lowercase hex, two digits per byte.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The digest a line should carry for `filter`: the first 8 bytes of a
/// SHA-256 over its bits.
fn filter_digest(filter: &BloomFilter) -> String {
    hex(&Sha256::digest(filter.as_bytes())[..8])
}

/// Set bits of `sent` also set in `got`, over set bits of `sent`, as the
/// line renders it.
fn overlap_text(got: &BloomFilter, sent: &BloomFilter) -> String {
    let ones = |bytes: &[u8]| bytes.iter().map(|b| b.count_ones() as usize).sum::<usize>();
    let both: Vec<u8> = got
        .as_bytes()
        .iter()
        .zip(sent.as_bytes())
        .map(|(a, b)| a & b)
        .collect();
    format!("{:.3}", ones(&both) as f64 / ones(sent.as_bytes()) as f64)
}

/// A received packet from `from` carrying `data`.
fn packet_from(from: &str, data: Vec<u8>) -> ReceivedPacket {
    ReceivedPacket {
        transport_id: TransportId::new(1),
        remote_addr: TransportAddr::from_string(from),
        data,
        timestamp_ms: 1_000,
    }
}

/// A frame of `len` bytes whose version nibble is 1, so no FMP node accepts
/// it. Every byte after the first differs from its neighbours, so a head
/// field that showed the wrong bytes would not match.
fn bad_version_frame(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| if i == 0 { 0x10 } else { 0x20 + i as u8 })
        .collect()
}

/// A msg1-phase frame of the msg1 wire size whose `payload_len` claims four
/// more bytes than the frame carries.
fn plus_four_frame() -> Vec<u8> {
    let mut frame: Vec<u8> = (0..MSG1_WIRE_SIZE).map(|i| i as u8).collect();
    frame[0] = 0x01;
    frame[1] = 0x00;
    let declared = (MSG1_WIRE_SIZE - COMMON_PREFIX_SIZE + 4) as u16;
    frame[2..4].copy_from_slice(&declared.to_le_bytes());
    frame
}

/// The sizes of the node's per-peer and per-link maps, which a flood from
/// unauthenticated sources must leave as they were.
fn map_sizes(node: &Node) -> [usize; 6] {
    [
        node.peers.len(),
        node.peers_by_index.len(),
        node.pending_outbound.len(),
        node.links.len(),
        node.addr_to_link.len(),
        node.peer_machines.len(),
    ]
}

/// How long a flood test waits after its flood, so the budget admits one
/// more line, which reports what the flood had withheld.
const REFILL: std::time::Duration = std::time::Duration::from_millis(1_100);

/// Check a budget-limited line's flood, whose last message was sent after
/// [`REFILL`]: the full burst is logged, no more than one line a second after
/// it, the withheld counts plus the lines logged do not exceed what was sent,
/// and the last line reports the lines withheld before it.
fn assert_bounded(logs: &LogCapture, message: &str, sent: u64, start: Instant) {
    let elapsed = start.elapsed();
    let lines = lines_with(logs, message);
    let n = lines.len() as u64;
    let ceiling = 10 + elapsed.as_secs_f64().ceil() as u64;
    assert!(n >= 10, "the full burst must be logged: {n} lines");
    assert!(
        n <= ceiling,
        "{n} lines in {elapsed:?}, more than {ceiling}"
    );
    let mut withheld = 0;
    for line in &lines {
        assert!(line.starts_with("DEBUG"), "{line}");
        withheld += field(line, "suppressed").parse::<u64>().expect("a count");
    }
    assert!(withheld + n <= sent, "{withheld} withheld + {n} logged");
    let last = lines.last().expect("lines were logged");
    let reported: u64 = field(last, "suppressed").parse().expect("a count");
    assert!(reported > 0, "the line after the flood reports it: {last}");
}

#[tokio::test]
async fn an_unknown_fmp_version_logs_the_sender_and_the_frames_first_bytes() {
    let mut node = make_node();
    let frame = bad_version_frame(20);
    let (logs, guard) = capture_logs_scoped();
    node.process_packet(packet_from("10.1.2.3:2121", frame.clone()))
        .await;
    node.process_packet(packet_from("10.1.2.4:2121", bad_version_frame(4)))
        .await;
    drop(guard);

    let lines = lines_with(&logs, "Unknown FMP version, dropping");
    assert_eq!(lines.len(), 2, "{lines:#?}");
    let line = &lines[0];
    assert_eq!(field(line, "remote_addr"), "10.1.2.3:2121", "{line}");
    assert_eq!(field(line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(line, "head"), hex(&frame[..8]), "{line}");
    assert_eq!(field(line, "suppressed"), "0", "{line}");

    let short = &lines[1];
    assert_eq!(field(short, "remote_addr"), "10.1.2.4:2121", "{short}");
    assert_eq!(field(short, "head"), hex(&bad_version_frame(4)), "{short}");
    assert_eq!(field(short, "head").len(), 8, "{short}");
}

#[tokio::test]
async fn a_payload_length_mismatch_logs_the_sender_and_the_frames_first_bytes() {
    let mut node = make_node();
    let frame = plus_four_frame();
    let (logs, guard) = capture_logs_scoped();
    node.process_packet(packet_from("10.5.6.7:2121", frame.clone()))
        .await;
    drop(guard);

    let line = expect_line(
        &logs,
        "FMP payload_len disagrees with frame length, dropping",
    );
    assert_eq!(field(&line, "remote_addr"), "10.5.6.7:2121", "{line}");
    assert_eq!(field(&line, "head"), hex(&frame[..8]), "{line}");
    assert_eq!(
        field(&line, "declared"),
        (MSG1_WIRE_SIZE - COMMON_PREFIX_SIZE + 4).to_string(),
        "{line}"
    );
    assert_eq!(
        field(&line, "expected"),
        (MSG1_WIRE_SIZE - COMMON_PREFIX_SIZE).to_string(),
        "{line}"
    );
    assert_eq!(field(&line, "suppressed"), "0", "{line}");
}

/// A distinct source address for frame `i` of a flood.
fn flood_source(i: u64) -> String {
    format!(
        "10.{}.{}.{}:2121",
        (i >> 16) & 0xff,
        (i >> 8) & 0xff,
        i & 0xff
    )
}

#[tokio::test]
async fn a_flood_of_bad_version_frames_from_many_sources_logs_a_bounded_number_of_lines() {
    const FRAMES: u64 = 2_000;
    // The budget fills when the node is built.
    let start = Instant::now();
    let mut node = make_node();
    let sizes = map_sizes(&node);

    let (logs, guard) = capture_logs_scoped();
    for i in 0..FRAMES {
        node.process_packet(packet_from(&flood_source(i), bad_version_frame(20)))
            .await;
    }
    tokio::time::sleep(REFILL).await;
    node.process_packet(packet_from(&flood_source(FRAMES), bad_version_frame(20)))
        .await;
    drop(guard);

    assert_bounded(&logs, "Unknown FMP version, dropping", FRAMES + 1, start);
    assert_eq!(map_sizes(&node), sizes, "the flood stored nothing");
}

#[tokio::test]
async fn a_flood_of_length_mismatches_logs_a_bounded_number_of_lines() {
    const FRAMES: u64 = 2_000;
    let start = Instant::now();
    let mut node = make_node();
    let sizes = map_sizes(&node);

    let (logs, guard) = capture_logs_scoped();
    for i in 0..FRAMES {
        node.process_packet(packet_from(&flood_source(i), plus_four_frame()))
            .await;
    }
    tokio::time::sleep(REFILL).await;
    node.process_packet(packet_from(&flood_source(FRAMES), plus_four_frame()))
        .await;
    drop(guard);

    assert_bounded(
        &logs,
        "FMP payload_len disagrees with frame length, dropping",
        FRAMES + 1,
        start,
    );
    assert_eq!(map_sizes(&node), sizes, "the flood stored nothing");
}

/// A link message type no specification assigns.
const UNASSIGNED_TYPE: u8 = 0x7F;

#[tokio::test]
async fn a_flood_of_unknown_link_message_types_logs_a_bounded_number_of_lines() {
    const MESSAGES: u64 = 2_000;
    let start = Instant::now();
    let mut node = make_node();
    let sizes = map_sizes(&node);

    let arrival = TransportAddr::from_string("127.0.0.1:9");
    let (logs, guard) = capture_logs_scoped();
    for i in 0..=MESSAGES {
        if i == MESSAGES {
            tokio::time::sleep(REFILL).await;
        }
        let from = make_node_addr((i % 251) as u8);
        node.dispatch_link_message(
            &from,
            &[UNASSIGNED_TYPE, 0, 0],
            false,
            (TransportId::new(1), &arrival),
        )
        .await;
    }
    drop(guard);

    assert_bounded(&logs, "Unknown link message type", MESSAGES + 1, start);
    assert_eq!(map_sizes(&node), sizes, "the flood stored nothing");
}

#[tokio::test]
async fn an_unknown_link_message_type_names_the_peer_that_sent_it() {
    let mut node = make_node();
    let from = make_node_addr(0x42);
    let arrival = TransportAddr::from_string("127.0.0.1:9");
    let (logs, guard) = capture_logs_scoped();
    node.dispatch_link_message(
        &from,
        &[UNASSIGNED_TYPE, 0, 0],
        false,
        (TransportId::new(1), &arrival),
    )
    .await;
    drop(guard);

    let line = expect_line(&logs, "Unknown link message type");
    assert_eq!(
        field(&line, "peer"),
        node.peer_display_name(&from),
        "{line}"
    );
    assert_eq!(
        field(&line, "msg_type"),
        UNASSIGNED_TYPE.to_string(),
        "{line}"
    );
    assert_eq!(field(&line, "suppressed"), "0", "{line}");
}

/// Each peer's tree role at `node`, as `show_peers` reports it: `parent`,
/// `child` or `none`, keyed by the peer's hex address.
fn roles_from_show_peers(node: &Node) -> Vec<(String, &'static str)> {
    let peers = crate::control::queries::show_peers(node);
    peers["peers"]
        .as_array()
        .expect("show_peers returns a peers array")
        .iter()
        .map(|row| {
            let role = if row["is_parent"] == true {
                "parent"
            } else if row["is_child"] == true {
                "child"
            } else {
                "none"
            };
            (
                row["node_addr"]
                    .as_str()
                    .expect("a hex address")
                    .to_string(),
                role,
            )
        })
        .collect()
}

/// The role `show_peers` gives `peer` at `node`.
fn role_of(node: &Node, peer: &NodeAddr) -> &'static str {
    let hex_addr = hex(peer.as_bytes());
    roles_from_show_peers(node)
        .into_iter()
        .find(|(a, _)| *a == hex_addr)
        .map(|(_, r)| r)
        .expect("show_peers lists the peer")
}

#[tokio::test]
async fn show_bloom_reports_each_peers_tree_role_on_both_renders() {
    // A triangle: three links, two of them tree links, so one is not.
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2), (0, 2)], false).await;
    let mut seen = std::collections::BTreeMap::new();

    for tn in nodes.iter_mut() {
        let node = &mut tn.node;
        let expected = roles_from_show_peers(node);
        let on_loop = crate::control::queries::show_bloom(node);
        node.record_stats_history();
        let off_loop = crate::control::queries::show_bloom_from_handle(&node.control_read_handle());

        let rows = on_loop["peer_filters"]
            .as_array()
            .expect("show_bloom returns a peer_filters array");
        assert_eq!(rows.len(), expected.len());
        for row in rows {
            let peer = row["peer"].as_str().expect("a hex address");
            let want = expected
                .iter()
                .find(|(a, _)| a == peer)
                .map(|(_, r)| *r)
                .expect("show_peers lists every bloom peer");
            assert_eq!(row["tree_role"], want, "{row}");
            *seen.entry(want).or_insert(0) += 1;
        }
        assert_eq!(
            on_loop["peer_filters"], off_loop["peer_filters"],
            "the on-loop and snapshot renders must agree"
        );
    }
    for role in ["parent", "child", "none"] {
        assert!(
            seen.get(role).is_some_and(|n| *n > 0),
            "precondition: some row is {role}: {seen:?}"
        );
    }

    cleanup_nodes(&mut nodes).await;
}

/// `is_tree_peer` is now read from `tree_role`; it must still say a peer is a
/// tree peer exactly when `show_peers`, which computes the relation on its
/// own, calls it a parent or a child.
#[tokio::test]
async fn is_tree_peer_holds_exactly_for_the_peers_show_peers_calls_parent_or_child() {
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2), (0, 2)], false).await;
    let mut non_tree = 0;
    for tn in &nodes {
        for (hex_addr, role) in roles_from_show_peers(&tn.node) {
            let bytes: [u8; 16] = hex::decode(&hex_addr).unwrap().try_into().unwrap();
            let peer = NodeAddr::from_bytes(bytes);
            assert_eq!(
                tn.node.is_tree_peer(&peer),
                role != "none",
                "{hex_addr} is {role}"
            );
            non_tree += usize::from(role == "none");
        }
    }
    assert!(
        non_tree > 0,
        "precondition: the triangle has a non-tree link"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The index of the root among `nodes`, and of some other node.
fn root_and_other(nodes: &[TestNode]) -> (usize, usize) {
    let root = nodes
        .iter()
        .position(|tn| tn.node.tree_state().is_root())
        .expect("a converged tree has a root");
    (root, if root == 0 { 1 } else { 0 })
}

#[tokio::test]
async fn a_sent_filter_announce_logs_the_digest_of_the_filter_it_sent() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let peer = *nodes[1].node.node_addr();
    let node = &mut nodes[0].node;
    let mut filter = BloomFilter::new();
    filter.insert(node.node_addr());
    filter.insert(&make_node_addr(0x31));

    // The debounce is a brake, not what is under test.
    node.bloom_state.set_update_debounce_ms(0);
    node.bloom_state.mark_update_needed(peer);
    let (logs, guard) = capture_logs_scoped();
    node.send_filter_announce_to_peer(&peer, filter.clone())
        .await
        .expect("the announce is sent");
    drop(guard);

    let sent = node
        .bloom_state
        .last_sent_filter(&peer)
        .expect("the send recorded the filter");
    assert_eq!(sent, &filter);
    let line = expect_line(&logs, "Sent FilterAnnounce");
    assert_eq!(field(&line, "digest"), filter_digest(sent), "{line}");

    cleanup_nodes(&mut nodes).await;
}

/// Deliver an announce of `filter` from `from` to `node`, with the next
/// sequence number, and return the line it logged.
async fn deliver_announce(node: &mut Node, from: &NodeAddr, filter: &BloomFilter) -> String {
    let seq = node.get_peer(from).expect("a peer").filter_sequence() + 1;
    let payload = FilterAnnounce::new(filter.clone(), seq).encode().unwrap();
    let (logs, guard) = capture_logs_scoped();
    node.handle_filter_announce(from, &payload[1..]).await;
    drop(guard);
    assert_eq!(
        node.get_peer(from).unwrap().inbound_filter(),
        Some(filter),
        "setup: the announce must be accepted"
    );
    expect_line(&logs, "Received FilterAnnounce")
}

#[tokio::test]
async fn a_child_returning_our_own_filter_logs_full_overlap_and_our_digest() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let (p, c) = root_and_other(&nodes);
    let child = *nodes[c].node.node_addr();
    let parent = &mut nodes[p].node;
    assert_eq!(role_of(parent, &child), "child", "precondition");
    let sent = parent
        .bloom_state
        .last_sent_filter(&child)
        .expect("precondition: the parent has sent its child a filter")
        .clone();

    // The child returns what we sent it, with itself added.
    let mut reflected = sent.clone();
    reflected.insert(&child);
    let line = deliver_announce(parent, &child, &reflected).await;
    assert_eq!(field(&line, "tree_role"), "child", "{line}");
    assert_eq!(
        field(&line, "overlap"),
        overlap_text(&reflected, &sent),
        "{line}"
    );
    let overlap: f64 = field(&line, "overlap").parse().expect("a number");
    assert!(overlap >= 0.9, "{line}");
    assert_eq!(field(&line, "digest"), filter_digest(&reflected), "{line}");

    // An honest subtree: addresses the parent never sent.
    let mut fresh = BloomFilter::new();
    for i in 0..200u16 {
        let mut bytes = [0xE0u8; 16];
        bytes[..2].copy_from_slice(&i.to_le_bytes());
        fresh.insert(&NodeAddr::from_bytes(bytes));
    }
    let line = deliver_announce(parent, &child, &fresh).await;
    assert_eq!(
        field(&line, "overlap"),
        overlap_text(&fresh, &sent),
        "{line}"
    );
    let low: f64 = field(&line, "overlap").parse().expect("a number");
    assert!(low < overlap, "{line}");
    assert_eq!(field(&line, "digest"), filter_digest(&fresh), "{line}");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_parent_announce_logs_the_parent_role_and_a_non_tree_peer_logs_no_overlap() {
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2), (0, 2)], false).await;
    // A node with a parent and a peer that is neither its parent nor child.
    let (x, parent, other) = nodes
        .iter()
        .enumerate()
        .find_map(|(i, tn)| {
            let roles = roles_from_show_peers(&tn.node);
            let parent = roles.iter().find(|(_, r)| *r == "parent")?.0.clone();
            let other = roles.iter().find(|(_, r)| *r == "none")?.0.clone();
            Some((i, parent, other))
        })
        .expect("precondition: a triangle leaves one node a non-tree peer");
    let addr_of = |hex_addr: &str| {
        let bytes: [u8; 16] = hex::decode(hex_addr).unwrap().try_into().unwrap();
        NodeAddr::from_bytes(bytes)
    };
    let (parent, other) = (addr_of(&parent), addr_of(&other));
    let node = &mut nodes[x].node;
    let sent = node
        .bloom_state
        .last_sent_filter(&parent)
        .expect("precondition: the node has sent its parent a filter")
        .clone();

    let mut from_parent = BloomFilter::new();
    from_parent.insert(&parent);
    from_parent.insert(&make_node_addr(0x51));
    let line = deliver_announce(node, &parent, &from_parent).await;
    assert_eq!(field(&line, "tree_role"), "parent", "{line}");
    assert_eq!(
        field(&line, "overlap"),
        overlap_text(&from_parent, &sent),
        "{line}"
    );
    assert_eq!(field(&line, "tree_peer"), "true", "{line}");

    let mut from_other = BloomFilter::new();
    from_other.insert(&other);
    let line = deliver_announce(node, &other, &from_other).await;
    assert_eq!(field(&line, "tree_role"), "none", "{line}");
    assert_eq!(field(&line, "overlap"), "none", "{line}");
    assert_eq!(field(&line, "tree_peer"), "false", "{line}");
    assert_eq!(field(&line, "digest"), filter_digest(&from_other), "{line}");

    cleanup_nodes(&mut nodes).await;
}

/// A transit request from an origin that is no node's peer.
fn transit_request(request_id: u64, target: NodeAddr) -> LookupRequest {
    let origin = make_node_addr(0x77);
    LookupRequest::new(
        request_id,
        target,
        origin,
        TreeCoordinate::root(origin),
        5,
        0,
    )
}

#[tokio::test]
async fn a_forwarded_lookup_names_its_sender_origin_and_recipients() {
    // node1 — node0 — node2: node 0 carries node 1's request on to node 2.
    let mut nodes = run_tree_test(3, &[(0, 1), (0, 2)], false).await;
    let node1 = *nodes[1].node.node_addr();
    let node2 = *nodes[2].node.node_addr();
    let request = transit_request(0x6833_0001, node2);
    let node = &mut nodes[0].node;

    let (logs, guard) = capture_logs_scoped();
    node.handle_lookup_request(&node1, &request.encode()[1..])
        .await;
    drop(guard);

    let line = expect_line(&logs, "Forwarding LookupRequest");
    assert_eq!(
        field(&line, "from"),
        node.peer_display_name(&node1),
        "{line}"
    );
    assert_eq!(
        field(&line, "origin"),
        node.peer_display_name(&make_node_addr(0x77)),
        "{line}"
    );
    assert_eq!(field(&line, "to"), node.peer_display_name(&node2), "{line}");
    assert_eq!(field(&line, "to_sender"), "false", "{line}");
    assert_eq!(field(&line, "peer_count"), "1", "{line}");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_lookup_whose_matching_tree_peers_include_its_sender_is_not_sent_back_to_it() {
    // node3 — node1 — node0 — node2. Node 3's filter at node 1 is made to
    // carry node 2, as a filter reflected back through a child would.
    let mut nodes = run_tree_test(4, &[(0, 1), (0, 2), (1, 3)], false).await;
    let node0 = *nodes[0].node.node_addr();
    let node2 = *nodes[2].node.node_addr();
    let node3 = *nodes[3].node.node_addr();
    let node = &mut nodes[1].node;
    assert!(node.is_tree_peer(&node0) && node.is_tree_peer(&node3));
    let peer3 = node.peers.get_mut(&node3).expect("node 3 is a peer");
    let mut reflected = peer3.inbound_filter().cloned().unwrap_or_default();
    reflected.insert(&node2);
    let seq = peer3.filter_sequence() + 1;
    peer3.update_filter(reflected, seq, Node::now_ms());
    assert!(
        node.get_peer(&node0).unwrap().may_reach(&node2),
        "precondition: node 0's filter at node 1 carries node 2"
    );

    let request = transit_request(0x6833_0002, node2);
    let (logs, guard) = capture_logs_scoped();
    node.handle_lookup_request(&node3, &request.encode()[1..])
        .await;
    drop(guard);

    let line = expect_line(&logs, "Forwarding LookupRequest");
    assert_eq!(
        field(&line, "from"),
        node.peer_display_name(&node3),
        "{line}"
    );
    assert_eq!(field(&line, "to"), node.peer_display_name(&node0), "{line}");
    assert_eq!(field(&line, "to_sender"), "false", "{line}");

    cleanup_nodes(&mut nodes).await;
}

/// A transit LookupResponse for `request_id`, encoded without its type byte.
fn response_payload(request_id: u64) -> Vec<u8> {
    let target = make_node_addr(0xBB);
    let coords = TreeCoordinate::from_addrs(vec![target, make_node_addr(0xF0)]).unwrap();
    let proof =
        Identity::generate().sign(&LookupResponse::proof_bytes(request_id, &target, &coords));
    LookupResponse::new(request_id, target, coords, proof).encode()[1..].to_vec()
}

/// A node with 64 registered peers, so one peer's share of the dedup cache
/// is the 64-entry floor, holding a full share of requests from `from` with
/// ids 1 to 64.
async fn node_with_full_share(from: &NodeAddr) -> Node {
    let mut node = unexpiring_node();
    register_peers(&mut node, 64);
    flood_requests(&mut node, from, 1, 64).await;
    assert_eq!(node.lookup.peer_entries(from), 64, "setup: a full share");
    node
}

#[tokio::test]
async fn a_dedup_eviction_logs_the_evicted_entrys_age_and_whether_it_was_answered() {
    let from = make_node_addr(0xAA);
    let start = Instant::now();
    let mut node = node_with_full_share(&from).await;
    // A response for request 1 goes back on its reverse path.
    node.handle_lookup_response(&make_node_addr(0xAB), &response_payload(1))
        .await;
    assert!(
        node.lookup.recent_requests[&1].response_forwarded,
        "setup: request 1 was answered"
    );

    let target = make_node_addr(0xBB);
    let (logs, guard) = capture_logs_scoped();
    node.handle_lookup_request(&from, &lookup_request_payload(65, &target))
        .await;
    drop(guard);
    let bound = start.elapsed().as_millis() as u64 + 1;
    let line = expect_line(
        &logs,
        "Lookup dedup cache full, evicting the oldest entry to make room",
    );
    assert_eq!(field(&line, "request_id"), "1", "{line}");
    assert_eq!(field(&line, "evicted_forwarded"), "true", "{line}");
    let age: u64 = field(&line, "evicted_age_ms").parse().expect("an integer");
    assert!(age <= bound, "{age} ms is longer than the test ran: {line}");

    let (logs, guard) = capture_logs_scoped();
    node.handle_lookup_request(&from, &lookup_request_payload(66, &target))
        .await;
    drop(guard);
    let line = expect_line(
        &logs,
        "Lookup dedup cache full, evicting the oldest entry to make room",
    );
    assert_eq!(field(&line, "request_id"), "2", "{line}");
    assert_eq!(field(&line, "evicted_forwarded"), "false", "{line}");
}

#[tokio::test]
async fn a_response_for_an_evicted_request_is_logged_as_evicted() {
    let from = make_node_addr(0xAA);
    let mut node = node_with_full_share(&from).await;
    let target = make_node_addr(0xBB);
    node.handle_lookup_request(&from, &lookup_request_payload(65, &target))
        .await;
    assert!(
        !node.lookup.recent_requests.contains_key(&1),
        "setup: request 1 was evicted"
    );

    let message = "LookupResponse does not match an outstanding request, dropping";
    let (logs, guard) = capture_logs_scoped();
    node.handle_lookup_response(&make_node_addr(0xAB), &response_payload(1))
        .await;
    drop(guard);
    let line = expect_line(&logs, message);
    assert_eq!(field(&line, "request_id"), "1", "{line}");
    assert_eq!(field(&line, "evicted_recently"), "true", "{line}");

    let (logs, guard) = capture_logs_scoped();
    node.handle_lookup_response(&make_node_addr(0xAB), &response_payload(9_999))
        .await;
    drop(guard);
    let line = expect_line(&logs, message);
    assert_eq!(field(&line, "evicted_recently"), "false", "{line}");
    assert!(log_field(&line, "request_id").is_some_and(|v| v == "9999"));
}
