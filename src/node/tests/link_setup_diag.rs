//! The link-setup lines carry the fields that let one node's log say where a
//! handshake message came from, which msg1 it was, and which session it
//! produced, and let two nodes' logs be joined line for line.
//!
//! Each test drives the condition a line reports through the real handler,
//! finds the line by its exact message, and checks the discriminating fields
//! against values derived independently: digests from the bytes that were
//! sent, session tags from the session the node holds afterwards, indices
//! and addresses from the packets themselves.

use super::spanning_tree::{
    TestNode, cleanup_nodes, initiate_handshake, make_test_node, process_available_packets,
};
use super::*;
use crate::noise::{HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE, NoiseSession};
use crate::proto::fmp::wire::{Msg1Header, build_msg1, build_msg2};
use crate::testutil::{LogCapture, capture_logs_scoped, log_field};
use sha2::{Digest, Sha256};

/// The first four bytes of `bytes` as 8 lowercase hex characters.
fn hex4(bytes: &[u8]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// The tag a line should carry for the msg1 whose wire bytes are `wire`.
fn msg1_tag(wire: &[u8]) -> String {
    hex4(&Sha256::digest(wire))
}

/// The tag a line should carry for `session`.
pub(super) fn session_tag(session: &NoiseSession) -> String {
    hex4(session.handshake_hash())
}

/// A session index as the lines display it.
pub(super) fn index_text(index: SessionIndex) -> String {
    format!("{:08x}", index.as_u32())
}

/// The line whose message is exactly `message`, or a panic listing every
/// captured line.
pub(super) fn expect_line(logs: &LogCapture, message: &str) -> String {
    logs.line(message)
        .unwrap_or_else(|| panic!("no line {message:?} in {:#?}", logs.lines()))
}

/// The value of `name` on `line`, or a panic naming the line.
pub(super) fn field(line: &str, name: &str) -> String {
    log_field(line, name)
        .unwrap_or_else(|| panic!("no field {name} on {line}"))
        .to_string()
}

/// Every captured line whose message is exactly `message`.
fn lines_with(logs: &LogCapture, message: &str) -> Vec<String> {
    let needle = format!(" message={message}");
    logs.lines()
        .into_iter()
        .filter(|line| {
            line.match_indices(&needle).any(|(at, _)| {
                let rest = &line[at + needle.len()..];
                rest.is_empty() || rest.starts_with(' ')
            })
        })
        .collect()
}

/// Run `node.handle_msg1(p)` with its log lines captured.
async fn msg1_logged(node: &mut Node, p: ReceivedPacket) -> LogCapture {
    let (logs, guard) = capture_logs_scoped();
    node.handle_msg1(p).await;
    drop(guard);
    logs
}

/// Run `node.handle_msg2(p)` with its log lines captured.
async fn msg2_logged(node: &mut Node, p: ReceivedPacket) -> LogCapture {
    let (logs, guard) = capture_logs_scoped();
    node.handle_msg2(p).await;
    drop(guard);
    logs
}

/// Two loopback nodes, node 0 having sent node 1 a msg1 that is taken out of
/// node 1's queue and returned. Node 0's leg keeps the msg1 it sent, as the
/// dial path does for its resends.
async fn dialled_pair() -> (Vec<TestNode>, ReceivedPacket) {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    initiate_handshake(&mut nodes, 0, 1).await;
    let msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's msg1 is queued at node 1");
    let leg = *nodes[0]
        .node
        .links
        .index()
        .get(&(nodes[0].transport_id, nodes[1].addr.clone()))
        .expect("node 0 holds its outbound leg");
    nodes[0]
        .node
        .peer_machines
        .get_mut(&leg)
        .expect("the leg's machine")
        .set_conn_handshake_msg1(msg1.data.clone(), 0);
    (nodes, msg1)
}

/// The link node 1 holds for the leg node 0's msg1 opened.
fn leg_link(nodes: &[TestNode], msg1: &ReceivedPacket) -> LinkId {
    *nodes[1]
        .node
        .links
        .index()
        .get(&(msg1.transport_id, msg1.remote_addr.clone()))
        .expect("node 1 holds a leg for the msg1's address")
}

/// A duplicate msg1 for a link still pending names the transport and the
/// link it resent the msg2 for.
#[tokio::test]
async fn a_duplicate_msg1_for_a_pending_inbound_link_logs_its_link() {
    let (mut nodes, msg1) = dialled_pair().await;
    nodes[1].node.handle_msg1(msg1.clone()).await;
    let link_id = leg_link(&nodes, &msg1);

    let logs = msg1_logged(&mut nodes[1].node, msg1.clone()).await;
    let line = expect_line(&logs, "Resent msg2 for duplicate msg1");
    assert_eq!(
        field(&line, "transport_id"),
        msg1.transport_id.to_string(),
        "{line}"
    );
    assert_eq!(field(&line, "link_id"), link_id.to_string(), "{line}");
    assert_eq!(
        field(&line, "remote_addr"),
        msg1.remote_addr.to_string(),
        "{line}"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The same resend, failing, names the transport and the link too.
#[tokio::test]
async fn a_failed_resend_to_a_pending_inbound_link_logs_its_link() {
    let (mut nodes, msg1) = dialled_pair().await;
    nodes[1].node.handle_msg1(msg1.clone()).await;
    let link_id = leg_link(&nodes, &msg1);
    // With node 0 gone, the loopback send of the resend fails.
    drop(nodes.remove(0));

    let logs = msg1_logged(&mut nodes[0].node, msg1.clone()).await;
    let line = expect_line(&logs, "Failed to resend msg2");
    assert_eq!(
        field(&line, "transport_id"),
        msg1.transport_id.to_string(),
        "{line}"
    );
    assert_eq!(field(&line, "link_id"), link_id.to_string(), "{line}");

    cleanup_nodes(&mut nodes).await;
}

/// A msg1 that fails the Noise step names where it came from.
#[tokio::test]
async fn a_msg1_that_fails_to_decrypt_logs_where_it_came_from() {
    let mut node = make_node();
    let tid = TransportId::new(7);
    let from = TransportAddr::from_string("10.0.0.2:2121");
    // 0xFF is not a valid public key prefix, so the Noise step rejects the
    // ephemeral key.
    let data = build_msg1(SessionIndex::new(5), &[0xFF; HANDSHAKE_MSG1_SIZE]);
    let p = ReceivedPacket {
        transport_id: tid,
        remote_addr: from,
        data,
        timestamp_ms: 1000,
    };
    let logs = msg1_logged(&mut node, p).await;

    let line = expect_line(&logs, "Failed to process msg1");
    assert_eq!(field(&line, "transport_id"), "transport:7", "{line}");
    assert_eq!(field(&line, "remote_addr"), "10.0.0.2:2121", "{line}");
}

/// A msg2 for an index with no pending handshake names where it came from.
#[tokio::test]
async fn a_msg2_for_an_unknown_index_logs_where_it_came_from() {
    let mut node = make_node();
    let tid = TransportId::new(7);
    let from = TransportAddr::from_string("10.0.0.2:2121");
    let data = build_msg2(
        SessionIndex::new(99),
        SessionIndex::new(42),
        &[0u8; HANDSHAKE_MSG2_SIZE],
    );
    let p = ReceivedPacket {
        transport_id: tid,
        remote_addr: from,
        data,
        timestamp_ms: 1000,
    };
    let logs = msg2_logged(&mut node, p).await;

    let line = expect_line(&logs, "No pending outbound handshake for index");
    assert_eq!(field(&line, "transport_id"), "transport:7", "{line}");
    assert_eq!(field(&line, "remote_addr"), "10.0.0.2:2121", "{line}");
    assert_eq!(field(&line, "receiver_idx"), "0000002a", "{line}");
}

/// The tag of the session `nodes[i]` holds for `nodes[j]`.
fn held_tag(nodes: &[TestNode], i: usize, j: usize) -> String {
    session_tag(
        nodes[i]
            .node
            .get_peer(nodes[j].node.node_addr())
            .and_then(|p| p.noise_session())
            .expect("a session is held"),
    )
}

/// When node 0 dials node 1, both promotion lines carry node 0's msg1 index
/// and digest and the same session tag, so the two logs join on them.
#[tokio::test]
async fn both_ends_log_the_same_msg1_and_session_tags_when_a_link_is_promoted() {
    let (mut nodes, msg1) = dialled_pair().await;
    let wire = msg1.data.clone();
    let a_index = Msg1Header::parse(&wire).expect("a msg1 header").sender_idx;

    let (logs, guard) = capture_logs_scoped();
    nodes[1].node.handle_msg1(msg1).await;
    for _ in 0..10 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    drop(guard);

    let lines = lines_with(&logs, "Connection promoted to active peer");
    assert_eq!(lines.len(), 2, "one promotion at each end: {lines:#?}");
    let a_line = lines
        .iter()
        .find(|l| field(l, "direction") == "outbound")
        .expect("node 0's outbound promotion");
    let b_line = lines
        .iter()
        .find(|l| field(l, "direction") == "inbound")
        .expect("node 1's inbound promotion");
    for (line, other) in [(b_line, &nodes[0].addr), (a_line, &nodes[1].addr)] {
        assert_eq!(field(line, "msg1_sidx"), index_text(a_index), "{line}");
        assert_eq!(field(line, "msg1_dg"), msg1_tag(&wire), "{line}");
        assert_eq!(field(line, "remote_addr"), other.to_string(), "{line}");
    }
    assert_eq!(
        field(a_line, "transport_id"),
        nodes[0].transport_id.to_string()
    );
    assert_eq!(
        field(b_line, "transport_id"),
        nodes[1].transport_id.to_string()
    );
    assert_eq!(field(b_line, "epoch"), held_tag(&nodes, 1, 0), "{b_line}");
    assert_eq!(field(a_line, "epoch"), held_tag(&nodes, 0, 1), "{a_line}");
    assert_eq!(field(a_line, "epoch"), field(b_line, "epoch"));

    cleanup_nodes(&mut nodes).await;
}

/// Both nodes dial each other, and node `r` reads the other node's msg3, which
/// promotes the other node's handshake inbound, before the msg2 that answers
/// its own msg1. The cross-connection then resolves at `r`'s msg2, whose lines
/// are returned with `r`'s msg1 as it went on the wire. Each outbound leg
/// keeps the msg1 it sent, as the dial path does.
async fn crossed_at_msg2(r: usize) -> (Vec<TestNode>, LogCapture, Vec<u8>) {
    let o = 1 - r;
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 0).await;
    let mut msg1s = Vec::new();
    for (from, to) in [(0, 1), (1, 0)] {
        let msg1 = nodes[to]
            .packet_rx
            .try_recv()
            .expect("each dial's msg1 is queued at the other node");
        let leg = *nodes[from]
            .node
            .links
            .index()
            .get(&(nodes[from].transport_id, nodes[to].addr.clone()))
            .expect("the dialling node holds its outbound leg");
        nodes[from]
            .node
            .peer_machines
            .get_mut(&leg)
            .expect("the leg's machine")
            .set_conn_handshake_msg1(msg1.data.clone(), 0);
        msg1s.push(msg1);
    }
    let r_msg1 = msg1s[r].clone();
    let o_msg1 = msg1s[o].clone();

    nodes[o].node.handle_msg1(r_msg1.clone()).await;
    nodes[r].node.handle_msg1(o_msg1).await;
    let held_msg2 = nodes[r]
        .packet_rx
        .try_recv()
        .expect("the msg2 answering r's msg1");
    let msg2 = nodes[o]
        .packet_rx
        .try_recv()
        .expect("the msg2 answering o's msg1");
    nodes[o].node.handle_msg2(msg2).await;
    let msg3 = nodes[r]
        .packet_rx
        .try_recv()
        .expect("o's msg3 for its own handshake");
    nodes[r].node.handle_msg3(msg3).await;
    assert!(
        nodes[r].node.get_peer(nodes[o].node.node_addr()).is_some(),
        "r promoted o's handshake before reading its own msg2"
    );

    let logs = msg2_logged(&mut nodes[r].node, held_msg2).await;
    for _ in 0..10 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    (nodes, logs, r_msg1.data)
}

/// A crossed pair, as `crossed_at_msg2(0)` builds it, in which node 0 has the
/// smaller address when `smaller` is set and the larger otherwise. Identities
/// are random, so the address order is only known once a pair exists; pairs
/// with the other order are discarded.
async fn crossed_at_node0(smaller: bool) -> (Vec<TestNode>, LogCapture, Vec<u8>) {
    for _ in 0..64 {
        let (mut nodes, logs, wire) = crossed_at_msg2(0).await;
        if (nodes[0].node.node_addr() < nodes[1].node.node_addr()) == smaller {
            return (nodes, logs, wire);
        }
        cleanup_nodes(&mut nodes).await;
    }
    panic!("64 random pairs all had the same address order");
}

/// A smaller node that resolves a cross-connection at msg2 swaps to its
/// outbound session. The swap line names its own msg1 and the session both
/// ends keep.
#[tokio::test]
async fn a_cross_connection_swapped_at_msg2_tags_its_msg1_and_the_surviving_session() {
    let (mut nodes, logs, wire) = crossed_at_node0(true).await;
    let line = expect_line(
        &logs,
        "Cross-connection: swapped to outbound session (our outbound wins)",
    );
    let index = Msg1Header::parse(&wire).expect("a msg1 header").sender_idx;

    assert_eq!(field(&line, "msg1_sidx"), index_text(index), "{line}");
    assert_eq!(field(&line, "msg1_dg"), msg1_tag(&wire), "{line}");
    assert_eq!(field(&line, "epoch"), held_tag(&nodes, 0, 1), "{line}");
    assert_eq!(held_tag(&nodes, 0, 1), held_tag(&nodes, 1, 0));
    assert_eq!(
        field(&line, "transport_id"),
        nodes[0].transport_id.to_string()
    );
    assert_eq!(field(&line, "remote_addr"), nodes[1].addr.to_string());

    cleanup_nodes(&mut nodes).await;
}

/// A larger node that resolves a cross-connection at msg2 keeps its inbound
/// session. The keep line tags the session both ends keep.
#[tokio::test]
async fn a_cross_connection_kept_at_msg2_tags_the_surviving_session() {
    let (mut nodes, logs, _) = crossed_at_node0(false).await;
    let line = expect_line(
        &logs,
        "Cross-connection: keeping inbound session and original their_index (peer outbound wins)",
    );

    assert_eq!(field(&line, "epoch"), held_tag(&nodes, 0, 1), "{line}");
    assert_eq!(held_tag(&nodes, 0, 1), held_tag(&nodes, 1, 0));
    assert_eq!(
        field(&line, "transport_id"),
        nodes[0].transport_id.to_string()
    );
    assert_eq!(field(&line, "remote_addr"), nodes[1].addr.to_string());

    cleanup_nodes(&mut nodes).await;
}
