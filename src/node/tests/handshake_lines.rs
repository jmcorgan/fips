//! Repeated handshake outcomes at msg3 are logged three times per peer and
//! session, then once as a notice, then only counted.

use super::silent_backoff::{discard, from_node0, next_phase, node0_initiator, pair};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;
use crate::peer::machine::PeerMachine;
use crate::proto::fmp::NegotiationPayload;
use crate::proto::fmp::wire::{Msg2Header, build_msg3};
use crate::testutil::{LogCapture, capture_logs_scoped, log_field};

/// A startup epoch node 0 never ran, to reach the restart gate.
const NEW_EPOCH: [u8; 8] = [8u8; 8];
/// The line each duplicate handshake's msg2 resend logs.
const RESEND: &str = "Resent msg2 for duplicate handshake (same epoch)";
/// The line each msg3 dropped by the restart gate logs.
const DAMPENED: &str = "Epoch mismatch dampened, dropping msg1";
/// The notice that replaces the first suppressed line.
const NOTICE: &str = "Suppressing repeated handshake lines for this peer";
/// The line that reports how many lines were suppressed.
const SUMMARY: &str = "Suppressed repeated handshake lines";

/// Node 0's framed msg3 under `index`, answering node 1's `msg2` on `leg`,
/// optionally declaring the handshake a rekey of node 1's session `rekey_of`.
fn msg3(leg: &mut PeerMachine, msg2: &[u8], index: u32, rekey_of: Option<SessionIndex>) -> Vec<u8> {
    let header = Msg2Header::parse(msg2).expect("msg2 header");
    let payload = NegotiationPayload::fmp(1, 1, crate::proto::fmp::NodeProfile::Full);
    let neg = match rekey_of {
        Some(idx) => payload.with_rekey_of(idx).encode(),
        None => payload.encode(),
    };
    let (noise_msg3, _) = leg
        .complete_handshake(header.noise_msg2(msg2), Some(&neg), 1100)
        .expect("the initiator reads node 1's msg2");
    build_msg3(SessionIndex::new(index), header.sender_idx, &noise_msg3)
}

/// One handshake of node 0's identity into node 1; whether node 1 sent a
/// further msg2 after the msg3.
async fn handshake(
    nodes: &mut [TestNode],
    epoch: [u8; 8],
    index: u32,
    rekey_of: Option<SessionIndex>,
) -> bool {
    discard(&mut nodes[0]);
    let (mut leg, m1) = node0_initiator(nodes, epoch, index);
    let p = from_node0(nodes, m1);
    nodes[1].node.handle_msg1(p).await;
    let m2 = next_phase(&mut nodes[0], 2).await.expect("msg2");
    let m3 = msg3(&mut leg, &m2.data, index, rekey_of);
    let p = from_node0(nodes, m3);
    nodes[1].node.handle_msg3(p).await;
    next_phase(&mut nodes[0], 2).await.is_some()
}

/// A rekey claim naming no session node 1 holds, so a duplicate handshake's
/// claim is a mismatch and node 1 resends its stored msg2.
const BAD: u32 = 0xBAD;

/// Two nodes with node 0's identity promoted at node 1 by one handshake at
/// node 0's startup epoch, the peer holding a stored msg2.
async fn promoted() -> Vec<TestNode> {
    let mut nodes = pair().await;
    let a = *nodes[0].node.node_addr();
    let epoch = nodes[0].node.startup_epoch();
    handshake(&mut nodes, epoch, 1, None).await;
    let peer = nodes[1].node.get_peer(&a).expect("promoted");
    assert!(peer.handshake_msg2().is_some());
    assert_ne!(peer.our_index(), Some(SessionIndex::new(BAD)));
    nodes
}

/// `n` same-epoch duplicate handshakes from node 0, msg1 indices from
/// `first`; how many drew a msg2 resend.
async fn duplicates(nodes: &mut [TestNode], first: u32, n: u32) -> u32 {
    let epoch = nodes[0].node.startup_epoch();
    let mut resent = 0;
    for i in 0..n {
        if handshake(nodes, epoch, first + i, Some(SessionIndex::new(BAD))).await {
            resent += 1;
        }
    }
    resent
}

/// Run node 1's heartbeat check, reaping node 0's peer, and return its logs.
async fn reap(nodes: &mut [TestNode]) -> LogCapture {
    let (logs, guard) = capture_logs_scoped();
    nodes[1].node.check_link_heartbeats().await;
    drop(guard);
    logs
}

#[tokio::test]
async fn repeated_duplicate_handshakes_log_three_resend_lines_then_one_suppression_notice() {
    let mut nodes = promoted().await;
    let a = *nodes[0].node.node_addr();
    let (link, idx) = {
        let p = nodes[1].node.get_peer(&a).unwrap();
        (p.link_id(), p.our_index())
    };
    let (logs, guard) = capture_logs_scoped();
    let resent = duplicates(&mut nodes, 10, 8).await;
    drop(guard);
    assert_eq!(resent, 8);
    assert_eq!(logs.lines_with(RESEND).len(), 3, "{:#?}", logs.lines());
    let n = logs.lines_with(NOTICE);
    assert_eq!(n.len(), 1, "{:#?}", logs.lines());
    assert_eq!(log_field(&n[0], "kind"), Some("resend"));
    let p = nodes[1].node.get_peer(&a).unwrap();
    assert_eq!(p.link_id(), link);
    assert_eq!(p.our_index(), idx);
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn repeated_dampened_epoch_changes_log_three_lines_then_one_notice() {
    let mut nodes = promoted().await;
    let a = *nodes[0].node.node_addr();
    let link = nodes[1].node.get_peer(&a).unwrap().link_id();
    let bad = nodes[1].node.stats().handshake.bad_state;
    let (logs, guard) = capture_logs_scoped();
    for i in 0..6 {
        nodes[1]
            .node
            .get_peer_mut(&a)
            .unwrap()
            .touch(Node::now_ms());
        handshake(&mut nodes, NEW_EPOCH, 20 + i, None).await;
    }
    drop(guard);
    assert_eq!(logs.lines_with(DAMPENED).len(), 3, "{:#?}", logs.lines());
    let n = logs.lines_with(NOTICE);
    assert_eq!(n.len(), 1, "{:#?}", logs.lines());
    assert_eq!(log_field(&n[0], "kind"), Some("restart"));
    assert_eq!(nodes[1].node.stats().handshake.bad_state, bad + 6);
    assert_eq!(nodes[1].node.get_peer(&a).unwrap().link_id(), link);
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn the_removal_of_a_peer_reports_how_many_handshake_lines_were_suppressed() {
    let mut nodes = promoted().await;
    duplicates(&mut nodes, 10, 8).await;
    let logs = reap(&mut nodes).await;
    let s = logs.lines_with(SUMMARY);
    assert_eq!(s.len(), 1, "{:#?}", logs.lines());
    assert_eq!(log_field(&s[0], "resend"), Some("5"));
    assert_eq!(log_field(&s[0], "resend_failed"), Some("0"));
    assert_eq!(log_field(&s[0], "restart"), Some("0"));
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_peer_with_three_duplicates_logs_each_and_its_removal_reports_nothing_suppressed() {
    let mut nodes = promoted().await;
    let (logs, guard) = capture_logs_scoped();
    duplicates(&mut nodes, 10, 3).await;
    drop(guard);
    assert_eq!(logs.lines_with(RESEND).len(), 3);
    assert!(logs.lines_with(NOTICE).is_empty());
    let logs = reap(&mut nodes).await;
    assert!(logs.lines_with(SUMMARY).is_empty(), "{:#?}", logs.lines());
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn suppressing_one_kind_does_not_hide_the_first_line_of_another() {
    let mut nodes = promoted().await;
    let a = *nodes[0].node.node_addr();
    duplicates(&mut nodes, 10, 8).await;
    nodes[1]
        .node
        .get_peer_mut(&a)
        .unwrap()
        .touch(Node::now_ms());
    let (logs, guard) = capture_logs_scoped();
    handshake(&mut nodes, NEW_EPOCH, 30, None).await;
    drop(guard);
    assert_eq!(logs.lines_with(DAMPENED).len(), 1, "{:#?}", logs.lines());
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn the_first_counted_line_after_a_session_change_follows_the_previous_sessions_summary() {
    let mut nodes = promoted().await;
    let a = *nodes[0].node.node_addr();
    duplicates(&mut nodes, 10, 5).await;
    nodes[1]
        .node
        .get_peer_mut(&a)
        .unwrap()
        .hs_lines_mut()
        .roll();
    let (logs, guard) = capture_logs_scoped();
    duplicates(&mut nodes, 20, 1).await;
    drop(guard);
    let lines = logs.lines();
    let s = lines
        .iter()
        .position(|l| l.contains(SUMMARY))
        .expect("summary");
    let r = lines
        .iter()
        .position(|l| l.contains(RESEND))
        .expect("resend");
    assert!(s < r, "{lines:#?}");
    assert_eq!(log_field(&lines[s], "resend"), Some("2"));
    cleanup_nodes(&mut nodes).await;
}
