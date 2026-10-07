//! The msg3 refusal for an identity whose sessions end without one
//! authenticated frame.
//!
//! A silent session is driven by hand at node 1 with node 0's identity: a
//! genuine XX msg1 and msg3 from a standalone initiator leg, with node 0
//! itself never processing anything, so node 1 promotes the session at msg3
//! and then hears nothing on it. Each attempt uses a fresh sender index and a
//! fresh ephemeral, as a real redial does. The link-dead reaper is driven by
//! a 0 s timeout and `check_link_heartbeats`.

use super::heartbeat::set_link_dead_timeout;
use super::spanning_tree::{TestNode, cleanup_nodes, drain_all_packets, initiate_handshake};
use super::*;
use crate::config::Config;
use crate::proto::fmp::NegotiationPayload;
use crate::proto::fmp::wire::{Msg2Header, build_msg1, build_msg3};
use crate::testutil::{capture_logs_scoped, log_field};
use crate::transport::ReceivedPacket;
use tokio::time::timeout;

/// Another startup epoch for node 0: a restart.
const NEW_EPOCH: [u8; 8] = [8u8; 8];

/// Two loopback nodes, node 1's reaper armed.
pub(super) async fn pair() -> Vec<TestNode> {
    let mut nodes = vec![
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
    ];
    set_link_dead_timeout(&mut nodes[1].node, 0);
    nodes
}

/// Discard everything queued at `tn` without processing it.
pub(super) fn discard(tn: &mut TestNode) {
    while tn.packet_rx.try_recv().is_ok() {}
}

/// Node 0's next packet of handshake `phase`, skipping anything else.
pub(super) async fn next_phase(tn: &mut TestNode, phase: u8) -> Option<ReceivedPacket> {
    loop {
        let pkt = timeout(Duration::from_millis(500), tn.packet_rx.recv())
            .await
            .ok()??;
        if pkt.data.first().is_some_and(|b| b & 0x0f == phase) {
            return Some(pkt);
        }
    }
}

/// Wrap `data` as a packet from node 0 arriving at node 1.
pub(super) fn from_node0(nodes: &[TestNode], data: Vec<u8>) -> ReceivedPacket {
    ReceivedPacket {
        transport_id: nodes[1].transport_id,
        remote_addr: nodes[0].addr.clone(),
        data,
        timestamp_ms: Node::now_ms(),
    }
}

/// A fresh XX initiator leg for node 0's identity at `epoch`, dialling node
/// 1, and the framed msg1 it sends under `index`.
pub(super) fn node0_initiator(
    nodes: &[TestNode],
    epoch: [u8; 8],
    index: u32,
) -> (PeerMachine, Vec<u8>) {
    let target = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let mut leg = outbound_leg(LinkId::new(0x5EED), target, 1000);
    let noise_msg1 = leg
        .start_handshake(nodes[0].node.identity().keypair(), epoch, 1000)
        .expect("start_handshake produces noise msg1");
    (leg, build_msg1(SessionIndex::new(index), &noise_msg1))
}

/// The framed msg3 `leg` answers node 1's framed `msg2` with, declaring no
/// rekey.
fn msg3_for(leg: &mut PeerMachine, msg2: &[u8], index: u32) -> Vec<u8> {
    let header = Msg2Header::parse(msg2).expect("msg2 header");
    let neg = NegotiationPayload::fmp(1, 1, crate::proto::fmp::NodeProfile::Full).encode();
    let (noise_msg3, _) = leg
        .complete_handshake(header.noise_msg2(msg2), Some(&neg), 1100)
        .expect("the initiator reads node 1's msg2");
    build_msg3(SessionIndex::new(index), header.sender_idx, &noise_msg3)
}

/// Run one handshake from node 0's identity at `epoch` to node 1 and stop
/// before any frame. Returns whether node 1 promoted it. Panics if node 1
/// does not answer the msg1.
async fn silent_session(nodes: &mut [TestNode], epoch: [u8; 8], index: u32) -> bool {
    let a = *nodes[0].node.node_addr();
    discard(&mut nodes[0]);
    let (mut leg, msg1) = node0_initiator(nodes, epoch, index);
    let packet = from_node0(nodes, msg1);
    nodes[1].node.handle_msg1(packet).await;
    let msg2 = next_phase(&mut nodes[0], 2)
        .await
        .expect("node 1 answers the msg1 with a msg2");
    let msg3 = msg3_for(&mut leg, &msg2.data, index);
    let packet = from_node0(nodes, msg3);
    nodes[1].node.handle_msg3(packet).await;
    nodes[1].node.get_peer(&a).is_some()
}

/// Reap node 1's silent session with node 0's identity.
async fn reap_node0(nodes: &mut [TestNode]) {
    let a = *nodes[0].node.node_addr();
    nodes[1].node.check_link_heartbeats().await;
    discard(&mut nodes[0]);
    assert!(
        nodes[1].node.get_peer(&a).is_none(),
        "the reaper removed it"
    );
}

/// `tn`'s silent-backoff and bad-state handshake reject counts.
fn handshake_counts(tn: &TestNode) -> (u64, u64) {
    let hs = &tn.node.stats().handshake;
    (hs.silent_backoff, hs.bad_state)
}

/// Three silent sessions of node 0 at its own epoch, each promoted and
/// reaped.
async fn three_reaped(nodes: &mut [TestNode]) {
    let epoch = nodes[0].node.startup_epoch();
    for index in 1..=3 {
        assert!(silent_session(nodes, epoch, index).await);
        reap_node0(nodes).await;
    }
}

#[tokio::test]
async fn three_silent_sessions_ended_by_link_dead_refuse_the_next_same_epoch_msg3_with_its_own_counter()
 {
    let mut nodes = pair().await;
    let a = *nodes[0].node.node_addr();
    three_reaped(&mut nodes).await;
    let (refused, bad) = handshake_counts(&nodes[1]);
    let epoch = nodes[0].node.startup_epoch();

    assert!(
        !silent_session(&mut nodes, epoch, 4).await,
        "the fourth msg3 was promoted"
    );
    let (refused_after, bad_after) = handshake_counts(&nodes[1]);
    assert_eq!(refused_after, refused + 1);
    assert_eq!(bad_after, bad, "the refusal is not counted as bad state");
    assert!(
        next_phase(&mut nodes[0], 2).await.is_none(),
        "a refused msg3 draws no msg2 resend"
    );
    assert!(
        nodes[1].node.peer_machines.is_empty(),
        "the refused leg is disposed"
    );
    assert_eq!(nodes[1].node.silent_sessions.count(&a), Some(3));

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_new_epoch_msg3_is_promoted_during_the_back_off() {
    let mut nodes = pair().await;
    let a = *nodes[0].node.node_addr();
    three_reaped(&mut nodes).await;

    assert!(silent_session(&mut nodes, NEW_EPOCH, 4).await);
    assert_eq!(
        nodes[1].node.get_peer(&a).unwrap().remote_epoch(),
        Some(NEW_EPOCH)
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_replayed_msg1_promotes_nothing_so_it_cannot_count_a_silent_session() {
    // On XX a session is promoted only on a msg3 bound to node 1's fresh
    // msg2, so a captured msg1 replayed after each reap draws a msg2 and
    // nothing else. This is why a session's setup digest is not recorded.
    let mut nodes = pair().await;
    let a = *nodes[0].node.node_addr();
    let epoch = nodes[0].node.startup_epoch();
    let (_, captured) = node0_initiator(&nodes, epoch, 1);
    for round in 0..3 {
        discard(&mut nodes[0]);
        let packet = from_node0(&nodes, captured.clone());
        nodes[1].node.handle_msg1(packet).await;
        assert!(
            next_phase(&mut nodes[0], 2).await.is_some(),
            "round {round}: node 1 answers the replay"
        );
        nodes[1].node.check_link_heartbeats().await;
        assert!(nodes[1].node.get_peer(&a).is_none(), "round {round}");
    }
    assert_eq!(nodes[1].node.silent_sessions.count(&a), None);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn one_authenticated_frame_clears_the_count_so_three_more_silent_sessions_are_needed() {
    let mut nodes = pair().await;
    let a = *nodes[0].node.node_addr();
    let epoch = nodes[0].node.startup_epoch();

    three_reaped(&mut nodes).await;
    assert!(
        !silent_session(&mut nodes, epoch, 4).await,
        "precondition: node 0's msg3s are refused"
    );

    // Node 1 dials node 0 while it refuses node 0's msg3s: its own dial
    // completes, and node 0's first frame on it clears the record.
    discard(&mut nodes[0]);
    initiate_handshake(&mut nodes, 1, 0).await;
    drain_all_packets(&mut nodes, false).await;
    let peer = nodes[1].node.get_peer(&a).expect("node 1's dial completed");
    assert!(peer.heard(), "node 0's frames reached node 1");
    assert_eq!(nodes[1].node.silent_sessions.count(&a), None);

    // A session that carried frames is not counted when it ends.
    nodes[1].node.remove_active_peer(&a);
    let b = *nodes[1].node.node_addr();
    nodes[0].node.remove_active_peer(&b);
    discard(&mut nodes[0]);
    discard(&mut nodes[1]);
    assert_eq!(nodes[1].node.silent_sessions.count(&a), None);

    // Two more silent sessions do not reach the limit again.
    for index in 5..=6 {
        assert!(silent_session(&mut nodes, epoch, index).await);
        reap_node0(&mut nodes).await;
    }
    assert!(
        silent_session(&mut nodes, epoch, 7).await,
        "the count went on from before the authenticated frame"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The line each refused msg3 logs.
const REFUSAL: &str =
    "Msg3 from a peer whose recent sessions carried no frame, refusing during its back-off";

#[tokio::test]
async fn refused_msg3s_during_a_back_off_log_three_lines_then_one_suppression_notice() {
    let mut nodes = pair().await;
    let a = *nodes[0].node.node_addr();
    three_reaped(&mut nodes).await;
    let (refused, _) = handshake_counts(&nodes[1]);
    let epoch = nodes[0].node.startup_epoch();

    let (logs, guard) = capture_logs_scoped();
    for index in 4..=11 {
        assert!(!silent_session(&mut nodes, epoch, index).await);
    }
    drop(guard);

    assert_eq!(logs.lines_with(REFUSAL).len(), 3, "{:#?}", logs.lines());
    let notices = logs.lines_with("Suppressing repeated handshake lines for this peer");
    assert_eq!(notices.len(), 1, "{:#?}", logs.lines());
    assert_eq!(log_field(&notices[0], "kind"), Some("refused"));
    assert_eq!(
        handshake_counts(&nodes[1]).0,
        refused + 8,
        "every refusal is counted"
    );
    assert!(nodes[1].node.get_peer(&a).is_none(), "nothing was promoted");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn the_first_frame_after_a_back_off_reports_how_many_refusal_lines_were_suppressed() {
    let mut nodes = pair().await;
    let a = *nodes[0].node.node_addr();
    let epoch = nodes[0].node.startup_epoch();
    three_reaped(&mut nodes).await;
    for index in 4..=8 {
        assert!(!silent_session(&mut nodes, epoch, index).await);
    }

    // Node 1's own dial completes, and node 0's first frame on it clears
    // the record that refused five handshakes.
    discard(&mut nodes[0]);
    let (logs, guard) = capture_logs_scoped();
    initiate_handshake(&mut nodes, 1, 0).await;
    drain_all_packets(&mut nodes, false).await;
    drop(guard);
    assert!(nodes[1].node.get_peer(&a).is_some_and(|p| p.heard()));

    let summaries = logs.lines_with("Suppressed repeated handshake lines");
    assert_eq!(summaries.len(), 1, "{:#?}", logs.lines());
    assert_eq!(log_field(&summaries[0], "refused"), Some("2"));

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn sessions_that_carried_a_frame_never_count_toward_the_back_off() {
    let mut nodes = vec![
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
        spanning_tree::make_test_node_with_config(Config::new(), 1280).await,
    ];
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();

    for round in 0..4 {
        initiate_handshake(&mut nodes, 0, 1).await;
        drain_all_packets(&mut nodes, false).await;
        let at_b = nodes[1].node.get_peer(&a);
        assert!(
            at_b.is_some(),
            "round {round}: node 1 promoted node 0's handshake"
        );
        assert!(at_b.unwrap().heard(), "round {round}: node 1 heard node 0");
        assert!(
            nodes[0].node.get_peer(&b).is_some_and(|p| p.heard()),
            "round {round}: node 0 heard node 1"
        );
        nodes[0].node.remove_active_peer(&b);
        nodes[1].node.remove_active_peer(&a);
        discard(&mut nodes[0]);
        discard(&mut nodes[1]);
    }
    assert_eq!(nodes[1].node.silent_sessions.count(&a), None);
    assert_eq!(nodes[0].node.silent_sessions.count(&b), None);
    assert_eq!(nodes[1].node.stats().handshake.silent_backoff, 0);

    cleanup_nodes(&mut nodes).await;
}
