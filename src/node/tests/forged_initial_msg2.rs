//! A msg2 that does not authenticate, or that authenticates under a static
//! other than the one dialed, must not end an initial (XX) dial.
//!
//! The index a msg2 names is our msg1's `sender_idx`, which travels in
//! cleartext, so anyone who saw the msg1 can send a msg2 under it. Under XX
//! the responder's static arrives in msg2, so any keyed node that saw the msg1
//! can also answer it with a msg2 that reads correctly under its own key (an
//! impostor). Either msg2 is discarded: the attempt keeps its handshake, its
//! expected identity, its resend schedule and its deadline, and the genuine
//! msg2 still completes it.

use super::*;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, initiate_handshake, make_test_node, process_available_packets,
};
use crate::noise::HANDSHAKE_MSG2_SIZE;
use crate::peer::machine::TimerKind;
use crate::proto::fmp::wire::{Msg1Header, Msg2Header, build_msg2};
use std::time::Duration;

/// Deliver queued packets until a round moves none, at most 50 rounds.
async fn pump_until_quiet(nodes: &mut [TestNode]) {
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if process_available_packets(nodes).await == 0 {
            break;
        }
    }
}

/// The msg2 a forger sends under the observed msg1 index.
#[derive(Debug, Clone, Copy)]
enum Forge {
    /// A full-length msg2 body that starts with a valid point and does not
    /// authenticate: the read reaches both DH operations before it fails.
    Garbage,
    /// A full-length msg2 body whose ephemeral is not a valid point.
    InvalidEphemeral,
    /// A real XX msg2 built by node 2, which took no part in the dial,
    /// answering the observed msg1 under its own static key.
    Impostor,
}

/// Node 2 forges a msg2 for node 0 under `observed`, the cleartext index read
/// off `msg1`, the dial's msg1 as it was seen on the wire.
async fn forge_msg2(
    nodes: &mut [TestNode],
    forge: Forge,
    msg1: &ReceivedPacket,
    observed: SessionIndex,
) -> ReceivedPacket {
    let noise = match forge {
        Forge::Garbage => {
            let mut noise = Identity::generate().pubkey_full().serialize().to_vec();
            noise.resize(HANDSHAKE_MSG2_SIZE, 0xA5);
            noise
        }
        Forge::InvalidEphemeral => vec![0xFF; HANDSHAKE_MSG2_SIZE],
        Forge::Impostor => {
            nodes[2].node.handle_msg1(msg1.clone()).await;
            let msg2 = tokio::time::timeout(Duration::from_secs(1), nodes[0].packet_rx.recv())
                .await
                .expect("the impostor answers the observed msg1")
                .expect("node 0's channel is open");
            assert_eq!(
                Msg2Header::parse(&msg2.data)
                    .expect("msg2 parses")
                    .receiver_idx,
                observed,
                "the impostor's msg2 names the observed index"
            );
            return msg2;
        }
    };
    ReceivedPacket::new(
        nodes[0].transport_id,
        nodes[2].addr.clone(),
        build_msg2(SessionIndex::new(0x5EED_F00D), observed, &noise),
    )
}

/// Run one dial from node 0 to node 1. With `forge`, deliver that msg2 to node
/// 0 after node 1 has answered and before node 1's genuine msg2 is read.
/// Report whether node 0 ended up with node 1 as an active peer.
async fn dial_with(forge: Option<Forge>) -> bool {
    let mut nodes = vec![
        make_test_node().await,
        make_test_node().await,
        make_test_node().await, // node 2 is the forger: it takes no part in the dial
    ];
    let node1_addr = *nodes[1].node.identity().node_addr();

    initiate_handshake(&mut nodes, 0, 1).await;

    // The forger reads the cleartext sender_idx off the msg1 on the wire.
    let msg1 = nodes[1].packet_rx.try_recv().expect("msg1 reached node 1");
    let observed = Msg1Header::parse(&msg1.data)
        .expect("msg1 parses")
        .sender_idx;

    // Node 1 answers; its genuine msg2 lands in node 0's channel. Hold it.
    nodes[1].node.handle_msg1(msg1.clone()).await;
    let genuine = nodes[0].packet_rx.try_recv().expect("genuine msg2 queued");

    if let Some(forge) = forge {
        let forged = forge_msg2(&mut nodes, forge, &msg1, observed).await;
        nodes[0].node.handle_msg2(forged).await;
    }

    nodes[0].node.handle_msg2(genuine).await;
    nodes[0].node.check_timeouts().await;
    pump_until_quiet(&mut nodes).await;

    let up = nodes[0].node.get_peer(&node1_addr).is_some();
    cleanup_nodes(&mut nodes).await;
    up
}

#[tokio::test]
async fn xx_initial_dial_completes_on_genuine_msg2_without_forgery() {
    assert!(dial_with(None).await, "the control dial must complete");
}

#[tokio::test]
async fn xx_garbage_initial_msg2_does_not_end_the_dial() {
    assert!(
        dial_with(Some(Forge::Garbage)).await,
        "node 0 must complete the dial on the genuine msg2 after a garbage one"
    );
}

#[tokio::test]
async fn xx_initial_msg2_with_an_invalid_ephemeral_does_not_end_the_dial() {
    assert!(
        dial_with(Some(Forge::InvalidEphemeral)).await,
        "node 0 must complete the dial on the genuine msg2 after one with an invalid ephemeral"
    );
}

#[tokio::test]
async fn xx_impostor_initial_msg2_does_not_end_the_dial() {
    assert!(
        dial_with(Some(Forge::Impostor)).await,
        "node 0 must complete the dial on the genuine msg2 after an impostor's"
    );
}

/// What a dial looks like from node 0 at one instant.
#[derive(Debug, PartialEq, Eq)]
struct Attempt {
    link: LinkId,
    handshake_held: bool,
    has_session: bool,
    expected: Option<NodeAddr>,
    remote_epoch: Option<[u8; 8]>,
    resend_count: u32,
    retransmit_at: Option<u64>,
    timeout_at: Option<u64>,
    last_activity: u64,
}

fn attempt(node: &Node, link: LinkId) -> Attempt {
    let machine = node.peer_machines.get(&link).expect("the dial's machine");
    let timers = node.peer_timers.get(&link);
    Attempt {
        link,
        handshake_held: machine
            .leg()
            .is_some_and(|leg| leg.noise_handshake.is_some()),
        has_session: machine.has_session(),
        expected: machine.conn_expected_identity().map(|id| *id.node_addr()),
        remote_epoch: machine.conn_remote_epoch(),
        resend_count: machine.resend_count(),
        retransmit_at: timers.and_then(|t| t.get(&TimerKind::HandshakeRetransmit).copied()),
        timeout_at: timers.and_then(|t| t.get(&TimerKind::HandshakeTimeout).copied()),
        last_activity: machine.conn_last_activity(),
    }
}

/// Node 0 dials node 1 through its own dial path, which stores the msg1 and
/// arms the resend and timeout timers. Returns the nodes, the dial's link, the
/// msg1 as it reached node 1 (left unanswered) and its cleartext index.
async fn dial_unanswered() -> (Vec<TestNode>, LinkId, ReceivedPacket, SessionIndex) {
    let mut nodes = vec![
        make_test_node().await,
        make_test_node().await,
        make_test_node().await,
    ];
    let node1 = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    nodes[0]
        .node
        .initiate_connection(tid, addr, Some(node1))
        .await
        .expect("node 0 dials node 1");

    let msg1 = tokio::time::timeout(Duration::from_secs(1), nodes[1].packet_rx.recv())
        .await
        .expect("the msg1 reaches node 1")
        .expect("node 1's channel is open");
    let observed = Msg1Header::parse(&msg1.data)
        .expect("msg1 parses")
        .sender_idx;
    let link = *nodes[0]
        .node
        .pending_outbound
        .get(&(tid, observed.as_u32()))
        .expect("the dial is registered under its msg1 index");
    (nodes, link, msg1, observed)
}

/// A forged msg2 leaves the attempt exactly as it was, and the msg1 resend
/// still fires at the time it was armed for, as a resend of the same msg1 on
/// the same attempt rather than a new dial.
async fn forged_msg2_leaves_the_resend_schedule(forge: Forge) {
    let (mut nodes, link, msg1, observed) = dial_unanswered().await;
    let before = attempt(&nodes[0].node, link);
    assert!(before.handshake_held, "the dial holds its handshake");
    let resend_at = before.retransmit_at.expect("the dial arms a msg1 resend");

    let forged = forge_msg2(&mut nodes, forge, &msg1, observed).await;
    nodes[0].node.handle_msg2(forged).await;
    nodes[0].node.check_timeouts().await;

    assert!(
        nodes[0].node.peer_machines.contains_key(&link),
        "the forged msg2 must not end the attempt"
    );
    assert_eq!(
        attempt(&nodes[0].node, link),
        before,
        "the forged msg2 must leave the attempt exactly as it was"
    );

    nodes[0].node.drive_peer_timers(resend_at).await;
    let resent = tokio::time::timeout(Duration::from_secs(1), nodes[1].packet_rx.recv())
        .await
        .expect("the msg1 is resent at its scheduled time")
        .expect("node 1's channel is open");
    assert_eq!(
        resent.data, msg1.data,
        "the resend is the attempt's own msg1"
    );
    assert_eq!(
        attempt(&nodes[0].node, link).resend_count,
        before.resend_count + 1
    );
    assert_eq!(
        nodes[0].node.pending_outbound.len(),
        1,
        "the resend belongs to the same attempt"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_garbage_initial_msg2_leaves_the_resend_schedule_as_it_was() {
    forged_msg2_leaves_the_resend_schedule(Forge::Garbage).await;
}

#[tokio::test]
async fn an_impostor_initial_msg2_leaves_the_resend_schedule_as_it_was() {
    forged_msg2_leaves_the_resend_schedule(Forge::Impostor).await;
}

/// Returns whether the dial is still in progress just at its handshake
/// timeout and just after it, measured from the dial's last activity before
/// any forgery, on the interval clock the timeout reads.
async fn alive_at_and_after_deadline(forge: Option<Forge>) -> (bool, bool) {
    let (mut nodes, link, msg1, observed) = dial_unanswered().await;
    let last_activity = nodes[0].node.peer_machines[&link].conn_active_at();
    let timeout_ms = nodes[0]
        .node
        .config()
        .node
        .rate_limit
        .handshake_timeout_secs
        * 1000;

    if let Some(forge) = forge {
        let forged = forge_msg2(&mut nodes, forge, &msg1, observed).await;
        nodes[0].node.handle_msg2(forged).await;
    }
    // The ordinary sweep, which reaps failed legs at once.
    nodes[0].node.check_timeouts().await;

    nodes[0]
        .node
        .drive_peer_timers(last_activity + timeout_ms)
        .await;
    let at = nodes[0].node.peer_machines.contains_key(&link);
    nodes[0]
        .node
        .drive_peer_timers(last_activity + timeout_ms + 1)
        .await;
    let after = nodes[0].node.peer_machines.contains_key(&link);
    cleanup_nodes(&mut nodes).await;
    (at, after)
}

#[tokio::test]
async fn a_garbage_initial_msg2_leaves_the_handshake_deadline_as_it_was() {
    let unforged = alive_at_and_after_deadline(None).await;
    assert_eq!(
        unforged,
        (true, false),
        "an unanswered dial ends at its deadline"
    );
    assert_eq!(
        alive_at_and_after_deadline(Some(Forge::Garbage)).await,
        unforged,
        "a garbage msg2 must neither end the dial early nor extend it"
    );
}

#[tokio::test]
async fn an_impostor_initial_msg2_leaves_the_handshake_deadline_as_it_was() {
    let unforged = alive_at_and_after_deadline(None).await;
    assert_eq!(
        unforged,
        (true, false),
        "an unanswered dial ends at its deadline"
    );
    assert_eq!(
        alive_at_and_after_deadline(Some(Forge::Impostor)).await,
        unforged,
        "an impostor's msg2 must neither end the dial early nor extend it"
    );
}

/// An impostor's msg2 must not put the impostor's identity on the dial, and
/// must not get a msg3 back: its handshake is never completed.
#[tokio::test]
async fn an_impostor_initial_msg2_keeps_the_dialed_identity_and_gets_no_msg3() {
    let (mut nodes, link, msg1, observed) = dial_unanswered().await;
    let node1_addr = *nodes[1].node.identity().node_addr();
    let node2_addr = *nodes[2].node.identity().node_addr();

    let forged = forge_msg2(&mut nodes, Forge::Impostor, &msg1, observed).await;
    nodes[0].node.handle_msg2(forged).await;

    let machine = nodes[0]
        .node
        .peer_machines
        .get(&link)
        .expect("the impostor's msg2 must not end the attempt");
    assert_eq!(
        machine.conn_expected_identity().map(|id| *id.node_addr()),
        Some(node1_addr),
        "the dial still expects the peer it named"
    );
    assert!(
        !machine.has_session(),
        "no session is made with the impostor"
    );
    assert!(
        nodes[0].node.get_peer(&node2_addr).is_none(),
        "the impostor must not enter the peer set"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(250), nodes[2].packet_rx.recv())
            .await
            .is_err(),
        "no msg3 may be sent to the impostor"
    );
    cleanup_nodes(&mut nodes).await;
}
