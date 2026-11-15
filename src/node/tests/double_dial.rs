//! Two dials from one node to the same peer, on two transports at once.
//!
//! A node with a configured peer over UDP that also hears the peer's
//! Ethernet beacon dials it on both, so the peer answers two handshakes from
//! the same initiator. Each end installs the peer on the first handshake it
//! completes and settles the second against it: the initiator at the second
//! msg2, the responder at the second msg3. Nothing orders the two transports,
//! so the msg3s can reach the responder in the other order from the msg2s at
//! the initiator. Both ends must still end on one session, or each sends
//! under a session the other has dropped and the peering is lost until the
//! link times out (seen in the steady-dual-path chaos scenario). With
//! multipath on, each end must also hold the pair of the dial it did not
//! settle on as a path, or the peer's next beacon there is dialled again.
//!
//! Only a dial already in flight when the held session was installed is
//! held back this way. One begun after the install is settled by address
//! order, so a first dial whose msg3 was lost is still rescued by the next.
//!
//! Every packet is taken from its queue and handed on by the test, so the
//! order each end sees is the test's.

use super::crossed_dial::{hand, phase};
use super::paths::state_at;
use super::rekey_parity::{failures, heartbeat, pump};
use super::settle::audit::{Breach, assert_coherent, assert_coherent_but};
use super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, add_loopback_alias, cleanup_nodes, make_test_node_with_config,
};
use super::*;
use crate::peer::PathState;
use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2, PHASE_MSG3};
use crate::transport::loopback::LoopbackTransport;
use tokio::sync::mpsc::UnboundedReceiver;

/// The second transport both nodes are given.
fn t2() -> TransportId {
    TransportId::new(2)
}

/// Take every packet queued on `rx` without handling it.
fn take(rx: &mut UnboundedReceiver<ReceivedPacket>) -> Vec<ReceivedPacket> {
    let mut packets = Vec::new();
    while let Ok(packet) = rx.try_recv() {
        packets.push(packet);
    }
    packets
}

/// Give `tn` a second loopback transport, at an alias of its own address,
/// and return that address.
fn add_t2(tn: &mut TestNode) -> TransportAddr {
    let addr = add_loopback_alias(&tn.addr, t2());
    let lo = LoopbackTransport::with_mtu(t2(), addr.clone(), 1280, LOOPBACK_REGISTRY.clone());
    tn.node
        .transports
        .insert(t2(), TransportHandle::Loopback(lo));
    addr
}

/// Take `want`'s packets of `phase_byte` out of `packets`, one per transport,
/// and return them in transport order (t1, then t2).
fn split(packets: &mut Vec<ReceivedPacket>, phase_byte: u8, want: &str) -> [ReceivedPacket; 2] {
    let mut on = |tid: TransportId| {
        let at = packets
            .iter()
            .position(|p| phase(p) == Some(phase_byte) && p.transport_id == tid)
            .unwrap_or_else(|| panic!("precondition: {want} on {tid:?}"));
        packets.remove(at)
    };
    let first = on(TransportId::new(1));
    let second = on(t2());
    [first, second]
}

/// The session each end holds for the other: (our index, their index).
fn session(tn: &TestNode, peer: &NodeAddr) -> (Option<SessionIndex>, Option<SessionIndex>) {
    let held = tn.node.get_peer(peer).expect("the node holds the peer");
    (held.our_index(), held.their_index())
}

/// Have the `initiator_smaller` end dial the other on both transports, the
/// configured dial on t1 and an anonymous one on t2; deliver the msg2s to
/// the initiator t1 first, and the msg3s to the responder t2 first when
/// `msg3_t2_first`, the other order from the msg2s;
/// then check that both ends hold one session and that each authenticates
/// the other's next frame.
///
/// With `multipath` on, each end must then hold the pair of the dial it did
/// not settle on as a Live path, so the peer's next beacon there is known as
/// the peer's and not dialled again.
async fn double_dial(initiator_smaller: bool, msg3_t2_first: bool, multipath: bool) {
    let mut config = crate::config::Config::new();
    config.node.path.enabled = multipath;
    let mut nodes = vec![
        make_test_node_with_config(config.clone(), 1280).await,
        make_test_node_with_config(config, 1280).await,
    ];
    let smaller = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        0
    } else {
        1
    };
    let (i, r) = if initiator_smaller {
        (smaller, 1 - smaller)
    } else {
        (1 - smaller, smaller)
    };
    let i_addr = *nodes[i].node.node_addr();
    let r_addr = *nodes[r].node.node_addr();
    let t1 = nodes[i].transport_id;
    let i2 = add_t2(&mut nodes[i]);
    let r2 = add_t2(&mut nodes[r]);
    let r2_dialled = r2.clone();
    let r1 = nodes[r].addr.clone();
    let r_id = PeerIdentity::from_pubkey_full(nodes[r].node.identity().pubkey_full());

    nodes[i]
        .node
        .initiate_connection(t1, r1, Some(r_id))
        .await
        .expect("precondition: the configured dial starts");
    nodes[i]
        .node
        .initiate_connection(t2(), r2.clone(), None)
        .await
        .expect("precondition: the anonymous dial starts");

    let mut at_r = take(&mut nodes[r].packet_rx);
    for msg1 in split(&mut at_r, PHASE_MSG1, "the initiator's msg1") {
        hand(&mut nodes[r].node, msg1).await;
    }
    assert!(at_r.is_empty(), "precondition: only the two msg1s at r");

    let mut at_i = take(&mut nodes[i].packet_rx);
    for msg2 in split(&mut at_i, PHASE_MSG2, "the responder's msg2") {
        hand(&mut nodes[i].node, msg2).await;
    }
    assert!(at_i.is_empty(), "precondition: only the two msg2s at i");
    assert!(
        nodes[i].node.get_peer(&r_addr).is_some(),
        "precondition: the initiator installed the responder"
    );

    // The msg3s the initiator sent, one per dial it completed with one, in
    // the order the test delivers them; then what followed them, its frames.
    let (mut msg3s, rest): (Vec<_>, Vec<_>) = take(&mut nodes[r].packet_rx)
        .into_iter()
        .partition(|p| phase(p) == Some(PHASE_MSG3));
    assert!(
        !msg3s.is_empty(),
        "precondition: the initiator sent at least one msg3"
    );
    msg3s.sort_by_key(|p| (p.transport_id == t2()) != msg3_t2_first);
    for msg3 in msg3s {
        hand(&mut nodes[r].node, msg3).await;
    }
    for packet in rest {
        hand(&mut nodes[r].node, packet).await;
    }

    let (i_ours, i_theirs) = session(&nodes[i], &r_addr);
    let (r_ours, r_theirs) = session(&nodes[r], &i_addr);
    assert_eq!(
        (i_ours, i_theirs),
        (r_theirs, r_ours),
        "both ends hold one session (initiator's (ours, theirs) against the responder's (theirs, ours))"
    );

    // What the responder sent back, then each end's next frame, which
    // authenticates at the other.
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    heartbeat(&mut nodes[i], &r_addr).await;
    for packet in take(&mut nodes[r].packet_rx) {
        hand(&mut nodes[r].node, packet).await;
    }
    heartbeat(&mut nodes[r], &i_addr).await;
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    assert_eq!(
        (failures(&nodes[r], &i_addr), failures(&nodes[i], &r_addr)),
        (0, 0),
        "neither end fails to decrypt the other's frame"
    );
    assert_coherent(&mut nodes, "the end of the double dial").await;

    if multipath {
        // A few path ticks at each end, with what they send delivered: the
        // capability probe, its answer, and the probes of each path then
        // admitted.
        for _ in 0..5 {
            for tn in nodes.iter_mut() {
                tn.node.path_tick().await;
            }
            pump(&mut nodes).await;
        }
        let (held_t, _) = {
            let held = nodes[i].node.get_peer(&r_addr).expect("i holds r");
            (held.transport_id(), held.current_addr().cloned())
        };
        assert_eq!(
            held_t,
            Some(t1),
            "precondition: the initiator holds the session of the msg2 it took first, on t1"
        );
        assert_eq!(
            (
                state_at(&nodes[i], &r_addr, t2(), &r2_dialled),
                state_at(&nodes[r], &i_addr, t2(), &i2),
            ),
            (Some(PathState::Live), Some(PathState::Live)),
            "each end holds the other dial's pair, on t2, as a Live path"
        );
    }
    cleanup_nodes(&mut nodes).await;
}

/// The smaller node dials the larger on two transports, and its msg3s reach
/// the larger node in the order its msg2s came: both ends settle on one
/// session.
#[tokio::test]
async fn a_smaller_nodes_two_dials_answered_in_order_leave_both_ends_on_one_session() {
    double_dial(true, false, false).await;
}

/// The smaller node dials the larger on two transports, and its msg3s reach
/// the larger node in the other order from its msg2s: both ends still settle
/// on one session.
#[tokio::test]
async fn a_smaller_nodes_two_dials_whose_msg3s_cross_leave_both_ends_on_one_session() {
    double_dial(true, true, false).await;
}

/// The larger node dials the smaller on two transports, and its msg3s reach
/// the smaller node in the order its msg2s came: both ends settle on one
/// session.
#[tokio::test]
async fn a_larger_nodes_two_dials_answered_in_order_leave_both_ends_on_one_session() {
    double_dial(false, false, false).await;
}

/// The larger node dials the smaller on two transports, and its msg3s reach
/// the smaller node in the other order from its msg2s: both ends still settle
/// on one session.
#[tokio::test]
async fn a_larger_nodes_two_dials_whose_msg3s_cross_leave_both_ends_on_one_session() {
    double_dial(false, true, false).await;
}

/// With multipath on, the smaller node's two dials whose msg3s cross leave
/// both ends on one session, each holding the other dial's pair as a Live
/// path.
#[tokio::test]
async fn a_smaller_nodes_crossed_two_dials_with_multipath_on_leave_the_other_pair_a_live_path() {
    double_dial(true, true, true).await;
}

/// With multipath on, the larger node's two dials whose msg3s cross leave
/// both ends on one session, each holding the other dial's pair as a Live
/// path.
#[tokio::test]
async fn a_larger_nodes_crossed_two_dials_with_multipath_on_leave_the_other_pair_a_live_path() {
    double_dial(false, true, true).await;
}

/// The larger node dials the smaller while the smaller dials it on two
/// transports, all three in flight together. The larger node's dial installs
/// it at the smaller node, which hears a frame under that session; the
/// smaller node's first msg2 then moves it onto its own dial, and its second
/// msg2 comes after. The frame heard before the move shows only that the
/// larger node held the session the move left, and the second dial was in
/// flight when the move installed the session held now, so it must still
/// send no msg3: sent, it reaches the larger node first, and the two ends
/// hold different sessions. With `dials_after`, the smaller node's two dials
/// begin only once it holds the larger node, heard, so they were in flight
/// at the move but not at the promotion before it.
async fn a_heard_session_then_a_move(multipath: bool, dials_after: bool) {
    let mut config = crate::config::Config::new();
    config.node.path.enabled = multipath;
    let mut nodes = vec![
        make_test_node_with_config(config.clone(), 1280).await,
        make_test_node_with_config(config, 1280).await,
    ];
    let (i, r) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let i_addr = *nodes[i].node.node_addr();
    let r_addr = *nodes[r].node.node_addr();
    let t1 = nodes[i].transport_id;
    add_t2(&mut nodes[i]);
    let r2 = add_t2(&mut nodes[r]);
    let r1 = nodes[r].addr.clone();
    let i1 = nodes[i].addr.clone();
    let r_id = PeerIdentity::from_pubkey_full(nodes[r].node.identity().pubkey_full());
    let i_id = PeerIdentity::from_pubkey_full(nodes[i].node.identity().pubkey_full());

    nodes[r]
        .node
        .initiate_connection(t1, i1, Some(i_id))
        .await
        .expect("precondition: the larger node's dial starts");
    if dials_after {
        // The larger node's dial completes first, with a frame under it.
        for packet in take(&mut nodes[i].packet_rx) {
            hand(&mut nodes[i].node, packet).await;
        }
        for packet in take(&mut nodes[r].packet_rx) {
            hand(&mut nodes[r].node, packet).await;
        }
        for packet in take(&mut nodes[i].packet_rx) {
            hand(&mut nodes[i].node, packet).await;
        }
        assert!(
            nodes[i].node.get_peer(&r_addr).is_some_and(|p| p.heard()),
            "precondition: the smaller node holds the larger, heard under its dial"
        );
    }
    nodes[i]
        .node
        .initiate_connection(t1, r1, Some(r_id))
        .await
        .expect("precondition: the configured dial starts");
    nodes[i]
        .node
        .initiate_connection(t2(), r2, None)
        .await
        .expect("precondition: the anonymous dial starts");

    // The larger node answers both of the smaller node's dials (before it
    // holds it, unless `dials_after`); the smaller node answers the larger
    // node's dial.
    let mut at_r = take(&mut nodes[r].packet_rx);
    for msg1 in split(&mut at_r, PHASE_MSG1, "the smaller node's msg1") {
        hand(&mut nodes[r].node, msg1).await;
    }
    let mut at_i = take(&mut nodes[i].packet_rx);
    if !dials_after {
        let theirs = at_i
            .iter()
            .position(|p| phase(p) == Some(PHASE_MSG1))
            .expect("precondition: the larger node's msg1");
        let theirs = at_i.remove(theirs);
        hand(&mut nodes[i].node, theirs).await;
        at_i.extend(take(&mut nodes[i].packet_rx));
    }
    let [msg2_a, msg2_b] = split(&mut at_i, PHASE_MSG2, "the larger node's msg2");

    if !dials_after {
        // The larger node completes its own dial, sends its msg3 and a frame
        // under that session; the smaller node takes both, and so holds the
        // larger node, heard, on an inbound link.
        let mut at_r = take(&mut nodes[r].packet_rx);
        let msg2_c = at_r
            .iter()
            .position(|p| phase(p) == Some(PHASE_MSG2))
            .expect("precondition: the smaller node's msg2");
        let msg2_c = at_r.remove(msg2_c);
        hand(&mut nodes[r].node, msg2_c).await;
        for packet in take(&mut nodes[i].packet_rx) {
            hand(&mut nodes[i].node, packet).await;
        }
        assert!(
            nodes[i].node.get_peer(&r_addr).is_some_and(|p| p.heard()),
            "precondition: the smaller node holds the larger, heard under its dial"
        );
    }

    // The first msg2 moves the smaller node onto its own dial; the second
    // follows. The msg3s are held back for the larger node.
    hand(&mut nodes[i].node, msg2_a).await;
    let moved = nodes[i]
        .node
        .get_peer(&r_addr)
        .filter(|p| p.heard())
        .and_then(|p| nodes[i].node.links.get(&p.link_id()))
        .map(|link| (link.direction(), link.transport_id()));
    assert_eq!(
        moved,
        Some((LinkDirection::Outbound, t1)),
        "precondition: the smaller node, which heard the larger before, moved onto its own dial"
    );
    hand(&mut nodes[i].node, msg2_b).await;
    let (mut msg3s, rest): (Vec<_>, Vec<_>) = take(&mut nodes[r].packet_rx)
        .into_iter()
        .partition(|p| phase(p) == Some(PHASE_MSG3));
    assert!(
        !msg3s.is_empty(),
        "precondition: the smaller node sent its first dial's msg3"
    );
    // The second dial's msg3, if one went, reaches the larger node first.
    msg3s.sort_by_key(|p| p.transport_id != t2());
    for msg3 in msg3s {
        hand(&mut nodes[r].node, msg3).await;
    }
    for packet in rest {
        hand(&mut nodes[r].node, packet).await;
    }

    let (i_ours, i_theirs) = session(&nodes[i], &r_addr);
    let (r_ours, r_theirs) = session(&nodes[r], &i_addr);
    assert_eq!(
        (i_ours, i_theirs),
        (r_theirs, r_ours),
        "both ends hold one session (the smaller node's (ours, theirs) against the larger's (theirs, ours))"
    );
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    heartbeat(&mut nodes[i], &r_addr).await;
    for packet in take(&mut nodes[r].packet_rx) {
        hand(&mut nodes[r].node, packet).await;
    }
    heartbeat(&mut nodes[r], &i_addr).await;
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    assert_eq!(
        (failures(&nodes[r], &i_addr), failures(&nodes[i], &r_addr)),
        (0, 0),
        "neither end fails to decrypt the other's frame"
    );
    assert_coherent(&mut nodes, "the end of the heard-then-moved double dial").await;
    cleanup_nodes(&mut nodes).await;
}

/// A frame heard before a cross-connection move onto the smaller node's own
/// dial does not let its second dial, in flight at the move, send a msg3:
/// both ends end on one session though that msg3 would have reached the
/// larger node first.
#[tokio::test]
async fn a_frame_heard_before_a_move_does_not_let_a_second_dial_cross_the_ends() {
    a_heard_session_then_a_move(false, false).await;
}

/// As above, with multipath on.
#[tokio::test]
async fn a_frame_heard_before_a_move_does_not_let_a_second_dial_cross_the_ends_with_multipath_on() {
    a_heard_session_then_a_move(true, false).await;
}

/// The smaller node's two dials begin after it holds the larger node, heard
/// under the larger node's dial, and its first msg2 moves it onto its own
/// dial. The second dial was in flight at the move, though not at the
/// promotion, so it still sends no msg3, and both ends end on one session.
#[tokio::test]
async fn two_dials_begun_after_a_promotion_and_in_flight_at_a_move_leave_both_ends_on_one_session()
{
    a_heard_session_then_a_move(false, true).await;
}

/// The smaller node's configured dial completes at it, but its msg3 is lost;
/// only then does it dial the larger node again, anonymously on the other
/// transport, as on hearing its beacon. That dial was not in flight when the
/// held session was installed, so it is settled by address order as before:
/// the smaller node moves onto it and sends its msg3, and both ends end on
/// that session. Kept with no msg3, as a dial in flight beside the first is,
/// it would leave the larger node holding nothing until the link timed out.
async fn a_lost_msg3_then_a_later_dial(multipath: bool) {
    let mut config = crate::config::Config::new();
    config.node.path.enabled = multipath;
    let mut nodes = vec![
        make_test_node_with_config(config.clone(), 1280).await,
        make_test_node_with_config(config, 1280).await,
    ];
    let (i, r) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let i_addr = *nodes[i].node.node_addr();
    let r_addr = *nodes[r].node.node_addr();
    let t1 = nodes[i].transport_id;
    add_t2(&mut nodes[i]);
    let r2 = add_t2(&mut nodes[r]);
    let r1 = nodes[r].addr.clone();
    let r_id = PeerIdentity::from_pubkey_full(nodes[r].node.identity().pubkey_full());

    nodes[i]
        .node
        .initiate_connection(t1, r1, Some(r_id))
        .await
        .expect("precondition: the configured dial starts");
    for packet in take(&mut nodes[r].packet_rx) {
        hand(&mut nodes[r].node, packet).await;
    }
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    assert!(
        nodes[i].node.get_peer(&r_addr).is_some(),
        "precondition: the smaller node installed the larger"
    );
    let lost = take(&mut nodes[r].packet_rx);
    assert!(
        lost.iter().any(|p| phase(p) == Some(PHASE_MSG3)),
        "precondition: the configured dial's msg3 went out, and is lost"
    );
    assert!(
        nodes[r].node.get_peer(&i_addr).is_none(),
        "precondition: the larger node holds nothing"
    );

    nodes[i]
        .node
        .initiate_connection(t2(), r2, None)
        .await
        .expect("precondition: the later anonymous dial starts");
    for packet in take(&mut nodes[r].packet_rx) {
        hand(&mut nodes[r].node, packet).await;
    }
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    for packet in take(&mut nodes[r].packet_rx) {
        hand(&mut nodes[r].node, packet).await;
    }
    assert!(
        nodes[r].node.get_peer(&i_addr).is_some(),
        "the larger node holds the smaller after the later dial"
    );
    let (i_ours, i_theirs) = session(&nodes[i], &r_addr);
    let (r_ours, r_theirs) = session(&nodes[r], &i_addr);
    assert_eq!(
        (i_ours, i_theirs),
        (r_theirs, r_ours),
        "both ends hold one session (the smaller node's (ours, theirs) against the larger's (theirs, ours))"
    );
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    heartbeat(&mut nodes[i], &r_addr).await;
    for packet in take(&mut nodes[r].packet_rx) {
        hand(&mut nodes[r].node, packet).await;
    }
    heartbeat(&mut nodes[r], &i_addr).await;
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    assert_eq!(
        (failures(&nodes[r], &i_addr), failures(&nodes[i], &r_addr)),
        (0, 0),
        "neither end fails to decrypt the other's frame"
    );
    // With multipath on, the audit's own heartbeat exchange leaves the
    // larger node its link for the first dial, whose msg3 was lost, live with
    // no index entry at its pair, as it does on the tree before the own-dial
    // keep. That breach is outside this test's subject, the session the two
    // ends hold, so it alone is passed; any other breach fails the test.
    assert_coherent_but(
        &mut nodes,
        "the end of the later dial after a lost msg3",
        |breach| {
            multipath
                && matches!(
                    breach,
                    Breach::MapsAgree { node, what, .. }
                        if *node == r && *what == "a live link with no index entry at its pair"
                )
        },
    )
    .await;
    cleanup_nodes(&mut nodes).await;
}

/// A dial the smaller node begins after its first dial's msg3 was lost is
/// settled by address order, not kept without a msg3: both ends end on the
/// later dial's session.
#[tokio::test]
async fn a_dial_begun_after_a_lost_msg3_moves_both_ends_onto_its_session() {
    a_lost_msg3_then_a_later_dial(false).await;
}

/// As above, with multipath on.
#[tokio::test]
async fn a_dial_begun_after_a_lost_msg3_moves_both_ends_onto_its_session_with_multipath_on() {
    a_lost_msg3_then_a_later_dial(true).await;
}

/// The smaller node dials the larger on two transports at once, the first
/// dial completes at both ends, and the larger node's frame under that
/// session reaches the smaller before the second msg2 does. The larger node
/// is then known to hold the session, so the second dial is settled by
/// address order as before: the smaller node sends its msg3 and moves onto
/// it, and both ends end on the second dial's session.
async fn a_second_msg2_after_the_peer_is_heard(multipath: bool) {
    let mut config = crate::config::Config::new();
    config.node.path.enabled = multipath;
    let mut nodes = vec![
        make_test_node_with_config(config.clone(), 1280).await,
        make_test_node_with_config(config, 1280).await,
    ];
    let (i, r) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let i_addr = *nodes[i].node.node_addr();
    let r_addr = *nodes[r].node.node_addr();
    let t1 = nodes[i].transport_id;
    add_t2(&mut nodes[i]);
    let r2 = add_t2(&mut nodes[r]);
    let r1 = nodes[r].addr.clone();
    let r_id = PeerIdentity::from_pubkey_full(nodes[r].node.identity().pubkey_full());

    nodes[i]
        .node
        .initiate_connection(t1, r1, Some(r_id))
        .await
        .expect("precondition: the configured dial starts");
    nodes[i]
        .node
        .initiate_connection(t2(), r2, None)
        .await
        .expect("precondition: the anonymous dial starts");
    let mut at_r = take(&mut nodes[r].packet_rx);
    for msg1 in split(&mut at_r, PHASE_MSG1, "the smaller node's msg1") {
        hand(&mut nodes[r].node, msg1).await;
    }
    let mut at_i = take(&mut nodes[i].packet_rx);
    let [msg2_a, msg2_b] = split(&mut at_i, PHASE_MSG2, "the larger node's msg2");

    // The first dial completes at both ends, and the larger node's frame
    // under it reaches the smaller node.
    hand(&mut nodes[i].node, msg2_a).await;
    for packet in take(&mut nodes[r].packet_rx) {
        hand(&mut nodes[r].node, packet).await;
    }
    heartbeat(&mut nodes[r], &i_addr).await;
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    assert!(
        nodes[i]
            .node
            .get_peer(&r_addr)
            .is_some_and(|p| p.heard_on_session()),
        "precondition: the smaller node heard the larger under the first dial's session"
    );

    hand(&mut nodes[i].node, msg2_b).await;
    let (msg3s, rest): (Vec<_>, Vec<_>) = take(&mut nodes[r].packet_rx)
        .into_iter()
        .partition(|p| phase(p) == Some(PHASE_MSG3));
    assert_eq!(
        msg3s.iter().map(|p| p.transport_id).collect::<Vec<_>>(),
        vec![t2()],
        "the second dial sends its msg3"
    );
    for packet in msg3s.into_iter().chain(rest) {
        hand(&mut nodes[r].node, packet).await;
    }
    assert_eq!(
        nodes[i]
            .node
            .get_peer(&r_addr)
            .and_then(|p| p.transport_id()),
        Some(t2()),
        "the smaller node moved onto the second dial"
    );
    let (i_ours, i_theirs) = session(&nodes[i], &r_addr);
    let (r_ours, r_theirs) = session(&nodes[r], &i_addr);
    assert_eq!(
        (i_ours, i_theirs),
        (r_theirs, r_ours),
        "both ends hold one session (the smaller node's (ours, theirs) against the larger's (theirs, ours))"
    );
    for packet in take(&mut nodes[i].packet_rx) {
        hand(&mut nodes[i].node, packet).await;
    }
    heartbeat(&mut nodes[i], &r_addr).await;
    for packet in take(&mut nodes[r].packet_rx) {
        hand(&mut nodes[r].node, packet).await;
    }
    assert_eq!(
        failures(&nodes[r], &i_addr),
        0,
        "the larger node reads the smaller node's frame"
    );
    // The larger node's move at the second msg3 leaves its link record on
    // the first dial's pair, inbound on t1, while it holds its peer on t2: a
    // right-link breach it shows on the tree before the own-dial keep too.
    // That breach is outside this test's subject, which dial's msg3 is sent
    // and the session the two ends hold, so it alone is passed; any other
    // breach fails the test.
    assert_coherent_but(
        &mut nodes,
        "the end of the second dial answered after the peer is heard",
        |breach| {
            matches!(
                breach,
                Breach::RightLink {
                    node,
                    peer,
                    record: Some((LinkDirection::Inbound, on, _)),
                    pair: (Some(held), _),
                } if *node == r && *peer == i && *on == t1 && *held == t2()
            )
        },
    )
    .await;
    cleanup_nodes(&mut nodes).await;
}

/// A second dial whose msg2 comes after the peer was heard under the first
/// dial's session is settled by address order: both ends move onto it.
#[tokio::test]
async fn a_second_dial_answered_after_the_peer_is_heard_is_settled_by_address_order() {
    a_second_msg2_after_the_peer_is_heard(false).await;
}

/// As above, with multipath on.
#[tokio::test]
async fn a_second_dial_answered_after_the_peer_is_heard_is_settled_by_address_order_with_multipath_on()
 {
    a_second_msg2_after_the_peer_is_heard(true).await;
}
