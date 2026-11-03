//! Characterisation tests: what master does today at five per-peer cells a
//! settlement change has to decide, asserted as master does it, so a change
//! to any of them shows up as a red test rather than passing unseen.
//!
//! None of these is coverage of a behaviour the code means to keep; each
//! records a value that was read from the code and is checked here by a
//! run. A change that means to move one replaces its test with one asserting
//! the new value, with a reproduction of why.
//!
//! Coverage map, by what each cell covers:
//!
//! | Cell | Test |
//! | --- | --- |
//! | heard-from after a crossing moves the smaller node | `chartest_a_crossing_leaves_the_smaller_node_unheard_until_the_peers_first_frame` |
//! | the end-to-end session at a restart found in this node's own msg2 | `chartest_a_restart_seen_in_our_msg2_keeps_the_fsp_session_of_an_unheard_peering` |
//! | the address index after a second own dial to the held link's address | `chartest_a_second_own_dial_to_the_held_links_address_leaves_that_link_without_an_index_entry` |
//! | the path MTU of a BLE peer that frames move to another link | `chartest_a_ble_peer_moved_by_its_frames_keeps_the_path_mtu_of_its_first_link` |
//! | the spin-bit role after a crossing | `chartest_after_a_crossing_both_ends_hold_the_spin_responder_role` |

use super::super::crossed_dial::{Dial, cross_dials, hand};
use super::super::rekey_parity::stale_session;
use super::super::spanning_tree::{
    TestNode, cleanup_nodes, initiate_handshake, make_test_node, restarted_node,
};
use super::super::*;
use super::crossed_tcp;
use super::crossing::{Second, second_msg1_late};

/// After crossed dials, right after the smaller node moves onto its own
/// outbound handshake and before any frame of the peer's, the smaller node
/// counts the peering as not heard from: the move does not set it.
#[tokio::test]
async fn chartest_a_crossing_leaves_the_smaller_node_unheard_until_the_peers_first_frame() {
    let crossed = cross_dials(Dial::AnsweredFromFirst).await;
    let (s, l) = (crossed.s, crossed.l);
    let mut nodes = crossed.nodes;
    let l_addr = *nodes[l].node.node_addr();
    assert!(
        !nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: the smaller node holds the larger")
            .is_heard(),
        "precondition: the smaller node, promoted on the peer's msg1, has not heard it"
    );
    hand(&mut nodes[s].node, crossed.msg2).await;
    let peer = nodes[s]
        .node
        .get_peer(&l_addr)
        .expect("precondition: the smaller node keeps the larger");
    assert_eq!(
        peer.our_index(),
        Some(crossed.outbound),
        "precondition: the smaller node moved to its outbound session"
    );
    let heard = peer.is_heard();
    cleanup_nodes(&mut nodes).await;
    assert!(
        !heard,
        "defect: master no longer leaves the moved peering unheard until the peer's first frame"
    );
}

/// A node holding a peering it was promoted on by the peer's msg1 and has
/// not heard from, with an end-to-end session to that peer, dials the peer,
/// which has restarted: the msg2 carries a new startup epoch and the node
/// replaces the peering. The end-to-end session is kept, because the old
/// peering was never heard from.
#[tokio::test]
async fn chartest_a_restart_seen_in_our_msg2_keeps_the_fsp_session_of_an_unheard_peering() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let a1 = *nodes[1].node.node_addr();
    initiate_handshake(&mut nodes, 1, 0).await;
    let msg1 = nodes[0]
        .packet_rx
        .try_recv()
        .expect("precondition: node 1's msg1 is queued at node 0");
    nodes[0].node.handle_msg1(msg1).await;
    let before = {
        let p = nodes[0]
            .node
            .get_peer(&a1)
            .expect("precondition: node 0 promoted node 1 on its msg1");
        assert!(!p.is_heard(), "precondition: node 0 has not heard node 1");
        p.link_id()
    };
    stale_session(&mut nodes[0].node, a1);

    let restarted = restarted_node(&nodes[1], Config::new());
    let mut old = std::mem::replace(&mut nodes[1], restarted);
    cleanup_nodes(std::slice::from_mut(&mut old)).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    let msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: node 0's msg1 is queued at the restarted node");
    nodes[1].node.handle_msg1(msg1).await;
    let msg2 = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok())
        .find(|p| {
            crate::proto::fmp::wire::CommonPrefix::parse(&p.data)
                .is_some_and(|c| c.phase == crate::proto::fmp::wire::PHASE_MSG2)
        })
        .expect("precondition: the restarted node's msg2 is queued at node 0");
    nodes[0].node.handle_msg2(msg2).await;
    assert!(
        nodes[0]
            .node
            .get_peer(&a1)
            .is_some_and(|p| p.link_id() != before),
        "precondition: node 0 replaced the peering on the restart its msg2 showed"
    );
    let kept = nodes[0].node.get_session(&a1).is_some();
    cleanup_nodes(&mut nodes).await;
    assert!(
        kept,
        "defect: master no longer keeps the end-to-end session of an unheard peering at a restart seen in its msg2"
    );
}

/// A dialer's second dial to the address of the link it holds the peer on
/// completes and moves the session; the held link is then left with no
/// `(transport, address)` entry.
#[tokio::test]
async fn chartest_a_second_own_dial_to_the_held_links_address_leaves_that_link_without_an_index_entry()
 {
    let mut late = second_msg1_late(true, Second::InOrder).await;
    let (d, r) = (late.d, late.r);
    let r_addr = *late.nodes[r].node.node_addr();
    let (link, key) = {
        let node = &late.nodes[d].node;
        let p = node
            .get_peer(&r_addr)
            .expect("precondition: the dialer holds the responder");
        let link = p.link_id();
        let k = node
            .links
            .get(&link)
            .expect("precondition: the held link is in the link map");
        (link, (k.transport_id(), k.remote_addr().clone()))
    };
    let entry = late.nodes[d].node.addr_to_link.get(&key).copied();
    cleanup_nodes(&mut late.nodes).await;
    assert_eq!(
        entry, None,
        "defect: master now keeps an index entry for the held link {link:?}"
    );
}

/// After crossed TCP dials both ends hold the spin-bit responder role: the
/// smaller node was promoted on the peer's msg1 and keeps that role when it
/// moves, and the larger node keeps its inbound session.
#[tokio::test]
async fn chartest_after_a_crossing_both_ends_hold_the_spin_responder_role() {
    let (mut nodes, s, l) = crossed_tcp(true).await;
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    let role = |tn: &TestNode, peer: &NodeAddr| {
        tn.node
            .get_peer(peer)
            .and_then(|p| p.mmp())
            .map(|m| m.spin_bit.is_initiator())
    };
    let roles = (role(&nodes[s], &l_addr), role(&nodes[l], &s_addr));
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        roles,
        (Some(false), Some(false)),
        "defect: master no longer leaves both ends of a crossing in the spin responder role"
    );
}

/// A BLE peer whose frames move it onto a second link of a smaller MTU
/// keeps the path MTU it was seeded with from its first link.
#[cfg(ble_available)]
#[tokio::test]
async fn chartest_a_ble_peer_moved_by_its_frames_keeps_the_path_mtu_of_its_first_link() {
    use super::super::ble::{base_config, ble_addr, larger_second, make_test_node_ble_with};
    use super::super::ble::{pooled_at, until};
    use super::super::spanning_tree::drain_all_packets;
    use crate::transport::ble::addr::BleAddr;
    use crate::transport::ble::io::MockBleStream;

    /// `tn`'s BLE transport.
    fn ble(
        tn: &TestNode,
    ) -> &crate::transport::ble::BleTransport<crate::transport::ble::io::MockBleIo> {
        match tn.node.transports.get(&tn.transport_id) {
            Some(crate::transport::TransportHandle::Ble(t)) => t,
            _ => panic!("precondition: the node's first transport is BLE"),
        }
    }

    /// The BLE address of `tn`'s own transport.
    fn own(tn: &TestNode) -> BleAddr {
        BleAddr::parse(tn.addr.as_str().expect("precondition: a text address"))
            .expect("precondition: a BLE address")
    }

    let mut nodes = vec![
        make_test_node_ble_with(1, base_config()).await,
        make_test_node_ble_with(2, base_config()).await,
    ];
    larger_second(&mut nodes);
    let (a0, a1) = (own(&nodes[0]), own(&nodes[1]));
    let (a0x, a1x) = (ble_addr(100), ble_addr(101));
    // The first link at 2048 and the second at 512, both dialled by node 0.
    let (l1_0, l1_1) = MockBleStream::pair(a0.clone(), a1.clone(), 2048);
    let (l2_0, l2_1) = MockBleStream::pair(a0x.clone(), a1x.clone(), 512);
    let bank = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::from([
        (a1.to_transport_addr().to_string(), l1_0),
        (a1x.to_transport_addr().to_string(), l2_0),
    ])));
    {
        let bank = std::sync::Arc::clone(&bank);
        ble(&nodes[0]).io().set_connect_handler(move |addr, _psm| {
            bank.lock()
                .expect("precondition: the stream bank lock")
                .remove(&addr.to_transport_addr().to_string())
                .ok_or(crate::transport::TransportError::ConnectionRefused)
        });
    }
    ble(&nodes[1]).io().inject_inbound(l1_1).await;
    ble(&nodes[0])
        .connect_async(&a1.to_transport_addr())
        .await
        .expect("precondition: node 0 connects the first link");
    until(|| pooled_at(&nodes[1], &a0.to_transport_addr())).await;
    ble(&nodes[1]).io().inject_inbound(l2_1).await;
    ble(&nodes[0])
        .connect_async(&a1x.to_transport_addr())
        .await
        .expect("precondition: node 0 connects the second link");
    assert!(
        until(|| pooled_at(&nodes[1], &a0x.to_transport_addr())
            && pooled_at(&nodes[0], &a1x.to_transport_addr()))
        .await,
        "precondition: both ends pool the second link"
    );
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let n0 = *nodes[0].node.node_addr();
    let n1 = *nodes[1].node.node_addr();
    let fips0 = crate::Ipv6Address::from_node_addr(&n0);
    let tid1 = nodes[1].transport_id;
    let (seeded, l1_mtu, l2_mtu) = {
        let handle = nodes[1]
            .node
            .transports
            .get(&tid1)
            .expect("precondition: node 1's transport");
        (
            nodes[1].node.path_mtu_lookup_get(&fips0),
            handle.link_mtu(&a0.to_transport_addr()),
            handle.link_mtu(&a0x.to_transport_addr()),
        )
    };
    assert!(
        seeded.is_some() && l1_mtu != l2_mtu,
        "precondition: node 1 seeded node 0's path MTU, and the two links' MTUs differ ({l1_mtu}, {l2_mtu})"
    );

    // Node 0 moves its traffic to the second link.
    let tid0 = nodes[0].transport_id;
    nodes[0]
        .node
        .get_peer_mut(&n1)
        .expect("precondition: node 0 holds node 1")
        .set_current_addr(tid0, a1x.to_transport_addr());
    nodes[0]
        .node
        .send_tree_announce_to_peer(&n1)
        .await
        .expect("precondition: node 0 sends on the second link");
    drain_all_packets(&mut nodes, false).await;
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&n0)
            .and_then(|p| p.current_addr().cloned()),
        Some(a0x.to_transport_addr()),
        "precondition: node 1 follows node 0 onto the second link"
    );
    let after = nodes[1].node.path_mtu_lookup_get(&fips0);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        after, seeded,
        "defect: master now reseeds the path MTU when frames move a BLE peer"
    );
}
