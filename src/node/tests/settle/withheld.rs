//! A lost first msg3 when a later dial's msg3 is withheld.
//!
//! The smaller node dials the larger on two loopback transports at once,
//! the first dial naming the peer and the second anonymous, and reads both
//! msg2s, the first dial's first. The first installs the peer and sends its
//! msg3; the second is a dial beside the node's own unheard dial that
//! installed the peer after it began, so the own-dial keep withholds its
//! msg3. In the same-side case the larger node dials the smaller, and dials
//! again before it hears the smaller; address order keeps it, and the
//! same-side rule withholds the later dial's msg3. Either way the first
//! dial's msg3 is lost. The node then resends that msg3 on the first dial's
//! link, as it does whenever it withholds a later dial's msg3 before the
//! peer is heard. The assertion is that the peer holds the dialer, on the
//! session the dialer holds it on, once everything else is delivered.
//!
//! A test's plain name runs multipath off, and its `_with_multipath_on`
//! sibling runs it on. Setup checks are marked `precondition:`; the
//! assertion of the behaviour is marked `defect:`.

use super::super::crossed_dial::{hand, phase};
use super::super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, add_loopback_alias, cleanup_nodes, make_test_node_with_config,
};
use super::super::*;
use super::{pump, with_path};
use crate::proto::fmp::wire::{PHASE_MSG2, PHASE_MSG3};
use crate::transport::loopback::LoopbackTransport;
use crate::transport::{TransportHandle, TransportId};

/// The second loopback transport's id.
fn t2() -> TransportId {
    TransportId::new(2)
}

/// Every packet queued at `tn`, taken off its queue.
fn taken(tn: &mut TestNode) -> Vec<ReceivedPacket> {
    std::iter::from_fn(|| tn.packet_rx.try_recv().ok()).collect()
}

/// Give `tn` a second loopback transport at a second address of its own,
/// whose packets land in its receive channel; returns that address.
fn add_t2(tn: &mut TestNode) -> TransportAddr {
    let addr = add_loopback_alias(&tn.addr, t2());
    let lo = LoopbackTransport::with_mtu(t2(), addr.clone(), 1280, LOOPBACK_REGISTRY.clone());
    tn.node
        .transports
        .insert(t2(), TransportHandle::Loopback(lo));
    addr
}

/// (ours, theirs) of the session `tn` holds `peer` on.
fn session(tn: &TestNode, peer: &NodeAddr) -> Option<(Option<SessionIndex>, Option<SessionIndex>)> {
    tn.node
        .get_peer(peer)
        .map(|p| (p.our_index(), p.their_index()))
}

/// Hand `nodes[to]` everything queued for it but the first msg3, which is
/// lost; the transports the msg3s came in on, in order.
async fn lose_first_msg3(nodes: &mut [TestNode], to: usize) -> Vec<TransportId> {
    let queued = taken(&mut nodes[to]);
    let msg3s: Vec<TransportId> = queued
        .iter()
        .filter(|p| phase(p) == Some(PHASE_MSG3))
        .map(|p| p.transport_id)
        .collect();
    let mut lost = false;
    for p in queued {
        if !lost && phase(&p) == Some(PHASE_MSG3) {
            lost = true;
            continue;
        }
        hand(&mut nodes[to].node, p).await;
    }
    msg3s
}

/// Whether `d` and `p` each hold the other on one session.
fn one_session(nodes: &[TestNode], d: usize, p: usize) -> bool {
    let at_d = session(&nodes[d], nodes[p].node.node_addr());
    let at_p = session(&nodes[p], nodes[d].node.node_addr());
    matches!(
        (at_d, at_p),
        (Some((so, st)), Some((lo, lt))) if so.is_some() && so == lt && st == lo
    )
}

/// Two nodes with multipath `on`, and (smaller, larger).
async fn pair(on: bool) -> (Vec<TestNode>, usize, usize) {
    let config = with_path(Config::new(), on);
    let nodes = vec![
        make_test_node_with_config(config.clone(), 1280).await,
        make_test_node_with_config(config, 1280).await,
    ];
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    (nodes, s, l)
}

/// Two concurrent dials from the smaller node, the first dial's msg3 lost.
async fn lost_first_msg3(on: bool) {
    let (mut nodes, s, l) = pair(on).await;
    let l_addr = *nodes[l].node.node_addr();
    let t1 = nodes[s].transport_id;
    add_t2(&mut nodes[s]);
    let l2 = add_t2(&mut nodes[l]);
    let l1 = nodes[l].addr.clone();
    let l_id = PeerIdentity::from_pubkey_full(nodes[l].node.identity().pubkey_full());
    nodes[s]
        .node
        .initiate_connection(t1, l1, Some(l_id))
        .await
        .expect("precondition: the first dial starts");
    nodes[s]
        .node
        .initiate_connection(t2(), l2, None)
        .await
        .expect("precondition: the second dial starts");
    for p in taken(&mut nodes[l]) {
        hand(&mut nodes[l].node, p).await;
    }
    let mut at_s = taken(&mut nodes[s]);
    at_s.sort_by_key(|p| p.transport_id == t2());
    assert_eq!(
        at_s.iter().filter(|p| phase(p) == Some(PHASE_MSG2)).count(),
        2,
        "precondition: both dials' msg2s reached the smaller node"
    );
    for p in at_s {
        hand(&mut nodes[s].node, p).await;
    }
    assert!(
        nodes[s].node.get_peer(&l_addr).is_some(),
        "precondition: the smaller node holds the larger"
    );
    let msg3s = lose_first_msg3(&mut nodes, l).await;
    assert!(
        msg3s.first() == Some(&t1) && !msg3s.contains(&t2()),
        "precondition: the first dial's msg3 went out first, on its own transport, and the second dial sent none: {msg3s:?}"
    );
    pump(&mut nodes).await;
    let one = one_session(&nodes, s, l);
    let (at_s, at_l) = (
        session(&nodes[s], &l_addr),
        session(&nodes[l], nodes[s].node.node_addr()),
    );
    cleanup_nodes(&mut nodes).await;
    assert!(
        one,
        "defect: with the first msg3 lost and the second withheld, the larger node must hold the smaller on the session the smaller holds; smaller {at_s:?}, larger {at_l:?}"
    );
}

#[tokio::test]
async fn a_lost_first_msg3_beside_a_withheld_second_dial_leaves_the_larger_node_holding_the_smaller()
 {
    lost_first_msg3(false).await;
}

/// [`a_lost_first_msg3_beside_a_withheld_second_dial_leaves_the_larger_node_holding_the_smaller`] with multipath on.
#[tokio::test]
async fn a_lost_first_msg3_beside_a_withheld_second_dial_leaves_the_larger_node_holding_the_smaller_with_multipath_on()
 {
    lost_first_msg3(true).await;
}

/// The larger node dials the smaller, its msg3 is lost, and it dials the
/// smaller again on a second transport before hearing it.
async fn lost_msg3_before_a_same_side_dial(on: bool) {
    let (mut nodes, s, l) = pair(on).await;
    let s_addr = *nodes[s].node.node_addr();
    let t1 = nodes[l].transport_id;
    add_t2(&mut nodes[l]);
    let s2 = add_t2(&mut nodes[s]);
    let s1 = nodes[s].addr.clone();
    let s_id = PeerIdentity::from_pubkey_full(nodes[s].node.identity().pubkey_full());
    nodes[l]
        .node
        .initiate_connection(t1, s1, Some(s_id))
        .await
        .expect("precondition: the first dial starts");
    for p in taken(&mut nodes[s]) {
        hand(&mut nodes[s].node, p).await;
    }
    for p in taken(&mut nodes[l]) {
        hand(&mut nodes[l].node, p).await;
    }
    assert!(
        nodes[l].node.get_peer(&s_addr).is_some(),
        "precondition: the larger node holds the smaller"
    );
    let msg3s = lose_first_msg3(&mut nodes, s).await;
    assert_eq!(
        msg3s,
        vec![t1],
        "precondition: the first dial's msg3 is lost"
    );
    assert!(
        nodes[s].node.get_peer(nodes[l].node.node_addr()).is_none(),
        "precondition: the smaller node holds no session for the larger"
    );
    nodes[l]
        .node
        .initiate_connection(t2(), s2, None)
        .await
        .expect("precondition: the second dial starts");
    pump(&mut nodes).await;
    let one = one_session(&nodes, l, s);
    let (at_l, at_s) = (
        session(&nodes[l], &s_addr),
        session(&nodes[s], nodes[l].node.node_addr()),
    );
    cleanup_nodes(&mut nodes).await;
    assert!(
        one,
        "defect: with the first msg3 lost and a same-side dial withheld, the smaller node must hold the larger on the session the larger holds; larger {at_l:?}, smaller {at_s:?}"
    );
}

#[tokio::test]
async fn a_lost_first_msg3_before_a_withheld_same_side_dial_leaves_the_smaller_node_holding_the_larger()
 {
    lost_msg3_before_a_same_side_dial(false).await;
}

/// [`a_lost_first_msg3_before_a_withheld_same_side_dial_leaves_the_smaller_node_holding_the_larger`] with multipath on.
#[tokio::test]
async fn a_lost_first_msg3_before_a_withheld_same_side_dial_leaves_the_smaller_node_holding_the_larger_with_multipath_on()
 {
    lost_msg3_before_a_same_side_dial(true).await;
}
