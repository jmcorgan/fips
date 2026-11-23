//! A lost first msg3 when a later dial's msg3 is withheld.
//!
//! The smaller node dials the larger on two loopback transports at once,
//! the first dial naming the peer and the second anonymous, and reads both
//! msg2s, the first dial's first. The first installs the peer and sends its
//! msg3; the second is a dial beside the node's own unheard dial that
//! installed the peer after it began, so the own-dial keep withholds its
//! msg3. When the first msg3 is lost, nothing reaches the larger node,
//! which holds no session for the smaller until the link-dead timeout. The
//! assertion is that the larger node holds the smaller, on the session the
//! smaller holds it on, once everything else is delivered.
//!
//! Both tests fail today, and are known defects until the initiator keeps
//! its first msg3 for a withheld dial.
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

/// Two concurrent dials from the smaller node, the first dial's msg3 lost.
async fn lost_first_msg3(on: bool) {
    let config = with_path(Config::new(), on);
    let mut nodes = vec![
        make_test_node_with_config(config.clone(), 1280).await,
        make_test_node_with_config(config, 1280).await,
    ];
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let s_addr = *nodes[s].node.node_addr();
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
    let at_l = taken(&mut nodes[l]);
    let msg3s: Vec<TransportId> = at_l
        .iter()
        .filter(|p| phase(p) == Some(PHASE_MSG3))
        .map(|p| p.transport_id)
        .collect();
    assert_eq!(
        msg3s,
        vec![t1],
        "precondition: the first dial's msg3 alone was sent, the second's withheld"
    );
    for p in at_l {
        if phase(&p) == Some(PHASE_MSG3) {
            continue;
        }
        hand(&mut nodes[l].node, p).await;
    }
    pump(&mut nodes).await;
    let at_s = session(&nodes[s], &l_addr);
    let at_l = session(&nodes[l], &s_addr);
    cleanup_nodes(&mut nodes).await;
    let one = matches!(
        (at_s, at_l),
        (Some((so, st)), Some((lo, lt))) if so.is_some() && so == lt && st == lo
    );
    assert!(
        one,
        "defect: with the first msg3 lost and the second withheld, the larger node must hold the smaller on the session the smaller holds; smaller {at_s:?}, larger {at_l:?}"
    );
}

#[tokio::test]
#[ignore = "known defect on next: a lost first msg3 is not rescued when the own-dial keep withholds the second dial's msg3"]
async fn a_lost_first_msg3_beside_a_withheld_second_dial_leaves_the_larger_node_holding_the_smaller()
 {
    lost_first_msg3(false).await;
}

/// [`a_lost_first_msg3_beside_a_withheld_second_dial_leaves_the_larger_node_holding_the_smaller`] with multipath on.
#[tokio::test]
#[ignore = "known defect on next: a lost first msg3 is not rescued when the own-dial keep withholds the second dial's msg3"]
async fn a_lost_first_msg3_beside_a_withheld_second_dial_leaves_the_larger_node_holding_the_smaller_with_multipath_on()
 {
    lost_first_msg3(true).await;
}
