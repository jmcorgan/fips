//! A crossed TCP peer that one end alone drops and then redials: which
//! direction each end is left holding its link in.
//!
//! Two real TCP nodes on 127.0.0.1 dial each other and settle on the
//! smaller node's dial, the smaller node holding the link `Outbound` and
//! the larger `Inbound`. Both ends are aged past the rekey floors. The
//! larger node alone then removes the smaller, as link-dead does at the end
//! that stops hearing first after a link flap, closes the connection the
//! smaller node's link ran on, and dials the smaller node again at its
//! listening address. The smaller node still holds the larger, and its link's
//! connection is gone, so the msg1, off that link and on a link old enough
//! to rekey, is its peer's rekey (FRC-1201 Section 5.7, rule 4.1), answered
//! on the msg1's connection; the larger node, holding no peer, installs the
//! answer as a new peer it dialed.
//!
//! The assertion is that the larger node, which dialed last, then holds
//! the link `Outbound` and the smaller node `Inbound`, which the chaos edge
//! agreement check reads from the peer listing. A test's plain name runs
//! multipath off, and its `_with_multipath_on` sibling runs it on. With
//! multipath on the crossing here leaves one connection and one path, so
//! the sibling runs the same shape as multipath off; the chaos run that
//! found the defect reached it with two paths, the smaller node's current
//! path on the larger node's dial connection and its own dial connection
//! still open.
//!
//! A second test runs the other role: the larger node alone dials, the
//! smaller drops and redials, so the larger node's link turns from its dial
//! to the smaller's, and then the larger node dials again. The assertion is
//! that the pair stays on the smaller node's dial, on one working session.
//!
//! Setup checks are marked `precondition:`; the assertion of the behaviour
//! is marked `defect:`.

use super::super::spanning_tree::{TestNode, cleanup_nodes};
use super::super::*;
use super::{
    AGED, crossed_tcp, heartbeat_reaches, pool, pump, resolve_connect, settled, tcp_dial, tcp_pair,
};
use fips_core::proto::settle::output::Why;

/// The direction `nodes[at]`'s link to `nodes[of]` was set up in, `None`
/// when it does not hold `of` or holds no record of that link.
fn direction(nodes: &[TestNode], at: usize, of: usize) -> Option<LinkDirection> {
    let peer = *nodes[of].node.node_addr();
    let link = nodes[at].node.get_peer(&peer)?.link_id();
    nodes[at].node.links.get(&link).map(|k| k.direction())
}

/// `nodes[d]` alone removes `nodes[k]`, as link-dead does at the end that
/// stops hearing first after a link flap, and dials it again once the
/// connection `k`'s link ran on has closed; `k` held the link as its dial,
/// and answers the msg1 as its peer's rekey on the msg1's connection.
/// Returns once frames authenticate each way under the new sessions.
async fn lone(nodes: &mut [TestNode], d: usize, k: usize) {
    heartbeat_reaches(nodes, k, d)
        .await
        .expect("precondition: frames authenticate from the keeper");
    heartbeat_reaches(nodes, d, k)
        .await
        .expect("precondition: frames authenticate from the dropper");
    assert_eq!(
        (direction(nodes, k, d), direction(nodes, d, k)),
        (Some(LinkDirection::Outbound), Some(LinkDirection::Inbound)),
        "precondition: the keeper holds the link as its dial"
    );
    let d_addr = *nodes[d].node.node_addr();
    let k_addr = *nodes[k].node.node_addr();
    for (at, peer) in [(k, d_addr), (d, k_addr)] {
        nodes[at]
            .node
            .get_peer_mut(&peer)
            .expect("precondition: each end holds the other")
            .test_backdate_session_established(AGED);
    }

    // The removal leaves the keeper's dial connection open, so the test
    // closes it, standing for the chaos run where the keeper's current
    // path ran on a connection the removal did close.
    let (tid, at) = {
        let p = nodes[d]
            .node
            .get_peer(&k_addr)
            .expect("precondition: the dropper holds the keeper");
        (
            p.transport_id()
                .expect("precondition: the peer has a transport"),
            p.current_addr()
                .cloned()
                .expect("precondition: the peer has a current address"),
        )
    };
    nodes[d].node.route_link_dead(k_addr, 0, Why::Dead).await;
    nodes[d].node.drain_closes().await;
    assert!(
        nodes[d].node.get_peer(&k_addr).is_none(),
        "precondition: the dropper removed the keeper"
    );
    nodes[d]
        .node
        .transports
        .get(&tid)
        .expect("precondition: the dropper's transport is held")
        .close_connection(&at)
        .await;
    for _ in 0..200 {
        if pool(&nodes[k]) == (0, 0) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        pool(&nodes[k]),
        (0, 0),
        "precondition: the keeper's connection to the dropper closed"
    );
    let (held, session) = nodes[k]
        .node
        .get_peer(&d_addr)
        .map(|p| (p.link_id(), p.our_index()))
        .expect("precondition: the keeper still holds the dropper");

    // The dropper dials again; its first frame under the new session
    // reaches the keeper.
    tcp_dial(nodes, d, k).await;
    resolve_connect(&mut nodes[d]).await;
    pump(nodes).await;
    assert!(
        nodes[d].node.get_peer(&k_addr).is_some(),
        "precondition: the dropper holds the keeper again"
    );
    heartbeat_reaches(nodes, d, k)
        .await
        .expect("precondition: frames authenticate from the dropper after the redial");
    heartbeat_reaches(nodes, k, d)
        .await
        .expect("precondition: frames authenticate from the keeper after the redial");
    let after = nodes[k]
        .node
        .get_peer(&d_addr)
        .map(|p| (p.link_id(), p.our_index()));
    assert!(
        after.is_some_and(|(link, ours)| link == held && ours != session),
        "precondition: the keeper answered the redial as a rekey, keeping its link ({held:?}, {session:?} before, {after:?} after)"
    );
}

/// Crossed dials, then the larger node drops the smaller and redials it:
/// the larger node must be left holding the link as its dial and the
/// smaller node as the larger's.
async fn lone_drop(on: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, true).await;
    lone(&mut nodes, l, s).await;
    let directions = (direction(&nodes, s, l), direction(&nodes, l, s));
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        directions,
        (Some(LinkDirection::Inbound), Some(LinkDirection::Outbound)),
        "defect: after the redial the larger node must hold the link Outbound and the smaller Inbound; (smaller, larger) hold {directions:?}"
    );
}

/// The larger node dials the smaller, which then drops the larger and
/// redials it, so the larger node's link turns from its dial to the
/// smaller's; then the larger node dials the smaller again. That later
/// dial is no longer its own dial on a link it dialed (FRC-1201 Section
/// 5.6), so the node address ordering keeps the smaller node's dial: the
/// pair stays on one session, the smaller node holding the link
/// `Outbound` and the larger `Inbound`. Moving onto the larger node's new
/// dial, as it would if its record still said it dialed the link, would
/// also leave one working session; the test holds the reading the turned
/// record gives.
async fn dial_after(on: bool) {
    let mut nodes = tcp_pair(on, true).await;
    let (s, l) = (0, 1);
    tcp_dial(&mut nodes, l, s).await;
    resolve_connect(&mut nodes[l]).await;
    pump(&mut nodes).await;
    lone(&mut nodes, s, l).await;
    let turned = (direction(&nodes, s, l), direction(&nodes, l, s));
    let link = nodes[s]
        .node
        .get_peer(nodes[l].node.node_addr())
        .map(|p| p.link_id());
    tcp_dial(&mut nodes, l, s).await;
    resolve_connect(&mut nodes[l]).await;
    pump(&mut nodes).await;
    let works = settled(&mut nodes, s, l).await;
    let directions = (direction(&nodes, s, l), direction(&nodes, l, s));
    let kept = nodes[s]
        .node
        .get_peer(nodes[l].node.node_addr())
        .map(|p| p.link_id());
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        turned,
        (Some(LinkDirection::Outbound), Some(LinkDirection::Inbound)),
        "defect: after the redial the smaller node must hold the link Outbound and the larger Inbound; (smaller, larger) hold {turned:?}"
    );
    works.expect(
        "defect: the pair is not on one working session after the larger node's later dial",
    );
    assert_eq!(
        (directions, kept),
        (
            (Some(LinkDirection::Outbound), Some(LinkDirection::Inbound)),
            link
        ),
        "defect: the larger node's later dial moved the pair off the smaller node's dial; (smaller, larger) hold {directions:?}, the smaller node's link {kept:?}, was {link:?}"
    );
}

#[tokio::test]
async fn a_crossed_tcp_peer_the_larger_node_alone_drops_and_redials_is_held_outbound_at_one_end_and_inbound_at_the_other()
 {
    lone_drop(false).await;
}

/// [`a_crossed_tcp_peer_the_larger_node_alone_drops_and_redials_is_held_outbound_at_one_end_and_inbound_at_the_other`] with multipath on.
#[tokio::test]
async fn a_crossed_tcp_peer_the_larger_node_alone_drops_and_redials_is_held_outbound_at_one_end_and_inbound_at_the_other_with_multipath_on()
 {
    lone_drop(true).await;
}

#[tokio::test]
async fn a_peer_the_smaller_node_alone_drops_and_redials_then_the_larger_dials_again_stays_on_the_smaller_nodes_dial()
 {
    dial_after(false).await;
}

/// [`a_peer_the_smaller_node_alone_drops_and_redials_then_the_larger_dials_again_stays_on_the_smaller_nodes_dial`] with multipath on.
#[tokio::test]
async fn a_peer_the_smaller_node_alone_drops_and_redials_then_the_larger_dials_again_stays_on_the_smaller_nodes_dial_with_multipath_on()
 {
    dial_after(true).await;
}
