//! Where an outbound dial came from, carried by its control machine.
//!
//! The transport-neighbour dial loop marks its dials as neighbour claims and
//! every other dial site as addressed. On this line a transport neighbour is
//! dialled anonymously (its beacon names no key), so its leg names no peer
//! until msg2 and the per-node in-flight counts never see it; the mark is
//! still set at the dial and kept across the pending-connect to
//! handshake-leg hand-off, so the gates read it the same way on both lines.

use super::spanning_tree::{TestNode, cleanup_nodes, make_test_node};
use super::tcp::make_test_node_tcp;
use super::*;
use crate::peer::handshake::DialOrigin;

/// Drive `tn`'s pending connects until none is left, for at most about a
/// second.
async fn connect_pending(tn: &mut TestNode) {
    for _ in 0..100 {
        tn.node.poll_pending_connects().await;
        if tn.node.peering.pending_connects.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the pending connect did not resolve");
}

/// Dial node 1 from node 0 over TCP with `identity` and `origin`, and return
/// the origin the pending connect and then the handshake leg record.
async fn origins_over_tcp(
    identity: Option<PeerIdentity>,
    origin: DialOrigin,
) -> (DialOrigin, DialOrigin) {
    let mut nodes = vec![make_test_node_tcp().await, make_test_node_tcp().await];
    let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    nodes[0]
        .node
        .initiate_connection_from(tid, addr, identity, origin)
        .await
        .expect("the dial starts");
    let pending = &nodes[0].node.peering.pending_connects;
    assert_eq!(pending.len(), 1, "one connection-oriented dial is pending");
    let (link, at_connect) = (pending[0].link_id, pending[0].origin);
    connect_pending(&mut nodes[0]).await;
    let at_leg = nodes[0].node.handshakes[&link].dial_origin();
    cleanup_nodes(&mut nodes).await;
    (at_connect, at_leg)
}

#[tokio::test]
async fn an_anonymous_neighbour_dial_keeps_its_origin_from_pending_connect_to_handshake_leg() {
    assert_eq!(
        origins_over_tcp(None, DialOrigin::NeighbourClaim).await,
        (DialOrigin::NeighbourClaim, DialOrigin::NeighbourClaim)
    );
}

#[tokio::test]
async fn an_identified_dial_is_recorded_as_addressed_from_pending_connect_to_handshake_leg() {
    let peer = PeerIdentity::from_pubkey_full(Identity::generate().pubkey_full());
    assert_eq!(
        origins_over_tcp(Some(peer), DialOrigin::Addressed).await,
        (DialOrigin::Addressed, DialOrigin::Addressed)
    );
}

#[tokio::test]
async fn an_anonymous_connectionless_neighbour_dial_is_marked_on_its_leg() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    nodes[0]
        .node
        .initiate_connection_from(tid, addr, None, DialOrigin::NeighbourClaim)
        .await
        .expect("the dial starts");
    let origins: Vec<_> = nodes[0]
        .node
        .connections()
        .map(|(_, machine)| machine.dial_origin())
        .collect();
    cleanup_nodes(&mut nodes).await;
    assert_eq!(origins, vec![DialOrigin::NeighbourClaim]);
}
