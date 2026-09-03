//! What the node does when the transport medium changes.
//!
//! The detector itself is tested in `node::netmon::tests`; these drive the
//! reaction. The property that matters is that a medium change *rebinds* the
//! send path without disturbing the peering — the peer keeps its Noise session,
//! its tree position and its routes, and only the socket underneath it moves.

use super::spanning_tree::*;
use super::*;
use crate::config::PeerConfig;
use crate::node::netmon::NetChange;
use crate::transport::TransportId;

/// Add `peer` to the node's config as an auto-connect peer.
///
/// Node config is immutable after construction, so this goes through the same
/// copy-on-write context swap the heartbeat tests use.
fn configure_auto_peer(node: &mut Node, peer: &PeerIdentity) {
    let peer_config = PeerConfig::new(peer.npub(), "udp", "127.0.0.1:1");
    node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.peers.push(peer_config);
        ctx.config = std::sync::Arc::new(cfg);
    });
}

/// The peer identity node `j` presents to its peers.
fn identity_of(nodes: &[TestNode], j: usize) -> PeerIdentity {
    PeerIdentity::from_pubkey_full(nodes[j].node.identity().pubkey_full())
}

/// Install a real `connect()`-ed UDP socket on a peer, the way the tick-driven
/// activation does.
///
/// The socket is opened against a discard port on loopback: nothing is ever
/// sent through it, and the test only cares whether the handle survives a
/// medium change.
#[cfg(target_os = "linux")]
fn install_connected_udp(node: &mut Node, addr: &NodeAddr, transport_id: TransportId) {
    let local: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    let peer_sa: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();

    let owned = crate::transport::udp::open_connected_fd(local, peer_sa, 65_536, 65_536)
        .expect("open a connected UDP socket");
    let bound = crate::transport::udp::ConnectedPeerSocket::from_fd(owned, peer_sa, local);
    let socket = std::sync::Arc::new(bound);
    let (packet_tx, _packet_rx) = crate::transport::packet_channel(8);
    let drain = crate::transport::udp::PeerRecvDrain::spawn(
        socket.clone(),
        transport_id,
        peer_sa,
        packet_tx,
    )
    .expect("spawn the peer recv drain");

    node.get_peer_mut(addr)
        .expect("peer present")
        .set_connected_udp(socket, drain);
}

/// **The defect this feature exists for.**
///
/// Established UDP peers get a per-peer `connect()`-ed socket. `open_connected_fd`
/// binds the wildcard and then calls `connect(2)`, which — as its own comment
/// says — "locks in the per-packet kernel route": the kernel resolves the route
/// once and auto-binds the local source address to whichever interface was
/// carrying it at that moment. It never re-evaluates.
///
/// So when the host changes medium, every peer keeps transmitting from an
/// address the routing table has abandoned, on a socket pinned to the interface
/// the node has just moved off. The only other code that drops these sockets
/// fires when the *peer* rotates its address — the mirror-image case. Nothing
/// covered a local move, and a local move is invisible in the data plane, which
/// is why it went unhandled.
///
/// Observed in the field as a peering that carried exactly one packet after a
/// route change and then stalled until the 30s liveness timeout, reporting
/// itself connected the whole time.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_medium_change_drops_connected_sockets_pinned_to_the_old_path() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let peer_1 = identity_of(&nodes, 1);
    configure_auto_peer(&mut nodes[0].node, &peer_1);

    let transport_id = nodes[0].transport_id;
    install_connected_udp(&mut nodes[0].node, &addr_1, transport_id);
    assert!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .connected_udp()
            .is_some(),
        "precondition: the peer holds a connected socket"
    );

    nodes[0]
        .node
        .handle_net_change(NetChange::for_test(1))
        .await;

    assert!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .connected_udp()
            .is_none(),
        "a socket pinned to the old source address must not survive the change"
    );
}

/// The rebind must not cost the peering. Everything above the socket — the
/// Noise session, the tree position, the routes — is unaffected by which local
/// address the node sends from, so a medium change that tore peers down would
/// be replacing a stall with a re-handshake for no reason.
#[tokio::test]
async fn a_medium_change_keeps_every_peering_intact() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let peer_1 = identity_of(&nodes, 1);
    configure_auto_peer(&mut nodes[0].node, &peer_1);
    let link_before = nodes[0].node.get_peer(&addr_1).unwrap().link_id();

    nodes[0]
        .node
        .handle_net_change(NetChange::for_test(1))
        .await;

    let peer = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("the peering must survive a medium change");
    assert_eq!(
        peer.link_id(),
        link_before,
        "the same link, not a rebuilt one: no re-handshake"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The far side has the same stale-address problem in reverse: it is still
/// sending to wherever it last heard us. One heartbeat over the new path
/// carries the node's new source address, so the peer re-pins on receipt rather
/// than waiting out its own heartbeat interval.
#[tokio::test]
async fn every_peer_is_heartbeated_so_the_far_side_re_pins() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let peer_1 = identity_of(&nodes, 1);
    configure_auto_peer(&mut nodes[0].node, &peer_1);

    let before = nodes[0]
        .node
        .get_peer(&addr_1)
        .unwrap()
        .last_heartbeat_sent();

    nodes[0]
        .node
        .handle_net_change(NetChange::for_test(1))
        .await;

    let after = nodes[0]
        .node
        .get_peer(&addr_1)
        .unwrap()
        .last_heartbeat_sent();
    assert!(
        after.is_some(),
        "every peer is heartbeated on a medium change"
    );
    assert!(
        before.is_none() || after > before,
        "the heartbeat must go now, not at the next due interval"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A node with no peers has nothing to rebind and must not care.
#[tokio::test]
async fn a_change_with_no_peers_is_harmless() {
    let mut node = make_node();
    node.handle_net_change(NetChange::for_test(1)).await;
    assert!(node.peers.is_empty());
}
