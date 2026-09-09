//! What the node does when the transport medium changes.
//!
//! The detector itself is tested in `node::netmon::tests`; these drive the
//! reaction. The property that matters is that a medium change *rebinds* the
//! send path without disturbing the peering — the peer keeps its Noise session,
//! its tree position and its routes, and only the socket underneath it moves.

use super::spanning_tree::*;
use super::*;
use crate::config::PeerConfig;
use crate::config::TcpConfig;
use crate::node::netmon::{NetChange, NetFingerprint, ProbeTarget};
use crate::transport::tcp::TcpTransport;
use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};

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
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
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
        .handle_net_change(NetChange::for_test_moved(1, &[addr_1]))
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

/// **A peer the change did not name keeps its socket.**
///
/// The reaction is scoped to `change.summary.moved`, and that is not an
/// optimisation. Keying the sample on peers put the trigger within reach of a
/// remote party: `probe_target` is the observed source of every authentic
/// packet, updated with no throttle, so a peer alternating between two
/// addresses can move the fingerprint at will. Node-wide, that peer could tear
/// down every other peering's send path on repeat. If this test starts failing
/// because the untouched peer lost its socket, that lever is back.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_peer_the_change_did_not_name_keeps_its_socket() {
    let mut nodes = run_tree_test(3, &[(0, 1), (0, 2)], false).await;
    verify_tree_convergence(&nodes);

    let moved = *nodes[1].node.node_addr();
    let untouched = *nodes[2].node.node_addr();
    let transport_id = nodes[0].transport_id;
    install_connected_udp(&mut nodes[0].node, &moved, transport_id);
    install_connected_udp(&mut nodes[0].node, &untouched, transport_id);

    let heartbeat_before = nodes[0]
        .node
        .get_peer(&untouched)
        .unwrap()
        .last_heartbeat_sent();

    nodes[0]
        .node
        .handle_net_change(NetChange::for_test_moved(1, &[moved]))
        .await;

    assert!(
        nodes[0]
            .node
            .get_peer(&moved)
            .unwrap()
            .connected_udp()
            .is_none(),
        "the peer that moved must lose its pinned socket"
    );
    assert!(
        nodes[0]
            .node
            .get_peer(&untouched)
            .unwrap()
            .connected_udp()
            .is_some(),
        "a peer whose source address did not move must keep its socket"
    );
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&untouched)
            .unwrap()
            .last_heartbeat_sent(),
        heartbeat_before,
        "and must not be heartbeated for another peer's move"
    );

    cleanup_nodes(&mut nodes).await;
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
        .handle_net_change(NetChange::for_test_moved(1, &[addr_1]))
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
        .handle_net_change(NetChange::for_test_moved(1, &[addr_1]))
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

/// A peer on a connection-oriented transport is deliberately left out of the
/// immediate fan-out.
///
/// The hazard the filter was written for is gone: every connection-oriented
/// send now enqueues onto its connection's bounded queue and returns, so none
/// of them can await the wire from the rx loop any more. The exclusion is kept
/// anyway, so that widening the fan-out is its own change with its own
/// evidence rather than a side effect of the one that bounded the write. Such
/// a peer keeps the periodic heartbeat it had before this detector existed.
///
/// **So this test guards a deliberate boundary, not a stall.** If the fan-out
/// is widened on purpose, this test is the thing to change, and changing it is
/// how that decision gets recorded.
///
/// The attempt stamp is the observation that sees the exclusion. The fan-out
/// records it for every peer it picks, before the send, and records the sent
/// stamp only for a send that returned. A connection-oriented send fails at
/// the readiness gate, so the sent stamp would sit still either way — whether
/// the peer was excluded or picked and failed — and on its own it cannot tell
/// the two apart.
#[tokio::test]
async fn a_peer_on_a_connection_oriented_transport_is_left_to_the_periodic_heartbeat() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let peer_1 = identity_of(&nodes, 1);
    configure_auto_peer(&mut nodes[0].node, &peer_1);

    // Re-pin the peer onto a TCP transport. Nothing is connected on it, which
    // is the point: the fan-out must decide from the transport's kind, before
    // it ever reaches a send.
    let tcp_id = TransportId::new(77);
    let cfg = TcpConfig {
        bind_addr: None,
        ..Default::default()
    };
    let (tx, _rx) = packet_channel(64);
    nodes[0].node.transports.insert(
        tcp_id,
        TransportHandle::Tcp(TcpTransport::new(tcp_id, None, cfg, tx)),
    );
    nodes[0]
        .node
        .peers
        .get_mut(&addr_1)
        .expect("peer 1 is established")
        .set_current_addr(tcp_id, TransportAddr::from_string("10.0.0.2:2121"));

    let before = nodes[0]
        .node
        .get_peer(&addr_1)
        .unwrap()
        .last_heartbeat_sent();

    nodes[0]
        .node
        .handle_net_change(NetChange::for_test_moved(1, &[addr_1]))
        .await;

    let after = nodes[0]
        .node
        .get_peer(&addr_1)
        .unwrap()
        .last_heartbeat_sent();
    assert_eq!(
        before, after,
        "a connection-oriented peer must not be heartbeated from the rx loop"
    );
    assert!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .last_heartbeat_attempt()
            .is_none(),
        "a connection-oriented peer must not even be attempted from the rx loop"
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

/// The detector reads the peer table through the published entity snapshot,
/// and this is the seam: what a peer's transport address is determines whether
/// it arrives on the other side as something to probe. Nothing else in the
/// tree exercises `PeerRow::probe_target`, because nothing renders it — so if
/// the publish site stopped populating it, every other test here would still
/// pass while the detector silently probed an empty table and never reported
/// anything again.
///
/// Each case re-pins the same established peer, because the address is the
/// only variable that matters: the projection is a property of the address,
/// not of the transport it was learned on. (The harness's own peers sit on a
/// synthetic `loopback:1` transport, which is itself correctly unprobeable.)
#[tokio::test]
async fn only_a_peer_with_an_ip_endpoint_reaches_the_probe() {
    // (address as the peer carries it, the destination the detector should
    // probe, why)
    let cases: [(TransportAddr, Option<&str>, &str); 6] = [
        (
            TransportAddr::from_string("10.0.0.2:2121"),
            Some("10.0.0.2:2121"),
            "an ordinary IPv4 peer is the whole point",
        ),
        (
            TransportAddr::from_string("[2001:db8::1]:2121"),
            Some("[2001:db8::1]:2121"),
            "IPv6 literals round-trip through the row",
        ),
        (
            TransportAddr::from_bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            None,
            "a MAC has no IP destination to ask the routing table about",
        ),
        (
            TransportAddr::from_string("example.com:2121"),
            None,
            "resolving a hostname would put DNS on the detector's sample path",
        ),
        (
            TransportAddr::from_string("abcdefghij234567.onion:2121"),
            None,
            "a .onion is reached through a local proxy, not a route",
        ),
        (
            TransportAddr::from_string("[fe80::1%eth0]:2121"),
            None,
            "a scoped link-local literal is not a parseable SocketAddr",
        ),
    ];

    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let transport_id = nodes[0]
        .node
        .peers
        .get(&addr_1)
        .and_then(|p| p.transport_id())
        .expect("peer 1 has a transport");

    for (addr, expected, why) in cases {
        nodes[0]
            .node
            .peers
            .get_mut(&addr_1)
            .expect("peer 1 is established")
            .set_current_addr(transport_id, addr.clone());

        // The snapshot is published from the tick, which is its only writer.
        nodes[0].node.record_stats_history();
        let snapshot = nodes[0].node.entities_snapshot.load_full();

        let got = crate::node::netmon::probe_targets(&snapshot)
            .into_iter()
            .find(|t| t.peer == addr_1)
            .map(|t| t.dest);

        let want = expected.map(|s| s.parse::<std::net::SocketAddr>().unwrap());
        assert_eq!(got, want, "{}: {}", addr, why);
    }

    cleanup_nodes(&mut nodes).await;
}

/// The seed the join-window fix rests on, wired end to end.
///
/// A peer the detector has not seen before is judged against the source its
/// connected socket was pinned to, and that value has to be the address
/// `connect(2)` actually chose — not the wildcard the bind was requested with.
/// `ConnectedPeerSocket::local_addr()` is the wildcard (`0.0.0.0:port`), and
/// reading *that* would compare an unspecified address against a real one for
/// every peer, so every peer joining would report a medium change: precisely
/// the "peer churn fires the fan-out" behaviour the intersection rule exists to
/// prevent. Nothing renders `bound_source`, so no other test would notice.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::test]
async fn a_peers_connected_socket_publishes_the_source_it_was_pinned_to() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let transport_id = nodes[0]
        .node
        .peers
        .get(&addr_1)
        .and_then(|p| p.transport_id())
        .expect("peer 1 has a transport");

    // No socket yet: nothing to seed from, and the peer must say so rather
    // than offering the wildcard.
    nodes[0].node.record_stats_history();
    let row = |n: &Node| {
        n.entities_snapshot
            .load_full()
            .peers
            .iter()
            .find(|r| r.node_addr == addr_1)
            .expect("peer 1 has a row")
            .clone()
    };
    assert_eq!(
        row(&nodes[0].node).bound_source,
        None,
        "a peer with no connected socket has no pinned source to be judged against"
    );

    // The helper connects to 127.0.0.1:9, so the kernel pins the loopback
    // source — a real address, and demonstrably not the `0.0.0.0` the bind was
    // requested with.
    install_connected_udp(&mut nodes[0].node, &addr_1, transport_id);
    // The harness peers sit on a synthetic `loopback:1` address, which is
    // correctly not probeable. Re-pin to a numeric endpoint on the same
    // transport so the row reaches the probe at all — the pinned source is a
    // property of the socket, not of the address, and survives this.
    nodes[0]
        .node
        .peers
        .get_mut(&addr_1)
        .expect("peer 1 is established")
        .set_current_addr(transport_id, TransportAddr::from_string("10.0.0.2:2121"));
    nodes[0].node.record_stats_history();

    assert_eq!(
        row(&nodes[0].node).bound_source,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        "the published source must be what connect(2) pinned, not the wildcard bind"
    );

    // Publishing it is only half the wiring. Nothing else asserts that
    // `probe_targets` carries `bound_source` through to the target, so
    // substituting `None` there leaves the whole suite green while silently
    // restoring the bug the first-sight rule exists to fix — the same failure
    // class as reading the wildcard `local_addr()`, one layer further on.
    let snapshot = nodes[0].node.entities_snapshot.load_full();
    let target = crate::node::netmon::probe_targets(&snapshot)
        .into_iter()
        .find(|t| t.peer == addr_1)
        .expect("an established UDP peer must be probeable");
    assert_eq!(
        target.bound,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        "the pinned source must reach the probe target, not stop at the row"
    );

    // And the last link: `sample()` has to carry it into the fingerprint, or a
    // first-seen peer is judged against nothing again. An empty previous
    // fingerprint is exactly the first-sight case, and the peer's socket is
    // pinned to loopback while the probe answers for a routable destination,
    // so the two disagree and a move must be reported.
    let sampled = NetFingerprint::sample(&[ProbeTarget {
        peer: addr_1,
        dest: "192.0.2.1:9".parse().unwrap(),
        bound: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        bind: None,
    }]);
    assert!(
        !NetFingerprint::default().moved(&sampled).is_empty(),
        "sample() must carry the pinned source into the fingerprint, or first \
         sight has nothing to judge against"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A heartbeat that did not go out must not be counted as one that did — in
/// the operator log, or in the peer's own idea of when it was last heard from.
///
/// A medium change is exactly the condition under which sends start failing,
/// so a count of peers *selected* would read identically whether every frame
/// left or none did, and the peer would then be suppressed for a full
/// `heartbeat_interval_secs` on the strength of a send that never landed.
///
/// The peer is re-pinned onto a UDP transport that was never started, which is
/// connectionless — so the fan-out selects it — and fails its send with
/// `NotStarted` before touching a socket.
#[tokio::test]
async fn a_heartbeat_that_failed_is_not_counted_and_does_not_suppress_the_next() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let peer_1 = identity_of(&nodes, 1);
    configure_auto_peer(&mut nodes[0].node, &peer_1);

    let dead_id = TransportId::new(88);
    let (tx, _rx) = packet_channel(64);
    nodes[0].node.transports.insert(
        dead_id,
        TransportHandle::Udp(crate::transport::udp::UdpTransport::new(
            dead_id,
            None,
            crate::config::UdpConfig::default(),
            tx,
        )),
    );
    nodes[0]
        .node
        .peers
        .get_mut(&addr_1)
        .expect("peer 1 is established")
        .set_current_addr(dead_id, TransportAddr::from_string("10.0.0.2:2121"));

    let before = nodes[0]
        .node
        .get_peer(&addr_1)
        .unwrap()
        .last_heartbeat_sent();

    let sent = nodes[0]
        .node
        .heartbeat_moved_peers_after_net_change(&[addr_1])
        .await;

    assert_eq!(
        sent, 0,
        "the count reports sends that succeeded, not peers picked out"
    );

    let peer = nodes[0].node.get_peer(&addr_1).unwrap();
    assert_eq!(
        peer.last_heartbeat_sent(),
        before,
        "a failed heartbeat must not move the interval that says the peer has heard from us"
    );
    assert!(
        peer.last_heartbeat_attempt().is_some(),
        "the attempt is still recorded, or a failing peer would be retried every tick"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The transport's bind address has to reach the probe, or the detector asks
/// the routing table a different question than the send path answers.
///
/// `open_connected_fd` binds `transports.udp.bind_addr` verbatim before it
/// connects, so under a non-wildcard bind the source is pinned to that address
/// whatever the route says. A probe left unconstrained takes the kernel's
/// choice instead, the two answers differ permanently, and every first-seen
/// peer reports a move that never happened. Nothing renders the field, so
/// substituting `None` at either the publish or the read leaves the rest of
/// the suite green.
///
/// The transport is started on `127.0.0.1:0`: `start_async` fills `local_addr`
/// from the socket the kernel actually bound, which is what the publish reads
/// and what the `!is_unspecified()` filter admits. No privileges are needed.
#[tokio::test]
async fn a_transports_bind_address_reaches_the_probe_target() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();

    let bound_id = TransportId::new(99);
    let (tx, _rx) = packet_channel(64);
    let mut udp = crate::transport::udp::UdpTransport::new(
        bound_id,
        None,
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        tx,
    );
    udp.start_async()
        .await
        .expect("bind a UDP socket on loopback");
    assert_eq!(
        udp.local_addr().map(|sa| sa.ip()),
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        "precondition: the transport is bound to a real address, not the wildcard"
    );
    nodes[0]
        .node
        .transports
        .insert(bound_id, TransportHandle::Udp(udp));

    // The harness peers sit on a synthetic `loopback:1` address, which is
    // correctly not probeable. Re-pin onto the bound transport with a numeric
    // endpoint so the row reaches the probe at all.
    nodes[0]
        .node
        .peers
        .get_mut(&addr_1)
        .expect("peer 1 is established")
        .set_current_addr(bound_id, TransportAddr::from_string("10.0.0.2:2121"));

    // The snapshot is published from the tick, which is its only writer.
    nodes[0].node.record_stats_history();
    let snapshot = nodes[0].node.entities_snapshot.load_full();
    let target = crate::node::netmon::probe_targets(&snapshot)
        .into_iter()
        .find(|t| t.peer == addr_1)
        .expect("a peer with a numeric endpoint must be probeable");
    assert_eq!(
        target.bind,
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        "the transport's bind address must reach the probe target, not stop at the row"
    );

    cleanup_nodes(&mut nodes).await;
}
