//! A UDP dial to a hostname must not lose its handshake to a slow lookup.
//!
//! The UDP transport resolves hostnames off the receive loop and waits for a
//! lookup for at most a short bound. A manual `connect` is dialed once and is
//! not retried when its first handshake send fails, so a lookup that outlasts
//! the bound must not fail that send: the transport holds the handshake and
//! sends it when the address arrives, and a resend during the lookup is not
//! counted against the resend budget. Each test drives a real transport with
//! a test resolver in place of the system one, and dials `peer.invalid`, a
//! name that cannot resolve for real, so a resolver hook that did not take
//! effect fails at once instead of reaching the network.

use super::*;
use crate::config::UdpConfig;
use crate::peer::machine::TimerKind;
use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1};
use crate::transport::udp::{TestResolver, UdpTransport};
use crate::transport::{TransportError, TransportHandle, TransportId};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::timeout;

/// The id of the node's only transport.
const UDP_ID: u32 = 1;

/// Bound on every wait for a datagram; only a failure reaches it.
const RECV_BOUND: Duration = Duration::from_secs(5);

/// A test resolver that answers `answer` for every name, after `gate` is
/// released when there is one.
fn resolver(gate: Option<Arc<Notify>>, answer: Result<SocketAddr, String>) -> TestResolver {
    Arc::new(move |_| {
        let gate = gate.clone();
        let answer = answer.clone();
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.notified().await;
            }
            answer.map_err(TransportError::InvalidAddress)
        })
    })
}

/// A running node whose only transport is a started UDP transport on
/// loopback that resolves hostnames through `hook`.
async fn hooked_node(hook: TestResolver) -> (Node, SocketAddr) {
    let mut node = make_node();
    let (tx, rx) = packet_channel(1024);
    let cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let mut udp = UdpTransport::new(TransportId::new(UDP_ID), None, cfg, tx);
    udp.hook_resolver(hook);
    udp.start_async().await.unwrap();
    let local = udp.local_addr().unwrap();
    node.transports
        .insert(TransportId::new(UDP_ID), TransportHandle::Udp(udp));
    node.packet_rx = Some(rx);
    node.supervisor.state = NodeState::Running;
    (node, local)
}

/// Await a dial or a timer pass, failing the test if it runs past
/// `RECV_BOUND`. The gated resolver is released only after the dial returns,
/// so a dial that awaits the lookup inline would otherwise hang the test
/// instead of failing it.
async fn capped<T>(fut: impl std::future::Future<Output = T>) -> T {
    timeout(RECV_BOUND, fut)
        .await
        .expect("the node did not return: it waited on DNS inline")
}

/// A peer: a non-blocking socket on loopback and an identity to dial.
fn peer() -> (std::net::UdpSocket, SocketAddr, Identity) {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind peer");
    sock.set_nonblocking(true).unwrap();
    let addr = sock.local_addr().unwrap();
    (sock, addr, Identity::generate())
}

/// The next datagram on `sock`, waiting up to `RECV_BOUND` while letting the
/// transport's lookup task run.
async fn recv(sock: &std::net::UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buf = [0u8; 2048];
    timeout(RECV_BOUND, async {
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => return (buf[..n].to_vec(), from),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(5)).await
                }
                Err(e) => panic!("peer receive failed: {e}"),
            }
        }
    })
    .await
    .expect("no datagram reached the peer")
}

/// Whether `sock` has nothing waiting, read from the kernel buffer.
fn empty(sock: &std::net::UdpSocket) -> bool {
    let mut buf = [0u8; 2048];
    matches!(sock.recv_from(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
}

/// The outbound handshake leg toward `target`.
fn leg_toward(node: &Node, target: &NodeAddr) -> LinkId {
    let legs: Vec<LinkId> = node
        .peer_machines
        .iter()
        .filter(|(_, m)| {
            m.leg().is_some()
                && m.conn_expected_identity()
                    .is_some_and(|id| id.node_addr() == target)
        })
        .map(|(link, _)| *link)
        .collect();
    assert_eq!(legs.len(), 1, "expected one outbound leg, found {legs:?}");
    legs[0]
}

/// Whether `bytes` is a handshake msg1.
fn is_msg1(bytes: &[u8]) -> bool {
    CommonPrefix::parse(bytes).is_some_and(|p| p.phase == PHASE_MSG1)
}

/// Stop every transport, so no lookup task outlives the test's sockets.
async fn stop_all(node: &mut Node) {
    for (_, t) in node.transports.iter_mut() {
        t.stop().await.ok();
    }
}

/// A manual dial is not retried, so a slow lookup must not fail its first send.
#[tokio::test]
async fn manual_connect_to_a_hostname_whose_lookup_outlasts_the_cold_wait_sends_msg1_when_the_lookup_completes()
 {
    let (sock, peer_addr, peer_id) = peer();
    let gate = Arc::new(Notify::new());
    let (mut node, local) = hooked_node(resolver(Some(gate.clone()), Ok(peer_addr))).await;
    let dialed = format!("peer.invalid:{}", peer_addr.port());

    capped(node.api_connect(&peer_id.npub(), &dialed, "udp"))
        .await
        .expect("api_connect should dial");
    let link = leg_toward(&node, peer_id.node_addr());
    assert!(
        !node.peer_machines[&link].is_failed(),
        "a lookup still running must not fail the dial"
    );

    // A resend while the lookup runs is refused without being counted.
    let at = *node
        .peer_machines
        .timers()
        .get(&link)
        .and_then(|timers| timers.get(&TimerKind::HandshakeRetransmit))
        .expect("the retransmit timer should be armed");
    capped(node.drive_peer_timers(at)).await;
    assert_eq!(node.connection_resend_count(link), 0);
    assert!(!node.peer_machines[&link].is_failed());
    assert!(empty(&sock), "nothing may reach the peer before the lookup");

    gate.notify_one();
    let (first, from) = recv(&sock).await;
    assert_eq!(from, local, "msg1 should come from the transport's socket");
    assert!(is_msg1(&first), "the held datagram should be msg1");

    // The refused resend left its timer due; now it goes out and counts.
    capped(node.drive_peer_timers(at)).await;
    assert_eq!(node.connection_resend_count(link), 1);
    let (second, _) = recv(&sock).await;
    assert_eq!(second, first, "the resend carries the same msg1");

    node.check_timeouts().await;
    assert!(
        node.peer_machines.contains_key(&link),
        "the leg should still be in place"
    );
    stop_all(&mut node).await;
}

/// A healthy resolver still dials on the first send, as before the change.
#[tokio::test]
async fn manual_connect_to_a_hostname_with_a_healthy_resolver_sends_msg1_at_once() {
    let (sock, peer_addr, peer_id) = peer();
    let (mut node, _) = hooked_node(resolver(None, Ok(peer_addr))).await;
    let dialed = format!("peer.invalid:{}", peer_addr.port());

    capped(node.api_connect(&peer_id.npub(), &dialed, "udp"))
        .await
        .expect("api_connect should dial");
    let (bytes, _) = recv(&sock).await;
    assert!(is_msg1(&bytes));
    let link = leg_toward(&node, peer_id.node_addr());
    assert!(!node.peer_machines[&link].is_failed());
    stop_all(&mut node).await;
}

/// A lookup that fails inside the cold wait fails the dial as it always has.
#[tokio::test]
async fn manual_connect_to_a_hostname_whose_lookup_fails_fast_fails_the_leg_as_before() {
    let (sock, peer_addr, peer_id) = peer();
    let failure = Err("DNS resolution failed for peer.invalid: Name or service not known".into());
    let (mut node, _) = hooked_node(resolver(None, failure)).await;
    let dialed = format!("peer.invalid:{}", peer_addr.port());

    capped(node.api_connect(&peer_id.npub(), &dialed, "udp"))
        .await
        .expect("api_connect should dial");
    let link = leg_toward(&node, peer_id.node_addr());
    assert!(
        node.peer_machines[&link].is_failed(),
        "a lookup that fails at once should fail the leg, as it always has"
    );
    assert!(empty(&sock));
    stop_all(&mut node).await;
}
