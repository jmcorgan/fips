//! A path to a receiver whose UDP MTU is smaller than the sender's. A
//! probe on a Probing path is padded to the sender's own link MTU (draft
//! Section 5.1, step 1, where padding is local), and a UDP receiver reads
//! into a buffer of its own MTU plus 100 bytes, so a padded probe from a
//! sender with the larger MTU arrives cut short, fails to authenticate and
//! is dropped. Each test runs two linked nodes over the loopback transport
//! and gives each a second, real UDP transport on 127.0.0.1, so the
//! receiver's buffer is the one a deployed node reads into.

use super::paths::{enabled, state_at};
use super::rekey_parity::{deliver, linked_pair};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;
use crate::config::UdpConfig;
use crate::peer::{PathState, peer_now};
use crate::transport::PacketRx;
use crate::transport::udp::UdpTransport;

/// The identifier of each node's second transport, the UDP one.
fn udp_id() -> TransportId {
    TransportId::new(2)
}

/// Give `tn` a UDP transport `udp_id()` on 127.0.0.1 with MTU `mtu`, and
/// return its address and the channel its datagrams arrive on.
async fn udp_on(tn: &mut TestNode, mtu: u16) -> (TransportAddr, PacketRx) {
    let (tx, rx) = packet_channel(256);
    let cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(mtu),
        ..Default::default()
    };
    let mut udp = UdpTransport::new(udp_id(), None, cfg, tx);
    udp.start_async()
        .await
        .expect("precondition: the UDP transport binds on 127.0.0.1");
    let addr = TransportAddr::from_string(
        &udp.local_addr()
            .expect("precondition: a bound UDP transport has an address")
            .to_string(),
    );
    tn.node
        .transports
        .insert(udp_id(), TransportHandle::Udp(udp));
    (addr, rx)
}

/// Hand every frame waiting at either node, on the loopback transport or
/// on its UDP channel in `udp`, to that node, until three rounds a few
/// milliseconds apart move none, so a datagram still in the kernel is
/// waited for.
async fn settle(nodes: &mut [TestNode], udp: &mut [PacketRx]) {
    let mut idle = 0;
    while idle < 3 {
        let mut moved = 0;
        for (tn, rx) in nodes.iter_mut().zip(udp.iter_mut()) {
            while let Ok(packet) = rx.try_recv() {
                tn.node.handle_encrypted_frame(packet).await;
                moved += 1;
            }
            moved += deliver(tn).await;
        }
        if moved == 0 {
            idle += 1;
            tokio::time::sleep(Duration::from_millis(5)).await;
        } else {
            idle = 0;
        }
    }
}

/// The earliest wake of either node's machine for the other.
fn next_wake(nodes: &[TestNode]) -> Option<crate::peer::PeerInstant> {
    let wake = |k: usize| {
        let peer = nodes[1 - k].node.node_addr();
        nodes[k].node.get_peer(peer)?.bundle()?.next_wake()
    };
    match (wake(0), wake(1)) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Link A (node 0) and B (node 1) with multipath enabled over the
/// loopback transport, give A a UDP transport of MTU 1472 and B one of MTU
/// `b_mtu`, and have A offer B's UDP address to its machine. Then step
/// both machines at each wake, every frame delivered between steps, until
/// A's path to B's UDP address is Live or Dead, or 40 s have passed on the
/// node clock. Returns the path's states at A in order, from the first it
/// was seen in, the MTU it proved, and how many datagrams A sent on its UDP
/// transport.
async fn prove(b_mtu: u16) -> (Vec<PathState>, Option<usize>, u64) {
    // The test addresses of the loopback transport read as Internet
    // addresses and 127.0.0.1 as a local one, so the link may hold paths
    // of both kinds.
    let mixed = || {
        let mut cfg = enabled();
        cfg.node.path.mix_kinds = true;
        cfg
    };
    let mut nodes = linked_pair(mixed(), mixed()).await;
    let (_, a_rx) = udp_on(&mut nodes[0], 1472).await;
    let (b_udp, b_rx) = udp_on(&mut nodes[1], b_mtu).await;
    let mut udp = [a_rx, b_rx];
    let b = *nodes[1].node.node_addr();
    nodes[0].node.offer_path(&b, udp_id(), b_udp.clone()).await;
    let mut seen = Vec::new();
    let note = |nodes: &[TestNode], seen: &mut Vec<PathState>| {
        let now = state_at(&nodes[0], &b, udp_id(), &b_udp);
        if let Some(s) = now.filter(|s| seen.last() != Some(s)) {
            seen.push(s);
        }
    };
    settle(&mut nodes, &mut udp).await;
    note(&nodes, &mut seen);
    let end = fips_core::time::deadline(peer_now(), Duration::from_secs(40));
    while !matches!(seen.last(), Some(PathState::Live | PathState::Dead)) {
        let Some(wake) = next_wake(&nodes).filter(|w| *w <= end) else {
            break;
        };
        {
            use fips_core::time::Instant as _;
            crate::time::advance(wake.saturating_duration_since(peer_now()));
        }
        for tn in nodes.iter_mut() {
            tn.node.path_tick().await;
        }
        settle(&mut nodes, &mut udp).await;
        note(&nodes, &mut seen);
    }
    let sent = match nodes[0].node.transports.get(&udp_id()) {
        Some(TransportHandle::Udp(t)) => t.stats().snapshot().packets_sent,
        _ => 0,
    };
    let mtu = nodes[0].node.get_peer(&b).and_then(|peer| {
        let paths = peer.bundle()?.paths();
        paths.get(paths.find(udp_id(), &b_udp)?)?.live().mtu()
    });
    cleanup_nodes(&mut nodes).await;
    (seen, mtu, sent)
}

/// A's path to B's UDP address is proven when B's MTU is as large as A's,
/// with the MTU of A's padded probe, which shows the run can prove a path,
/// and also when B's is smaller, so A's padded probe, 1472 bytes, is cut
/// at B's 1380-byte buffer: the path still reaches Live within its
/// discovery probes, by a probe of the smallest size, which proves no MTU.
#[tokio::test]
async fn a_path_to_a_receiver_with_a_smaller_udp_mtu_is_proven() {
    let padded = 1472 - crate::proto::fmp::wire::FRAME_OVERHEAD;
    let (control, mtu, _) = prove(1472).await;
    assert_eq!(
        (control.last(), mtu),
        (Some(&PathState::Live), Some(padded)),
        "precondition: proven at equal MTUs: {control:?}"
    );
    let (smaller, mtu, sent) = prove(1280).await;
    assert!(
        !smaller.contains(&PathState::Dead) && smaller.last() == Some(&PathState::Live),
        "proven toward the smaller MTU: {smaller:?}, {sent} datagrams sent on A's UDP transport"
    );
    assert_eq!(mtu, None, "a probe of the smallest size proves no MTU");
}
