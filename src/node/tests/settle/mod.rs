//! Peer settlement tests on real nodes: how two nodes that dial each other,
//! restart, or rekey end up with one session on one link.
//!
//! The known-defect tests here assert the correct behaviour and fail today;
//! they are `#[ignore]`d and run by `testing/known-defect-lane.sh`, which
//! expects each to fail at its `defect:` assertion. Every assertion that
//! states the behaviour under test carries a message starting `defect:`, and
//! every setup check one starting `precondition:` (see `README.md`).
//!
//! This file holds the drivers the files share: real TCP nodes on
//! 127.0.0.1, a crossed TCP dial, delivery until the nodes are idle, and
//! the check that two nodes are left on one working session.

pub(super) mod audit;
mod bounds;
mod carry;
mod clock;
mod crossing;
mod fsp;
mod lane;
mod live;

use super::spanning_tree::{
    TestNode, add_loopback_alias, bridge_to_unbounded, cleanup_nodes, loopback_tap,
    make_test_node_with_config, process_available_packets,
};
use super::*;
use crate::config::TcpConfig;
use crate::proto::link::LinkMessageType;
use crate::transport::tcp::TcpTransport;
use crate::transport::{TransportHandle, TransportId};

/// `config` with multipath set as `on`. Every test here states the setting
/// it runs instead of taking the daemon's default, so a change of default
/// changes none of them.
pub(super) fn with_path(mut config: Config, on: bool) -> Config {
    config.node.path.enabled = on;
    config
}

/// A loopback test node with multipath set as `on`.
pub(super) async fn loopback_node(on: bool) -> TestNode {
    make_test_node_with_config(with_path(Config::new(), on), 1280).await
}

/// A node with one real TCP transport, transport id 1, listening on an
/// ephemeral port of 127.0.0.1, with multipath set as `on`.
pub(super) async fn tcp_node(on: bool) -> TestNode {
    let mut node = make_node_with(with_path(Config::new(), on));
    let transport_id = TransportId::new(1);
    let config = TcpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1400),
        ..Default::default()
    };
    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = TcpTransport::new(transport_id, None, config, packet_tx);
    transport
        .start_async()
        .await
        .expect("precondition: the TCP transport starts");
    let addr = TransportAddr::from_string(
        &transport
            .local_addr()
            .expect("precondition: the TCP transport is bound")
            .to_string(),
    );
    node.transports
        .insert(transport_id, TransportHandle::Tcp(transport));
    TestNode {
        node,
        transport_id,
        packet_rx: bridge_to_unbounded(packet_rx),
        addr,
    }
}

/// Two TCP nodes with multipath set as `on`, index 0 the smaller node
/// address when `zero_smaller`.
pub(super) async fn tcp_pair(on: bool, zero_smaller: bool) -> Vec<TestNode> {
    loop {
        let mut nodes = vec![tcp_node(on).await, tcp_node(on).await];
        if (nodes[0].node.node_addr() < nodes[1].node.node_addr()) == zero_smaller {
            return nodes;
        }
        cleanup_nodes(&mut nodes).await;
    }
}

/// The TCP pool's (inbound, outbound) connection counts at `tn`'s first
/// transport; (0, 0) when it has no TCP transport there.
pub(super) fn pool(tn: &TestNode) -> (u64, u64) {
    match tn.node.transports.get(&tn.transport_id) {
        Some(TransportHandle::Tcp(t)) => {
            let s = t.stats().snapshot();
            (s.pool_inbound, s.pool_outbound)
        }
        _ => (0, 0),
    }
}

/// Start a dial from `nodes[i]` to `nodes[j]`'s listening address through
/// `initiate_connection`, the path a configured peer takes.
pub(super) async fn tcp_dial(nodes: &mut [TestNode], i: usize, j: usize) {
    let id = PeerIdentity::from_pubkey_full(nodes[j].node.identity().pubkey_full());
    let addr = nodes[j].addr.clone();
    let tid = nodes[i].transport_id;
    nodes[i]
        .node
        .initiate_connection(tid, addr, Some(id))
        .await
        .expect("precondition: the dial starts");
}

/// Poll `tn`'s pending connects until none is left, for up to 2 s.
pub(super) async fn resolve_connect(tn: &mut TestNode) {
    for _ in 0..200 {
        tn.node.poll_pending_connects().await;
        if tn.node.peering.pending_connects.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("precondition: the TCP connect resolved within 2 s");
}

/// Deliver between the nodes, polling their pending connects, until ten
/// rounds 10 ms apart move nothing, or 300 rounds pass. Serves loopback and
/// TCP nodes alike: a TCP frame reaches the receive channel from the
/// connection's own task, so one idle round does not mean the nodes are
/// idle.
pub(super) async fn pump(nodes: &mut [TestNode]) {
    let mut idle = 0;
    for _ in 0..300 {
        for n in nodes.iter_mut() {
            n.node.poll_pending_connects().await;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        if process_available_packets(nodes).await == 0 {
            idle += 1;
            if idle >= 10 {
                return;
            }
        } else {
            idle = 0;
        }
    }
}

/// (packets received, consecutive decrypt failures) at `nodes[at]` for its
/// peer `nodes[from]`, or `None` when it does not hold that peer.
pub(super) fn received(nodes: &[TestNode], at: usize, from: usize) -> Option<(u64, u32)> {
    let from_addr = *nodes[from].node.node_addr();
    nodes[at].node.get_peer(&from_addr).map(|p| {
        (
            p.link_stats().packets_recv,
            p.consecutive_decrypt_failures(),
        )
    })
}

/// Whether a heartbeat `nodes[from]` sends now, on its current session,
/// authenticates at `nodes[to]`: it is sent, and after delivery `to` has
/// received more frames from `from` with no decrypt failure. Counters
/// already recorded do not count. The error says what was seen.
pub(super) async fn heartbeat_reaches(
    nodes: &mut [TestNode],
    from: usize,
    to: usize,
) -> Result<(), String> {
    let to_addr = *nodes[to].node.node_addr();
    let before = received(nodes, to, from);
    let sent = nodes[from]
        .node
        .send_encrypted_link_message(&to_addr, &[LinkMessageType::Heartbeat.to_byte()])
        .await;
    if let Err(e) = sent {
        return Err(format!("send failed ({e}); before {before:?}"));
    }
    pump(nodes).await;
    let after = received(nodes, to, from);
    match (before, after) {
        (Some((b, _)), Some((a, 0))) if a > b => Ok(()),
        _ => Err(format!("before {before:?} after {after:?}")),
    }
}

/// Whether `nodes[a]` and `nodes[b]` hold each other on one session, each
/// end's index the other's peer index, on which a heartbeat sent now
/// authenticates each way. The error says what was seen.
pub(super) async fn settled(nodes: &mut [TestNode], a: usize, b: usize) -> Result<(), String> {
    let a_addr = *nodes[a].node.node_addr();
    let b_addr = *nodes[b].node.node_addr();
    let at_a = nodes[a]
        .node
        .get_peer(&b_addr)
        .map(|p| (p.our_index(), p.their_index()));
    let at_b = nodes[b]
        .node
        .get_peer(&a_addr)
        .map(|p| (p.our_index(), p.their_index()));
    let same = matches!(
        (at_a, at_b),
        (Some((ao, at)), Some((bo, bt))) if ao.is_some() && ao == bt && at == bo
    );
    let fresh = [
        heartbeat_reaches(nodes, a, b).await,
        heartbeat_reaches(nodes, b, a).await,
    ];
    if same && fresh.iter().all(Result::is_ok) {
        Ok(())
    } else {
        Err(format!(
            "one session {same}; (ours, theirs) at node {a} {at_a:?}, at node {b} {at_b:?}; heartbeats {a} to {b}, back: {fresh:?}"
        ))
    }
}

/// Crossed TCP dials: both nodes dial each other through
/// `initiate_connection`, both connects resolve and both msg1s are sent
/// before either is read; then everything is delivered. Returns the nodes
/// and the indices of the smaller and the larger node.
pub(super) async fn crossed_tcp(on: bool, zero_smaller: bool) -> (Vec<TestNode>, usize, usize) {
    let mut nodes = tcp_pair(on, zero_smaller).await;
    let (s, l) = if zero_smaller { (0, 1) } else { (1, 0) };
    tcp_dial(&mut nodes, 0, 1).await;
    tcp_dial(&mut nodes, 1, 0).await;
    resolve_connect(&mut nodes[0]).await;
    resolve_connect(&mut nodes[1]).await;
    let s_out: Vec<u32> = nodes[s].node.pending_outbound.keys().map(|k| k.1).collect();
    assert_eq!(
        s_out.len(),
        1,
        "precondition: the smaller node's dial is pending"
    );
    assert_eq!(
        nodes[l].node.pending_outbound.len(),
        1,
        "precondition: the larger node's dial is pending"
    );
    assert_eq!(
        pool(&nodes[s]).1,
        1,
        "precondition: the smaller node holds its outbound connection"
    );
    assert_eq!(
        pool(&nodes[l]).1,
        1,
        "precondition: the larger node holds its outbound connection"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    pump(&mut nodes).await;
    let l_addr = *nodes[l].node.node_addr();
    let s_addr = *nodes[s].node.node_addr();
    assert_eq!(
        nodes[s].node.get_peer(&l_addr).and_then(|p| p.our_index()),
        Some(SessionIndex::new(s_out[0])),
        "precondition: the smaller node moved to its outbound session"
    );
    assert!(
        nodes[l].node.get_peer(&s_addr).is_some(),
        "precondition: the larger node holds the smaller"
    );
    (nodes, s, l)
}

/// Map session index `index` under transport `tid` to `peer` in `node`'s
/// session-index map, with no link machine binding it. The map is keyed by
/// the bare index, whatever transport the link runs on, so `tid` is not
/// part of the key; it is kept so a test names the transport it plants
/// for, and the planting is written once, here.
pub(super) fn bind_index(node: &mut Node, _tid: TransportId, index: u32, peer: NodeAddr) {
    node.peers_by_index.raw().insert(index, peer);
}

/// A second loopback address for the node listening on `existing`, for
/// transport `tid`: what is sent there lands in that node's receive channel,
/// registered under `tid`.
pub(super) fn alias(existing: &TransportAddr, tid: TransportId) -> TransportAddr {
    add_loopback_alias(existing, tid)
}

/// A new loopback address on transport `tid` whose packets land in the
/// returned channel, so a test sees what a node sends there. The address is
/// registered under `tid`.
pub(super) fn tap(
    tid: TransportId,
) -> (
    TransportAddr,
    tokio::sync::mpsc::UnboundedReceiver<ReceivedPacket>,
) {
    loopback_tap(tid)
}
