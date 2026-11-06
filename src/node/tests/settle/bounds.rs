//! A pending dial under a spray of msg2s it cannot read: the dial is kept,
//! and the node's handshake state stays within its bounds.
//!
//! A party that saw a dialing node's msg1 can send it any number of msg2s
//! under the msg1's sender index: garbage with a valid point, or a real
//! msg2 captured from another handshake. Each is refused. These tests check
//! the attempt survives, that no forged msg2 grows any per-peer or
//! handshake map of the node, and that the genuine msg2 still completes the
//! dial afterwards. How many of them the node reads is not asserted.

use super::super::spanning_tree::{TestNode, cleanup_nodes};
use super::super::*;
use super::{loopback_node, pump};
use crate::noise::HANDSHAKE_MSG2_SIZE;
use crate::proto::fmp::wire::{Msg1Header, Msg2Header, build_msg2};

/// How many forged msg2s each test sends.
const SPRAY: u64 = 1000;

/// Node 0 dials node 1 through its own dial path. Returns the nodes, the
/// dial's link, the msg1 as it reached node 1 (unanswered) and its sender
/// index. Node 2 is the forger.
async fn dial_unanswered() -> (Vec<TestNode>, LinkId, ReceivedPacket, SessionIndex) {
    let mut nodes = vec![
        loopback_node(false).await,
        loopback_node(false).await,
        loopback_node(false).await,
    ];
    let node1 = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    nodes[0]
        .node
        .initiate_connection(tid, addr, node1)
        .await
        .expect("precondition: node 0 dials node 1");
    let msg1 = tokio::time::timeout(Duration::from_secs(1), nodes[1].packet_rx.recv())
        .await
        .expect("precondition: the msg1 reaches node 1")
        .expect("precondition: node 1's channel is open");
    let observed = Msg1Header::parse(&msg1.data)
        .expect("precondition: the msg1 parses")
        .sender_idx;
    let link = *nodes[0]
        .node
        .pending_outbound
        .get(&(tid, observed.as_u32()))
        .expect("precondition: the dial is registered under its msg1 index");
    (nodes, link, msg1, observed)
}

/// `noise` under the observed index, sent to node 0 from the forger's
/// address.
fn forged(nodes: &[TestNode], observed: SessionIndex, noise: &[u8]) -> ReceivedPacket {
    ReceivedPacket::new(
        nodes[0].transport_id,
        nodes[2].addr.clone(),
        build_msg2(SessionIndex::new(0x5EED_F00D), observed, noise),
    )
}

/// A full-length msg2 body whose ephemeral is a valid point and whose
/// encrypted epoch is garbage.
fn garbage_noise() -> Vec<u8> {
    let mut noise = Identity::generate().pubkey_full().serialize().to_vec();
    noise.resize(HANDSHAKE_MSG2_SIZE, 0xA5);
    noise
}

/// A real msg2 captured off the wire from another handshake: node 2 dials
/// node 1, node 1 answers, and the forger keeps the answer's noise body.
async fn captured_real_noise(nodes: &mut [TestNode]) -> Vec<u8> {
    let node1 = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let (tid, addr) = (nodes[2].transport_id, nodes[1].addr.clone());
    nodes[2]
        .node
        .initiate_connection(tid, addr, node1)
        .await
        .expect("precondition: node 2 dials node 1");
    let msg1 = tokio::time::timeout(Duration::from_secs(1), nodes[1].packet_rx.recv())
        .await
        .expect("precondition: node 2's msg1 reaches node 1")
        .expect("precondition: node 1's channel is open");
    nodes[1].node.handle_msg1(msg1).await;
    let msg2 = tokio::time::timeout(Duration::from_secs(1), nodes[2].packet_rx.recv())
        .await
        .expect("precondition: node 1 answers node 2")
        .expect("precondition: node 2's channel is open");
    let header = Msg2Header::parse(&msg2.data).expect("precondition: the msg2 parses");
    msg2.data[header.noise_msg2_offset..].to_vec()
}

/// The sizes of every map a msg2 could grow on `node`, by name, the
/// per-peer ones for each of `others`.
fn sizes(node: &Node, others: &[NodeAddr]) -> Vec<(&'static str, usize)> {
    let mut sizes = vec![
        ("peers", node.peers.len()),
        ("peer_machines", node.peer_machines.len()),
        ("pending_outbound", node.pending_outbound.len()),
        ("links", node.links.len()),
        ("addr_to_link", node.addr_to_link.len()),
        ("peers_by_index", node.peers_by_index.len()),
        ("index_allocator", node.index_allocator.count()),
        ("link_records", node.link_records.len()),
        ("restart_dampener", node.restart_dampener.len()),
    ];
    for peer in others {
        sizes.push(("replayed_msg1s", node.replayed_msg1s.count(peer)));
        let silent = node.silent_sessions.count(peer).unwrap_or(0);
        sizes.push(("silent_sessions", silent as usize));
    }
    sizes
}

/// Spray node 0's pending dial with forged msg2s, then let node 1's genuine
/// answer through. The dial must be pending after the spray, no forged msg2
/// may have found the dial gone, no map may have grown, and the genuine
/// msg2 must complete the dial.
async fn spray_keeps_the_dial(replay: bool) {
    let (mut nodes, link, msg1, observed) = dial_unanswered().await;
    let tid = nodes[0].transport_id;
    let noise = if replay {
        captured_real_noise(&mut nodes).await
    } else {
        garbage_noise()
    };
    let packet = forged(&nodes, observed, &noise);
    let others = [*nodes[1].node.node_addr(), *nodes[2].node.node_addr()];
    let unknown_before = nodes[0].node.stats().handshake.unknown_connection;
    let before = sizes(&nodes[0].node, &others);
    for _ in 0..SPRAY {
        nodes[0].node.handle_msg2(packet.clone()).await;
    }
    let after = sizes(&nodes[0].node, &others);
    let mut bad = Vec::new();
    let unknown = nodes[0].node.stats().handshake.unknown_connection - unknown_before;
    if unknown != 0 {
        bad.push(format!("{unknown} forged msg2s found the dial gone"));
    }
    if nodes[0]
        .node
        .pending_outbound
        .get(&(tid, observed.as_u32()))
        != Some(&link)
    {
        bad.push("the dial is not pending after the spray".to_string());
    }
    for ((name, b), (_, a)) in before.iter().zip(after.iter()) {
        if a > b {
            bad.push(format!("{name} grew from {b} to {a}"));
        }
    }
    let node1 = *nodes[1].node.node_addr();
    nodes[1].node.handle_msg1(msg1).await;
    let genuine = tokio::time::timeout(Duration::from_secs(1), nodes[0].packet_rx.recv())
        .await
        .expect("precondition: node 1's genuine msg2 is queued")
        .expect("precondition: node 0's channel is open");
    nodes[0].node.handle_msg2(genuine).await;
    pump(&mut nodes).await;
    if nodes[0].node.get_peer(&node1).is_none() {
        bad.push("the genuine msg2 did not complete the dial".to_string());
    }
    cleanup_nodes(&mut nodes).await;
    assert!(bad.is_empty(), "defect: {bad:#?}");
}

#[tokio::test]
async fn a_pending_dial_keeps_its_attempt_and_bounded_state_through_garbage_msg2s() {
    spray_keeps_the_dial(false).await;
}

#[tokio::test]
async fn a_pending_dial_keeps_its_attempt_and_bounded_state_through_replayed_msg2s() {
    spray_keeps_the_dial(true).await;
}
