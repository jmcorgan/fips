//! What a refused msg2 costs a dialling node, and that refusing any number of
//! them leaves the genuine msg2 able to finish the handshake.
//!
//! A msg2 names the dialling node's pending attempt by the index that travels
//! in cleartext in msg1, so anyone who saw the msg1 can send msg2s under it.
//! Nothing short of reading a msg2 tells the responder's from a forgery, and a
//! forgery must not end the attempt, so every one is read. A msg2 that does
//! not come from the responder's ephemeral fails at its encrypted static key,
//! after one DH, `ee`; the `es` DH that follows needs the static that failed
//! to decrypt. These tests count the DHs across the refused reads, then
//! deliver the genuine msg2 and check that it completes the first dial or the
//! rekey.

use super::*;
use crate::node::tests::link_session_diag::{
    HeldMsg2Pair, complete_held, rekey_pair_with_held_msg2,
};
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, make_test_node, process_available_packets,
};
use crate::noise::{HANDSHAKE_MSG2_SIZE, dh_ops};
use crate::proto::fmp::wire::{Msg1Header, Msg2Header, build_msg2};
use crate::transport::ReceivedPacket;
use crate::utils::index::SessionIndex;

/// Refused msg2s of each kind delivered per test. Large enough that a
/// per-message regression in the DH count cannot hide in the total.
const N: u64 = 256;

/// Deliver queued packets until a round moves none, at most 50 rounds.
async fn pump_until_quiet(nodes: &mut [TestNode]) {
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if process_available_packets(nodes).await == 0 {
            break;
        }
    }
}

/// A full-length msg2 body whose ephemeral is a valid point and whose
/// encrypted static key does not authenticate.
fn garbage_noise() -> Vec<u8> {
    let mut noise = Identity::generate().pubkey_full().serialize().to_vec();
    noise.resize(HANDSHAKE_MSG2_SIZE, 0xA5);
    noise
}

/// `noise` under `observed`, delivered to `to` as if sent from `from`.
fn msg2_under(
    to: &TestNode,
    from: &TransportAddr,
    observed: SessionIndex,
    noise: &[u8],
) -> ReceivedPacket {
    ReceivedPacket::new(
        to.transport_id,
        from.clone(),
        build_msg2(SessionIndex::new(0x5EED_F00D), observed, noise),
    )
}

/// The next packet in `node`'s queue, waiting at most a second for it.
async fn next_packet(node: &mut TestNode) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(1), node.packet_rx.recv())
        .await
        .expect("a packet arrives")
        .expect("the node's channel is open")
}

/// A real msg2 captured from another handshake: node 2 dials node 1, node 1
/// answers, and the forger keeps the answer's noise body.
async fn captured_real_noise(nodes: &mut [TestNode]) -> Vec<u8> {
    let node1 = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let (tid, addr) = (nodes[2].transport_id, nodes[1].addr.clone());
    nodes[2]
        .node
        .initiate_connection(tid, addr, Some(node1))
        .await
        .expect("node 2 dials node 1");
    let msg1 = next_packet(&mut nodes[1]).await;
    nodes[1].node.handle_msg1(msg1).await;
    let msg2 = next_packet(&mut nodes[2]).await;
    let header = Msg2Header::parse(&msg2.data).expect("node 1's msg2 parses");
    msg2.data[header.noise_msg2_offset..].to_vec()
}

#[tokio::test]
async fn a_pending_dial_spends_one_dh_on_each_refused_msg2_and_the_genuine_msg2_still_completes_it()
{
    let mut nodes = vec![
        make_test_node().await,
        make_test_node().await,
        make_test_node().await, // node 2 is the forger: it takes no part in the dial
    ];
    let node1_addr = *nodes[1].node.identity().node_addr();
    let node1 = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    nodes[0]
        .node
        .initiate_connection(tid, addr, Some(node1))
        .await
        .expect("node 0 dials node 1");

    // The forger reads the cleartext sender index off the msg1 on the wire.
    let msg1 = next_packet(&mut nodes[1]).await;
    let observed = Msg1Header::parse(&msg1.data)
        .expect("msg1 parses")
        .sender_idx;
    let replay = captured_real_noise(&mut nodes).await;

    // Node 1 answers; hold its genuine msg2 back from node 0.
    nodes[1].node.handle_msg1(msg1).await;
    let genuine = next_packet(&mut nodes[0]).await;

    let forger = nodes[2].addr.clone();
    let garbage = msg2_under(&nodes[0], &forger, observed, &garbage_noise());
    let replayed = msg2_under(&nodes[0], &forger, observed, &replay);

    let dh_before = dh_ops();
    for _ in 0..N {
        nodes[0].node.handle_msg2(garbage.clone()).await;
        nodes[0].node.handle_msg2(replayed.clone()).await;
    }
    let spent = dh_ops() - dh_before;

    assert_eq!(
        spent,
        2 * N,
        "each of the {} refused msg2s must cost exactly one DH",
        2 * N
    );
    assert!(
        nodes[0].node.get_peer(&node1_addr).is_none(),
        "no forged msg2 completes the dial"
    );

    nodes[0].node.handle_msg2(genuine).await;
    pump_until_quiet(&mut nodes).await;
    assert!(
        nodes[0].node.get_peer(&node1_addr).is_some(),
        "the genuine msg2 must complete the dial after {} refused msg2s",
        2 * N
    );

    // Once the dial has completed, a msg2 under its index finds nothing to
    // read and costs no DH.
    let dh_before = dh_ops();
    nodes[0].node.handle_msg2(garbage).await;
    assert_eq!(
        dh_ops() - dh_before,
        0,
        "a msg2 after completion costs no DH"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_rekey_cycle_spends_one_dh_on_each_refused_msg2_and_the_genuine_msg2_still_completes_it()
{
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;
    let rekey_idx = Msg2Header::parse(&held_msg2.data)
        .expect("the held msg2 parses")
        .receiver_idx;

    // The forgeries carry node 1's address as their source, as a spoofed UDP
    // source would.
    let node1_source = nodes[1].addr.clone();
    let garbage = msg2_under(&nodes[0], &node1_source, rekey_idx, &garbage_noise());

    let dh_before = dh_ops();
    for _ in 0..N {
        nodes[0].node.handle_msg2(garbage.clone()).await;
    }
    let spent = dh_ops() - dh_before;
    assert_eq!(
        spent, N,
        "each of the {N} refused rekey msg2s must cost exactly one DH"
    );
    let peer = nodes[0].node.get_peer(&node1_addr).unwrap();
    assert!(
        peer.rekey_in_progress() && peer.pending_new_session().is_none(),
        "no forged rekey msg2 completes or ends node 0's rekey"
    );

    // Release the genuine msg2: node 0 completes its rekey and node 1 reads
    // the msg3.
    complete_held(&mut nodes, held_msg2).await;
    assert!(
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 0 must hold the rekey's pending session after the genuine msg2"
    );
    assert!(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 1 must hold its pending session after node 0's msg3"
    );

    cleanup_nodes(&mut nodes).await;
}
