//! The cap on what forged msg2s cost a link rekey in flight.
//!
//! A rekey msg2 names the attempt by the index its msg1 carried in
//! cleartext, so anyone who saw the msg1 can send msg2s under it from any
//! address, and nothing short of a read tells the peer's msg2 from a
//! forgery. The rekey reads a budget of refused msg2s from anywhere; past
//! it, it reads a msg2 only when it arrived on the peer's link and drops
//! the rest unread, counted as off the link. The genuine msg2 from the
//! established link is always read, so a forger cannot end the rekey; an
//! honest peer that roams mid-rekey after the budget has its msg2 dropped,
//! and the rekey's msg1 resend draws it again.

use super::*;
use crate::node::tests::session::{HeldMsg2Pair, build_ipv6_packet, held_msg2_pair};
use crate::node::tests::spanning_tree::{TestNode, cleanup_nodes, process_available_packets};
use crate::noise::{HANDSHAKE_MSG2_SIZE, dh_ops};
use crate::proto::fmp::wire::build_msg2;
use crate::transport::ReceivedPacket;
use crate::utils::index::SessionIndex;

/// Forged msg2s in a spray.
const SPRAY: u64 = 1000;

/// The refused msg2 reads a link rekey allows itself before it reads only
/// msg2s from the link: `Config::fmp().reads`.
const BUDGET: u64 = 8;

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
/// encrypted epoch does not authenticate, so reading it costs a DH.
fn garbage_noise() -> Vec<u8> {
    let mut noise = Identity::generate().pubkey_full().serialize().to_vec();
    noise.resize(HANDSHAKE_MSG2_SIZE, 0xA5);
    noise
}

/// An address no link of the pair uses.
fn elsewhere() -> TransportAddr {
    TransportAddr::from_string("192.0.2.9:2121")
}

/// A garbage msg2 under `index`, delivered to `to` as if sent from `from`.
fn forged(to: &TestNode, from: &TransportAddr, index: SessionIndex) -> ReceivedPacket {
    ReceivedPacket::new(
        to.transport_id,
        from.clone(),
        build_msg2(SessionIndex::new(0x5EED_F00D), index, &garbage_noise()),
    )
}

/// `packet` as if it came from `from`.
fn moved(packet: &ReceivedPacket, from: &TransportAddr) -> ReceivedPacket {
    ReceivedPacket::new(packet.transport_id, from.clone(), packet.data.clone())
}

/// What a run of msg2s cost node 0: the DHs its reads ran, and the
/// refusals counted as unauthenticated and as off the link.
#[derive(Debug, PartialEq, Eq)]
struct Cost {
    reads: u64,
    refused: u64,
    dropped: u64,
}

/// Deliver `packet` to node 0 `n` times and return what it cost.
async fn deliver(node: &mut TestNode, packet: &ReceivedPacket, n: u64) -> Cost {
    let before = node.node.stats().handshake.snapshot();
    let dh = dh_ops();
    for _ in 0..n {
        node.node.handle_msg2(packet.clone()).await;
    }
    let after = node.node.stats().handshake.snapshot();
    Cost {
        reads: dh_ops() - dh,
        refused: after.bad_state - before.bad_state,
        dropped: after.off_link - before.off_link,
    }
}

/// Spend node 0's budget of refused reads with a spray from off the link,
/// and check that it read no more than the budget.
async fn spend_budget(pair: &mut HeldMsg2Pair) {
    let spray = forged(&pair.nodes[0], &elsewhere(), pair.rekey_idx);
    let cost = deliver(&mut pair.nodes[0], &spray, SPRAY).await;
    assert!(
        cost.reads <= BUDGET,
        "defect: {} reads of forged rekey msg2s from off the link, past the budget of {BUDGET}",
        cost.reads
    );
    assert_eq!(
        cost,
        Cost {
            reads: BUDGET,
            refused: BUDGET,
            dropped: SPRAY - BUDGET,
        },
        "the first {BUDGET} forgeries are read and refused, and the rest dropped unread"
    );
    let peer = pair.nodes[0].node.get_peer(&pair.node1_addr).unwrap();
    assert_eq!(
        peer.rekey_our_index(),
        Some(pair.rekey_idx),
        "the forgeries leave the rekey in flight"
    );
}

/// Run one rekey tick on each node, then check that data decodes both ways
/// under the new sessions and that node 0 cut over.
async fn completed(pair: &mut HeldMsg2Pair) {
    pair.nodes[0].node.poll_link_rekeys().await;
    pair.nodes[1].node.poll_link_rekeys().await;
    pump_until_quiet(&mut pair.nodes).await;

    let fwd = build_ipv6_packet(&pair.fips0, &pair.fips1, b"post-rekey 0 to 1");
    let rev = build_ipv6_packet(&pair.fips1, &pair.fips0, b"post-rekey 1 to 0");
    pair.nodes[0].node.handle_tun_outbound(fwd.clone()).await;
    pair.nodes[1].node.handle_tun_outbound(rev.clone()).await;
    pump_until_quiet(&mut pair.nodes).await;

    let got: Vec<Vec<u8>> = std::iter::from_fn(|| pair.tun1_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![fwd], "node 0 to node 1 decodes after the rekey");
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| pair.tun0_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![rev], "node 1 to node 0 decodes after the rekey");

    let peer = pair.nodes[0].node.get_peer(&pair.node1_addr).unwrap();
    assert_ne!(
        peer.our_index(),
        pair.node0_idx_before,
        "node 0 completed the rekey on the genuine msg2 and cut over"
    );
    assert!(!peer.rekey_in_progress(), "node 0 is not left mid-rekey");
    assert_ne!(
        pair.nodes[1]
            .node
            .get_peer(&pair.node0_addr)
            .unwrap()
            .our_index(),
        pair.node1_idx_before,
        "node 1 adopted its pending session on node 0's first new frame"
    );
}

async fn spray_costs_at_most_the_budget(multipath: bool) {
    let mut pair = held_msg2_pair(multipath).await;
    spend_budget(&mut pair).await;
    let genuine = pair.held_msg2.clone();
    pair.nodes[0].node.handle_msg2(genuine).await;
    completed(&mut pair).await;
    cleanup_nodes(&mut pair.nodes).await;
}

#[tokio::test]
async fn a_spray_of_forged_rekey_msg2s_costs_at_most_its_budget_of_reads_and_the_genuine_one_completes()
 {
    spray_costs_at_most_the_budget(false).await;
}

#[tokio::test]
async fn a_spray_of_forged_rekey_msg2s_costs_at_most_its_budget_of_reads_and_the_genuine_one_completes_with_multipath_on()
 {
    spray_costs_at_most_the_budget(true).await;
}

async fn genuine_is_read_after_the_budget(multipath: bool) {
    let mut pair = held_msg2_pair(multipath).await;
    spend_budget(&mut pair).await;
    // A forgery whose source is node 1's address, as a spoofed UDP source
    // would be, arrives on the link: it is read and refused.
    let link = pair.nodes[1].addr.clone();
    let spoofed = forged(&pair.nodes[0], &link, pair.rekey_idx);
    let cost = deliver(&mut pair.nodes[0], &spoofed, 1).await;
    assert_eq!(
        cost.dropped, 0,
        "defect: a msg2 from the established link was dropped unread after the budget was spent"
    );
    assert_eq!(
        cost,
        Cost {
            reads: 1,
            refused: 1,
            dropped: 0,
        },
        "a msg2 from the link is read, and a forged one refused"
    );
    let genuine = pair.held_msg2.clone();
    let cost = deliver(&mut pair.nodes[0], &genuine, 1).await;
    assert_eq!(cost.dropped, 0, "the genuine msg2 from the link is read");
    completed(&mut pair).await;
    cleanup_nodes(&mut pair.nodes).await;
}

#[tokio::test]
async fn the_genuine_rekey_msg2_from_the_established_link_is_read_after_the_budget_is_spent() {
    genuine_is_read_after_the_budget(false).await;
}

#[tokio::test]
async fn the_genuine_rekey_msg2_from_the_established_link_is_read_after_the_budget_is_spent_with_multipath_on()
 {
    genuine_is_read_after_the_budget(true).await;
}

async fn roamed_msg2_is_dropped_and_retried(multipath: bool) {
    let mut pair = held_msg2_pair(multipath).await;
    spend_budget(&mut pair).await;
    // Node 1's genuine msg2, arriving from a pair off the link as if node 1
    // had moved, is dropped unread and leaves the rekey in flight.
    let roamed = moved(&pair.held_msg2, &elsewhere());
    let cost = deliver(&mut pair.nodes[0], &roamed, 1).await;
    assert_eq!(
        cost.reads, 0,
        "defect: a msg2 from off the link was read after the budget was spent"
    );
    assert_eq!(
        cost,
        Cost {
            reads: 0,
            refused: 0,
            dropped: 1,
        },
        "the msg2 from a new pair is dropped unread"
    );
    let peer = pair.nodes[0].node.get_peer(&pair.node1_addr).unwrap();
    assert_eq!(
        peer.rekey_our_index(),
        Some(pair.rekey_idx),
        "the rekey is still in flight"
    );
    // The rekey resends its msg1 at +1 s; node 1 answers it with the msg2
    // it holds, which reaches node 0 on the link and completes the rekey.
    crate::time::advance(Duration::from_secs(1));
    pair.nodes[0].node.poll_link_rekeys().await;
    assert_eq!(
        process_available_packets(&mut pair.nodes[1..]).await,
        1,
        "node 1 has the resent msg1 queued"
    );
    let before = pair.nodes[0].node.stats().handshake.snapshot();
    let dh = dh_ops();
    process_available_packets(&mut pair.nodes[..1]).await;
    let after = pair.nodes[0].node.stats().handshake.snapshot();
    assert!(
        dh_ops() > dh && after.off_link == before.off_link && after.bad_state == before.bad_state,
        "node 1's msg2 for the resent msg1 is read on the link and accepted"
    );
    completed(&mut pair).await;
    cleanup_nodes(&mut pair.nodes).await;
}

#[tokio::test]
async fn a_rekey_msg2_from_a_new_pair_after_the_budget_is_dropped_and_the_rekey_retries() {
    roamed_msg2_is_dropped_and_retried(false).await;
}

#[tokio::test]
async fn a_rekey_msg2_from_a_new_pair_after_the_budget_is_dropped_and_the_rekey_retries_with_multipath_on()
 {
    roamed_msg2_is_dropped_and_retried(true).await;
}
