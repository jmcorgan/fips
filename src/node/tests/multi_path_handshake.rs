//! Handshake and rekey messages under index-only demux.
//!
//! Established frames are identified by session index alone (see
//! `multi_path.rs`), but a fresh handshake stays bound to the transport it was
//! dialed on: a msg2 that arrives on another transport than its msg1 went out
//! on is discarded before any state changes, and the dial completes on its
//! own. A rekey msg2 is different: the link is already established, so a
//! genuine one is accepted from any transport and matched by the initiator's
//! index alone, and a forged one leaves the rekey cycle in place.
//!
//! A rekey's msg2 is dispatched by its attempt index's binding in
//! `peers_by_index`, which is keyed by the index alone, so moving the peer
//! onto another transport between rekey msg1 and the end of the attempt
//! cannot leave a stale binding behind. The same binding recognises a copy
//! of a rekey's msg3 that arrives after the hand-over, whichever transport
//! it comes in on.
//!
//! The loopback transport stamps a delivered packet with the receiving
//! transport's id, so a node given a second transport here sees which of its
//! two a packet came in on, whatever transport sent it.

use super::rekey_parity::{age_link, deliver, linked_pair, rekey_config, trigger_age};
use super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, add_loopback_alias, initiate_handshake, make_test_node,
};
use super::*;
use crate::transport::TransportHandle;
use crate::transport::loopback::LoopbackTransport;
use fips_core::proto::rekey::Role;

/// The second transport both nodes share, standing in for the wifi next
/// to the cable that `TestNode` comes with.
fn wifi() -> TransportId {
    TransportId::new(2)
}

/// Where a frame "from the wifi" claims to come from.
const FOREIGN_ADDR: &str = "10.9.9.9:9999";

/// Give `node` a second loopback transport, `wifi()`, on a fresh address that
/// delivers into the node's existing packet channel as received on `wifi()`.
/// Returns that address.
fn add_wifi(node: &mut TestNode) -> TransportAddr {
    let addr = add_loopback_alias(&node.addr, wifi());
    let transport = LoopbackTransport::new(wifi(), addr.clone(), LOOPBACK_REGISTRY.clone());
    node.node
        .transports
        .insert(wifi(), TransportHandle::Loopback(transport));
    addr
}

/// A packet sent to either of a node's two transports arrives stamped with
/// that transport's id, not the sender's: the receiving end of a link names
/// the transport the frame came in on.
#[tokio::test]
async fn each_of_a_nodes_two_transports_stamps_its_own_id_on_what_it_receives() {
    let mut node = make_test_node().await;
    let wifi_addr = add_wifi(&mut node);
    let sender = LoopbackTransport::new(
        TransportId::new(9),
        TransportAddr::from_string("loopback:sender"),
        LOOPBACK_REGISTRY.clone(),
    );

    sender.send_async(&node.addr, b"cable").await.unwrap();
    sender.send_async(&wifi_addr, b"wifi").await.unwrap();

    let cable = node.packet_rx.try_recv().expect("the cable packet arrived");
    let radio = node.packet_rx.try_recv().expect("the wifi packet arrived");
    assert_eq!(cable.data, b"cable");
    assert_eq!(
        cable.transport_id, node.transport_id,
        "a packet to the cable's address is received on the cable"
    );
    assert_eq!(radio.data, b"wifi");
    assert_eq!(
        radio.transport_id,
        wifi(),
        "a packet to the wifi's address is received on the wifi"
    );
}

/// Node 0 dials node 1 over the cable and node 1 answers. Returns the msg2
/// queued at node 0, not yet handled.
async fn dial_to_msg2(nodes: &mut [TestNode]) -> ReceivedPacket {
    initiate_handshake(nodes, 0, 1).await;
    let msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("msg1 queued at node 1");
    nodes[1].node.handle_msg1(msg1).await;
    let msg2 = nodes[0]
        .packet_rx
        .try_recv()
        .expect("msg2 queued at node 0");
    assert_eq!(
        msg2.transport_id, nodes[0].transport_id,
        "precondition: the msg2 came back on the cable"
    );
    msg2
}

#[tokio::test]
async fn a_fresh_msg2_on_another_transport_is_discarded_and_the_dial_completes_on_its_own() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let _wifi_0 = add_wifi(&mut nodes[0]);
    let msg2 = dial_to_msg2(&mut nodes).await;
    let addr_1 = *nodes[1].node.node_addr();

    nodes[0]
        .node
        .handle_msg2(ReceivedPacket::new(
            wifi(),
            TransportAddr::from_string(FOREIGN_ADDR),
            msg2.data.clone(),
        ))
        .await;
    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "a msg2 on a transport the dial never used must not promote"
    );

    nodes[0].node.handle_msg2(msg2).await;
    let peer = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("the msg2 on the dial's own transport completes it");
    assert_eq!(peer.transport_id(), Some(nodes[0].transport_id));
    assert_eq!(peer.current_addr(), Some(&nodes[1].addr));
}

#[tokio::test]
async fn a_garbage_msg2_with_a_sniffed_index_on_another_transport_leaves_the_handshake_pending() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let _wifi_0 = add_wifi(&mut nodes[0]);
    let genuine = dial_to_msg2(&mut nodes).await;
    let addr_1 = *nodes[1].node.node_addr();

    // Same header, so the same receiver index; the Noise payload is spoiled.
    let mut forged = genuine.data.clone();
    let n = forged.len();
    for b in &mut forged[n - 40..] {
        *b ^= 0x5A;
    }
    nodes[0]
        .node
        .handle_msg2(ReceivedPacket::new(
            wifi(),
            TransportAddr::from_string(FOREIGN_ADDR),
            forged,
        ))
        .await;

    nodes[0].node.handle_msg2(genuine).await;
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "a garbage msg2 on another transport must leave the handshake for the genuine one"
    );
}

// ============================================================================
// Rekey msg2 from any transport, and removal of a rekey's dispatch entry
// ============================================================================

/// The rekey interval `trigger_age()` is cut for.
const REKEY_AFTER_SECS: u64 = 60;

/// Two nodes peered over the cable, each also reachable over `wifi()`, with
/// their link aged past the rekey trigger. `config` adjusts both nodes'
/// configuration. Returns the nodes and each one's wifi address.
async fn aged_pair_with_wifi(
    config: impl Fn(&mut crate::config::Config),
) -> (Vec<TestNode>, TransportAddr, TransportAddr) {
    let mut cfg = rekey_config(REKEY_AFTER_SECS);
    config(&mut cfg);
    let mut nodes = linked_pair(cfg.clone(), cfg).await;
    let wifi_0 = add_wifi(&mut nodes[0]);
    let wifi_1 = add_wifi(&mut nodes[1]);
    age_link(&mut nodes, 0, 1, trigger_age());
    (nodes, wifi_0, wifi_1)
}

/// Start `nodes[from]`'s rekey to `nodes[to]` and return its rekey index.
/// The rekey msg1 is left queued at `to`.
async fn start_rekey(nodes: &mut [TestNode], from: usize, to: usize) -> SessionIndex {
    let to_addr = *nodes[to].node.node_addr();
    nodes[from].node.poll_link_rekeys().await;
    let peer = nodes[from].node.get_peer(&to_addr).unwrap();
    assert!(
        peer.rekey_in_progress(),
        "precondition: the rekey initiator started a rekey"
    );
    peer.rekey_our_index()
        .expect("an in-flight rekey holds an index")
}

/// Whether `node` dispatches frames and msg2s naming `index`: a rekey
/// attempt's index is bound in `peers_by_index` for its msg2.
fn dispatches(node: &Node, index: SessionIndex) -> bool {
    node.peers_by_index.contains_key(&index.as_u32())
}

/// Start node 0's rekey and have node 1 answer it. Returns the rekey index and
/// the rekey msg2 queued at node 0, not yet handled.
async fn rekey_to_msg2(nodes: &mut [TestNode]) -> (SessionIndex, ReceivedPacket) {
    let index = start_rekey(nodes, 0, 1).await;
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: only the rekey msg1 is queued at the responder"
    );
    let msg2 = nodes[0]
        .packet_rx
        .try_recv()
        .expect("rekey msg2 queued at node 0");
    assert_eq!(
        msg2.transport_id, nodes[0].transport_id,
        "precondition: the rekey msg2 came back on the cable"
    );
    (index, msg2)
}

#[tokio::test]
async fn a_genuine_rekey_msg2_on_another_transport_completes_the_rekey() {
    let (mut nodes, _wifi_0, wifi_1) = aged_pair_with_wifi(|_| {}).await;
    let addr_1 = *nodes[1].node.node_addr();
    let (index, msg2) = rekey_to_msg2(&mut nodes).await;

    nodes[0]
        .node
        .handle_msg2(ReceivedPacket::new(wifi(), wifi_1, msg2.data))
        .await;

    let peer = nodes[0].node.get_peer(&addr_1).unwrap();
    assert!(
        !peer.rekey_in_progress(),
        "a genuine rekey msg2 from another transport completes the rekey"
    );
    assert_eq!(peer.pending_role(), Some(Role::Initiator));
    assert_eq!(peer.pending_our_index(), Some(index));
    assert_eq!(
        nodes[0].node.peers_by_index.get(&index.as_u32()),
        Some(&addr_1),
        "the new session's index is registered for dispatch"
    );
    assert_eq!(
        peer.transport_id(),
        Some(nodes[0].transport_id),
        "a rekey msg2 does not move the peer"
    );
}

#[tokio::test]
async fn a_forged_rekey_msg2_on_another_transport_keeps_the_rekey_cycle() {
    let (mut nodes, _wifi_0, _wifi_1) = aged_pair_with_wifi(|_| {}).await;
    let addr_1 = *nodes[1].node.node_addr();
    let (index, genuine) = rekey_to_msg2(&mut nodes).await;

    // Same header, so the same receiver index; the Noise payload is spoiled.
    let mut forged = genuine.data.clone();
    let n = forged.len();
    for b in &mut forged[n - 40..] {
        *b ^= 0x5A;
    }
    nodes[0]
        .node
        .handle_msg2(ReceivedPacket::new(
            wifi(),
            TransportAddr::from_string(FOREIGN_ADDR),
            forged,
        ))
        .await;

    // Checked before the genuine msg2: it would complete the rekey through
    // the by-index fallback even if the forgery had removed the entry.
    assert!(
        nodes[0].node.get_peer(&addr_1).unwrap().rekey_in_progress(),
        "a forged rekey msg2 must not abandon the rekey"
    );
    assert!(
        dispatches(&nodes[0].node, index),
        "a forged rekey msg2 must leave the rekey's msg2 dispatch entry"
    );

    nodes[0].node.handle_msg2(genuine).await;
    let peer = nodes[0].node.get_peer(&addr_1).unwrap();
    assert!(!peer.rekey_in_progress(), "the genuine msg2 completes it");
    assert_eq!(peer.pending_role(), Some(Role::Initiator));
    assert_eq!(peer.pending_our_index(), Some(index));
}

/// Index of the node with the larger node address, which loses a dual rekey
/// initiation, and of the other.
fn loser_and_winner(nodes: &[TestNode]) -> (usize, usize) {
    if nodes[0].node.node_addr() > nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    }
}

/// Move `nodes[from]`'s peer `nodes[to]` onto `wifi()` at `to_wifi`, as a
/// single path there: the test stand-in for the path switch that will move a
/// peer between held paths.
fn rebind_onto_wifi(nodes: &mut [TestNode], from: usize, to: usize, to_wifi: &TransportAddr) {
    let to_addr = *nodes[to].node.node_addr();
    let peer = nodes[from].node.get_peer_mut(&to_addr).unwrap();
    peer.repin(wifi(), to_wifi.clone());
    assert_eq!(peer.transport_id(), Some(wifi()), "precondition: rebound");
}

/// Both nodes start a rekey and the rekeys cross. The loser completes its
/// own on the winner's msg2, its index bound while it holds the winner on
/// the cable, then is moved to hold the winner on `wifi()`, and gives its
/// rekey up when the winner's msg3 hands it the winner's: its own rekey's
/// binding is removed by index, whichever transport the peer is on now.
#[tokio::test]
async fn a_rekey_abandoned_after_a_transport_rebind_removes_its_dispatch_entry_by_index() {
    let (mut nodes, wifi_0, wifi_1) = aged_pair_with_wifi(|_| {}).await;
    let (loser, winner) = loser_and_winner(&nodes);
    let wifi_of_winner = if winner == 0 { wifi_0 } else { wifi_1 };
    let winner_addr = *nodes[winner].node.node_addr();

    let index = start_rekey(&mut nodes, loser, winner).await;
    assert!(
        dispatches(&nodes[loser].node, index),
        "control: the rekey's msg2 dispatch entry is present"
    );
    let _ = start_rekey(&mut nodes, winner, loser).await;

    // Each answers the other's msg1 on the cable it arrived on.
    deliver(&mut nodes[winner]).await;
    deliver(&mut nodes[loser]).await;
    assert_eq!(
        nodes[loser]
            .node
            .get_peer(&winner_addr)
            .unwrap()
            .pending_our_index(),
        Some(index),
        "control: the loser completed its own rekey on the winner's msg2"
    );
    rebind_onto_wifi(&mut nodes, loser, winner, &wifi_of_winner);
    // The winner completes its own on the loser's msg2 and sends its msg3 on
    // the cable, where the loser's leg for it waits.
    deliver(&mut nodes[winner]).await;
    deliver(&mut nodes[loser]).await;

    let peer = nodes[loser].node.get_peer(&winner_addr).unwrap();
    assert_eq!(
        peer.pending_role(),
        Some(Role::Responder),
        "control: the loser gave up its rekey and took the winner's"
    );
    assert!(
        !dispatches(&nodes[loser].node, index),
        "the abandoned rekey's msg2 dispatch entry must be removed"
    );
}

#[tokio::test]
async fn a_rekey_timed_out_after_a_transport_rebind_removes_its_dispatch_entry_by_index() {
    let (mut nodes, _wifi_0, wifi_1) = aged_pair_with_wifi(|cfg| {
        cfg.node.rate_limit.handshake_max_resends = 0;
    })
    .await;
    let addr_1 = *nodes[1].node.node_addr();

    let index = start_rekey(&mut nodes, 0, 1).await;
    assert!(
        dispatches(&nodes[0].node, index),
        "control: the rekey's msg2 dispatch entry is present"
    );
    rebind_onto_wifi(&mut nodes, 0, 1, &wifi_1);

    // With a zero resend budget the msg1 is never resent, and the first
    // poll past the attempt's deadline abandons the cycle.
    crate::time::advance(Duration::from_millis(1_100));
    nodes[0].node.poll_link_rekeys().await;

    assert!(
        !nodes[0].node.get_peer(&addr_1).unwrap().rekey_in_progress(),
        "control: the abandon fired"
    );
    assert!(
        !dispatches(&nodes[0].node, index),
        "the timed-out rekey's msg2 dispatch entry must be removed"
    );
}

#[tokio::test]
async fn removing_a_peer_after_a_transport_rebind_removes_its_rekey_dispatch_entry_by_index() {
    let (mut nodes, _wifi_0, wifi_1) = aged_pair_with_wifi(|_| {}).await;
    let addr_1 = *nodes[1].node.node_addr();

    let index = start_rekey(&mut nodes, 0, 1).await;
    assert!(
        dispatches(&nodes[0].node, index),
        "control: the rekey's msg2 dispatch entry is present"
    );
    rebind_onto_wifi(&mut nodes, 0, 1, &wifi_1);

    nodes[0].node.remove_active_peer(&addr_1);

    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "control: the peer was removed"
    );
    assert!(
        !dispatches(&nodes[0].node, index),
        "the removed peer's rekey msg2 dispatch entry must be removed"
    );
}

/// A link rekey's initiator resends its msg3 until it hears the peer under
/// the new session. A copy that reaches the responder on another transport
/// after its leg handed the first to the peer's link rekey machine names the
/// leg's index, which `peers_by_index` binds by the index alone, so the copy
/// is recognised there too: it changes nothing and is not counted as an
/// unknown connection.
#[tokio::test]
async fn a_rekey_msg3_copy_on_another_transport_after_the_hand_over_is_dropped_uncounted() {
    let (mut nodes, wifi_0, _wifi_1) = aged_pair_with_wifi(|_| {}).await;
    let addr_0 = *nodes[0].node.node_addr();
    let (_, msg2) = rekey_to_msg2(&mut nodes).await;
    nodes[0].node.handle_msg2(msg2).await;

    let msg3 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("rekey msg3 queued at node 1");
    assert_eq!(
        crate::proto::fmp::wire::CommonPrefix::parse(&msg3.data).map(|c| c.phase),
        Some(crate::proto::fmp::wire::PHASE_MSG3),
        "precondition: the packet queued at the responder is the msg3"
    );
    assert_eq!(
        msg3.transport_id, nodes[1].transport_id,
        "precondition: the msg3 came in on the cable"
    );
    let copy = msg3.data.clone();
    nodes[1].node.handle_msg3(msg3).await;
    let pending = nodes[1].node.get_peer(&addr_0).unwrap().pending_our_index();
    assert!(
        pending.is_some(),
        "precondition: the leg handed the rekey over"
    );

    let unknown = nodes[1].node.stats().handshake.unknown_connection;
    nodes[1]
        .node
        .handle_msg3(ReceivedPacket::new(wifi(), wifi_0, copy))
        .await;
    assert_eq!(
        nodes[1].node.get_peer(&addr_0).unwrap().pending_our_index(),
        pending,
        "the copy changes nothing"
    );
    assert_eq!(
        nodes[1].node.stats().handshake.unknown_connection,
        unknown,
        "a copy on another transport is not counted as an unknown connection"
    );
}
