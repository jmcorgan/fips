//! Per-peer state across a change of the peer's link or session: what a new
//! or replaced peer is sent at once, and what a cleared session releases.
//!
//! - A peer promoted for an identity announced to just now, by a fresh dial
//!   or by a restart's msg1, is sent a TreeAnnounce at once: no stamp of the
//!   peer it replaces is carried over to rate-limit it.
//! - A redial answered as a rekey, from either end, resends the filter.
//! - A restart's msg1 releases the path MTU clamp entry of the session it
//!   clears, so the new peer is seeded from its link.
//! - Over BLE, the initiator's link is marked verified when it promotes the
//!   peer on its msg2, before any frame of the responder's arrives.

use super::super::rekey_parity::trigger_age;
use super::super::rekey_parity::{deliver, linked_pair, pump, rekey_config, stale_session};
use super::super::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, restarted_node,
};
use super::super::*;
use super::{loopback_node, with_path};
use fips_core::proto::rekey::Role;

/// Milliseconds on the clock the TreeAnnounce rate-limit stamp is kept in.
fn stamp_ms() -> u64 {
    crate::time::mono_ms()
}

/// Two loopback nodes, node 0 having dialed node 1, delivered until idle.
async fn peered() -> Vec<TestNode> {
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let a1 = *nodes[1].node.node_addr();
    let a0 = *nodes[0].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&a1).is_some() && nodes[1].node.get_peer(&a0).is_some(),
        "precondition: the two nodes are peered"
    );
    nodes
}

/// Record at `nodes[at]` a TreeAnnounce sent to `peer` just now, and return
/// a reading of the stamp's clock strictly later than the stamp.
async fn announced_just_now(nodes: &mut [TestNode], at: usize, peer: &NodeAddr) -> u64 {
    let stamp = stamp_ms();
    let p = nodes[at]
        .node
        .get_peer_mut(peer)
        .expect("precondition: the node holds the peer");
    p.record_tree_announce_sent(stamp);
    assert!(
        !p.can_send_tree_announce(stamp),
        "precondition: the peer is inside its TreeAnnounce interval"
    );
    while stamp_ms() <= stamp {
        tokio::task::yield_now().await;
    }
    stamp_ms()
}

/// Whether `nodes[at]`'s peer `peer` was sent a TreeAnnounce at or after
/// `since` and holds none pending, with the values seen.
fn sent_at_once(nodes: &[TestNode], at: usize, peer: &NodeAddr, since: u64) -> Result<(), String> {
    let p = nodes[at]
        .node
        .get_peer(peer)
        .expect("precondition: the node holds the new peer");
    let (stamp, pending) = (
        p.last_tree_announce_sent_ms(),
        p.has_pending_tree_announce(),
    );
    if stamp.is_some_and(|s| s >= since) && !pending {
        Ok(())
    } else {
        Err(format!(
            "last TreeAnnounce stamp {stamp:?} against {since} after the old peer's, pending {pending}"
        ))
    }
}

/// A fresh dial, after the previous peer of that identity was removed at
/// both ends, promotes on its msg2 and sends the new peer a TreeAnnounce at
/// once, although the previous peer was sent one just now.
#[tokio::test]
async fn a_peer_promoted_for_an_identity_announced_to_just_now_is_sent_a_tree_announce_at_once() {
    let mut nodes = peered().await;
    let a0 = *nodes[0].node.node_addr();
    let a1 = *nodes[1].node.node_addr();
    let since = announced_just_now(&mut nodes, 0, &a1).await;
    nodes[0].node.remove_active_peer(&a1);
    nodes[1].node.remove_active_peer(&a0);
    assert!(
        nodes[0].node.get_peer(&a1).is_none() && nodes[1].node.get_peer(&a0).is_none(),
        "precondition: both ends removed the previous peering"
    );
    initiate_handshake(&mut nodes, 0, 1).await;
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: only node 0's msg1 is queued at node 1"
    );
    let msg2 = nodes[0]
        .packet_rx
        .try_recv()
        .expect("precondition: node 1's msg2 is queued at node 0");
    nodes[0].node.handle_msg2(msg2).await;
    let result = sent_at_once(&nodes, 0, &a1, since);
    cleanup_nodes(&mut nodes).await;
    assert!(result.is_ok(), "defect: {result:?}");
}

/// Node 1 restarts and dials node 0, which last heard node 1 long enough
/// ago that the msg1 is accepted as a restart, and node 0 handles the msg1.
/// The restarted node takes the old one's place in `nodes`.
async fn restart_dial(nodes: &mut [TestNode]) {
    let a1 = *nodes[1].node.node_addr();
    let before = nodes[0]
        .node
        .get_peer(&a1)
        .expect("precondition: node 0 holds node 1")
        .link_id();
    nodes[0]
        .node
        .get_peer_mut(&a1)
        .expect("precondition: node 0 holds node 1")
        .touch(Node::now_ms().saturating_sub(60_000));
    nodes[0]
        .node
        .get_peer_mut(&a1)
        .expect("precondition: node 0 holds node 1")
        .test_backdate_heard(std::time::Duration::from_secs(60));
    let restarted = restarted_node(&nodes[1], with_path(Config::new(), false));
    let mut old = std::mem::replace(&mut nodes[1], restarted);
    cleanup_nodes(std::slice::from_mut(&mut old)).await;
    initiate_handshake(nodes, 1, 0).await;
    let msg1 = nodes[0]
        .packet_rx
        .try_recv()
        .expect("precondition: the restarted node's msg1 is queued at node 0");
    nodes[0].node.handle_msg1(msg1).await;
    assert!(
        nodes[0]
            .node
            .get_peer(&a1)
            .is_some_and(|p| p.link_id() != before),
        "precondition: node 0 replaced node 1's peering on the restart msg1"
    );
}

/// A restart's msg1 replaces a peer that was sent a TreeAnnounce just now,
/// and the new peer is sent one at once.
#[tokio::test]
async fn a_peer_replaced_by_a_restart_after_an_announce_just_now_is_sent_a_tree_announce_at_once() {
    let mut nodes = peered().await;
    let a1 = *nodes[1].node.node_addr();
    let since = announced_just_now(&mut nodes, 0, &a1).await;
    restart_dial(&mut nodes).await;
    let result = sent_at_once(&nodes, 0, &a1, since);
    cleanup_nodes(&mut nodes).await;
    assert!(result.is_ok(), "defect: {result:?}");
}

/// A drops its side of an aged link and redials B; B answers as a rekey.
/// A holds B's filter within three Bloom ticks.
async fn redial(redialer_smaller: bool) {
    let mut nodes = linked_pair(
        with_path(rekey_config(60), false),
        with_path(rekey_config(60), false),
    )
    .await;
    let zero_smaller = nodes[0].node.node_addr() < nodes[1].node.node_addr();
    let (a, b) = if zero_smaller == redialer_smaller {
        (0, 1)
    } else {
        (1, 0)
    };
    let a_addr = *nodes[a].node.node_addr();
    let b_addr = *nodes[b].node.node_addr();
    assert!(
        nodes[a]
            .node
            .get_peer(&b_addr)
            .expect("precondition: A holds B")
            .inbound_filter()
            .is_some(),
        "precondition: A holds B's filter on the first peering"
    );
    for tn in nodes.iter_mut() {
        tn.node.bloom_state.set_update_debounce_ms(0);
    }

    nodes[b]
        .node
        .get_peer_mut(&a_addr)
        .expect("precondition: B holds A")
        .test_backdate_session_established(trigger_age());
    nodes[a].node.remove_active_peer(&b_addr);
    initiate_handshake(&mut nodes, a, b).await;
    assert_eq!(
        deliver(&mut nodes[b]).await,
        1,
        "precondition: only A's msg1 is queued at B"
    );
    let pending = {
        let peer = nodes[b]
            .node
            .get_peer(&a_addr)
            .expect("precondition: B holds A");
        assert_eq!(
            peer.pending_role(),
            Some(Role::Responder),
            "precondition: B answers the redial as a rekey"
        );
        peer.pending_our_index()
            .expect("precondition: B's pending has an index")
    };

    pump(&mut nodes).await;
    assert_eq!(
        nodes[b]
            .node
            .get_peer(&a_addr)
            .expect("precondition: B holds A")
            .our_index(),
        Some(pending),
        "precondition: B cut over to the redial's session"
    );
    assert!(
        nodes[a].node.get_peer(&b_addr).is_some(),
        "precondition: A holds B again"
    );

    for _ in 0..3 {
        for tn in nodes.iter_mut() {
            tn.node.check_bloom_state().await;
        }
        pump(&mut nodes).await;
    }
    let holds = nodes[a]
        .node
        .get_peer(&b_addr)
        .is_some_and(|p| p.inbound_filter().is_some());
    cleanup_nodes(&mut nodes).await;
    assert!(
        holds,
        "defect: A (the {} node) does not hold B's filter after B answered its redial as a rekey",
        if redialer_smaller {
            "smaller"
        } else {
            "larger"
        }
    );
}

#[tokio::test]
async fn redial_from_the_smaller_node_answered_as_a_rekey_resends_the_filter() {
    redial(true).await;
}

#[tokio::test]
async fn redial_from_the_larger_node_answered_as_a_rekey_resends_the_filter() {
    redial(false).await;
}

/// A restart's msg1 clears the end-to-end session the old peering held and
/// releases the clamp entry that session tightened, so the new peer's path
/// MTU is seeded from its link again, as a first promotion over that link
/// seeds it.
#[tokio::test]
async fn a_restart_msg1_releases_the_clamp_entry_of_the_session_it_clears() {
    let mut nodes = peered().await;
    let a1 = *nodes[1].node.node_addr();
    let fips = crate::Ipv6Address::from_node_addr(&a1);
    let seed = nodes[0].node.path_mtu_lookup_get(&fips);
    let tighter = seed
        .expect("precondition: the promotion seeded the peer's path MTU from its link")
        .checked_sub(100)
        .expect("precondition: the seed leaves room for a tighter clamp");
    stale_session(&mut nodes[0].node, a1);
    nodes[0].node.path_mtu_lookup_insert(fips, tighter);
    assert_eq!(
        nodes[0].node.path_mtu_lookup_get(&fips),
        Some(tighter),
        "precondition: the session's tightened clamp entry is held"
    );
    restart_dial(&mut nodes).await;
    assert!(
        nodes[0].node.get_session(&a1).is_none(),
        "precondition: the restart cleared the session"
    );
    let after = nodes[0].node.path_mtu_lookup_get(&fips);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        after, seed,
        "defect: the clamp entry the cleared session tightened outlived it"
    );
}

/// The next packet queued at `tn`, waiting up to 2 s for the BLE mock's
/// background tasks to deliver it.
#[cfg(ble_available)]
async fn next_packet(tn: &mut TestNode) -> ReceivedPacket {
    tokio::time::timeout(Duration::from_secs(2), tn.packet_rx.recv())
        .await
        .expect("precondition: a packet arrived within 2 s")
        .expect("precondition: the receive channel is open")
}

/// Whether `tn`'s BLE link at `addr` is marked verified; `None` when none
/// is pooled there.
#[cfg(ble_available)]
async fn verified(tn: &TestNode, addr: &TransportAddr) -> Option<bool> {
    match tn.node.transports.get(&tn.transport_id) {
        Some(crate::transport::TransportHandle::Ble(t)) => t.is_verified(addr).await,
        _ => panic!("precondition: the node's first transport is BLE"),
    }
}

/// Over BLE, a dialer that promotes the peer on its msg2 marks its own link
/// verified then, before it has handled any frame of the responder's: the
/// msg2 answers its own fresh ephemeral key, which a replayed capture
/// cannot.
#[cfg(ble_available)]
#[tokio::test]
async fn the_ble_initiators_link_is_verified_before_any_responder_frame() {
    use super::super::ble::{base_config, larger_second, link_genuinely, make_test_node_ble_from};
    use super::super::crossed_dial::{hand, phase};
    use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2};

    let mut nodes = vec![
        make_test_node_ble_from(1, base_config(), with_path(Config::new(), false)).await,
        make_test_node_ble_from(2, base_config(), with_path(Config::new(), false)).await,
    ];
    larger_second(&mut nodes);
    let _bank = link_genuinely(&nodes).await;
    let a1 = *nodes[1].node.node_addr();
    let link = nodes[1].addr.clone();
    initiate_handshake(&mut nodes, 0, 1).await;
    let msg1 = next_packet(&mut nodes[1]).await;
    assert_eq!(
        phase(&msg1),
        Some(PHASE_MSG1),
        "precondition: node 0's msg1 reaches node 1 first"
    );
    hand(&mut nodes[1].node, msg1).await;
    let msg2 = next_packet(&mut nodes[0]).await;
    assert_eq!(
        phase(&msg2),
        Some(PHASE_MSG2),
        "precondition: node 1's msg2 reaches node 0 first"
    );
    assert_eq!(
        verified(&nodes[0], &link).await,
        Some(false),
        "precondition: node 0's link is pooled and not yet verified"
    );
    hand(&mut nodes[0].node, msg2).await;
    assert!(
        nodes[0].node.get_peer(&a1).is_some(),
        "precondition: node 0 promoted node 1 on its msg2"
    );
    let marked = verified(&nodes[0], &link).await;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        marked,
        Some(true),
        "defect: the initiator's link is not verified after it promoted the peer on the msg2"
    );
}
