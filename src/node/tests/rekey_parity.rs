//! Link rekeys between two ends whose K-bits have fallen out of step.
//!
//! The K-bit in an established frame's header says which key epoch the
//! sender is on. Two paths leave the two ends of a link holding K-bits that
//! do not reflect the same history: a peer restart that our rekey msg1
//! reveals (the restarted peer promotes the msg1 as a fresh link at K-bit 0,
//! while we complete it as a rekey), and a second-path dial that we answer as
//! a rekey and the dialing peer completes as a cross-connection swap. After
//! either, the peer's frames on a new session can carry a K-bit equal to
//! ours. These tests drive both paths over loopback and assert on promotion
//! of the pending session and on the receiver's consecutive decryption
//! failure count, never on whether the peer survives.

use super::*;
use crate::node::tests::spanning_tree::{
    TestNode, add_loopback_alias, cleanup_nodes, drain_all_packets, initiate_handshake,
    make_test_node_with_config, process_available_packets, restarted_node, run_tree_test,
};
use crate::proto::fmp::RekeyRole;
use crate::proto::fmp::wire::{
    CommonPrefix, FLAG_KEY_EPOCH, PHASE_ESTABLISHED, PHASE_MSG2, build_established_header,
};
use crate::proto::link::LinkMessageType;
use rand::Rng;

/// Rekey interval for both ends of the pairs below.
const REKEY_AFTER_SECS: u64 = 60;

/// Frames a test sends after the cutover it is about, well past the 20
/// consecutive failures at which the base code removes a peer.
const FRAMES: usize = 25;

/// A config with rekey on, triggered `after_secs` after the last one and never
/// by message count.
pub(super) fn rekey_config(after_secs: u64) -> crate::config::Config {
    let mut config = crate::config::Config::new();
    config.node.rekey.enabled = true;
    config.node.rekey.after_secs = after_secs;
    config.node.rekey.after_messages = u64::MAX;
    config
}

/// A session age past the jittered rekey trigger, and past the 30 s link
/// floor below which a msg1 from an established peer is a duplicate, not a
/// rekey. Backdating a session this far ages its link with it.
pub(super) fn trigger_age() -> Duration {
    Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1)
}

/// Send one heartbeat from `from` to its peer `to` on `from`'s current
/// session.
pub(super) async fn heartbeat(from: &mut TestNode, to: &NodeAddr) {
    from.node
        .send_encrypted_link_message(to, &[LinkMessageType::Heartbeat.to_byte()])
        .await
        .expect("heartbeat send");
}

/// Process every packet queued at `tn`, and only there.
pub(super) async fn deliver(tn: &mut TestNode) -> usize {
    process_available_packets(std::slice::from_mut(tn)).await
}

/// Deliver queued packets between the nodes until a round moves none.
pub(super) async fn pump(nodes: &mut [TestNode]) {
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if process_available_packets(nodes).await == 0 {
            break;
        }
    }
}

/// `tn`'s consecutive decryption failure count for `peer`. A peer that is no
/// longer held panics here, which the caller's test counts as a failure.
pub(super) fn failures(tn: &TestNode, peer: &NodeAddr) -> u32 {
    tn.node
        .get_peer(peer)
        .expect("the receiver still holds the sender as a peer")
        .consecutive_decrypt_failures()
}

/// Age the link session each node holds for the other by `age`.
pub(super) fn age_link(nodes: &mut [TestNode], a: usize, b: usize, age: Duration) {
    let a_addr = *nodes[a].node.node_addr();
    let b_addr = *nodes[b].node.node_addr();
    nodes[a]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .test_backdate_session_established(age);
    nodes[b]
        .node
        .get_peer_mut(&a_addr)
        .unwrap()
        .test_backdate_session_established(age);
}

/// Two loopback nodes peered over FMP, node 0 dialling node 1.
pub(super) async fn linked_pair(
    cfg0: crate::config::Config,
    cfg1: crate::config::Config,
) -> Vec<TestNode> {
    let mut nodes = vec![
        make_test_node_with_config(cfg0, 1280).await,
        make_test_node_with_config(cfg1, 1280).await,
    ];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr1).is_some() && nodes[1].node.get_peer(&addr0).is_some(),
        "precondition: the pair is peered"
    );
    nodes
}

/// Start `from`'s rekey to `to`, have `to` answer it as the responder, and
/// complete it at `from`, leaving `from` holding an initiator pending. Returns
/// the index of the pending `to` holds.
pub(super) async fn rekey_to_pending(
    nodes: &mut [TestNode],
    from: usize,
    to: usize,
) -> SessionIndex {
    let from_addr = *nodes[from].node.node_addr();
    let to_addr = *nodes[to].node.node_addr();
    nodes[from].node.check_rekey().await;
    assert!(
        nodes[from]
            .node
            .get_peer(&to_addr)
            .unwrap()
            .rekey_in_progress(),
        "precondition: the rekey initiator started a rekey"
    );
    assert_eq!(
        deliver(&mut nodes[to]).await,
        1,
        "precondition: only the rekey msg1 is queued at the responder"
    );
    let index = {
        let peer = nodes[to].node.get_peer(&from_addr).unwrap();
        assert_eq!(
            peer.pending_role(),
            Some(RekeyRole::Responder),
            "precondition: the responder holds a responder pending after the msg1"
        );
        peer.pending_our_index().unwrap()
    };
    assert_eq!(
        deliver(&mut nodes[from]).await,
        1,
        "precondition: only the msg2 is queued at the rekey initiator"
    );
    assert_eq!(
        nodes[from].node.get_peer(&to_addr).unwrap().pending_role(),
        Some(RekeyRole::Initiator),
        "precondition: the rekey initiator holds its pending after the msg2"
    );
    index
}

/// Run `node`'s rekey tick, which cuts over the pending it initiated.
pub(super) async fn cutover(tn: &mut TestNode, peer: &NodeAddr) {
    let expected = tn.node.get_peer(peer).unwrap().pending_our_index();
    tn.node.check_rekey().await;
    let p = tn.node.get_peer(peer).unwrap();
    assert!(
        p.pending_new_session().is_none() && p.our_index() == expected,
        "precondition: the tick cut over to the pending session"
    );
}

/// A link node A dialled to node B, after B restarted and A's rekey msg1
/// revealed it. Built by [`restart_revealed_by_our_rekey`].
struct RestartedPeer {
    /// A at 0, the restarted B at 1.
    nodes: Vec<TestNode>,
    a_addr: NodeAddr,
    b_addr: NodeAddr,
    /// The index of the pending session A's rekey produced.
    pending_index: SessionIndex,
    /// The restarted B's frames to A that arrived after its msg2, held back.
    held: Vec<ReceivedPacket>,
}

/// Peer A and B, restart B, and let A's rekey msg1 reach the restarted B.
///
/// B has no peer for A, so it promotes the msg1 as a fresh link at K-bit 0.
/// A completes B's msg2 as a rekey, sees B's new startup epoch, and holds the
/// session as an initiator pending. B's first frames on the new link, which
/// name A's pending index, are held back from A.
async fn restart_revealed_by_our_rekey() -> RestartedPeer {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let a_addr = *nodes[0].node.node_addr();
    let b_addr = *nodes[1].node.node_addr();

    let restarted = restarted_node(&nodes[1], rekey_config(REKEY_AFTER_SECS));
    drop(std::mem::replace(&mut nodes[1], restarted));

    nodes[0]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .test_backdate_session_established(trigger_age());
    nodes[0].node.check_rekey().await;
    assert!(
        nodes[0].node.get_peer(&b_addr).unwrap().rekey_in_progress(),
        "precondition: A started a rekey to the restarted B"
    );
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: only A's rekey msg1 is queued at the restarted B"
    );
    assert!(
        nodes[1].node.get_peer(&a_addr).is_some(),
        "precondition: the restarted B promoted A's msg1 as a fresh link"
    );

    let mut queued: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    let at = queued
        .iter()
        .position(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_MSG2))
        .expect("precondition: the restarted B's msg2 is queued at A");
    let msg2 = queued.remove(at);
    assert!(
        queued
            .iter()
            .all(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_ESTABLISHED)),
        "precondition: everything else queued at A is an established frame"
    );
    nodes[0].node.handle_msg2(msg2).await;

    let pending_index = {
        let peer = nodes[0].node.get_peer(&b_addr).unwrap();
        assert_eq!(
            peer.pending_role(),
            Some(RekeyRole::Initiator),
            "precondition: A holds an initiator pending after the msg2"
        );
        assert_eq!(
            peer.remote_epoch(),
            Some(nodes[1].node.startup_epoch()),
            "precondition: A recorded the restarted B's startup epoch"
        );
        peer.pending_our_index().unwrap()
    };
    assert!(
        !nodes[1].node.get_peer(&a_addr).unwrap().current_k_bit(),
        "precondition: the restarted B is at K-bit 0"
    );

    RestartedPeer {
        nodes,
        a_addr,
        b_addr,
        pending_index,
        held: queued,
    }
}

/// Hand each held frame to A, asserting that every one decrypts.
async fn deliver_held(r: &mut RestartedPeer) {
    for packet in std::mem::take(&mut r.held) {
        r.nodes[0].node.handle_encrypted_frame(packet).await;
        assert_eq!(
            failures(&r.nodes[0], &r.b_addr),
            0,
            "precondition: A decrypts the restarted B's first frames on its new session"
        );
    }
}

/// Origin of the split: our rekey reveals a peer restart, we cut over, and
/// then the restarted peer rekeys. Its frames on the new session must be
/// adopted by A without a decryption failure.
#[tokio::test]
async fn a_peer_restart_revealed_by_our_rekey_leaves_the_peers_next_rekey_adopted_without_decrypt_failures()
 {
    let mut r = restart_revealed_by_our_rekey().await;
    let (a_addr, b_addr) = (r.a_addr, r.b_addr);
    cutover(&mut r.nodes[0], &b_addr).await;
    deliver_held(&mut r).await;

    // B rekeys and A answers.
    age_link(&mut r.nodes, 0, 1, trigger_age());
    let a_pending = rekey_to_pending(&mut r.nodes, 1, 0).await;
    cutover(&mut r.nodes[1], &a_addr).await;
    let frame_kbit = r.nodes[1].node.get_peer(&a_addr).unwrap().current_k_bit();

    for n in 1..=FRAMES {
        heartbeat(&mut r.nodes[1], &a_addr).await;
        deliver(&mut r.nodes[0]).await;
        assert_eq!(
            failures(&r.nodes[0], &b_addr),
            0,
            "A's decrypt-failure count after B's frame {n}"
        );
        if n == 1 {
            let peer = r.nodes[0].node.get_peer(&b_addr).unwrap();
            assert!(
                peer.pending_new_session().is_none() && peer.our_index() == Some(a_pending),
                "A's pending session is promoted by B's frame 1"
            );
            assert_eq!(
                peer.current_k_bit(),
                frame_kbit,
                "A's K-bit equals the frame's after the promotion"
            );
        }
    }

    cleanup_nodes(&mut r.nodes).await;
}

/// The restarted peer's first frames name our pending index with K-bit 0,
/// equal to ours. They must promote the pending before our own tick does.
#[tokio::test]
async fn a_restarted_peers_first_frames_on_our_pending_index_promote_it_before_our_cutover() {
    let mut r = restart_revealed_by_our_rekey().await;
    let (a_addr, b_addr) = (r.a_addr, r.b_addr);
    let held = std::mem::take(&mut r.held);
    let total = held.len() + 3;
    let mut held = held.into_iter();

    for n in 1..=total {
        match held.next() {
            Some(packet) => r.nodes[0].node.handle_encrypted_frame(packet).await,
            None => {
                heartbeat(&mut r.nodes[1], &a_addr).await;
                deliver(&mut r.nodes[0]).await;
            }
        }
        assert_eq!(
            failures(&r.nodes[0], &b_addr),
            0,
            "A's decrypt-failure count after B's frame {n}"
        );
        if n == 1 {
            let peer = r.nodes[0].node.get_peer(&b_addr).unwrap();
            assert!(
                peer.pending_new_session().is_none() && peer.our_index() == Some(r.pending_index),
                "A's pending session is promoted by B's frame 1"
            );
            assert!(
                !peer.current_k_bit(),
                "A's K-bit is the frame's, 0, after the promotion"
            );
        }
    }

    cleanup_nodes(&mut r.nodes).await;
}

/// A peer's frame on our pending index authenticates against the pending
/// session even when its K-bit already equals ours. It must promote the
/// pending, and our K-bit must then be the frame's.
#[tokio::test]
async fn a_peer_rekey_frame_on_our_pending_index_promotes_it_even_when_the_k_bits_already_match() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let a_addr = *nodes[0].node.node_addr();
    let b_addr = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    nodes[0]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .force_kbit(true);

    // B rekeys, A answers, B cuts over from K-bit 0 to 1.
    let a_pending = rekey_to_pending(&mut nodes, 1, 0).await;
    cutover(&mut nodes[1], &a_addr).await;
    assert!(
        nodes[1].node.get_peer(&a_addr).unwrap().current_k_bit(),
        "precondition: B sends at K-bit 1 after its cutover"
    );

    for n in 1..=FRAMES {
        heartbeat(&mut nodes[1], &a_addr).await;
        deliver(&mut nodes[0]).await;
        assert_eq!(
            failures(&nodes[0], &b_addr),
            0,
            "A's decrypt-failure count after B's frame {n}"
        );
        if n == 1 {
            let peer = nodes[0].node.get_peer(&b_addr).unwrap();
            assert!(
                peer.pending_new_session().is_none() && peer.our_index() == Some(a_pending),
                "A's pending session is promoted by B's frame 1"
            );
            assert!(
                peer.current_k_bit(),
                "A's K-bit is the frame's, 1, after the promotion"
            );
        }
    }

    cleanup_nodes(&mut nodes).await;
}

/// After a cutover on a rekey that revealed a peer restart, our K-bit must be
/// 0, the value the restarted peer holds, and a later cutover must toggle it
/// as usual. A peer that only tries its pending on a K-bit that differs from
/// its own must then adopt our next rekey.
#[tokio::test]
async fn our_cutover_after_a_restart_revealing_msg2_takes_k_bit_zero_so_an_old_gate_peer_adopts_our_next_rekey()
 {
    let mut r = restart_revealed_by_our_rekey().await;
    let (a_addr, b_addr) = (r.a_addr, r.b_addr);
    cutover(&mut r.nodes[0], &b_addr).await;
    r.nodes[1].node.get_peer_mut(&a_addr).unwrap().set_oldgate();
    deliver_held(&mut r).await;

    // A rekeys again, B answers, A cuts over.
    age_link(&mut r.nodes, 0, 1, trigger_age());
    let b_pending = rekey_to_pending(&mut r.nodes, 0, 1).await;
    cutover(&mut r.nodes[0], &b_addr).await;

    for n in 1..=FRAMES {
        heartbeat(&mut r.nodes[0], &b_addr).await;
        deliver(&mut r.nodes[1]).await;
        assert_eq!(
            failures(&r.nodes[1], &a_addr),
            0,
            "B's decrypt-failure count after A's frame {n}"
        );
        if n == 1 {
            let peer = r.nodes[1].node.get_peer(&a_addr).unwrap();
            assert!(
                peer.pending_new_session().is_none() && peer.our_index() == Some(b_pending),
                "B's pending session is promoted by A's frame 1"
            );
        }
    }
    assert_eq!(
        r.nodes[0].node.get_peer(&b_addr).unwrap().current_k_bit(),
        r.nodes[1].node.get_peer(&a_addr).unwrap().current_k_bit(),
        "A's K-bit equals B's after B adopts A's rekey"
    );

    cleanup_nodes(&mut r.nodes).await;
}

/// A pair caught mid-rekey: node 0 (B) initiated, node 1 (A) answered and
/// holds the responder pending, and B's msg2 is held back. Returns A's pending
/// index.
async fn responder_pending_pair() -> (Vec<TestNode>, SessionIndex) {
    let mut nodes = linked_pair(rekey_config(REKEY_AFTER_SECS), rekey_config(u64::MAX)).await;
    age_link(&mut nodes, 0, 1, trigger_age());
    let b_addr = *nodes[0].node.node_addr();
    nodes[0].node.check_rekey().await;
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: only B's rekey msg1 is queued at A"
    );
    let index = {
        let peer = nodes[1].node.get_peer(&b_addr).unwrap();
        assert_eq!(
            peer.pending_role(),
            Some(RekeyRole::Responder),
            "precondition: A holds a responder pending after the msg1"
        );
        peer.pending_our_index().unwrap()
    };
    let held: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    assert_eq!(held.len(), 1, "precondition: only A's msg2 is held");
    (nodes, index)
}

/// A frame naming the pending index that does not authenticate against any
/// session neither promotes the pending nor escapes the failure count, at
/// either K-bit.
#[tokio::test]
async fn a_frame_on_the_pending_index_that_does_not_authenticate_neither_promotes_nor_escapes_the_failure_count()
 {
    let (mut nodes, pending_index) = responder_pending_pair().await;
    let b_addr = *nodes[0].node.node_addr();
    let (kbit, index) = {
        let peer = nodes[1].node.get_peer(&b_addr).unwrap();
        (peer.current_k_bit(), peer.our_index())
    };
    let failures_before = failures(&nodes[1], &b_addr);

    for (i, frame_kbit) in [kbit, !kbit].into_iter().enumerate() {
        let mut ciphertext = vec![0u8; 48];
        rand::rng().fill_bytes(&mut ciphertext);
        let flags = if frame_kbit { FLAG_KEY_EPOCH } else { 0 };
        let mut data = build_established_header(
            pending_index,
            1000 + i as u64,
            flags,
            ciphertext.len() as u16,
        )
        .to_vec();
        data.extend_from_slice(&ciphertext);
        let packet = ReceivedPacket::new(nodes[1].transport_id, nodes[0].addr.clone(), data);
        nodes[1].node.handle_encrypted_frame(packet).await;
    }

    let peer = nodes[1].node.get_peer(&b_addr).unwrap();
    assert_eq!(
        peer.pending_our_index(),
        Some(pending_index),
        "A keeps its pending session after frames that do not authenticate"
    );
    assert_eq!(peer.current_k_bit(), kbit, "A's K-bit is unchanged");
    assert_eq!(peer.our_index(), index, "A's current index is unchanged");
    assert_eq!(
        failures(&nodes[1], &b_addr),
        failures_before + 2,
        "A counts both frames as decryption failures"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A frame on the current index with a K-bit that differs from ours is tried
/// against the pending session, fails there, and must still decrypt on the
/// current session.
#[tokio::test]
async fn a_k_flipped_frame_on_the_current_index_that_fails_the_trial_still_decrypts_on_the_current_session()
 {
    let (mut nodes, pending_index) = responder_pending_pair().await;
    let a_addr = *nodes[1].node.node_addr();
    let b_addr = *nodes[0].node.node_addr();
    let (kbit, index, recv_before) = {
        let peer = nodes[1].node.get_peer(&b_addr).unwrap();
        (
            peer.current_k_bit(),
            peer.our_index(),
            peer.link_stats().packets_recv,
        )
    };
    nodes[0]
        .node
        .get_peer_mut(&a_addr)
        .unwrap()
        .force_kbit(!kbit);

    heartbeat(&mut nodes[0], &a_addr).await;
    deliver(&mut nodes[1]).await;

    let peer = nodes[1].node.get_peer(&b_addr).unwrap();
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "A's decrypt-failure count after B's K-flipped frame"
    );
    assert_eq!(
        peer.pending_our_index(),
        Some(pending_index),
        "A keeps its pending session"
    );
    assert_eq!(peer.current_k_bit(), kbit, "A's K-bit is unchanged");
    assert_eq!(peer.our_index(), index, "A's current index is unchanged");
    assert_eq!(
        peer.link_stats().packets_recv,
        recv_before + 1,
        "A receives B's frame on its current session"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A second-path dial on an aged session is answered as a rekey by the
/// larger node and completed as a cross-connection swap by the smaller one,
/// which keeps its K-bit. The smaller node's frames on the new session must
/// promote the larger node's pending session, leave the two K-bits equal,
/// and count no decryption failure.
///
/// A node never dials a peer it holds a session with, but such a dial still
/// arrives from an older node or a caller that dials by hand, so the dial is
/// started directly here.
#[tokio::test]
async fn an_alternate_path_dial_on_an_aged_session_leaves_both_ends_able_to_authenticate() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    age_link(&mut nodes, s, l, Duration::from_secs(31));
    let s_index_before = nodes[s].node.get_peer(&l_addr).unwrap().our_index();

    // The smaller node dials the larger one on a second address.
    let alias = add_loopback_alias(&nodes[l].addr);
    let l_identity = PeerIdentity::from_pubkey_full(nodes[l].node.identity().pubkey_full());
    let s_transport = nodes[s].transport_id;
    nodes[s]
        .node
        .initiate_connection(s_transport, alias, l_identity)
        .await
        .expect("precondition: the dial on the alternate address starts");

    // Deliver the msg1 to the larger node only: it answers as a rekey.
    assert_eq!(
        deliver(&mut nodes[l]).await,
        1,
        "precondition: only the smaller node's msg1 is queued at the larger node"
    );
    let pending_index = {
        let peer = nodes[l].node.get_peer(&s_addr).unwrap();
        assert_eq!(
            peer.pending_role(),
            Some(RekeyRole::Responder),
            "precondition: L holds a responder pending after the msg1"
        );
        peer.pending_our_index()
            .expect("precondition: L's responder pending has an index")
    };

    // The smaller node completes the dial as a cross-connection swap.
    pump(&mut nodes).await;
    assert_ne!(
        nodes[s].node.get_peer(&l_addr).unwrap().our_index(),
        s_index_before,
        "precondition: S swapped to the alternate-path session"
    );

    for n in 1..=5 {
        heartbeat(&mut nodes[s], &l_addr).await;
        deliver(&mut nodes[l]).await;
        assert_eq!(
            failures(&nodes[l], &s_addr),
            0,
            "L's decrypt-failure count after S's heartbeat {n}"
        );
        if n == 1 {
            let peer = nodes[l].node.get_peer(&s_addr).unwrap();
            assert!(
                peer.pending_new_session().is_none(),
                "L's pending session is promoted by heartbeat 1"
            );
            assert_eq!(
                peer.our_index(),
                Some(pending_index),
                "L's current index is the pending index after heartbeat 1"
            );
            assert_eq!(
                peer.current_k_bit(),
                nodes[s].node.get_peer(&l_addr).unwrap().current_k_bit(),
                "L's K-bit equals S's after the adoption"
            );
        }
    }

    // The larger node's reply decrypts at the smaller node.
    let recv_before = nodes[s]
        .node
        .get_peer(&l_addr)
        .unwrap()
        .link_stats()
        .packets_recv;
    heartbeat(&mut nodes[l], &s_addr).await;
    deliver(&mut nodes[s]).await;
    assert_eq!(
        failures(&nodes[s], &l_addr),
        0,
        "S's decrypt-failure count after L's heartbeat"
    );
    assert_eq!(
        nodes[s]
            .node
            .get_peer(&l_addr)
            .unwrap()
            .link_stats()
            .packets_recv,
        recv_before + 1,
        "S receives L's heartbeat on its current session"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Hand A a fresh msg1 with the restarted B's identity and startup epoch,
/// arriving from B's address on A's established link, after discarding
/// whatever was queued at B. Returns whether anything A sent in answer is a
/// msg2 queued at B.
async fn crossing_dial_from_restarted_peer(r: &mut RestartedPeer) -> bool {
    while r.nodes[1].packet_rx.try_recv().is_ok() {}
    let b_identity = r.nodes[1].node.identity().clone();
    let b_epoch = r.nodes[1].node.startup_epoch();
    let source = r.nodes[0]
        .node
        .get_peer(&r.b_addr)
        .unwrap()
        .current_addr()
        .cloned()
        .expect("precondition: A holds B's link address");
    let data = super::establish_chartests::craft_msg1_wire(
        &r.nodes[0].node,
        &b_identity,
        b_epoch,
        SessionIndex::new(0x7171),
        Node::now_ms(),
    );
    let transport_id = r.nodes[0].transport_id;
    r.nodes[0]
        .node
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            source,
            data,
            Node::now_ms(),
        ))
        .await;
    std::iter::from_fn(|| r.nodes[1].packet_rx.try_recv().ok())
        .any(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_MSG2))
}

/// Our rekey revealed B's restart, and A has cut over to the session it
/// produced. 12 s later a crossing dial from B, which promoted A's msg1 as
/// a fresh link, must not be taken for a rekey: the link A shares with the
/// restarted B is 12 s old, however old A's peering is.
#[tokio::test]
async fn a_peer_restart_revealed_by_our_rekey_restarts_our_link_age_so_its_crossing_dial_is_not_taken_for_a_rekey()
 {
    let mut r = restart_revealed_by_our_rekey().await;
    let b_addr = r.b_addr;
    cutover(&mut r.nodes[0], &b_addr).await;
    deliver_held(&mut r).await;
    let link = {
        let p = r.nodes[0].node.get_peer_mut(&b_addr).unwrap();
        p.test_backdate_session_established(Duration::from_secs(12));
        p.test_backdate_drain_started(Duration::from_secs(12));
        p.link_id()
    };

    let answered = crossing_dial_from_restarted_peer(&mut r).await;

    let p = r.nodes[0].node.get_peer(&b_addr).expect("A keeps B");
    assert!(
        p.pending_new_session().is_none(),
        "the crossing dial must arm no pending"
    );
    assert_eq!(p.link_id(), link, "A's peering must keep its link");
    assert!(!answered, "the crossing dial must draw no msg2");
    cleanup_nodes(&mut r.nodes).await;
}

/// Our rekey revealed B's restart, and A still holds the pending it
/// produced. A crossing dial from B, silent at A for 16 s, must be refused
/// while the pending is held: A keeps its pending and its link, and the
/// cutover then proceeds.
#[tokio::test]
async fn a_resent_dial_from_a_silent_restarted_peer_while_our_restart_pending_is_held_is_refused_and_keeps_the_link()
 {
    let mut r = restart_revealed_by_our_rekey().await;
    let b_addr = r.b_addr;
    let link = {
        let p = r.nodes[0].node.get_peer_mut(&b_addr).unwrap();
        p.touch(Node::now_ms() - 16_000);
        p.link_id()
    };

    let answered = crossing_dial_from_restarted_peer(&mut r).await;

    let p = r.nodes[0]
        .node
        .get_peer(&b_addr)
        .expect("A must keep its peering with B");
    assert_eq!(p.link_id(), link, "A's peering must keep its link");
    assert_eq!(
        p.pending_our_index(),
        Some(r.pending_index),
        "A must keep the pending its rekey produced"
    );
    assert!(!answered, "the crossing dial must draw no msg2");
    cutover(&mut r.nodes[0], &b_addr).await;
    deliver_held(&mut r).await;
    cleanup_nodes(&mut r.nodes).await;
}
