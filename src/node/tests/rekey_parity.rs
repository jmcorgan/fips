//! Link rekeys between two ends whose K-bits have fallen out of step.
//!
//! The K-bit in an established frame's header says which key epoch the
//! sender is on. A peer restart that our rekey reveals leaves the two ends of
//! a link holding K-bits that do not reflect the same history: the restarted
//! peer promotes our rekey as a fresh link at K-bit 0, while we complete it as
//! a rekey, cutting over at once to K-bit 0 to match. After that, the peer's
//! frames on a new session can carry a K-bit equal to ours. These tests drive that path over loopback, with the XX
//! rekey's three messages, and assert on promotion of the pending session and
//! on the receiver's consecutive decryption failure count, never on whether
//! the peer survives.

use super::*;
use crate::node::tests::spanning_tree::{
    TestNode, add_loopback_alias, cleanup_nodes, drain_all_packets, initiate_handshake,
    make_test_node_with_config, process_available_packets, restarted_node,
};
use crate::proto::fmp::wire::{
    CommonPrefix, FLAG_KEY_EPOCH, PHASE_ESTABLISHED, PHASE_MSG2, PHASE_MSG3,
    build_established_header,
};
use crate::proto::link::LinkMessageType;
use fips_core::proto::rekey::Role;
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
    config.node.rekey.after_secs = after_secs;
    config.node.rekey.after_messages = u64::MAX;
    config
}

/// A session age past the jittered rekey trigger.
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

/// Start `from`'s rekey to `to` and run its three messages: `to` answers the
/// msg1, `from` completes the msg2 and holds an initiator pending, and `to`
/// completes the msg3 and holds a responder pending. Returns the index of the
/// pending `to` holds.
pub(super) async fn rekey_to_pending(
    nodes: &mut [TestNode],
    from: usize,
    to: usize,
) -> SessionIndex {
    let from_addr = *nodes[from].node.node_addr();
    let to_addr = *nodes[to].node.node_addr();
    nodes[from].node.poll_link_rekeys().await;
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
    assert_eq!(
        deliver(&mut nodes[from]).await,
        1,
        "precondition: only the msg2 is queued at the rekey initiator"
    );
    assert_eq!(
        nodes[from].node.get_peer(&to_addr).unwrap().pending_role(),
        Some(Role::Initiator),
        "precondition: the rekey initiator holds its pending after the msg2"
    );
    assert_eq!(
        deliver(&mut nodes[to]).await,
        1,
        "precondition: only the msg3 is queued at the responder"
    );
    let peer = nodes[to].node.get_peer(&from_addr).unwrap();
    assert!(
        peer.pending_new_session().is_some(),
        "precondition: the responder holds its pending after the msg3"
    );
    peer.pending_our_index().unwrap()
}

/// Advance the test clock past the delay after which a link rekey's
/// initiator cuts over to the pending session it completed.
pub(super) fn pass_cutover_delay() {
    crate::time::advance(fips_core::proto::rekey::Config::fmp().delay);
}

/// Run `node`'s rekey tick after the cutover delay, which cuts over the
/// pending it initiated.
pub(super) async fn cutover(tn: &mut TestNode, peer: &NodeAddr) {
    let expected = tn.node.get_peer(peer).unwrap().pending_our_index();
    pass_cutover_delay();
    tn.node.poll_link_rekeys().await;
    let p = tn.node.get_peer(peer).unwrap();
    assert!(
        p.pending_new_session().is_none() && p.our_index() == expected,
        "precondition: the tick cut over to the pending session"
    );
}

/// A link node A dialled to node B, after B restarted and A's rekey
/// revealed it. Built by [`restart_revealed_by_our_rekey`].
pub(super) struct RestartedPeer {
    /// A at 0, the restarted B at 1.
    pub(super) nodes: Vec<TestNode>,
    pub(super) a_addr: NodeAddr,
    pub(super) b_addr: NodeAddr,
    /// The index of the session A's rekey produced, current at A since
    /// the msg2 that revealed the restart.
    pub(super) new_index: SessionIndex,
    /// The restarted B's frames to A that arrived after its promotion of
    /// A's msg3, held back.
    pub(super) held: Vec<ReceivedPacket>,
}

/// Peer A and B, restart B, and let A's rekey reach the restarted B, as
/// [`reveal_restart`] does.
async fn restart_revealed_by_our_rekey() -> RestartedPeer {
    reveal_restart(
        linked_pair(
            rekey_config(REKEY_AFTER_SECS),
            rekey_config(REKEY_AFTER_SECS),
        )
        .await,
    )
    .await
}

/// Restart B in the pair `nodes` built by [`linked_pair`], A at 0, and run
/// A's rekey to the restarted B.
///
/// B has no peer for A: its leg answers A's rekey msg1, and it promotes A's
/// msg3 as a fresh link at K-bit 0. A reads B's msg2, sees B's new startup
/// epoch, and cuts over to the new session at once at K-bit 0, the value
/// the restarted B holds, keeping its msg3 to resend until B is heard. A's
/// msg3 and the frames A sent after its cutover reach B in that order. B's
/// first frames on the new link are held back from A.
pub(super) async fn reveal_restart(mut nodes: Vec<TestNode>) -> RestartedPeer {
    let a_addr = *nodes[0].node.node_addr();
    let b_addr = *nodes[1].node.node_addr();

    let restarted = restarted_node(&nodes[1], rekey_config(REKEY_AFTER_SECS));
    drop(std::mem::replace(&mut nodes[1], restarted));

    nodes[0]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .test_backdate_session_established(trigger_age());
    nodes[0].node.poll_link_rekeys().await;
    assert!(
        nodes[0].node.get_peer(&b_addr).unwrap().rekey_in_progress(),
        "precondition: A started a rekey to the restarted B"
    );
    let attempt = nodes[0]
        .node
        .get_peer(&b_addr)
        .unwrap()
        .rekey_our_index()
        .expect("precondition: A's rekey holds an index");
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: only A's rekey msg1 is queued at the restarted B"
    );

    let mut queued: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    let at = queued
        .iter()
        .position(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_MSG2))
        .expect("precondition: the restarted B's msg2 is queued at A");
    let msg2 = queued.remove(at);
    nodes[0].node.handle_msg2(msg2).await;

    {
        let peer = nodes[0].node.get_peer(&b_addr).unwrap();
        assert!(
            peer.pending_role().is_none() && peer.our_index() == Some(attempt),
            "precondition: A cut over to its rekey's session at the msg2 that revealed the restart"
        );
        assert!(!peer.current_k_bit(), "precondition: A is at K-bit 0");
        assert_eq!(
            peer.remote_epoch(),
            Some(nodes[1].node.startup_epoch()),
            "precondition: A recorded the restarted B's startup epoch"
        );
    }

    let to_b: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[1].packet_rx.try_recv().ok()).collect();
    assert_eq!(
        to_b.first()
            .and_then(|p| CommonPrefix::parse(&p.data))
            .map(|c| c.phase),
        Some(PHASE_MSG3),
        "precondition: A's msg3 is the first thing queued at the restarted B"
    );
    for packet in to_b {
        match CommonPrefix::parse(&packet.data).map(|c| c.phase) {
            Some(PHASE_MSG3) => nodes[1].node.handle_msg3(packet).await,
            _ => nodes[1].node.handle_encrypted_frame(packet).await,
        }
    }
    {
        let peer = nodes[1]
            .node
            .get_peer(&a_addr)
            .expect("precondition: the restarted B promoted A's rekey as a fresh link");
        assert!(
            !peer.current_k_bit(),
            "precondition: the restarted B is at K-bit 0"
        );
        assert_eq!(
            peer.consecutive_decrypt_failures(),
            0,
            "precondition: the restarted B decrypts what A sent after its cutover"
        );
    }

    queued.extend(std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()));
    assert!(
        queued
            .iter()
            .all(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_ESTABLISHED)),
        "precondition: everything else queued at A is an established frame"
    );

    RestartedPeer {
        nodes,
        a_addr,
        b_addr,
        new_index: attempt,
        held: queued,
    }
}

/// Hand each held frame to A, asserting that every one decrypts.
pub(super) async fn deliver_held(r: &mut RestartedPeer) {
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

/// The msg2 of our rekey that reveals a peer restart cuts over at once, to
/// K-bit 0, the value the restarted peer promoted our rekey at: a
/// three-message rekey has its msg3 to resend, so nothing waits for the
/// peer's frames. The restarted peer's first frames then decrypt on our
/// new session.
#[tokio::test]
async fn a_restart_our_rekey_msg2_reveals_cuts_over_at_once_and_the_restarted_peers_first_frames_decrypt()
 {
    let mut r = restart_revealed_by_our_rekey().await;
    let (a_addr, b_addr) = (r.a_addr, r.b_addr);
    {
        let peer = r.nodes[0].node.get_peer(&b_addr).unwrap();
        assert!(
            peer.pending_new_session().is_none() && peer.our_index() == Some(r.new_index),
            "A holds the rekey's session as current, with nothing pending"
        );
        assert!(!peer.current_k_bit(), "A's K-bit is 0");
    }
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
    }
    let peer = r.nodes[0].node.get_peer(&b_addr).unwrap();
    assert_eq!(
        peer.our_index(),
        Some(r.new_index),
        "A stays on the session"
    );
    assert!(!peer.current_k_bit(), "A's K-bit stays 0");

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

/// Give `node` an established end-to-end session with `peer`, keyed by a
/// handshake of its own, as one held before `peer` restarted would be.
pub(super) fn stale_session(node: &mut Node, peer: NodeAddr) {
    let remote = crate::Identity::generate();
    let mut initiator = crate::noise::HandshakeState::new_initiator(node.identity().keypair());
    initiator.set_local_epoch([1; 8]);
    let mut responder = crate::noise::HandshakeState::new_responder(remote.keypair());
    responder.set_local_epoch([2; 8]);
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    let msg3 = initiator.write_message_3().unwrap();
    responder.read_message_3(&msg3).unwrap();
    let entry = crate::node::session::SessionEntry::keyed(
        peer,
        initiator.into_session().unwrap(),
        crate::node::session::session_at(1_000),
        true,
    );
    node.sessions.insert(peer, entry);
    assert!(
        node.get_session(&peer).is_some(),
        "precondition: a session is held"
    );
}

/// The cutover at the msg2 of a rekey that revealed a peer restart takes
/// K-bit 0, the value the restarted peer holds, and a later cutover toggles
/// it as usual; the peer adopts our next rekey and the two K-bits stay
/// equal. The cutover clears the end-to-end session the restarted peer
/// lost.
#[tokio::test]
async fn our_cutover_at_a_restart_revealing_msg2_takes_k_bit_zero_and_our_next_rekey_toggles_it() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let b_addr = *nodes[1].node.node_addr();
    stale_session(&mut nodes[0].node, b_addr);
    let mut r = reveal_restart(nodes).await;
    let a_addr = r.a_addr;
    assert!(
        !r.nodes[0].node.get_peer(&b_addr).unwrap().current_k_bit(),
        "A takes K-bit 0 at the cutover a revealed restart caused"
    );
    assert!(
        r.nodes[0].node.get_session(&b_addr).is_none(),
        "the cutover a revealed restart caused clears the end-to-end session the restarted peer lost"
    );
    deliver_held(&mut r).await;

    // A rekeys again, B answers, A cuts over.
    age_link(&mut r.nodes, 0, 1, trigger_age());
    let b_pending = rekey_to_pending(&mut r.nodes, 0, 1).await;
    cutover(&mut r.nodes[0], &b_addr).await;
    assert!(
        r.nodes[0].node.get_peer(&b_addr).unwrap().current_k_bit(),
        "A's next cutover toggles its K-bit to 1"
    );

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

/// A pair caught mid-rekey: node 0 (B) initiated and holds its initiator
/// pending, node 1 (A) completed B's msg3 and holds the responder pending, and
/// neither has cut over. Returns A's pending index.
async fn responder_pending_pair() -> (Vec<TestNode>, SessionIndex) {
    let mut nodes = linked_pair(rekey_config(REKEY_AFTER_SECS), rekey_config(u64::MAX)).await;
    age_link(&mut nodes, 0, 1, trigger_age());
    let index = rekey_to_pending(&mut nodes, 0, 1).await;
    let b_addr = *nodes[0].node.node_addr();
    assert_eq!(
        nodes[1].node.get_peer(&b_addr).unwrap().pending_role(),
        Some(Role::Responder),
        "precondition: A holds a responder pending after the msg3"
    );
    let held: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    assert!(held.is_empty(), "precondition: nothing is queued at B");
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

/// A cross-connection move puts the peer on the winning session with a new
/// link rekey machine built from what the replaced one hands back. The
/// smaller node's own rekey in flight is abandoned and its drain of the
/// previous session ends, each releasing its index, and the decrypt workers
/// are given the new session; the moved session keeps the replaced one's
/// key-epoch bit, start, timestamp base and link age, the peer's startup
/// epoch, the key-epoch bit last seen on the peer's frames, and the replay
/// record.
///
/// The larger node dials the smaller one. The smaller node rekeys the link,
/// cuts over and hears the peer under the new session, starts another
/// rekey, and then dials the larger node on a second address, which the
/// larger node answers with a fresh leg and the smaller node completes as a
/// swap: the smaller node's outbound handshake wins the crossing.
#[tokio::test]
async fn a_cross_connection_move_abandons_our_rekey_ends_the_drain_and_keeps_the_k_bits_start_link_age_and_record()
 {
    let mut nodes = vec![
        make_test_node_with_config(rekey_config(REKEY_AFTER_SECS), 1280).await,
        make_test_node_with_config(rekey_config(REKEY_AFTER_SECS), 1280).await,
    ];
    let (s, l) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    initiate_handshake(&mut nodes, l, s).await;
    drain_all_packets(&mut nodes, false).await;

    // S's rekey, its cutover, and L's frame under the new session.
    age_link(&mut nodes, s, l, trigger_age());
    rekey_to_pending(&mut nodes, s, l).await;
    cutover(&mut nodes[s], &l_addr).await;
    deliver(&mut nodes[l]).await;
    deliver(&mut nodes[s]).await;
    let drained = nodes[s]
        .node
        .get_peer(&l_addr)
        .unwrap()
        .previous_our_index()
        .expect("precondition: S drains the session its cutover replaced");

    // L's session is old enough to answer a msg1 as a rekey; S's own rekey
    // is in flight, its msg1 lost.
    nodes[l]
        .node
        .get_peer_mut(&s_addr)
        .unwrap()
        .test_backdate_session_established(trigger_age());
    let attempt = super::start_link_rekey(&mut nodes[s].node, &l_addr).await;
    while nodes[l].packet_rx.try_recv().is_ok() {}
    let replaced = nodes[s].node.get_peer(&l_addr).unwrap().our_index();
    let before = nodes[s].node.get_peer(&l_addr).unwrap().link_anchors();
    assert!(
        before.as_ref().is_some_and(|a| a.peer_k.is_some()),
        "precondition: S has seen L's key-epoch bit"
    );
    #[cfg(unix)]
    {
        use crate::node::decrypt_worker::DecryptWorkerPool;
        let node = &mut nodes[s].node;
        node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
        let offer = node.get_peer(&l_addr).unwrap().offer_to_workers();
        node.run_link_outputs(&l_addr, offer);
    }

    // S dials L on a second address; L answers on a fresh leg, and S
    // completes the dial as a cross-connection swap.
    super::control::quieten(&mut nodes[s], &l_addr);
    let alias = add_loopback_alias(&nodes[l].addr);
    let l_npub = nodes[l].node.npub();
    nodes[s]
        .node
        .api_connect(&l_npub, &alias.to_string(), "loopback")
        .await
        .expect("precondition: api_connect on an alternate path succeeds");
    assert_eq!(
        deliver(&mut nodes[l]).await,
        1,
        "precondition: only S's dial msg1 is queued at L"
    );
    assert!(
        deliver(&mut nodes[s]).await >= 1,
        "precondition: L's msg2 reaches S"
    );

    let peer = nodes[s].node.get_peer(&l_addr).unwrap();
    assert_ne!(
        peer.our_index(),
        replaced,
        "precondition: S moved to the dial's session"
    );
    assert!(!peer.rekey_in_progress(), "the move abandons S's own rekey");
    assert_eq!(peer.previous_our_index(), None, "the move ends S's drain");
    let transport = peer.transport_id().unwrap();
    for (what, index) in [("drained", drained), ("rekey attempt", attempt)] {
        assert!(
            !nodes[s]
                .node
                .peers_by_index
                .contains_key(&(transport, index.as_u32())),
            "the {what} index is unbound at the move"
        );
    }
    super::link_index_audit::audit(&nodes[s].node, "the cross-connection move");
    assert_eq!(
        nodes[s].node.get_peer(&l_addr).unwrap().link_anchors(),
        before,
        "the moved session keeps the K-bits, start, timestamp base, link age, peer epoch and record"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Our link rekey's new session takes the inverse of the K-bit the peer
/// was last seen sending under the current session, not the inverse of our
/// own: with the two ends' K-bits out of step, the new session's frames
/// then carry a K-bit that differs from the one the peer seals under, which
/// is what a peer that tries its pending session only on a differing K-bit
/// needs. A frame a decrypt worker authenticated counts as seen: on a node
/// with a decrypt pool nearly every frame under the current session is
/// opened there.
#[tokio::test]
async fn our_link_rekey_takes_the_inverse_of_the_k_bit_the_peer_was_last_seen_sending_inline_or_through_a_decrypt_worker()
 {
    let mut nodes = linked_pair(rekey_config(REKEY_AFTER_SECS), crate::config::Config::new()).await;
    let a_addr = *nodes[0].node.node_addr();
    let b_addr = *nodes[1].node.node_addr();
    // A is at K-bit 1, B at 0, and A has heard B at 0.
    nodes[0]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .force_kbit(true);
    heartbeat(&mut nodes[1], &a_addr).await;
    deliver(&mut nodes[0]).await;

    age_link(&mut nodes, 0, 1, trigger_age());
    rekey_to_pending(&mut nodes, 0, 1).await;
    cutover(&mut nodes[0], &b_addr).await;
    assert!(
        nodes[0].node.get_peer(&b_addr).unwrap().current_k_bit(),
        "A's new session takes 1, the inverse of the 0 it heard from B, not 0, the inverse of its own"
    );

    #[cfg(unix)]
    {
        use crate::node::decrypt_worker::DecryptFallback;

        // B adopts on A's frame and seals at A's new K-bit, 1. What B sends
        // A from here is opened by a decrypt worker: A sees only the bounce.
        heartbeat(&mut nodes[0], &b_addr).await;
        deliver(&mut nodes[1]).await;
        assert!(
            nodes[1].node.get_peer(&a_addr).unwrap().current_k_bit(),
            "precondition: B adopted A's new session at K-bit 1"
        );
        let _ = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).count();
        let current = nodes[0]
            .node
            .get_peer(&b_addr)
            .unwrap()
            .our_index()
            .unwrap();
        let mut data = 0u32.to_le_bytes().to_vec();
        data.push(crate::proto::link::LinkMessageType::Heartbeat.to_byte());
        let bounce = DecryptFallback {
            source_node_addr: b_addr,
            transport_id: nodes[0].transport_id,
            remote_addr: nodes[1].addr.clone(),
            timestamp_ms: Node::now_ms(),
            packet_len: data.len() + 32,
            receiver_idx: current.as_u32(),
            fmp_counter: 1,
            fmp_flags: FLAG_KEY_EPOCH,
            fmp_plaintext_len: data.len(),
            packet_data: data,
            fmp_plaintext_offset: 0,
        };
        nodes[0].node.process_decrypt_fallback(bounce).await;

        age_link(&mut nodes, 0, 1, trigger_age());
        rekey_to_pending(&mut nodes, 0, 1).await;
        cutover(&mut nodes[0], &b_addr).await;
        assert!(
            !nodes[0].node.get_peer(&b_addr).unwrap().current_k_bit(),
            "A's next session takes 0, the inverse of the 1 a decrypt worker saw from B"
        );
    }

    cleanup_nodes(&mut nodes).await;
}
