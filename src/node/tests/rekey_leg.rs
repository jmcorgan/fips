//! The inbound legs: a link handshake's responder state from msg1 to msg3,
//! and the hand-over of a peer's link rekey from a leg to the peer's link
//! rekey machine.
//!
//! On this line a peer's link rekey arrives as a new XX handshake. The node
//! answers its msg1 on a fresh leg, which draws its index as a lease, and
//! reads its msg3 on a fork of the leg's handshake. A msg3 that declares a
//! rekey of a session the authenticated peer's machine holds, current or
//! previous, is handed to that machine, lease and all; every other exit of a
//! leg releases the lease. These tests drive the legs over loopback, most of
//! them with a hand-run initiator whose msg3 the test writes, and check the
//! node's allocator against the leases held after every exit.

use super::link_index_audit::audit;
use super::link_setup_diag::session_tag;
use super::rekey_parity::{
    age_link, deliver, failures, heartbeat, linked_pair, pass_cutover_delay, pump, rekey_config,
    trigger_age,
};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;
use crate::Identity;
use crate::proto::fmp::NodeProfile;
use crate::proto::fmp::wire::{
    CommonPrefix, Msg2Header, NegotiationPayload, PHASE_MSG1, PHASE_MSG2, PHASE_MSG3, TLV_REKEY_OF,
    build_msg1, build_msg3,
};

/// Rekey interval for the pairs below.
const REKEY_AFTER_SECS: u64 = 60;

/// A link handshake a test runs by hand as its initiator, under an identity
/// and from an address it chooses, writing the msg3 and its negotiation
/// payload itself.
struct HandDial {
    hs: crate::noise::HandshakeState,
    ours: SessionIndex,
}

impl HandDial {
    /// Send node `to` a msg1 under `identity`'s key and startup epoch
    /// `epoch`, from node `from`'s address, with `ours` as the dial's index.
    async fn open(
        nodes: &mut [TestNode],
        from: usize,
        to: usize,
        identity: &Identity,
        epoch: [u8; 8],
        ours: u32,
    ) -> Self {
        let mut hs = crate::noise::HandshakeState::new_initiator(identity.keypair());
        hs.set_local_epoch(epoch);
        let ours = SessionIndex::new(ours);
        let msg1 = build_msg1(ours, &hs.write_message_1().expect("the msg1 builds"));
        let packet = ReceivedPacket::new(nodes[to].transport_id, nodes[from].addr.clone(), msg1);
        nodes[to].node.handle_msg1(packet).await;
        Self { hs, ours }
    }

    /// The msg2 answering this dial, taken off node `from`'s queue with
    /// every other packet queued there.
    fn msg2(&self, nodes: &mut [TestNode], from: usize) -> Vec<u8> {
        let ours = self.ours;
        taken(&mut nodes[from])
            .into_iter()
            .find(|p| {
                phase(p) == Some(PHASE_MSG2)
                    && Msg2Header::parse(&p.data).is_some_and(|h| h.receiver_idx == ours)
            })
            .expect("the leg's msg2 is queued at the dialing address")
            .data
    }

    /// Read `msg2` and write the framed msg3 carrying `payload`.
    fn msg3(&self, msg2: &[u8], payload: &[u8]) -> Vec<u8> {
        let header = Msg2Header::parse(msg2).expect("a framed msg2");
        let (mut fork, _) = self
            .hs
            .fork_msg2(&msg2[header.noise_msg2_offset..])
            .expect("the msg2 reads");
        let mut msg3 = fork.write_message_3().expect("the msg3 builds");
        msg3.extend(fork.encrypt_payload(payload).expect("the payload seals"));
        build_msg3(self.ours, header.sender_idx, &msg3)
    }

    /// Answer the leg's msg2 off node `from`'s queue with a msg3 carrying
    /// `payload`, delivered to node `to` from `from`'s address.
    async fn finish(&self, nodes: &mut [TestNode], from: usize, to: usize, payload: &[u8]) {
        let msg2 = self.msg2(nodes, from);
        let msg3 = self.msg3(&msg2, payload);
        let packet = ReceivedPacket::new(nodes[to].transport_id, nodes[from].addr.clone(), msg3);
        nodes[to].node.handle_msg3(packet).await;
    }
}

/// The negotiation payload of a link handshake, declaring `rekey_of` when
/// given.
fn payload(rekey_of: Option<SessionIndex>) -> Vec<u8> {
    let p = NegotiationPayload::fmp(1, 1, NodeProfile::Full);
    match rekey_of {
        Some(idx) => p.with_rekey_of(idx).encode(),
        None => p.encode(),
    }
}

/// Every packet queued at `tn`, taken off its queue.
fn taken(tn: &mut TestNode) -> Vec<ReceivedPacket> {
    std::iter::from_fn(|| tn.packet_rx.try_recv().ok()).collect()
}

/// The handshake phase of `p`.
fn phase(p: &ReceivedPacket) -> Option<u8> {
    CommonPrefix::parse(&p.data).map(|c| c.phase)
}

/// The index node `at`'s peer `of` declares a rekey of their link by: the
/// index `of` receives the current session on.
fn declared(nodes: &[TestNode], at: usize, of: usize) -> SessionIndex {
    let peer = *nodes[of].node.node_addr();
    nodes[at]
        .node
        .get_peer(&peer)
        .unwrap()
        .their_index()
        .expect("the peer holds a session")
}

/// Check node `at` after a leg's exit: its allocator holds exactly the
/// leases its link machines hold, no leg is left, and the address of its
/// peer at `peer` names the peer's link.
fn exited(nodes: &[TestNode], at: usize, peer: usize, exit: &str) {
    let node = &nodes[at].node;
    audit(node, exit);
    assert!(node.pending_inbound.is_empty(), "{exit}: no leg is pending");
    assert!(
        node.peer_machines.values().all(|m| m.leg().is_none()),
        "{exit}: no leg machine is left"
    );
    let peer_addr = *nodes[peer].node.node_addr();
    let link = node.get_peer(&peer_addr).map(|p| p.link_id());
    assert_eq!(
        node.addr_to_link
            .get(&(nodes[at].transport_id, nodes[peer].addr.clone()))
            .copied(),
        link,
        "{exit}: the peer's address names the peer's link"
    );
}

/// Index node `observed`'s peer is dialed under, and the observed node, of a
/// linked pair whose observed node is the larger by address when `larger`.
fn order(nodes: &[TestNode], larger: bool) -> (usize, usize) {
    let zero_larger = nodes[0].node.node_addr() > nodes[1].node.node_addr();
    if zero_larger == larger {
        (1, 0)
    } else {
        (0, 1)
    }
}

/// Every exit of a leg releases its lease, or hands it on: a link setup's
/// promotion moves it to the link's machine, a declared rekey to the peer's
/// machine, a cross-connection whose inbound handshake wins to the moved
/// session, and every other exit (a mismatched declaration, a malformed
/// one, a negotiation failure, an ACL refusal, a msg3 from this node
/// itself, the silent-session back-off, a dampened restart, expiry, and a
/// cross-connection whose outbound handshake wins) releases it. After each,
/// the allocator holds exactly the leases the link machines hold, no leg is
/// left, and the peer's address names the peer's link. Run with the
/// observed node larger and smaller by address, so both sides of the
/// cross-connection run.
#[tokio::test]
async fn every_leg_exit_releases_its_lease() {
    for larger in [true, false] {
        let mut nodes = linked_pair(
            rekey_config(REKEY_AFTER_SECS),
            rekey_config(REKEY_AFTER_SECS),
        )
        .await;
        let (a, b) = order(&nodes, larger);
        let a_id = nodes[a].node.identity().clone();
        let a_epoch = nodes[a].node.startup_epoch();
        let b_id = nodes[b].node.identity().clone();
        let b_epoch = nodes[b].node.startup_epoch();
        exited(&nodes, b, a, "link setup's promotion");

        // A declared rekey of the session B holds goes to B's machine.
        let dial = HandDial::open(&mut nodes, a, b, &a_id, a_epoch, 0x1D00_0001).await;
        let rekey_of = declared(&nodes, a, b);
        dial.finish(&mut nodes, a, b, &payload(Some(rekey_of)))
            .await;
        let a_addr = *nodes[a].node.node_addr();
        assert!(
            nodes[b]
                .node
                .get_peer(&a_addr)
                .unwrap()
                .pending_new_session()
                .is_some(),
            "precondition ({larger}): B's machine holds the handed-over rekey"
        );
        exited(&nodes, b, a, "a declared rekey handed over");

        // A declaration naming no session B holds is answered with the
        // stored msg2 and released.
        let dial = HandDial::open(&mut nodes, a, b, &a_id, a_epoch, 0x1D00_0002).await;
        dial.finish(
            &mut nodes,
            a,
            b,
            &payload(Some(SessionIndex::new(0xDEAD_BEEF))),
        )
        .await;
        exited(&nodes, b, a, "a mismatched declaration");

        let malformed = NegotiationPayload::fmp(1, 1, NodeProfile::Full)
            .with_tlv(TLV_REKEY_OF, vec![1, 2, 3])
            .encode();
        let dial = HandDial::open(&mut nodes, a, b, &a_id, a_epoch, 0x1D00_0003).await;
        dial.finish(&mut nodes, a, b, &malformed).await;
        exited(&nodes, b, a, "a malformed declaration");

        let dial = HandDial::open(&mut nodes, a, b, &a_id, a_epoch, 0x1D00_0004).await;
        dial.finish(&mut nodes, a, b, &[0xff; 3]).await;
        exited(&nodes, b, a, "a negotiation failure");

        let stranger = Identity::generate();
        let dir = tempfile::tempdir().unwrap();
        nodes[b].node.peer_acl = crate::node::acl::PeerAclReloader::with_paths(
            dir.path().join("peers.allow"),
            dir.path().join("peers.deny"),
        );
        std::fs::write(
            dir.path().join("peers.deny"),
            format!("{}\n", stranger.npub()),
        )
        .unwrap();
        nodes[b].node.reload_peer_acl().await;
        let dial = HandDial::open(&mut nodes, a, b, &stranger, [3; 8], 0x1D00_0005).await;
        dial.finish(&mut nodes, a, b, &payload(None)).await;
        exited(&nodes, b, a, "an ACL refusal");

        let dial = HandDial::open(&mut nodes, a, b, &b_id, b_epoch, 0x1D00_0006).await;
        dial.finish(&mut nodes, a, b, &payload(None)).await;
        exited(&nodes, b, a, "a msg3 from this node itself");

        let silent = Identity::generate();
        let silent_addr = *crate::PeerIdentity::from_pubkey_full(silent.pubkey_full()).node_addr();
        for _ in 0..3 {
            let _ = nodes[b].node.silent_sessions.ended(
                silent_addr,
                Some([4; 8]),
                None,
                crate::time::mono_ms(),
            );
        }
        let dial = HandDial::open(&mut nodes, a, b, &silent, [4; 8], 0x1D00_0007).await;
        dial.finish(&mut nodes, a, b, &payload(None)).await;
        assert!(
            nodes[b].node.get_peer(&silent_addr).is_none(),
            "precondition ({larger}): the silent identity is refused"
        );
        exited(&nodes, b, a, "the silent-session back-off");

        let dial = HandDial::open(&mut nodes, a, b, &a_id, [5; 8], 0x1D00_0008).await;
        dial.finish(&mut nodes, a, b, &payload(None)).await;
        exited(&nodes, b, a, "a dampened restart");

        let _dial = HandDial::open(&mut nodes, a, b, &stranger, [3; 8], 0x1D00_0009).await;
        let timeout_ms = nodes[b]
            .node
            .config()
            .node
            .rate_limit
            .handshake_timeout_secs
            * 1000;
        nodes[b]
            .node
            .check_timeouts_at(Node::now_ms() + timeout_ms + 1_000)
            .await;
        exited(&nodes, b, a, "expiry");

        // A fresh dial crossing the link B holds with the same peer: B's
        // inbound handshake wins when B is the larger.
        let dial = HandDial::open(&mut nodes, a, b, &a_id, a_epoch, 0x1D00_000A).await;
        let before = nodes[b].node.get_peer(&a_addr).unwrap().our_index();
        dial.finish(&mut nodes, a, b, &payload(None)).await;
        let after = nodes[b].node.get_peer(&a_addr).unwrap().our_index();
        assert_eq!(
            after != before,
            larger,
            "precondition: B moves to the crossing dial's session exactly when its inbound wins"
        );
        exited(&nodes, b, a, "a cross-connection");

        cleanup_nodes(&mut nodes).await;
    }
}

/// A msg3 from this node's own key, which a node reaching itself through a
/// second address or a reflected msg1 produces, ends its leg with the lease
/// on the leg's index released.
#[tokio::test]
async fn self_connect_exit_releases_its_lease() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let b_id = nodes[1].node.identity().clone();
    let b_epoch = nodes[1].node.startup_epoch();
    let held = nodes[1].node.index_allocator.count();
    let dial = HandDial::open(&mut nodes, 0, 1, &b_id, b_epoch, 0x1D00_0101).await;
    assert_eq!(
        nodes[1].node.index_allocator.count(),
        held + 1,
        "precondition: the leg leased an index"
    );
    dial.finish(&mut nodes, 0, 1, &payload(None)).await;
    assert_eq!(
        nodes[1].node.index_allocator.count(),
        held,
        "the self exit releases the leg's lease"
    );
    exited(&nodes, 1, 0, "a msg3 from this node itself");
    cleanup_nodes(&mut nodes).await;
}

/// A msg3 whose negotiation payload does not decode ends its leg with the
/// lease on the leg's index released. The arm sits ahead of the ACL gate,
/// so any key able to complete a msg3 reaches it.
#[tokio::test]
async fn negotiation_reject_releases_its_lease() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let stranger = Identity::generate();
    let held = nodes[1].node.index_allocator.count();
    let dial = HandDial::open(&mut nodes, 0, 1, &stranger, [6; 8], 0x1D00_0201).await;
    dial.finish(&mut nodes, 0, 1, &[0xff; 3]).await;
    assert_eq!(
        nodes[1].node.index_allocator.count(),
        held,
        "the negotiation reject releases the leg's lease"
    );
    exited(&nodes, 1, 0, "a negotiation failure");
    cleanup_nodes(&mut nodes).await;
}

/// A msg3 that does not read leaves the leg as it was, its pending entry,
/// its machine and the lease on its index, so the genuine msg3 still
/// completes it: the receiver index it names travels in cleartext in msg2's
/// header, so anyone on the path can send one first.
#[tokio::test]
async fn unreadable_final_keeps_the_leg() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let a_id = nodes[0].node.identity().clone();
    let a_epoch = nodes[0].node.startup_epoch();
    let a_addr = *nodes[0].node.node_addr();
    let dial = HandDial::open(&mut nodes, 0, 1, &a_id, a_epoch, 0x1D00_0301).await;
    let msg2 = dial.msg2(&mut nodes, 0);
    let leg_index = Msg2Header::parse(&msg2).unwrap().sender_idx;
    let genuine = dial.msg3(&msg2, &payload(Some(declared(&nodes, 0, 1))));

    let mut forged = genuine.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    let packet = ReceivedPacket::new(nodes[1].transport_id, nodes[0].addr.clone(), forged);
    nodes[1].node.handle_msg3(packet).await;
    let key = (nodes[1].transport_id, leg_index.as_u32());
    assert!(
        nodes[1].node.pending_inbound.contains_key(&key),
        "an unreadable msg3 keeps the leg's pending entry"
    );
    assert!(
        nodes[1].node.index_allocator.is_allocated(leg_index),
        "and the lease on its index"
    );
    audit(&nodes[1].node, "an unreadable msg3");

    let packet = ReceivedPacket::new(nodes[1].transport_id, nodes[0].addr.clone(), genuine);
    nodes[1].node.handle_msg3(packet).await;
    assert_eq!(
        nodes[1].node.get_peer(&a_addr).unwrap().pending_our_index(),
        Some(leg_index),
        "the genuine msg3 completes the kept leg, as a rekey under its index"
    );
    exited(&nodes, 1, 0, "the genuine msg3 after an unreadable one");
    cleanup_nodes(&mut nodes).await;
}

/// A msg1 from an address whose leg answered a different msg1 gets a leg of
/// its own, and the first leg still completes on its msg3: XX msg2 is bound
/// to the initiator's ephemeral, so one leg cannot answer both, and a new
/// msg1 must not discard a genuine leg awaiting its msg3.
#[tokio::test]
async fn different_msg1_gets_its_own_leg() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let a_id = nodes[0].node.identity().clone();
    let a_epoch = nodes[0].node.startup_epoch();
    let a_addr = *nodes[0].node.node_addr();
    let first = HandDial::open(&mut nodes, 0, 1, &a_id, a_epoch, 0x1D00_0401).await;
    let msg2 = first.msg2(&mut nodes, 0);
    let second = HandDial::open(&mut nodes, 0, 1, &a_id, a_epoch, 0x1D00_0402).await;
    assert_eq!(
        nodes[1].node.pending_inbound.len(),
        2,
        "the second msg1 gets a leg of its own"
    );
    let second_msg2 = second.msg2(&mut nodes, 0);
    assert_ne!(
        Msg2Header::parse(&second_msg2).unwrap().sender_idx,
        Msg2Header::parse(&msg2).unwrap().sender_idx,
        "each leg answers under its own index"
    );

    let msg3 = first.msg3(&msg2, &payload(Some(declared(&nodes, 0, 1))));
    let packet = ReceivedPacket::new(nodes[1].transport_id, nodes[0].addr.clone(), msg3);
    nodes[1].node.handle_msg3(packet).await;
    assert_eq!(
        nodes[1].node.get_peer(&a_addr).unwrap().pending_our_index(),
        Some(Msg2Header::parse(&msg2).unwrap().sender_idx),
        "the first leg completes on its msg3"
    );
    audit(&nodes[1].node, "two legs from one address");
    cleanup_nodes(&mut nodes).await;
}

/// A rekey this node gives up releases its attempt's index: its msg1 is
/// lost every time, and at the attempt's end the index is unbound and goes
/// back to the allocator.
#[tokio::test]
async fn abandon_releases_the_attempt_index() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let b_addr = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    nodes[0].node.poll_link_rekeys().await;
    let attempt = nodes[0]
        .node
        .get_peer(&b_addr)
        .unwrap()
        .rekey_our_index()
        .expect("precondition: node 0 started a rekey");
    assert!(nodes[0].node.index_allocator.is_allocated(attempt));
    for _ in 0..40 {
        let _ = taken(&mut nodes[1]);
        crate::time::advance(Duration::from_secs(1));
        nodes[0].node.poll_link_rekeys().await;
        if !nodes[0].node.get_peer(&b_addr).unwrap().rekey_in_progress() {
            break;
        }
    }
    assert!(
        !nodes[0].node.get_peer(&b_addr).unwrap().rekey_in_progress(),
        "precondition: the unanswered rekey was given up"
    );
    assert!(
        !nodes[0].node.index_allocator.is_allocated(attempt),
        "the abandoned rekey's index goes back to the allocator"
    );
    assert!(
        !nodes[0]
            .node
            .peers_by_index
            .contains_key(&(nodes[0].transport_id, attempt.as_u32())),
        "and is unbound"
    );
    audit(&nodes[0].node, "an abandoned rekey");
    cleanup_nodes(&mut nodes).await;
}

/// Through rekeys answered, abandoned and handed over, the indices the
/// allocator holds are exactly the leases the link machines and legs hold,
/// at both ends after every step.
#[tokio::test]
async fn leases_outstanding_equal_leases_held() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let addrs = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    for round in 0..3 {
        let (from, to) = (round % 2, 1 - round % 2);
        age_link(&mut nodes, 0, 1, trigger_age());
        nodes[from].node.poll_link_rekeys().await;
        if round == 1 {
            // This round's msg1 and its resends are all lost until the
            // attempt ends.
            while nodes[from]
                .node
                .get_peer(&addrs[to])
                .unwrap()
                .rekey_in_progress()
            {
                let _ = taken(&mut nodes[to]);
                crate::time::advance(Duration::from_secs(1));
                nodes[from].node.poll_link_rekeys().await;
            }
        } else {
            deliver(&mut nodes[to]).await;
            audit(&nodes[to].node, "a leg answering the msg1");
            deliver(&mut nodes[from]).await;
            deliver(&mut nodes[to]).await;
            pass_cutover_delay();
            nodes[from].node.poll_link_rekeys().await;
            pump(&mut nodes).await;
        }
        for (i, tn) in nodes.iter().enumerate() {
            audit(&tn.node, &format!("round {round} at node {i}"));
        }
    }
    cleanup_nodes(&mut nodes).await;
}

/// A rekey this node starts on its message counter, against a peer whose
/// session is young, converges: the peer reads no session age, only the
/// rekey the msg3 declares, so it takes the handshake as a rekey rather
/// than a dial crossing its link, and both ends cut over to one session.
/// Run with the initiator smaller and larger by address, since a crossing
/// misread splits the pair in only one order.
#[tokio::test]
async fn count_triggered_rekey_on_a_young_session_converges() {
    for initiator_smaller in [true, false] {
        let mut cfg = rekey_config(3600);
        cfg.node.rekey.after_messages = 1;
        let mut nodes = linked_pair(cfg.clone(), cfg).await;
        let zero_smaller = nodes[0].node.node_addr() < nodes[1].node.node_addr();
        let (i, r) = if zero_smaller == initiator_smaller {
            (0, 1)
        } else {
            (1, 0)
        };
        let (i_addr, r_addr) = (*nodes[i].node.node_addr(), *nodes[r].node.node_addr());
        // Only the initiator is aged, past the floors below which its machine
        // starts nothing; one frame crosses its message trigger.
        nodes[i]
            .node
            .get_peer_mut(&r_addr)
            .unwrap()
            .test_backdate_session_established(Duration::from_secs(32));
        heartbeat(&mut nodes[i], &r_addr).await;
        deliver(&mut nodes[r]).await;
        nodes[i].node.poll_link_rekeys().await;
        assert!(
            nodes[i].node.get_peer(&r_addr).unwrap().rekey_in_progress(),
            "precondition ({initiator_smaller}): the message trigger started a rekey"
        );
        deliver(&mut nodes[r]).await;
        deliver(&mut nodes[i]).await;
        deliver(&mut nodes[r]).await;
        pass_cutover_delay();
        nodes[i].node.poll_link_rekeys().await;
        pump(&mut nodes).await;

        let tag = |at: usize, of: &NodeAddr| {
            session_tag(
                nodes[at]
                    .node
                    .get_peer(of)
                    .unwrap()
                    .noise_session()
                    .unwrap(),
            )
        };
        assert_eq!(
            tag(i, &r_addr),
            tag(r, &i_addr),
            "both ends hold one session (initiator smaller: {initiator_smaller})"
        );
        for (from, to, to_addr, from_addr) in [(i, r, r_addr, i_addr), (r, i, i_addr, r_addr)] {
            heartbeat(&mut nodes[from], &to_addr).await;
            deliver(&mut nodes[to]).await;
            assert_eq!(
                failures(&nodes[to], &from_addr),
                0,
                "frames from node {from} decrypt at node {to} (initiator smaller: {initiator_smaller})"
            );
        }
        cleanup_nodes(&mut nodes).await;
    }
}

/// A rekey's msg3 that is lost is resent from the initiator's ladder while
/// its cutover waits, and the copy completes the responder's leg; both ends
/// then hold the new session.
#[tokio::test]
async fn lost_xx_final_is_resent_until_heard() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let (a_addr, b_addr) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    age_link(&mut nodes, 0, 1, trigger_age());
    nodes[0].node.poll_link_rekeys().await;
    deliver(&mut nodes[1]).await;
    deliver(&mut nodes[0]).await;
    let lost = taken(&mut nodes[1]);
    assert!(
        lost.iter().any(|p| phase(p) == Some(PHASE_MSG3)),
        "precondition: the first msg3 was sent, and is lost"
    );
    assert!(
        nodes[1]
            .node
            .get_peer(&a_addr)
            .unwrap()
            .pending_new_session()
            .is_none(),
        "precondition: the responder holds no pending without the msg3"
    );

    crate::time::advance(Duration::from_secs(1));
    nodes[0].node.poll_link_rekeys().await;
    let resent = taken(&mut nodes[1]);
    assert!(
        resent.iter().any(|p| phase(p) == Some(PHASE_MSG3)),
        "the msg3 is resent at the ladder's first rung"
    );
    for p in resent {
        nodes[1].node.process_packet(p).await;
    }
    assert!(
        nodes[1]
            .node
            .get_peer(&a_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "the resent msg3 completes the responder's leg"
    );

    pass_cutover_delay();
    nodes[0].node.poll_link_rekeys().await;
    pump(&mut nodes).await;
    assert_eq!(
        session_tag(
            nodes[0]
                .node
                .get_peer(&b_addr)
                .unwrap()
                .noise_session()
                .unwrap()
        ),
        session_tag(
            nodes[1]
                .node
                .get_peer(&a_addr)
                .unwrap()
                .noise_session()
                .unwrap()
        ),
        "both ends hold the new session"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Copies of a rekey's msg3 that reach the responder after its leg handed
/// the first to the peer's machine change nothing and are not counted
/// against the peer.
#[tokio::test]
async fn a_rekey_msg3_copy_after_the_hand_over_is_dropped_uncounted() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let a_addr = *nodes[0].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    nodes[0].node.poll_link_rekeys().await;
    deliver(&mut nodes[1]).await;
    deliver(&mut nodes[0]).await;
    let msg3: Vec<ReceivedPacket> = taken(&mut nodes[1]);
    let copy = msg3
        .iter()
        .find(|p| phase(p) == Some(PHASE_MSG3))
        .expect("precondition: the msg3")
        .data
        .clone();
    for p in msg3 {
        nodes[1].node.process_packet(p).await;
    }
    let pending = nodes[1].node.get_peer(&a_addr).unwrap().pending_our_index();
    assert!(
        pending.is_some(),
        "precondition: the leg handed the rekey over"
    );
    let unknown = nodes[1].node.stats().handshake.unknown_connection;
    let packet = ReceivedPacket::new(nodes[1].transport_id, nodes[0].addr.clone(), copy);
    nodes[1].node.handle_msg3(packet).await;
    assert_eq!(
        nodes[1].node.get_peer(&a_addr).unwrap().pending_our_index(),
        pending,
        "the copy changes nothing"
    );
    assert_eq!(
        nodes[1].node.stats().handshake.unknown_connection,
        unknown,
        "the copy is not counted as an unknown connection"
    );
    audit(&nodes[1].node, "a msg3 copy after the hand-over");
    cleanup_nodes(&mut nodes).await;
}

/// A frame the peer sends on the previous session after this node's cutover
/// does not stop the resends of the msg3 the peer has not heard: only a
/// frame under the new session shows the peer holds it. Inline and through
/// the decrypt worker's report alike.
#[tokio::test]
async fn a_previous_session_frame_does_not_stop_the_msg3_resends() {
    for through_worker in [false, cfg!(unix)] {
        let mut nodes = linked_pair(
            rekey_config(REKEY_AFTER_SECS),
            rekey_config(REKEY_AFTER_SECS),
        )
        .await;
        let (a_addr, b_addr) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
        age_link(&mut nodes, 0, 1, trigger_age());
        nodes[0].node.poll_link_rekeys().await;
        deliver(&mut nodes[1]).await;
        deliver(&mut nodes[0]).await;
        let _lost = taken(&mut nodes[1]);
        pass_cutover_delay();
        nodes[0].node.poll_link_rekeys().await;
        let _lost = taken(&mut nodes[1]);
        assert!(
            nodes[0].node.get_peer(&b_addr).unwrap().is_draining(),
            "precondition: node 0 cut over with its msg3 unheard"
        );

        // Node 1, which never got the msg3, sends on the old session.
        heartbeat(&mut nodes[1], &a_addr).await;
        if through_worker {
            #[cfg(unix)]
            {
                use crate::node::decrypt_worker::DecryptFallback;
                let frame = taken(&mut nodes[0]);
                assert_eq!(frame.len(), 1, "precondition: one frame");
                let previous = nodes[0]
                    .node
                    .get_peer(&b_addr)
                    .unwrap()
                    .previous_our_index()
                    .unwrap();
                let mut data = 0u32.to_le_bytes().to_vec();
                data.push(crate::proto::link::LinkMessageType::Heartbeat.to_byte());
                let bounce = DecryptFallback {
                    source_node_addr: b_addr,
                    transport_id: nodes[0].transport_id,
                    remote_addr: nodes[1].addr.clone(),
                    timestamp_ms: Node::now_ms(),
                    packet_len: data.len() + 32,
                    receiver_idx: previous.as_u32(),
                    fmp_counter: 1_000,
                    fmp_flags: 0,
                    fmp_plaintext_len: data.len(),
                    packet_data: data,
                    fmp_plaintext_offset: 0,
                };
                nodes[0].node.process_decrypt_fallback(bounce).await;
            }
        } else {
            deliver(&mut nodes[0]).await;
        }

        crate::time::advance(Duration::from_secs(2));
        nodes[0].node.poll_link_rekeys().await;
        assert!(
            taken(&mut nodes[1])
                .iter()
                .any(|p| phase(p) == Some(PHASE_MSG3)),
            "the msg3 is still resent after a previous-session frame (through a worker: {through_worker})"
        );
        cleanup_nodes(&mut nodes).await;
    }
}

/// A rekey msg2 that is lost is drawn again by the initiator's msg1
/// resend: the leg answers the identical msg1 with its stored msg2, and the
/// rekey completes at both ends on one session.
#[tokio::test]
async fn dropped_rekey_msg2_does_not_split_the_link() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let (a_addr, b_addr) = (*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    age_link(&mut nodes, 0, 1, trigger_age());
    nodes[0].node.poll_link_rekeys().await;
    deliver(&mut nodes[1]).await;
    assert!(
        taken(&mut nodes[0])
            .iter()
            .any(|p| phase(p) == Some(PHASE_MSG2)),
        "precondition: the msg2 was sent, and is lost"
    );
    crate::time::advance(Duration::from_secs(1));
    nodes[0].node.poll_link_rekeys().await;
    let resent = taken(&mut nodes[1]);
    assert!(
        resent.iter().any(|p| phase(p) == Some(PHASE_MSG1)),
        "precondition: the msg1 is resent"
    );
    for p in resent {
        nodes[1].node.process_packet(p).await;
    }
    assert_eq!(
        nodes[1].node.pending_inbound.len(),
        1,
        "the resent msg1 draws the leg's stored msg2, not a new leg"
    );
    deliver(&mut nodes[0]).await;
    deliver(&mut nodes[1]).await;
    pass_cutover_delay();
    nodes[0].node.poll_link_rekeys().await;
    pump(&mut nodes).await;
    assert_eq!(
        session_tag(
            nodes[0]
                .node
                .get_peer(&b_addr)
                .unwrap()
                .noise_session()
                .unwrap()
        ),
        session_tag(
            nodes[1]
                .node
                .get_peer(&a_addr)
                .unwrap()
                .noise_session()
                .unwrap()
        ),
        "both ends hold the new session"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Both ends start a link rekey at once and each completes its own: each
/// receives the other's msg3 while holding its own pending. The two
/// completions resolve to the smaller node's, so both ends converge on the
/// session the smaller node initiated, and frames then deliver both ways.
#[tokio::test]
async fn crossed_three_message_rekeys_both_holding_pending_converge_on_the_smaller_initiators_epoch()
 {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let addrs = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    let (s, l) = if addrs[0] < addrs[1] { (0, 1) } else { (1, 0) };
    age_link(&mut nodes, 0, 1, trigger_age());
    nodes[0].node.poll_link_rekeys().await;
    nodes[1].node.poll_link_rekeys().await;
    // Each leg answers the other's msg1.
    deliver(&mut nodes[0]).await;
    deliver(&mut nodes[1]).await;
    // Each completes its own on the other's msg2 and holds its pending.
    deliver(&mut nodes[0]).await;
    deliver(&mut nodes[1]).await;
    for (x, y) in [(0, 1), (1, 0)] {
        assert!(
            nodes[x]
                .node
                .get_peer(&addrs[y])
                .unwrap()
                .pending_new_session()
                .is_some(),
            "precondition: node {x} holds its own pending"
        );
    }
    let smaller_epoch = session_tag(
        nodes[s]
            .node
            .get_peer(&addrs[l])
            .unwrap()
            .pending_new_session()
            .unwrap(),
    );
    // Each leg hands the other's msg3 to its machine.
    deliver(&mut nodes[0]).await;
    deliver(&mut nodes[1]).await;
    pass_cutover_delay();
    nodes[0].node.poll_link_rekeys().await;
    nodes[1].node.poll_link_rekeys().await;
    pump(&mut nodes).await;

    for (x, y) in [(s, l), (l, s)] {
        assert_eq!(
            session_tag(
                nodes[x]
                    .node
                    .get_peer(&addrs[y])
                    .unwrap()
                    .noise_session()
                    .unwrap()
            ),
            smaller_epoch,
            "node {x} holds the session the smaller node initiated"
        );
    }
    for (from, to) in [(0, 1), (1, 0)] {
        heartbeat(&mut nodes[from], &addrs[to]).await;
        deliver(&mut nodes[to]).await;
        assert_eq!(
            failures(&nodes[to], &addrs[from]),
            0,
            "frames from node {from} decrypt at node {to}"
        );
    }
    for tn in nodes.iter() {
        audit(&tn.node, "the crossed rekeys");
    }
    cleanup_nodes(&mut nodes).await;
}

/// This node's rekey msg3 is lost and it cuts over after the delay; inside
/// that window the peer, still on the session this node now drains, starts
/// its own rekey, which declares that session by this node's previous index.
/// The leg hands the peer's completion to this node's machine, which settles
/// the crossing; then this node's resent msg3 reaches the peer. Both ends
/// end on one session and frames deliver both ways, in either address order.
#[tokio::test]
async fn a_rekey_crossing_a_lost_final_after_the_delayed_cutover_converges_on_one_epoch() {
    for first_smaller in [true, false] {
        let mut nodes = linked_pair(
            rekey_config(REKEY_AFTER_SECS),
            rekey_config(REKEY_AFTER_SECS),
        )
        .await;
        let zero_smaller = nodes[0].node.node_addr() < nodes[1].node.node_addr();
        let (a, b) = if zero_smaller == first_smaller {
            (0, 1)
        } else {
            (1, 0)
        };
        let (a_addr, b_addr) = (*nodes[a].node.node_addr(), *nodes[b].node.node_addr());
        age_link(&mut nodes, 0, 1, trigger_age());

        // A's rekey: its msg3, and every resend, lost; A cuts over after the
        // delay.
        nodes[a].node.poll_link_rekeys().await;
        deliver(&mut nodes[b]).await;
        deliver(&mut nodes[a]).await;
        let mut held_msg3 = taken(&mut nodes[b])
            .into_iter()
            .filter(|p| phase(p) == Some(PHASE_MSG3))
            .collect::<Vec<_>>();
        pass_cutover_delay();
        nodes[a].node.poll_link_rekeys().await;
        held_msg3.extend(
            taken(&mut nodes[b])
                .into_iter()
                .filter(|p| phase(p) == Some(PHASE_MSG3)),
        );
        assert!(
            nodes[a].node.get_peer(&b_addr).unwrap().is_draining(),
            "precondition ({first_smaller}): A cut over with its msg3 unheard"
        );

        // B's own rekey, declaring the session A now drains.
        nodes[b].node.poll_link_rekeys().await;
        assert!(
            nodes[b].node.get_peer(&a_addr).unwrap().rekey_in_progress(),
            "precondition ({first_smaller}): B started its own rekey"
        );
        deliver(&mut nodes[a]).await;
        deliver(&mut nodes[b]).await;
        deliver(&mut nodes[a]).await;

        // A's resent msg3 reaches B.
        let resend = held_msg3.pop().expect("precondition: a msg3 was sent");
        nodes[b].node.handle_msg3(resend).await;
        for _ in 0..3 {
            pass_cutover_delay();
            nodes[a].node.poll_link_rekeys().await;
            nodes[b].node.poll_link_rekeys().await;
            pump(&mut nodes).await;
        }

        assert_eq!(
            session_tag(
                nodes[a]
                    .node
                    .get_peer(&b_addr)
                    .unwrap()
                    .noise_session()
                    .unwrap()
            ),
            session_tag(
                nodes[b]
                    .node
                    .get_peer(&a_addr)
                    .unwrap()
                    .noise_session()
                    .unwrap()
            ),
            "both ends hold one session (first smaller: {first_smaller})"
        );
        for (from, to, to_addr, from_addr) in [(a, b, b_addr, a_addr), (b, a, a_addr, b_addr)] {
            heartbeat(&mut nodes[from], &to_addr).await;
            deliver(&mut nodes[to]).await;
            assert_eq!(
                failures(&nodes[to], &from_addr),
                0,
                "frames from node {from} decrypt at node {to} (first smaller: {first_smaller})"
            );
        }
        cleanup_nodes(&mut nodes).await;
    }
}
