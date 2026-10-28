//! A peer restart that a msg2 reveals: the msg2 of this node's own link
//! rekey, or of a dial it made to an identity it already holds.
//!
//! A restart means the same thing however it is learned. The process that
//! held the session on record has gone, so what this node held about it is
//! stale: the end-to-end session, the spanning-tree declaration and the
//! filter it last accepted, and the clamp entry the session tightened. Each
//! test drives a restart over loopback and asserts that both ends end up on
//! one session with that state reset and announced again.

use super::*;
use crate::node::tests::rekey_parity::{
    cutover, deliver, deliver_held, failures, heartbeat, linked_pair, pump, rekey_config,
    reveal_restart, stale_session,
};
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, initiate_handshake, restarted_node,
};

/// Rekey interval for both ends of the pairs below.
const REKEY_AFTER_SECS: u64 = 60;

/// Exchange filter announces both ways, so each end holds the other's.
async fn exchange_filters(nodes: &mut [TestNode]) {
    for tn in nodes.iter_mut() {
        tn.node.check_bloom_state().await;
    }
    pump(nodes).await;
}

/// Give `node` a clamp entry for `peer` tighter than its link seed, as a
/// path MTU notification inside a session with `peer` writes. Returns the
/// seed.
fn tighten_clamp(node: &mut Node, peer: &NodeAddr) -> Option<u16> {
    let fips = crate::Ipv6Address::from_node_addr(peer);
    let seed = node.path_mtu_lookup_get(&fips);
    node.path_mtu_lookup_insert(fips, seed.map_or(1200, |s| s - 100));
    seed
}

/// `node`'s clamp entry for `peer`.
fn clamp(node: &Node, peer: &NodeAddr) -> Option<u16> {
    node.path_mtu_lookup_get(&crate::Ipv6Address::from_node_addr(peer))
}

/// Our rekey msg2 reveals that B restarted. At the cutover A resets what it
/// held for B's previous run (its tree declaration, its filter, the
/// end-to-end session and the clamp entry that session tightened) and
/// announces its tree and filter again under the new session, which B
/// decrypts; B's own announces, whose sequence numbers began again, are
/// then accepted.
#[tokio::test]
async fn restart_seen_in_a_rekey_msg2_resets_tree_bloom_and_sessions() {
    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let a_addr = *nodes[0].node.node_addr();
    let b_addr = *nodes[1].node.node_addr();
    exchange_filters(&mut nodes).await;
    {
        let a = &nodes[0].node;
        assert!(
            a.tree_state().peer_declaration(&b_addr).is_some()
                && a.get_peer(&b_addr).unwrap().filter_sequence() > 0,
            "precondition: A holds B's tree declaration and filter"
        );
    }
    stale_session(&mut nodes[0].node, b_addr);
    let seed = tighten_clamp(&mut nodes[0].node, &b_addr);
    // A announced its tree to B at the link's setup; lift the rate limit
    // so the restart's announce goes at once.
    nodes[0]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .set_last_tree_announce_sent_ms(0);

    let mut r = reveal_restart(nodes).await;
    cutover(&mut r.nodes[0], &b_addr).await;

    {
        let a = &r.nodes[0].node;
        assert!(
            a.tree_state().peer_declaration(&b_addr).is_none(),
            "the cutover a revealed restart caused drops B's previous tree declaration"
        );
        assert_eq!(
            a.get_peer(&b_addr).unwrap().filter_sequence(),
            0,
            "the cutover a revealed restart caused drops B's previous filter"
        );
        assert!(
            a.bloom_state().last_sent_filter(&b_addr).is_none(),
            "the cutover a revealed restart caused forgets the filter A last sent B's previous run"
        );
        assert!(
            a.get_session(&b_addr).is_none(),
            "the cutover a revealed restart caused ends the end-to-end session B lost"
        );
        assert_eq!(
            clamp(a, &b_addr),
            seed,
            "the clamp entry the ended session tightened goes with it, back to the link seed"
        );
    }

    // A's announces reach B under the new session, its filter once the
    // debounce since its last announce to B has passed.
    crate::time::advance(Duration::from_secs(1));
    r.nodes[0].node.check_bloom_state().await;
    deliver(&mut r.nodes[1]).await;
    {
        let b = &r.nodes[1].node;
        let peer = b.get_peer(&a_addr).expect("B holds A");
        assert_eq!(
            peer.consecutive_decrypt_failures(),
            0,
            "B decrypts everything A sent after its cutover"
        );
        assert!(
            b.tree_state().peer_declaration(&a_addr).is_some(),
            "B accepts the tree announce A sent again under the new session"
        );
        assert!(
            peer.filter_sequence() > 0,
            "B accepts the filter A announced again under the new session"
        );
    }

    // B's announces, sequenced from its restart, are accepted at A.
    let (tree_stale, bloom_stale) = {
        let m = r.nodes[0].node.metrics();
        (m.tree.stale.get(), m.bloom.stale.get())
    };
    deliver_held(&mut r).await;
    r.nodes[1].node.check_bloom_state().await;
    deliver(&mut r.nodes[0]).await;
    let a = &r.nodes[0].node;
    assert_eq!(
        (a.metrics().tree.stale.get(), a.metrics().bloom.stale.get()),
        (tree_stale, bloom_stale),
        "A refuses none of the restarted B's tree or filter announces as stale"
    );
    assert!(
        a.tree_state().peer_declaration(&b_addr).is_some()
            && a.get_peer(&b_addr).unwrap().filter_sequence() > 0,
        "A holds the restarted B's tree declaration and filter"
    );

    cleanup_nodes(&mut r.nodes).await;
}

/// A restart our rekey msg2 reveals ends the session A was still setting up
/// to B, but keeps the TUN packet held behind it, unanswered: B is back, so
/// the next session to it sends the packet, where an answer would fail a
/// connect that the restarted peer could take.
#[tokio::test]
async fn a_restart_seen_in_a_rekey_msg2_keeps_the_tun_packets_held_behind_the_session_it_ends() {
    use crate::node::tests::discovery::{drain_tun, install_tun_channel, tun_packet};

    let mut nodes = linked_pair(
        rekey_config(REKEY_AFTER_SECS),
        rekey_config(REKEY_AFTER_SECS),
    )
    .await;
    let b_addr = *nodes[1].node.node_addr();
    let b_identity = nodes[1].node.identity().clone();
    let rx = install_tun_channel(&mut nodes[0].node);
    let entry = crate::node::session::SessionEntry::opened_for_test(
        &b_identity.pubkey_full(),
        nodes[0].node.identity().keypair(),
        crate::node::session::session_at(1_000),
    );
    nodes[0].node.sessions.insert(b_addr, entry);
    let packet = tun_packet(&nodes[0].node, &b_addr);
    nodes[0].node.test_hold(
        b_addr,
        crate::ipv6tun::link::PeerKey::from_xonly(&b_identity.pubkey()),
        packet,
    );

    let mut r = reveal_restart(nodes).await;
    cutover(&mut r.nodes[0], &b_addr).await;

    let a = &r.nodes[0].node;
    assert!(
        a.get_session(&b_addr).is_none(),
        "precondition: the revealed restart ended the session in setup"
    );
    let answers = drain_tun(&rx);
    assert!(
        answers.is_empty(),
        "a restarted peer is back, so its held packets must not be answered as \
         unreachable: {answers:?}"
    );
    assert_eq!(
        a.pending_tun_total_packets(),
        1,
        "the packet held behind the ended session must stay held for the next session"
    );

    cleanup_nodes(&mut r.nodes).await;
}

/// This node dials an identity it already holds, and the msg2 carries a
/// startup epoch other than the one on record: the peer restarted, so the
/// two handshakes are no cross-connection. In either address order the
/// dialer tears down the stale peering, with its end-to-end session and the
/// clamp entry it tightened, and installs the peer from its own handshake,
/// which the restarted peer holds too, so frames each way authenticate.
#[tokio::test]
async fn outbound_completion_with_a_changed_epoch_replaces_the_machine() {
    for dialer_smaller in [true, false] {
        let mut nodes = linked_pair(
            rekey_config(REKEY_AFTER_SECS),
            rekey_config(REKEY_AFTER_SECS),
        )
        .await;
        let zero_smaller = nodes[0].node.node_addr() < nodes[1].node.node_addr();
        let (d, r) = if zero_smaller == dialer_smaller {
            (0, 1)
        } else {
            (1, 0)
        };
        let d_addr = *nodes[d].node.node_addr();
        let r_addr = *nodes[r].node.node_addr();
        let old_link = nodes[d].node.get_peer(&r_addr).unwrap().link_id();
        stale_session(&mut nodes[d].node, r_addr);
        let seed = tighten_clamp(&mut nodes[d].node, &r_addr);

        let restarted = restarted_node(&nodes[r], rekey_config(REKEY_AFTER_SECS));
        drop(std::mem::replace(&mut nodes[r], restarted));
        let epoch = nodes[r].node.startup_epoch();
        initiate_handshake(&mut nodes, d, r).await;
        deliver(&mut nodes[r]).await;
        assert!(
            nodes[r].node.get_peer(&d_addr).is_some(),
            "precondition ({dialer_smaller}): the restarted node promoted the dial as a fresh link"
        );
        deliver(&mut nodes[d]).await;

        {
            let dn = &nodes[d].node;
            let peer = dn.get_peer(&r_addr).expect("the dialer holds the peer");
            assert_ne!(
                peer.link_id(),
                old_link,
                "the dialer installs the peer from its own dial (dialer smaller: {dialer_smaller})"
            );
            assert_eq!(
                peer.remote_epoch(),
                Some(epoch),
                "the dialer records the restarted peer's epoch (dialer smaller: {dialer_smaller})"
            );
            assert!(
                dn.get_session(&r_addr).is_none(),
                "the dialer ends the end-to-end session the restarted peer lost (dialer smaller: {dialer_smaller})"
            );
            assert_eq!(
                clamp(dn, &r_addr),
                seed,
                "the clamp entry the ended session tightened goes with it (dialer smaller: {dialer_smaller})"
            );
        }

        // Both ends hold the session of the dial: the dialer's frames
        // authenticate at the restarted node and its frames at the dialer.
        heartbeat(&mut nodes[d], &r_addr).await;
        deliver(&mut nodes[r]).await;
        assert!(
            nodes[r]
                .node
                .get_peer(&d_addr)
                .is_some_and(|p| p.is_heard()),
            "the restarted node hears the dialer under the dial's session (dialer smaller: {dialer_smaller})"
        );
        heartbeat(&mut nodes[r], &d_addr).await;
        deliver(&mut nodes[d]).await;
        assert_eq!(
            failures(&nodes[d], &r_addr),
            0,
            "the dialer decrypts the restarted node's frames (dialer smaller: {dialer_smaller})"
        );

        cleanup_nodes(&mut nodes).await;
    }
}
