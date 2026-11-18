//! A peer whose first packet from a new address is its timed rekey msg1.
//!
//! B follows a peer's frames to a new address, not its msg1s, so a rekey
//! msg1 that is the first packet A sends after its address changes reaches
//! B off the established link and is answered as a redial. A keeps its
//! link: it adopts B's msg2 as the answer to its own rekey and cuts over to
//! that session, while B replaces its peering with the redial's leg at A's
//! first frame under it. Both ends must come out holding one session, with
//! B still holding A's tree declaration and filter and its own parent, and
//! A re-announcing nothing.
//!
//! The pair is the one of `roam_redial`. A's rekey is brought due by
//! backdating its session, so its msg1 goes out from its new address at
//! the step its address changes, before any heartbeat from there.

use super::paths::{beacon, loopback};
use super::rekey_parity::trigger_age;
use super::roam_gates::e2e;
use super::roam_redial::{Multipath, OldAddr, Pair, since};
use super::spanning_tree::{add_loopback_alias, cleanup_nodes, loopback_tap};

/// A's address changes on a link 60 s old with its rekey due, so its rekey
/// msg1 is its first packet from the new address; the pair then runs 20 s.
/// A, the smaller node, is B's parent, so B keeping A's declaration keeps
/// its own parent too.
async fn rekey_from_an_unseen_address(mp: Multipath, workers: bool) {
    rekey_from(mp, workers, false).await;
}

/// [`rekey_from_an_unseen_address`], from an address B holds as a path of
/// A's it is still probing when `probing`: B heard a beacon of A there
/// before A moved to it.
async fn rekey_from(mp: Multipath, workers: bool, probing: bool) {
    let mut pair = Pair::new(mp, true).await;
    #[cfg(unix)]
    if workers {
        pair.workers_on();
    }
    #[cfg(not(unix))]
    let _ = workers;
    pair.run(60).await;
    let (a, b) = (pair.a_addr(), pair.b_addr());
    let tid = pair.nodes[1].transport_id;
    let new = if probing {
        // Nothing reaches A at its next address yet, so B's probes there go
        // unanswered and the path stays unproven.
        let (new, _lost) = loopback_tap(pair.nodes[0].transport_id);
        loopback(&pair.nodes[1], tid).set_autoconnect(true);
        beacon(&pair.nodes[1], tid, &new, &pair.nodes[0]);
        pair.step().await;
        let held = pair.nodes[1]
            .node
            .get_peer(&a)
            .map(|p| p.path_match(tid, &new));
        assert!(
            matches!(held, Some(crate::peer::Match::Unproven)),
            "precondition: B holds A's next address as a path it has not proven: {held:?}"
        );
        pair.deliver_to_a(&new);
        new
    } else {
        add_loopback_alias(&pair.nodes[0].addr, pair.nodes[0].transport_id)
    };
    let a_link = pair.nodes[0].node.get_peer(&b).map(|p| p.link_id());
    let b_parent = *pair.nodes[1].node.tree_state().my_declaration().parent_id();
    assert_eq!(b_parent, a, "precondition: A is B's parent");
    let had = pair.nodes[1]
        .node
        .get_peer(&a)
        .map(|p| (p.declaration().is_some(), p.inbound_filter().is_some()));
    let was = pair.nodes[1].node.stats().handshake.snapshot();
    let announces = pair.nodes[0]
        .node
        .get_peer(&b)
        .and_then(|p| p.last_tree_announce_sent_ms());
    pair.nodes[0]
        .node
        .get_peer_mut(&b)
        .expect("precondition: A holds B")
        .test_backdate_session_established(trigger_age());
    pair.move_a_to(OldAddr::Blackhole, new);
    pair.nodes[0].node.poll_link_rekeys().await;
    assert!(
        pair.nodes[0]
            .node
            .get_peer(&b)
            .is_some_and(|p| p.rekey_in_progress()),
        "precondition: A's rekey started at its new address"
    );
    pair.pump().await;
    pair.run(20).await;
    let r = since(&pair.nodes[1].node.stats().handshake.snapshot(), &was);
    let held = pair.nodes[1]
        .node
        .get_peer(&a)
        .map(|p| (p.declaration().is_some(), p.inbound_filter().is_some()));
    let parent = *pair.nodes[1].node.tree_state().my_declaration().parent_id();
    let a_kept = pair.nodes[0].node.get_peer(&b).map(|p| p.link_id()) == a_link;
    let announced = pair.nodes[0]
        .node
        .get_peer(&b)
        .and_then(|p| p.last_tree_announce_sent_ms());
    let o = pair.outcome().await;
    assert!(
        r.redials == 1
            && r.redials_proven == 1
            && o.a_dropped.is_none()
            && a_kept
            && held == had
            && held == Some((true, true))
            && parent == b_parent
            && announced == announces
            && o.works,
        "defect: {r:?} held {held:?} had {had:?} parent kept {} A kept its link {a_kept} \
         announces {announces:?} -> {announced:?} {o:?}",
        parent == b_parent
    );
    cleanup_nodes(&mut pair.nodes).await;
}

#[tokio::test]
async fn a_rekey_msg1_from_an_address_the_responder_has_not_seen_is_answered_as_a_redial_and_both_ends_keep_tree_filter_and_traffic_multipath_off()
 {
    rekey_from_an_unseen_address(Multipath::Off, false).await;
}

#[tokio::test]
async fn a_rekey_msg1_from_an_address_the_responder_has_not_seen_is_answered_as_a_redial_and_both_ends_keep_tree_filter_and_traffic_multipath_on()
 {
    rekey_from_an_unseen_address(Multipath::On, false).await;
}

/// The multipath-off case with each node's decrypt workers running.
#[cfg(unix)]
#[tokio::test]
async fn a_rekey_msg1_from_an_address_the_responder_has_not_seen_is_answered_as_a_redial_and_both_ends_keep_tree_filter_and_traffic_with_decrypt_workers()
 {
    rekey_from_an_unseen_address(Multipath::Off, true).await;
}

/// The same rekey msg1 from an unseen address with an end-to-end session
/// held at both ends: A keeps its link and its end-to-end session, B swaps
/// and opens the session again, which A takes as a rekey of the one it
/// holds. Datagrams flow both ways at every second after the change, and
/// neither end drops one for an unknown session.
async fn rekey_unseen_keeps_end_to_end_traffic(mp: Multipath) {
    let mut pair = Pair::new(mp, true).await;
    let (a, b) = (pair.a_addr(), pair.b_addr());
    let b_key = pair.nodes[1].node.identity().pubkey_full();
    pair.nodes[0]
        .node
        .initiate_session(b, b_key)
        .await
        .expect("precondition: A opens a session to B");
    pair.pump().await;
    pair.run(60).await;
    assert!(
        e2e(&mut pair, 0, 1).await && e2e(&mut pair, 1, 0).await,
        "precondition: end-to-end datagrams flow both ways"
    );
    let unknown = |p: &Pair| {
        [
            p.nodes[0].node.stats().session.unknown_session,
            p.nodes[1].node.stats().session.unknown_session,
        ]
    };
    let dropped = unknown(&pair);
    let was = pair.nodes[1].node.stats().handshake.snapshot();
    let a_link = pair.nodes[0].node.get_peer(&b).map(|p| p.link_id());
    pair.nodes[0]
        .node
        .get_peer_mut(&b)
        .expect("precondition: A holds B")
        .test_backdate_session_established(trigger_age());
    pair.move_a(OldAddr::Blackhole);
    pair.nodes[0].node.poll_link_rekeys().await;
    pair.pump().await;
    let mut failed = Vec::new();
    for s in 1..=20u64 {
        pair.run(1).await;
        let (ab, ba) = (e2e(&mut pair, 0, 1).await, e2e(&mut pair, 1, 0).await);
        if !(ab && ba) {
            failed.push((s, ab, ba));
        }
    }
    let r = since(&pair.nodes[1].node.stats().handshake.snapshot(), &was);
    let a_kept = pair.nodes[0].node.get_peer(&b).map(|p| p.link_id()) == a_link;
    let b_holds = pair.nodes[1].node.get_peer(&a).is_some();
    let after = unknown(&pair);
    cleanup_nodes(&mut pair.nodes).await;
    assert!(
        r.redials_proven == 1
            && r.redial_session_reopens == 1
            && a_kept
            && b_holds
            && failed.is_empty()
            && after == dropped,
        "defect: proven {} reopened {} A kept its link {a_kept} B holds A {b_holds} \
         seconds without traffic both ways {failed:?} unknown-session drops {dropped:?} -> {after:?}",
        r.redials_proven,
        r.redial_session_reopens
    );
}

#[tokio::test]
async fn a_rekey_msg1_from_an_address_the_responder_has_not_seen_keeps_end_to_end_traffic_flowing_both_ways_multipath_off()
 {
    rekey_unseen_keeps_end_to_end_traffic(Multipath::Off).await;
}

#[tokio::test]
async fn a_rekey_msg1_from_an_address_the_responder_has_not_seen_keeps_end_to_end_traffic_flowing_both_ways_multipath_on()
 {
    rekey_unseen_keeps_end_to_end_traffic(Multipath::On).await;
}

/// A rekey msg1 that is A's first packet from an address B holds as a path
/// of A's it has not proven, learned from a beacon: off B's link, so it is
/// answered as a redial, and both ends come out as from an unseen address,
/// A keeping its link and B its tree and filter state for A.
#[tokio::test]
async fn a_rekey_msg1_from_a_pair_the_responder_is_probing_is_answered_as_a_redial_and_both_ends_recover_multipath_on()
 {
    rekey_from(Multipath::On, false, true).await;
}
