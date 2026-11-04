//! FRC-1201 Section 5.6: the tie-break in both address orders, the
//! own-dial rule, a msg1 after the peer is held, and the local rules for a
//! late second dial, a late stored msg2 and an aged link.

use super::*;
use crate::proto::settle::model::judge::{LocalRule, Reply, Transition};

/// The smaller node's listen address and the larger node's, and the
/// source port each dials from.
const SMALL_AT: u16 = 1;
const LARGE_AT: u16 = 2;
const SMALL_SRC: u16 = 11;
const LARGE_SRC: u16 = 12;

/// One end of a crossing: `me` dials the peer (handshake `mine`), reads
/// the peer's msg1 (handshake `theirs`), then reads the msg2 of its own.
fn crossing(me: Node, peer: Node, binding: Binding) -> (Judge, Step) {
    let (mine, theirs, peer_at, peer_src) = if me < peer {
        (1, 2, LARGE_AT, LARGE_SRC)
    } else {
        (2, 1, SMALL_AT, SMALL_SRC)
    };
    let mut j = judge(me, peer);
    let s = last(
        &mut j,
        &[
            dial(mine, 1, at(peer_at), binding),
            msg1(theirs, theirs * 100, E1, 2, at(peer_src), binding),
            msg2(mine, E1, at(peer_at)),
        ],
    );
    (j, s)
}

#[test]
fn the_tie_break_moves_the_smaller_node_onto_its_own_dial() {
    // frc-1201:1048-1058.
    let (j, s) = crossing(SMALL, LARGE, Binding::Connectionless);
    assert_eq!(s.change, Some(Transition::Move));
    assert_eq!(j.settled(), Some((Hs(1), LinkId(1), at(LARGE_AT))));
    let p = j.peering.as_ref().expect("held");
    // The moved node holds the link as one it dialed, keeps its setup msg1,
    // and keeps the link's age (:1058-1063).
    assert!(p.dialed);
    assert_eq!(p.setup, at(LARGE_AT));
    assert_eq!(p.msg1, Some(Bytes(200)));
    assert_eq!(p.linkborn, 0);
}

#[test]
fn the_tie_break_keeps_the_larger_nodes_inbound_handshake() {
    // frc-1201:1051-1057.
    let (j, s) = crossing(LARGE, SMALL, Binding::Connectionless);
    assert_eq!(s.change, Some(Transition::Keep));
    assert_eq!(j.settled(), Some((Hs(1), LinkId(2), at(SMALL_SRC))));
}

#[test]
fn both_ends_of_a_crossing_settle_on_the_handshake_the_smaller_node_dialed() {
    // frc-1201:1057-1058: the outcomes are complements, whichever node
    // address is the smaller.
    for (a, b) in [(Node(1), Node(2)), (Node(9), Node(3))] {
        let (ja, _) = crossing(a, b, Binding::Connectionless);
        let (jb, _) = crossing(b, a, Binding::Connectionless);
        let ha = ja.settled().map(|s| s.0);
        let hb = jb.settled().map(|s| s.0);
        assert_eq!(ha, hb);
        assert_eq!(ha, Some(Hs(1)), "the smaller node's dial is handshake 1");
    }
}

#[test]
fn a_held_link_this_node_dialed_moves_onto_its_later_dial_whatever_the_ordering() {
    // frc-1201:1070-1075, for the larger node, which the tie-break alone
    // would keep where it is.
    let mut j = judge(LARGE, SMALL);
    let s = last(
        &mut j,
        &[
            dial(1, 1, at(SMALL_AT), Binding::Connectionless),
            msg2(1, E1, at(SMALL_AT)),
            wait(2_000),
            dial(2, 2, at(5), Binding::Connectionless),
            msg2(2, E1, at(5)),
        ],
    );
    assert_eq!(s.change, Some(Transition::Move));
    assert_eq!(j.settled(), Some((Hs(2), LinkId(2), at(5))));
}

#[test]
fn a_msg2_with_a_changed_epoch_is_not_a_cross_connection() {
    // frc-1201:1067-1068 and :979-984.
    let mut j = judge(LARGE, SMALL);
    let s = last(
        &mut j,
        &[
            dial(2, 1, at(SMALL_AT), Binding::Connectionless),
            msg1(1, 100, E1, 2, at(SMALL_SRC), Binding::Connectionless),
            msg2(2, E2, at(SMALL_AT)),
        ],
    );
    assert_eq!(s.change, Some(Transition::Replace));
    assert_eq!(j.settled(), Some((Hs(2), LinkId(1), at(SMALL_AT))));
}

#[test]
fn a_msg1_that_arrives_after_the_peer_is_held_is_a_replacement_the_heard_floor_refuses() {
    // frc-1201:1085-1092: the first handshake to complete is kept.
    let mut j = judge(LARGE, SMALL);
    let s = last(
        &mut j,
        &[
            dial(2, 1, at(SMALL_AT), Binding::Connectionless),
            msg2(2, E1, at(SMALL_AT)),
            msg1(1, 100, E1, 2, at(SMALL_SRC), Binding::Connectionless),
        ],
    );
    assert_eq!(s.reply, Some(Reply::Silent));
    assert!(s.refused.is_some());
    assert_eq!(j.settled(), Some((Hs(2), LinkId(1), at(SMALL_AT))));
}

#[test]
fn after_a_late_second_dial_the_peers_first_frame_under_the_old_session_moves_back() {
    // The model's late-second-dial rule (the operator's option (c)).
    let mut j = judge(LARGE, SMALL);
    let moved = last(
        &mut j,
        &[
            dial(1, 1, at(SMALL_AT), Binding::Connected),
            msg2(1, E1, at(SMALL_AT)),
            wait(2_000),
            dial(2, 2, at(5), Binding::Connected),
            msg2(2, E1, at(5)),
        ],
    );
    assert_eq!(moved.change, Some(Transition::Move));
    assert_eq!(moved.rule, Some(LocalRule::LateSecondDial));
    assert!(moved.closes.is_empty(), "the old session is kept");
    let back = j.step(frame(1, at(SMALL_AT)));
    assert_eq!(back.change, Some(Transition::Move));
    assert_eq!(back.rule, Some(LocalRule::LateSecondDial));
    assert_eq!(back.closes, alloc::vec![at(5)]);
    assert_eq!(j.settled(), Some((Hs(1), LinkId(1), at(SMALL_AT))));
}

#[test]
fn after_a_late_second_dial_the_peers_first_frame_under_the_new_session_drops_the_old() {
    // The model's late-second-dial rule (the operator's option (c)).
    let mut j = judge(LARGE, SMALL);
    j.run(&[
        dial(1, 1, at(SMALL_AT), Binding::Connected),
        msg2(1, E1, at(SMALL_AT)),
        wait(2_000),
        dial(2, 2, at(5), Binding::Connected),
        msg2(2, E1, at(5)),
    ]);
    let kept = j.step(frame(2, at(5)));
    assert_eq!(kept.change, None);
    assert_eq!(kept.rule, Some(LocalRule::LateSecondDial));
    assert_eq!(kept.closes, alloc::vec![at(SMALL_AT)]);
    assert_eq!(j.settled(), Some((Hs(2), LinkId(2), at(5))));
    assert_eq!(j.peering.as_ref().and_then(|p| p.fallback), None);
}

#[test]
fn a_stored_msg2_sent_after_the_peer_is_held_elsewhere_installs_nothing() {
    // The model's late-stored-msg2 rule.
    let mut j = judge(LARGE, SMALL);
    let s = last(
        &mut j,
        &[
            dial(2, 1, at(SMALL_AT), Binding::Connected),
            Event::Msg1 {
                hs: Hs(1),
                bytes: Bytes(100),
                epoch: E1,
                link: LinkId(2),
                from: at(SMALL_SRC),
                binding: Binding::Connected,
                sent: false,
            },
            msg2(2, E1, at(SMALL_AT)),
            Event::Msg2Sent { hs: Hs(1) },
        ],
    );
    assert_eq!(s.reply, Some(Reply::Stored));
    assert_eq!(s.change, None);
    assert_eq!(s.rule, Some(LocalRule::StoredLate));
    assert_eq!(j.settled(), Some((Hs(2), LinkId(1), at(SMALL_AT))));
    assert!(j.legs.is_empty());
}

#[test]
fn a_stored_msg2_sent_with_no_peer_held_installs_the_peer() {
    // frc-1201:1199: install once a send of the stored msg2 succeeds.
    let mut j = judge(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            Event::Msg1 {
                hs: Hs(2),
                bytes: Bytes(200),
                epoch: E1,
                link: LinkId(1),
                from: at(LARGE_SRC),
                binding: Binding::Connected,
                sent: false,
            },
            Event::Msg2Sent { hs: Hs(2) },
        ],
    );
    assert_eq!(s.change, Some(Transition::Promote));
    assert_eq!(j.settled(), Some((Hs(2), LinkId(1), at(LARGE_SRC))));
}

#[test]
fn a_dial_on_the_peers_aged_link_completing_while_held_is_left_open() {
    // The model's aged-link rule: undecided, so the model answers open and
    // changes nothing.
    let mut j = judge(LARGE, SMALL);
    let s = last(
        &mut j,
        &[
            msg1(1, 100, E1, 1, at(SMALL_SRC), Binding::Connectionless),
            frame(1, at(SMALL_SRC)),
            wait(30_000),
            dial(2, 2, at(SMALL_SRC), Binding::Connectionless),
            msg2(2, E1, at(SMALL_SRC)),
        ],
    );
    assert!(s.open);
    assert_eq!(s.rule, Some(LocalRule::AgedLink));
    assert_eq!(s.change, None);
    assert_eq!(j.settled(), Some((Hs(1), LinkId(1), at(SMALL_SRC))));
}
