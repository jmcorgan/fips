//! FRC-1201 Section 5.7: one test per classification rule, in order.

use super::*;
use crate::proto::settle::model::judge::{Class, Reply, Transition};

/// Long enough for the link and its session to be eligible as a rekey.
const AGED: Ms = 30_000;

#[test]
fn rule_1_a_msg1_from_an_identity_not_held_installs_the_peer() {
    // frc-1201:1107; and :1042, whether or not this node's own dial is in
    // flight.
    for own in [false, true] {
        let mut j = judge(SMALL, LARGE);
        if own {
            j.step(dial(1, 7, at(9), Binding::Connectionless));
        }
        let s = j.step(msg1(10, 100, E1, 1, at(9), Binding::Connectionless));
        assert_eq!(s.class, Some(Class::NotHeld));
        assert_eq!(s.reply, Some(Reply::Msg2));
        assert_eq!(s.change, Some(Transition::Promote));
        assert_eq!(j.settled(), Some((Hs(10), LinkId(1), at(9))));
    }
}

#[test]
fn rule_2_a_changed_epoch_is_a_restart() {
    // frc-1201:1111, and :960: torn down, then answered as not held.
    let mut j = responder(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            wait(20_000),
            msg1(11, 110, E2, 2, at(8), Binding::Connectionless),
        ],
    );
    assert_eq!(s.class, Some(Class::Restart));
    assert_eq!(s.reply, Some(Reply::Msg2));
    assert_eq!(s.change, Some(Transition::Replace));
    assert_eq!(j.settled(), Some((Hs(11), LinkId(2), at(8))));
    assert_eq!(j.peering.as_ref().map(|p| p.epoch), Some(E2));
}

#[test]
fn rule_3_1_a_resend_of_the_setup_msg1_draws_the_same_msg2() {
    // frc-1201:1120: answered with the msg2 sent then; nothing allocated.
    let mut j = responder(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            wait(500),
            msg1(10, 100, E1, 1, at(9), Binding::Connectionless),
        ],
    );
    assert_eq!(s.class, Some(Class::Resend));
    assert_eq!(s.reply, Some(Reply::Stored));
    assert_eq!(s.change, None);
    assert_eq!(j.settled(), Some((Hs(10), LinkId(1), at(9))));
}

#[test]
fn rule_3_2_a_copy_with_a_rewritten_header_is_discarded() {
    // frc-1201:1123: the record holds the setup msg1's ephemeral.
    let mut j = responder(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            wait(500),
            msg1(10, 101, E1, 1, at(9), Binding::Connectionless),
        ],
    );
    assert_eq!(s.class, Some(Class::Copy));
    assert_eq!(s.reply, Some(Reply::Silent));
    assert_eq!(s.change, None);
}

#[test]
fn rule_3_3_any_other_msg1_on_a_young_link_replaces_the_peer() {
    // frc-1201:1125: a fresh dial from a peer that lost its side, past the
    // gates: the frame was 15 s ago and the link is still too young.
    let mut j = responder(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            wait(15_000),
            msg1(11, 110, E1, 2, at(8), Binding::Connectionless),
        ],
    );
    assert_eq!(s.class, Some(Class::Replacement));
    assert_eq!(s.reply, Some(Reply::Msg2));
    assert_eq!(s.change, Some(Transition::Replace));
    assert_eq!(j.settled(), Some((Hs(11), LinkId(2), at(8))));
}

#[test]
fn rule_3_3_a_refused_replacement_is_recorded_so_its_resends_are_copies() {
    // frc-1201:1127-1130.
    let mut j = responder(SMALL, LARGE);
    let refused = last(
        &mut j,
        &[
            wait(500),
            msg1(11, 110, E1, 2, at(8), Binding::Connectionless),
        ],
    );
    assert_eq!(refused.class, Some(Class::Replacement));
    assert_eq!(refused.reply, Some(Reply::Silent));
    assert!(refused.refused.is_some());
    let resend = last(
        &mut j,
        &[
            wait(20_000),
            msg1(11, 110, E1, 2, at(8), Binding::Connectionless),
        ],
    );
    assert_eq!(resend.class, Some(Class::Copy));
    assert_eq!(resend.reply, Some(Reply::Silent));
    assert_eq!(j.settled(), Some((Hs(10), LinkId(1), at(9))));
}

#[test]
fn rule_4_1_an_eligible_msg1_off_a_reachable_link_is_discarded() {
    // frc-1201:1134: a second path, not a rekey of this link.
    let mut j = responder(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            wait(AGED),
            msg1(11, 110, E1, 2, at(8), Binding::Connectionless),
        ],
    );
    assert_eq!(s.class, Some(Class::OffLink));
    assert_eq!(s.reply, Some(Reply::Silent));
    assert_eq!(j.peering.as_ref().and_then(|p| p.pending), None);
}

#[test]
fn rule_4_1_an_eligible_msg1_off_an_unreachable_link_goes_on_to_the_next_rule() {
    // frc-1201:1141-1143: the link's connection has closed.
    let mut j = judge(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            msg1(10, 100, E1, 1, at(9), Binding::Connected),
            frame(10, at(9)),
            wait(AGED),
            Event::Close { at: at(9) },
            msg1(11, 110, E1, 2, at(8), Binding::Connected),
        ],
    );
    assert_eq!(s.class, Some(Class::Rekey));
    assert_eq!(s.reply, Some(Reply::Msg2));
}

#[test]
fn rule_4_2_while_a_pending_session_is_held_only_its_arming_msg1_is_answered() {
    // frc-1201:1144: the arming msg1's resend draws its msg2; any other is
    // discarded.
    let mut j = responder(SMALL, LARGE);
    j.run(&[
        wait(AGED),
        msg1(11, 110, E1, 1, at(9), Binding::Connectionless),
    ]);
    let resend = j.step(msg1(11, 110, E1, 1, at(9), Binding::Connectionless));
    assert_eq!(resend.class, Some(Class::Pending));
    assert_eq!(resend.reply, Some(Reply::Stored));
    let other = j.step(msg1(12, 120, E1, 1, at(9), Binding::Connectionless));
    assert_eq!(other.class, Some(Class::Pending));
    assert_eq!(other.reply, Some(Reply::Silent));
}

#[test]
fn rule_4_3_an_eligible_copy_the_record_holds_is_discarded() {
    // frc-1201:1147: a copy of the setup msg1, header rewritten, on the
    // link once it is old enough to rekey.
    let mut j = responder(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            wait(AGED),
            msg1(10, 101, E1, 1, at(9), Binding::Connectionless),
        ],
    );
    assert_eq!(s.class, Some(Class::Recorded));
    assert_eq!(s.reply, Some(Reply::Silent));
}

#[test]
fn rule_4_4_a_rekey_msg1_during_this_nodes_own_rekey_is_discarded_by_the_smaller_node() {
    // frc-1201:1149, resolved as frc-1201:1187-1188 states: the smaller
    // node discards the peer's rekey msg1 while its own attempt runs, and
    // the larger answers it.
    for (me, peer, answer) in [(SMALL, LARGE, Reply::Silent), (LARGE, SMALL, Reply::Msg2)] {
        let mut j = responder(me, peer);
        let s = last(
            &mut j,
            &[
                wait(AGED),
                Event::RekeyStart { hs: Hs(20) },
                msg1(11, 110, E1, 1, at(9), Binding::Connectionless),
            ],
        );
        assert_eq!(s.class, Some(Class::Simultaneous));
        assert_eq!(s.reply, Some(answer));
    }
}

#[test]
fn rule_4_5_an_eligible_msg1_on_the_link_is_the_peers_rekey() {
    // frc-1201:1151: answered, and a pending session armed by it.
    let mut j = responder(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            wait(AGED),
            msg1(11, 110, E1, 1, at(9), Binding::Connectionless),
        ],
    );
    assert_eq!(s.class, Some(Class::Rekey));
    assert_eq!(s.reply, Some(Reply::Msg2));
    assert_eq!(s.change, None);
    let pending = j.peering.as_ref().and_then(|p| p.pending).map(|p| p.hs);
    assert_eq!(pending, Some(Hs(11)));
    // The peer's first frame under it is the cutover.
    let cut = j.step(frame(11, at(9)));
    assert_eq!(cut.change, Some(Transition::RekeyCutover));
    assert_eq!(j.settled(), Some((Hs(11), LinkId(1), at(9))));
}
