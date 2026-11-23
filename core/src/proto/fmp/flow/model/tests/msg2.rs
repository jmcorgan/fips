//! FRC-2201 Sections 5.3, 5.6 and 5.7 at the initiator: this node's own
//! msg2, through the identity check, the peering decision, the restart
//! gates and the rules for a second link, in that order.

use super::super::history::Claim;
use super::super::history::{Epoch, Event, Hs, LinkId, Named};
use super::super::judge::{Class, Refusal, Reply, Transition};
use super::{
    E1, E2, LARGE, SMALL, answer, at, closes, dial, dial_naming, frame, held_by_answer,
    held_by_dial, hello, holds, judge, last,
};

#[test]
fn a_msg2_whose_static_is_not_the_named_identity_is_dropped_and_the_attempt_goes_on() {
    let mut j = judge(SMALL);
    j.step(dial_naming(1, 10, 7, Named::Other));
    let s = j.step(answer(1, E1));
    assert_eq!(s.refused, Some(Refusal::Identity));
    assert_eq!(
        s.reply,
        Some(Reply::Silent),
        "no msg3 for a mismatched msg2"
    );
    assert_eq!(s.change, None, "a mismatch installs no session");
    assert_eq!(j.attempts.len(), 1, "the attempt continues");
}

#[test]
fn a_dial_that_named_no_one_installs_whoever_answers() {
    let mut j = judge(SMALL);
    j.step(dial_naming(1, 10, 7, Named::Anyone));
    let s = j.step(answer(1, E1));
    assert_eq!(s.change, Some(Transition::Promote));
    assert_eq!(s.reply, Some(Reply::Final));
}

#[test]
fn a_refused_msg2_abandons_the_attempt_without_msg3_and_closes_its_connection() {
    let mut j = judge(SMALL);
    j.step(dial(1, 10, 7));
    let s = j.step(Event::Msg2 {
        hs: Hs(1),
        epoch: E1,
        refused: true,
    });
    assert_eq!(s.refused, Some(Refusal::Declined));
    assert_eq!(
        s.reply,
        Some(Reply::Silent),
        "an initiator that refuses sends no msg3"
    );
    assert_eq!(closes(&s), [at(7)], "the new link is torn down");
    assert!(j.attempts.is_empty() && j.peering.is_none());
}

#[test]
fn a_msg2_of_an_identity_not_held_promotes_and_sends_msg3() {
    let mut j = judge(LARGE);
    j.step(dial(1, 10, 7));
    let s = j.step(answer(1, E1));
    assert_eq!(s.class, Some(Class::NotHeld));
    assert_eq!(s.change, Some(Transition::Promote));
    assert_eq!(s.reply, Some(Reply::Final));
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
    assert_eq!(j.needs(), [(LinkId(10), at(7))]);
}

#[test]
fn a_msg2_restart_inside_the_interval_of_a_frame_is_refused_without_msg3() {
    let mut j = judge(SMALL);
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(frame(1, 7));
    j.step(Event::Advance(14_999));
    j.step(dial(2, 11, 8));
    let s = j.step(answer(2, E2));
    assert_eq!(s.class, Some(Class::Restart));
    assert_eq!(s.refused, Some(Refusal::Heard));
    assert_eq!(
        s.reply,
        Some(Reply::Silent),
        "an initiator that refuses sends no msg3"
    );
    assert_eq!(closes(&s), [at(8)]);
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
}

#[test]
fn a_msg2_restart_inside_the_dampener_is_refused() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::Advance(20_000));
    j.step(hello(2, 11, 8));
    let s = j.step(last(2, E2, Claim::None));
    assert_eq!(
        s.change,
        Some(Transition::Replace),
        "precondition: a restart accepted"
    );
    j.step(Event::Advance(10_000));
    j.step(dial(3, 12, 9));
    let s = j.step(answer(3, Epoch(3)));
    assert_eq!(s.refused, Some(Refusal::Dampened));
    assert_eq!(s.reply, Some(Reply::Silent));
    assert_eq!(holds(&j), Some((Hs(2), LinkId(11))));
}

#[test]
fn a_msg2_restart_past_both_gates_replaces_the_peer_closes_the_old_link_and_stamps() {
    let mut j = judge(SMALL);
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(frame(1, 7));
    j.step(Event::Advance(15_000));
    j.step(dial(2, 11, 8));
    let s = j.step(answer(2, E2));
    assert_eq!(s.class, Some(Class::Restart));
    assert_eq!(s.change, Some(Transition::Replace));
    assert_eq!(s.reply, Some(Reply::Final));
    assert_eq!(closes(&s), [at(7)]);
    assert_eq!(
        j.stamp,
        Some(15_000),
        "an accepted epoch change stamps the dampener"
    );
    assert_eq!(holds(&j), Some((Hs(2), LinkId(11))));
    assert_eq!(j.peering.map(|p| p.epoch), Some(E2));
}

#[test]
fn the_smaller_node_completing_its_dial_second_moves_onto_it_and_closes_the_link_it_left() {
    let mut j = judge(SMALL);
    j.step(dial(2, 11, 8));
    held_by_answer(&mut j, 1, 10, 7, E1);
    let s = j.step(answer(2, E1));
    assert_eq!(s.class, Some(Class::Crossing));
    assert_eq!(s.change, Some(Transition::Move));
    assert_eq!(s.reply, Some(Reply::Final));
    assert_eq!(closes(&s), [at(7)], "the link left is torn down");
    assert!(!s.disconnect, "no Disconnect on the session left");
    assert_eq!(holds(&j), Some((Hs(2), LinkId(11))));
}

#[test]
fn the_smaller_node_does_not_leave_a_live_inbound_link_and_sends_no_msg3() {
    let mut j = judge(SMALL);
    j.step(dial(2, 11, 8));
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(frame(1, 7));
    j.step(Event::Advance(19_999));
    let s = j.step(answer(2, E1));
    assert_eq!(s.class, Some(Class::Crossing));
    assert_eq!(s.refused, Some(Refusal::Live));
    assert_eq!(s.reply, Some(Reply::Silent));
    assert_eq!(closes(&s), [at(8)], "the new link is torn down");
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
}

#[test]
fn the_larger_node_completing_its_dial_second_keeps_what_it_holds_and_sends_no_msg3() {
    let mut j = judge(LARGE);
    j.step(dial(2, 11, 8));
    held_by_answer(&mut j, 1, 10, 7, E1);
    let s = j.step(answer(2, E1));
    assert_eq!(s.class, Some(Class::Crossing));
    assert_eq!(s.change, Some(Transition::Keep));
    assert_eq!(s.reply, Some(Reply::Silent));
    assert_eq!(closes(&s), [at(8)]);
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
}

#[test]
fn a_second_dial_by_the_same_side_moves_off_a_link_that_is_not_live_in_either_address_order() {
    for me in [SMALL, LARGE] {
        let mut j = judge(me);
        held_by_dial(&mut j, 1, 10, 7, E1);
        j.step(Event::Advance(20_000));
        j.step(dial(2, 11, 8));
        let s = j.step(answer(2, E1));
        assert_eq!(s.class, Some(Class::SameSide), "{me:?}");
        assert_eq!(s.change, Some(Transition::Move), "{me:?}");
        assert_eq!(s.reply, Some(Reply::Final), "{me:?}");
        assert_eq!(closes(&s), [at(7)], "{me:?}: the old link closes");
        assert!(!s.disconnect, "{me:?}: without a Disconnect");
    }
}

#[test]
fn a_second_dial_by_the_same_side_does_not_displace_a_link_live_by_its_frame() {
    let mut j = judge(LARGE);
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(Event::Advance(25_000));
    j.step(frame(1, 7));
    j.step(Event::Advance(1_000));
    j.step(dial(2, 11, 8));
    let s = j.step(answer(2, E1));
    assert_eq!(s.class, Some(Class::SameSide));
    assert_eq!(s.refused, Some(Refusal::Live));
    assert_eq!(s.reply, Some(Reply::Silent));
    assert_eq!(closes(&s), [at(8)]);
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
}

#[test]
fn a_second_dial_by_the_same_side_does_not_displace_a_link_whose_msg2_arrived_inside_the_window() {
    let mut j = judge(SMALL);
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(Event::Advance(19_999));
    j.step(dial(2, 11, 8));
    let s = j.step(answer(2, E1));
    assert_eq!(s.refused, Some(Refusal::Live));
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
}

#[test]
fn moving_at_msg2_abandons_this_nodes_rekey() {
    let mut j = judge(SMALL);
    j.step(dial(2, 11, 8));
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::RekeyStart { hs: Hs(9) });
    assert_eq!(j.rekey, Some(Hs(9)), "precondition: a rekey in flight");
    let s = j.step(answer(2, E1));
    assert_eq!(s.change, Some(Transition::Move));
    assert_eq!(j.rekey, None);
}
