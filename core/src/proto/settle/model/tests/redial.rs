//! `LocalRule::DeferredRedial` (the operator's decision, 2026-11-17): a
//! fresh same-epoch msg1 off the established link of a held peering that
//! has been heard from is answered into a redial beside the peering, which
//! only the peer's first frame under the redial's session replaces. A
//! peering not yet heard from keeps the replacement at the msg1.

use super::*;
use crate::proto::settle::model::judge::{Class, Gate, LocalRule, Reply, Transition};

/// Long enough for the link and its session to be eligible as a rekey.
const AGED: Ms = 30_000;

/// A fresh msg1 of the peer's from a new address, `at(8)`.
fn redial(hs: u32) -> Event {
    msg1(hs, hs * 10, E1, hs, at(8), Binding::Connectionless)
}

#[test]
fn a_fresh_msg1_off_an_eligible_reachable_link_is_answered_and_leaves_the_peering_until_its_frame()
{
    let mut j = responder(SMALL, LARGE);
    let s = last(&mut j, &[wait(AGED), redial(11)]);
    assert_eq!(s.class, Some(Class::Redial));
    assert_eq!(s.reply, Some(Reply::Msg2));
    assert_eq!(s.change, None);
    assert_eq!(s.rule, Some(LocalRule::DeferredRedial));
    assert_eq!(j.settled(), Some((Hs(10), LinkId(1), at(9))));
    let swap = j.step(frame(11, at(8)));
    assert_eq!(swap.change, Some(Transition::Replace));
    assert_eq!(swap.rule, Some(LocalRule::DeferredRedial));
    assert_eq!(j.settled(), Some((Hs(11), LinkId(11), at(8))));
    assert!(j.peering.as_ref().is_some_and(|p| p.heard));
}

#[test]
fn a_fresh_msg1_off_a_young_link_is_answered_as_a_redial_and_not_held_by_the_heard_floor() {
    let mut j = responder(SMALL, LARGE);
    let s = last(&mut j, &[wait(500), redial(11)]);
    assert_eq!(s.class, Some(Class::Redial));
    assert_eq!(s.refused, None);
    assert_eq!(s.reply, Some(Reply::Msg2));
    assert_eq!(j.step(frame(11, at(8))).change, Some(Transition::Replace));
}

#[test]
fn a_frame_under_the_held_session_leaves_the_redial_pending_and_its_timeout_drops_it() {
    let mut j = responder(SMALL, LARGE);
    j.run(&[wait(AGED), redial(11), frame(10, at(9))]);
    assert_eq!(j.settled(), Some((Hs(10), LinkId(1), at(9))));
    assert!(j.redial.is_some());
    let t = j.step(Event::Timeout { hs: Hs(11) });
    assert_eq!(t.rule, Some(LocalRule::DeferredRedial));
    assert!(j.redial.is_none());
    assert_eq!(j.step(frame(11, at(8))).change, None);
    assert_eq!(j.settled(), Some((Hs(10), LinkId(1), at(9))));
}

#[test]
fn a_fresh_msg1_off_the_link_of_an_unheard_peering_is_a_replacement_at_the_msg1_and_not_a_redial() {
    let mut j = judge(SMALL, LARGE);
    j.step(msg1(10, 100, E1, 1, at(9), Binding::Connectionless));
    let s = last(&mut j, &[wait(999), redial(11)]);
    assert_eq!(s.class, Some(Class::Replacement));
    assert_eq!(s.refused, Some(Gate::Unheard));
    assert_eq!(s.reply, Some(Reply::Silent));
    assert!(j.redial.is_none());
    let again = last(&mut j, &[wait(1), redial(12)]);
    assert_eq!(again.class, Some(Class::Replacement));
    assert_eq!(again.refused, None);
    assert_eq!(again.change, Some(Transition::Replace));
    assert!(j.redial.is_none());
    assert_eq!(j.settled().map(|(hs, ..)| hs), Some(Hs(12)));
}

#[test]
fn a_second_redial_within_one_second_is_refused_and_a_later_one_replaces_it() {
    let mut j = responder(SMALL, LARGE);
    j.run(&[wait(AGED), redial(11)]);
    let early = last(&mut j, &[wait(999), redial(12)]);
    assert_eq!(early.refused, Some(Gate::Slot));
    let late = last(&mut j, &[wait(1), redial(12)]);
    assert_eq!(late.refused, None);
    assert_eq!(late.reply, Some(Reply::Msg2));
    assert_eq!(j.redial.map(|r| r.leg.hs), Some(Hs(12)));
    assert_eq!(j.step(frame(11, at(8))).change, None);
}

#[test]
fn the_swap_of_a_heard_peering_stamps_the_dampener_and_an_answered_redial_does_not() {
    let mut j = responder(SMALL, LARGE);
    j.run(&[wait(AGED), redial(11)]);
    assert_eq!(j.stamp, None);
    j.step(frame(11, at(8)));
    assert_eq!(j.stamp, Some(AGED));
    let held = last(
        &mut j,
        &[
            wait(5_000),
            msg1(12, 120, E1, 12, at(7), Binding::Connectionless),
        ],
    );
    assert_eq!(held.refused, Some(Gate::Dampened));
}

#[test]
fn an_armed_redials_copy_is_a_copy_and_its_byte_identical_resend_draws_the_stored_msg2() {
    let mut j = responder(SMALL, LARGE);
    j.run(&[wait(AGED), redial(11)]);
    let resend = last(&mut j, &[wait(1_000), redial(11)]);
    assert_eq!(resend.reply, Some(Reply::Stored));
    let copy = last(
        &mut j,
        &[msg1(11, 111, E1, 13, at(7), Binding::Connectionless)],
    );
    assert_eq!(copy.class, Some(Class::OffLink));
    assert_eq!(copy.reply, Some(Reply::Silent));
}

#[test]
fn a_redial_whose_peering_is_lost_first_installs_the_peer_at_its_frame() {
    let mut j = responder(SMALL, LARGE);
    j.run(&[wait(AGED), redial(11), Event::Lost]);
    assert_eq!(j.settled(), None);
    let s = j.step(frame(11, at(8)));
    assert_eq!(s.change, Some(Transition::Promote));
    assert_eq!(j.settled(), Some((Hs(11), LinkId(11), at(8))));
}
