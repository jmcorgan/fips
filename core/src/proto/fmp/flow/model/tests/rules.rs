//! The judge's local rules: each one's value, and the outcome it decides
//! where the FRC would decide otherwise or is silent.

use super::super::history::{Claim, Event, Hs, LinkId};
use super::super::judge::{LocalRule, Params, Refusal, Reply, Transition};
use super::{
    E1, E2, LARGE, SMALL, answer, at, dial, frame, held_by_answer, held_by_dial, hello, holds,
    judge, judge_with, last,
};

#[test]
fn the_local_parameters_switch_on_exactly_the_three_rules_that_replace_an_frc_rule() {
    let frc = Params::default();
    let local = Params::local();
    assert!(frc.live && !frc.disconnect && frc.stamps);
    assert!(!local.live && local.disconnect && !local.stamps);
    assert_eq!((local.interval, local.window), (frc.interval, frc.window));
    assert_eq!((frc.interval, frc.window), (15_000, 20_000));
}

#[test]
fn no_live_test_moves_the_smaller_node_off_a_live_inbound_link() {
    let mut j = judge_with(SMALL, Params::local());
    j.step(dial(2, 11, 8));
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(frame(1, 7));
    let s = j.step(answer(2, E1));
    assert_eq!(s.change, Some(Transition::Move));
    assert_eq!(
        s.rule,
        Some(LocalRule::NoLiveTest),
        "the FRC would refuse here"
    );
}

#[test]
fn no_live_test_keeps_an_unheard_own_dial_installed_after_this_dial_began() {
    let mut j = judge_with(LARGE, Params::local());
    j.step(dial(2, 11, 8));
    j.step(Event::Advance(100));
    held_by_dial(&mut j, 1, 10, 7, E1);
    let s = j.step(answer(2, E1));
    assert_eq!(s.refused, Some(Refusal::Live));
    assert_eq!(s.reply, Some(Reply::Silent), "no msg3 beside its own dial");
    assert_eq!(
        s.rule, None,
        "the FRC's test, by the msg2 just read, agrees"
    );
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
}

#[test]
fn no_live_test_moves_off_an_own_dial_installed_before_this_dial_began_inside_the_window() {
    let mut j = judge_with(SMALL, Params::local());
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(Event::Advance(1_000));
    j.step(dial(2, 11, 8));
    let s = j.step(answer(2, E1));
    assert_eq!(s.change, Some(Transition::Move));
    assert_eq!(s.rule, Some(LocalRule::NoLiveTest));
}

#[test]
fn no_live_test_moves_off_an_own_dial_heard_since_it_was_installed() {
    let mut j = judge_with(SMALL, Params::local());
    j.step(dial(2, 11, 8));
    j.step(Event::Advance(100));
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(frame(1, 7));
    let s = j.step(answer(2, E1));
    assert_eq!(s.change, Some(Transition::Move));
    assert_eq!(s.rule, Some(LocalRule::NoLiveTest));
}

#[test]
fn refusal_disconnect_sends_a_disconnect_on_a_refused_msg3() {
    let mut j = judge_with(SMALL, Params::local());
    j.step(hello(1, 10, 7));
    let s = j.step(Event::Msg3 {
        hs: Hs(1),
        epoch: E1,
        claim: Claim::None,
        refused: true,
    });
    assert!(s.disconnect);
    assert_eq!(s.rule, Some(LocalRule::RefusalDisconnect));
    assert_eq!(s.closes, [at(7)]);
}

#[test]
fn dampener_stamp_leaves_a_msg2_restart_unstamped_and_a_msg3_restart_stamped() {
    let mut j = judge_with(SMALL, Params::local());
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(Event::Advance(20_000));
    j.step(dial(2, 11, 8));
    let s = j.step(answer(2, E2));
    assert_eq!(s.change, Some(Transition::Replace));
    assert_eq!(s.rule, Some(LocalRule::DampenerStamp));
    assert_eq!(j.stamp, None);
    j.step(Event::Advance(20_000));
    j.step(hello(3, 12, 9));
    let s = j.step(last(3, E1, Claim::None));
    assert_eq!(s.change, Some(Transition::Replace));
    assert_eq!(j.stamp, Some(40_000));
}

#[test]
fn keep_ends_attempt_is_named_at_the_larger_nodes_keep() {
    let mut j = judge(LARGE);
    j.step(dial(2, 11, 8));
    held_by_answer(&mut j, 1, 10, 7, E1);
    let s = j.step(answer(2, E1));
    assert_eq!(s.rule, Some(LocalRule::KeepEndsAttempt));
    assert_eq!(s.reply, Some(Reply::Silent));
}

#[test]
fn stale_keeps_leg_leaves_the_handshake_for_its_timeout() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(hello(2, 11, 8));
    let s = j.step(last(2, E1, Claim::Other));
    assert_eq!(s.rule, Some(LocalRule::StaleKeepsLeg));
    assert_eq!(j.legs.len(), 1);
    assert_eq!(j.step(Event::Timeout { hs: Hs(2) }).closes, [at(8)]);
}

#[test]
fn no_live_test_orders_the_attempt_and_the_install_by_event_not_by_the_clock() {
    let mut j = judge_with(LARGE, Params::local());
    j.step(dial(2, 11, 8));
    held_by_dial(&mut j, 1, 10, 7, E1);
    let s = j.step(answer(2, E1));
    assert_eq!(
        s.refused,
        Some(Refusal::Live),
        "a dial begun before the install, in the same millisecond, is kept beside it"
    );
}
