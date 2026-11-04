//! FRC-1201 Section 5.5: the restart gates' edges, the definition of heard
//! from, and the dampener stamping the model chooses.

use super::*;
use crate::proto::settle::model::judge::{Gate, LocalRule, Transition};

/// A replacement msg1 from a new address, on a link still too young to
/// rekey.
fn replacement(hs: u32) -> Event {
    msg1(hs, hs * 10, E1, hs, at(8), Binding::Connectionless)
}

/// A judge holding the peer from its msg1 at time 0, never heard from.
fn unheard() -> Judge {
    let mut j = judge(SMALL, LARGE);
    j.step(msg1(10, 100, E1, 1, at(9), Binding::Connectionless));
    j
}

#[test]
fn the_unheard_floor_refuses_a_replacement_until_the_peering_is_one_second_old() {
    // frc-1201:995-997.
    let mut j = unheard();
    let early = last(&mut j, &[wait(999), replacement(11)]);
    assert_eq!(early.refused, Some(Gate::Unheard));
    assert_eq!(early.change, None);
    let mut j = unheard();
    let late = last(&mut j, &[wait(1_000), replacement(11)]);
    assert_eq!(late.refused, None);
    assert_eq!(late.change, Some(Transition::Replace));
}

#[test]
fn the_heard_floor_refuses_a_replacement_within_fifteen_seconds_of_the_last_frame() {
    // frc-1201:998-1001: counted from the last authenticated frame.
    let mut j = unheard();
    j.run(&[wait(5_000), frame(10, at(9))]);
    let early = last(&mut j, &[wait(14_999), replacement(11)]);
    assert_eq!(early.refused, Some(Gate::Heard));
    let late = last(&mut j, &[wait(1), replacement(12)]);
    assert_eq!(late.refused, None);
    assert_eq!(late.change, Some(Transition::Replace));
}

#[test]
fn the_heard_floor_counts_from_installation_when_no_frame_has_arrived() {
    // frc-1201:1000-1001: a peering this node set up by its own handshake
    // is heard from at once, with no frame yet.
    let mut j = judge(SMALL, LARGE);
    j.run(&[
        dial(1, 1, at(9), Binding::Connectionless),
        wait(2_000),
        msg2(1, E1, at(9)),
    ]);
    let early = last(&mut j, &[wait(14_999), replacement(11)]);
    assert_eq!(early.refused, Some(Gate::Heard));
    let late = last(&mut j, &[wait(1), replacement(12)]);
    assert_eq!(late.refused, None);
}

#[test]
fn heard_from_starts_at_the_first_frame_for_a_peering_installed_from_a_msg1() {
    // frc-1201:986-988: unheard until a frame authenticates, so only the
    // one-second floor holds before it; heard from at the frame.
    let mut j = unheard();
    let before = last(&mut j, &[wait(1_500), replacement(11)]);
    assert_eq!(before.refused, None);
    let mut j = unheard();
    let after = last(
        &mut j,
        &[wait(1_000), frame(10, at(9)), wait(500), replacement(11)],
    );
    assert_eq!(after.refused, Some(Gate::Heard));
}

#[test]
fn the_dampener_refuses_until_fifteen_seconds_after_the_last_accepted_restart() {
    // frc-1201:1002-1005: the ceiling counts from both the peering's last
    // frame and the last accepted restart or replacement.
    let mut j = unheard();
    let first = last(
        &mut j,
        &[
            frame(10, at(9)),
            wait(15_000),
            msg1(11, 110, E2, 2, at(8), Binding::Connectionless),
        ],
    );
    assert_eq!(first.change, Some(Transition::Replace));
    assert_eq!(j.stamp, Some(15_000));
    // The new peering is unheard and past its floor, but the dampener
    // still holds.
    let early = last(
        &mut j,
        &[
            wait(14_999),
            msg1(12, 120, Epoch(3), 3, at(7), Binding::Connectionless),
        ],
    );
    assert_eq!(early.refused, Some(Gate::Dampened));
    let late = last(
        &mut j,
        &[
            wait(1),
            msg1(12, 120, Epoch(3), 3, at(7), Binding::Connectionless),
        ],
    );
    assert_eq!(late.refused, None);
    assert_eq!(late.change, Some(Transition::Replace));
}

#[test]
fn between_the_floors_and_the_ceiling_the_model_refuses_only_while_dampened() {
    // frc-1201:1021-1022 leaves it to the node: an unheard peering two
    // seconds old, never dampened, is replaced.
    let mut j = unheard();
    let s = last(&mut j, &[wait(2_000), replacement(11)]);
    assert_eq!(s.refused, None);
    assert_eq!(s.change, Some(Transition::Replace));
}

#[test]
fn a_replacement_at_a_msg1_stamps_the_dampener_only_if_the_old_peering_was_heard() {
    // The model's stamping rule: heard, stamped; unheard, not.
    let mut j = unheard();
    let s = last(&mut j, &[wait(2_000), replacement(11)]);
    assert_eq!(s.rule, Some(LocalRule::DampenerStamp));
    assert_eq!(j.stamp, None);
    let mut j = unheard();
    let s = last(&mut j, &[frame(10, at(9)), wait(15_000), replacement(11)]);
    assert_eq!(s.rule, Some(LocalRule::DampenerStamp));
    assert_eq!(j.stamp, Some(15_000));
}

#[test]
fn a_restart_found_at_this_nodes_own_msg2_does_not_stamp_the_dampener() {
    // The model's stamping rule, with frc-1201:979-984: a changed epoch in
    // an initial msg2 tears down and installs, without the tie-break.
    let mut j = judge(SMALL, LARGE);
    let s = last(
        &mut j,
        &[
            msg1(10, 100, E1, 1, at(9), Binding::Connectionless),
            frame(10, at(9)),
            wait(20_000),
            dial(1, 2, at(8), Binding::Connectionless),
            msg2(1, E2, at(8)),
        ],
    );
    assert_eq!(s.change, Some(Transition::Replace));
    assert_eq!(s.rule, Some(LocalRule::DampenerStamp));
    assert_eq!(j.stamp, None);
    assert_eq!(j.settled(), Some((Hs(1), LinkId(2), at(8))));
}

#[test]
fn a_restart_revealed_in_a_rekey_msg2_keeps_the_link_and_does_not_stamp_the_dampener() {
    // The model's stamping rule, with frc-1201:967-978: the link is kept,
    // the report waits for the cutover, and the link's age restarts.
    let mut j = responder(SMALL, LARGE);
    let pending = last(
        &mut j,
        &[
            wait(30_000),
            Event::RekeyStart { hs: Hs(20) },
            Event::RekeyMsg2 {
                hs: Hs(20),
                epoch: E2,
            },
        ],
    );
    assert_eq!(pending.change, None);
    let cut = j.step(Event::RekeyCutover);
    assert_eq!(cut.change, Some(Transition::Restarted));
    assert_eq!(cut.rule, Some(LocalRule::DampenerStamp));
    assert_eq!(j.stamp, None);
    let p = j.peering.as_ref().expect("the peer is kept");
    assert_eq!((p.link, p.epoch, p.linkborn), (LinkId(1), E2, 30_000));
}
