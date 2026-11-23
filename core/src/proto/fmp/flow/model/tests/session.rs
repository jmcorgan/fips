//! FRC-2201 Sections 5.6, 6.5, 7.2, 7.4 and 7.6: frames, this node's own
//! rekey, timeouts, loss and restart.

use super::super::history::{Event, Hs, LinkId};
use super::super::judge::{Reply, Transition};
use super::{E1, E2, LARGE, SMALL, at, closes, dial, frame, held_by_answer, hello, holds, judge};

#[test]
fn a_frame_of_the_current_session_moves_the_peers_address_and_a_handshake_does_not() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(hello(2, 11, 9));
    assert_eq!(
        j.settled().map(|x| x.2),
        Some(at(7)),
        "a msg1 moves nothing"
    );
    j.step(frame(1, 8));
    assert_eq!(j.settled().map(|x| x.2), Some(at(8)));
}

#[test]
fn a_frame_under_a_session_not_held_changes_nothing() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    let s = j.step(frame(5, 8));
    assert_eq!(s.change, None);
    assert_eq!(j.settled().map(|x| x.2), Some(at(7)));
    assert_eq!(j.peering.and_then(|p| p.framed), None);
}

#[test]
fn this_nodes_rekey_sends_msg3_and_cuts_over_at_its_own_check() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::RekeyStart { hs: Hs(2) });
    let s = j.step(Event::RekeyMsg2 {
        hs: Hs(2),
        epoch: E1,
    });
    assert_eq!(s.reply, Some(Reply::Final));
    assert_eq!(s.change, None);
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
    let s = j.step(Event::RekeyCutover);
    assert_eq!(s.change, Some(Transition::RekeyCutover));
    assert_eq!(holds(&j), Some((Hs(2), LinkId(10))));
}

#[test]
fn a_rekey_msg2_with_a_changed_epoch_is_recorded_and_the_link_stands() {
    let mut j = judge(LARGE);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::RekeyStart { hs: Hs(2) });
    let s = j.step(Event::RekeyMsg2 {
        hs: Hs(2),
        epoch: E2,
    });
    assert_eq!(s.change, Some(Transition::Restarted));
    assert_eq!(j.peering.map(|p| (p.epoch, p.link)), Some((E2, LinkId(10))));
    assert_eq!(j.stamp, None);
}

#[test]
fn no_rekey_starts_while_a_pending_session_of_its_own_is_held() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::RekeyStart { hs: Hs(2) });
    j.step(Event::RekeyMsg2 {
        hs: Hs(2),
        epoch: E1,
    });
    j.step(Event::RekeyStart { hs: Hs(3) });
    assert_eq!(j.rekey, None);
}

#[test]
fn a_timed_out_attempt_or_reclaimed_handshake_closes_a_connection_no_link_uses() {
    let mut j = judge(SMALL);
    j.step(dial(1, 10, 7));
    j.step(hello(2, 11, 8));
    j.step(hello(3, 12, 8));
    assert_eq!(closes(&j.step(Event::Timeout { hs: Hs(1) })), [at(7)]);
    assert!(
        closes(&j.step(Event::Timeout { hs: Hs(2) })).is_empty(),
        "another handshake still uses the connection"
    );
    assert_eq!(closes(&j.step(Event::Timeout { hs: Hs(3) })), [at(8)]);
    assert!(j.needs().is_empty());
}

#[test]
fn a_lost_peer_is_removed_and_a_restart_forgets_everything() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    assert_eq!(j.step(Event::Lost).change, Some(Transition::Remove));
    assert!(j.peering.is_none());
    held_by_answer(&mut j, 2, 11, 7, E1);
    j.step(dial(3, 12, 8));
    j.step(Event::Restart);
    assert!(j.peering.is_none() && j.attempts.is_empty() && j.legs.is_empty());
}
