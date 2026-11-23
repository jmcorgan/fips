//! FRC-2201 Sections 5.6, 5.7 and 7.3 at the responder: a completed msg3,
//! through the checks before classification, then classified by epoch,
//! declaration and who dialed the established link.

use super::super::history::{Claim, Epoch, Event, Hs, LinkId};
use super::super::judge::{Class, Judge, Refusal, Reply, Transition};
use super::{
    E1, E2, LARGE, SMALL, answer, at, closes, dial, frame, held_by_answer, held_by_dial, hello,
    holds, judge, last,
};

#[test]
fn a_msg3_of_an_identity_not_held_installs_whatever_it_declares() {
    for claim in [Claim::None, Claim::Held, Claim::Other] {
        let mut j = judge(SMALL);
        j.step(hello(1, 10, 7));
        let s = j.step(last(1, E1, claim));
        assert_eq!(s.class, Some(Class::NotHeld), "{claim:?}");
        assert_eq!(s.change, Some(Transition::Promote), "{claim:?}");
        assert_eq!(s.reply, Some(Reply::Silent), "{claim:?}");
        assert_eq!(holds(&j), Some((Hs(1), LinkId(10))), "{claim:?}");
    }
}

#[test]
fn a_msg3_refused_before_classification_is_abandoned_silently_and_closes_its_connection() {
    let mut j = judge(SMALL);
    j.step(hello(1, 10, 7));
    let s = j.step(Event::Msg3 {
        hs: Hs(1),
        epoch: E1,
        claim: Claim::None,
        refused: true,
    });
    assert_eq!(s.refused, Some(Refusal::Declined));
    assert_eq!(s.reply, Some(Reply::Silent));
    assert!(
        !s.disconnect,
        "a refusal sends nothing, a Disconnect included"
    );
    assert_eq!(closes(&s), [at(7)]);
    assert!(j.peering.is_none() && j.legs.is_empty());
}

#[test]
fn a_msg3_restart_inside_the_interval_of_a_frame_is_refused_and_its_link_torn_down() {
    let mut j = judge(LARGE);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(frame(1, 7));
    j.step(Event::Advance(14_999));
    j.step(hello(2, 11, 8));
    let s = j.step(last(2, E2, Claim::None));
    assert_eq!(s.class, Some(Class::Restart));
    assert_eq!(s.refused, Some(Refusal::Heard));
    assert_eq!(closes(&s), [at(8)]);
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
    assert_eq!(j.stamp, None, "a refusal stamps nothing");
}

#[test]
fn a_msg3_restart_inside_the_dampener_is_refused() {
    let mut j = judge(LARGE);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::Advance(20_000));
    j.step(hello(2, 11, 8));
    j.step(last(2, E2, Claim::None));
    j.step(Event::Advance(14_999));
    j.step(hello(3, 12, 9));
    let s = j.step(last(3, Epoch(3), Claim::None));
    assert_eq!(s.refused, Some(Refusal::Dampened));
    assert_eq!(holds(&j), Some((Hs(2), LinkId(11))));
}

#[test]
fn a_msg3_restart_past_both_gates_replaces_the_peer_and_stamps_the_dampener() {
    let mut j = judge(SMALL);
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(Event::Advance(15_000));
    j.step(hello(2, 11, 8));
    let s = j.step(last(2, E2, Claim::None));
    assert_eq!(s.class, Some(Class::Restart));
    assert_eq!(s.change, Some(Transition::Replace));
    assert_eq!(closes(&s), [at(7)]);
    assert_eq!(j.stamp, Some(15_000));
    assert_eq!(holds(&j), Some((Hs(2), LinkId(11))));
}

#[test]
fn a_restart_is_classified_before_the_declaration() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::Advance(20_000));
    j.step(hello(2, 11, 7));
    let s = j.step(last(2, E2, Claim::Held));
    assert_eq!(s.class, Some(Class::Restart), "rule 1 before rule 3");
    assert_eq!(s.change, Some(Transition::Replace));
}

#[test]
fn a_claim_of_another_session_keeps_the_session_and_resends_the_stored_msg2() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(hello(2, 11, 7));
    let s = j.step(last(2, E1, Claim::Other));
    assert_eq!(s.class, Some(Class::Stale));
    assert_eq!(s.reply, Some(Reply::Stored));
    assert_eq!(s.change, None);
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
}

#[test]
fn a_claim_of_the_session_held_is_the_peers_rekey_left_pending_until_its_frame() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(hello(2, 11, 7));
    let s = j.step(last(2, E1, Claim::Held));
    assert_eq!(s.class, Some(Class::Rekey));
    assert_eq!(s.change, Some(Transition::Rekey));
    assert!(
        closes(&s).is_empty(),
        "the rekey runs on the established link"
    );
    assert_eq!(
        holds(&j),
        Some((Hs(1), LinkId(10))),
        "the responder does not lead"
    );
    let s = j.step(frame(2, 7));
    assert_eq!(s.change, Some(Transition::RekeyCutover));
    assert_eq!(holds(&j), Some((Hs(2), LinkId(10))), "the link stays");
}

#[test]
fn the_larger_node_of_a_simultaneous_rekey_abandons_its_own_and_answers_the_peers() {
    let mut j = judge(LARGE);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::RekeyStart { hs: Hs(9) });
    j.step(hello(2, 11, 7));
    let s = j.step(last(2, E1, Claim::Held));
    assert_eq!(s.change, Some(Transition::Rekey));
    assert_eq!(j.rekey, None, "its own rekey is abandoned");
    assert_eq!(j.peering.and_then(|p| p.pending).map(|d| d.hs), Some(Hs(2)));
}

#[test]
fn the_smaller_node_of_a_simultaneous_rekey_drops_the_peers_msg3() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::RekeyStart { hs: Hs(9) });
    j.step(hello(2, 11, 7));
    let s = j.step(last(2, E1, Claim::Held));
    assert_eq!(s.refused, Some(Refusal::Tied));
    assert_eq!(s.change, None);
    assert_eq!(j.rekey, Some(Hs(9)), "it keeps its own rekey");
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    j.step(Event::RekeyStart { hs: Hs(9) });
    j.step(Event::RekeyMsg2 {
        hs: Hs(9),
        epoch: E1,
    });
    j.step(hello(2, 11, 7));
    let s = j.step(last(2, E1, Claim::Held));
    assert_eq!(
        s.refused,
        Some(Refusal::Tied),
        "a pending session it initiated counts as its own rekey"
    );
}

#[test]
fn the_larger_node_completing_its_inbound_second_moves_onto_it_and_closes_its_own_link() {
    let mut j = judge(LARGE);
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(hello(2, 11, 8));
    let s = j.step(last(2, E1, Claim::None));
    assert_eq!(s.class, Some(Class::Crossing));
    assert_eq!(s.change, Some(Transition::Move));
    assert_eq!(closes(&s), [at(7)]);
    assert!(!s.disconnect);
    assert_eq!(holds(&j), Some((Hs(2), LinkId(11))));
}

#[test]
fn the_smaller_node_completing_its_inbound_second_keeps_its_own_link() {
    let mut j = judge(SMALL);
    held_by_dial(&mut j, 1, 10, 7, E1);
    j.step(hello(2, 11, 8));
    let s = j.step(last(2, E1, Claim::None));
    assert_eq!(s.class, Some(Class::Crossing));
    assert_eq!(s.change, Some(Transition::Keep));
    assert_eq!(
        closes(&s),
        [at(8)],
        "the losing handshake's link is torn down"
    );
    assert_eq!(holds(&j), Some((Hs(1), LinkId(10))));
}

#[test]
fn a_second_handshake_dialed_by_the_peer_moves_the_responder_onto_it_in_either_order() {
    for me in [SMALL, LARGE] {
        let mut j = judge(me);
        held_by_answer(&mut j, 1, 10, 7, E1);
        j.step(frame(1, 7));
        j.step(hello(2, 11, 8));
        let s = j.step(last(2, E1, Claim::None));
        assert_eq!(s.class, Some(Class::SameSide), "{me:?}");
        assert_eq!(s.change, Some(Transition::Move), "{me:?}: live or not");
        assert_eq!(closes(&s), [at(7)], "{me:?}");
        assert_eq!(holds(&j), Some((Hs(2), LinkId(11))), "{me:?}");
    }
}

#[test]
fn a_msg3_of_no_pending_handshake_is_dropped() {
    let mut j = judge(SMALL);
    held_by_answer(&mut j, 1, 10, 7, E1);
    let s = j.step(last(1, E1, Claim::None));
    assert_eq!(s.class, None, "a completed handshake's msg3 is dropped");
    assert_eq!(s.change, None);
}

/// One end's completion in a simultaneous dial.
#[derive(Clone, Copy, Debug)]
enum Turn {
    /// The smaller node reads the msg2 of its dial.
    SmallMsg2,
    /// The larger node reads the msg2 of its dial.
    LargeMsg2,
    /// The smaller node reads the larger's msg3, if the larger sent one.
    SmallMsg3,
    /// The larger node reads the smaller's msg3, if the smaller sent one.
    LargeMsg3,
}

/// Both ends of a simultaneous dial, each a judge: the smaller node's dial
/// is handshake 1 and the larger's handshake 2, each at the other's
/// address, completed in `order`.
fn crossed(order: &[Turn]) -> (Judge, Judge) {
    let mut s = judge(SMALL);
    let mut l = judge(LARGE);
    s.step(dial(1, 11, 8));
    l.step(dial(2, 21, 7));
    s.step(hello(2, 12, 8));
    l.step(hello(1, 22, 7));
    let (mut sent_s, mut sent_l) = (false, false);
    for turn in order {
        match turn {
            Turn::SmallMsg2 => sent_s = s.step(answer(1, E1)).reply == Some(Reply::Final),
            Turn::LargeMsg2 => sent_l = l.step(answer(2, E1)).reply == Some(Reply::Final),
            Turn::SmallMsg3 if sent_l => {
                s.step(last(2, E1, Claim::None));
            }
            Turn::LargeMsg3 if sent_s => {
                l.step(last(1, E1, Claim::None));
            }
            Turn::SmallMsg3 | Turn::LargeMsg3 => {}
        }
    }
    (s, l)
}

#[test]
fn both_ends_of_a_simultaneous_dial_settle_on_the_smaller_nodes_dial_in_every_order() {
    use Turn::{LargeMsg2, LargeMsg3, SmallMsg2, SmallMsg3};
    for order in [
        [SmallMsg2, LargeMsg2, SmallMsg3, LargeMsg3],
        [SmallMsg2, LargeMsg3, LargeMsg2, SmallMsg3],
        [LargeMsg2, SmallMsg3, SmallMsg2, LargeMsg3],
        [SmallMsg2, LargeMsg2, LargeMsg3, SmallMsg3],
        [LargeMsg2, SmallMsg2, SmallMsg3, LargeMsg3],
    ] {
        let (s, l) = crossed(&order);
        assert_eq!(s.settled().map(|x| x.0), Some(Hs(1)), "{order:?}");
        assert_eq!(l.settled().map(|x| x.0), Some(Hs(1)), "{order:?}");
    }
}
