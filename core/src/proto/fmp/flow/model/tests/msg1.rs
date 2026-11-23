//! FRC-2201 Section 5.2: a msg1 that passed admission draws the stored
//! msg2 when it is a duplicate, and otherwise opens its own handshake.

use super::super::judge::Reply;
use super::{E1, LARGE, SMALL, at, held_by_answer, hello, judge};

#[test]
fn a_duplicate_msg1_from_the_same_source_draws_the_stored_msg2_and_opens_no_handshake() {
    let mut j = judge(SMALL);
    assert_eq!(j.step(hello(1, 10, 7)).reply, Some(Reply::Msg2));
    let s = j.step(hello(1, 11, 7));
    assert_eq!(
        s.reply,
        Some(Reply::Stored),
        "a duplicate is answered with the msg2 built for it"
    );
    assert_eq!(j.legs.len(), 1, "a duplicate opens no second handshake");
}

#[test]
fn a_msg1_of_another_handshake_from_the_same_source_opens_its_own_beside_the_pending_one() {
    let mut j = judge(SMALL);
    j.step(hello(1, 10, 7));
    let s = j.step(hello(2, 11, 7));
    assert_eq!(
        s.reply,
        Some(Reply::Msg2),
        "it is answered as a new handshake"
    );
    assert_eq!(
        j.needs().len(),
        2,
        "the pending handshake is neither discarded nor replaced"
    );
}

#[test]
fn the_same_handshake_from_another_source_is_not_a_duplicate() {
    let mut j = judge(SMALL);
    j.step(hello(1, 10, 7));
    let s = j.step(hello(1, 11, 8));
    assert_eq!(s.reply, Some(Reply::Msg2));
    assert_eq!(j.legs.len(), 2);
}

#[test]
fn a_msg1_from_a_held_peers_address_opens_its_own_handshake_and_changes_nothing() {
    let mut j = judge(LARGE);
    held_by_answer(&mut j, 1, 10, 7, E1);
    let s = j.step(hello(2, 11, 7));
    assert_eq!(s.reply, Some(Reply::Msg2));
    assert_eq!(s.change, None, "a msg1 authenticates nobody");
    assert_eq!(j.settled().map(|(_, _, a)| a), Some(at(7)));
    assert_eq!(j.legs.len(), 1);
}
