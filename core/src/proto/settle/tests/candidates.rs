//! Candidate rules for two settlement cases, the late second dial and the
//! dial on the peer's aged link, run in the world on the scripted pins of
//! those cases. The rekey machine now answers the rekey after a dial on
//! the aged link under the core's own rules, since the peer's fresh rekey
//! displaces the pending the dial left; the aged move is kept as a
//! candidate, and its test shows what it still changes.
//!
//! The candidates are built into the core behind a test-only choice
//! (`Candidate` in `faults.rs`), each changing one decision:
//!
//! - **Dialer settle**, for the late second dial: the dialer keeps the
//!   session it moved off decryptable, and the peer's first frame under
//!   either session settles the one it keeps, as the model encodes the
//!   operator's rule. The comparison with the model keeps the model's
//!   fallback here, so the late second dial is no named difference.
//! - **Responder hold**, for the late second dial: a responder that
//!   replaced an unheard peering keeps the replaced session for 15 s, and
//!   the dialer's first frame under either settles the one it keeps; the
//!   dialer keeps the session it moved off as under the dialer's rule.
//! - **Aged move**, for the dial on the peer's aged link: an own dial
//!   completing for a peer held through a link old enough to rekey moves
//!   onto that dial, whatever the held link's direction.
//!
//! The candidate's nodes are joint nodes with multipath off
//! (`joint/party.rs`): the core under the candidate, with a real rekey
//! machine and bundle per held peer. A session the core keeps is the peer's
//! machines left as they are, receive-only, beside the machines the shell
//! builds for the session the peer is held on next, from what the kept ones
//! show and a copy of their replay record (`joint::machines::Machines::beside`).
//! That is a test's choice: the node has no second machine for one peer.
//!
//! The scripted pins of the two cases run under each candidate. Comparing
//! a candidate with the core's own rules across the starts, which the
//! retired explorers did, is left to a later decision. The tests need the
//! `slow-tests` feature.

use alloc::string::String;
use alloc::vec::Vec;

use super::super::faults::{Candidate, under_candidate};
use super::regress::{aged_pending_adopted, aged_rekey_answered, late_dial_splits};

/// The splits after each late second dial pin's schedule, with the core
/// at both ends running `c`.
fn late(c: Option<Candidate>) -> Vec<String> {
    under_candidate(c, || {
        [
            "second msg2 first, larger dialer",
            "second msg2 first, smaller dialer",
        ]
        .into_iter()
        .flat_map(|name| late_dial_splits(6, name))
        .collect()
    })
}

#[test]
fn both_late_dial_candidates_settle_a_late_second_dial_answered_in_the_other_order() {
    assert!(
        !late(None).is_empty(),
        "precondition: the core's own rules split there"
    );
    for c in [Candidate::DialerSettle, Candidate::ResponderHold] {
        let split = late(Some(c));
        assert!(split.is_empty(), "{c:?}: the two ends split: {split:?}");
    }
    let split = late(Some(Candidate::AgedMove));
    assert!(
        !split.is_empty(),
        "the aged move leaves the late second dial as it was"
    );
}

#[test]
fn the_aged_move_candidate_has_the_pending_a_dial_on_the_aged_link_leaves_adopted_and_every_rule_answers_the_rekey()
 {
    let adopted = |c| under_candidate(c, aged_pending_adopted);
    assert!(
        !adopted(None),
        "precondition: under the core's own rules node 1 keeps its session, so node 0's pending is not adopted"
    );
    assert!(
        adopted(Some(Candidate::AgedMove)),
        "under the aged move node 1 moves onto its dial and node 0 adopts the pending at its frame"
    );
    for c in [Candidate::DialerSettle, Candidate::ResponderHold] {
        assert!(
            !adopted(Some(c)),
            "{c:?} leaves the dial on the aged link as it was"
        );
    }
    // Node 1's next rekey displaces a pending left unadopted, so it is
    // answered under every rule, whether or not the frame arrived first.
    let answered = |c, frame_first| under_candidate(c, || aged_rekey_answered(frame_first));
    for c in [
        None,
        Some(Candidate::AgedMove),
        Some(Candidate::DialerSettle),
        Some(Candidate::ResponderHold),
    ] {
        for frame_first in [true, false] {
            assert!(
                answered(c, frame_first),
                "{c:?}, frame first {frame_first}: node 1's rekey was left unanswered"
            );
        }
    }
}
