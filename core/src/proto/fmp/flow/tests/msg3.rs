//! Tests of the XX flow at msg3: the promote, the restart gate, the claims,
//! the crossing, the silent-session refusal, and the promote refusals.

use super::*;
use crate::proto::settle::gates::Refusal;
use crate::proto::settle::output::{Build, Denial, Transition, Why};

/// Whether `out` refuses with `why`.
fn rejects(out: &[O], why: Denial<super::super::Deny>) -> bool {
    out.iter()
        .any(|o| matches!(o, Output::Reject { why: w, .. } if *w == why))
}

/// A frame of `peer` from `port` at `at`.
fn frame(table: &mut T, peer: NodeAddr, port: u16, at: u64) {
    go(
        table,
        Input::Heard {
            peer,
            from: pair(port),
            kind: 0,
        },
        at,
    );
}

#[test]
fn a_msg3_from_an_identity_not_held_installs_it_as_responder() {
    let mut a = node(large(), false);
    let link = answered(&mut a, 1, 5, None, 0);
    let out = xx(&mut a, msg3(link, small(), E1, RekeyClaim::None, 5), 10);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Install(i) if i.peer == small()
                && i.link == link
                && !i.initiator
                && i.rekey == Build::Fresh
                && i.pair == pair(5)
        )),
        "installed as responder on the answer's link: {out:?}"
    );
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Promote,
                ..
            }
        )),
        "a promote: {out:?}"
    );
    assert!(a.legs().get(link).is_none(), "the leg is done");
    assert!(a.flow().answer(link).is_none(), "and so is the answer");
    let again = xx(&mut a, msg3(link, small(), E1, RekeyClaim::None, 5), 20);
    assert!(again.is_empty(), "a copy finds no answer: {again:?}");
}

#[test]
fn a_restart_at_msg3_is_refused_while_the_peering_was_heard_inside_the_interval_and_accepted_after()
{
    let mut a = node(small(), false);
    let first = held_by_answer(&mut a, large(), E1, 1, 5, 0);
    frame(&mut a, large(), 5, 5_000);
    let link = answered(&mut a, 2, 6, None, 10_000);
    let out = xx(&mut a, msg3(link, large(), E2, RekeyClaim::None, 6), 19_999);
    assert!(
        rejects(&out, Denial::Gate(Refusal::Heard)),
        "defect: a restart is accepted 15 s inside the last frame: {out:?}"
    );
    assert!(
        retires_quietly(&out, link),
        "the answer goes, closing nothing"
    );
    assert_eq!(
        a.held(&large()).map(|h| h.link),
        Some(first),
        "the peer stays"
    );
    let link = answered(&mut a, 3, 7, None, 20_000);
    let out = xx(&mut a, msg3(link, large(), E2, RekeyClaim::None, 7), 20_000);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Remove {
                why: Why::Restart,
                ..
            }
        )),
        "15 s after the last frame the restart is accepted: {out:?}"
    );
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Replace,
                ..
            }
        )),
        "and replaces the peer: {out:?}"
    );
    assert_eq!(a.held(&large()).map(|h| h.epoch), Some(E2));
    assert_eq!(
        a.gates().stamp(&large()),
        Some(t(20_000)),
        "the accepted restart stamps the dampener"
    );
}

/// Records current behaviour (rule XX-02): open to change by decision.
#[test]
fn a_restart_at_msg3_is_refused_inside_the_interval_from_the_install_when_no_frame_was_heard() {
    let mut a = node(small(), false);
    held_by_answer(&mut a, large(), E1, 1, 5, 1_000);
    let link = answered(&mut a, 2, 6, None, 2_000);
    let out = xx(&mut a, msg3(link, large(), E2, RekeyClaim::None, 6), 15_999);
    assert!(
        rejects(&out, Denial::Gate(Refusal::Heard)),
        "defect: an unheard peering installed under 15 s ago is restarted: {out:?}"
    );
    let link = answered(&mut a, 3, 7, None, 16_000);
    let out = xx(&mut a, msg3(link, large(), E2, RekeyClaim::None, 7), 16_000);
    assert!(
        installs(&out, large()),
        "15 s from the install it is accepted: {out:?}"
    );
}

#[test]
fn a_msg3_claiming_a_session_not_held_repeats_the_stored_msg2_and_leaves_the_peer() {
    let mut a = node(small(), false);
    let first = held_by_answer(&mut a, large(), E1, 1, 5, 0);
    let link = answered(&mut a, 2, 6, None, 10);
    let out = xx(&mut a, msg3(link, large(), E1, RekeyClaim::Mismatch, 6), 20);
    assert!(
        a.held(&large()).map(|h| h.link) == Some(first) && !installs(&out, large()),
        "defect: a mismatched claim replaced the peer: {out:?}"
    );
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Flow(Out::Repeat { peer, link: l }) if *peer == large() && *l == link)),
        "the held peer's stored msg2 is repeated on the msg3's connection: {out:?}"
    );
    assert!(
        retires_quietly(&out, link),
        "the answer goes, closing nothing"
    );
}

#[test]
fn a_msg3_claiming_the_session_held_hands_the_leg_and_its_lease_to_the_peers_rekey() {
    let mut a = node(small(), false);
    let first = held_by_answer(&mut a, large(), E1, 1, 5, 0);
    let link = answered(&mut a, 2, 6, None, 10);
    let out = xx(&mut a, msg3(link, large(), E1, RekeyClaim::Matches, 6), 20);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Flow(Out::Rekey { peer, link: l, lease }) if *peer == large() && *l == link && lease.index() == 2
        )),
        "defect: the claimed rekey does not reach the peer's machine with the leg's lease: {out:?}"
    );
    assert!(
        retires_quietly(&out, link),
        "the answer's link goes, closing nothing"
    );
    assert_eq!(
        a.held(&large()).map(|h| h.link),
        Some(first),
        "the peer stays"
    );
}

#[test]
fn a_crossing_at_msg3_moves_the_larger_node_onto_its_inbound_session_and_keeps_the_smaller_on_its_own()
 {
    // The larger node holds the peer on its own dial and moves.
    let mut b = node(large(), false);
    let own = held_by_dial(&mut b, small(), E1, 1, 1, 0);
    let link = answered(&mut b, 2, 3, None, 10);
    let out = xx(&mut b, msg3(link, small(), E1, RekeyClaim::None, 4), 20);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Install(i) if i.link == link && i.pair == pair(4) && !i.initiator && i.rekey == Build::FromCarry
        )),
        "the larger node moves onto the answer at the msg3's pair: {out:?}"
    );
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Move,
                ..
            }
        )),
        "as a move, the column next's node runs: {out:?}"
    );
    assert!(
        retires_quietly(&out, own),
        "its own dial's link goes, closing nothing: {out:?}"
    );
    assert_eq!(b.held(&small()).map(|h| h.link), Some(link));
    // The smaller node keeps its own dial and drops the answer.
    let mut a = node(small(), false);
    let own = held_by_dial(&mut a, large(), E1, 1, 1, 0);
    let link = answered(&mut a, 2, 3, None, 10);
    let out = xx(&mut a, msg3(link, large(), E1, RekeyClaim::None, 3), 20);
    assert!(!installs(&out, large()), "nothing installed: {out:?}");
    assert!(
        retires_quietly(&out, link),
        "the answer goes, closing nothing"
    );
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Keep,
                ..
            }
        )),
        "as a keep, the column next's node runs: {out:?}"
    );
    assert_eq!(a.held(&large()).map(|h| h.link), Some(own));
}

/// Records current behaviour (rule XX-03): open to change by decision. The
/// incidental part is the count that refuses; the refusal at msg3 is not.
#[test]
fn a_silent_identitys_msg3_is_refused_at_the_epoch_it_counted_and_promoted_at_another() {
    let mut a = node(large(), false);
    for n in 1..=3u32 {
        let at = u64::from(n) * 100;
        held_by_answer(&mut a, small(), E1, n, 5, at);
        go(&mut a, Input::Dead { peer: small() }, at + 50);
    }
    assert!(
        a.gates().silenced(&small(), Some(E1), t(400)),
        "precondition: three silent sessions start the refusal"
    );
    let link = answered(&mut a, 4, 5, None, 400);
    let out = xx(&mut a, msg3(link, small(), E1, RekeyClaim::None, 5), 400);
    assert!(
        rejects(&out, Denial::Gate(Refusal::Silent)),
        "refused at the counted epoch: {out:?}"
    );
    assert!(
        retires_quietly(&out, link),
        "the answer goes, closing nothing"
    );
    let link = answered(&mut a, 5, 5, None, 500);
    let out = xx(&mut a, msg3(link, small(), E2, RekeyClaim::None, 5), 500);
    assert!(
        installs(&out, small()),
        "defect: a msg3 at another epoch is refused for the old one's silence: {out:?}"
    );
}

/// Records current behaviour (rule XX-05): open to change by decision.
#[test]
fn a_leaf_refuses_a_second_peer_at_msg3_and_removes_the_link_at_once() {
    let mut a = node(small(), true);
    held_by_answer(&mut a, large(), E1, 1, 5, 0);
    let link = answered(&mut a, 2, 6, None, 10);
    let out = xx(&mut a, msg3(link, third(), E1, RekeyClaim::None, 6), 20);
    assert!(
        rejects(&out, Denial::Flow(super::super::Deny::Leaf)),
        "the leaf refuses: {out:?}"
    );
    assert!(
        a.legs().get(link).is_none(),
        "defect: the refused answer's leg is left for its reap: {out:?}"
    );
    assert!(retires_quietly(&out, link), "closing nothing: {out:?}");
}

#[test]
fn the_peer_cap_at_msg3_leaves_the_answer_for_its_reap() {
    let params = Params {
        peers: 1,
        ..Params::default()
    };
    let mut a = node_with(small(), params);
    held_by_answer(&mut a, large(), E1, 1, 5, 0);
    let link = answered(&mut a, 2, 6, None, 10);
    let out = xx(&mut a, msg3(link, third(), E1, RekeyClaim::None, 6), 20);
    assert!(rejects(&out, Denial::Cap), "the cap refuses: {out:?}");
    assert!(a.legs().get(link).is_some(), "the leg is left for its reap");
    let again = xx(&mut a, msg3(link, third(), E1, RekeyClaim::None, 6), 30);
    assert!(again.is_empty(), "nothing completes it: {again:?}");
}

#[test]
fn a_msg3_for_no_anonymous_answer_changes_nothing() {
    let mut a = node(small(), false);
    let dial = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let out = xx(&mut a, msg3(dial, large(), E1, RekeyClaim::None, 1), 10);
    assert!(out.is_empty(), "a dial's link is no answer: {out:?}");
    let out = xx(
        &mut a,
        msg3(LinkNo(99), large(), E1, RekeyClaim::None, 1),
        10,
    );
    assert!(out.is_empty(), "nor is an unknown one: {out:?}");
}
