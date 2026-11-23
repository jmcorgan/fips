//! Tests of the XX flow at msg2: this node's dials, the anonymous ones
//! included, the decision parked until the msg3 is sent, the own-dial keep,
//! address order, the restart, the promote refusals, and the shell's
//! failures and refusals.

use super::*;
use crate::proto::settle::links::Dir;
use crate::proto::settle::output::{Build, Denial, Transition, Why};

#[test]
fn an_anonymous_dial_completes_under_the_identity_its_msg2_taught() {
    let mut a = node(small(), false);
    let link = opened(&xx(&mut a, anon_dial(1, 1), 0));
    assert_eq!(
        a.legs().get(link).and_then(|l| l.peer()),
        None,
        "precondition: the dial names no one"
    );
    let out = xx(&mut a, msg2(link, large(), E1, 1), 10);
    assert!(
        finals(&out, link),
        "defect: the anonymous dial's msg2 asks for no msg3: {out:?}"
    );
    let out = xx(&mut a, In::FinalSent { link }, 10);
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Install(i) if i.peer == large() && i.initiator)),
        "the identity the msg2 taught is installed as initiator: {out:?}"
    );
    assert_eq!(
        a.held(&large()).map(|h| h.link),
        Some(link),
        "held on the dial"
    );
}

/// next's `heard_on_session` starts afresh at a move. The smaller node,
/// heard before it moves onto its first dial, gets a msg2 on a further dial
/// that was in flight at the move: that dial is beside the new own dial,
/// unheard under its session, and is kept with no msg3.
#[test]
fn a_dial_in_flight_at_the_smaller_nodes_move_is_beside_its_new_own_dial_though_the_peer_was_heard_before()
 {
    let mut s = node(small(), false);
    held_by_answer(&mut s, large(), E1, 1, 1, 0);
    go(
        &mut s,
        Input::Heard {
            peer: large(),
            from: pair(1),
            kind: 0,
        },
        1_000,
    );
    let moved = opened(&go(&mut s, dial(large(), 2, 2), 2_000));
    let later = opened(&go(&mut s, dial(large(), 3, 3), 2_000));
    xx(&mut s, msg2(moved, large(), E1, 2), 3_000);
    let out = xx(&mut s, In::FinalSent { link: moved }, 3_000);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Move,
                ..
            }
        )),
        "precondition: the smaller node moves onto its first dial: {out:?}"
    );
    let out = xx(&mut s, msg2(later, large(), E1, 3), 4_000);
    assert!(
        !finals(&out, later),
        "defect: the dial in flight at the move sends a msg3: {out:?}"
    );
    assert_eq!(
        s.held(&large()).map(|h| h.link),
        Some(moved),
        "the peer stays on the dial it moved onto"
    );
}

#[test]
fn a_msg2_installs_nothing_until_its_msg3_is_sent() {
    let mut a = node(small(), false);
    let link = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let out = xx(&mut a, msg2(link, large(), E1, 1), 10);
    assert!(finals(&out, link), "the msg2 asks for the msg3: {out:?}");
    assert!(
        !installs(&out, large()),
        "defect: the msg2 installs before its msg3 send's outcome: {out:?}"
    );
    assert!(a.held(&large()).is_none(), "defect: nothing is held yet");
    let out = xx(&mut a, In::FinalSent { link }, 10);
    assert!(installs(&out, large()), "the send installs: {out:?}");
}

/// Records current behaviour (rule XX-06): open to change by decision. The
/// incidental part is the heard path offered; the own-dial keep with no msg3 is
/// not.
#[test]
fn a_msg2_beside_this_nodes_own_dial_is_kept_at_once_with_no_msg3_and_offers_its_pair() {
    let mut a = node(small(), false);
    let first = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let beside = opened(&go(&mut a, dial(large(), 2, 2), 0));
    xx(&mut a, msg2(first, large(), E1, 1), 10);
    let out = xx(&mut a, In::FinalSent { link: first }, 10);
    assert!(
        installs(&out, large()),
        "precondition: the first dial installs"
    );
    let out = xx(&mut a, msg2(beside, large(), E1, 2), 20);
    assert!(
        !finals(&out, beside),
        "defect: a msg2 beside this node's own unheard dial sends a msg3: {out:?}"
    );
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Flow(Out::Offer { peer, pair: p }) if *peer == large() && *p == pair(2))),
        "the msg2's pair is offered to the peer's link: {out:?}"
    );
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Keep,
                ..
            }
        )),
        "the peer is kept: {out:?}"
    );
    assert_eq!(
        a.held(&large()).map(|h| h.link),
        Some(first),
        "on its first dial"
    );
    assert!(
        a.legs().get(beside).is_none(),
        "the second dial is given up"
    );
}

#[test]
fn a_dial_in_flight_at_the_install_is_settled_by_address_order_once_the_peer_was_heard() {
    let mut a = node(small(), false);
    let first = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let beside = opened(&go(&mut a, dial(large(), 2, 2), 0));
    xx(&mut a, msg2(first, large(), E1, 1), 10);
    xx(&mut a, In::FinalSent { link: first }, 10);
    go(
        &mut a,
        Input::Heard {
            peer: large(),
            from: pair(1),
            kind: 0,
        },
        15,
    );
    let out = xx(&mut a, msg2(beside, large(), E1, 2), 20);
    assert!(
        finals(&out, beside),
        "a heard peer's second dial sends its msg3: {out:?}"
    );
    let out = xx(&mut a, In::FinalSent { link: beside }, 20);
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Swapped { own: true, .. })),
        "the smaller node moves onto its dial: {out:?}"
    );
}

/// Records current behaviour (rule XX-01): open to change by decision. The
/// incidental part is the larger node's msg3 at its keep; the smaller node's
/// move onto its later dial is not.
#[test]
fn a_later_dial_of_a_held_peer_is_settled_by_address_order_once_its_msg3_is_sent() {
    // The smaller node moves onto its dial.
    let mut a = node(small(), false);
    let first = held_by_dial(&mut a, large(), E1, 1, 1, 0);
    let later = opened(&go(&mut a, dial(large(), 2, 2), 10));
    let out = xx(&mut a, msg2(later, large(), E1, 2), 20);
    assert!(finals(&out, later), "a later dial sends its msg3: {out:?}");
    let out = xx(&mut a, In::FinalSent { link: later }, 20);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Install(i) if i.link == later && i.rekey == Build::FromCarry
        )),
        "the smaller node moves onto its later dial: {out:?}"
    );
    assert_eq!(a.held(&large()).map(|h| h.link), Some(later));
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Retire { link, .. } if *link == first)),
        "and retires the link it left: {out:?}"
    );
    // The larger node keeps the peer where it is.
    let mut b = node(large(), false);
    let first = held_by_dial(&mut b, small(), E1, 1, 1, 0);
    let later = opened(&go(&mut b, dial(small(), 2, 2), 10));
    let out = xx(&mut b, msg2(later, small(), E1, 2), 20);
    assert!(
        finals(&out, later),
        "the larger node sends its msg3 too: {out:?}"
    );
    let out = xx(&mut b, In::FinalSent { link: later }, 20);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Keep,
                ..
            }
        )),
        "the larger node keeps the peer: {out:?}"
    );
    assert_eq!(b.held(&small()).map(|h| h.link), Some(first));
}

#[test]
fn the_smaller_nodes_move_at_msg2_leaves_open_the_connection_its_dial_was_set_up_at() {
    // The peer dialed in from port 1 and is held there; this node's own
    // dial went to port 2, and the peer answers it from port 1.
    let mut a = node(small(), false);
    let held = held_by_answer(&mut a, large(), E1, 1, 1, 0);
    let later = opened(&go(&mut a, dial(large(), 2, 2), 10));
    xx(&mut a, msg2(later, large(), E1, 1), 20);
    let out = xx(&mut a, In::FinalSent { link: later }, 20);
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Swapped { own: false, .. })),
        "precondition: the smaller node moves onto its dial: {out:?}"
    );
    assert_eq!(
        a.held(&large()).map(|h| (h.link, h.current.clone())),
        Some((later, pair(1))),
        "held on the dial, at the msg2's pair"
    );
    assert!(
        retires_quietly(&out, held),
        "defect: the move closes the connection its dial was set up at, which next leaves open: {out:?}"
    );
    assert_eq!(
        a.links().get(later).map(|r| r.setup.clone()),
        Some(pair(2)),
        "the dial's link keeps the pair it was set up at"
    );
}

/// The smaller node's move closes the link it left, which here was set up
/// at the pair its dial was set up at too: that pair stays in the retire's
/// closes, since the retire of the link left chose it, though the move
/// leaves the dial's own connection open otherwise.
#[test]
fn the_smaller_nodes_move_at_msg2_closes_the_link_it_left_when_its_dial_was_set_up_at_the_same_pair()
 {
    // The peer dialed in from port 2 and is held there; this node's own
    // dial went to port 2 too, and the peer answers it from port 1.
    let mut a = node(small(), false);
    let held = held_by_answer(&mut a, large(), E1, 1, 2, 0);
    let later = opened(&go(&mut a, dial(large(), 2, 2), 10));
    xx(&mut a, msg2(later, large(), E1, 1), 20);
    let out = xx(&mut a, In::FinalSent { link: later }, 20);
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Swapped { own: false, .. })),
        "precondition: the smaller node moves onto its dial: {out:?}"
    );
    let closes = out.iter().find_map(|o| {
        if let Output::Retire { link, closes } = o
            && *link == held
        {
            Some(closes.clone())
        } else {
            None
        }
    });
    assert_eq!(
        closes,
        Some(alloc::vec![pair(2)]),
        "defect: the move leaves open the connection of the link it left: {out:?}"
    );
}

/// A failed dial expects by its timeout the identity its failure noted,
/// ahead of the one it named.
#[test]
fn a_failed_dial_past_its_deadline_asks_for_a_retry_of_the_identity_its_failure_noted() {
    let mut a = node(small(), false);
    let link = opened(&go(&mut a, dial(large(), 1, 1), 0));
    xx(
        &mut a,
        In::Failed {
            link,
            learned: Some(third()),
        },
        0,
    );
    let out = xx(&mut a, In::Due, 1_000_000);
    let retries: Vec<NodeAddr> = out
        .iter()
        .filter_map(|o| {
            if let Output::Retry { peer } = o {
                Some(*peer)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        retries,
        alloc::vec![third()],
        "defect: the timeout retries the identity the dial named, not the one its failure noted: {out:?}"
    );
}

#[test]
fn a_dial_past_its_deadline_asks_for_a_retry_of_the_identity_it_expects_before_its_reap() {
    let mut a = node(small(), false);
    let named = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let anon = opened(&xx(&mut a, anon_dial(2, 2), 0));
    xx(&mut a, msg2(anon, third(), E1, 2), 0);
    xx(&mut a, In::FinalFailed { link: anon }, 0);
    let answer = answered(&mut a, 3, 3, None, 0);
    let retries = |out: &[O]| {
        let mut peers: Vec<NodeAddr> = out
            .iter()
            .filter_map(|o| {
                if let Output::Retry { peer } = o {
                    Some(*peer)
                } else {
                    None
                }
            })
            .collect();
        peers.sort();
        peers
    };
    let out = xx(&mut a, In::Due, 10);
    assert!(retries(&out).is_empty(), "nothing is due yet: {out:?}");
    let late = 1_000_000;
    let out = xx(&mut a, In::Due, late);
    let mut want = alloc::vec![large(), third()];
    want.sort();
    assert_eq!(
        retries(&out),
        want,
        "defect: a dial past its deadline asks for no retry of the identity it named, or that its msg2 taught; an answer asks none"
    );
    let out = a.poll(t(late));
    for link in [named, anon, answer] {
        assert!(
            out.iter()
                .any(|o| matches!(o, Output::Retire { link: l, .. } if *l == link)),
            "the poll at the same instant reaps {link:?}: {out:?}"
        );
    }
    let out = xx(&mut a, In::Sweep, late);
    assert!(
        retries(&out).is_empty(),
        "the failed dial, reaped, is not swept again: {out:?}"
    );
}

#[test]
fn a_dial_its_timer_reaps_alone_asks_for_a_retry_of_the_identity_it_expects_and_an_answer_asks_none()
 {
    let mut a = node(small(), false);
    let named = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let anon = opened(&xx(&mut a, anon_dial(2, 2), 0));
    xx(&mut a, msg2(anon, third(), E1, 2), 0);
    xx(&mut a, In::FinalFailed { link: anon }, 0);
    let answer = answered(&mut a, 3, 3, None, 0);
    let retries = |out: &[O]| -> Vec<NodeAddr> {
        out.iter()
            .filter_map(|o| {
                if let Output::Retry { peer } = o {
                    Some(*peer)
                } else {
                    None
                }
            })
            .collect()
    };
    let out = xx(&mut a, In::Timed { link: named }, 10);
    assert_eq!(
        retries(&out),
        alloc::vec![large()],
        "defect: a dial its timer reaps alone asks for no retry of the identity it named: {out:?}"
    );
    let out = xx(&mut a, In::Timed { link: anon }, 10);
    assert_eq!(
        retries(&out),
        alloc::vec![third()],
        "defect: a failed dial its timer reaps asks for no retry of the identity its msg2 taught: {out:?}"
    );
    let out = xx(&mut a, In::Timed { link: answer }, 10);
    assert!(retries(&out).is_empty(), "an answer asks none: {out:?}");
    let out = xx(&mut a, In::Sweep, 10);
    assert!(
        retries(&out).is_empty(),
        "the failed dial its timer took is not swept again: {out:?}"
    );
}

#[test]
fn an_identified_dials_failed_connection_retries_the_identity_it_named_and_an_anonymous_ones_retries_none()
 {
    let mut a = node(small(), false);
    let named = opened(&go(
        &mut a,
        Input::Connecting {
            peer: large(),
            to: pair(1),
            resends: None,
        },
        0,
    ));
    let out = xx(
        &mut a,
        In::Unconnected {
            link: named,
            retry: Some(large()),
        },
        10,
    );
    assert!(
        retires_quietly(&out, named),
        "the link goes, closing nothing: {out:?}"
    );
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Retry { peer } if *peer == large())),
        "defect: an identified dial's failed connection asks for no retry: {out:?}"
    );
    let anon = opened(&xx(
        &mut a,
        In::AnonConnecting {
            to: pair(2),
            resends: None,
        },
        20,
    ));
    let out = xx(
        &mut a,
        In::Unconnected {
            link: anon,
            retry: None,
        },
        30,
    );
    assert!(
        retires_quietly(&out, anon),
        "the link goes, closing nothing: {out:?}"
    );
    assert!(
        !out.iter().any(|o| matches!(o, Output::Retry { .. })),
        "an anonymous dial's asks for none: {out:?}"
    );
}

#[test]
fn a_restarted_peers_msg2_replaces_it_with_no_gate() {
    let mut a = node(small(), false);
    held_by_dial(&mut a, large(), E1, 1, 1, 0);
    go(
        &mut a,
        Input::Heard {
            peer: large(),
            from: pair(1),
            kind: 0,
        },
        1_000,
    );
    let link = opened(&go(&mut a, dial(large(), 2, 2), 1_500));
    let out = xx(&mut a, msg2(link, large(), E2, 2), 2_000);
    assert!(finals(&out, link), "the restart sends its msg3: {out:?}");
    let out = xx(&mut a, In::FinalSent { link }, 2_000);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Remove {
                why: Why::OwnRestart,
                ..
            }
        )),
        "the restarted peer is removed though heard just now: {out:?}"
    );
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Replace,
                ..
            }
        )),
        "and replaced: {out:?}"
    );
    assert_eq!(a.held(&large()).map(|h| h.epoch), Some(E2));
}

/// Records current behaviour (rule XX-05): open to change by decision.
#[test]
fn a_leaf_refuses_a_second_peer_at_msg2_and_removes_the_link_at_once() {
    let mut a = node(small(), true);
    held_by_dial(&mut a, large(), E1, 1, 1, 0);
    let link = opened(&go(&mut a, dial(third(), 2, 2), 10));
    xx(&mut a, msg2(link, third(), E1, 2), 20);
    let out = xx(&mut a, In::FinalSent { link }, 20);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reject {
                why: Denial::Flow(super::super::Deny::Leaf),
                ..
            }
        )),
        "the leaf refuses a second peer: {out:?}"
    );
    assert!(
        a.legs().get(link).is_none(),
        "defect: the refused dial's leg is left for its reap: {out:?}"
    );
    assert!(
        retires_quietly(&out, link),
        "its link goes, closing nothing: {out:?}"
    );
    assert!(a.held(&third()).is_none(), "nothing installed");
}

#[test]
fn the_peer_cap_at_msg2_leaves_the_dials_leg_for_its_reap() {
    let params = Params {
        peers: 1,
        ..Params::default()
    };
    let mut a = node_with(small(), params);
    held_by_dial(&mut a, large(), E1, 1, 1, 0);
    let link = opened(&go(&mut a, dial(third(), 2, 2), 10));
    xx(&mut a, msg2(link, third(), E1, 2), 20);
    let out = xx(&mut a, In::FinalSent { link }, 20);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reject {
                why: Denial::Cap,
                ..
            }
        )),
        "the cap refuses: {out:?}"
    );
    assert!(a.legs().get(link).is_some(), "the leg is left for its reap");
    assert!(
        !out.iter().any(|o| matches!(o, Output::Retire { .. })),
        "nothing is retired yet: {out:?}"
    );
    let again = xx(&mut a, msg2(link, third(), E1, 2), 30);
    assert!(again.is_empty(), "nothing completes it: {again:?}");
    let out = a.poll(t(10 + 30_000));
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Retire { link: l, .. } if *l == link)),
        "the reap retires it: {out:?}"
    );
}

#[test]
fn a_msg2_from_a_static_other_than_the_one_dialed_keeps_the_leg() {
    let mut a = node(small(), false);
    let link = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let out = xx(&mut a, msg2(link, third(), E1, 1), 10);
    assert!(
        out.is_empty(),
        "the shell's refusal; the core does nothing: {out:?}"
    );
    assert!(a.legs().get(link).is_some(), "the leg stays");
    let out = xx(&mut a, msg2(link, large(), E1, 1), 20);
    assert!(
        finals(&out, link),
        "the dialed peer's msg2 still completes it"
    );
}

#[test]
fn a_failed_msg3_send_installs_nothing_and_the_sweep_retries_the_identity_the_msg2_taught() {
    let mut a = node(small(), false);
    let link = opened(&xx(&mut a, anon_dial(1, 1), 0));
    xx(&mut a, msg2(link, large(), E1, 1), 10);
    let out = xx(&mut a, In::FinalFailed { link }, 10);
    assert!(out.is_empty(), "nothing is installed: {out:?}");
    assert!(a.held(&large()).is_none(), "nothing is held");
    let out = xx(&mut a, In::FinalSent { link }, 10);
    assert!(out.is_empty(), "a late send outcome does nothing: {out:?}");
    let out = xx(&mut a, In::Sweep, 1_000);
    assert!(
        matches!(out.first(), Some(Output::Retry { peer }) if *peer == large()),
        "the sweep retries whom the msg2 taught first: {out:?}"
    );
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Retire { link: l, .. } if *l == link)),
        "and retires the leg's link: {out:?}"
    );
    assert!(a.legs().get(link).is_none(), "the leg is gone");
}

#[test]
fn a_refusal_at_msg2_ends_the_leg_at_once_closing_nothing_and_retries_whom_the_shell_names() {
    let mut a = node(small(), false);
    let link = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let out = xx(
        &mut a,
        In::Refused {
            link,
            retry: Some(large()),
        },
        10,
    );
    assert!(
        out.iter().any(|o| matches!(o, Output::Free { .. })),
        "the lease comes back: {out:?}"
    );
    assert!(retires_quietly(&out, link), "closing nothing: {out:?}");
    assert!(
        matches!(out.last(), Some(Output::Retry { peer }) if *peer == large()),
        "the retry the shell names: {out:?}"
    );
    let held = held_by_dial(&mut a, third(), E1, 2, 2, 20);
    let out = xx(
        &mut a,
        In::Refused {
            link: held,
            retry: None,
        },
        30,
    );
    assert!(
        out.is_empty(),
        "a held peer's link is no refusal's: {out:?}"
    );
    assert!(a.held(&third()).is_some());
}

#[test]
fn an_anonymous_dial_on_a_connection_starts_on_its_link_and_a_failed_connection_closes_nothing() {
    let mut a = node(small(), false);
    let link = opened(&xx(
        &mut a,
        In::AnonConnecting {
            to: pair(7),
            resends: Some(2),
        },
        0,
    ));
    assert_eq!(a.links().get(link).map(|r| r.dir), Some(Dir::Outbound));
    let out = xx(
        &mut a,
        In::AnonDial(AnonDial {
            to: pair(7),
            msg1: 1u32.to_be_bytes().to_vec(),
            lease: IndexLease::for_test(1),
            resends: None,
            link: Some(link),
        }),
        10,
    );
    assert!(
        out.is_empty(),
        "the dial starts on the link it waited on: {out:?}"
    );
    assert_eq!(a.legs().get(link).map(|l| l.resends()), Some(2));
    let other = opened(&xx(
        &mut a,
        In::AnonConnecting {
            to: pair(8),
            resends: None,
        },
        20,
    ));
    let out = xx(&mut a, In::AnonConnectFailed { link: other }, 30);
    assert!(retires_quietly(&out, other), "closing nothing: {out:?}");
}

/// A session this node dialed that ends before the peer's first frame is
/// not counted toward the peer's silent-session back-off: the peer may have
/// refused its msg3, and the peer's frames then had no session to arrive
/// on. A session the peer dialed still counts.
#[test]
fn a_dialed_session_that_ends_unheard_is_not_counted_silent_and_an_answered_one_is() {
    let mut a = node(small(), false);
    held_by_dial(&mut a, large(), E1, 1, 5, 0);
    go(&mut a, Input::Dead { peer: large() }, 50);
    assert!(
        a.held(&large()).is_none(),
        "precondition: the dial's peer is removed"
    );
    assert_eq!(
        a.gates().silent(&large()),
        None,
        "defect: the session this node dialed is counted against the peer"
    );
    held_by_answer(&mut a, large(), E1, 2, 6, 100);
    go(&mut a, Input::Dead { peer: large() }, 150);
    assert!(
        a.held(&large()).is_none(),
        "precondition: the answer's peer is removed"
    );
    assert_eq!(
        a.gates().silent(&large()),
        Some(1),
        "the session the peer dialed is counted"
    );
}
