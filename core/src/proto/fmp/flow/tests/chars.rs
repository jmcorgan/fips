//! Characterisations of where the XX flow on the shared table meets next's
//! code: the stored answer's byte rule, the silent-session record against
//! the gates' memory, the admission cap's count, the crossing's guards, the
//! install mark against next's `predates`, the retry after each failure at
//! msg2, the shell's refusals, and next's restart floor against the gate.

use super::*;
use crate::proto::fmp::SilentSessions;
use crate::proto::settle::gates::{Ask, Gates, Liveness, Source};
use crate::proto::settle::links::Holder;

#[test]
fn a_resend_of_the_answered_msg1_draws_the_stored_msg2_until_its_msg3_and_no_other_msg1_does() {
    let mut a = node(large(), false);
    let link = answered(&mut a, 1, 5, None, 0);
    let arrived = |n: u32, port: u16| Input::Arrived {
        from: pair(port),
        bytes: n.to_be_bytes().to_vec(),
    };
    let stored = |out: &[O]| {
        out.iter().any(|o| {
            matches!(o, Output::Answer { link: l, msg2, stored: true } if *l == link && *msg2 == answer(1))
        })
    };
    let out = go(&mut a, arrived(1, 5), 10);
    assert!(stored(&out), "the same bytes draw the stored msg2: {out:?}");
    let out = go(&mut a, arrived(2, 5), 10);
    assert!(
        !stored(&out),
        "other bytes from the address draw nothing, unsent though the answer is (the IK flow answers any): {out:?}"
    );
    let out = go(&mut a, arrived(1, 6), 10);
    assert!(
        !stored(&out),
        "nor do the same bytes from another address: {out:?}"
    );
    go(&mut a, Input::Sent { link }, 20);
    let out = go(&mut a, arrived(1, 5), 30);
    assert!(
        stored(&out),
        "once sent, the same bytes still draw it: {out:?}"
    );
    xx(&mut a, msg3(link, small(), E1, RekeyClaim::None, 5), 40);
    let out = go(&mut a, arrived(1, 5), 50);
    assert!(
        out.is_empty(),
        "after the msg3, a held peer's link answers no msg1 here: {out:?}"
    );
}

/// Records current behaviour (rule XX-03): open to change by decision.
#[test]
fn the_gates_count_silent_sessions_and_refuse_as_nexts_silent_sessions_record_does() {
    let params = super::super::params(Params::default());
    let mut gates: Gates<TestInstant> = Gates::new();
    let mut record = SilentSessions::new();
    let peer = small();
    // (instant in ms, epoch, setup ephemeral), with a repeated setup, an
    // epoch change, and gaps past the refusal and past the record's
    // horizon.
    let ends: &[(u64, Epoch, Option<u32>)] = &[
        (1_000, E1, Some(1)),
        (2_000, E1, Some(2)),
        (2_500, E1, Some(2)),
        (3_000, E1, Some(3)),
        (40_000, E1, Some(4)),
        (41_000, E1, None),
        (50_000, E2, Some(5)),
        (51_000, E2, Some(6)),
        (52_000, E2, Some(7)),
        (2_000_000, E2, Some(8)),
    ];
    let probes = [0u64, 1, 500, 29_999, 30_000, 31_000, 100_000, 700_000];
    for &(at, epoch, setup) in ends {
        let setup = setup.map(eph);
        gates.ended(peer, Some(epoch), setup, t(at), None, &params);
        record.ended(peer, Some(epoch), setup, at);
        assert_eq!(
            gates.silent(&peer),
            record.count(&peer),
            "the count after the session ended at {at}"
        );
        for d in probes {
            let now = at + d;
            let ours = gates.refusing(&peer, t(now));
            let next = record.refusing(&peer, now);
            assert_eq!(
                ours.map(|s| (s.epoch, s.silent, s.remaining.as_millis() as u64)),
                next.map(|b| (b.epoch, b.silent, b.remaining_ms)),
                "the refusal at {now}, after the session ended at {at}"
            );
        }
    }
    gates.heard(&peer);
    record.heard(&peer);
    assert_eq!(
        gates.silent(&peer),
        record.count(&peer),
        "a frame forgets both"
    );
}

#[test]
fn the_admission_cap_counts_asks_and_unsent_answers_and_a_sent_answer_frees_its_place() {
    let params = Params {
        pending: 2,
        ..Params::default()
    };
    let mut a = node_with(large(), params);
    let ask = asked(&xx(&mut a, anon(1, 5, None), 0));
    let link = answered(&mut a, 2, 6, None, 0);
    let stranger = Input::Arrived {
        from: pair(7),
        bytes: 9u32.to_be_bytes().to_vec(),
    };
    let full = |out: &[O]| {
        out.iter().any(|o| {
            matches!(
                o,
                Output::Reject {
                    why: crate::proto::settle::output::Denial::Full,
                    ..
                }
            )
        })
    };
    let out = go(&mut a, stranger.clone_input(), 10);
    assert!(
        full(&out),
        "an ask and an unsent answer fill a cap of two: {out:?}"
    );
    go(&mut a, Input::Sent { link }, 20);
    let out = go(&mut a, stranger.clone_input(), 30);
    assert!(!full(&out), "the sent answer frees its place: {out:?}");
    xx(
        &mut a,
        In::Refused {
            link: ask,
            retry: None,
        },
        40,
    );
    assert!(
        a.links().get(ask).is_none(),
        "the refused ask's link is gone"
    );
}

/// A copy of an `Arrived` input, which is all this file copies.
trait CloneInput {
    /// The copy.
    fn clone_input(&self) -> Input<In>;
}

impl CloneInput for Input<In> {
    fn clone_input(&self) -> Input<In> {
        let Input::Arrived { from, bytes } = self else {
            panic!("precondition: only an arrival is copied");
        };
        Input::Arrived {
            from: from.clone(),
            bytes: bytes.clone(),
        }
    }
}

#[test]
fn every_answers_link_is_its_own_so_the_crossings_guards_are_always_true() {
    let mut a = node(small(), false);
    let held = held_by_dial(&mut a, large(), E1, 1, 5, 0);
    for (n, port) in [(2u32, 5u16), (3, 5), (4, 6)] {
        let link = answered(&mut a, n, port, Some(held), 10);
        assert_ne!(link, held, "an answer's link is never the held link");
        assert_eq!(
            a.links().get(link).map(|r| r.holder),
            Some(Holder::Leg),
            "its leg holds it, not a peer"
        );
        assert!(
            a.held(&large()).is_some(),
            "and the peer it may cross is held, so holds a session"
        );
    }
}

#[test]
fn a_dial_predates_the_session_held_exactly_when_opened_before_its_install_or_move() {
    let mut a = node(small(), false);
    let before = opened(&xx(&mut a, anon_dial(1, 1), 0));
    let held = held_by_dial(&mut a, large(), E1, 2, 2, 10);
    assert!(
        a.flow().predates(&large(), before),
        "an anonymous dial in flight at the install predates it"
    );
    let after = opened(&xx(&mut a, anon_dial(3, 3), 20));
    assert!(
        !a.flow().predates(&large(), after),
        "an anonymous dial opened after the install does not, as next's link-id mark says"
    );
    assert_eq!(
        a.legs().get(after).and_then(|l| l.held()),
        None,
        "though its leg records no held link, so the held link the leg records cannot stand for the mark"
    );
    let named = opened(&go(&mut a, dial(large(), 4, 4), 30));
    assert!(
        !a.flow().predates(&large(), named),
        "nor does an identified one"
    );
    // A move takes a fresh mark: the smaller node moves onto a later dial.
    xx(&mut a, msg2(named, large(), E1, 4), 40);
    xx(&mut a, In::FinalSent { link: named }, 40);
    assert_eq!(a.held(&large()).map(|h| h.link), Some(named));
    assert_ne!(named, held);
    assert!(
        a.flow().predates(&large(), after),
        "a dial in flight at the move predates the session moved onto"
    );
}

/// Records current behaviour (rule XX-04): open to change by decision.
#[test]
fn the_retry_after_each_failure_at_msg2_goes_to_the_identity_the_leg_expects_by_then() {
    let retried = |out: &[O]| {
        out.iter().find_map(|o| {
            if let Output::Retry { peer } = o {
                Some(*peer)
            } else {
                None
            }
        })
    };
    // A completion that failed before it learned anyone: the identified
    // dial retries whom it dialed, the anonymous one no one.
    let mut a = node(small(), false);
    let named = opened(&go(&mut a, dial(large(), 1, 1), 0));
    let anon = opened(&xx(&mut a, anon_dial(2, 2), 0));
    xx(
        &mut a,
        In::Failed {
            link: named,
            learned: None,
        },
        10,
    );
    xx(
        &mut a,
        In::Failed {
            link: anon,
            learned: None,
        },
        10,
    );
    let out = xx(&mut a, In::Sweep, 20);
    assert_eq!(retried(&out), Some(large()), "whom the dial named: {out:?}");
    assert_eq!(
        out.iter()
            .filter(|o| matches!(o, Output::Retry { .. }))
            .count(),
        1,
        "and no retry for the anonymous dial: {out:?}"
    );
    // A completion or negotiation that failed after it learned the
    // answering static: next's leg expects that identity then.
    let anon = opened(&xx(&mut a, anon_dial(3, 3), 30));
    xx(
        &mut a,
        In::Failed {
            link: anon,
            learned: Some(third()),
        },
        40,
    );
    let out = xx(&mut a, In::Sweep, 50);
    assert_eq!(
        retried(&out),
        Some(third()),
        "whom the completion learned: {out:?}"
    );
    // A failed msg3 send: the identity the msg2 taught.
    let anon = opened(&xx(&mut a, anon_dial(4, 4), 60));
    xx(&mut a, msg2(anon, large(), E1, 4), 70);
    xx(&mut a, In::FinalFailed { link: anon }, 70);
    let out = xx(&mut a, In::Sweep, 80);
    assert_eq!(
        retried(&out),
        Some(large()),
        "whom the msg2 taught: {out:?}"
    );
    // The self check at msg2: next retries the learned identity, which the
    // shell names, and the flow retries exactly that.
    let anon = opened(&xx(&mut a, anon_dial(5, 5), 90));
    let out = xx(
        &mut a,
        In::Refused {
            link: anon,
            retry: Some(small()),
        },
        100,
    );
    assert_eq!(
        retried(&out),
        Some(small()),
        "whom the shell names: {out:?}"
    );
}

#[test]
fn an_anonymous_msg1_whose_index_could_not_be_drawn_retires_its_link_closing_nothing_and_takes_no_lease()
 {
    let mut a = node(large(), false);
    let link = asked(&xx(&mut a, anon(1, 5, None), 0));
    let out = xx(&mut a, In::Refused { link, retry: None }, 0);
    assert!(
        matches!(out.as_slice(), [Output::Retire { link: l, closes }] if *l == link && closes.is_empty()),
        "only the link goes, closing nothing, with no lease and no retry: {out:?}"
    );
    assert!(a.links().get(link).is_none(), "the link record is gone");
    let late = xx(&mut a, hello(link, 1), 10);
    assert!(
        matches!(late.as_slice(), [Output::Free { .. }]),
        "a late answer hands its lease back: {late:?}"
    );
}

#[test]
fn a_crossing_return_at_msg2_ends_the_parked_dial_closing_nothing_and_retries_no_one() {
    let mut a = node(small(), false);
    held_by_dial(&mut a, large(), E1, 1, 1, 0);
    let later = opened(&go(&mut a, dial(large(), 2, 2), 10));
    let out = xx(&mut a, msg2(later, large(), E1, 2), 20);
    assert!(finals(&out, later), "precondition: the dial is parked");
    let out = xx(
        &mut a,
        In::Refused {
            link: later,
            retry: None,
        },
        20,
    );
    assert!(retires_quietly(&out, later), "closing nothing: {out:?}");
    assert!(
        !out.iter().any(|o| matches!(o, Output::Retry { .. })),
        "no retry: {out:?}"
    );
    let out = xx(&mut a, In::FinalSent { link: later }, 20);
    assert!(out.is_empty(), "nothing is left to carry out: {out:?}");
}

#[test]
fn the_gate_read_as_heard_refuses_exactly_where_nexts_idle_floor_and_dampener_refuse() {
    let params = super::super::params(Params::default());
    let floor = 15_000u64;
    let peer = small();
    let mut checked = 0;
    for installed in [0u64, 4_000] {
        for last in [None, Some(6_000u64), Some(20_000)] {
            for stamp in [None, Some(1_000u64), Some(12_000)] {
                for now in (0..=40_000u64).step_by(500) {
                    if last.is_some_and(|l| l > now)
                        || stamp.is_some_and(|s| s > now)
                        || installed > now
                    {
                        continue;
                    }
                    let mut gates: Gates<TestInstant> = Gates::new();
                    if let Some(s) = stamp {
                        gates.plant(peer, t(s));
                    }
                    let ask = Ask {
                        source: Source::Restart,
                        held: Some(Liveness {
                            heard: true,
                            installed: t(installed),
                            last: last.map(t),
                        }),
                        ephemeral: None,
                        epoch: Some(E2),
                        memory: None,
                    };
                    let ours = gates.gate(peer, ask, t(now), &params).is_some();
                    let idle = now - last.unwrap_or(installed);
                    let dampened = stamp.is_some_and(|s| now - s < floor);
                    let next = idle < floor || dampened;
                    assert_eq!(
                        ours, next,
                        "installed {installed}, last {last:?}, stamp {stamp:?}, at {now}"
                    );
                    checked += 1;
                }
            }
        }
    }
    assert!(
        checked > 500,
        "precondition: the grid ran ({checked} cases)"
    );
}
