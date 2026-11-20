//! Tests of the judgements for the rows the reference model has no
//! history for: path events, attribution by a proven path, a punched dial,
//! a failed msg2 send, a failed dial resend, an orphaned bundle, the
//! admission cap, the links a move retires, the reset a move hands the
//! per-peer data, the answer a msg1 is asked for only once admitted, and
//! the max-peers cap at each of its three sites.

use alloc::vec::Vec;

use super::*;
use crate::proto::rekey::IndexLease;
use crate::proto::settle::gates::Refusal;
use crate::testutil::TestInstant;
use crate::transport::{TransportAddr, TransportId};

fn pair(port: u16) -> Pair {
    Pair {
        transport: TransportId::new(1),
        addr: TransportAddr::from_string(&alloc::format!("10.0.0.1:{port}")),
    }
}

/// The smaller node.
fn small() -> NodeAddr {
    NodeAddr::from_bytes([1; 16])
}

/// The larger node.
fn large() -> NodeAddr {
    NodeAddr::from_bytes([2; 16])
}

fn t(ms: u64) -> TestInstant {
    TestInstant(ms)
}

fn eph(n: u32) -> EphemeralDigest {
    let mut key = [0u8; 33];
    key[..4].copy_from_slice(&n.to_be_bytes());
    EphemeralDigest::of_noise_msg1(&key).expect("33 bytes carry an ephemeral")
}

const E1: Epoch = [1; 8];

/// The epoch of a peer that restarted.
const E2: Epoch = [2; 8];

/// The msg2 answering msg1 `n`.
fn answer(n: u32) -> Vec<u8> {
    [&[2u8][..], &n.to_be_bytes()].concat()
}

/// Msg1 `n` from `peer` at `port`, at `epoch`.
fn read(peer: NodeAddr, n: u32, port: u16, epoch: Epoch) -> Read {
    Read {
        peer,
        from: pair(port),
        bytes: n.to_be_bytes().to_vec(),
        ephemeral: eph(n),
        epoch,
    }
}

/// Msg1 `n` from `peer` at `port`, epoch 1.
fn msg1(peer: NodeAddr, n: u32, port: u16) -> Input {
    Input::Msg1 {
        read: read(peer, n, port, E1),
        reachable: true,
    }
}

/// The answer the shell builds for msg1 `n` once asked on `link`.
fn reply(link: LinkNo, n: u32) -> Input {
    Input::Hello(Hello {
        link,
        msg2: answer(n),
        lease: IndexLease::for_test(n),
    })
}

/// The link of the ask in `out`, if the core asked for an answer.
fn asked(out: &[Output]) -> Option<LinkNo> {
    out.iter().find_map(|o| {
        if let Output::Ask { link, .. } = o {
            Some(*link)
        } else {
            None
        }
    })
}

/// Take `input`, msg1 `n`, at `at`, and give the answer the core asks for,
/// if it asks; the outputs of both steps.
fn greet(table: &mut Table<TestInstant>, input: Input, n: u32, at: u64) -> Vec<Output> {
    let mut out = go(table, input, at);
    if let Some(link) = asked(&out) {
        out.extend(go(table, reply(link, n), at));
    }
    out
}

/// Msg1 `n` from `peer` at `port`, epoch 1, answered if the core asks.
fn hi(table: &mut Table<TestInstant>, peer: NodeAddr, n: u32, port: u16, at: u64) -> Vec<Output> {
    greet(table, msg1(peer, n, port), n, at)
}

fn dial(peer: NodeAddr, n: u32, port: u16) -> Dial {
    Dial {
        peer,
        to: pair(port),
        msg1: n.to_be_bytes().to_vec(),
        lease: IndexLease::for_test(n),
        resends: None,
        link: None,
    }
}

/// Release every lease in `out`; an install is kept as the link opened.
fn drain(out: Vec<Output>) -> Vec<Output> {
    out.into_iter()
        .filter_map(|o| match o {
            Output::Free { lease } => {
                lease.release();
                None
            }
            Output::Install(i) => {
                let link = i.link;
                i.lease.release();
                Some(Output::Opened { link })
            }
            other @ (Output::Opened { .. }
            | Output::Ask { .. }
            | Output::Answer { .. }
            | Output::Resend { .. }
            | Output::Rekey { .. }
            | Output::Reset { .. }
            | Output::Remove { .. }
            | Output::Retire { .. }
            | Output::Release { .. }
            | Output::Close { .. }
            | Output::Swapped { .. }
            | Output::Retry { .. }
            | Output::Reject { .. }
            | Output::Hold { .. }
            | Output::Settle { .. }) => Some(other),
        })
        .collect()
}

fn go(table: &mut Table<TestInstant>, input: Input, at: u64) -> Vec<Output> {
    drain(table.step(input, t(at)))
}

/// The link a dial opened.
fn opened(out: &[Output]) -> LinkNo {
    out.iter()
        .find_map(|o| {
            if let Output::Opened { link } = o {
                Some(*link)
            } else {
                None
            }
        })
        .expect("a dial opens a link")
}

/// The link a fresh answer went out on.
fn answered(out: &[Output]) -> LinkNo {
    out.iter()
        .find_map(|o| {
            if let Output::Answer {
                link,
                stored: false,
                ..
            } = o
            {
                Some(*link)
            } else {
                None
            }
        })
        .expect("precondition: the msg1 was answered")
}

/// Whether `out` refuses for the admission cap.
fn full(out: &[Output]) -> bool {
    out.iter().any(|o| {
        matches!(
            o,
            Output::Reject {
                why: Denial::Full,
                ..
            }
        )
    })
}

/// `me` holding `large()` from its msg1 `n` at `port`, its answer sent.
fn responder(me: NodeAddr, n: u32, port: u16) -> (Table<TestInstant>, LinkNo) {
    let mut table = Table::new(me, Params::default());
    let link = answered(&hi(&mut table, large(), n, port, 0));
    go(&mut table, Input::Sent { link }, 0);
    assert!(
        table.held(&large()).is_some(),
        "precondition: the peer is held"
    );
    (table, link)
}

/// `small()` holding `large()` on its own dial to `port`.
fn dialer(port: u16) -> (Table<TestInstant>, LinkNo) {
    let mut table = Table::new(small(), Params::default());
    let link = opened(&go(&mut table, Input::Dial(dial(large(), 1, port)), 0));
    let msg2 = Input::Msg2 {
        link,
        epoch: E1,
        from: pair(port),
    };
    go(&mut table, msg2, 0);
    assert_eq!(
        table.held(&large()).map(|h| h.link),
        Some(link),
        "precondition: the peer is held on the dial"
    );
    (table, link)
}

fn indexed(table: &Table<TestInstant>, port: u16, link: LinkNo) -> bool {
    table.links().index().contains(&(pair(port), link))
}

/// A switch to a Live path at `to`.
fn switched(link: LinkNo, to: u16) -> Input {
    Input::Switched {
        link,
        to: pair(to),
        proven: Proven::Live,
    }
}

#[test]
fn a_path_moved_rekeys_the_links_index_entry_to_the_new_pair() {
    let (mut table, link) = dialer(1);
    go(&mut table, switched(link, 5), 0);
    assert!(
        indexed(&table, 5, link),
        "precondition: the path is indexed"
    );
    let moved = Input::Moved {
        link,
        from: pair(5),
        to: pair(6),
        roam: false,
    };
    go(&mut table, moved, 0);
    assert!(
        indexed(&table, 6, link),
        "the moved path is indexed at its new pair"
    );
    assert!(!indexed(&table, 5, link), "and not at the pair it left");
}

#[test]
fn a_path_switched_adds_the_new_pair_to_the_index() {
    let (mut table, link) = dialer(1);
    go(&mut table, switched(link, 7), 0);
    assert!(indexed(&table, 7, link));
    assert!(indexed(&table, 1, link), "the setup address stays");
}

#[test]
fn a_path_released_drops_its_pair_and_closes_unless_in_use_or_kept() {
    let (mut table, link) = dialer(1);
    let other = opened(&go(&mut table, Input::Dial(dial(small(), 2, 3)), 0));
    for (port, on) in [(5, link), (6, link), (8, link), (8, other)] {
        let state = Input::State {
            link: on,
            pair: pair(port),
            proven: Proven::Live,
        };
        go(&mut table, state, 0);
    }
    let mut released = |port, keep| {
        let input = Input::Released {
            link,
            pair: pair(port),
            keep,
        };
        match go(&mut table, input, 0).as_slice() {
            [Output::Release { closes, .. }] => closes.clone(),
            other => panic!("a release reports its closes, got {other:?}"),
        }
    };
    assert_eq!(released(5, false), alloc::vec![pair(5)]);
    assert!(released(6, true).is_empty(), "kept");
    assert!(released(8, false).is_empty(), "another link's live path");
    assert!(
        !indexed(&table, 5, link),
        "a released pair leaves the index"
    );
    assert!(!indexed(&table, 8, link));
}

#[test]
fn a_path_state_change_to_probing_stops_it_counting_as_in_use() {
    let (mut table, link) = dialer(1);
    go(&mut table, switched(link, 5), 0);
    assert!(table.links().in_use(&pair(5), LinkNo(u64::MAX)));
    let probing = Input::State {
        link,
        pair: pair(5),
        proven: Proven::Probing,
    };
    go(&mut table, probing, 0);
    assert!(!indexed(&table, 5, link), "a probing path is not indexed");
    assert!(!table.links().in_use(&pair(5), LinkNo(u64::MAX)));
}

#[test]
fn a_msg1_from_a_proven_path_is_on_the_link() {
    let (mut table, link) = responder(small(), 10, 9);
    let state = Input::State {
        link,
        pair: pair(4),
        proven: Proven::Live,
    };
    go(&mut table, state, 0);
    let mut on = |n, port| {
        hi(&mut table, large(), n, port, 0)
            .into_iter()
            .find_map(|o| {
                if let Output::Rekey { arrival, .. } = o {
                    Some(arrival.on_link)
                } else {
                    None
                }
            })
            .expect("a same-epoch msg1 goes to the rekey machine")
    };
    assert!(on(11, 4), "from the proven path");
    assert!(on(12, 9), "from the setup address");
    assert!(!on(13, 3), "from elsewhere");
}

/// Whether `table` takes msg1 `n` of `large()` from `port`, at its epoch
/// on record, as on the link.
fn on_link(table: &mut Table<TestInstant>, n: u32, port: u16) -> bool {
    go(table, msg1(large(), n, port), 0)
        .into_iter()
        .find_map(|o| {
            if let Output::Rekey { arrival, .. } = o {
                Some(arrival.on_link)
            } else {
                None
            }
        })
        .expect("precondition: a same-epoch msg1 goes to the rekey machine")
}

/// `small()` holding `large()` on its own dial to `to`, answered from
/// `from`, so the core's record of where the peer is starts at `from` and
/// the link's setup pair is `to`.
fn answered_from(to: u16, from: u16) -> (Table<TestInstant>, LinkNo) {
    let mut table = Table::new(small(), Params::default());
    let link = opened(&go(&mut table, Input::Dial(dial(large(), 1, to)), 0));
    let msg2 = Input::Msg2 {
        link,
        epoch: E1,
        from: pair(from),
    };
    go(&mut table, msg2, 0);
    assert!(
        table
            .held(&large())
            .is_some_and(|h| h.link == link && h.current == pair(from)),
        "precondition: the peer is held on the dial, at the msg2's source"
    );
    (table, link)
}

/// A held link's setup pair is on the link while the peer is not capable,
/// and off it once the bundle finds the peer capable and holds no path
/// there; a proven path stays on the link. The node counts a capable
/// peer's pair its bundle holds no path at as off the link (multipath draft
/// Section 5.10).
#[test]
fn a_capable_peers_bare_setup_pair_is_off_the_link_in_the_table() {
    let (mut table, link) = answered_from(9, 4);
    let state = Input::State {
        link,
        pair: pair(4),
        proven: Proven::Live,
    };
    go(&mut table, state, 0);
    assert!(
        on_link(&mut table, 11, 9),
        "precondition: a peer not capable is on the link at its setup pair"
    );
    go(&mut table, Input::Capable { link }, 0);
    assert!(
        table.links().get(link).is_some_and(|r| r.capable),
        "defect: the record does not hold the link capable"
    );
    assert!(
        !on_link(&mut table, 12, 9),
        "defect: a capable peer's setup pair, at which no path is held, is on the link"
    );
    assert!(
        on_link(&mut table, 13, 4),
        "defect: a capable peer's proven path is off the link"
    );
}

/// A msg1 from the pair the core's record of the peer is at, where the
/// link holds no path and the index names no link, is off the link: the
/// node counts the bundle's proven paths and the index, never where the
/// peer was last seen. The setup pair of a peer not capable stays on it.
#[test]
fn a_msg1_from_the_pair_the_core_holds_the_peer_at_with_no_path_there_is_off_the_link() {
    let (mut table, _) = answered_from(9, 4);
    assert!(
        on_link(&mut table, 11, 9),
        "precondition: the setup pair of a peer not capable is on the link"
    );
    assert!(
        !on_link(&mut table, 12, 4),
        "defect: the pair the core holds the peer at, with no path or index entry there, is on the link"
    );
}

/// A msg1 from a pair whose path is still probing is off the link, at the
/// setup pair and at the pair the core holds the peer at alike; once the
/// path is acknowledged it is on the link.
#[test]
fn a_msg1_from_a_pair_whose_path_is_probing_is_off_the_link() {
    let (mut table, link) = answered_from(9, 4);
    for port in [9, 4] {
        let probing = Input::State {
            link,
            pair: pair(port),
            proven: Proven::Probing,
        };
        go(&mut table, probing, 0);
    }
    assert!(
        !on_link(&mut table, 11, 9),
        "defect: the setup pair, whose path is probing, is on the link"
    );
    assert!(
        !on_link(&mut table, 12, 4),
        "defect: the pair the core holds the peer at, whose path is probing, is on the link"
    );
    let acked = Input::State {
        link,
        pair: pair(4),
        proven: Proven::Acked,
    };
    go(&mut table, acked, 0);
    assert!(
        on_link(&mut table, 13, 4),
        "defect: an acknowledged path is off the link"
    );
}

/// A msg1 from a held link's setup pair, at which the link holds no path,
/// is off the link once the index no longer names the link there: when
/// the bundle released the path at the pair, and when a newer link, here
/// a second dial to the same pair, is the one the index names, as the
/// node's index names the newest.
#[test]
fn a_msg1_from_a_setup_pair_the_index_names_another_link_at_is_off_the_link() {
    let (mut table, link) = dialer(1);
    assert!(
        on_link(&mut table, 11, 1),
        "precondition: the setup pair of a peer not capable is on the link"
    );
    let second = opened(&go(&mut table, Input::Dial(dial(large(), 2, 1)), 0));
    assert!(
        indexed(&table, 1, second) && second > link,
        "precondition: the second dial is the newer link at the pair"
    );
    assert!(
        !on_link(&mut table, 12, 1),
        "defect: the setup pair is on the link where the index names a newer link"
    );

    let (mut table, link) = dialer(1);
    let released = Input::Released {
        link,
        pair: pair(1),
        keep: true,
    };
    go(&mut table, released, 0);
    assert!(
        !on_link(&mut table, 13, 1),
        "defect: the setup pair whose path the bundle released is on the link"
    );
}

#[test]
fn a_punched_input_opens_a_dial_leg_at_the_punched_pair() {
    let mut table = Table::new(small(), Params::default());
    let link = opened(&go(&mut table, Input::Punched(dial(large(), 1, 6)), 0));
    assert_eq!(
        table.links().get(link).map(|r| r.setup.clone()),
        Some(pair(6))
    );
    assert_eq!(
        table.legs().get(link).map(|l| l.kind().clone()),
        Some(Kind::Dial)
    );
}

#[test]
fn a_failed_msg2_send_keeps_the_stored_answer_for_the_resend() {
    let mut table = Table::new(small(), Params::default());
    let link = answered(&hi(&mut table, large(), 10, 9, 0));
    go(&mut table, Input::SendFailed { link }, 0);
    let again = hi(&mut table, large(), 10, 9, 500);
    let expect = Output::Answer {
        link,
        msg2: answer(10),
        stored: true,
    };
    assert!(
        again.contains(&expect),
        "the resend draws the stored msg2: {again:?}"
    );
}

#[test]
fn an_unsent_dial_resend_is_tried_again_at_the_next_tick_and_not_before() {
    // The unsent-resend probe, through the table: an executor that sleeps until
    // `next_wake`, never into the past (a wake at or before its last poll
    // polls again a millisecond on), and whose every msg1 resend fails to
    // send. The node re-arms a failed resend at its tick, one second on
    // (`TICK`, `src/node/mod.rs:64`), and tries it once a tick until the
    // dial's deadline.
    let mut table = Table::new(small(), Params::default());
    let link = opened(&go(&mut table, Input::Dial(dial(large(), 1, 1)), 0));
    let mut now = table.next_wake().expect("a dial wakes for its resend").0;
    let mut polls = 0u32;
    let mut tried = Vec::new();
    loop {
        let out = drain(table.poll(t(now)));
        polls += 1;
        if out
            .iter()
            .any(|o| matches!(o, Output::Retire { link: l, .. } if *l == link))
        {
            break;
        }
        let resent = out
            .iter()
            .any(|o| matches!(o, Output::Resend { link: l, .. } if *l == link));
        assert!(
            resent,
            "precondition: a poll at the dial's wake {now} resends or reaps it: {out:?}"
        );
        tried.push(now);
        go(&mut table, Input::SendFailed { link }, now);
        let wake = table.next_wake().expect("the dial is still in flight").0;
        now = wake.max(now + 1);
    }
    let want: Vec<u64> = (1..30).map(|s| s * 1_000).collect();
    assert_eq!(
        (polls, tried.len()),
        (30, want.len()),
        "defect: {polls} polls and {} resends before the dial's deadline, \
         where the node tries a failed resend once a tick",
        tried.len()
    );
    assert_eq!(tried, want, "each failed resend is tried again one tick on");
}

#[test]
fn a_failed_dial_resend_is_due_at_the_next_poll_whatever_its_instant() {
    // The node re-arms a failed resend at the instant it failed
    // (`src/node/handlers/timeout.rs:526`), so its next tick tries it again
    // wherever that tick falls. A failed resend stored as due one tick on
    // agrees with that only when the polls fall on that grid, so this
    // executor polls off it: one millisecond after a failure, then just
    // short of the tick.
    let mut table = Table::new(small(), Params::default());
    let link = opened(&go(&mut table, Input::Dial(dial(large(), 1, 1)), 0));
    let resends = |out: &[Output]| {
        out.iter()
            .filter(|o| matches!(o, Output::Resend { link: l, .. } if *l == link))
            .count()
    };
    let first = table.next_wake().expect("a dial wakes for its resend").0;
    assert_eq!(
        resends(&drain(table.poll(t(first)))),
        1,
        "precondition: the dial's first resend is asked for at its wake {first}"
    );
    let mut failed = first;
    go(&mut table, Input::SendFailed { link }, failed);
    for at in [first + 1, first + 999] {
        let wake = table.next_wake().expect("the dial is still in flight").0;
        assert_eq!(
            wake,
            failed + 1_000,
            "defect: the wake reported after a resend failed at {failed} is {wake}, \
             not one tick on"
        );
        assert_eq!(
            resends(&drain(table.poll(t(at)))),
            1,
            "defect: a poll at {at}, after a resend failed at {failed} and before \
             the tick at {wake}, does not try it again"
        );
        failed = at;
        go(&mut table, Input::SendFailed { link }, failed);
    }
    let at = first + 1_500;
    assert_eq!(
        resends(&drain(table.poll(t(at)))),
        1,
        "precondition: the resend that failed at {failed} is asked for at {at}"
    );
    go(&mut table, Input::Sent { link }, at);
    assert_eq!(
        resends(&drain(table.poll(t(at + 1)))),
        0,
        "defect: a resend sent at {at} is asked for again a millisecond on"
    );
}

#[test]
fn a_send_failure_after_a_dials_last_resend_asks_for_no_more() {
    // A dial with its last resend sent has none to try again, whatever cap
    // stopped it, so a failed send reported after that (one no resend asked
    // for) leaves the dial waiting for its deadline.
    let params = Params {
        resends: 2,
        ..Params::default()
    };
    let mut table = Table::new(small(), params);
    let link = opened(&go(&mut table, Input::Dial(dial(large(), 1, 1)), 0));
    let resends = |out: &[Output]| {
        out.iter()
            .filter(|o| matches!(o, Output::Resend { link: l, .. } if *l == link))
            .count()
    };
    let mut last = 0;
    for n in 1..=2 {
        last = table.next_wake().expect("the dial is still in flight").0;
        assert_eq!(
            resends(&drain(table.poll(t(last)))),
            1,
            "precondition: resend {n} is asked for at {last}"
        );
        go(&mut table, Input::Sent { link }, last);
    }
    let deadline = 30_000;
    assert_eq!(
        table.next_wake().map(|w| w.0),
        Some(deadline),
        "precondition: with both resends sent the dial waits for its deadline"
    );
    go(&mut table, Input::SendFailed { link }, last + 1);
    assert_eq!(
        resends(&drain(table.poll(t(last + 2)))),
        0,
        "defect: a send failure after the dial's last resend asks for a third"
    );
    assert_eq!(
        table.next_wake().map(|w| w.0),
        Some(deadline),
        "the dial still waits for its deadline"
    );
}

#[test]
fn a_msg1_from_the_address_of_an_unsent_answer_draws_that_answer_whatever_its_bytes() {
    // FRC-1201 Section 5.8: the stored msg2 alone, before any Noise read,
    // to any msg1 from that address, as the model and the current node
    // answer it; a peer that restarted meanwhile sends a msg1 of its own.
    let mut table = Table::new(small(), Params::default());
    let link = answered(&hi(&mut table, large(), 10, 9, 0));
    go(&mut table, Input::SendFailed { link }, 0);
    let other = hi(&mut table, large(), 11, 9, 500);
    let expect = Output::Answer {
        link,
        msg2: answer(10),
        stored: true,
    };
    assert!(
        other.contains(&expect),
        "another msg1 from that address draws the stored msg2: {other:?}"
    );
}

#[test]
fn an_orphaned_bundle_removes_the_peer_and_retires_its_link() {
    let (mut table, link) = dialer(1);
    let out = go(&mut table, Input::Orphaned { peer: large() }, 0);
    assert!(out.contains(&Output::Remove {
        peer: large(),
        why: Why::Orphaned,
    }));
    assert!(table.held(&large()).is_none());
    assert!(table.links().get(link).is_none(), "its link is retired");
}

/// The node routes an orphaned bundle through its link-dead path, whose
/// control machine notes the loss for a reconnect, as it does a dead link.
#[test]
fn an_orphaned_bundles_peer_is_retried() {
    let (mut table, _) = dialer(1);
    let out = go(&mut table, Input::Orphaned { peer: large() }, 0);
    assert!(
        out.contains(&Output::Retry { peer: large() }),
        "defect: an orphaned bundle's peer is not retried: {out:?}"
    );
}

/// A peer held at epoch 1 torn down, past the unheard floor, in each of
/// the three ways a new session replaces it: a msg1 at a new epoch, the
/// rekey machine's replacement request, and this node's own dial answered
/// at a new epoch. The node's control machine reports each loss for a
/// reconnect before the new session is promoted, as at a dead link.
#[test]
fn a_restarted_or_replaced_peer_is_retried_in_each_of_the_three_ways() {
    const LATER: Epoch = [2; 8];
    let restart = || {
        let (mut table, _) = responder(small(), 10, 9);
        let msg1 = Input::Msg1 {
            read: read(large(), 11, 9, LATER),
            reachable: true,
        };
        go(&mut table, msg1, 2_000)
    };
    let replacement = || {
        let (mut table, _) = responder(small(), 10, 9);
        go(&mut table, Input::Replace(read(large(), 11, 9, E1)), 2_000)
    };
    let own = || {
        let (mut table, _) = dialer(1);
        let link = opened(&go(&mut table, Input::Dial(dial(large(), 2, 5)), 2_000));
        let msg2 = Input::Msg2 {
            link,
            epoch: LATER,
            from: pair(5),
        };
        go(&mut table, msg2, 2_000)
    };
    let ways: [(Why, &dyn Fn() -> Vec<Output>); 3] = [
        (Why::Restart, &restart),
        (Why::Replacement, &replacement),
        (Why::OwnRestart, &own),
    ];
    for (why, way) in ways {
        let out = way();
        assert!(
            out.contains(&Output::Remove { peer: large(), why }),
            "precondition: the held peer is removed for {why:?}: {out:?}"
        );
        assert!(
            out.contains(&Output::Retry { peer: large() }),
            "defect: a peer removed for {why:?} is not retried: {out:?}"
        );
    }
}

/// The connections the table's outputs `out` close for a retired link.
fn retired(out: &[Output]) -> Vec<Pair> {
    out.iter()
        .find_map(|o| {
            if let Output::Retire { closes, .. } = o {
                Some(closes.clone())
            } else {
                None
            }
        })
        .expect("precondition: the link is retired")
}

/// The node's removal hands back the paths the bundle still holds and
/// closes the ones it does not mark to keep; the path at the setup pair,
/// released before the bundle was orphaned and marked to keep, was not
/// closed at its release, and the removal does not close it either.
#[test]
fn an_orphaned_peer_closes_its_bundles_paths_and_not_a_setup_pair_released_to_keep() {
    let (mut table, link) = dialer(1);
    for (port, proven) in [(1, Proven::Live), (5, Proven::Probing)] {
        let state = Input::State {
            link,
            pair: pair(port),
            proven,
        };
        go(&mut table, state, 0);
    }
    let release = Input::Released {
        link,
        pair: pair(1),
        keep: true,
    };
    assert!(
        released(&go(&mut table, release, 0)).is_empty(),
        "precondition: the setup pair's path is released to keep"
    );
    let out = go(&mut table, Input::Orphaned { peer: large() }, 0);
    assert_eq!(
        retired(&out),
        alloc::vec![pair(5)],
        "defect: the removal closes the setup pair its release kept: {out:?}"
    );
}

/// The node's operator disconnect closes the connection at the pair the
/// peer was held at, without asking whether another link uses it, as a
/// stale connection's cleanup does.
#[test]
fn an_operator_disconnect_closes_the_peers_pair_though_a_dial_uses_it() {
    let (mut table, _) = responder(small(), 10, 9);
    let third = NodeAddr::from_bytes([3; 16]);
    let dialed = opened(&go(&mut table, Input::Dial(dial(third, 2, 9)), 0));
    assert!(
        table.links().in_use(&pair(9), LinkNo(u64::MAX)),
        "precondition: the dial uses the peer's pair"
    );
    let out = go(&mut table, Input::Admin { peer: large() }, 0);
    assert_eq!(
        retired(&out),
        alloc::vec![pair(9)],
        "defect: the disconnect keeps the peer's pair open: {out:?}"
    );
    assert!(table.links().get(dialed).is_some(), "the dial's link stays");
}

#[test]
fn a_msg1_past_the_admission_cap_is_rejected_and_holds_no_leg() {
    let params = Params {
        pending: 2,
        ..Params::default()
    };
    let mut table = Table::new(small(), params);
    for n in 3..5u8 {
        let peer = NodeAddr::from_bytes([n; 16]);
        let link = answered(&hi(&mut table, peer, n.into(), n.into(), 0));
        go(&mut table, Input::SendFailed { link }, 0);
    }
    assert_eq!(
        table.legs().answering(),
        2,
        "precondition: two answers in flight"
    );
    let out = hi(&mut table, NodeAddr::from_bytes([5; 16]), 5, 5, 0);
    assert!(full(&out), "the third is refused: {out:?}");
    assert_eq!(table.legs().answering(), 2, "and holds no leg");
    let early = Input::Arrived {
        from: pair(6),
        bytes: alloc::vec![6],
    };
    assert!(
        full(&go(&mut table, early, 0)),
        "refused before any Diffie-Hellman too"
    );
}

/// The smaller node's crossing: its dial to `at(2)`, the larger node's
/// msg1 from `at(12)` answered and sent, then the dial's msg2 from `at(2)`.
fn crossing() -> (Table<TestInstant>, LinkNo, LinkNo, Vec<Output>) {
    crossed(2)
}

/// The smaller node's crossing as [`crossing`] makes it, with the dial's
/// msg2 from `at(from)`.
fn crossed(from: u16) -> (Table<TestInstant>, LinkNo, LinkNo, Vec<Output>) {
    let mut table = Table::new(small(), Params::default());
    let dialed = opened(&go(&mut table, Input::Dial(dial(large(), 1, 2)), 0));
    let inbound = answered(&hi(&mut table, large(), 2, 12, 0));
    go(&mut table, Input::Sent { link: inbound }, 0);
    let msg2 = Input::Msg2 {
        link: dialed,
        epoch: E1,
        from: pair(from),
    };
    let out = go(&mut table, msg2, 0);
    (table, dialed, inbound, out)
}

#[test]
fn a_crossing_moves_the_smaller_node_and_retires_the_inbound_link() {
    let (table, dialed, inbound, out) = crossing();
    assert_eq!(table.held(&large()).map(|h| h.link), Some(dialed));
    let retired = Output::Retire {
        link: inbound,
        closes: alloc::vec![pair(12)],
    };
    assert!(
        out.contains(&retired),
        "the inbound link is retired and its connection closed: {out:?}"
    );
    assert!(table.links().get(inbound).is_none());
}

/// The smaller node's dial to `at(2)` is answered over the larger node's
/// dial connection, from `at(12)`, the pair its msg1 came from: the move
/// lands the peering on that pair, so the inbound link it retires leaves
/// that connection open, as the node keeps it by renewing the bundle there
/// before it closes the link it leaves.
#[test]
fn a_move_onto_a_dial_answered_from_the_peers_other_pair_keeps_that_pair_open() {
    let (table, dialed, inbound, out) = crossed(12);
    assert_eq!(
        table.held(&large()).map(|h| (h.link, h.current.clone())),
        Some((dialed, pair(12))),
        "precondition: the peering moved onto the dial, at the msg2's pair"
    );
    let closes = retired(&out);
    assert!(
        !closes.contains(&pair(12)),
        "defect: the move closed the connection the peering moved onto: {out:?}"
    );
    assert!(
        table.links().in_use(&pair(12), inbound),
        "the moved-onto link uses the msg2's pair"
    );
}

/// The same move leaves the dial's own connection, at `at(2)`, used by no
/// path of the moved-onto link and by no handshake, so it closes with the
/// link the move retires, as the node closes it once the move is done.
#[test]
fn a_move_onto_a_dial_answered_from_the_peers_other_pair_closes_the_dials_own_connection() {
    let (table, dialed, inbound, out) = crossed(12);
    assert_eq!(
        table.held(&large()).map(|h| (h.link, h.current.clone())),
        Some((dialed, pair(12))),
        "precondition: the peering moved onto the dial, at the msg2's pair"
    );
    assert!(
        !table.links().in_use(&pair(2), inbound),
        "precondition: no link uses the dial's own connection after the move"
    );
    assert!(
        retired(&out).contains(&pair(2)),
        "defect: the move left the dial's own connection open with no link using it: {out:?}"
    );
}

#[test]
fn a_late_second_dial_in_order_retires_the_link_moved_off() {
    let mut table = Table::new(large(), Params::default());
    let first = opened(&go(&mut table, Input::Dial(dial(small(), 1, 1)), 0));
    let msg2 = Input::Msg2 {
        link: first,
        epoch: E1,
        from: pair(1),
    };
    go(&mut table, msg2, 0);
    let second = opened(&go(&mut table, Input::Dial(dial(small(), 2, 5)), 2_000));
    let msg2 = Input::Msg2 {
        link: second,
        epoch: E1,
        from: pair(5),
    };
    let out = go(&mut table, msg2, 2_000);
    assert_eq!(table.held(&small()).map(|h| h.link), Some(second));
    let retired = Output::Retire {
        link: first,
        closes: alloc::vec![pair(1)],
    };
    assert!(
        out.contains(&retired),
        "the link moved off is retired: {out:?}"
    );
}

#[test]
fn a_move_resets_peer_data() {
    let (_, _, _, out) = crossing();
    let reset = Output::Reset {
        peer: large(),
        transition: Transition::Move,
    };
    assert!(out.contains(&reset));
}

/// The connections the table's outputs `out` close for a released path.
fn released(out: &[Output]) -> Vec<Pair> {
    out.iter()
        .find_map(|o| {
            if let Output::Release { closes, .. } = o {
                Some(closes.clone())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

/// The table and a shell's record of a link read each bundle report the
/// same way, through `Links::mirror`: a switch adds the path Live, a state
/// change sets its state, a move keeps its state at the new pair, and a
/// release drops it and closes its connection. Each record is held to the
/// paths stated here, so each of the table's switches over those reports
/// turns this red.
#[test]
fn the_table_and_the_record_read_the_mirror_the_same_way() {
    let (mut table, link) = dialer(1);
    let mut record = Links::new();
    let at = record.open(pair(1), Dir::Outbound, Holder::Peer(large()));
    let reports = |l: LinkNo| {
        [
            switched(l, 5),
            Input::State {
                link: l,
                pair: pair(5),
                proven: Proven::Probing,
            },
            Input::Moved {
                link: l,
                from: pair(5),
                to: pair(6),
                roam: false,
            },
            Input::State {
                link: l,
                pair: pair(6),
                proven: Proven::Live,
            },
            Input::Released {
                link: l,
                pair: pair(6),
                keep: false,
            },
        ]
    };
    let expected = [
        (alloc::vec![(pair(5), Proven::Live)], alloc::vec![]),
        (alloc::vec![(pair(5), Proven::Probing)], alloc::vec![]),
        (alloc::vec![(pair(6), Proven::Probing)], alloc::vec![]),
        (alloc::vec![(pair(6), Proven::Live)], alloc::vec![]),
        (alloc::vec![], alloc::vec![pair(6)]),
    ];
    for ((to_table, to_record), (paths, closes)) in
        reports(link).into_iter().zip(reports(at)).zip(expected)
    {
        let shown = alloc::format!("{to_record:?}");
        let out = go(&mut table, to_table, 0);
        let closed = record.mirror(&to_record);
        assert_eq!(
            record.get(at).expect("the record holds the link").paths,
            paths,
            "the record after {shown}"
        );
        assert_eq!(closed, closes, "the record's closes after {shown}");
        assert_eq!(
            table
                .links()
                .get(link)
                .expect("the table holds the link")
                .paths,
            paths,
            "the table after {shown}"
        );
        assert_eq!(released(&out), closes, "the table's closes after {shown}");
    }
}

#[test]
fn a_connecting_dials_pair_is_in_use_before_its_msg1_and_a_failed_connect_retires_it_with_no_lease()
{
    let mut table = Table::new(small(), Params::default());
    let connecting = Input::Connecting {
        peer: large(),
        to: pair(7),
        resends: None,
    };
    let link = opened(&go(&mut table, connecting, 0));
    assert!(
        table.links().derived().contains(&(pair(7), link))
            && table.links().in_use(&pair(7), LinkNo(u64::MAX)),
        "defect: a connecting dial's address is not in the index or in use before its msg1"
    );
    assert!(table.legs().get(link).is_none(), "no leg before the msg1");
    let out = table.step(Input::ConnectFailed { link }, t(500));
    assert_eq!(
        out,
        [Output::Retire {
            link,
            closes: alloc::vec![pair(7)],
        }],
        "the failed connect retires the link, closes its connection and frees no lease"
    );
    assert!(table.links().get(link).is_none());
}

#[test]
fn a_dial_after_its_connect_starts_its_leg_on_the_link_the_connect_opened() {
    let mut table = Table::new(small(), Params::default());
    let connecting = Input::Connecting {
        peer: large(),
        to: pair(8),
        resends: Some(2),
    };
    let link = opened(&go(&mut table, connecting, 0));
    let msg1 = Dial {
        link: Some(link),
        ..dial(large(), 1, 8)
    };
    let out = go(&mut table, Input::Dial(msg1), 200);
    assert!(
        out.is_empty(),
        "defect: the dial after its connect opens another link, got {out:?}"
    );
    let leg = table
        .legs()
        .get(link)
        .expect("the leg is on the connect's link");
    assert_eq!(leg.peer(), Some(large()));
    // The connect's cap of two resends holds, not the configured five.
    let mut resends = Vec::new();
    for at in [1_200, 3_200, 7_200] {
        for o in drain(table.poll(t(at))) {
            if let Output::Resend { link: l, .. } = o {
                assert_eq!(l, link, "the resend is on the connect's link");
                resends.push(at);
                go(&mut table, Input::Sent { link }, at);
            }
        }
    }
    assert_eq!(resends, [1_200, 3_200], "the connect's resend cap holds");

    let stray = Dial {
        link: Some(LinkNo(99)),
        ..dial(large(), 2, 9)
    };
    let out = table.step(Input::Dial(stray), t(7_300));
    let [Output::Free { lease }] = <[Output; 1]>::try_from(out).expect("one output") else {
        panic!("a dial naming a link no connect holds frees its lease alone");
    };
    assert_eq!(lease.release(), 2);
}

/// The `Swapped` output in `out`, as `(own, unpin)`.
fn swapped(out: &[Output]) -> Option<(bool, bool)> {
    out.iter().find_map(|o| {
        if let Output::Swapped { own, unpin, .. } = o {
            Some((*own, *unpin))
        } else {
            None
        }
    })
}

/// The msg2 of `small()`'s dial on `link`, from `port`, at `at`.
fn msg2(table: &mut Table<TestInstant>, link: LinkNo, port: u16, at: u64) -> Vec<Output> {
    go(
        table,
        Input::Msg2 {
            link,
            epoch: E1,
            from: pair(port),
        },
        at,
    )
}

#[test]
fn a_move_onto_a_later_dial_to_a_peer_held_on_the_link_it_dialled_ends_the_pin() {
    // The smaller node holds the larger on the link the larger dialed (an
    // answered msg1), dials it again at another address, and the
    // same-epoch msg2 moves it: the held link was not this node's dial, but
    // the dial was made while the peer was held on it.
    let (mut table, inbound) = responder(small(), 1, 3);
    let dialed = opened(&go(&mut table, Input::Dial(dial(large(), 2, 5)), 1_000));
    let out = msg2(&mut table, dialed, 5, 1_100);
    assert_eq!(
        table.held(&large()).map(|h| h.link),
        Some(dialed),
        "precondition: the msg2 moved the peer off {inbound:?} onto the dial"
    );
    assert_eq!(
        swapped(&out),
        Some((false, true)),
        "defect: the pin of a peer held on the link it dialed is kept at a move onto a later dial"
    );
}

#[test]
fn a_move_onto_a_dial_made_before_the_peer_was_held_keeps_the_pin() {
    // The dial starts with the peer not held; the peer's msg1 is answered
    // and installs it on the link it dialed; then the dial's msg2 moves it.
    let mut table = Table::new(small(), Params::default());
    let dialed = opened(&go(&mut table, Input::Dial(dial(large(), 1, 5)), 0));
    let inbound = answered(&hi(&mut table, large(), 2, 3, 100));
    go(&mut table, Input::Sent { link: inbound }, 100);
    assert!(
        table.held(&large()).is_some_and(|h| h.link == inbound),
        "precondition: the answer installed the peer"
    );
    let out = msg2(&mut table, dialed, 5, 200);
    assert_eq!(table.held(&large()).map(|h| h.link), Some(dialed));
    assert_eq!(
        swapped(&out),
        Some((false, false)),
        "a dial made before the peer was held keeps the pin"
    );
}

#[test]
fn a_second_dial_made_before_the_peer_was_held_and_answered_after_a_crossing_ends_the_pin() {
    // Two dials before the peer is held; its msg1 is answered and installs
    // it; the first dial's msg2 moves it (the crossing), and the second's
    // then moves it again, off a link this node dialed.
    let mut table = Table::new(small(), Params::default());
    let first = opened(&go(&mut table, Input::Dial(dial(large(), 1, 5)), 0));
    let second = opened(&go(&mut table, Input::Dial(dial(large(), 2, 6)), 0));
    let inbound = answered(&hi(&mut table, large(), 3, 3, 100));
    go(&mut table, Input::Sent { link: inbound }, 100);
    let crossing = msg2(&mut table, first, 5, 200);
    assert_eq!(
        swapped(&crossing),
        Some((false, false)),
        "precondition: the crossing moves the peer and keeps the pin"
    );
    let out = msg2(&mut table, second, 6, 300);
    assert_eq!(table.held(&large()).map(|h| h.link), Some(second));
    assert_eq!(
        swapped(&out),
        Some((true, true)),
        "a move off this node's own dial ends the pin"
    );
}

/// The outputs `out`, each named by its variant, in order.
fn kinds(out: &[Output]) -> Vec<&'static str> {
    out.iter()
        .map(|o| match o {
            Output::Opened { .. } => "Opened",
            Output::Ask { .. } => "Ask",
            Output::Answer { .. } => "Answer",
            Output::Resend { .. } => "Resend",
            Output::Rekey { .. } => "Rekey",
            Output::Install(_) => "Install",
            Output::Reset { .. } => "Reset",
            Output::Remove { .. } => "Remove",
            Output::Retire { .. } => "Retire",
            Output::Release { .. } => "Release",
            Output::Close { .. } => "Close",
            Output::Free { .. } => "Free",
            Output::Swapped { .. } => "Swapped",
            Output::Retry { .. } => "Retry",
            Output::Reject { .. } => "Reject",
            Output::Hold { .. } => "Hold",
            Output::Settle { .. } => "Settle",
        })
        .collect()
}

/// A msg1 at a new epoch from the held peer `large()`, msg1 `n`.
fn restart(n: u32, port: u16) -> Input {
    Input::Msg1 {
        read: read(large(), n, port, E2),
        reachable: true,
    }
}

#[test]
fn a_refused_msg1_asks_for_no_answer() {
    // The current node classifies a msg1 and runs its late check before it
    // writes a msg2 or draws an index (`handle_msg1`), so a refused msg1
    // costs neither.
    let (mut table, _) = responder(small(), 10, 9);
    let out = go(&mut table, restart(11, 9), 500);
    assert!(
        kinds(&out).contains(&"Reject"),
        "precondition: a restart inside the unheard floor is refused: {out:?}"
    );
    assert!(
        asked(&out).is_none(),
        "defect: a refused msg1 asks for an answer: {out:?}"
    );
    assert!(
        !kinds(&out).contains(&"Free"),
        "and hands back no lease, since it took none: {out:?}"
    );
}

#[test]
fn a_rekey_msg1_asks_for_no_answer() {
    // A same-epoch msg1 of a held peer is the rekey machine's to answer.
    let (mut table, _) = responder(small(), 10, 9);
    let out = go(&mut table, msg1(large(), 11, 9), 2_000);
    assert!(
        kinds(&out).contains(&"Rekey"),
        "precondition: the msg1 goes to the rekey machine: {out:?}"
    );
    assert!(
        asked(&out).is_none(),
        "defect: a rekey msg1 asks the core's shell for an answer: {out:?}"
    );
    assert!(
        !kinds(&out).contains(&"Free"),
        "and hands back no lease, since it took none: {out:?}"
    );
}

#[test]
fn an_abandoned_answer_frees_its_link_and_takes_no_lease() {
    // The shell's late check refuses a msg1 the core admitted: the link the
    // msg1 opened is retired, and no leg ever held a lease for it.
    let mut table = Table::new(small(), Params::default());
    let out = go(&mut table, msg1(large(), 10, 9), 0);
    let link = asked(&out).expect("precondition: the msg1 is admitted");
    assert!(indexed(&table, 9, link), "precondition: its link is open");
    let out = go(&mut table, Input::Abandon { link }, 0);
    assert_eq!(
        kinds(&out),
        ["Retire"],
        "the abandon retires the link and frees nothing: {out:?}"
    );
    assert!(table.links().get(link).is_none(), "its link is retired");
    assert!(!indexed(&table, 9, link), "and leaves the index");
    assert!(table.legs().get(link).is_none(), "no leg was opened");
    assert!(table.held(&large()).is_none(), "and no peer installed");
    let late = table.step(reply(link, 10), t(0));
    assert_eq!(
        kinds(&late),
        ["Free"],
        "an answer to the abandoned ask hands its lease back: {late:?}"
    );
    drain(late);
    assert!(table.legs().get(link).is_none(), "and opens no leg");
}

#[test]
fn a_restarts_teardown_comes_before_its_answer_is_asked_for() {
    // The current node removes the restarted peer, notes it lost, and only
    // then authorizes the msg1 and builds its answer.
    let (mut table, _) = responder(small(), 10, 9);
    let out = go(&mut table, restart(11, 9), 2_000);
    let order = kinds(&out);
    let removed = order
        .iter()
        .position(|k| *k == "Remove")
        .expect("precondition: the restart tears the held peer down");
    let ask = order
        .iter()
        .position(|k| *k == "Ask")
        .expect("precondition: the restart is admitted");
    assert!(
        removed < ask,
        "defect: the answer is asked for before the teardown: {order:?}"
    );
}

/// A table for `small()` with a max-peers cap of `peers`, holding
/// `held` peers, each from its own answered msg1.
fn capped(peers: usize, held: u8) -> Table<TestInstant> {
    let params = Params {
        peers,
        ..Params::default()
    };
    let mut table = Table::new(small(), params);
    for n in 0..held {
        let peer = NodeAddr::from_bytes([10 + n; 16]);
        let link = answered(&hi(&mut table, peer, (10 + n).into(), (10 + n).into(), 0));
        go(&mut table, Input::Sent { link }, 0);
        assert!(
            table.held(&peer).is_some(),
            "precondition: {peer:?} is held"
        );
    }
    table
}

/// Whether `out` refuses for the max-peers cap.
fn cap(out: &[Output]) -> bool {
    out.iter().any(|o| {
        matches!(
            o,
            Output::Reject {
                why: Denial::Cap,
                ..
            }
        )
    })
}

#[test]
fn a_msg1_from_a_new_identity_at_the_peer_cap_is_refused_before_any_answer() {
    // The node's early gate drops a msg1 from an identity it does not hold
    // at `max_peers`, before any msg2 and before the restart gates.
    let mut table = capped(2, 2);
    let out = go(&mut table, msg1(large(), 1, 1), 0);
    assert!(
        cap(&out),
        "defect: a new identity's msg1 at the peer cap is not refused for it: {out:?}"
    );
    assert!(asked(&out).is_none(), "and no answer is asked for: {out:?}");
    assert!(table.legs().answering() == 0, "no leg is opened");
    assert!(table.held(&large()).is_none());
}

#[test]
fn a_held_identity_at_the_peer_cap_restarts_as_before() {
    // The cap counts identities not held: a held peer's restart replaces it
    // at the cap as it would below it.
    let mut table = capped(2, 2);
    let peer = NodeAddr::from_bytes([10; 16]);
    let restart = Input::Msg1 {
        read: read(peer, 20, 10, E2),
        reachable: true,
    };
    let out = greet(&mut table, restart, 20, 2_000);
    assert!(
        !cap(&out),
        "a held identity is not refused for the cap: {out:?}"
    );
    assert!(
        out.contains(&Output::Remove {
            peer,
            why: Why::Restart,
        }),
        "the restart tears the held peer down: {out:?}"
    );
    let link = answered(&out);
    let out = go(&mut table, Input::Sent { link }, 2_000);
    assert!(!cap(&out), "and its answer installs at the cap: {out:?}");
    assert_eq!(table.held(&peer).map(|h| h.link), Some(link));
}

#[test]
fn a_dial_completing_to_a_new_identity_at_the_peer_cap_is_not_installed() {
    // The node refuses a promotion at `max_peers` and frees its index; the
    // dial's link goes with it.
    let mut table = capped(2, 2);
    let link = opened(&go(&mut table, Input::Dial(dial(large(), 1, 1)), 0));
    let msg2 = Input::Msg2 {
        link,
        epoch: E1,
        from: pair(1),
    };
    let out = table.step(msg2, t(0));
    let freed = out.iter().any(|o| matches!(o, Output::Free { .. }));
    let installed = out.iter().any(|o| matches!(o, Output::Install(_)));
    let out = drain(out);
    assert!(
        cap(&out) && !installed,
        "defect: a dial to a new identity at the peer cap installs it: {out:?}"
    );
    assert!(freed, "its lease comes back: {out:?}");
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Retire { link: l, .. } if *l == link)),
        "and its link is retired: {out:?}"
    );
    assert!(table.held(&large()).is_none());
    assert!(table.legs().get(link).is_none());
    assert!(table.links().get(link).is_none());
}

#[test]
fn an_answer_sent_to_a_new_identity_once_the_peer_cap_filled_is_not_installed() {
    // Two msg1s are admitted below the cap; the second's answer goes out
    // first and fills it. The node refuses the first's promotion at
    // `max_peers` and frees its index; its link goes with it.
    let mut table = capped(2, 1);
    let other = NodeAddr::from_bytes([3; 16]);
    let first = answered(&hi(&mut table, large(), 1, 1, 0));
    let second = answered(&hi(&mut table, other, 2, 2, 0));
    go(&mut table, Input::Sent { link: second }, 0);
    assert!(
        table.held(&other).is_some(),
        "precondition: the second answer filled the cap"
    );
    let out = table.step(Input::Sent { link: first }, t(0));
    let freed = out.iter().any(|o| matches!(o, Output::Free { .. }));
    let installed = out.iter().any(|o| matches!(o, Output::Install(_)));
    let out = drain(out);
    assert!(
        cap(&out) && !installed,
        "defect: an answer sent to a new identity at the peer cap installs it: {out:?}"
    );
    assert!(freed, "its lease comes back: {out:?}");
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Retire { link: l, .. } if *l == first)),
        "and its link is retired: {out:?}"
    );
    assert!(table.held(&large()).is_none());
    assert!(table.legs().get(first).is_none());
    assert!(table.links().get(first).is_none());
}

#[test]
fn a_zero_peer_cap_admits_any_number() {
    // `max_peers` 0 means no cap.
    let mut table = capped(0, 3);
    let out = go(&mut table, msg1(large(), 1, 1), 0);
    assert!(!cap(&out), "nothing is refused for the cap: {out:?}");
    assert!(asked(&out).is_some(), "the msg1 is admitted: {out:?}");
}

#[test]
fn a_switch_moves_the_held_record_to_the_new_active_path_in_the_table() {
    // The bundle switched the link's active path from the setup address to
    // a second path; the bundle and the node hold the peer there now.
    let (mut table, link) = dialer(1);
    assert_eq!(
        table.held(&large()).map(|h| h.current.clone()),
        Some(pair(1)),
        "precondition: the peer is held at the dial's address"
    );
    go(&mut table, switched(link, 5), 0);
    assert_eq!(
        table.held(&large()).map(|h| h.current.clone()),
        Some(pair(5)),
        "defect: the core keeps the peer at the path switched away from"
    );
}

/// The pair at `port` on a second transport.
fn other(port: u16) -> Pair {
    Pair {
        transport: TransportId::new(2),
        addr: TransportAddr::from_string(&alloc::format!("10.0.0.1:{port}")),
    }
}

/// The roam resets among `out`.
fn roams(out: &[Output]) -> usize {
    out.iter()
        .filter(|o| {
            matches!(
                o,
                Output::Reset {
                    transition: Transition::Roam,
                    ..
                }
            )
        })
        .count()
}

#[test]
fn a_frame_from_another_transport_moves_nothing_in_the_core() {
    // A one-path bundle follows a frame's source on its own transport only;
    // a frame from another transport leaves the bundle, and the node, with
    // the peer at the active path.
    let (mut table, _) = dialer(1);
    let heard = Input::Heard {
        peer: large(),
        from: other(1),
    };
    let out = go(&mut table, heard, 1_000);
    let h = table
        .held(&large())
        .expect("precondition: the peer is held");
    assert_eq!(
        (h.heard, h.last),
        (true, Some(t(1_000))),
        "the frame sets the peering heard and its last frame"
    );
    assert_eq!(
        (h.current.clone(), roams(&out)),
        (pair(1), 0),
        "defect: the frame moved the core's record of the peer off the active path"
    );
}

#[test]
fn a_one_path_roam_moves_the_cores_record_and_resets_once() {
    // The frame from the new address, then the bundle's roam to it, as a
    // shell feeds them: the roam moves the peer and resets once.
    let (mut table, link) = dialer(1);
    let heard = Input::Heard {
        peer: large(),
        from: pair(4),
    };
    let mut out = go(&mut table, heard, 1_000);
    let roam = Input::Moved {
        link,
        from: pair(1),
        to: pair(4),
        roam: true,
    };
    out.extend(go(&mut table, roam, 1_000));
    assert_eq!(
        table.held(&large()).map(|h| h.current.clone()),
        Some(pair(4)),
        "defect: the roam left the core's record of the peer at the pair it left"
    );
    assert_eq!(
        roams(&out),
        1,
        "defect: the roam did not reset exactly once"
    );
}

#[test]
fn a_path_the_bundle_followed_moves_the_cores_record_and_resets_nothing() {
    // The link holds two paths. A NAT rebinds the peer's address of the
    // active path, and the bundle follows a path message from there: the
    // frame, then the bundle's move, as a shell feeds them. The node runs
    // that move as a column of its own, Follow, and resets nothing as a
    // roam.
    let (mut table, link) = dialer(1);
    let second = Input::State {
        link,
        pair: pair(5),
        proven: Proven::Live,
    };
    go(&mut table, second, 0);
    let heard = Input::Heard {
        peer: large(),
        from: pair(4),
    };
    let mut out = go(&mut table, heard, 1_000);
    let follow = Input::Moved {
        link,
        from: pair(1),
        to: pair(4),
        roam: false,
    };
    out.extend(go(&mut table, follow, 1_000));
    assert_eq!(
        table.held(&large()).map(|h| h.current.clone()),
        Some(pair(4)),
        "defect: the follow left the core's record of the peer at the pair it left"
    );
    assert_eq!(
        roams(&out),
        0,
        "defect: the follow reset the peer's data as a roam"
    );
}

#[test]
fn a_switch_to_an_acknowledged_path_leaves_it_acknowledged() {
    // The bundle hands over to a path acknowledged and not Live, a Suspect
    // one say, and holds it acknowledged: the switch records it so.
    let (mut table, link) = dialer(1);
    let acked = Input::State {
        link,
        pair: pair(5),
        proven: Proven::Acked,
    };
    go(&mut table, acked, 0);
    let handover = Input::Switched {
        link,
        to: pair(5),
        proven: Proven::Acked,
    };
    go(&mut table, handover, 0);
    let rec = table.links().get(link).expect("the table holds the link");
    assert_eq!(
        rec.paths,
        alloc::vec![(pair(5), Proven::Acked)],
        "defect: the switch recorded the acknowledged path as Live"
    );
    assert_eq!(
        table.held(&large()).map(|h| h.current.clone()),
        Some(pair(5)),
        "and the peer is held there"
    );
}

/// A table holding the larger node, heard, from its msg1 1 at port 9,
/// at 40 s: past both floors.
fn held_heard() -> Table<TestInstant> {
    let mut table = Table::new(small(), Params::default());
    let out = hi(&mut table, large(), 1, 9, 0);
    let link = answered(&out);
    go(&mut table, Input::Sent { link }, 0);
    go(
        &mut table,
        Input::Heard {
            peer: large(),
            from: pair(9),
        },
        40_000,
    );
    table
}

/// Redial `n` of the larger node from `port`, answered and sent at `at`:
/// the leg's link.
fn redialed(table: &mut Table<TestInstant>, n: u32, port: u16, at: u64) -> LinkNo {
    let out = greet(table, Input::Redial(read(large(), n, port, E1)), n, at);
    let link = answered(&out);
    let out = go(table, Input::Sent { link }, at);
    assert!(
        !out.iter()
            .any(|o| matches!(o, Output::Opened { .. } | Output::Remove { .. })),
        "defect: a redial's sent answer installed or removed: {out:?}"
    );
    link
}

#[test]
fn a_redial_opens_a_leg_and_leaves_the_held_peer() {
    let mut table = held_heard();
    let before = table.held(&large()).map(|h| h.link);
    let link = redialed(&mut table, 2, 8, 40_100);
    assert_eq!(table.held(&large()).map(|h| h.link), before);
    assert_eq!(table.redialing(&large()), Some(link));
    assert!(table.legs().get(link).is_some());
}

#[test]
fn a_frame_under_a_sent_redial_leg_replaces_the_held_peer_for_redial() {
    let mut table = held_heard();
    let old = table.held(&large()).map(|h| h.link).expect("held");
    let link = redialed(&mut table, 2, 8, 40_100);
    let out = go(
        &mut table,
        Input::LegHeard {
            link,
            from: pair(8),
        },
        40_200,
    );
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Remove {
                why: Why::Redial,
                ..
            }
        )) && out.iter().any(
            |o| matches!(o, Output::Retire { link: l, closes } if *l == old && closes.is_empty())
        ) && out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Replace,
                ..
            }
        )),
        "defect: the leg's frame did not replace the peer for a redial: {out:?}"
    );
    let h = table.held(&large()).expect("held");
    assert!(h.link == link && h.heard && h.current == pair(8));
    assert_eq!(table.redialing(&large()), None);
}

#[test]
fn a_redial_leg_reaped_at_its_deadline_leaves_the_held_peer() {
    let mut table = held_heard();
    let old = table.held(&large()).map(|h| h.link);
    let link = redialed(&mut table, 2, 8, 40_100);
    let out = drain(table.poll(t(40_100 + 30_000)));
    assert!(
        out.iter()
            .any(|o| matches!(o, Output::Retire { link: l, .. } if *l == link)),
        "the leg is reaped: {out:?}"
    );
    assert_eq!(table.held(&large()).map(|h| h.link), old);
    assert_eq!(table.redialing(&large()), None);
    let late = go(
        &mut table,
        Input::LegHeard {
            link,
            from: pair(8),
        },
        70_200,
    );
    assert!(
        late.is_empty(),
        "a reaped leg is heard by nothing: {late:?}"
    );
}

#[test]
fn a_redial_leg_whose_peer_is_gone_installs_at_its_send_and_is_no_longer_a_redial() {
    let mut table = held_heard();
    let out = greet(
        &mut table,
        Input::Redial(read(large(), 2, 8, E1)),
        2,
        40_100,
    );
    let link = answered(&out);
    go(&mut table, Input::Dead { peer: large() }, 40_150);
    let out = go(&mut table, Input::Sent { link }, 40_200);
    assert!(
        out.iter().any(|o| matches!(
            o,
            Output::Reset {
                transition: Transition::Promote,
                ..
            }
        )),
        "{out:?}"
    );
    assert_eq!(table.held(&large()).map(|h| h.link), Some(link));
    assert_eq!(table.redialing(&large()), None);
}

#[test]
fn one_redial_leg_per_identity() {
    let mut table = held_heard();
    let first = redialed(&mut table, 2, 8, 40_100);
    let early = greet(
        &mut table,
        Input::Redial(read(large(), 3, 7, E1)),
        3,
        41_099,
    );
    assert!(
        early.iter().any(|o| matches!(
            o,
            Output::Reject {
                why: Denial::Held,
                ..
            }
        )),
        "{early:?}"
    );
    assert_eq!(table.redialing(&large()), Some(first));
    let late = greet(
        &mut table,
        Input::Redial(read(large(), 3, 7, E1)),
        3,
        41_100,
    );
    assert!(
        late.iter()
            .any(|o| matches!(o, Output::Retire { link, .. } if *link == first)),
        "the older leg is abandoned: {late:?}"
    );
    assert_ne!(table.redialing(&large()), Some(first));
}

#[test]
fn the_redial_memory_refuses_a_seen_ephemeral() {
    let mut table = held_heard();
    let first = redialed(&mut table, 2, 8, 40_100);
    go(&mut table, Input::ConnectFailed { link: first }, 40_200);
    let again = greet(
        &mut table,
        Input::Redial(read(large(), 2, 7, E1)),
        2,
        42_000,
    );
    assert!(
        again.iter().any(|o| matches!(
            o,
            Output::Reject {
                why: Denial::Gate(Refusal::Redialed),
                ..
            }
        )),
        "defect: {again:?}"
    );
}
