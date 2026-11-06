//! Authentication failures (multipath v1 draft, Sections 5.3 and 5.6):
//! which frames count and on which path, the reset on an authentic frame,
//! the trip that marks a path Dead when another path is usable, and the
//! warning when none is. Every test drives a `Bundle` in the shell, which
//! also checks after every `charge` that a trip makes the next wake due at
//! once.

use alloc::vec::Vec;

use super::shell::*;
use crate::proto::path::{Charge, Output, PathRef, PathState, Switch, Why};
use crate::testutil::TestInstant;

/// The type byte of a session datagram.
const DATAGRAM: u8 = 0x00;

/// The draft's `AUTH_FAIL_LIMIT`.
const LIMIT: usize = 20;

/// Charge `k` failures from `to` at the node's instant, and return what
/// each did.
fn charges(n: &mut Node, to: &PathRef, k: usize) -> Vec<Charge> {
    (0..k).map(|_| n.charge(to.transport, &to.addr)).collect()
}

/// `k` charges of `what`.
fn each(what: Charge, k: usize) -> Vec<Charge> {
    core::iter::repeat_n(what, k).collect()
}

/// `LIMIT - 1` counted failures and then `last`.
fn up_to(last: Charge) -> Vec<Charge> {
    let mut v = each(Charge::Counted, LIMIT - 1);
    v.push(last);
    v
}

#[test]
fn failures_from_a_pair_neither_original_nor_acked_count_toward_nothing() {
    let mut n = Node::capable(101);
    // A Probing path on transport 2, never acked.
    n.candidate(t(2), addr(2));
    assert_eq!(state(&n, &q()), PathState::Probing);
    let unknown = [pair(t(1), addr(9)), pair(t(3), addr(1)), q()];
    for to in &unknown {
        assert_eq!(
            charges(&mut n, to, 2 * LIMIT),
            each(Charge::Nothing, 2 * LIMIT)
        );
    }
    assert_eq!(path(&n, &p()).live().fails(), 0, "the original path");
    assert_eq!(path(&n, &q()).live().fails(), 0, "the Probing path");
    assert_eq!(state(&n, &p()), PathState::Live);
    assert_eq!(state(&n, &q()), PathState::Probing);
}

#[test]
fn an_acked_dead_path_counts_its_failures() {
    let mut n = two(102);
    shut(&mut n, 10, &q());
    assert_eq!(state(&n, &q()), PathState::Dead);
    assert_eq!(charges(&mut n, &q(), 5), each(Charge::Counted, 5));
    assert_eq!(path(&n, &q()).live().fails(), 5);
    assert_eq!(path(&n, &p()).live().fails(), 0);
}

#[test]
fn an_acked_dead_path_at_the_limit_stays_dead_with_a_warning() {
    let mut n = two(103);
    shut(&mut n, 10, &q());
    let since = path(&n, &q()).dead_since();
    n.now = TestInstant(20);
    assert_eq!(charges(&mut n, &q(), LIMIT), up_to(Charge::Warn));
    let out = n.poll();
    assert!(states(&out).is_empty(), "{out:?}");
    assert_eq!(state(&n, &q()), PathState::Dead);
    assert_eq!(path(&n, &q()).dead_since(), since, "its grace runs on");
}

#[test]
fn at_the_limit_with_another_usable_path_the_path_trips_and_is_dead_from_the_failures_instant() {
    let mut n = two(104);
    assert_eq!(active(&n), Some(p()));
    n.now = TestInstant(30);
    assert_eq!(charges(&mut n, &p(), LIMIT), up_to(Charge::Tripped));
    n.now = TestInstant(50);
    let out = n.poll();
    let id = path(&n, &p()).path_id();
    assert_eq!(
        states(&out)[..1],
        [(
            p(),
            id,
            Some(PathState::Live),
            Some(PathState::Dead),
            Why::AuthLimit
        )]
    );
    assert_eq!(path(&n, &p()).dead_since(), Some(TestInstant(30)));
    let switched = out.iter().any(|o| {
        matches!(o, Output::Switched { from: Some(f), to, why: Switch::Mandatory }
            if *f == p() && *to == q())
    });
    assert!(switched, "{out:?}");
    assert_eq!(active(&n), Some(q()));
}

#[test]
fn an_acked_suspect_path_is_usable_enough_for_a_trip() {
    let mut n = two(112);
    step(&mut n, 10, down(2));
    assert_eq!(state(&n, &q()), PathState::Suspect);
    assert_eq!(charges(&mut n, &p(), LIMIT), up_to(Charge::Tripped));
    let out = n.poll();
    assert_eq!(state(&n, &p()), PathState::Dead);
    let switched = out
        .iter()
        .any(|o| matches!(o, Output::Switched { to, why: Switch::Mandatory, .. } if *to == q()));
    assert!(switched, "{out:?}");
}

#[test]
fn garbage_on_an_acked_standby_marks_it_dead_and_leaves_the_active_path_alone() {
    let mut n = two(105);
    assert_eq!(charges(&mut n, &q(), LIMIT), up_to(Charge::Tripped));
    let out = n.poll();
    assert_eq!(
        states(&out)
            .iter()
            .map(|c| (c.0.clone(), c.3, c.4))
            .collect::<Vec<_>>(),
        [(q(), Some(PathState::Dead), Why::AuthLimit)]
    );
    assert!(
        !out.iter().any(|o| matches!(o, Output::Switched { .. })),
        "{out:?}"
    );
    assert_eq!(active(&n), Some(p()));
    assert_eq!(path(&n, &p()).live().fails(), 0);
}

#[test]
fn at_the_limit_with_no_other_usable_path_the_path_is_kept_and_a_warning_returned() {
    // A link of one path, its peer not known to be capable.
    let mut n = Node::new(106);
    assert_eq!(charges(&mut n, &p(), LIMIT), up_to(Charge::Warn));
    assert_eq!(n.b.next_wake(), None);
    // A capable peer, with the other path only Probing.
    let mut m = Node::capable(106);
    m.candidate(t(2), addr(2));
    assert_eq!(charges(&mut m, &p(), LIMIT), up_to(Charge::Warn));
    // The other path acked and Dead.
    let mut d = two(106);
    shut(&mut d, 10, &q());
    assert_eq!(charges(&mut d, &p(), LIMIT), up_to(Charge::Warn));
    for n in [&mut n, &mut m, &mut d] {
        n.now = TestInstant(n.now.0 + 1);
        n.poll();
        assert_eq!(state(n, &p()), PathState::Live);
        assert_eq!(active(n), Some(p()));
    }
}

#[test]
fn an_authentic_frame_on_a_path_resets_its_failure_count() {
    let mut n = two(107);
    assert_eq!(
        charges(&mut n, &p(), LIMIT - 1),
        each(Charge::Counted, LIMIT - 1)
    );
    assert_eq!(
        charges(&mut n, &q(), LIMIT - 1),
        each(Charge::Counted, LIMIT - 1)
    );
    n.account(t(1), &addr(1), 100, DATAGRAM);
    assert_eq!(path(&n, &p()).live().fails(), 0);
    assert_eq!(
        path(&n, &q()).live().fails(),
        (LIMIT - 1) as u32,
        "only its own path"
    );
    assert_eq!(
        charges(&mut n, &p(), LIMIT - 1),
        each(Charge::Counted, LIMIT - 1)
    );
    assert_eq!(state(&n, &p()), PathState::Live);
}

/// An authentic frame the shell does not account (one too short to carry a
/// message) starts its own path's count again and no other, and one from a
/// pair no path holds starts none.
#[test]
fn an_authentic_frame_resets_only_its_own_paths_count() {
    let mut n = two(113);
    assert_eq!(charges(&mut n, &p(), 3), each(Charge::Counted, 3));
    assert_eq!(charges(&mut n, &q(), 3), each(Charge::Counted, 3));
    n.authentic(t(2), &addr(2));
    assert_eq!(path(&n, &q()).live().fails(), 0, "its own path");
    assert_eq!(path(&n, &p()).live().fails(), 3, "the other path");
    assert_eq!(charges(&mut n, &q(), 2), each(Charge::Counted, 2));
    for to in [pair(t(1), addr(9)), pair(t(3), addr(2))] {
        n.authentic(to.transport, &to.addr);
    }
    assert_eq!(path(&n, &p()).live().fails(), 3, "no path's pair: p");
    assert_eq!(path(&n, &q()).live().fails(), 2, "no path's pair: q");
}

#[test]
fn the_warning_comes_once() {
    let mut n = Node::new(108);
    let got = charges(&mut n, &p(), 25);
    let mut want = up_to(Charge::Warn);
    want.extend(each(Charge::Counted, 5));
    assert_eq!(got, want);
    assert_eq!(path(&n, &p()).live().fails(), 25);
}

#[test]
fn a_recorded_trip_makes_the_next_wake_due_at_once() {
    let mut n = Node::capable(109);
    live_path(&mut n, t(2), addr(2), 0xB);
    n.now = TestInstant(70);
    n.poll();
    let wake = n.b.next_wake().expect("probes are timed");
    assert!(wake > n.now);
    // The shell checks the wake after each charge.
    assert_eq!(charges(&mut n, &p(), LIMIT), up_to(Charge::Tripped));
    assert_eq!(n.b.next_wake(), Some(TestInstant(70)));
    // The poll the shell makes at once applies the trip.
    let out = n.poll();
    assert_eq!(state(&n, &p()), PathState::Dead);
    assert_eq!(active(&n), Some(q()), "{out:?}");
    assert!(n.b.next_wake().is_some_and(|w| w > n.now));
}

#[test]
fn a_trip_no_longer_possible_at_the_step_is_dropped() {
    let mut n = two(110);
    // Each path trips while the other is Live; the step marks the first
    // Dead, after which the second is the only usable path.
    assert_eq!(charges(&mut n, &p(), LIMIT), up_to(Charge::Tripped));
    assert_eq!(charges(&mut n, &q(), LIMIT), up_to(Charge::Tripped));
    let out = n.poll();
    assert_eq!(state(&n, &p()), PathState::Dead);
    assert_eq!(state(&n, &q()), PathState::Live, "{out:?}");
    assert_eq!(active(&n), Some(q()));
    // The dropped trip is not applied by a later step either.
    n.now = TestInstant(1);
    n.poll();
    assert_eq!(state(&n, &q()), PathState::Live);
}

#[test]
fn an_orphaned_bundle_charges_nothing() {
    let mut n = Node::new(111);
    let out = step(&mut n, 10, gone(1));
    assert!(out.iter().any(|o| matches!(o, Output::Orphaned)), "{out:?}");
    assert_eq!(
        charges(&mut n, &p(), 2 * LIMIT),
        each(Charge::Nothing, 2 * LIMIT)
    );
    assert_eq!(n.b.next_wake(), None);
}
