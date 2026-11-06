//! The active path (multipath v1 draft, Sections 5.6 and 5.7): the
//! mandatory change of active path when it fails, the probes sent at once
//! to acked Dead paths, and to acked paths being probed again after Dead,
//! when nothing is Live, the removal of a local
//! transport and the handover it may force, and the bundle reporting
//! itself orphaned when no original or acked path is left. Every test
//! drives a `Bundle` in the shell, which also checks after every step that
//! no switch goes to a path not acked, that an active path is held while
//! an acked path is, that the bundle is orphaned at most once, and that no
//! path is released while it is active except as its transport goes.

use alloc::vec::Vec;

use super::shell::*;
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::path::wire::PathProbe;
use crate::proto::path::{Account, Input, Output, PathRef, PathState, Roam, Source, Switch, Why};
use crate::testutil::{TestInstant, allocations};

/// The type byte of a heartbeat, a link message that marks the peer's
/// active path.
const HEARTBEAT: u8 = 0x51;

/// A padded probe's length on a link MTU of 1280.
const PADDED: usize = 1280 - FRAME_OVERHEAD;

/// The fourth path, on transport 4.
fn s() -> PathRef {
    pair(t(4), addr(4))
}

/// The switches in `out`: from, to and why.
fn switched(out: &[Out]) -> Vec<(Option<PathRef>, PathRef, Switch)> {
    out.iter()
        .filter_map(|o| {
            let Output::Switched { from, to, why } = o else {
                return None;
            };
            Some((from.clone(), to.clone(), *why))
        })
        .collect()
}

/// How many times `out` reports the bundle orphaned.
fn orphaned(out: &[Out]) -> usize {
    out.iter().filter(|o| matches!(o, Output::Orphaned)).count()
}

/// Poll at every wake up to `until` milliseconds, answering nothing, and
/// return every output.
fn silent(n: &mut Node, until: u64) -> Vec<Out> {
    let mut all = Vec::new();
    while let Some(out) = n.tick(TestInstant(until)) {
        all.extend(out);
    }
    all
}

#[test]
fn when_the_active_path_goes_suspect_traffic_moves_to_a_live_path() {
    let mut n = two(71);
    let out = step(&mut n, 100, down(1));
    assert_eq!(state(&n, &p()), PathState::Suspect);
    assert_eq!(switched(&out), [(Some(p()), q(), Switch::Mandatory)]);
    assert_eq!(active(&n), Some(q()));
    // Our path messages say so: ACTIVE on the new active path only.
    let out = n.tick(TestInstant(200)).expect("a wake at 200 ms");
    assert!(probe_on(&out, &q()).flags.active());
    assert!(!probe_on(&out, &p()).flags.active());
}

#[test]
fn the_mandatory_switch_prefers_an_acked_suspect_path_over_staying_on_a_dead_active_path() {
    let mut n = Node::capable(72);
    live_path(&mut n, t(2), addr(2), 0xB);
    let out = step(&mut n, 10, down(2));
    assert!(switched(&out).is_empty(), "{out:?}");
    assert_eq!(state(&n, &q()), PathState::Suspect);
    let out = shut(&mut n, 20, &p());
    assert_eq!(state(&n, &p()), PathState::Dead);
    assert_eq!(switched(&out), [(Some(p()), q(), Switch::Mandatory)]);
    assert_eq!(active(&n), Some(q()));
}

#[test]
fn a_suspect_active_path_with_nothing_live_stays_active_beside_a_faster_suspect_path() {
    let mut n = Node::capable(73);
    let out = n.candidate(t(2), addr(2));
    let (on_p, on_q) = (probe_on(&out, &p()), probe_on(&out, &q()));
    n.ack(t(2), addr(2), ack_for(&on_q, 0xB));
    n.now = TestInstant(100);
    n.ack(t(1), addr(1), ack_for(&on_p, 0xA));
    let rtt = |to: &PathRef| path(&n, to).live().rtt().expect("a round trip");
    assert!(rtt(&q()) < rtt(&p()));
    step(&mut n, 150, down(2));
    let out = step(&mut n, 160, down(1));
    assert_eq!(state(&n, &p()), PathState::Suspect);
    assert_eq!(state(&n, &q()), PathState::Suspect);
    assert!(switched(&out).is_empty(), "{out:?}");
    // Both stay Suspect for these polls: the active path is not swapped
    // for the other Suspect one, however much faster.
    let out = silent(&mut n, 1_500);
    assert!(switched(&out).is_empty(), "{out:?}");
    assert_eq!(state(&n, &p()), PathState::Suspect);
    assert_eq!(state(&n, &q()), PathState::Suspect);
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn a_dead_active_path_with_nothing_live_or_suspect_stays_active_and_nothing_is_orphaned() {
    let mut n = Node::capable(74);
    live_path(&mut n, t(2), addr(2), 0xB);
    shut(&mut n, 0, &q());
    let out = shut(&mut n, 10, &p());
    assert!(switched(&out).is_empty(), "{out:?}");
    let out = silent(&mut n, 120_000);
    assert!(switched(&out).is_empty(), "{out:?}");
    assert_eq!(orphaned(&out), 0);
    assert_eq!(state(&n, &p()), PathState::Dead);
    assert_eq!(state(&n, &q()), PathState::Dead);
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn acked_dead_paths_are_probed_at_once_when_the_active_path_leaves_live_with_nothing_live() {
    let mut n = Node::capable(75);
    live_path(&mut n, t(2), addr(2), 0xB);
    live_path(&mut n, t(3), addr(3), 0xC);
    shut(&mut n, 0, &q());
    shut(&mut n, 0, &r());
    // The Dead cadence would probe them first at 1 s.
    assert_eq!(path(&n, &q()).live().next_at(), Some(TestInstant(1_000)));
    let out = step(&mut n, 300, down(1));
    assert_eq!(probe_on(&out, &q()).len, PADDED);
    assert_eq!(probe_on(&out, &r()).len, PADDED);
    assert_eq!(state(&n, &q()), PathState::Dead);
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn a_removed_transport_discards_its_paths_and_releases_them() {
    let mut n = Node::capable(76);
    live_path(&mut n, t(2), addr(2), 0xB);
    let other = pair(t(2), addr(5));
    n.candidate(t(2), addr(5));
    let (live, probing) = (path(&n, &q()).path_id(), path(&n, &other).path_id());
    let out = step(&mut n, 10, gone(2));
    assert_eq!(
        states(&out),
        [
            (q(), live, Some(PathState::Live), None, Why::Removed),
            (
                other.clone(),
                probing,
                Some(PathState::Probing),
                None,
                Why::Removed
            ),
        ]
    );
    let pairs: Vec<PathRef> = released(&out).into_iter().map(|(to, _)| to).collect();
    assert_eq!(pairs, [q(), other]);
    assert_eq!(n.b.paths().len(), 1);
    assert!(switched(&out).is_empty(), "{out:?}");
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn when_the_active_transport_goes_the_acked_dead_path_last_live_takes_over_and_is_probed_at_once() {
    let mut n = Node::capable(77);
    live_path(&mut n, t(2), addr(2), 0xB);
    live_path(&mut n, t(3), addr(3), 0xC);
    // The third path is Dead longest; the second was Live most recently.
    shut(&mut n, 100, &r());
    shut(&mut n, 200, &q());
    let out = step(&mut n, 300, gone(1));
    assert_eq!(orphaned(&out), 0);
    assert_eq!(switched(&out), [(None, q(), Switch::Handover)]);
    assert_eq!(active(&n), Some(q()));
    assert_eq!(probe_on(&out, &q()).len, PADDED);
    assert_eq!(probe_on(&out, &r()).len, PADDED);
    assert!(probe_on(&out, &q()).flags.active());
}

#[test]
fn when_the_active_path_is_discarded_with_nothing_live_every_acked_dead_path_is_probed_at_once() {
    let mut n = Node::capable(78);
    live_path(&mut n, t(2), addr(2), 0xB);
    live_path(&mut n, t(3), addr(3), 0xC);
    live_path(&mut n, t(4), addr(4), 0xD);
    shut(&mut n, 100, &r());
    shut(&mut n, 100, &s());
    step(&mut n, 150, down(2));
    let out = step(&mut n, 200, gone(1));
    assert_eq!(switched(&out), [(None, q(), Switch::Handover)]);
    assert_eq!(state(&n, &q()), PathState::Suspect);
    assert_eq!(probe_on(&out, &r()).len, PADDED);
    assert_eq!(probe_on(&out, &s()).len, PADDED);
}

#[test]
fn when_a_suspect_active_path_goes_dead_with_nothing_live_the_acked_dead_paths_are_probed_at_once()
{
    let mut n = Node::capable(79);
    live_path(&mut n, t(2), addr(2), 0xB);
    shut(&mut n, 0, &q());
    // The active path leaves Live: the Dead path is probed at once.
    let out = step(&mut n, 100, down(1));
    probe_on(&out, &q());
    assert_eq!(path(&n, &q()).live().outstanding(), 1);
    // The active path goes on from Suspect to Dead while that probe is
    // out: the Dead path is probed at once again.
    let out = shut(&mut n, 450, &p());
    assert_eq!(state(&n, &p()), PathState::Dead);
    probe_on(&out, &q());
    assert_eq!(path(&n, &q()).live().outstanding(), 2);
}

#[test]
fn with_no_original_or_acked_path_left_the_bundle_is_orphaned_once() {
    let mut n = Node::capable(80);
    let created = q();
    n.candidate(t(2), addr(2));
    let id = n.id(0);
    let out = step(&mut n, 100, gone(1));
    assert_eq!(orphaned(&out), 1, "{out:?}");
    assert!(switched(&out).is_empty(), "{out:?}");
    assert_eq!(
        states(&out),
        [(p(), id, Some(PathState::Live), None, Why::Removed)]
    );
    // The Probing path is held, never active, and nothing is timed.
    assert_eq!(n.b.paths().len(), 1);
    assert_eq!(active(&n), None);
    assert_eq!(n.b.next_wake(), None);
    // The bundle answers nothing after it.
    let after = [
        Input::Poll,
        Input::Probe {
            transport: t(2),
            addr: addr(2),
            msg: probe_from(0xB, 1, 27),
        },
        Input::Candidate {
            transport: t(3),
            addr: addr(3),
            source: Source::Config,
        },
        gone(2),
    ];
    for (k, input) in after.into_iter().enumerate() {
        let out = step(&mut n, 5_000 + k as u64, input);
        assert!(out.is_empty(), "{out:?}");
    }
    assert_eq!(state(&n, &created), PathState::Probing);
    let out = n.close();
    assert_eq!(released(&out).len(), 1);
}

#[test]
fn after_orphaned_account_binds_nothing_and_allocates_nothing() {
    let mut n = Node::capable(81);
    let out = step(&mut n, 10, gone(1));
    assert_eq!(orphaned(&out), 1);
    assert!(n.b.paths().is_empty());
    let a1 = addr(1);
    let nothing = Account {
        path: None,
        sample: false,
        roam: Roam::Unmoved,
    };
    let before = allocations();
    for k in 0..100u64 {
        let got = n.b.account(TestInstant(20 + k), t(1), &a1, 100, HEARTBEAT);
        assert!(got == nothing);
    }
    assert_eq!(allocations(), before, "account allocated");
    assert!(n.b.paths().is_empty(), "a frame bound a path");
}

#[test]
fn a_dead_active_path_past_its_grace_is_discarded_in_the_step_another_path_turns_live() {
    let mut n = Node::capable(82);
    live_path(&mut n, t(2), addr(2), 0xB);
    shut(&mut n, 0, &q());
    shut(&mut n, 10, &p());
    let id = n.id(0);
    silent(&mut n, 650_000);
    assert_eq!(active(&n), Some(p()), "kept past its grace while active");
    // The second path answers its next Dead probe.
    let probe: PathProbe = loop {
        let out = n.tick(TestInstant(800_000)).expect("a Dead probe");
        if let Some((_, probe)) = probes(&out).into_iter().find(|(to, _)| *to == q()) {
            break probe;
        }
    };
    let out = n.ack(t(2), addr(2), ack_for(&probe, 0xB));
    assert_eq!(switched(&out), [(Some(p()), q(), Switch::Mandatory)]);
    assert!(
        states(&out).contains(&(p(), id, Some(PathState::Dead), None, Why::Grace)),
        "{out:?}"
    );
    let pairs: Vec<PathRef> = released(&out).into_iter().map(|(to, _)| to).collect();
    assert_eq!(pairs, [p()]);
    assert_eq!(n.b.paths().len(), 1);
}

#[test]
fn losing_the_active_transport_moves_traffic_to_a_live_standby() {
    let mut n = Node::capable(83);
    // The second path's round trip is 100 ms, the third's none.
    let out = n.candidate(t(2), addr(2));
    let on_q = probe_on(&out, &q());
    n.now = TestInstant(100);
    n.ack(t(2), addr(2), ack_for(&on_q, 0xB));
    live_path(&mut n, t(3), addr(3), 0xC);
    let out = step(&mut n, 150, gone(1));
    assert_eq!(switched(&out), [(None, r(), Switch::Handover)]);
    assert_eq!(active(&n), Some(r()));
    assert_eq!(orphaned(&out), 0);
}

#[test]
fn losing_a_standby_transport_leaves_the_active_path_where_it_is() {
    let mut n = Node::capable(84);
    // The original's round trip is 100 ms; the other two answer at once.
    let out = n.candidate(t(2), addr(2));
    let (on_p, on_q) = (probe_on(&out, &p()), probe_on(&out, &q()));
    n.ack(t(2), addr(2), ack_for(&on_q, 0xB));
    n.now = TestInstant(100);
    n.ack(t(1), addr(1), ack_for(&on_p, 0xA));
    live_path(&mut n, t(3), addr(3), 0xC);
    let id = path(&n, &q()).path_id();
    let out = step(&mut n, 150, gone(2));
    assert_eq!(
        states(&out),
        [(q(), id, Some(PathState::Live), None, Why::Removed)]
    );
    assert!(switched(&out).is_empty(), "{out:?}");
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn released_keep_is_true_only_for_the_peers_active_path() {
    let mut n = Node::capable(86);
    live_path(&mut n, t(2), addr(2), 0xB);
    let other = pair(t(2), addr(5));
    n.candidate(t(2), addr(5));
    // The peer sends its link messages on the second path.
    n.account(t(2), &addr(2), 100, HEARTBEAT);
    let out = step(&mut n, 10, gone(2));
    assert_eq!(keeps(&out), [(q(), true), (other, false)]);
}

#[test]
fn no_switch_goes_to_a_path_not_acked() {
    let mut n = Node::capable(87);
    n.candidate(t(2), addr(2));
    // The peer's own probe on the path: answered, and still not acked.
    step(
        &mut n,
        5,
        Input::Probe {
            transport: t(2),
            addr: addr(2),
            msg: probe_from(0xB, 1, 27),
        },
    );
    let mut out = shut(&mut n, 10, &p());
    out.extend(silent(&mut n, 20_000));
    assert_eq!(state(&n, &q()), PathState::Probing);
    assert!(switched(&out).is_empty(), "{out:?}");
    assert_eq!(active(&n), Some(p()));
    // With the original gone, no acked path is left.
    let out = step(&mut n, 20_000, gone(1));
    assert!(switched(&out).is_empty(), "{out:?}");
    assert_eq!(orphaned(&out), 1);
}

/// With nothing Live, a Suspect path made active in place of a discarded
/// active path is probed in the step that makes it active (draft Section
/// 5.7), not at its next standby probe.
#[test]
fn a_suspect_path_made_active_at_a_discard_is_probed_at_once() {
    let mut n = Node::capable(91);
    live_path(&mut n, t(2), addr(2), 0xB);
    let out = step(&mut n, 150, down(2));
    let at150 = probes(&out).into_iter().filter(|(p, _)| *p == q()).count();
    assert_eq!(state(&n, &q()), PathState::Suspect);
    let out = step(&mut n, 160, gone(1));
    assert_eq!(switched(&out), [(None, q(), Switch::Handover)]);
    let on_q = probes(&out).into_iter().filter(|(p, _)| *p == q()).count();
    assert_eq!(on_q, 1, "probes on q at 150: {at150}, at 160: {out:?}");
}

/// With nothing Live, an acked path being probed again after Dead and made
/// active in place of a discarded active path is probed in the step that
/// makes it active (draft Section 5.7), not at the end of its backoff.
#[test]
fn an_acked_probing_path_made_active_at_a_discard_is_probed_at_once() {
    let mut n = Node::capable(92);
    live_path(&mut n, t(2), addr(2), 0xB);
    shut(&mut n, 100, &q());
    assert_eq!(state(&n, &q()), PathState::Dead);
    step(&mut n, 150, down(2));
    let out = step(
        &mut n,
        200,
        Input::Carrier {
            transport: t(2),
            up: true,
        },
    );
    let at200 = probes(&out).into_iter().filter(|(p, _)| *p == q()).count();
    assert_eq!(state(&n, &q()), PathState::Probing, "{out:?}");
    let out = step(&mut n, 210, gone(1));
    assert_eq!(switched(&out), [(None, q(), Switch::Handover)]);
    let on_q = probes(&out).into_iter().filter(|(p, _)| *p == q()).count();
    assert_eq!(on_q, 1, "probes on q at 200: {at200}, at 210: {out:?}");
}

/// The standby, acked, starves until it is Dead, and the peer's probe on
/// it brings it back to Probing, as in the flap suites; its own probes go
/// unanswered. When the active path then times out with nothing Live, the
/// standby is probed in the step the active path goes Suspect (draft
/// Section 5.7), not at its next scheduled probe.
#[test]
fn a_standby_the_peers_probe_revived_to_probing_is_probed_at_once_when_the_active_path_times_out() {
    let mut n = two(93);
    let mut log = Log::default();
    let mut only_p = |_: u64, to: &PathRef| *to == p();
    run(&mut n, &mut log, 30_000, &mut only_p);
    assert_eq!(
        state(&n, &q()),
        PathState::Dead,
        "precondition: q starved to Dead"
    );
    let revived = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: probe_from(peer(&q()), 9, 1200),
    };
    at(&mut n, &mut log, 30_000, revived);
    assert_eq!(
        state(&n, &q()),
        PathState::Probing,
        "precondition: q revived"
    );
    assert!(path(&n, &q()).acked(), "precondition: q acked in this link");
    run(&mut n, &mut log, 34_000, &mut only_p);
    let last = *log.on(&q()).last().expect("q probed since its revival");
    let fail = last + 600;
    run(&mut n, &mut log, fail, &mut only_p);
    let next = path(&n, &q()).live().next_at().expect("a next probe on q");
    assert_eq!(
        state(&n, &q()),
        PathState::Probing,
        "precondition: still Probing"
    );
    // From here nothing is answered: p times out.
    let mut none = |_: u64, _: &PathRef| false;
    run(&mut n, &mut log, fail + 3_000, &mut none);
    let left = log
        .changes(&p())
        .into_iter()
        .find(|c| c.0 > fail && c.2 == Some(PathState::Suspect))
        .expect("p went Suspect")
        .0;
    assert!(
        next.0 > left,
        "precondition: q's scheduled probe ({}) falls after p leaves Live ({left}); q probed at {:?}",
        next.0,
        log.on(&q())
    );
    let on_q: Vec<u64> = log.on(&q()).into_iter().filter(|at| *at > fail).collect();
    assert_eq!(
        on_q.first().copied(),
        Some(left),
        "q, acked and Probing, is probed when p leaves Live with nothing Live \
         (probes on q after {fail}: {on_q:?}; scheduled at {})",
        next.0
    );
}

/// A standby revived to Probing by the peer's probe that has sent seven
/// unanswered probes and has its eighth outstanding has sent all its
/// discovery probes (draft Section 5.6): when the active path fails with
/// nothing Live, it is not probed at once, and it goes Dead when the
/// eighth times out.
#[test]
fn a_revived_standby_that_has_sent_its_discovery_probes_is_not_probed_at_once_when_the_active_path_fails()
 {
    let mut n = two(94);
    let mut log = Log::default();
    let mut only_p = |_: u64, to: &PathRef| *to == p();
    run(&mut n, &mut log, 30_000, &mut only_p);
    assert_eq!(
        state(&n, &q()),
        PathState::Dead,
        "precondition: q starved to Dead"
    );
    let revived = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: probe_from(peer(&q()), 9, 1200),
    };
    at(&mut n, &mut log, 30_000, revived);
    assert_eq!(
        state(&n, &q()),
        PathState::Probing,
        "precondition: q revived"
    );
    assert!(path(&n, &q()).acked(), "precondition: q acked in this link");
    let mut ms = 30_000;
    loop {
        let live = path(&n, &q()).live();
        if live.misses() == 7 && live.outstanding() == 1 {
            break;
        }
        assert_eq!(
            state(&n, &q()),
            PathState::Probing,
            "q left Probing at {ms}"
        );
        ms += 10;
        assert!(
            ms < 200_000,
            "q never reached seven misses and one outstanding"
        );
        run(&mut n, &mut log, ms, &mut only_p);
    }
    assert_eq!(
        state(&n, &p()),
        PathState::Live,
        "precondition: p Live at {ms}"
    );
    // Carrier loss takes p Suspect inside the one timeout in which q has
    // sent all eight and is still Probing.
    let out = step(&mut n, ms + 1, down(1));
    assert_eq!(state(&n, &p()), PathState::Suspect, "{out:?}");
    assert_eq!(
        state(&n, &q()),
        PathState::Probing,
        "precondition: nothing Live"
    );
    let on_q = probes(&out)
        .into_iter()
        .filter(|(to, _)| *to == q())
        .count();
    assert_eq!(
        on_q, 0,
        "q, its discovery probes sent, sends nothing at once: {out:?}"
    );
    let mut none = |_: u64, _: &PathRef| false;
    run(&mut n, &mut log, ms + 120_000, &mut none);
    assert_eq!(
        state(&n, &q()),
        PathState::Dead,
        "q Dead when its eighth times out"
    );
}

/// A standby, acked, Dead and stopped, brought back to Probing by its
/// carrier's return stays stopped, so its next probe waits for the floor.
/// When the active path fails before then with nothing Live, the standby
/// is probed in that step (draft Section 5.7), as one the peer's probe
/// revived would be.
#[test]
fn a_standby_brought_back_by_carrier_is_probed_at_once_when_the_active_path_fails() {
    let mut n = Node::capable(95);
    live_path(&mut n, t(2), addr(2), 0xB);
    shut(&mut n, 100, &q());
    assert_eq!(state(&n, &q()), PathState::Dead, "precondition: q Dead");
    step(&mut n, 150, down(2));
    let out = step(
        &mut n,
        200,
        Input::Carrier {
            transport: t(2),
            up: true,
        },
    );
    assert_eq!(state(&n, &q()), PathState::Probing, "precondition: {out:?}");
    assert!(path(&n, &q()).acked(), "precondition: q acked in this link");
    assert!(path(&n, &q()).live().stopped(), "precondition: q stopped");
    let at200 = probes(&out)
        .into_iter()
        .filter(|(to, _)| *to == q())
        .count();
    assert_eq!(
        at200, 0,
        "precondition: q's probe is held by the floor: {out:?}"
    );
    let next = path(&n, &q()).live().next_at().expect("a next probe on q");
    assert!(
        next > TestInstant(210),
        "precondition: q's next probe ({next:?}) falls after 210 ms"
    );
    let out = step(&mut n, 210, down(1));
    assert_eq!(state(&n, &p()), PathState::Suspect, "{out:?}");
    let on_q = probes(&out)
        .into_iter()
        .filter(|(to, _)| *to == q())
        .count();
    assert_eq!(
        on_q, 1,
        "q, acked and Probing, is probed when p fails: {out:?}"
    );
}
