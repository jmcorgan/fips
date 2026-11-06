//! A link started again at the pair FMP v1 moved it to (`Bundle::renew`),
//! as a won crossed handshake starts one (multipath v1 draft, Sections 5.2
//! and 5.4): what the new link keeps of the old one and what it drops.
//! Every test drives a `Bundle` in the shell.

use alloc::vec::Vec;

use super::pin::pin;
use super::shell::*;
use crate::proto::path::{Config, Output, PathRef, PathState, Switch, Why};
use crate::testutil::TestInstant;

/// A renewed link keeps one path at its active path's pair, under a new
/// `path_id`, Live, acked and active, with its slot and its count of failures;
/// the capability record and the candidates go, the operator's pin and the cost
/// hold stay, and only the other path comes back released.
#[test]
fn a_renewed_link_keeps_its_active_paths_pair_slot_and_failure_count() {
    let mut n = Node::capable(60);
    let qi = live_path(&mut n, t(2), addr(2), 0xB);
    n.cost = 3.0;
    assert_eq!(
        switched(&step(&mut n, 100, pin(2))),
        [Switch::Pinned],
        "the pin of q moves the link there"
    );
    n.cost = 5.0;
    assert_eq!(
        switched(&step(&mut n, 200, pin(1))),
        [Switch::Pinned],
        "the pin of p moves it back"
    );
    n.now = TestInstant(250);
    assert_eq!(
        n.b.cost(n.now, 9.0),
        3.0,
        "the cost from before the first change is held"
    );
    for _ in 0..3 {
        n.charge(t(1), &addr(1));
    }
    *n.b.driver_mut(0).expect("p's slot") = Slot::default();
    let marker = n.b.paths().get(0).unwrap().driver().serial;
    let old: Vec<u32> = [0, qi].into_iter().map(|i| n.id(i)).collect();
    assert!(n.b.candidates().iter().count() > 0, "q's candidate is held");

    let out = n.renew();

    assert_eq!(keeps(&out), [(q(), false)], "q alone comes back");
    let paths = n.b.paths();
    assert_eq!(paths.len(), 1);
    let path = paths.get(0).unwrap();
    assert_eq!((path.transport_id(), path.addr()), (t(1), &addr(1)));
    assert!(!old.contains(&path.path_id()), "a new path_id");
    assert_eq!(path.state(), PathState::Live);
    assert!(path.acked());
    assert_eq!(paths.active_index(), Some(0));
    assert_eq!(path.live().fails(), 3, "the failure count carried");
    assert_eq!(path.driver().serial, marker, "the slot carried");
    assert!(!n.b.capable(), "a new link holds no capability record");
    assert_eq!(n.b.candidates().iter().count(), 0);
    assert!(
        n.b.pin().is_some_and(|pin| pin.names(&p())),
        "the pin carried"
    );
    assert_eq!(n.b.cost(n.now, 9.0), 3.0, "the hold carried");
}

/// A link renewed at the pair of a standby path it holds, as when a peer
/// capable of multipath answers a redial from that path's pair (FRC-1201,
/// Section 5.6; multipath v1 draft, Section 5.4), keeps that path as the
/// new link's original path, under a new `path_id`, Live, acked and
/// active, with its slot and its count of failed frames, and does not
/// release it: a release would close the connection the link now sends
/// on. Only the old active path comes back released.
#[test]
fn a_link_renewed_at_a_held_standbys_pair_keeps_that_path_and_releases_only_the_old_active_one() {
    let mut n = Node::capable(62);
    let qi = live_path(&mut n, t(2), addr(2), 0xB);
    assert_eq!(
        active(&n),
        Some(p()),
        "precondition: p is active, q stands by"
    );
    assert!(n.b.capable(), "precondition: the peer is capable");
    for _ in 0..2 {
        n.charge(t(2), &addr(2));
    }
    *n.b.driver_mut(qi).expect("q's slot") = Slot::default();
    let marker = n.b.paths().get(qi).unwrap().driver().serial;
    let old: Vec<u32> = [0, qi].into_iter().map(|i| n.id(i)).collect();

    let out = n.renew_to((t(2), addr(2)));

    let released = keeps(&out);
    assert!(
        released.iter().all(|(to, _)| *to != q()),
        "q, where the link moved, is not released: {released:?}"
    );
    assert_eq!(released.len(), 1, "p alone comes back: {released:?}");
    assert_eq!(released[0].0, p());
    let paths = n.b.paths();
    assert_eq!(paths.len(), 1);
    let path = paths.get(0).unwrap();
    assert_eq!((path.transport_id(), path.addr()), (t(2), &addr(2)));
    assert!(!old.contains(&path.path_id()), "a new path_id");
    assert_eq!(path.state(), PathState::Live);
    assert!(path.acked());
    assert_eq!(paths.active_index(), Some(0));
    assert_eq!(path.live().fails(), 2, "q's failure count carried");
    assert_eq!(path.driver().serial, marker, "q's slot carried");
    assert!(!n.b.capable(), "a new link holds no capability record");
}

/// A logged change of state: the path, its `path_id`, its state before and
/// after, and why.
type Logged = (PathRef, u32, Option<PathState>, Option<PathState>, Why);

/// Every change of state in `out`, in order.
fn logged(out: &[Out]) -> Vec<Logged> {
    out.iter()
        .filter_map(|o| {
            let Output::State {
                to,
                path_id,
                from,
                next,
                why,
            } = o
            else {
                return None;
            };
            Some((to.clone(), *path_id, *from, *next, *why))
        })
        .collect()
}

/// A renewed link logs every old path as ending and its new original path
/// as beginning, each for `Why::Renewed`, the path that stays at the pair
/// included: its `path_id` changes, and a reader of the log that keys paths
/// by `path_id` would otherwise hold the old one open, in the state it was
/// last logged in, and count the new one's probes against it.
#[test]
fn a_renewed_link_logs_each_old_path_ending_and_its_new_original_beginning() {
    let mut n = Node::capable(63);
    let qi = live_path(&mut n, t(2), addr(2), 0xB);
    let old: Vec<u32> = [0, qi].into_iter().map(|i| n.id(i)).collect();

    let out = n.renew_to((t(2), addr(2)));

    let new = n.id(0);
    assert_eq!(
        logged(&out),
        [
            (p(), old[0], Some(PathState::Live), None, Why::Renewed),
            (q(), old[1], Some(PathState::Live), None, Why::Renewed),
            (q(), new, None, Some(PathState::Live), Why::Renewed),
        ],
        "both old paths end and q's pair begins again under its new id"
    );
}

/// A path kept while still Probing logs its ending in that state, as the path
/// a renewal keeps at the msg2's pair can be: a reader of the log holds it open
/// as Probing under its old `path_id` until that line, and the new original
/// begins Live under its new one.
#[test]
fn a_renewed_link_logs_a_kept_probing_path_ending_and_its_pair_beginning_live() {
    let mut n = Node::capable(64);
    n.candidate(t(2), addr(2));
    let qi = n.b.paths().find(t(2), &addr(2)).expect("q is admitted");
    assert_eq!(
        n.b.paths().get(qi).unwrap().state(),
        PathState::Probing,
        "precondition: q is still Probing"
    );
    let old: Vec<u32> = [0, qi].into_iter().map(|i| n.id(i)).collect();

    let out = n.renew_to((t(2), addr(2)));

    let new = n.id(0);
    assert_eq!(
        logged(&out),
        [
            (p(), old[0], Some(PathState::Live), None, Why::Renewed),
            (q(), old[1], Some(PathState::Probing), None, Why::Renewed),
            (q(), new, None, Some(PathState::Live), Why::Renewed),
        ],
        "q ends as Probing and its pair begins again Live under its new id"
    );
}

/// A link renewed at a pair its active path is not on, as when the winning
/// msg2 of a crossed dial came from another transport or address (multipath
/// v1 draft, Section 5.4), starts again with one path at that pair, under a
/// new `path_id`, Live, acked and active, with a slot of its own and no
/// failed frame counted; the old active path comes back released, marked
/// to keep while the peer is not known to be capable, as `close` marks it.
#[test]
fn a_link_renewed_at_another_pair_starts_there_and_releases_its_old_path() {
    let mut n = Node::new(61);
    for _ in 0..3 {
        n.charge(t(1), &addr(1));
    }
    *n.b.driver_mut(0).expect("p's slot") = Slot::default();
    let marker = n.b.paths().get(0).unwrap().driver().serial;
    let old = n.id(0);

    let out = n.renew_to((t(2), addr(2)));

    assert_eq!(keeps(&out), [(p(), true)], "p comes back, kept");
    let paths = n.b.paths();
    assert_eq!(paths.len(), 1);
    let path = paths.get(0).unwrap();
    assert_eq!((path.transport_id(), path.addr()), (t(2), &addr(2)));
    assert_ne!(path.path_id(), old, "a new path_id");
    assert_eq!(path.state(), PathState::Live);
    assert!(path.acked());
    assert_eq!(paths.active_index(), Some(0));
    assert_eq!(path.live().fails(), 0, "no failure counted on the new pair");
    assert_ne!(path.driver().serial, marker, "a slot of its own");
    assert!(!n.b.capable(), "a new link holds no capability record");
}

/// A renewed link's record of capability probes starts again with it
/// (multipath v1 draft, Sections 5.2 and 5.4): a candidate offered at the
/// renewal instant gets a new first round of probes from that instant, not
/// the rest of the old link's round.
#[test]
fn a_renewed_link_starts_its_capability_probes_with_a_new_first_round() {
    let cfg = Config::draft();
    let mut n = Node::new(61);
    let out = n.candidate(t(2), addr(2));
    probe_on(&out, &p());
    let mut log = Log::default();
    let renewal = 15_000;
    run(&mut n, &mut log, renewal, &mut |_, _| false);
    let before: Vec<u64> = log
        .probes
        .iter()
        .filter(|(_, to, _)| *to == p())
        .map(|(at, _, _)| *at)
        .collect();
    assert_eq!(
        before,
        [ms(spacing(1, &cfg))],
        "precondition: the old link's second probe went, its third not yet"
    );
    assert_eq!(n.b.capability().sent(), 2, "precondition: two probes sent");

    n.now = TestInstant(renewal);
    n.renew();
    assert_eq!(n.b.capability().sent(), 0, "the record starts again");
    let out = n.candidate(t(2), addr(2));
    probe_on(&out, &p());
    let mut log = Log::default();
    let end = 70_000;
    run(&mut n, &mut log, end, &mut |_, _| false);

    let mut expected = alloc::vec![renewal];
    for k in 1..=3 {
        let last = *expected.last().unwrap();
        expected.push(last + ms(spacing(k, &cfg)));
    }
    assert!(
        *expected.last().unwrap() <= end,
        "the fourth falls inside the run"
    );
    let mut after: Vec<u64> = alloc::vec![renewal];
    after.extend(
        log.probes
            .iter()
            .filter(|(_, to, _)| *to == p())
            .map(|(at, _, _)| *at),
    );
    assert_eq!(
        after, expected,
        "a first round of {} over the span from the renewal, then one span on",
        cfg.budget
    );
    assert!(
        !after.contains(&(ms(spacing(1, &cfg)) * 2)),
        "none where the old record would have sent its third"
    );
    assert_eq!(
        n.b.capability().sent(),
        4,
        "the record counts from the renewal"
    );
}

/// `d` in whole milliseconds.
fn ms(d: crate::time::Duration) -> u64 {
    u64::try_from(d.as_millis()).expect("a span in range")
}

/// The reason of every change of active path in `out`, in order.
fn switched(out: &[Out]) -> Vec<Switch> {
    out.iter()
        .filter_map(|o| {
            let crate::proto::path::Output::Switched { why, .. } = o else {
                return None;
            };
            Some(*why)
        })
        .collect()
}
