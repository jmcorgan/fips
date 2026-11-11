//! The size a path proves (multipath v1 draft, Section 5.1, where padding is
//! local): the ladder a Probing or Dead path's probes step down once a
//! padded one goes unanswered, the upward search on a Live path on a
//! connectionless transport, and the report of each change of the size
//! proven. Every test drives a `Bundle` in the shell,
//! through a stand-in hop that carries a probe only up to a given size and
//! answers what it carries at once, at the size it came.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::shell::*;
use crate::proto::fmp::wire::FRAME_OVERHEAD;
use crate::proto::path::wire::PATH_PROBE_MIN_SIZE;
use crate::proto::path::{Input, Output, PathRef, PathState, Why};
use crate::testutil::TestInstant;

/// A padded probe's length on the default link MTU of 1280.
const PADDED: usize = 1280 - FRAME_OVERHEAD;

/// The ladder's rungs below [`PADDED`]: three quarters and half of it.
const RUNGS: [usize; 2] = [PADDED * 3 / 4, PADDED / 2];

/// What a run through the hop sent and logged.
#[derive(Default)]
struct Seen {
    /// The probes and state changes.
    log: Log,
    /// Each change of proven size reported, in frame bytes.
    proven: Vec<(PathRef, usize)>,
}

impl Seen {
    /// Log the outputs `out` of a step at `n`'s instant.
    fn add(&mut self, n: &Node, out: &[Out]) {
        self.log.add(n.now, out);
        for o in out {
            if let Output::Proven { to, mtu } = o {
                self.proven.push((to.clone(), *mtu));
            }
        }
    }
}

/// Answer at once each probe in `out`, and in the outputs of each answer,
/// that `carries` lets through, given the instant in milliseconds, the
/// probe's pair and its length, and log it all.
fn hop(
    n: &mut Node,
    seen: &mut Seen,
    out: Vec<Out>,
    carries: &mut dyn FnMut(u64, &PathRef, usize) -> bool,
) {
    let mut queue = VecDeque::from([out]);
    while let Some(out) = queue.pop_front() {
        seen.add(n, &out);
        for (to, probe) in probes(&out) {
            if carries(n.now.0, &to, probe.len) {
                queue.push_back(n.ack(to.transport, to.addr.clone(), ack_for(&probe, peer(&to))));
            }
        }
    }
}

/// Poll at every wake up to `until` milliseconds, handling each poll's
/// outputs as [`hop`] does.
fn run_hop(
    n: &mut Node,
    seen: &mut Seen,
    until: u64,
    carries: &mut dyn FnMut(u64, &PathRef, usize) -> bool,
) {
    while let Some(out) = n.tick(TestInstant(until)) {
        hop(n, seen, out, carries);
    }
}

/// A hop that carries every probe on the original path and, on every other,
/// those no longer than `fits` bytes.
fn narrow(fits: usize) -> impl FnMut(u64, &PathRef, usize) -> bool {
    move |_, to, len| *to == p() || len <= fits
}

/// The lengths of the probes on `to` that `log` holds, with their instants.
fn sizes_on(log: &Log, to: &PathRef) -> Vec<(u64, usize)> {
    log.probes
        .iter()
        .filter(|(_, p, _)| p == to)
        .map(|(at, _, probe)| (*at, probe.len))
        .collect()
}

/// The search probes on `to` that `log` holds, with their instants: the
/// probes padded past the smallest size sent after `to` went Live.
fn searches(log: &Log, to: &PathRef) -> Vec<(u64, usize)> {
    let live = log
        .changes(to)
        .iter()
        .find(|c| c.2 == Some(PathState::Live))
        .map(|c| c.0);
    sizes_on(log, to)
        .into_iter()
        .filter(|&(at, len)| live.is_some_and(|l| at > l) && len > PATH_PROBE_MIN_SIZE)
        .collect()
}

/// The states the path on `to` entered, in order.
fn entered(log: &Log, to: &PathRef) -> Vec<Option<PathState>> {
    log.changes(to).iter().map(|c| c.2).collect()
}

#[test]
fn a_probing_path_across_a_hop_narrower_than_its_link_mtu_proves_the_largest_rung_it_carries() {
    // q's link MTU is 1280, and a hop on it carries no frame over 1000
    // bytes. Its first probe, padded, is dropped and times out at 400 ms;
    // the next steps down to three quarters of the padded size, which the
    // hop carries, and proves that size as q goes Live.
    let fits = 1000 - FRAME_OVERHEAD;
    let mut n = Node::capable(301);
    let mut seen = Seen::default();
    let out = n.candidate(t(2), addr(2));
    hop(&mut n, &mut seen, out, &mut narrow(fits));
    run_hop(&mut n, &mut seen, 500, &mut narrow(fits));
    assert_eq!(
        sizes_on(&seen.log, &q()).first(),
        Some(&(0, PADDED)),
        "precondition: q's first probe is padded to the link MTU"
    );
    assert_eq!(
        seen.log.changes(&q()).get(1).map(|c| (c.2, c.3)),
        Some((Some(PathState::Live), Why::Answered)),
        "precondition: q is proven"
    );
    assert_eq!(
        path(&n, &q()).live().mtu(),
        Some(RUNGS[0]),
        "defect: a path across a hop narrower than its link MTU proves the largest size of the \
         ladder the hop carries: {:?}",
        sizes_on(&seen.log, &q())
    );
}

#[test]
fn a_probing_path_whose_probes_all_go_unanswered_steps_down_the_ladder_and_starts_again() {
    // Every probe on q is dropped: its eight discovery probes take the
    // padded size, then each rung, then the smallest, and then start again
    // from the padded size.
    let mut n = Node::capable(302);
    let mut seen = Seen::default();
    let out = n.candidate(t(2), addr(2));
    hop(&mut n, &mut seen, out, &mut narrow(0));
    run_hop(&mut n, &mut seen, 30_000, &mut narrow(0));
    let lens: Vec<usize> = sizes_on(&seen.log, &q())
        .into_iter()
        .map(|(_, len)| len)
        .take(8)
        .collect();
    let cycle = [PADDED, RUNGS[0], RUNGS[1], PATH_PROBE_MIN_SIZE];
    let want: Vec<usize> = cycle.iter().chain(cycle.iter()).copied().collect();
    assert_eq!(
        lens, want,
        "defect: the discovery probes step down the ladder"
    );
}

#[test]
fn a_hop_that_carries_only_the_smallest_size_proves_the_path_with_no_mtu() {
    // A hop narrower than every padded rung: the path is still proven, by
    // the smallest probe, which proves no MTU.
    let mut n = Node::capable(303);
    let mut seen = Seen::default();
    let out = n.candidate(t(2), addr(2));
    hop(&mut n, &mut seen, out, &mut narrow(PATH_PROBE_MIN_SIZE));
    run_hop(&mut n, &mut seen, 5_000, &mut narrow(PATH_PROBE_MIN_SIZE));
    assert_eq!(
        state(&n, &q()),
        PathState::Live,
        "the smallest probe proves q"
    );
    assert_eq!(path(&n, &q()).live().mtu(), None, "and proves no MTU");
}

#[test]
fn after_loss_steps_the_ladder_down_the_search_proves_the_link_mtu_again() {
    // q's first probe, padded, is lost; nothing else is. The ladder's next
    // probe proves three quarters of the padded size, and the search then
    // proves the padded size again. Each change is reported in frame bytes.
    let mut n = Node::capable(304);
    let mut seen = Seen::default();
    let lossy = &mut |at: u64, to: &PathRef, _: usize| *to == p() || at > 0;
    let out = n.candidate(t(2), addr(2));
    hop(&mut n, &mut seen, out, lossy);
    run_hop(&mut n, &mut seen, 5_000, lossy);
    assert_eq!(
        sizes_on(&seen.log, &q()).get(1),
        Some(&(400, RUNGS[0])),
        "precondition: the ladder's next probe takes three quarters of the padded size"
    );
    assert_eq!(state(&n, &q()), PathState::Live, "precondition: q proven");
    assert_eq!(
        path(&n, &q()).live().mtu(),
        Some(PADDED),
        "defect: a larger size proven by the search replaces the smaller one: {:?}",
        sizes_on(&seen.log, &q())
    );
    assert_eq!(
        seen.proven,
        [(q(), RUNGS[0] + FRAME_OVERHEAD), (q(), 1280)],
        "each change of proven size is reported once, in frame bytes"
    );
}

#[test]
fn the_search_stops_at_its_resolution_and_starts_again_after_its_raise_interval() {
    // A hop carries no frame over 1100 bytes. The ladder proves three
    // quarters of the padded size, more than 32 bytes short of the hop's,
    // and the search climbs to within 32 bytes of the hop's size, then
    // sends nothing more until ten minutes on, when it starts again with a
    // probe of the link MTU.
    let fits = 1100 - FRAME_OVERHEAD;
    let mut n = Node::capable(305);
    let mut seen = Seen::default();
    let out = n.candidate(t(2), addr(2));
    hop(&mut n, &mut seen, out, &mut narrow(fits));
    run_hop(&mut n, &mut seen, 60_000, &mut narrow(fits));
    assert!(
        fits - RUNGS[0] > 32,
        "precondition: the rung proven lies outside the search's resolution"
    );
    let mtu = path(&n, &q()).live().mtu().unwrap_or(0);
    let found = searches(&seen.log, &q());
    assert!(
        mtu > fits - 32 && mtu <= fits,
        "defect: the search climbs to within its resolution of the hop's size, not {mtu}: \
         {found:?}"
    );
    assert_eq!(
        found.first().map(|f| f.1),
        Some(PADDED),
        "the link MTU first"
    );
    assert!(
        found.len() <= 8 && found.iter().all(|&(at, _)| at < 30_000),
        "defect: the search stops at its resolution: {found:?}"
    );
    let ended = found.last().map_or(0, |f| f.0);
    run_hop(&mut n, &mut seen, 700_000, &mut narrow(fits));
    let again: Vec<(u64, usize)> = searches(&seen.log, &q())
        .into_iter()
        .filter(|&(at, _)| at > 30_000)
        .collect();
    assert!(
        again
            .first()
            .is_some_and(|&(at, len)| at >= ended + 600_000 && len == PADDED),
        "the search starts again with the link MTU ten minutes after it ended at {ended}: \
         {again:?}"
    );
    assert_eq!(
        path(&n, &q()).live().mtu(),
        Some(mtu),
        "and proves the same size"
    );
}

#[test]
fn a_lost_search_probe_is_no_miss_and_no_loss_sample() {
    // Every search probe over the hop's size is lost; q stays Live with an
    // ETX of 1 and no probe unanswered.
    let fits = 1000 - FRAME_OVERHEAD;
    let mut n = Node::capable(306);
    let mut seen = Seen::default();
    let out = n.candidate(t(2), addr(2));
    hop(&mut n, &mut seen, out, &mut narrow(fits));
    run_hop(&mut n, &mut seen, 60_000, &mut narrow(fits));
    let lost = searches(&seen.log, &q())
        .iter()
        .filter(|&&(_, len)| len > fits)
        .count();
    assert!(lost >= 2, "precondition: search probes were lost");
    let live = path(&n, &q()).live();
    assert_eq!(
        live.etx(),
        1.0,
        "defect: a lost search probe is no loss sample"
    );
    assert_eq!(live.misses(), 0, "defect: a lost search probe is no miss");
    assert_eq!(
        entered(&seen.log, &q()),
        [Some(PathState::Probing), Some(PathState::Live)],
        "defect: q never leaves Live"
    );
}

#[test]
fn no_size_search_runs_on_a_connection_oriented_transport() {
    // q is on a connection-oriented transport, where an oversized probe
    // closes the connection. Its first probe, padded, is lost, so the
    // ladder proves three quarters of the padded size; no probe larger
    // than the smallest goes on q once it is Live.
    let mut n = Node::capable(307).with(Stub::default().oriented(t(2)));
    let mut seen = Seen::default();
    let lossy = &mut |at: u64, to: &PathRef, _: usize| *to == p() || at > 50;
    let out = n.candidate(t(2), addr(2));
    hop(&mut n, &mut seen, out, lossy);
    n.now = TestInstant(50);
    let out = n.step(Input::Connected {
        transport: t(2),
        addr: addr(2),
        ok: true,
    });
    hop(&mut n, &mut seen, out, lossy);
    run_hop(&mut n, &mut seen, 600, lossy);
    assert_eq!(
        path(&n, &q()).live().mtu(),
        Some(RUNGS[0]),
        "precondition: the ladder proves a size below the link MTU"
    );
    run_hop(&mut n, &mut seen, 60_000, lossy);
    assert_eq!(
        searches(&seen.log, &q()),
        [],
        "defect: no size search on a connection-oriented transport"
    );
}
