//! The return to the path a mandatory change left
//! (`proto::path::tests::returns::...`), driven through `Bundle`'s inputs
//! in the shell, with every path's round trips set by a `Net` from its
//! first probe on. An outage is a span in which a path's probes go
//! unanswered.

use alloc::vec;

use super::choice::{offer, run, start};
use super::shell::{Net, Node, active, p, path, q, r, scored};
use crate::proto::path::{Config, PathRef, PathState, Switch};

/// When the outage of p starts, in milliseconds.
const CUT: u64 = 40_000;

/// When it ends.
const HEAL: u64 = CUT + 2_000;

/// The round trip on `to` at `now`: 5 ms on p outside the outage and no
/// answer in it, 25 ms on q, `on_r` on r where given, and no answer
/// anywhere else. Idle, q scores within the switch margin of p.
fn rtts(now: u64, to: &PathRef, on_r: Option<u64>) -> Option<u64> {
    if *to == p() {
        (!(CUT..HEAL).contains(&now)).then_some(5)
    } else if *to == q() {
        Some(25)
    } else if *to == r() {
        on_r
    } else {
        None
    }
}

/// Whether p is Live and scores better than q, both with enough samples,
/// by any amount.
fn ahead(n: &Node, cfg: &Config) -> bool {
    let min = usize::from(cfg.min_samples);
    path(n, &p()).state() == PathState::Live
        && scored(n, &p(), min)
            .zip(scored(n, &q(), min))
            .is_some_and(|(on_p, on_q)| on_p < on_q)
}

/// Whether p scores better than q by `cfg`'s margin, both with enough
/// samples: what a discretionary change on score from q to p waits on
/// without the return.
fn leads(n: &Node, cfg: &Config) -> bool {
    let min = usize::from(cfg.min_samples);
    scored(n, &p(), min)
        .zip(scored(n, &q(), min))
        .is_some_and(|(on_p, on_q)| on_q > on_p * cfg.switch_margin)
}

#[test]
fn a_path_a_mandatory_change_left_is_returned_to_one_dwell_after_it_outscores_within_the_margin() {
    let cfg = Config::draft();
    let rtt = |now: u64, to: &PathRef| rtts(now, to, None);
    let mut net = Net::new(&rtt);
    let mut n = start(960, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, CUT), vec![], "idle, p keeps the link");
    let left = run(&mut n, &mut net, HEAL);
    assert!(
        matches!(left.as_slice(), [(_, Some(from), to, Switch::Mandatory)] if *from == p() && *to == q()),
        "precondition: the outage moved the link from p to q by the mandatory rule, {left:?}"
    );
    let mut first = None;
    let mut led = false;
    let seen = net.run(&mut n, HEAL + 20_000, &mut |n, at| {
        if first.is_none() && ahead(n, &cfg) {
            first = Some(at);
        }
        led |= leads(n, &cfg);
    });
    let first = first.expect("p, Live again, outscores q");
    assert!(!led, "precondition: p never beats q by the margin");
    assert_eq!(
        seen,
        vec![(first + 2_000, Some(q()), p(), Switch::Discretionary)],
        "defect: the return to p, Live again and ahead of q from {first} ms, waited on the margin"
    );
}

#[test]
fn after_a_mandatory_change_a_path_it_did_not_leave_still_needs_the_margin() {
    let cfg = Config::draft();
    // r, offered after the change, answers in 21 ms: ahead of q, within
    // the margin of it. p does not come back.
    let rtt = |now: u64, to: &PathRef| {
        if *to == p() && now >= CUT {
            None
        } else {
            rtts(now, to, Some(21))
        }
    };
    let mut net = Net::new(&rtt);
    let mut n = start(961, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, CUT), vec![], "idle, p keeps the link");
    let left = run(&mut n, &mut net, HEAL);
    assert!(
        matches!(left.as_slice(), [(_, Some(from), to, Switch::Mandatory)] if *from == p() && *to == q()),
        "precondition: the outage moved the link from p to q by the mandatory rule, {left:?}"
    );
    offer(&mut n, &mut net, &r());
    let min = usize::from(cfg.min_samples);
    let mut ahead = false;
    let seen = net.run(&mut n, HEAL + 20_000, &mut |n, _| {
        ahead |= scored(n, &r(), min)
            .zip(scored(n, &q(), min))
            .is_some_and(|(on_r, on_q)| on_r < on_q && on_q <= on_r * cfg.switch_margin);
    });
    assert!(
        ahead,
        "precondition: r scores ahead of q, within the margin"
    );
    assert_eq!(
        seen,
        vec![],
        "defect: r took the link from q within the margin"
    );
    assert_eq!(active(&n), Some(q()));
}
