//! The hold on a link's cost across a change of active path
//! (`proto::path::tests::hold::...`), driven through `Bundle`'s inputs in
//! the shell, with every path's round trips set by a `Net` from its first
//! probe on. The shell gives the bundle the link's cost in `Node::cost`.

use alloc::vec;
use alloc::vec::Vec;

use super::choice::{offer, rtts, run, start};
use super::pin::pin;
use super::shell::{Net, Node, Out, Turn, down, gone, p, q, step, turns};
use crate::proto::path::{Input, PathRef, Switch};
use crate::testutil::TestInstant;

/// The instant `ms` milliseconds after the link was made.
fn at(ms: u64) -> TestInstant {
    TestInstant(ms)
}

/// Run `n` through `net` to `ms` milliseconds with no change of active
/// path, then step a receiver report there.
fn report(n: &mut Node, net: &mut Net<'_>, ms: u64) -> Vec<Out> {
    assert_eq!(run(n, net, ms), vec![], "no change before the report");
    let out = step(n, ms, Input::Report);
    net.take(ms, &out);
    assert_eq!(turns(ms, &out), vec![], "the report changes no path");
    out
}

/// Step `input` at `ms` milliseconds, its probes on their way through
/// `net`, and return the changes of active path it made.
fn change(n: &mut Node, net: &mut Net<'_>, ms: u64, input: Input) -> Vec<Turn> {
    let out = step(n, ms, input);
    net.take(ms, &out);
    turns(ms, &out)
}

#[test]
fn a_switch_holds_the_reported_link_cost_for_the_dwell_and_the_reports_that_span_it() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);
    let mut net = Net::new(&rtt);
    let mut n = start(200, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 1_000), vec![]);
    n.cost = 1.5;
    assert_eq!(
        change(&mut n, &mut net, 1_000, pin(2)),
        vec![(1_000, Some(p()), q(), Switch::Pinned)]
    );
    n.cost = 3.0;
    assert_eq!(n.b.cost(at(1_000), 3.0), 1.5, "held at the change");
    assert_eq!(run(&mut n, &mut net, 3_001), vec![]);
    assert_eq!(
        n.b.cost(at(3_001), 3.0),
        1.5,
        "the dwell has passed, with no report"
    );
    report(&mut n, &mut net, 3_001);
    assert_eq!(n.b.cost(at(3_001), 3.0), 1.5, "one report");
    report(&mut n, &mut net, 3_002);
    assert_eq!(n.b.cost(at(3_002), 3.0), 3.0, "both reports and the dwell");
    assert_eq!(
        n.b.cost(at(1_001), 3.0),
        1.5,
        "both reports, within the dwell"
    );
}

#[test]
fn a_report_with_no_change_of_path_changes_nothing() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);
    let mut net = Net::new(&rtt);
    let mut n = start(201, &mut net);
    offer(&mut n, &mut net, &q());
    n.cost = 2.0;
    report(&mut n, &mut net, 500);
    report(&mut n, &mut net, 500);
    assert_eq!(n.b.cost(at(500), 4.0), 4.0, "no hold, before any change");

    // A first change, whose hold both its reports and its dwell end.
    assert_eq!(run(&mut n, &mut net, 1_000), vec![]);
    n.cost = 1.5;
    assert_eq!(
        change(&mut n, &mut net, 1_000, pin(2)),
        vec![(1_000, Some(p()), q(), Switch::Pinned)]
    );
    n.cost = 2.0;
    report(&mut n, &mut net, 1_500);
    report(&mut n, &mut net, 1_600);
    assert_eq!(n.b.cost(at(3_500), 4.0), 4.0, "the first hold has ended");

    // Reports with no hold in force count toward no later hold.
    report(&mut n, &mut net, 3_500);
    report(&mut n, &mut net, 3_500);
    assert_eq!(n.b.cost(at(3_500), 4.0), 4.0, "still no hold");
    assert_eq!(run(&mut n, &mut net, 4_000), vec![]);
    assert_eq!(
        change(&mut n, &mut net, 4_000, pin(1)),
        vec![(4_000, Some(q()), p(), Switch::Pinned)]
    );
    assert_eq!(run(&mut n, &mut net, 6_500), vec![]);
    assert_eq!(
        n.b.cost(at(6_500), 4.0),
        2.0,
        "the dwell has passed, with no report since the change"
    );
    report(&mut n, &mut net, 6_500);
    assert_eq!(n.b.cost(at(6_500), 4.0), 2.0, "one report");
    report(&mut n, &mut net, 6_501);
    assert_eq!(n.b.cost(at(6_501), 4.0), 4.0, "both reports");
}

/// A node with p at 5 ms and q at 200 ms, pinned to q at 1 s with the
/// link's cost 1.5, the pin lifted at 1.01 s, one report at 1.5 s, and the
/// link's cost 3.0 from then: the first hold owes one report.
fn lifted(seed: u64, net: &mut Net<'_>) -> Node {
    let mut n = start(seed, net);
    offer(&mut n, net, &q());
    assert_eq!(run(&mut n, net, 1_000), vec![]);
    n.cost = 1.5;
    assert_eq!(
        change(&mut n, net, 1_000, pin(2)),
        vec![(1_000, Some(p()), q(), Switch::Pinned)]
    );
    assert_eq!(run(&mut n, net, 1_010), vec![]);
    assert_eq!(change(&mut n, net, 1_010, Input::Unpin), vec![]);
    report(&mut n, net, 1_500);
    n.cost = 3.0;
    n
}

#[test]
fn a_report_in_the_step_that_changes_path_neither_releases_nor_counts_toward_the_hold() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 5, 200);

    // With polls only, the link leaves q for p once, at `back`.
    let mut net = Net::new(&rtt);
    let mut n = lifted(202, &mut net);
    let seen = run(&mut n, &mut net, 10_000);
    let [(back, _, _, _)] = seen[..] else {
        panic!("one change after the pin lifts: {seen:?}");
    };
    assert_eq!(seen, vec![(back, Some(q()), p(), Switch::Discretionary)]);
    assert!(
        back >= 3_000,
        "the first hold's dwell has passed at {back} ms, so only its owed report keeps it"
    );

    // The same node, with a report stepped at `back`.
    let mut net = Net::new(&rtt);
    let mut n = lifted(202, &mut net);
    assert_eq!(run(&mut n, &mut net, back), vec![]);
    assert_eq!(n.b.cost(at(back), 3.0), 1.5, "before the change");
    assert_eq!(
        change(&mut n, &mut net, back, Input::Report),
        vec![(back, Some(q()), p(), Switch::Discretionary)],
        "the report's step changes the path"
    );
    assert_eq!(n.b.cost(at(back), 3.0), 1.5, "after the change");
    report(&mut n, &mut net, back + 2_001);
    assert_eq!(
        n.b.cost(at(back + 2_001), 3.0),
        1.5,
        "one report after the change"
    );
    report(&mut n, &mut net, back + 2_002);
    assert_eq!(
        n.b.cost(at(back + 2_002), 3.0),
        3.0,
        "two reports after the change"
    );
}

#[test]
fn a_change_during_a_hold_keeps_the_cost_already_held() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);
    let mut net = Net::new(&rtt);
    let mut n = start(203, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 1_000), vec![]);
    n.cost = 1.5;
    assert_eq!(
        change(&mut n, &mut net, 1_000, pin(2)),
        vec![(1_000, Some(p()), q(), Switch::Pinned)]
    );
    n.cost = 3.0;
    assert_eq!(run(&mut n, &mut net, 1_500), vec![]);
    assert_eq!(
        change(&mut n, &mut net, 1_500, pin(1)),
        vec![(1_500, Some(q()), p(), Switch::Pinned)]
    );
    assert_eq!(
        n.b.cost(at(1_500), 3.0),
        1.5,
        "the cost held from the first change"
    );
    report(&mut n, &mut net, 1_600);
    assert_eq!(
        n.b.cost(at(3_600), 3.0),
        1.5,
        "past the second change's dwell, with one report since it"
    );
    report(&mut n, &mut net, 3_600);
    assert_eq!(n.b.cost(at(3_600), 3.0), 3.0, "both reports and the dwell");
    assert_eq!(
        n.b.cost(at(3_499), 3.0),
        1.5,
        "within the dwell from the second change"
    );
}

#[test]
fn every_kind_of_change_holds_the_cost() {
    // Each case starts with no hold, so the cost before the change is the
    // link's cost, 1.5.
    let held = |n: &Node, ms: u64| {
        assert_eq!(n.b.cost(at(ms), 9.0), 1.5, "the cost held at {ms} ms");
    };

    // Mandatory: the active path's carrier is lost.
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 50);
    let mut net = Net::new(&rtt);
    let mut n = start(204, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 5_000), vec![]);
    n.cost = 1.5;
    assert_eq!(n.b.cost(at(5_000), 9.0), 9.0, "no hold before");
    assert_eq!(
        change(&mut n, &mut net, 5_000, down(1)),
        vec![(5_000, Some(p()), q(), Switch::Mandatory)]
    );
    held(&n, 5_000);

    // Handover: the active path's transport is removed.
    let mut net = Net::new(&rtt);
    let mut n = start(205, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 5_000), vec![]);
    n.cost = 1.5;
    assert_eq!(n.b.cost(at(5_000), 9.0), 9.0, "no hold before");
    assert_eq!(
        change(&mut n, &mut net, 5_000, gone(1)),
        vec![(5_000, None, q(), Switch::Handover)]
    );
    held(&n, 5_000);

    // Discretionary: q scores better by the margin for the dwell.
    let rtt = |_: u64, to: &PathRef| rtts(to, 200, 1);
    let mut net = Net::new(&rtt);
    let mut n = start(206, &mut net);
    n.cost = 1.5;
    offer(&mut n, &mut net, &q());
    let seen = run(&mut n, &mut net, 30_000);
    let [(moved, _, _, _)] = seen[..] else {
        panic!("one change to the faster path: {seen:?}");
    };
    assert_eq!(seen, vec![(moved, Some(p()), q(), Switch::Discretionary)]);
    held(&n, moved);

    // Pinned: the operator pins q.
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);
    let mut net = Net::new(&rtt);
    let mut n = start(207, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 1_000), vec![]);
    n.cost = 1.5;
    assert_eq!(n.b.cost(at(1_000), 9.0), 9.0, "no hold before");
    assert_eq!(
        change(&mut n, &mut net, 1_000, pin(2)),
        vec![(1_000, Some(p()), q(), Switch::Pinned)]
    );
    held(&n, 1_000);
}

/// `holding()` is false with no hold, true from a change of path, still
/// true after the hold has ended while only polls made before the next
/// wake are stepped (which the shell checks change nothing), and false
/// after the next step that is not such a poll; the cost is the live one
/// on both sides of those steps.
#[test]
fn a_bundle_is_holding_only_from_a_change_of_path_until_the_hold_is_found_ended() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);
    let mut net = Net::new(&rtt);
    let mut n = start(208, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 1_000), vec![]);
    assert!(!n.b.holding(), "no hold before any change");
    n.cost = 1.5;
    assert_eq!(
        change(&mut n, &mut net, 1_000, pin(2)),
        vec![(1_000, Some(p()), q(), Switch::Pinned)]
    );
    assert!(n.b.holding(), "holding from the change");
    n.cost = 3.0;
    assert_eq!(run(&mut n, &mut net, 3_001), vec![]);
    report(&mut n, &mut net, 3_001);
    assert!(n.b.holding(), "one report owed");
    report(&mut n, &mut net, 3_002);
    assert_eq!(n.b.cost(at(3_002), 3.0), 3.0, "the hold has ended");
    assert!(
        n.b.next_wake().is_some_and(|wake| wake > at(3_002)),
        "precondition: a poll at 3.002 s is made before the next wake"
    );

    let out = step(&mut n, 3_002, Input::Poll);
    assert!(out.is_empty(), "an early poll gives nothing");
    assert!(
        n.b.holding(),
        "an early poll leaves the ended hold in place"
    );
    assert_eq!(
        n.b.cost(at(3_002), 3.0),
        3.0,
        "the live cost after the poll"
    );

    let out = step(&mut n, 3_002, Input::Report);
    net.take(3_002, &out);
    assert_eq!(turns(3_002, &out), vec![], "the report changes no path");
    assert!(!n.b.holding(), "a step that is not an early poll clears it");
    assert_eq!(
        n.b.cost(at(3_002), 3.0),
        3.0,
        "the live cost after the report"
    );
}
