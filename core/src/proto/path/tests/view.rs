//! The operator's view of a link's paths (`proto::path::tests::view::...`),
//! read through `Bundle::view` from a bundle driven through its inputs in
//! the shell, with every path's round trips set by a `Net` from its first
//! probe on.

use alloc::vec;

use super::choice::{offer, rtts, run, start};
use super::pin::{onto_q, pin};
use super::shell::{Net, Node, active, down, marked, p, path, peer, q, step, turns};
use crate::proto::path::{Input, PathRef, PathState, PathView, Switch};
use crate::testutil::TestInstant;

/// The view's entry for the path on `to`.
fn shown(n: &Node, ms: u64, to: &PathRef) -> PathView {
    n.b.view(TestInstant(ms))
        .paths
        .into_iter()
        .find(|v| v.to == *to)
        .expect("the view shows the path")
}

/// Whether the view at `ms` shows the pin in force exactly when the link
/// is on a path the pin names: the view and selection agree.
fn agrees(n: &Node, ms: u64) -> bool {
    let view = n.b.view(TestInstant(ms));
    let named = active(n).is_some_and(|a| view.paths.iter().any(|v| v.to == a && v.pinned));
    view.pin.is_none_or(|pin| pin.enforced == named)
}

#[test]
fn the_view_shows_each_paths_state_which_is_active_and_which_the_peer_sends_on() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);
    let mut net = Net::new(&rtt);
    let mut n = onto_q(230, &mut net);
    // The peer says it sends on p, and not on q.
    for (to, k, sends) in [(p(), 1, true), (q(), 2, false)] {
        let input = Input::Probe {
            transport: to.transport,
            addr: to.addr.clone(),
            msg: marked(peer(&to), k, sends),
        };
        let out = step(&mut n, 5_000, input);
        net.take(5_000, &out);
    }
    let (on_p, on_q) = (shown(&n, 5_000, &p()), shown(&n, 5_000, &q()));
    assert!(on_p.remote && !on_p.active, "the peer sends on p, we not");
    assert!(on_q.active && !on_q.remote, "we send on q, the peer not");
    for v in [&on_p, &on_q] {
        assert_eq!(v.state, PathState::Live, "{:?}", v.to);
        assert!(v.acked, "{:?}", v.to);
        assert!(v.score.is_some(), "{:?} has a round trip", v.to);
        assert_eq!(v.id, path(&n, &v.to).path_id());
    }
    assert!(on_q.pinned && !on_p.pinned);
}

#[test]
fn the_view_shows_a_pin_enforced_while_a_live_path_it_names_is_held_and_suspended_otherwise() {
    // q's probes go unanswered from 5.6 s, so none is answered after its
    // carrier is lost at 6 s, until 8 s.
    let quiet = 5_600..8_000;
    let rtt = |now: u64, to: &PathRef| {
        if *to == q() && quiet.contains(&now) {
            None
        } else {
            rtts(to, 1, 200)
        }
    };
    let mut net = Net::new(&rtt);
    let mut n = onto_q(231, &mut net);
    let enforced = |n: &Node, ms: u64| n.b.view(TestInstant(ms)).pin.map(|pin| pin.enforced);
    assert_eq!(enforced(&n, 5_000), Some(true), "in force on q");
    let mut steps = 0;
    let mut watch = |n: &Node, now: u64| {
        assert!(agrees(n, now), "the view and selection differ at {now} ms");
        steps += 1;
    };
    assert_eq!(net.run(&mut n, 6_000, &mut watch), vec![]);
    let out = step(&mut n, 6_000, down(2));
    net.take(6_000, &out);
    assert_eq!(
        turns(6_000, &out),
        vec![(6_000, Some(q()), p(), Switch::Mandatory)]
    );
    assert!(agrees(&n, 6_000));
    assert_eq!(
        enforced(&n, 6_000),
        Some(false),
        "kept and suspended while q is down"
    );
    assert_eq!(active(&n), Some(p()));
    assert_eq!(net.run(&mut n, quiet.end, &mut watch), vec![]);
    assert_eq!(enforced(&n, quiet.end), Some(false), "still suspended");
    let seen = net.run(&mut n, 30_000, &mut watch);
    let [(back, Some(from), to, Switch::Pinned)] = &seen[..] else {
        panic!("the link goes back to q once: {seen:?}");
    };
    assert_eq!((from, to), (&p(), &q()), "at {back} ms");
    assert_eq!(enforced(&n, 30_000), Some(true), "in force again on q");
    assert!(steps > 0, "the view was checked after every step");
    let out = step(&mut n, 30_000, Input::Unpin);
    net.take(30_000, &out);
    assert_eq!(n.b.view(TestInstant(30_000)).pin, None, "lifted");
}

#[test]
fn the_view_shows_the_cost_held_from_a_change_until_the_dwell_and_two_reports() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);
    let mut net = Net::new(&rtt);
    let mut n = start(232, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 1_000), vec![]);
    let held = |n: &Node, ms: u64| n.b.view(TestInstant(ms)).held;
    assert!(!held(&n, 1_000), "nothing held before a change");
    let out = step(&mut n, 1_000, pin(2));
    net.take(1_000, &out);
    assert_eq!(
        turns(1_000, &out),
        vec![(1_000, Some(p()), q(), Switch::Pinned)]
    );
    assert!(held(&n, 1_000), "held at the change");
    for ms in [1_500, 1_600] {
        assert_eq!(run(&mut n, &mut net, ms), vec![]);
        let out = step(&mut n, ms, Input::Report);
        net.take(ms, &out);
    }
    assert!(held(&n, 1_600), "two reports, within the dwell");
    assert!(n.b.holding(), "precondition: no step since the dwell ended");
    assert!(!held(&n, 3_500), "the dwell has passed with both reports");
}
