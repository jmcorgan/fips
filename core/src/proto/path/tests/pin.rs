//! An operator's pin of a link (`proto::path::tests::pin::...`), driven
//! through `Bundle`'s inputs in the shell, with every path's round trips
//! set by a `Net` from its first probe on.

use alloc::vec;
use alloc::vec::Vec;

use super::choice::{offer, placed, role, rtts, run, start};
use super::shell::{
    Net, Node, Turn, active, addr, down, gone, p, pair, path, q, r, scored, step, t, turns,
};
use crate::proto::path::{Config, Input, PathRef, PathState, Pin, Role, Switch};

/// The pin of the path at `k`'s address on transport `k`.
pub(super) fn pin(k: u8) -> Input {
    Input::Pin {
        transport: t(u32::from(k)),
        addr: Some(addr(k)),
    }
}

/// Run `n` through `net` to `until` milliseconds, and return the instant
/// the path on `to` first turned Live and every change of active path.
fn live_at(n: &mut Node, net: &mut Net<'_>, to: &PathRef, until: u64) -> (u64, Vec<Turn>) {
    let mut at = None;
    let seen = net.run(n, until, &mut |n, now| {
        if at.is_none() && path(n, to).state() == PathState::Live {
            at = Some(now);
        }
    });
    (at.expect("the path turns Live"), seen)
}

/// A node whose link runs on p at 1 ms, with q at 200 ms Live beside it
/// from 5 s, pinned to q at 5 s.
pub(super) fn onto_q(seed: u64, net: &mut Net<'_>) -> Node {
    let mut n = start(seed, net);
    offer(&mut n, net, &q());
    assert_eq!(run(&mut n, net, 5_000), vec![]);
    let out = step(&mut n, 5_000, pin(2));
    net.take(5_000, &out);
    assert_eq!(
        turns(5_000, &out),
        vec![(5_000, Some(p()), q(), Switch::Pinned)]
    );
    n
}

#[test]
fn a_pinned_path_wins_and_holds() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);
    let mut net = Net::new(&rtt);
    let mut n = onto_q(190, &mut net);
    assert_eq!(run(&mut n, &mut net, 65_000), vec![], "the pin holds");
    assert_eq!(active(&n), Some(q()));
    let cfg = Config::draft();
    let (on_p, on_q) = (scored(&n, &p(), 2), scored(&n, &q(), 2));
    assert!(
        on_p.zip(on_q)
            .is_some_and(|(on_p, on_q)| on_q > on_p * cfg.switch_margin),
        "p scores better by the margin: {on_p:?} against {on_q:?}"
    );
}

#[test]
fn a_pin_is_suspended_while_nothing_it_names_is_live_and_applies_again() {
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
    let mut n = onto_q(191, &mut net);
    assert_eq!(run(&mut n, &mut net, 6_000), vec![]);
    let out = step(&mut n, 6_000, down(2));
    net.take(6_000, &out);
    assert_eq!(path(&n, &q()).state(), PathState::Suspect);
    assert_eq!(
        turns(6_000, &out),
        vec![(6_000, Some(q()), p(), Switch::Mandatory)],
        "the link leaves the pinned path when it fails"
    );
    let mut steps = 0;
    let seen = net.run(&mut n, quiet.end, &mut |n, _| {
        assert_ne!(path(n, &q()).state(), PathState::Live);
        steps += 1;
    });
    assert_eq!(seen, vec![], "the link stays off the pinned path");
    assert!(steps > 0, "the bundle stepped while q was not Live");
    assert!(n.b.pin().is_some(), "the pin is kept, suspended");
    let (back, seen) = live_at(&mut n, &mut net, &q(), 30_000);
    assert_eq!(
        seen,
        vec![(back, Some(p()), q(), Switch::Pinned)],
        "q turned Live again at {back} ms"
    );
}

#[test]
fn a_pin_on_a_transport_chooses_among_its_paths() {
    let five = pair(t(2), addr(5));
    let rtt = |_: u64, to: &PathRef| {
        if *to == five {
            Some(2)
        } else {
            rtts(to, 1, 60)
        }
    };
    let mut net = Net::new(&rtt);
    let mut n = start(192, &mut net);
    offer(&mut n, &mut net, &q());
    offer(&mut n, &mut net, &five);
    assert_eq!(run(&mut n, &mut net, 40_000), vec![]);
    let (on_q, on_five) = (scored(&n, &q(), 2), scored(&n, &five, 2));
    assert!(
        on_q.zip(on_five)
            .is_some_and(|(on_q, on_five)| on_five < on_q),
        "the second path on the transport scores better: {on_five:?} against {on_q:?}"
    );
    let out = step(
        &mut n,
        40_000,
        Input::Pin {
            transport: t(2),
            addr: None,
        },
    );
    assert_eq!(
        turns(40_000, &out),
        vec![(40_000, Some(p()), five, Switch::Pinned)]
    );
}

#[test]
fn a_pin_ends_when_its_transport_is_removed_or_its_interface_leaves() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);

    // The transport is removed; configuration lists q afresh after.
    let mut net = Net::new(&rtt);
    let mut n = onto_q(193, &mut net);
    let out = step(&mut n, 6_000, gone(2));
    net.take(6_000, &out);
    assert_eq!(n.b.pin(), None, "removal ends the pin");
    assert_eq!(active(&n), Some(p()));
    offer(&mut n, &mut net, &q());
    let (at, seen) = live_at(&mut n, &mut net, &q(), 30_000);
    assert_eq!(
        seen,
        vec![],
        "q turned Live at {at} ms, and is not moved to"
    );

    // The interface leaves and comes back, releasing q's candidate.
    let mut net = Net::new(&rtt);
    let mut n = onto_q(194, &mut net);
    let left = Input::Present {
        transport: t(2),
        present: false,
    };
    let out = step(&mut n, 6_000, left);
    net.take(6_000, &out);
    assert_eq!(n.b.pin(), None, "presence loss ends the pin");
    assert_eq!(active(&n), Some(p()));
    let back = Input::Present {
        transport: t(2),
        present: true,
    };
    let out = step(&mut n, 6_000, back);
    net.take(6_000, &out);
    let (at, seen) = live_at(&mut n, &mut net, &q(), 30_000);
    assert_eq!(
        seen,
        vec![],
        "q turned Live at {at} ms, and is not moved to"
    );
}

#[test]
fn a_pinned_backup_path_carries_the_link_and_yields_at_once_when_unpinned() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 20, 1);
    let mut net = Net::new(&rtt);
    let mut n = placed(195, role(2, Role::Backup), &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 5_000), vec![]);
    let (on_p, on_q) = (scored(&n, &p(), 2), scored(&n, &q(), 2));
    assert!(
        on_p.zip(on_q).is_some_and(|(on_p, on_q)| on_q < on_p),
        "the backup path scores better: {on_q:?} against {on_p:?}"
    );
    let out = step(&mut n, 5_000, pin(2));
    net.take(5_000, &out);
    assert_eq!(
        turns(5_000, &out),
        vec![(5_000, Some(p()), q(), Switch::Pinned)],
        "the pin comes before the tiers"
    );
    let out = step(&mut n, 5_001, Input::Unpin);
    assert_eq!(
        turns(5_001, &out),
        vec![(5_001, Some(q()), p(), Switch::Discretionary)],
        "the backup path yields at once"
    );
}

#[test]
fn after_unpinning_the_margin_and_the_dwell_apply_again() {
    let cfg = Config::draft();
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 200);
    let mut net = Net::new(&rtt);
    let mut n = onto_q(196, &mut net);
    assert_eq!(run(&mut n, &mut net, 10_000), vec![]);
    let (on_p, on_q) = (scored(&n, &p(), 2), scored(&n, &q(), 2));
    assert!(
        on_p.zip(on_q)
            .is_some_and(|(on_p, on_q)| on_q > on_p * cfg.switch_margin),
        "p scores better by the margin: {on_p:?} against {on_q:?}"
    );
    let out = step(&mut n, 10_000, Input::Unpin);
    net.take(10_000, &out);
    assert_eq!(turns(10_000, &out), vec![], "no change as the pin lifts");
    assert_eq!(
        run(&mut n, &mut net, 30_000),
        vec![(12_000, Some(q()), p(), Switch::Discretionary)],
        "one dwell after the pin lifts"
    );
}

#[test]
fn a_pin_naming_no_held_path_is_kept_until_its_path_turns_live() {
    let rtt = |_: u64, to: &PathRef| if *to == r() { Some(50) } else { rtts(to, 1, 1) };
    let mut net = Net::new(&rtt);
    let mut n = start(197, &mut net);
    assert_eq!(run(&mut n, &mut net, 1_000), vec![]);
    let out = step(&mut n, 1_000, pin(3));
    assert_eq!(turns(1_000, &out), vec![]);
    let kept = Pin {
        transport: t(3),
        addr: Some(addr(3)),
    };
    assert_eq!(n.b.pin(), Some(&kept), "a pin naming no path is kept");
    offer(&mut n, &mut net, &r());
    let (at, seen) = live_at(&mut n, &mut net, &r(), 10_000);
    assert_eq!(
        seen,
        vec![(at, Some(p()), r(), Switch::Pinned)],
        "r turned Live at {at} ms"
    );
}

#[test]
fn a_failed_pinned_active_path_gives_way_to_another_the_pin_names() {
    // t(2) holds q, 60 ms, and five, 2 ms, which stops answering at 41 s;
    // p, unpinned, answers in 1 ms.
    let five = pair(t(2), addr(5));
    let rtt = |now: u64, to: &PathRef| {
        if *to == five {
            if now >= 41_000 { None } else { Some(2) }
        } else {
            rtts(to, 1, 60)
        }
    };
    let mut net = Net::new(&rtt);
    let mut n = start(902, &mut net);
    offer(&mut n, &mut net, &q());
    offer(&mut n, &mut net, &five);
    assert_eq!(run(&mut n, &mut net, 40_000), vec![]);
    let out = step(
        &mut n,
        40_000,
        Input::Pin {
            transport: t(2),
            addr: None,
        },
    );
    net.take(40_000, &out);
    assert_eq!(
        turns(40_000, &out),
        vec![(40_000, Some(p()), five.clone(), Switch::Pinned)]
    );
    let seen = run(&mut n, &mut net, 45_000);
    assert_ne!(path(&n, &five).state(), PathState::Live);
    assert_eq!(seen.len(), 1, "{seen:?}");
    let (_, from, to, why) = seen[0].clone();
    assert_eq!((from, to, why), (Some(five), q(), Switch::Mandatory));
}
