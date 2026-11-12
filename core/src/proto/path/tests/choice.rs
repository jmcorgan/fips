//! Which path carries a link (`proto::path::tests::choice::...`), driven
//! through `Bundle`'s inputs in the shell, with every path's round trips
//! set by a `Net` from its first probe on.

use alloc::vec;
use alloc::vec::Vec;

use core::cell::Cell;

use super::shell::{
    Fact, Net, Node, Out, Stub, Turn, active, addr, down, p, pair, path, q, r, scored, step, t,
    turns,
};
use crate::proto::path::{Config, Medium, Params, PathRef, PathState, Role, Switch};
use crate::time::Duration;

/// A node whose peer has shown it is capable at instant 0, with the
/// outputs of that step on their way through `net`.
pub(super) fn start(seed: u64, net: &mut Net<'_>) -> Node {
    tuned(seed, Config::draft(), net)
}

/// A node as [`start`] makes it, whose bundle runs with `cfg`.
pub(super) fn tuned(seed: u64, cfg: Config, net: &mut Net<'_>) -> Node {
    built(seed, cfg, Stub::default(), net)
}

/// A node as [`start`] makes it, under the host's `facts`.
pub(super) fn placed(seed: u64, facts: Stub, net: &mut Net<'_>) -> Node {
    built(seed, Config::draft(), facts, net)
}

/// A node as [`start`] makes it, whose bundle runs with `cfg` under the
/// host's `facts`.
fn built(seed: u64, cfg: Config, facts: Stub, net: &mut Net<'_>) -> Node {
    let params = Params::new(cfg).expect("valid settings");
    let mut n = Node::on(seed, params, facts, p());
    let out = n.heard();
    net.take(0, &out);
    n
}

/// The host's facts with transport `k`'s role set to `role`.
pub(super) fn role(k: u32, role: Role) -> Stub {
    Stub::default().fact(t(k), Fact::Role(role))
}

/// The round trip on `to`: `on_p` milliseconds on p, `on_q` on q, and no
/// answer anywhere else.
pub(super) fn rtts(to: &PathRef, on_p: u64, on_q: u64) -> Option<u64> {
    if *to == p() {
        Some(on_p)
    } else if *to == q() {
        Some(on_q)
    } else {
        None
    }
}

/// Whether q scores better than p by `cfg`'s margin, both with enough
/// samples: what a discretionary change from p to q waits on.
fn leads(n: &Node, cfg: &Config) -> bool {
    let min = usize::from(cfg.min_samples);
    scored(n, &p(), min)
        .zip(scored(n, &q(), min))
        .is_some_and(|(on_p, on_q)| on_p > on_q * cfg.switch_margin)
}

/// Configuration lists the candidate `to` at the node's instant, and its
/// probe goes out through `net`.
pub(super) fn offer(n: &mut Node, net: &mut Net<'_>, to: &PathRef) -> Vec<Out> {
    let out = n.candidate(to.transport, to.addr.clone());
    net.take(n.now.0, &out);
    out
}

/// Run `n` through `net` to `until` milliseconds, watching nothing.
pub(super) fn run(n: &mut Node, net: &mut Net<'_>, until: u64) -> Vec<Turn> {
    net.run(n, until, &mut |_, _| {})
}

/// `ms` milliseconds.
fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

#[test]
fn withdrawal_prefers_a_selectable_standby_over_a_barely_live_one() {
    let rtt = |_: u64, to: &PathRef| {
        if *to == q() {
            Some(5)
        } else if *to == p() || *to == r() {
            Some(1)
        } else {
            None
        }
    };
    let mut net = Net::new(&rtt);
    let mut n = start(167, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 35_000), vec![]);
    offer(&mut n, &mut net, &r());
    assert_eq!(run(&mut n, &mut net, 35_002), vec![]);
    assert_eq!(path(&n, &r()).state(), PathState::Live);
    assert_eq!(path(&n, &r()).live().samples(), 1, "r is barely Live");
    assert!(path(&n, &q()).live().samples() >= 2, "q has enough samples");
    let out = step(&mut n, 35_002, down(1));
    assert_eq!(
        turns(35_002, &out),
        vec![(35_002, Some(p()), q(), Switch::Mandatory)],
        "a path with enough samples beats a faster one with too few"
    );
}

#[test]
fn the_mandatory_change_takes_the_best_score_not_the_latest_round_trip() {
    let rtt = |now: u64, to: &PathRef| {
        if *to == q() {
            Some(if now < 38_000 { 5 } else { 80 })
        } else if *to == r() {
            Some(20)
        } else if *to == p() {
            Some(1)
        } else {
            None
        }
    };
    let mut net = Net::new(&rtt);
    let mut n = start(168, &mut net);
    offer(&mut n, &mut net, &q());
    offer(&mut n, &mut net, &r());
    assert_eq!(run(&mut n, &mut net, 39_001), vec![]);
    let (qs, rs) = (path(&n, &q()).live(), path(&n, &r()).live());
    assert_eq!(
        qs.rtt(),
        Some(ms(80)),
        "q's latest round trip is its slow one"
    );
    assert_eq!(
        qs.min_rtt(),
        Some(ms(5)),
        "q's least is still in its window"
    );
    assert_eq!(rs.rtt(), Some(ms(20)));
    let out = step(&mut n, 39_001, down(1));
    assert_eq!(
        turns(39_001, &out),
        vec![(39_001, Some(p()), q(), Switch::Mandatory)],
        "the least score wins, not the least latest round trip"
    );
}

#[test]
fn a_cable_under_a_slightly_better_wifi_is_not_left() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 10, 1);
    let mut net = Net::new(&rtt);
    let mut n = start(170, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 60_000), vec![]);
    let (on_p, on_q) = (scored(&n, &p(), 2), scored(&n, &q(), 2));
    assert!(
        on_q.zip(on_p).is_some_and(|(on_q, on_p)| on_q < on_p),
        "q scores better: {on_q:?} against {on_p:?}"
    );
    assert!(!leads(&n, &Config::draft()), "but not by the margin");
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn a_degraded_active_path_is_left_one_dwell_after_the_margin_first_holds() {
    // A dwell that ends between probe wakes, so only its own wake ends it.
    let cfg = Config {
        switch_dwell: ms(2_050),
        ..Config::draft()
    };
    let rtt = |_: u64, to: &PathRef| rtts(to, 200, 5);
    let mut net = Net::new(&rtt);
    let mut n = tuned(171, cfg, &mut net);
    offer(&mut n, &mut net, &q());
    let mut first = None;
    let seen = net.run(&mut n, 20_000, &mut |n, at| {
        if first.is_none() && leads(n, &cfg) {
            first = Some(at);
        }
    });
    let first = first.expect("the margin holds");
    assert_eq!(
        seen,
        vec![(first + 2_050, Some(p()), q(), Switch::Discretionary)],
        "the margin first held at {first} ms"
    );
}

#[test]
fn the_dwell_restarts_when_the_margin_stops_holding() {
    let cfg = Config::draft();

    // p answers in 1 ms from 1 s on, before the dwell started on the
    // margin can end, and its least round trip drops below q's.
    let rtt = |now: u64, to: &PathRef| rtts(to, if now < 1_000 { 200 } else { 1 }, 5);
    let mut net = Net::new(&rtt);
    let mut n = start(172, &mut net);
    offer(&mut n, &mut net, &q());
    let mut held = Vec::new();
    let seen = net.run(&mut n, 60_000, &mut |n, at| {
        if leads(n, &cfg) {
            held.push(at);
        }
    });
    let (first, last) = (held.first(), held.last());
    assert!(
        first.zip(last).is_some_and(|(f, l)| *l < f + 2_000),
        "the margin held from {first:?} ms to {last:?} ms, less than a dwell"
    );
    assert_eq!(seen, vec![], "the dwell ended with the margin");

    // q fails while the dwell runs and comes back: the dwell starts again
    // when q turns Live, and q waits a whole dwell from then.
    let rtt = |_: u64, to: &PathRef| rtts(to, 200, 5);
    let mut net = Net::new(&rtt);
    let mut n = start(173, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 1_500), vec![]);
    assert!(leads(&n, &cfg), "the dwell runs when q fails");
    let out = step(&mut n, 1_500, down(2));
    net.take(1_500, &out);
    assert_eq!(path(&n, &q()).state(), PathState::Suspect);
    let mut back = None;
    let seen = net.run(&mut n, 60_000, &mut |n, at| {
        if back.is_none() && path(n, &q()).state() == PathState::Live {
            back = Some(at);
        }
    });
    let back = back.expect("q answers again");
    assert_eq!(
        seen,
        vec![(back + 2_000, Some(p()), q(), Switch::Discretionary)],
        "q turned Live again at {back} ms"
    );
}

#[test]
fn a_standby_with_too_few_samples_is_not_selectable() {
    let cfg = Config {
        min_samples: 10,
        ..Config::draft()
    };
    let rtt = |_: u64, to: &PathRef| rtts(to, 200, 5);
    let mut net = Net::new(&rtt);
    let mut n = tuned(174, cfg, &mut net);
    offer(&mut n, &mut net, &q());
    let mut tenth = None;
    let seen = net.run(&mut n, 30_000, &mut |n, at| {
        if tenth.is_none() && path(n, &q()).live().samples() >= 10 {
            assert!(
                path(n, &p()).live().samples() >= 10,
                "p has its samples first"
            );
            tenth = Some(at);
        }
    });
    let tenth = tenth.expect("q has ten samples");
    assert_eq!(
        seen,
        vec![(tenth + 2_000, Some(p()), q(), Switch::Discretionary)],
        "q's tenth sample came at {tenth} ms"
    );
}

#[test]
fn a_tie_keeps_the_current_path() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 5, 5);
    let mut net = Net::new(&rtt);
    let mut n = start(175, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 35_000), vec![]);
    // q carries the link, so a tie ranks p, the lower index, first.
    let out = step(&mut n, 35_000, down(1));
    net.take(35_000, &out);
    assert_eq!(
        turns(35_000, &out),
        vec![(35_000, Some(p()), q(), Switch::Mandatory)]
    );
    assert_eq!(run(&mut n, &mut net, 95_000), vec![]);
    assert_eq!(path(&n, &p()).state(), PathState::Live);
    let (on_p, on_q) = (scored(&n, &p(), 2), scored(&n, &q(), 2));
    assert!(on_p.is_some(), "p is scored");
    assert_eq!(on_p, on_q, "p and q tie");
    assert_eq!(active(&n), Some(q()));
}

#[test]
fn a_dwell_toward_one_path_is_not_inherited_by_another() {
    let rtt = |_: u64, to: &PathRef| {
        if *to == p() {
            Some(200)
        } else if *to == q() {
            Some(20)
        } else if *to == r() {
            Some(5)
        } else {
            None
        }
    };
    let mut net = Net::new(&rtt);
    let mut n = start(901, &mut net);
    offer(&mut n, &mut net, &q());
    let mut q_leads = None;
    let seen = net.run(&mut n, 1_500, &mut |n, now| {
        let (on_p, on_q) = (scored(n, &p(), 2), scored(n, &q(), 2));
        if q_leads.is_none() && on_p.zip(on_q).is_some_and(|(a, b)| a > b * 1.3) {
            q_leads = Some(now);
        }
    });
    assert_eq!(seen, vec![]);
    let q_leads = q_leads.expect("q leads p by the margin before r is offered");
    // r is offered inside the dwell toward q and soon ranks first.
    offer(&mut n, &mut net, &r());
    let mut r_ready = None;
    let seen = net.run(&mut n, 20_000, &mut |n, now| {
        if r_ready.is_none() && scored(n, &r(), 2).is_some() {
            r_ready = Some(now);
        }
    });
    let r_ready = r_ready.expect("r is scored");
    assert!(
        r_ready < q_leads + 2_000,
        "r is ready inside q's dwell: {q_leads} {r_ready}"
    );
    assert_eq!(seen.len(), 1, "{seen:?}");
    let (at, from, to, why) = seen[0].clone();
    assert_eq!((from, to, why), (Some(p()), r(), Switch::Discretionary));
    assert!(
        at >= r_ready + 2_000,
        "switched at {at}, r ready at {r_ready}, q led from {q_leads}"
    );
}

#[test]
fn a_dwell_ends_while_the_active_path_is_not_live() {
    // p and a second path on its transport, so one carrier loss makes
    // both Suspect.
    let five = pair(t(1), addr(5));
    let quiet = Cell::new((0, 0));
    let rtt = |now: u64, to: &PathRef| {
        let (from, until) = quiet.get();
        if (from..until).contains(&now) {
            None
        } else if *to == five {
            Some(5)
        } else if *to == p() {
            Some(150)
        } else {
            None
        }
    };
    let margin = Config::draft().switch_margin;
    // A first run finds the dwell's start and p's answers inside it.
    let mut net = Net::new(&rtt);
    let mut n = start(300, &mut net);
    offer(&mut n, &mut net, &five);
    let (mut first, mut answers, mut count) = (None, Vec::new(), 0);
    let seen = net.run(&mut n, 20_000, &mut |n, at| {
        let lead = scored(n, &p(), 2)
            .zip(scored(n, &five, 2))
            .is_some_and(|(a, b)| a > b * margin);
        if first.is_none() && lead {
            first = Some(at);
        }
        let c = path(n, &p()).live().samples();
        if c != count {
            answers.push(at);
            count = c;
        }
    });
    let first = first.expect("the margin holds");
    assert_eq!(
        seen,
        vec![(
            first + 2_000,
            Some(p()),
            five.clone(),
            Switch::Discretionary
        )]
    );
    // Just after one of p's answers nothing of p's is in flight.
    let cut = answers
        .iter()
        .copied()
        .find(|&a| a > first)
        .expect("p answers inside the dwell")
        + 1;
    assert!(cut < first + 2_000, "the cut at {cut} is inside the dwell");
    // A second run: at the cut the carrier is lost, and both paths go
    // unanswered for 5 s, past the dwell's end. The shell checks every
    // step's next wake is after it.
    quiet.set((cut, cut + 5_000));
    let mut net = Net::new(&rtt);
    let mut n = start(300, &mut net);
    offer(&mut n, &mut net, &five);
    assert_eq!(run(&mut n, &mut net, cut), vec![]);
    let out = step(&mut n, cut, down(1));
    net.take(cut, &out);
    assert_eq!(path(&n, &p()).state(), PathState::Suspect);
    assert_eq!(path(&n, &five).state(), PathState::Suspect);
    let seen = run(&mut n, &mut net, cut + 20_000);
    assert!(
        seen.iter()
            .all(|&(at, _, _, why)| why != Switch::Discretionary || at >= cut + 5_000),
        "no discretionary change while neither path is Live: {seen:?}"
    );
}

#[test]
fn a_backup_path_is_not_selected_while_a_normal_one_is_live() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 200, 5);
    let mut net = Net::new(&rtt);
    let mut n = placed(176, role(2, Role::Backup), &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 60_000), vec![]);
    assert!(leads(&n, &Config::draft()), "q scores better by the margin");
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn a_backup_active_path_yields_to_a_normal_one_at_once() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 50);
    let mut net = Net::new(&rtt);
    let mut n = placed(177, role(1, Role::Backup), &mut net);
    offer(&mut n, &mut net, &q());
    let mut live = None;
    let seen = net.run(&mut n, 30_000, &mut |n, at| {
        let on_q = path(n, &q()).live();
        if live.is_none() && path(n, &q()).state() == PathState::Live {
            live = Some((at, on_q.samples(), on_q.rtt()));
        }
    });
    let (at, samples, latest) = live.expect("q turns Live");
    assert_eq!(samples, 1, "q has one sample when it turns Live");
    assert!(
        latest > path(&n, &p()).live().rtt(),
        "q's round trip is worse than p's"
    );
    assert_eq!(
        seen,
        vec![(at, Some(p()), q(), Switch::Discretionary)],
        "q turned Live at {at} ms"
    );
}

#[test]
fn a_backup_path_carries_the_link_while_nothing_else_is_live() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 5, 5);
    let mut net = Net::new(&rtt);
    let mut n = placed(178, role(2, Role::Backup), &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 5_000), vec![]);
    assert_eq!(path(&n, &q()).state(), PathState::Live);
    let out = step(&mut n, 5_000, down(1));
    net.take(5_000, &out);
    assert_eq!(
        turns(5_000, &out),
        vec![(5_000, Some(p()), q(), Switch::Mandatory)],
        "the backup path takes the link when p fails"
    );
    let mut back = None;
    let seen = net.run(&mut n, 30_000, &mut |n, at| {
        if back.is_none() && path(n, &p()).state() == PathState::Live {
            back = Some(at);
        }
    });
    let back = back.expect("p answers again");
    assert_eq!(
        seen,
        vec![(back, Some(q()), p(), Switch::Discretionary)],
        "p turned Live again at {back} ms"
    );
}

#[test]
fn a_path_whose_transport_turned_never_ranks_below_a_backup_one() {
    let rtt = |_: u64, to: &PathRef| {
        if *to == r() { Some(1) } else { rtts(to, 5, 20) }
    };
    let mut net = Net::new(&rtt);
    let mut n = start(179, &mut net);
    offer(&mut n, &mut net, &q());
    offer(&mut n, &mut net, &r());
    assert_eq!(run(&mut n, &mut net, 10_000), vec![]);
    let (on_q, on_r) = (scored(&n, &q(), 2), scored(&n, &r(), 2));
    assert!(
        on_q.zip(on_r).is_some_and(|(on_q, on_r)| on_r < on_q),
        "r scores better: {on_r:?} against {on_q:?}"
    );
    n.facts.change(t(2), Fact::Role(Role::Backup));
    n.facts.change(t(3), Fact::Role(Role::Never));
    assert_eq!(path(&n, &r()).state(), PathState::Live, "r is still held");
    let out = step(&mut n, 10_000, down(1));
    assert_eq!(
        turns(10_000, &out),
        vec![(10_000, Some(p()), q(), Switch::Mandatory)],
        "the backup path ranks above the never one"
    );
}

#[test]
fn with_equal_round_trips_a_preferred_cable_carries_the_link_in_both_orders() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 5, 5);

    // The cable carried the first handshake.
    let mut net = Net::new(&rtt);
    let mut n = placed(180, role(1, Role::Preferred), &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 30_000), vec![]);
    assert_eq!(active(&n), Some(p()));

    // The wireless network carried it.
    let mut net = Net::new(&rtt);
    let mut n = placed(181, role(2, Role::Preferred), &mut net);
    offer(&mut n, &mut net, &q());
    let mut second = None;
    let seen = net.run(&mut n, 30_000, &mut |n, at| {
        if second.is_none() && path(n, &q()).live().samples() >= 2 {
            second = Some(at);
        }
    });
    let second = second.expect("q has two samples");
    assert_eq!(
        seen,
        vec![(second + 2_000, Some(p()), q(), Switch::Discretionary)],
        "q's second sample came at {second} ms"
    );
    assert_eq!(scored(&n, &p(), 2), scored(&n, &q(), 2), "p and q tie");
    assert_eq!(active(&n), Some(q()));
}

#[test]
fn a_preferred_path_outside_the_margin_of_the_best_gives_way() {
    let cfg = Config::draft();
    let rtt = |_: u64, to: &PathRef| rtts(to, 200, 5);
    let mut net = Net::new(&rtt);
    let mut n = placed(182, role(1, Role::Preferred), &mut net);
    offer(&mut n, &mut net, &q());
    let mut first = None;
    let seen = net.run(&mut n, 30_000, &mut |n, at| {
        if first.is_none() && leads(n, &cfg) {
            first = Some(at);
        }
    });
    let first = first.expect("q scores better than the margin");
    assert_eq!(
        seen,
        vec![(first + 2_000, Some(p()), q(), Switch::Discretionary)],
        "the margin first held at {first} ms"
    );
    assert_eq!(active(&n), Some(q()));
}

#[test]
fn a_preferred_active_path_outside_the_margin_gives_way_with_a_second_preferred_path() {
    // p and q preferred, r normal and best. q is within the margin of r,
    // p is outside it, and p is within the margin of q, so only the
    // margin of the best tells p to give way.
    for with_q in [false, true] {
        let rtt = move |_: u64, to: &PathRef| {
            if *to == p() {
                Some(35)
            } else if *to == q() && with_q {
                Some(25)
            } else if *to == r() {
                Some(1)
            } else {
                None
            }
        };
        let facts = Stub::default()
            .fact(t(1), Fact::Role(Role::Preferred))
            .fact(t(2), Fact::Role(Role::Preferred));
        let mut net = Net::new(&rtt);
        let mut n = placed(903, facts, &mut net);
        if with_q {
            offer(&mut n, &mut net, &q());
        }
        offer(&mut n, &mut net, &r());
        let seen = run(&mut n, &mut net, 60_000);
        let (on_p, on_r) = (scored(&n, &p(), 2).unwrap(), scored(&n, &r(), 2).unwrap());
        assert!(
            on_p > 1.3 * on_r,
            "p is outside the margin of the best: {on_p} {on_r}"
        );
        let to = if with_q {
            let on_q = scored(&n, &q(), 2).unwrap();
            assert!(
                on_q <= 1.3 * on_r && on_p <= 1.3 * on_q,
                "{on_p} {on_q} {on_r}"
            );
            q()
        } else {
            r()
        };
        assert_eq!(seen.len(), 1, "with_q={with_q}: {seen:?}");
        let (_, from, at, why) = seen[0].clone();
        assert_eq!(
            (from, at, why),
            (Some(p()), to, Switch::Discretionary),
            "with_q={with_q}"
        );
    }
}

/// The link MTU of a transport too small to carry a `FilterAnnounce`.
const SMALL: usize = 1_000;

#[test]
fn a_path_that_cannot_carry_a_filter_announce_gives_way_to_one_that_can() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 1, 50);
    let mut net = Net::new(&rtt);
    let mut n = placed(183, Stub::default().mtu(t(1), SMALL), &mut net);
    offer(&mut n, &mut net, &q());
    let mut second = None;
    let seen = net.run(&mut n, 30_000, &mut |n, at| {
        if second.is_none() && path(n, &q()).live().samples() >= 2 {
            second = Some(at);
        }
    });
    let second = second.expect("q has two samples");
    assert!(
        scored(&n, &p(), 2)
            .zip(scored(&n, &q(), 2))
            .is_some_and(|(on_p, on_q)| on_p < on_q),
        "p scores better than q"
    );
    assert_eq!(
        seen,
        vec![(second + 2_000, Some(p()), q(), Switch::Discretionary)],
        "q's second sample came at {second} ms"
    );
    assert_eq!(active(&n), Some(q()));
}

#[test]
fn the_mandatory_change_takes_a_path_that_carries_a_filter_announce() {
    let rtt = |_: u64, to: &PathRef| {
        if *to == r() { Some(20) } else { rtts(to, 1, 1) }
    };
    let mut net = Net::new(&rtt);
    let mut n = placed(184, Stub::default().mtu(t(2), SMALL), &mut net);
    offer(&mut n, &mut net, &q());
    offer(&mut n, &mut net, &r());
    assert_eq!(run(&mut n, &mut net, 10_000), vec![]);
    let (on_q, on_r) = (scored(&n, &q(), 2), scored(&n, &r(), 2));
    assert!(
        on_q.zip(on_r).is_some_and(|(on_q, on_r)| on_q < on_r),
        "q scores better: {on_q:?} against {on_r:?}"
    );
    let out = step(&mut n, 10_000, down(1));
    assert_eq!(
        turns(10_000, &out),
        vec![(10_000, Some(p()), r(), Switch::Mandatory)],
        "the path that carries a filter takes the link"
    );
}

#[test]
fn with_no_live_path_that_carries_a_filter_announce_the_score_decides() {
    let cfg = Config::draft();
    let facts = Stub::default().mtu(t(1), SMALL).mtu(t(2), SMALL);
    let rtt = |_: u64, to: &PathRef| rtts(to, 200, 5);
    let mut net = Net::new(&rtt);
    let mut n = placed(185, facts, &mut net);
    offer(&mut n, &mut net, &q());
    let mut first = None;
    let seen = net.run(&mut n, 30_000, &mut |n, at| {
        if first.is_none() && leads(n, &cfg) {
            first = Some(at);
        }
    });
    let first = first.expect("q scores better than the margin");
    assert_eq!(
        seen,
        vec![(first + 2_000, Some(p()), q(), Switch::Discretionary)],
        "the margin first held at {first} ms"
    );
}

#[test]
fn a_normal_path_too_small_for_a_filter_announce_is_kept_over_a_backup_path_that_carries_one() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 5, 5);
    let facts = role(2, Role::Backup).mtu(t(1), SMALL);
    let mut net = Net::new(&rtt);
    let mut n = placed(186, facts, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 60_000), vec![]);
    assert_eq!(path(&n, &q()).state(), PathState::Live);
    let on_q = scored(&n, &q(), 2);
    assert!(on_q.is_some(), "q is scored");
    assert_eq!(scored(&n, &p(), 2), on_q, "p and q tie");
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn a_link_mtu_of_exactly_the_filter_frame_carries_a_filter_announce() {
    // p, 1 ms, has a link MTU one byte short of the frame, or exactly the
    // frame; q, 50 ms, exactly the frame. Only the short p gives way.
    for (on_p, moves) in [(1_070, true), (1_071, false)] {
        let rtt = |_: u64, to: &PathRef| rtts(to, 1, 50);
        let facts = Stub::default().mtu(t(1), on_p).mtu(t(2), 1_071);
        let mut net = Net::new(&rtt);
        let mut n = placed(185, facts, &mut net);
        offer(&mut n, &mut net, &q());
        let seen = run(&mut n, &mut net, 30_000);
        let to: Vec<_> = seen
            .iter()
            .map(|(_, _, to, why)| (to.clone(), *why))
            .collect();
        let want = if moves {
            vec![(q(), Switch::Discretionary)]
        } else {
            vec![]
        };
        assert_eq!(to, want, "p's link MTU {on_p}");
    }
}

/// The host's facts with transport `k`'s medium set to `medium`.
fn medium(k: u32, medium: Medium) -> Stub {
    Stub::default().fact(t(k), Fact::Medium(medium))
}

/// The host's facts with p on a wireless network and q on a cable.
fn wifi_and_cable() -> Stub {
    medium(1, Medium::Wireless).fact(t(2), Fact::Medium(Medium::Wired))
}

#[test]
fn a_cable_within_the_margin_of_a_better_scoring_wifi_takes_the_link_one_dwell_after_its_second_sample()
 {
    // p, the wireless network the link was made on, answers in 5 ms; q,
    // the cable, in 6 ms: within the margin, but scoring a little worse.
    let rtt = |_: u64, to: &PathRef| rtts(to, 5, 6);
    let mut net = Net::new(&rtt);
    let mut n = placed(190, wifi_and_cable(), &mut net);
    offer(&mut n, &mut net, &q());
    let mut second = None;
    let seen = net.run(&mut n, 30_000, &mut |n, at| {
        if second.is_none() && path(n, &q()).live().samples() >= 2 {
            second = Some(at);
        }
    });
    let second = second.expect("precondition: q has two samples");
    let (on_p, on_q) = (scored(&n, &p(), 2).unwrap(), scored(&n, &q(), 2).unwrap());
    assert!(
        on_p < on_q && on_q <= on_p * 1.3,
        "precondition: the cable scores worse, within the margin: {on_p} {on_q}"
    );
    assert_eq!(
        seen,
        vec![(second + 2_000, Some(p()), q(), Switch::Discretionary)],
        "defect: the cable within the margin did not take the link one dwell after its \
         second sample at {second} ms"
    );
    assert_eq!(active(&n), Some(q()));
}

#[test]
fn a_link_made_on_a_cable_stays_there_while_a_wifi_scores_better_within_the_margin() {
    // p, the cable the link was made on, answers in 6 ms; q, the wireless
    // network, in 5 ms.
    let rtt = |_: u64, to: &PathRef| rtts(to, 6, 5);
    let facts = medium(1, Medium::Wired).fact(t(2), Fact::Medium(Medium::Wireless));
    let mut net = Net::new(&rtt);
    let mut n = placed(191, facts, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 60_000), vec![]);
    assert_eq!(path(&n, &q()).state(), PathState::Live);
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn the_mandatory_change_takes_a_cable_within_the_margin_over_a_better_scoring_wifi() {
    // p fails; q, a wireless network, answers in 5 ms, and r, a cable, in
    // 6 ms.
    let rtt = |_: u64, to: &PathRef| {
        if *to == r() { Some(6) } else { rtts(to, 1, 5) }
    };
    let facts = medium(2, Medium::Wireless).fact(t(3), Fact::Medium(Medium::Wired));
    let mut net = Net::new(&rtt);
    let mut n = placed(192, facts, &mut net);
    offer(&mut n, &mut net, &q());
    offer(&mut n, &mut net, &r());
    assert_eq!(run(&mut n, &mut net, 10_000), vec![]);
    let (on_q, on_r) = (scored(&n, &q(), 2).unwrap(), scored(&n, &r(), 2).unwrap());
    assert!(
        on_q < on_r && on_r <= on_q * 1.3,
        "precondition: the cable scores worse, within the margin: {on_q} {on_r}"
    );
    let out = step(&mut n, 10_000, down(1));
    assert_eq!(
        turns(10_000, &out),
        vec![(10_000, Some(p()), r(), Switch::Mandatory)],
        "defect: the mandatory change took the wireless network over the cable within the margin"
    );
}

#[test]
fn a_cable_outside_the_margin_of_a_wifi_gives_way_to_it_and_does_not_take_the_link_from_it() {
    let cfg = Config::draft();

    // The link was made on the cable, p, at 50 ms; the wireless network,
    // q, answers in 5 ms, better than the margin.
    let rtt = |_: u64, to: &PathRef| rtts(to, 50, 5);
    let facts = medium(1, Medium::Wired).fact(t(2), Fact::Medium(Medium::Wireless));
    let mut net = Net::new(&rtt);
    let mut n = placed(193, facts, &mut net);
    offer(&mut n, &mut net, &q());
    let mut first = None;
    let seen = net.run(&mut n, 30_000, &mut |n, at| {
        if first.is_none() && leads(n, &cfg) {
            first = Some(at);
        }
    });
    let first = first.expect("q scores better than the margin");
    assert_eq!(
        seen,
        vec![(first + 2_000, Some(p()), q(), Switch::Discretionary)],
        "the margin first held at {first} ms"
    );

    // The link was made on the wireless network, p, at 5 ms; the cable, q,
    // answers in 50 ms.
    let rtt = |_: u64, to: &PathRef| rtts(to, 5, 50);
    let mut net = Net::new(&rtt);
    let mut n = placed(194, wifi_and_cable(), &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 60_000), vec![]);
    assert_eq!(path(&n, &q()).state(), PathState::Live);
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn an_unknown_medium_on_either_side_keeps_the_rule_of_score_alone() {
    // p answers in 5 ms and q in 6 ms, within the margin: with either
    // medium unknown, the link stays where it was made.
    for (on_p, on_q) in [
        (Medium::Unknown, Medium::Wired),
        (Medium::Wireless, Medium::Unknown),
        (Medium::Unknown, Medium::Unknown),
    ] {
        let rtt = |_: u64, to: &PathRef| rtts(to, 5, 6);
        let facts = medium(1, on_p).fact(t(2), Fact::Medium(on_q));
        let mut net = Net::new(&rtt);
        let mut n = placed(195, facts, &mut net);
        offer(&mut n, &mut net, &q());
        assert_eq!(run(&mut n, &mut net, 60_000), vec![], "{on_p:?} {on_q:?}");
        assert_eq!(path(&n, &q()).state(), PathState::Live);
        assert_eq!(active(&n), Some(p()), "{on_p:?} {on_q:?}");
    }
}

#[test]
fn a_cable_too_small_for_a_filter_announce_does_not_take_the_link_from_a_wifi_that_carries_one() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 5, 5);
    let mut net = Net::new(&rtt);
    let mut n = placed(196, wifi_and_cable().mtu(t(2), SMALL), &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 60_000), vec![]);
    assert_eq!(path(&n, &q()).state(), PathState::Live);
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn a_preferred_wifi_within_the_margin_keeps_the_link_over_a_cable() {
    let rtt = |_: u64, to: &PathRef| rtts(to, 6, 5);
    let facts = wifi_and_cable().fact(t(1), Fact::Role(Role::Preferred));
    let mut net = Net::new(&rtt);
    let mut n = placed(197, facts, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, 60_000), vec![]);
    assert_eq!(path(&n, &q()).state(), PathState::Live);
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn a_path_outside_the_margin_of_the_best_gives_way_to_a_cable_within_it_whatever_its_medium() {
    // q is a wireless network that scores best and r a cable within the
    // margin of it. p, a cable or of unknown medium, is outside the margin
    // of q and within the margin of r, so only the margin of the best tells
    // p to give way.
    for on_p in [Medium::Wired, Medium::Unknown] {
        let rtt = |_: u64, to: &PathRef| {
            if *to == r() {
                Some(25)
            } else {
                rtts(to, 40, 1)
            }
        };
        let facts = medium(1, on_p)
            .fact(t(2), Fact::Medium(Medium::Wireless))
            .fact(t(3), Fact::Medium(Medium::Wired));
        let mut net = Net::new(&rtt);
        let mut n = placed(198, facts, &mut net);
        offer(&mut n, &mut net, &q());
        offer(&mut n, &mut net, &r());
        let seen = run(&mut n, &mut net, 60_000);
        let on_p_score = scored(&n, &p(), 2).unwrap();
        let on_q = scored(&n, &q(), 2).unwrap();
        let on_r = scored(&n, &r(), 2).unwrap();
        assert!(
            on_p_score > 1.3 * on_q && on_r <= 1.3 * on_q && on_p_score <= 1.3 * on_r,
            "precondition: {on_p:?}: {on_p_score} {on_q} {on_r}"
        );
        let to: Vec<_> = seen
            .iter()
            .map(|(_, from, to, why)| (from.clone(), to.clone(), *why))
            .collect();
        assert_eq!(
            to,
            vec![(Some(p()), r(), Switch::Discretionary)],
            "defect: p, {on_p:?}, outside the margin of the best did not give way to the cable \
             within it"
        );
    }
}

/// The changes of active path from the onset of load at 40 s to 340 s on
/// a link made on p, a cable that answers in `idle_p` milliseconds while
/// idle, with q, a wireless network, in `idle_q`: from the onset on, the
/// active path answers in 200 ms, as load that follows the link would
/// make it.
fn under_load(seed: u64, idle_p: u64, idle_q: u64) -> Vec<Turn> {
    loaded(seed, (Medium::Wired, idle_p), (Medium::Wireless, idle_q))
}

/// The changes of active path from the onset of load at 40 s to 340 s on
/// a link made on p, whose medium and idle round trip in milliseconds are
/// `on_p`, with q as `on_q` says: from the onset on, the active path
/// answers in 200 ms, as load that follows the link would make it.
fn loaded(seed: u64, on_p: (Medium, u64), on_q: (Medium, u64)) -> Vec<Turn> {
    let ((medium_p, idle_p), (medium_q, idle_q)) = (on_p, on_q);
    let on_p = Cell::new(true);
    let rtt = |now: u64, to: &PathRef| {
        let loaded = now >= 40_000 && ((*to == p()) == on_p.get());
        Some(if loaded {
            200
        } else {
            rtts(to, idle_p, idle_q)?
        })
    };
    let facts = medium(1, medium_p).fact(t(2), Fact::Medium(medium_q));
    let mut net = Net::new(&rtt);
    let mut n = placed(seed, facts, &mut net);
    offer(&mut n, &mut net, &q());
    let seen = net.run(&mut n, 340_000, &mut |n, _| {
        on_p.set(active(n) == Some(p()));
    });
    seen.into_iter().filter(|s| s.0 >= 40_000).collect()
}

#[test]
fn load_that_follows_the_link_does_not_flap_it_between_a_cable_and_a_wifi_slightly_faster_at_its_best()
 {
    // The cable, p, answers in 6 ms idle and the wireless network, q, in
    // 5 ms: within the margin, so the cable holds the link while both are
    // idle. Load on the cable must not hand the link to q before it has
    // lasted the horizon, since the medium takes the link back from q one
    // dwell later.
    let seen = under_load(199, 6, 5);
    let at: Vec<_> = seen.iter().map(|s| (s.0, s.2.transport)).collect();
    let horizon = Config::draft().horizon.as_millis() as u64;
    assert!(
        seen.len() <= 2 * (300_000 / horizon) as usize,
        "defect: {} changes in 300 s of load, at most two a horizon: {at:?}",
        seen.len()
    );
    assert!(
        seen.first().is_some_and(|s| s.0 >= 40_000 + horizon),
        "the cable keeps the link until the load has lasted the horizon: {at:?}"
    );
}

#[test]
fn load_that_follows_the_link_moves_it_between_a_cable_faster_at_its_best_and_a_wifi_at_most_twice_a_horizon()
 {
    let seen = under_load(200, 4, 5);
    let at: Vec<_> = seen.iter().map(|s| (s.0, s.2.transport)).collect();
    let horizon = Config::draft().horizon.as_millis() as u64;
    assert!(
        seen.len() <= 2 * (300_000 / horizon) as usize,
        "{} changes in 300 s of load: {at:?}",
        seen.len()
    );
}

#[test]
fn load_that_follows_the_link_does_not_flap_it_between_a_wifi_and_a_slower_cable_outside_the_margin()
 {
    // The wireless network, p, answers in 5 ms idle and the cable, q, in
    // 50 ms: outside the margin, so the wireless network holds the link
    // while both are idle. Load on it raises its score over the window
    // past the cable's, but not its least round trip over the horizon
    // until the load has lasted the horizon; the cable's faster medium
    // must not take the link before then, since the wireless network
    // takes it back once the load has followed the link to the cable.
    let seen = loaded(201, (Medium::Wireless, 5), (Medium::Wired, 50));
    let at: Vec<_> = seen.iter().map(|s| (s.0, s.2.transport)).collect();
    let horizon = Config::draft().horizon.as_millis() as u64;
    assert!(
        seen.len() <= 2 * (300_000 / horizon) as usize,
        "defect: {} changes in 300 s of load, at most two a horizon: {at:?}",
        seen.len()
    );
    assert!(
        seen.first().is_some_and(|s| s.0 >= 40_000 + horizon),
        "the wireless network keeps the link until the load has lasted the horizon: {at:?}"
    );
}
