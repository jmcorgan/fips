//! Discretionary changes away from a loaded active path
//! (`proto::path::tests::damping::...`), driven through `Bundle`'s inputs
//! in the shell, with every path's round trips set by a `Net` from its
//! first probe on. Load is a rise in the active path's round trips at a
//! set instant, as a queue in front of its probes gives.

use alloc::vec;

use super::choice::{offer, rtts, run, start, tuned};
use super::pin::pin;
use super::shell::{Net, Node, active, down, p, path, q, scored, step, turns};
use crate::proto::path::select::steady;
use crate::proto::path::{Config, PathRef, PathState, Switch};
use crate::time::Duration;

/// When the load on p starts, in milliseconds.
const LOAD: u64 = 40_000;

/// p's round trip at `now`: `idle` milliseconds before the load, 200 from
/// it on.
fn loaded(now: u64, idle: u64) -> u64 {
    if now < LOAD { idle } else { 200 }
}

/// Whether q's score beats p's by `cfg`'s margin over the window, both
/// with enough samples: what a change on score from p waited on before
/// the horizon.
fn leads(n: &Node, cfg: &Config) -> bool {
    let min = usize::from(cfg.min_samples);
    scored(n, &p(), min)
        .zip(scored(n, &q(), min))
        .is_some_and(|(on_p, on_q)| on_p > on_q * cfg.switch_margin)
}

/// Whether q's score beats p's score over the horizon by `cfg`'s margin.
fn leads_steady(n: &Node, cfg: &Config) -> bool {
    let min = usize::from(cfg.min_samples);
    steady(path(n, &p()).live())
        .zip(scored(n, &q(), min))
        .is_some_and(|(on_p, on_q)| on_p > on_q * cfg.switch_margin)
}

#[test]
fn a_rival_that_beats_the_loaded_active_paths_window_but_not_its_horizon_does_not_take_the_link() {
    let cfg = Config::draft();
    // p answers in 5 ms idle and 200 ms loaded; q, idle throughout, in
    // 30 ms: slower than p at its best, faster than p loaded.
    let rtt = |now: u64, to: &PathRef| rtts(to, loaded(now, 5), 30);
    let mut net = Net::new(&rtt);
    let mut n = start(950, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(
        run(&mut n, &mut net, LOAD),
        vec![],
        "idle, p keeps the link"
    );
    let mut led = None;
    let until = LOAD + cfg.horizon.as_millis() as u64 - 5_000;
    let seen = net.run(&mut n, until, &mut |n, at| {
        if led.is_none() && leads(n, &cfg) {
            led = Some(at);
        }
    });
    let led = led.expect("precondition: q leads p over the window under the load");
    assert!(
        led < LOAD + 10_000,
        "precondition: within the window at the active cadence, at {led} ms"
    );
    assert_eq!(
        seen,
        vec![],
        "defect: load on p alone moved the link to q, slower at its best"
    );
    assert_eq!(active(&n), Some(p()));
}

#[test]
fn a_rival_that_beats_the_active_paths_horizon_too_takes_the_link_one_dwell_after() {
    // A dwell that ends between probe wakes, so only its own wake ends it.
    let cfg = Config {
        switch_dwell: Duration::from_millis(2_050),
        ..Config::draft()
    };
    let rtt = |now: u64, to: &PathRef| rtts(to, loaded(now, 5), 30);
    let mut net = Net::new(&rtt);
    let mut n = tuned(951, cfg, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, LOAD), vec![]);
    let mut first = None;
    let until = LOAD + 2 * cfg.horizon.as_millis() as u64;
    let seen = net.run(&mut n, until, &mut |n, at| {
        if first.is_none() && leads_steady(n, &cfg) {
            first = Some(at);
        }
    });
    let first = first.expect("the load outlasts the horizon");
    let horizon = cfg.horizon.as_millis() as u64;
    assert!(
        first >= LOAD + horizon,
        "p's least round trip over the horizon rose only once the load had lasted it, at \
         {first} ms"
    );
    assert_eq!(
        seen,
        vec![(first + 2_050, Some(p()), q(), Switch::Discretionary)],
        "q beat p's score over the horizon from {first} ms"
    );
}

#[test]
fn a_move_to_a_path_faster_at_its_best_than_the_loaded_active_path_is_not_held() {
    let cfg = Config::draft();
    // q answers in 8 ms, faster than p's 10 ms idle but within the margin
    // of it; under the load on p, q leads p over the window, and is the
    // faster of the two at its best over the horizon.
    let rtt = |now: u64, to: &PathRef| rtts(to, loaded(now, 10), 8);
    let mut net = Net::new(&rtt);
    let mut n = start(952, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, LOAD), vec![], "within the margin");
    let mut led = None;
    let seen = net.run(&mut n, LOAD + 20_000, &mut |n, at| {
        if led.is_none() && leads(n, &cfg) {
            led = Some(at);
        }
    });
    let led = led.expect("q leads p over the window under the load");
    assert!(
        !leads_steady(&n, &cfg),
        "precondition: q does not beat p's score over the horizon"
    );
    assert_eq!(
        seen,
        vec![(led + 2_000, Some(p()), q(), Switch::Discretionary)],
        "defect: the move to q, faster at its best, waited past one dwell from {led} ms"
    );
}

#[test]
fn a_mandatory_move_and_a_pinned_one_are_not_held() {
    let rtt = |now: u64, to: &PathRef| rtts(to, loaded(now, 5), 30);

    // p's carrier is lost under the load: the link leaves p at once.
    let mut net = Net::new(&rtt);
    let mut n = start(953, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, LOAD + 10_000), vec![]);
    let out = step(&mut n, LOAD + 10_000, down(1));
    assert_eq!(path(&n, &p()).state(), PathState::Suspect);
    assert_eq!(
        turns(LOAD + 10_000, &out),
        vec![(LOAD + 10_000, Some(p()), q(), Switch::Mandatory)]
    );

    // A pin of q, slower at its best than p, moves the link at once.
    let mut net = Net::new(&rtt);
    let mut n = start(954, &mut net);
    offer(&mut n, &mut net, &q());
    assert_eq!(run(&mut n, &mut net, LOAD + 10_000), vec![]);
    let out = step(&mut n, LOAD + 10_000, pin(2));
    assert_eq!(
        turns(LOAD + 10_000, &out),
        vec![(LOAD + 10_000, Some(p()), q(), Switch::Pinned)]
    );
}
