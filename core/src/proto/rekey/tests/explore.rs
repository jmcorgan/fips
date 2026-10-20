//! Bounded exhaustive exploration of two machines.
//!
//! From each scenario's starting world, every sequence of up to `depth`
//! events from a finite alphabet is enumerated breadth first: deliver any
//! datagram in flight, duplicate a handshake message, deliver a bit-flipped
//! copy of a frame, advance time to the next deadline of either end, poll
//! one end late across a suspend, seal a data frame at either end, and (for the session
//! shape) inject a msg3 under a third identity or a third party's setup.
//! States are de-duplicated on a canonical key of both machines, the
//! datagrams in flight, the clock and the event budget the path spent, so
//! a counterexample found is a shortest one.
//!
//! A machine holds linear leases and cannot be cloned, so each state is
//! rebuilt by replaying its path from the scenario's start; the world is
//! deterministic, so a path names one state. A datagram never delivered is
//! a lost one: the heal discards whatever is still in flight, so loss needs
//! no event of its own, and late delivery is a delivery after an advance. The simulator's per-step
//! oracles run on every replayed step: forged input changing nothing (O5),
//! sealing only under an epoch the peer has held, leases and bindings
//! conserved (O3), bounded memory (O6), the worker and orphan oracles, and
//! O4 after every timely poll. Every frontier state is fuzzed and then
//! healed: faults off, a clean channel, traffic both ways, and O1 must hold
//! within the liveness bound.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use super::sim::{Cfg, Chan, Flight, Origin, World, heal, params, run_until, tail};
use super::stub::{Ik, Local, Msg, Stub, Xk, XkFrame, Xx, bytes, ephemerals, forge3};
use crate::proto::rekey::MsgKind;
use crate::testutil::SplitMix64;

/// One event the explorer chooses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Act {
    /// Deliver the datagram now.
    Deliver(u64),
    /// Put a copy of a handshake message in flight.
    Dup(u64),
    /// Deliver a copy of a frame with one bit flipped.
    Flip(u64),
    /// Advance to the earliest next wake and poll whoever is due.
    Advance,
    /// Advance 8 s past node `x`'s next wake and poll only it: one late
    /// poll across a suspend.
    Late(usize),
    /// Node `x` seals a data frame.
    Data(usize),
    /// A msg3 under a third identity, for the latest setup and ack.
    Third,
    /// A third party's setup toward node `x` on carrier 2.
    Stranger(usize),
}

/// How many of the budgeted events one path may hold.
#[derive(Clone, Copy, Debug)]
struct Budget {
    dups: usize,
    data: usize,
    forgeries: usize,
    late: usize,
}

/// One exploration: a start, a depth and the event budgets.
struct Scenario<P: Stub> {
    name: &'static str,
    start: fn() -> World<P>,
    depth: usize,
    budget: Budget,
}

/// Rebuild the world a path leads to.
fn replay<P: Stub>(sc: &Scenario<P>, path: &[Act]) -> World<P> {
    replay_logged(sc, path, false)
}

/// Rebuild the world a path leads to, logging events when `logging`.
fn replay_logged<P: Stub>(sc: &Scenario<P>, path: &[Act], logging: bool) -> World<P> {
    let mut w = (sc.start)();
    w.logging = logging;
    for &a in path {
        apply(&mut w, a);
        if w.failure.is_some() {
            break;
        }
    }
    w
}

/// Carry out one event.
fn apply<P: Stub>(w: &mut World<P>, a: Act) {
    match a {
        Act::Deliver(id) => w.deliver(id),
        Act::Dup(id) => {
            let now = w.now;
            w.copy(id, now);
        }
        Act::Flip(id) => {
            if let Some(f) = w.flight.iter().find(|f| f.id == id).cloned() {
                let mut b = bytes(&f.msg);
                let i = b.len() - 2;
                b[i] ^= 0x10;
                let msg = match f.msg {
                    Msg::Hs(k, _) => Msg::Hs(k, b),
                    Msg::Frame(_, t) => Msg::Frame(b, t),
                };
                w.inject(f.to, msg, Origin::Forged, 1);
            }
        }
        Act::Advance => {
            if let Some(t) = w.wake() {
                w.now = w.now.max(t);
                for x in 0..2 {
                    if w.n[x].wake.is_some_and(|wk| wk <= w.now) {
                        w.poll(x);
                    }
                }
            }
        }
        Act::Late(x) => {
            if let Some(t) = w.n[x].wake {
                w.now = w.now.max(t + 8_000);
                w.poll(x);
            }
        }
        Act::Data(x) => w.data(x),
        Act::Third => {
            let pick = |k: MsgKind| {
                w.flight
                    .iter()
                    .rev()
                    .find(|f| matches!(&f.msg, Msg::Hs(m, _) if *m == k))
                    .cloned()
            };
            if let (Some(s), Some(a)) = (pick(MsgKind::Setup), pick(MsgKind::Ack)) {
                let (ei, er) = ephemerals(&bytes(&s.msg), &bytes(&a.msg));
                let m3 = forge3(&Local::new(99, 99), ei, er);
                w.inject(s.to, Msg::Hs(MsgKind::Msg3, m3), Origin::Forged, 1);
            }
        }
        Act::Stranger(x) => {
            let mut m = alloc::vec![1u8];
            m.extend_from_slice(&(0xfeed_u64 + w.now).to_le_bytes());
            w.inject(x, Msg::Hs(MsgKind::Setup, m), Origin::Forged, 2);
        }
    }
}

/// The events available in `w` for a path that has spent `used`.
fn options<P: Stub>(w: &World<P>, path: &[Act], b: Budget) -> Vec<Act> {
    let count = |f: fn(&Act) -> bool| path.iter().filter(|a| f(a)).count();
    let dups = count(|a| matches!(a, Act::Dup(_)));
    let data = count(|a| matches!(a, Act::Data(_)));
    let forged = count(|a| matches!(a, Act::Flip(_) | Act::Third | Act::Stranger(_)));
    let late = count(|a| matches!(a, Act::Late(_)));
    let mut out = Vec::new();
    for f in &w.flight {
        out.push(Act::Deliver(f.id));
        let frame = matches!(f.msg, Msg::Frame(..));
        if !frame && dups < b.dups && !matches!(f.origin, Origin::Copy(_)) {
            out.push(Act::Dup(f.id));
        }
        if frame && forged < b.forgeries {
            out.push(Act::Flip(f.id));
        }
    }
    if w.wake().is_some() {
        out.push(Act::Advance);
    }
    for x in 0..2 {
        if late < b.late && w.n[x].wake.is_some() {
            out.push(Act::Late(x));
        }
        if data < b.data && w.n[x].m.is_some() {
            out.push(Act::Data(x));
        }
    }
    if P::fsp().is_some() && forged < b.forgeries {
        let has = |k: MsgKind| {
            w.flight
                .iter()
                .any(|f: &Flight| matches!(&f.msg, Msg::Hs(m, _) if *m == k))
        };
        if has(MsgKind::Setup) && has(MsgKind::Ack) {
            out.push(Act::Third);
        }
        out.push(Act::Stranger(0));
        out.push(Act::Stranger(1));
    }
    out
}

/// The canonical hash of a world, with the budgeted events the path to it
/// spent: a state reached with more budget left has successors one reached
/// with less cannot, so the two are not the same node of the search.
fn key<P: Stub>(w: &World<P>, path: &[Act]) -> (u64, [usize; 4]) {
    let count = |f: fn(&Act) -> bool| path.iter().filter(|a| f(a)).count();
    let spent = [
        count(|a| matches!(a, Act::Dup(_))),
        count(|a| matches!(a, Act::Data(_))),
        count(|a| matches!(a, Act::Flip(_) | Act::Third | Act::Stranger(_))),
        count(|a| matches!(a, Act::Late(_))),
    ];
    (w.key(), spent)
}

/// Heal `w`: what is still in flight is lost, then faults off, a clean
/// FIFO channel and data both ways every two seconds, until both ends agree
/// or the liveness bound passes; then O1.
fn heals<P: Stub>(w: &mut World<P>) -> Result<(), String> {
    let p = params::<P>();
    let mut cfg = Cfg::clean();
    cfg.gap = [2_000, 2_000];
    cfg.fault_end = 0;
    w.chan = Some(Chan::new(0, cfg));
    let start = w.now;
    w.flight.clear();
    let end = start + heal(&p);
    while w.failure.is_none() && w.now < end {
        if w.converged().is_ok() {
            return Ok(());
        }
        let next = w.now + 1_000;
        run_until(w, next);
    }
    if let Some(f) = w.failure.take() {
        return Err(f);
    }
    w.converged()
}

/// Deliver seeded random byte strings of every input kind the profile
/// takes to both nodes: each must change nothing but candidates (O5) and
/// panic nowhere.
fn fuzz<P: Stub>(w: &mut World<P>, seed: u64) {
    let mut g = SplitMix64::new(seed);
    let mut kinds = alloc::vec![MsgKind::Ack];
    if P::fsp().is_some() || P::MESSAGES == 3 {
        kinds.extend([MsgKind::Setup, MsgKind::Msg3]);
    } else {
        kinds.push(MsgKind::Msg1);
    }
    for to in 0..2 {
        for _ in 0..4 {
            for &k in &kinds {
                let len = g.below(80) as usize;
                let b: Vec<u8> = (0..len).map(|_| g.next_u64() as u8).collect();
                w.inject(to, Msg::Hs(k, b), Origin::Forged, 2);
            }
            // The shell drops a frame shorter than its header before any
            // machine sees it.
            let len = super::stub::HEADER + g.below(67) as usize;
            let b: Vec<u8> = (0..len).map(|_| g.next_u64() as u8).collect();
            let tag = crate::proto::rekey::TagSource::new().draw();
            w.inject(to, Msg::Frame(b, tag), Origin::Forged, 1);
        }
    }
}

/// What one exploration covered.
#[derive(Debug, Default)]
struct Stats {
    states: usize,
    depth: usize,
    healed: usize,
}

/// Explore `sc` breadth first and panic with the shortest failing path,
/// then fuzz and heal every frontier state.
fn explore<P: Stub>(sc: &Scenario<P>) -> Stats {
    let mut seen: BTreeSet<(u64, [usize; 4])> = BTreeSet::new();
    let root = replay(sc, &[]);
    if let Some(f) = &root.failure {
        panic!("{}: the start fails: {f}", sc.name);
    }
    seen.insert(key(&root, &[]));
    let mut frontier: Vec<Vec<Act>> = alloc::vec![Vec::new()];
    let mut stats = Stats::default();
    let mut leaves: Vec<Vec<Act>> = Vec::new();
    for depth in 0..sc.depth {
        let mut next = Vec::new();
        for path in &frontier {
            let w = replay(sc, path);
            let opts = options(&w, path, sc.budget);
            if opts.is_empty() {
                leaves.push(path.clone());
            }
            for a in opts {
                let mut p = path.clone();
                p.push(a);
                let w2 = replay(sc, &p);
                if let Some(f) = &w2.failure {
                    let w2 = replay_logged(sc, &p, true);
                    panic!(
                        "{} at depth {}: {f}\npath {p:?}\nlog tail:\n{}",
                        sc.name,
                        depth + 1,
                        tail(&w2.log)
                    );
                }
                if seen.insert(key(&w2, &p)) {
                    next.push(p);
                }
            }
        }
        stats.states = seen.len();
        stats.depth = depth + 1;
        if std::env::var_os("FIPS_EXPLORE_TRACE").is_some() {
            std::eprintln!("{}: depth {} frontier {}", sc.name, depth + 1, next.len());
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    leaves.extend(frontier);
    for (i, path) in leaves.iter().enumerate() {
        let mut w = replay(sc, path);
        fuzz(&mut w, i as u64);
        if let Some(f) = w.failure.take() {
            panic!("{}: fuzzing the state after {path:?}: {f}", sc.name);
        }
        if heals(&mut w).is_err() {
            let mut w = replay_logged(sc, path, true);
            fuzz(&mut w, i as u64);
            let f = heals(&mut w).expect_err("a replayed path heals the same way");
            if std::env::var_os("FIPS_EXPLORE_TRACE").is_some() {
                std::eprintln!("FULL LOG\n{}", w.log.join("\n"));
            }
            panic!(
                "{}: the state after {path:?} does not heal: {f}\nlog tail:\n{}",
                sc.name,
                tail(&w.log)
            );
        }
        stats.healed += 1;
    }
    stats
}

/// A pair whose node 0 rekeys first: its first jitter draw is the lowest,
/// node 1's the highest.
fn first<P: Stub>() -> World<P> {
    let mut w = World::<P>::pair_queued(params::<P>(), false, [alloc::vec![0], alloc::vec![30]]);
    prime(&mut w);
    w
}

/// As [`first`], with the larger address at node 0.
fn first_swapped<P: Stub>() -> World<P> {
    let mut w = World::<P>::pair_queued(params::<P>(), true, [alloc::vec![0], alloc::vec![30]]);
    prime(&mut w);
    w
}

/// A pair whose ends draw equal jitter and so start in the same instant.
fn crossing<P: Stub>() -> World<P> {
    let mut w = World::<P>::pair_queued(params::<P>(), false, [Vec::new(), Vec::new()]);
    prime(&mut w);
    w
}

/// Advance a fresh pair to its first trigger, polling whoever is due, so
/// the first attempt (or both crossing attempts) is in flight.
fn prime<P: Stub>(w: &mut World<P>) {
    if let Some(t) = w.wake() {
        w.now = t;
        for x in 0..2 {
            if w.n[x].wake.is_some_and(|wk| wk <= t) {
                w.poll(x);
            }
        }
    }
}

/// A first handshake with node 0 dialing.
fn opening() -> World<Xk> {
    World::<Xk>::opening(params::<Xk>(), false, None)
}

/// As [`opening`], node 0 the larger address.
fn opening_swapped() -> World<Xk> {
    World::<Xk>::opening(params::<Xk>(), true, None)
}

/// An XK rekey whose initiator (node 0) has completed and whose msg3 and
/// first probe were lost, the responder silent: the confirmation window is
/// running.
fn confirming() -> World<Xk> {
    let mut w = first::<Xk>();
    deliver_kind(&mut w, MsgKind::Setup);
    deliver_kind(&mut w, MsgKind::Ack);
    let ids: Vec<u64> = w.flight.iter().map(|f| f.id).collect();
    for id in ids {
        w.lose(id);
    }
    w
}

/// An XK rekey node 0 assumed: its msg3 reached node 1, which cut over, but
/// every frame node 1 sent was lost until the confirmation deadline passed;
/// one data frame node 1 sealed under the old epoch before the rekey is
/// still in flight, so its delivery is a drained-epoch frame after an
/// assumed cutover.
fn assumed() -> World<Xk> {
    let mut w = first::<Xk>();
    w.data(1);
    let old = w.flight.last().map(|f| f.id);
    deliver_kind(&mut w, MsgKind::Setup);
    deliver_kind(&mut w, MsgKind::Ack);
    deliver_kind(&mut w, MsgKind::Msg3);
    for _ in 0..64 {
        let lost: Vec<u64> = w
            .flight
            .iter()
            .map(|f| f.id)
            .filter(|&id| Some(id) != old)
            .collect();
        for id in lost {
            w.lose(id);
        }
        if w.t.assumed > 0 {
            break;
        }
        apply(&mut w, Act::Advance);
    }
    assert!(w.t.assumed > 0, "the start reaches an assumed cutover");
    w
}

/// Deliver the first datagram in flight of handshake kind `k`.
fn deliver_kind<P: Stub>(w: &mut World<P>, k: MsgKind) {
    if let Some(id) = w
        .flight
        .iter()
        .find(|f| matches!(&f.msg, Msg::Hs(m, _) if *m == k))
        .map(|f| f.id)
    {
        w.deliver(id);
    }
}

/// The budgets most scenarios use.
const SMALL: Budget = Budget {
    dups: 1,
    data: 1,
    forgeries: 1,
    late: 1,
};

/// The explorations of each profile.
type Scenarios = (
    Vec<Scenario<Ik>>,
    Vec<Scenario<Xk>>,
    Vec<Scenario<XkFrame>>,
    Vec<Scenario<Xx>>,
);

/// The explorations, by profile; run by the test below.
fn scenarios() -> Scenarios {
    let ik = alloc::vec![
        Scenario {
            name: "ik one rekey",
            start: first::<Ik>,
            depth: 6,
            budget: SMALL,
        },
        Scenario {
            name: "ik one rekey, larger initiator",
            start: first_swapped::<Ik>,
            depth: 6,
            budget: SMALL,
        },
        Scenario {
            name: "ik crossing",
            start: crossing::<Ik>,
            depth: 6,
            budget: SMALL,
        },
    ];
    let xk = alloc::vec![
        Scenario {
            name: "xk one rekey",
            start: first::<Xk>,
            depth: 5,
            budget: SMALL,
        },
        Scenario {
            name: "xk one rekey, larger initiator",
            start: first_swapped::<Xk>,
            depth: 5,
            budget: SMALL,
        },
        Scenario {
            name: "xk crossing",
            start: crossing::<Xk>,
            depth: 5,
            budget: SMALL,
        },
        Scenario {
            name: "xk confirmation window, msg3 and probe lost",
            start: confirming,
            depth: 5,
            budget: SMALL,
        },
        Scenario {
            name: "xk assumed cutover, an old frame in flight",
            start: assumed,
            depth: 5,
            budget: SMALL,
        },
        Scenario {
            name: "xk first handshake",
            start: opening,
            depth: 6,
            budget: SMALL,
        },
        Scenario {
            name: "xk first handshake, larger dialer",
            start: opening_swapped,
            depth: 6,
            budget: SMALL,
        },
    ];
    let frame = alloc::vec![Scenario {
        name: "xk frame-driven responder, one rekey",
        start: first::<XkFrame>,
        depth: 5,
        budget: SMALL,
    }];
    let xx = alloc::vec![
        Scenario {
            name: "xx one rekey",
            start: first::<Xx>,
            depth: 6,
            budget: SMALL,
        },
        Scenario {
            name: "xx crossing",
            start: crossing::<Xx>,
            depth: 6,
            budget: SMALL,
        },
    ];
    (ik, xk, frame, xx)
}

#[test]
fn every_explored_interleaving_keeps_the_invariants_and_heals() {
    let (ik, xk, frame, xx) = scenarios();
    // The scenarios are independent and deterministic, so they run on
    // threads of their own.
    let report: Vec<(&str, Stats)> = std::thread::scope(|s| {
        let mut handles = Vec::new();
        for sc in &ik {
            handles.push(s.spawn(move || (sc.name, explore(sc))));
        }
        for sc in &xk {
            handles.push(s.spawn(move || (sc.name, explore(sc))));
        }
        for sc in &frame {
            handles.push(s.spawn(move || (sc.name, explore(sc))));
        }
        for sc in &xx {
            handles.push(s.spawn(move || (sc.name, explore(sc))));
        }
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    });
    for (name, s) in &report {
        std::eprintln!(
            "explored {name}: {} states to depth {}, {} healed",
            s.states,
            s.depth,
            s.healed
        );
        assert!(s.states > 1 && s.healed > 0, "{name} explored nothing");
    }
}
