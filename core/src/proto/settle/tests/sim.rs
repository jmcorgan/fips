//! Seeded long runs of the settlement core in the world, with shrinking.
//!
//! The explorer covers every short schedule from a named start; these runs
//! cover long ones from a cold start, drawn from a seed. Two nodes, each
//! made by a maker (the core at both ends by default), are configured to
//! dial one another, or one dials and the other waits, on one of four
//! transport models: connectionless, connection-oriented, BLE, or one of
//! each direction. A run then takes one event per step until its fault
//! phase ends, heals, and checks the properties:
//!
//! - **Loss.** A packet drawn as lost is never delivered; the next advance
//!   of the clock drops it with whatever else is in flight.
//! - **Duplication.** A handshake message drawn as duplicated is copied
//!   once, just before its first delivery.
//! - **Delay.** Each packet draws a heavy-tailed delay, and of the packets
//!   a connection lets through the one sent earliest plus its delay is
//!   delivered first, so later packets overtake it. The world bounds a
//!   delay at one wake, so a delay that long is a loss: at a step drawn as
//!   late the clock advances with packets still in flight.
//! - **Partitions.** In a window drawn from the seed nothing is delivered.
//! - **Restarts, rekeys, frames, connection faults and wall steps**, each
//!   drawn per step, the first and the last within a per-run cap.
//!
//! Every decision is a pure function of the seed and a stable key: a
//! packet's decisions of its number in the world, a step's of its ordinal.
//! A run is recorded as the explorer's events it took, so the explorer's
//! replay rebuilds any run, and a failing run is shrunk by removing events
//! from its schedule while it still fails with the same property at the
//! same node, as the rekey machine's simulator removes decisions. Set
//! `FIPS_SETTLE_SIM_NOSHRINK` to report the full schedule instead.
//!
//! The properties are the explorer's: those of every step after every
//! event, and those of a healed world at the end, with a split exempt on a
//! run that showed a known shape.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::model::history::Epoch;
use super::explore::{Act, apply};
use super::oracle::{by_shape, every_step, heal, healed};
use super::starts::{A, B, BLE, Maker, TCP, UDP, dial_home, world_of};
use super::stub::core;
use super::world::{Ms, Pkt, State, World};
use crate::testutil::SplitMix64;

/// The step cap of one run, so a guard switched off that makes the world
/// spin fails instead of hanging.
const STEPS: usize = 5_000;

/// The transports a run's two nodes dial each other on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Model {
    /// Both on the connectionless transport.
    Datagram,
    /// Both on the connection-oriented transport.
    Stream,
    /// Both on BLE.
    Ble,
    /// Node 0 on the connectionless transport, node 1 on the
    /// connection-oriented one.
    Mixed,
}

/// The draws of one run, each per mille unless named otherwise.
#[derive(Clone, Copy, Debug)]
pub struct Cfg {
    /// The transports.
    pub model: Model,
    /// A packet is lost.
    pub loss: u64,
    /// A handshake message is duplicated.
    pub dup: u64,
    /// Packets draw a heavy-tailed delay; otherwise they arrive in order.
    pub reorder: bool,
    /// A step advances the clock with packets still in flight.
    pub late: u64,
    /// A step restarts a node.
    pub restart: u64,
    /// The most restarts in a run.
    pub restarts: usize,
    /// A step starts an own rekey.
    pub rekey: u64,
    /// A step sends a frame now.
    pub frame: u64,
    /// A step fails a connection, or a connect window.
    pub fail: u64,
    /// A step steps the wall clock.
    pub wall: u64,
    /// The most wall steps in a run.
    pub walls: usize,
    /// One partition window is drawn.
    pub partition: bool,
    /// When the fault phase ends, on the world's clock.
    pub end: Ms,
}

impl Cfg {
    /// A faulty run on `model`.
    pub fn faulty(model: Model) -> Self {
        Self {
            model,
            loss: 100,
            dup: 100,
            reorder: true,
            late: 30,
            restart: 30,
            restarts: 2,
            rekey: 80,
            frame: 80,
            fail: 25,
            wall: 10,
            walls: 1,
            partition: true,
            end: 300_000,
        }
    }

    /// A clean run on `model`: no loss, duplicate, reordering, late
    /// advance, restart, failure, wall step or partition; rekeys and frames
    /// only.
    pub fn clean(model: Model) -> Self {
        Self {
            model,
            loss: 0,
            dup: 0,
            reorder: false,
            late: 0,
            restart: 0,
            restarts: 0,
            rekey: 80,
            frame: 80,
            fail: 0,
            wall: 0,
            walls: 0,
            partition: false,
            end: 300_000,
        }
    }
}

/// What failed: the property and node, which a shrink must keep, and what
/// was found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// The property and the node index, or a planted label.
    pub label: String,
    /// What was found.
    pub what: String,
}

/// The outcome of one run.
pub struct Report {
    /// The events the run took.
    pub acts: Vec<Act>,
    /// The first failure, if any.
    pub failure: Option<Failure>,
    /// The world's log, when logging.
    pub log: Vec<String>,
    /// The healed world's digest.
    pub digest: String,
}

/// A check run after every event; a non-empty answer fails the run with
/// its first entry.
pub type Check = fn(&World, &Init) -> Vec<Failure>;

/// What a check knows of the run's start.
pub struct Init {
    /// Each node's epoch in its first life.
    pub epochs: Vec<Epoch>,
}

/// The properties of every step, as failures.
pub fn properties(w: &World, _: &Init) -> Vec<Failure> {
    every_step(w).into_iter().map(failure).collect()
}

fn failure(b: super::oracle::Breach) -> Failure {
    Failure {
        label: format!("{:?} at n{}", b.oracle, b.node),
        what: b.what,
    }
}

/// Whether `b` is a responder pending of the peer's own rekey that the
/// peer has since given up unanswered: it sent the msg1 in this life and
/// holds no rekey of it, so nothing will adopt the pending before its hold
/// clears it, past the heal. The one breach of another cause the shape
/// exemption had spared in these runs (seed 29 of the two-transport set,
/// on a path that had shown `RekeyInstall` long before), so its own
/// exemption, which a test below holds.
fn abandoned(w: &World, b: &super::oracle::Breach) -> bool {
    let Some(&hs) = b.about.last().filter(|_| b.what.starts_with("pending:")) else {
        return false;
    };
    let me = w.ids[b.node];
    w.parties.iter().enumerate().any(|(y, p)| {
        let v = p.view();
        y != b.node
            && v.rekeys.contains(&(me, hs))
            && v.peers.iter().any(|q| q.peer == me && q.rekey != Some(hs))
    })
}

/// The world of a run: two nodes on `cfg`'s transports, in the address
/// order and dialing as the seed draws, with their first dials made.
pub fn world(seed: u64, cfg: &Cfg, mk: Maker) -> World {
    let ids = if SplitMix64::mix(seed, &[0]).is_multiple_of(2) {
        [A, B]
    } else {
        [B, A]
    };
    let (t0, t1) = match cfg.model {
        Model::Datagram => (UDP, UDP),
        Model::Stream => (TCP, TCP),
        Model::Ble => (BLE, BLE),
        Model::Mixed => (UDP, TCP),
    };
    let both = SplitMix64::mix(seed, &[1]).is_multiple_of(2);
    let d0 = [(1, t0)];
    let d1 = [(0, t1)];
    let none: [(usize, u8); 0] = [];
    let dials: [&[(usize, u8)]; 2] = [&d0, if both { &d1 } else { &none }];
    let mut w = world_of(mk, &ids, &dials);
    dial_home(&mut w, 0, 1, t0);
    if both {
        dial_home(&mut w, 1, 0, t1);
    }
    w
}

/// A heavy-tailed delay in packet numbers: most packets none or one, a few
/// tens.
fn delay(seed: u64, id: u64) -> u64 {
    let u = SplitMix64::mix(seed, &[3, id]) % 1_000 + 1;
    1_000 / u - 1
}

/// The partition window of a run, if it draws one.
fn partition(seed: u64, cfg: &Cfg) -> Option<(Ms, Ms)> {
    cfg.partition.then(|| {
        let from = SplitMix64::mix(seed, &[5]) % cfg.end;
        let len = 5_000 + SplitMix64::mix(seed, &[6]) % 25_000;
        (from, from + len)
    })
}

/// What a run has spent of its capped events, and the packets it copied.
#[derive(Default)]
struct Spent {
    restarts: usize,
    walls: usize,
    dups: BTreeSet<u64>,
}

/// The event step `step` of a run of `seed` takes in `w`.
fn choose(w: &World, seed: u64, step: usize, cfg: &Cfg, spent: &Spent) -> Option<Act> {
    let n = w.parties.len();
    let mut g = SplitMix64::new(SplitMix64::mix(seed, &[4, step as u64]));
    let r = g.below(1_000);
    let mut at = 0;
    let mut band = |p: u64| {
        let hit = r >= at && r < at + p;
        at += p;
        hit
    };
    if band(cfg.restart) && spent.restarts < cfg.restarts {
        return Some(Act::Restart(g.below(n as u64) as usize));
    }
    if band(cfg.rekey) {
        let x = g.below(n as u64) as usize;
        if let Some(y) = (0..n).find(|&y| y != x && w.parties[x].rekeyable(w.ids[y])) {
            return Some(Act::Rekey(x, y));
        }
    }
    if band(cfg.frame) {
        let x = g.below(n as u64) as usize;
        if !w.parties[x].held().is_empty() {
            return Some(Act::Frame(x));
        }
    }
    if band(cfg.wall) && spent.walls < cfg.walls {
        return Some(Act::Wall);
    }
    if band(cfg.fail) {
        let e = g.below(2) as usize;
        if let Some(c) = w.net.conns.iter().find(|c| c.state == State::Open) {
            return Some(Act::Fail(c.id, e));
        }
        if let Some(c) = w.net.conns.iter().find(|c| c.state == State::Connecting) {
            return Some(Act::Connect(c.id, false));
        }
    }
    if let Some(c) = w.net.conns.iter().find(|c| c.state == State::Connecting) {
        return Some(Act::Connect(c.id, true));
    }
    let cut = partition(seed, cfg).is_some_and(|(a, b)| (a..b).contains(&w.net.now));
    let lost = |id: u64| SplitMix64::mix(seed, &[1, id]) % 1_000 < cfg.loss;
    let next = w
        .net
        .flight
        .iter()
        .filter(|f| w.net.deliverable(f) && (f.pkt == Pkt::Eof || !(cut || lost(f.id))))
        .min_by_key(|f| {
            let d = if cfg.reorder { delay(seed, f.id) } else { 0 };
            (f.id + d, f.id)
        });
    if let Some(f) = next
        && !band(cfg.late)
    {
        if f.pkt.handshake()
            && !f.copy
            && !spent.dups.contains(&f.id)
            && SplitMix64::mix(seed, &[2, f.id]) % 1_000 < cfg.dup
        {
            return Some(Act::Dup(f.id));
        }
        return Some(Act::Deliver(f.id));
    }
    w.wake().map(|_| Act::Advance)
}

/// Whether a scripted event can be taken in `w`: a shrunk schedule may
/// name a connection that was never opened, or a rekey the node cannot
/// start, and such an event is skipped.
fn valid(w: &World, a: Act) -> bool {
    match a {
        Act::Connect(c, _) | Act::Fail(c, _) => (c as usize) < w.net.conns.len(),
        Act::Rekey(x, y) => w.parties[x].rekeyable(w.ids[y]),
        Act::Deliver(_)
        | Act::Dup(_)
        | Act::Restart(_)
        | Act::Advance
        | Act::Leap
        | Act::Frame(_)
        | Act::Wall
        | Act::Replay(_)
        | Act::Third(_)
        | Act::Garbage(_)
        | Act::Path(_)
        | Act::Dial(..) => true,
    }
}

/// Run `cfg` from `seed`'s world with nodes made by `mk`: the drawn events
/// until the fault phase ends, or `script`'s events if given; then a heal.
/// `check` runs after every event, and the healed properties at the end.
pub fn run(
    seed: u64,
    cfg: &Cfg,
    mk: Maker,
    script: Option<&[Act]>,
    check: Check,
    logging: bool,
) -> Report {
    let mut acts = Vec::new();
    let mut log = Vec::new();
    let mut digest = String::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut w = world(seed, cfg, mk);
        w.net.logging = logging;
        let init = Init {
            epochs: w.parties.iter().map(|p| p.epoch()).collect(),
        };
        let mut spent = Spent::default();
        let mut found = check(&w, &init).into_iter().next();
        let mut step = 0;
        while found.is_none() && step < STEPS {
            let a = match script {
                Some(s) => match s.get(step) {
                    Some(&a) if valid(&w, a) => a,
                    Some(_) => {
                        step += 1;
                        continue;
                    }
                    None => break,
                },
                None => {
                    if w.net.now >= cfg.end {
                        break;
                    }
                    match choose(&w, seed, step, cfg, &spent) {
                        Some(a) => a,
                        None => break,
                    }
                }
            };
            match a {
                Act::Restart(_) => spent.restarts += 1,
                Act::Wall => spent.walls += 1,
                Act::Dup(id) => {
                    spent.dups.insert(id);
                }
                Act::Deliver(_)
                | Act::Connect(..)
                | Act::Fail(..)
                | Act::Advance
                | Act::Leap
                | Act::Rekey(..)
                | Act::Frame(_)
                | Act::Replay(_)
                | Act::Third(_)
                | Act::Garbage(_)
                | Act::Path(_)
                | Act::Dial(..) => {}
            }
            apply(&mut w, a);
            acts.push(a);
            found = check(&w, &init).into_iter().next();
            step += 1;
        }
        if found.is_none() && step >= STEPS {
            found = Some(Failure {
                label: String::from("steps"),
                what: format!("the run took {STEPS} steps"),
            });
        }
        if found.is_none() {
            heal(&mut w);
            found = check(&w, &init)
                .into_iter()
                .chain(
                    healed(&w)
                        .into_iter()
                        .filter(|b| !by_shape(&w, b) && !abandoned(&w, b))
                        .map(failure),
                )
                .next();
        }
        log = core::mem::take(&mut w.net.log);
        digest = w.digest();
        found
    }));
    let failure = result.unwrap_or_else(|e| {
        let msg = e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| String::from(*s)))
            .unwrap_or_default();
        Some(Failure {
            label: String::from("panic"),
            what: msg,
        })
    });
    Report {
        acts,
        failure,
        log,
        digest,
    }
}

/// Remove events from a failing run's schedule, halves first and then
/// smaller pieces down to one event, while it still fails with the same
/// label; return the shortest failing schedule found.
pub fn shrink(
    seed: u64,
    cfg: &Cfg,
    mk: Maker,
    acts: &[Act],
    label: &str,
    check: Check,
) -> Vec<Act> {
    let mut cur = acts.to_vec();
    if fault!(NoShrink) {
        return cur;
    }
    let fails = |s: &[Act]| {
        run(seed, cfg, mk, Some(s), check, false)
            .failure
            .is_some_and(|f| f.label == label)
    };
    let mut chunk = cur.len().div_ceil(2).max(1);
    loop {
        let mut removed = false;
        let mut i = 0;
        while i < cur.len() {
            let mut trial = cur.clone();
            trial.drain(i..(i + chunk).min(cur.len()));
            if fails(&trial) {
                cur = trial;
                removed = true;
            } else {
                i += chunk;
            }
        }
        if !removed {
            if chunk == 1 {
                break;
            }
            chunk = chunk.div_ceil(2);
        }
    }
    cur
}

/// Run `cfg` from every seed of `seeds` with the core at both ends, and
/// panic with the first failure's seed, its shrunk schedule and the log of
/// that schedule.
pub fn runs(name: &str, seeds: core::ops::Range<u64>, cfg: &Cfg) {
    for seed in seeds {
        let r = run(seed, cfg, core, None, properties, false);
        let Some(f) = r.failure else {
            continue;
        };
        if std::env::var_os("FIPS_SETTLE_SIM_NOSHRINK").is_some() {
            let again = run(seed, cfg, core, Some(&r.acts), properties, true);
            panic!(
                "{name} seed {seed}: {}: {}\nschedule {:?}\nlog:\n{}",
                f.label,
                f.what,
                r.acts,
                again.log.join("\n")
            );
        }
        let min = shrink(seed, cfg, core, &r.acts, &f.label, properties);
        let again = run(seed, cfg, core, Some(&min), properties, true);
        panic!(
            "{name} seed {seed}: {}: {}\nshortest schedule ({} of {} events) {min:?} fails with {:?}\nlog:\n{}",
            f.label,
            f.what,
            min.len(),
            r.acts.len(),
            again.failure,
            again.log.join("\n")
        );
    }
}

/// Seeds per transport model, faulty and clean.
const SEEDS: u64 = 64;

/// Each transport model's seed set of faulty runs.
fn faulty(model: Model) {
    runs(&format!("faulty {model:?}"), 0..SEEDS, &Cfg::faulty(model));
}

#[test]
fn seeded_faulty_runs_on_the_connectionless_transport_keep_the_properties_and_heal() {
    faulty(Model::Datagram);
}

#[test]
fn seeded_faulty_runs_on_the_connection_oriented_transport_keep_the_properties_and_heal() {
    faulty(Model::Stream);
}

#[test]
fn seeded_faulty_runs_on_ble_keep_the_properties_and_heal() {
    faulty(Model::Ble);
}

#[test]
fn seeded_faulty_runs_on_two_transports_keep_the_properties_and_heal() {
    faulty(Model::Mixed);
}

/// Runs outside the seed sets that each reached a difference between the
/// rekey machine's decisions and the model's that the comparison resyncs
/// by name, before that resync existed.
const REACHED: [(Model, u64, &str); 4] = [
    (Model::Stream, 8, "the larger node yields its own rekey"),
    (Model::Stream, 34, "an own rekey ends with its peering"),
    (Model::Stream, 53, "a far-end close not yet seen here"),
    (Model::Stream, 80, "a frame under the drained session"),
];

#[test]
fn seeded_runs_that_reached_a_resynced_difference_keep_the_properties_and_heal() {
    for (model, seed, what) in REACHED {
        runs(what, seed..seed + 1, &Cfg::faulty(model));
    }
}

#[test]
fn seeded_clean_runs_on_every_transport_model_keep_the_properties_and_heal() {
    for model in [Model::Datagram, Model::Stream, Model::Ble, Model::Mixed] {
        runs(&format!("clean {model:?}"), 0..SEEDS, &Cfg::clean(model));
    }
}

#[test]
fn a_seeded_run_replays_byte_identically_from_its_seed_and_from_its_schedule() {
    for model in [Model::Stream, Model::Mixed] {
        for seed in 0..4 {
            let cfg = Cfg::faulty(model);
            let a = run(seed, &cfg, core, None, properties, true);
            let b = run(seed, &cfg, core, None, properties, true);
            assert!(a.acts.len() > 50, "{model:?} seed {seed}: a long run");
            assert_eq!(a.acts, b.acts, "{model:?} seed {seed}: the same events");
            assert_eq!(a.log, b.log, "{model:?} seed {seed}: the same log");
            assert_eq!(a.digest, b.digest, "{model:?} seed {seed}: the same world");
            let c = run(seed, &cfg, core, Some(&a.acts), properties, true);
            assert_eq!(a.log, c.log, "{model:?} seed {seed}: the schedule's log");
            assert_eq!(
                a.digest, c.digest,
                "{model:?} seed {seed}: the schedule's world"
            );
        }
    }
}

/// The planted failure: node 0 is in a later life than its first and the
/// two nodes hold each other.
fn planted(w: &World, init: &Init) -> Vec<Failure> {
    let back = w.parties[0].epoch() != init.epochs[0]
        && w.parties[0].held().contains(&w.ids[1])
        && w.parties[1].held().contains(&w.ids[0]);
    if back {
        alloc::vec![Failure {
            label: String::from("planted"),
            what: String::from("node 0 restarted and the pair is up again"),
        }]
    } else {
        Vec::new()
    }
}

/// The longest schedule the planted failure may shrink to: a restart of
/// node 0 and a handshake after it (a reconnect wake, the msg1, the msg2
/// and a connect window or two).
const PLANTED: usize = 6;

#[test]
fn a_planted_failing_run_shrinks_to_its_cause() {
    let mut cfg = Cfg::faulty(Model::Datagram);
    cfg.restart = 20;
    cfg.restarts = 1;
    let (seed, r) = (0..64)
        .map(|seed| (seed, run(seed, &cfg, core, None, planted, false)))
        .find(|(_, r)| {
            r.failure.is_some()
                && r.acts
                    .iter()
                    .position(|a| *a == Act::Restart(0))
                    .is_some_and(|i| i > 20)
        })
        .expect("a seed restarts node 0 after twenty events and fails");
    let min = shrink(seed, &cfg, core, &r.acts, "planted", planted);
    let again = run(seed, &cfg, core, Some(&min), planted, false);
    assert!(
        again.failure.is_some(),
        "seed {seed}: the shrunk schedule still fails"
    );
    assert!(
        min.contains(&Act::Restart(0)),
        "seed {seed}: the shrunk schedule keeps its cause: {min:?}"
    );
    assert!(
        min.len() <= PLANTED,
        "seed {seed}: {} events of {} left, over {PLANTED}: {min:?}",
        min.len(),
        r.acts.len()
    );
}

#[test]
fn a_seeded_run_holds_a_pending_of_a_rekey_its_initiator_gave_up_and_only_that_is_spared() {
    // Seed 29 of the two-transport set: long after a restart left a node
    // installed from its peer's rekey, the two ends hold one session, and
    // the other node's own rekey, its msg2s lost, is given up while the
    // pending its last msg1 armed is held. Before the shape exemption was
    // narrowed, the shape spared it.
    use super::world::Shape;
    let cfg = Cfg::faulty(Model::Mixed);
    let r = run(29, &cfg, core, None, properties, false);
    let mut w = world(29, &cfg, core);
    for &a in &r.acts {
        if valid(&w, a) {
            apply(&mut w, a);
        }
    }
    heal(&mut w);
    assert!(
        w.kinds().contains(&Shape::RekeyInstall),
        "precondition: the path showed the shape"
    );
    let found = healed(&w);
    assert!(
        found
            .iter()
            .any(|b| b.what.starts_with("pending:") && !by_shape(&w, b) && abandoned(&w, b)),
        "the pending of the given-up rekey is found, and spared by its own cause: {found:?}"
    );
    assert!(
        found.iter().all(|b| by_shape(&w, b) || abandoned(&w, b)),
        "nothing else is: {found:?}"
    );
    assert!(r.failure.is_none(), "so the run passes: {:?}", r.failure);
}
