//! The joint world explored: each start's reach at each pairing, the
//! checks that the explorer's key of a joint node is sound, and the sweeps
//! of every start's interleavings against the settlement properties.
//!
//! The explorer is the settlement world's (`../explore.rs`), run on starts whose
//! nodes are joint nodes (`starts.rs`), at each pairing of the two
//! multipath settings. A run names its pairing, the mode at each end, in
//! every line it prints.
//!
//! A sweep runs every start but the two late-dial cases left for later
//! (their defects are pinned in `../regress.rs` and shown on real machines
//! in `party.rs`), checks every explored state and every healed leaf, and
//! exempts only a split on a path that showed a known shape and the breach
//! `pins.rs` holds of a proven path left with no connection ([`lapsed`]).
//! Each exempted breach is counted by its cause in the line a sweep
//! prints. A heal runs every wake for a minute, and a capable link's
//! bundles wake every fraction of a second while they probe, so the sweeps
//! of the starts whose links turn capable at On with On take tens of
//! minutes each: those run one test per start, and the two mixed pairings'
//! sweeps one test each, only in the slow explorers' build.
//!
//! The explorer rebuilds each state by replaying its path, and merges two
//! states whose keys are equal. So a joint node's key must be a function
//! of its path alone, whatever else the process ran (one node's path
//! identifiers never move another's, in this world or in another), and
//! must hold every field of a machine that a successor reads, not only
//! what the machine shows.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::proto::path::{Input as PathInput, Source};
use crate::proto::rekey::Close;

use super::super::super::model::history::{Hs, Node};
use super::super::explore::{Act, apply, explore, explore_within, none, reached, replay};
use super::super::oracle::{Breach, Oracle, by_shape};
use super::super::party::Configured;
use super::super::starts::{A, B, Start, TCP, UDP, dial_home, home, model, settle, world_of};
use super::super::world::{Party, Pkt, World};
use super::Mode;
use super::facts::pair;
use super::machines::{Kit, Machines, exchange, kits, unused};

/// The name of the pairing of joint nodes at `a` and at `b`, as a run
/// prints it after a start's name.
pub fn pairing(a: Mode, b: Mode) -> String {
    format!(" ({} with {})", a.name(), b.name())
}

#[test]
fn every_named_start_reaches_its_target_depth_with_the_machines_off() {
    let starts = super::starts::off();
    let wrong = reached(&starts, &pairing(Mode::Off, Mode::Off));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn every_named_start_reaches_its_target_depth_with_the_machines_on() {
    let starts = super::starts::on();
    let wrong = reached(&starts, &pairing(Mode::On, Mode::On));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn every_named_start_reaches_its_target_depth_with_the_machines_on_against_off() {
    let starts = super::starts::on_off();
    let wrong = reached(&starts, &pairing(Mode::On, Mode::Off));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn every_named_start_reaches_its_target_depth_with_the_machines_off_against_on() {
    let starts = super::starts::off_on();
    let wrong = reached(&starts, &pairing(Mode::Off, Mode::On));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_cold_start_reaches_its_stated_depth_off_with_off() {
    let wrong = reached(&[super::starts::cold_off()], &pairing(Mode::Off, Mode::Off));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn the_cold_start_reaches_its_stated_depth_on_with_on() {
    let wrong = reached(&[super::starts::cold_on()], &pairing(Mode::On, Mode::On));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The deepest a cold start is measured to: past any depth its budget
/// reaches.
const COLD_MOST: usize = 40;

/// How long a measurement of the cold start may explore, from the
/// variable `FIPS_SETTLE_COLD_LIMIT` in seconds: by default 120 s, the
/// reach budget in a debug build on 12 cores.
fn cold_limit() -> std::time::Duration {
    let secs = std::env::var("FIPS_SETTLE_COLD_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);
    std::time::Duration::from_secs(secs)
}

#[test]
#[ignore = "a measurement run by hand: how deep the cold start is explored within the reach budget"]
fn the_cold_start_is_explored_as_deep_as_the_reach_budget_allows_at_off_and_at_on() {
    let limit = cold_limit();
    let runs = [
        (super::starts::cold_off(), pairing(Mode::Off, Mode::Off)),
        (super::starts::cold_on(), pairing(Mode::On, Mode::On)),
    ];
    let report: Vec<_> = std::thread::scope(|sc| {
        let hs: Vec<_> = runs
            .iter()
            .map(|(st, _)| sc.spawn(move || explore_within(st, COLD_MOST, limit, &none)))
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    });
    for ((st, label), stats) in runs.iter().zip(&report) {
        std::eprintln!(
            "cold {}{label}: within {} s depth {} states {} frontier {:?} ms {:?} cut {:?}",
            st.name,
            limit.as_secs(),
            stats.depth,
            stats.states,
            stats.frontier,
            stats.ms,
            stats.cut
        );
    }
}

#[test]
fn two_worlds_on_one_path_have_one_digest() {
    let starts = super::starts::off();
    for st in starts.iter().filter(|s| matches!(s.number, 1 | 3 | 8)) {
        let stats = explore(st, 3, &none);
        for path in &stats.leaves {
            // Two worlds stepped in turn, so a draw one makes would move
            // the other's if the two shared a stream.
            let (mut a, mut b) = (replay(st, &[]), replay(st, &[]));
            for &act in path {
                apply(&mut a, act);
                apply(&mut b, act);
            }
            assert_eq!(
                a.digest(),
                b.digest(),
                "{}: {path:?} reached two worlds",
                st.name
            );
            assert_eq!(
                replay(st, path).digest(),
                a.digest(),
                "{}: {path:?} rebuilt alone reached another world",
                st.name
            );
        }
    }
}

/// Handshake names for the machines' own setups and rekeys.
const H0: Hs = Hs(0x0101_0001);

/// One of node 0's machines for node 1 at `mode`, set up on UDP at
/// instant 0, with its kit.
fn machine(mode: Mode) -> (Machines, Kit) {
    let (mut ka, mut kb) = kits();
    let ((sa, ra), (sb, _), _) = exchange(&mut ka, &mut kb, B, H0);
    unused(&mut kb, sb);
    let (m, _) = Machines::fresh(&mut ka, 0, B, mode, sa, ra, home(1, UDP), home(0, UDP));
    (m, ka)
}

/// The key `m` writes at `now`.
fn keyed(m: &Machines, now: u64) -> String {
    let mut out = String::new();
    m.key(now, &mut out);
    out
}

/// Every field of `m`'s rekey machine that can change.
fn rekeyed(m: &Machines) -> String {
    let mut out = String::new();
    let _ = m.rekey().state(&mut out);
    out
}

/// Two joint nodes at Off, node 0 dialing node 1 on UDP, settled.
fn paired() -> World {
    let mut w = world_of(super::off, &[A, B], &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    w
}

/// Node 0 sends node 1 a frame now, which is lost; its bytes.
fn lost(w: &mut World) -> Vec<u8> {
    apply(w, Act::Frame(0));
    let i = w
        .net
        .flight
        .iter()
        .position(|f| f.to == 1 && matches!(f.pkt, Pkt::Frame { .. }))
        .expect("node 0 sends node 1 a frame");
    match w.net.flight.remove(i).pkt {
        Pkt::Frame { wire, .. } => w.net.wires[wire as usize].clone(),
        other @ (Pkt::Msg1 { .. } | Pkt::Msg2 { .. } | Pkt::Eof) => panic!("a frame: {other:?}"),
    }
}

#[test]
fn a_state_differing_only_inside_a_machine_has_its_own_key() {
    let t = 1_000;
    // The rekey machine: one more frame sealed, so its session's counter
    // differs, which neither `view` nor `bindings` shows.
    let (mut a, mut ka) = machine(Mode::Off);
    let (mut b, mut kb) = machine(Mode::Off);
    let _ = b.seal(t, &[0x51, 0, 0, 0, 0]).expect("the session seals");
    assert_eq!(
        (
            format!("{:?}", a.rekey().view()),
            a.rekey().bindings(),
            format!("{:?}", a.bundle()),
        ),
        (
            format!("{:?}", b.rekey().view()),
            b.rekey().bindings(),
            format!("{:?}", b.bundle()),
        ),
        "precondition: the two rekey machines show the same and the bundles are equal"
    );
    assert_ne!(
        keyed(&a, t),
        keyed(&b, t),
        "a rekey machine that sealed one more frame has its own key"
    );
    assert_ne!(
        a.seal(t, &[0x51, 0, 0, 0, 0]),
        b.seal(t, &[0x51, 0, 0, 0, 0]),
        "and its next frame is other bytes"
    );
    a.close(&mut ka, t, Close::Admin);
    b.close(&mut kb, t, Close::Admin);

    // The bundle: a candidate held, which no path shows.
    let (mut a, mut ka) = machine(Mode::On);
    let (mut b, mut kb) = machine(Mode::On);
    let tb = pair(home(1, TCP));
    let candidate = PathInput::Candidate {
        transport: tb.transport,
        addr: tb.addr.clone(),
        source: Source::Config,
    };
    // Offered from no address of this node's, so the machines keep no
    // note of where it came from: the two differ inside the bundle alone.
    let _ = b.path(&mut kb, t, candidate, None);
    assert_eq!(
        (
            rekeyed(&a),
            a.active(),
            a.local(home(1, UDP)),
            a.local(home(1, TCP))
        ),
        (
            rekeyed(&b),
            b.active(),
            b.local(home(1, UDP)),
            b.local(home(1, TCP))
        ),
        "precondition: the two rekey machines are equal, and so are their paths and this node's addresses"
    );
    assert_ne!(
        keyed(&a, t),
        keyed(&b, t),
        "a bundle holding a candidate has its own key"
    );
    // The candidate's probes go unanswered: the bundle that holds it
    // keeps waking for them, and the other has nothing to do.
    let (mut pa, mut pb) = (Vec::new(), Vec::new());
    let mut wake = t;
    for _ in 0..20 {
        let Some(w) = b.wake() else { break };
        wake = w;
        pa.push(format!("{:?}", a.path(&mut ka, w, PathInput::Poll, None)));
        pb.push(format!("{:?}", b.path(&mut kb, w, PathInput::Poll, None)));
    }
    assert_ne!(pa, pb, "and the same polls do other things in each");
    a.close(&mut ka, wake, Close::Admin);
    b.close(&mut kb, wake, Close::Admin);

    // Through the world: two worlds that differ only in a frame node 0
    // sealed and lost have their own keys.
    let (mut x, mut y) = (paired(), paired());
    let _ = lost(&mut x);
    let _ = lost(&mut y);
    let _ = lost(&mut y);
    assert_eq!(
        format!("{:?}", x.parties[0].view()),
        format!("{:?}", y.parties[0].view()),
        "precondition: node 0 shows the same in both worlds"
    );
    assert_ne!(x.key(), y.key(), "the two worlds have their own keys");
    assert_ne!(
        lost(&mut x),
        lost(&mut y),
        "and node 0's next frame differs"
    );
}

/// Why a sweep of the joint party exempts a breach at a healed leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Spared {
    /// A split on a path that showed a known shape other than the two
    /// defects left for later (`by_shape`).
    Shape,
    /// [`lapsed`].
    Lapsed,
    /// [`untimed`].
    Untimed,
}

impl Spared {
    /// Every cause, in the order a sweep's line counts them.
    const ALL: [Self; 3] = [Self::Shape, Self::Lapsed, Self::Untimed];
}

/// The exemption of the joint party's sweeps, and its cause: the first of
/// `by_shape`, [`lapsed`] and [`untimed`] that names `b`.
fn spared(w: &World, b: &Breach) -> Option<Spared> {
    if by_shape(w, b) {
        Some(Spared::Shape)
    } else if lapsed(w, b) {
        Some(Spared::Lapsed)
    } else if untimed(w, b) {
        Some(Spared::Untimed)
    } else {
        None
    }
}

/// What a node of the model, which runs no link-dead timer, leaves once
/// healed beside a joint node, which runs the node's: the model still
/// holds the joint node on a link whose frames were lost in flight, the
/// joint node's timer removed it, and the model refuses each redial, so
/// the joint node holds a configured peer it cannot reach and the model
/// keeps open the connection a refused redial came on. A node would have
/// removed the silent peer too and taken the redial. Only a pairing of a
/// joint node with the model reaches it: two joint nodes both run the
/// timer.
pub fn untimed(w: &World, b: &Breach) -> bool {
    let stale = |x: usize, y: usize| {
        x != y
            && w.parties[x].joint().is_none()
            && w.parties[y].joint().is_some()
            && w.parties[x].held().contains(&w.ids[y])
            && !w.parties[y].held().contains(&w.ids[x])
    };
    let n = w.parties.len();
    if b.oracle == Oracle::OneSession && b.what.ends_with("is configured and not held") {
        (0..n).any(|x| stale(x, b.node))
    } else if b.oracle == Oracle::ConnectionsInUse && b.what.ends_with("open, no link uses it") {
        (0..n).any(|y| stale(b.node, y))
    } else {
        false
    }
}

/// A pair a node's link counts in use while its connection is closed,
/// where the node's bundle holds the pair as an acknowledged path that is
/// not Live. The bundle asks for a connection only for a path it admitted
/// from a candidate or whose connect failed, never after a failed send,
/// so a proven path whose connection failed is not connected again and
/// stays acknowledged, and counted, until its Dead grace ends. A finding
/// about the bundle, pinned in `pins.rs`.
pub fn lapsed(w: &World, b: &Breach) -> bool {
    b.oracle == Oracle::ConnectionsInUse
        && w.parties[b.node]
            .lapsed()
            .iter()
            .any(|at| b.what == format!("{at:?} in use, its connection closed"))
}

#[test]
fn each_breach_the_pins_hold_is_exempted_by_its_own_cause_and_a_settled_pair_by_none() {
    use super::super::oracle::{every_step, heal, healed};
    use Act::{Connect, Deliver, Fail, Leap};
    let on = super::starts::on();
    let start = |n: u8| on.iter().find(|s| s.number == n).expect("the start");
    let cases: [(u8, &[Act], Spared); 1] = [(
        2,
        &[
            Deliver(0),
            Deliver(1),
            Deliver(2),
            Deliver(5),
            Connect(0, true),
            Leap,
            Fail(0, 0),
        ],
        Spared::Lapsed,
    )];
    for (n, path, cause) in cases {
        let mut w = replay(start(n), path);
        heal(&mut w);
        let found: Vec<Breach> = every_step(&w).into_iter().chain(healed(&w)).collect();
        assert!(
            !found.is_empty(),
            "start {n}, {path:?}: the pinned breaches are found"
        );
        for b in &found {
            let got = spared(&w, b);
            assert_eq!(
                got,
                Some(cause),
                "start {n}, {path:?}: {b:?} is exempted by its own cause"
            );
        }
    }
    // Start 2 with the model at node 0 and a joint node at node 1: the
    // model's dial completes, the frames are lost for the link-dead
    // timeout, the joint node's timer removes the model, and the model,
    // which runs no timer, refuses every redial.
    let st = chosen(super::starts::uncapped(model_off), |s| s.number == 2).remove(0);
    let path = [
        Act::Dup(0),
        Connect(0, false),
        Deliver(0),
        Deliver(2),
        Act::Advance,
        Act::Advance,
        Act::Advance,
    ];
    let mut w = replay(&st, &path);
    heal(&mut w);
    let found = healed(&w);
    assert!(
        found.len() == 2,
        "precondition: the model's stale peering leaves two breaches: {found:?}"
    );
    for b in &found {
        assert_eq!(
            spared(&w, b),
            Some(Spared::Untimed),
            "{b:?} is exempted as the model's missing timer"
        );
    }
    // Start 2's script settles both ends, capable, and then holds for a
    // heal: the cause names nothing there.
    let st = start(2);
    let mut scratch = replay(st, &[]);
    let script = (st.script)(&mut scratch);
    let mut w = replay(st, &script);
    heal(&mut w);
    for x in 0..w.parties.len() {
        assert!(
            w.parties[x].lapsed().is_empty(),
            "node {x} holds no lapsed path once settled"
        );
    }
}

/// Sweep each of `runs` at the pairing `label` names, one thread per
/// start, and return every breach found, each with its path: every state
/// checked at every step and every leaf healed and checked, with
/// [`spared`] as the exemption, whose breaches each start's line counts
/// by cause.
pub(super) fn swept(runs: &[Start], label: &str) -> Vec<String> {
    use super::super::oracle::sweep;
    let report = std::thread::scope(|sc| {
        let hs: Vec<_> = runs
            .iter()
            .map(|st| {
                sc.spawn(move || {
                    let counts = Spared::ALL.map(|_| AtomicUsize::new(0));
                    let exempt = |w: &World, b: &Breach| match spared(w, b) {
                        Some(s) => {
                            if let Some(i) = Spared::ALL.iter().position(|c| *c == s) {
                                counts[i].fetch_add(1, Ordering::Relaxed);
                            }
                            true
                        }
                        None => false,
                    };
                    let t = std::time::Instant::now();
                    let swept = sweep(st, st.depth, &exempt);
                    let ms = t.elapsed().as_millis();
                    let by: Vec<(Spared, usize)> = Spared::ALL
                        .iter()
                        .zip(&counts)
                        .map(|(s, n)| (*s, n.load(Ordering::Relaxed)))
                        .filter(|(_, n)| *n > 0)
                        .collect();
                    (swept, ms, by)
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect::<Vec<_>>()
    });
    let mut wrong = Vec::new();
    for (st, (swept, ms, by)) in runs.iter().zip(report) {
        std::eprintln!(
            "joint {:>2} {}{label}: {} states, {} leaves healed in {ms} ms, exempted {:?}, breaches by cause {by:?}, states showing a pinned clause {:?}",
            st.number,
            st.name,
            swept.stats.states,
            swept.stats.leaves.len(),
            swept.exempted,
            swept.pinned
        );
        for (b, path) in swept.found {
            wrong.push(format!(
                "{}{label}: {:?} at n{}: {}\n  path {path:?}",
                st.name, b.oracle, b.node, b.what
            ));
        }
    }
    wrong
}

/// The starts of `starts` that `keep` takes, the two late-dial cases left
/// for later aside (their defects are pinned in `../regress.rs` and shown
/// on real machines in `party.rs`).
pub(super) fn chosen(starts: Vec<Start>, keep: impl Fn(&Start) -> bool) -> Vec<Start> {
    starts
        .into_iter()
        .filter(|s| !matches!(s.number, 6 | 7) && keep(s))
        .collect()
}

/// The starts whose links turn capable at On with On, so that each healed
/// leaf steps both bundles' probes for a minute: their sweeps at that
/// pairing take tens of minutes each and run in the slow explorers' lane,
/// one test per start.
pub const CAPABLE: &[&str] = &[
    "crossing, two transports",
    "crossing, connection-oriented",
    "crossing during a rekey",
];

/// The starts on real bundles whose links turn capable at On with On, so
/// that each healed leaf steps a minute of probes and each sweep there
/// takes minutes: they run in the slow explorers' lane, together in one
/// test, each on a thread of its own.
pub const DOUBLED: &[&str] = &[
    "crossing while capability probes are out",
    "restart on a two-path link",
    "late second dial at a capable peer",
    "carrier loss of the active path",
    "the only path's transport removed",
    "a NAT rebound of the second path",
    "a path removed at the peer",
];

/// The start named `name` at On with On, alone.
#[cfg(feature = "slow-explorers")]
fn on_alone(name: &str) -> Vec<Start> {
    chosen(super::starts::on(), |s| s.name == name)
}

#[test]
fn every_explored_interleaving_of_the_joint_party_keeps_the_properties_off() {
    let wrong = swept(
        &chosen(super::starts::off(), |_| true),
        &pairing(Mode::Off, Mode::Off),
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn every_explored_interleaving_of_the_joint_party_keeps_the_properties_on() {
    let runs = chosen(super::starts::on(), |s| {
        !CAPABLE.contains(&s.name) && !DOUBLED.contains(&s.name)
    });
    let wrong = swept(&runs, &pairing(Mode::On, Mode::On));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_sweep_of_start_2_keeps_the_properties_on_with_on() {
    let wrong = swept(&on_alone(CAPABLE[0]), &pairing(Mode::On, Mode::On));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_sweep_of_start_3_keeps_the_properties_on_with_on() {
    let wrong = swept(&on_alone(CAPABLE[1]), &pairing(Mode::On, Mode::On));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_sweep_of_start_9_keeps_the_properties_on_with_on() {
    let wrong = swept(&on_alone(CAPABLE[2]), &pairing(Mode::On, Mode::On));
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_sweeps_of_the_two_path_starts_keep_the_properties_on_with_on() {
    let wrong = swept(
        &chosen(super::starts::on(), |s| DOUBLED.contains(&s.name)),
        &pairing(Mode::On, Mode::On),
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[cfg(feature = "slow-explorers")]
#[test]
fn every_explored_interleaving_of_the_joint_party_keeps_the_properties_on_against_off() {
    let wrong = swept(
        &chosen(super::starts::on_off(), |_| true),
        &pairing(Mode::On, Mode::Off),
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[cfg(feature = "slow-explorers")]
#[test]
fn every_explored_interleaving_of_the_joint_party_keeps_the_properties_off_against_on() {
    let wrong = swept(
        &chosen(super::starts::off_on(), |_| true),
        &pairing(Mode::Off, Mode::On),
    );
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A joint node at multipath off at node 0, and the model elsewhere.
#[cfg(feature = "slow-explorers")]
fn off_model(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    if ix == 0 {
        super::off(ix, me, configured)
    } else {
        model(ix, me, configured)
    }
}

/// The model at node 0, and a joint node at multipath off elsewhere.
fn model_off(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    if ix == 0 {
        model(ix, me, configured)
    } else {
        super::off(ix, me, configured)
    }
}

#[cfg(feature = "slow-explorers")]
#[test]
fn every_explored_interleaving_of_the_core_keeps_the_properties_and_heals() {
    // The core's own explorer, on joint nodes at multipath off: every
    // named start but the two late-dial cases left
    // for later, the one with two paths on real bundles, with the core at
    // both ends and at either end against the model. Minutes on twelve
    // cores, and past nextest's limit on two, so it runs in the slow
    // explorers' build.
    let makers: [(super::super::starts::Maker, &str); 3] = [
        (super::off, " (core and core)"),
        (off_model, " (core and model)"),
        (model_off, " (model and core)"),
    ];
    let mut wrong = Vec::new();
    for (mk, label) in makers {
        let runs = chosen(super::starts::uncapped(mk), |s| s.number <= 14);
        wrong.extend(swept(&runs, label));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
