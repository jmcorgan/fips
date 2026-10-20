//! Bounded exhaustive exploration of a new node against each deployed
//! release, and of two new nodes on the production profiles.
//!
//! Each scenario runs a [`Duo`] normally until the first handshake message
//! of a rekey or first handshake is sent, and from that instant holds every
//! packet: from the start, every sequence of up to `depth` events is
//! enumerated breadth first, an event being the delivery of any packet in
//! flight (in any order, so late and reordered delivery are covered), a
//! second copy of a handshake message, a data frame sealed at either end,
//! or an advance to the next tick or wake of either end. A packet never
//! delivered is lost: the heal discards whatever is still in flight.
//!
//! The ends hold real Noise state and linear leases and cannot be cloned or
//! hashed, so each state is rebuilt by replaying its path from the start
//! (the world is deterministic, seeded per run), and paths are not
//! de-duplicated: the search is exhaustive over paths, which costs more
//! states than the stub explorer's but misses none. After every event each
//! end's own resource check holds (a new link node's index map against its
//! machine and pool) and nothing panics; every path at the frontier is then
//! healed (faults off, data both ways every second) and must converge on
//! one current epoch, or end in the outcome the deployed release forces
//! and the design accepts, with no index lease leaked. Across the whole
//! path and heal, no data frame a new node sealed in a rekey is refused
//! once delivered: a new node seals only under an epoch its peer holds,
//! whatever the deployed peer does, unless that peer's own defect splits
//! the link.
//!
//! The depth is 3 by default (about 16 s on a 12-core host in a debug
//! build); `FIPS_LEGACY_DEPTH` asks for more.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{Class, Duo, Rel, fmp, fsp};

/// One event the explorer chooses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Act {
    /// Deliver the packet now.
    Deliver(u64),
    /// Put a second copy of a handshake message in flight.
    Dup(u64),
    /// Advance to the next tick or wake of either end.
    Advance,
    /// End `x` seals a data frame.
    Data(usize),
}

/// What a healed path may end in besides convergence with nothing in
/// flight, as the deployed release forces it.
#[derive(Clone, Copy, Debug)]
struct Allow {
    /// The link removed at one end: a 0.5.0 or 0.5.1 link responder's
    /// self-cutover on a lost msg2 splits the link until link-dead.
    split: bool,
    /// Rotation stopped with data flowing: a 0.5.0 or 0.5.1 session node's
    /// own rekey never retires.
    stall: bool,
}

/// One exploration.
struct Scenario {
    name: String,
    start: Box<dyn Fn() -> Duo + Send + Sync>,
    depth: usize,
    allow: Allow,
    /// The ends whose every delivered data frame must be accepted: the
    /// new nodes of a rekey. A first handshake has none, since a frame
    /// sealed under the first epoch before the peer has read its msg3 is
    /// lost by design: there is no other epoch to seal under.
    new: [bool; 2],
}

/// Whether a class is a handshake message.
fn handshake(c: Class) -> bool {
    matches!(
        c,
        Class::Msg1 | Class::Msg2 | Class::Setup | Class::Ack | Class::Msg3
    )
}

/// Whether a class opens a rekey or a first handshake.
fn opener(c: Class) -> bool {
    matches!(c, Class::Msg1 | Class::Setup)
}

/// Run `duo` to the first handshake message after `from`, then hold. Data
/// flows every 5 s until then, which keeps every liveness rule satisfied
/// at a fifth of the cost each replay pays; the explorer's own data events
/// place frames around the handshake.
fn prime(mut duo: Duo, from: u64) -> Duo {
    duo.period = [Some(5_000), Some(5_000)];
    duo.run_until(from);
    let sent = duo.run_to(from + 200_000, Some(opener));
    assert!(sent, "the scenario reaches a handshake");
    duo.hold();
    duo
}

/// Rebuild the state a path leads to, checking every end after each event.
fn replay(sc: &Scenario, path: &[Act]) -> Result<Duo, String> {
    let mut duo = (sc.start)();
    for &a in path {
        match a {
            Act::Deliver(id) => duo.deliver_now(id),
            Act::Dup(id) => duo.copy(id),
            Act::Advance => duo.advance(),
            Act::Data(x) => duo.send_data(x),
        }
        for x in 0..2 {
            duo.n[x].check()?;
        }
    }
    Ok(duo)
}

/// Replay `path` once under a panic guard, so a failure names its path:
/// at a frontier path heal it and check that no lease leaked; otherwise
/// return the events available after it.
fn visit(sc: &Scenario, path: &[Act], frontier: bool) -> Vec<Act> {
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let before = crate::proto::rekey::leaked();
        let duo = replay(sc, path)?;
        if !frontier {
            return Ok(options(&duo, path));
        }
        heals(duo, sc.allow, sc.new)?;
        match crate::proto::rekey::leaked() - before {
            0 => Ok(Vec::new()),
            n => Err(format!("{n} index leases leaked")),
        }
    }));
    match run {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => panic!("{} after {path:?}: {e}", sc.name),
        Err(p) => {
            let what = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| String::from(*s)))
                .unwrap_or_default();
            panic!("{} after {path:?}: panicked: {what}", sc.name)
        }
    }
}

/// The events available in `duo` to a path that has already taken `path`.
fn options(duo: &Duo, path: &[Act]) -> Vec<Act> {
    let dups = path.iter().any(|a| matches!(a, Act::Dup(_)));
    let data = path.iter().any(|a| matches!(a, Act::Data(_)));
    let mut out = Vec::new();
    for (id, _, class) in duo.in_flight() {
        out.push(Act::Deliver(id));
        if !dups && handshake(class) {
            out.push(Act::Dup(id));
        }
    }
    out.push(Act::Advance);
    if !data {
        out.push(Act::Data(0));
        out.push(Act::Data(1));
    }
    out
}

/// Heal a frontier state and check how it ends. The heal stops early once
/// both ends are quiet and accept each other's data under their current
/// epoch, a state nothing changes before the next trigger.
fn heals(mut duo: Duo, allow: Allow, new: [bool; 2]) -> Result<(), String> {
    duo.release();
    let end = duo.now + 300_000;
    while duo.now < end {
        let next = duo.now + 5_000;
        duo.run_until(next);
        let alive = duo.n[0].alive() && duo.n[1].alive();
        if alive && duo.n[0].quiet() && duo.n[1].quiet() && duo.converged(true).is_ok() {
            break;
        }
    }
    for (x, strict) in new.into_iter().enumerate() {
        if strict && !allow.split && !duo.lost[x].is_empty() {
            return Err(format!(
                "{}'s data sent at {:?} was refused\n{}",
                duo.n[x].name(),
                duo.lost[x],
                duo.transcript()
            ));
        }
    }
    let removed = !duo.n[0].alive() || !duo.n[1].alive();
    if !(allow.split && removed) {
        duo.converged(!allow.stall)
            .map_err(|e| format!("not converged after healing: {e}\n{}", duo.transcript()))?;
    }
    for x in 0..2 {
        duo.n[x].finish()?;
    }
    Ok(())
}

/// What one exploration covered.
#[derive(Debug, Default)]
struct Stats {
    paths: usize,
    depth: usize,
    healed: usize,
}

/// Explore `sc` breadth first, replaying each path once, and panic with
/// the shortest failing path; every path at the full depth is healed.
fn explore(sc: &Scenario) -> Stats {
    let mut frontier: Vec<(Vec<Act>, Vec<Act>)> =
        alloc::vec![(Vec::new(), visit(sc, &[], sc.depth == 0))];
    let mut stats = Stats::default();
    for depth in 0..sc.depth {
        let last = depth + 1 == sc.depth;
        let mut next = Vec::new();
        for (path, opts) in &frontier {
            for &a in opts {
                let mut p = path.clone();
                p.push(a);
                let more = visit(sc, &p, last);
                stats.healed += usize::from(last);
                next.push((p, more));
            }
        }
        stats.paths += next.len();
        stats.depth = depth + 1;
        frontier = next;
    }
    stats
}

/// The new node's jitter draw for a trigger at 105 s.
const EARLY: u16 = 0;
/// The new node's jitter draw for a trigger at 135 s.
const LATE: u16 = 30;
/// The new node's jitter draw for a trigger at 120 s.
const MID: u16 = 15;

/// The link scenarios: against each release, a rekey the new node starts
/// (it the smaller), one the deployed node starts (the new node the larger)
/// and both starting in the same second; and two new nodes, one starting
/// and both.
fn links(depth: usize) -> Vec<Scenario> {
    let mut out = Vec::new();
    for rel in Rel::ALL {
        let allow = Allow {
            split: rel == Rel::V050,
            stall: false,
        };
        for (what, new_first, new_jitter, old_jitter, new_smaller) in [
            ("new node starts", true, EARLY, 15, true),
            ("deployed node starts", true, LATE, -15, false),
            ("both start", false, EARLY, -15, true),
        ] {
            let s = fmp::Setup {
                rel,
                new_first,
                new_jitter,
                old_jitter,
                new_smaller,
                new_k: false,
            };
            let x = usize::from(!new_first);
            out.push(Scenario {
                name: format!("link, {what}, against {rel:?}"),
                start: Box::new(move || prime(fmp::link(&s, 11).0, 100_000)),
                depth,
                allow,
                new: [x == 0, x == 1],
            });
        }
    }
    let allow = Allow {
        split: false,
        stall: false,
    };
    for (what, jitter) in [("one starts", [EARLY, LATE]), ("both start", [MID, MID])] {
        out.push(Scenario {
            name: format!("link between new nodes, {what}"),
            start: Box::new(move || prime(fmp::new_link(13, jitter), 100_000)),
            depth,
            allow,
            new: [true, true],
        });
    }
    out
}

/// The session scenarios: against each release, a rekey the new node
/// starts (it the smaller), one the deployed node starts (the new node the
/// larger), both starting in the same tick, and a first handshake opened
/// by both ends; and the same between two new nodes. Each rekey scenario
/// runs again with the node this release ships (the machine polled on the
/// shell's tick only) in place of the new node, and between two of them.
fn sessions(depth: usize) -> Vec<Scenario> {
    let mut out = Vec::new();
    for rel in Rel::ALL {
        let allow = Allow {
            split: false,
            stall: rel == Rel::V050,
        };
        for (what, new_jitter, old_jitter, new_smaller, crossing, shipped) in [
            ("new node starts", 0, 15, true, false, false),
            ("deployed node starts", 30, -15, false, false, false),
            ("both start", 0, -15, true, true, false),
            ("shipped node starts", 0, 15, true, false, true),
            (
                "deployed node starts with a shipped node",
                30,
                -15,
                false,
                false,
                true,
            ),
            ("both start, one shipped", 0, -15, true, true, true),
        ] {
            let s = fsp::Setup {
                rel,
                new_smaller,
                new_jitter,
                old_jitter,
                established: true,
                old_messages: None,
                shipped,
            };
            out.push(Scenario {
                name: format!("session, {what}, against {rel:?}"),
                start: Box::new(move || {
                    let mut duo = fsp::session(&s, 17);
                    if crossing {
                        duo.phase = [0, 0];
                    }
                    prime(duo, 100_000)
                }),
                depth,
                allow,
                new: [true, false],
            });
        }
        for (new_smaller, shipped) in [(true, false), (false, false), (true, true), (false, true)] {
            let s = fsp::Setup {
                rel,
                new_smaller,
                new_jitter: 0,
                old_jitter: 15,
                established: false,
                old_messages: None,
                shipped,
            };
            out.push(Scenario {
                name: format!(
                    "first handshake, both open, {} node {}, against {rel:?}",
                    if shipped { "shipped" } else { "new" },
                    if new_smaller { "smaller" } else { "larger" }
                ),
                start: Box::new(move || {
                    let mut duo = fsp::session(&s, 19);
                    duo.run_until(1_000);
                    duo.act(0, |end, now, out| end.open(now, out));
                    duo.act(1, |end, now, out| end.open(now, out));
                    duo.hold();
                    duo
                }),
                depth,
                allow,
                new: [false, false],
            });
        }
    }
    let allow = Allow {
        split: false,
        stall: false,
    };
    for (what, jitter, shipped) in [
        ("one starts", [0, 30], false),
        ("both start", [15, 15], false),
        ("one starts, both shipped", [0, 30], true),
        ("both start, both shipped", [15, 15], true),
    ] {
        out.push(Scenario {
            name: format!("session between new nodes, {what}"),
            start: Box::new(move || prime(fsp::new_session(23, jitter, true, shipped), 100_000)),
            depth,
            allow,
            new: [true, true],
        });
    }
    for shipped in [false, true] {
        out.push(Scenario {
            name: format!(
                "first handshake between {} nodes, both open",
                if shipped { "shipped" } else { "new" }
            ),
            start: Box::new(move || {
                let mut duo = fsp::new_session(29, [0, 30], false, shipped);
                duo.run_until(1_000);
                duo.act(0, |end, now, out| end.open(now, out));
                duo.act(1, |end, now, out| end.open(now, out));
                duo.hold();
                duo
            }),
            depth,
            allow,
            new: [false, false],
        });
    }
    out
}

#[test]
fn every_explored_interleaving_against_each_deployed_release_heals() {
    let depth = std::env::var("FIPS_LEGACY_DEPTH")
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(3);
    let mut all = links(depth);
    all.extend(sessions(depth));
    let report: Vec<(String, Stats, u128)> = std::thread::scope(|s| {
        let handles: Vec<_> = all
            .iter()
            .map(|sc| {
                s.spawn(move || {
                    let t = std::time::Instant::now();
                    let stats = explore(sc);
                    (sc.name.clone(), stats, t.elapsed().as_millis())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    });
    for (name, s, ms) in &report {
        std::eprintln!(
            "explored {name}: {} paths to depth {}, {} healed, {ms} ms",
            s.paths,
            s.depth,
            s.healed
        );
        assert!(
            s.depth == depth && s.healed > 0,
            "{name} stopped short of depth {depth}"
        );
    }
}
