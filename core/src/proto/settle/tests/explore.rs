//! Bounded exhaustive exploration of the settlement world.
//!
//! From each named start, every sequence of up to the start's depth of
//! events from a finite alphabet is enumerated breadth first: deliver any
//! packet a connection lets through, duplicate a handshake message,
//! resolve a connect window either way, fail an open connection at one
//! end, restart a node, advance to the next wake, start an own rekey, send
//! a frame now, step the wall clock (where the start allows it), replay a
//! captured msg1, inject a third identity's msg1 or a forged msg2, and the
//! start's path events. Loss is non-delivery: whatever is never delivered
//! was lost. States are de-duplicated on a canonical key of the world and
//! the budgeted events the path spent, so a state found is found by a
//! shortest path.
//!
//! The settlement core holds linear index leases and is not `Clone`, so
//! each state is rebuilt by replaying its path from the start, as the
//! rekey explorer does; the world is deterministic, so a path names one
//! state.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::model::history::{Addr, Bytes, Epoch, Hs, Node};
use super::starts::Start;
use super::world::{Pkt, State, World};

/// The identity a third party's msg1 and a forged msg2 claim.
pub const THIRD: Node = Node(99);

/// One event the explorer chooses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Act {
    /// Deliver the packet now.
    Deliver(u64),
    /// Put a copy of a handshake message in flight.
    Dup(u64),
    /// The connect window of connection `c` ends: open, or failed.
    Connect(u32, bool),
    /// End `e` of connection `c` sees it fail.
    Fail(u32, usize),
    /// Node `x` restarts.
    Restart(usize),
    /// Advance to the earliest wake and wake whoever is due.
    Advance,
    /// Node `x` starts its own rekey of the node at index `y`.
    Rekey(usize, usize),
    /// Node `x` sends a frame to every peer it holds, now.
    Frame(usize),
    /// The wall clock steps forward.
    Wall,
    /// Captured msg1 `k` is replayed at its receiver.
    Replay(usize),
    /// A third identity's msg1 reaches node `x`.
    Third(usize),
    /// A forged msg2 reaches node `x`.
    Garbage(usize),
    /// The start's path event `i`.
    Path(usize),
}

/// How many of each budgeted event one path may hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Duplicates.
    pub dups: usize,
    /// Restarts.
    pub restarts: usize,
    /// Replays, third-party msg1s and forged msg2s.
    pub forgeries: usize,
    /// Frames sent now.
    pub frames: usize,
    /// Wall steps.
    pub walls: usize,
    /// Failed connects and failed connections.
    pub faults: usize,
    /// Own rekeys started.
    pub rekeys: usize,
    /// Path events.
    pub paths: usize,
}

/// The budget most starts use: one of each.
pub const SMALL: Budget = Budget {
    dups: 1,
    restarts: 1,
    forgeries: 1,
    frames: 1,
    walls: 1,
    faults: 1,
    rekeys: 1,
    paths: 2,
};

/// The budgeted events a path spent, in [`Budget`]'s field order.
pub fn spent(path: &[Act]) -> [usize; 8] {
    let mut s = [0; 8];
    for a in path {
        match a {
            Act::Dup(_) => s[0] += 1,
            Act::Restart(_) => s[1] += 1,
            Act::Replay(_) | Act::Third(_) | Act::Garbage(_) => s[2] += 1,
            Act::Frame(_) => s[3] += 1,
            Act::Wall => s[4] += 1,
            Act::Connect(_, false) | Act::Fail(..) => s[5] += 1,
            Act::Rekey(..) => s[6] += 1,
            Act::Path(_) => s[7] += 1,
            Act::Deliver(_) | Act::Connect(_, true) | Act::Advance => {}
        }
    }
    s
}

/// Carry out one event.
pub fn apply(w: &mut World, a: Act) {
    match a {
        Act::Deliver(id) => w.deliver(id),
        Act::Dup(id) => w.duplicate(id),
        Act::Connect(c, ok) => w.connected(c, ok),
        Act::Fail(c, e) => w.fail(c, e),
        Act::Restart(x) => w.restart(x),
        Act::Advance => w.advance(),
        Act::Rekey(x, y) => {
            let peer = w.ids[y];
            w.input(x, super::world::Input::Rekey { peer });
        }
        Act::Frame(x) => w.input(x, super::world::Input::Beat),
        Act::Wall => w.net.wall += super::world::WALL_STEP,
        Act::Replay(k) => w.replay(k),
        Act::Third(x) => forge(w, x, true),
        Act::Garbage(x) => forge(w, x, false),
        Act::Path(i) => {
            if let Some(&(x, ev)) = w.paths.get(i) {
                w.used[i] = true;
                w.input(x, super::world::Input::Path(ev));
            }
        }
    }
}

/// Put a third identity's msg1, or a forged msg2, in flight to node `x` on
/// its first connectionless transport.
fn forge(w: &mut World, x: usize, msg1: bool) {
    let Some(t) = w
        .net
        .kinds
        .iter()
        .find(|(_, k)| **k == super::world::Kind::Datagram)
        .map(|(t, _)| *t)
    else {
        return;
    };
    let to = w.net.home(x, t);
    let src = Addr {
        transport: t,
        at: 900,
    };
    let n = (u32::from(THIRD.0) << 24) | (w.net.next as u32 & 0xffff);
    let pkt = if msg1 {
        Pkt::Msg1 {
            id: THIRD,
            hs: Hs(n),
            bytes: Bytes(n),
            epoch: Epoch(n),
        }
    } else {
        Pkt::Msg2 {
            id: THIRD,
            hs: Hs(n),
            epoch: Epoch(n),
        }
    };
    w.net.inject(x, to, src, pkt);
}

/// The events available in `w` to a path that has spent `path`'s budget.
pub fn options(w: &World, path: &[Act], st: &Start) -> Vec<Act> {
    let s = spent(path);
    let b = st.budget;
    let mut out = Vec::new();
    for f in &w.net.flight {
        if w.net.deliverable(f) {
            out.push(Act::Deliver(f.id));
        }
        if s[0] < b.dups && f.pkt.handshake() && !f.copy {
            out.push(Act::Dup(f.id));
        }
    }
    for c in &w.net.conns {
        match c.state {
            State::Connecting => {
                out.push(Act::Connect(c.id, true));
                if s[5] < b.faults {
                    out.push(Act::Connect(c.id, false));
                }
            }
            State::Open if s[5] < b.faults => {
                out.push(Act::Fail(c.id, 0));
                out.push(Act::Fail(c.id, 1));
            }
            State::Open | State::Closed(_) => {}
        }
    }
    if w.wake().is_some() {
        out.push(Act::Advance);
    }
    for x in 0..w.parties.len() {
        if s[1] < b.restarts {
            out.push(Act::Restart(x));
        }
        let held = w.parties[x].held();
        if s[3] < b.frames && !held.is_empty() {
            out.push(Act::Frame(x));
        }
        if s[6] < b.rekeys {
            for peer in held {
                if let Some(y) = w.index(peer)
                    && w.parties[x].rekeyable(peer)
                {
                    out.push(Act::Rekey(x, y));
                }
            }
        }
        if st.forged && s[2] < b.forgeries {
            out.push(Act::Third(x));
            out.push(Act::Garbage(x));
        }
    }
    if st.wall && s[4] < b.walls {
        out.push(Act::Wall);
    }
    if st.forged && s[2] < b.forgeries {
        // A replay of a resend is a replay of its original: one per
        // distinct capture.
        for (k, f) in w.net.captured.iter().enumerate() {
            let first = w
                .net
                .captured
                .iter()
                .position(|g| (g.to, g.local, g.src, g.pkt) == (f.to, f.local, f.src, f.pkt));
            if first == Some(k) {
                out.push(Act::Replay(k));
            }
        }
    }
    for (i, used) in w.used.iter().enumerate() {
        if !used && s[7] < b.paths {
            out.push(Act::Path(i));
        }
    }
    out
}

/// The search key of the state `path` leads to: the world's canonical
/// hash and the budget the path spent. A state reached with more budget
/// left has successors one reached with less cannot, so the two are not
/// one node of the search.
pub fn key(w: &World, path: &[Act]) -> (u64, [usize; 8]) {
    (w.key(), spent(path))
}

/// Rebuild the world `path` leads to from `st`'s start.
pub fn replay(st: &Start, path: &[Act]) -> World {
    replay_logged(st, path, false)
}

/// As [`replay`], logging every event when `logging`.
pub fn replay_logged(st: &Start, path: &[Act], logging: bool) -> World {
    let mut w = (st.build)(st.maker);
    w.net.logging = logging;
    for &a in path {
        apply(&mut w, a);
    }
    w
}

/// What one exploration covered.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Distinct states seen, the start included.
    pub states: usize,
    /// The depth explored to.
    pub depth: usize,
    /// The frontier's size after each depth.
    pub frontier: Vec<usize>,
    /// The paths left at the deepest level, and every dead end.
    pub leaves: Vec<Vec<Act>>,
    /// The keys seen.
    pub seen: BTreeSet<(u64, [usize; 8])>,
}

/// A check run on every state the explorer reaches; an error stops it with
/// the shortest failing path.
pub type Check<'a> = &'a (dyn Fn(&World, &[Act]) -> Result<(), String> + Sync);

/// Explore `st` breadth first to `depth`, running `check` on every state,
/// and panic with the shortest path that fails it.
pub fn explore(st: &Start, depth: usize, check: Check<'_>) -> Stats {
    let root = replay(st, &[]);
    if let Err(e) = check(&root, &[]) {
        panic!("{}: the start fails: {e}", st.name);
    }
    let mut stats = Stats::default();
    stats.seen.insert(key(&root, &[]));
    let mut frontier: Vec<Vec<Act>> = alloc::vec![Vec::new()];
    for d in 0..depth {
        let mut next = Vec::new();
        for path in &frontier {
            let w = replay(st, path);
            let opts = options(&w, path, st);
            if opts.is_empty() {
                stats.leaves.push(path.clone());
            }
            for a in opts {
                let mut p = path.clone();
                p.push(a);
                let w2 = replay(st, &p);
                if let Err(e) = check(&w2, &p) {
                    let w2 = replay_logged(st, &p, true);
                    panic!(
                        "{} at depth {}: {e}\npath {p:?}\nlog:\n{}",
                        st.name,
                        d + 1,
                        w2.net.log.join("\n")
                    );
                }
                if stats.seen.insert(key(&w2, &p)) {
                    next.push(p);
                }
            }
        }
        stats.depth = d + 1;
        stats.frontier.push(next.len());
        if std::env::var_os("FIPS_SETTLE_EXPLORE_TRACE").is_some() {
            std::eprintln!("{}: depth {} frontier {}", st.name, d + 1, next.len());
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    stats.states = stats.seen.len();
    stats.leaves.extend(frontier);
    stats
}

/// No check: every state passes.
pub fn none(_: &World, _: &[Act]) -> Result<(), String> {
    Ok(())
}

/// Explore every start on a thread of its own, returning each start's
/// statistics and wall time in milliseconds, in the order of `starts`.
pub fn explore_all(
    starts: &[Start],
    depth: impl Fn(&Start) -> usize + Sync,
    check: Check<'_>,
) -> Vec<(Stats, u128)> {
    let depth = &depth;
    std::thread::scope(|s| {
        let handles: Vec<_> = starts
            .iter()
            .map(|st| {
                s.spawn(move || {
                    let t = std::time::Instant::now();
                    let stats = explore(st, depth(st), check);
                    (stats, t.elapsed().as_millis())
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    })
}

#[test]
fn every_named_start_reaches_its_target_depth_over_the_model() {
    let starts = super::starts::starts();
    // Each start's script runs first, so a start that no longer reaches
    // its target state fails before the long exploration.
    let targets: Vec<_> = starts
        .iter()
        .map(|st| {
            let mut w = (st.build)(st.maker);
            let script = (st.script)(&mut w);
            (key(&w, &script), script.len())
        })
        .collect();
    let more = usize::from(fault!(ReachOneMore));
    let report = explore_all(&starts, |st| st.depth + more, &none);
    let mut wrong = Vec::new();
    for ((st, (stats, ms)), (target, len)) in starts.iter().zip(&report).zip(&targets) {
        std::eprintln!(
            "reach {:>2} {}: depth {} states {} frontier {:?} in {ms} ms",
            st.number,
            st.name,
            stats.depth,
            stats.states,
            stats.frontier
        );
        let (target, len) = (*target, *len);
        if len + 2 > st.depth {
            wrong.push(alloc::format!(
                "{}: depth {} is less than its script ({}) plus two",
                st.name,
                st.depth,
                len
            ));
        }
        if !stats.seen.contains(&target) {
            wrong.push(alloc::format!(
                "{}: the target state was not explored",
                st.name
            ));
        }
        if stats.states > st.cap {
            wrong.push(alloc::format!(
                "{}: {} states, over its cap of {}",
                st.name,
                stats.states,
                st.cap
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_replayed_path_rebuilds_the_same_world() {
    let starts = super::starts::starts();
    for st in starts.iter().filter(|s| matches!(s.number, 1 | 3 | 8)) {
        let stats = explore(st, 4, &none);
        for path in &stats.leaves {
            let a = replay(st, path).digest();
            let b = replay(st, path).digest();
            assert_eq!(a, b, "{}: {path:?} rebuilt a different world", st.name);
        }
    }
}
