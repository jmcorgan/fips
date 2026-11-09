//! Bounded exhaustive exploration of the settlement world.
//!
//! From each named start, every sequence of up to the start's depth of
//! events from a finite alphabet is enumerated breadth first: deliver any
//! packet a connection lets through, duplicate a handshake message,
//! resolve a connect window either way, fail an open connection at one
//! end, restart a node, advance to the next wake, leap over the path
//! bundles' wakes to the next other wake (where a bundle wakes first),
//! start an own rekey, send a frame now, step the wall clock (where the start allows it), replay a
//! captured msg1, inject a third identity's msg1 or a forged msg2, the
//! start's path events, and, on the cold start alone, a node's dial. Loss is non-delivery: whatever is never delivered
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
use super::starts::{Start, UDP, home};
use super::world::{PathEv, Pkt, State, World};

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
    /// Advance to the earliest wake that is not a path bundle's, running
    /// the bundles' wakes on the way and delivering their path messages
    /// ([`World::leap`]).
    Leap,
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
    /// Node `x` dials the node at index `y` at its home on UDP: offered
    /// only on a cold start, once per node.
    Dial(usize, usize),
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

/// The budgeted events a path spent, in [`Budget`]'s field order, and
/// last the nodes that dialed, one bit each.
pub fn spent(path: &[Act]) -> [usize; 9] {
    let mut s = [0; 9];
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
            Act::Dial(x, _) => s[8] |= 1 << x,
            Act::Deliver(_) | Act::Connect(_, true) | Act::Advance | Act::Leap => {}
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
        Act::Leap => w.leap(),
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
                match ev {
                    // A NAT's change is the world's, not the node's.
                    PathEv::Rebound { from, to } => w.net.rebind(x, from, to),
                    PathEv::Candidate { .. } | PathEv::Carrier { .. } | PathEv::Gone { .. } => {
                        w.input(x, super::world::Input::Path(ev))
                    }
                }
            }
        }
        Act::Dial(x, y) => super::starts::dial(w, x, y, home(y, UDP), None),
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
            wire: 0,
        }
    } else {
        Pkt::Msg2 {
            id: THIRD,
            hs: Hs(n),
            epoch: Epoch(n),
            wire: 0,
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
    if w.leaps() {
        out.push(Act::Leap);
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
    if st.cold {
        for x in (0..w.parties.len()).filter(|x| s[8] & (1 << x) == 0) {
            out.extend(
                (0..w.parties.len())
                    .filter(|y| *y != x)
                    .map(|y| Act::Dial(x, y)),
            );
        }
    }
    out
}

/// The search key of the state `path` leads to: the world's canonical
/// hash and the budget the path spent. A state reached with more budget
/// left has successors one reached with less cannot, so the two are not
/// one node of the search.
pub fn key(w: &World, path: &[Act]) -> (u64, [usize; 9]) {
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
    /// Distinct states seen, the start included, to the depth explored.
    pub states: usize,
    /// The depth explored to.
    pub depth: usize,
    /// The frontier's size after each depth.
    pub frontier: Vec<usize>,
    /// The paths left at the deepest level, and every dead end.
    pub leaves: Vec<Vec<Act>>,
    /// The keys seen, a depth a time limit ended included.
    pub seen: BTreeSet<(u64, [usize; 9])>,
    /// The time from the start's first replay to the end of each depth,
    /// in milliseconds.
    pub ms: Vec<u128>,
    /// Where a time limit or a state cap ended the search, if one did: how
    /// many paths of the deepest frontier it had expanded into the next
    /// depth, of how many.
    pub cut: Option<(usize, usize)>,
}

/// A check run on every state the explorer reaches; an error stops it with
/// the shortest failing path.
pub type Check<'a> = &'a (dyn Fn(&World, &[Act]) -> Result<(), String> + Sync);

/// Explore `st` breadth first to `depth`, running `check` on every state,
/// and panic with the shortest path that fails it.
pub fn explore(st: &Start, depth: usize, check: Check<'_>) -> Stats {
    search(st, depth, None, None, check)
}

/// As [`explore`], to `depth` or until `limit` has passed, whichever
/// comes first. A depth the limit ends part way is not counted: the
/// statistics are those of the deepest depth explored whole within the
/// limit, and [`Stats::cut`] says how far into the next the search got.
pub fn explore_within(
    st: &Start,
    depth: usize,
    limit: std::time::Duration,
    check: Check<'_>,
) -> Stats {
    search(st, depth, Some(limit), None, check)
}

/// Breadth-first search of `st` to `depth`, stopping once `limit` has
/// passed or more than `cap` states are seen, where either is given.
fn search(
    st: &Start,
    depth: usize,
    limit: Option<std::time::Duration>,
    cap: Option<usize>,
    check: Check<'_>,
) -> Stats {
    let begun = std::time::Instant::now();
    let over =
        |seen: usize| limit.is_some_and(|l| begun.elapsed() > l) || cap.is_some_and(|c| seen > c);
    let root = replay(st, &[]);
    if let Err(e) = check(&root, &[]) {
        panic!("{}: the start fails: {e}", st.name);
    }
    let mut stats = Stats::default();
    stats.seen.insert(key(&root, &[]));
    stats.states = 1;
    let mut frontier: Vec<Vec<Act>> = alloc::vec![Vec::new()];
    for d in 0..depth {
        let mut next = Vec::new();
        let mut ends = Vec::new();
        for (i, path) in frontier.iter().enumerate() {
            if over(stats.seen.len()) {
                stats.cut = Some((i, frontier.len()));
                break;
            }
            let w = replay(st, path);
            let opts = options(&w, path, st);
            if opts.is_empty() {
                ends.push(path.clone());
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
        if stats.cut.is_some() {
            break;
        }
        stats.depth = d + 1;
        stats.states = stats.seen.len();
        stats.frontier.push(next.len());
        stats.ms.push(begun.elapsed().as_millis());
        stats.leaves.extend(ends);
        if std::env::var_os("FIPS_SETTLE_EXPLORE_TRACE").is_some() {
            std::eprintln!("{}: depth {} frontier {}", st.name, d + 1, next.len());
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    stats.leaves.extend(frontier);
    stats
}

/// No check: every state passes.
pub fn none(_: &World, _: &[Act]) -> Result<(), String> {
    Ok(())
}

/// Explore every start on a thread of its own, each until its depth or
/// until it has seen more states than its cap, returning each start's
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
                    let stats = search(st, depth(st), None, Some(st.cap), check);
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

/// Explore every start of `starts` to its depth, one more with
/// `ReachOneMore`, and return what is wrong with its reach: a depth short
/// of its script plus two, a target state not explored, or more states
/// than its cap. Each start's script runs first, so a start that no longer
/// reaches its target state fails before the long exploration, and its
/// exploration ends as soon as it passes its cap, so a start that grew
/// fails without exploring the whole of the depth it grew into. Each
/// start's line is printed with `label` after its name.
pub fn reached(starts: &[Start], label: &str) -> Vec<String> {
    let targets: Vec<_> = starts
        .iter()
        .map(|st| {
            let mut w = (st.build)(st.maker);
            let script = (st.script)(&mut w);
            (key(&w, &script), script.len())
        })
        .collect();
    let more = usize::from(fault!(ReachOneMore));
    let report = explore_all(starts, |st| st.depth + more, &none);
    let mut wrong = Vec::new();
    for ((st, (stats, ms)), (target, len)) in starts.iter().zip(&report).zip(&targets) {
        std::eprintln!(
            "reach {:>2} {}{label}: depth {} states {} frontier {:?} in {ms} ms{}",
            st.number,
            st.name,
            stats.depth,
            stats.states,
            stats.frontier,
            match stats.cut {
                Some((i, n)) => alloc::format!(
                    ", ended at its cap {} paths of {n} into depth {}",
                    i,
                    stats.depth + 1
                ),
                None => String::new(),
            }
        );
        let (target, len) = (*target, *len);
        if len + 2 > st.depth {
            wrong.push(alloc::format!(
                "{}{label}: depth {} is less than its script ({}) plus two",
                st.name,
                st.depth,
                len
            ));
        }
        if !stats.seen.contains(&target) {
            wrong.push(alloc::format!(
                "{}{label}: the target state was not explored",
                st.name
            ));
        }
        if stats.seen.len() > st.cap {
            wrong.push(alloc::format!(
                "{}{label}: {} states, over its cap of {}",
                st.name,
                stats.seen.len(),
                st.cap
            ));
        }
    }
    wrong
}

#[test]
fn every_named_start_reaches_its_target_depth_over_the_model() {
    let wrong = reached(&super::starts::starts(), "");
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
