//! The joint world's own oracles: what a joint node's core, its machines
//! and its shell must agree on, which the stand-in core's party holds by
//! construction or does not model.
//!
//! A joint node gives the oracles its [`Facts`] (`Party::joint`): for each
//! peer its core holds, what the core records and what the shell holds for
//! it, side by side, and the node's index leases. [`check`] reads them
//! after every step, in `../oracle.rs`'s `every_step`:
//!
//! - one view of each peer ([`Oracle::OneView`]): (a) the shell holds one
//!   rekey machine for each peer the core holds, built or carried at the
//!   install of the link the core holds the peer on, and the machine's
//!   proven identity is that peer; (b) once the machine has the peer's
//!   startup epoch, the core's record of it is the same, except after the
//!   core's gates refused a restart the machine found, where the two
//!   differ by the core's own decision, and while the machine's own
//!   completed rekey waits for its cutover: the machine records the
//!   restart that rekey's answer reveals when it reads the answer, and
//!   reports it at the cutover (`Output::PeerRestarted` beside
//!   `Installed`), so the core cannot hear of it sooner; (c) until the
//!   machine's first cutover, its current session is the one the install's
//!   handshake made, by the shell's map of handshake names to sessions. The
//!   core holds no session of its own, so (c) checks the shell;
//! - the leases ([`Oracle::Leases`]): the indices the node's pool has
//!   handed out are exactly those its live handshake legs hold and those
//!   its machines bind, each once. A lease is linear, so one the shell
//!   lost shows here as an index nothing holds, and one released twice
//!   cannot be written;
//! - no orphan machine ([`Oracle::NoOrphan`]): every peer the core holds
//!   has its machines, and the shell holds machines for no other peer;
//! - the paths mirrored ([`Oracle::Mirrored`]): (a) the core's record of
//!   each held link's paths is its bundle's paths, order aside, each with
//!   the state the shell reports for it (Live for a Live path, acked for
//!   another acknowledged one, probing otherwise); (b) the core's index is
//!   its derivation from the records; (c) the core's record of where the
//!   peer is, `Held.current`, is the bundle's active path;
//! - every output delivered ([`Oracle::Delivered`]): each replacement
//!   request, restart and teardown of a rekey machine and each orphaning of
//!   a bundle reached the core as its input in the step that emitted it,
//!   and no such input reached the core without one. The shell keeps the
//!   count of each per step ([`Ledger`]) and records what [`delivered`]
//!   finds;
//! - attribution ([`Oracle::Attributed`]): at each msg1 the core takes as
//!   a held peer's, its answer to whether the msg1 is on the peer's link is
//!   the node's: on a pair the bundle holds a path at, whether that path is
//!   Live or acknowledged; on a pair it holds none at, whether the peer is
//!   not capable and the index names the link. The shell judges it when
//!   the core decides and records what it finds.
//!
//! The machines' own oracles ([`Oracle::Machine`], its text naming which)
//! are the rekey simulator's and the path simulator's, through the
//! predicates both simulators call (`rekey/tests/oracles.rs`, the path
//! shell's `Checks`): after every step, bounded memory, key retention and,
//! after a poll, the deadlines on each rekey machine, and conservation of
//! the node's indices against its machines' bindings and its legs
//! ([`machine`], [`node`]); around each msg1 handed to a machine, and each
//! copied msg2, that a msg1 the record owes arms no pending, that a repeat
//! changes nothing, and that a copied msg1 which arms a pending, the
//! accepted residual, adopts, confirms and refreshes nothing ([`took`]);
//! on each bundle step, the path shell's checks, the next wake lying ahead
//! of the step among them; and once healed, convergence of each pair's
//! two machines (`../oracle.rs`, `healed`). The shell runs each where it
//! knows what it needs (whether the step polled the machine, a delivery's
//! before and after) and records what fails. Two are not checked: the
//! simulator's data-traffic and lossless rules need traffic and runs the
//! world does not have, and its worker rule needs a decrypt worker, which
//! no joint node runs.
//!
//! Three clauses are pinned, not asserted, because the core is known to
//! part there from the bundle or the node, in code a later step owns: each
//! is counted ([`Pin`], [`pinned_in`]) and printed by a sweep, and a test
//! in `pins.rs` fails on it. (c) of the mirror, since the core follows
//! every frame's source and does not follow a switch; in (a), the active
//! path the bundle holds acknowledged and not Live, which the core records
//! Live after a switch to it; and in attribution, the three shapes where
//! the core's rule is wider than the node's (a capable peer's setup pair
//! with no path; the pair the core's record of the peer followed a frame
//! to, which no index entry holds and no path proves; and a setup pair
//! whose path is still probing).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::rekey::Digest;
use crate::proto::rekey::tests::oracles::{self as rules, Change, Owed, Peek, Seen};
use crate::proto::rekey::tests::stub::{Ev, Ik};
use crate::proto::settle::links::{LinkNo, Proven};
use crate::testutil::TestInstant;

use super::machines::{Event, Machine};

use super::super::super::model::history::{Addr, Hs, Node};
use super::super::oracle::Oracle;
use super::super::world::World;

/// A clause of the joint world's oracles that is pinned, not asserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pin {
    /// The core's record of where the peer is is not the bundle's active
    /// path.
    Current,
    /// The core records Live an active path the bundle holds acknowledged
    /// and not Live, as a switch to it writes it.
    SwitchedLive,
    /// The core took a msg1 as on the peer's link in a shape where the
    /// node's rule is narrower.
    Attribution,
}

/// The machine outputs the core must hear of, each by the input it
/// becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Told {
    /// A replacement request, which becomes `Input::Replace`.
    Replace,
    /// A restart found, which becomes `Input::Restarted`.
    Restart,
    /// A teardown, which becomes `Input::Ended`.
    Teardown,
    /// An orphaned bundle, which becomes `Input::Orphaned`.
    Orphan,
}

impl Told {
    /// Every kind, in the ledger's order.
    const ALL: [Self; 4] = [Self::Replace, Self::Restart, Self::Teardown, Self::Orphan];
}

/// One step's count of the outputs the core must hear of and of the
/// inputs that tell it, by kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    emitted: [u32; 4],
    stepped: [u32; 4],
}

impl Ledger {
    /// A machine emitted an output of kind `t`.
    pub fn emit(&mut self, t: Told) {
        self.emitted[t as usize] += 1;
    }

    /// The core was stepped with an input of kind `t`.
    pub fn step(&mut self, t: Told) {
        self.stepped[t as usize] += 1;
    }
}

/// Each kind whose outputs in one step were not matched one for one by
/// the core's inputs, in the shell's ledger `l`.
pub fn delivered(l: &Ledger) -> Vec<String> {
    Told::ALL
        .iter()
        .filter(|t| l.emitted[**t as usize] != l.stepped[**t as usize])
        .map(|t| {
            format!(
                "{t:?}: {} emitted by the machines, {} reached the core",
                l.emitted[*t as usize], l.stepped[*t as usize]
            )
        })
        .collect()
}

/// What the joint world's oracles read of one joint node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    /// Each peer the core holds.
    pub peers: Vec<Peer>,
    /// The peers the shell holds machines for that the core does not hold.
    pub stray: Vec<Node>,
    /// The indices the node's pool has handed out.
    pub pool: Vec<u32>,
    /// The index each live handshake leg holds, by the shell's record of
    /// the lease it gave the core.
    pub legs: Vec<u32>,
    /// The indices every machine binds.
    pub bound: Vec<u32>,
    /// The core's index equals its derivation from the link records.
    pub derived: bool,
    /// What the shell found at a step: an output the core did not hear of,
    /// or a msg1 the core attributed otherwise than the node.
    pub found: Vec<(Oracle, String)>,
    /// The pinned shapes the shell met at a step.
    pub pins: Vec<(Pin, String)>,
}

/// One peer the core holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The peer.
    pub peer: Node,
    /// The link the core holds it on.
    pub link: LinkNo,
    /// The core's record of its startup epoch.
    pub epoch: [u8; 8],
    /// The core's record of where it is.
    pub current: Addr,
    /// The core's record of its link's paths.
    pub paths: Vec<(Addr, Proven)>,
    /// What the shell holds for it; `None` for no machines.
    pub shell: Option<Shell>,
}

/// What the shell holds for one peer the core holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shell {
    /// The link the machines were built or carried at the install of.
    pub link: LinkNo,
    /// The peer the rekey machine's identity names, when it is proven and
    /// names a world node.
    pub identity: Option<Node>,
    /// The machine's record of the peer's startup epoch.
    pub epoch: Option<[u8; 8]>,
    /// The core's gates refused a restart the machine found, and nothing
    /// has set the two records of the peer's epoch equal since.
    pub gated: bool,
    /// The machine's own completed rekey waits for its cutover, which is
    /// when it reports a restart the rekey's answer revealed.
    pub waiting: bool,
    /// The machine has cut over since the install.
    pub cut: bool,
    /// The name of the machine's current session.
    pub current: Option<Hs>,
    /// The handshake of the install.
    pub origin: Hs,
    /// The bundle's paths, each with the state the shell reports for it.
    pub paths: Vec<(Addr, Proven)>,
    /// The bundle's active path.
    pub active: Option<Addr>,
}

/// The start of the message of the rekey simulator's convergence rule,
/// which a sweep exempts as it exempts a split, on a path that showed a
/// known shape.
pub const CONVERGED: &str = "O1:";

/// The rekey machine's deadlines that its checks read, in ms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// How long an own attempt may run (`Params::budget`).
    pub budget: u64,
    /// How long a previous epoch may be kept (`Config::retention`).
    pub retention: u64,
}

/// The rekey simulator's per-step rules on machine `m` of node `x` at
/// `now`, read through `peek`: bounded memory and key retention, and after
/// a poll (`polled`) its next wake ahead and its own attempt, started at
/// `start`, within its budget.
#[allow(clippy::too_many_arguments)]
pub fn machine(
    x: usize,
    m: &Machine,
    peek: &Peek<'_, Ik, TestInstant>,
    now: u64,
    polled: bool,
    start: Option<u64>,
    l: Limits,
) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(rules::memory(x, peek).err());
    out.extend(rules::retained(x, peek, l.retention, now, polled).err());
    if polled {
        out.extend(rules::ahead(x, m.next_wake().map(|t| t.0), now).err());
        out.extend(rules::attempt(x, m, start, now, l.budget).err());
    }
    out
}

/// The rekey simulator's conservation rule at node `x`: the `held`
/// indices its pool handed out are the `bound` its machines bind and its
/// legs hold.
pub fn node(x: usize, held: usize, bound: usize) -> Vec<String> {
    rules::balanced(x, held, bound).err().into_iter().collect()
}

/// The rekey simulator's rules around one delivery of handshake `hs` to a
/// machine of node `x`, which `change` says what it did to and `events`
/// what it emitted. For a msg1, `e` is its ephemeral and `owed` the list
/// of those the record owes, which the delivery adds to: a msg1 on the
/// list arms no pending, a copied msg1 that arms one is the accepted
/// residual and adopts, confirms and refreshes nothing, and any other copy
/// of a msg1 on the list changes nothing. For another message `e` is
/// `None`, and a `repeat` changes nothing.
#[allow(clippy::too_many_arguments)]
pub fn took(
    x: usize,
    hs: Hs,
    copy: bool,
    repeat: bool,
    owed: &mut Owed,
    e: Option<&Digest>,
    change: &Change,
    events: &[Event],
) -> Vec<String> {
    let evs = evs(events);
    let seen = Seen {
        origin: if copy { "a copy" } else { "a delivery" },
        root: u64::from(hs.0),
        x,
    };
    let mut repeat = repeat;
    if let Some(e) = e {
        repeat = repeat || (copy && owed.owes(e));
        if let Err(m) = rules::rearmed(&seen, owed, e, change, &evs) {
            return alloc::vec![m];
        }
        owed.add(*e, change.armed, &evs);
        if copy && change.armed {
            return rules::contained(x, change, &evs);
        }
    }
    rules::unchanged(&seen, repeat, change, &evs)
        .err()
        .into_iter()
        .collect()
}

/// A machine's events as the rekey simulator's predicates read them.
fn evs(events: &[Event]) -> Vec<Ev<u8>> {
    use crate::proto::rekey::Output as O;
    events
        .iter()
        .filter_map(|e| match e {
            Event::Rekey(o) => Some(match o {
                O::Send { msg, kind, route } => Ev::Send(*kind, msg.clone(), *route),
                O::Prompt { tag } => Ev::Prompt(*tag),
                O::Deliver { slot, tag, .. } => Ev::Deliver(*slot, *tag, Vec::new()),
                O::Bind {
                    transport,
                    index,
                    tag,
                    purpose,
                } => Ev::Bind(*transport, *index, *tag, *purpose),
                O::Unbind { transport, index } => Ev::Unbind(*transport, *index),
                O::Delegate {
                    tag,
                    transport,
                    index,
                    ..
                } => Ev::Delegate(*tag, *transport, *index, None),
                O::Revoke {
                    tag,
                    transport,
                    index,
                } => Ev::Revoke(*tag, *transport, *index),
                O::Release(_) => Ev::Release(0),
                O::Installed {
                    tag,
                    role,
                    evidence,
                } => Ev::Installed(*tag, *role, *evidence),
                O::Retired { tag } => Ev::Retired(*tag),
                O::Reverted { tag } => Ev::Reverted(*tag),
                O::PeerRestarted { layer, epoch } => Ev::Restarted(*layer, *epoch),
                O::Rekeyed { role } => Ev::Rekeyed(*role),
                O::ReplaceRequested { .. } => Ev::Replace,
                O::Reject(r) => Ev::Reject(*r),
                O::Abandoned(a) => Ev::Abandoned(*a),
                O::Teardown(t) => Ev::Teardown(*t),
            }),
            Event::Prompt { tag, .. } => Some(Ev::Prompt(*tag)),
            Event::Freed(i) => Some(Ev::Release(*i)),
            Event::Path(_) | Event::Roamed { .. } | Event::Bound { .. } => None,
        })
        .collect()
}

/// Every breach of the joint world's oracles in `f`, each with its oracle.
pub fn check(f: &Facts) -> Vec<(Oracle, String)> {
    judge(f).0
}

/// Every pinned clause `f` shows.
pub fn pinned(f: &Facts) -> Vec<(Pin, String)> {
    judge(f).1
}

/// Every pinned clause each joint node of `w` shows, with its node.
pub fn pinned_in(w: &World) -> Vec<(usize, Pin, String)> {
    w.parties
        .iter()
        .enumerate()
        .filter_map(|(x, p)| p.joint().map(|f| (x, f)))
        .flat_map(|(x, f)| {
            pinned(&f)
                .into_iter()
                .map(move |(pin, what)| (x, pin, what))
        })
        .collect()
}

/// The breaches found and the pinned clauses shown.
type Judged = (Vec<(Oracle, String)>, Vec<(Pin, String)>);

/// The breaches and the pinned clauses of `f`.
fn judge(f: &Facts) -> Judged {
    let mut out = Vec::new();
    let mut pins = f.pins.clone();
    one_view(f, &mut out);
    leases(f, &mut out);
    no_orphan(f, &mut out);
    mirrored(f, &mut out, &mut pins);
    out.extend(f.found.iter().cloned());
    (out, pins)
}

/// `paths` in one order, for a comparison that sets order aside.
fn sorted(paths: &[(Addr, Proven)]) -> Vec<(Addr, Proven)> {
    let rank = |p: Proven| match p {
        Proven::Live => 0,
        Proven::Acked => 1,
        Proven::Probing => 2,
    };
    let mut v = paths.to_vec();
    v.sort_unstable_by_key(|(a, p)| (a.transport, a.at, rank(*p)));
    v
}

/// Each held link's paths mirrored, and the index derived.
fn mirrored(f: &Facts, out: &mut Vec<(Oracle, String)>, pins: &mut Vec<(Pin, String)>) {
    if !f.derived {
        out.push((
            Oracle::Mirrored,
            String::from("the index is not its derivation from the link records"),
        ));
    }
    for p in &f.peers {
        let Some(s) = &p.shell else { continue };
        let (core, bundle) = (sorted(&p.paths), sorted(&s.paths));
        if core != bundle {
            // The bundle's active path, acknowledged and not Live, which
            // a switch to it records Live in the core.
            let switched: Vec<(Addr, Proven)> = s
                .paths
                .iter()
                .map(|&(a, q)| {
                    if Some(a) == s.active && q == Proven::Acked {
                        (a, Proven::Live)
                    } else {
                        (a, q)
                    }
                })
                .collect();
            let what = format!(
                "{:?}: the core records the paths {core:?}, the bundle holds {bundle:?}",
                p.peer
            );
            if sorted(&switched) == core {
                pins.push((Pin::SwitchedLive, what));
            } else {
                out.push((Oracle::Mirrored, what));
            }
        }
        if Some(p.current) != s.active {
            pins.push((
                Pin::Current,
                format!(
                    "{:?}: the core has the peer at {:?}, the bundle's active path is {:?}",
                    p.peer, p.current, s.active
                ),
            ));
        }
    }
}

/// One view of each held peer.
fn one_view(f: &Facts, out: &mut Vec<(Oracle, String)>) {
    for p in &f.peers {
        let Some(s) = &p.shell else {
            out.push((
                Oracle::OneView,
                format!("{:?}: no rekey machine for a held peer", p.peer),
            ));
            continue;
        };
        if s.link != p.link {
            out.push((
                Oracle::OneView,
                format!(
                    "{:?}: the machine was built at the install of {:?}, the core holds the peer on {:?}",
                    p.peer, s.link, p.link
                ),
            ));
        }
        if s.identity != Some(p.peer) {
            out.push((
                Oracle::OneView,
                format!("{:?}: the machine's identity is {:?}", p.peer, s.identity),
            ));
        }
        if let Some(e) = s.epoch
            && !s.gated
            && !s.waiting
            && e != p.epoch
        {
            out.push((
                Oracle::OneView,
                format!(
                    "{:?}: startup epoch {e:?} in the machine, {:?} in the core",
                    p.peer, p.epoch
                ),
            ));
        }
        if !s.cut && s.current != Some(s.origin) {
            out.push((
                Oracle::OneView,
                format!(
                    "{:?}: before any cutover the machine runs {:?}, the install's handshake is {:?}",
                    p.peer, s.current, s.origin
                ),
            ));
        }
    }
}

/// Every index the pool handed out is held once, by a leg or a machine.
fn leases(f: &Facts, out: &mut Vec<(Oracle, String)>) {
    let mut pool = f.pool.clone();
    pool.sort_unstable();
    let mut held: Vec<u32> = f.legs.iter().chain(&f.bound).copied().collect();
    held.sort_unstable();
    if pool != held {
        out.push((
            Oracle::Leases,
            format!("the pool has handed out {pool:?}, the legs and machines hold {held:?}"),
        ));
    }
}

/// Machines for exactly the peers the core holds.
fn no_orphan(f: &Facts, out: &mut Vec<(Oracle, String)>) {
    for p in f.peers.iter().filter(|p| p.shell.is_none()) {
        out.push((
            Oracle::NoOrphan,
            format!("{:?}: held by the core with no machines", p.peer),
        ));
    }
    for n in &f.stray {
        out.push((
            Oracle::NoOrphan,
            format!("{n:?}: machines for a peer the core does not hold"),
        ));
    }
}

use super::super::super::model::history::Event as Happened;
use super::super::super::model::judge::{Class, Transition as M};
use super::super::explore::{Act, apply, replay};
use super::super::oracle::{Breach, HEAL, every_step, healed};
use super::super::shadow::Entry;
use super::super::starts::{A, B, TCP, UDP, age, dial_home, home, settle, world_of};

/// Start `number`'s first variant with joint nodes at Off at both ends.
fn start(number: u8) -> super::super::starts::Start {
    super::starts::off()
        .into_iter()
        .find(|s| s.number == number)
        .expect("the start")
}

/// Apply each of `acts` to `w`, and every breach seen after each.
fn watched(w: &mut World, acts: &[Act]) -> Vec<Breach> {
    let mut out = every_step(w);
    for &a in acts {
        apply(w, a);
        out.extend(every_step(w));
    }
    out
}

/// Deliver everything in flight one packet at a time, opening every
/// connect window, and every breach seen after each delivery.
fn flushed(w: &mut World) -> Vec<Breach> {
    let mut out = Vec::new();
    for _ in 0..256 {
        let connecting: Vec<u32> = w
            .net
            .conns
            .iter()
            .filter(|c| c.state == super::super::world::State::Connecting)
            .map(|c| c.id)
            .collect();
        for c in connecting {
            w.connected(c, true);
            out.extend(every_step(w));
        }
        let Some(id) = w
            .net
            .flight
            .iter()
            .find(|f| w.net.deliverable(f))
            .map(|f| f.id)
        else {
            break;
        };
        w.deliver(id);
        out.extend(every_step(w));
    }
    out
}

/// Heal `w` as the settlement oracles' heal does, with every breach seen
/// after each delivery and each wake on the way, and the healed properties
/// at its end: a node's liveness timer may end within the heal a state an
/// every-step property breaks, so the end alone would not show it.
fn healing(w: &mut World) -> Vec<Breach> {
    let end = w.net.now + HEAL;
    let mut out = Vec::new();
    loop {
        out.extend(flushed(w));
        match w.wake() {
            Some(t) if t <= end => {
                w.advance();
                out.extend(every_step(w));
            }
            Some(_) | None => break,
        }
    }
    w.net.now = w.net.now.max(end);
    out.extend(flushed(w));
    out.extend(every_step(w));
    out.extend(healed(w));
    out
}

/// The breaches of `oracle` among `found`.
fn of(found: &[Breach], oracle: Oracle) -> Vec<Breach> {
    found
        .iter()
        .filter(|b| b.oracle == oracle)
        .cloned()
        .collect()
}

/// Whether node `x` logged a peer change `m`.
fn changed(w: &World, x: usize, m: M) -> bool {
    w.parties[x].view().log.iter().any(|e| {
        matches!(
            e,
            Entry::Ev { rec, .. } if rec.change == Some(m)
        )
    })
}

/// Whether node `x` logged a msg1 of class `class`.
fn classed(w: &World, x: usize, class: Class) -> bool {
    w.parties[x].view().log.iter().any(|e| {
        matches!(
            e,
            Entry::Ev { ev: Happened::Msg1 { .. }, rec, .. } if rec.class == Some(class)
        )
    })
}

/// Node `x`'s facts.
fn facts(w: &World, x: usize) -> Facts {
    w.parties[x].joint().expect("a joint node gives its facts")
}

#[test]
fn one_view_reads_a_restart_on_both_sides_of_the_core() {
    // A restart revealed in a rekey msg2. The restart start's pair, aged
    // past the floors; node 1 restarts and forgets node 0, and node 0's
    // own rekey reaches it as a new peer's msg1, so node 0's machine finds
    // the restart in the answer and the core takes it.
    let st = start(8);
    let mut scratch = replay(&st, &[]);
    let script = (st.script)(&mut scratch);
    let mut w = replay(&st, &[]);
    let mut found = watched(&mut w, &script[..2]);
    age(&mut w, 40_000);
    found.extend(watched(&mut w, &[Act::Restart(1)]));
    assert!(w.parties[0].rekeyable(B), "precondition: node 0 may rekey");
    found.extend(watched(&mut w, &[Act::Rekey(0, 1)]));
    found.extend(flushed(&mut w));
    w.run_until(w.net.now + 1_000);
    found.extend(every_step(&w));
    found.extend(flushed(&mut w));
    found.extend(healing(&mut w));
    let wrong = of(&found, Oracle::OneView);
    assert!(
        wrong.is_empty(),
        "one view of the peer through a restart found at a rekey: {wrong:?}"
    );
    assert!(
        changed(&w, 0, M::Restarted),
        "precondition: node 0's core took the restart its machine found"
    );

    // A restart replacement: the restart start as it is. Node 0 restarts
    // and dials again, and node 1 replaces its peering of node 0's old life
    // with the new one.
    let mut w = replay(&st, &[]);
    let mut found = watched(&mut w, &script);
    found.extend(healing(&mut w));
    let wrong = of(&found, Oracle::OneView);
    assert!(
        wrong.is_empty(),
        "one view of the peer through a restart replacement: {wrong:?}"
    );
    assert!(
        classed(&w, 1, Class::Restart),
        "precondition: node 1 took node 0's msg1 of its new life as a restart"
    );
}

#[test]
fn one_view_reads_the_session_a_move_built_from() {
    // The connection-oriented crossing: node 0 moves the peering of node 1
    // onto its own dial's link, and its machine is built again on that
    // dial's handshake.
    let st = start(3);
    let mut scratch = replay(&st, &[]);
    let script = (st.script)(&mut scratch);
    let mut w = replay(&st, &[]);
    let mut found = watched(&mut w, &script);
    found.extend(healing(&mut w));
    let wrong = of(&found, Oracle::OneView);
    assert!(
        wrong.is_empty(),
        "one view of the peer through a move: {wrong:?}"
    );
    assert!(
        changed(&w, 0, M::Move),
        "precondition: node 0 moved the peering"
    );
}

#[test]
fn one_view_fires_on_a_planted_identity() {
    let mut w = world_of(super::off, &[A, B], &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    let f = facts(&w, 0);
    assert!(
        check(&f).is_empty(),
        "precondition: nothing is wrong with the pair: {:?}",
        check(&f)
    );
    assert_eq!(f.peers.len(), 1, "precondition: node 0 holds node 1");
    let planted = |plant: &dyn Fn(&mut Shell)| {
        let mut g = f.clone();
        if let Some(s) = g.peers[0].shell.as_mut() {
            plant(s);
        }
        check(&g)
    };
    let fired = |found: Vec<(Oracle, String)>, what: &str| {
        assert!(
            found.iter().any(|(o, _)| *o == Oracle::OneView),
            "{what}: {found:?}"
        );
    };
    fired(
        planted(&|s| s.identity = Some(A)),
        "a machine of another identity is found",
    );
    fired(
        planted(&|s| s.identity = None),
        "a machine with no proven identity is found",
    );
    fired(
        planted(&|s| s.link = LinkNo(s.link.0 + 1)),
        "a machine built for another link is found",
    );
    fired(
        planted(&|s| s.epoch = Some([9; 8])),
        "a machine with another startup epoch is found",
    );
    assert!(
        planted(&|s| {
            s.epoch = Some([9; 8]);
            s.gated = true;
        })
        .is_empty(),
        "and not once the core's gates refused the restart it found"
    );
    assert!(
        planted(&|s| {
            s.epoch = Some([9; 8]);
            s.waiting = true;
        })
        .is_empty(),
        "nor while its own rekey that found it waits for its cutover"
    );
    fired(
        planted(&|s| s.current = Some(Hs(s.origin.0 + 1))),
        "a machine running another session before its first cutover is found",
    );
    assert!(
        planted(&|s| {
            s.current = Some(Hs(s.origin.0 + 1));
            s.cut = true;
        })
        .is_empty(),
        "and not after a cutover"
    );
    let mut g = f.clone();
    g.peers[0].shell = None;
    fired(check(&g), "a held peer with no machine is found");
}

#[test]
fn leases_fire_on_a_free_the_shell_lost() {
    // A rekey msg1 of a held peer: the core hands the answer's lease back,
    // and the shell returns its index to the pool.
    let mut w = world_of(super::off, &[A, B], &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    age(&mut w, 40_000);
    assert!(w.parties[0].rekeyable(B), "precondition: node 0 may rekey");
    let mut found = watched(&mut w, &[Act::Rekey(0, 1)]);
    settle(&mut w);
    found.extend(every_step(&w));
    let wrong = of(&found, Oracle::Leases);
    assert!(
        wrong.is_empty(),
        "every index is held by a leg or a machine: {wrong:?}"
    );
    let pending = w.parties[1].view().peers.first().and_then(|p| p.pending);
    assert!(
        pending.is_some(),
        "precondition: node 1 took node 0's rekey through its machine"
    );
}

#[test]
fn no_orphan_fires_on_a_machine_past_its_peer() {
    // The pair on the connection-oriented transport; node 0 sees the link's
    // one connection fail, and the core removes node 1.
    let mut w = world_of(super::off, &[A, B], &[&[(1, TCP)], &[]]);
    dial_home(&mut w, 0, 1, TCP);
    settle(&mut w);
    let c = w
        .net
        .conns
        .iter()
        .find(|c| c.ends[0].node == 0 && c.ends[0].remote == home(1, TCP))
        .map(|c| c.id)
        .expect("precondition: node 0's connection to node 1");
    let found = watched(&mut w, &[Act::Fail(c, 0)]);
    let wrong = of(&found, Oracle::NoOrphan);
    assert!(wrong.is_empty(), "no machine outlives its peer: {wrong:?}");
    assert!(
        !w.parties[0].held().contains(&B),
        "precondition: node 0's core removed node 1"
    );
}

#[test]
fn mirrored_fires_on_a_path_the_core_did_not_take() {
    use super::super::starts::second;
    use super::feeds::{arrive, beat, crossed, paired};
    // A roam at Off: node 1's frame from its second address moves node 0's
    // one path there.
    let mut w = paired(super::off);
    let pkt = beat(&mut w, 1, 0);
    arrive(&mut w, 0, second(1, UDP), pkt);
    let wrong = of(&every_step(&w), Oracle::Mirrored);
    assert!(
        wrong.is_empty(),
        "the core's record of the link follows its one path's roam: {wrong:?}"
    );
    let active = facts(&w, 0).peers[0].shell.as_ref().and_then(|s| s.active);
    assert_eq!(
        active,
        Some(second(1, UDP)),
        "precondition: node 0's one path roamed"
    );
    // A second path at On: a frame heard from node 1's TCP home makes the
    // pair a candidate, and both ends prove a path there.
    let w = crossed(super::on);
    for x in 0..2 {
        let wrong = of(&every_step(&w), Oracle::Mirrored);
        assert!(
            wrong.is_empty(),
            "the core's record of each link holds its bundle's two paths: {wrong:?}"
        );
        let held = facts(&w, x).peers[0]
            .shell
            .as_ref()
            .map_or(0, |s| s.paths.len());
        assert_eq!(held, 2, "precondition: node {x}'s bundle holds two paths");
    }
}

#[test]
fn delivered_matches_each_output_to_its_input() {
    use super::super::world::{Input, PathEv};
    use super::feeds::paired;
    // A replacement request: a fresh msg1 on a young link.
    let mut w = paired(super::off);
    dial_home(&mut w, 1, 0, UDP);
    let found = flushed(&mut w);
    let wrong = of(&found, Oracle::Delivered);
    assert!(
        wrong.is_empty(),
        "the replacement request reached the core: {wrong:?}"
    );
    assert!(
        classed(&w, 0, Class::Replacement),
        "precondition: node 0's machine asked for the replacement"
    );

    // An orphaned bundle: node 0's one transport goes, and its bundle has
    // no path left.
    let mut w = paired(super::off);
    w.input(0, Input::Path(PathEv::Gone { transport: UDP }));
    let wrong = of(&every_step(&w), Oracle::Delivered);
    assert!(
        wrong.is_empty(),
        "the orphaned bundle reached the core: {wrong:?}"
    );
    assert!(
        !w.parties[0].held().contains(&B),
        "precondition: node 0's core removed node 1 with its bundle orphaned"
    );

    // A restart found at a rekey's msg2.
    let mut w = paired(super::off);
    age(&mut w, 40_000);
    apply(&mut w, Act::Restart(1));
    apply(&mut w, Act::Rekey(0, 1));
    let mut found = flushed(&mut w);
    w.run_until(w.net.now + 1_000);
    found.extend(every_step(&w));
    found.extend(flushed(&mut w));
    let wrong = of(&found, Oracle::Delivered);
    assert!(
        wrong.is_empty(),
        "the restart the machine found reached the core: {wrong:?}"
    );
    assert!(
        changed(&w, 0, M::Restarted),
        "precondition: node 0's core took the restart"
    );
}

#[test]
fn attributed_reads_a_roamed_link_as_the_node_does() {
    use super::super::starts::second;
    use super::super::world::{Input, Pkt};
    use super::feeds::{arrive, beat, paired};
    // Multipath off: node 0's one path to node 1 roams to node 1's second
    // address; node 1's rekey msg1 then arrives from there, on the link's
    // one path, which is not its setup address.
    let mut w = paired(super::off);
    age(&mut w, 40_000);
    let pkt = beat(&mut w, 1, 0);
    arrive(&mut w, 0, second(1, UDP), pkt);
    w.net.flight.clear();
    w.input(1, Input::Rekey { peer: A });
    let i = w
        .net
        .flight
        .iter()
        .position(|f| f.to == 0 && matches!(f.pkt, Pkt::Msg1 { .. }))
        .expect("precondition: node 1 sends a rekey msg1");
    let msg1 = w.net.flight.remove(i).pkt;
    arrive(&mut w, 0, second(1, UDP), msg1);
    let wrong = of(&every_step(&w), Oracle::Attributed);
    assert!(
        wrong.is_empty(),
        "the msg1 on the roamed path is on the link to the core as to the node: {wrong:?}"
    );
    assert!(
        classed(&w, 0, Class::Rekey),
        "precondition: node 0's machine took the msg1 as a rekey"
    );
}

/// Whether one of `found` says `what`.
fn says(found: &[String], what: &str) -> bool {
    found.iter().any(|m| m.contains(what))
}

/// Node 0's machines for node 1 at `mode`, set up on UDP at instant 0,
/// with node 0's kit.
fn machined(mode: super::Mode) -> (super::machines::Machines, super::machines::Kit) {
    use super::machines::{Machines, exchange, kits, unused};
    let (mut ka, mut kb) = kits();
    let ((sa, ra), (sb, _), _) = exchange(&mut ka, &mut kb, B, Hs(0x0101_0001));
    unused(&mut kb, sb);
    let (m, _) = Machines::fresh(&mut ka, 0, B, mode, sa, ra, home(1, UDP), home(0, UDP));
    (m, ka)
}

#[test]
fn each_machine_predicate_fires_on_a_planted_state() {
    use super::machines::Event as Done;
    use crate::proto::rekey::tests::oracles::{Change, Owed};
    use crate::proto::rekey::tests::stub::read_msg1;
    use crate::proto::rekey::{Msg1Read, Output, RECORD_BOUND, Role};
    let l = Limits {
        budget: 30_000,
        retention: 60_000,
    };
    let (mut m, mut ka) = machined(super::Mode::Off);

    // Bounded memory and key retention, on a planted reading.
    let rk = m.rekey();
    assert!(
        machine(0, rk, &rk.peek(), 1_000, false, None, l).is_empty(),
        "precondition: a new machine keeps every rule"
    );
    let mut p = rk.peek();
    p.record = RECORD_BOUND + 2;
    assert!(
        says(&machine(0, rk, &p, 1_000, false, None, l), "record holds"),
        "a record over its bound is found"
    );
    let mut p = rk.peek();
    let started = p.current.as_ref().map(|c| c.started.0).unwrap_or(0);
    p.drain_end = Some(TestInstant(started + l.retention + 1));
    assert!(
        says(
            &machine(0, rk, &p, 1_000, false, None, l),
            "keeps a previous epoch"
        ),
        "a previous epoch kept past its ceiling is found"
    );

    // The deadlines, after a poll: a next wake not ahead of it, and an own
    // attempt past its budget.
    let wake = rk
        .next_wake()
        .map(|t| t.0)
        .expect("precondition: the time trigger is a wake");
    assert!(
        says(
            &machine(0, rk, &rk.peek(), wake, true, None, l),
            "is not after the poll"
        ),
        "a next wake that is not after the poll is found"
    );
    let _ = m.trigger(&mut ka, 40_000, Hs(0x0101_0002));
    let rk = m.rekey();
    assert_eq!(
        rk.view().cycle,
        crate::proto::rekey::CycleView::Init,
        "precondition: an own attempt is in flight"
    );
    assert!(
        says(
            &machine(0, rk, &rk.peek(), 40_000 + l.budget, true, Some(40_000), l),
            "outlived its deadline"
        ),
        "an own attempt past its budget is found"
    );

    // Conservation, on a node that holds two peers.
    let st = start(11);
    let mut w = replay(&st, &[]);
    let _ = (st.script)(&mut w);
    settle(&mut w);
    let x = (0..w.parties.len())
        .find(|&x| w.parties[x].held().len() == 2)
        .expect("precondition: a node of the three holds two peers");
    let f = facts(&w, x);
    let bound = f.legs.len() + f.bound.len();
    assert!(
        node(x, f.pool.len(), bound).is_empty(),
        "precondition: the node's indices are its machines' and legs'"
    );
    assert!(
        says(
            &node(x, f.pool.len(), bound + 1),
            "indices, its machine and legs"
        ),
        "an index nothing holds is found"
    );

    // Around one delivery.
    let msg = super::names::msg1(
        B,
        super::super::super::model::history::Epoch(u32::from(B.0) << 8),
        A,
        Hs(0x0201_0003),
        super::names::index(Hs(0x0201_0003)),
    );
    let e = read_msg1(&ka.local, &msg)
        .expect("the msg1 reads")
        .get()
        .ephemeral();
    let hs = Hs(0x0201_0003);
    let armed = Change {
        armed: true,
        refreshed: false,
        changed: true,
    };
    let still = Change {
        armed: false,
        refreshed: false,
        changed: false,
    };
    let moved = Change {
        armed: false,
        refreshed: false,
        changed: true,
    };
    let mut owed = Owed::default();
    assert!(
        took(0, hs, false, false, &mut owed, Some(&e), &armed, &[]).is_empty(),
        "precondition: a first msg1 may arm a pending"
    );
    assert!(
        says(
            &took(0, hs, false, false, &mut owed, Some(&e), &armed, &[]),
            "armed a pending from a msg1 its record holds"
        ),
        "a msg1 the record owes that arms a pending is found"
    );
    assert!(
        took(0, hs, true, false, &mut owed, Some(&e), &still, &[]).is_empty(),
        "precondition: a copy that changes nothing keeps the rules"
    );
    assert!(
        says(
            &took(0, hs, true, false, &mut owed, Some(&e), &moved, &[]),
            "changed the state"
        ),
        "a copy of a msg1 taken before that changes the state is found"
    );
    let refreshed = Change {
        armed: true,
        refreshed: true,
        changed: true,
    };
    assert!(
        says(
            &took(
                0,
                hs,
                true,
                false,
                &mut Owed::default(),
                Some(&e),
                &refreshed,
                &[]
            ),
            "refreshed liveness"
        ),
        "a residual replay that refreshes liveness is found"
    );
    let cut = [Done::Rekey(Output::Rekeyed {
        role: Role::Responder,
    })];
    assert!(
        says(
            &took(
                0,
                hs,
                true,
                false,
                &mut Owed::default(),
                Some(&e),
                &armed,
                &cut
            ),
            "a residual replay"
        ),
        "a residual replay that cuts over is found"
    );
    assert!(
        says(
            &took(0, hs, true, true, &mut Owed::default(), None, &moved, &[]),
            "changed the state"
        ),
        "a repeated reply that changes the state is found"
    );
    m.close(&mut ka, 40_000, crate::proto::rekey::Close::Admin);
}

#[test]
fn each_path_check_fires_on_a_planted_output() {
    use super::facts::pair;
    use crate::proto::path::{Input as PathInput, Output as PathOutput, PathState};
    // Multipath off: a poll before any wake that does nothing keeps every
    // rule; a connection asked for, or a poll that reports anything, does
    // not.
    let (mut m, ka) = machined(super::Mode::Off);
    let poll = PathInput::Poll;
    assert_eq!(
        m.plant(&ka, 1_000, &poll, &[]),
        Ok(()),
        "precondition: an early poll that does nothing keeps every rule"
    );
    let connect = PathOutput::Connect {
        to: pair(home(1, TCP)),
    };
    assert!(
        m.plant(&ka, 1_000, &poll, &[connect]).is_err(),
        "a connection asked for with multipath off is found"
    );
    assert!(
        m.plant(&ka, 1_000, &poll, &[PathOutput::Capable]).is_err(),
        "a poll before the next wake that reports anything is found"
    );
    let mut ka = ka;
    m.close(&mut ka, 1_000, crate::proto::rekey::Close::Admin);
    // Multipath on: the bundle orphaned twice.
    let (mut m, mut ka) = machined(super::Mode::On);
    assert_eq!(
        m.bundle().paths().get(0).map(|p| p.state()),
        Some(PathState::Live),
        "precondition: the original path is Live"
    );
    let carrier = PathInput::Carrier {
        transport: pair(home(1, TCP)).transport,
        up: true,
    };
    assert!(
        m.plant(
            &ka,
            1_000,
            &carrier,
            &[PathOutput::Orphaned, PathOutput::Orphaned]
        )
        .is_err(),
        "a bundle orphaned twice is found"
    );
    m.close(&mut ka, 1_000, crate::proto::rekey::Close::Admin);
}
