//! The settlement properties, checked on the world.
//!
//! Seven oracles, one per property of the settlement plan, in its order:
//!
//! - [`Oracle::OneSession`]: once healed, two nodes that hold each other
//!   hold one session, and a frame sealed now under each end's current
//!   session would open at the other (asked of the parties, nothing
//!   delivered, no counter read); and neither holds a responder pending
//!   the other end has no handshake able to adopt. A node also holds each
//!   peer it is configured to dial.
//! - [`Oracle::RightLink`]: the peer's link record is the link its
//!   session's handshake was set up on, and the smaller node of a pair
//!   whose own dial of the peer was answered is not left on an inbound
//!   link (FRC-1201 Section 5.6's tie-break).
//! - [`Oracle::MapsAgree`]: the party's own maps agree with each other.
//! - [`Oracle::ConnectionsInUse`]: once healed, every open connection is
//!   one a live link of its node uses, and every connection a live link
//!   uses is open.
//! - [`Oracle::Fresh`]: each peer change is the model's, step by step.
//! - [`Oracle::Classified`]: each msg1 is classified and gated as the model
//!   says.
//! - [`Oracle::Bounded`]: what a party keeps stays within its bounds.
//!
//! A joint node (`joint/`) is held to more, which the stand-in core's
//! party holds by construction or does not model, each checked at every
//! step over what the node gives in [`super::world::Party::joint`]
//! (`joint/oracle.rs`):
//!
//! - [`Oracle::OneView`]: one rekey machine for each peer the core holds,
//!   built or carried at the install of the link the core holds it on, for
//!   that peer, with the core's record of the peer's startup epoch, and,
//!   until its first cutover, running the session of that install's
//!   handshake.
//! - [`Oracle::Leases`]: every session index the node's pool has handed
//!   out is held by a handshake leg or a rekey machine.
//! - [`Oracle::NoOrphan`]: a rekey machine and bundle for every peer the
//!   core holds, and for no other.
//! - [`Oracle::Mirrored`]: the core's record of each held link's paths is
//!   its bundle's, and the index is derived from the records.
//! - [`Oracle::Delivered`]: every replacement request, restart and
//!   teardown of a rekey machine and every orphaning of a bundle reached
//!   the core in the step that emitted it, and nothing else fed those
//!   inputs.
//! - [`Oracle::Attributed`]: each msg1 the core took as a held peer's is
//!   on that peer's link exactly where the node's rule puts it.
//! - [`Oracle::Machine`]: the rekey machines' and the bundles' own
//!   oracles, from their simulators' predicates, the text naming which;
//!   among them, once healed, the two machines of each pair converged on
//!   one session with nothing in progress, which a sweep exempts where it
//!   exempts a split.
//!
//! Three clauses of those, where the core is known to part from the
//! bundle or the node, are pinned, not asserted: counted, printed by a
//! sweep and held by the failing tests of `joint/pins.rs`.
//!
//! `RightLink`, `MapsAgree`, `Fresh`, `Classified`, `Bounded` and a joint
//! node's own hold at every step. `OneSession` and `ConnectionsInUse` hold once the world is
//! healed ([`heal`]): every connect window opened, everything in flight
//! delivered, and the clocks run wake by wake for [`HEAL`] with no fault.
//! The horizon is shorter than the rekey machine's pending hold, so a
//! pending left for its hold to clear is still seen. The model and the
//! stand-in core's party run no link-dead timer, so there two ends left on
//! different sessions stay that way, and a node holding a peer the other
//! end has forgotten is left to that timer and is not a breach. A joint
//! node runs the node's liveness timer (`joint/party.rs`), so a peer whose
//! link authenticates nothing for the link-dead timeout is removed within
//! the heal.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::explore::{Check, Stats, explore, replay};
use super::shadow;
use super::starts::Start;
use super::world::{Dir, Kind, Ms, State, View, World};

/// How long a heal runs.
pub const HEAL: Ms = 60_000;

/// The seven properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Oracle {
    /// One session, and no pending left unadoptable.
    OneSession,
    /// The right link.
    RightLink,
    /// The maps agree.
    MapsAgree,
    /// Connections in use.
    ConnectionsInUse,
    /// Each peer change is the model's.
    Fresh,
    /// Each msg1's class and gate are the model's.
    Classified,
    /// Bounds.
    Bounded,
    /// One rekey machine for each held peer, agreeing with the core.
    OneView,
    /// Every index lease held by a leg or a machine.
    Leases,
    /// No machine without a held peer, and no held peer without one.
    NoOrphan,
    /// Each held link's paths in the core are its bundle's.
    Mirrored,
    /// Each machine output the core must hear of reached it.
    Delivered,
    /// Each held peer's msg1 attributed to its link as the node does.
    Attributed,
    /// A rekey machine's or a bundle's own oracle.
    Machine,
}

/// One breach.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Breach {
    /// The property.
    pub oracle: Oracle,
    /// The node index it was found at.
    pub node: usize,
    /// What was found.
    pub what: String,
}

fn breach(oracle: Oracle, node: usize, what: String) -> Breach {
    Breach { oracle, node, what }
}

/// The properties that hold at every step.
pub fn every_step(w: &World) -> Vec<Breach> {
    let mut out = Vec::new();
    for (x, p) in w.parties.iter().enumerate() {
        let v = p.view();
        right_link(x, &v, &mut out);
        for a in &v.audit {
            out.push(breach(Oracle::MapsAgree, x, a.clone()));
        }
        for &(name, size, bound) in &v.bounds {
            if size > bound {
                out.push(breach(
                    Oracle::Bounded,
                    x,
                    format!("{name}: {size}, over {bound}"),
                ));
            }
        }
        if let Some(f) = p.joint() {
            for (oracle, what) in super::joint::oracle::check(&f) {
                out.push(breach(oracle, x, what));
            }
        }
        if !v.log.is_empty() {
            for d in shadow::compare(v.me, &v.log).diffs {
                let oracle = if d.classified {
                    Oracle::Classified
                } else {
                    Oracle::Fresh
                };
                out.push(breach(oracle, x, format!("{:?}: {}", d.peer, d.what)));
            }
        }
    }
    out
}

fn right_link(x: usize, v: &View, out: &mut Vec<Breach>) {
    if fault!(RightLinkOff) {
        return;
    }
    for p in &v.peers {
        if fault!(RightLinkPairOnly) {
            // The defect's shape: only the link's address against the
            // peer's, which two links at one pair cannot tell apart.
            if p.at != p.current {
                out.push(breach(
                    Oracle::RightLink,
                    x,
                    format!("{:?}: link at {:?}, peer at {:?}", p.peer, p.at, p.current),
                ));
            }
            continue;
        }
        if p.link != p.origin {
            out.push(breach(
                Oracle::RightLink,
                x,
                format!(
                    "{:?}: link set up by {:?}, session from {:?}",
                    p.peer, p.link, p.origin
                ),
            ));
        }
        if !fault!(RightLinkNoDirection) && v.me < p.peer && p.dir == Dir::Inbound && p.answered {
            out.push(breach(
                Oracle::RightLink,
                x,
                format!(
                    "{:?}: the smaller node's dial was answered, link inbound",
                    p.peer
                ),
            ));
        }
    }
}

/// The properties that hold once the world is healed.
pub fn healed(w: &World) -> Vec<Breach> {
    let mut out = Vec::new();
    let views: Vec<View> = w.parties.iter().map(|p| p.view()).collect();
    for (x, v) in views.iter().enumerate() {
        for c in &v.configured {
            if !v.peers.iter().any(|p| p.peer == *c) {
                out.push(breach(
                    Oracle::OneSession,
                    x,
                    format!("held: {c:?} is configured and not held"),
                ));
            }
        }
        for p in &v.peers {
            let Some(y) = w.index(p.peer) else {
                continue;
            };
            let Some(q) = views[y].peers.iter().find(|q| q.peer == v.me) else {
                continue;
            };
            if x < y && !fault!(OneSessionNoSplit) && p.cur != q.cur {
                out.push(breach(
                    Oracle::OneSession,
                    x,
                    format!("split: {:?}: {:?} here, {:?} there", p.peer, p.cur, q.cur),
                ));
            }
            if !fault!(OneSessionNoFresh) && !w.parties[y].holds(v.me, p.cur) {
                out.push(breach(
                    Oracle::OneSession,
                    x,
                    format!(
                        "fresh: {:?}: a frame under {:?} would not open there",
                        p.peer, p.cur
                    ),
                ));
            }
            if x < y
                && let (Some(a), Some(b)) = (w.parties[x].rekey(p.peer), w.parties[y].rekey(v.me))
                && let Err(m) =
                    crate::proto::rekey::tests::oracles::converged(Some(a), Some(b), w.net.now)
            {
                out.push(breach(Oracle::Machine, x, format!("{m} ({:?})", p.peer)));
            }
            if let Some((hs, false)) = p.pending
                && !fault!(OneSessionNoPending)
                && q.rekey != Some(hs)
                && q.pending.map(|(h, _)| h) != Some(hs)
                && q.cur != hs
                && !q.dials.contains(&hs)
            {
                out.push(breach(
                    Oracle::OneSession,
                    x,
                    format!("pending: {:?}: {hs:?}, which the peer cannot adopt", p.peer),
                ));
            }
        }
    }
    if !fault!(OneSessionNoSplit) {
        for &(x, peer) in &w.ended {
            out.push(breach(
                Oracle::OneSession,
                x,
                format!(
                    "split: {peer:?}: held there on another session, removed here by the link-dead timer"
                ),
            ));
        }
    }
    for c in &w.net.conns {
        if c.state != State::Open || w.net.kind(c.ends[0].remote.transport) == Kind::Datagram {
            continue;
        }
        for e in c.ends {
            if !views[e.node].needs.contains(&e.remote) {
                out.push(breach(
                    Oracle::ConnectionsInUse,
                    e.node,
                    format!("c{} to {:?} open, no link uses it", c.id, e.remote),
                ));
            }
        }
    }
    out.extend(needs_open(w));
    out
}

/// The second clause of [`Oracle::ConnectionsInUse`]: every connection a
/// live link of its node uses is open. [`healed`] checks it once healed;
/// a test may read it at a step it names, where a sweep cannot see a
/// connection a live link still needed being closed, since by the heal
/// the link that needed it is gone.
pub fn needs_open(w: &World) -> Vec<Breach> {
    let mut out = Vec::new();
    for (x, p) in w.parties.iter().enumerate() {
        for at in p.view().needs {
            if w.net.kind(at.transport) != Kind::Datagram && w.net.conn(x, at).is_none() {
                out.push(breach(
                    Oracle::ConnectionsInUse,
                    x,
                    format!("{at:?} in use, its connection closed"),
                ));
            }
        }
    }
    out
}

/// Heal `w`: no more faults, every connect window opens, everything in
/// flight is delivered, and the clocks run wake by wake for [`HEAL`].
pub fn heal(w: &mut World) {
    let end = w.net.now + HEAL;
    loop {
        super::starts::settle(w);
        match w.wake() {
            Some(t) if t <= end => w.advance(),
            _ => break,
        }
    }
    w.net.now = w.net.now.max(end);
    super::starts::settle(w);
}

/// Whether a breach at a healed world is exempt: a split on a path that
/// showed one of the known shapes.
pub type Exempt<'a> = &'a (dyn Fn(&World, &Breach) -> bool + Sync);

/// The exemption of the model's convergence with itself: a `OneSession`
/// breach on a path where a known shape other than the two defects left
/// for later was seen. Nothing else is exempt.
pub fn by_shape(w: &World, b: &Breach) -> bool {
    converging(b) && w.shapes.iter().any(|s| !s.pinned())
}

/// Whether `b` is a breach of convergence: a split or another clause of
/// one session, or a joint pair's machines not converged.
fn converging(b: &Breach) -> bool {
    b.oracle == Oracle::OneSession
        || (b.oracle == Oracle::Machine && b.what.starts_with(super::joint::oracle::CONVERGED))
}

/// The exemption of the runs against the models of deployed nodes: a
/// `OneSession` breach on a path where any known shape was seen, the two
/// defects left for later included.
#[cfg(feature = "slow-explorers")]
pub fn by_any_shape(w: &World, b: &Breach) -> bool {
    converging(b) && !w.shapes.is_empty()
}

/// What a sweep found: the explorer's statistics, the first breach of each
/// oracle at each node with its path, how many healed leaves had a breach
/// exempted, per shape, and how many explored states showed each pinned
/// clause of the joint world's oracles.
pub struct Swept {
    /// The explorer's statistics.
    pub stats: Stats,
    /// The first breach of each oracle at each node, with its path.
    pub found: Vec<(Breach, Vec<super::explore::Act>)>,
    /// Leaves with an exempted breach, by the shapes their path showed.
    pub exempted: Vec<(Vec<super::world::Shape>, usize)>,
    /// Explored states showing each pinned clause, by clause.
    pub pinned: Vec<(super::joint::oracle::Pin, usize)>,
}

/// Every breach on the path of `st` to depth `depth`, and at its leaves
/// once healed, with the shortest path to each, keyed by oracle and node;
/// a breach `exempt` names is counted instead.
pub fn sweep(st: &Start, depth: usize, exempt: Exempt<'_>) -> Swept {
    let found = std::sync::Mutex::new(Vec::new());
    let pins = std::sync::Mutex::new(Vec::<(super::joint::oracle::Pin, usize)>::new());
    let check = |w: &World, path: &[super::explore::Act]| -> Result<(), String> {
        let mut f = found.lock().unwrap_or_else(|e| e.into_inner());
        for b in every_step(w) {
            note(&mut f, b, path);
        }
        drop(f);
        let mut seen: Vec<super::joint::oracle::Pin> = super::joint::oracle::pinned_in(w)
            .into_iter()
            .map(|(_, pin, _)| pin)
            .collect();
        seen.sort_unstable();
        seen.dedup();
        if !seen.is_empty() {
            let mut p = pins.lock().unwrap_or_else(|e| e.into_inner());
            for pin in seen {
                match p.iter_mut().find(|(q, _)| *q == pin) {
                    Some((_, n)) => *n += 1,
                    None => p.push((pin, 1)),
                }
            }
        }
        Ok(())
    };
    let stats = explore(st, depth, &check as Check<'_>);
    let mut f = found.into_inner().unwrap_or_else(|e| e.into_inner());
    let mut exempted: Vec<(Vec<super::world::Shape>, usize)> = Vec::new();
    for path in &stats.leaves {
        let mut w = replay(st, path);
        heal(&mut w);
        let mut spared = false;
        for b in every_step(&w).into_iter().chain(healed(&w)) {
            if exempt(&w, &b) {
                spared = true;
            } else {
                note(&mut f, b, path);
            }
        }
        if spared {
            match exempted.iter_mut().find(|(s, _)| *s == w.shapes) {
                Some((_, n)) => *n += 1,
                None => exempted.push((w.shapes.clone(), 1)),
            }
        }
    }
    if std::env::var_os("FIPS_SETTLE_EXPLORE_TRACE").is_some() {
        for (b, path) in &f {
            let mut w = super::explore::replay_logged(st, path, true);
            heal(&mut w);
            std::eprintln!(
                "{}: {:?} at n{}: {}\n{}",
                st.name,
                b.oracle,
                b.node,
                b.what,
                w.net.log.join("\n")
            );
        }
    }
    let mut pinned = pins.into_inner().unwrap_or_else(|e| e.into_inner());
    pinned.sort_unstable();
    Swept {
        stats,
        found: f,
        exempted,
        pinned,
    }
}

/// Keep the first breach of each oracle at each node.
fn note(f: &mut Vec<(Breach, Vec<super::explore::Act>)>, b: Breach, path: &[super::explore::Act]) {
    if !f
        .iter()
        .any(|(g, _)| g.oracle == b.oracle && g.node == b.node)
    {
        f.push((b, path.to_vec()));
    }
}

/// Run `steps` on `w`, checking every step, then heal and return every
/// breach seen on the way and after.
pub fn follow(w: &mut World, steps: &[super::starts::Do]) -> Vec<Breach> {
    let mut out = every_step(w);
    for d in steps {
        super::starts::run(w, core::slice::from_ref(d));
        out.extend(every_step(w));
    }
    heal(w);
    out.extend(every_step(w));
    out.extend(healed(w));
    out
}

/// Run `st`'s script from its start, checking every step, then heal and
/// return every breach seen on the way and after.
pub fn scripted(st: &Start) -> Vec<Breach> {
    let mut scratch = replay(st, &[]);
    let acts = (st.script)(&mut scratch);
    let mut w = replay(st, &[]);
    let mut out = every_step(&w);
    for a in acts {
        super::explore::apply(&mut w, a);
        out.extend(every_step(&w));
    }
    heal(&mut w);
    out.extend(every_step(&w));
    out.extend(healed(&w));
    out
}

/// A node whose view and keys a test sets.
struct Planted {
    view: View,
    keys: Vec<(
        super::super::model::history::Node,
        super::super::model::history::Hs,
    )>,
}

impl super::world::Party for Planted {
    fn input(&mut self, _: &mut super::world::Net, _: super::world::Input) {}
    fn wake(&self) -> Option<Ms> {
        None
    }
    fn digest(&self) -> String {
        format!("{:?}", self.view)
    }
    fn holds(
        &self,
        peer: super::super::model::history::Node,
        hs: super::super::model::history::Hs,
    ) -> bool {
        self.keys.contains(&(peer, hs))
    }
    fn held(&self) -> Vec<super::super::model::history::Node> {
        self.view.peers.iter().map(|p| p.peer).collect()
    }
    fn rekeyable(&self, _: super::super::model::history::Node) -> bool {
        false
    }
    fn view(&self) -> View {
        self.view.clone()
    }
    fn epoch(&self) -> super::super::model::history::Epoch {
        super::super::model::history::Epoch(0)
    }
}

#[cfg(test)]
mod checks {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    use super::super::super::model::history::{Hs, Node};
    use super::super::starts::{A, B, UDP, home, starts};
    use super::super::world::{Dir, Kind, Net, Party, PeerView, View, World};
    use super::*;

    /// One held peer, on the link of `link`, its session from `origin`.
    fn peer(peer: Node, cur: u32, link: u32, dir: Dir, answered: bool) -> PeerView {
        PeerView {
            peer,
            cur: Hs(cur),
            origin: Hs(cur),
            link: Hs(link),
            dir,
            at: home(0, UDP),
            current: home(0, UDP),
            answered,
            pending: None,
            rekey: None,
            dials: Vec::new(),
        }
    }

    /// A world of two planted nodes, A and B.
    fn planted(a: PeerView, b: PeerView, keys: [Vec<(Node, Hs)>; 2]) -> World {
        let [ka, kb] = keys;
        let mut va = View::empty(A);
        va.peers.push(a);
        let mut vb = View::empty(B);
        vb.peers.push(b);
        let parties: Vec<Box<dyn Party>> = alloc::vec![
            Box::new(Planted { view: va, keys: ka }),
            Box::new(Planted { view: vb, keys: kb }),
        ];
        World::new(
            parties,
            alloc::vec![A, B],
            Net::new(
                &[(UDP, Kind::Datagram)],
                alloc::vec![Vec::new(), Vec::new()],
            ),
        )
    }

    #[test]
    fn right_link_fires_when_both_ends_of_a_crossing_settle_on_the_larger_nodes_dial() {
        // One session, on the link its handshake ran on at both ends; but
        // that handshake is the larger node's dial, so the smaller node,
        // whose own dial was answered, is left inbound.
        let w = planted(
            peer(B, 2, 2, Dir::Inbound, true),
            peer(A, 2, 2, Dir::Outbound, true),
            [alloc::vec![(B, Hs(2))], alloc::vec![(A, Hs(2))]],
        );
        let found = every_step(&w);
        assert!(
            found
                .iter()
                .any(|b| b.oracle == Oracle::RightLink && b.node == 0),
            "the smaller node's direction is a breach: {found:?}"
        );
        assert!(
            healed(&w).is_empty(),
            "nothing else is wrong with the state"
        );
    }

    #[test]
    fn one_session_fires_on_complementary_indices_with_no_fresh_frame() {
        // Both ends name one session, and neither can open a frame under
        // it: indices that agree are not a session that works.
        let w = planted(
            peer(B, 1, 1, Dir::Outbound, true),
            peer(A, 1, 1, Dir::Inbound, false),
            [Vec::new(), Vec::new()],
        );
        let found = healed(&w);
        assert!(
            found
                .iter()
                .any(|b| b.oracle == Oracle::OneSession && b.what.starts_with("fresh:")),
            "the probe sees no frame would open: {found:?}"
        );
    }

    #[test]
    fn a_replacement_over_another_connection_closes_the_replaced_links_connection() {
        // The crossing on the connection-oriented transport with every
        // frame and the first msg2s lost: node 0 replaces its unheard
        // peering with node 1's dial, loses its link and redials, and node
        // 1 replaces with that redial. Node 1's end of node 0's first
        // connection then carries no link, and the replacement closes it.
        use super::super::explore::Act;
        let st = starts()
            .into_iter()
            .find(|s| s.number == 3)
            .expect("start 3");
        let mut path = alloc::vec![Act::Deliver(0), Act::Deliver(1)];
        path.extend([Act::Advance; 5]);
        let mut w = replay(&st, &path);
        heal(&mut w);
        assert_eq!(
            w.parties[1].held(),
            [A],
            "precondition: the pair is up again"
        );
        let left: Vec<Breach> = healed(&w)
            .into_iter()
            .filter(|b| b.oracle == Oracle::ConnectionsInUse)
            .collect();
        assert!(
            left.is_empty(),
            "no connection is left without a link: {left:?}"
        );
    }

    #[test]
    fn model_parties_settle_on_every_start() {
        // The model with the operator's late-dial rule, as both ends of
        // every start but the aged link (where the model is undecided) and
        // the two paths (which the model does not know): every property at
        // every step, and once healed at every leaf. A split on a path that
        // showed a known shape is counted, not failed; the observation
        // tests below show each shape.
        let all: Vec<_> = starts()
            .into_iter()
            .filter(|s| !matches!(s.number, 7 | 12))
            .collect();
        let report = std::thread::scope(|sc| {
            let hs: Vec<_> = all
                .iter()
                .map(|st| {
                    sc.spawn(move || {
                        let t = std::time::Instant::now();
                        let swept = sweep(st, st.depth, &by_shape);
                        (swept, t.elapsed().as_millis())
                    })
                })
                .collect();
            hs.into_iter()
                .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
                .collect::<Vec<_>>()
        });
        let mut wrong = Vec::new();
        for (st, (swept, ms)) in all.iter().zip(report) {
            std::eprintln!(
                "settle {:>2} {}: {} states, {} leaves healed in {ms} ms, exempted {:?}",
                st.number,
                st.name,
                swept.stats.states,
                swept.stats.leaves.len(),
                swept.exempted
            );
            for (b, path) in swept.found {
                wrong.push(format!(
                    "{}: {:?} at n{}: {}\n  path {path:?}",
                    st.name, b.oracle, b.node, b.what
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn classified_fires_on_a_refusal_the_model_does_not_make() {
        use super::super::super::model::history::{Binding, Bytes, Epoch, Event, LinkId};
        use super::super::super::model::judge::{Class, Gate};
        use super::super::shadow::{Entry, Rec, Refusal};
        // A first msg1 of a peer the node does not hold, the same class the
        // model gives it, and a refusal the model does not make.
        let msg1 = Event::Msg1 {
            hs: Hs(1),
            bytes: Bytes(1),
            epoch: Epoch(1),
            link: LinkId(1),
            from: home(1, UDP),
            binding: Binding::Connectionless,
            sent: true,
        };
        let mut view = View::empty(A);
        view.log.push(Entry::Ev {
            at: 0,
            peer: B,
            ev: msg1,
            rec: Rec {
                class: Some(Class::NotHeld),
                refused: Some(Refusal::Gate(Gate::Heard)),
                ..Rec::default()
            },
        });
        let parties: Vec<Box<dyn Party>> = alloc::vec![Box::new(Planted {
            view,
            keys: Vec::new()
        })];
        let w = World::new(
            parties,
            alloc::vec![A],
            Net::new(&[(UDP, Kind::Datagram)], alloc::vec![Vec::new()]),
        );
        let found = every_step(&w);
        assert!(
            found.iter().any(|b| b.oracle == Oracle::Classified),
            "a refusal the model does not make is a difference of class: {found:?}"
        );
    }
}
