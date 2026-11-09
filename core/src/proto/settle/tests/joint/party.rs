//! A joint node: the settlement core, with a real rekey machine and a real
//! path bundle per held peer, as a node of the world.
//!
//! [`JointParty`] has the stand-in core party's structure (`../stub.rs`):
//! one core [`Table`] and a stub shell that carries out its outputs front
//! to back, sends the handshake messages and frames, closes what the core
//! closes on transports that hold connections, and supplies what the core
//! leaves to the node (the heartbeat, the reconnect, the close of an
//! inbound connection whose msg1 left nothing that uses it, and the
//! world's adapter close of a replaced link's connection). In place of the
//! stand-in's transcribed rekey side, each held peer has a [`Machines`]:
//! its `Rekey<Ik>` and its `Bundle`, built at an install, rebuilt and
//! renewed at a move and closed at a removal as the node does.
//!
//! The handshake messages and frames are real stub IK messages, carried as
//! a packet's wire bytes beside its abstract fields. Each ephemeral is
//! drawn from a world name (`names.rs`), and the node keeps the one-to-one
//! map from handshake names to the sessions they made, so what a machine
//! holds reads as world names. The index leases are drawn from and freed
//! into the node's own index pool; the replay records of closed links are
//! filed in the node's record store.
//!
//! One rule for the peer's address: wherever the shell sends to the peer,
//! asks whether its link is reachable, or counts what its link uses, the
//! address is the bundle's active path, as the node's is (`current_addr`),
//! never the core's `Held.current`.
//!
//! On every call the shell checks the core's own promises and the
//! machines', and reports a broken one as an incoherence of its maps: no
//! lease is dropped unreleased, the transport-address index equals its
//! recomputation, a poll before the core's next wake does nothing, every
//! frame the world let through opens or is refused only as a replay, and
//! the index map equals what the machines bind. It logs every history event and what the core and the
//! machine decided, as the stand-in does, for the shadow.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use crate::identity::NodeAddr;
use crate::proto::fmp::EphemeralDigest;
use crate::proto::path::{Input as PathInput, PathState, Source};
use crate::proto::rekey::tests::stub::{Hs as Attempt, Ik, Kid, Msg1, hint, kid, read_msg1};
use crate::proto::rekey::{
    self, Authentic, Completed, CycleView, EpochTag, Msg1Read, Profile, Reason, Record,
    RecordStore, Replayable, Role as Side, Route, allocate, leaked,
};
use crate::proto::settle::input::{Dial as Dialed, Hello, Input as In};
use crate::proto::settle::links::{Dir as LinkDir, Holder, LinkNo, Proven};
use crate::proto::settle::output::{Build, Install, Output, Why};
use crate::proto::settle::params::Params;
use crate::proto::settle::table::Table;
use crate::testutil::TestInstant;

use super::super::super::model::history::{Addr, Bytes, Epoch, Event, Hs, LinkId, Node};
use super::super::super::model::judge::{Class, Transition as M};
use super::super::drive::{addr, change, class, pair, refusal};
use super::super::explore::THIRD;
use super::super::oracle::Oracle;
use super::super::party::{Configured, binding};
use super::super::shadow::{Entry, Rec, Refusal};
use super::super::starts::{A, B, C};
use super::super::world::{
    Dir, HANDSHAKE, HEARTBEAT, Input, Kind, Ms, Net, Party, PathEv, PeerView, Pkt, RETRY,
    State as Link, View,
};
use super::Mode;
use super::feeds::{self, Listings};
use super::machines::{Event as Ev, Kit, Machines, Setup, messaged};
use super::names::{self, Names};
use super::oracle::{Ledger, Limits, Pin, Told};
use super::route::{self, Ctx, Routed, Send, route};
use crate::proto::rekey::tests::oracles::{Before, Owed};
use crate::transport::TransportId;

/// The plaintext of every frame the shell sends: the stub link's
/// heartbeat, as long as the link's floor.
const BEAT: &[u8] = &[0x51, 0, 0, 0, 0];

/// What a link's handshake is to this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// This node's own dial of `to`, from `from`.
    Dial { to: Addr, from: Option<Addr> },
    /// An answer to the peer's msg1.
    Answer,
}

/// The handshake a core link was opened for.
#[derive(Debug)]
struct Run {
    hs: Hs,
    peer: Node,
    role: Role,
    /// The msg1's abstract bytes.
    bytes: Bytes,
    /// The epoch its msg1 or msg2 carried.
    epoch: Option<Epoch>,
    /// The msg1 on the wire.
    msg1: Vec<u8>,
    /// This node's address on the handshake's path.
    local: Addr,
    /// This node's handshake state, for a dial.
    state: Option<Attempt>,
    /// The completed handshake, until an install takes it.
    done: Option<Completed<Ik>>,
    /// The setup record a responder notes at its install.
    record: Option<Record>,
    /// The index of the lease the leg holds.
    index: u32,
}

/// A peer the core holds, as the shell keeps it.
#[derive(Debug)]
struct Held {
    machines: Machines,
    /// The link the peer was installed or moved onto.
    link: LinkNo,
    /// The handshake of that link.
    origin: Hs,
    /// One of this node's own dials of the peer was answered while it was
    /// held, or installed it.
    answered: bool,
    beat: Ms,
    /// This node's own rekey msg1: its name and its bytes.
    own: Option<(Hs, Vec<u8>)>,
    /// When an authentic frame of the peer last arrived, or the link was
    /// set up, for the dial rule's liveness.
    heard: Ms,
    /// The pairs the node's feeds list for the peer.
    listed: Listings,
    /// The core's gates refused a restart the rekey machine found, so the
    /// two records of the peer's startup epoch differ by the core's own
    /// decision until something sets them equal again.
    gated: bool,
    /// The rekey machine has cut over since the install.
    cut: bool,
    /// The ephemerals of the msg1s the rekey machine answered, refused or
    /// handed to a replacement, which its record owes, kept from its
    /// outputs (the rekey simulator's list).
    owed: Owed,
    /// When this node's own rekey of the peer in flight started.
    started: Option<Ms>,
}

/// A msg1's answer built before the core decides on it: the completed
/// handshake, the setup record it would note, and the index of the lease
/// the answer's leg would hold.
type Built = (Completed<Ik>, Record, u32);

/// What one call's outputs did, in the model step's fields.
#[derive(Debug, Default)]
struct Fx {
    class: Option<Class>,
    refused: Option<Refusal>,
    change: Option<M>,
    removed: Option<Why>,
    /// Answers asked for: the link, whether the answer was stored, and the
    /// msg2.
    answers: Vec<(LinkNo, bool, Vec<u8>)>,
    /// Dials whose msg1 the core asked to resend.
    resends: Vec<(LinkNo, Vec<u8>)>,
    /// Links the core opened.
    opened: Vec<LinkNo>,
    /// Connections closed.
    closes: Vec<Addr>,
    /// The arrival the core handed the rekey machine.
    arrival: Option<rekey::Arrival>,
    /// A msg1 came from a pair the peer's bundle holds Live or acked.
    proven: bool,
}

/// Everything the node keeps, the log aside.
#[derive(Debug)]
struct State {
    ix: usize,
    now: Ms,
    /// When the core was last polled.
    polled: Option<Ms>,
    me: Node,
    mode: Mode,
    life: u32,
    count: u32,
    configured: Vec<Configured>,
    retry: BTreeMap<u8, Ms>,
    idle: BTreeMap<(u8, u16), Ms>,
    table: Table<TestInstant>,
    runs: BTreeMap<LinkNo, Run>,
    peers: BTreeMap<u8, Held>,
    /// The node's capabilities its machines borrow.
    kit: Kit,
    /// The replay records of closed links.
    store: RecordStore,
    /// Handshake names and the sessions they made.
    names: Names,
    /// Which peer each bound index routes to.
    bound: BTreeMap<u32, u8>,
    /// The connections the peers' bundles asked for that have not yet
    /// been seen to settle: the peer, and its pair. An entry leaves when it
    /// is reported settled or when the peer is removed, and stays across a
    /// move, as the node's list does.
    connecting: Vec<(u8, Addr)>,
    /// Broken promises, seen by the shell.
    audit: Vec<String>,
    /// The peers the log names, whose shadows see every close.
    known: BTreeSet<u8>,
    /// The rekey msg1s sent in this life.
    rekeys: Vec<(Node, Hs)>,
    /// The two start floors of an own rekey, in ms.
    floors: (Ms, Ms),
    /// What the shell found at a step for the joint world's oracles: an
    /// output the core did not hear of, a msg1 attributed otherwise than
    /// the node attributes it.
    found: Vec<(Oracle, String)>,
    /// The pinned shapes the shell met at a step, for the oracles' count.
    /// No successor and no verdict reads it, so the key leaves it out.
    pins: Vec<(Pin, String)>,
    /// This step's count of the machine outputs the core must hear of and
    /// of the inputs that told it. Empty between steps, so the key leaves
    /// it out.
    ledger: Ledger,
    /// The peers whose machines this step polled. Empty between steps, so
    /// the key leaves it out.
    stepped: Vec<u8>,
    /// This step is a packet the explorer copied. False between steps, so
    /// the key leaves it out.
    copy: bool,
    /// The peers the liveness timer removed in this step, each with the
    /// handshake of the session it was held on, which the world takes
    /// after it. Empty between steps, so the key leaves it out.
    expired: Vec<(Node, Hs)>,
    /// The rekey machines' deadlines their checks read.
    limits: Limits,
}

/// One node, judged by the settlement core with real machines.
pub struct JointParty {
    s: State,
    log: Vec<Entry>,
}

/// The node address the core and the machine name identity `n` by.
fn key(n: Node) -> NodeAddr {
    names::addr(n)
}

/// The world identity of node address `a`.
fn who(a: &NodeAddr) -> Option<Node> {
    [A, B, C, THIRD].into_iter().find(|n| names::addr(*n) == *a)
}

fn at(a: Addr) -> (u8, u16) {
    (a.transport, a.at)
}

/// The node's record store, sized as `link_records` sizes it at the
/// default `max_peers` of 128.
fn store() -> RecordStore {
    RecordStore::new(256)
}

/// Give every lease in `out` back to `kit`'s pool and drop the rest.
fn discard(kit: &mut Kit, out: Vec<Output>) {
    for o in out {
        match o {
            Output::Free { lease } => kit.pool.free(lease.release()),
            Output::Install(i) => kit.pool.free(i.lease.release()),
            Output::Opened { .. }
            | Output::Answer { .. }
            | Output::Resend { .. }
            | Output::Rekey { .. }
            | Output::Reset { .. }
            | Output::Remove { .. }
            | Output::Retire { .. }
            | Output::Release { .. }
            | Output::Close { .. }
            | Output::Retry { .. }
            | Output::Reject { .. }
            | Output::Hold { .. }
            | Output::Settle { .. } => {}
        }
    }
}

/// The session the epoch `tag` of `m` holds.
fn session(m: &Machines, tag: EpochTag) -> Option<Kid> {
    let (v, p) = (m.rekey().view(), m.rekey().peek());
    [
        (v.current.map(|e| e.tag), p.current),
        (v.pending.map(|e| e.tag), p.pending),
        (v.previous.map(|e| e.tag), p.previous),
    ]
    .into_iter()
    .find(|(t, _)| *t == Some(tag))
    .and_then(|(_, e)| e.map(|e| kid(e.session)))
}

/// When the node's liveness timer removes the peer `m` is for, if
/// nothing is heard before it: the link-dead timeout after the later of
/// its current session's base and the last frame its rekey machine
/// authenticated under any session (`silence`, `check_link_heartbeats`,
/// `src/node/handlers/mmp.rs`). `None` while this node's own rekey of the
/// peer is in flight, which suspends the timer (`rekey_in_progress`), and
/// for a session with no base, whose age the node reads as zero. The node
/// checks on its one-second tick; the world removes the peer at the
/// deadline itself, at most a tick before the node would.
fn deadline(m: &Machines) -> Option<Ms> {
    let v = m.rekey().view();
    if v.cycle == CycleView::Init {
        return None;
    }
    let base = v.current.and_then(|e| e.base)?.0;
    let heard = v.last_rx.map_or(0, |t| t.0);
    Some(base.max(heard) + feeds::LIVE)
}

/// The ephemeral digest the core keeps for a msg1, from the stub's.
fn ephemeral(tok: &Msg1) -> EphemeralDigest {
    let mut b = [0u8; 33];
    b[..32].copy_from_slice(&tok.ephemeral().0);
    EphemeralDigest::of_noise_msg1(&b).expect("33 bytes carry an ephemeral")
}

impl JointParty {
    /// Node `ix` with identity `me` and multipath setting `mode`,
    /// redialing `configured`.
    pub fn new(ix: usize, me: Node, configured: Vec<Configured>, mode: Mode) -> Self {
        let cfg = mode.rekey();
        let ms = |d: crate::time::Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        let floors = (ms(cfg.config().floor_link), ms(cfg.config().floor_session));
        let limits = Limits {
            budget: ms(cfg.budget),
            retention: ms(cfg.config().retention),
        };
        Self {
            s: State {
                ix,
                now: 0,
                polled: None,
                me,
                mode,
                life: 0,
                count: 0,
                configured,
                retry: BTreeMap::new(),
                idle: BTreeMap::new(),
                table: Table::new(key(me), Params::default()),
                runs: BTreeMap::new(),
                peers: BTreeMap::new(),
                kit: Kit::new(me, Epoch(u32::from(me.0) << 8), &super::kinds()),
                store: store(),
                names: Names::default(),
                bound: BTreeMap::new(),
                connecting: Vec::new(),
                audit: Vec::new(),
                known: BTreeSet::new(),
                rekeys: Vec::new(),
                floors,
                found: Vec::new(),
                pins: Vec::new(),
                ledger: Ledger::default(),
                stepped: Vec::new(),
                copy: false,
                expired: Vec::new(),
                limits,
            },
            log: Vec::new(),
        }
    }

    fn epoch(&self) -> Epoch {
        Epoch((u32::from(self.s.me.0) << 8) | self.s.life)
    }

    /// The handshake name `fresh` gives next.
    fn next(&self) -> Hs {
        Hs((u32::from(self.s.me.0) << 24) | (self.s.life << 16) | (self.s.count + 1))
    }

    fn fresh(&mut self) -> Hs {
        let hs = self.next();
        self.s.count += 1;
        hs
    }

    /// The instant the core is called at: the monotonic clock, or with
    /// `PacketStamp` the packet's wall stamp.
    fn at(net: &Net, stamp: Option<i64>) -> TestInstant {
        match stamp {
            Some(s) if fault!(PacketStamp) => TestInstant(u64::try_from(s).unwrap_or(0)),
            Some(_) | None => TestInstant(net.now),
        }
    }

    /// Call the core, checking that a poll one tick before its next wake
    /// does nothing and that its index is derived.
    fn core(&mut self, input: In, at: TestInstant) -> Vec<Output> {
        if let Some(w) = self.s.table.next_wake().filter(|w| *w > at) {
            let early = self.s.table.poll(TestInstant(w.0 - 1));
            if !early.is_empty() {
                self.s
                    .audit
                    .push(format!("a poll before the next wake acted: {early:?}"));
                discard(&mut self.s.kit, early);
            }
        }
        let told = if matches!(input, In::Replace(_)) {
            Some(Told::Replace)
        } else if matches!(input, In::Restarted { .. }) {
            Some(Told::Restart)
        } else if matches!(input, In::Ended { .. }) {
            Some(Told::Teardown)
        } else if matches!(input, In::Orphaned { .. }) {
            Some(Told::Orphan)
        } else {
            None
        };
        if let Some(t) = told {
            self.s.ledger.step(t);
        }
        let out = self.s.table.step(input, at);
        self.check();
        out
    }

    fn check(&mut self) {
        let links = self.s.table.links();
        if links.index() != &links.derived() {
            self.s
                .audit
                .push(String::from("the index is not its records' recomputation"));
        }
    }

    /// The peer's address as this node sends to it: the bundle's active
    /// path; `None` while no path is active.
    fn to(&self, peer: Node) -> Option<Addr> {
        if fault!(SendsByHeld) {
            // The defect's shape: the core's record of where the peer is.
            return self.s.table.held(&key(peer)).map(|h| addr(&h.current));
        }
        self.s.peers.get(&peer.0).and_then(|p| p.machines.active())
    }

    /// This node's own address on its path to the peer's pair `to`.
    fn from(&self, peer: Node, to: Addr) -> Option<Addr> {
        self.s.peers.get(&peer.0).and_then(|p| p.machines.local(to))
    }

    fn note(&mut self, now: Ms, peer: Node, ev: Event, mut rec: Rec) {
        rec.heard = self.s.table.held(&key(peer)).is_some_and(|h| h.heard);
        self.s.known.insert(peer.0);
        self.log.push(Entry::Ev {
            at: now,
            peer,
            ev,
            rec,
        });
    }

    /// Tell every peer's shadow of each connection closed.
    fn closes(&mut self, now: Ms, closes: &[Addr]) {
        let known: Vec<u8> = self.s.known.iter().copied().collect();
        for &at in closes {
            for &k in &known {
                self.note(now, Node(k), Event::Close { at }, Rec::default());
            }
        }
    }

    /// Every address whose connection a live link of this node uses: a
    /// link's setup address while a leg holds it or it has no paths, its
    /// live or acknowledged paths, and each held peer's address.
    fn needs(&self) -> Vec<Addr> {
        let links = self.s.table.links();
        let mut out: Vec<Addr> = Vec::new();
        let nos: BTreeSet<LinkNo> = links.index().iter().map(|(_, l)| *l).collect();
        for l in nos {
            let Some(r) = links.get(l) else { continue };
            if r.paths.is_empty() || r.holder == Holder::Leg {
                out.push(addr(&r.setup));
            }
            for (p, s) in &r.paths {
                if s.counts() {
                    out.push(addr(p));
                }
            }
        }
        for k in self.s.peers.keys() {
            if let Some(a) = self.to(Node(*k)) {
                out.push(a);
            }
        }
        out
    }

    fn uses(&self, at: Addr) -> bool {
        self.needs().contains(&at)
    }

    /// Note the inbound connection a msg1 arrived on at `src` when nothing
    /// uses it afterwards.
    fn unused(&mut self, net: &Net, src: Addr) {
        if net.kind(src.transport) != Kind::Datagram
            && net.conn(self.s.ix, src).is_some()
            && !self.uses(src)
        {
            self.s.idle.entry(at(src)).or_insert(net.now + HANDSHAKE);
        }
    }

    /// Whether the held peer's link is reachable: connectionless, or its
    /// active path's connection still open. A held peer with no active
    /// path is not.
    fn reachable(&self, net: &Net, peer: Node) -> bool {
        if self.s.table.held(&key(peer)).is_none() {
            return true;
        }
        let Some(cur) = self.to(peer) else {
            return false;
        };
        let ix = self.s.ix;
        // A connection the far end closed is still reachable here until
        // its end-of-stream arrives: the node knows only its own end.
        let unseen = |c: &super::super::world::Conn| match c.state {
            super::super::world::State::Closed(e) => {
                c.ends[1 - e].node == ix
                    && c.ends[1 - e].remote == cur
                    && net
                        .flight
                        .iter()
                        .any(|f| f.conn == Some(c.id) && f.to == ix && f.pkt == Pkt::Eof)
            }
            super::super::world::State::Connecting | super::super::world::State::Open => false,
        };
        net.kind(cur.transport) == Kind::Datagram
            || net.conn(ix, cur).is_some()
            || (!fault!(ReachablePeeks) && net.conns.iter().any(unseen))
    }

    /// Name each session `peer`'s machine holds that has no name yet, with
    /// `hs`, the handshake the call that made it was about.
    fn named(&mut self, peer: Node, hs: Option<Hs>) {
        let State {
            peers,
            names,
            audit,
            ..
        } = &mut self.s;
        let Some(p) = peers.get(&peer.0) else {
            return;
        };
        let pk = p.machines.rekey().peek();
        for e in [pk.current, pk.pending, pk.previous].into_iter().flatten() {
            let k = kid(e.session);
            if names.name(k).is_some() {
                continue;
            }
            match hs {
                Some(h) if names.kid(h).is_none() => names.note(h, k),
                Some(_) | None => {
                    audit.push(format!("{peer:?}: a session with no name, after {hs:?}"));
                }
            }
        }
    }

    /// The name of the session `m` holds as current.
    fn current(&self, m: &Machines) -> Option<Hs> {
        let pk = m.rekey().peek();
        pk.current.and_then(|e| self.s.names.name(kid(e.session)))
    }

    /// Route `events` of `peer`'s machines, the bundle's about `link`.
    fn route(
        &mut self,
        peer: Node,
        link: Option<LinkNo>,
        released: Option<LinkNo>,
        events: Vec<Ev>,
    ) -> Routed {
        let State {
            peers,
            bound,
            audit,
            ledger,
            ..
        } = &mut self.s;
        for e in &events {
            let told = if matches!(e, Ev::Rekey(rekey::Output::ReplaceRequested { .. })) {
                Some(Told::Replace)
            } else if matches!(e, Ev::Rekey(rekey::Output::PeerRestarted { .. })) {
                Some(Told::Restart)
            } else if matches!(e, Ev::Rekey(rekey::Output::Teardown(_))) {
                Some(Told::Teardown)
            } else if matches!(e, Ev::Path(crate::proto::path::Output::Orphaned)) {
                Some(Told::Orphan)
            } else {
                None
            };
            if let Some(t) = told {
                ledger.emit(t);
            }
        }
        let Some(p) = peers.get_mut(&peer.0) else {
            return Routed::default();
        };
        if events
            .iter()
            .any(|e| matches!(e, Ev::Rekey(rekey::Output::Rekeyed { .. })))
        {
            p.cut = true;
        }
        let r = route(
            events,
            Ctx {
                peer,
                key: key(peer),
                link,
                released,
                machines: &p.machines,
                bound,
            },
        );
        audit.extend(r.broken.iter().cloned());
        r
    }

    /// The link `peer` is held on.
    fn link(&self, peer: Node) -> Option<LinkNo> {
        self.s.table.held(&key(peer)).map(|h| h.link)
    }

    /// Step the core with each of `inputs`, carrying out what it asks. A
    /// restart the machine found that the core's gates refuse is noted on
    /// the peer, since the two records of its startup epoch then differ by
    /// the core's decision; one the core takes clears the note.
    fn inputs(&mut self, net: &mut Net, inputs: Vec<In>, fx: &mut Fx) {
        for i in inputs {
            let restarted = if let In::Restarted { peer, .. } = &i {
                who(peer)
            } else {
                None
            };
            let out = self.core(i, TestInstant(net.now));
            if let Some(n) = restarted
                && let Some(p) = self.s.peers.get_mut(&n.0)
            {
                p.gated = out.iter().any(|o| {
                    matches!(
                        o,
                        Output::Reject {
                            source: Some(crate::proto::settle::gates::Source::RekeyMsg2),
                            ..
                        }
                    )
                });
            }
            self.effects(net, out, fx);
        }
    }

    /// Carry out the sends of `peer`'s machines: an own msg1 or a reply to
    /// the peer, a prompt as a frame. `src` and `local` are where the msg1
    /// being answered arrived, if any.
    fn sends(
        &mut self,
        net: &mut Net,
        peer: Node,
        sends: Vec<Send>,
        answering: Option<(Hs, Addr, Addr)>,
    ) {
        let (ix, me, epoch) = (self.s.ix, self.s.me, self.epoch());
        for s in sends {
            match s {
                Send::Msg1(msg) => {
                    let Some(to) = self.to(peer) else { continue };
                    let next = self.next();
                    let Some(p) = self.s.peers.get_mut(&peer.0) else {
                        continue;
                    };
                    let hs = match &p.own {
                        Some((h, b)) if *b == msg => *h,
                        Some(_) | None => {
                            p.own = Some((next, msg.clone()));
                            p.started = Some(net.now);
                            self.s.count += 1;
                            self.s.rekeys.push((peer, next));
                            self.note(
                                net.now,
                                peer,
                                Event::RekeyStart { hs: next },
                                Rec::default(),
                            );
                            next
                        }
                    };
                    let from = self.from(peer, to);
                    let wire = net.intern(&msg);
                    let pkt = Pkt::Msg1 {
                        id: me,
                        hs,
                        bytes: Bytes(hs.0),
                        epoch,
                        wire,
                    };
                    net.send(ix, from, to, pkt);
                }
                Send::Msg2 { msg, route } => {
                    let Some((hs, src, local)) = answering else {
                        self.s
                            .audit
                            .push(format!("{peer:?}: a msg2 that answers no msg1"));
                        continue;
                    };
                    let wire = net.intern(&msg);
                    let pkt = Pkt::Msg2 {
                        id: me,
                        hs,
                        epoch,
                        wire,
                    };
                    match route {
                        Route::Arrival => {
                            net.send(ix, Some(local), src, pkt);
                        }
                        Route::Established { fallback } => {
                            self.reply(net, peer, src, pkt, fallback)
                        }
                    }
                }
                Send::Prompt { tag, wire } => {
                    let Some(to) = self.to(peer) else { continue };
                    let hs = self
                        .s
                        .peers
                        .get(&peer.0)
                        .and_then(|p| session(&p.machines, tag))
                        .and_then(|k| self.s.names.name(k));
                    let Some(hs) = hs else {
                        self.s
                            .audit
                            .push(format!("{peer:?}: a prompt under a session with no name"));
                        continue;
                    };
                    let from = self.from(peer, to);
                    let wire = net.intern(&wire);
                    net.send(ix, from, to, Pkt::Frame { id: me, hs, wire });
                }
                Send::Path { to, bytes } => self.carry(net, peer, to, &bytes),
                Send::Connect { to } => {
                    // A connection already open or opening to the pair is
                    // the one the transport reports on.
                    if net.conn(ix, to).is_none() {
                        let from = self.from(peer, to);
                        net.connect(ix, from, to);
                    }
                    self.s.connecting.push((peer.0, to));
                }
            }
        }
    }

    /// Send the bundle's path message `bytes` to the peer's pair `to`,
    /// sealed under the current session, from this node's address on that
    /// path. On a connection-oriented transport it goes only on a
    /// connection already open or opening there: the bundle asks for one
    /// before it probes, and an answer goes back on the connection the
    /// probe came in on.
    fn carry(&mut self, net: &mut Net, peer: Node, to: Addr, bytes: &[u8]) {
        let (ix, me, now) = (self.s.ix, self.s.me, net.now);
        if net.kind(to.transport) != Kind::Datagram && net.conn(ix, to).is_none() {
            return;
        }
        let from = self.from(peer, to);
        let Some(p) = self.s.peers.get(&peer.0) else {
            return;
        };
        let Some(hs) = self.current(&p.machines) else {
            self.s
                .audit
                .push(format!("{peer:?}: a current session with no name"));
            return;
        };
        let Some(p) = self.s.peers.get_mut(&peer.0) else {
            return;
        };
        let Some(sealed) = p.machines.seal(now, bytes) else {
            return;
        };
        let wire = net.intern(&sealed);
        net.send(ix, from, to, Pkt::Frame { id: me, hs, wire });
    }

    /// Tell each bundle of the connections it asked for that have settled:
    /// opened, or failed or gone. One still opening waits, as the node's
    /// path tick reads them (`poll_connects`).
    fn connects(&mut self, net: &mut Net) {
        let (ix, now) = (self.s.ix, net.now);
        for (k, to) in core::mem::take(&mut self.s.connecting) {
            let ok = match net.conn(ix, to).map(|(i, _)| net.conns[i].state) {
                Some(Link::Connecting) => {
                    self.s.connecting.push((k, to));
                    continue;
                }
                Some(Link::Open) => true,
                Some(Link::Closed(_)) | None => false,
            };
            let peer = Node(k);
            let q = super::facts::pair(to);
            let Some(p) = self.s.peers.get_mut(&k) else {
                continue;
            };
            let input = PathInput::Connected {
                transport: q.transport,
                addr: q.addr,
                ok,
            };
            let events = p.machines.path(&mut self.s.kit, now, input, None);
            let link = self.link(peer);
            let r = self.route(peer, link, None, events);
            let mut fx = Fx::default();
            self.cut(net, peer, r, &mut fx);
            self.closes(now, &fx.closes);
        }
    }

    /// A reply to the held peer goes on its established path, or, with
    /// `fallback`, on the msg1's own connection when that path's
    /// connection is gone (`answer_msg1`).
    fn reply(&mut self, net: &mut Net, peer: Node, src: Addr, pkt: Pkt, fallback: bool) {
        let ix = self.s.ix;
        let Some(cur) = self.to(peer) else {
            return;
        };
        if net.kind(cur.transport) == Kind::Datagram || net.conn(ix, cur).is_some() {
            let from = self.from(peer, cur);
            net.send(ix, from, cur, pkt);
        } else if fallback
            && src.transport == cur.transport
            && src != cur
            && net.conn(ix, src).is_some()
        {
            net.send(ix, None, src, pkt);
        }
    }

    /// Send one frame to `peer` under its current session, now.
    fn announce(&mut self, net: &mut Net, peer: Node) {
        let (ix, me, now) = (self.s.ix, self.s.me, net.now);
        let Some(to) = self.to(peer) else {
            return;
        };
        let from = self.from(peer, to);
        let Some(p) = self.s.peers.get(&peer.0) else {
            return;
        };
        let Some(hs) = self.current(&p.machines) else {
            self.s
                .audit
                .push(format!("{peer:?}: a current session with no name"));
            return;
        };
        let Some(p) = self.s.peers.get_mut(&peer.0) else {
            return;
        };
        p.beat = now;
        let Some(sealed) = p.machines.seal(now, BEAT) else {
            return;
        };
        let wire = net.intern(&sealed);
        net.send(ix, from, to, Pkt::Frame { id: me, hs, wire });
    }

    /// Announce after a peer change that leaves this node a session.
    fn changed(&mut self, net: &mut Net, peer: Node, change: Option<M>) {
        if matches!(
            change,
            Some(M::Promote | M::Replace | M::Move | M::Keep | M::RekeyCutover | M::Restarted)
        ) {
            self.announce(net, peer);
        }
    }

    /// The addresses of the link the core holds `peer` on, as its record
    /// has them: the setup address, then each path's.
    fn addrs(&self, peer: Node) -> Vec<Addr> {
        self.s
            .table
            .held(&key(peer))
            .and_then(|h| self.s.table.links().get(h.link))
            .map(|r| {
                core::iter::once(&r.setup)
                    .chain(r.paths.iter().map(|(q, _)| q))
                    .map(addr)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Carry out the core's outputs.
    fn effects(&mut self, net: &mut Net, out: Vec<Output>, fx: &mut Fx) {
        for o in out {
            match o {
                Output::Opened { link } => fx.opened.push(link),
                Output::Answer { link, stored, msg2 } => fx.answers.push((link, stored, msg2)),
                Output::Resend { link, bytes } => fx.resends.push((link, bytes)),
                Output::Rekey { arrival, .. } => fx.arrival = Some(arrival),
                Output::Install(i) => self.install(net, i, fx),
                Output::Reset { peer, transition } => {
                    let m = change(transition);
                    if matches!(m, M::Keep | M::Move)
                        && let Some(p) = who(&peer).and_then(|n| self.s.peers.get_mut(&n.0))
                    {
                        p.answered = true;
                    }
                    fx.change = Some(m);
                }
                Output::Remove { peer, why } => {
                    // The defect's shape: the replaced peering's machines
                    // kept for the peering that replaces it.
                    let kept = fault!(ReplaceKeepsMachine)
                        && matches!(why, Why::Replacement | Why::Restart);
                    if let Some(n) = who(&peer).filter(|_| !kept) {
                        self.remove(net, n);
                        if self.s.configured.iter().any(|c| c.peer == n) {
                            self.s.retry.insert(n.0, net.now + RETRY);
                        }
                    }
                    fx.removed = Some(why);
                    if fx.class.is_none() {
                        fx.class = match why {
                            Why::Restart => Some(Class::Restart),
                            Why::Replacement => Some(Class::Replacement),
                            Why::OwnRestart
                            | Why::Ended
                            | Why::Orphaned
                            | Why::Disconnect
                            | Why::Dead
                            | Why::Admin
                            | Why::Closed => None,
                        };
                    }
                }
                Output::Retire { closes, .. }
                | Output::Release { closes, .. }
                | Output::Close { closes } => {
                    for p in closes {
                        let a = addr(&p);
                        if net.kind(a.transport) != Kind::Datagram {
                            net.close(self.s.ix, a);
                            fx.closes.push(a);
                        }
                    }
                }
                Output::Free { lease } => {
                    if fault!(LeaseForgotten) {
                        // The defect's shape: the lease gone, its index
                        // never back in the pool.
                        let _ = lease.release();
                    } else {
                        self.s.kit.pool.free(lease.release());
                    }
                }
                Output::Retry { peer } => {
                    if let Some(n) = who(&peer)
                        && self.s.configured.iter().any(|c| c.peer == n)
                    {
                        self.s.retry.insert(n.0, net.now + RETRY);
                    }
                }
                Output::Reject { source, why, .. } => {
                    fx.refused = Some(refusal(why));
                    if fx.class.is_none() {
                        fx.class = source.and_then(class);
                    }
                }
                Output::Hold { peer, link } | Output::Settle { peer, link, .. } => {
                    self.s.audit.push(format!(
                        "a candidate rule's hold of {link:?} for {peer:?}, which no joint node runs"
                    ));
                }
            }
        }
    }

    /// The core removed `peer`: close its machines, file the record.
    fn remove(&mut self, net: &mut Net, peer: Node) {
        if fault!(CloseSkipped) {
            // The defect's shape: the machines left in the map.
            return;
        }
        let Some(p) = self.s.peers.remove(&peer.0) else {
            return;
        };
        self.s.connecting.retain(|(k, _)| *k != peer.0);
        let now = net.now;
        // The machine of a removed peer: what the bundle releases goes with
        // the link, whose closes the core's retire holds.
        let (events, carry) = p.machines.close(&mut self.s.kit, now, rekey::Close::Admin);
        for e in events {
            if let Ev::Rekey(rekey::Output::Unbind { index, .. }) = e
                && self.s.bound.remove(&index).is_none()
            {
                self.s
                    .audit
                    .push(format!("index {index} unbound at a close, not bound"));
            }
        }
        if let Some(c) = carry {
            self.s
                .store
                .file(key(peer), c.peer_epoch.unwrap_or_default(), c.record);
        }
    }

    /// The core installed a peer: build its machines on the completed
    /// handshake, or move them onto it.
    fn install(&mut self, net: &mut Net, i: Install, fx: &mut Fx) {
        let now = net.now;
        let Some(run) = self.s.runs.get_mut(&i.link) else {
            self.s.audit.push(format!(
                "install on {:?}, which no handshake opened",
                i.link
            ));
            self.s.kit.pool.free(i.lease.release());
            return;
        };
        let (hs, peer, local) = (run.hs, run.peer, run.local);
        let Some(done) = run.done.take() else {
            self.s.audit.push(format!(
                "install on {:?}, whose handshake did not complete",
                i.link
            ));
            self.s.kit.pool.free(i.lease.release());
            return;
        };
        let noted = run.record.take();
        let to = addr(&i.pair);
        let epoch = done.epoch;
        let theirs = done.theirs.unwrap_or(0);
        let setup = Setup {
            done,
            lease: i.lease,
            theirs,
        };
        let old = self.s.peers.remove(&peer.0);
        let moved = matches!((i.rekey, &old), (Build::FromCarry, Some(_)));
        // The record a move carries keeps what it owes.
        let mut owed = Owed::default();
        let (machines, events, answered, beat, heard, off) = match (i.rekey, old) {
            (Build::Fresh, Some(old)) if fault!(ReplaceKeepsMachine) => {
                // The defect's shape: the replaced peering's machines run
                // on, and the new handshake's lease goes unused.
                self.s.kit.pool.free(setup.lease.release());
                (old.machines, Vec::new(), false, now, now, None)
            }
            (Build::FromCarry, Some(old)) => {
                owed = old.owed;
                let (m, ev) = old.machines.moved(&mut self.s.kit, now, setup, to, local);
                (m, ev, old.answered, old.beat, old.heard, Some(old.link))
            }
            (rebuilt, old) => {
                if let Some(old) = old {
                    self.s.audit.push(format!(
                        "{peer:?}: a {rebuilt:?} install over machines no removal closed"
                    ));
                    self.s.peers.insert(peer.0, old);
                    self.remove(net, peer);
                }
                let filed = self.s.store.take(&key(peer), epoch);
                let record = match noted {
                    Some(mut r) => {
                        r.absorb(filed);
                        r
                    }
                    None => filed,
                };
                let (m, ev) = Machines::fresh(
                    &mut self.s.kit,
                    now,
                    peer,
                    self.s.mode,
                    setup,
                    record,
                    to,
                    local,
                );
                (m, ev, false, now, now, None)
            }
        };
        self.s.peers.insert(
            peer.0,
            Held {
                machines,
                link: i.link,
                origin: hs,
                answered: answered || i.initiator,
                beat,
                own: None,
                heard,
                listed: Listings::default(),
                gated: false,
                cut: false,
                owed,
                started: None,
            },
        );
        self.s.retry.remove(&peer.0);
        self.named(peer, Some(hs));
        let mut r = self.route(peer, Some(i.link), off, events);
        if !moved {
            // A new bundle reports nothing: its original path is Live.
            r.inputs.push(In::State {
                link: i.link,
                pair: i.pair,
                proven: Proven::Live,
            });
        }
        self.inputs(net, r.inputs, fx);
        // The bundle started again with no candidate: the configuration's
        // pairs for the peer are offered to it, as `paths_renewed` does.
        for (at, from) in feeds::configured(&self.s.configured, peer) {
            self.offer(net, peer, at, from, Source::Config, fx);
        }
    }

    /// `source` reports that `peer` may be reachable at `at`, from this
    /// node's address `from` or its home on that transport: offered to the
    /// peer's bundle unless a feed lists it already, and nothing with
    /// multipath disabled or for a peer not held.
    fn offer(
        &mut self,
        net: &mut Net,
        peer: Node,
        at: Addr,
        from: Option<Addr>,
        source: Source,
        fx: &mut Fx,
    ) {
        if !self.s.mode.enabled() {
            return;
        }
        let Some(p) = self.s.peers.get_mut(&peer.0) else {
            return;
        };
        if !p.listed.report(source, at) {
            return;
        }
        let local = from.unwrap_or_else(|| net.home(self.s.ix, at.transport));
        let q = super::facts::pair(at);
        let input = PathInput::Candidate {
            transport: q.transport,
            addr: q.addr,
            source,
        };
        let events = p
            .machines
            .path(&mut self.s.kit, net.now, input, Some(local));
        let link = self.link(peer);
        let r = self.route(peer, link, None, events);
        self.cut(net, peer, r, fx);
    }

    /// A msg1's answer, built before the core decides on it: the `Hello`
    /// with a fresh lease, and what an install would take from it.
    fn hello(&mut self, tok: &Msg1, hs: Hs, bytes: &[u8], from: Addr) -> (Hello, Built) {
        let kit = &mut self.s.kit;
        let lease = allocate(&mut kit.pool).expect("the node's pool has an index");
        let index = lease.index();
        kit.local.name(names::answerer(hs));
        let (done, msg2) = tok
            .answer(&kit.local, Some(lease.index()))
            .expect("the stub IK msg2 always writes");
        let record = Record::setup(tok.digest(), tok.ephemeral(), Some(msg2.clone()));
        let hello = Hello {
            peer: tok.remote().addr(),
            from: pair(from),
            bytes: bytes.to_vec(),
            ephemeral: ephemeral(tok),
            epoch: tok.epoch(),
            msg2,
            lease,
        };
        (hello, (done, record, index))
    }

    fn dial(&mut self, net: &mut Net, peer: Node, to: Addr, from: Option<Addr>) {
        if let Some(p) = self.s.peers.get(&peer.0)
            && !feeds::dials(self.s.mode, &p.machines, p.heard, net.now)
        {
            // A capable peer is not dialled while its link is live: the
            // address is a requested candidate instead.
            let mut fx = Fx::default();
            self.offer(net, peer, to, from, Source::Request, &mut fx);
            self.closes(net.now, &fx.closes);
            return;
        }
        let hs = self.fresh();
        let b = Bytes(hs.0);
        let kit = &mut self.s.kit;
        let lease = allocate(&mut kit.pool).expect("the node's pool has an index");
        let index = lease.index();
        kit.local.name(names::opener(hs));
        let (state, msg1) = Ik::initiate(&kit.local, &names::key(peer), Some(lease.index()))
            .expect("the stub IK msg1 always writes");
        net.connect(self.s.ix, from, to);
        let wire = net.intern(&msg1);
        let pkt = Pkt::Msg1 {
            id: self.s.me,
            hs,
            bytes: b,
            epoch: self.epoch(),
            wire,
        };
        net.send(self.s.ix, from, to, pkt);
        let d = Dialed {
            peer: key(peer),
            to: pair(to),
            msg1: msg1.clone(),
            lease,
        };
        let out = self.core(In::Dial(d), TestInstant(net.now));
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
        let Some(&link) = fx.opened.first() else {
            self.s
                .audit
                .push(format!("a dial of {peer:?} opened no link"));
            return;
        };
        let local = from.unwrap_or_else(|| net.home(self.s.ix, to.transport));
        self.s.runs.insert(
            link,
            Run {
                hs,
                peer,
                role: Role::Dial { to, from },
                bytes: b,
                epoch: None,
                msg1,
                local,
                state: Some(state),
                done: None,
                record: None,
                index,
            },
        );
        self.s.retry.remove(&peer.0);
        let ev = Event::Dial {
            hs,
            link: LinkId(link.0 as u32),
            to,
            binding: binding(net.kind(to.transport)),
        };
        self.note(net.now, peer, ev, Rec::default());
    }

    /// Whether the held peer's link and session are past the two start
    /// floors at `now`, as the machine's start reads them.
    fn eligible(&self, m: &Machines, now: Ms) -> bool {
        let v = m.rekey().view();
        let (link, session) = self.s.floors;
        now.saturating_sub(v.link_since.0) >= link
            && v.current
                .is_some_and(|c| now.saturating_sub(c.started.0) >= session)
    }

    /// The model's class for what the peer's machine did with a msg1:
    /// `pending` is the pending session before the call, `eligible`
    /// whether the link was past its floors.
    fn classify(
        &mut self,
        peer: Node,
        r: &Routed,
        pending: Option<Kid>,
        eligible: bool,
    ) -> Option<Class> {
        if r.replace.is_some() {
            return Some(Class::Replacement);
        }
        if r.sends.iter().any(|s| matches!(s, Send::Msg2 { .. })) {
            let now = self
                .s
                .peers
                .get(&peer.0)
                .and_then(|p| p.machines.rekey().peek().pending.map(|e| kid(e.session)));
            return Some(if r.yielded {
                Class::Simultaneous
            } else if now.is_some() && now != pending {
                Class::Rekey
            } else if pending.is_some() {
                Class::Pending
            } else {
                Class::Resend
            });
        }
        match r.reject? {
            Reason::OffLink => Some(Class::OffLink),
            Reason::PendingHeld => Some(Class::Pending),
            Reason::DualInitWon => Some(Class::Simultaneous),
            Reason::AnsweredBefore if eligible => Some(Class::Recorded),
            Reason::AnsweredBefore => Some(Class::Copy),
            Reason::EpochChanged => None,
            why @ (Reason::IndexExhausted
            | Reason::HandshakeWrite
            | Reason::ReplyUnauthenticated
            | Reason::LateReply
            | Reason::UnknownAttempt
            | Reason::UnknownIndex
            | Reason::SetupMalformed
            | Reason::TieBreakKept
            | Reason::CandidatesFull
            | Reason::FinalNoAttempt
            | Reason::FinalUnauthenticated
            | Reason::KeyMismatch
            | Reason::StaleIncarnation
            | Reason::Replay
            | Reason::FrameUnauthenticated
            | Reason::ShortPlaintext
            | Reason::DelegatedEpoch
            | Reason::NotEstablished
            | Reason::StaleTag
            | Reason::NotDelegated
            | Reason::AlreadyDelegated
            | Reason::NotOffered
            | Reason::AttemptInFlight
            | Reason::AlreadyEstablished
            | Reason::CandidateExpired
            | Reason::NotRekey) => {
                self.s
                    .audit
                    .push(format!("{peer:?}: a msg1 refused {why:?}"));
                None
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn msg1(
        &mut self,
        net: &mut Net,
        (src, local): (Addr, Addr),
        id: Node,
        hs: Hs,
        b: Bytes,
        e: Epoch,
        wire: u32,
        stamp: i64,
    ) {
        let (ix, now, at) = (self.s.ix, net.now, Self::at(net, Some(stamp)));
        let bytes = if wire == 0 {
            names::msg1(id, e, self.s.me, hs, names::index(hs))
        } else {
            net.bytes(wire).to_vec()
        };
        let Some(tok) = read_msg1(&self.s.kit.local, &bytes) else {
            return;
        };
        let sent = net.sendable(ix, src);
        let proven = self.s.peers.get(&id.0).is_some_and(|p| {
            route::proven(&p.machines, &super::facts::pair(src)) != Proven::Probing
        });
        let stale = self.addrs(id);
        let reachable = self.reachable(net, id);
        let (hello, built) = self.hello(tok.get(), hs, &bytes, src);
        let mut built = Some(built);
        let mut out = self.core(In::Msg1 { hello, reachable }, at);
        if let Some(on) = out.iter().find_map(|o| {
            if let Output::Rekey { arrival, .. } = o {
                Some(arrival.on_link)
            } else {
                None
            }
        }) {
            self.attribute(id, src, on);
        }
        let mut fx = Fx {
            proven,
            ..Fx::default()
        };
        if out.iter().any(|o| matches!(o, Output::Rekey { .. })) {
            self.effects(net, out, &mut fx);
            let arrival = fx.arrival.expect("a rekey output carries its arrival");
            let Some(p) = self.s.peers.get_mut(&id.0) else {
                self.s.audit.push(format!(
                    "a rekey hand-off for {id:?}, which has no machines"
                ));
                return;
            };
            let pending = p.machines.rekey().peek().pending.map(|e| kid(e.session));
            let before = Before::of(p.machines.rekey(), false);
            let events = p.machines.msg1(&mut self.s.kit, now, hs, &bytes, arrival);
            let change = before.change(p.machines.rekey());
            let ephemeral = tok.get().ephemeral();
            let copy = self.s.copy;
            let failed = super::oracle::took(
                ix,
                hs,
                copy,
                false,
                &mut p.owed,
                Some(&ephemeral),
                &change,
                &events,
            );
            self.s
                .found
                .extend(failed.into_iter().map(|m| (Oracle::Machine, m)));
            let eligible = self
                .s
                .peers
                .get(&id.0)
                .is_some_and(|p| self.eligible(&p.machines, now));
            self.named(id, Some(hs));
            let link = self.link(id);
            let r = self.route(id, link, None, events);
            fx.class = self.classify(id, &r, pending, eligible);
            let Routed {
                sends,
                inputs,
                replace,
                ..
            } = r;
            self.sends(net, id, sends, Some((hs, src, local)));
            self.inputs(net, inputs, &mut fx);
            match replace {
                Some(tok) => {
                    let (hello, b2) = self.replacement(&tok, hs, &bytes, src);
                    built = Some(b2);
                    out = self.core(In::Replace(hello), at);
                }
                None => {
                    self.logged_msg1(net, id, src, hs, b, e, sent, &fx, None);
                    return;
                }
            }
        }
        self.effects(net, out, &mut fx);
        let mut stored = None;
        for (link, was, msg2) in core::mem::take(&mut fx.answers) {
            if was {
                stored = Some((link, msg2));
                continue;
            }
            let (done, record, index) = match built.take() {
                Some((d, r, i)) => (Some(d), Some(r), i),
                None => (None, None, 0),
            };
            self.s.runs.insert(
                link,
                Run {
                    hs,
                    peer: id,
                    role: Role::Answer,
                    bytes: b,
                    epoch: Some(e),
                    msg1: bytes.clone(),
                    local,
                    state: None,
                    done,
                    record,
                    index,
                },
            );
            if fx.class.is_none() {
                fx.class = Some(Class::NotHeld);
            }
            let input = if sent {
                let wire = net.intern(&msg2);
                let pkt = Pkt::Msg2 {
                    id: self.s.me,
                    hs,
                    epoch: self.epoch(),
                    wire,
                };
                net.send(ix, Some(local), src, pkt);
                In::Sent { link }
            } else {
                In::SendFailed { link }
            };
            let out = self.core(input, at);
            self.effects(net, out, &mut fx);
        }
        if fx.change.is_none() && fx.removed.is_some() {
            fx.change = Some(M::Remove);
        }
        // The world's adapter choice, as the model party makes it where
        // FRC-1201 is silent: a replacement or restart over another
        // connection closes the replaced link's connections when no link
        // uses them. The model's link has one address; a joint link's
        // traffic goes to its bundle's path, which a move or a roam may
        // have taken off the setup address, so its paths' connections
        // close too, as a dead link's do.
        if !fault!(ReplacedConnKept) && matches!(fx.removed, Some(Why::Restart | Why::Replacement))
        {
            for old in stale {
                if net.kind(old.transport) != Kind::Datagram && old != src && !self.uses(old) {
                    net.close(ix, old);
                }
            }
        }
        self.logged_msg1(net, id, src, hs, b, e, sent, &fx, stored);
        self.unused(net, src);
    }

    /// Judge the core's answer `on` to whether a msg1 of the held `peer`
    /// from `from` is on its link against the node's rule: on a pair the
    /// bundle holds a path at, whether the path is Live or acknowledged; on
    /// a pair it holds none at, whether the peer is not capable and the
    /// index names the link. A difference is recorded, as pinned where the
    /// core's rule is known to be wider than the node's.
    fn attribute(&mut self, peer: Node, from: Addr, on: bool) {
        let s = &mut self.s;
        let (Some(h), Some(p)) = (s.table.held(&key(peer)), s.peers.get(&peer.0)) else {
            return;
        };
        let q = super::facts::pair(from);
        let bundle = p.machines.bundle();
        let held = bundle.paths().find(q.transport, &q.addr).is_some();
        let proven = route::proven(&p.machines, &q) != Proven::Probing;
        let links = s.table.links();
        let at = pair(from);
        let indexed = links.at(&at).any(|l| l == h.link);
        let capable = bundle.capable();
        let node = if held { proven } else { !capable && indexed };
        if node == on {
            return;
        }
        let setup = links.get(h.link).is_some_and(|r| r.setup == at);
        let shape = if !on {
            None
        } else if !held && capable && setup {
            Some("a capable peer's setup pair, at which no path is held")
        } else if !held && !indexed && h.current == at {
            Some(
                "the pair the core's record of the peer followed a frame to, held by no path or index entry",
            )
        } else if held && !proven && !indexed && h.current == at {
            Some(
                "the pair the core's record of the peer followed a frame to, held by no index entry, whose path is still probing",
            )
        } else if held && !proven && setup {
            Some("the setup pair, whose path is still probing")
        } else {
            None
        };
        let what = format!(
            "{peer:?}: a msg1 from {from:?} on the link to the core {on}, to the node {node} (path held {held}, proven {proven}, capable {capable}, indexed {indexed})"
        );
        match shape {
            Some(why) => s.pins.push((Pin::Attribution, format!("{what}: {why}"))),
            None => s.found.push((Oracle::Attributed, what)),
        }
    }

    /// A change of the node's transport `transport`, given to every held
    /// peer's bundle.
    fn transported(&mut self, net: &mut Net, input: PathInput) {
        let now = net.now;
        let peers: Vec<u8> = self.s.peers.keys().copied().collect();
        for k in peers {
            let peer = Node(k);
            let Some(p) = self.s.peers.get_mut(&k) else {
                continue;
            };
            let events = p.machines.path(&mut self.s.kit, now, input.clone(), None);
            let link = self.link(peer);
            let r = self.route(peer, link, None, events);
            let mut fx = Fx::default();
            self.cut(net, peer, r, &mut fx);
            self.closes(now, &fx.closes);
        }
    }

    /// The fresh answer the core's gates take at a replacement the machine
    /// asked for.
    fn replacement(
        &mut self,
        tok: &Authentic<Msg1, Replayable>,
        hs: Hs,
        bytes: &[u8],
        from: Addr,
    ) -> (Hello, Built) {
        self.hello(tok.get(), hs, bytes, from)
    }

    /// Log a msg1 and what it led to: the closes, the stored answer's
    /// resend and its install, and the announce.
    #[allow(clippy::too_many_arguments)]
    fn logged_msg1(
        &mut self,
        net: &mut Net,
        id: Node,
        src: Addr,
        hs: Hs,
        b: Bytes,
        e: Epoch,
        sent: bool,
        fx: &Fx,
        stored: Option<(LinkNo, Vec<u8>)>,
    ) {
        let now = net.now;
        let opened = self
            .s
            .runs
            .iter()
            .find(|(_, r)| r.hs == hs && r.peer == id && r.role == Role::Answer)
            .map(|(l, _)| l.0 as u32);
        let ev = Event::Msg1 {
            hs,
            bytes: b,
            epoch: e,
            link: LinkId(opened.unwrap_or(0x8000_0000 | (hs.0 & 0x7fff_ffff))),
            from: src,
            binding: binding(net.kind(src.transport)),
            sent,
        };
        let rec = Rec {
            class: if stored.is_some() { None } else { fx.class },
            refused: fx.refused,
            change: fx.change,
            heard: false,
            proven: fx.proven,
        };
        self.note(now, id, ev, rec);
        self.closes(now, &fx.closes);
        self.changed(net, id, fx.change);
        if let Some((link, msg2)) = stored
            && sent
        {
            self.resend_stored(net, link, &msg2);
        }
    }

    /// A resent msg1 drew the stored answer on `link`: send it, and tell
    /// the core, which installs the peer unless it is held.
    fn resend_stored(&mut self, net: &mut Net, link: LinkNo, msg2: &[u8]) {
        let Some((hs, peer, local)) = self.s.runs.get(&link).map(|r| (r.hs, r.peer, r.local))
        else {
            return;
        };
        let Some(to) = self.s.table.links().get(link).map(|r| addr(&r.setup)) else {
            return;
        };
        let wire = net.intern(msg2);
        let pkt = Pkt::Msg2 {
            id: self.s.me,
            hs,
            epoch: self.epoch(),
            wire,
        };
        net.send(self.s.ix, Some(local), to, pkt);
        let out = self.core(In::Sent { link }, TestInstant(net.now));
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
        let rec = Rec {
            change: fx.change,
            ..Rec::default()
        };
        self.note(net.now, peer, Event::Msg2Sent { hs }, rec);
        self.closes(net.now, &fx.closes);
        self.changed(net, peer, fx.change);
    }

    #[allow(clippy::too_many_arguments)]
    fn msg2(
        &mut self,
        net: &mut Net,
        src: Addr,
        id: Node,
        hs: Hs,
        e: Epoch,
        wire: u32,
        stamp: i64,
    ) {
        let (now, at) = (net.now, Self::at(net, Some(stamp)));
        let dial = self
            .s
            .runs
            .iter()
            .find(|(l, r)| {
                r.hs == hs
                    && r.peer == id
                    && matches!(r.role, Role::Dial { .. })
                    && self.s.table.legs().get(**l).is_some()
            })
            .map(|(l, _)| *l);
        let Some(link) = dial else {
            self.reply2(net, id, hs, e, wire);
            return;
        };
        let State { runs, kit, .. } = &mut self.s;
        let Some(run) = runs.get_mut(&link) else {
            return;
        };
        let bytes = if wire == 0 {
            names::msg2(id, e, hs, &run.msg1, names::index(hs)).map(|(w, _)| w)
        } else {
            Some(net.bytes(wire).to_vec())
        };
        let read = bytes.and_then(|b| {
            run.state
                .as_ref()
                .and_then(|st| Ik::reply(st, &kit.local, &b).ok())
        });
        let Some(read) = read else {
            return;
        };
        let epoch = read.done.epoch;
        run.done = Some(read.done);
        run.epoch = Some(e);
        let input = In::Msg2 {
            link,
            epoch,
            from: pair(src),
        };
        let out = self.core(input, at);
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
        if fx.change.is_none() && fx.removed.is_some() {
            fx.change = Some(M::Remove);
        }
        if matches!(fx.change, Some(M::Promote | M::Replace | M::Move)) {
            net.mark(self.s.ix, src, true);
        }
        let rec = Rec {
            refused: fx.refused,
            change: fx.change,
            ..Rec::default()
        };
        let ev = Event::Msg2 {
            hs,
            epoch: e,
            from: src,
        };
        self.note(now, id, ev, rec);
        self.closes(now, &fx.closes);
        self.changed(net, id, fx.change);
    }

    /// A msg2 no dial of this node waits for: the reply to an own rekey,
    /// routed by its index to the machine that bound it.
    fn reply2(&mut self, net: &mut Net, id: Node, hs: Hs, e: Epoch, wire: u32) {
        let now = net.now;
        let Some(own) = self
            .s
            .peers
            .get(&id.0)
            .and_then(|p| p.own.as_ref().map(|(_, b)| b.clone()))
        else {
            return;
        };
        let bytes = if wire == 0 {
            match names::msg2(id, e, hs, &own, names::index(hs)) {
                Some((w, _)) => w,
                None => return,
            }
        } else {
            net.bytes(wire).to_vec()
        };
        let Some(index) = Ik::index(&bytes) else {
            return;
        };
        if self.s.bound.get(&index) != Some(&id.0) {
            return;
        }
        let Some(p) = self.s.peers.get_mut(&id.0) else {
            return;
        };
        let before = Before::of(p.machines.rekey(), false);
        let waited = p.machines.rekey().view().cycle == CycleView::Init;
        let events = p.machines.reply(&mut self.s.kit, now, &bytes);
        if self.s.copy {
            // A copy of a reply that arrives with no own attempt waiting
            // for one is a repeat; while one waits, the copy may be the
            // first of the two to arrive.
            let change = before.change(p.machines.rekey());
            let failed = super::oracle::took(
                self.s.ix,
                hs,
                true,
                !waited,
                &mut p.owed,
                None,
                &change,
                &events,
            );
            self.s
                .found
                .extend(failed.into_iter().map(|m| (Oracle::Machine, m)));
        }
        let mine = p.own.as_ref().map(|(h, _)| *h);
        self.named(id, mine);
        let link = self.link(id);
        let r = self.route(id, link, None, events);
        let accepted = r.reject.is_none();
        let mut fx = Fx::default();
        self.sends(net, id, r.sends, None);
        self.inputs(net, r.inputs, &mut fx);
        if accepted {
            self.note(now, id, Event::RekeyMsg2 { hs, epoch: e }, Rec::default());
        }
    }

    /// A frame from `id` under the session of `hs`, which the world let
    /// through because this node holds it: demultiplexed by its receiver
    /// index to the peer's machine, opened there, accounted to the bundle,
    /// and heard by the core from its real source; a one-path roam and a
    /// cutover it caused go to the core after.
    fn frame(
        &mut self,
        net: &mut Net,
        (src, local): (Addr, Addr),
        id: Node,
        hs: Hs,
        wire: u32,
        stamp: i64,
    ) {
        let (now, at) = (net.now, Self::at(net, Some(stamp)));
        if wire == 0 {
            // A frame of an abstract far end; no joint world holds one yet.
            return;
        }
        let bytes = net.bytes(wire).to_vec();
        let index = hint(&bytes).index;
        match self.s.bound.get(&index) {
            Some(k) if *k == id.0 => {}
            // An index no machine binds: the node drops the frame. The
            // index map is checked against the machines' bindings at every
            // view, so this is no drift of the maps; it is a frame sealed
            // for an earlier answer of the same handshake, which the world
            // names as one session with the answer held now (one msg1
            // answered again after the peer was removed, or in a later
            // life), and which the gate therefore let through.
            None => return,
            Some(k) => {
                self.s.audit.push(format!(
                    "a frame from {id:?} under {hs:?} that this node holds names index {index}, bound to peer {k}"
                ));
                return;
            }
        }
        let Some(p) = self.s.peers.get_mut(&id.0) else {
            return;
        };
        let (opened, buf) = p.machines.frame(&mut self.s.kit, now, &bytes);
        let link = self.link(id);
        let r = self.route(id, link, None, opened);
        let Some(range) = r.delivered.clone() else {
            // A replay opened under the keys the name maps to, so the maps
            // agree: its counter was seen under an earlier answer of the
            // same handshake, which the world names as one session with
            // this one (as for an unbound index, above). Any other refusal
            // of a frame the gate let through is a broken promise.
            if r.reject != Some(rekey::Reason::Replay) {
                self.s.audit.push(format!(
                    "a frame from {id:?} under {hs:?}, which this node holds, did not open: {:?}",
                    r.reject
                ));
            }
            return;
        };
        let kind = buf.get(range.start).copied().unwrap_or(0);
        let Some(p) = self.s.peers.get_mut(&id.0) else {
            return;
        };
        p.heard = now;
        let (roamed, unpathed) =
            p.machines
                .account(&mut self.s.kit, now, src, local, bytes.len(), kind);
        let mut fx = Fx::default();
        let out = self.core(
            In::Heard {
                peer: key(id),
                from: pair(src),
            },
            at,
        );
        self.effects(net, out, &mut fx);
        let link = self.link(id);
        let moved = self.route(id, link, None, roamed);
        self.inputs(net, moved.inputs, &mut fx);
        if feeds::heard(self.s.mode, unpathed, kind) {
            self.offer(net, id, src, Some(local), Source::Heard, &mut fx);
        }
        self.cut(net, id, r, &mut fx);
        if messaged(kind) {
            let plain = buf.get(range).unwrap_or_default();
            if let Some(p) = self.s.peers.get_mut(&id.0) {
                let events = p.machines.message(&mut self.s.kit, now, src, local, plain);
                let link = self.link(id);
                let r = self.route(id, link, None, events);
                self.cut(net, id, r, &mut fx);
            }
        }
        net.mark(self.s.ix, src, true);
        let rec = Rec {
            change: fx.change,
            ..Rec::default()
        };
        self.note(now, id, Event::Frame { hs, from: src }, rec);
        self.closes(now, &fx.closes);
        self.changed(net, id, fx.change);
    }

    /// Carry out a frame's or a poll's routed events: the sends, the core
    /// inputs, and a cutover, which is the shell's change unless the core
    /// names another (a restart revealed).
    fn cut(&mut self, net: &mut Net, peer: Node, r: Routed, fx: &mut Fx) {
        let Routed {
            sends,
            inputs,
            cut,
            abandoned,
            unadopted,
            ..
        } = r;
        self.sends(net, peer, sends, None);
        if cut {
            fx.change = Some(M::RekeyCutover);
        }
        let orphaned = inputs.iter().any(|i| matches!(i, In::Orphaned { .. }));
        self.inputs(net, inputs, fx);
        if orphaned && !self.s.peers.contains_key(&peer.0) {
            // The node takes an orphaned link as dead (`route_link_dead`),
            // and the shadow reads the removal as it reads a dead link's.
            self.note(
                net.now,
                peer,
                Event::Lost,
                Rec {
                    change: Some(M::Remove),
                    ..Rec::default()
                },
            );
        }
        if abandoned {
            self.log.push(Entry::Abandon { peer });
        }
        if unadopted {
            self.log.push(Entry::Unadopted { peer });
        }
    }

    /// The leg on `link` ended unanswered.
    fn ended(&mut self, net: &mut Net, link: LinkNo, run: (Hs, Node, Role)) {
        let out = self.core(In::ConnectFailed { link }, TestInstant(net.now));
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
        self.timed_out(net, run, &fx);
    }

    fn timed_out(&mut self, net: &mut Net, (hs, peer, role): (Hs, Node, Role), fx: &Fx) {
        self.note(net.now, peer, Event::Timeout { hs }, Rec::default());
        self.closes(net.now, &fx.closes);
        if matches!(role, Role::Dial { .. }) && self.s.configured.iter().any(|c| c.peer == peer) {
            self.s.retry.insert(peer.0, net.now + RETRY);
        }
    }

    /// The connection this node sees at `at` closed, or its connect failed.
    fn closed(&mut self, net: &mut Net, at: Addr) {
        let now = net.now;
        self.closes(now, &[at]);
        let gone: Vec<(LinkNo, (Hs, Node, Role))> = self
            .s
            .runs
            .iter()
            .filter(|(l, r)| {
                self.s.table.legs().get(**l).is_some()
                    && match r.role {
                        Role::Dial { to, .. } => to == at,
                        Role::Answer => self
                            .s
                            .table
                            .links()
                            .get(**l)
                            .is_some_and(|k| addr(&k.setup) == at),
                    }
            })
            .map(|(l, r)| (*l, (r.hs, r.peer, r.role)))
            .collect();
        for (link, run) in gone {
            self.ended(net, link, run);
        }
        if net.kind(at.transport) != Kind::Datagram {
            let peers: Vec<Node> = self.s.peers.keys().map(|&k| Node(k)).collect();
            for p in peers {
                self.lost(net, p, at);
            }
        }
        if !self.uses(at) {
            net.close(self.s.ix, at);
        }
    }

    /// The connection at `at` of a held peer's link closed. A link of one
    /// path whose active path it was is dead at once: the node leaves it to
    /// its liveness timer, which removes the peer the same way within the
    /// link-dead timeout, and the world takes the close as that removal,
    /// earlier. A link of several paths is told through its bundle, as a
    /// failed send tells it, and its liveness timer decides the rest.
    fn lost(&mut self, net: &mut Net, peer: Node, at: Addr) {
        let now = net.now;
        let Some(p) = self.s.peers.get(&peer.0) else {
            return;
        };
        let several = p.machines.bundle().paths().paths().len() > 1;
        if several {
            // A connection the bundle asked for is reported when it
            // settles, not as a failed send.
            if self.s.connecting.contains(&(peer.0, at)) {
                return;
            }
            let held = p
                .machines
                .bundle()
                .paths()
                .paths()
                .iter()
                .any(|q| super::facts::addr(q.transport_id(), q.addr()) == at);
            if !held {
                return;
            }
            let q = super::facts::pair(at);
            let Some(p) = self.s.peers.get_mut(&peer.0) else {
                return;
            };
            let events = p.machines.path(
                &mut self.s.kit,
                now,
                crate::proto::path::Input::SendFailed {
                    transport: q.transport,
                    addr: q.addr,
                },
                None,
            );
            let link = self.link(peer);
            let r = self.route(peer, link, None, events);
            let mut fx = Fx::default();
            self.cut(net, peer, r, &mut fx);
            self.closes(now, &fx.closes);
            return;
        }
        if self.to(peer) != Some(at) {
            return;
        }
        self.dead(net, peer, Some(at));
    }

    /// The node removes `peer` as dead: its link closed at `at`, at one
    /// path, or its liveness timer ran out with `at` `None`. The core is
    /// told `Dead`, as the node's link-dead path tells it, and the node
    /// redials as the core asks.
    fn dead(&mut self, net: &mut Net, peer: Node, at: Option<Addr>) {
        let now = net.now;
        let kept = self.addrs(peer);
        let out = self.core(In::Dead { peer: key(peer) }, TestInstant(now));
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
        // The world's adapter choice: the core keeps a dead link's
        // connections, as the current node does; the link's other paths'
        // connections that no link uses are closed.
        for a in kept {
            if !fault!(ReplacedConnKept)
                && Some(a) != at
                && net.kind(a.transport) != Kind::Datagram
                && !self.uses(a)
            {
                net.close(self.s.ix, a);
            }
        }
        self.note(
            now,
            peer,
            Event::Lost,
            Rec {
                change: Some(M::Remove),
                ..Rec::default()
            },
        );
        self.closes(now, &fx.closes);
    }

    fn wake(&mut self, net: &mut Net) {
        let (ix, me, now, epoch) = (self.s.ix, self.s.me, net.now, self.epoch());
        let at = TestInstant(now);
        let polled = self.s.table.poll(at);
        self.s.polled = Some(now);
        self.check();
        let mut fx = Fx::default();
        let mut reaped = Vec::new();
        for o in &polled {
            if let Output::Retire { link, .. } = o
                && let Some(r) = self.s.runs.get(link)
            {
                reaped.push((r.hs, r.peer, r.role));
            }
        }
        self.effects(net, polled, &mut fx);
        for (link, bytes) in core::mem::take(&mut fx.resends) {
            if let Some(Run {
                hs,
                bytes: b,
                role: Role::Dial { to, from },
                ..
            }) = self.s.runs.get(&link)
            {
                let (hs, b, to, from) = (*hs, *b, *to, *from);
                let wire = net.intern(&bytes);
                let pkt = Pkt::Msg1 {
                    id: me,
                    hs,
                    bytes: b,
                    epoch,
                    wire,
                };
                net.send(ix, from, to, pkt);
                let out = self.core(In::Sent { link }, at);
                self.effects(net, out, &mut fx);
            }
        }
        if self.s.table.next_wake().is_some_and(|w| w <= at) {
            self.s.audit.push(String::from(
                "after a poll the core's next wake is still due",
            ));
        }
        self.closes(now, &core::mem::take(&mut fx.closes));
        for run in reaped {
            self.timed_out(net, run, &Fx::default());
        }
        self.connects(net);
        let peers: Vec<u8> = self.s.peers.keys().copied().collect();
        for k in peers {
            let peer = Node(k);
            if self
                .s
                .peers
                .get(&k)
                .and_then(|p| deadline(&p.machines))
                .is_some_and(|d| d <= now)
            {
                let held = self.s.peers.get(&k).and_then(|p| self.current(&p.machines));
                self.dead(net, peer, None);
                if let Some(hs) = held {
                    self.s.expired.push((peer, hs));
                }
                continue;
            }
            if self
                .s
                .peers
                .get(&k)
                .and_then(|p| p.machines.wake())
                .is_some_and(|w| w <= now)
            {
                let next = self.next();
                let Some(p) = self.s.peers.get_mut(&k) else {
                    continue;
                };
                let events = p.machines.poll(&mut self.s.kit, now, next);
                self.s.stepped.push(k);
                self.named(peer, Some(next));
                let link = self.link(peer);
                let r = self.route(peer, link, None, events);
                let cut = r.cut;
                let mut fx = Fx::default();
                self.cut(net, peer, r, &mut fx);
                if cut {
                    let rec = Rec {
                        change: Some(fx.change.unwrap_or(M::RekeyCutover)),
                        ..Rec::default()
                    };
                    self.note(now, peer, Event::RekeyCutover, rec);
                    self.closes(now, &fx.closes);
                    self.announce(net, peer);
                } else {
                    self.closes(now, &fx.closes);
                }
            }
            if self
                .s
                .peers
                .get(&k)
                .is_some_and(|p| now >= p.beat + HEARTBEAT)
            {
                self.announce(net, peer);
            }
        }
        let due: Vec<(u8, u16)> = self
            .s
            .idle
            .iter()
            .filter(|(_, t)| now >= **t)
            .map(|(k, _)| *k)
            .collect();
        for (transport, at) in due {
            self.s.idle.remove(&(transport, at));
            let a = Addr { transport, at };
            if !fault!(RefusedConnKept) && !self.uses(a) {
                net.close(ix, a);
            }
        }
        for c in self.s.configured.clone() {
            let due = self.s.retry.get(&c.peer.0).is_some_and(|&t| now >= t);
            let idle = !self.s.peers.contains_key(&c.peer.0)
                && !self.s.runs.iter().any(|(l, r)| {
                    r.peer == c.peer
                        && matches!(r.role, Role::Dial { .. })
                        && self.s.table.legs().get(*l).is_some()
                });
            if due && idle {
                self.dial(net, c.peer, c.to, c.from);
            } else if due {
                self.s.retry.remove(&c.peer.0);
            }
        }
    }

    /// Start an own rekey of `peer` now, through the machine's time
    /// trigger, which every other start condition still decides.
    fn trigger(&mut self, net: &mut Net, peer: Node) {
        let now = net.now;
        let next = self.next();
        let Some(p) = self.s.peers.get_mut(&peer.0) else {
            return;
        };
        let events = p.machines.trigger(&mut self.s.kit, now, next);
        self.named(peer, Some(next));
        let link = self.link(peer);
        let r = self.route(peer, link, None, events);
        let mut fx = Fx::default();
        self.cut(net, peer, r, &mut fx);
        self.closes(now, &fx.closes);
    }

    /// The node's process restarts: everything is forgotten, and it dials
    /// each configured peer again.
    fn restart(&mut self, net: &mut Net) {
        self.wipe(net.now);
        let s = &mut self.s;
        s.life += 1;
        s.count = 0;
        s.table = Table::new(key(s.me), Params::default());
        s.runs.clear();
        s.rekeys.clear();
        s.connecting.clear();
        s.retry.clear();
        s.idle.clear();
        s.names = Names::default();
        s.store = store();
        let epoch = Epoch((u32::from(s.me.0) << 8) | s.life);
        s.kit = Kit::new(s.me, epoch, &super::kinds());
        self.log.push(Entry::Restart);
        for c in self.s.configured.clone() {
            self.dial(net, c.peer, c.to, c.from);
        }
    }

    /// Give back everything the core and the shell hold: the process ends.
    fn wipe(&mut self, now: Ms) {
        let out = self.s.table.close(TestInstant(now));
        discard(&mut self.s.kit, out);
        for (_, p) in core::mem::take(&mut self.s.peers) {
            let (events, _) = p
                .machines
                .close(&mut self.s.kit, now, rekey::Close::Shutdown);
            drop(events);
        }
        self.s.bound.clear();
    }
}

impl JointParty {
    /// The node's state key: every field of [`State`], each held peer's
    /// machines by [`Machines::key`] and the kit without its scratch
    /// buffer, which a machine writes before it reads. The fields are
    /// named one by one, so a field added to the state is a compile error
    /// here until it is keyed or left out with a reason.
    fn key(&self) -> String {
        let State {
            ix,
            now,
            polled,
            me,
            mode,
            life,
            count,
            configured,
            retry,
            idle,
            table,
            runs,
            peers,
            kit,
            store,
            names,
            bound,
            connecting,
            audit,
            known,
            rekeys,
            floors,
            found,
            pins: _,
            ledger: _,
            stepped: _,
            copy: _,
            expired: _,
            limits,
        } = &self.s;
        let mut out = format!(
            "{ix} {now} {polled:?} {me:?} {mode:?} {life} {count} {configured:?} {retry:?} {idle:?} {table:?} {runs:?} "
        );
        for (k, p) in peers {
            let Held {
                machines,
                link,
                origin,
                answered,
                beat,
                own,
                heard,
                listed,
                gated,
                cut,
                owed,
                started,
            } = p;
            let _ = write!(
                out,
                "{k}: {link:?} {origin:?} {answered} {beat} {own:?} {heard} {listed:?} {gated} {cut} {owed:?} {started:?} "
            );
            machines.key(*now, &mut out);
        }
        let Kit {
            local,
            pool,
            tags,
            jitter,
            scratch: _,
            draws,
            facts,
        } = kit;
        let _ = write!(
            out,
            " {local:?} {pool:?} {tags:?} {jitter:?} {draws:?} {facts:?} {store:?} {names:?} {bound:?} {connecting:?} {audit:?} {known:?} {rekeys:?} {floors:?} {found:?} {limits:?}"
        );
        out
    }
}

impl JointParty {
    /// The machines' own oracles after a step at `now`: each rekey
    /// machine's per-step rules, as after a poll for one this step polled,
    /// the conservation of the node's indices, and the path shell's checks
    /// of each bundle step, each failure recorded for the oracles.
    fn machined(&mut self, now: Ms) {
        let s = &mut self.s;
        let mut failed = Vec::new();
        let mut bound = 0;
        for (k, p) in &mut s.peers {
            let rk = p.machines.rekey();
            bound += rk.bindings().len();
            let polled = s.stepped.contains(k);
            failed.extend(super::oracle::machine(
                s.ix,
                rk,
                &rk.peek(),
                now,
                polled,
                p.started,
                s.limits,
            ));
            failed.extend(p.machines.failures());
        }
        bound += s
            .runs
            .keys()
            .filter(|l| s.table.legs().get(**l).is_some())
            .count();
        failed.extend(super::oracle::node(s.ix, s.kit.pool.used.len(), bound));
        s.found
            .extend(failed.into_iter().map(|m| (Oracle::Machine, m)));
    }

    /// What the joint world's oracles read of this node: for each peer the
    /// core holds, its record beside what the shell holds for it, and the
    /// node's index leases.
    fn facts(&self) -> super::oracle::Facts {
        use super::oracle::{Facts, Peer, Shell};
        let s = &self.s;
        let mut peers = Vec::new();
        // The core names its peers by address; the world has four
        // identities, so each is asked for.
        for (k, h) in [A, B, C, THIRD]
            .into_iter()
            .filter_map(|n| s.table.held(&key(n)).map(|h| (n, h)))
        {
            let shell = s.peers.get(&k.0).map(|p| {
                let rk = p.machines.rekey();
                let v = rk.view();
                Shell {
                    link: p.link,
                    identity: match v.identity {
                        rekey::Identity::Proven(key) => names::node(&key),
                        rekey::Identity::Claimed(_) => None,
                    },
                    epoch: v.peer_epoch,
                    gated: p.gated,
                    waiting: matches!(v.cycle, CycleView::PendI(_)),
                    cut: p.cut,
                    current: self.current(&p.machines),
                    origin: p.origin,
                    paths: p
                        .machines
                        .bundle()
                        .paths()
                        .paths()
                        .iter()
                        .map(|q| {
                            let r = crate::proto::path::PathRef {
                                transport: q.transport_id(),
                                addr: q.addr().clone(),
                            };
                            (
                                super::facts::addr(q.transport_id(), q.addr()),
                                route::proven(&p.machines, &r),
                            )
                        })
                        .collect(),
                    active: p.machines.active(),
                }
            });
            peers.push(Peer {
                peer: k,
                link: h.link,
                epoch: h.epoch,
                current: addr(&h.current),
                paths: s
                    .table
                    .links()
                    .get(h.link)
                    .map(|r| r.paths.iter().map(|(q, st)| (addr(q), *st)).collect())
                    .unwrap_or_default(),
                shell,
            });
        }
        let stray = s
            .peers
            .keys()
            .map(|&k| Node(k))
            .filter(|n| s.table.held(&key(*n)).is_none())
            .collect();
        Facts {
            peers,
            stray,
            pool: s.kit.pool.used.iter().copied().collect(),
            legs: s
                .runs
                .iter()
                .filter(|(l, _)| s.table.legs().get(**l).is_some())
                .map(|(_, r)| r.index)
                .collect(),
            bound: s
                .peers
                .values()
                .flat_map(|p| {
                    p.machines
                        .rekey()
                        .bindings()
                        .iter()
                        .map(|b| b.index)
                        .collect::<Vec<u32>>()
                })
                .collect(),
            derived: s.table.links().index() == &s.table.links().derived(),
            found: s.found.clone(),
            pins: s.pins.clone(),
        }
    }
}

impl JointParty {
    /// The earliest instant the node has something to do: the core's next
    /// wake, each held peer's machines, heartbeat and liveness deadline,
    /// the redials and the idle connections' closes; the bundles' wakes
    /// left out unless `bundles`.
    fn due(&self, bundles: bool) -> Option<Ms> {
        let s = &self.s;
        let table = s
            .table
            .next_wake()
            .map(|t| t.0)
            .filter(|&t| s.polled.is_none_or(|p| t > p));
        let peers = s.peers.values().flat_map(|p| {
            let m = if bundles {
                p.machines.wake()
            } else {
                p.machines.paced()
            };
            [m, Some(p.beat + HEARTBEAT), deadline(&p.machines)]
        });
        let rest = s.retry.values().chain(s.idle.values()).map(|&t| Some(t));
        core::iter::once(table)
            .chain(peers)
            .chain(rest)
            .flatten()
            .min()
    }
}

impl Drop for JointParty {
    fn drop(&mut self) {
        self.wipe(0);
    }
}

impl Party for JointParty {
    fn input(&mut self, net: &mut Net, inp: Input) {
        let leaks = leaked();
        self.s.now = net.now;
        self.s.ledger = Ledger::default();
        self.s.stepped.clear();
        self.s.copy = matches!(inp, Input::Packet { copy: true, .. });
        match inp {
            Input::Packet {
                src,
                local,
                pkt,
                stamp,
                ..
            } => match pkt {
                Pkt::Msg1 {
                    id,
                    hs,
                    bytes: b,
                    epoch,
                    wire,
                } => self.msg1(net, (src, local), id, hs, b, epoch, wire, stamp),
                Pkt::Msg2 {
                    id,
                    hs,
                    epoch,
                    wire,
                } => self.msg2(net, src, id, hs, epoch, wire, stamp),
                Pkt::Frame { id, hs, wire } => self.frame(net, (src, local), id, hs, wire, stamp),
                Pkt::Eof => self.closed(net, src),
            },
            Input::Closed { at } | Input::ConnectFailed { to: at } => self.closed(net, at),
            Input::Wake => self.wake(net),
            Input::Restart => self.restart(net),
            Input::Dial { peer, to, from } => self.dial(net, peer, to, from),
            Input::Rekey { peer } => {
                if self.rekeyable(peer) {
                    self.trigger(net, peer);
                }
            }
            Input::Beat => {
                for peer in self.held() {
                    self.announce(net, peer);
                }
            }
            Input::Path(PathEv::Candidate {
                peer,
                at,
                from,
                source,
            }) => {
                let mut fx = Fx::default();
                self.offer(net, peer, at, from, source, &mut fx);
                self.closes(net.now, &fx.closes);
            }
            Input::Path(PathEv::Carrier { transport, up }) => {
                let transport = TransportId::new(u32::from(transport));
                self.transported(net, PathInput::Carrier { transport, up });
            }
            Input::Path(PathEv::Gone { transport }) => {
                let transport = TransportId::new(u32::from(transport));
                self.transported(net, PathInput::Removed { transport });
            }
            // The stand-in's abstract path events: a joint node's bundle
            // writes the core's mirror, and nothing else may.
            Input::Path(
                PathEv::Moved { .. }
                | PathEv::Switched { .. }
                | PathEv::Released { .. }
                | PathEv::State { .. },
            ) => {}
            // The world applies a NAT's change; no node is told of it.
            Input::Path(PathEv::Rebound { .. }) => {}
        }
        self.s
            .runs
            .retain(|l, _| self.s.table.links().get(*l).is_some());
        if leaked() != leaks {
            self.s.audit.push(format!(
                "{} leases dropped unreleased",
                leaked().saturating_sub(leaks)
            ));
        }
        let ledger = core::mem::take(&mut self.s.ledger);
        for what in super::oracle::delivered(&ledger) {
            self.s.found.push((Oracle::Delivered, what));
        }
        self.machined(net.now);
        self.s.stepped.clear();
        self.s.copy = false;
    }

    fn wake(&self) -> Option<Ms> {
        self.due(true)
    }

    fn paced(&self) -> Option<Ms> {
        self.due(false)
    }

    fn digest(&self) -> String {
        self.key()
    }

    fn epoch(&self) -> Epoch {
        JointParty::epoch(self)
    }

    fn holds(&self, peer: Node, hs: Hs) -> bool {
        let Some(want) = self.s.names.kid(hs) else {
            return false;
        };
        self.s.peers.get(&peer.0).is_some_and(|p| {
            let pk = p.machines.rekey().peek();
            [pk.current, pk.pending, pk.previous]
                .into_iter()
                .flatten()
                .any(|e| kid(e.session) == want)
        })
    }

    fn held(&self) -> Vec<Node> {
        self.s.peers.keys().map(|&k| Node(k)).collect()
    }

    fn lapsed(&self) -> Vec<Addr> {
        let mut out = Vec::new();
        for p in self.s.peers.values() {
            for q in p.machines.bundle().paths().paths() {
                if q.acked() && q.state() != PathState::Live {
                    out.push(super::facts::addr(q.transport_id(), q.addr()));
                }
            }
        }
        out
    }

    fn joint(&self) -> Option<super::oracle::Facts> {
        Some(self.facts())
    }

    fn rekey(&self, peer: Node) -> Option<&super::machines::Machine> {
        self.s.peers.get(&peer.0).map(|p| p.machines.rekey())
    }

    fn expired(&mut self) -> Vec<(Node, Hs)> {
        core::mem::take(&mut self.s.expired)
    }

    fn rekeyable(&self, peer: Node) -> bool {
        self.s.table.held(&key(peer)).is_some()
            && self.s.peers.get(&peer.0).is_some_and(|p| {
                matches!(p.machines.rekey().view().cycle, CycleView::Idle)
                    && self.eligible(&p.machines, self.s.now)
            })
    }

    fn view(&self) -> View {
        let s = &self.s;
        let mut v = View::empty(s.me);
        v.configured = s.configured.iter().map(|c| c.peer).collect();
        v.log = self.log.clone();
        v.audit = s.audit.clone();
        v.rekeys = s.rekeys.clone();
        v.needs = self.needs();
        let links = s.table.links();
        let live = |l: &LinkNo| s.table.legs().get(*l).is_some();
        let mut bound: Vec<(u32, u8)> = Vec::new();
        for (k, p) in &s.peers {
            let peer = Node(*k);
            let rk = p.machines.rekey();
            bound.extend(rk.bindings().iter().map(|b| (b.index, *k)));
            let Some(h) = s.table.held(&key(peer)) else {
                v.audit.push(format!("peer {k}: machines and no held peer"));
                continue;
            };
            let Some(r) = links.get(h.link) else {
                v.audit
                    .push(format!("peer {k}: link {:?} has no record", h.link));
                continue;
            };
            if r.holder != Holder::Peer(key(peer)) {
                v.audit.push(format!(
                    "peer {k}: link {:?} held by {:?}",
                    h.link, r.holder
                ));
            }
            let Some(run) = s.runs.get(&h.link) else {
                v.audit
                    .push(format!("peer {k}: link {:?} has no handshake", h.link));
                continue;
            };
            let Some(cur) = self.current(&p.machines) else {
                v.audit
                    .push(format!("peer {k}: a current session with no name"));
                continue;
            };
            let (view, peek) = (rk.view(), rk.peek());
            let pending = peek
                .pending
                .and_then(|e| s.names.name(kid(e.session)))
                .map(|h| (h, view.pending.is_some_and(|e| e.role == Side::Initiator)));
            let rekey = match view.cycle {
                CycleView::Init => p.own.as_ref().map(|(h, _)| *h),
                CycleView::Idle | CycleView::PendI(_) | CycleView::PendR => None,
            };
            v.bounds.push(("record", peek.record, 64));
            v.peers.push(PeerView {
                peer,
                cur,
                origin: p.origin,
                link: run.hs,
                dir: match r.dir {
                    LinkDir::Inbound => Dir::Inbound,
                    LinkDir::Outbound => Dir::Outbound,
                },
                at: addr(&r.setup),
                current: addr(&h.current),
                answered: p.answered,
                pending,
                rekey,
                dials: s
                    .runs
                    .iter()
                    .filter(|(l, r)| {
                        r.peer == peer && matches!(r.role, Role::Dial { .. }) && live(l)
                    })
                    .map(|(_, r)| r.hs)
                    .collect(),
            });
        }
        bound.sort_unstable();
        let mut map: Vec<(u32, u8)> = s.bound.iter().map(|(i, k)| (*i, *k)).collect();
        map.sort_unstable();
        if bound != map {
            v.audit.push(format!(
                "the index map {map:?} is not what the machines bind {bound:?}"
            ));
        }
        v.bounds.push(("peers", s.peers.len(), 8));
        v.bounds
            .push(("legs", s.runs.keys().filter(|l| live(l)).count(), 8));
        v
    }
}

use super::super::explore::{Act, apply, replay};
use super::super::oracle::{Breach, heal, healed, scripted};
use super::super::starts::{
    Start, TCP, UDP, age, dial_home, home, second, settle, starts, world_of,
};
use super::super::world::World;

/// Start `number`'s first variant, with joint nodes at Off at both ends.
fn start(number: u8) -> Start {
    let mut st = starts()
        .into_iter()
        .find(|s| s.number == number)
        .expect("the start exists");
    st.maker = super::off;
    st
}

/// Start `number`'s world after its own script.
fn scripted_world(number: u8) -> World {
    let st = start(number);
    let mut w = replay(&st, &[]);
    let _ = (st.script)(&mut w);
    w
}

/// Node `x`'s view of node `y`.
fn peer(w: &World, x: usize, y: usize) -> PeerView {
    let id = w.ids[y];
    w.parties[x]
        .view()
        .peers
        .into_iter()
        .find(|p| p.peer == id)
        .unwrap_or_else(|| panic!("n{x} holds n{y}"))
}

/// Two joint nodes at Off, node 0 dialing node 1 on UDP, settled.
fn pair_up() -> World {
    let mut w = world_of(super::off, &[A, B], &[&[(1, UDP)], &[]]);
    dial_home(&mut w, 0, 1, UDP);
    settle(&mut w);
    w
}

/// The frame node `x` sends node `y` at once, taken out of flight.
fn beat(w: &mut World, x: usize, y: usize) -> Pkt {
    apply(w, Act::Frame(x));
    let i = w
        .net
        .flight
        .iter()
        .position(|f| f.to == y && matches!(f.pkt, Pkt::Frame { .. }))
        .unwrap_or_else(|| panic!("n{x} sends n{y} a frame"));
    w.net.flight.remove(i).pkt
}

/// Deliver to node `y` the frame `pkt`, arriving from `src`.
fn arrive(w: &mut World, y: usize, src: Addr, pkt: Pkt) {
    let local = home(y, src.transport);
    w.net.inject(y, local, src, pkt);
    let id = w.net.flight.last().expect("injected").id;
    w.deliver(id);
}

/// What node `x` logged for the msg1 of handshake `hs`.
fn logged(w: &World, x: usize, hs: Hs) -> Option<Rec> {
    w.parties[x].view().log.into_iter().find_map(|e| match e {
        Entry::Ev {
            ev: Event::Msg1 { hs: h, .. },
            rec,
            ..
        } if h == hs => Some(rec),
        Entry::Ev { .. }
        | Entry::Abandon { .. }
        | Entry::Unadopted { .. }
        | Entry::Restart
        | Entry::Fallback => None,
    })
}

#[test]
fn a_crossing_on_a_connection_oriented_transport_leaves_the_smaller_node_at_its_dials_pair_on_real_machines()
 {
    let w = scripted_world(3);
    let p = peer(&w, 0, 1);
    assert_eq!(
        p.dir,
        Dir::Outbound,
        "precondition: the smaller node settled on its own dial's link"
    );
    assert_eq!(
        p.current,
        home(1, TCP),
        "the smaller node holds the larger at the pair it dialed, not at the inbound connection's"
    );
}

#[test]
fn a_crossing_settles_on_one_session_on_real_machines() {
    let st = start(1);
    let found = scripted(&st);
    assert!(found.is_empty(), "every property holds: {found:?}");
    let mut w = replay(&st, &[]);
    let _ = (st.script)(&mut w);
    heal(&mut w);
    let (p, q) = (peer(&w, 0, 1), peer(&w, 1, 0));
    assert_eq!(p.cur, q.cur, "both ends hold one session");
    assert!(
        w.parties[1].holds(A, p.cur) && w.parties[0].holds(B, q.cur),
        "and each holds the keys of the other's"
    );
}

#[test]
fn a_rekey_cuts_over_at_both_ends_and_the_old_session_drains() {
    let mut w = pair_up();
    age(&mut w, 40_000);
    let first = peer(&w, 0, 1).cur;
    assert_eq!(peer(&w, 1, 0).cur, first, "precondition: one session");
    assert!(w.parties[0].rekeyable(B), "precondition: past both floors");
    apply(&mut w, Act::Rekey(0, 1));
    let rekey = peer(&w, 0, 1).rekey.expect("node 0's own rekey is out");
    settle(&mut w);
    assert_eq!(
        peer(&w, 1, 0).pending,
        Some((rekey, false)),
        "node 1 answered and holds the rekey pending"
    );
    w.run_until(w.net.now + 1_000);
    settle(&mut w);
    let (p, q) = (peer(&w, 0, 1), peer(&w, 1, 0));
    assert_eq!(p.cur, rekey, "node 0 cut over to its rekey");
    assert_eq!(q.cur, rekey, "node 1 cut over at node 0's frame");
    assert!(
        w.parties[0].holds(B, first) && w.parties[1].holds(A, first),
        "the old session still opens while it drains"
    );
    age(&mut w, 20_000);
    assert!(
        !w.parties[0].holds(B, first) && !w.parties[1].holds(A, first),
        "and is gone once drained"
    );
    let left: Vec<Breach> = healed(&w);
    assert!(left.is_empty(), "nothing is left wrong: {left:?}");
}

#[test]
fn after_a_frame_from_another_transport_sends_stay_on_the_active_path() {
    let mut w = scripted_world(2);
    settle(&mut w);
    age(&mut w, 40_000);
    let active = peer(&w, 0, 1).current;
    assert_eq!(
        active,
        home(1, UDP),
        "precondition: node 0 holds node 1 on node 0's own dial, over UDP"
    );
    let off = at_of(TCP, 1001);
    let pkt = beat(&mut w, 1, 0);
    arrive(&mut w, 0, off, pkt);
    assert_eq!(
        peer(&w, 0, 1).current,
        off,
        "precondition: the core's record of the peer followed the frame to the other transport"
    );
    apply(&mut w, Act::Frame(0));
    assert!(w.parties[0].rekeyable(B), "precondition: past both floors");
    apply(&mut w, Act::Rekey(0, 1));
    let sent: Vec<(Addr, Pkt)> = w
        .net
        .flight
        .iter()
        .filter(|f| f.to == 1)
        .map(|f| (f.local, f.pkt))
        .collect();
    let there = |frame: bool| {
        sent.iter().any(|(to, p)| {
            *to == active
                && matches!(
                    (frame, p),
                    (true, Pkt::Frame { .. }) | (false, Pkt::Msg1 { .. })
                )
        })
    };
    assert!(
        there(true) && there(false),
        "the heartbeat and the rekey msg1 go to the bundle's active path: {sent:?}"
    );
    assert!(
        sent.iter().all(|(to, _)| *to == active),
        "and nothing goes where the core's record moved: {sent:?}"
    );
}

fn at_of(transport: u8, at: u16) -> Addr {
    Addr { transport, at }
}

#[test]
fn a_restart_revealed_in_a_rekey_msg2_reaches_the_core() {
    let mut w = pair_up();
    age(&mut w, 40_000);
    let before = w.parties[1].epoch();
    apply(&mut w, Act::Restart(1));
    assert_ne!(
        w.parties[1].epoch(),
        before,
        "precondition: node 1 restarted"
    );
    assert!(w.parties[0].rekeyable(B), "precondition: node 0 may rekey");
    apply(&mut w, Act::Rekey(0, 1));
    settle(&mut w);
    w.run_until(w.net.now + 1_000);
    settle(&mut w);
    // The initiator cuts over at the next check, or at the peer's first
    // frame under the new session if it comes first; either is logged with
    // the change the core made.
    let cut = w.parties[0].view().log.into_iter().find_map(|e| match e {
        Entry::Ev {
            ev: ev @ (Event::RekeyCutover | Event::Frame { .. }),
            rec,
            ..
        } if rec.change.is_some() && rec.change != Some(M::Promote) => Some((ev, rec.change)),
        Entry::Ev { .. }
        | Entry::Abandon { .. }
        | Entry::Unadopted { .. }
        | Entry::Restart
        | Entry::Fallback => None,
    });
    assert_eq!(
        cut.map(|(_, c)| c),
        Some(Some(M::Restarted)),
        "node 0's cutover is the core's restart, the link kept: {cut:?}"
    );
    heal(&mut w);
    let left: Vec<Breach> = super::super::oracle::every_step(&w)
        .into_iter()
        .chain(healed(&w))
        .collect();
    assert!(left.is_empty(), "every property holds after: {left:?}");
}

#[test]
fn a_fresh_msg1_on_a_young_link_reaches_the_gates() {
    let mut w = pair_up();
    dial_home(&mut w, 1, 0, UDP);
    let hs = match w.net.flight.iter().find(|f| f.to == 0).map(|f| f.pkt) {
        Some(Pkt::Msg1 { hs, .. }) => hs,
        other => panic!("precondition: node 1's msg1 is in flight: {other:?}"),
    };
    let id = w
        .net
        .flight
        .iter()
        .find(|f| f.to == 0)
        .map(|f| f.id)
        .expect("in flight");
    w.deliver(id);
    let rec = logged(&w, 0, hs).expect("node 0 logged the msg1");
    assert_eq!(
        rec.class,
        Some(Class::Replacement),
        "the machine took the fresh msg1 on the young link for a replacement"
    );
    assert!(
        rec.refused.is_some() || rec.change.is_some(),
        "and the restart gates judged it: {rec:?}"
    );
}

#[test]
fn a_one_path_roam_reaches_the_link_record() {
    let mut w = pair_up();
    let pkt = beat(&mut w, 1, 0);
    arrive(&mut w, 0, second(1, UDP), pkt);
    let needs = w.parties[0].view().needs;
    assert!(
        needs.contains(&second(1, UDP)) && !needs.contains(&home(1, UDP)),
        "the link's one path, as the core records it, followed the frame to the new address: {needs:?}"
    );
    let left: Vec<Breach> = super::super::oracle::every_step(&w);
    assert!(left.is_empty(), "the maps agree: {left:?}");
}

/// When node `x` last logged a frame from node `y`, and when it logged
/// its loss of `y`, if it did.
fn hearing(w: &World, x: usize, y: usize) -> (Option<Ms>, Option<Ms>) {
    let id = w.ids[y];
    let (mut heard, mut lost) = (None, None);
    for e in w.parties[x].view().log {
        if let Entry::Ev { at, peer, ev, .. } = e
            && peer == id
        {
            match ev {
                Event::Frame { .. } => heard = Some(at),
                Event::Lost => lost = Some(at),
                Event::Advance(_)
                | Event::Dial { .. }
                | Event::Msg1 { .. }
                | Event::Msg2 { .. }
                | Event::Msg2Sent { .. }
                | Event::RekeyStart { .. }
                | Event::RekeyMsg2 { .. }
                | Event::RekeyCutover
                | Event::Timeout { .. }
                | Event::Close { .. }
                | Event::Restart => {}
            }
        }
    }
    (heard, lost)
}

#[test]
fn a_peer_silent_for_the_link_dead_timeout_is_removed_then_and_redialled() {
    // Everything node 1 sends node 0 is lost from here on; node 0's frames
    // still reach node 1.
    let mut w = pair_up();
    for _ in 0..64 {
        w.net.flight.retain(|f| f.to != 0);
        if hearing(&w, 0, 1).1.is_some() {
            break;
        }
        w.advance();
        w.net.flight.retain(|f| f.to != 0);
        w.drain(64);
    }
    let (heard, lost) = hearing(&w, 0, 1);
    let heard = heard.expect("precondition: node 0 heard node 1 once");
    assert_eq!(
        lost,
        Some(heard + super::feeds::LIVE),
        "node 0 removes node 1 at the link-dead timeout after the last frame it authenticated"
    );
    assert!(!w.parties[0].held().contains(&B), "and holds it no more");
    let end = w.net.now + RETRY;
    w.run_until(end);
    assert!(
        w.net
            .flight
            .iter()
            .any(|f| f.to == 1 && matches!(f.pkt, Pkt::Msg1 { id, .. } if id == A)),
        "node 0 redials its configured peer at the retry interval"
    );
}

#[test]
fn a_peer_silent_past_the_link_dead_timeout_on_a_link_of_several_paths_is_removed_and_the_pair_heals()
 {
    // The connection-oriented crossing, multipath on at both ends: node 1
    // holds node 0 on the inbound TCP link and has turned capable, so its
    // link has a second path, Probing, at node 0's TCP home. Then the
    // link's one connection fails: node 0, at one path, removes node 1;
    // node 1, at two, is told only of a failed send, and its liveness
    // timer removes node 0 once nothing is heard for the link-dead
    // timeout. The second path reaches the same shape from a restart.
    use super::super::explore::Act::{Connect, Deliver, Dup, Fail, Restart};
    let st = super::starts::on()
        .into_iter()
        .find(|s| s.number == 3)
        .expect("the connection-oriented crossing");
    let paths: [&[Act]; 2] = [
        &[
            Deliver(0),
            Deliver(1),
            Deliver(2),
            Deliver(3),
            Deliver(4),
            Deliver(5),
            Fail(0, 0),
        ],
        &[
            Dup(0),
            Restart(1),
            Connect(2, true),
            Deliver(3),
            Deliver(4),
            Deliver(5),
            Fail(2, 0),
        ],
    ];
    for path in paths {
        let mut w = replay(&st, path);
        let holds = |w: &World, x: usize| w.parties[x].held().contains(&w.ids[1 - x]);
        assert!(
            holds(&w, 0) != holds(&w, 1),
            "precondition: {path:?} leaves one end holding the other"
        );
        heal(&mut w);
        let found: Vec<Breach> = super::super::oracle::every_step(&w)
            .into_iter()
            .chain(healed(&w))
            .collect();
        assert!(
            found.is_empty(),
            "after {path:?}, the end that kept its peer removes it at the link-dead timeout and the pair heals: {found:?}"
        );
    }
}

#[test]
fn every_start_settles_scripted_off_with_off() {
    let mut wrong = Vec::new();
    for mut st in starts().into_iter().filter(|s| !matches!(s.number, 6 | 7)) {
        st.maker = super::off;
        for b in scripted(&st) {
            wrong.push(format!(
                "{} (off with off): {:?} at n{}: {}",
                st.name, b.oracle, b.node, b.what
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn starts_6_and_7_show_their_two_defects_on_real_machines() {
    for mut st in starts().into_iter().filter(|s| matches!(s.number, 6 | 7)) {
        st.maker = super::off;
        let found = scripted(&st);
        // Start 6's two ends hold each other on different sessions, so
        // each hears nothing the other sends, and one end's liveness timer
        // ends the split by removing its peer within the heal.
        let clause = if st.number == 6 { "split:" } else { "pending:" };
        assert!(
            found
                .iter()
                .any(|b| b.oracle == Oracle::OneSession && b.what.starts_with(clause)),
            "{} shows its defect at the {clause} clause: {found:?}",
            st.name
        );
        // The machines of the split pair have not converged either, which
        // is the same defect seen from the machines.
        assert!(
            found.iter().all(|b| b.oracle == Oracle::OneSession
                || (b.oracle == Oracle::Machine && b.what.starts_with(super::oracle::CONVERGED))),
            "{} shows nothing else: {found:?}",
            st.name
        );
    }
}
