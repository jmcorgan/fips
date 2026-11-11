//! A model of the current node's settlement, transcribed from `master` at
//! `db946033` (the line ranges are in this directory's README), running a
//! real rekey machine and a real path bundle per held peer.
//!
//! [`MasterParty`] decides as the node does: the duplicate-msg1 short
//! circuit, `establish_inbound`'s classification, the hand-off of a
//! same-epoch msg1 to the peer's link rekey machine, the restart and
//! replacement gates with the replay memory, the inbound promotion,
//! `establish_outbound`'s promote, restart, swap and keep, the close of a
//! losing leg by `addr_carries_other_peer`, the release of a path, the link
//! timers and the feeds of the bundles. Its gates read the clock the node
//! reads, the peer clock, which a step of the wall clock does not move. A
//! swap moves the session and keeps the peer's link record, as
//! `move_session` does, counts the peering heard (FRC-1201 Section 5.5),
//! and starts the bundle again at the msg2's pair.
//!
//! Its rekey and its paths are the machines': a peer's [`Machines`]
//! (`../joint/machines.rs`) take each same-epoch msg1, each own rekey's
//! msg2, each frame and each poll, and [`route`] turns what they ask for
//! into sends and the node's own bookkeeping. The peer's address is the
//! bundle's active path, as the node's is (`current_addr`). Its messages are
//! real stub IK messages, carried as a packet's wire bytes beside its
//! abstract fields, and an abstract far end's are written from their names
//! (`../joint/names.rs`).
//!
//! It logs every history event it sees and what it did, so the oracles
//! can compare it with the reference model step by step.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use super::super::super::model::history::{Addr, Bytes, Epoch, Event, Hs, LinkId, Node};
use super::super::super::model::judge::{Class, Gate, Transition};
use super::super::drive::{addr, epoch as wired};
use super::super::joint::Mode;
use super::super::joint::feeds::{self, Listings};
use super::super::joint::machines::{Event as Ev, Kit, Machines, Setup, messaged};
use super::super::joint::names;
use super::super::joint::party::{BEAT, deadline, session, store};
use super::super::joint::route::{self, Ctx, Routed, Send};
use super::super::party::{Configured, binding};
use super::super::shadow::{Entry, Rec, Refusal};
use super::super::world::{
    Dir, HANDSHAKE, HEARTBEAT, Input, Kind, Ms, Net, Party, PathEv, PeerView, Pkt, RESEND, RESENDS,
    RETRY, State as Open, View,
};
use crate::proto::path::{Input as PathInput, Match, Output as PathOutput, PathState, Source};
use crate::proto::rekey::tests::stub::{Hs as Attempt, Ik, Kid, Msg1, hint, kid, read_msg1};
use crate::proto::rekey::{
    self, Arrival, Completed, CycleView, IndexLease, Msg1Read, Profile, Reason, Record,
    RecordStore, Role as Side, Route, allocate, leaked,
};
use crate::proto::settle::input::Input as In;
use crate::proto::settle::links::LinkNo;
use crate::transport::TransportId;

/// `EPOCH_RESTART_MIN_INTERVAL_SECS`, in ms.
const INTERVAL: Ms = 15_000;
/// `UNHEARD_PEERING_MIN_AGE_MS`.
const UNHEARD: Ms = 1_000;
/// `MAX_REPLAYED_MSG1S`.
const REPLAYS: usize = 8;

/// A link record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Link {
    dir: Dir,
    remote: Addr,
    hs: Hs,
    /// A released path at `remote` queued its connection's close, so no
    /// connection there is this link's any more.
    closing: bool,
}

/// An own dial in flight (`pending_outbound` and its `PeerMachine`).
#[derive(Debug)]
struct Dial {
    peer: Node,
    link: u32,
    to: Addr,
    from: Option<Addr>,
    /// This node's address on the handshake's path.
    local: Addr,
    resends: u32,
    next: Ms,
    deadline: Ms,
    /// The msg1 on the wire.
    msg1: Vec<u8>,
    /// The handshake's state.
    state: Attempt,
    /// The index the leg holds.
    lease: IndexLease,
}

/// A msg1's answer: the completed handshake, the msg2, the setup record a
/// responder notes, and the index the session takes.
#[derive(Debug)]
struct Answered {
    done: Completed<Ik>,
    msg2: Vec<u8>,
    record: Record,
    lease: IndexLease,
}

/// An inbound leg whose msg2 could not be sent: its stored msg2 waits for
/// a resend of the msg1.
#[derive(Debug)]
struct Leg {
    peer: Node,
    link: u32,
    /// This node's address on the handshake's path.
    local: Addr,
    deadline: Ms,
    answer: Answered,
}

/// An active peer.
#[derive(Debug)]
struct Peer {
    link: u32,
    origin: Hs,
    /// An authenticated frame arrived on this peering, or this node
    /// initiated it (`is_heard`).
    heard: bool,
    /// When the peer was promoted, on the peer clock (`promoted_at`).
    promoted: Ms,
    /// When an authenticated frame last arrived, on the peer clock; the
    /// promotion before the first (`heard_at`).
    last: Ms,
    answered: bool,
    machines: Machines,
    beat: Ms,
    /// This node's own rekey msg1: its name and its bytes.
    own: Option<(Hs, Vec<u8>)>,
    /// The pairs the node's feeds list for the peer.
    listed: Listings,
}

/// Everything the node keeps, the log aside.
#[derive(Debug)]
struct State {
    ix: usize,
    now: Ms,
    me: Node,
    mode: Mode,
    life: u32,
    count: u32,
    nlinks: u32,
    configured: Vec<Configured>,
    retry: BTreeMap<u8, Ms>,
    links: BTreeMap<u32, Link>,
    index: BTreeMap<(u8, u16), u32>,
    peers: BTreeMap<u8, Peer>,
    dials: BTreeMap<u32, Dial>,
    legs: BTreeMap<u32, Leg>,
    dampener: BTreeMap<u8, Ms>,
    replayed: BTreeMap<u8, Vec<(Hs, Ms)>>,
    /// Inbound connections whose msg1 left no link, by address, and when
    /// the node gives up on each.
    idle: BTreeMap<(u8, u16), Ms>,
    /// The node's capabilities its machines borrow.
    kit: Kit,
    /// The replay records of closed links.
    store: RecordStore,
    /// Handshake names and the sessions they made.
    names: names::Names,
    /// Which peer each bound index routes to.
    bound: BTreeMap<u32, u8>,
    /// The next counter of each session's frames from an abstract far end,
    /// which sends no bytes, so the receiving shell numbers them.
    counters: BTreeMap<u32, u64>,
    /// The two start floors of an own rekey, in ms.
    floors: (Ms, Ms),
    /// Broken promises, seen by the shell.
    audit: Vec<String>,
    /// The connections the peers' bundles asked for that have not yet been
    /// seen to settle: the peer, and its pair (`PathDriver::connecting`).
    connecting: Vec<(u8, Addr)>,
    /// The connections released paths left to close
    /// (`PathDriver::closing`), closed once the step that released them is
    /// done, and at the next wake for a renewal's.
    closing: Vec<Addr>,
    /// The peers the liveness timer removed in this step, each with the
    /// handshake of the session it was held on and that session's origin,
    /// which the world takes after it. Empty between steps, so the key
    /// leaves it out.
    expired: Vec<(Node, Hs, Hs)>,
}

/// The current node.
pub struct MasterParty {
    s: State,
    log: Vec<Entry>,
}

/// The model of `master` as a node.
pub fn master(ix: usize, me: Node, configured: Vec<Configured>) -> alloc::boxed::Box<dyn Party> {
    alloc::boxed::Box::new(MasterParty::new(ix, me, configured, Mode::Off))
}

/// The model of `master` as a node with multipath on, the setting a release
/// flips to.
pub fn master_on(ix: usize, me: Node, configured: Vec<Configured>) -> alloc::boxed::Box<dyn Party> {
    alloc::boxed::Box::new(MasterParty::new(ix, me, configured, Mode::On))
}

fn key(a: Addr) -> (u8, u16) {
    (a.transport, a.at)
}

/// The link of this node's numbers that `link` names.
fn no(link: LinkNo) -> Option<u32> {
    u32::try_from(link.0).ok()
}

impl MasterParty {
    /// Node `ix` with identity `me` and multipath setting `mode`, redialing
    /// `configured`.
    pub fn new(ix: usize, me: Node, configured: Vec<Configured>, mode: Mode) -> Self {
        let cfg = mode.rekey();
        let ms = |d: crate::time::Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        let floors = (ms(cfg.config().floor_link), ms(cfg.config().floor_session));
        let kinds = super::super::joint::kinds();
        Self {
            s: State {
                ix,
                now: 0,
                me,
                mode,
                life: 0,
                count: 0,
                nlinks: 0,
                configured,
                retry: BTreeMap::new(),
                links: BTreeMap::new(),
                index: BTreeMap::new(),
                peers: BTreeMap::new(),
                dials: BTreeMap::new(),
                legs: BTreeMap::new(),
                dampener: BTreeMap::new(),
                replayed: BTreeMap::new(),
                idle: BTreeMap::new(),
                kit: Kit::new(me, Epoch(u32::from(me.0) << 8), &kinds),
                store: store(),
                names: names::Names::default(),
                bound: BTreeMap::new(),
                counters: BTreeMap::new(),
                floors,
                audit: Vec::new(),
                connecting: Vec::new(),
                closing: Vec::new(),
                expired: Vec::new(),
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

    fn link(&mut self, dir: Dir, remote: Addr, hs: Hs) -> u32 {
        self.s.nlinks += 1;
        let id = self.s.nlinks;
        self.s.links.insert(
            id,
            Link {
                dir,
                remote,
                hs,
                closing: false,
            },
        );
        self.s.index.insert(key(remote), id);
        id
    }

    /// `remove_link`: the record and every index entry naming it.
    fn unlink(&mut self, id: u32) {
        self.s.links.remove(&id);
        self.s.index.retain(|_, l| *l != id);
    }

    /// Every address whose connection a live link of this node uses: a
    /// link's setup address, unless a released path there queued its close,
    /// and each held peer's proven paths, the active one among them.
    fn needs(&self) -> Vec<Addr> {
        let links = self.s.links.values().filter(|l| !l.closing);
        let mut out: Vec<Addr> = links.map(|l| l.remote).collect();
        for p in self.s.peers.values() {
            out.extend(
                p.machines
                    .bundle()
                    .paths()
                    .paths()
                    .iter()
                    .filter(|q| q.acked() || q.state() == PathState::Live)
                    .map(|q| super::super::joint::facts::addr(q.transport_id(), q.addr())),
            );
        }
        out
    }

    /// Whether a link or a peer of this node sends at `at`.
    fn uses(&self, at: Addr) -> bool {
        self.needs().contains(&at)
    }

    /// `addr_carries_other_peer`: whether a peer on a link other than `link`
    /// sends or is proven at `at`.
    fn carried(&self, at: Addr, link: u32) -> bool {
        self.s
            .peers
            .values()
            .any(|p| p.link != link && matches!(p.machines.matched(at), Match::Proven { .. }))
    }

    /// Note the inbound connection a msg1 arrived on at `src` when it left
    /// no link there: the node closes it at the handshake timeout unless a
    /// link has come to use it.
    fn unused(&mut self, net: &Net, src: Addr) {
        if net.kind(src.transport) != Kind::Datagram
            && net.conn(self.s.ix, src).is_some()
            && !self.uses(src)
        {
            self.s.idle.entry(key(src)).or_insert(net.now + HANDSHAKE);
        }
    }

    fn heard(&self, peer: Node) -> bool {
        self.s.peers.get(&peer.0).is_some_and(|p| p.heard)
    }

    fn note(&mut self, now: Ms, peer: Node, ev: Event, mut rec: Rec) {
        rec.heard = self.heard(peer);
        self.log.push(Entry::Ev {
            at: now,
            peer,
            ev,
            rec,
        });
    }

    /// The peer's address as this node sends to it: the bundle's active
    /// path; `None` while no path is active.
    fn to(&self, peer: Node) -> Option<Addr> {
        self.s.peers.get(&peer.0).and_then(|p| p.machines.active())
    }

    /// This node's own address on its path to the peer's pair `to`.
    fn from(&self, peer: Node, to: Addr) -> Option<Addr> {
        self.s.peers.get(&peer.0).and_then(|p| p.machines.local(to))
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

    /// The pending session of `peer`'s machine.
    fn pending(&self, peer: Node) -> Option<Kid> {
        let p = self.s.peers.get(&peer.0)?;
        p.machines.rekey().peek().pending.map(|e| kid(e.session))
    }

    /// Route `events` of `peer`'s machines.
    fn route(&mut self, peer: Node, events: Vec<Ev>) -> Routed {
        let State {
            peers,
            bound,
            audit,
            ..
        } = &mut self.s;
        let Some(p) = peers.get_mut(&peer.0) else {
            return Routed::default();
        };
        let r = route::route(
            events,
            Ctx {
                peer,
                key: names::addr(peer),
                link: Some(LinkNo(u64::from(p.link))),
                released: None,
                machines: &p.machines,
                bound,
            },
        );
        audit.extend(r.broken.iter().cloned());
        r
    }

    /// Carry out what a call of `peer`'s machines asked for: the sends, the
    /// abandons for the log, and what the core would be told, which here
    /// the node does itself (`run_link_step`, `run_outputs`). Returns the
    /// peer change it amounts to. A connection a released path leaves is
    /// queued, for the caller's [`Self::drain`].
    fn carry(&mut self, net: &mut Net, peer: Node, r: Routed) -> Option<Transition> {
        let Routed {
            sends,
            inputs,
            abandoned,
            unadopted,
            ..
        } = r;
        self.sends(net, peer, sends, None);
        let mut change = None;
        for i in inputs {
            match i {
                // The link is kept, on the session the restarted peer holds
                // (`reset_restarted`).
                In::Restarted { .. } => change = Some(Transition::Restarted),
                In::Ended { .. } | In::Orphaned { .. } => self.lost(net, peer),
                // A path that moved takes the link's index entry with it.
                In::Moved { link, from, to } => {
                    let (from, to) = (addr(&from), addr(&to));
                    if self.s.index.get(&key(from)).copied() == no(link) {
                        self.s.index.remove(&key(from));
                        if let Some(l) = no(link) {
                            self.s.index.entry(key(to)).or_insert(l);
                        }
                    }
                }
                // The link's address lookup gains the pair switched to.
                In::Switched { link, to, .. } => {
                    if let Some(l) = no(link) {
                        self.s.index.entry(key(addr(&to))).or_insert(l);
                    }
                }
                In::Released { link, pair, keep } => self.release(no(link), addr(&pair), keep),
                // The node logs a path's state and does nothing else with it.
                In::State { .. } => {}
                i @ (In::Dial(_)
                | In::Punched(_)
                | In::ConnectFailed { .. }
                | In::Arrived { .. }
                | In::Msg1 { .. }
                | In::Replace(_)
                | In::Msg2 { .. }
                | In::Heard { .. }
                | In::Disconnect { .. }
                | In::Dead { .. }
                | In::Admin { .. }
                | In::Sent { .. }
                | In::SendFailed { .. }
                | In::HeldFrame { .. }
                | In::HoldLost { .. }) => {
                    self.s.audit.push(format!(
                        "{peer:?}: a machine's event routed to {:?}",
                        core::mem::discriminant(&i)
                    ));
                }
            }
        }
        if abandoned {
            self.log.push(Entry::Abandon { peer });
        }
        if unadopted {
            self.log.push(Entry::Unadopted { peer });
        }
        change
    }

    /// `release_path`: the path at `to` of the link `link` is handed back.
    /// The link's address lookup loses the pair, and unless `keep` says the
    /// peer may still send there, or another peer's link uses it, its
    /// connection is queued to close.
    fn release(&mut self, link: Option<u32>, to: Addr, keep: bool) {
        let Some(link) = link else {
            return;
        };
        if self.s.index.get(&key(to)) == Some(&link) {
            self.s.index.remove(&key(to));
        }
        if keep || self.carried(to, link) {
            return;
        }
        if let Some(l) = self.s.links.get_mut(&link).filter(|l| l.remote == to) {
            l.closing = true;
        }
        self.s.closing.push(to);
    }

    /// `drain_closes`: close every connection a released path left. The
    /// queue is not read again against what happened since it was filled.
    fn drain(&mut self, net: &mut Net) {
        for at in core::mem::take(&mut self.s.closing) {
            if net.kind(at.transport) != Kind::Datagram {
                net.close(self.s.ix, at);
                self.closed(net, at);
            }
        }
    }

    /// Carry out the sends of `peer`'s machines. `answering` is the msg1 a
    /// msg2 answers, with where it arrived and whether on a proven path, if
    /// any.
    fn sends(
        &mut self,
        net: &mut Net,
        peer: Node,
        sends: Vec<Send>,
        answering: Option<(Hs, Addr, Addr, bool)>,
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
                            self.s.count += 1;
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
                    let Some((hs, src, local, proven)) = answering else {
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
                    // An answer on the arrival goes there only when the msg1
                    // came on one of the link's proven paths.
                    match route {
                        Route::Arrival if proven => {
                            net.send(ix, Some(local), src, pkt);
                        }
                        Route::Arrival => self.answer(net, peer, src, pkt, true),
                        Route::Established { fallback } => {
                            self.answer(net, peer, src, pkt, fallback);
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
                Send::Path { to, bytes } => self.message(net, peer, to, &bytes),
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
    /// path. On a connection-oriented transport it goes only on a connection
    /// already open or opening there (`send_via`, which does not dial).
    fn message(&mut self, net: &mut Net, peer: Node, to: Addr, bytes: &[u8]) {
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

    /// Step `peer`'s bundle with `input` and carry out what it asks,
    /// closing the connections it left (`step_path`). A candidate is offered
    /// from `local`.
    fn stepped(&mut self, net: &mut Net, peer: Node, input: PathInput, local: Option<Addr>) {
        let Some(p) = self.s.peers.get_mut(&peer.0) else {
            return;
        };
        let events = p.machines.path(&mut self.s.kit, net.now, input, local);
        let r = self.route(peer, events);
        self.carry(net, peer, r);
        self.drain(net);
    }

    /// `intake`: `source` reports that `peer` may be reachable at `at`, from
    /// this node's address `from` or its home on that transport: offered to
    /// the peer's bundle unless a feed lists it already, and nothing with
    /// multipath disabled or for a peer not held.
    fn offer(&mut self, net: &mut Net, peer: Node, at: Addr, from: Option<Addr>, source: Source) {
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
        let q = super::super::joint::facts::pair(at);
        let input = PathInput::Candidate {
            transport: q.transport,
            addr: q.addr,
            source,
        };
        self.stepped(net, peer, input, Some(local));
    }

    /// `paths_renewed`: the bundle started again with no candidate, so what
    /// the feeds listed for the old one is forgotten and the configuration's
    /// pairs for the peer are offered to it.
    fn renewed(&mut self, net: &mut Net, peer: Node) {
        if let Some(p) = self.s.peers.get_mut(&peer.0) {
            p.listed = Listings::default();
        }
        for (at, from) in feeds::configured(&self.s.configured, peer) {
            self.offer(net, peer, at, from, Source::Config);
        }
    }

    /// `poll_connects`: tell each bundle of the connections it asked for
    /// that have settled, opened or failed or gone. One still opening
    /// waits.
    fn connects(&mut self, net: &mut Net) {
        let ix = self.s.ix;
        for (k, to) in core::mem::take(&mut self.s.connecting) {
            let ok = match net.conn(ix, to).map(|(i, _)| net.conns[i].state) {
                Some(Open::Connecting) => {
                    self.s.connecting.push((k, to));
                    continue;
                }
                Some(Open::Open) => true,
                Some(Open::Closed(_)) | None => false,
            };
            let q = super::super::joint::facts::pair(to);
            let input = PathInput::Connected {
                transport: q.transport,
                addr: q.addr,
                ok,
            };
            self.stepped(net, Node(k), input, None);
        }
    }

    /// A change of the node's transport, given to every held peer's bundle.
    fn transported(&mut self, net: &mut Net, input: PathInput) {
        for k in self.held() {
            self.stepped(net, k, input.clone(), None);
        }
    }

    /// `close_handshake_link_connection`: close a leg's connection unless
    /// `addr_carries_other_peer` (a peer on another link sends or is proven
    /// there).
    fn close_leg(&mut self, net: &mut Net, id: u32) {
        let Some(l) = self.s.links.get(&id).copied() else {
            return;
        };
        if !self.carried(l.remote, id) {
            net.close(self.s.ix, l.remote);
            self.closed(net, l.remote);
        }
    }

    /// Send a frame to `peer` under its current session.
    fn announce(&mut self, net: &mut Net, peer: Node) {
        let (ix, me, now) = (self.s.ix, self.s.me, net.now);
        let Some(to) = self.to(peer) else {
            return;
        };
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
        let from = self.from(peer, to);
        let wire = net.intern(&sealed);
        net.send(ix, from, to, Pkt::Frame { id: me, hs, wire });
    }

    /// `answer_msg1`: a reply to a held peer's msg1 goes on its established
    /// link, or, with `fallback`, on the msg1's own connection when that
    /// link's connection is gone and the msg1 came on the same
    /// connection-oriented transport.
    fn answer(&mut self, net: &mut Net, peer: Node, src: Addr, pkt: Pkt, fallback: bool) {
        let ix = self.s.ix;
        let Some(cur) = self.to(peer) else {
            return;
        };
        let kind = net.kind(cur.transport);
        if kind == Kind::Datagram || net.conn(ix, cur).is_some() {
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

    fn dial(&mut self, net: &mut Net, peer: Node, to: Addr, from: Option<Addr>) {
        if let Some(p) = self.s.peers.get(&peer.0)
            && !feeds::dials(self.s.mode, &p.machines, p.last, net.now)
        {
            // A capable peer is not dialled while its link is live: the
            // address is a requested candidate instead
            // (`connect_candidate`).
            self.offer(net, peer, to, from, Source::Request);
            return;
        }
        let hs = self.fresh();
        let link = self.link(Dir::Outbound, to, hs);
        let now = net.now;
        let kit = &mut self.s.kit;
        let lease = allocate(&mut kit.pool).expect("the node's pool has an index");
        kit.local.name(names::opener(hs));
        let (state, msg1) = Ik::initiate(&kit.local, &names::key(peer), Some(lease.index()))
            .expect("the stub IK msg1 always writes");
        net.connect(self.s.ix, from, to);
        let wire = net.intern(&msg1);
        let pkt = Pkt::Msg1 {
            id: self.s.me,
            hs,
            bytes: Bytes(hs.0),
            epoch: self.epoch(),
            wire,
        };
        net.send(self.s.ix, from, to, pkt);
        let local = from.unwrap_or_else(|| net.home(self.s.ix, to.transport));
        self.s.dials.insert(
            hs.0,
            Dial {
                peer,
                link,
                to,
                from,
                local,
                resends: 0,
                next: now + RESEND,
                deadline: now + HANDSHAKE,
                msg1,
                state,
                lease,
            },
        );
        self.s.retry.remove(&peer.0);
        let ev = Event::Dial {
            hs,
            link: LinkId(link),
            to,
            binding: binding(net.kind(to.transport)),
        };
        self.note(now, peer, ev, Rec::default());
    }

    /// A dial ends unanswered: its leg is reaped.
    fn reap(&mut self, net: &mut Net, hs: Hs) {
        let Some(d) = self.s.dials.remove(&hs.0) else {
            return;
        };
        self.s.kit.pool.free(d.lease.release());
        self.close_leg(net, d.link);
        self.unlink(d.link);
        if self.s.configured.iter().any(|c| c.peer == d.peer) {
            self.s.retry.insert(d.peer.0, net.now + RETRY);
        }
        self.note(net.now, d.peer, Event::Timeout { hs }, Rec::default());
    }

    /// Close `peer`'s machines as it is removed, filing the replay record,
    /// and return its link.
    fn close(&mut self, now: Ms, peer: Node) -> Option<u32> {
        let p = self.s.peers.remove(&peer.0)?;
        self.s.connecting.retain(|(k, _)| *k != peer.0);
        let (events, carry) = p.machines.close(&mut self.s.kit, now, rekey::Close::Admin);
        for e in events {
            if let Ev::Rekey(rekey::Output::Unbind { index, .. }) = e
                && self.s.bound.remove(&index).is_none()
            {
                self.s
                    .audit
                    .push(format!("index {index} unbound at a close, not bound"));
            }
            // `release_path` with the peer removed: what a capable peer may
            // no longer send on is queued to close.
            if let Ev::Path(PathOutput::Released {
                to, keep: false, ..
            }) = &e
                && !self.carried(route::at(to), p.link)
            {
                self.s.closing.push(route::at(to));
            }
        }
        if let Some(c) = carry {
            self.s.store.file(
                names::addr(peer),
                c.peer_epoch.unwrap_or_default(),
                c.record,
            );
        }
        Some(p.link)
    }

    /// The node removes `peer`, as at a machine's teardown, an orphaned
    /// bundle or the liveness timer: the link goes with it, and a configured
    /// peer is dialled again (`route_link_dead`).
    fn lost(&mut self, net: &mut Net, peer: Node) {
        let now = net.now;
        let Some(link) = self.close(now, peer) else {
            return;
        };
        self.unlink(link);
        if self.s.configured.iter().any(|c| c.peer == peer) {
            self.s.retry.insert(peer.0, now + RETRY);
        }
        self.note(
            now,
            peer,
            Event::Lost,
            Rec {
                change: Some(Transition::Remove),
                ..Rec::default()
            },
        );
    }

    /// The answer to the msg1 `tok` of handshake `hs`, with a fresh index.
    fn answered(&mut self, tok: &Msg1, hs: Hs) -> Answered {
        let kit = &mut self.s.kit;
        let lease = allocate(&mut kit.pool).expect("the node's pool has an index");
        kit.local.name(names::answerer(hs));
        let (done, msg2) = tok
            .answer(&kit.local, Some(lease.index()))
            .expect("the stub IK msg2 always writes");
        let record = Record::setup(tok.digest(), tok.ephemeral(), Some(msg2.clone()));
        Answered {
            done,
            msg2,
            record,
            lease,
        }
    }

    /// `link_reachable`: whether the held peer's link is reachable:
    /// connectionless, or its active path's connection still open. A held
    /// peer with no active path is not.
    fn reachable(&self, net: &Net, peer: Node) -> bool {
        let Some(cur) = self.to(peer) else {
            return false;
        };
        net.kind(cur.transport) == Kind::Datagram || net.conn(self.s.ix, cur).is_some()
    }

    /// Hand a same-epoch msg1 of the held peer `id` to its rekey machine,
    /// and carry out what it asks. Returns whether the machine asked for
    /// the restart gates: otherwise the msg1 is done with, and logged here.
    #[allow(clippy::too_many_arguments)]
    fn handed(
        &mut self,
        net: &mut Net,
        (src, local): (Addr, Addr),
        id: Node,
        hs: Hs,
        msg1: &[u8],
        ev: Event,
    ) -> bool {
        let now = net.now;
        let reachable = self.reachable(net, id);
        let pending = self.pending(id);
        let floors = self.s.floors;
        let indexed = self.s.index.get(&key(src)).copied();
        let Some(p) = self.s.peers.get_mut(&id.0) else {
            return false;
        };
        // On the link: from a path proven at this end, or, on a link whose
        // peer is not capable, from a pair it holds no path for that the
        // index maps to the link. A held path still probing is off it.
        let (on_link, onpath) = match p.machines.matched(src) {
            Match::Proven { .. } => (true, true),
            Match::Unproven => (false, false),
            Match::None => (
                !p.machines.bundle().capable() && indexed == Some(p.link),
                false,
            ),
        };
        let arrival = Arrival { on_link, reachable };
        let events = p.machines.msg1(&mut self.s.kit, now, hs, msg1, arrival);
        let ok = p.machines.eligible(floors, now);
        self.named(id, Some(hs));
        let r = self.route(id, events);
        let after = self.pending(id);
        let class = match route::class(&r, pending, after, ok) {
            Ok(c) => c,
            Err(why) => {
                self.s.audit.push(format!("{id:?}: a msg1 refused {why:?}"));
                None
            }
        };
        let replace = r.replace.is_some();
        let Routed { sends, inputs, .. } = r;
        self.sends(net, id, sends, Some((hs, src, local, onpath)));
        let rest = Routed {
            inputs,
            ..Routed::default()
        };
        self.carry(net, id, rest);
        if replace {
            return true;
        }
        self.note(
            now,
            id,
            ev,
            Rec {
                class,
                proven: onpath,
                ..Rec::default()
            },
        );
        false
    }

    /// `handle_msg1`.
    #[allow(clippy::too_many_arguments)]
    fn msg1(
        &mut self,
        net: &mut Net,
        (src, local): (Addr, Addr),
        id: Node,
        hs: Hs,
        bytes: Bytes,
        epoch: Epoch,
        wire: u32,
    ) {
        let (ix, now, me) = (self.s.ix, net.now, self.s.me);
        let bind = binding(net.kind(src.transport));
        let msg1 = if wire == 0 {
            names::msg1(id, epoch, me, hs, names::index(hs))
        } else {
            net.bytes(wire).to_vec()
        };
        let Some(tok) = read_msg1(&self.s.kit.local, &msg1) else {
            return;
        };
        // The pre-crypto duplicate short circuit: an inbound link from this
        // address with no peer on it resends its stored msg2.
        if let Some(&l) = self.s.index.get(&key(src))
            && self.s.links.get(&l).is_some_and(|k| k.dir == Dir::Inbound)
            && !self.s.peers.values().any(|p| p.link == l)
        {
            let ev = Event::Msg1 {
                hs,
                bytes,
                epoch,
                link: LinkId(l),
                from: src,
                binding: bind,
                sent: true,
            };
            let leg = self
                .s
                .legs
                .iter()
                .find(|(_, g)| g.link == l)
                .map(|(k, _)| Hs(*k));
            let Some(lhs) = leg else {
                self.note(now, id, ev, Rec::default());
                return;
            };
            let sent = net.sendable(ix, src);
            let ev = Event::Msg1 {
                hs,
                bytes,
                epoch,
                link: LinkId(l),
                from: src,
                binding: bind,
                sent,
            };
            self.note(now, id, ev, Rec::default());
            if sent && let Some(g) = self.s.legs.remove(&lhs.0) {
                let w = net.intern(&g.answer.msg2);
                let pkt = Pkt::Msg2 {
                    id: me,
                    hs: lhs,
                    epoch: self.epoch(),
                    wire: w,
                };
                net.send(ix, Some(g.local), src, pkt);
                // `promote_resent`: promoted unless the peer is held.
                if self.s.peers.contains_key(&g.peer.0) {
                    self.s.kit.pool.free(g.answer.lease.release());
                    self.note(now, g.peer, Event::Msg2Sent { hs: lhs }, Rec::default());
                } else {
                    let (peer, local) = (g.peer, g.local);
                    self.install(net, peer, lhs, g.answer, l, (src, local));
                    let rec = Rec {
                        change: Some(Transition::Promote),
                        ..Rec::default()
                    };
                    self.note(now, peer, Event::Msg2Sent { hs: lhs }, rec);
                    self.announce(net, peer);
                }
            }
            return;
        }
        let sent = net.sendable(ix, src);
        let link_id = self.s.nlinks + 1;
        // Read before the machine or the teardown changes the peer's paths.
        let proven = self
            .s
            .peers
            .get(&id.0)
            .is_some_and(|p| matches!(p.machines.matched(src), Match::Proven { .. }));
        let ev = Event::Msg1 {
            hs,
            bytes,
            epoch,
            link: LinkId(link_id),
            from: src,
            binding: bind,
            sent,
        };
        // `establish_inbound`, then the link machine for a same epoch.
        let class = match self.s.peers.get(&id.0) {
            None => Class::NotHeld,
            Some(p) if p.machines.rekey().view().peer_epoch != Some(wired(epoch)) => Class::Restart,
            Some(_) => {
                if !self.handed(net, (src, local), id, hs, &msg1, ev) {
                    return;
                }
                Class::Replacement
            }
        };
        if class != Class::NotHeld {
            // The replay memory and the gates, on the peer clock.
            let old = self
                .s
                .peers
                .get(&id.0)
                .expect("a restart or replacement of a held peer");
            let (old_heard, last, promoted) = (old.heard, old.last, old.promoted);
            let refused = if !old_heard && self.replay(id, hs, now) {
                Some(Refusal::Replay)
            } else {
                let (idle, min) = if old_heard {
                    (now - last, INTERVAL)
                } else {
                    (now - promoted, UNHEARD)
                };
                let dampened = self
                    .s
                    .dampener
                    .get(&id.0)
                    .is_some_and(|&t| now - t < INTERVAL);
                if idle < min || dampened {
                    Some(Refusal::Gate(if idle >= min {
                        Gate::Dampened
                    } else if old_heard {
                        Gate::Heard
                    } else {
                        Gate::Unheard
                    }))
                } else {
                    None
                }
            };
            if let Some(r) = refused {
                self.note(
                    now,
                    id,
                    ev,
                    Rec {
                        class: Some(class),
                        refused: Some(r),
                        proven,
                        ..Rec::default()
                    },
                );
                return;
            }
            self.s.dampener.retain(|_, t| now - *t < INTERVAL);
            if old_heard {
                self.s.dampener.insert(id.0, now);
            }
            // The old peer's teardown: its link retired, its connection
            // kept.
            if let Some(link) = self.close(now, id) {
                self.unlink(link);
            }
        }
        // The promotion tail: a new inbound link, the msg2, the peer.
        let link = self.link(Dir::Inbound, src, hs);
        debug_assert_eq!(link, link_id);
        let answer = self.answered(tok.get(), hs);
        let change = if sent {
            let w = net.intern(&answer.msg2);
            let pkt = Pkt::Msg2 {
                id: me,
                hs,
                epoch: self.epoch(),
                wire: w,
            };
            net.send(ix, Some(local), src, pkt);
            self.install(net, id, hs, answer, link, (src, local));
            Some(if class == Class::NotHeld {
                Transition::Promote
            } else {
                Transition::Replace
            })
        } else {
            let leg = Leg {
                peer: id,
                link,
                local,
                deadline: now + HANDSHAKE,
                answer,
            };
            if let Some(old) = self.s.legs.insert(hs.0, leg) {
                self.s.kit.pool.free(old.answer.lease.release());
            }
            (class != Class::NotHeld).then_some(Transition::Remove)
        };
        self.note(
            now,
            id,
            ev,
            Rec {
                class: Some(class),
                change,
                proven,
                ..Rec::default()
            },
        );
        if sent {
            self.announce(net, id);
        }
    }

    /// `ReplayedMsg1s::verdict`: whether a msg1 replacing an unheard peering
    /// is refused, on the interval clock.
    fn replay(&mut self, id: Node, hs: Hs, now: Ms) -> bool {
        let Some(seen) = self.s.replayed.get_mut(&id.0) else {
            return false;
        };
        seen.retain(|&(_, at)| now - at < INTERVAL);
        seen.iter().any(|(e, _)| *e == hs) || seen.len() >= REPLAYS
    }

    /// `finish_inbound` and the no-peer promotion: the responder's peer, on
    /// the answer `answer`, its machines holding the replay record the node
    /// filed for the peer at this epoch beside the setup's.
    #[allow(clippy::too_many_arguments)]
    fn install(
        &mut self,
        net: &mut Net,
        id: Node,
        hs: Hs,
        answer: Answered,
        link: u32,
        (src, local): (Addr, Addr),
    ) {
        let now = net.now;
        let Answered {
            done,
            mut record,
            lease,
            ..
        } = answer;
        record.absorb(self.s.store.take(&names::addr(id), done.epoch));
        let theirs = done.theirs.unwrap_or(0);
        let setup = Setup {
            done,
            lease,
            theirs,
        };
        let (machines, events) = Machines::fresh(
            &mut self.s.kit,
            now,
            id,
            self.s.mode,
            setup,
            record,
            src,
            local,
        );
        self.s.peers.insert(
            id.0,
            Peer {
                link,
                origin: hs,
                heard: false,
                promoted: now,
                last: now,
                answered: false,
                machines,
                beat: now,
                own: None,
                listed: Listings::default(),
            },
        );
        self.named(id, Some(hs));
        let r = self.route(id, events);
        self.carry(net, id, r);
        // `note_unheard_promotion`.
        let seen = self.s.replayed.entry(id.0).or_default();
        seen.retain(|&(_, at)| now - at < INTERVAL);
        if !seen.iter().any(|(e, _)| *e == hs) {
            seen.push((hs, now));
        }
        if seen.len() > REPLAYS {
            seen.remove(0);
        }
        self.s.retry.remove(&id.0);
        self.renewed(net, id);
    }

    /// `handle_msg2` and `establish_outbound`.
    fn msg2(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, epoch: Epoch, wire: u32) {
        let now = net.now;
        let State { dials, kit, .. } = &mut self.s;
        let Some(d) = dials.get(&hs.0).filter(|d| d.peer == id) else {
            self.reply(net, id, hs, epoch, wire);
            return;
        };
        let bytes = if wire == 0 {
            names::msg2(id, epoch, hs, &d.msg1, names::index(hs)).map(|(w, _)| w)
        } else {
            Some(net.bytes(wire).to_vec())
        };
        let Some(read) = bytes.and_then(|b| Ik::reply(&d.state, &kit.local, &b).ok()) else {
            return;
        };
        let Some(d) = dials.remove(&hs.0) else {
            return;
        };
        let done = read.done;
        let theirs = done.theirs.unwrap_or(0);
        let peer_epoch = done.epoch;
        let (link, local, lease) = (d.link, d.local, d.lease);
        let ev = Event::Msg2 {
            hs,
            epoch,
            from: src,
        };
        let same = self
            .s
            .peers
            .get(&id.0)
            .is_some_and(|p| p.machines.rekey().view().peer_epoch == Some(wired(epoch)));
        let change = if same {
            let own = self.s.peers.get(&id.0).is_some_and(|p| {
                self.s
                    .links
                    .get(&p.link)
                    .is_some_and(|l| l.dir == Dir::Outbound)
            });
            let wins = self.s.me < id;
            let change = if own || wins {
                // The swap: `move_session` onto this dial's session at the
                // msg2's pair; the link record is kept.
                let old = self.s.peers.remove(&id.0).expect("held above");
                let setup = Setup {
                    done,
                    lease,
                    theirs,
                };
                let (machines, events) =
                    old.machines.moved(&mut self.s.kit, now, setup, src, local);
                // The move holds this node's own dial, so the peering is
                // heard (FRC-1201 Section 5.5), and the memory of the msg1s
                // that promoted it unheard goes, as its first frame's would.
                let heard = old.heard || !fault!(MoveLeavesUnheard);
                if heard && !old.heard {
                    self.s.replayed.remove(&id.0);
                }
                self.s.peers.insert(
                    id.0,
                    Peer {
                        link: old.link,
                        origin: hs,
                        heard,
                        promoted: old.promoted,
                        last: old.last,
                        answered: true,
                        machines,
                        beat: old.beat,
                        own: None,
                        listed: Listings::default(),
                    },
                );
                self.named(id, Some(hs));
                // A renewal's closes wait for the next wake (`run_renewed`).
                let r = self.route(id, events);
                self.carry(net, id, r);
                self.renewed(net, id);
                net.mark(self.s.ix, src, true);
                Transition::Move
            } else {
                self.s.kit.pool.free(lease.release());
                if let Some(p) = self.s.peers.get_mut(&id.0) {
                    p.answered = true;
                }
                Transition::Keep
            };
            self.close_leg(net, link);
            self.unlink(link);
            change
        } else {
            let restart = self.s.peers.contains_key(&id.0);
            if let Some(old) = self.close(now, id) {
                self.unlink(old);
            }
            let record = self.s.store.take(&names::addr(id), peer_epoch);
            let setup = Setup {
                done,
                lease,
                theirs,
            };
            let (machines, events) = Machines::fresh(
                &mut self.s.kit,
                now,
                id,
                self.s.mode,
                setup,
                record,
                src,
                local,
            );
            self.s.peers.insert(
                id.0,
                Peer {
                    link,
                    origin: hs,
                    heard: true,
                    promoted: now,
                    last: now,
                    answered: true,
                    machines,
                    beat: now,
                    own: None,
                    listed: Listings::default(),
                },
            );
            self.named(id, Some(hs));
            let r = self.route(id, events);
            self.carry(net, id, r);
            self.renewed(net, id);
            net.mark(self.s.ix, src, true);
            if restart {
                Transition::Replace
            } else {
                Transition::Promote
            }
        };
        self.s.retry.remove(&id.0);
        self.note(
            now,
            id,
            ev,
            Rec {
                change: Some(change),
                ..Rec::default()
            },
        );
        self.announce(net, id);
    }

    /// A msg2 no dial of this node waits for: the reply to an own rekey,
    /// routed by its index to the machine that bound it.
    fn reply(&mut self, net: &mut Net, id: Node, hs: Hs, epoch: Epoch, wire: u32) {
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
            match names::msg2(id, epoch, hs, &own, names::index(hs)) {
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
        let events = p.machines.reply(&mut self.s.kit, now, &bytes);
        let mine = p.own.as_ref().map(|(h, _)| *h);
        self.named(id, mine);
        let r = self.route(id, events);
        let accepted = r.reject.is_none();
        self.carry(net, id, r);
        if accepted {
            self.note(now, id, Event::RekeyMsg2 { hs, epoch }, Rec::default());
        }
    }

    /// What an abstract far end's frame under the session of `hs` is on
    /// the wire: the next frame of that session, or, for a copy the
    /// explorer made, the last one again, which the machine refuses as a
    /// replay.
    fn sealed(&mut self, id: Node, hs: Hs, copy: bool) -> Option<Vec<u8>> {
        let want = self.s.names.kid(hs)?;
        let p = self.s.peers.get(&id.0)?;
        p.machines
            .written(&mut self.s.counters, (hs, want), copy, BEAT)
    }

    /// A frame from `id` under the session of `hs`, which the world let
    /// through because this node holds it (`handle_encrypted_frame`): opened
    /// by the peer's machine, its outputs carried out, then accounted
    /// (`account_authentic`), under whichever session it opened: the bundle
    /// follows or does not follow its source, the peer is heard, and a path
    /// message goes to the bundle.
    fn frame(
        &mut self,
        net: &mut Net,
        (src, local): (Addr, Addr),
        id: Node,
        hs: Hs,
        (wire, copy): (u32, bool),
    ) {
        let now = net.now;
        let bytes = if wire == 0 {
            match self.sealed(id, hs, copy) {
                Some(b) => b,
                None => return,
            }
        } else {
            net.bytes(wire).to_vec()
        };
        let index = hint(&bytes).index;
        match self.s.bound.get(&index) {
            Some(k) if *k == id.0 => {}
            // An index no machine binds: the node drops the frame.
            None => return,
            Some(k) => {
                self.s.audit.push(format!(
                    "a frame from {id:?} under {hs:?} names index {index}, bound to peer {k}"
                ));
                return;
            }
        }
        let Some(p) = self.s.peers.get_mut(&id.0) else {
            return;
        };
        let (opened, buf) = p.machines.frame(&mut self.s.kit, now, &bytes);
        let r = self.route(id, opened);
        let Some(range) = r.delivered.clone() else {
            // A replay opened under the keys the name maps to; any other
            // refusal of a frame the world's gate let through is a broken
            // promise.
            if r.reject != Some(Reason::Replay) {
                self.s.audit.push(format!(
                    "a frame from {id:?} under {hs:?}, which this node holds, did not open: {:?}",
                    r.reject
                ));
            }
            return;
        };
        let kind = buf.get(range.start).copied().unwrap_or(0);
        let cut = r.cut;
        let revealed = self.carry(net, id, r);
        self.drain(net);
        let Some(p) = self.s.peers.get_mut(&id.0) else {
            return;
        };
        let first = !p.heard;
        p.heard = true;
        p.last = now;
        let (moved, unpathed) =
            p.machines
                .account(&mut self.s.kit, now, src, local, bytes.len(), kind);
        // A one-path roam leaves the index as it is: the setup address keeps
        // its entry.
        let roamed = moved.iter().any(|e| matches!(e, Ev::Roamed { .. }));
        if first {
            self.s.replayed.remove(&id.0);
        }
        net.mark(self.s.ix, src, true);
        if feeds::heard(self.s.mode, unpathed, kind) {
            self.offer(net, id, src, Some(local), Source::Heard);
        }
        if messaged(kind) {
            let plain = buf.get(range).unwrap_or_default();
            if let Some(p) = self.s.peers.get_mut(&id.0) {
                let events = p.machines.message(&mut self.s.kit, now, src, local, plain);
                let r = self.route(id, events);
                self.carry(net, id, r);
                self.drain(net);
            }
        }
        let change = if cut {
            Some(revealed.unwrap_or(Transition::RekeyCutover))
        } else {
            roamed.then_some(Transition::Roam)
        };
        self.note(
            now,
            id,
            Event::Frame { hs, from: src },
            Rec {
                change,
                ..Rec::default()
            },
        );
    }

    /// A connection this node sees at `at` closed. The node removes no
    /// peer for it; the liveness timer does, later. A link of several paths
    /// that holds a path there is told through its bundle, as a failed send
    /// tells it (`send_unreachable`), unless its bundle asked for the
    /// connection and it has not settled, which is reported when it does.
    fn closed(&mut self, net: &mut Net, at: Addr) {
        let now = net.now;
        if net.kind(at.transport) != Kind::Datagram {
            for k in self.held() {
                let told = self.s.peers.get(&k.0).is_some_and(|p| {
                    let paths = p.machines.bundle().paths();
                    paths.paths().len() > 1
                        && !matches!(p.machines.matched(at), Match::None)
                        && !self.s.connecting.contains(&(k.0, at))
                });
                if told {
                    let q = super::super::joint::facts::pair(at);
                    let input = PathInput::SendFailed {
                        transport: q.transport,
                        addr: q.addr,
                    };
                    if let Some(p) = self.s.peers.get_mut(&k.0) {
                        let events = p.machines.path(&mut self.s.kit, now, input, None);
                        let r = self.route(k, events);
                        self.carry(net, k, r);
                    }
                }
            }
        }
        let peers: Vec<Node> = self
            .s
            .peers
            .keys()
            .map(|&k| Node(k))
            .chain(self.s.dials.values().map(|d| d.peer))
            .collect();
        let mut done = Vec::new();
        for p in peers {
            if !done.contains(&p) {
                done.push(p);
                self.note(now, p, Event::Close { at }, Rec::default());
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
        let r = self.route(peer, events);
        self.carry(net, peer, r);
    }

    fn wake(&mut self, net: &mut Net) {
        let (ix, me, now, epoch) = (self.s.ix, self.s.me, net.now, self.epoch());
        self.drain(net);
        self.connects(net);
        let mut reaped = Vec::new();
        for (k, d) in self.s.dials.iter_mut() {
            if now >= d.deadline {
                reaped.push(Hs(*k));
            } else if now >= d.next && d.resends < RESENDS {
                d.resends += 1;
                d.next = now + (RESEND << d.resends);
                let wire = net.intern(&d.msg1);
                let pkt = Pkt::Msg1 {
                    id: me,
                    hs: Hs(*k),
                    bytes: Bytes(*k),
                    epoch,
                    wire,
                };
                net.send(ix, d.from, d.to, pkt);
            }
        }
        for hs in reaped {
            self.reap(net, hs);
        }
        let stale: Vec<u32> = self
            .s
            .legs
            .iter()
            .filter(|(_, g)| now >= g.deadline)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            let Some(g) = self.s.legs.remove(&k) else {
                continue;
            };
            self.s.kit.pool.free(g.answer.lease.release());
            self.close_leg(net, g.link);
            self.unlink(g.link);
            self.note(now, g.peer, Event::Timeout { hs: Hs(k) }, Rec::default());
        }
        let peers: Vec<u8> = self.s.peers.keys().copied().collect();
        for k in peers {
            let peer = Node(k);
            // `check_link_heartbeats`: a peer silent for the link-dead
            // timeout is removed, unless this node's own rekey is in flight.
            if self
                .s
                .peers
                .get(&k)
                .and_then(|p| deadline(&p.machines))
                .is_some_and(|d| d <= now)
            {
                let held = self
                    .s
                    .peers
                    .get(&k)
                    .and_then(|p| self.current(&p.machines).map(|hs| (hs, p.origin)));
                self.lost(net, peer);
                if let Some((hs, origin)) = held {
                    self.s.expired.push((peer, hs, origin));
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
                self.named(peer, Some(next));
                let r = self.route(peer, events);
                let cut = r.cut;
                let revealed = self.carry(net, peer, r);
                self.drain(net);
                if cut {
                    let rec = Rec {
                        change: Some(revealed.unwrap_or(Transition::RekeyCutover)),
                        ..Rec::default()
                    };
                    self.note(now, peer, Event::RekeyCutover, rec);
                    self.announce(net, peer);
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
                && !self.s.dials.values().any(|d| d.peer == c.peer);
            if due && idle {
                self.dial(net, c.peer, c.to, c.from);
            } else if due {
                self.s.retry.remove(&c.peer.0);
            }
        }
    }

    /// Give back everything the node holds: the process ends.
    fn wipe(&mut self, now: Ms) {
        for (_, p) in core::mem::take(&mut self.s.peers) {
            let (events, _) = p
                .machines
                .close(&mut self.s.kit, now, rekey::Close::Shutdown);
            drop(events);
        }
        for (_, d) in core::mem::take(&mut self.s.dials) {
            self.s.kit.pool.free(d.lease.release());
        }
        for (_, g) in core::mem::take(&mut self.s.legs) {
            self.s.kit.pool.free(g.answer.lease.release());
        }
        self.s.bound.clear();
        self.s.connecting.clear();
        self.s.closing.clear();
    }

    /// The node's process restarts: everything is forgotten, and it dials
    /// each configured peer again.
    fn restart(&mut self, net: &mut Net) {
        self.wipe(net.now);
        let s = &mut self.s;
        s.life += 1;
        s.count = 0;
        s.retry.clear();
        s.links.clear();
        s.index.clear();
        s.dampener.clear();
        s.replayed.clear();
        s.idle.clear();
        s.counters.clear();
        s.names = names::Names::default();
        s.store = store();
        let epoch = Epoch((u32::from(s.me.0) << 8) | s.life);
        s.kit = Kit::new(s.me, epoch, &super::super::joint::kinds());
        self.log.push(Entry::Restart);
        for c in self.s.configured.clone() {
            self.dial(net, c.peer, c.to, c.from);
        }
    }

    /// The node's state key: every field of [`State`], each held peer's
    /// machines by [`Machines::key`] and the kit without its scratch
    /// buffer, which a machine writes before it reads. The fields are named
    /// one by one, so a field added to the state is a compile error here
    /// until it is keyed.
    fn key(&self) -> String {
        let State {
            ix,
            now,
            me,
            mode,
            life,
            count,
            nlinks,
            configured,
            retry,
            links,
            index,
            peers,
            dials,
            legs,
            dampener,
            replayed,
            idle,
            kit,
            store,
            names,
            bound,
            counters,
            floors,
            audit,
            connecting,
            closing,
            expired: _,
        } = &self.s;
        let mut out = format!(
            "{ix} {now} {me:?} {mode:?} {life} {count} {nlinks} {configured:?} {retry:?} {links:?} {index:?} {dials:?} {legs:?} {dampener:?} {replayed:?} {idle:?} "
        );
        for (k, p) in peers {
            let Peer {
                link,
                origin,
                heard,
                promoted,
                last,
                answered,
                machines,
                beat,
                own,
                listed,
            } = p;
            let _ = write!(
                out,
                "{k}: {link} {origin:?} {heard} {promoted} {last} {answered} {beat} {own:?} {listed:?} "
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
            " {local:?} {pool:?} {tags:?} {jitter:?} {draws:?} {facts:?} {store:?} {names:?} {bound:?} {counters:?} {floors:?} {audit:?} {connecting:?} {closing:?}"
        );
        out
    }
}

impl MasterParty {
    /// The earliest instant the node has something to do: a dial's or a
    /// leg's timers, each held peer's machines, heartbeat and liveness
    /// deadline, the redials and the idle connections' closes, and a
    /// renewal's closes left for this wake; the bundles' wakes left out
    /// unless `bundles`.
    fn due(&self, bundles: bool) -> Option<Ms> {
        let s = &self.s;
        let dials = s
            .dials
            .values()
            .flat_map(|d| [Some(d.deadline), (d.resends < RESENDS).then_some(d.next)]);
        let legs = s.legs.values().map(|g| Some(g.deadline));
        let peers = s.peers.values().flat_map(|p| {
            let m = if bundles {
                p.machines.wake()
            } else {
                p.machines.paced()
            };
            [m, Some(p.beat + HEARTBEAT), deadline(&p.machines)]
        });
        let retry = s.retry.values().chain(s.idle.values()).map(|&t| Some(t));
        let closing = (!s.closing.is_empty()).then_some(s.now);
        dials
            .chain(legs)
            .chain(peers)
            .chain(retry)
            .chain(core::iter::once(closing))
            .flatten()
            .min()
    }
}

impl Drop for MasterParty {
    fn drop(&mut self) {
        self.wipe(0);
    }
}

impl Party for MasterParty {
    fn input(&mut self, net: &mut Net, inp: Input) {
        let leaks = leaked();
        self.s.now = net.now;
        match inp {
            Input::Packet {
                src,
                local,
                pkt,
                copy,
                ..
            } => match pkt {
                Pkt::Msg1 {
                    id,
                    hs,
                    bytes,
                    epoch,
                    wire,
                } => {
                    self.msg1(net, (src, local), id, hs, bytes, epoch, wire);
                    self.unused(net, src);
                }
                Pkt::Msg2 {
                    id,
                    hs,
                    epoch,
                    wire,
                } => self.msg2(net, src, id, hs, epoch, wire),
                Pkt::Frame { id, hs, wire } => {
                    self.frame(net, (src, local), id, hs, (wire, copy));
                }
                Pkt::Eof => self.closed(net, src),
            },
            Input::Closed { at } => self.closed(net, at),
            Input::ConnectFailed { to } => {
                let failed: Vec<Hs> = self
                    .s
                    .dials
                    .iter()
                    .filter(|(_, d)| d.to == to)
                    .map(|(k, _)| Hs(*k))
                    .collect();
                for hs in failed {
                    self.reap(net, hs);
                }
            }
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
            }) => self.offer(net, peer, at, from, source),
            Input::Path(PathEv::Carrier { transport, up }) => {
                let transport = TransportId::new(u32::from(transport));
                self.transported(net, PathInput::Carrier { transport, up });
            }
            Input::Path(PathEv::Gone { transport }) => {
                let transport = TransportId::new(u32::from(transport));
                self.transported(net, PathInput::Removed { transport });
            }
            // The world applies a NAT's change; no node is told of it.
            Input::Path(PathEv::Rebound { .. }) => {}
        }
        if leaked() != leaks {
            self.s.audit.push(format!(
                "{} leases dropped unreleased",
                leaked().saturating_sub(leaks)
            ));
        }
    }

    fn wake(&self) -> Option<Ms> {
        self.due(true)
    }

    fn paced(&self) -> Option<Ms> {
        self.due(false)
    }

    fn expired(&mut self) -> Vec<(Node, Hs, Hs)> {
        core::mem::take(&mut self.s.expired)
    }

    fn lapsed(&self) -> Vec<Addr> {
        let mut out = Vec::new();
        for p in self.s.peers.values() {
            for q in p.machines.bundle().paths().paths() {
                if q.acked() && q.state() != PathState::Live {
                    out.push(super::super::joint::facts::addr(q.transport_id(), q.addr()));
                }
            }
        }
        out
    }

    fn digest(&self) -> String {
        self.key()
    }

    fn epoch(&self) -> Epoch {
        MasterParty::epoch(self)
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

    fn heard(&self, peer: Node) -> Option<bool> {
        self.s.peers.get(&peer.0).map(|p| p.heard)
    }

    fn rekeyable(&self, peer: Node) -> bool {
        self.s.peers.get(&peer.0).is_some_and(|p| {
            p.machines.rekey().view().cycle == CycleView::Idle
                && p.machines.eligible(self.s.floors, self.s.now)
        })
    }

    fn view(&self) -> View {
        let s = &self.s;
        let mut v = View::empty(s.me);
        v.configured = s.configured.iter().map(|c| c.peer).collect();
        v.log = self.log.clone();
        v.audit = s.audit.clone();
        v.needs = self.needs();
        for (k, p) in &s.peers {
            let Some(l) = s.links.get(&p.link) else {
                v.audit
                    .push(format!("peer {k}: link {} has no record", p.link));
                continue;
            };
            if s.peers.iter().any(|(j, q)| j != k && q.link == p.link) {
                v.audit.push(format!("peer {k}: link {} shared", p.link));
            }
            let Some(cur) = self.current(&p.machines) else {
                v.audit
                    .push(format!("peer {k}: a current session with no name"));
                continue;
            };
            let rk = p.machines.rekey();
            let (view, peek) = (rk.view(), rk.peek());
            v.bounds.push(("record", peek.record, 64));
            v.peers.push(PeerView {
                peer: Node(*k),
                cur,
                origin: p.origin,
                link: l.hs,
                dir: l.dir,
                at: l.remote,
                current: p.machines.active().unwrap_or(l.remote),
                answered: p.answered,
                pending: peek
                    .pending
                    .and_then(|e| s.names.name(kid(e.session)))
                    .map(|h| (h, view.pending.is_some_and(|e| e.role == Side::Initiator))),
                rekey: match view.cycle {
                    CycleView::Init => p.own.as_ref().map(|(h, _)| *h),
                    CycleView::Idle | CycleView::PendI(_) | CycleView::PendR => None,
                },
                dials: s
                    .dials
                    .iter()
                    .filter(|(_, d)| d.peer.0 == *k)
                    .map(|(h, _)| Hs(*h))
                    .collect(),
            });
        }
        for (a, l) in &s.index {
            if !s.links.contains_key(l) {
                v.audit.push(format!("index {a:?}: link {l} has no record"));
            }
        }
        for (h, d) in &s.dials {
            if !s.links.contains_key(&d.link) {
                v.audit
                    .push(format!("dial {h}: link {} has no record", d.link));
            }
        }
        for (h, g) in &s.legs {
            if !s.links.contains_key(&g.link) {
                v.audit
                    .push(format!("leg {h}: link {} has no record", g.link));
            }
        }
        v.bounds.push(("peers", s.peers.len(), 8));
        v.bounds.push(("dials", s.dials.len(), 8));
        v.bounds.push(("legs", s.legs.len(), 8));
        for seen in s.replayed.values() {
            v.bounds.push(("replay memory", seen.len(), REPLAYS));
        }
        v
    }
}
