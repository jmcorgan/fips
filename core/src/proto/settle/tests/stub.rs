//! The settlement core as a node of the world.
//!
//! [`CoreParty`] is the one-node driver of `drive.rs` facing the world: one
//! core [`Table`] for the node and a [`RekeySide`] per peer it holds, with
//! a stub shell that carries out the core's outputs. The shell sends the
//! msg1s, msg2s and frames, closes what the core closes on transports that
//! hold connections, keeps each installed session's index lease until the
//! peer is removed, builds or carries the peer's rekey side at an install,
//! and supplies what the core leaves to the node: the heartbeat, the
//! reconnect, the own rekey and its cutover, the close of an inbound
//! connection whose msg1 left nothing that uses it, and the world's adapter
//! close of a replaced link's connection (as `ModelParty` makes it).
//!
//! On every call the shell checks the core's own promises and reports a
//! broken one as an incoherence of its maps: no lease is dropped
//! unreleased, the transport-address index equals its recomputation from
//! the link records, and a poll before the core's next wake does nothing.
//!
//! It logs every history event it sees and what the core did, as the model
//! of `master` does, so the oracles compare it with the reference model
//! step by step.
//!
//! Under a candidate rule the shell also keeps a session the core holds
//! beside the peer's own, with its rekey side and lease, so frames under it
//! still open; it hands such a frame to the core, and the loss of that
//! session's connection, and swaps or drops the session when the core
//! settles it.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::rekey::{IndexLease, leaked};
use crate::proto::settle::faults::{Candidate, candidate};
use crate::proto::settle::input::{Dial as Dialed, Hello, Input as In};
use crate::proto::settle::links::{Dir as LinkDir, Holder, LinkNo, Proven};
use crate::proto::settle::output::{Build, Output, Why};
use crate::proto::settle::params::Params;
use crate::proto::settle::table::Table;
use crate::testutil::TestInstant;

use super::super::model::history::{Addr, Bytes, Epoch, Event, Hs, LinkId, Node};
use super::super::model::judge::{Class, Transition as M};
use super::drive::{addr, bytes, change, class, eph, epoch as wire, node, pair, refusal};
use super::party::{Configured, binding};
use super::rekeyside::{Answer, Out, RekeySide};
use super::shadow::{Entry, Rec, Refusal};
use super::world::{
    Dir, HANDSHAKE, HEARTBEAT, Input, Kind, Ms, Net, Party, PathEv, PeerView, Pkt, RETRY, View,
};

/// What a link's handshake is to this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// This node's own dial of `to`, from `from`.
    Dial { to: Addr, from: Option<Addr> },
    /// An answer to the peer's msg1.
    Answer,
}

/// The handshake a core link was opened for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Run {
    hs: Hs,
    peer: Node,
    role: Role,
    bytes: Bytes,
    /// The epoch its msg1 or msg2 carried.
    epoch: Option<Epoch>,
}

/// A peer the core holds, as the shell keeps it.
#[derive(Debug)]
struct Peer {
    rekey: RekeySide,
    /// The handshake the peer was installed or moved onto.
    origin: Hs,
    /// One of this node's own dials of the peer was answered while it was
    /// held, or installed it.
    answered: bool,
    beat: Ms,
    /// The installed session's index lease.
    session: Option<IndexLease>,
}

/// What one call's outputs did, in the model step's fields.
#[derive(Debug, Default)]
struct Fx {
    class: Option<Class>,
    refused: Option<Refusal>,
    change: Option<M>,
    removed: Option<Why>,
    /// Answers asked for: the link, and whether the answer was stored.
    answers: Vec<(LinkNo, bool)>,
    /// Dials whose msg1 the core asked to resend.
    resends: Vec<LinkNo>,
    /// Links the core opened.
    opened: Vec<LinkNo>,
    /// Connections closed.
    closes: Vec<Addr>,
    /// The arrival the core handed the rekey side.
    arrival: Option<crate::proto::rekey::Arrival>,
}

/// Everything the node keeps, the log aside.
#[derive(Debug)]
struct State {
    ix: usize,
    now: Ms,
    /// When the core was last polled.
    polled: Option<Ms>,
    me: Node,
    life: u32,
    count: u32,
    configured: Vec<Configured>,
    retry: BTreeMap<u8, Ms>,
    idle: BTreeMap<(u8, u16), Ms>,
    table: Table<TestInstant>,
    runs: BTreeMap<LinkNo, Run>,
    peers: BTreeMap<u8, Peer>,
    lease: u32,
    /// Broken promises of the core, seen by the shell.
    audit: Vec<String>,
    /// The peers the log names, whose shadows see every close.
    known: BTreeSet<u8>,
    /// The rekey msg1s sent in this life.
    rekeys: Vec<(Node, Hs)>,
    /// The candidate rule the core runs, if any.
    cand: Option<Candidate>,
    /// The sessions a candidate rule keeps, by peer: the kept link and the
    /// peer as the shell held it on that session.
    kept: BTreeMap<u8, (LinkNo, Peer)>,
}

/// One node, judged by the settlement core.
pub struct CoreParty {
    s: State,
    log: Vec<Entry>,
    shadow: bool,
}

/// The settlement core as a node, running the candidate rule the process
/// names in `FIPS_SETTLE_CANDIDATE`, if any.
pub fn core(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    under(ix, me, configured, candidate())
}

/// The settlement core as a node running the candidate rule `cand`, or
/// its own rules with none. It is compared with the model under its own
/// rules and the dialer's candidate, which the model encodes; the other
/// candidates are not.
pub fn under(
    ix: usize,
    me: Node,
    configured: Vec<Configured>,
    cand: Option<Candidate>,
) -> Box<dyn Party> {
    let shadow = matches!(cand, None | Some(Candidate::DialerSettle));
    Box::new(CoreParty::new(ix, me, configured, shadow, cand))
}

/// The settlement core as a node, compared with no model: for the start
/// with two paths, which the model does not know.
pub fn core_unshadowed(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    Box::new(CoreParty::new(ix, me, configured, false, candidate()))
}

/// The core at node 0 and the model elsewhere.
pub fn core_model(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    if ix == 0 {
        core(ix, me, configured)
    } else {
        super::starts::model(ix, me, configured)
    }
}

/// The model at node 0 and the core elsewhere.
pub fn model_core(ix: usize, me: Node, configured: Vec<Configured>) -> Box<dyn Party> {
    if ix == 0 {
        super::starts::model(ix, me, configured)
    } else {
        core(ix, me, configured)
    }
}

fn key(a: Addr) -> (u8, u16) {
    (a.transport, a.at)
}

impl CoreParty {
    /// Node `ix` with identity `me`, redialing `configured`, running the
    /// candidate rule `cand` if any; `shadow` says whether the oracles
    /// compare it with the model.
    pub fn new(
        ix: usize,
        me: Node,
        configured: Vec<Configured>,
        shadow: bool,
        cand: Option<Candidate>,
    ) -> Self {
        let log = if cand == Some(Candidate::DialerSettle) {
            alloc::vec![Entry::Fallback]
        } else {
            Vec::new()
        };
        Self {
            s: State {
                ix,
                now: 0,
                polled: None,
                me,
                life: 0,
                count: 0,
                configured,
                retry: BTreeMap::new(),
                idle: BTreeMap::new(),
                table: Table::new(node(me), Params::default()).under(cand),
                runs: BTreeMap::new(),
                peers: BTreeMap::new(),
                lease: 0,
                audit: Vec::new(),
                known: BTreeSet::new(),
                rekeys: Vec::new(),
                cand,
                kept: BTreeMap::new(),
            },
            log,
            shadow,
        }
    }

    fn epoch(&self) -> Epoch {
        Epoch((u32::from(self.s.me.0) << 8) | self.s.life)
    }

    fn fresh(&mut self) -> Hs {
        self.s.count += 1;
        Hs((u32::from(self.s.me.0) << 24) | (self.s.life << 16) | self.s.count)
    }

    fn lease(&mut self) -> IndexLease {
        self.s.lease += 1;
        IndexLease::for_test(self.s.lease)
    }

    /// The instant the core is called at: the monotonic clock, or with
    /// `PacketStamp` the packet's wall stamp, the shape of a shell that
    /// hands the core what a packet says.
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
            // The latest instant before the next wake: a poll there must
            // do nothing either.
            let early = self.s.table.poll(TestInstant(w.0 - 1));
            if !early.is_empty() {
                self.s
                    .audit
                    .push(format!("a poll before the next wake acted: {early:?}"));
                drop_outputs(early);
            }
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

    fn note(&mut self, now: Ms, peer: Node, ev: Event, mut rec: Rec) {
        rec.heard = self.s.table.held(&node(peer)).is_some_and(|h| h.heard);
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
    /// live or acknowledged paths, and each held peer's current address.
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
            if let Some(h) = self.s.table.held(&node(Node(*k))) {
                out.push(addr(&h.current));
            }
        }
        out
    }

    fn uses(&self, at: Addr) -> bool {
        self.needs().contains(&at)
    }

    /// Note the inbound connection a msg1 arrived on at `src` when nothing
    /// uses it afterwards (as `ModelParty` does).
    fn unused(&mut self, net: &Net, src: Addr) {
        if net.kind(src.transport) != Kind::Datagram
            && net.conn(self.s.ix, src).is_some()
            && !self.uses(src)
        {
            self.s.idle.entry(key(src)).or_insert(net.now + HANDSHAKE);
        }
    }

    /// Whether the held peer's current connection is still open.
    fn reachable(&self, net: &Net, peer: Node) -> bool {
        let Some(h) = self.s.table.held(&node(peer)) else {
            return true;
        };
        let (ix, cur) = (self.s.ix, addr(&h.current));
        // A connection the far end closed is still reachable here until
        // its end-of-stream arrives: the node knows only its own end.
        let unseen = |c: &super::world::Conn| match c.state {
            super::world::State::Closed(e) => {
                c.ends[1 - e].node == ix
                    && c.ends[1 - e].remote == cur
                    && net
                        .flight
                        .iter()
                        .any(|f| f.conn == Some(c.id) && f.to == ix && f.pkt == Pkt::Eof)
            }
            super::world::State::Connecting | super::world::State::Open => false,
        };
        net.kind(cur.transport) == Kind::Datagram
            || net.conn(ix, cur).is_some()
            || (!fault!(ReachablePeeks) && net.conns.iter().any(unseen))
    }

    /// Carry out the core's outputs.
    fn effects(&mut self, net: &mut Net, out: Vec<Output>, fx: &mut Fx) {
        for o in out {
            match o {
                Output::Opened { link } => fx.opened.push(link),
                Output::Answer { link, stored, .. } => fx.answers.push((link, stored)),
                Output::Resend { link, .. } => fx.resends.push(link),
                Output::Rekey { arrival, .. } => fx.arrival = Some(arrival),
                Output::Install(i) => self.install(net, i),
                Output::Reset { peer, transition } => {
                    let m = change(transition);
                    if matches!(m, M::Keep | M::Move)
                        && let Some(p) = self.s.peers.get_mut(&peer.as_bytes()[0])
                    {
                        p.answered = true;
                    }
                    fx.change = Some(m);
                }
                Output::Remove { peer, why } => {
                    let k = peer.as_bytes()[0];
                    if let Some(mut p) = self.s.peers.remove(&k)
                        && let Some(l) = p.session.take()
                    {
                        l.release();
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
                    if self.s.configured.iter().any(|c| c.peer.0 == k) {
                        self.s.retry.insert(k, net.now + RETRY);
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
                    lease.release();
                }
                Output::Retry { peer } => {
                    let k = peer.as_bytes()[0];
                    if self.s.configured.iter().any(|c| c.peer.0 == k) {
                        self.s.retry.insert(k, net.now + RETRY);
                    }
                }
                Output::Reject { source, why, .. } => {
                    fx.refused = Some(refusal(why));
                    if fx.class.is_none() {
                        fx.class = source.and_then(class);
                    }
                }
                Output::Hold { peer, link } => self.hold(peer.as_bytes()[0], link),
                Output::Settle { peer, link, back } => {
                    self.settle(peer.as_bytes()[0], link, back);
                }
            }
        }
    }

    /// Keep the session of `link`, the one the peer `k` is held on now,
    /// decryptable beside the next: its rekey side and its lease go to the
    /// kept slot, so the install or removal that follows leaves them.
    fn hold(&mut self, k: u8, link: LinkNo) {
        if fault!(CandidateHoldsNothing) {
            return;
        }
        let Some(p) = self.s.peers.get_mut(&k) else {
            self.s.audit.push(format!(
                "a hold of {link:?} for peer {k}, which has no side"
            ));
            return;
        };
        let kept = Peer {
            rekey: p.rekey.clone(),
            origin: p.origin,
            answered: p.answered,
            beat: p.beat,
            session: p.session.take(),
        };
        if let Some((_, mut old)) = self.s.kept.insert(k, (link, kept))
            && let Some(l) = old.session.take()
        {
            l.release();
        }
    }

    /// The kept session of `link` for peer `k` is kept no longer: with
    /// `back` it is the peer's again and the one held instead is dropped,
    /// otherwise it is dropped.
    fn settle(&mut self, k: u8, link: LinkNo, back: bool) {
        let Some((l, mut kept)) = self.s.kept.remove(&k) else {
            return;
        };
        if l != link {
            self.s
                .audit
                .push(format!("peer {k}: settled {link:?}, kept {l:?}"));
        }
        if back {
            if let Some(mut cur) = self.s.peers.remove(&k)
                && let Some(lease) = cur.session.take()
            {
                lease.release();
            }
            self.s.peers.insert(k, kept);
        } else if let Some(lease) = kept.session.take() {
            lease.release();
        }
    }

    /// The core installed a peer: keep its session's lease, and build its
    /// rekey side, or carry it across a move.
    fn install(&mut self, net: &Net, i: crate::proto::settle::output::Install) {
        let Some(run) = self.s.runs.get(&i.link).copied() else {
            self.s.audit.push(format!(
                "install on {:?}, which no handshake opened",
                i.link
            ));
            i.lease.release();
            return;
        };
        let (me, now) = (self.s.me, net.now);
        let epoch = run.epoch.unwrap_or(Epoch(0));
        let old = self.s.peers.remove(&run.peer.0);
        let (rekey, answered, beat) = match (i.rekey, old) {
            (Build::FromCarry, Some(mut old)) => {
                if let Some(l) = old.session.take() {
                    l.release();
                }
                (old.rekey.moved(run.hs), old.answered, old.beat)
            }
            (Build::FromCarry | Build::Fresh, old) => {
                if let Some(mut old) = old
                    && let Some(l) = old.session.take()
                {
                    l.release();
                }
                let setup = (!i.initiator).then_some(run.bytes);
                (
                    RekeySide::new(me, run.peer, run.hs, epoch, now, setup),
                    false,
                    now,
                )
            }
        };
        self.s.peers.insert(
            run.peer.0,
            Peer {
                rekey,
                origin: run.hs,
                answered: answered || i.initiator,
                beat,
                session: Some(i.lease),
            },
        );
        self.s.retry.remove(&run.peer.0);
    }

    /// Send one frame to `peer` under the session held, now.
    fn announce(&mut self, net: &mut Net, peer: Node) {
        let (ix, me, now) = (self.s.ix, self.s.me, net.now);
        let Some(to) = self.s.table.held(&node(peer)).map(|h| addr(&h.current)) else {
            return;
        };
        if let Some(p) = self.s.peers.get_mut(&peer.0) {
            p.beat = now;
            let hs = p.rekey.cur;
            net.send(ix, None, to, Pkt::Frame { id: me, hs });
        }
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

    /// A reply from the held peer's rekey side goes on its established
    /// link, or on the msg1's own connection when that link's connection is
    /// gone (`answer_msg1`, as the model of `master` sends it).
    fn reply(&mut self, net: &mut Net, peer: Node, src: Addr, hs: Hs) {
        let ix = self.s.ix;
        let Some(cur) = self.s.table.held(&node(peer)).map(|h| addr(&h.current)) else {
            return;
        };
        let pkt = Pkt::Msg2 {
            id: self.s.me,
            hs,
            epoch: self.epoch(),
        };
        if net.kind(cur.transport) == Kind::Datagram || net.conn(ix, cur).is_some() {
            net.send(ix, None, cur, pkt);
        } else if src.transport == cur.transport && src != cur && net.conn(ix, src).is_some() {
            net.send(ix, None, src, pkt);
        }
    }

    fn hello(&mut self, id: Node, hs: Hs, b: Bytes, e: Epoch, from: Addr) -> Hello {
        Hello {
            peer: node(id),
            from: pair(from),
            bytes: bytes(b),
            ephemeral: eph(hs),
            epoch: wire(e),
            msg2: [&[2u8][..], &hs.0.to_be_bytes()].concat(),
            lease: self.lease(),
        }
    }

    fn dial(&mut self, net: &mut Net, peer: Node, to: Addr, from: Option<Addr>) {
        let hs = self.fresh();
        let b = Bytes(hs.0);
        net.connect(self.s.ix, from, to);
        let pkt = Pkt::Msg1 {
            id: self.s.me,
            hs,
            bytes: b,
            epoch: self.epoch(),
        };
        net.send(self.s.ix, from, to, pkt);
        let d = Dialed {
            peer: node(peer),
            to: pair(to),
            msg1: bytes(b),
            lease: self.lease(),
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
        self.s.runs.insert(
            link,
            Run {
                hs,
                peer,
                role: Role::Dial { to, from },
                bytes: b,
                epoch: None,
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

    #[allow(clippy::too_many_arguments)]
    fn msg1(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, b: Bytes, e: Epoch, stamp: i64) {
        let (ix, now, at) = (self.s.ix, net.now, Self::at(net, Some(stamp)));
        let sent = net.sendable(ix, src);
        let stale = self
            .s
            .table
            .held(&node(id))
            .and_then(|h| self.s.table.links().get(h.link).map(|r| addr(&r.setup)));
        let reachable = self.reachable(net, id);
        let hello = self.hello(id, hs, b, e, src);
        let mut out = self.core(In::Msg1 { hello, reachable }, at);
        let mut fx = Fx::default();
        if out.iter().any(|o| matches!(o, Output::Rekey { .. })) {
            self.effects(net, out, &mut fx);
            let arrival = fx.arrival.expect("a rekey output carries its arrival");
            let Some(p) = self.s.peers.get_mut(&id.0) else {
                self.s
                    .audit
                    .push(format!("a rekey hand-off for {id:?}, which has no side"));
                return;
            };
            let (cls, answer) = p.rekey.msg1(now, hs, b, arrival);
            fx.class = Some(cls);
            match answer {
                Answer::Replace => {
                    let hello = self.hello(id, hs, b, e, src);
                    out = self.core(In::Replace(hello), at);
                }
                Answer::Msg2(h) | Answer::Stored(h) => {
                    self.reply(net, id, src, h);
                    self.logged_msg1(net, id, src, hs, b, e, sent, &fx, None);
                    return;
                }
                Answer::Silent => {
                    self.logged_msg1(net, id, src, hs, b, e, sent, &fx, None);
                    return;
                }
            }
        }
        self.effects(net, out, &mut fx);
        let mut stored = None;
        for (link, was) in core::mem::take(&mut fx.answers) {
            if was {
                stored = Some(link);
                continue;
            }
            self.s.runs.insert(
                link,
                Run {
                    hs,
                    peer: id,
                    role: Role::Answer,
                    bytes: b,
                    epoch: Some(e),
                },
            );
            if fx.class.is_none() {
                fx.class = Some(Class::NotHeld);
            }
            let input = if sent {
                let pkt = Pkt::Msg2 {
                    id: self.s.me,
                    hs,
                    epoch: self.epoch(),
                };
                net.send(ix, None, src, pkt);
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
        // The world's adapter choice, as `ModelParty` makes it where
        // FRC-1201 is silent: a replacement or restart over another
        // connection closes the replaced link's connection when no link
        // uses it. The core keeps the connection, as the current node does.
        if !fault!(ReplacedConnKept)
            && matches!(fx.removed, Some(Why::Restart | Why::Replacement))
            && let Some(old) = stale
            && net.kind(old.transport) != Kind::Datagram
            && old != src
            && !self.uses(old)
        {
            net.close(ix, old);
        }
        self.logged_msg1(net, id, src, hs, b, e, sent, &fx, stored);
        self.unused(net, src);
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
        stored: Option<LinkNo>,
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
        };
        self.note(now, id, ev, rec);
        self.closes(now, &fx.closes);
        self.changed(net, id, fx.change);
        if let Some(link) = stored
            && sent
        {
            self.resend_stored(net, link);
        }
    }

    /// A resent msg1 drew the stored answer on `link`: send it, and tell
    /// the core, which installs the peer unless it is held.
    fn resend_stored(&mut self, net: &mut Net, link: LinkNo) {
        let Some(run) = self.s.runs.get(&link).copied() else {
            return;
        };
        let Some(to) = self.s.table.links().get(link).map(|r| addr(&r.setup)) else {
            return;
        };
        let pkt = Pkt::Msg2 {
            id: self.s.me,
            hs: run.hs,
            epoch: self.epoch(),
        };
        net.send(self.s.ix, None, to, pkt);
        let out = self.core(In::Sent { link }, TestInstant(net.now));
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
        let rec = Rec {
            change: fx.change,
            ..Rec::default()
        };
        self.note(net.now, run.peer, Event::Msg2Sent { hs: run.hs }, rec);
        self.closes(net.now, &fx.closes);
        self.changed(net, run.peer, fx.change);
    }

    fn msg2(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, e: Epoch, stamp: i64) {
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
            let mine = self
                .s
                .peers
                .get_mut(&id.0)
                .is_some_and(|p| p.rekey.msg2(now, hs, e));
            if mine {
                self.note(now, id, Event::RekeyMsg2 { hs, epoch: e }, Rec::default());
            }
            return;
        };
        if let Some(r) = self.s.runs.get_mut(&link) {
            r.epoch = Some(e);
        }
        let input = In::Msg2 {
            link,
            epoch: wire(e),
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

    fn frame(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, stamp: i64) {
        let (now, at) = (net.now, Self::at(net, Some(stamp)));
        let current = self.s.peers.get(&id.0).is_some_and(|p| p.rekey.holds(hs));
        if !current
            && self
                .s
                .kept
                .get(&id.0)
                .is_some_and(|(_, p)| p.rekey.holds(hs))
        {
            self.kept_frame(net, src, id, hs, at);
            return;
        }
        if !self.s.peers.contains_key(&id.0) {
            return;
        }
        let out = self.core(
            In::Heard {
                peer: node(id),
                from: pair(src),
            },
            at,
        );
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
        let cut = self
            .s
            .peers
            .get_mut(&id.0)
            .and_then(|p| p.rekey.frame(now, hs));
        self.cut(net, id, cut, at, &mut fx);
        net.mark(self.s.ix, src, true);
        let rec = Rec {
            change: fx.change,
            ..Rec::default()
        };
        self.note(now, id, Event::Frame { hs, from: src }, rec);
        self.closes(now, &fx.closes);
        self.changed(net, id, fx.change);
    }

    /// A frame under a session a candidate rule kept: the core says whether
    /// the peer is back on it, and the peer's rekey side, if it is held,
    /// takes the frame.
    fn kept_frame(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, at: TestInstant) {
        let now = net.now;
        let input = In::HeldFrame {
            peer: node(id),
            from: pair(src),
        };
        let out = self.core(input, at);
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
        let cut = self
            .s
            .peers
            .get_mut(&id.0)
            .filter(|p| p.rekey.holds(hs))
            .and_then(|p| p.rekey.frame(now, hs));
        self.cut(net, id, cut, at, &mut fx);
        net.mark(self.s.ix, src, true);
        let rec = Rec {
            change: fx.change,
            ..Rec::default()
        };
        self.note(now, id, Event::Frame { hs, from: src }, rec);
        self.closes(now, &fx.closes);
        self.changed(net, id, fx.change);
    }

    /// The rekey side cut over: a plain rekey is the shell's change, a
    /// restart revealed goes to the core.
    fn cut(&mut self, net: &mut Net, id: Node, out: Option<Out>, at: TestInstant, fx: &mut Fx) {
        match out {
            Some(Out::Rekeyed { .. }) => fx.change = Some(M::RekeyCutover),
            Some(Out::Restarted { epoch, .. }) => {
                let input = In::Restarted {
                    peer: node(id),
                    epoch: wire(epoch),
                };
                let out = self.core(input, at);
                self.effects(net, out, fx);
            }
            Some(Out::Send(_) | Out::Abandoned | Out::Unadopted) | None => {}
        }
    }

    /// The leg on `link` ended unanswered.
    fn ended(&mut self, net: &mut Net, link: LinkNo, run: Run) {
        let out = self.core(In::ConnectFailed { link }, TestInstant(net.now));
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
        self.timed_out(net, run, &fx);
    }

    fn timed_out(&mut self, net: &mut Net, run: Run, fx: &Fx) {
        self.note(
            net.now,
            run.peer,
            Event::Timeout { hs: run.hs },
            Rec::default(),
        );
        self.closes(net.now, &fx.closes);
        if matches!(run.role, Role::Dial { .. })
            && self.s.configured.iter().any(|c| c.peer == run.peer)
        {
            self.s.retry.insert(run.peer.0, net.now + RETRY);
        }
    }

    /// The connection this node sees at `at` closed, or its connect failed.
    fn closed(&mut self, net: &mut Net, at: Addr) {
        let now = net.now;
        self.closes(now, &[at]);
        let lost: Vec<u8> = self
            .s
            .kept
            .iter()
            .filter(|(_, (l, _))| {
                net.kind(at.transport) != Kind::Datagram
                    && self
                        .s
                        .table
                        .links()
                        .get(*l)
                        .is_some_and(|r| addr(&r.setup) == at)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in lost {
            let out = self.core(
                In::HoldLost {
                    peer: node(Node(k)),
                },
                TestInstant(now),
            );
            let mut fx = Fx::default();
            self.effects(net, out, &mut fx);
        }
        let gone: Vec<(LinkNo, Run)> = self
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
            .map(|(l, r)| (*l, *r))
            .collect();
        for (link, run) in gone {
            self.ended(net, link, run);
        }
        let lost: Vec<Node> = self
            .s
            .peers
            .keys()
            .map(|&k| Node(k))
            .filter(|&p| {
                let Some(h) = self.s.table.held(&node(p)) else {
                    return false;
                };
                let setup = self.s.table.links().get(h.link).map(|r| addr(&r.setup));
                net.kind(at.transport) != Kind::Datagram
                    && (addr(&h.current) == at || setup == Some(at))
            })
            .collect();
        for p in lost {
            // A connection-oriented link whose connection closed is dead.
            let kept: Vec<Addr> = self
                .s
                .table
                .held(&node(p))
                .and_then(|h| self.s.table.links().get(h.link))
                .map(|r| {
                    core::iter::once(&r.setup)
                        .chain(r.paths.iter().map(|(q, _)| q))
                        .map(addr)
                        .collect()
                })
                .unwrap_or_default();
            let out = self.core(In::Dead { peer: node(p) }, TestInstant(now));
            let mut fx = Fx::default();
            self.effects(net, out, &mut fx);
            // The world's adapter choice again: the core keeps a dead
            // link's connections, as the current node does; the link's
            // other paths' connections that no link uses are closed.
            for a in kept {
                if !fault!(ReplacedConnKept)
                    && a != at
                    && net.kind(a.transport) != Kind::Datagram
                    && !self.uses(a)
                {
                    net.close(self.s.ix, a);
                }
            }
            self.note(
                now,
                p,
                Event::Lost,
                Rec {
                    change: Some(M::Remove),
                    ..Rec::default()
                },
            );
            self.closes(now, &fx.closes);
        }
        if !self.uses(at) {
            net.close(self.s.ix, at);
        }
    }

    fn wake(&mut self, net: &mut Net) {
        let (ix, me, now, epoch) = (self.s.ix, self.s.me, net.now, self.epoch());
        let at = TestInstant(now);
        let polled = self.s.table.poll(at);
        self.s.polled = Some(now);
        self.check();
        let mut fx = Fx::default();
        let mut reaped = Vec::new();
        let settled: Vec<LinkNo> = polled
            .iter()
            .filter_map(|o| {
                if let Output::Settle { link, .. } = o {
                    Some(*link)
                } else {
                    None
                }
            })
            .collect();
        for o in &polled {
            if let Output::Retire { link, .. } = o
                && !settled.contains(link)
                && let Some(run) = self.s.runs.get(link).copied()
            {
                reaped.push(run);
            }
        }
        self.effects(net, polled, &mut fx);
        for link in core::mem::take(&mut fx.resends) {
            if let Some(Run {
                hs,
                bytes: b,
                role: Role::Dial { to, from },
                ..
            }) = self.s.runs.get(&link).copied()
            {
                let pkt = Pkt::Msg1 {
                    id: me,
                    hs,
                    bytes: b,
                    epoch,
                };
                net.send(ix, from, to, pkt);
                let out = self.core(In::Sent { link }, at);
                self.effects(net, out, &mut fx);
            }
        }
        if self.s.table.next_wake().is_some_and(|w| w <= at) {
            // A wake the poll and its resends left due would wake the node
            // again at once, for ever; it is a broken promise, and is not
            // offered again.
            self.s.audit.push(String::from(
                "after a poll the core's next wake is still due",
            ));
        }
        self.closes(now, &core::mem::take(&mut fx.closes));
        for run in reaped {
            self.timed_out(net, run, &Fx::default());
        }
        let peers: Vec<u8> = self.s.peers.keys().copied().collect();
        for k in peers {
            let peer = Node(k);
            let outs = self
                .s
                .peers
                .get_mut(&k)
                .map(|p| p.rekey.poll(now))
                .unwrap_or_default();
            for o in outs {
                match o {
                    Out::Send(hs) => {
                        let to = self.s.table.held(&node(peer)).map(|h| addr(&h.current));
                        if let Some(to) = to {
                            let pkt = Pkt::Msg1 {
                                id: me,
                                hs,
                                bytes: Bytes(hs.0),
                                epoch,
                            };
                            net.send(ix, None, to, pkt);
                        }
                    }
                    Out::Rekeyed { .. } | Out::Restarted { .. } => {
                        let mut fx = Fx::default();
                        self.cut(net, peer, Some(o), at, &mut fx);
                        let rec = Rec {
                            change: Some(fx.change.unwrap_or(M::RekeyCutover)),
                            ..Rec::default()
                        };
                        self.note(now, peer, Event::RekeyCutover, rec);
                        self.closes(now, &fx.closes);
                        self.announce(net, peer);
                    }
                    Out::Abandoned => self.log.push(Entry::Abandon { peer }),
                    Out::Unadopted => self.log.push(Entry::Unadopted { peer }),
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

    /// A path event of a peer's bundle, on the link the peer holds or the
    /// dial of it in flight. A bundle starts with its setup path, so the
    /// first event on a link adds that path, live.
    fn path(&mut self, net: &mut Net, ev: PathEv) {
        let peer = match ev {
            PathEv::Moved { peer, .. }
            | PathEv::Switched { peer, .. }
            | PathEv::Released { peer, .. }
            | PathEv::State { peer, .. } => peer,
        };
        let held = self.s.table.held(&node(peer)).map(|h| h.link);
        let dialed = self
            .s
            .runs
            .iter()
            .rev()
            .find(|(l, r)| {
                r.peer == peer
                    && matches!(r.role, Role::Dial { .. })
                    && self.s.table.legs().get(**l).is_some()
            })
            .map(|(l, _)| *l);
        let Some(link) = held.or(dialed) else {
            return;
        };
        let at = TestInstant(net.now);
        if let Some(r) = self.s.table.links().get(link)
            && r.paths.is_empty()
        {
            let setup = r.setup.clone();
            let out = self.core(
                In::State {
                    link,
                    pair: setup,
                    proven: Proven::Live,
                },
                at,
            );
            drop_outputs(out);
        }
        let input = match ev {
            PathEv::Moved { from, to, .. } => In::Moved {
                link,
                from: pair(from),
                to: pair(to),
            },
            PathEv::Switched { from, to, .. } => In::Switched {
                link,
                from: pair(from),
                to: pair(to),
            },
            PathEv::Released { at, keep, .. } => In::Released {
                link,
                pair: pair(at),
                keep,
            },
            PathEv::State { at, live, .. } => In::State {
                link,
                pair: pair(at),
                proven: if live { Proven::Live } else { Proven::Probing },
            },
        };
        let out = self.core(input, at);
        let mut fx = Fx::default();
        self.effects(net, out, &mut fx);
    }

    /// Give back everything the core and the shell hold: the process ends.
    fn wipe(&mut self, now: Ms) {
        let out = self.s.table.close(TestInstant(now));
        drop_outputs(out);
        for (_, mut p) in core::mem::take(&mut self.s.peers) {
            if let Some(l) = p.session.take() {
                l.release();
            }
        }
        for (_, (_, mut p)) in core::mem::take(&mut self.s.kept) {
            if let Some(l) = p.session.take() {
                l.release();
            }
        }
    }
}

/// Release every lease in `out` and drop the rest.
fn drop_outputs(out: Vec<Output>) {
    for o in out {
        match o {
            Output::Free { lease } => {
                lease.release();
            }
            Output::Install(i) => {
                i.lease.release();
            }
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

impl Drop for CoreParty {
    fn drop(&mut self) {
        self.wipe(0);
    }
}

impl Party for CoreParty {
    fn input(&mut self, net: &mut Net, inp: Input) {
        let leaks = leaked();
        self.s.now = net.now;
        match inp {
            Input::Packet {
                src, pkt, stamp, ..
            } => match pkt {
                Pkt::Msg1 {
                    id,
                    hs,
                    bytes: b,
                    epoch,
                } => self.msg1(net, src, id, hs, b, epoch, stamp),
                Pkt::Msg2 { id, hs, epoch } => self.msg2(net, src, id, hs, epoch, stamp),
                Pkt::Frame { id, hs } => self.frame(net, src, id, hs, stamp),
                Pkt::Eof => self.closed(net, src),
            },
            Input::Closed { at } | Input::ConnectFailed { to: at } => self.closed(net, at),
            Input::Wake => self.wake(net),
            Input::Restart => {
                self.wipe(net.now);
                let s = &mut self.s;
                s.life += 1;
                s.count = 0;
                s.table = Table::new(node(s.me), Params::default()).under(s.cand);
                s.runs.clear();
                s.rekeys.clear();
                s.retry.clear();
                s.idle.clear();
                self.log.push(Entry::Restart);
                for c in self.s.configured.clone() {
                    self.dial(net, c.peer, c.to, c.from);
                }
            }
            Input::Dial { peer, to, from } => self.dial(net, peer, to, from),
            Input::Rekey { peer } => {
                if self.rekeyable(peer) {
                    let hs = self.fresh();
                    let (now, me, epoch, ix) = (net.now, self.s.me, self.epoch(), self.s.ix);
                    let to = self.s.table.held(&node(peer)).map(|h| addr(&h.current));
                    if let (Some(to), Some(p)) = (to, self.s.peers.get_mut(&peer.0)) {
                        p.rekey.start(now, hs);
                        self.s.rekeys.push((peer, hs));
                        let pkt = Pkt::Msg1 {
                            id: me,
                            hs,
                            bytes: Bytes(hs.0),
                            epoch,
                        };
                        net.send(ix, None, to, pkt);
                        self.note(now, peer, Event::RekeyStart { hs }, Rec::default());
                    }
                }
            }
            Input::Beat => {
                for peer in self.held() {
                    self.announce(net, peer);
                }
            }
            Input::Path(ev) => self.path(net, ev),
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
    }

    fn wake(&self) -> Option<Ms> {
        let s = &self.s;
        let table = s
            .table
            .next_wake()
            .map(|t| t.0)
            .filter(|&t| s.polled.is_none_or(|p| t > p));
        let peers = s
            .peers
            .values()
            .flat_map(|p| [p.rekey.wake(), Some(p.beat + HEARTBEAT)]);
        let rest = s.retry.values().chain(s.idle.values()).map(|&t| Some(t));
        core::iter::once(table)
            .chain(peers)
            .chain(rest)
            .flatten()
            .min()
    }

    fn digest(&self) -> String {
        format!("{:?}", self.s)
    }

    fn epoch(&self) -> Epoch {
        CoreParty::epoch(self)
    }

    fn holds(&self, peer: Node, hs: Hs) -> bool {
        self.s.peers.get(&peer.0).is_some_and(|p| p.rekey.holds(hs))
            || self
                .s
                .kept
                .get(&peer.0)
                .is_some_and(|(_, p)| p.rekey.holds(hs))
    }

    fn held(&self) -> Vec<Node> {
        self.s.peers.keys().map(|&k| Node(k)).collect()
    }

    fn rekeyable(&self, peer: Node) -> bool {
        self.s.table.held(&node(peer)).is_some()
            && self
                .s
                .peers
                .get(&peer.0)
                .is_some_and(|p| p.rekey.idle() && p.rekey.eligible(self.s.now))
    }

    fn view(&self) -> View {
        let s = &self.s;
        let mut v = View::empty(s.me);
        v.configured = s.configured.iter().map(|c| c.peer).collect();
        if self.shadow {
            v.log = self.log.clone();
        }
        v.audit = s.audit.clone();
        v.rekeys = s.rekeys.clone();
        v.needs = self.needs();
        let links = s.table.links();
        let live = |l: &LinkNo| s.table.legs().get(*l).is_some();
        for (k, p) in &s.peers {
            let peer = Node(*k);
            let Some(h) = s.table.held(&node(peer)) else {
                v.audit
                    .push(format!("peer {k}: a rekey side and no held peer"));
                continue;
            };
            let Some(r) = links.get(h.link) else {
                v.audit
                    .push(format!("peer {k}: link {:?} has no record", h.link));
                continue;
            };
            if r.holder != Holder::Peer(node(peer)) {
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
            v.bounds.push(("record", p.rekey.recorded(), 64));
            v.peers.push(PeerView {
                peer,
                cur: p.rekey.cur,
                origin: p.origin,
                link: run.hs,
                dir: match r.dir {
                    LinkDir::Inbound => Dir::Inbound,
                    LinkDir::Outbound => Dir::Outbound,
                },
                at: addr(&r.setup),
                current: addr(&h.current),
                answered: p.answered,
                pending: p.rekey.pending(),
                rekey: p.rekey.rekey(),
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
        let held: usize = s
            .peers
            .keys()
            .filter(|k| s.table.held(&node(Node(**k))).is_some())
            .count();
        let sessions = s.peers.values().filter(|p| p.session.is_some()).count();
        if sessions != held {
            v.audit
                .push(format!("{sessions} session leases for {held} held peers"));
        }
        v.bounds.push(("peers", s.peers.len(), 8));
        v.bounds
            .push(("legs", s.runs.keys().filter(|l| live(l)).count(), 8));
        v
    }
}

/// One run of the core explorer: a start with its nodes' maker.
struct Explored {
    st: super::starts::Start,
    ends: &'static str,
}

/// Every start but the two late-dial cases left for later, each with the
/// core at both ends and with the core at either end against the model;
/// the start with two paths with the core at both ends and no shadow.
fn core_runs() -> Vec<Explored> {
    let mut out = Vec::new();
    for number in 1..=14u8 {
        if matches!(number, 6 | 7) {
            continue;
        }
        let makers: &[(super::starts::Maker, &'static str)] = if number == 12 {
            &[(core_unshadowed, "core and core")]
        } else {
            &[
                (core, "core and core"),
                (core_model, "core and model"),
                (model_core, "model and core"),
            ]
        };
        for &(mk, ends) in makers {
            for mut st in super::starts::starts()
                .into_iter()
                .filter(|s| s.number == number)
            {
                st.maker = mk;
                out.push(Explored { st, ends });
            }
        }
    }
    out
}

/// The exemption of the core explorer: a split on a path that showed a
/// known shape, and [`unseen_path`].
fn exempt(w: &super::world::World, b: &super::oracle::Breach) -> bool {
    super::oracle::by_shape(w, b) || unseen_path(w, b)
}

/// On the start with two paths, a connection in use at an address that
/// only a path event names and at which the world opened no connection,
/// since the world's path events are abstract.
pub fn unseen_path(w: &super::world::World, b: &super::oracle::Breach) -> bool {
    let abstract_path = |at: Addr| {
        w.paths.iter().any(|(_, ev)| match *ev {
            PathEv::Moved { to, .. } | PathEv::Switched { to, .. } => to == at,
            PathEv::State { at: a, .. } | PathEv::Released { at: a, .. } => a == at,
        }) && !w
            .net
            .conns
            .iter()
            .any(|c| c.ends.iter().any(|e| e.remote == at))
    };
    b.oracle == super::oracle::Oracle::ConnectionsInUse
        && !w.paths.is_empty()
        && w.paths
            .iter()
            .flat_map(|(_, ev)| match *ev {
                PathEv::Moved { to, from, .. } | PathEv::Switched { to, from, .. } => [to, from],
                PathEv::State { at, .. } | PathEv::Released { at, .. } => [at, at],
            })
            .any(|a| abstract_path(a) && b.what.starts_with(&format!("{a:?} in use")))
}

#[test]
fn every_explored_interleaving_of_the_core_keeps_the_properties_and_heals() {
    use super::oracle::sweep;
    let runs = core_runs();
    let report = std::thread::scope(|sc| {
        let hs: Vec<_> = runs
            .iter()
            .map(|r| {
                sc.spawn(move || {
                    let t = std::time::Instant::now();
                    let swept = sweep(&r.st, r.st.depth, &exempt);
                    (swept, t.elapsed().as_millis())
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect::<Vec<_>>()
    });
    let mut wrong = Vec::new();
    for (r, (swept, ms)) in runs.iter().zip(report) {
        std::eprintln!(
            "core {:>2} {} ({}): {} states, {} leaves healed in {ms} ms, exempted {:?}",
            r.st.number,
            r.st.name,
            r.ends,
            swept.stats.states,
            swept.stats.leaves.len(),
            swept.exempted
        );
        for (b, path) in swept.found {
            wrong.push(format!(
                "{} ({}): {:?} at n{}: {}\n  path {path:?}",
                r.st.name, r.ends, b.oracle, b.node, b.what
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
