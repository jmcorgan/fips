//! The model as a node of the world.
//!
//! [`ModelParty`] holds one reference-model [`Judge`] per peer identity.
//! It turns what the world delivers into the model's history events, and
//! each [`Step`]'s reply and closes into sends and closes. The model has no
//! timers, so the party keeps them, from the world's constants: msg1
//! resends and the handshake deadline, the reclaim of a stored msg2, the
//! heartbeat, the reconnect after a failed dial or a removal, and its own
//! rekey's resends and cutover. A node announces itself with one frame
//! whenever a peer change leaves it a session, as the node's tree announce
//! does.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::model::history::{Addr, Binding, Bytes, Epoch, Event, Hs, LinkId, Node};
use super::super::model::judge::{Judge, LocalRule, Params, Reply, Step, Transition};
use super::world::{
    CHECK, Dir, HANDSHAKE, HEARTBEAT, Input, Kind, Ms, Net, Party, PeerView, Pkt, RESEND, RESENDS,
    RETRY, View,
};

/// The link age before a rekey, `Config::fmp().link_age`
/// (`rekey/params.rs`), which the model's own rekey waits for.
const LINKAGE: Ms = 30_000;
/// The session age before a rekey, `Config::fmp().session_age`.
const SESSIONAGE: Ms = 10_000;

/// One of this node's own initial dials in flight.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Dial {
    link: LinkId,
    to: Addr,
    from: Option<Addr>,
    bytes: Bytes,
    resends: u32,
    next: Ms,
    deadline: Ms,
}

/// A msg2 this node sent or stored, kept so a resend repeats it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Answer {
    to: Addr,
    pkt: Pkt,
}

/// This node's own rekey msg1 in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Own {
    hs: Hs,
    to: Addr,
    resends: u32,
    next: Ms,
    deadline: Ms,
}

/// Everything this node keeps about one peer identity.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Side {
    judge: Judge,
    dials: BTreeMap<u32, Dial>,
    answers: BTreeMap<u32, Answer>,
    stored: BTreeMap<u32, (Answer, Ms)>,
    links: BTreeMap<u32, LinkId>,
    rekey: Option<Own>,
    cutover: Option<Ms>,
    beat: Ms,
}

/// A peer this node redials whenever it holds none and has no dial out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Configured {
    /// The peer.
    pub peer: Node,
    /// The address dialed.
    pub to: Addr,
    /// The local address dialed from.
    pub from: Option<Addr>,
}

/// One node, judged by the reference model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelParty {
    ix: usize,
    me: Node,
    life: u32,
    count: u32,
    nlinks: u32,
    configured: Vec<Configured>,
    retry: BTreeMap<u8, Ms>,
    sides: BTreeMap<u8, Side>,
    /// Inbound connections whose msg1 left nothing that uses them, by
    /// address, and when the node gives up on each.
    idle: BTreeMap<(u8, u16), Ms>,
}

/// The model's binding for a transport model.
pub fn binding(kind: Kind) -> Binding {
    match kind {
        Kind::Datagram => Binding::Connectionless,
        Kind::Stream | Kind::Ble => Binding::Connected,
    }
}

impl ModelParty {
    /// Node `ix` with identity `me`, redialing `configured`.
    pub fn new(ix: usize, me: Node, configured: Vec<Configured>) -> Self {
        Self {
            ix,
            me,
            life: 0,
            count: 0,
            nlinks: 0,
            configured,
            retry: BTreeMap::new(),
            sides: BTreeMap::new(),
            idle: BTreeMap::new(),
        }
    }

    /// Whether any judge still needs the connection at `at`.
    fn uses(&self, at: Addr) -> bool {
        self.sides
            .values()
            .any(|s| s.judge.needs().iter().any(|(_, a)| *a == at))
    }

    /// Note the inbound connection a msg1 arrived on at `src` when nothing
    /// uses it afterwards: the node closes it at the handshake timeout
    /// unless something has come to use it by then.
    fn unused(&mut self, net: &Net, src: Addr) {
        if net.kind(src.transport) != Kind::Datagram
            && net.conn(self.ix, src).is_some()
            && !self.uses(src)
        {
            self.idle
                .entry((src.transport, src.at))
                .or_insert(net.now + HANDSHAKE);
        }
    }

    /// Close each noted inbound connection whose time is up and which
    /// nothing uses.
    fn reap(&mut self, net: &mut Net) {
        let now = net.now;
        let due: Vec<(u8, u16)> = self
            .idle
            .iter()
            .filter(|(_, t)| now >= **t)
            .map(|(k, _)| *k)
            .collect();
        for (transport, at) in due {
            self.idle.remove(&(transport, at));
            let a = Addr { transport, at };
            if !fault!(RefusedConnKept) && !self.uses(a) {
                net.close(self.ix, a);
            }
        }
    }

    /// This node's startup epoch.
    fn epoch(&self) -> Epoch {
        Epoch((u32::from(self.me.0) << 8) | self.life)
    }

    /// A fresh handshake, unique across this node's restarts.
    fn fresh(&mut self) -> Hs {
        self.count += 1;
        Hs((u32::from(self.me.0) << 24) | (self.life << 16) | self.count)
    }

    /// A fresh link number.
    fn link(&mut self) -> LinkId {
        self.nlinks += 1;
        LinkId(self.nlinks)
    }

    /// The side of `peer`, its judge brought up to `now`.
    fn side(&mut self, peer: Node, now: Ms) -> &mut Side {
        let me = self.me;
        let s = self.sides.entry(peer.0).or_insert_with(|| Side {
            judge: Judge::new(me, peer, Params::default()),
            dials: BTreeMap::new(),
            answers: BTreeMap::new(),
            stored: BTreeMap::new(),
            links: BTreeMap::new(),
            rekey: None,
            cutover: None,
            beat: now,
        });
        if s.judge.now < now {
            let gap = now - s.judge.now;
            s.judge.step(Event::Advance(gap));
        }
        s
    }

    /// Step `peer`'s judge with `e` and carry out what the step says.
    fn step(&mut self, net: &mut Net, peer: Node, e: Event) -> Step {
        let side = self.side(peer, net.now);
        let step = side.judge.step(e);
        if fault!(ModelDropsFallback)
            && step.rule == Some(LocalRule::LateSecondDial)
            && step.change == Some(Transition::Move)
            && let Some(p) = side.judge.peering.as_mut()
        {
            // The defect's shape: an adapter that keeps nothing of the
            // session the late dial moved off.
            p.fallback = None;
        }
        self.effects(net, peer, &step);
        step
    }

    /// Close what `step` closes, tell every judge, and announce a session
    /// a peer change left this node.
    fn effects(&mut self, net: &mut Net, peer: Node, step: &Step) {
        for &at in &step.closes {
            net.close(self.ix, at);
            for s in self.sides.values_mut() {
                s.judge.step(Event::Close { at });
            }
        }
        match step.change {
            Some(
                Transition::Promote
                | Transition::Replace
                | Transition::Move
                | Transition::Keep
                | Transition::RekeyCutover
                | Transition::Restarted,
            ) => self.announce(net, peer),
            Some(Transition::Remove) => {
                if self.configured.iter().any(|c| c.peer == peer) {
                    self.retry.insert(peer.0, net.now + RETRY);
                }
            }
            Some(Transition::Roam) | None => {}
        }
    }

    /// Send one frame to `peer` under the session held, now.
    fn announce(&mut self, net: &mut Net, peer: Node) {
        let (me, ix) = (self.me, self.ix);
        let s = self.side(peer, net.now);
        if let Some((hs, _, at)) = s.judge.settled() {
            s.beat = net.now;
            net.send(
                ix,
                None,
                at,
                Pkt::Frame {
                    id: me,
                    hs,
                    wire: 0,
                },
            );
        }
    }

    /// Start an own dial of `peer` at `to`.
    fn dial(&mut self, net: &mut Net, peer: Node, to: Addr, from: Option<Addr>) {
        let hs = self.fresh();
        let link = self.link();
        let bytes = Bytes(hs.0);
        let kind = net.kind(to.transport);
        net.connect(self.ix, from, to);
        let pkt = Pkt::Msg1 {
            id: self.me,
            hs,
            bytes,
            epoch: self.epoch(),
            wire: 0,
        };
        net.send(self.ix, from, to, pkt);
        let now = net.now;
        let s = self.side(peer, now);
        s.judge.step(Event::Dial {
            hs,
            link,
            to,
            binding: binding(kind),
        });
        s.dials.insert(
            hs.0,
            Dial {
                link,
                to,
                from,
                bytes,
                resends: 0,
                next: now + RESEND,
                deadline: now + HANDSHAKE,
            },
        );
        self.retry.remove(&peer.0);
    }

    /// A dial or stored leg `hs` of `peer` ended.
    fn ended(&mut self, net: &mut Net, peer: Node, hs: Hs) {
        let s = self.side(peer, net.now);
        let was = s.dials.remove(&hs.0).is_some();
        s.stored.remove(&hs.0);
        self.step(net, peer, Event::Timeout { hs });
        if was && self.configured.iter().any(|c| c.peer == peer) {
            self.retry.insert(peer.0, net.now + RETRY);
        }
    }

    fn msg1(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, bytes: Bytes, epoch: Epoch) {
        let (ix, me, mine) = (self.ix, self.me, self.epoch());
        let sent = net.sendable(ix, src);
        let known = self
            .sides
            .get(&id.0)
            .and_then(|s| s.links.get(&hs.0))
            .copied();
        let link = known.unwrap_or_else(|| self.link());
        let kind = net.kind(src.transport);
        let s = self.side(id, net.now);
        s.links.insert(hs.0, link);
        let stale = s.judge.peering.as_ref().map(|p| (p.setup, p.binding));
        let step = s.judge.step(Event::Msg1 {
            hs,
            bytes,
            epoch,
            link,
            from: src,
            binding: binding(kind),
            sent,
        });
        let answer = Answer {
            to: src,
            pkt: Pkt::Msg2 {
                id: me,
                hs,
                epoch: mine,
                wire: 0,
            },
        };
        let mut done = None;
        match step.reply {
            Some(Reply::Msg2) => {
                net.send(ix, None, src, answer.pkt);
                s.answers.insert(hs.0, answer);
            }
            Some(Reply::Deferred) => {
                s.stored.insert(hs.0, (answer, net.now + HANDSHAKE));
            }
            Some(Reply::Stored) => {
                let leg = s
                    .stored
                    .iter()
                    .find(|(_, (a, _))| a.to == src)
                    .map(|(k, v)| (*k, v.0));
                if let Some((k, a)) = leg {
                    if sent {
                        net.send(ix, None, a.to, a.pkt);
                        s.stored.remove(&k);
                        s.answers.insert(k, a);
                        done = Some(Hs(k));
                    }
                } else if let Some(a) = s.answers.get(&bytes.0) {
                    net.send(ix, None, src, a.pkt);
                }
            }
            Some(Reply::Silent) | None => {}
        }
        self.effects(net, id, &step);
        // A local choice, where FRC-1201 is silent: a replacement or
        // restart tears the stale peering down, and its link's connection
        // is closed by the close rule, as a crossing's losing link's is,
        // when the new msg1 came over another connection and no link of
        // this node uses it. The FRC states the close for the crossing
        // alone; `master` keeps the connection.
        if !fault!(ReplacedConnKept)
            && matches!(step.change, Some(Transition::Replace | Transition::Remove))
            && let Some((at, Binding::Connected)) = stale
            && at != src
            && !self.uses(at)
        {
            net.close(self.ix, at);
        }
        if let Some(hs) = done {
            self.step(net, id, Event::Msg2Sent { hs });
        }
        self.unused(net, src);
    }

    fn msg2(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, epoch: Epoch) {
        let now = net.now;
        let s = self.side(id, now);
        if s.dials.remove(&hs.0).is_some() {
            let step = self.step(
                net,
                id,
                Event::Msg2 {
                    hs,
                    epoch,
                    from: src,
                },
            );
            if matches!(
                step.change,
                Some(Transition::Promote | Transition::Replace | Transition::Move)
            ) {
                net.mark(self.ix, src, true);
            }
        } else if s.rekey.is_some_and(|r| r.hs == hs) {
            s.rekey = None;
            s.cutover = Some(now + CHECK);
            self.step(net, id, Event::RekeyMsg2 { hs, epoch });
        }
    }

    fn closed(&mut self, net: &mut Net, at: Addr) {
        let peers: Vec<Node> = self.sides.values().map(|s| s.judge.peer).collect();
        for peer in peers {
            let s = self.side(peer, net.now);
            s.judge.step(Event::Close { at });
            let gone: Vec<u32> = s
                .dials
                .iter()
                .filter(|(_, d)| d.to == at)
                .map(|(k, _)| *k)
                .chain(
                    s.stored
                        .iter()
                        .filter(|(_, (a, _))| a.to == at)
                        .map(|(k, _)| *k),
                )
                .collect();
            let lost = s.judge.peering.as_ref().is_some_and(|p| {
                p.binding == Binding::Connected && (p.current == at || p.setup == at)
            });
            for k in gone {
                self.ended(net, peer, Hs(k));
            }
            if lost {
                // A connection-oriented link whose connection closed is
                // dead: the node removes the peer.
                self.step(net, peer, Event::Lost);
            }
        }
        // A resend may have reconnected before this close was read; the
        // leg it belonged to is gone, and the node closes its connection
        // when no live link uses the address (`timeout.rs:164`).
        if !self.uses(at) {
            net.close(self.ix, at);
        }
    }

    fn wake_side(&mut self, net: &mut Net, peer: Node) {
        let (ix, me, now, epoch) = (self.ix, self.me, net.now, self.epoch());
        let s = self.side(peer, now);
        let mut ended = Vec::new();
        for (k, d) in s.dials.iter_mut() {
            if now >= d.deadline {
                ended.push(*k);
            } else if now >= d.next && d.resends < RESENDS {
                d.resends += 1;
                d.next = now + (RESEND << d.resends);
                let pkt = Pkt::Msg1 {
                    id: me,
                    hs: Hs(*k),
                    bytes: d.bytes,
                    epoch,
                    wire: 0,
                };
                net.send(ix, d.from, d.to, pkt);
            }
        }
        ended.extend(
            s.stored
                .iter()
                .filter(|(_, (_, t))| now >= *t)
                .map(|(k, _)| *k),
        );
        if let Some(r) = s.rekey.as_mut() {
            if now >= r.deadline {
                // The model has no rekey deadline; the abandoned rekey is
                // no longer in flight.
                s.rekey = None;
                s.judge.rekey = None;
            } else if now >= r.next && r.resends < RESENDS {
                r.resends += 1;
                r.next = now + (RESEND << r.resends);
                let pkt = Pkt::Msg1 {
                    id: me,
                    hs: r.hs,
                    bytes: Bytes(r.hs.0),
                    epoch,
                    wire: 0,
                };
                let to = r.to;
                net.send(ix, None, to, pkt);
            }
        }
        for k in ended {
            self.ended(net, peer, Hs(k));
        }
        let s = self.side(peer, now);
        if s.cutover.is_some_and(|t| now >= t) {
            s.cutover = None;
            self.step(net, peer, Event::RekeyCutover);
        }
        let s = self.side(peer, now);
        if s.judge.settled().is_some() && now >= s.beat + HEARTBEAT {
            if fault!(NoHeartbeat) {
                s.beat = now;
            } else {
                self.announce(net, peer);
            }
        }
    }

    fn redial(&mut self, net: &mut Net) {
        for c in self.configured.clone() {
            let due = self.retry.get(&c.peer.0).is_some_and(|&t| net.now >= t);
            let s = self.sides.get(&c.peer.0);
            let idle = s.is_none_or(|s| s.judge.peering.is_none() && s.dials.is_empty());
            if due && idle {
                self.dial(net, c.peer, c.to, c.from);
            } else if due {
                self.retry.remove(&c.peer.0);
            }
        }
    }
}

impl Party for ModelParty {
    fn input(&mut self, net: &mut Net, inp: Input) {
        match inp {
            Input::Packet { src, pkt, .. } => match pkt {
                Pkt::Msg1 {
                    id,
                    hs,
                    bytes,
                    epoch,
                    ..
                } => self.msg1(net, src, id, hs, bytes, epoch),
                Pkt::Msg2 { id, hs, epoch, .. } => self.msg2(net, src, id, hs, epoch),
                Pkt::Frame { id, hs, .. } => {
                    if self.sides.contains_key(&id.0) {
                        self.step(net, id, Event::Frame { hs, from: src });
                        net.mark(self.ix, src, true);
                    }
                }
                Pkt::Eof => self.closed(net, src),
            },
            Input::Closed { at } | Input::ConnectFailed { to: at } => self.closed(net, at),
            Input::Wake => {
                let peers: Vec<Node> = self.sides.values().map(|s| s.judge.peer).collect();
                for peer in peers {
                    self.wake_side(net, peer);
                }
                self.reap(net);
                self.redial(net);
            }
            Input::Restart => {
                self.life += 1;
                self.count = 0;
                self.sides.clear();
                self.retry.clear();
                self.idle.clear();
                for c in self.configured.clone() {
                    self.dial(net, c.peer, c.to, c.from);
                }
            }
            Input::Dial { peer, to, from } => self.dial(net, peer, to, from),
            Input::Rekey { peer } => {
                if self.rekeyable(peer) {
                    let hs = self.fresh();
                    let (ix, me, epoch, now) = (self.ix, self.me, self.epoch(), net.now);
                    let s = self.side(peer, now);
                    let (_, _, to) = s.judge.settled().expect("rekeyable holds the peer");
                    s.judge.step(Event::RekeyStart { hs });
                    s.rekey = Some(Own {
                        hs,
                        to,
                        resends: 0,
                        next: now + RESEND,
                        deadline: now + HANDSHAKE,
                    });
                    net.send(
                        ix,
                        None,
                        to,
                        Pkt::Msg1 {
                            id: me,
                            hs,
                            bytes: Bytes(hs.0),
                            epoch,
                            wire: 0,
                        },
                    );
                }
            }
            Input::Beat => {
                for peer in self.held() {
                    self.announce(net, peer);
                }
            }
            Input::Path(_) => {}
        }
    }

    fn wake(&self) -> Option<Ms> {
        let mut t: Option<Ms> = None;
        let mut at = |v: Ms| t = Some(t.map_or(v, |t| t.min(v)));
        for s in self.sides.values() {
            for d in s.dials.values() {
                at(d.deadline);
                if d.resends < RESENDS {
                    at(d.next);
                }
            }
            for (_, dl) in s.stored.values() {
                at(*dl);
            }
            if let Some(r) = s.rekey {
                at(r.deadline);
                if r.resends < RESENDS {
                    at(r.next);
                }
            }
            if let Some(c) = s.cutover {
                at(c);
            }
            if s.judge.settled().is_some() {
                at(s.beat + HEARTBEAT);
            }
        }
        for v in self.retry.values().chain(self.idle.values()) {
            at(*v);
        }
        t
    }

    fn digest(&self) -> String {
        format!("{self:?}")
    }

    fn epoch(&self) -> Epoch {
        ModelParty::epoch(self)
    }

    fn holds(&self, peer: Node, hs: Hs) -> bool {
        self.sides
            .get(&peer.0)
            .and_then(|s| s.judge.peering.as_ref())
            .is_some_and(|p| {
                p.hs == hs
                    || p.pending.is_some_and(|pd| pd.hs == hs)
                    || p.fallback.is_some_and(|f| f.hs == hs)
            })
    }

    fn held(&self) -> Vec<Node> {
        self.sides
            .values()
            .filter(|s| s.judge.peering.is_some())
            .map(|s| s.judge.peer)
            .collect()
    }

    /// A node starts its own rekey only on a link and session old enough
    /// to be rekeyed (the rekey machine's floors).
    fn rekeyable(&self, peer: Node) -> bool {
        self.sides.get(&peer.0).is_some_and(|s| {
            let now = s.judge.now;
            s.rekey.is_none()
                && s.cutover.is_none()
                && s.judge.peering.as_ref().is_some_and(|p| {
                    now.saturating_sub(p.linkborn) >= LINKAGE
                        && now.saturating_sub(p.sessionborn) >= SESSIONAGE
                })
        })
    }

    /// The model is the specification, so its peer is always on the link
    /// of the handshake it holds: the view names that handshake for both,
    /// and a node's direction is whether the model's peering was dialed.
    fn view(&self) -> View {
        let mut v = View::empty(self.me);
        v.configured = self.configured.iter().map(|c| c.peer).collect();
        v.bounds.push(("peers", self.sides.len(), 8));
        for s in self.sides.values() {
            let j = &s.judge;
            v.needs.extend(j.needs().into_iter().map(|(_, at)| at));
            let mut dials: Vec<u32> = s.dials.keys().copied().collect();
            let mut attempts: Vec<u32> = j.attempts.iter().map(|a| a.hs.0).collect();
            dials.sort_unstable();
            attempts.sort_unstable();
            if dials != attempts {
                v.audit.push(format!(
                    "{:?}: dials {dials:?}, attempts {attempts:?}",
                    j.peer
                ));
            }
            let mut stored: Vec<u32> = s.stored.keys().copied().collect();
            let mut legs: Vec<u32> = j.legs.iter().map(|l| l.hs.0).collect();
            stored.sort_unstable();
            legs.sort_unstable();
            if stored != legs {
                v.audit
                    .push(format!("{:?}: stored {stored:?}, legs {legs:?}", j.peer));
            }
            v.bounds.push(("dials", s.dials.len(), 8));
            v.bounds.push(("legs", j.legs.len(), 8));
            if let Some(p) = &j.peering {
                v.bounds.push(("record", p.record.len(), 64));
                v.peers.push(PeerView {
                    peer: j.peer,
                    cur: p.hs,
                    origin: p.hs,
                    link: p.hs,
                    dir: if p.dialed {
                        Dir::Outbound
                    } else {
                        Dir::Inbound
                    },
                    at: p.setup,
                    current: p.current,
                    answered: false,
                    pending: p.pending.map(|pd| (pd.hs, pd.initiator)),
                    rekey: s.rekey.map(|r| r.hs),
                    dials: dials.iter().map(|&k| Hs(k)).collect(),
                });
            }
        }
        v
    }
}
