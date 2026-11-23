//! A model of next's handshake settlement, transcribed from next's shell
//! at the port's base (`be5204f9e`; the line ranges are in this
//! directory's README), as a node of the settlement world.
//!
//! [`NextParty`] decides as next's node does, abstractly: no keys, no
//! rekey machine, no path bundle. An XX msg1 names no one, so it opens an
//! inbound leg and is answered with a msg2 at once, unless it repeats the
//! bytes a pending leg at its source answered, which draws that leg's
//! stored msg2. A msg2 is checked against the identity the dial named,
//! then classified by `establish_outbound`: a new identity is promoted, a
//! changed epoch replaces the peer with no gate, a dial beside this node's
//! own unheard dial that installed the peer after it began is kept with no
//! msg3, and anything else is settled by address order, the smaller node
//! swapping onto its dial and the larger keeping what it holds; both send
//! msg3. A msg3 is classified by `establish_inbound`: a new identity is
//! promoted, a changed epoch is refused while the peering was heard or
//! installed less than 15 s ago or the dampener holds, and otherwise
//! replaces the peer and stamps the dampener; a claim of a session not
//! held repeats the stored msg2; no claim is a crossing, which the larger
//! node's inbound wins whoever dialed either link.
//!
//! It logs, per peer identity, each event of the judge's history it saw
//! and what it did, in the judge's terms, so `judged.rs` can replay each
//! peer's log through the judge and compare them step by step. The log is
//! shared through [`Log`], since the world holds its parties as trait
//! objects.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use super::super::model::history as xx;
use super::super::model::judge::{Class, Refusal, Reply, Transition};
use crate::proto::settle::model::history::{Addr, Bytes, Epoch, Hs, Node};
use crate::proto::settle::tests::world::{
    Dir, Extra, HANDSHAKE, HEARTBEAT, Input, Kind, Ms, Net, Party, PeerView, Pkt, RESEND, RESENDS,
    View,
};

/// `link_dead_timeout_secs`, 30 s (`src/config/node.rs:1757`).
const LINKDEAD: Ms = 30_000;

/// `EPOCH_RESTART_MIN_INTERVAL_SECS`, 15 s, in ms.
const INTERVAL: Ms = 15_000;

/// The packets an XX party adds to the world's: the anonymous msg1 and the
/// msg3. An XX msg2 and a frame are the world's own `Msg2` and `Frame`,
/// which carry what an XX msg2 teaches: the identity and the epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Packet {
    /// A msg1. It names no one on the wire; `id` is its sender, carried so
    /// the receiver's log can put it in that identity's history, and never
    /// read by the receiver's rules.
    Msg1 {
        /// The sender, for the log only.
        id: Node,
        /// The handshake.
        hs: Hs,
        /// Its exact bytes.
        bytes: Bytes,
    },
    /// A msg3 from `id` completing `hs`, carrying `epoch` and the session
    /// of the peer's it declares a rekey of, if any.
    Msg3 {
        /// The sender's identity, which the msg3 authenticates.
        id: Node,
        /// The handshake it completes.
        hs: Hs,
        /// The sender's epoch.
        epoch: Epoch,
        /// The handshake of the session it claims to replace.
        claim: Option<Hs>,
    },
}

impl Extra for Packet {
    fn handshake(&self) -> bool {
        true
    }
    fn opens(&self) -> bool {
        matches!(self, Self::Msg1 { .. })
    }
    fn wire(&self) -> u32 {
        0
    }
    fn bare(self) -> Self {
        self
    }
}

/// What next did with one event, in the judge's terms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Did {
    /// The completed handshake's class.
    pub class: Option<Class>,
    /// The check that refused it.
    pub refused: Option<Refusal>,
    /// What next sent.
    pub reply: Option<Reply>,
    /// The peer change.
    pub change: Option<Transition>,
}

/// One logged event: when, of which peer, the judge's event, and what next
/// did with it.
pub type Entry = (Ms, Node, xx::Event, Did);

/// The log a party shares with whoever reads it after a run.
pub type Log = Rc<RefCell<Vec<Entry>>>;

/// A link record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Link {
    dir: Dir,
    remote: Addr,
    hs: Hs,
}

/// An own dial in flight (`pending_outbound` and its machine).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Dial {
    peer: Node,
    hs: Hs,
    bytes: Bytes,
    to: Addr,
    from: Option<Addr>,
    resends: u32,
    next: Ms,
    deadline: Ms,
}

/// A pending inbound leg, parked at `SentMsg2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Leg {
    hs: Hs,
    bytes: Bytes,
    from: Addr,
    local: Addr,
    msg2: Pkt<Packet>,
    deadline: Ms,
    /// The msg1's sender, for the log only.
    id: Node,
}

/// A held peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Peer {
    hs: Hs,
    link: u32,
    epoch: Epoch,
    current: Addr,
    /// `heard_at`: the install, a move, or the last frame.
    heard: Ms,
    /// `heard_on_session`: a frame heard under the session the link holds.
    framed: bool,
    /// `mark`: the next link id when the session was installed or moved
    /// onto, so a dial on a lower link predates it.
    mark: u32,
    /// The msg2 this node answered the peer's handshake with, as responder.
    msg2: Option<Pkt<Packet>>,
    /// A peer's rekey completed here and not yet cut over to.
    pending: Option<Hs>,
    beat: Ms,
}

/// next's node, as a party of the world.
#[derive(Debug)]
pub struct NextParty {
    ix: usize,
    me: Node,
    life: u32,
    count: u32,
    nextlink: u32,
    now: Ms,
    links: BTreeMap<u32, Link>,
    dials: BTreeMap<u32, Dial>,
    legs: BTreeMap<u32, Leg>,
    peers: BTreeMap<Node, Peer>,
    dampener: BTreeMap<Node, Ms>,
    log: Log,
}

impl NextParty {
    /// Node `me`, at index `ix` of the world, logging to `log`.
    pub fn new(ix: usize, me: Node, log: Log) -> Self {
        Self {
            ix,
            me,
            life: 0,
            count: 0,
            nextlink: 1,
            now: 0,
            links: BTreeMap::new(),
            dials: BTreeMap::new(),
            legs: BTreeMap::new(),
            peers: BTreeMap::new(),
            dampener: BTreeMap::new(),
            log,
        }
    }

    fn mine(&self) -> Epoch {
        Epoch(u32::from(self.me.0) * 100 + self.life)
    }

    fn fresh(&mut self) -> Hs {
        self.count += 1;
        Hs((u32::from(self.me.0) << 24) | (self.life << 16) | self.count)
    }

    fn link(&mut self, dir: Dir, remote: Addr, hs: Hs) -> u32 {
        let id = self.nextlink;
        self.nextlink += 1;
        self.links.insert(id, Link { dir, remote, hs });
        id
    }

    fn note(&self, peer: Node, e: xx::Event, did: Did) {
        self.log.borrow_mut().push((self.now, peer, e, did));
    }

    /// Send the peer one frame now, as the tree announce after a promotion
    /// or a move does, and as a heartbeat.
    fn announce(&mut self, net: &mut Net<Packet>, peer: Node) {
        let me = self.me;
        let Some(p) = self.peers.get_mut(&peer) else {
            return;
        };
        p.beat = self.now + HEARTBEAT;
        let pkt = Pkt::Frame {
            id: me,
            hs: p.hs,
            wire: 0,
        };
        let to = p.current;
        net.send(self.ix, None, to, pkt);
    }

    fn dial(&mut self, net: &mut Net<Packet>, peer: Node, to: Addr, from: Option<Addr>) {
        let hs = self.fresh();
        let bytes = Bytes(hs.0);
        let link = self.link(Dir::Outbound, to, hs);
        self.dials.insert(
            link,
            Dial {
                peer,
                hs,
                bytes,
                to,
                from,
                resends: 0,
                next: self.now + RESEND,
                deadline: self.now + HANDSHAKE,
            },
        );
        let e = xx::Event::Dial {
            hs: xh(hs),
            link: xx::LinkId(link),
            to: xa(to),
            binding: binding(net.kind(to.transport)),
            named: xx::Named::Peer,
        };
        self.note(peer, e, Did::default());
        let me = self.me;
        net.send(
            self.ix,
            from,
            to,
            Pkt::Flow(Packet::Msg1 { id: me, hs, bytes }),
        );
    }

    /// An anonymous msg1 (`handshake.rs:415-470`, `:557-645`).
    fn msg1(
        &mut self,
        net: &mut Net<Packet>,
        src: Addr,
        local: Addr,
        id: Node,
        hs: Hs,
        bytes: Bytes,
    ) {
        let held = |l: u32| self.peers.values().any(|p| p.link == l);
        let pending = self
            .legs
            .iter()
            .find(|(l, leg)| leg.from == src && !held(**l))
            .map(|(l, leg)| (*l, *leg));
        let kind = net.kind(src.transport);
        if let Some((l, leg)) = pending
            && leg.bytes == bytes
        {
            net.send(self.ix, Some(local), src, leg.msg2);
            let e = msg1_event(leg.hs, l, src, kind);
            self.note(id, e, reply(Reply::Stored));
            return;
        }
        let link = self.link(Dir::Inbound, src, hs);
        let msg2 = Pkt::Msg2 {
            id: self.me,
            hs,
            epoch: self.mine(),
            wire: 0,
        };
        self.legs.insert(
            link,
            Leg {
                hs,
                bytes,
                from: src,
                local,
                msg2,
                deadline: self.now + HANDSHAKE,
                id,
            },
        );
        net.send(self.ix, Some(local), src, msg2);
        self.note(id, msg1_event(hs, link, src, kind), reply(Reply::Msg2));
    }

    /// The msg2 of an own dial (`handshake.rs:986-1243`, `:1250-1535`;
    /// `establish_outbound` and `dial_outbound`, `fmp/core.rs:765-810`).
    fn msg2(&mut self, net: &mut Net<Packet>, src: Addr, id: Node, hs: Hs, epoch: Epoch) {
        let Some((&link, &dial)) = self.dials.iter().find(|(_, d)| d.hs == hs) else {
            return;
        };
        if dial.peer != id {
            // `StaticMismatch`: the msg2 is dropped and the leg kept. The
            // judge's history of `id` holds no dial, so nothing is logged.
            return;
        }
        let e = xx::Event::Msg2 {
            hs: xh(hs),
            epoch: xe(epoch),
            refused: false,
        };
        self.dials.remove(&link);
        let me = self.me;
        let msg3 = Pkt::Flow(Packet::Msg3 {
            id: me,
            hs,
            epoch: self.mine(),
            claim: None,
        });
        let Some(p) = self.peers.get(&id).copied() else {
            self.install(id, hs, link, epoch, src, None);
            net.send(self.ix, None, src, msg3);
            self.announce(net, id);
            return self.note(
                id,
                e,
                done(Class::NotHeld, Transition::Promote, Reply::Final),
            );
        };
        if epoch != p.epoch {
            // `RestartThenPromote`, with no gate and no stamp.
            self.links.remove(&p.link);
            self.install(id, hs, link, epoch, src, None);
            net.send(self.ix, None, src, msg3);
            self.announce(net, id);
            return self.note(
                id,
                e,
                done(Class::Restart, Transition::Replace, Reply::Final),
            );
        }
        let own = self
            .links
            .get(&p.link)
            .is_some_and(|l| l.dir == Dir::Outbound);
        let class = if own {
            Class::SameSide
        } else {
            Class::Crossing
        };
        if link < p.mark && !p.framed && own {
            // `OwnDialKeep`: no msg3, the held session kept, the dial's
            // link dropped (`facts.loser`).
            self.links.remove(&link);
            let did = Did {
                class: Some(class),
                refused: Some(Refusal::Live),
                reply: Some(Reply::Silent),
                change: None,
            };
            return self.note(id, e, did);
        }
        net.send(self.ix, None, src, msg3);
        if self.me < id {
            // `CrossConnectionSwap`: onto the dial, at the msg2's pair.
            self.links.remove(&p.link);
            let mark = self.nextlink;
            let q = self.peers.get_mut(&id).expect("held");
            q.hs = hs;
            q.link = link;
            q.current = src;
            q.heard = self.now;
            q.framed = false;
            q.mark = mark;
            q.pending = None;
            self.announce(net, id);
            return self.note(id, e, done(class, Transition::Move, Reply::Final));
        }
        // `CrossConnectionKeep`: msg3 sent, the dial's link dropped.
        self.links.remove(&link);
        self.note(id, e, done(class, Transition::Keep, Reply::Final));
    }

    /// A msg3 on an inbound leg (`handshake.rs:1680-2190`;
    /// `establish_inbound`, `fmp/core.rs:642-764`; the crossing,
    /// `peer_actions.rs:553-690`).
    fn msg3(
        &mut self,
        net: &mut Net<Packet>,
        src: Addr,
        id: Node,
        hs: Hs,
        epoch: Epoch,
        claim: Option<Hs>,
    ) {
        let Some((&link, &leg)) = self.legs.iter().find(|(_, l)| l.hs == hs) else {
            return;
        };
        let p = self.peers.get(&id).copied();
        let declared = match (claim, p) {
            (None, _) => xx::Claim::None,
            (Some(h), Some(p)) if h == p.hs => xx::Claim::Held,
            (Some(_), _) => xx::Claim::Other,
        };
        let e = xx::Event::Msg3 {
            hs: xh(hs),
            epoch: xe(epoch),
            claim: declared,
            refused: false,
        };
        self.legs.remove(&link);
        let Some(p) = p else {
            self.install(id, hs, link, epoch, leg.from, Some(leg.msg2));
            self.announce(net, id);
            return self.note(
                id,
                e,
                done(Class::NotHeld, Transition::Promote, Reply::Silent),
            );
        };
        if epoch != p.epoch {
            let idle = self.now.saturating_sub(p.heard) < INTERVAL;
            let damped = self
                .dampener
                .get(&id)
                .is_some_and(|t| self.now.saturating_sub(*t) < INTERVAL);
            if idle || damped {
                // `EpochRestartDampened`: the leg and its link go.
                self.links.remove(&link);
                let why = if idle {
                    Refusal::Heard
                } else {
                    Refusal::Dampened
                };
                let did = Did {
                    class: Some(Class::Restart),
                    refused: Some(why),
                    reply: Some(Reply::Silent),
                    change: None,
                };
                return self.note(id, e, did);
            }
            self.dampener.insert(id, self.now);
            self.links.remove(&p.link);
            self.install(id, hs, link, epoch, leg.from, Some(leg.msg2));
            self.announce(net, id);
            return self.note(
                id,
                e,
                done(Class::Restart, Transition::Replace, Reply::Silent),
            );
        }
        match declared {
            xx::Claim::Other => {
                // `RepeatMsg2`, on the msg3's connection; the leg goes.
                if let Some(m) = p.msg2 {
                    net.send(self.ix, Some(leg.local), src, m);
                }
                self.links.remove(&link);
                let did = Did {
                    class: Some(Class::Stale),
                    reply: Some(Reply::Stored),
                    ..Did::default()
                };
                self.note(id, e, did);
            }
            xx::Claim::Held => {
                // `PeerRekey`: the read goes to the peer's link rekey
                // machine, which this model does not run; it holds the
                // session pending until the peer's first frame under it.
                self.links.remove(&link);
                if let Some(q) = self.peers.get_mut(&id) {
                    q.pending = Some(hs);
                }
                self.note(id, e, done(Class::Rekey, Transition::Rekey, Reply::Silent));
            }
            xx::Claim::None => {
                let own = self
                    .links
                    .get(&p.link)
                    .is_some_and(|l| l.dir == Dir::Outbound);
                let class = if own {
                    Class::Crossing
                } else {
                    Class::SameSide
                };
                if self.me >= id {
                    // Our inbound wins: onto the leg's session, at the msg3's
                    // pair, on the link the peer is held on, whose record
                    // stays as it was; the leg's link is retired, closing
                    // nothing (`ResolveInboundCrossConnection`,
                    // `peer_actions.rs`).
                    self.links.remove(&link);
                    let mark = self.nextlink;
                    let q = self.peers.get_mut(&id).expect("held");
                    q.hs = hs;
                    q.current = src;
                    q.heard = self.now;
                    q.framed = false;
                    q.mark = mark;
                    q.msg2 = Some(leg.msg2);
                    q.pending = None;
                    self.announce(net, id);
                    return self.note(id, e, done(class, Transition::Move, Reply::Silent));
                }
                self.links.remove(&link);
                self.note(id, e, done(class, Transition::Keep, Reply::Silent));
            }
        }
    }

    fn install(
        &mut self,
        id: Node,
        hs: Hs,
        link: u32,
        epoch: Epoch,
        at: Addr,
        msg2: Option<Pkt<Packet>>,
    ) {
        let mark = self.nextlink;
        self.peers.insert(
            id,
            Peer {
                hs,
                link,
                epoch,
                current: at,
                heard: self.now,
                framed: false,
                mark,
                msg2,
                pending: None,
                beat: self.now + HEARTBEAT,
            },
        );
    }

    /// A frame that opened under a session this node holds.
    fn frame(&mut self, src: Addr, id: Node, hs: Hs) {
        let now = self.now;
        let Some(p) = self.peers.get_mut(&id) else {
            return;
        };
        let change = if p.hs == hs {
            None
        } else if p.pending == Some(hs) {
            p.hs = hs;
            p.pending = None;
            Some(Transition::RekeyCutover)
        } else {
            return;
        };
        p.heard = now;
        p.framed = true;
        p.current = src;
        let e = xx::Event::Frame {
            hs: xh(hs),
            from: xa(src),
        };
        self.note(
            id,
            e,
            Did {
                change,
                ..Did::default()
            },
        );
    }

    fn timers(&mut self, net: &mut Net<Packet>) {
        let now = self.now;
        let me = self.me;
        for (link, d) in self.dials.clone() {
            if d.deadline <= now {
                self.dials.remove(&link);
                self.links.remove(&link);
                self.note(d.peer, xx::Event::Timeout { hs: xh(d.hs) }, Did::default());
            } else if d.next <= now && d.resends < RESENDS {
                let pkt = Pkt::Flow(Packet::Msg1 {
                    id: me,
                    hs: d.hs,
                    bytes: d.bytes,
                });
                net.send(self.ix, d.from, d.to, pkt);
                let q = self.dials.get_mut(&link).expect("dial");
                q.resends += 1;
                q.next = now + (RESEND << q.resends);
            }
        }
        for (link, l) in self.legs.clone() {
            if l.deadline <= now {
                self.legs.remove(&link);
                self.links.remove(&link);
                self.note(l.id, xx::Event::Timeout { hs: xh(l.hs) }, Did::default());
            }
        }
        for (id, p) in self.peers.clone() {
            if now.saturating_sub(p.heard) >= LINKDEAD {
                self.peers.remove(&id);
                self.links.remove(&p.link);
                self.note(
                    id,
                    xx::Event::Lost,
                    Did {
                        change: Some(Transition::Remove),
                        ..Did::default()
                    },
                );
            } else if p.beat <= now {
                self.announce(net, id);
            }
        }
    }
}

impl Party<Packet> for NextParty {
    fn input(&mut self, net: &mut Net<Packet>, inp: Input<Packet>) {
        self.now = net.now;
        match inp {
            Input::Packet {
                src, local, pkt, ..
            } => match pkt {
                Pkt::Flow(Packet::Msg1 { id, hs, bytes }) => {
                    self.msg1(net, src, local, id, hs, bytes)
                }
                Pkt::Flow(Packet::Msg3 {
                    id,
                    hs,
                    epoch,
                    claim,
                }) => self.msg3(net, src, id, hs, epoch, claim),
                Pkt::Msg2 { id, hs, epoch, .. } => self.msg2(net, src, id, hs, epoch),
                Pkt::Frame { id, hs, .. } => self.frame(src, id, hs),
                Pkt::Msg1 { .. } | Pkt::Eof => {}
            },
            Input::Dial { peer, to, from } => self.dial(net, peer, to, from),
            Input::Wake => self.timers(net),
            Input::Beat => {
                for id in self.peers.keys().copied().collect::<Vec<_>>() {
                    self.announce(net, id);
                }
            }
            Input::Restart => {
                let (ix, me, life, log) = (self.ix, self.me, self.life, self.log.clone());
                let mut known: Vec<Node> = log.borrow().iter().map(|e| e.1).collect();
                known.sort();
                known.dedup();
                *self = Self::new(ix, me, log);
                self.life = life + 1;
                self.now = net.now;
                for id in known {
                    self.note(id, xx::Event::Restart, Did::default());
                }
            }
            Input::Closed { .. }
            | Input::ConnectFailed { .. }
            | Input::Rekey { .. }
            | Input::Path(_) => {}
        }
    }

    fn wake(&self) -> Option<Ms> {
        let dials = self.dials.values().flat_map(|d| {
            let resend = (d.resends < RESENDS).then_some(d.next);
            [Some(d.deadline), resend]
        });
        let legs = self.legs.values().map(|l| Some(l.deadline));
        let peers = self
            .peers
            .values()
            .flat_map(|p| [Some(p.beat), Some(p.heard + LINKDEAD)]);
        dials.chain(legs).chain(peers).flatten().min()
    }

    fn digest(&self) -> String {
        format!(
            "{:?}{:?}{:?}{:?}{:?}{:?}{}",
            self.links, self.dials, self.legs, self.peers, self.dampener, self.life, self.nextlink
        )
    }

    fn holds(&self, peer: Node, hs: Hs) -> bool {
        self.peers
            .get(&peer)
            .is_some_and(|p| p.hs == hs || p.pending == Some(hs))
    }

    fn held(&self) -> Vec<Node> {
        self.peers.keys().copied().collect()
    }

    fn rekeyable(&self, _peer: Node) -> bool {
        false
    }

    fn view(&self) -> View {
        let mut v = View::empty(self.me);
        for (id, p) in &self.peers {
            let link = self.links.get(&p.link);
            v.peers.push(PeerView {
                peer: *id,
                cur: p.hs,
                origin: p.hs,
                link: link.map_or(p.hs, |l| l.hs),
                dir: link.map_or(Dir::Inbound, |l| l.dir),
                at: link.map_or(p.current, |l| l.remote),
                current: p.current,
                answered: link.is_some_and(|l| l.dir == Dir::Outbound),
                pending: p.pending.map(|h| (h, false)),
                rekey: None,
                dials: self
                    .dials
                    .values()
                    .filter(|d| d.peer == *id)
                    .map(|d| d.hs)
                    .collect(),
            });
        }
        v.needs = self.links.values().map(|l| l.remote).collect();
        v
    }

    fn epoch(&self) -> Epoch {
        self.mine()
    }
}

/// The judge's binding for a transport of kind `kind`.
pub fn binding(kind: Kind) -> xx::Binding {
    match kind {
        Kind::Datagram => xx::Binding::Connectionless,
        Kind::Stream | Kind::Ble => xx::Binding::Connected,
    }
}

/// The judge's msg1 event of `hs` on `link` from `from`.
fn msg1_event(hs: Hs, link: u32, from: Addr, kind: Kind) -> xx::Event {
    xx::Event::Msg1 {
        hs: xh(hs),
        link: xx::LinkId(link),
        from: xa(from),
        binding: binding(kind),
    }
}

/// The judge's handshake for the world's `hs`.
pub fn xh(hs: Hs) -> xx::Hs {
    xx::Hs(hs.0)
}

/// The judge's address for the world's `a`.
pub fn xa(a: Addr) -> xx::Addr {
    xx::Addr {
        transport: a.transport,
        at: a.at,
    }
}

/// The judge's epoch for the world's `e`.
pub fn xe(e: Epoch) -> xx::Epoch {
    xx::Epoch(e.0)
}

/// What next did when it only sent `r`.
fn reply(r: Reply) -> Did {
    Did {
        reply: Some(r),
        ..Did::default()
    }
}

/// A completed handshake of class `class` that made change `change` and
/// sent `r`.
fn done(class: Class, change: Transition, r: Reply) -> Did {
    Did {
        class: Some(class),
        refused: None,
        reply: Some(r),
        change: Some(change),
    }
}
