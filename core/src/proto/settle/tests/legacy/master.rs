//! A model of the current node's settlement, transcribed from `master` at
//! `2ba790b2` (the line ranges are in this directory's README).
//!
//! [`MasterParty`] decides as the node does: the duplicate-msg1 short
//! circuit, `establish_inbound`'s classification, the hand-off of a
//! same-epoch msg1 to the peer's link rekey machine (here [`RekeySide`]),
//! the restart and replacement gates with the replay memory, the inbound
//! promotion, `establish_outbound`'s promote, restart, swap and keep, the
//! close of a losing leg by `addr_carries_other_peer`, and the leg timers.
//! Its gates read the clocks the node reads: the heard floor compares the
//! wall clock with the wall stamp of the last frame, the unheard floor two
//! packet stamps, the dampener the monotonic clock. A swap moves the
//! session and keeps the peer's link record, as `move_session` does.
//!
//! It logs every history event it sees and what it did, so the oracles
//! can compare it with the reference model step by step.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::super::model::history::{Addr, Bytes, Epoch, Event, Hs, LinkId, Node};
use super::super::super::model::judge::{Class, Gate, Transition};
use super::super::party::{Configured, binding};
use super::super::rekeyside::{Answer, Out, RekeySide};
use super::super::shadow::{Entry, Rec, Refusal};
use super::super::world::{
    Dir, HANDSHAKE, HEARTBEAT, Input, Kind, Ms, Net, Party, PeerView, Pkt, RESEND, RESENDS, RETRY,
    View,
};
use crate::proto::rekey::Arrival;

/// `EPOCH_RESTART_MIN_INTERVAL_SECS` (`handshake.rs:58`), in ms.
const INTERVAL: Ms = 15_000;
/// `UNHEARD_PEERING_MIN_AGE_MS`.
const UNHEARD: i64 = 1_000;
/// `MAX_REPLAYED_MSG1S` (`handshake.rs:103`).
const REPLAYS: usize = 8;

/// A link record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Link {
    dir: Dir,
    remote: Addr,
    hs: Hs,
}

/// An own dial in flight (`pending_outbound` and its `PeerMachine`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Dial {
    peer: Node,
    link: u32,
    to: Addr,
    from: Option<Addr>,
    resends: u32,
    next: Ms,
    deadline: Ms,
}

/// An inbound leg whose msg2 could not be sent: its stored msg2 waits for
/// a resend of the msg1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Leg {
    peer: Node,
    link: u32,
    from: Addr,
    bytes: Bytes,
    epoch: Epoch,
    deadline: Ms,
}

/// An active peer.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Peer {
    link: u32,
    origin: Hs,
    current: Addr,
    heard: bool,
    last_seen: i64,
    authenticated: i64,
    answered: bool,
    rekey: RekeySide,
    beat: Ms,
}

/// Everything the node keeps, the log aside.
#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    ix: usize,
    now: Ms,
    me: Node,
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
    replayed: BTreeMap<u8, Vec<(Hs, i64)>>,
    /// Inbound connections whose msg1 left no link, by address, and when
    /// the node gives up on each.
    idle: BTreeMap<(u8, u16), Ms>,
}

/// The current node.
pub struct MasterParty {
    s: State,
    log: Vec<Entry>,
}

/// The model of `master` as a node.
pub fn master(ix: usize, me: Node, configured: Vec<Configured>) -> alloc::boxed::Box<dyn Party> {
    alloc::boxed::Box::new(MasterParty::new(ix, me, configured))
}

fn key(a: Addr) -> (u8, u16) {
    (a.transport, a.at)
}

impl MasterParty {
    /// Node `ix` with identity `me`, redialing `configured`.
    pub fn new(ix: usize, me: Node, configured: Vec<Configured>) -> Self {
        Self {
            s: State {
                ix,
                now: 0,
                me,
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
            },
            log: Vec::new(),
        }
    }

    fn epoch(&self) -> Epoch {
        Epoch((u32::from(self.s.me.0) << 8) | self.s.life)
    }

    fn fresh(&mut self) -> Hs {
        self.s.count += 1;
        Hs((u32::from(self.s.me.0) << 24) | (self.s.life << 16) | self.s.count)
    }

    fn link(&mut self, dir: Dir, remote: Addr, hs: Hs) -> u32 {
        self.s.nlinks += 1;
        let id = self.s.nlinks;
        self.s.links.insert(id, Link { dir, remote, hs });
        self.s.index.insert(key(remote), id);
        id
    }

    /// `remove_link`: the record and every index entry naming it.
    fn unlink(&mut self, id: u32) {
        self.s.links.remove(&id);
        self.s.index.retain(|_, l| *l != id);
    }

    /// Whether a link or a peer of this node sends at `at`.
    fn uses(&self, at: Addr) -> bool {
        self.s.links.values().any(|l| l.remote == at)
            || self.s.peers.values().any(|p| p.current == at)
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

    /// `close_handshake_link_connection`: close a leg's connection unless
    /// `addr_carries_other_peer` (a peer on another link sends there).
    fn close_leg(&mut self, net: &mut Net, id: u32) {
        let Some(l) = self.s.links.get(&id).copied() else {
            return;
        };
        let carried = self
            .s
            .peers
            .values()
            .any(|p| p.link != id && p.current == l.remote);
        if !carried {
            net.close(self.s.ix, l.remote);
            self.closed(net, l.remote);
        }
    }

    /// Send a frame to `peer` under its current session.
    fn announce(&mut self, net: &mut Net, peer: Node) {
        let (ix, me, now) = (self.s.ix, self.s.me, net.now);
        if let Some(p) = self.s.peers.get_mut(&peer.0) {
            p.beat = now;
            let pkt = Pkt::Frame {
                id: me,
                hs: p.rekey.cur,
                wire: 0,
            };
            let to = p.current;
            net.send(ix, None, to, pkt);
        }
    }

    /// `answer_msg1`: a reply to a held peer's msg1 goes on its established
    /// link, or on the msg1's own connection when that link's connection is
    /// gone and the msg1 came on the same connection-oriented transport.
    fn answer(&mut self, net: &mut Net, peer: Node, src: Addr, pkt: Pkt) {
        let ix = self.s.ix;
        let Some(cur) = self.s.peers.get(&peer.0).map(|p| p.current) else {
            return;
        };
        let kind = net.kind(cur.transport);
        if kind == Kind::Datagram || net.conn(ix, cur).is_some() {
            net.send(ix, None, cur, pkt);
        } else if src.transport == cur.transport && src != cur && net.conn(ix, src).is_some() {
            net.send(ix, None, src, pkt);
        }
    }

    fn dial(&mut self, net: &mut Net, peer: Node, to: Addr, from: Option<Addr>) {
        let hs = self.fresh();
        let link = self.link(Dir::Outbound, to, hs);
        let now = net.now;
        net.connect(self.s.ix, from, to);
        let pkt = Pkt::Msg1 {
            id: self.s.me,
            hs,
            bytes: Bytes(hs.0),
            epoch: self.epoch(),
            wire: 0,
        };
        net.send(self.s.ix, from, to, pkt);
        self.s.dials.insert(
            hs.0,
            Dial {
                peer,
                link,
                to,
                from,
                resends: 0,
                next: now + RESEND,
                deadline: now + HANDSHAKE,
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

    /// A dial ends unanswered: its leg is reaped (`timeout.rs:164`).
    fn reap(&mut self, net: &mut Net, hs: Hs) {
        let Some(d) = self.s.dials.remove(&hs.0) else {
            return;
        };
        self.close_leg(net, d.link);
        self.unlink(d.link);
        if self.s.configured.iter().any(|c| c.peer == d.peer) {
            self.s.retry.insert(d.peer.0, net.now + RETRY);
        }
        self.note(net.now, d.peer, Event::Timeout { hs }, Rec::default());
    }

    /// `handle_msg1` (`handshake.rs:623-1420`).
    #[allow(clippy::too_many_arguments)]
    fn msg1(
        &mut self,
        net: &mut Net,
        src: Addr,
        id: Node,
        hs: Hs,
        bytes: Bytes,
        epoch: Epoch,
        stamp: i64,
    ) {
        let (ix, now) = (self.s.ix, net.now);
        let bind = binding(net.kind(src.transport));
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
                .map(|(k, g)| (Hs(*k), *g));
            let Some((lhs, g)) = leg else {
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
            if sent {
                let pkt = Pkt::Msg2 {
                    id: self.s.me,
                    hs: lhs,
                    epoch: self.epoch(),
                    wire: 0,
                };
                net.send(ix, None, src, pkt);
                self.s.legs.remove(&lhs.0);
                // `promote_resent`: promoted unless the peer is held.
                if self.s.peers.contains_key(&g.peer.0) {
                    self.note(now, g.peer, Event::Msg2Sent { hs: lhs }, Rec::default());
                } else {
                    self.install(net, g.peer, lhs, g.bytes, g.epoch, l, src, stamp);
                    let rec = Rec {
                        change: Some(Transition::Promote),
                        ..Rec::default()
                    };
                    self.note(now, g.peer, Event::Msg2Sent { hs: lhs }, rec);
                    self.announce(net, g.peer);
                }
            }
            return;
        }
        let sent = net.sendable(ix, src);
        let link_id = self.s.nlinks + 1;
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
            Some(p) if p.rekey.epoch != epoch => Class::Restart,
            Some(p) => {
                let on_link = p.current == src || self.s.index.get(&key(src)) == Some(&p.link);
                let cur = p.current;
                let reachable =
                    net.kind(cur.transport) == Kind::Datagram || net.conn(ix, cur).is_some();
                let arrival = Arrival { on_link, reachable };
                let p = self.s.peers.get_mut(&id.0).expect("held above");
                let (class, answer) = p.rekey.msg1(now, hs, bytes, arrival);
                let me = self.s.me;
                let mine = self.epoch();
                match answer {
                    Answer::Replace => class,
                    Answer::Msg2(h) | Answer::Stored(h) => {
                        self.answer(
                            net,
                            id,
                            src,
                            Pkt::Msg2 {
                                id: me,
                                hs: h,
                                epoch: mine,
                                wire: 0,
                            },
                        );
                        self.note(
                            now,
                            id,
                            ev,
                            Rec {
                                class: Some(class),
                                ..Rec::default()
                            },
                        );
                        return;
                    }
                    Answer::Silent => {
                        self.note(
                            now,
                            id,
                            ev,
                            Rec {
                                class: Some(class),
                                ..Rec::default()
                            },
                        );
                        return;
                    }
                }
            }
        };
        if class != Class::NotHeld {
            // The replay memory and the gates (`handshake.rs:973-1130`).
            let old = self
                .s
                .peers
                .get(&id.0)
                .expect("a restart or replacement of a held peer");
            let (old_heard, last_seen, authenticated) =
                (old.heard, old.last_seen, old.authenticated);
            let refused = if !old_heard && self.replay(id, hs, stamp) {
                Some(Refusal::Replay)
            } else {
                let (idle, min) = if old_heard {
                    (net.wallnow() - last_seen, INTERVAL as i64)
                } else {
                    (stamp - authenticated, UNHEARD)
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
            let old = self.s.peers.remove(&id.0).expect("held above");
            self.unlink(old.link);
        }
        // The promotion tail: a new inbound link, the msg2, the peer.
        let link = self.link(Dir::Inbound, src, hs);
        debug_assert_eq!(link, link_id);
        let change = if sent {
            let pkt = Pkt::Msg2 {
                id: self.s.me,
                hs,
                epoch: self.epoch(),
                wire: 0,
            };
            net.send(ix, None, src, pkt);
            self.install(net, id, hs, bytes, epoch, link, src, stamp);
            Some(if class == Class::NotHeld {
                Transition::Promote
            } else {
                Transition::Replace
            })
        } else {
            self.s.legs.insert(
                hs.0,
                Leg {
                    peer: id,
                    link,
                    from: src,
                    bytes,
                    epoch,
                    deadline: now + HANDSHAKE,
                },
            );
            (class != Class::NotHeld).then_some(Transition::Remove)
        };
        self.note(
            now,
            id,
            ev,
            Rec {
                class: Some(class),
                change,
                ..Rec::default()
            },
        );
        if sent {
            self.announce(net, id);
        }
    }

    /// `ReplayedMsg1s::verdict` (`handshake.rs:170-190`): whether a msg1
    /// replacing an unheard peering is refused.
    fn replay(&mut self, id: Node, hs: Hs, stamp: i64) -> bool {
        let Some(seen) = self.s.replayed.get_mut(&id.0) else {
            return false;
        };
        seen.retain(|&(_, at)| stamp - at < INTERVAL as i64);
        seen.iter().any(|(e, _)| *e == hs) || seen.len() >= REPLAYS
    }

    /// `finish_inbound` and the no-peer promotion: the responder's peer.
    #[allow(clippy::too_many_arguments)]
    fn install(
        &mut self,
        net: &mut Net,
        id: Node,
        hs: Hs,
        bytes: Bytes,
        epoch: Epoch,
        link: u32,
        src: Addr,
        stamp: i64,
    ) {
        let now = net.now;
        let rekey = RekeySide::new(self.s.me, id, hs, epoch, now, Some(bytes));
        self.s.peers.insert(
            id.0,
            Peer {
                link,
                origin: hs,
                current: src,
                heard: false,
                last_seen: stamp,
                authenticated: stamp,
                answered: false,
                rekey,
                beat: now,
            },
        );
        // `note_unheard_promotion`.
        let seen = self.s.replayed.entry(id.0).or_default();
        seen.retain(|&(_, at)| stamp - at < INTERVAL as i64);
        if !seen.iter().any(|(e, _)| *e == hs) {
            seen.push((hs, stamp));
        }
        if seen.len() > REPLAYS {
            seen.remove(0);
        }
        self.s.retry.remove(&id.0);
    }

    /// `handle_msg2` (`handshake.rs:1870-2383`) and `establish_outbound`
    /// (`fmp/core.rs:538`).
    fn msg2(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, epoch: Epoch, stamp: i64) {
        let now = net.now;
        let Some(d) = self.s.dials.get(&hs.0).copied().filter(|d| d.peer == id) else {
            let mine = self
                .s
                .peers
                .get_mut(&id.0)
                .is_some_and(|p| p.rekey.msg2(now, hs, epoch));
            if mine {
                self.note(now, id, Event::RekeyMsg2 { hs, epoch }, Rec::default());
            }
            return;
        };
        self.s.dials.remove(&hs.0);
        let ev = Event::Msg2 {
            hs,
            epoch,
            from: src,
        };
        let change = match self.s.peers.get(&id.0) {
            Some(p) if p.rekey.epoch == epoch => {
                let own = self
                    .s
                    .links
                    .get(&p.link)
                    .is_some_and(|l| l.dir == Dir::Outbound);
                let wins = self.s.me < id;
                let p = self.s.peers.get_mut(&id.0).expect("held above");
                p.answered = true;
                let change = if own || wins {
                    // The swap: `move_session` onto this dial's session at
                    // the msg2's pair; the link record is kept.
                    p.rekey = p.rekey.moved(hs);
                    p.origin = hs;
                    p.current = src;
                    net.mark(self.s.ix, src, true);
                    Transition::Move
                } else {
                    Transition::Keep
                };
                self.close_leg(net, d.link);
                self.unlink(d.link);
                change
            }
            held => {
                let restart = held.is_some();
                if let Some(old) = self.s.peers.remove(&id.0) {
                    self.unlink(old.link);
                }
                let rekey = RekeySide::new(self.s.me, id, hs, epoch, now, None);
                self.s.peers.insert(
                    id.0,
                    Peer {
                        link: d.link,
                        origin: hs,
                        current: src,
                        heard: true,
                        last_seen: stamp,
                        authenticated: stamp,
                        answered: true,
                        rekey,
                        beat: now,
                    },
                );
                net.mark(self.s.ix, src, true);
                if restart {
                    Transition::Replace
                } else {
                    Transition::Promote
                }
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

    fn frame(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, stamp: i64) {
        let now = net.now;
        let Some(p) = self.s.peers.get_mut(&id.0) else {
            return;
        };
        let ev = Event::Frame { hs, from: src };
        if let Some(out) = p.rekey.frame(now, hs) {
            p.heard = true;
            p.last_seen = stamp;
            let change = match out {
                Out::Restarted { .. } => Transition::Restarted,
                Out::Send(_) | Out::Rekeyed { .. } | Out::Abandoned | Out::Unadopted => {
                    Transition::RekeyCutover
                }
            };
            self.s.replayed.remove(&id.0);
            net.mark(self.s.ix, src, true);
            self.note(
                now,
                id,
                ev,
                Rec {
                    change: Some(change),
                    ..Rec::default()
                },
            );
            return;
        }
        let mut change = None;
        if p.rekey.cur == hs {
            p.heard = true;
            p.last_seen = stamp;
            if p.current != src {
                p.current = src;
                change = Some(Transition::Roam);
            }
            self.s.replayed.remove(&id.0);
            net.mark(self.s.ix, src, true);
        }
        self.note(
            now,
            id,
            ev,
            Rec {
                change,
                ..Rec::default()
            },
        );
    }

    /// A connection this node sees at `at` closed. The node removes no
    /// peer for it; link-dead does, later.
    fn closed(&mut self, net: &mut Net, at: Addr) {
        let now = net.now;
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

    fn wake(&mut self, net: &mut Net) {
        let (ix, me, now, epoch) = (self.s.ix, self.s.me, net.now, self.epoch());
        let mut reaped = Vec::new();
        for (k, d) in self.s.dials.iter_mut() {
            if now >= d.deadline {
                reaped.push(Hs(*k));
            } else if now >= d.next && d.resends < RESENDS {
                d.resends += 1;
                d.next = now + (RESEND << d.resends);
                let pkt = Pkt::Msg1 {
                    id: me,
                    hs: Hs(*k),
                    bytes: Bytes(*k),
                    epoch,
                    wire: 0,
                };
                net.send(ix, d.from, d.to, pkt);
            }
        }
        for hs in reaped {
            self.reap(net, hs);
        }
        let stale: Vec<(u32, Leg)> = self
            .s
            .legs
            .iter()
            .filter(|(_, g)| now >= g.deadline)
            .map(|(k, g)| (*k, *g))
            .collect();
        for (k, g) in stale {
            self.s.legs.remove(&k);
            self.close_leg(net, g.link);
            self.unlink(g.link);
            self.note(now, g.peer, Event::Timeout { hs: Hs(k) }, Rec::default());
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
                        let to = self.s.peers[&k].current;
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
                    Out::Rekeyed { .. } | Out::Restarted { .. } => {
                        let change = if matches!(o, Out::Restarted { .. }) {
                            Transition::Restarted
                        } else {
                            Transition::RekeyCutover
                        };
                        self.note(
                            now,
                            peer,
                            Event::RekeyCutover,
                            Rec {
                                change: Some(change),
                                ..Rec::default()
                            },
                        );
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
                && !self.s.dials.values().any(|d| d.peer == c.peer);
            if due && idle {
                self.dial(net, c.peer, c.to, c.from);
            } else if due {
                self.s.retry.remove(&c.peer.0);
            }
        }
    }
}

impl Party for MasterParty {
    fn input(&mut self, net: &mut Net, inp: Input) {
        self.s.now = net.now;
        match inp {
            Input::Packet {
                src, pkt, stamp, ..
            } => match pkt {
                Pkt::Msg1 {
                    id,
                    hs,
                    bytes,
                    epoch,
                    ..
                } => {
                    self.msg1(net, src, id, hs, bytes, epoch, stamp);
                    self.unused(net, src);
                }
                Pkt::Msg2 { id, hs, epoch, .. } => self.msg2(net, src, id, hs, epoch, stamp),
                Pkt::Frame { id, hs, .. } => self.frame(net, src, id, hs, stamp),
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
            Input::Restart => {
                let s = &mut self.s;
                s.life += 1;
                s.count = 0;
                s.retry.clear();
                s.links.clear();
                s.index.clear();
                s.peers.clear();
                s.dials.clear();
                s.legs.clear();
                s.dampener.clear();
                s.replayed.clear();
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
                    let p = self
                        .s
                        .peers
                        .get_mut(&peer.0)
                        .expect("rekeyable holds the peer");
                    p.rekey.start(now, hs);
                    let to = p.current;
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
                    self.note(now, peer, Event::RekeyStart { hs }, Rec::default());
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
        let s = &self.s;
        let dials = s
            .dials
            .values()
            .flat_map(|d| [Some(d.deadline), (d.resends < RESENDS).then_some(d.next)]);
        let legs = s.legs.values().map(|g| Some(g.deadline));
        let peers = s
            .peers
            .values()
            .flat_map(|p| [p.rekey.wake(), Some(p.beat + HEARTBEAT)]);
        let retry = s.retry.values().chain(s.idle.values()).map(|&t| Some(t));
        dials.chain(legs).chain(peers).chain(retry).flatten().min()
    }

    fn digest(&self) -> String {
        format!("{:?}", self.s)
    }

    fn epoch(&self) -> Epoch {
        MasterParty::epoch(self)
    }

    fn holds(&self, peer: Node, hs: Hs) -> bool {
        self.s.peers.get(&peer.0).is_some_and(|p| p.rekey.holds(hs))
    }

    fn held(&self) -> Vec<Node> {
        self.s.peers.keys().map(|&k| Node(k)).collect()
    }

    fn rekeyable(&self, peer: Node) -> bool {
        self.s
            .peers
            .get(&peer.0)
            .is_some_and(|p| p.rekey.idle() && p.rekey.eligible(self.s.now))
    }

    fn view(&self) -> View {
        let s = &self.s;
        let mut v = View::empty(s.me);
        v.configured = s.configured.iter().map(|c| c.peer).collect();
        v.log = self.log.clone();
        v.needs = s
            .links
            .values()
            .map(|l| l.remote)
            .chain(s.peers.values().map(|p| p.current))
            .collect();
        for (k, p) in &s.peers {
            let Some(l) = s.links.get(&p.link) else {
                v.audit
                    .push(format!("peer {k}: link {} has no record", p.link));
                continue;
            };
            if s.peers.iter().any(|(j, q)| j != k && q.link == p.link) {
                v.audit.push(format!("peer {k}: link {} shared", p.link));
            }
            v.bounds.push(("record", p.rekey.recorded(), 64));
            v.peers.push(PeerView {
                peer: Node(*k),
                cur: p.rekey.cur,
                origin: p.origin,
                link: l.hs,
                dir: l.dir,
                at: l.remote,
                current: p.current,
                answered: p.answered,
                pending: p.rekey.pending(),
                rekey: p.rekey.rekey(),
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
