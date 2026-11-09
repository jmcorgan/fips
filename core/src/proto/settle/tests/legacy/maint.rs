//! A model of the deployed node's settlement, transcribed from `maint` at
//! `9fc10516` (the line ranges are in this directory's README).
//!
//! `maint` has no rekey machine: its rekey rules are inline in
//! `establish_inbound`'s same-epoch arm and in `ActivePeer`'s pending slot,
//! so this file transcribes them as [`Rekey`]. Beside that, [`MaintParty`]
//! decides as the deployed node does: the duplicate-msg1 short circuit,
//! `establish_inbound`'s classification, the restart and replacement gates
//! with the replay memory (the same as `master`'s), the inbound promotion,
//! whose failed msg2 send leaves nothing behind, and `establish_outbound`,
//! which swaps a held peer onto this node's dial by the address tie-break
//! alone, whatever the msg2's epoch and whoever dialed the held link. A
//! swap replaces the session and keeps the peer's link and address, as
//! `replace_session` does.
//!
//! Where `maint` and `master` decide alike, the code is `master.rs`'s with
//! the line references changed; the differences are listed in the README.
//! It logs every history event it sees and what it did, as `master.rs`
//! does, so the oracles compare it with the reference model step by step.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::super::model::history::{Addr, Bytes, Epoch, Event, Hs, LinkId, Node};
use super::super::super::model::judge::{Class, Gate, Transition};
use super::super::party::{Configured, binding};
use super::super::rekeyside::{Answer, Out};
use super::super::shadow::{Entry, Rec, Refusal};
use super::super::world::{
    CHECK, Dir, HANDSHAKE, HEARTBEAT, Input, Kind, Ms, Net, Party, PeerView, Pkt, RESEND, RESENDS,
    RETRY, View,
};

/// `EPOCH_RESTART_MIN_INTERVAL_SECS` (`handshake.rs:52`), in ms.
const INTERVAL: Ms = 15_000;
/// `UNHEARD_PEERING_MIN_AGE_MS` (`handshake.rs:73`).
const UNHEARD: i64 = 1_000;
/// `MAX_REPLAYED_MSG1S` (`handshake.rs:91`).
const REPLAYS: usize = 8;
/// `REKEY_MIN_LINK_AGE_SECS` (`fmp/core.rs:627`), in ms.
const LINKAGE: Ms = 30_000;
/// `REKEY_MIN_CUTOVER_AGE_SECS`, the drain window (`fsp/limits.rs:9`).
const SESSIONAGE: Ms = 10_000;
/// `pending_hold` (`rekey.rs:133`) at stock settings: the drain ceiling,
/// 120 s, above the 64 s link silence.
const HOLD: Ms = 120_000;
/// `DRAIN_WINDOW_SECS` (`rekey.rs:27`).
const DRAIN: Ms = 10_000;
/// `ENDED_MSG1_RECORD` (`fmp/core.rs:184`).
const ENDED: usize = 256;

/// Where a peer's rekey stands: `rekey_in_progress` and the pending slot
/// with its role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cycle {
    /// No rekey in flight and no pending.
    Idle,
    /// This node's own rekey msg1 is out (`set_rekey_state`).
    Init { hs: Hs, next: Ms, resends: u32 },
    /// This node answered the peer's rekey (`answer_rekey`): the pending
    /// and the msg1 that armed it, held from `since`.
    PendR { hs: Hs, armed: Bytes, since: Ms },
    /// This node's own rekey was answered (`set_pending_session`); the
    /// tick cuts over at `at`.
    PendI {
        hs: Hs,
        restarted: Option<Epoch>,
        at: Ms,
    },
}

/// One peer's rekey state on `maint`: the session slots of `ActivePeer`,
/// its answered record (`AnsweredMsg1s`), and the same-epoch arm of
/// `establish_inbound` that judges a msg1 against them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rekey {
    me: Node,
    peer: Node,
    /// The current session.
    pub cur: Hs,
    /// The peer's epoch on record.
    pub epoch: Epoch,
    /// `link_established_at`.
    link_since: Ms,
    /// `session_established_at`.
    started: Ms,
    /// The link-setup msg1 this peering was promoted from, and the session
    /// its stored msg2 answers, for a responder (`note_setup`).
    setup: Option<(Bytes, Hs)>,
    /// The ended list: the setup msg1 and every armed msg1 whose pending
    /// has left.
    ended: Vec<Bytes>,
    cycle: Cycle,
    /// The previous session and when its drain ends.
    drain: Option<(Hs, Ms)>,
}

impl Rekey {
    /// The state of a peering set up at `now` by handshake `hs`, the peer
    /// at `epoch`; `setup` is the msg1 this node answered, for a
    /// responder.
    pub fn new(me: Node, peer: Node, hs: Hs, epoch: Epoch, now: Ms, setup: Option<Bytes>) -> Self {
        Self {
            me,
            peer,
            cur: hs,
            epoch,
            link_since: now,
            started: now,
            setup: setup.map(|b| (b, hs)),
            ended: setup.into_iter().collect(),
            cycle: Cycle::Idle,
            drain: None,
        }
    }

    /// `replace_session` at a cross-connection swap: only the session
    /// changes; its age, the link's age, the pending slot and the record
    /// stay.
    fn swapped(&mut self, hs: Hs) {
        self.cur = hs;
    }

    /// Whether frames under `hs` open: the current, the pending and the
    /// previous session.
    pub fn holds(&self, hs: Hs) -> bool {
        self.cur == hs
            || self.pending().is_some_and(|(p, _)| p == hs)
            || self.drain.is_some_and(|(d, _)| d == hs)
    }

    /// Whether `hs` is the previous session, still draining.
    fn draining(&self, hs: Hs) -> bool {
        self.drain.is_some_and(|(d, _)| d == hs)
    }

    /// The pending session and whether this node started it.
    pub fn pending(&self) -> Option<(Hs, bool)> {
        match self.cycle {
            Cycle::PendR { hs, .. } => Some((hs, false)),
            Cycle::PendI { hs, .. } => Some((hs, true)),
            Cycle::Idle | Cycle::Init { .. } => None,
        }
    }

    /// This node's own rekey in flight, unanswered.
    pub fn rekey(&self) -> Option<Hs> {
        match self.cycle {
            Cycle::Init { hs, .. } => Some(hs),
            Cycle::Idle | Cycle::PendR { .. } | Cycle::PendI { .. } => None,
        }
    }

    /// Neither a rekey in progress nor a pending held, which `poll_rekey`
    /// requires before it triggers one.
    pub fn idle(&self) -> bool {
        self.cycle == Cycle::Idle
    }

    /// The link and session age floors of `establish_inbound`'s rekey arm.
    pub fn eligible(&self, now: Ms) -> bool {
        now.saturating_sub(self.link_since) >= LINKAGE
            && now.saturating_sub(self.started) >= SESSIONAGE
    }

    /// `establish_inbound`'s same-epoch arm (`fmp/core.rs:827-948`): a
    /// msg1 of `bytes` from the held peer, its class and the answer.
    /// `on_link` and `reachable` are `msg1_on_link` and `link_reachable`;
    /// `answerable` is whether `answer_msg1` can send, since a rekey
    /// answer that cannot be sent arms nothing.
    pub fn msg1(
        &mut self,
        now: Ms,
        hs: Hs,
        bytes: Bytes,
        on_link: bool,
        reachable: bool,
        answerable: bool,
    ) -> (Class, Answer) {
        let ended = self.ended.contains(&bytes);
        if !self.eligible(now) {
            if let Some((b, setup)) = self.setup
                && b == bytes
            {
                return (Class::Resend, Answer::Stored(setup));
            }
            if ended {
                return (Class::Copy, Answer::Silent);
            }
            return (Class::Replacement, Answer::Replace);
        }
        if !on_link && reachable {
            return (Class::OffLink, Answer::Silent);
        }
        match self.cycle {
            Cycle::PendR { hs: h, armed, .. } if armed == bytes => {
                return (Class::Pending, Answer::Stored(h));
            }
            Cycle::PendR { .. } | Cycle::PendI { .. } => return (Class::Pending, Answer::Silent),
            Cycle::Idle | Cycle::Init { .. } => {}
        }
        if ended {
            return (Class::Recorded, Answer::Silent);
        }
        if let Cycle::Init { .. } = self.cycle {
            // Dual initiation: the smaller node keeps its own; the larger
            // abandons its own first, then answers.
            if self.me < self.peer {
                return (Class::Simultaneous, Answer::Silent);
            }
            self.cycle = Cycle::Idle;
            return (
                Class::Simultaneous,
                self.respond(now, hs, bytes, answerable),
            );
        }
        (Class::Rekey, self.respond(now, hs, bytes, answerable))
    }

    /// The `RekeyRespond` arm (`handshake.rs:948-1068`): a drain in
    /// progress is completed, the answer sent, and the pending armed with
    /// it when the send went out.
    fn respond(&mut self, now: Ms, hs: Hs, bytes: Bytes, answerable: bool) -> Answer {
        self.drain = None;
        if !answerable {
            return Answer::Silent;
        }
        self.cycle = Cycle::PendR {
            hs,
            armed: bytes,
            since: now,
        };
        Answer::Msg2(hs)
    }

    /// The pending leaves: an armed msg1 joins the ended list
    /// (`release_pending`, `AnsweredMsg1s::end`).
    fn release(&mut self) {
        if let Cycle::PendR { armed, .. } = self.cycle {
            if self.ended.len() == ENDED {
                self.ended.remove(0);
            }
            self.ended.push(armed);
        }
        self.cycle = Cycle::Idle;
    }

    /// Start this node's own rekey `hs`; false when a cycle runs.
    pub fn start(&mut self, now: Ms, hs: Hs) -> bool {
        if !self.idle() {
            return false;
        }
        self.cycle = Cycle::Init {
            hs,
            next: now + RESEND,
            resends: 0,
        };
        true
    }

    /// The rekey arm of `handle_msg2` (`handshake.rs:1599-1735`): the msg2
    /// of this node's own rekey `hs`, carrying the peer's `epoch`, which is
    /// put on record at once; false when it answers nothing in flight.
    pub fn msg2(&mut self, now: Ms, hs: Hs, epoch: Epoch) -> bool {
        if self.rekey() != Some(hs) {
            return false;
        }
        let restarted = (epoch != self.epoch).then_some(epoch);
        self.epoch = epoch;
        self.cycle = Cycle::PendI {
            hs,
            restarted,
            at: now + CHECK,
        };
        true
    }

    /// A frame under `hs` opened (`handle_encrypted_frame`, the pending
    /// trial, `encrypted.rs:100-200`): under the pending session of either
    /// role, `adopt_pending` promotes it.
    pub fn frame(&mut self, now: Ms, hs: Hs) -> Option<Out> {
        match self.cycle {
            Cycle::PendR { hs: p, .. } if p == hs => Some(self.cut(now, hs, false, None)),
            Cycle::PendI {
                hs: p, restarted, ..
            } if p == hs => Some(self.cut(now, hs, true, restarted)),
            Cycle::Idle | Cycle::Init { .. } | Cycle::PendR { .. } | Cycle::PendI { .. } => None,
        }
    }

    /// `cutover_to_new_session` and `handle_peer_kbit_flip`: the current
    /// session drains, the pending becomes current, and a pending whose
    /// msg2 revealed a restart restarts the link's age as it leaves.
    fn cut(&mut self, now: Ms, hs: Hs, initiator: bool, restarted: Option<Epoch>) -> Out {
        self.release();
        self.drain = Some((self.cur, now + DRAIN));
        self.cur = hs;
        self.started = now;
        match restarted {
            Some(epoch) => {
                self.link_since = now;
                Out::Restarted { hs, epoch }
            }
            None => Out::Rekeyed { hs, initiator },
        }
    }

    /// `check_rekey` and the rekey resends (`rekey.rs:148-345`, `:511-540`;
    /// `poll_rekey` and `poll_rekey_resends`, `fmp/core.rs:738`, `:784`): the drain's
    /// end, the own rekey's resends and its abandon once they are spent,
    /// the initiator's cutover at the tick, and a responder pending
    /// retired at its hold.
    pub fn poll(&mut self, now: Ms) -> Vec<Out> {
        let mut out = Vec::new();
        if self.drain.is_some_and(|(_, t)| now >= t) {
            self.drain = None;
        }
        match self.cycle {
            Cycle::Init { next, resends, .. } if now >= next && resends >= RESENDS => {
                self.cycle = Cycle::Idle;
                out.push(Out::Abandoned);
            }
            Cycle::Init { hs, next, resends } if now >= next => {
                self.cycle = Cycle::Init {
                    hs,
                    next: now + (RESEND << (resends + 1)),
                    resends: resends + 1,
                };
                out.push(Out::Send(hs));
            }
            Cycle::PendI { hs, restarted, at } if now >= at => {
                out.push(self.cut(now, hs, true, restarted));
            }
            Cycle::PendR { since, .. } if now >= since + HOLD => {
                self.release();
                out.push(Out::Unadopted);
            }
            Cycle::Idle | Cycle::Init { .. } | Cycle::PendI { .. } | Cycle::PendR { .. } => {}
        }
        out
    }

    /// The earliest instant something is due.
    pub fn wake(&self) -> Option<Ms> {
        let cycle = match self.cycle {
            Cycle::Init { next, .. } => Some(next),
            Cycle::PendR { since, .. } => Some(since + HOLD),
            Cycle::PendI { at, .. } => Some(at),
            Cycle::Idle => None,
        };
        let drain = self.drain.map(|(_, t)| t);
        match (cycle, drain) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// A link record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Link {
    dir: Dir,
    remote: Addr,
    hs: Hs,
}

/// An own dial in flight (its `PeerMachine` and `pending_outbound`).
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
    rekey: Rekey,
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
    dampener: BTreeMap<u8, Ms>,
    replayed: BTreeMap<u8, Vec<(Hs, i64)>>,
    /// Inbound connections whose msg1 left no link, by address, and when
    /// the node gives up on each.
    idle: BTreeMap<(u8, u16), Ms>,
}

/// The deployed node.
pub struct MaintParty {
    s: State,
    log: Vec<Entry>,
}

/// The model of `maint` as a node.
pub fn maint(ix: usize, me: Node, configured: Vec<Configured>) -> alloc::boxed::Box<dyn Party> {
    alloc::boxed::Box::new(MaintParty::new(ix, me, configured))
}

fn key(a: Addr) -> (u8, u16) {
    (a.transport, a.at)
}

impl MaintParty {
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

    /// `remove_link` (`node/mod.rs:2925`): the record and every index
    /// entry naming it.
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
    /// no link there: the world's adapter closes it at the handshake
    /// timeout unless a link has come to use it, as for `master.rs`.
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

    /// `close_handshake_link_connection` (`node/mod.rs:2878-2897`): close a
    /// leg's connection unless `addr_carries_other_peer`.
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

    /// Where `answer_msg1` (`handshake.rs:533-576`) sends a reply to a held
    /// peer's msg1 from `src`: its established link, or the msg1's own
    /// connection when that link's connection is gone and the msg1 came on
    /// the same connection-oriented transport; `None` when neither can.
    fn route(&self, net: &Net, peer: Node, src: Addr) -> Option<Addr> {
        let ix = self.s.ix;
        let cur = self.s.peers.get(&peer.0)?.current;
        let kind = net.kind(cur.transport);
        if kind == Kind::Datagram || net.conn(ix, cur).is_some() {
            Some(cur)
        } else if src.transport == cur.transport && src != cur && net.conn(ix, src).is_some() {
            Some(src)
        } else {
            None
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

    /// A dial ends unanswered: its leg is reaped and the dial goes back on
    /// the retry schedule (`timeout.rs`).
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

    /// `handle_msg1` (`handshake.rs:578-1535`).
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
        // The pre-crypto duplicate short circuit (`:667-716`): an inbound
        // link from this address with no peer on it resends its stored
        // msg2. A failed msg2 send removes the link with its machine, so
        // no such link holds one, and the msg1 is dropped.
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
            self.note(now, id, ev, Rec::default());
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
        // `establish_inbound` (`fmp/core.rs:827-948`).
        let class = match self.s.peers.get(&id.0) {
            None => Class::NotHeld,
            Some(p) if p.rekey.epoch != epoch => Class::Restart,
            Some(p) => {
                // `msg1_on_link` and `link_reachable` (`handshake.rs:220-265`,
                // `:501-520`).
                let on_link = p.current == src || self.s.index.get(&key(src)) == Some(&p.link);
                let cur = p.current;
                let reachable =
                    net.kind(cur.transport) == Kind::Datagram || net.conn(ix, cur).is_some();
                let route = self.route(net, id, src);
                let p = self.s.peers.get_mut(&id.0).expect("held above");
                let (class, answer) =
                    p.rekey
                        .msg1(now, hs, bytes, on_link, reachable, route.is_some());
                let me = self.s.me;
                let mine = self.epoch();
                match answer {
                    Answer::Replace => class,
                    Answer::Msg2(h) | Answer::Stored(h) => {
                        if let Some(to) = route {
                            let pkt = Pkt::Msg2 {
                                id: me,
                                hs: h,
                                epoch: mine,
                                wire: 0,
                            };
                            net.send(ix, None, to, pkt);
                        }
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
            // The replay memory and the gates (`handshake.rs:1069-1225`).
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
            // The old peer's teardown (`remove_active_peer`), run before the
            // msg2 is sent: its link retired, its connection kept.
            let old = self.s.peers.remove(&id.0).expect("held above");
            self.unlink(old.link);
        }
        // The promotion tail: a new inbound link, the msg2, the peer. A
        // failed send removes the link and the machine (the executor's
        // `SendHandshake` arm, `peer_actions.rs:170-215`), so nothing is
        // left to answer a resend.
        let change = if sent {
            let link = self.link(Dir::Inbound, src, hs);
            debug_assert_eq!(link, link_id);
            let pkt = Pkt::Msg2 {
                id: self.s.me,
                hs,
                epoch: self.epoch(),
                wire: 0,
            };
            net.send(ix, None, src, pkt);
            self.install(id, hs, bytes, epoch, link, src, stamp, now);
            Some(if class == Class::NotHeld {
                Transition::Promote
            } else {
                Transition::Replace
            })
        } else {
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

    /// `ReplayedMsg1s::verdict` (`handshake.rs:148-168`): whether a msg1
    /// replacing an unheard peering is refused.
    fn replay(&mut self, id: Node, hs: Hs, stamp: i64) -> bool {
        let Some(seen) = self.s.replayed.get_mut(&id.0) else {
            return false;
        };
        seen.retain(|&(_, at)| stamp - at < INTERVAL as i64);
        seen.iter().any(|(e, _)| *e == hs) || seen.len() >= REPLAYS
    }

    /// The responder's promotion tails (`handshake.rs:1380-1395`, `:1514-1530`): the peer
    /// with its stored msg2 and setup msg1, and `note_unheard_promotion`.
    #[allow(clippy::too_many_arguments)]
    fn install(
        &mut self,
        id: Node,
        hs: Hs,
        bytes: Bytes,
        epoch: Epoch,
        link: u32,
        src: Addr,
        stamp: i64,
        now: Ms,
    ) {
        let rekey = Rekey::new(self.s.me, id, hs, epoch, now, Some(bytes));
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

    /// `handle_msg2` (`handshake.rs:1576-2120`) and `establish_outbound`
    /// (`fmp/core.rs:950-959`).
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
        let me = self.s.me;
        let change = match self.s.peers.get_mut(&id.0) {
            Some(p) => {
                // A cross-connection, whatever the msg2's epoch and whoever
                // dialed the held link: the smaller node swaps onto its
                // dial's session, the larger keeps its own.
                p.answered = true;
                let change = if me < id {
                    p.rekey.swapped(hs);
                    p.origin = hs;
                    Transition::Move
                } else {
                    Transition::Keep
                };
                self.close_leg(net, d.link);
                self.unlink(d.link);
                change
            }
            None => {
                let rekey = Rekey::new(me, id, hs, epoch, now, None);
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

    /// `handle_encrypted_frame` (`encrypted.rs:47-370`): a frame under the
    /// pending session promotes it; any frame that opens, under the
    /// current, pending or previous session, moves the peer's address to
    /// its source and marks the peering heard, and the first one forgets
    /// the replay memory.
    fn frame(&mut self, net: &mut Net, src: Addr, id: Node, hs: Hs, stamp: i64) {
        let now = net.now;
        let Some(p) = self.s.peers.get_mut(&id.0) else {
            return;
        };
        let ev = Event::Frame { hs, from: src };
        let cut = p.rekey.frame(now, hs);
        if cut.is_none() && p.rekey.cur != hs && !p.rekey.draining(hs) {
            self.note(now, id, ev, Rec::default());
            return;
        }
        let first = !p.heard;
        p.heard = true;
        p.last_seen = stamp;
        let roamed = p.current != src;
        p.current = src;
        let change = match cut {
            Some(Out::Restarted { .. }) => Some(Transition::Restarted),
            Some(Out::Send(_) | Out::Rekeyed { .. } | Out::Abandoned | Out::Unadopted) => {
                Some(Transition::RekeyCutover)
            }
            None => roamed.then_some(Transition::Roam),
        };
        if first {
            self.s.replayed.remove(&id.0);
        }
        net.mark(self.s.ix, src, true);
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

impl Party for MaintParty {
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
        let peers = s
            .peers
            .values()
            .flat_map(|p| [p.rekey.wake(), Some(p.beat + HEARTBEAT)]);
        let retry = s.retry.values().chain(s.idle.values()).map(|&t| Some(t));
        dials.chain(peers).chain(retry).flatten().min()
    }

    fn digest(&self) -> String {
        format!("{:?}", self.s)
    }

    fn epoch(&self) -> Epoch {
        MaintParty::epoch(self)
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
            v.bounds.push(("record", p.rekey.ended.len(), ENDED));
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
        v.bounds.push(("peers", s.peers.len(), 8));
        v.bounds.push(("dials", s.dials.len(), 8));
        for seen in s.replayed.values() {
            v.bounds.push(("replay memory", seen.len(), REPLAYS));
        }
        v
    }
}
