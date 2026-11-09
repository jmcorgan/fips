//! The one-node driver: one settlement core, and the real rekey machine and
//! path bundle of the peer it holds, fed a reference-model history event by
//! event.
//!
//! [`Drive`] faces one peer identity, as one model `Judge` does, on the stub
//! IK profile, at the multipath setting it is built with. It maps each
//! `history::Event` to what the node does: a msg1, written as that peer
//! writes it from the handshake's name (`joint/names.rs`), to `Msg1`, with
//! `Sent` or `SendFailed` after an answer by the event's `sent`; a msg2 to
//! `Msg2`; a frame, sealed as the peer seals it under the session it names,
//! to the machine, the bundle and `Heard`; an own dial's timeout to
//! `ConnectFailed`; a lost peer to `Dead`. A same-epoch msg1 goes to the
//! [`Machines`] with the core's arrival, and what they ask of the core comes
//! back by the joint world's routing (`joint/route.rs`), so a replacement
//! request is `Replace` and a restart report `Restarted`. An own rekey starts
//! through the machine's trigger, so it starts only where the node's would,
//! and its msg2 and cutover are the machine's: each is what the machine did,
//! not what the history says it should. Each step comes back as a [`Did`], in
//! the model `Step`'s fields: the class, a refusal, the reply, the peer
//! change, the connections closed and whether the peering is heard
//! afterwards. Closes on a connectionless binding, and of a connection
//! already closed, are dropped, as the shell drops them. Its rekey machines'
//! own triggers are quieted, since a history says when a rekey starts.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use crate::identity::NodeAddr;
use crate::proto::rekey::tests::stub::{Hs as Attempt, Ik, Kid, kid, read_msg1};
use crate::proto::rekey::{
    self, Completed, Profile, Record, RecordStore, Role as Side, Wire, allocate,
};
use crate::proto::settle::gates::{Refusal as Gated, Source};
use crate::proto::settle::input::{Dial, Input};
use crate::proto::settle::links::{LinkNo, Pair, Proven};
use crate::proto::settle::model::history::{Addr, Binding, Bytes, Epoch, Event, Hs, Ms, Node};
use crate::proto::settle::model::judge::{Class, Gate, Reply, Transition as M};
use crate::proto::settle::output::{Build, Denial, Install, Output, Transition, Why};
use crate::proto::settle::params::Params;
use crate::proto::settle::table::Table;
use crate::testutil::TestInstant;
use crate::transport::{TransportAddr, TransportId};

use super::joint::Mode;
use super::joint::facts::Transports;
use super::joint::machines::{Event as Ev, Kit, Machines, Setup};
use super::joint::names;
use super::joint::party::BEAT;
use super::joint::route::{self, Built, Ctx, Routed, Send, route};
use super::shadow::Refusal;
use super::world::Kind;

/// The pair of model address `a`.
pub fn pair(a: Addr) -> Pair {
    Pair {
        transport: TransportId::new(u32::from(a.transport)),
        addr: TransportAddr::from_string(&format!("10.0.0.1:{}", a.at)),
    }
}

/// The wire epoch of model epoch `e`.
pub fn epoch(e: Epoch) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&e.0.to_be_bytes());
    b
}

/// The model address of pair `p`, the inverse of [`pair`].
pub fn addr(p: &Pair) -> Addr {
    let at = p
        .addr
        .as_str()
        .and_then(|s| s.rsplit(':').next())
        .and_then(|s| s.parse().ok())
        .expect("a pair made by `pair`");
    Addr {
        transport: p.transport.as_u32() as u8,
        at,
    }
}

/// What the driver did with one event, in the model's step fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Did {
    /// The msg1's class.
    pub class: Option<Class>,
    /// A refusal.
    pub refused: Option<Refusal>,
    /// The reply.
    pub reply: Option<Reply>,
    /// The peer change.
    pub change: Option<M>,
    /// The connections closed.
    pub closes: Vec<Addr>,
    /// Whether the peering is heard afterwards.
    pub heard: bool,
}

/// A handshake the core runs on one of its links.
struct Run {
    hs: Hs,
    link: LinkNo,
    /// The msg1 on the wire.
    msg1: Wire,
    /// This node's handshake state, for a dial.
    state: Option<Attempt>,
    /// The completed handshake, until an install takes it.
    done: Option<Completed<Ik>>,
    /// The setup record a responder notes at its install.
    record: Option<Record>,
}

/// What the peer seals a session's frames from: the messages of the
/// handshake that made it, and this node's index for it.
struct Exchange {
    hs: Hs,
    msg1: Wire,
    msg2: Wire,
    ours: u32,
    /// The side the peer took.
    sealer: Side,
    /// The next counter the peer seals at.
    counter: u64,
}

/// The sender's index in a handshake message: the four bytes after its
/// type, in both of the stub IK's messages.
fn sender(msg: &[u8]) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&msg[1..5]);
    u32::from_le_bytes(b)
}

/// This node's own address on the transport of the peer's pair `a`, which
/// the world behind a history never reads.
fn home(a: Addr) -> Addr {
    Addr {
        transport: a.transport,
        at: 0,
    }
}

/// One node's core and the machines of the peer it holds.
pub struct Drive {
    me: Node,
    peer: Node,
    mode: Mode,
    now: Ms,
    /// How many times this node has restarted.
    life: u32,
    table: Table<TestInstant>,
    machines: Option<Machines>,
    /// The link the peer was installed or moved onto.
    link: Option<LinkNo>,
    /// The node's capabilities its machines borrow.
    kit: Kit,
    /// The replay records of closed links.
    store: RecordStore,
    /// Handshake names and the sessions they made.
    names: names::Names,
    /// Which peer each bound index routes to.
    bound: BTreeMap<u32, u8>,
    runs: Vec<Run>,
    exchanges: Vec<Exchange>,
    /// This node's own rekey msg1: its name and its bytes.
    own: Option<(Hs, Wire)>,
    /// Each address seen, and its binding.
    addrs: Vec<(Addr, Binding)>,
    closed: Vec<Addr>,
}

/// The node's record store, as a joint node sizes it.
fn store() -> RecordStore {
    RecordStore::new(256)
}

impl Drive {
    /// Node `me` facing `peer`, at time 0, with multipath setting `mode`.
    pub fn new(me: Node, peer: Node, mode: Mode) -> Self {
        Self {
            me,
            peer,
            mode,
            now: 0,
            life: 0,
            table: Table::new(names::addr(me), Params::default()),
            machines: None,
            link: None,
            kit: Kit::new(me, Epoch(0), &BTreeMap::new()),
            store: store(),
            names: names::Names::default(),
            bound: BTreeMap::new(),
            runs: Vec::new(),
            exchanges: Vec::new(),
            own: None,
            addrs: Vec::new(),
            closed: Vec::new(),
        }
    }

    fn key(&self) -> NodeAddr {
        names::addr(self.peer)
    }

    fn core(&mut self, input: Input) -> Vec<Output> {
        self.table.step(input, TestInstant(self.now))
    }

    fn saw(&mut self, a: Addr, b: Binding) {
        if !self.addrs.iter().any(|(x, _)| *x == a) {
            self.addrs.push((a, b));
            let kinds = self
                .addrs
                .iter()
                .map(|(x, b)| {
                    let kind = match b {
                        Binding::Connected => Kind::Stream,
                        Binding::Connectionless => Kind::Datagram,
                    };
                    (x.transport, kind)
                })
                .collect();
            self.kit.facts = Transports::new(&kinds);
        }
    }

    fn opened(&self, hs: Hs) -> Option<LinkNo> {
        self.runs.iter().rev().find(|r| r.hs == hs).map(|r| r.link)
    }

    /// Take one event.
    pub fn step(&mut self, ev: Event) -> Did {
        let mut did = Did::default();
        match ev {
            Event::Advance(ms) => self.now += ms,
            Event::Dial {
                hs, to, binding, ..
            } => {
                self.saw(to, binding);
                self.dial(hs, to, &mut did);
            }
            Event::Msg1 {
                hs,
                bytes: b,
                epoch: e,
                from,
                binding,
                sent,
                ..
            } => {
                self.saw(from, binding);
                self.msg1(hs, b, e, from, sent, &mut did);
            }
            Event::Msg2Sent { hs } => {
                if let Some(link) = self.opened(hs) {
                    let out = self.core(Input::Sent { link });
                    self.effects(out, &mut did);
                    did.reply = Some(Reply::Stored);
                }
            }
            Event::Msg2 { hs, epoch: e, from } => self.msg2(hs, e, from, &mut did),
            Event::Timeout { hs } => {
                if let Some(link) = self.opened(hs) {
                    let out = self.core(Input::ConnectFailed { link });
                    self.effects(out, &mut did);
                }
            }
            Event::Frame { hs, from } => self.frame(hs, from, &mut did),
            Event::RekeyStart { hs } => self.start(hs, &mut did),
            Event::RekeyMsg2 { hs, epoch: e } => self.reply(hs, e, &mut did),
            Event::RekeyCutover => self.cutover(&mut did),
            Event::Close { at } => self.closed.push(at),
            Event::Lost => {
                let peer = self.key();
                let out = self.core(Input::Dead { peer });
                self.effects(out, &mut did);
            }
            Event::Restart => self.restart(),
        }
        did.heard = self.table.held(&self.key()).is_some_and(|h| h.heard);
        did
    }

    /// The node's process restarts: everything but the world's connections
    /// is forgotten.
    fn restart(&mut self) {
        let out = self.table.close(TestInstant(self.now));
        self.effects(out, &mut Did::default());
        self.close(rekey::Close::Shutdown);
        self.life += 1;
        self.table = Table::new(names::addr(self.me), Params::default());
        self.kit = Kit::new(self.me, Epoch(self.life), &BTreeMap::new());
        for (a, b) in core::mem::take(&mut self.addrs) {
            self.saw(a, b);
        }
        self.store = store();
        self.names = names::Names::default();
        self.bound.clear();
        self.runs.clear();
        self.exchanges.clear();
        self.own = None;
        self.link = None;
    }

    /// Close the peer's machines, if any are held, and file their record.
    fn close(&mut self, why: rekey::Close) {
        let Some(m) = self.machines.take() else {
            return;
        };
        let (events, carry) = m.close(&mut self.kit, self.now, why);
        for e in events {
            if let Ev::Rekey(rekey::Output::Unbind { index, .. }) = e {
                self.bound.remove(&index);
            }
        }
        if let Some(c) = carry {
            self.store
                .file(self.key(), c.peer_epoch.unwrap_or_default(), c.record);
        }
        self.own = None;
    }

    /// An own dial of the peer at `to`.
    fn dial(&mut self, hs: Hs, to: Addr, did: &mut Did) {
        let lease = allocate(&mut self.kit.pool).expect("the node's pool has an index");
        self.kit.local.name(names::opener(hs));
        let (state, msg1) =
            Ik::initiate(&self.kit.local, &names::key(self.peer), Some(lease.index()))
                .expect("the stub IK msg1 always writes");
        let d = Dial {
            peer: self.key(),
            to: pair(to),
            msg1: msg1.clone(),
            lease,
        };
        let out = self.core(Input::Dial(d));
        for o in &out {
            if let Output::Opened { link } = o {
                self.runs.push(Run {
                    hs,
                    link: *link,
                    msg1: msg1.clone(),
                    state: Some(state.clone()),
                    done: None,
                    record: None,
                });
            }
        }
        self.effects(out, did);
    }

    /// The msg2 of an own dial `hs`, written as the peer at epoch `e` writes
    /// it.
    fn msg2(&mut self, hs: Hs, e: Epoch, from: Addr, did: &mut Did) {
        let Some(i) = self.runs.iter().rposition(|r| r.hs == hs) else {
            return;
        };
        let binding = self.bound_at(i);
        self.saw(from, binding);
        let run = &mut self.runs[i];
        let link = run.link;
        let (wire, _) = names::msg2(self.peer, e, hs, &run.msg1, names::index(hs))
            .expect("the msg1 of an own dial reads at the peer");
        let state = run.state.as_ref().expect("a msg2 answers an own dial");
        let read = Ik::reply(state, &self.kit.local, &wire).expect("the peer's msg2 reads");
        let epoch = read.done.epoch;
        let msg1 = run.msg1.clone();
        run.done = Some(read.done);
        self.exchanged(hs, msg1, wire, Side::Responder);
        let out = self.core(Input::Msg2 {
            link,
            epoch,
            from: pair(from),
        });
        self.effects(out, did);
    }

    /// Note the messages of handshake `hs`, which the peer took `sealer` in,
    /// and this node's index for its session: the sender's in this node's
    /// own message of the two.
    fn exchanged(&mut self, hs: Hs, msg1: Wire, msg2: Wire, sealer: Side) {
        let ours = sender(match sealer {
            Side::Initiator => &msg2,
            Side::Responder => &msg1,
        });
        let counter = self
            .exchanges
            .iter()
            .find(|x| x.hs == hs)
            .map_or(0, |x| x.counter);
        self.exchanges.retain(|x| x.hs != hs);
        self.exchanges.push(Exchange {
            hs,
            msg1,
            msg2,
            ours,
            sealer,
            counter,
        });
    }

    /// The binding of run `i`'s link, by its setup address.
    fn bound_at(&self, i: usize) -> Binding {
        let link = self.runs[i].link;
        let setup = self.table.links().get(link).map(|r| r.setup.clone());
        self.addrs
            .iter()
            .find(|(a, _)| Some(pair(*a)) == setup)
            .map_or(Binding::Connectionless, |(_, b)| *b)
    }

    /// Whether the held peer's link is reachable: its active path's
    /// connection is open, or the path is connectionless. A held peer with
    /// no active path is not reachable, as the node's `link_reachable`.
    fn reachable(&self) -> bool {
        if self.table.held(&self.key()).is_none() {
            return true;
        }
        let Some(cur) = self.machines.as_ref().and_then(Machines::active) else {
            return false;
        };
        match self.addrs.iter().find(|(a, _)| *a == cur) {
            Some((a, Binding::Connected)) => !self.closed.contains(a),
            Some((_, Binding::Connectionless)) | None => true,
        }
    }

    /// The session the peer's machine holds pending.
    fn pending(&self) -> Option<Kid> {
        let m = self.machines.as_ref()?;
        m.rekey().peek().pending.map(|e| kid(e.session))
    }

    /// Whether the link and its session are old enough to rekey, as the
    /// machine reads it at a msg1 (`judge_msg1`).
    fn eligible(&self, m: &Machines) -> bool {
        let params = self.mode.rekey();
        let cfg = params.config();
        let ms = |d: crate::time::Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        let v = m.rekey().view();
        self.now.saturating_sub(v.link_since.0) >= ms(cfg.link_age)
            && v.current
                .is_some_and(|c| self.now.saturating_sub(c.started.0) >= ms(cfg.session_age))
    }

    /// Name each session the peer's machine holds that has no name yet,
    /// with `hs`, the handshake the call that made it was about.
    fn named(&mut self, hs: Hs) {
        let Some(m) = self.machines.as_ref() else {
            return;
        };
        let pk = m.rekey().peek();
        for e in [pk.current, pk.pending, pk.previous].into_iter().flatten() {
            let k = kid(e.session);
            if self.names.name(k).is_none() {
                self.names.note(hs, k);
            }
        }
    }

    /// Route `events` of the peer's machines, the bundle's about the link
    /// the peer holds now, or `released` for a path it released at a move.
    fn routed(&mut self, released: Option<LinkNo>, events: Vec<Ev>) -> Routed {
        let link = self.table.held(&self.key()).map(|h| h.link);
        let (peer, key) = (self.peer, self.key());
        let Some(machines) = self.machines.as_ref() else {
            return Routed::default();
        };
        let r = route(
            events,
            Ctx {
                peer,
                key,
                link,
                released,
                machines,
                bound: &mut self.bound,
            },
        );
        assert!(
            r.broken.is_empty(),
            "the machines broke a promise: {:?}",
            r.broken
        );
        r
    }

    /// Step the core with each of `inputs`, carrying out what it asks.
    fn inputs(&mut self, inputs: Vec<Input>, did: &mut Did) {
        for i in inputs {
            let out = self.core(i);
            self.effects(out, did);
        }
    }

    /// A msg1's route through the machine: its class and reply, then what
    /// the machine asks of the core. True when the machine asked for a
    /// replacement, which goes through the gates next.
    fn rekeyed(&mut self, hs: Hs, wire: &[u8], arrival: rekey::Arrival, did: &mut Did) -> bool {
        let before = self.pending();
        let now = self.now;
        let Some(m) = self.machines.as_mut() else {
            return false;
        };
        let events = m.msg1(&mut self.kit, now, hs, wire, arrival);
        let eligible = self.machines.as_ref().is_some_and(|m| self.eligible(m));
        self.named(hs);
        let r = self.routed(None, events);
        let after = self.pending();
        did.class = route::class(&r, before, after, eligible)
            .unwrap_or_else(|why| panic!("a msg1 refused {why:?}"));
        let replace = r.replace.is_some();
        if !replace {
            let answered = r.sends.iter().find_map(|s| match s {
                Send::Msg2 { msg, .. } => Some(msg.clone()),
                Send::Msg1(_) | Send::Prompt { .. } | Send::Path { .. } | Send::Connect { .. } => {
                    None
                }
            });
            did.reply = Some(match (&answered, did.class) {
                (None, _) => Reply::Silent,
                (Some(_), Some(Class::Resend | Class::Pending)) => Reply::Stored,
                (Some(_), _) => Reply::Msg2,
            });
            if let Some(msg2) = answered {
                self.exchanged(hs, wire.to_vec(), msg2, Side::Initiator);
            }
        }
        self.inputs(r.inputs, did);
        replace
    }

    fn msg1(&mut self, hs: Hs, b: Bytes, e: Epoch, from: Addr, sent: bool, did: &mut Did) {
        // A copy with a rewritten header differs only in the sender's index,
        // which the msg1's tag does not cover, so a history's exact bytes are
        // that index.
        let wire = names::msg1(self.peer, e, self.me, hs, b.0);
        let tok = read_msg1(&self.kit.local, &wire).expect("a msg1 to this node reads");
        let (hello, mut built) = route::answer(&mut self.kit, tok.get(), hs, &wire, from);
        let reachable = self.reachable();
        let mut out = self.core(Input::Msg1 { hello, reachable });
        let arrival = out.iter().find_map(|o| {
            if let Output::Rekey { arrival, .. } = o {
                Some(*arrival)
            } else {
                None
            }
        });
        if let Some(arrival) = arrival {
            self.effects(out, did);
            if !self.rekeyed(hs, &wire, arrival, did) {
                return;
            }
            let (hello, again) = route::answer(&mut self.kit, tok.get(), hs, &wire, from);
            built = again;
            out = self.core(Input::Replace(hello));
        }
        self.admitted(out, hs, &wire, built, sent, did);
    }

    /// The outputs of an admission: a stored answer, a refusal, or a fresh
    /// answer sent at once or not.
    fn admitted(
        &mut self,
        out: Vec<Output>,
        hs: Hs,
        wire: &[u8],
        built: Built,
        sent: bool,
        did: &mut Did,
    ) {
        let mut fresh = None;
        for o in &out {
            match o {
                Output::Answer { stored: true, .. } => did.reply = Some(Reply::Stored),
                Output::Answer {
                    link,
                    stored: false,
                    msg2,
                } => fresh = Some((*link, msg2.clone())),
                Output::Reject { source, why, .. } => {
                    did.reply = Some(Reply::Silent);
                    did.refused = Some(refusal(*why));
                    if did.class.is_none() {
                        did.class = source.and_then(class);
                    }
                }
                Output::Remove { why, .. } if did.class.is_none() => {
                    did.class = Some(if *why == Why::Restart {
                        Class::Restart
                    } else {
                        Class::Replacement
                    });
                }
                Output::Opened { .. }
                | Output::Resend { .. }
                | Output::Rekey { .. }
                | Output::Install(_)
                | Output::Reset { .. }
                | Output::Remove { .. }
                | Output::Retire { .. }
                | Output::Release { .. }
                | Output::Close { .. }
                | Output::Free { .. }
                | Output::Retry { .. }
                | Output::Hold { .. }
                | Output::Settle { .. } => {}
            }
        }
        self.effects(out, did);
        let Some((link, msg2)) = fresh else {
            return;
        };
        if did.class.is_none() {
            did.class = Some(Class::NotHeld);
        }
        let (done, record, _) = built;
        self.runs.push(Run {
            hs,
            link,
            msg1: wire.to_vec(),
            state: None,
            done: Some(done),
            record: Some(record),
        });
        self.exchanged(hs, wire.to_vec(), msg2, Side::Initiator);
        let (input, reply) = if sent {
            (Input::Sent { link }, Reply::Msg2)
        } else {
            (Input::SendFailed { link }, Reply::Deferred)
        };
        did.reply = Some(reply);
        let out = self.core(input);
        self.effects(out, did);
    }

    /// A frame of the peer under the session of `hs`, if the machine holds
    /// it: sealed as the peer seals it, opened by the machine, accounted to
    /// the bundle and heard by the core from `from`; a one-path roam and a
    /// cutover it caused go to the core after.
    fn frame(&mut self, hs: Hs, from: Addr, did: &mut Did) {
        let now = self.now;
        let Some(wire) = self.sealed(hs) else {
            return;
        };
        let Some(m) = self.machines.as_mut() else {
            return;
        };
        let (opened, buf) = m.frame(&mut self.kit, now, &wire);
        let r = self.routed(None, opened);
        let range = r.delivered.clone().unwrap_or_else(|| {
            panic!("a frame under {hs:?}, which is held, opens: {:?}", r.reject)
        });
        let kind = buf.get(range.start).copied().unwrap_or(0);
        let Some(m) = self.machines.as_mut() else {
            return;
        };
        let (roamed, _) = m.account(&mut self.kit, now, from, home(from), wire.len(), kind);
        let peer = self.key();
        let out = self.core(Input::Heard {
            peer,
            from: pair(from),
        });
        self.effects(out, did);
        let moved = self.routed(None, roamed);
        self.inputs(moved.inputs, did);
        self.applied(r, did);
    }

    /// The peer's next frame under the session of `hs`, if the machine
    /// holds it, with the key-epoch bit that session's frames carry: the
    /// current or the previous epoch's, or the other for a pending one, which
    /// the peer has cut over to.
    fn sealed(&mut self, hs: Hs) -> Option<Wire> {
        let want = self.names.kid(hs)?;
        let m = self.machines.as_ref()?;
        let (pk, v) = (m.rekey().peek(), m.rekey().view());
        let held = |s: Option<Kid>| s == Some(want);
        let cur = v.current.as_ref().map(|e| e.k);
        let k = if held(pk.current.map(|e| kid(e.session))) {
            cur?
        } else if held(pk.previous.map(|e| kid(e.session))) {
            v.previous.as_ref()?.k
        } else if held(pk.pending.map(|e| kid(e.session))) {
            !cur?
        } else {
            return None;
        };
        let x = self.exchanges.iter_mut().find(|x| x.hs == hs)?;
        let counter = x.counter;
        x.counter += 1;
        Some(names::frame(
            x.sealer,
            (&x.msg1, &x.msg2),
            x.ours,
            counter,
            k,
            BEAT,
        ))
    }

    /// An own rekey `hs`, through the machine's time trigger, which every
    /// other start condition still decides.
    fn start(&mut self, hs: Hs, did: &mut Did) {
        let now = self.now;
        let Some(m) = self.machines.as_mut() else {
            return;
        };
        let events = m.trigger(&mut self.kit, now, hs);
        self.named(hs);
        let r = self.routed(None, events);
        for s in &r.sends {
            if let Send::Msg1(msg) = s {
                self.own = Some((hs, msg.clone()));
            }
        }
        self.applied(r, did);
    }

    /// The msg2 of this node's own rekey `hs`, written as the peer at epoch
    /// `e` writes it; nothing when it answers nothing in flight.
    fn reply(&mut self, hs: Hs, e: Epoch, did: &mut Did) {
        let now = self.now;
        let Some(msg1) = self
            .own
            .as_ref()
            .filter(|(h, _)| *h == hs)
            .map(|(_, m)| m.clone())
        else {
            return;
        };
        let Some((wire, _)) = names::msg2(self.peer, e, hs, &msg1, names::index(hs)) else {
            return;
        };
        let Some(m) = self.machines.as_mut() else {
            return;
        };
        let events = m.reply(&mut self.kit, now, &wire);
        self.named(hs);
        self.exchanged(hs, msg1, wire, Side::Responder);
        let r = self.routed(None, events);
        self.applied(r, did);
    }

    /// The machine's own answered rekey cuts over: a poll at the instant its
    /// proof came.
    fn cutover(&mut self, did: &mut Did) {
        let now = self.now;
        let Some(m) = self.machines.as_mut() else {
            return;
        };
        // Quieted, the poll starts no rekey, so its name goes unused.
        let events = m.poll(&mut self.kit, now, Hs(u32::MAX));
        let r = self.routed(None, events);
        self.applied(r, did);
    }

    /// A frame's or a poll's routed events: a cutover is the driver's change
    /// unless the core names another (a restart revealed).
    fn applied(&mut self, r: Routed, did: &mut Did) {
        if r.cut {
            did.change = Some(M::RekeyCutover);
        }
        self.inputs(r.inputs, did);
    }

    /// Carry out the outputs: give back leases, build or close the machines,
    /// and record the change and the closes.
    fn effects(&mut self, out: Vec<Output>, did: &mut Did) {
        let reset = out.iter().rev().find_map(|o| {
            if let Output::Reset { transition, .. } = o {
                Some(*transition)
            } else {
                None
            }
        });
        let mut removed = false;
        for o in out {
            match o {
                Output::Free { lease } => self.kit.pool.free(lease.release()),
                Output::Install(i) => self.install(i, did),
                Output::Remove { .. } => {
                    removed = true;
                    self.close(rekey::Close::Admin);
                }
                Output::Retire { closes, .. }
                | Output::Release { closes, .. }
                | Output::Close { closes } => {
                    for p in closes {
                        self.closing(&p, did);
                    }
                }
                Output::Opened { .. }
                | Output::Answer { .. }
                | Output::Resend { .. }
                | Output::Rekey { .. }
                | Output::Reset { .. }
                | Output::Retry { .. }
                | Output::Reject { .. }
                | Output::Hold { .. }
                | Output::Settle { .. } => {}
            }
        }
        if let Some(t) = reset {
            did.change = Some(change(t));
        } else if removed && did.change.is_none() {
            did.change = Some(M::Remove);
        }
    }

    /// A close of `p`, as the shell makes it: only on a binding that holds
    /// a connection, and only once.
    fn closing(&mut self, p: &Pair, did: &mut Did) {
        let Some((a, b)) = self.addrs.iter().find(|(a, _)| pair(*a) == *p).copied() else {
            return;
        };
        if b == Binding::Connected && !self.closed.contains(&a) {
            self.closed.push(a);
            did.closes.push(a);
        }
    }

    /// The core installed the peer: build its machines on the completed
    /// handshake, or move them onto it.
    fn install(&mut self, i: Install, did: &mut Did) {
        let now = self.now;
        let run = self
            .runs
            .iter_mut()
            .rev()
            .find(|r| r.link == i.link)
            .expect("an install is on a link a handshake opened");
        let hs = run.hs;
        let noted = run.record.take();
        let done = run
            .done
            .take()
            .expect("an install takes a finished handshake");
        let (epoch, theirs) = (done.epoch, done.theirs.unwrap_or(0));
        let to = addr(&i.pair);
        let setup = Setup {
            done,
            lease: i.lease,
            theirs,
        };
        let old = self.machines.take();
        let moved = matches!((i.rekey, &old), (Build::FromCarry, Some(_)));
        let (mut m, events) = match (i.rekey, old) {
            (Build::FromCarry, Some(old)) => old.moved(&mut self.kit, now, setup, to, home(to)),
            (rebuilt, old) => {
                assert!(
                    old.is_none(),
                    "a {rebuilt:?} install over machines no removal closed"
                );
                let filed = self.store.take(&self.key(), epoch);
                let record = match noted {
                    Some(mut r) => {
                        r.absorb(filed);
                        r
                    }
                    None => filed,
                };
                Machines::fresh(
                    &mut self.kit,
                    now,
                    self.peer,
                    self.mode,
                    setup,
                    record,
                    to,
                    home(to),
                )
            }
        };
        m.quiet();
        self.machines = Some(m);
        let off = self.link.filter(|_| moved);
        self.link = Some(i.link);
        self.own = None;
        self.named(hs);
        let r = self.routed(off, events);
        let mut inputs = r.inputs;
        if !moved {
            // A new bundle reports nothing: its original path is Live.
            inputs.push(Input::State {
                link: i.link,
                pair: i.pair,
                proven: Proven::Live,
            });
        }
        self.inputs(inputs, did);
    }
}

impl Drop for Drive {
    fn drop(&mut self) {
        let out = self.table.close(TestInstant(self.now));
        route::discard(&mut self.kit, out);
        self.close(rekey::Close::Shutdown);
    }
}

/// The model's name for the core's transition `t`.
pub fn change(t: Transition) -> M {
    match t {
        Transition::Promote => M::Promote,
        Transition::Replace => M::Replace,
        Transition::Move => M::Move,
        Transition::Keep => M::Keep,
        Transition::Restarted => M::Restarted,
        Transition::Roam => M::Roam,
    }
}

/// The model's class for the gate source `s`, where it has one.
pub fn class(s: Source) -> Option<Class> {
    match s {
        Source::NotHeld => Some(Class::NotHeld),
        Source::Restart => Some(Class::Restart),
        Source::Replacement => Some(Class::Replacement),
        Source::OwnMsg2 | Source::RekeyMsg2 => None,
    }
}

/// The shadow's refusal for the core's denial `d`.
pub fn refusal(d: Denial) -> Refusal {
    match d {
        Denial::Gate(Gated::Unheard) => Refusal::Gate(Gate::Unheard),
        Denial::Gate(Gated::Heard) => Refusal::Gate(Gate::Heard),
        Denial::Gate(Gated::Dampened) => Refusal::Gate(Gate::Dampened),
        Denial::Gate(Gated::Replayed | Gated::ReplayFull) => Refusal::Replay,
        Denial::Gate(Gated::Silent) => Refusal::Silent,
        Denial::Full => Refusal::Full,
    }
}
