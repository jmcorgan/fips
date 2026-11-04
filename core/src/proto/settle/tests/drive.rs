//! The one-node driver: one settlement core, and the rekey side of the
//! peer it holds, fed a reference-model history event by event.
//!
//! [`Drive`] faces one peer identity, as one model `Judge` does. It maps
//! each `history::Event` to the core's inputs (a msg1 to `Msg1`, with
//! `Sent` or `SendFailed` after an answer by the event's `sent`; a msg2 to
//! `Msg2`; a frame to `Heard`; an own dial's timeout to `ConnectFailed`; a
//! lost peer to `Dead`), hands a same-epoch msg1 to the [`RekeySide`] with
//! the core's arrival, and routes that side's replacement request and
//! restart report back to the core as `Replace` and `Restarted`. Each step
//! comes back as a [`Did`], in the model `Step`'s fields: the class, a
//! refusal, the reply, the peer change, the connections closed and whether
//! the peering is heard afterwards. Closes on a connectionless binding,
//! and of a connection already closed, are dropped, as the shell drops
//! them. Every lease the core hands out is released at once, since the
//! driver keeps no sessions.

use alloc::format;
use alloc::vec::Vec;

use crate::identity::NodeAddr;
use crate::proto::fmp::EphemeralDigest;
use crate::proto::rekey::IndexLease;
use crate::proto::settle::gates::{Refusal as Gated, Source};
use crate::proto::settle::input::{Dial, Hello, Input};
use crate::proto::settle::links::{LinkNo, Pair};
use crate::proto::settle::model::history::{Addr, Binding, Bytes, Epoch, Event, Hs, Ms, Node};
use crate::proto::settle::model::judge::{Class, Gate, Reply, Transition as M};
use crate::proto::settle::output::{Denial, Output, Transition, Why};
use crate::proto::settle::params::Params;
use crate::proto::settle::table::Table;
use crate::testutil::TestInstant;
use crate::transport::{TransportAddr, TransportId};

use super::rekeyside::{Answer, Out, RekeySide};
use super::shadow::Refusal;

/// The node address of model node `n`.
pub fn node(n: Node) -> NodeAddr {
    NodeAddr::from_bytes([n.0; 16])
}

/// The pair of model address `a`.
pub fn pair(a: Addr) -> Pair {
    Pair {
        transport: TransportId::new(u32::from(a.transport)),
        addr: TransportAddr::from_string(&format!("10.0.0.1:{}", a.at)),
    }
}

/// The ephemeral digest of handshake `h`.
pub fn eph(h: Hs) -> EphemeralDigest {
    let mut key = [0u8; 33];
    key[..4].copy_from_slice(&h.0.to_be_bytes());
    EphemeralDigest::of_noise_msg1(&key).expect("33 bytes carry an ephemeral")
}

/// The wire epoch of model epoch `e`.
pub fn epoch(e: Epoch) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&e.0.to_be_bytes());
    b
}

fn bytes(b: Bytes) -> Vec<u8> {
    b.0.to_be_bytes().to_vec()
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
#[derive(Clone, Copy, Debug)]
struct Run {
    hs: Hs,
    link: LinkNo,
    /// The msg1's bytes, for an answer.
    bytes: Option<Bytes>,
    /// The epoch its msg1 or msg2 carried.
    epoch: Option<Epoch>,
}

/// One node's core and the rekey side of the peer it holds.
pub struct Drive {
    me: Node,
    peer: Node,
    now: Ms,
    table: Table<TestInstant>,
    side: Option<RekeySide>,
    runs: Vec<Run>,
    /// Each address seen, and its binding.
    addrs: Vec<(Addr, Binding)>,
    closed: Vec<Addr>,
    leases: u32,
}

impl Drive {
    /// Node `me` facing `peer`, at time 0.
    pub fn new(me: Node, peer: Node) -> Self {
        Self {
            me,
            peer,
            now: 0,
            table: Table::new(node(me), Params::default()),
            side: None,
            runs: Vec::new(),
            addrs: Vec::new(),
            closed: Vec::new(),
            leases: 0,
        }
    }

    fn lease(&mut self) -> IndexLease {
        self.leases += 1;
        IndexLease::for_test(self.leases)
    }

    fn core(&mut self, input: Input) -> Vec<Output> {
        self.table.step(input, TestInstant(self.now))
    }

    fn saw(&mut self, a: Addr, b: Binding) {
        if !self.addrs.iter().any(|(x, _)| *x == a) {
            self.addrs.push((a, b));
        }
    }

    fn link(&self, hs: Hs) -> Option<LinkNo> {
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
                let d = Dial {
                    peer: node(self.peer),
                    to: pair(to),
                    msg1: bytes(Bytes(hs.0)),
                    lease: self.lease(),
                };
                let out = self.core(Input::Dial(d));
                for o in &out {
                    if let Output::Opened { link } = o {
                        self.runs.push(Run {
                            hs,
                            link: *link,
                            bytes: None,
                            epoch: None,
                        });
                    }
                }
                self.effects(out, &mut did);
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
                if let Some(link) = self.link(hs) {
                    let out = self.core(Input::Sent { link });
                    self.effects(out, &mut did);
                    did.reply = Some(Reply::Stored);
                }
            }
            Event::Msg2 { hs, epoch: e, from } => {
                if let Some(i) = self.runs.iter().rposition(|r| r.hs == hs) {
                    self.runs[i].epoch = Some(e);
                    let binding = self.binding_of_run(i);
                    self.saw(from, binding);
                    let link = self.runs[i].link;
                    let out = self.core(Input::Msg2 {
                        link,
                        epoch: epoch(e),
                        from: pair(from),
                    });
                    self.effects(out, &mut did);
                }
            }
            Event::Timeout { hs } => {
                if let Some(link) = self.link(hs) {
                    let out = self.core(Input::ConnectFailed { link });
                    self.effects(out, &mut did);
                }
            }
            Event::Frame { hs, from } => self.frame(hs, from, &mut did),
            Event::RekeyStart { hs } => {
                let now = self.now;
                if let Some(s) = self.side.as_mut() {
                    s.start(now, hs);
                }
            }
            Event::RekeyMsg2 { hs, epoch: e } => {
                let now = self.now;
                if let Some(s) = self.side.as_mut() {
                    s.msg2(now, hs, e);
                }
            }
            Event::RekeyCutover => {
                let now = self.now;
                let out = self.side.as_mut().and_then(|s| s.cutover(now));
                self.rekeyed(out, &mut did);
            }
            Event::Close { at } => self.closed.push(at),
            Event::Lost => {
                let out = self.core(Input::Dead {
                    peer: node(self.peer),
                });
                self.effects(out, &mut did);
            }
            Event::Restart => {
                let out = self.table.close(TestInstant(self.now));
                self.effects(out, &mut Did::default());
                self.table = Table::new(node(self.me), Params::default());
                self.side = None;
                self.runs.clear();
            }
        }
        did.heard = self.table.held(&node(self.peer)).is_some_and(|h| h.heard);
        did
    }

    /// The binding of run `i`'s link, by its setup address.
    fn binding_of_run(&self, i: usize) -> Binding {
        let link = self.runs[i].link;
        let setup = self.table.links().get(link).map(|r| r.setup.clone());
        self.addrs
            .iter()
            .find(|(a, _)| Some(pair(*a)) == setup)
            .map_or(Binding::Connectionless, |(_, b)| *b)
    }

    fn hello(&mut self, hs: Hs, b: Bytes, e: Epoch, from: Addr) -> Hello {
        Hello {
            peer: node(self.peer),
            from: pair(from),
            bytes: bytes(b),
            ephemeral: eph(hs),
            epoch: epoch(e),
            msg2: [&[2u8][..], &hs.0.to_be_bytes()].concat(),
            lease: self.lease(),
        }
    }

    /// Whether the held peer's current connection is still open.
    fn reachable(&self) -> bool {
        let Some(h) = self.table.held(&node(self.peer)) else {
            return true;
        };
        match self.addrs.iter().find(|(a, _)| pair(*a) == h.current) {
            Some((a, Binding::Connected)) => !self.closed.contains(a),
            Some((_, Binding::Connectionless)) | None => true,
        }
    }

    fn msg1(&mut self, hs: Hs, b: Bytes, e: Epoch, from: Addr, sent: bool, did: &mut Did) {
        let hello = self.hello(hs, b, e, from);
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
            let now = self.now;
            let Some(side) = self.side.as_mut() else {
                return;
            };
            let (class, answer) = side.msg1(now, hs, b, arrival);
            did.class = Some(class);
            if answer != Answer::Replace {
                did.reply = answer.reply();
                return;
            }
            let hello = self.hello(hs, b, e, from);
            out = self.core(Input::Replace(hello));
        }
        self.admitted(out, hs, b, e, sent, did);
    }

    /// The outputs of an admission: a stored answer, a refusal, or a fresh
    /// answer sent at once or not.
    fn admitted(
        &mut self,
        out: Vec<Output>,
        hs: Hs,
        b: Bytes,
        e: Epoch,
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
                    ..
                } => fresh = Some(*link),
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
                | Output::Retry { .. } => {}
            }
        }
        self.effects(out, did);
        let Some(link) = fresh else {
            return;
        };
        if did.class.is_none() {
            did.class = Some(Class::NotHeld);
        }
        self.runs.push(Run {
            hs,
            link,
            bytes: Some(b),
            epoch: Some(e),
        });
        let (input, reply) = if sent {
            (Input::Sent { link }, Reply::Msg2)
        } else {
            (Input::SendFailed { link }, Reply::Deferred)
        };
        did.reply = Some(reply);
        let out = self.core(input);
        self.effects(out, did);
    }

    fn frame(&mut self, hs: Hs, from: Addr, did: &mut Did) {
        if !self.side.as_ref().is_some_and(|s| s.holds(hs)) {
            return;
        }
        let out = self.core(Input::Heard {
            peer: node(self.peer),
            from: pair(from),
        });
        self.effects(out, did);
        let now = self.now;
        let out = self.side.as_mut().and_then(|s| s.frame(now, hs));
        self.rekeyed(out, did);
    }

    /// The rekey side's cutover: a plain rekey is the driver's change, a
    /// restart revealed goes to the core.
    fn rekeyed(&mut self, out: Option<Out>, did: &mut Did) {
        match out {
            Some(Out::Rekeyed { .. }) => did.change = Some(M::RekeyCutover),
            Some(Out::Restarted { epoch: e, .. }) => {
                let out = self.core(Input::Restarted {
                    peer: node(self.peer),
                    epoch: epoch(e),
                });
                self.effects(out, did);
            }
            Some(Out::Send(_) | Out::Abandoned | Out::Unadopted) | None => {}
        }
    }

    /// Carry out the outputs: release leases, build or drop the rekey
    /// side, and record the change and the closes.
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
                Output::Free { lease } => {
                    lease.release();
                }
                Output::Install(i) => {
                    i.lease.release();
                    self.installed(i.link, reset);
                }
                Output::Remove { .. } => {
                    removed = true;
                    self.side = None;
                }
                Output::Retire { closes, .. }
                | Output::Release { closes, .. }
                | Output::Close { closes } => {
                    for p in closes {
                        self.close(&p, did);
                    }
                }
                Output::Opened { .. }
                | Output::Answer { .. }
                | Output::Resend { .. }
                | Output::Rekey { .. }
                | Output::Reset { .. }
                | Output::Retry { .. }
                | Output::Reject { .. } => {}
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
    fn close(&mut self, p: &Pair, did: &mut Did) {
        let Some((a, b)) = self.addrs.iter().find(|(a, _)| pair(*a) == *p).copied() else {
            return;
        };
        if b == Binding::Connected && !self.closed.contains(&a) {
            self.closed.push(a);
            did.closes.push(a);
        }
    }

    /// The peer was installed on `link`: build its rekey side, or carry it
    /// across a move.
    fn installed(&mut self, link: LinkNo, reset: Option<Transition>) {
        let Some(run) = self.runs.iter().rev().find(|r| r.link == link).copied() else {
            return;
        };
        let e = run.epoch.unwrap_or(Epoch(0));
        self.side = match (reset, self.side.take()) {
            (Some(Transition::Move), Some(old)) => Some(old.moved(run.hs)),
            (Some(_) | None, _) => Some(RekeySide::new(
                self.me, self.peer, run.hs, e, self.now, run.bytes,
            )),
        };
    }
}

fn change(t: Transition) -> M {
    match t {
        Transition::Promote => M::Promote,
        Transition::Replace => M::Replace,
        Transition::Move => M::Move,
        Transition::Keep => M::Keep,
        Transition::Restarted => M::Restarted,
        Transition::Roam => M::Roam,
    }
}

fn class(s: Source) -> Option<Class> {
    match s {
        Source::NotHeld => Some(Class::NotHeld),
        Source::Restart => Some(Class::Restart),
        Source::Replacement => Some(Class::Replacement),
        Source::OwnMsg2 | Source::RekeyMsg2 => None,
    }
}

fn refusal(d: Denial) -> Refusal {
    match d {
        Denial::Gate(Gated::Unheard) => Refusal::Gate(Gate::Unheard),
        Denial::Gate(Gated::Heard) => Refusal::Gate(Gate::Heard),
        Denial::Gate(Gated::Dampened) => Refusal::Gate(Gate::Dampened),
        Denial::Gate(Gated::Replayed | Gated::ReplayFull) => Refusal::Replay,
        Denial::Gate(Gated::Silent) => Refusal::Silent,
        Denial::Full => Refusal::Full,
    }
}
