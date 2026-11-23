//! The XX flow as a node of the settlement world: scripted runs of two
//! nodes whose decisions are the flow's, on a settlement table
//! (`Table<TestInstant, Xx>`), against the same runs of two nodes of next's
//! transcribed rules (`next.rs`) and against the judge (`../model/`).
//!
//! [`FlowParty`] is the shell around the table: it turns the world's
//! packets into the flow's inputs (an anonymous msg1 into `In::Anon`, the
//! ask answered with `In::Hello` and the send told with `Input::Sent`, a
//! msg2 into `In::Msg2`, the asked msg3 sent and told with `In::FinalSent`,
//! a msg3 into `In::Msg3`, a frame of the session held into
//! `Input::Heard`), and the table's outputs into packets. Like `NextParty`
//! it runs no keys, rekey machine or path bundle: a session is named by the
//! handshake that made it, and a frame opens under the session of the
//! handshake it names. It sends a frame at each install and move, as the
//! tree announce does, and one a heartbeat apart after; a peer unheard for
//! the link-dead timeout is fed as `Input::Dead`. The table's own timers
//! run at each wake through `Table::poll` and the flow's sweep.
//!
//! Each run is scripted on a named start, as `judged.rs`'s are, and run
//! twice, once on two flow nodes and once on two next nodes, with the same
//! deliveries. It asserts that each flow node logs, peer by peer, the same
//! events and outcomes as the next node in its place, in the judge's terms,
//! and that its differences from the judge are the ones `judged.rs` names
//! for next. The flow's log is built from what the table holds before and
//! after each input and the refusals it outputs; the class of a completed
//! handshake is read from the table's state before it, as the judge's
//! history names it.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use super::super::model::history as xx;
use super::super::model::judge::{Class, Refusal, Reply, Transition};
use super::super::{Anon, In, Out, Xx};
use super::judged::{Known, compare};
use super::next::{Did, Entry, Log, NextParty, Packet, binding, xa, xe, xh};
use crate::identity::NodeAddr;
use crate::proto::fmp::{EphemeralDigest, RekeyClaim};
use crate::proto::rekey::IndexLease;
use crate::proto::settle::flow::Outs;
use crate::proto::settle::gates::{self, Epoch as Stamp};
use crate::proto::settle::input::{Dial as Dialed, Input as TableInput};
use crate::proto::settle::links::{Dir as LinkDir, LinkNo, Pair};
use crate::proto::settle::model::history::{Addr, Bytes, Epoch, Hs, Node};
use crate::proto::settle::output::{Denial, Output};
use crate::proto::settle::params::Params;
use crate::proto::settle::table::Table;
use crate::proto::settle::tests::world::{
    Dir, HEARTBEAT, Input, Kind, Ms, Net, Party, PeerView, Pkt, View, World,
};
use crate::testutil::TestInstant;
use crate::transport::{TransportAddr, TransportId};

/// `link_dead_timeout_secs`, 30 s, as `next.rs` has it.
const LINKDEAD: Ms = 30_000;

/// The table of a flow node.
type T = Table<TestInstant, Xx>;

/// The settlement core's identity of the world's `n`, ordered as the
/// world's numbers are.
fn na(n: Node) -> NodeAddr {
    NodeAddr::from_bytes([n.0; 16])
}

/// The settlement core's epoch of the world's `e`.
fn stamp(e: Epoch) -> Stamp {
    let mut s = [0u8; 8];
    s[4..].copy_from_slice(&e.0.to_be_bytes());
    s
}

/// The settlement core's pair of the world's address `a`.
fn pair(a: Addr) -> Pair {
    Pair {
        transport: TransportId::new(u32::from(a.transport)),
        addr: TransportAddr::from_string(&format!("10.0.{}.1:{}", a.transport, a.at)),
    }
}

/// The ephemeral of handshake `hs`.
fn eph(hs: Hs) -> EphemeralDigest {
    let mut key = [0u8; 33];
    key[..4].copy_from_slice(&hs.0.to_be_bytes());
    EphemeralDigest::of_noise_msg1(&key).expect("33 bytes carry an ephemeral")
}

/// The judge's link of the table's `link`.
fn xl(link: LinkNo) -> xx::LinkId {
    xx::LinkId(link.0 as u32)
}

/// What a link of the table is to the shell.
#[derive(Clone, Copy, Debug)]
enum Role {
    /// This node's dial of `peer`, with its msg1.
    Dial {
        peer: Node,
        bytes: Bytes,
        to: Addr,
        from: Option<Addr>,
    },
    /// An answer to `id`'s msg1, with the msg2 it sent.
    Answer {
        id: Node,
        local: Addr,
        msg2: Pkt<Packet>,
    },
}

/// The shell's record of one link of the table.
#[derive(Clone, Copy, Debug)]
struct Shell {
    hs: Hs,
    role: Role,
}

/// A node of the settlement world whose decisions are the XX flow's.
pub struct FlowParty {
    ix: usize,
    me: Node,
    life: u32,
    count: u32,
    now: Ms,
    table: T,
    links: BTreeMap<LinkNo, Shell>,
    pairs: BTreeMap<String, Addr>,
    heard: BTreeMap<Node, Ms>,
    beat: BTreeMap<Node, Ms>,
    log: Log,
}

impl FlowParty {
    /// Node `me`, at index `ix` of the world, logging to `log`.
    pub fn new(ix: usize, me: Node, log: Log) -> Self {
        Self {
            ix,
            me,
            life: 0,
            count: 0,
            now: 0,
            table: Table::flowing(
                na(me),
                super::super::params(Params::default()),
                Xx::new(false),
            ),
            links: BTreeMap::new(),
            pairs: BTreeMap::new(),
            heard: BTreeMap::new(),
            beat: BTreeMap::new(),
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

    fn note(&self, peer: Node, e: xx::Event, did: Did) {
        self.log.borrow_mut().push((self.now, peer, e, did));
    }

    /// The table's pair of `a`, remembered so a pair the table names can be
    /// sent to.
    fn pair(&mut self, a: Addr) -> Pair {
        let p = pair(a);
        self.pairs.insert(format!("{p:?}"), a);
        p
    }

    /// The world's address of the table's pair `p`.
    fn addr(&self, p: &Pair) -> Option<Addr> {
        self.pairs.get(&format!("{p:?}")).copied()
    }

    /// The world's identity of the core's `peer`.
    fn node(peer: &NodeAddr) -> Node {
        Node(peer.as_bytes()[0])
    }

    /// The handshake of the session `peer` is held on.
    fn session(&self, peer: Node) -> Option<Hs> {
        let h = self.table.held(&na(peer))?;
        self.links.get(&h.link).map(|s| s.hs)
    }

    fn step(&mut self, input: TableInput<In>) -> Vec<Outs<TestInstant, Xx>> {
        self.table.step(input, TestInstant(self.now))
    }

    /// Send `peer` a frame on the session it is held on now.
    fn announce(&mut self, net: &mut Net<Packet>, peer: Node) {
        let Some(hs) = self.session(peer) else {
            return;
        };
        let Some(to) = self
            .table
            .held(&na(peer))
            .and_then(|h| self.addr(&h.current))
        else {
            return;
        };
        self.beat.insert(peer, self.now + HEARTBEAT);
        let me = self.me;
        net.send(
            self.ix,
            None,
            to,
            Pkt::Frame {
                id: me,
                hs,
                wire: 0,
            },
        );
    }

    fn dial(&mut self, net: &mut Net<Packet>, peer: Node, to: Addr, from: Option<Addr>) {
        let hs = self.fresh();
        let bytes = Bytes(hs.0);
        let at = self.pair(to);
        let out = self.step(TableInput::Dial(Dialed {
            peer: na(peer),
            to: at,
            msg1: hs.0.to_be_bytes().to_vec(),
            lease: IndexLease::for_test(hs.0),
            resends: None,
            link: None,
        }));
        let Some(link) = out.iter().find_map(|o| {
            if let Output::Opened { link } = o {
                Some(*link)
            } else {
                None
            }
        }) else {
            return;
        };
        self.links.insert(
            link,
            Shell {
                hs,
                role: Role::Dial {
                    peer,
                    bytes,
                    to,
                    from,
                },
            },
        );
        let e = xx::Event::Dial {
            hs: xh(hs),
            link: xl(link),
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

    fn msg1(
        &mut self,
        net: &mut Net<Packet>,
        src: Addr,
        local: Addr,
        id: Node,
        hs: Hs,
        bytes: Bytes,
    ) {
        let from = self.pair(src);
        let kind = net.kind(src.transport);
        let out = self.step(TableInput::Flow(In::Anon(Anon {
            from,
            bytes: bytes.0.to_be_bytes().to_vec(),
            ephemeral: eph(hs),
            rekey_of: None,
        })));
        for o in &out {
            if let Output::Answer {
                link, stored: true, ..
            } = o
                && let Some(s) = self.links.get(link).copied()
                && let Role::Answer { msg2, .. } = s.role
            {
                net.send(self.ix, Some(local), src, msg2);
                let e = xx::Event::Msg1 {
                    hs: xh(s.hs),
                    link: xl(*link),
                    from: xa(src),
                    binding: binding(kind),
                };
                self.note(
                    id,
                    e,
                    Did {
                        reply: Some(Reply::Stored),
                        ..Did::default()
                    },
                );
                return;
            }
        }
        let Some(link) = out.iter().find_map(|o| {
            if let Output::Flow(Out::Ask { link }) = o {
                Some(*link)
            } else {
                None
            }
        }) else {
            return;
        };
        let msg2 = Pkt::Msg2 {
            id: self.me,
            hs,
            epoch: self.mine(),
            wire: 0,
        };
        self.links.insert(
            link,
            Shell {
                hs,
                role: Role::Answer { id, local, msg2 },
            },
        );
        self.step(TableInput::Flow(In::Hello {
            link,
            msg2: [&[2u8][..], &hs.0.to_be_bytes()].concat(),
            lease: IndexLease::for_test(hs.0),
        }));
        net.send(self.ix, Some(local), src, msg2);
        self.step(TableInput::Sent { link });
        let e = xx::Event::Msg1 {
            hs: xh(hs),
            link: xl(link),
            from: xa(src),
            binding: binding(kind),
        };
        self.note(
            id,
            e,
            Did {
                reply: Some(Reply::Msg2),
                ..Did::default()
            },
        );
    }

    /// The class of a completed handshake of `id` at `epoch`, read from the
    /// table before it: `own` is the class when the held link is this
    /// node's dial, `other` when it is the peer's.
    fn class(&self, id: Node, epoch: Epoch, own: Class, other: Class) -> Class {
        match self.table.held(&na(id)) {
            None => Class::NotHeld,
            Some(h) if h.epoch != stamp(epoch) => Class::Restart,
            Some(h) => {
                let dialed = self
                    .table
                    .links()
                    .get(h.link)
                    .is_some_and(|r| r.dir == LinkDir::Outbound);
                if dialed { own } else { other }
            }
        }
    }

    /// The change a completed handshake of class `class` made to `id`'s
    /// peering, from the link it was held on before and after.
    /// What a step did to `id`, from the session it was held on `before`
    /// to the one it is held on now: a move changes the session, whether
    /// or not it changes the link, as at the larger node's crossing at msg3.
    fn change(&self, id: Node, class: Class, before: Option<Hs>) -> Option<Transition> {
        let after = self.session(id);
        match (before, after) {
            (_, None) => None,
            (None, Some(_)) => Some(Transition::Promote),
            (Some(_), Some(_)) if class == Class::Restart => Some(Transition::Replace),
            (Some(b), Some(a)) if a != b => Some(Transition::Move),
            (Some(_), Some(_)) => Some(Transition::Keep),
        }
    }

    fn msg2(&mut self, net: &mut Net<Packet>, src: Addr, id: Node, hs: Hs, epoch: Epoch) {
        let Some((&link, &dial)) = self.links.iter().find(|(_, s)| s.hs == hs) else {
            return;
        };
        let Role::Dial { peer, .. } = dial.role else {
            return;
        };
        if peer != id {
            // The static mismatch: the shell drops the msg2 and keeps the
            // leg, with no input.
            return;
        }
        let e = xx::Event::Msg2 {
            hs: xh(hs),
            epoch: xe(epoch),
            refused: false,
        };
        let class = self.class(id, epoch, Class::SameSide, Class::Crossing);
        let before = self.session(id);
        let from = self.pair(src);
        let out = self.step(TableInput::Flow(In::Msg2 {
            link,
            epoch: stamp(epoch),
            from,
            peer: na(id),
        }));
        let finals = out
            .iter()
            .any(|o| matches!(o, Output::Flow(Out::Final { link: l }) if *l == link));
        let offered = out
            .iter()
            .any(|o| matches!(o, Output::Flow(Out::Offer { .. })));
        if !finals {
            let did = Did {
                class: Some(class),
                refused: offered.then_some(Refusal::Live),
                reply: Some(Reply::Silent),
                change: None,
            };
            return self.note(id, e, did);
        }
        let me = self.me;
        net.send(
            self.ix,
            None,
            src,
            Pkt::Flow(Packet::Msg3 {
                id: me,
                hs,
                epoch: self.mine(),
                claim: None,
            }),
        );
        self.step(TableInput::Flow(In::FinalSent { link }));
        let change = self.change(id, class, before);
        if matches!(
            change,
            Some(Transition::Promote | Transition::Replace | Transition::Move)
        ) {
            self.heard.insert(id, self.now);
            self.announce(net, id);
        }
        self.note(
            id,
            e,
            Did {
                class: Some(class),
                refused: None,
                reply: Some(Reply::Final),
                change,
            },
        );
    }

    fn msg3(
        &mut self,
        net: &mut Net<Packet>,
        src: Addr,
        id: Node,
        hs: Hs,
        epoch: Epoch,
        claim: Option<Hs>,
    ) {
        let Some((&link, &shell)) = self.links.iter().find(|(_, s)| s.hs == hs) else {
            return;
        };
        let Role::Answer { local, .. } = shell.role else {
            return;
        };
        let held = self.session(id);
        let (declared, claimed) = match (claim, held) {
            (None, _) => (xx::Claim::None, RekeyClaim::None),
            (Some(h), Some(s)) if h == s => (xx::Claim::Held, RekeyClaim::Matches),
            (Some(_), _) => (xx::Claim::Other, RekeyClaim::Mismatch),
        };
        let e = xx::Event::Msg3 {
            hs: xh(hs),
            epoch: xe(epoch),
            claim: declared,
            refused: false,
        };
        let class = self.class(id, epoch, Class::Crossing, Class::SameSide);
        let before = self.session(id);
        let from = self.pair(src);
        let out = self.step(TableInput::Flow(In::Msg3 {
            link,
            peer: na(id),
            epoch: stamp(epoch),
            claim: claimed,
            from,
        }));
        for o in &out {
            if let Output::Reject {
                why: Denial::Gate(g),
                ..
            } = o
            {
                let refused = if matches!(g, gates::Refusal::Dampened) {
                    Refusal::Dampened
                } else {
                    Refusal::Heard
                };
                let did = Did {
                    class: Some(class),
                    refused: Some(refused),
                    reply: Some(Reply::Silent),
                    change: None,
                };
                return self.note(id, e, did);
            }
            if let Output::Flow(Out::Repeat { peer, .. }) = o {
                let msg2 = self
                    .table
                    .held(peer)
                    .and_then(|h| self.links.get(&h.link))
                    .and_then(|s| {
                        if let Role::Answer { msg2, .. } = s.role {
                            Some(msg2)
                        } else {
                            None
                        }
                    });
                if let Some(m) = msg2 {
                    net.send(self.ix, Some(local), src, m);
                }
                let did = Did {
                    class: Some(Class::Stale),
                    reply: Some(Reply::Stored),
                    ..Did::default()
                };
                return self.note(id, e, did);
            }
            if let Output::Flow(Out::Rekey { .. }) = o {
                let did = Did {
                    class: Some(Class::Rekey),
                    refused: None,
                    reply: Some(Reply::Silent),
                    change: Some(Transition::Rekey),
                };
                return self.note(id, e, did);
            }
        }
        // A session installed on a link other than the answer's, the link
        // the peer is held on, is the answer's: that link's record takes
        // it, as next's node rebuilds the held link's machine on it, and
        // the answer's link goes.
        for o in &out {
            if let Output::Install(i) = o
                && i.link != link
            {
                self.links.insert(i.link, shell);
                self.links.remove(&link);
            }
        }
        let change = self.change(id, class, before);
        if matches!(
            change,
            Some(Transition::Promote | Transition::Replace | Transition::Move)
        ) {
            self.heard.insert(id, self.now);
            self.announce(net, id);
        }
        self.note(
            id,
            e,
            Did {
                class: Some(class),
                refused: None,
                reply: Some(Reply::Silent),
                change,
            },
        );
    }

    fn frame(&mut self, src: Addr, id: Node, hs: Hs) {
        if self.session(id) != Some(hs) {
            return;
        }
        let from = self.pair(src);
        self.step(TableInput::Heard {
            peer: na(id),
            from,
            kind: 0,
        });
        self.heard.insert(id, self.now);
        let e = xx::Event::Frame {
            hs: xh(hs),
            from: xa(src),
        };
        self.note(id, e, Did::default());
    }

    /// The table's outputs at a wake: resends, and the timeouts of dials and
    /// answers it reaps.
    fn reaped(&mut self, net: &mut Net<Packet>, out: Vec<Outs<TestInstant, Xx>>) {
        for o in out {
            if let Output::Resend { link, .. } = o {
                if let Some(s) = self.links.get(&link).copied()
                    && let Role::Dial {
                        bytes, to, from, ..
                    } = s.role
                {
                    let me = self.me;
                    net.send(
                        self.ix,
                        from,
                        to,
                        Pkt::Flow(Packet::Msg1 {
                            id: me,
                            hs: s.hs,
                            bytes,
                        }),
                    );
                }
            } else if let Output::Retire { link, .. } = o {
                let held = self
                    .table
                    .held_peers()
                    .any(|p| self.table.held(p).is_some_and(|h| h.link == link));
                if held {
                    continue;
                }
                if let Some(s) = self.links.remove(&link) {
                    let who = match s.role {
                        Role::Dial { peer, .. } => peer,
                        Role::Answer { id, .. } => id,
                    };
                    self.note(who, xx::Event::Timeout { hs: xh(s.hs) }, Did::default());
                }
            }
        }
    }

    fn timers(&mut self, net: &mut Net<Packet>) {
        let out = self.table.poll(TestInstant(self.now));
        self.reaped(net, out);
        let out = self.step(TableInput::Flow(In::Sweep));
        self.reaped(net, out);
        let held: Vec<Node> = self.table.held_peers().map(Self::node).collect();
        for id in held {
            let heard = self.heard.get(&id).copied().unwrap_or(self.now);
            if self.now.saturating_sub(heard) >= LINKDEAD {
                self.step(TableInput::Dead { peer: na(id) });
                self.heard.remove(&id);
                self.beat.remove(&id);
                self.note(
                    id,
                    xx::Event::Lost,
                    Did {
                        change: Some(Transition::Remove),
                        ..Did::default()
                    },
                );
            } else if self.beat.get(&id).is_some_and(|b| *b <= self.now) {
                self.announce(net, id);
            }
        }
    }
}

impl Party<Packet> for FlowParty {
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
                let held: Vec<Node> = self.table.held_peers().map(Self::node).collect();
                for id in held {
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
        let table = self.table.next_wake().map(|t| t.0);
        let beats = self.beat.values().copied();
        let dead = self.heard.values().map(|h| h + LINKDEAD);
        table.into_iter().chain(beats).chain(dead).min()
    }

    fn digest(&self) -> String {
        let held: Vec<(Node, Option<Hs>)> = self
            .table
            .held_peers()
            .map(|p| (Self::node(p), self.session(Self::node(p))))
            .collect();
        format!("{held:?}{:?}{:?}{}", self.heard, self.beat, self.life)
    }

    fn holds(&self, peer: Node, hs: Hs) -> bool {
        self.session(peer) == Some(hs)
    }

    fn held(&self) -> Vec<Node> {
        self.table.held_peers().map(Self::node).collect()
    }

    fn rekeyable(&self, _peer: Node) -> bool {
        false
    }

    fn view(&self) -> View {
        let mut v = View::empty(self.me);
        for p in self.table.held_peers() {
            let id = Self::node(p);
            let Some(h) = self.table.held(p) else {
                continue;
            };
            let Some(hs) = self.session(id) else {
                continue;
            };
            let dialed = self
                .table
                .links()
                .get(h.link)
                .is_some_and(|r| r.dir == LinkDir::Outbound);
            let dir = if dialed { Dir::Outbound } else { Dir::Inbound };
            let current = self.addr(&h.current).unwrap_or(Addr {
                transport: 0,
                at: 0,
            });
            v.peers.push(PeerView {
                peer: id,
                cur: hs,
                origin: hs,
                link: hs,
                dir,
                at: current,
                current,
                answered: dir == Dir::Outbound,
                pending: None,
                rekey: None,
                dials: Vec::new(),
            });
        }
        v
    }

    fn epoch(&self) -> Epoch {
        self.mine()
    }
}

/// The smaller node's identity.
const S: Node = Node(1);

/// The larger node's identity.
const L: Node = Node(2);

/// Node `x`'s one address.
fn home(x: usize) -> Addr {
    Addr {
        transport: 1,
        at: 1 + x as u16,
    }
}

/// Which node runs which rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rules {
    /// The XX flow on a settlement table.
    Flow,
    /// next's transcribed rules.
    Next,
}

/// Two nodes running `rules`, the smaller at index 0, over one
/// connectionless transport, and their logs.
struct Run {
    world: World<Packet>,
    logs: [Log; 2],
}

impl Run {
    fn new(rules: Rules) -> Self {
        let logs: [Log; 2] = [
            Rc::new(RefCell::new(Vec::new())),
            Rc::new(RefCell::new(Vec::new())),
        ];
        let party = |ix: usize, me: Node, log: Log| -> Box<dyn Party<Packet>> {
            match rules {
                Rules::Flow => Box::new(FlowParty::new(ix, me, log)),
                Rules::Next => Box::new(NextParty::new(ix, me, log)),
            }
        };
        let parties = vec![party(0, S, logs[0].clone()), party(1, L, logs[1].clone())];
        let net = Net::flowing(&[(1, Kind::Datagram)], vec![vec![home(0)], vec![home(1)]]);
        Self {
            world: World::flowing(parties, vec![S, L], net),
            logs,
        }
    }

    fn dial(&mut self, x: usize) {
        let peer = [L, S][x];
        self.world.input(
            x,
            Input::Dial {
                peer,
                to: home(1 - x),
                from: None,
            },
        );
    }

    fn deliver(&mut self, to: usize, kind: fn(&Pkt<Packet>) -> bool) {
        let id = self
            .world
            .net
            .flight
            .iter()
            .find(|f| f.to == to && kind(&f.pkt))
            .map(|f| f.id)
            .expect("precondition: the packet is in flight");
        self.world.deliver(id);
    }

    fn lose_frames(&mut self, to: usize) {
        self.world
            .net
            .flight
            .retain(|f| !(f.to == to && matches!(f.pkt, Pkt::Frame { .. })));
    }

    fn drain(&mut self) {
        self.world.drain(64);
    }

    fn at(&mut self, t: u64) {
        assert!(
            self.world.net.flight.is_empty(),
            "precondition: nothing in flight when the clock moves"
        );
        self.world.run_until(t);
    }

    fn held(&self, x: usize) -> Option<Hs> {
        let peer = [L, S][x];
        self.world.parties[x]
            .view()
            .peers
            .iter()
            .find(|p| p.peer == peer)
            .map(|p| p.cur)
    }

    /// Each node's log, its link numbers left out, since the two kinds of
    /// node number their links each their own way.
    fn logs(&self) -> [Vec<Entry>; 2] {
        let bare = |e: &Entry| {
            let event = if let xx::Event::Dial {
                hs,
                to,
                binding,
                named,
                ..
            } = e.2
            {
                xx::Event::Dial {
                    hs,
                    link: xx::LinkId(0),
                    to,
                    binding,
                    named,
                }
            } else if let xx::Event::Msg1 {
                hs, from, binding, ..
            } = e.2
            {
                xx::Event::Msg1 {
                    hs,
                    link: xx::LinkId(0),
                    from,
                    binding,
                }
            } else {
                e.2
            };
            (e.0, e.1, event, e.3)
        };
        [
            self.logs[0].borrow().iter().map(bare).collect(),
            self.logs[1].borrow().iter().map(bare).collect(),
        ]
    }

    /// The known causes of each node's differences from the judge, each
    /// difference required to have one.
    fn known(&self) -> Vec<(Node, Known)> {
        let mut out: Vec<(Node, Known)> = compare(S, &self.logs[0].borrow())
            .into_iter()
            .chain(compare(L, &self.logs[1].borrow()))
            .map(|d| {
                (
                    d.me,
                    d.known().unwrap_or_else(|| {
                        panic!("defect: a difference with no known cause: {d:?}")
                    }),
                )
            })
            .collect();
        out.sort();
        out
    }
}

/// A msg1.
fn m1(p: &Pkt<Packet>) -> bool {
    matches!(p, Pkt::Flow(Packet::Msg1 { .. }))
}

/// A msg2.
fn m2(p: &Pkt<Packet>) -> bool {
    matches!(p, Pkt::Msg2 { .. })
}

/// A msg3.
fn m3(p: &Pkt<Packet>) -> bool {
    matches!(p, Pkt::Flow(Packet::Msg3 { .. }))
}

/// Run `script` on two flow nodes and on two next nodes; require each flow
/// node's log to be the next node's, event by event, and return the flow
/// run.
fn both(script: impl Fn(&mut Run)) -> Run {
    let mut flow = Run::new(Rules::Flow);
    script(&mut flow);
    let mut next = Run::new(Rules::Next);
    script(&mut next);
    let (f, n) = (flow.logs(), next.logs());
    for x in 0..2 {
        let first = f[x].iter().zip(&n[x]).position(|(a, b)| a != b);
        assert!(
            first.is_none() && f[x].len() == n[x].len(),
            "defect: node {x}'s log under the flow differs from next's at entry {first:?}:\nflow {:#?}\nnext {:#?}",
            f[x],
            n[x]
        );
    }
    assert_eq!(
        (flow.held(0), flow.held(1)),
        (next.held(0), next.held(1)),
        "defect: the flow nodes end on other sessions than next's"
    );
    flow
}

#[test]
fn a_lone_dial_on_flow_nodes_logs_what_next_does_and_settles_as_the_judge_does() {
    let r = both(|r| {
        r.dial(0);
        r.drain();
    });
    assert!(r.held(0).is_some(), "precondition: the dial installs");
    assert_eq!(r.held(0), r.held(1));
    assert_eq!(r.known(), []);
}

#[test]
fn a_simultaneous_dial_on_flow_nodes_logs_what_next_does_in_every_order() {
    type Order = [(usize, fn(&Pkt<Packet>) -> bool); 4];
    let orders: [(Order, &[(Node, Known)]); 4] = [
        ([(0, m2), (1, m2), (0, m3), (1, m3)], &[]),
        (
            [(0, m2), (1, m3), (1, m2), (0, m3)],
            &[(L, Known::KeepSendsFinal)],
        ),
        ([(1, m2), (0, m3), (0, m2), (1, m3)], &[]),
        ([(0, m2), (1, m2), (1, m3), (0, m3)], &[]),
    ];
    for (i, (order, expected)) in orders.iter().enumerate() {
        let r = both(|r| {
            r.dial(0);
            r.dial(1);
            r.deliver(0, m1);
            r.deliver(1, m1);
            for (to, kind) in order {
                r.deliver(*to, *kind);
            }
            r.drain();
        });
        assert!(
            r.held(0).is_some(),
            "order {i}: precondition: a session held"
        );
        assert_eq!(r.held(0), r.held(1), "order {i}: both ends on one session");
        assert_eq!(r.known(), *expected, "order {i}");
    }
}

#[test]
fn two_dials_of_one_flow_node_answered_in_turn_log_what_next_does() {
    for x in [0, 1] {
        let r = both(|r| {
            r.dial(x);
            r.dial(x);
            r.deliver(1 - x, m1);
            r.deliver(1 - x, m1);
            r.deliver(x, m2);
            r.deliver(x, m2);
            r.drain();
        });
        assert!(
            r.held(x).is_some(),
            "node {x}: precondition: a session held"
        );
        assert_eq!(
            r.held(x),
            r.held(1 - x),
            "node {x}: both ends on one session"
        );
        assert_eq!(r.known(), [], "node {x}");
    }
}

#[test]
fn a_redial_by_either_flow_node_while_it_holds_the_peer_logs_what_next_does() {
    for (x, expected) in [
        (0, &[][..]),
        (
            1,
            &[(S, Known::SameSideByOrder), (L, Known::SameSideByOrder)][..],
        ),
    ] {
        let r = both(|r| {
            r.dial(x);
            r.drain();
            r.at(5_000);
            r.dial(x);
            r.drain();
        });
        assert_eq!(r.held(0), r.held(1), "node {x}: both ends on one session");
        assert_eq!(r.known(), expected, "node {x}");
    }
}

#[test]
fn a_restart_answered_at_the_dialers_msg2_on_flow_nodes_logs_what_next_does() {
    let r = both(|r| {
        r.dial(0);
        r.drain();
        r.at(2_000);
        r.world.restart(1);
        r.at(3_000);
        r.dial(0);
        r.drain();
    });
    assert_eq!(
        r.held(0),
        r.held(1),
        "precondition: both ends on the redial"
    );
    assert_eq!(r.known(), [(S, Known::Msg2RestartUngated)]);
}

#[test]
fn a_restart_at_msg3_of_a_peering_installed_inside_the_interval_with_no_frame_on_flow_nodes_logs_what_next_does()
 {
    let r = both(|r| {
        r.dial(0);
        r.deliver(1, m1);
        r.deliver(0, m2);
        r.lose_frames(1);
        r.deliver(1, m3);
        r.drain();
        r.at(5_000);
        r.world.restart(0);
        r.at(6_000);
        r.dial(0);
        r.deliver(1, m1);
        r.deliver(0, m2);
        r.lose_frames(1);
        r.deliver(1, m3);
        r.lose_frames(0);
        r.lose_frames(1);
    });
    assert_eq!(r.known(), [(L, Known::InstallFloor)]);
}
