//! The settlement core's judgements: msg1 intake, msg2 completion,
//! crossings, own dials, restarts, removals and path events.
//!
//! [`Table`] holds every link record ([`Links`]), every handshake leg in
//! flight ([`Legs`]), the peer held for each identity ([`Held`]) and the
//! restart gates' memory ([`Gates`]). [`Table::step`] takes one input and
//! returns the outputs the shell runs front to back; [`Table::poll`] runs
//! the legs' timers and [`Table::close`] gives everything back.
//!
//! The rules, each as the current node has it unless said otherwise:
//!
//! - **A msg1** from an address whose answer could not be sent draws that
//!   stored answer, whatever its bytes (FRC-1201 Section 5.8); once sent,
//!   only the msg1 it answered, byte for byte, draws it again. Otherwise,
//!   from an identity not held (rule 1) or at an epoch other than the one
//!   on record (rule 2), it asks the gate and, if accepted, tears down any
//!   held peer and only then asks the shell for its answer. The answer the
//!   shell gives opens a responder leg, which is installed once it is
//!   sent; the shell may refuse instead, and the link the msg1 opened is
//!   retired. A same-epoch msg1 from a held identity goes to the peer's
//!   rekey machine with where it arrived: on the link when it comes from
//!   one of the link's paths that is Live or acknowledged, or, from a pair
//!   the link holds no path at, when the peer is not capable and the index
//!   names the link there. A replacement the machine asks for (rule 3.3)
//!   comes back and asks the gate the same way.
//! - **A redial** (operator decision, 2026-11-17): a fresh same-epoch msg1
//!   off the established link, which the machine asks to have answered as
//!   one, asks the gate as a redial and is answered by a responder leg on
//!   its own link beside the held peer, which it leaves as it is. At most
//!   one is pending per identity: a later one replaces it once it is as old
//!   as the unheard floor, and is refused before. Like any admitted msg1 it
//!   is asked for its answer first, and its memory is noted and an older
//!   pending redial abandoned only when the answer comes. Its answer, once sent,
//!   installs nothing while the peer is held. The first frame that
//!   authenticates under it (`LegHeard`) replaces the peering by the leg,
//!   for a redial (`Why::Redial`), and the swap stamps the dampener if the
//!   peering it replaced was heard. A leg no frame proves is reaped at its
//!   deadline. If the held peer is gone before then, the leg's send
//!   installs it as any answer's does.
//! - **A dial** opens its link when the node starts it: with its msg1
//!   for a dial that opens no connection first, and before its msg1 for
//!   one that does (`Input::Connecting`), whose leg starts when the msg1
//!   follows. Either way its address is in the index and in use from the
//!   start, as the node's link and index entry are, and a connection that
//!   fails retires the link.
//! - **The max-peers cap**: at the cap, a msg1 from an identity not held is
//!   refused before any answer is asked for, and a completed handshake
//!   that would install an identity not held installs nothing: its lease
//!   comes back and its link is retired. A held identity is judged as
//!   below whatever the count.
//! - **A msg2** of this node's own dial installs the peer if none is held,
//!   and replaces it if its epoch changed, which the gate accepts without a
//!   stamp. Otherwise this node holds the peer already: if the held link is
//!   one this node dialed, it moves onto the new dial (Section 5.6's
//!   own-dial rule); if not, the smaller node moves and the larger keeps
//!   its inbound handshake (the tie-break). The link a move leaves, and the
//!   dial the larger node gives up, are retired by the close rule.
//! - **A teardown** for a restart or replacement, a rekey teardown, a dead
//!   link or a `Disconnect` keeps the old link's connection, as the
//!   current node keeps it; an operator disconnect, an orphaned bundle and
//!   the core's close apply the close rule. A peer removed before one
//!   frame authenticated is a silent session to the gates.
//! - **Heard**: a frame sets the peering heard and its last frame and
//!   makes the gates forget its replay memory and silent sessions. A move
//!   onto this node's own dial sets heard too (FRC-1201 Section 5.5); the
//!   gates forget at the peer's next frame.
//! - **Where the peer is** moves only where its bundle moves it, as the
//!   node has it: a move of the path the peer is at takes it to the new
//!   pair, and a switch of the active path takes it there. Only a one-path
//!   roam resets its per-peer data, as a roam; a path the bundle moved at
//!   a path message resets nothing, as a switch does not. A frame from a
//!   pair the bundle does not follow moves nothing.
//!
//! The gate both decides and stamps, so each input's method decides first
//! and changes state only after, rather than through a separate plan.
//!
//! In a test build a table can also run one candidate rule for the two
//! settlement cases left for later, chosen with `Table::under`; each keeps
//! the rules above and changes one decision (the test-only block at the
//! end of this file). No other build has any of it.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[cfg(test)]
use super::faults::Candidate;
use super::gates::{Ask, Epoch, Gates, Liveness, Source};
use super::input::{Dial, Hello, Input, Read};
use super::legs::{Kind, LegOut, Legs, Start};
use super::links::{Dir, Holder, LinkNo, LinkRec, Links, Pair, Proven};
use super::output::{Build, Denial, Install, Output, Transition, Why};
use super::params::Params;
use crate::identity::NodeAddr;
use crate::proto::fmp::EphemeralDigest;
use crate::proto::rekey::Arrival;
use crate::time::Instant;

/// The peer held for one identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held<I> {
    /// The link it holds.
    pub link: LinkNo,
    /// Its epoch on record.
    pub epoch: Epoch,
    /// Where it is now.
    pub current: Pair,
    /// A frame of it authenticated, or this node dialed it.
    pub heard: bool,
    /// When it was installed.
    pub installed: I,
    /// When its last frame authenticated.
    pub last: Option<I>,
    /// The ephemeral of the msg1 it was installed from, as responder.
    pub setup: Option<EphemeralDigest>,
}

impl<I: Instant> Held<I> {
    fn liveness(&self) -> Liveness<I> {
        Liveness {
            heard: self.heard,
            installed: self.installed,
            last: self.last,
        }
    }
}

/// What a responder leg's install needs that the leg does not keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Answered {
    ephemeral: EphemeralDigest,
    epoch: Epoch,
    /// The msg1 tore a held peer down, and its answer went out at once.
    replaces: bool,
    /// The answer was sent.
    sent: bool,
    /// It answers a redial: a frame under it, not its send, replaces the
    /// held peer.
    redial: bool,
}

/// An admitted msg1 waiting for the answer the shell builds: what its leg
/// takes once the answer comes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Asked {
    peer: NodeAddr,
    msg1: Vec<u8>,
    answered: Answered,
}

/// Test-only, for a candidate rule: a session kept beside the peer's
/// own, with the peer as it was held on it.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Kept<I> {
    /// The peer as held on the kept session; its link is the kept one.
    held: Held<I>,
    /// A frame under the kept session puts the peer back on it.
    back: bool,
    /// This node moved off the kept session onto its own later dial, as
    /// against replacing it as the responder.
    dialer: bool,
    /// When the kept session is dropped unsettled, if ever.
    until: Option<I>,
}

/// A dial whose connection is being opened: its link is recorded, and its
/// leg starts at the [`Input::Dial`] that names the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Connect {
    peer: NodeAddr,
    resends: Option<u32>,
    /// The link the peer was held on when the connect started.
    held: Option<LinkNo>,
}

/// Every link, leg and held peer of one node, and the gates.
#[derive(Debug, PartialEq, Eq)]
pub struct Table<I> {
    me: NodeAddr,
    params: Params,
    links: Links,
    legs: Legs<I>,
    held: BTreeMap<NodeAddr, Held<I>>,
    answered: BTreeMap<LinkNo, Answered>,
    connects: BTreeMap<LinkNo, Connect>,
    asked: BTreeMap<LinkNo, Asked>,
    /// The pending redial of each identity: its leg's link and when it
    /// was answered.
    redials: BTreeMap<NodeAddr, (LinkNo, I)>,
    gates: Gates<I>,
    /// Test-only: the candidate rule this node runs, if any.
    #[cfg(test)]
    cand: Option<Candidate>,
    /// Test-only: the sessions a candidate rule keeps, by peer.
    #[cfg(test)]
    holds: BTreeMap<NodeAddr, Kept<I>>,
}

impl<I: Instant> Table<I> {
    /// A node `me` holding nothing.
    pub fn new(me: NodeAddr, params: Params) -> Self {
        Self {
            me,
            params,
            links: Links::new(),
            legs: Legs::new(),
            held: BTreeMap::new(),
            answered: BTreeMap::new(),
            connects: BTreeMap::new(),
            asked: BTreeMap::new(),
            redials: BTreeMap::new(),
            gates: Gates::new(),
            #[cfg(test)]
            cand: None,
            #[cfg(test)]
            holds: BTreeMap::new(),
        }
    }

    /// Test-only: the same table running the candidate rule `cand`.
    #[cfg(test)]
    pub(crate) fn under(mut self, cand: Option<Candidate>) -> Self {
        self.cand = cand;
        self
    }

    /// The link records.
    pub fn links(&self) -> &Links {
        &self.links
    }

    /// The legs in flight.
    pub fn legs(&self) -> &Legs<I> {
        &self.legs
    }

    /// The peer held for `peer`.
    pub fn held(&self, peer: &NodeAddr) -> Option<&Held<I>> {
        self.held.get(peer)
    }

    /// The link of `peer`'s pending redial, if any.
    pub fn redialing(&self, peer: &NodeAddr) -> Option<LinkNo> {
        self.redials.get(peer).map(|(link, _)| *link)
    }

    /// When [`Table::poll`] next has something to do.
    pub fn next_wake(&self) -> Option<I> {
        #[cfg(test)]
        if let Some(k) = self.holds.values().filter_map(|k| k.until).min() {
            return Some(self.legs.next_wake().map_or(k, |w| w.min(k)));
        }
        self.legs.next_wake()
    }

    /// Take one input at `now`.
    pub fn step(&mut self, input: Input, now: I) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Dial(d) => self.dial(d, now, &mut out),
            Input::Connecting { peer, to, resends } => self.connecting(peer, to, resends, &mut out),
            Input::Punched(d) if fault!(PunchedDropped) => {
                out.push(Output::Free { lease: d.lease })
            }
            Input::Punched(d) => self.dial(d, now, &mut out),
            Input::ConnectFailed { link } => self.abandon(link, &mut out),
            Input::Arrived { from, bytes } => self.arrived(&from, &bytes, &mut out),
            Input::Msg1 { read, reachable } => self.msg1(read, reachable, now, &mut out),
            Input::Replace(read) => self.admit(Source::Replacement, read, now, &mut out),
            Input::Redial(read) => self.redial(read, now, &mut out),
            Input::LegHeard { .. } if fault!(LegHeardIgnored) => {}
            Input::LegHeard { link, from } => self.leg_heard(link, from, now, &mut out),
            Input::Hello(hello) => self.hello(hello, now, &mut out),
            Input::Abandon { link } => self.unasked(link, &mut out),
            Input::Msg2 { link, epoch, from } => self.msg2(link, epoch, from, now, &mut out),
            Input::Restarted { peer, epoch } => self.restarted(peer, epoch, now, &mut out),
            Input::Ended { peer } => self.remove(peer, Why::Ended, now, &mut out),
            Input::Orphaned { .. } if fault!(OrphanedIgnored) => {}
            Input::Orphaned { peer } => self.remove(peer, Why::Orphaned, now, &mut out),
            Input::Heard { peer, from } => self.heard(peer, from, now, &mut out),
            Input::Disconnect { peer } => self.remove(peer, Why::Disconnect, now, &mut out),
            Input::Dead { peer } => self.remove(peer, Why::Dead, now, &mut out),
            Input::Admin { peer } => self.remove(peer, Why::Admin, now, &mut out),
            Input::Sent { link } => self.sent(link, now, &mut out),
            Input::SendFailed { link } => self.unsent(link, now, &mut out),
            Input::Moved { .. } if fault!(PathMoveIgnored) => {}
            Input::Switched { .. } if fault!(SwitchIgnored) => {}
            Input::State { .. } if fault!(StateIgnored) => {}
            Input::Switched { link, to, proven } => self.switched(link, to, proven),
            Input::Moved {
                link,
                from,
                to,
                roam,
            } => self.moved(link, from, to, roam, &mut out),
            i @ (Input::State { .. } | Input::Capable { .. }) => {
                self.links.mirror(&i);
            }
            i @ Input::Released { link, .. } => {
                let closes = self.links.mirror(&i);
                if fault!(ReleaseKeepsPair)
                    && let Input::Released { pair, .. } = i
                {
                    self.links.path(link, pair, Proven::Live);
                }
                out.push(Output::Release { link, closes });
            }
            #[cfg(test)]
            Input::HeldFrame { peer, .. } => self.held_frame(peer, now, &mut out),
            #[cfg(test)]
            Input::HoldLost { peer } => self.unhold(peer, false, &mut out),
        }
        out
    }

    /// The legs' resends and reaps due at `now`.
    pub fn poll(&mut self, now: I) -> Vec<Output> {
        let mut out = Vec::new();
        #[cfg(test)]
        self.expire(now, &mut out);
        for o in self.legs.poll(now, &mut self.links) {
            match o {
                LegOut::Resend { link, bytes } => out.push(Output::Resend { link, bytes }),
                LegOut::Reaped {
                    link,
                    closes,
                    lease,
                    ..
                } => {
                    self.answered.remove(&link);
                    if !fault!(RedialLegKept) {
                        self.redials.retain(|_, (l, _)| *l != link);
                    }
                    out.push(Output::Free { lease });
                    out.push(Output::Retire { link, closes });
                }
            }
        }
        out
    }

    /// Give everything back: every leg's lease, every held peer, every
    /// link an unanswered ask opened, and the connections the close rule
    /// closes.
    pub fn close(&mut self, now: I) -> Vec<Output> {
        let mut out = Vec::new();
        let mut closed = self.legs.close(&mut self.links);
        self.answered.clear();
        self.redials.clear();
        for link in core::mem::take(&mut self.connects).into_keys() {
            closed.closes.extend(self.links.retire(link));
        }
        out.extend(
            closed
                .leases
                .into_iter()
                .map(|lease| Output::Free { lease }),
        );
        let mut closes = closed.closes;
        for link in core::mem::take(&mut self.asked).into_keys() {
            closes.extend(self.links.retire(link));
        }
        if !closes.is_empty() {
            out.push(Output::Close { closes });
        }
        let peers: Vec<NodeAddr> = self.held.keys().copied().collect();
        for peer in peers {
            self.remove(peer, Why::Closed, now, &mut out);
        }
        #[cfg(test)]
        for peer in self.holds.keys().copied().collect::<Vec<_>>() {
            self.unhold(peer, true, &mut out);
        }
        out
    }

    /// A dial's leg starts, on the link a [`Input::Connecting`] opened for
    /// it or on one opened here. A dial naming a link no connect holds
    /// gives its lease back and starts nothing.
    fn dial(&mut self, d: Dial, now: I, out: &mut Vec<Output>) {
        let (link, c, opened) = match d.link {
            None => {
                let link = self.links.open(d.to, Dir::Outbound, Holder::Leg);
                let c = Connect {
                    peer: d.peer,
                    resends: d.resends,
                    held: self.held.get(&d.peer).map(|h| h.link),
                };
                (link, c, true)
            }
            Some(link) => {
                let Some(c) = self.connects.remove(&link) else {
                    out.push(Output::Free { lease: d.lease });
                    return;
                };
                if self.links.get(link).is_some() {
                    (link, c, false)
                } else {
                    let link = self.links.open(d.to, Dir::Outbound, Holder::Leg);
                    (link, c, true)
                }
            }
        };
        let start = Start {
            link,
            peer: Some(c.peer),
            msg1: d.msg1,
            lease: d.lease,
            resends: c.resends,
            held: c.held,
        };
        if let Some(old) = self.legs.dial(start, now, &self.params) {
            out.push(Output::Free { lease: old.lease() });
        }
        if opened {
            out.push(Output::Opened { link });
        }
    }

    /// A dial on a connection still to be opened: its link opens now, in
    /// the index and in use, with no leg until its msg1.
    fn connecting(
        &mut self,
        peer: NodeAddr,
        to: Pair,
        resends: Option<u32>,
        out: &mut Vec<Output>,
    ) {
        let link = self.links.open(to, Dir::Outbound, Holder::Leg);
        if fault!(ConnectingUnlinked) || node_fault!(ConnectingUnlinked) {
            // The link's record waits for the msg1, as when only a dial
            // with its msg1 opened one.
            let _ = self.links.retire(link);
        }
        let held = self.held.get(&peer).map(|h| h.link);
        self.connects.insert(
            link,
            Connect {
                peer,
                resends,
                held,
            },
        );
        out.push(Output::Opened { link });
    }

    /// A leg ends unfinished: its lease returns and its link is retired. A
    /// dial still connecting has no leg and no lease, and its link is
    /// retired alone.
    fn abandon(&mut self, link: LinkNo, out: &mut Vec<Output>) {
        if self.connects.remove(&link).is_some() {
            let closes = self.links.retire(link);
            out.push(Output::Retire { link, closes });
            return;
        }
        let Some(leg) = self.legs.take(link) else {
            return;
        };
        self.answered.remove(&link);
        self.redials.retain(|_, (l, _)| *l != link);
        out.push(Output::Free { lease: leg.lease() });
        let closes = self.links.retire(link);
        out.push(Output::Retire { link, closes });
    }

    /// The stored answer to `bytes` from `from`, if a responder leg there
    /// holds one: one not yet sent answers any msg1 from that address, one
    /// sent answers its own msg1 alone.
    fn stored(&self, from: &Pair, bytes: &[u8]) -> Option<(LinkNo, Vec<u8>)> {
        self.links.at(from).find_map(|l| {
            let unsent = !fault!(StoredByBytes) && self.answered.get(&l).is_some_and(|a| !a.sent);
            let msg2 = if unsent {
                self.legs.msg2(l)
            } else {
                self.legs.stored(l, bytes)
            };
            msg2.map(|m| (l, m.to_vec()))
        })
    }

    /// Whether the answers in flight, built or asked for, have reached the
    /// admission cap.
    fn full(&self) -> bool {
        !fault!(CapLifted) && self.legs.answering() + self.asked.len() >= self.params.pending
    }

    /// Whether `peer` is not held and the peers held have reached the
    /// max-peers cap; a cap of 0 holds any number.
    fn capped(&self, peer: &NodeAddr) -> bool {
        !(fault!(CapNotCounted) || node_fault!(CapNotCounted))
            && self.params.peers > 0
            && !self.held.contains_key(peer)
            && self.held.len() >= self.params.peers
    }

    /// A completed handshake on `link` that the max-peers cap refuses:
    /// the leg's lease comes back and its link is retired.
    fn refuse(&mut self, peer: NodeAddr, leg: super::legs::Leg<I>, out: &mut Vec<Output>) {
        let link = leg.link();
        self.answered.remove(&link);
        out.push(Output::Reject {
            peer: Some(peer),
            source: None,
            why: Denial::Cap,
        });
        out.push(Output::Free { lease: leg.lease() });
        let closes = self.links.retire(link);
        out.push(Output::Retire { link, closes });
    }

    fn arrived(&self, from: &Pair, bytes: &[u8], out: &mut Vec<Output>) {
        if let Some((link, msg2)) = self.stored(from, bytes) {
            out.push(Output::Answer {
                link,
                msg2,
                stored: true,
            });
        } else if self.full() {
            out.push(Output::Reject {
                peer: None,
                source: None,
                why: Denial::Full,
            });
        }
    }

    fn msg1(&mut self, read: Read, reachable: bool, now: I, out: &mut Vec<Output>) {
        if let Some((link, msg2)) = self.stored(&read.from, &read.bytes) {
            out.push(Output::Answer {
                link,
                msg2,
                stored: true,
            });
            return;
        }
        if fault!(AnswerBeforeAdmit) || node_fault!(AnswerBeforeAdmit) {
            // The defect's shape: the answer asked for before the msg1 is
            // classified, so a refused or rekey msg1 costs one too.
            self.ask(read.clone(), false, out);
        }
        if self.capped(&read.peer) {
            out.push(Output::Reject {
                peer: Some(read.peer),
                source: None,
                why: Denial::Cap,
            });
            return;
        }
        let source = match self.held.get(&read.peer) {
            None => Source::NotHeld,
            Some(h) if h.epoch != read.epoch => Source::Restart,
            Some(h) => {
                let arrival = Arrival {
                    on_link: self.attributed(h, &read.from),
                    reachable,
                    heard: h.heard,
                };
                out.push(Output::Rekey {
                    peer: read.peer,
                    arrival,
                });
                return;
            }
        };
        self.admit(source, read, now, out);
    }

    /// Whether a msg1 from `from` is on `h`'s link, as the node judges it
    /// ([`Placement::on_link`]): where the core's record of the peer is
    /// does not count.
    fn attributed(&self, h: &Held<I>, from: &Pair) -> bool {
        if fault!(AttributeByCurrent) || node_fault!(AttributeByCurrent) {
            let Some(r) = self.links.get(h.link) else {
                return false;
            };
            return (r.setup == *from && !r.capable)
                || h.current == *from
                || r.paths.iter().any(|(p, s)| p == from && s.counts());
        }
        self.links
            .placement(from, |l| self.legs.get(l).and_then(|g| g.peer()))
            .on_link(h.link)
    }

    /// Rules 1, 2 and 3.3: through the cap and the gate, tear down any
    /// held peer, and ask for the answer.
    fn admit(&mut self, source: Source, read: Read, now: I, out: &mut Vec<Output>) {
        let peer = read.peer;
        let held = self.held.get(&peer).map(Held::liveness);
        let source = if held.is_none() {
            Source::NotHeld
        } else {
            source
        };
        let refused = if self.full() {
            Some(Denial::Full)
        } else if source == Source::Replacement && fault!(ReplacementUngated) {
            None
        } else {
            let ask = Ask {
                source,
                held,
                ephemeral: Some(read.ephemeral),
                epoch: Some(read.epoch),
            };
            self.gates
                .gate(peer, ask, now, &self.params)
                .map(Denial::Gate)
        };
        if let Some(why) = refused {
            out.push(Output::Reject {
                peer: Some(peer),
                source: Some(source),
                why,
            });
            return;
        }
        if held.is_some() {
            let why = match source {
                Source::Restart => Why::Restart,
                Source::NotHeld
                | Source::Replacement
                | Source::Redial
                | Source::OwnMsg2
                | Source::RekeyMsg2 => Why::Replacement,
            };
            #[cfg(test)]
            self.hold_replaced(peer, source, now, out);
            self.remove(peer, why, now, out);
        }
        self.ask(read, held.is_some(), out);
    }

    /// Open the link an admitted msg1 arrived on and ask the shell for its
    /// answer; `replaces` says the msg1 tore a held peer down. The link
    /// opened.
    fn ask(&mut self, read: Read, replaces: bool, out: &mut Vec<Output>) -> LinkNo {
        let link = self.links.open(read.from, Dir::Inbound, Holder::Leg);
        let answered = Answered {
            ephemeral: read.ephemeral,
            epoch: read.epoch,
            replaces,
            sent: false,
            redial: false,
        };
        let asked = Asked {
            peer: read.peer,
            msg1: read.bytes,
            answered,
        };
        self.asked.insert(link, asked);
        out.push(Output::Ask {
            link,
            peer: read.peer,
        });
        link
    }

    /// The answer to an ask: its responder leg opens, holding the lease,
    /// and the msg2 goes out. An answer to no ask hands its lease back.
    fn hello(&mut self, hello: Hello, now: I, out: &mut Vec<Output>) {
        let Some(asked) = self.asked.remove(&hello.link) else {
            out.push(Output::Free { lease: hello.lease });
            return;
        };
        let link = hello.link;
        if asked.answered.redial {
            self.arm(asked.peer, asked.answered.ephemeral, now, out);
        }
        let start = Start {
            link,
            peer: Some(asked.peer),
            msg1: asked.msg1,
            lease: hello.lease,
            resends: None,
            held: None,
        };
        if let Some(old) = self
            .legs
            .answer(start, hello.msg2.clone(), now, &self.params)
        {
            out.push(Output::Free { lease: old.lease() });
        }
        let redial = asked.answered.redial;
        self.answered.insert(link, asked.answered);
        if redial {
            self.redials.insert(asked.peer, (link, now));
        }
        out.push(Output::Answer {
            link,
            msg2: hello.msg2,
            stored: false,
        });
    }

    /// The shell refused an asked msg1: the link it opened is retired.
    fn unasked(&mut self, link: LinkNo, out: &mut Vec<Output>) {
        if self.asked.remove(&link).is_none() {
            return;
        }
        let closes = self.links.retire(link);
        out.push(Output::Retire { link, closes });
    }

    /// A msg2 or a msg1 resend the shell was asked for went out.
    fn sent(&mut self, link: LinkNo, now: I, out: &mut Vec<Output>) {
        let Some(leg) = self.legs.get(link) else {
            return;
        };
        let peer = match (leg.kind(), leg.peer()) {
            (Kind::Dial, _) => {
                self.legs.resent(link, now, &self.params);
                return;
            }
            (Kind::Answer { .. }, None) => return,
            (Kind::Answer { .. }, Some(peer)) => peer,
        };
        let redial = self.answered.get(&link).is_some_and(|a| a.redial);
        if self.held.contains_key(&peer) && redial && fault!(RedialInstallsAtSent) {
            self.swap(peer, link, None, now, out);
            return;
        }
        if self.held.contains_key(&peer) {
            // The peer is held through another link by now, or it is the
            // peer a redial's leg would replace at its first frame: the leg
            // installs nothing and answers resends until it is heard or
            // reaped.
            if let Some(a) = self.answered.get_mut(&link) {
                a.sent = true;
            }
            return;
        }
        // A redial's leg whose peer is gone installs as any answer does,
        // and is no longer a redial.
        if !fault!(RedialLegKept) {
            self.redials.retain(|_, (l, _)| *l != link);
        }
        if self.capped(&peer) {
            if let Some(leg) = self.legs.take(link) {
                self.refuse(peer, leg, out);
            }
            return;
        }
        let (Some(leg), Some(a), Some(pair)) = (
            self.legs.take(link),
            self.answered.remove(&link),
            self.links.get(link).map(|r| r.setup.clone()),
        ) else {
            return;
        };
        self.links.hold(link, Holder::Peer(peer));
        self.held.insert(
            peer,
            Held {
                link,
                epoch: a.epoch,
                current: pair.clone(),
                heard: false,
                installed: now,
                last: None,
                setup: Some(a.ephemeral),
            },
        );
        self.gates.promoted(peer, a.ephemeral, now, &self.params);
        out.push(Output::Install(Install {
            peer,
            link,
            pair,
            rekey: Build::Fresh,
            initiator: false,
            lease: leg.lease(),
        }));
        let transition = if a.replaces {
            Transition::Replace
        } else {
            Transition::Promote
        };
        out.push(Output::Reset { peer, transition });
    }

    /// A redial: through the cap, the silent-session refusal, the slot rule
    /// and the rest of the gate, then asked for its answer as any admitted
    /// msg1 is. The held peer is left as it is; the answer ([`Table::hello`])
    /// opens the leg beside it.
    fn redial(&mut self, read: Read, now: I, out: &mut Vec<Output>) {
        let peer = read.peer;
        let Some(held) = self.held.get(&peer).map(Held::liveness) else {
            // Gone since the machine asked: a msg1 from an identity not
            // held.
            self.admit(Source::NotHeld, read, now, out);
            return;
        };
        let pending = self.redials.get(&peer).copied();
        let refused = if self.full() {
            Some(Denial::Full)
        } else if self.gates.silenced(&peer, Some(read.epoch), now) {
            Some(Denial::Gate(super::gates::Refusal::Silent))
        } else if pending
            .is_some_and(|(_, at)| now.saturating_duration_since(at) < self.params.unheard)
            && !fault!(RedialSlotIgnored)
        {
            Some(Denial::Held)
        } else {
            let ask = Ask {
                source: Source::Redial,
                held: Some(held),
                ephemeral: Some(read.ephemeral),
                epoch: Some(read.epoch),
            };
            self.gates
                .gate(peer, ask, now, &self.params)
                .map(Denial::Gate)
        };
        if let Some(why) = refused {
            out.push(Output::Reject {
                peer: Some(peer),
                source: Some(Source::Redial),
                why,
            });
            return;
        }
        let link = self.ask(read, false, out);
        if let Some(a) = self.asked.get_mut(&link) {
            a.answered.redial = true;
        }
    }

    /// The answer to a redial's ask is coming: the identity's older pending
    /// redial, which no frame proved, is abandoned, and the msg1's
    /// ephemeral goes into the redial memory. Run after the shell's checks,
    /// as the node notes a redial only once the ACL has passed it.
    fn arm(&mut self, peer: NodeAddr, ephemeral: EphemeralDigest, now: I, out: &mut Vec<Output>) {
        if let Some((old, _)) = self.redials.get(&peer).copied() {
            self.abandon(old, out);
        }
        self.gates.redialed(peer, ephemeral, now, &self.params);
    }

    /// A frame authenticated under the redial's leg on `link`, from
    /// `from`: the peer holds the redial's keys, so the leg replaces the
    /// held peer, or installs the peer if none is held by now.
    fn leg_heard(&mut self, link: LinkNo, from: Pair, now: I, out: &mut Vec<Output>) {
        let Some(peer) = self
            .redials
            .iter()
            .find(|(_, (l, _))| *l == link)
            .map(|(p, _)| *p)
        else {
            return;
        };
        self.swap(peer, link, Some(from), now, out);
    }

    /// Replace the peer held for `peer`, if any, by the redial's leg on
    /// `link`, heard at `now` from `from` (its setup address when `None`).
    fn swap(
        &mut self,
        peer: NodeAddr,
        link: LinkNo,
        from: Option<Pair>,
        now: I,
        out: &mut Vec<Output>,
    ) {
        let (Some(leg), Some(a), Some(setup)) = (
            self.legs.take(link),
            self.answered.remove(&link),
            self.links.get(link).map(|r| r.setup.clone()),
        ) else {
            return;
        };
        let pair = from.unwrap_or(setup);
        self.redials.remove(&peer);
        let heard = self.held.get(&peer).map(|h| h.heard);
        if heard.is_some() {
            self.remove(peer, Why::Redial, now, out);
        }
        self.gates.swapped(peer, heard == Some(true), now);
        self.links.hold(link, Holder::Peer(peer));
        self.held.insert(
            peer,
            Held {
                link,
                epoch: a.epoch,
                current: pair.clone(),
                heard: true,
                installed: now,
                last: Some(now),
                setup: Some(a.ephemeral),
            },
        );
        self.gates.heard(&peer);
        out.push(Output::Install(Install {
            peer,
            link,
            pair,
            rekey: Build::Fresh,
            initiator: false,
            lease: leg.lease(),
        }));
        let transition = if heard.is_some() {
            Transition::Replace
        } else {
            Transition::Promote
        };
        out.push(Output::Reset { peer, transition });
    }

    /// A send the shell was asked for failed. A msg2: the leg keeps it
    /// for the resend, and a teardown it caused is no longer part of one
    /// replacement. A dial's msg1 resend: it is tried again at the next
    /// poll.
    fn unsent(&mut self, link: LinkNo, now: I, out: &mut Vec<Output>) {
        if matches!(self.legs.get(link).map(|l| l.kind()), Some(Kind::Dial)) {
            self.legs.unsent(link, now, &self.params);
            return;
        }
        if fault!(SendFailedDropsLeg) {
            self.abandon(link, out);
            return;
        }
        if let Some(a) = self.answered.get_mut(&link) {
            a.replaces = false;
        }
    }

    fn msg2(&mut self, link: LinkNo, epoch: Epoch, from: Pair, now: I, out: &mut Vec<Output>) {
        let peer = match self.legs.get(link).map(|l| (l.kind(), l.peer())) {
            Some((Kind::Dial, Some(peer))) => peer,
            Some((Kind::Dial, None) | (Kind::Answer { .. }, _)) | None => return,
        };
        let Some(h) = self.held.get(&peer) else {
            self.dialed(peer, link, epoch, from, Transition::Promote, now, out);
            return;
        };
        if h.epoch != epoch {
            let ask = Ask {
                source: Source::OwnMsg2,
                held: Some(h.liveness()),
                ephemeral: None,
                epoch: Some(epoch),
            };
            if let Some(r) = self.gates.gate(peer, ask, now, &self.params) {
                out.push(Output::Reject {
                    peer: Some(peer),
                    source: Some(Source::OwnMsg2),
                    why: Denial::Gate(r),
                });
                self.abandon(link, out);
                return;
            }
            self.remove(peer, Why::OwnRestart, now, out);
            self.dialed(peer, link, epoch, from, Transition::Replace, now, out);
            return;
        }
        let own = !fault!(IgnoreOwnDial)
            && self
                .links
                .get(h.link)
                .is_some_and(|r| r.dir == Dir::Outbound);
        let moves = own || self.me < peer;
        #[cfg(test)]
        let moves = moves || self.aged(h, now);
        if moves {
            self.moveto(peer, link, from, own, out);
            return;
        }
        let Some(leg) = self.legs.take(link) else {
            return;
        };
        out.push(Output::Free { lease: leg.lease() });
        let closes = self.links.retire(link);
        out.push(Output::Retire { link, closes });
        out.push(Output::Reset {
            peer,
            transition: Transition::Keep,
        });
    }

    /// Install the peer from this node's own completed dial on `link`.
    #[allow(clippy::too_many_arguments)]
    fn dialed(
        &mut self,
        peer: NodeAddr,
        link: LinkNo,
        epoch: Epoch,
        from: Pair,
        transition: Transition,
        now: I,
        out: &mut Vec<Output>,
    ) {
        let Some(leg) = self.legs.take(link) else {
            return;
        };
        if self.capped(&peer) {
            self.refuse(peer, leg, out);
            return;
        }
        self.links.hold(link, Holder::Peer(peer));
        self.held.insert(
            peer,
            Held {
                link,
                epoch,
                current: from.clone(),
                heard: true,
                installed: now,
                last: None,
                setup: None,
            },
        );
        out.push(Output::Install(Install {
            peer,
            link,
            pair: from,
            rekey: Build::Fresh,
            initiator: true,
            lease: leg.lease(),
        }));
        out.push(Output::Reset { peer, transition });
    }

    /// Move the held peer onto this node's completed dial on `link`, at the
    /// msg2's pair `from`, which `link`'s record takes as a path, and retire
    /// the link it leaves. `own` says the held link was one this node
    /// dialed. The move ends an operator's pin of the peer's path when
    /// `own`, or when the dial was made while the peer was held on the link
    /// it leaves, as the node's `own_dial || later_dial` reads it.
    fn moveto(
        &mut self,
        peer: NodeAddr,
        link: LinkNo,
        from: Pair,
        own: bool,
        out: &mut Vec<Output>,
    ) {
        let (Some(leg), Some(h)) = (self.legs.take(link), self.held.get_mut(&peer)) else {
            return;
        };
        #[cfg(test)]
        let before = h.clone();
        let old = h.link;
        let later = leg.held() == Some(old) && !fault!(UnpinOwnOnly) && !node_fault!(UnpinOwnOnly);
        let unpin = own || later;
        h.link = link;
        // Read before `from` is taken: whether the msg2 came over the
        // connection the dial was set up at.
        let answered = self.links.get(link).is_some_and(|r| r.setup == from);
        if !fault!(MoveKeepsOldPair) {
            h.current = from;
        }
        // FRC-1201 Section 5.5: a peering this node set up as initiator is
        // heard once that handshake completed, and the move holds this
        // node's own dial.
        if !fault!(MoveLeavesUnheard) {
            h.heard = true;
        }
        let pair = h.current.clone();
        self.links.hold(link, Holder::Peer(peer));
        // The shell renews the bundle at the install's pair only after this
        // step, so the record takes that path now, Live as the renewal makes
        // it: the node renews before it closes the link it leaves, and the
        // retire below must count the connection the peering moved onto.
        if !(fault!(MoveClosesNewPair) || node_fault!(MoveClosesNewPair)) {
            self.links.path(link, pair.clone(), Proven::Live);
        }
        let retire = !kept(own);
        #[cfg(test)]
        let retire = retire && !self.hold_moved_off(peer, before, own, out);
        out.push(Output::Install(Install {
            peer,
            link,
            pair,
            rekey: Build::FromCarry,
            initiator: true,
            lease: leg.lease(),
        }));
        if !fault!(MoveNoReset) {
            out.push(Output::Reset {
                peer,
                transition: Transition::Move,
            });
        }
        out.push(Output::Swapped { peer, own, unpin });
        if retire {
            let mut closes = self.links.retire(old);
            if !answered {
                self.unused(link, old, &mut closes);
            }
            out.push(Output::Retire { link: old, closes });
        }
    }

    /// Add to `closes` the pair `link` was set up at when no live link uses
    /// it, `link` itself included, once `old` is retired: a move onto a dial
    /// answered from another pair leaves the dial's own connection to no
    /// path and no handshake, and the node closes it with the link the move
    /// left. The move calls it only when the msg2 came from another pair:
    /// the peer has just answered over the connection it came on, so a
    /// record that does not name that pair in use is wrong, not the
    /// connection unused.
    fn unused(&self, link: LinkNo, old: LinkNo, closes: &mut Vec<Pair>) {
        if fault!(MoveLeavesDialOpen) || node_fault!(MoveLeavesDialOpen) {
            return;
        }
        let Some(setup) = self.links.get(link).map(|r| r.setup.clone()) else {
            return;
        };
        if !closes.contains(&setup) && !self.links.in_use(&setup, old) {
            closes.push(setup);
        }
    }

    fn restarted(&mut self, peer: NodeAddr, epoch: Epoch, now: I, out: &mut Vec<Output>) {
        let Some(h) = self.held.get(&peer) else {
            return;
        };
        let ask = Ask {
            source: Source::RekeyMsg2,
            held: Some(h.liveness()),
            ephemeral: None,
            epoch: Some(epoch),
        };
        if let Some(r) = self.gates.gate(peer, ask, now, &self.params) {
            out.push(Output::Reject {
                peer: Some(peer),
                source: Some(Source::RekeyMsg2),
                why: Denial::Gate(r),
            });
            return;
        }
        if let Some(h) = self.held.get_mut(&peer) {
            h.epoch = epoch;
        }
        out.push(Output::Reset {
            peer,
            transition: Transition::Restarted,
        });
    }

    /// The bundle of `link` moved its path at `from` to `to`: the link's
    /// record follows, and a peer held on the link at `from` is now at
    /// `to`. A one-path roam (`roam`) resets the peer's data as a roam; a
    /// path the bundle moved at a path message resets nothing, as a switch
    /// does not, since the node runs that move as its own column, Follow.
    fn moved(&mut self, link: LinkNo, from: Pair, to: Pair, roam: bool, out: &mut Vec<Output>) {
        self.links.mirror(&Input::Moved {
            link,
            from: from.clone(),
            to: to.clone(),
            roam,
        });
        if fault!(HeardMovesPeer) || node_fault!(HeardMovesPeer) {
            return;
        }
        let Some((peer, h)) = self
            .held
            .iter_mut()
            .find(|(_, h)| h.link == link && h.current == from)
        else {
            return;
        };
        h.current = to;
        if roam || fault!(FollowResets) || node_fault!(FollowResets) {
            out.push(Output::Reset {
                peer: *peer,
                transition: Transition::Roam,
            });
        }
    }

    /// The bundle of `link` switched its active path to `to`, which it
    /// holds `proven`: the link's record takes the path in that state, and
    /// the peer held on the link is now there.
    fn switched(&mut self, link: LinkNo, to: Pair, proven: Proven) {
        self.links.mirror(&Input::Switched {
            link,
            to: to.clone(),
            proven,
        });
        if fault!(SwitchLeavesPeer) || node_fault!(SwitchLeavesPeer) {
            return;
        }
        if let Some(h) = self.held.values_mut().find(|h| h.link == link) {
            h.current = to;
        }
    }

    /// A frame of `peer` authenticated, from `from`: the peering is heard
    /// and the gates forget. Where the peer is moves only where its bundle
    /// moves it, at a path's move or switch, never with the frame alone.
    fn heard(&mut self, peer: NodeAddr, from: Pair, now: I, out: &mut Vec<Output>) {
        let Some(h) = self.held.get_mut(&peer) else {
            return;
        };
        h.heard = true;
        h.last = Some(now);
        self.gates.heard(&peer);
        #[cfg(test)]
        let h = {
            self.unhold(peer, true, out);
            self.held.get_mut(&peer).expect("held above")
        };
        if (fault!(HeardMovesPeer) || node_fault!(HeardMovesPeer)) && h.current != from {
            h.current = from;
            out.push(Output::Reset {
                peer,
                transition: Transition::Roam,
            });
        }
    }

    /// Tear the held peer down and retire its link. Only an operator
    /// disconnect, an orphaned bundle and the core's close close its
    /// connections; the other teardowns keep them, as the current node
    /// does. An orphaned bundle and an operator disconnect close what the
    /// node's removal closes: each path the bundle still holds that no
    /// other link uses, and not a setup pair whose path the bundle already
    /// released, which that release closed or kept; a disconnect closes
    /// the pair the peer was held at too, whatever else uses it. A
    /// reconnect is asked for where the node notes the loss for
    /// one: a dead link, a `Disconnect` and an orphaned bundle, which the
    /// node removes through its link-dead path, and a restart, a
    /// replacement and an own-dial restart, whose loss the peer's control
    /// machine reports before the new session is promoted.
    fn remove(&mut self, peer: NodeAddr, why: Why, now: I, out: &mut Vec<Output>) {
        let Some(h) = self.held.remove(&peer) else {
            return;
        };
        if !h.heard {
            self.gates
                .ended(peer, Some(h.epoch), h.setup, now, &self.params);
        }
        #[cfg(test)]
        if self.holds.get(&peer).is_some_and(|k| k.held.link == h.link) {
            // A candidate keeps this session: its link stays.
            out.push(Output::Remove { peer, why });
            return;
        }
        let own = self.links.get(h.link).map(removable).unwrap_or_default();
        let mut closes = self.links.retire(h.link);
        if matches!(why, Why::Orphaned | Why::Admin)
            && !(fault!(RemovalClosesEveryPair) || node_fault!(RemovalClosesEveryPair))
        {
            closes.retain(|p| own.contains(p));
            if why == Why::Admin && !closes.contains(&h.current) {
                closes.insert(0, h.current.clone());
            }
        }
        let close = match why {
            Why::Orphaned | Why::Admin | Why::Closed => true,
            Why::Restart
            | Why::Replacement
            | Why::Redial
            | Why::OwnRestart
            | Why::Ended
            | Why::Disconnect
            | Why::Dead => false,
        };
        #[cfg(test)]
        self.unhold(peer, close, out);
        out.push(Output::Remove { peer, why });
        out.push(Output::Retire {
            link: h.link,
            closes: if close { closes } else { Vec::new() },
        });
        let retry = match why {
            Why::Dead | Why::Disconnect => true,
            Why::Orphaned => !(fault!(OrphanedNoRetry) || node_fault!(OrphanedNoRetry)),
            Why::Restart | Why::Replacement | Why::OwnRestart => {
                !(fault!(RestartNoRetry) || node_fault!(RestartNoRetry))
            }
            Why::Redial | Why::Ended | Why::Admin | Why::Closed => false,
        };
        if retry {
            out.push(Output::Retry { peer });
        }
    }
}

/// The candidate rules, test-only. Each keeps the core's own rules and
/// changes one decision, so the explorer can compare the two.
#[cfg(test)]
impl<I: Instant> Table<I> {
    /// How long a responder keeps a replaced unheard session.
    const KEPT_FOR: core::time::Duration = core::time::Duration::from_secs(15);

    /// Whether, under the aged-link candidate, this node's own dial
    /// completing for `h` moves onto it: the held link is old enough to
    /// rekey, so the peer can only have answered the dial as a rekey or a
    /// replacement.
    fn aged(&self, h: &Held<I>, now: I) -> bool {
        self.cand == Some(Candidate::AgedMove)
            && !fault!(AgedTieBreak)
            && now.saturating_duration_since(h.installed)
                >= crate::proto::rekey::Config::fmp().link_age
    }

    /// At a move off a held link this node dialed, keep the session moved
    /// off under either late-dial candidate: one the peer's frame puts the
    /// peer back on under the dialer's rule, receive-only under the
    /// responder's. Whether it was kept.
    fn hold_moved_off(
        &mut self,
        peer: NodeAddr,
        before: Held<I>,
        own: bool,
        out: &mut Vec<Output>,
    ) -> bool {
        let back = match self.cand {
            Some(Candidate::DialerSettle | Candidate::ResponderHold) => true,
            Some(Candidate::AgedMove) | None => return false,
        };
        if !own {
            return false;
        }
        self.unhold(peer, true, out);
        out.push(Output::Hold {
            peer,
            link: before.link,
        });
        let kept = Kept {
            held: before,
            back,
            dialer: true,
            until: None,
        };
        self.holds.insert(peer, kept);
        true
    }

    /// At a replacement of an unheard peering under the responder's
    /// candidate, keep the replaced session for a while, dropping any
    /// earlier kept one; the removal that follows then keeps its link.
    fn hold_replaced(&mut self, peer: NodeAddr, source: Source, now: I, out: &mut Vec<Output>) {
        let Some(h) = self.held.get(&peer) else {
            return;
        };
        if self.cand != Some(Candidate::ResponderHold) || source != Source::Replacement || h.heard {
            return;
        }
        let kept = Kept {
            held: h.clone(),
            back: true,
            dialer: false,
            until: Some(super::params::deadline(now, Self::KEPT_FOR)),
        };
        self.unhold(peer, true, out);
        out.push(Output::Hold {
            peer,
            link: kept.held.link,
        });
        self.holds.insert(peer, kept);
    }

    /// Drop the session kept for `peer`, if any, and retire its link,
    /// closing what the close rule closes when `close`.
    fn unhold(&mut self, peer: NodeAddr, close: bool, out: &mut Vec<Output>) {
        let Some(k) = self.holds.remove(&peer) else {
            return;
        };
        let link = k.held.link;
        out.push(Output::Settle {
            peer,
            link,
            back: false,
        });
        let closes = self.links.retire(link);
        out.push(Output::Retire {
            link,
            closes: if close { closes } else { Vec::new() },
        });
    }

    /// A frame of `peer` under the kept session: unless that session is
    /// receive-only, the peer is back on it, and the link it held instead
    /// is retired by the close rule.
    fn held_frame(&mut self, peer: NodeAddr, now: I, out: &mut Vec<Output>) {
        if !self.holds.get(&peer).is_some_and(|k| k.back) {
            return;
        }
        let Some(k) = self.holds.remove(&peer) else {
            return;
        };
        out.push(Output::Settle {
            peer,
            link: k.held.link,
            back: true,
        });
        let mut held = k.held;
        held.heard = true;
        held.last = Some(now);
        self.links.hold(held.link, Holder::Peer(peer));
        self.gates.heard(&peer);
        if let Some(cur) = self.held.insert(peer, held) {
            let closes = self.links.retire(cur.link);
            out.push(Output::Retire {
                link: cur.link,
                closes,
            });
        }
        let transition = if k.dialer {
            Transition::Move
        } else {
            Transition::Replace
        };
        out.push(Output::Reset { peer, transition });
    }

    /// Drop every kept session whose time is up.
    fn expire(&mut self, now: I, out: &mut Vec<Output>) {
        let due: Vec<NodeAddr> = self
            .holds
            .iter()
            .filter(|(_, k)| k.until.is_some_and(|t| t <= now))
            .map(|(p, _)| *p)
            .collect();
        for peer in due {
            self.unhold(peer, true, out);
        }
    }
}

/// The pairs a removal of the link `r` may close: the paths its bundle
/// still holds, or its setup pair while it holds none and has not released
/// its path there, the link then having no bundle to report one.
fn removable(r: &LinkRec) -> Vec<Pair> {
    if r.paths.is_empty() && !r.released {
        return alloc::vec![r.setup.clone()];
    }
    r.paths.iter().map(|(p, _)| p.clone()).collect()
}

/// Whether a move keeps the link it leaves, which only a test-only switch
/// makes it do; `own` says that link was this node's own dial.
fn kept(own: bool) -> bool {
    if fault!(MoveKeepsInboundLink) {
        return true;
    }
    own && fault!(ModelFallbackInCore)
}

#[cfg(test)]
#[path = "tests/table.rs"]
mod tests;
