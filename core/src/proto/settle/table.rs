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
//!   held peer and opens a responder leg whose answer is installed once it
//!   is sent. A same-epoch msg1 from a held identity goes to the peer's
//!   rekey machine with where it arrived: on the link when it comes from
//!   the link's setup address, the peer's current address or one of the
//!   link's proven paths. A replacement the machine asks for (rule 3.3)
//!   comes back and asks the gate the same way.
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
//! - **Heard**: a frame sets the peering heard and its last frame, makes
//!   the gates forget its replay memory and silent sessions, and moves the
//!   peer's current address if it came from elsewhere. A move does not set
//!   heard.
//!
//! The gate both decides and stamps, so each input's method decides first
//! and changes state only after, rather than through a separate plan.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::gates::{Ask, Epoch, Gates, Liveness, Source};
use super::input::{Dial, Hello, Input};
use super::legs::{Kind, LegOut, Legs, Start};
use super::links::{Dir, Holder, LinkNo, Links, Pair, Proven};
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
    gates: Gates<I>,
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
            gates: Gates::new(),
        }
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

    /// When [`Table::poll`] next has something to do.
    pub fn next_wake(&self) -> Option<I> {
        self.legs.next_wake()
    }

    /// Take one input at `now`.
    pub fn step(&mut self, input: Input, now: I) -> Vec<Output> {
        let mut out = Vec::new();
        match input {
            Input::Dial(d) => self.dial(d, now, &mut out),
            Input::Punched(d) if fault!(PunchedDropped) => {
                out.push(Output::Free { lease: d.lease })
            }
            Input::Punched(d) => self.dial(d, now, &mut out),
            Input::ConnectFailed { link } => self.abandon(link, &mut out),
            Input::Arrived { from, bytes } => self.arrived(&from, &bytes, &mut out),
            Input::Msg1 { hello, reachable } => self.msg1(hello, reachable, now, &mut out),
            Input::Replace(hello) => self.admit(Source::Replacement, hello, now, &mut out),
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
            Input::SendFailed { link } => self.unsent(link, &mut out),
            Input::Moved { .. } if fault!(PathMoveIgnored) => {}
            Input::Moved { link, from, to } => self.links.moved(link, &from, to),
            Input::Switched { .. } if fault!(SwitchIgnored) => {}
            Input::Switched { link, to, .. } => self.links.path(link, to, Proven::Live),
            Input::Released { link, pair, keep } => {
                let closes = self.links.release(link, &pair, keep);
                if fault!(ReleaseKeepsPair) {
                    self.links.path(link, pair, Proven::Live);
                }
                out.push(Output::Release { link, closes });
            }
            Input::State { .. } if fault!(StateIgnored) => {}
            Input::State { link, pair, proven } => self.links.path(link, pair, proven),
        }
        out
    }

    /// The legs' resends and reaps due at `now`.
    pub fn poll(&mut self, now: I) -> Vec<Output> {
        let mut out = Vec::new();
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
                    out.push(Output::Free { lease });
                    out.push(Output::Retire { link, closes });
                }
            }
        }
        out
    }

    /// Give everything back: every leg's lease, every held peer, and the
    /// connections the close rule closes.
    pub fn close(&mut self, now: I) -> Vec<Output> {
        let mut out = Vec::new();
        let closed = self.legs.close(&mut self.links);
        self.answered.clear();
        out.extend(
            closed
                .leases
                .into_iter()
                .map(|lease| Output::Free { lease }),
        );
        if !closed.closes.is_empty() {
            out.push(Output::Close {
                closes: closed.closes,
            });
        }
        let peers: Vec<NodeAddr> = self.held.keys().copied().collect();
        for peer in peers {
            self.remove(peer, Why::Closed, now, &mut out);
        }
        out
    }

    fn dial(&mut self, d: Dial, now: I, out: &mut Vec<Output>) {
        let link = self.links.open(d.to, Dir::Outbound, Holder::Leg);
        let start = Start {
            link,
            peer: Some(d.peer),
            msg1: d.msg1,
            lease: d.lease,
        };
        if let Some(old) = self.legs.dial(start, now, &self.params) {
            out.push(Output::Free { lease: old.lease() });
        }
        out.push(Output::Opened { link });
    }

    /// A leg ends unfinished: its lease returns and its link is retired.
    fn abandon(&mut self, link: LinkNo, out: &mut Vec<Output>) {
        let Some(leg) = self.legs.take(link) else {
            return;
        };
        self.answered.remove(&link);
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

    /// Whether the answers in flight have reached the admission cap.
    fn full(&self) -> bool {
        !fault!(CapLifted) && self.legs.answering() >= self.params.pending
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

    fn msg1(&mut self, hello: Hello, reachable: bool, now: I, out: &mut Vec<Output>) {
        if let Some((link, msg2)) = self.stored(&hello.from, &hello.bytes) {
            out.push(Output::Answer {
                link,
                msg2,
                stored: true,
            });
            out.push(Output::Free { lease: hello.lease });
            return;
        }
        let source = match self.held.get(&hello.peer) {
            None => Source::NotHeld,
            Some(h) if h.epoch != hello.epoch => Source::Restart,
            Some(h) => {
                let arrival = Arrival {
                    on_link: self.attributed(h, &hello.from),
                    reachable,
                };
                out.push(Output::Rekey {
                    peer: hello.peer,
                    arrival,
                });
                out.push(Output::Free { lease: hello.lease });
                return;
            }
        };
        self.admit(source, hello, now, out);
    }

    /// Whether a msg1 from `from` is on `h`'s link.
    fn attributed(&self, h: &Held<I>, from: &Pair) -> bool {
        let Some(r) = self.links.get(h.link) else {
            return false;
        };
        if fault!(AttributeBySetupOnly) {
            return r.setup == *from;
        }
        r.setup == *from
            || h.current == *from
            || r.paths.iter().any(|(p, s)| p == from && s.counts())
    }

    /// Rules 1, 2 and 3.3: through the cap and the gate, tear down any
    /// held peer, and answer.
    fn admit(&mut self, source: Source, hello: Hello, now: I, out: &mut Vec<Output>) {
        let peer = hello.peer;
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
                ephemeral: Some(hello.ephemeral),
                epoch: Some(hello.epoch),
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
            out.push(Output::Free { lease: hello.lease });
            return;
        }
        if held.is_some() {
            let why = match source {
                Source::Restart => Why::Restart,
                Source::NotHeld | Source::Replacement | Source::OwnMsg2 | Source::RekeyMsg2 => {
                    Why::Replacement
                }
            };
            self.remove(peer, why, now, out);
        }
        let link = self.links.open(hello.from, Dir::Inbound, Holder::Leg);
        let start = Start {
            link,
            peer: Some(peer),
            msg1: hello.bytes,
            lease: hello.lease,
        };
        if let Some(old) = self
            .legs
            .answer(start, hello.msg2.clone(), now, &self.params)
        {
            out.push(Output::Free { lease: old.lease() });
        }
        self.answered.insert(
            link,
            Answered {
                ephemeral: hello.ephemeral,
                epoch: hello.epoch,
                replaces: held.is_some(),
                sent: false,
            },
        );
        out.push(Output::Answer {
            link,
            msg2: hello.msg2,
            stored: false,
        });
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
        if self.held.contains_key(&peer) {
            // The peer is held through another link by now: the leg
            // installs nothing and answers resends until it is reaped.
            if let Some(a) = self.answered.get_mut(&link) {
                a.sent = true;
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

    /// The msg2 could not be sent; the leg keeps it for the resend. A
    /// teardown it caused is no longer part of one replacement.
    fn unsent(&mut self, link: LinkNo, out: &mut Vec<Output>) {
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
        if own || self.me < peer {
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

    /// Move the held peer onto this node's completed dial on `link`, and
    /// retire the link it leaves. `own` says the held link was one this
    /// node dialed.
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
        let old = h.link;
        h.link = link;
        if !fault!(MoveKeepsOldPair) {
            h.current = from;
        }
        if fault!(MoveSetsHeard) {
            h.heard = true;
        }
        let pair = h.current.clone();
        self.links.hold(link, Holder::Peer(peer));
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
        if !kept(own) {
            let closes = self.links.retire(old);
            out.push(Output::Retire { link: old, closes });
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

    fn heard(&mut self, peer: NodeAddr, from: Pair, now: I, out: &mut Vec<Output>) {
        let Some(h) = self.held.get_mut(&peer) else {
            return;
        };
        h.heard = true;
        h.last = Some(now);
        self.gates.heard(&peer);
        if h.current != from {
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
    /// does.
    fn remove(&mut self, peer: NodeAddr, why: Why, now: I, out: &mut Vec<Output>) {
        let Some(h) = self.held.remove(&peer) else {
            return;
        };
        if !h.heard {
            self.gates
                .ended(peer, Some(h.epoch), h.setup, now, &self.params);
        }
        let closes = self.links.retire(h.link);
        let close = match why {
            Why::Orphaned | Why::Admin | Why::Closed => true,
            Why::Restart
            | Why::Replacement
            | Why::OwnRestart
            | Why::Ended
            | Why::Disconnect
            | Why::Dead => false,
        };
        out.push(Output::Remove { peer, why });
        out.push(Output::Retire {
            link: h.link,
            closes: if close { closes } else { Vec::new() },
        });
        match why {
            Why::Dead | Why::Disconnect => out.push(Output::Retry { peer }),
            Why::Restart
            | Why::Replacement
            | Why::OwnRestart
            | Why::Ended
            | Why::Orphaned
            | Why::Admin
            | Why::Closed => {}
        }
    }
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
