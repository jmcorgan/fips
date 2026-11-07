//! The model's judgements: what one node does with each event of a
//! [`history`](super::history), by FRC-1201 Sections 5.5 to 5.8 and the
//! operator's decisions.
//!
//! [`Judge`] holds one node's view of one peer identity. [`Judge::step`]
//! takes one event and returns a [`Step`]: the msg1's class, a restart gate
//! that refused it, the reply, the peer change, the connections the change
//! closes, and the local rule that decided it where the FRC is silent.
//! [`Judge::settled`] and [`Judge::needs`] read the state a history leaves.
//!
//! Each FRC rule's outcome is written once, on its own line, with the rule
//! named beside it, so a table test that cites the rule reds when that line
//! changes.

use alloc::vec::Vec;

use super::history::{Addr, Binding, Bytes, Epoch, Event, Hs, LinkId, Ms, Node};

/// The FRC-1201 intervals the judgements read, in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// `UNHEARD_PEERING_MIN_AGE`, the first restart-gate floor (1 s).
    pub unheard: Ms,
    /// `EPOCH_RESTART_MIN_INTERVAL`, the second floor and the ceiling (15 s).
    pub interval: Ms,
    /// `REKEY_MIN_LINK_AGE` (30 s).
    pub linkage: Ms,
    /// `REKEY_MIN_SESSION_AGE`, which a node chooses between 10 s and 30 s;
    /// the model's default is 10 s ([`LocalRule::SessionAge`]).
    pub sessionage: Ms,
}

impl Default for Params {
    /// The FRC's values, and 10 s for the session age.
    fn default() -> Self {
        Self {
            unheard: 1_000,
            interval: 15_000,
            linkage: 30_000,
            sessionage: 10_000,
        }
    }
}

/// A msg1's class from a held identity, FRC-1201 Section 5.7, in the order
/// the rules are applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Rule 1: no peer of that identity is held.
    NotHeld,
    /// Rule 2: the epoch differs from the one on record; a restart.
    Restart,
    /// Rule 3.1: not eligible as a rekey, and a byte-for-byte resend of the
    /// msg1 the link was set up from.
    Resend,
    /// Rule 3.2: not eligible, and a copy the record holds.
    Copy,
    /// Rule 3.3: not eligible, any other msg1: a replacement.
    Replacement,
    /// Rule 4.1: eligible, off the established link while it is reachable.
    OffLink,
    /// Rule 4.2: eligible, while a pending session is held.
    Pending,
    /// Rule 4.3: eligible, a copy the record holds.
    Recorded,
    /// Rule 4.4: eligible, while this node's own rekey is in flight.
    Simultaneous,
    /// Rule 4.5: eligible, the peer's rekey.
    Rekey,
}

/// A restart gate that refused a restart or replacement, FRC-1201 Section
/// 5.5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// The first floor: the peering is unheard and younger than
    /// [`Params::unheard`].
    Unheard,
    /// The second floor: the peering is heard and a frame of it (or its
    /// installation) is within [`Params::interval`].
    Heard,
    /// The ceiling not yet reached: a restart or replacement of the
    /// identity was accepted within [`Params::interval`].
    Dampened,
}

/// What the node sends in answer to an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Nothing: the input is discarded silently, or needs no answer.
    Silent,
    /// A fresh msg2.
    Msg2,
    /// The msg2 already sent (or stored) for this msg1, byte for byte.
    Stored,
    /// A msg2 built but not yet sent, stored on a responder leg.
    Deferred,
}

/// The eight ways a peer's link, session or existence changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// A peer installed for an identity not held.
    Promote,
    /// The held peer torn down and a new one installed (a restart or a
    /// replacement at a msg1, or a restart at this node's msg2).
    Replace,
    /// The peer moved onto this node's outbound handshake (the smaller
    /// node of a crossing, or a node whose own later dial was answered).
    Move,
    /// The larger node of a crossing keeps its inbound handshake.
    Keep,
    /// A rekey cutover. Not named `Cutover`: the core's scan for the
    /// deployed rekey code bans that identifier.
    RekeyCutover,
    /// A restart revealed in a rekey msg2, the link kept.
    Restarted,
    /// An authenticated frame moved the peer's current address.
    Roam,
    /// The peer removed.
    Remove,
}

/// The model's choices where FRC-1201 is silent or leaves the choice to the
/// node. Each is named by what it decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalRule {
    /// A node whose own later dial is answered while it holds the peer on a
    /// link it dialed moves onto the new session but keeps the session it
    /// moved off until the peer's first authenticated frame shows which
    /// one the peer holds (the operator's option (c)). The FRC moves the
    /// peer and says nothing of the old session.
    LateSecondDial,
    /// A responder leg whose stored msg2 is sent after the peer is already
    /// held through another link resends that msg2 and installs nothing.
    /// The FRC says to install once a send succeeds, and is silent on a
    /// peer already held by then.
    StoredLate,
    /// The restart dampener's stamp (the last accepted restart or
    /// replacement, which the gates' ceiling counts from): a restart or
    /// replacement found at a msg1 stamps it if the old peering was heard;
    /// a restart found at this node's own msg2 does not; a restart revealed
    /// in a rekey msg2 with the link kept does not. The FRC does not say
    /// which acceptances count.
    DampenerStamp,
    /// This node's own dial, sent on the peer's established link once that
    /// link was old enough to rekey, completes while the peer is held: the
    /// peer will have read the msg1 as a rekey, not a dial. Undecided by
    /// the operator; the model answers [`Step::open`].
    AgedLink,
    /// Between the gates' floors and their ceiling the FRC lets a node
    /// refuse or accept; the model refuses there only while dampened.
    BetweenFloors,
    /// The msg1 record (rules 3.2 and 4.3) holds the setup msg1's ephemeral
    /// and every msg1 of the epoch on record answered or refused under
    /// rules 3 and 4, for the life of the peering; a new peering starts a
    /// new record.
    RecordScope,
    /// `REKEY_MIN_SESSION_AGE` is 10 s by default ([`Params::sessionage`]).
    SessionAge,
}

/// What one event did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// The msg1's class, for a msg1 from the peer that reached Section 5.7.
    pub class: Option<Class>,
    /// The restart gate that refused a restart or replacement.
    pub refused: Option<Gate>,
    /// What the node sends.
    pub reply: Option<Reply>,
    /// The peer change, if any.
    pub change: Option<Transition>,
    /// The connections this step closes, by the close rule.
    pub closes: Vec<Addr>,
    /// Whether the node sends a `Disconnect`.
    pub disconnect: bool,
    /// The local rule that decided this step, where one did.
    pub rule: Option<LocalRule>,
    /// The model leaves this step's outcome undecided.
    pub open: bool,
}

/// A session the peer may still hold, kept under
/// [`LocalRule::LateSecondDial`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fallback {
    /// The handshake of the session moved off.
    pub hs: Hs,
    /// Its link.
    pub link: LinkId,
    /// Its link's binding.
    pub binding: Binding,
    /// Its link's setup address.
    pub setup: Addr,
    /// The peer's current address on it.
    pub current: Addr,
}

/// A pending session from a completed rekey not yet cut over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The rekey handshake.
    pub hs: Hs,
    /// This node started the rekey.
    pub initiator: bool,
    /// As responder: the msg1 that armed it, for rule 4.2.
    pub armed: Option<Bytes>,
    /// As initiator: the changed epoch its msg2 carried.
    pub restarted: Option<Epoch>,
}

/// The peer this node holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peering {
    /// The handshake whose session is current.
    pub hs: Hs,
    /// The epoch on record.
    pub epoch: Epoch,
    /// The peer's link.
    pub link: LinkId,
    /// The link's binding.
    pub binding: Binding,
    /// The address the link was set up at: the address this node dialed,
    /// or the source of the msg1 it installed the peer from.
    pub setup: Addr,
    /// The link was set up by this node's own dial.
    pub dialed: bool,
    /// The msg1 the peer was installed from as responder, kept for rule 3.1
    /// (and kept across a move, FRC-1201 Section 5.6).
    pub msg1: Option<Bytes>,
    /// The peer's current address.
    pub current: Addr,
    /// When the peering was installed.
    pub installed: Ms,
    /// Where the link's age runs from.
    pub linkborn: Ms,
    /// Where the current session's age runs from.
    pub sessionborn: Ms,
    /// The peering is heard from (FRC-1201 Section 5.5).
    pub heard: bool,
    /// The last authenticated frame of the peering.
    pub last: Option<Ms>,
    /// The pending session, if any.
    pub pending: Option<Pending>,
    /// The session kept under [`LocalRule::LateSecondDial`].
    pub fallback: Option<Fallback>,
    /// The msg1 record, by ephemeral ([`LocalRule::RecordScope`]).
    pub record: Vec<Hs>,
}

/// This node's own initial dial in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// The handshake.
    pub hs: Hs,
    /// The link opened for it.
    pub link: LinkId,
    /// The address dialed.
    pub to: Addr,
    /// The link's binding.
    pub binding: Binding,
    /// The dial went on the peer's established link once that link was
    /// old enough to rekey ([`LocalRule::AgedLink`]).
    pub aged: bool,
}

/// A responder leg holding a msg2 it could not send yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leg {
    /// The msg1's handshake.
    pub hs: Hs,
    /// The msg1's bytes.
    pub bytes: Bytes,
    /// The msg1's epoch.
    pub epoch: Epoch,
    /// The link the msg1 arrived on.
    pub link: LinkId,
    /// The msg1's source.
    pub from: Addr,
    /// The link's binding.
    pub binding: Binding,
}

/// One node's view of one peer identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Judge {
    /// This node's address.
    pub me: Node,
    /// The peer's address.
    pub peer: Node,
    /// The intervals.
    pub params: Params,
    /// The clock.
    pub now: Ms,
    /// The peer held, if any.
    pub peering: Option<Peering>,
    /// This node's own initial dials in flight.
    pub attempts: Vec<Attempt>,
    /// Responder legs with a stored msg2.
    pub legs: Vec<Leg>,
    /// This node's own rekey in flight.
    pub rekey: Option<Hs>,
    /// The dampener: when a restart or replacement of the identity was
    /// last accepted and stamped ([`LocalRule::DampenerStamp`]).
    pub stamp: Option<Ms>,
    /// Connections that have closed.
    pub closed: Vec<Addr>,
}

impl Judge {
    /// A node `me` that holds nothing of peer `peer`, at time 0.
    pub fn new(me: Node, peer: Node, params: Params) -> Self {
        Self {
            me,
            peer,
            params,
            now: 0,
            peering: None,
            attempts: Vec::new(),
            legs: Vec::new(),
            rekey: None,
            stamp: None,
            closed: Vec::new(),
        }
    }

    /// Runs a whole history, returning one step per event.
    pub fn run(&mut self, history: &[Event]) -> Vec<Step> {
        history.iter().map(|e| self.step(*e)).collect()
    }

    /// The handshake whose session this node holds, its link, and the
    /// peer's current address on it.
    pub fn settled(&self) -> Option<(Hs, LinkId, Addr)> {
        self.peering.as_ref().map(|p| (p.hs, p.link, p.current))
    }

    /// Each live link and the `(transport, address)` it still needs: its
    /// setup address, while its handshake is in flight or (before links
    /// have bundles) while it lives.
    pub fn needs(&self) -> Vec<(LinkId, Addr)> {
        let mut out = Vec::new();
        if let Some(p) = &self.peering {
            out.push((p.link, p.setup));
            if let Some(f) = &p.fallback {
                out.push((f.link, f.setup));
            }
        }
        out.extend(self.attempts.iter().map(|a| (a.link, a.to)));
        out.extend(self.legs.iter().map(|l| (l.link, l.from)));
        out
    }

    /// Takes one event.
    pub fn step(&mut self, event: Event) -> Step {
        match event {
            Event::Advance(ms) => {
                self.now += ms;
                Step::default()
            }
            Event::Dial {
                hs,
                link,
                to,
                binding,
            } => self.dial(hs, link, to, binding),
            Event::Msg1 {
                hs,
                bytes,
                epoch,
                link,
                from,
                binding,
                sent,
            } => {
                let leg = Leg {
                    hs,
                    bytes,
                    epoch,
                    link,
                    from,
                    binding,
                };
                self.msg1(leg, sent)
            }
            Event::Msg2Sent { hs } => self.sent(hs),
            Event::Msg2 { hs, epoch, from } => self.msg2(hs, epoch, from),
            Event::Timeout { hs } => self.timeout(hs),
            Event::Frame { hs, from } => self.frame(hs, from),
            Event::RekeyStart { hs } => {
                if self.peering.is_some() {
                    self.rekey = Some(hs);
                }
                Step::default()
            }
            Event::RekeyMsg2 { hs, epoch } => self.rekeyed(hs, epoch),
            Event::RekeyCutover => self.cutover(),
            Event::Close { at } => {
                self.closed.push(at);
                Step::default()
            }
            Event::Lost => {
                let change = self.peering.take().map(|_| Transition::Remove);
                Step {
                    change,
                    ..Step::default()
                }
            }
            Event::Restart => {
                *self = Self::new(self.me, self.peer, self.params);
                Step::default()
            }
        }
    }

    fn dial(&mut self, hs: Hs, link: LinkId, to: Addr, binding: Binding) -> Step {
        let aged = self
            .peering
            .as_ref()
            .is_some_and(|p| self.onlink(p, to) && self.eligible(p) && self.reachable(p));
        self.attempts.push(Attempt {
            hs,
            link,
            to,
            binding,
            aged,
        });
        Step::default()
    }

    /// FRC-1201 Section 5.7: classify and answer a msg1.
    fn msg1(&mut self, leg: Leg, sent: bool) -> Step {
        // Section 5.8: a msg1 from the address of a leg holding a stored
        // msg2 draws that msg2 alone, before any classification.
        if self.legs.iter().any(|l| l.from == leg.from) {
            return reply(None, Reply::Stored);
        }
        let Some(p) = self.peering.as_ref() else {
            return self.install(Class::NotHeld, leg, sent); // rule 1 (frc-1201:1107)
        };
        if leg.epoch != p.epoch {
            return self.replace(Class::Restart, leg, sent); // rule 2 (:1111)
        }
        if !self.eligible(p) {
            if p.msg1 == Some(leg.bytes) {
                return reply(Some(Class::Resend), Reply::Stored); // rule 3.1 (:1120)
            }
            if p.record.contains(&leg.hs) {
                return reply(Some(Class::Copy), Reply::Silent); // rule 3.2 (:1123)
            }
            return self.replace(Class::Replacement, leg, sent); // rule 3.3 (:1125)
        }
        if !self.onlink(p, leg.from) && self.reachable(p) {
            return reply(Some(Class::OffLink), Reply::Silent); // rule 4.1 (:1134)
        }
        if let Some(pd) = p.pending {
            let resend = !pd.initiator && pd.armed == Some(leg.bytes);
            let answer = if resend { Reply::Stored } else { Reply::Silent };
            return reply(Some(Class::Pending), answer); // rule 4.2 (:1144)
        }
        if p.record.contains(&leg.hs) {
            return reply(Some(Class::Recorded), Reply::Silent); // rule 4.3 (:1147)
        }
        if self.rekey.is_some() {
            // Rule 4.4 (:1149), as Section 5.8 states Section 7.3's
            // outcome: the smaller node discards the peer's rekey msg1.
            if self.me < self.peer {
                return reply(Some(Class::Simultaneous), Reply::Silent);
            }
            let mut step = self.arm(leg);
            step.class = Some(Class::Simultaneous);
            step.open = true; // whether the larger node's own rekey goes on is Section 7.3's
            return step;
        }
        let mut step = self.arm(leg);
        step.class = Some(Class::Rekey); // rule 4.5 (:1151)
        step
    }

    /// Answers the peer's rekey msg1 and arms a pending session.
    fn arm(&mut self, leg: Leg) -> Step {
        let p = self
            .peering
            .as_mut()
            .expect("arm runs only for a held peer");
        p.pending = Some(Pending {
            hs: leg.hs,
            initiator: false,
            armed: Some(leg.bytes),
            restarted: None,
        });
        p.record.push(leg.hs);
        Step {
            reply: Some(Reply::Msg2),
            ..Step::default()
        }
    }

    /// A restart (rule 2) or replacement (rule 3.3), through the gates.
    fn replace(&mut self, class: Class, leg: Leg, sent: bool) -> Step {
        let p = self
            .peering
            .as_mut()
            .expect("replace runs only for a held peer");
        let gate = gated(p, self.stamp, self.now, &self.params);
        if let Some(gate) = gate {
            if class == Class::Replacement {
                p.record.push(leg.hs); // so its resends are copies (rule 3.3)
            }
            return Step {
                class: Some(class),
                refused: Some(gate),
                reply: Some(Reply::Silent),
                ..Step::default()
            };
        }
        if p.heard {
            self.stamp = Some(self.now); // stamped: the old peering was heard
        }
        self.peering = None;
        let mut step = self.install(class, leg, sent);
        step.rule = Some(LocalRule::DampenerStamp);
        if step.change == Some(Transition::Promote) {
            step.change = Some(Transition::Replace);
        } else {
            step.change = Some(Transition::Remove);
        }
        step
    }

    /// Answers a msg1 as from an identity not held, and installs the peer
    /// once the msg2 is sent.
    fn install(&mut self, class: Class, leg: Leg, sent: bool) -> Step {
        if !sent {
            self.legs.push(leg);
            return reply(Some(class), Reply::Deferred);
        }
        self.peering = Some(self.answered(leg));
        Step {
            class: Some(class),
            reply: Some(Reply::Msg2),
            change: Some(Transition::Promote),
            ..Step::default()
        }
    }

    /// The peering a responder installs from a msg1.
    fn answered(&self, leg: Leg) -> Peering {
        Peering {
            hs: leg.hs,
            epoch: leg.epoch,
            link: leg.link,
            binding: leg.binding,
            setup: leg.from,
            dialed: false,
            msg1: Some(leg.bytes),
            current: leg.from,
            installed: self.now,
            linkborn: self.now,
            sessionborn: self.now,
            heard: false,
            last: None,
            pending: None,
            fallback: None,
            record: alloc::vec![leg.hs],
        }
    }

    /// A stored msg2's send succeeded.
    fn sent(&mut self, hs: Hs) -> Step {
        let Some(i) = self.legs.iter().position(|l| l.hs == hs) else {
            return Step::default();
        };
        let leg = self.legs.remove(i);
        if self.peering.is_some() {
            return Step {
                reply: Some(Reply::Stored),
                rule: Some(LocalRule::StoredLate),
                ..Step::default()
            };
        }
        self.peering = Some(self.answered(leg));
        Step {
            reply: Some(Reply::Stored),
            change: Some(Transition::Promote),
            ..Step::default()
        }
    }

    /// FRC-1201 Sections 5.5 and 5.6: this node's own initial handshake
    /// completes.
    fn msg2(&mut self, hs: Hs, epoch: Epoch, from: Addr) -> Step {
        let Some(i) = self.attempts.iter().position(|a| a.hs == hs) else {
            return Step::default();
        };
        let a = self.attempts.remove(i);
        let dialed = self.dialed(a, epoch, from);
        let Some(p) = self.peering.as_mut() else {
            self.peering = Some(dialed);
            return change(Transition::Promote);
        };
        if epoch != p.epoch {
            // A restart at this node's own msg2: no tie-break (:979), and
            // no dampener stamp.
            self.peering = Some(dialed);
            let mut step = change(Transition::Replace);
            step.rule = Some(LocalRule::DampenerStamp);
            return step;
        }
        if a.aged {
            return Step {
                rule: Some(LocalRule::AgedLink),
                open: true,
                ..Step::default()
            };
        }
        if p.dialed {
            // A held link this node dialed (:1070): move whatever the
            // ordering, and keep the session moved off.
            p.fallback = Some(Fallback {
                hs: p.hs,
                link: p.link,
                binding: p.binding,
                setup: p.setup,
                current: p.current,
            });
            moveto(p, a, from);
            let mut step = change(Transition::Move);
            step.rule = Some(LocalRule::LateSecondDial);
            return step;
        }
        if self.me < self.peer {
            // The tie-break (:1048): the smaller node keeps its outbound
            // handshake and tears down the inbound link.
            let (link, setup, binding) = (p.link, p.setup, p.binding);
            moveto(p, a, from);
            let mut step = change(Transition::Move);
            step.closes = self.close(link, setup, binding);
            return step;
        }
        // The larger node keeps its inbound handshake.
        let mut step = change(Transition::Keep);
        step.closes = self.close(a.link, a.to, a.binding);
        step
    }

    /// The peering this node installs from its own completed handshake.
    fn dialed(&self, a: Attempt, epoch: Epoch, from: Addr) -> Peering {
        Peering {
            hs: a.hs,
            epoch,
            link: a.link,
            binding: a.binding,
            setup: a.to,
            dialed: true,
            msg1: None,
            current: from,
            installed: self.now,
            linkborn: self.now,
            sessionborn: self.now,
            heard: true,
            last: None,
            pending: None,
            fallback: None,
            record: Vec::new(),
        }
    }

    /// An attempt ends, or a leg is reclaimed: its link is torn down.
    fn timeout(&mut self, hs: Hs) -> Step {
        if let Some(i) = self.attempts.iter().position(|a| a.hs == hs) {
            let a = self.attempts.remove(i);
            return Step {
                closes: self.close(a.link, a.to, a.binding),
                ..Step::default()
            };
        }
        if let Some(i) = self.legs.iter().position(|l| l.hs == hs) {
            let l = self.legs.remove(i);
            return Step {
                closes: self.close(l.link, l.from, l.binding),
                ..Step::default()
            };
        }
        Step::default()
    }

    /// An authenticated frame from the peer.
    fn frame(&mut self, hs: Hs, from: Addr) -> Step {
        let now = self.now;
        let Some(p) = self.peering.as_mut() else {
            return Step::default();
        };
        let mut step = Step::default();
        if p.fallback.is_some_and(|f| f.hs == hs) {
            // The peer holds the session this node moved off: back onto it.
            let f = p.fallback.take().expect("checked above");
            let (link, setup, binding) = (p.link, p.setup, p.binding);
            p.hs = f.hs;
            p.link = f.link;
            p.binding = f.binding;
            p.setup = f.setup;
            p.current = f.current;
            p.dialed = true;
            step.change = Some(Transition::Move);
            step.rule = Some(LocalRule::LateSecondDial);
            step.closes = self.close(link, setup, binding);
        } else if p.hs == hs {
            if let Some(f) = p.fallback.take() {
                step.rule = Some(LocalRule::LateSecondDial);
                step.closes = self.close(f.link, f.setup, f.binding);
            }
        } else if p.pending.is_some_and(|pd| !pd.initiator && pd.hs == hs) {
            p.hs = hs;
            p.sessionborn = now;
            p.pending = None;
            step.change = Some(Transition::RekeyCutover);
        } else {
            return step;
        }
        let p = self.peering.as_mut().expect("held above");
        p.heard = true;
        p.last = Some(now);
        if p.current != from && step.change.is_none() {
            p.current = from;
            step.change = Some(Transition::Roam);
        }
        step
    }

    /// The msg2 of this node's own rekey.
    fn rekeyed(&mut self, hs: Hs, epoch: Epoch) -> Step {
        if self.rekey != Some(hs) {
            return Step::default();
        }
        self.rekey = None;
        if let Some(p) = self.peering.as_mut() {
            let restarted = (epoch != p.epoch).then_some(epoch);
            p.pending = Some(Pending {
                hs,
                initiator: true,
                armed: None,
                restarted,
            });
        }
        Step::default()
    }

    /// This node cuts over to its own rekey's pending session.
    fn cutover(&mut self) -> Step {
        let now = self.now;
        let Some(p) = self.peering.as_mut() else {
            return Step::default();
        };
        let Some(pd) = p.pending.filter(|pd| pd.initiator) else {
            return Step::default();
        };
        p.pending = None;
        p.hs = pd.hs;
        p.sessionborn = now;
        let Some(epoch) = pd.restarted else {
            return change(Transition::RekeyCutover);
        };
        // Section 5.5: record the new epoch, keep the link, restart its
        // age, report at the cutover; no dampener stamp.
        p.epoch = epoch;
        p.linkborn = now;
        let mut step = change(Transition::Restarted);
        step.rule = Some(LocalRule::DampenerStamp);
        step
    }

    /// Rule 3's condition: the link and its session are old enough to
    /// rekey (frc-1201:1112-1118).
    fn eligible(&self, p: &Peering) -> bool {
        self.now - p.linkborn >= self.params.linkage
            && self.now - p.sessionborn >= self.params.sessionage
    }

    /// Rule 4.1's "on the established link": the peer's transport, from
    /// its current address or the link's setup address.
    fn onlink(&self, p: &Peering, from: Addr) -> bool {
        from.transport == p.setup.transport && (from == p.current || from == p.setup)
    }

    /// Rule 4.1's "reachable": connectionless, or the connection still
    /// held.
    fn reachable(&self, p: &Peering) -> bool {
        p.binding == Binding::Connectionless || !self.closed.contains(&p.current)
    }

    /// The close rule (FRC-1201 Section 5.6, :1063-1065): tearing down a
    /// link closes its connection if the binding is connection-oriented
    /// and no remaining link needs that address.
    fn close(&self, link: LinkId, setup: Addr, binding: Binding) -> Vec<Addr> {
        let used = self
            .needs()
            .iter()
            .any(|(l, at)| *l != link && *at == setup);
        if binding == Binding::Connected && !used && !self.closed.contains(&setup) {
            alloc::vec![setup]
        } else {
            Vec::new()
        }
    }
}

/// The restart gates (FRC-1201 Section 5.5, :990-1022) over a held peering.
fn gated(p: &Peering, stamp: Option<Ms>, now: Ms, params: &Params) -> Option<Gate> {
    if !p.heard && now - p.installed < params.unheard {
        return Some(Gate::Unheard); // first floor (:995)
    }
    if p.heard && now - p.last.unwrap_or(p.installed) < params.interval {
        return Some(Gate::Heard); // second floor (:998)
    }
    if stamp.is_some_and(|s| now - s < params.interval) {
        return Some(Gate::Dampened); // until the ceiling (:1002)
    }
    None
}

/// Moves a peering onto this node's completed outbound handshake: the
/// session, its link and the msg2's source; the session's start, the
/// link's age and the setup msg1 are kept (FRC-1201 Section 5.6).
fn moveto(p: &mut Peering, a: Attempt, from: Addr) {
    p.hs = a.hs;
    p.link = a.link;
    p.binding = a.binding;
    p.setup = a.to;
    p.dialed = true;
    p.current = from;
    p.heard = true;
}

fn reply(class: Option<Class>, answer: Reply) -> Step {
    Step {
        class,
        reply: Some(answer),
        ..Step::default()
    }
}

fn change(t: Transition) -> Step {
    Step {
        change: Some(t),
        ..Step::default()
    }
}
