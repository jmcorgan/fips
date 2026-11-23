//! The XX judge: what one node does with each event of a
//! [`history`](super::history), by FRC-2201 Sections 5.2 to 5.7 and 7.2 to
//! 7.4, and the local rules named in [`LocalRule`].
//!
//! [`Judge`] holds one node's view of one peer identity. [`Judge::step`]
//! takes one event and returns a [`Step`]: the class of a completed
//! handshake, the check that refused it, what the node sends, the peer
//! change, the connections the change closes, and the local rule that
//! decided it where one did. [`Judge::settled`] and [`Judge::needs`] read
//! the state a history leaves.
//!
//! Each FRC rule's outcome is written once, on its own line, with its FRC
//! line (`frc-2201:N`, fips-frcs `c5df033`) beside it, so a table test
//! that cites the rule reds when that line changes.

use alloc::vec::Vec;

use super::history::{Addr, Binding, Claim, Epoch, Event, Hs, LinkId, Ms, Named, Node};

/// The FRC-2201 intervals the judgements read, in milliseconds, and the
/// switches for the local rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// `EPOCH_RESTART_MIN_INTERVAL`, the window of both restart gates
    /// (15 s).
    pub interval: Ms,
    /// `LINK_LIVE_WINDOW`, twice the longer of `HEARTBEAT_INTERVAL` and its
    /// default (20 s at the defaults).
    pub window: Ms,
    /// The live-link test of Section 5.7 is applied. Off, the node keeps
    /// [`LocalRule::NoLiveTest`].
    pub live: bool,
    /// A responder that refuses a msg3 at its peering decision sends a
    /// `Disconnect` ([`LocalRule::RefusalDisconnect`]). FRC-2201 sends
    /// nothing.
    pub disconnect: bool,
    /// An epoch change accepted at this node's own msg2 stamps the
    /// dampener. Off, only one accepted at a msg3 does
    /// ([`LocalRule::DampenerStamp`]).
    pub stamps: bool,
}

impl Default for Params {
    /// The FRC's values and rules.
    fn default() -> Self {
        Self {
            interval: 15_000,
            window: 20_000,
            live: true,
            disconnect: false,
            stamps: true,
        }
    }
}

impl Params {
    /// The FRC's values with the three local rules that change an FRC
    /// rule on: [`LocalRule::NoLiveTest`],
    /// [`LocalRule::RefusalDisconnect`] and [`LocalRule::DampenerStamp`].
    pub fn local() -> Self {
        Self {
            live: false,
            disconnect: true,
            stamps: false,
            ..Self::default()
        }
    }
}

/// The class of a completed handshake against what the node holds of the
/// peer (FRC-2201 Section 5.7, "Classifying a completed msg3", and the
/// same order at msg2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// No established session of the identity is held: a new peer.
    NotHeld,
    /// Rule 1: a different epoch, a restart (Section 5.6).
    Restart,
    /// Rule 2: a rekey declaration naming a session index other than the
    /// one held.
    Stale,
    /// Rule 3: a rekey declaration naming the session held (Section 7.2).
    Rekey,
    /// Rule 4, the tie-break: two handshakes dialed from opposite ends.
    Crossing,
    /// Rule 4, a second handshake dialed by the same side.
    SameSide,
}

/// A check that refused a message or a completed handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The msg2's static is not the identity the dial named (Section
    /// 5.3): the msg2 is dropped and the attempt goes on.
    Identity,
    /// The attribution check, the peering decision or the negotiation
    /// verdict (Sections 5.2 and 5.8.4): the handshake is abandoned.
    Declined,
    /// The first restart gate: the peering carried an authenticated frame
    /// within [`Params::interval`] (Section 5.6).
    Heard,
    /// The second restart gate: this node accepted an epoch change of the
    /// identity within [`Params::interval`] (Section 5.6).
    Dampened,
    /// The established link is live, so the initiator does not leave it
    /// (Section 5.7).
    Live,
    /// The smaller node of a simultaneous rekey keeps its own and drops
    /// the peer's msg3 (Section 7.3).
    Tied,
}

/// What the node sends in answer to an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Nothing.
    Silent,
    /// A fresh msg2.
    Msg2,
    /// The msg2 this node already built for that handshake, byte for byte.
    Stored,
    /// The msg3 of this node's own attempt.
    Final,
}

/// The ways a peer's link, session or existence changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    /// A peer installed for an identity not held.
    Promote,
    /// The held peer torn down and the completed handshake installed: an
    /// accepted restart.
    Replace,
    /// The peer moved onto the completed handshake's session and link, the
    /// link it held torn down.
    Move,
    /// The node keeps the session it holds and tears the completed
    /// handshake's link down.
    Keep,
    /// The peer's rekey completed here as responder: a pending session.
    Rekey,
    /// A pending session became current. Not named `Cutover`: a scan of
    /// the core bans that identifier.
    RekeyCutover,
    /// This node's own rekey msg2 carried a changed epoch: recorded, the
    /// link kept.
    Restarted,
    /// The peer removed.
    Remove,
}

/// The judge's choices where FRC-2201 is silent or leaves the choice to
/// the node, and the rules a node keeps in place of an FRC rule. Each is
/// named by what it decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalRule {
    /// No live-link test (Section 5.7) is applied: in its place the
    /// initiator leaves the established link only when it is not its own
    /// dial, unheard since it was installed or moved onto, and installed
    /// or moved onto after this attempt began, by the order of events (the
    /// own-dial keep). Set
    /// where the FRC's test would have decided otherwise.
    NoLiveTest,
    /// A responder that refuses a msg3 at its peering decision sends a
    /// `Disconnect` on the session the msg3 completed. FRC-2201 sends
    /// nothing (Section 5.2).
    RefusalDisconnect,
    /// Only an epoch change accepted at a msg3 stamps the dampener. The
    /// gates are optional (Section 5.6), so counting fewer acceptances
    /// refuses less, which a node may do.
    DampenerStamp,
    /// The larger node of a crossing completed at its own msg2 keeps what
    /// it holds and sends no msg3. The FRC says it keeps, and that a check
    /// after the identity check that refuses ends the attempt without
    /// msg3; it does not say the keep is such a refusal.
    KeepEndsAttempt,
    /// A msg3 whose rekey declaration names a session index not held
    /// changes nothing, and its pending inbound handshake is left for its
    /// timeout. The FRC says to keep the session and resend the stored
    /// msg2, and is silent on the handshake.
    StaleKeepsLeg,
}

/// What one event did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Step {
    /// The completed handshake's class.
    pub class: Option<Class>,
    /// The check that refused it.
    pub refused: Option<Refusal>,
    /// What the node sends.
    pub reply: Option<Reply>,
    /// The peer change, if any.
    pub change: Option<Transition>,
    /// The connections this step closes.
    pub closes: Vec<Addr>,
    /// Whether the node sends a `Disconnect`.
    pub disconnect: bool,
    /// The local rule that decided this step, where one did.
    pub rule: Option<LocalRule>,
}

/// A pending session from a completed rekey not yet cut over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The rekey handshake.
    pub hs: Hs,
    /// This node started the rekey.
    pub initiator: bool,
}

/// The peer this node holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// or the source of the msg1 it answered.
    pub setup: Addr,
    /// This node dialed the link, so it is the initiator of the handshake
    /// that set it up; a rekey does not change it (Section 5.7).
    pub dialed: bool,
    /// The peer's current address (Section 6.5).
    pub current: Addr,
    /// The judge's step count when the peer was installed or last moved
    /// onto this link: the order of events, not the clock, says whether an
    /// attempt began before it.
    pub since: u64,
    /// When the peer's msg2 that installed this link arrived, where this
    /// node's own dial set it up.
    pub msg2at: Option<Ms>,
    /// The last authenticated frame on this link.
    pub onlink: Option<Ms>,
    /// The last authenticated frame of the peering, on any link.
    pub framed: Option<Ms>,
    /// The pending session, if any.
    pub pending: Option<Pending>,
}

/// This node's own initial attempt in flight.
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
    /// The identity it names.
    pub named: Named,
    /// The judge's step count when it began.
    pub began: u64,
}

/// A pending inbound handshake: a msg1 answered, its msg3 not yet read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leg {
    /// The handshake.
    pub hs: Hs,
    /// The link it set up.
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
    /// The intervals and local rules.
    pub params: Params,
    /// The clock.
    pub now: Ms,
    /// The peer held, if any.
    pub peering: Option<Peering>,
    /// This node's own initial attempts in flight.
    pub attempts: Vec<Attempt>,
    /// Pending inbound handshakes.
    pub legs: Vec<Leg>,
    /// This node's own rekey in flight, before its msg2.
    pub rekey: Option<Hs>,
    /// The dampener: when an epoch change of the identity was last
    /// accepted and stamped.
    pub stamp: Option<Ms>,
    /// The events taken so far.
    pub steps: u64,
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
            steps: 0,
        }
    }

    /// Runs a whole history, returning one step per event.
    pub fn run(&mut self, history: &[Event]) -> Vec<Step> {
        history.iter().map(|e| self.step(*e)).collect()
    }

    /// The handshake whose session this node holds, its link, and the
    /// peer's current address on it.
    pub fn settled(&self) -> Option<(Hs, LinkId, Addr)> {
        self.peering.map(|p| (p.hs, p.link, p.current))
    }

    /// Each live link and the address it was set up at.
    pub fn needs(&self) -> Vec<(LinkId, Addr)> {
        let mut out = Vec::new();
        out.extend(self.peering.iter().map(|p| (p.link, p.setup)));
        out.extend(self.attempts.iter().map(|a| (a.link, a.to)));
        out.extend(self.legs.iter().map(|l| (l.link, l.from)));
        out
    }

    /// Takes one event.
    pub fn step(&mut self, event: Event) -> Step {
        self.steps += 1;
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
                named,
            } => {
                let began = self.steps;
                self.attempts.push(Attempt {
                    hs,
                    link,
                    to,
                    binding,
                    named,
                    began,
                });
                Step::default()
            }
            Event::Msg1 {
                hs,
                link,
                from,
                binding,
            } => self.msg1(Leg {
                hs,
                link,
                from,
                binding,
            }),
            Event::Msg2 { hs, epoch, refused } => self.msg2(hs, epoch, refused),
            Event::Msg3 {
                hs,
                epoch,
                claim,
                refused,
            } => self.msg3(hs, epoch, claim, refused),
            Event::Frame { hs, from } => self.frame(hs, from),
            Event::Timeout { hs } => self.timeout(hs),
            Event::RekeyStart { hs } => {
                // Section 7.1: not while a cycle or a pending session of
                // this node's is open.
                if self.peering.is_some_and(|p| p.pending.is_none()) && self.rekey.is_none() {
                    self.rekey = Some(hs);
                }
                Step::default()
            }
            Event::RekeyMsg2 { hs, epoch } => self.rekeyed(hs, epoch),
            Event::RekeyCutover => self.cutover(),
            Event::Lost => {
                self.rekey = None;
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

    /// FRC-2201 Section 5.2: a msg1 that passed admission.
    fn msg1(&mut self, leg: Leg) -> Step {
        if self
            .legs
            .iter()
            .any(|l| l.from == leg.from && l.hs == leg.hs)
        {
            return reply(Reply::Stored); // a duplicate draws the stored msg2 (frc-2201:898)
        }
        self.legs.push(leg); // any other msg1 starts its own handshake, beside any pending one (:908, :913)
        reply(Reply::Msg2)
    }

    /// FRC-2201 Sections 5.3, 5.6 and 5.7: this node's own msg2, checked
    /// in the order of Section 5.7.
    fn msg2(&mut self, hs: Hs, epoch: Epoch, refused: bool) -> Step {
        let Some(i) = self.attempts.iter().position(|a| a.hs == hs) else {
            return Step::default();
        };
        let a = self.attempts[i];
        if a.named == Named::Other {
            return Step {
                refused: Some(Refusal::Identity), // dropped, the attempt goes on (frc-2201:1037)
                reply: Some(Reply::Silent),
                ..Step::default()
            };
        }
        if refused {
            return self.abandon(i, None, Refusal::Declined); // no msg3 (:890, :1506)
        }
        let Some(p) = self.peering else {
            self.attempts.remove(i);
            self.peering = Some(self.dialed(a, epoch, None));
            return done(
                Class::NotHeld,
                Transition::Promote,
                Reply::Final,
                Vec::new(),
            );
        };
        if epoch != p.epoch {
            if let Some(gate) = self.gate(&p) {
                return self.abandon(i, Some(Class::Restart), gate); // the initiator's gate (:1382)
            }
            let rule = if self.params.stamps {
                self.stamp = Some(self.now); // stamped when accepted (:1380)
                None
            } else {
                Some(LocalRule::DampenerStamp)
            };
            self.attempts.remove(i);
            self.rekey = None;
            self.peering = Some(self.dialed(a, epoch, None));
            let closes = self.teardown(&[(p.setup, p.binding), (p.current, p.binding)]);
            return Step {
                rule,
                ..done(Class::Restart, Transition::Replace, Reply::Final, closes)
            };
        }
        let class = if p.dialed {
            Class::SameSide
        } else {
            Class::Crossing
        };
        if class == Class::Crossing && self.me > self.peer {
            self.attempts.remove(i);
            let closes = self.teardown(&[(a.to, a.binding)]);
            return Step {
                rule: Some(LocalRule::KeepEndsAttempt),
                ..done(class, Transition::Keep, Reply::Silent, closes) // the larger keeps (:1430)
            };
        }
        let (live, rule) = self.live(&p, &a);
        if live {
            return Step {
                rule,
                ..self.abandon(i, Some(class), Refusal::Live) // no move off a live link (:1431, :1476)
            };
        }
        self.attempts.remove(i);
        self.rekey = None; // moving abandons this node's rekey (:1467)
        self.peering = Some(self.dialed(a, p.epoch, Some(p)));
        let closes = self.teardown(&[(p.setup, p.binding), (p.current, p.binding)]);
        Step {
            rule,
            ..done(class, Transition::Move, Reply::Final, closes) // the smaller moves onto its dial (:1430); the same side moves (:1483)
        }
    }

    /// FRC-2201 Sections 5.6, 5.7 and 7.3: a completed msg3, checked and
    /// classified in the order of Section 5.7.
    fn msg3(&mut self, hs: Hs, epoch: Epoch, claim: Claim, refused: bool) -> Step {
        let Some(i) = self.legs.iter().position(|l| l.hs == hs) else {
            return Step::default(); // a msg3 of no pending handshake is dropped (frc-2201:2553)
        };
        let leg = self.legs[i];
        if refused {
            self.legs.remove(i);
            let closes = self.teardown(&[(leg.from, leg.binding)]);
            let disconnect = self.params.disconnect; // silent (:892, :1507)
            return Step {
                refused: Some(Refusal::Declined),
                reply: Some(Reply::Silent),
                closes,
                disconnect,
                rule: disconnect.then_some(LocalRule::RefusalDisconnect),
                ..Step::default()
            };
        }
        let Some(p) = self.peering else {
            self.legs.remove(i);
            self.peering = Some(self.answered(leg, epoch, None));
            return done(
                Class::NotHeld,
                Transition::Promote,
                Reply::Silent,
                Vec::new(),
            ); // whatever it declares (:1465)
        };
        if epoch != p.epoch {
            self.legs.remove(i);
            if let Some(gate) = self.gate(&p) {
                let closes = self.teardown(&[(leg.from, leg.binding)]);
                return Step {
                    class: Some(Class::Restart), // rule 1 (:1451), the responder's gate (:1382)
                    refused: Some(gate),
                    reply: Some(Reply::Silent),
                    closes,
                    ..Step::default()
                };
            }
            self.stamp = Some(self.now); // stamped when accepted (:1380)
            self.rekey = None;
            self.peering = Some(self.answered(leg, epoch, None));
            let closes = self.teardown(&[(p.setup, p.binding), (p.current, p.binding)]);
            return done(Class::Restart, Transition::Replace, Reply::Silent, closes);
        }
        match claim {
            Claim::Other => Step {
                class: Some(Class::Stale), // rule 2: keep the session, resend the stored msg2 (:1452)
                reply: Some(Reply::Stored),
                rule: Some(LocalRule::StaleKeepsLeg),
                ..Step::default()
            },
            Claim::Held => self.rekeyed_by_peer(i, p),
            Claim::None if p.dialed && self.me < self.peer => {
                self.legs.remove(i);
                let closes = self.teardown(&[(leg.from, leg.binding)]);
                done(Class::Crossing, Transition::Keep, Reply::Silent, closes) // the smaller keeps (:1428)
            }
            Claim::None => {
                let class = if p.dialed {
                    Class::Crossing // the larger moves onto its inbound (:1427)
                } else {
                    Class::SameSide // the responder moves (:1485)
                };
                self.legs.remove(i);
                self.rekey = None; // moving abandons this node's rekey (:1467)
                self.peering = Some(self.answered(leg, p.epoch, Some(p)));
                let closes = self.teardown(&[(p.setup, p.binding), (p.current, p.binding)]);
                done(class, Transition::Move, Reply::Silent, closes)
            }
        }
    }

    /// FRC-2201 Sections 7.2 and 7.3: the peer's declared rekey of the
    /// session held completes here, on the pending inbound handshake `i`.
    fn rekeyed_by_peer(&mut self, i: usize, p: Peering) -> Step {
        let own = self.rekey.is_some() || p.pending.is_some_and(|d| d.initiator);
        if own && self.me < self.peer {
            return Step {
                class: Some(Class::Rekey),
                refused: Some(Refusal::Tied), // the smaller keeps its own rekey and drops the msg3 (frc-2201:2450)
                reply: Some(Reply::Silent),
                ..Step::default()
            };
        }
        let leg = self.legs.remove(i);
        self.rekey = None; // the larger abandons its own and completes as responder (:2450)
        let pending = Some(Pending {
            hs: leg.hs,
            initiator: false,
        });
        self.peering = Some(Peering { pending, ..p });
        let closes = self.teardown(&[(leg.from, leg.binding)]);
        done(Class::Rekey, Transition::Rekey, Reply::Silent, closes) // rule 3 (:1455)
    }

    /// The peering a completed own attempt `a` sets up at `epoch`, moved
    /// from `from` if one was held.
    fn dialed(&self, a: Attempt, epoch: Epoch, from: Option<Peering>) -> Peering {
        Peering {
            hs: a.hs,
            epoch,
            link: a.link,
            binding: a.binding,
            setup: a.to,
            dialed: true,
            current: a.to,
            since: self.steps,
            msg2at: Some(self.now),
            onlink: None,
            framed: from.and_then(|p| p.framed),
            pending: None,
        }
    }

    /// The peering an answered handshake `leg` sets up at `epoch`, moved
    /// from `from` if one was held.
    fn answered(&self, leg: Leg, epoch: Epoch, from: Option<Peering>) -> Peering {
        Peering {
            hs: leg.hs,
            epoch,
            link: leg.link,
            binding: leg.binding,
            setup: leg.from,
            dialed: false,
            current: leg.from,
            since: self.steps,
            msg2at: None,
            onlink: None,
            framed: from.and_then(|p| p.framed),
            pending: None,
        }
    }

    /// The restart gate that refuses an epoch change of `p` now, if any
    /// (FRC-2201 Section 5.6).
    fn gate(&self, p: &Peering) -> Option<Refusal> {
        let within = |t: Ms| self.now.saturating_sub(t) < self.params.interval;
        if p.framed.is_some_and(within) {
            return Some(Refusal::Heard); // a frame within the interval (frc-2201:1378)
        }
        if self.stamp.is_some_and(within) {
            return Some(Refusal::Dampened); // an epoch change accepted within it (:1379)
        }
        None
    }

    /// Whether the initiator of attempt `a` stays on `p`'s link, and the
    /// local rule that decided it where the FRC's test would not have.
    fn live(&self, p: &Peering, a: &Attempt) -> (bool, Option<LocalRule>) {
        let within = |t: Ms| self.now.saturating_sub(t) < self.params.window;
        let frc = p.onlink.is_some_and(within) || p.msg2at.is_some_and(within); // live (frc-2201:1476)
        if self.params.live {
            return (frc, None);
        }
        let own = p.dialed && p.onlink.is_none() && a.began < p.since;
        (own, (own != frc).then_some(LocalRule::NoLiveTest))
    }

    /// Abandons attempt `i` without msg3, tearing its link down.
    fn abandon(&mut self, i: usize, class: Option<Class>, why: Refusal) -> Step {
        let a = self.attempts.remove(i);
        let closes = self.teardown(&[(a.to, a.binding)]);
        Step {
            class,
            refused: Some(why),
            reply: Some(Reply::Silent),
            closes,
            ..Step::default()
        }
    }

    /// A frame under `hs` from `from`.
    fn frame(&mut self, hs: Hs, from: Addr) -> Step {
        let now = self.now;
        let Some(p) = self.peering.as_mut() else {
            return Step::default();
        };
        let change = if p.hs == hs {
            None
        } else if p.pending.is_some_and(|d| d.hs == hs) {
            p.hs = hs; // a frame authenticated under the pending session promotes it (frc-2201:2478)
            p.pending = None;
            Some(Transition::RekeyCutover)
        } else {
            return Step::default();
        };
        p.onlink = Some(now);
        p.framed = Some(now);
        p.current = from; // only an established frame moves the address (:2314)
        Step {
            change,
            ..Step::default()
        }
    }

    /// The handshake timeout or the end of resends for `hs`.
    fn timeout(&mut self, hs: Hs) -> Step {
        if self.rekey == Some(hs) {
            self.rekey = None;
            return Step::default();
        }
        if let Some(i) = self.attempts.iter().position(|a| a.hs == hs) {
            let a = self.attempts.remove(i);
            let closes = self.teardown(&[(a.to, a.binding)]);
            return closing(closes);
        }
        if let Some(i) = self.legs.iter().position(|l| l.hs == hs) {
            let l = self.legs.remove(i); // reclaimed (frc-2201:2563)
            let closes = self.teardown(&[(l.from, l.binding)]);
            return closing(closes);
        }
        Step::default()
    }

    /// This node's own rekey msg2 (FRC-2201 Sections 5.6 and 7.2).
    fn rekeyed(&mut self, hs: Hs, epoch: Epoch) -> Step {
        if self.rekey != Some(hs) {
            return Step::default();
        }
        self.rekey = None;
        let Some(p) = self.peering.as_mut() else {
            return Step::default();
        };
        p.pending = Some(Pending {
            hs,
            initiator: true,
        });
        let change = if epoch != p.epoch {
            p.epoch = epoch; // the initiator records the new epoch, the link stands (frc-2201:1373)
            Some(Transition::Restarted)
        } else {
            None
        };
        Step {
            reply: Some(Reply::Final),
            change,
            ..Step::default()
        }
    }

    /// The initiator's cutover to its pending session (FRC-2201 Section
    /// 7.4).
    fn cutover(&mut self) -> Step {
        let Some(p) = self.peering.as_mut() else {
            return Step::default();
        };
        let Some(d) = p.pending.filter(|d| d.initiator) else {
            return Step::default();
        };
        p.hs = d.hs; // the initiator leads (frc-2201:2483)
        p.pending = None;
        Step {
            change: Some(Transition::RekeyCutover),
            ..Step::default()
        }
    }

    /// The connections among `links` (each an address and its binding)
    /// that close now that their link is gone: those of a connected
    /// transport that no remaining link uses (FRC-2201 Section 5.7).
    fn teardown(&self, links: &[(Addr, Binding)]) -> Vec<Addr> {
        let mut out = Vec::new();
        for &(at, binding) in links {
            if binding == Binding::Connected && !self.uses(at) && !out.contains(&at) {
                out.push(at);
            }
        }
        out
    }

    /// Whether a remaining link uses the connection at `at`.
    fn uses(&self, at: Addr) -> bool {
        self.peering
            .is_some_and(|p| p.setup == at || p.current == at)
            || self.attempts.iter().any(|a| a.to == at)
            || self.legs.iter().any(|l| l.from == at)
    }
}

/// A step that only sends `r`.
fn reply(r: Reply) -> Step {
    Step {
        reply: Some(r),
        ..Step::default()
    }
}

/// A step that only closes `closes`.
fn closing(closes: Vec<Addr>) -> Step {
    Step {
        closes,
        ..Step::default()
    }
}

/// A completed handshake of class `class` that made change `change`,
/// sent `r` and closed `closes`.
fn done(class: Class, change: Transition, r: Reply, closes: Vec<Addr>) -> Step {
    Step {
        class: Some(class),
        change: Some(change),
        reply: Some(r),
        closes,
        ..Step::default()
    }
}
