//! The rekey machine's decisions, transcribed over the world's abstract
//! handshakes.
//!
//! The settlement core leaves FRC-1201 Section 5.7 rules 3.1, 3.2 and 4.1
//! to 4.5 with the peer's link rekey machine, and takes that machine's
//! replacement request, restart report and teardown as inputs. The world
//! needs those rules at the far end of every held peer, so [`RekeySide`]
//! states them as the machine at `2ba790b2` decides them (the line ranges
//! are in this directory's README):
//!
//! - `judge_msg1`: eligibility by link and session age, the copy kinds
//!   (the setup msg1, the msg1 that armed a pending, one the record holds,
//!   a fresh one), the off-link refusal, the pending refusal, the
//!   simultaneous resolution by address order and the answer that arms a
//!   pending; with `apply`'s recording of every refused or replaced fresh
//!   ephemeral;
//! - the frame that cuts a responder's pending over, and the drain that
//!   keeps the previous session open for a while after any cutover;
//! - the initiator's msg2, its cutover one check later, and the restart a
//!   changed epoch in that msg2 reveals;
//! - in `poll`, the own rekey's resends and deadline and the pending
//!   hold's expiry.
//!
//! It is a transcription, not the machine: its tests show that it agrees
//! with the reference model on every rule 3 and 4 history, not that it
//! agrees with the machine.

use alloc::vec::Vec;

use super::super::model::history::{Bytes, Epoch, Hs, Node};
use super::super::model::judge::{Class, Reply};
use super::world::{CHECK, HANDSHAKE, Ms, RESEND, RESENDS};
use crate::proto::rekey::Arrival;

/// `Config::fmp().link_age` (`rekey/params.rs:113`).
pub const LINKAGE: Ms = 30_000;
/// `Config::fmp().session_age` (`rekey/params.rs:128`).
pub const SESSIONAGE: Ms = 10_000;
/// `Config::fmp().hold`, how long a responder's pending waits for the
/// initiator's first frame (`rekey/params.rs`).
pub const HOLD: Ms = 120_000;
/// `Config::fmp().drain`, how long the previous session still opens after
/// a cutover.
pub const DRAIN: Ms = 10_000;

/// Where the machine's rekey cycle stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cycle {
    /// No rekey in flight.
    Idle,
    /// This node's own rekey msg1 is out.
    Init {
        hs: Hs,
        next: Ms,
        resends: u32,
        deadline: Ms,
    },
    /// This node answered the peer's rekey and waits for its first frame.
    PendR { hs: Hs, armed: Bytes, deadline: Ms },
    /// This node's own rekey was answered; it cuts over at `at`.
    PendI {
        hs: Hs,
        restarted: Option<Epoch>,
        at: Ms,
    },
}

/// What the machine answers a msg1 with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// A fresh msg2 for handshake `hs`; a pending is armed.
    Msg2(Hs),
    /// The msg2 already sent for handshake `hs`, again.
    Stored(Hs),
    /// Nothing.
    Silent,
    /// The replacement request: the shell runs the restart gates.
    Replace,
}

impl Answer {
    /// The model's reply this answer stands for. A replacement's reply is
    /// the gates', so it has none here.
    pub fn reply(self) -> Option<Reply> {
        match self {
            Self::Msg2(_) => Some(Reply::Msg2),
            Self::Stored(_) => Some(Reply::Stored),
            Self::Silent => Some(Reply::Silent),
            Self::Replace => None,
        }
    }
}

/// What a poll or a frame did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Out {
    /// Send this node's own rekey msg1 of `hs`, again.
    Send(Hs),
    /// Cut over to `hs`.
    Rekeyed {
        /// The new session.
        hs: Hs,
        /// This node started the rekey.
        initiator: bool,
    },
    /// Cut over to `hs`, whose msg2 revealed the peer's restart to
    /// `epoch`; the link is kept.
    Restarted {
        /// The new session.
        hs: Hs,
        /// The peer's new epoch.
        epoch: Epoch,
    },
    /// This node's own rekey reached its deadline unanswered.
    Abandoned,
    /// The responder's pending was never adopted and is dropped.
    Unadopted,
}

/// One held peer's rekey machine, as the world sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RekeySide {
    me: Node,
    peer: Node,
    /// The current session.
    pub cur: Hs,
    /// The peer's epoch on record.
    pub epoch: Epoch,
    link_since: Ms,
    started: Ms,
    /// The setup msg1's exact bytes, when this node answered it.
    setup: Option<(Bytes, Hs)>,
    record: Vec<Hs>,
    cycle: Cycle,
    drain: Option<(Hs, Ms)>,
}

impl RekeySide {
    /// The machine of a peering set up at `now` by handshake `hs`, the
    /// peer at `epoch`; `setup` is the msg1 this node answered, for a
    /// responder.
    pub fn new(me: Node, peer: Node, hs: Hs, epoch: Epoch, now: Ms, setup: Option<Bytes>) -> Self {
        let mut record = Vec::new();
        if setup.is_some() {
            record.push(hs);
        }
        Self {
            me,
            peer,
            cur: hs,
            epoch,
            link_since: now,
            started: now,
            setup: setup.map(|b| (b, hs)),
            record,
            cycle: Cycle::Idle,
            drain: None,
        }
    }

    /// The machine rebuilt on handshake `hs` after a cross-connection
    /// move: the link's age, the session's start and the record are
    /// carried (`impl From<Carry> for SetupFacts`), the cycle is not.
    pub fn moved(&self, hs: Hs) -> Self {
        Self {
            cur: hs,
            cycle: Cycle::Idle,
            drain: None,
            ..self.clone()
        }
    }

    /// Whether frames under `hs` open.
    pub fn holds(&self, hs: Hs) -> bool {
        self.cur == hs
            || self.pending().is_some_and(|(p, _)| p == hs)
            || self.drain.is_some_and(|(d, _)| d == hs)
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

    /// Whether an own rekey may start.
    pub fn idle(&self) -> bool {
        self.cycle == Cycle::Idle
    }

    /// Whether the link and its session are old enough to rekey.
    pub fn eligible(&self, now: Ms) -> bool {
        now.saturating_sub(self.link_since) >= LINKAGE
            && now.saturating_sub(self.started) >= SESSIONAGE
    }

    /// How many ephemerals the record holds.
    pub fn recorded(&self) -> usize {
        self.record.len()
    }

    /// `judge_msg1` and `apply` (`rekey/machine.rs:853-951`, `:1123-1135`):
    /// a same-epoch msg1 from the peer, its class and the answer.
    pub fn msg1(&mut self, now: Ms, hs: Hs, bytes: Bytes, arrival: Arrival) -> (Class, Answer) {
        let eligible = self.eligible(now);
        let armed = match self.cycle {
            Cycle::PendR { hs, armed, .. } => Some((hs, armed)),
            Cycle::Idle | Cycle::Init { .. } | Cycle::PendI { .. } => None,
        };
        #[derive(PartialEq)]
        enum Copied {
            Setup,
            Armed,
            Seen,
            Fresh,
        }
        let copy = if self.setup.is_some_and(|(b, _)| b == bytes) {
            Copied::Setup
        } else if armed.is_some_and(|(_, b)| b == bytes) {
            Copied::Armed
        } else if self.record.contains(&hs) || armed.is_some_and(|(h, _)| h == hs) {
            Copied::Seen
        } else {
            Copied::Fresh
        };
        let fresh = copy == Copied::Fresh;
        if !eligible {
            return match copy {
                Copied::Setup => {
                    let (_, setup) = self.setup.expect("a setup copy has a setup");
                    (Class::Resend, Answer::Stored(setup))
                }
                Copied::Armed | Copied::Seen => (Class::Copy, Answer::Silent),
                Copied::Fresh => {
                    self.record.push(hs);
                    (Class::Replacement, Answer::Replace)
                }
            };
        }
        if !arrival.on_link && arrival.reachable {
            if fresh {
                self.record.push(hs);
            }
            return (Class::OffLink, Answer::Silent);
        }
        match (self.cycle, copy) {
            (Cycle::PendR { .. }, Copied::Armed) => {
                let (h, _) = armed.expect("armed under a responder pending");
                (Class::Pending, Answer::Stored(h))
            }
            (Cycle::PendR { .. } | Cycle::PendI { .. }, Copied::Fresh)
                if fault!(PendingAnswers) =>
            {
                (Class::Pending, self.respond(now, hs, bytes))
            }
            (Cycle::PendR { .. } | Cycle::PendI { .. }, _) => {
                if fresh {
                    self.record.push(hs);
                }
                (Class::Pending, Answer::Silent)
            }
            (Cycle::Idle | Cycle::Init { .. }, Copied::Setup | Copied::Seen | Copied::Armed) => {
                (Class::Recorded, Answer::Silent)
            }
            (Cycle::Init { .. }, Copied::Fresh) => {
                // `resolve(AtAnswer, Unanswered)`: the smaller node keeps
                // its own attempt, the larger yields it.
                if self.me < self.peer {
                    self.record.push(hs);
                    (Class::Simultaneous, Answer::Silent)
                } else {
                    (Class::Simultaneous, self.respond(now, hs, bytes))
                }
            }
            (Cycle::Idle, Copied::Fresh) => (Class::Rekey, self.respond(now, hs, bytes)),
        }
    }

    /// Answer the peer's rekey and hold its pending (`respond`, from
    /// `rekey/machine.rs:1380`).
    fn respond(&mut self, now: Ms, hs: Hs, bytes: Bytes) -> Answer {
        self.cycle = Cycle::PendR {
            hs,
            armed: bytes,
            deadline: now + HOLD,
        };
        Answer::Msg2(hs)
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
            deadline: now + HANDSHAKE,
        };
        true
    }

    /// The msg2 of this node's own rekey `hs`, carrying the peer's
    /// `epoch`; false when it answers nothing in flight.
    pub fn msg2(&mut self, now: Ms, hs: Hs, epoch: Epoch) -> bool {
        if self.rekey() != Some(hs) {
            return false;
        }
        let restarted = (epoch != self.epoch).then_some(epoch);
        self.cycle = Cycle::PendI {
            hs,
            restarted,
            at: now + CHECK,
        };
        true
    }

    /// A frame under `hs` opened (`frame`, from `rekey/machine.rs:1790`):
    /// under the pending session, the cutover.
    pub fn frame(&mut self, now: Ms, hs: Hs) -> Option<Out> {
        match self.cycle {
            Cycle::PendR { hs: p, .. } if p == hs => Some(self.cut(now, hs, false, None)),
            Cycle::PendI {
                hs: p, restarted, ..
            } if p == hs => Some(self.cut(now, hs, true, restarted)),
            Cycle::Idle | Cycle::Init { .. } | Cycle::PendR { .. } | Cycle::PendI { .. } => None,
        }
    }

    fn cut(&mut self, now: Ms, hs: Hs, initiator: bool, restarted: Option<Epoch>) -> Out {
        self.drain = Some((self.cur, now + DRAIN));
        self.cur = hs;
        self.started = now;
        self.cycle = Cycle::Idle;
        if !self.record.contains(&hs) {
            self.record.push(hs);
        }
        match restarted {
            Some(epoch) => {
                self.epoch = epoch;
                self.link_since = now;
                Out::Restarted { hs, epoch }
            }
            None => Out::Rekeyed { hs, initiator },
        }
    }

    /// This node's own answered rekey cuts over now, not one check after
    /// its reply: the model's explicit cutover event.
    pub fn cutover(&mut self, now: Ms) -> Option<Out> {
        match self.cycle {
            Cycle::PendI { hs, restarted, .. } => Some(self.cut(now, hs, true, restarted)),
            Cycle::Idle | Cycle::Init { .. } | Cycle::PendR { .. } => None,
        }
    }

    /// What is due at `now` (`poll`, from `rekey/machine.rs:2161`).
    pub fn poll(&mut self, now: Ms) -> Vec<Out> {
        let mut out = Vec::new();
        if self.drain.is_some_and(|(_, t)| now >= t) {
            self.drain = None;
        }
        match self.cycle {
            Cycle::Init { deadline, .. } if now >= deadline => {
                self.cycle = Cycle::Idle;
                out.push(Out::Abandoned);
            }
            Cycle::Init {
                hs,
                next,
                resends,
                deadline,
            } if now >= next && resends < RESENDS => {
                self.cycle = Cycle::Init {
                    hs,
                    next: now + (RESEND << (resends + 1)),
                    resends: resends + 1,
                    deadline,
                };
                out.push(Out::Send(hs));
            }
            Cycle::PendI { hs, restarted, at } if now >= at => {
                out.push(self.cut(now, hs, true, restarted));
            }
            Cycle::PendR { hs, deadline, .. } if now >= deadline => {
                self.record.push(hs);
                self.cycle = Cycle::Idle;
                out.push(Out::Unadopted);
            }
            Cycle::Idle | Cycle::Init { .. } | Cycle::PendI { .. } | Cycle::PendR { .. } => {}
        }
        out
    }

    /// The earliest instant something is due.
    pub fn wake(&self) -> Option<Ms> {
        let cycle = match self.cycle {
            Cycle::Init {
                next,
                resends,
                deadline,
                ..
            } => Some(if resends < RESENDS {
                next.min(deadline)
            } else {
                deadline
            }),
            Cycle::PendR { deadline, .. } => Some(deadline),
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

#[cfg(test)]
mod checks {
    use alloc::vec::Vec;

    use super::super::super::model::history::{Addr, Binding, Event, LinkId};
    use super::super::super::model::judge::{Judge, Params, Transition};
    use super::*;

    const SMALL: Node = Node(1);
    const LARGE: Node = Node(2);
    const E1: Epoch = Epoch(1);
    /// Long enough for the link and its session to be eligible.
    const AGED: Ms = 30_000;

    fn at(port: u16) -> Addr {
        Addr {
            transport: 1,
            at: port,
        }
    }

    fn msg1(hs: u32, bytes: u32, link: u32, from: Addr, binding: Binding) -> Event {
        Event::Msg1 {
            hs: Hs(hs),
            bytes: Bytes(bytes),
            epoch: E1,
            link: LinkId(link),
            from,
            binding,
            sent: true,
        }
    }

    /// The model's installing msg1 and first frame, as the model tests'
    /// responder: handshake 10, bytes 100, link 1, from `at(9)`.
    fn responder() -> [Event; 2] {
        [
            msg1(10, 100, 1, at(9), Binding::Connectionless),
            Event::Frame {
                hs: Hs(10),
                from: at(9),
            },
        ]
    }

    /// What one step decided: the msg1's class and reply, and the peer
    /// change.
    type Got = (Option<Class>, Option<Reply>, Option<Transition>);

    /// Runs `history` through the model and through a rekey side set up
    /// by its first msg1, and returns both decisions at every later msg1
    /// and frame. A msg1 is on the link when it comes from the setup
    /// address, and the link is reachable until a close at that address.
    fn both(me: Node, peer: Node, history: &[Event]) -> Vec<(Got, Got)> {
        let mut j = Judge::new(me, peer, Params::default());
        let mut side: Option<(RekeySide, Addr)> = None;
        let mut closed = Vec::new();
        let mut now: Ms = 0;
        let mut out = Vec::new();
        for &ev in history {
            let s = j.step(ev);
            let model = (s.class, s.reply, s.change);
            match (ev, side.as_mut()) {
                (Event::Advance(ms), _) => now += ms,
                (Event::Close { at }, _) => closed.push(at),
                (
                    Event::Msg1 {
                        hs, bytes, from, ..
                    },
                    None,
                ) => {
                    side = Some((RekeySide::new(me, peer, hs, E1, now, Some(bytes)), from));
                }
                (
                    Event::Msg1 {
                        hs, bytes, from, ..
                    },
                    Some((r, setup)),
                ) => {
                    let arrival = Arrival {
                        on_link: from == *setup,
                        reachable: !closed.contains(setup),
                    };
                    let (class, answer) = r.msg1(now, hs, bytes, arrival);
                    out.push((model, (Some(class), answer.reply(), None)));
                }
                (Event::Frame { hs, .. }, Some((r, _))) => {
                    let change = match r.frame(now, hs) {
                        Some(Out::Rekeyed { .. }) => Some(Transition::RekeyCutover),
                        Some(Out::Restarted { .. }) => Some(Transition::Restarted),
                        Some(Out::Send(_) | Out::Abandoned | Out::Unadopted) | None => None,
                    };
                    out.push((model, (None, None, change)));
                }
                (Event::RekeyStart { hs }, Some((r, _))) => {
                    assert!(r.start(now, hs), "precondition: the own rekey starts");
                }
                _ => {}
            }
        }
        out
    }

    /// Compares the model's frame decisions on the change alone, since a
    /// frame has no class or reply.
    fn agree(name: &str, steps: &[(Got, Got)]) {
        assert!(
            !steps.is_empty(),
            "{name}: precondition: something was compared"
        );
        for (i, (model, side)) in steps.iter().enumerate() {
            let model = if side.0.is_none() {
                (None, None, model.2)
            } else {
                *model
            };
            assert_eq!(
                &model, side,
                "{name}: step {i}: the model, then the rekey side"
            );
        }
    }

    #[test]
    fn the_rekey_side_agrees_with_the_model_on_every_rule_3_and_4_history() {
        // The rule 3.1, 3.2 and 4.1 to 4.5 histories of the model's own
        // classification tests (`model/tests/classify.rs`), in its order.
        let r = responder();
        let cl = Binding::Connectionless;
        let histories: Vec<(&str, Node, Node, Vec<Event>)> = alloc::vec![
            (
                "3.1 a resend of the setup msg1",
                SMALL,
                LARGE,
                alloc::vec![r[0], r[1], Event::Advance(500), msg1(10, 100, 1, at(9), cl)],
            ),
            (
                "3.2 a copy with a rewritten header",
                SMALL,
                LARGE,
                alloc::vec![r[0], r[1], Event::Advance(500), msg1(10, 101, 1, at(9), cl)],
            ),
            (
                "4.1 off a reachable link",
                SMALL,
                LARGE,
                alloc::vec![
                    r[0],
                    r[1],
                    Event::Advance(AGED),
                    msg1(11, 110, 2, at(8), cl)
                ],
            ),
            (
                "4.1 off an unreachable link",
                SMALL,
                LARGE,
                alloc::vec![
                    msg1(10, 100, 1, at(9), Binding::Connected),
                    Event::Frame {
                        hs: Hs(10),
                        from: at(9),
                    },
                    Event::Advance(AGED),
                    Event::Close { at: at(9) },
                    msg1(11, 110, 2, at(8), Binding::Connected),
                ],
            ),
            (
                "4.2 only the arming msg1 is answered while pending",
                SMALL,
                LARGE,
                alloc::vec![
                    r[0],
                    r[1],
                    Event::Advance(AGED),
                    msg1(11, 110, 1, at(9), cl),
                    msg1(11, 110, 1, at(9), cl),
                    msg1(12, 120, 1, at(9), cl),
                ],
            ),
            (
                "4.3 an eligible copy the record holds",
                SMALL,
                LARGE,
                alloc::vec![
                    r[0],
                    r[1],
                    Event::Advance(AGED),
                    msg1(10, 101, 1, at(9), cl)
                ],
            ),
            (
                "4.4 during an own rekey, the smaller node",
                SMALL,
                LARGE,
                alloc::vec![
                    r[0],
                    r[1],
                    Event::Advance(AGED),
                    Event::RekeyStart { hs: Hs(20) },
                    msg1(11, 110, 1, at(9), cl),
                ],
            ),
            (
                "4.4 during an own rekey, the larger node",
                LARGE,
                SMALL,
                alloc::vec![
                    r[0],
                    r[1],
                    Event::Advance(AGED),
                    Event::RekeyStart { hs: Hs(20) },
                    msg1(11, 110, 1, at(9), cl),
                ],
            ),
            (
                "4.5 the peer's rekey, and its first frame",
                SMALL,
                LARGE,
                alloc::vec![
                    r[0],
                    r[1],
                    Event::Advance(AGED),
                    msg1(11, 110, 1, at(9), cl),
                    Event::Frame {
                        hs: Hs(11),
                        from: at(9),
                    },
                ],
            ),
        ];
        for (name, me, peer, history) in &histories {
            agree(name, &both(*me, *peer, history));
        }
    }
}
