//! Handshake legs: each initial handshake in flight, with its deadline,
//! its resend schedule and the session index it holds.
//!
//! A dial leg is this node's own initial handshake: it holds the msg1 it
//! sent, resends it byte for byte (FRC-1201 Section 5.8) one resend
//! interval after the dial and then at doubling intervals up to the
//! configured count, and is reaped at its handshake deadline. A responder
//! leg holds the msg1 it answered and the msg2 it built, answers a resend
//! of that msg1 with the same msg2, and is reaped at its deadline too. Each
//! deadline is counted from the leg's start, so a leg cannot outlive it
//! whatever clock the frames it sees were stamped by.
//!
//! Every leg holds a session index lease from the start, and the lease
//! leaves only with the leg: taken with it when the handshake completes,
//! returned with it when it is reaped, and returned by [`Legs::close`],
//! so no index leaks. Reaping or closing a leg retires its link by the
//! close rule.
//!
//! A resend is committed only once the shell reports it sent
//! ([`Legs::resent`]), as the current node commits one; a failed send is
//! tried again at the next poll.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::links::{LinkNo, Links, Pair};
use super::params::{Params, backoff, deadline};
use crate::identity::NodeAddr;
use crate::proto::rekey::IndexLease;
use crate::time::{Duration, Instant};

/// Which end a leg is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// This node's own dial.
    Dial,
    /// This node's answer to the peer's msg1, holding the msg2 it built.
    Answer {
        /// The msg2, byte for byte.
        msg2: Vec<u8>,
    },
}

/// One handshake in flight.
#[derive(Debug, PartialEq, Eq)]
pub struct Leg<I> {
    link: LinkNo,
    peer: Option<NodeAddr>,
    kind: Kind,
    msg1: Vec<u8>,
    sent: u32,
    next: Option<I>,
    deadline: I,
    lease: IndexLease,
}

impl<I: Instant> Leg<I> {
    /// The leg's link.
    pub fn link(&self) -> LinkNo {
        self.link
    }

    /// The identity the leg dialed or learned, if known.
    pub fn peer(&self) -> Option<NodeAddr> {
        self.peer
    }

    /// Which end it is.
    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    /// The msg1 it sent or answered.
    pub fn msg1(&self) -> &[u8] {
        &self.msg1
    }

    /// When it is reaped.
    pub fn deadline(&self) -> I {
        self.deadline
    }

    /// Give the leg up for its lease: the handshake completed, and the
    /// index is the new session's.
    pub fn lease(self) -> IndexLease {
        self.lease
    }

    /// When the leg next needs a poll.
    fn wake(&self) -> I {
        match self.next {
            Some(n) if n < self.deadline => n,
            Some(_) | None => self.deadline,
        }
    }
}

/// What starts a leg.
#[derive(Debug, PartialEq, Eq)]
pub struct Start {
    /// The link the handshake runs on.
    pub link: LinkNo,
    /// The identity dialed, or learned from the msg1, if known.
    pub peer: Option<NodeAddr>,
    /// The msg1 this node sent, or the one it answered, byte for byte.
    pub msg1: Vec<u8>,
    /// The session index the leg holds.
    pub lease: IndexLease,
}

/// What a poll asks of the shell.
#[derive(Debug, PartialEq, Eq)]
pub enum LegOut {
    /// Send this dial's msg1 again, byte for byte, and report it with
    /// [`Legs::resent`] once it is sent.
    Resend {
        /// The leg's link.
        link: LinkNo,
        /// The msg1.
        bytes: Vec<u8>,
    },
    /// The leg reached its deadline. Its link is retired, these
    /// connections close, and the lease returns to the allocator.
    Reaped {
        /// The leg's link.
        link: LinkNo,
        /// The identity it dialed or learned, if known.
        peer: Option<NodeAddr>,
        /// Whether it was this node's own dial.
        dialed: bool,
        /// The connections the link's retirement closes.
        closes: Vec<Pair>,
        /// The leg's lease.
        lease: IndexLease,
    },
}

/// What [`Legs::close`] returns.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Closed {
    /// Every leg's lease.
    pub leases: Vec<IndexLease>,
    /// The connections the legs' links' retirement closes.
    pub closes: Vec<Pair>,
}

/// Every handshake leg in flight, by link.
#[derive(Debug, PartialEq, Eq)]
pub struct Legs<I> {
    legs: BTreeMap<LinkNo, Leg<I>>,
}

impl<I> Default for Legs<I> {
    fn default() -> Self {
        Self {
            legs: BTreeMap::new(),
        }
    }
}

/// Whether `at` has come by `now`.
fn due<I: Instant>(at: I, now: I) -> bool {
    if fault!(PollAhead) {
        return now
            .checked_add(Duration::from_millis(1))
            .is_none_or(|ahead| at <= ahead);
    }
    at <= now
}

impl<I: Instant> Legs<I> {
    /// No legs.
    pub fn new() -> Self {
        Self::default()
    }

    /// This node dialed at `now`, as `start` says. Returns a leg the link
    /// already held, which the caller must give up, since a link holds
    /// one leg.
    #[must_use]
    pub fn dial(&mut self, start: Start, now: I, params: &Params) -> Option<Leg<I>> {
        let next = (params.resends > 0).then(|| deadline(now, params.resend));
        self.open(start, Kind::Dial, next, now, params)
    }

    /// This node answered the peer's msg1 with `msg2` at `now`, as `start`
    /// says. Returns a leg the link already held, as [`Legs::dial`] does.
    #[must_use]
    pub fn answer(
        &mut self,
        start: Start,
        msg2: Vec<u8>,
        now: I,
        params: &Params,
    ) -> Option<Leg<I>> {
        self.open(start, Kind::Answer { msg2 }, None, now, params)
    }

    fn open(
        &mut self,
        start: Start,
        kind: Kind,
        next: Option<I>,
        now: I,
        params: &Params,
    ) -> Option<Leg<I>> {
        let leg = Leg {
            link: start.link,
            peer: start.peer,
            kind,
            msg1: start.msg1,
            sent: 0,
            next,
            deadline: deadline(now, params.handshake),
            lease: start.lease,
        };
        self.legs.insert(start.link, leg)
    }

    /// The leg on `link`.
    pub fn get(&self, link: LinkNo) -> Option<&Leg<I>> {
        self.legs.get(&link)
    }

    /// Take the leg on `link` away: its handshake completed or was
    /// superseded, and the caller now holds its lease.
    pub fn take(&mut self, link: LinkNo) -> Option<Leg<I>> {
        self.legs.remove(&link)
    }

    /// The msg2 a responder leg on `link` answers a copy of `msg1` with:
    /// the one it stored, byte for byte. `None` when the leg is not a
    /// responder leg of that msg1.
    pub fn stored(&self, link: LinkNo, msg1: &[u8]) -> Option<&[u8]> {
        let leg = self.legs.get(&link)?;
        match &leg.kind {
            Kind::Answer { msg2 } if leg.msg1 == msg1 && !fault!(AnswerFresh) => Some(msg2),
            Kind::Answer { .. } | Kind::Dial => None,
        }
    }

    /// The msg2 a responder leg on `link` stored, whatever msg1 asks.
    pub fn msg2(&self, link: LinkNo) -> Option<&[u8]> {
        match &self.legs.get(&link)?.kind {
            Kind::Answer { msg2 } if !fault!(AnswerFresh) => Some(msg2),
            Kind::Answer { .. } | Kind::Dial => None,
        }
    }

    /// The resend [`Legs::poll`] asked for on `link` was sent at `now`:
    /// count it and schedule the next, at twice the last interval.
    pub fn resent(&mut self, link: LinkNo, now: I, params: &Params) {
        let Some(leg) = self.legs.get_mut(&link) else {
            return;
        };
        leg.sent = leg.sent.saturating_add(1);
        leg.next = (leg.sent < params.resends)
            .then(|| deadline(now, backoff(leg.sent, params.resend, Duration::MAX)));
    }

    /// How many responder legs are in flight.
    pub fn answering(&self) -> usize {
        self.legs
            .values()
            .filter(|l| matches!(l.kind, Kind::Answer { .. }))
            .count()
    }

    /// When the earliest leg next needs a poll.
    pub fn next_wake(&self) -> Option<I> {
        self.legs.values().map(Leg::wake).min()
    }

    /// The resends due and the legs past their deadline at `now`. A
    /// reaped leg's link is retired from `links`.
    pub fn poll(&mut self, now: I, links: &mut Links) -> Vec<LegOut> {
        let reaped: Vec<LinkNo> = self
            .legs
            .values()
            .filter(|l| due(l.deadline, now) && !fault!(LegNeverReaped))
            .map(|l| l.link)
            .collect();
        let mut out = Vec::new();
        for link in reaped {
            if let Some(leg) = self.legs.remove(&link) {
                out.push(LegOut::Reaped {
                    link,
                    peer: leg.peer,
                    dialed: leg.kind == Kind::Dial,
                    closes: links.retire(link),
                    lease: leg.lease,
                });
            }
        }
        for leg in self.legs.values() {
            if leg.next.is_some_and(|n| due(n, now)) {
                let mut bytes = leg.msg1.clone();
                if fault!(ResendFresh) {
                    bytes.push(0);
                }
                out.push(LegOut::Resend {
                    link: leg.link,
                    bytes,
                });
            }
        }
        out
    }

    /// Close every leg: each lease is returned and each link retired.
    pub fn close(&mut self, links: &mut Links) -> Closed {
        let mut closed = Closed::default();
        let keep = if fault!(LeaseKept) {
            self.legs.keys().next().copied()
        } else {
            None
        };
        let all = core::mem::take(&mut self.legs);
        for (link, leg) in all {
            closed.closes.extend(links.retire(link));
            if Some(link) == keep {
                self.legs.insert(link, leg);
            } else {
                closed.leases.push(leg.lease);
            }
        }
        closed
    }
}

#[cfg(test)]
#[path = "tests/legs.rs"]
mod tests;
