//! Handshake legs: each initial handshake in flight, with its deadline,
//! its resend schedule and the session index it holds.
//!
//! A dial leg is this node's own initial handshake: it holds the msg1 it
//! sent, resends it byte for byte (FRC-1201 Section 5.8) a second after
//! the dial, as the node does whatever its configured interval, and then at
//! waits of the configured interval growing by the configured multiplier, up to the configured count or the dial's own lower cap, and
//! is reaped at its handshake deadline. A responder
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
//! ([`Legs::resent`]), as the current node commits one. A failed send
//! ([`Legs::unsent`]) is tried again at the next poll, whatever its
//! instant, as the node re-arms a failed resend for its next tick; the
//! wake the leg reports meanwhile is one [`Params::retry`] on, so it is
//! never in the past.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::links::{LinkNo, Links, Pair};
use super::params::{Params, deadline};
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
    resends: u32,
    next: Option<I>,
    /// A resend's send failed: it is due at the next poll, and `next` is
    /// only the wake reported meanwhile.
    retry: bool,
    deadline: I,
    lease: IndexLease,
    held: Option<LinkNo>,
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

    /// For a dial, the link the peer was held on when the dial's link
    /// opened; `None` for a dial of a peer not held then, and for an
    /// answer.
    pub fn held(&self) -> Option<LinkNo> {
        self.held
    }

    /// How many resends it has sent.
    pub fn sent(&self) -> u32 {
        self.sent
    }

    /// How many resends it may send in all.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn resends(&self) -> u32 {
        self.resends
    }

    /// When its next resend is scheduled, if one is: `None` for an answer
    /// and for a dial with every resend sent.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn next_resend(&self) -> Option<I> {
        self.next
    }

    /// Whether a poll at `now` resends its msg1: a resend that could not be
    /// sent, or one scheduled at or before `now`.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn resend_due(&self, now: I) -> bool {
        self.retry || self.next.is_some_and(|n| due(n, now))
    }

    /// The session index its lease holds.
    pub fn index(&self) -> u32 {
        self.lease.index()
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
    /// A cap on this dial's msg1 resends below the configured count
    /// ([`Params::resends`]), or `None` for the configured count. The
    /// node caps a dial an mDNS advert directs at a node it is not
    /// configured to dial (its `DISCOVERY_RESENDS`); an answer resends
    /// nothing, so it gives `None`.
    pub resends: Option<u32>,
    /// For a dial, the link the peer was held on when the dial's link
    /// opened, as the node notes it at the dial (`note_held`); `None` for
    /// a peer not held then, and for an answer.
    pub held: Option<LinkNo>,
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
        let cap = match start.resends {
            Some(c) if !fault!(OriginIgnored) && !node_fault!(OriginIgnored) => {
                c.min(params.resends)
            }
            Some(_) | None => params.resends,
        };
        let first = if fault!(FirstResendAtInterval) || node_fault!(FirstResendAtInterval) {
            params.resend
        } else {
            params.first
        };
        let next = (cap > 0).then(|| deadline(now, first));
        self.open(start, Kind::Dial, cap, next, now, params)
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
        self.open(start, Kind::Answer { msg2 }, 0, None, now, params)
    }

    fn open(
        &mut self,
        start: Start,
        kind: Kind,
        resends: u32,
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
            resends,
            next,
            retry: false,
            deadline: deadline(now, params.handshake),
            lease: start.lease,
            held: start.held,
        };
        self.legs.insert(start.link, leg)
    }

    /// Every leg, by link.
    pub fn iter(&self) -> impl Iterator<Item = &Leg<I>> {
        self.legs.values()
    }

    /// The leg on `link`.
    pub fn get(&self, link: LinkNo) -> Option<&Leg<I>> {
        self.legs.get(&link)
    }

    /// Give the leg on `link` its own reaping instant and next resend, for
    /// a shell's resync of a handshake a test planted past its writers with
    /// instants of its own.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn replant(&mut self, link: LinkNo, deadline: I, next: Option<I>) {
        if let Some(leg) = self.legs.get_mut(&link) {
            leg.deadline = deadline;
            leg.next = next;
        }
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
    /// count it and schedule the next, [`Params::wait`] later.
    pub fn resent(&mut self, link: LinkNo, now: I, params: &Params) {
        let Some(leg) = self.legs.get_mut(&link) else {
            return;
        };
        leg.retry = false;
        leg.sent = leg.sent.saturating_add(1);
        leg.next = (leg.sent < leg.resends).then(|| deadline(now, params.wait(leg.sent)));
    }

    /// The resend [`Legs::poll`] asked for on `link` could not be sent at
    /// `now`: it is not counted, it is due again at the next poll, and the
    /// leg's wake is one [`Params::retry`] on. A responder leg, or a dial
    /// with every resend already sent (no next resend scheduled, whatever
    /// cap stopped it), has none to try again.
    pub fn unsent(&mut self, link: LinkNo, now: I, params: &Params) {
        let Some(leg) = self.legs.get_mut(&link) else {
            return;
        };
        let capped = leg.next.is_none() && !fault!(UnsentPastCap) && !node_fault!(UnsentPastCap);
        if leg.kind != Kind::Dial || capped {
            return;
        }
        if fault!(UnsentStaysDue) || node_fault!(UnsentStaysDue) {
            return;
        }
        leg.retry = !(fault!(UnsentDueAtWake) || node_fault!(UnsentDueAtWake));
        leg.next = Some(deadline(now, params.retry));
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
        let mut out = Vec::new();
        self.reap(now, None, links, &mut out);
        for leg in self.legs.values() {
            if leg.retry || leg.next.is_some_and(|n| due(n, now)) {
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

    /// [`Legs::poll`]'s reap of the leg on `link` alone at `now`, if it is
    /// past its deadline then, and no resend: for a shell that times its
    /// answers out at a sweep of its own, and for a shell's comparison that
    /// asks whether the core would reap a leg its shell is reaping.
    pub fn reap_one(&mut self, link: LinkNo, now: I, links: &mut Links) -> Vec<LegOut> {
        let mut out = Vec::new();
        self.reap(now, Some(link), links, &mut out);
        out
    }

    /// Reap into `out` the legs past their deadline at `now`, or only the
    /// one on `only`, retiring each one's link from `links`.
    fn reap(&mut self, now: I, only: Option<LinkNo>, links: &mut Links, out: &mut Vec<LegOut>) {
        let reaped: Vec<LinkNo> = self
            .legs
            .values()
            .filter(|l| only.is_none_or(|o| o == l.link))
            .filter(|l| due(l.deadline, now) && !fault!(LegNeverReaped))
            .map(|l| l.link)
            .collect();
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
