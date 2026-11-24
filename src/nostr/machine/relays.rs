//! The node's relay subscriptions: the two it opens at start (traversal
//! signals addressed to it on its DM relays, and every advert on its advert
//! relays), and the retry of a subscribe that failed, after 2 s, doubling
//! to 60 s. The subscription ids are fixed when the book is made, so a
//! retry names the subscriptions the first attempt did.

use core::time::Duration;

use fips_core::time::{Instant, deadline};

use super::params::{SUBSCRIBE_RETRY_FIRST, SUBSCRIBE_RETRY_MAX};
use super::rendezvous::io::{ReqId, SubId};

/// Where the start-up sequence stands: subscribe, then publish the inbox
/// relay list, then either done or a retry of the whole sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The subscribe `ReqId` is running.
    Subscribing(ReqId),
    /// The subscribe ended, accepted or not, and the inbox relay list is
    /// being published.
    Publishing { subscribed: bool },
    /// The subscribe failed; the sequence runs again at the retry deadline.
    Waiting,
    /// Subscribed; nothing more to do.
    Subscribed,
}

/// The subscriptions and the start-up sequence's state.
#[derive(Debug)]
pub struct Book<I> {
    /// The traversal signals addressed to this node.
    pub signals: SubId,
    /// Every advert.
    pub adverts: SubId,
    phase: Phase,
    retry_delay: Duration,
    retry_at: Option<I>,
}

impl<I: Instant> Book<I> {
    /// The book for the subscriptions `signals` and `adverts`, whose first
    /// subscribe is `req`.
    pub fn new(signals: SubId, adverts: SubId, req: ReqId) -> Self {
        Self {
            signals,
            adverts,
            phase: Phase::Subscribing(req),
            retry_delay: SUBSCRIBE_RETRY_FIRST,
            retry_at: None,
        }
    }

    /// A retry's subscribe, `req`, is running.
    pub fn retrying(&mut self, req: ReqId) {
        self.phase = Phase::Subscribing(req);
    }

    /// The subscribe `req` ended, accepted or not. Returns whether it was
    /// the one running.
    pub fn subscribed(&mut self, req: ReqId, accepted: bool) -> bool {
        if self.phase != Phase::Subscribing(req) {
            return false;
        }
        self.phase = Phase::Publishing {
            subscribed: accepted,
        };
        true
    }

    /// The inbox relay list publish after a subscribe ended at `now`.
    /// Returns whether the subscribe had been accepted; if not, the retry
    /// is set, each one waiting twice as long as the last, up to 60 s.
    pub fn published(&mut self, now: I) -> bool {
        let Phase::Publishing { subscribed } = self.phase else {
            return false;
        };
        if subscribed {
            self.phase = Phase::Subscribed;
            return true;
        }
        self.phase = Phase::Waiting;
        self.retry_at = Some(deadline(now, self.retry_delay));
        self.retry_delay = self.retry_delay.saturating_mul(2).min(SUBSCRIBE_RETRY_MAX);
        false
    }

    /// Whether the retry is due at `now`; if so, it is taken.
    pub fn retry_due(&mut self, now: I) -> bool {
        if self.retry_at.is_some_and(|at| at <= now) {
            self.retry_at = None;
            true
        } else {
            false
        }
    }

    /// The retry deadline, while one is set.
    pub fn deadline(&self) -> Option<I> {
        self.retry_at
    }
}
