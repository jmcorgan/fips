//! This node's inbox relay list (kind 10050): when it is next republished,
//! and the publish in flight. Peers look up lists no older than 30 days,
//! and a relay that was down at start-up has not seen ours at all, so once
//! subscribed the node republishes it every day.

use fips_core::time::{Instant, deadline};

use super::params::INBOX_REPUBLISH;
use super::rendezvous::io::ReqId;

/// Why the inbox relay list is being published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// The start-up sequence's publish, after the subscribe.
    Startup,
    /// The daily republish.
    Republish,
}

/// Our inbox relay list's schedule.
#[derive(Debug)]
pub struct Lists<I> {
    republish_at: Option<I>,
    sending: Option<(ReqId, Purpose)>,
}

impl<I: Instant> Lists<I> {
    /// No list sent and none scheduled.
    pub fn new() -> Self {
        Self {
            republish_at: None,
            sending: None,
        }
    }

    /// The publish `req` is sending the list.
    pub fn sending(&mut self, req: ReqId, purpose: Purpose) {
        self.sending = Some((req, purpose));
    }

    /// The publish `req` ended. Returns its purpose if it was the one in
    /// flight.
    pub fn sent(&mut self, req: ReqId) -> Option<Purpose> {
        match self.sending {
            Some((sending, purpose)) if sending == req => {
                self.sending = None;
                Some(purpose)
            }
            _ => None,
        }
    }

    /// Republish a day after `now`.
    pub fn schedule(&mut self, now: I) {
        self.republish_at = Some(deadline(now, INBOX_REPUBLISH));
    }

    /// Whether the republish is due at `now`; if so, the next one is set a
    /// day after `now`, when this one is issued.
    pub fn due(&mut self, now: I) -> bool {
        if self.republish_at.is_some_and(|at| at <= now) {
            self.schedule(now);
            true
        } else {
            false
        }
    }

    /// The next republish.
    pub fn deadline(&self) -> Option<I> {
        self.republish_at
    }
}
