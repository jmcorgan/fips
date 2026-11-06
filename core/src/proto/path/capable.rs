//! The capability record of one link: the capability probes sent to a
//! peer not yet known to implement multipath, the one outstanding, and
//! when the next may go (multipath v1 draft, Section 5.2).
//!
//! The first `budget` probes are spread over `span`; after them the gap
//! starts at `span` and doubles after each unanswered probe up to `cap`.
//! Only one is outstanding at a time. The count is the link's and never
//! starts again: a new link starts a new record. The record is reported
//! unanswered once, when the last probe of the first round times out.
//!
//! A capability probe draws its `probe_id` from the original path's
//! sequence but is held here, outside the path's ring, so its timeout
//! never counts toward the path's liveness. When it times out, or when
//! the peer turns capable some other way, the machine hands it to the
//! path's record of timed-out probes, so a late answer still gives a
//! round trip (Section 5.6). Sans-IO, with no allocation.

use super::live::Sent;
use super::params::Config;
use super::wire::PATH_PROBE_MIN_SIZE;
use crate::time::{Duration, Instant, backoff, deadline};

/// The capability probes of one link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability<I> {
    /// Capability probes sent on the link.
    sent: u32,
    /// The one outstanding, with our `path_id` of the path it went on.
    out: Option<(u32, Sent<I>)>,
    /// When the next may go; `None` for at once.
    next_at: Option<I>,
    /// Whether the first round has been reported unanswered.
    told: bool,
}

impl<I: Instant> Capability<I> {
    /// Capability probes sent on the link.
    pub fn sent(&self) -> u32 {
        self.sent
    }

    /// When the next capability probe may go; `None` for at once.
    pub fn next_at(&self) -> Option<I> {
        self.next_at
    }

    /// Whether the first round has been reported unanswered.
    pub fn told(&self) -> bool {
        self.told
    }

    /// The record of a new link: nothing sent, the first probe due at once.
    pub(super) fn new() -> Self {
        Self {
            sent: 0,
            out: None,
            next_at: None,
            told: false,
        }
    }

    /// The gap after the `sent`-th capability probe, counted from 1: an
    /// even share of `span` while `sent` is below `budget`, and then
    /// `span` doubled once for each probe past the first round, up to
    /// `cap` (draft Section 5.2).
    pub(super) fn gap(sent: u32, cfg: &Config) -> Duration {
        let budget = u32::from(cfg.budget);
        if sent < budget {
            cfg.span / budget
        } else {
            backoff(sent - budget, cfg.span, cfg.cap)
        }
    }

    /// Whether a capability probe may go at `now`: none is outstanding and
    /// the gap after the last has passed.
    pub(super) fn due(&self, now: I) -> bool {
        self.out.is_none() && self.next_at.is_none_or(|at| at <= now)
    }

    /// Record a capability probe sent at `now` on our path `path` with
    /// `probe_id`, unanswered after `timeout`, and schedule the next.
    pub(super) fn send(
        &mut self,
        now: I,
        path: u32,
        probe_id: u32,
        timeout: Duration,
        cfg: &Config,
    ) {
        self.sent = self.sent.saturating_add(1);
        let sent = Sent {
            probe_id,
            at: now,
            due: deadline(now, timeout),
            len: PATH_PROBE_MIN_SIZE,
        };
        self.out = Some((path, sent));
        self.next_at = Some(deadline(now, Self::gap(self.sent, cfg)));
    }

    /// Time out the outstanding probe if it was due at or before `now`, or
    /// with `overdue` strictly before it, and return it, with whether its
    /// timeout ends the first round unanswered, which is true once.
    pub(super) fn expire(
        &mut self,
        now: I,
        overdue: bool,
        cfg: &Config,
    ) -> Option<(Sent<I>, bool)> {
        let (_, sent) = self.out?;
        if sent.due > now || (overdue && sent.due == now) {
            return None;
        }
        self.out = None;
        let round = !self.told && self.sent >= u32::from(cfg.budget);
        self.told |= round;
        Some((sent, round))
    }

    /// Match an answer from the peer naming our path `path` and
    /// `probe_id`: the outstanding probe, taken if it is the one. A probe
    /// that timed out is no longer held here.
    pub(super) fn answer(&mut self, path: u32, probe_id: u32) -> Option<Sent<I>> {
        let (on, sent) = self.out?;
        if on != path || sent.probe_id != probe_id {
            return None;
        }
        self.out = None;
        Some(sent)
    }

    /// Take the outstanding probe, as the peer turns capable.
    pub(super) fn take(&mut self) -> Option<Sent<I>> {
        self.out.take().map(|(_, sent)| sent)
    }

    /// The instant the record has work: the outstanding probe's timeout,
    /// else, while a candidate makes the link `eligible`, the next probe's
    /// time. `None` when neither applies, or when the next probe is due at
    /// once.
    pub(super) fn wake(&self, eligible: bool) -> Option<I> {
        match self.out {
            Some((_, sent)) => Some(sent.due),
            None if eligible => self.next_at,
            None => None,
        }
    }
}

#[cfg(test)]
#[path = "tests/capable.rs"]
mod tests;
