//! Resend ladders: integer backoff, rung accounting and deadline arithmetic.
//!
//! A schedule is a short ascending list of offsets from an origin, worked
//! out once with integer arithmetic so it is the same on every target
//! (`f64::powi` is not). A ladder is a schedule anchored at an instant with
//! a cursor. A late poll takes every overdue rung at once, which produces
//! one send: the absolute deadline of the state the ladder belongs to bounds
//! how long it runs, not the number of sends.

use crate::time::{Duration, Instant};

/// The most rungs a schedule holds. The longest default is the rekey msg3
/// ladder: four probe rungs and four keepalive-only rungs.
pub(crate) const MAX_RUNGS: usize = 16;

/// `t + d`, or `t` itself past the end of the clock's range.
///
/// At the end of the range a deadline falls due at once. Every expiry is a
/// safe transition, so that is the side to err on, and a 64-bit millisecond
/// clock reaches it after half a billion years.
pub(crate) fn later<I: Instant>(t: I, d: Duration) -> I {
    t.checked_add(d).unwrap_or(t)
}

/// Whole milliseconds in `d`, saturating.
pub(crate) fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// What one rung of a schedule carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rung {
    /// A resend, or for the rekey msg3 ladder a probe rung.
    Send,
    /// A keepalive under the current epoch and nothing else.
    Keepalive,
}

/// Offsets from an origin, ascending, in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Schedule {
    at: [u64; MAX_RUNGS],
    keepalive: u16,
    len: u8,
}

impl Schedule {
    /// No rungs.
    pub(crate) const EMPTY: Self = Self {
        at: [0; MAX_RUNGS],
        keepalive: 0,
        len: 0,
    };

    /// The offset of resend `i` (from 0) of a doubling ladder whose first
    /// interval is `first`: `first`, `3 first`, `7 first`, and so on.
    fn doubled(first: u64, i: usize) -> u64 {
        let factor = 1u64
            .checked_shl(u32::try_from(i + 1).unwrap_or(u32::MAX))
            .map_or(u64::MAX, |p| p - 1);
        first.saturating_mul(factor)
    }

    /// Up to `count` doubling resends with first interval `first`, keeping
    /// only those strictly before `end` when an end is given. Returns the
    /// schedule and how many requested rungs fell at or after the end.
    pub(crate) fn doubling(first: Duration, count: u8, end: Option<Duration>) -> (Self, u8) {
        let first = millis(first).max(1);
        let end = end.map(millis);
        let mut sched = Self::EMPTY;
        let mut dropped = 0u8;
        for i in 0..usize::from(count) {
            let at = Self::doubled(first, i);
            let inside = end.is_none_or(|e| at < e);
            if inside && sched.push(at, Rung::Send) {
                continue;
            }
            dropped = dropped.saturating_add(1);
        }
        (sched, dropped)
    }

    /// The doubling probe rungs of [`Schedule::doubling`] before `end`, with
    /// keepalive-only rungs added wherever two consecutive frames (the
    /// sends at the origin, each probe rung, and finally the end itself)
    /// would be more than `gap` apart. The count returned adds every rung,
    /// probe or keepalive, that did not fit in [`MAX_RUNGS`], so a setting
    /// that loses one is reported rather than silently sent short.
    pub(crate) fn probes(first: Duration, count: u8, end: Duration, gap: Duration) -> (Self, u8) {
        let (sends, mut dropped) = Self::doubling(first, count, Some(end));
        let gap = millis(gap).max(1);
        let mut sched = Self::EMPTY;
        let mut last = 0u64;
        let points = sends.offsets().map(Some).chain(core::iter::once(None));
        for point in points {
            let next = point.unwrap_or(millis(end));
            // Keepalives at `last + i gap` while each is more than `gap`
            // before `next`.
            let late = fault!(KeepaliveLate) && last <= 18_000;
            let fill = if late {
                0
            } else {
                next.saturating_sub(last).saturating_sub(1) / gap
            };
            for i in 1..=fill {
                if !sched.push(last.saturating_add(i.saturating_mul(gap)), Rung::Keepalive) {
                    let rest = u8::try_from(fill - i + 1).unwrap_or(u8::MAX);
                    dropped = dropped.saturating_add(rest);
                    break;
                }
            }
            last = last.saturating_add(fill.saturating_mul(gap));
            if let Some(at) = point {
                if !sched.push(at, Rung::Send) {
                    dropped = dropped.saturating_add(1);
                }
                last = at;
            }
        }
        (sched, dropped)
    }

    /// Append a rung; false when the schedule is full.
    fn push(&mut self, at: u64, rung: Rung) -> bool {
        let i = usize::from(self.len);
        let Some(slot) = self.at.get_mut(i) else {
            return false;
        };
        *slot = at;
        if rung == Rung::Keepalive {
            self.keepalive |= 1 << i;
        }
        self.len += 1;
        true
    }

    /// The offsets in order.
    pub(crate) fn offsets(&self) -> impl Iterator<Item = u64> + '_ {
        self.at.iter().take(usize::from(self.len)).copied()
    }

    /// The number of rungs.
    pub(crate) fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// The offset of the last rung that sends, or `None` when none does.
    pub(crate) fn last_send(&self) -> Option<u64> {
        (0..self.len())
            .rev()
            .find(|&i| self.rung(i) == Rung::Send)
            .and_then(|i| self.at.get(i).copied())
    }

    /// What rung `i` carries.
    fn rung(&self, i: usize) -> Rung {
        if self.keepalive & (1 << i) != 0 {
            Rung::Keepalive
        } else {
            Rung::Send
        }
    }
}

/// What a poll took from a ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Taken {
    /// Some overdue rung was a sending rung (for the msg3 ladder, a probe
    /// rung); otherwise every overdue rung was keepalive-only.
    pub(crate) send: bool,
    /// The offset of the latest overdue rung.
    pub(crate) latest: u64,
    /// No rung is left after this one.
    pub(crate) last: bool,
}

/// A schedule anchored at an instant, with a cursor at the next rung.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ladder<I> {
    origin: I,
    sched: Schedule,
    next: u8,
}

impl<I: Instant> Ladder<I> {
    /// A ladder whose first rung is the schedule's first offset after
    /// `origin`.
    pub(crate) fn new(origin: I, sched: Schedule) -> Self {
        Self {
            origin,
            sched,
            next: 0,
        }
    }

    /// The instant of the next rung, or `None` when every rung is taken.
    pub(crate) fn next_at(&self) -> Option<I> {
        let at = self.sched.at.get(usize::from(self.next))?;
        if self.next >= self.sched.len {
            return None;
        }
        Some(later(self.origin, Duration::from_millis(*at)))
    }

    /// Whether a rung is due at `now`.
    pub(crate) fn due(&self, now: I) -> bool {
        self.next_at().is_some_and(|t| t <= now)
    }

    /// Take every rung due at `now`, or `None` when none is.
    pub(crate) fn take(&mut self, now: I) -> Option<Taken> {
        let mut taken: Option<Taken> = None;
        while self.due(now) {
            let i = usize::from(self.next);
            let send = self.sched.rung(i) == Rung::Send;
            let latest = self.sched.at.get(i).copied().unwrap_or(0);
            taken = Some(Taken {
                send: send || taken.is_some_and(|t| t.send),
                latest,
                last: false,
            });
            self.next += 1;
        }
        taken.map(|t| Taken {
            last: self.next >= self.sched.len,
            ..t
        })
    }
}

#[cfg(test)]
#[path = "tests/ladder.rs"]
mod tests;
