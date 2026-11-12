//! Rate limiting for inbound traversal signals, ahead of any cryptography.
//!
//! The notify loop used to hand every kind-21059 event straight to
//! `unwrap_signal_event`, which is two NIP-44 decrypts and a signature verify,
//! on the single task that also routes answers and processes adverts. Nothing
//! bounded how fast an unauthenticated stranger could schedule that work, and
//! the per-npub offer admission cannot: it keys on the sender's public key,
//! which only exists once the first decrypt has already run.
//!
//! **What can be keyed on, and what cannot.** Before decryption there is no
//! sender identity at all. The outer event is signed by a key generated per
//! event, so bucketing on its author hands an attacker a fresh allowance for
//! free, and `created_at` and the p-tag are equally attacker-chosen. The relay
//! the event arrived over is drawn from our own configured set, but it is not
//! an isolation boundary either: an attacker publishes to the same relays the
//! honest peer does, and a duplicate event is attributed to whichever relay
//! won the delivery race. So the shared allowance here is deliberately a
//! single global bucket, and it is indiscriminate by construction.
//!
//! **What the reserve is for.** An indiscriminate limit sheds our own
//! traversals along with the attacker's, and since the attacker sets the rate,
//! every retry lands in the same shed. The second bucket is drawn only while
//! this node has traversals of its own outstanding, so a flood costs a node
//! its inbound offers, which is irreducible without a pre-decrypt identity,
//! rather than also costing it the answers to offers it sent.
//!
//! **Lock discipline.** `admit` takes `now` as a parameter rather than reading
//! the clock, so the type is testable without sleeping and holds no state that
//! has to be advanced by a timer. It takes instants of any
//! `fips_core::time::Instant` type and holds no lock: the runtime keeps the
//! gate behind one `std::sync::Mutex`, makes its whole decision under it, and
//! never awaits inside it, as `offer_admission` does; moving anything awaited
//! inside that lock would hold it across a decrypt.

use fips_core::time::Instant;

/// Sustained inbound traversal signals per second admitted for decryption,
/// across all senders and relays.
///
/// A traversal exchange is a handful of events (one offer and one answer per
/// attempt), and the signal subscription is opened with `limit(0)` so relays
/// replay no stored backlog, which means there is no legitimate burst larger
/// than the number of peers bootstrapping in the same second. Raising this
/// buys a larger rendezvous hub headroom at the cost of handing an attacker
/// the same multiple of decrypt work; lowering it starts shedding honest
/// signals on a busy node, which shows up in the log as the shed counter
/// rather than as silence.
pub(crate) const SIGNAL_RATE_PER_SEC: f64 = 5.0;

/// Burst capacity of the shared allowance, in signals.
pub(crate) const SIGNAL_BURST: f64 = 20.0;

/// Sustained rate of the reserve, drawn only while this node has traversals
/// of its own outstanding.
///
/// It is sized like the shared allowance rather than smaller because the case
/// it exists for is onboarding fanout: a node that has just sent offers to
/// tens of peers receives their answers back in a burst, and shedding those
/// looks to an operator like relay flakiness. Lowering it re-exposes that
/// case; raising it lets a flood arriving while we happen to be mid-traversal
/// buy more decrypt work than the shared allowance alone would.
pub(crate) const ANSWER_RESERVE_RATE_PER_SEC: f64 = 5.0;

/// Burst capacity of the reserve, in signals.
pub(crate) const ANSWER_RESERVE_BURST: f64 = 20.0;

/// Which allowance refused an inbound signal.
///
/// The two are different operator stories: the first says the node shed a
/// signal while it had nothing of its own in flight, the second says a flood
/// is now deep enough to reach traversals this node started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalShed {
    /// The shared allowance is exhausted.
    Shared,
    /// The shared allowance and the answer reserve are both exhausted.
    Reserve,
}

/// One token bucket, refilled from the caller's clock.
#[derive(Debug)]
struct Bucket<I> {
    tokens: f64,
    burst: f64,
    rate_per_sec: f64,
    last: I,
}

impl<I: Instant> Bucket<I> {
    fn new(rate_per_sec: f64, burst: f64, now: I) -> Self {
        Self {
            tokens: burst,
            burst,
            rate_per_sec,
            last: now,
        }
    }

    /// Advance the bucket to `now`, capped at its burst.
    fn refill(&mut self, now: I) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.burst);
            self.last = now;
        }
    }

    /// Whether a whole token is available, without taking it.
    fn ready(&self) -> bool {
        self.tokens >= 1.0
    }

    fn take(&mut self) {
        self.tokens -= 1.0;
    }
}

/// The pre-decrypt allowance for inbound traversal signals.
#[derive(Debug)]
pub struct SignalGate<I> {
    shared: Bucket<I>,
    reserve: Bucket<I>,
}

impl<I: Instant> SignalGate<I> {
    /// Build a gate whose buckets start full as of `now`.
    pub fn new(now: I) -> Self {
        Self::with_limits(
            SIGNAL_RATE_PER_SEC,
            SIGNAL_BURST,
            ANSWER_RESERVE_RATE_PER_SEC,
            ANSWER_RESERVE_BURST,
            now,
        )
    }

    fn with_limits(
        shared_rate: f64,
        shared_burst: f64,
        reserve_rate: f64,
        reserve_burst: f64,
        now: I,
    ) -> Self {
        Self {
            shared: Bucket::new(shared_rate, shared_burst, now),
            reserve: Bucket::new(reserve_rate, reserve_burst, now),
        }
    }

    /// Take one signal's worth of allowance, or say which bucket refused it.
    ///
    /// `awaiting_answers` says whether this node has traversals of its own
    /// outstanding; only then may the reserve be drawn. The shared bucket is
    /// always tried first, so the reserve is spent only on what the flood
    /// would otherwise have shed.
    pub fn admit(&mut self, awaiting_answers: bool, now: I) -> Result<(), SignalShed> {
        self.shared.refill(now);
        if self.shared.ready() {
            self.shared.take();
            return Ok(());
        }
        if !awaiting_answers {
            return Err(SignalShed::Shared);
        }
        self.reserve.refill(now);
        if self.reserve.ready() {
            self.reserve.take();
            return Ok(());
        }
        Err(SignalShed::Reserve)
    }
}

#[cfg(test)]
#[path = "tests/gate.rs"]
mod tests;
