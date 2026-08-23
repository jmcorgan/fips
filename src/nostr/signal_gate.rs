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
//! has to be advanced by a timer. It does its whole decision under one
//! `std::sync::Mutex` and never awaits inside it, as `offer_admission` does;
//! moving anything awaited inside that lock would hold it across a decrypt.

use std::sync::Mutex;
use std::time::Instant;

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
const SIGNAL_RATE_PER_SEC: f64 = 5.0;

/// Burst capacity of the shared allowance, in signals.
const SIGNAL_BURST: f64 = 20.0;

/// Sustained rate of the reserve, drawn only while this node has traversals
/// of its own outstanding.
///
/// It is sized like the shared allowance rather than smaller because the case
/// it exists for is onboarding fanout: a node that has just sent offers to
/// tens of peers receives their answers back in a burst, and shedding those
/// looks to an operator like relay flakiness. Lowering it re-exposes that
/// case; raising it lets a flood arriving while we happen to be mid-traversal
/// buy more decrypt work than the shared allowance alone would.
const ANSWER_RESERVE_RATE_PER_SEC: f64 = 5.0;

/// Burst capacity of the reserve, in signals.
const ANSWER_RESERVE_BURST: f64 = 20.0;

/// Which allowance refused an inbound signal.
///
/// The two are different operator stories: the first says the node shed a
/// signal while it had nothing of its own in flight, the second says a flood
/// is now deep enough to reach traversals this node started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SignalShed {
    /// The shared allowance is exhausted.
    Shared,
    /// The shared allowance and the answer reserve are both exhausted.
    Reserve,
}

/// One token bucket, refilled from the caller's clock.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    burst: f64,
    rate_per_sec: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate_per_sec: f64, burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            burst,
            rate_per_sec,
            last: now,
        }
    }

    /// Advance the bucket to `now`, capped at its burst.
    fn refill(&mut self, now: Instant) {
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
pub(super) struct SignalGate {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    shared: Bucket,
    reserve: Bucket,
}

impl SignalGate {
    /// Build a gate whose buckets start full as of `now`.
    pub(super) fn new(now: Instant) -> Self {
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
        now: Instant,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner {
                shared: Bucket::new(shared_rate, shared_burst, now),
                reserve: Bucket::new(reserve_rate, reserve_burst, now),
            }),
        }
    }

    /// Take one signal's worth of allowance, or say which bucket refused it.
    ///
    /// `awaiting_answers` says whether this node has traversals of its own
    /// outstanding; only then may the reserve be drawn. The shared bucket is
    /// always tried first, so the reserve is spent only on what the flood
    /// would otherwise have shed.
    pub(super) fn admit(&self, awaiting_answers: bool, now: Instant) -> Result<(), SignalShed> {
        let mut inner = self.inner.lock().expect("signal-gate mutex poisoned");
        inner.shared.refill(now);
        if inner.shared.ready() {
            inner.shared.take();
            return Ok(());
        }
        if !awaiting_answers {
            return Err(SignalShed::Shared);
        }
        inner.reserve.refill(now);
        if inner.reserve.ready() {
            inner.reserve.take();
            return Ok(());
        }
        Err(SignalShed::Reserve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_flood_is_admitted_up_to_the_burst_and_shed_after_it() {
        let start = Instant::now();
        let gate = SignalGate::new(start);

        let admitted = (0..1000)
            .filter(|_| gate.admit(false, start).is_ok())
            .count();

        assert_eq!(admitted, SIGNAL_BURST as usize);
        assert_eq!(gate.admit(false, start), Err(SignalShed::Shared));
    }

    #[test]
    fn tokens_refill_so_a_steady_legitimate_signal_rate_is_never_shed() {
        let start = Instant::now();
        let gate = SignalGate::new(start);

        // One second per iteration at exactly the sustained rate, for long
        // enough that an arithmetic error in the refill drains the bucket.
        for second in 0..100u64 {
            let now = start + Duration::from_secs(second);
            for signal in 0..SIGNAL_RATE_PER_SEC as usize {
                assert_eq!(
                    gate.admit(false, now),
                    Ok(()),
                    "signal {signal} of second {second} should be admitted"
                );
            }
        }
    }

    #[test]
    fn a_flood_cannot_shed_the_answers_to_traversals_this_node_started() {
        let start = Instant::now();
        let gate = SignalGate::new(start);

        // The flood arrives while this node has nothing outstanding, so it
        // cannot reach the reserve at all.
        for _ in 0..1000 {
            let _ = gate.admit(false, start);
        }
        assert_eq!(gate.admit(false, start), Err(SignalShed::Shared));

        let admitted = (0..1000)
            .filter(|_| gate.admit(true, start).is_ok())
            .count();
        assert_eq!(admitted, ANSWER_RESERVE_BURST as usize);
        assert_eq!(gate.admit(true, start), Err(SignalShed::Reserve));
    }

    #[test]
    fn the_reserve_is_untouched_while_the_shared_allowance_still_has_tokens() {
        let start = Instant::now();
        let gate = SignalGate::new(start);

        // Every one of these is inside the shared burst, so none of them may
        // spend the reserve even though the caller is entitled to it.
        for _ in 0..SIGNAL_BURST as usize {
            assert_eq!(gate.admit(true, start), Ok(()));
        }

        let reserve_admitted = (0..1000)
            .filter(|_| gate.admit(true, start).is_ok())
            .count();
        assert_eq!(reserve_admitted, ANSWER_RESERVE_BURST as usize);
    }
}
