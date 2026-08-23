//! Per-link-peer budget for induced routing-error emissions.
//!
//! A transit node synthesizes a routing error (CoordsRequired, PathBroken or
//! MtuExceeded) in response to a datagram it could not forward. Every field of
//! that datagram is chosen by whoever sent it, so a per-destination or
//! per-source gate can be escaped by varying the field it is keyed on. The one
//! value at the emission point an attacker cannot mint is the authenticated
//! link peer the frame arrived from, whose cardinality is bounded by the peer
//! table and by admission. This budget is keyed on it, and is consulted ahead
//! of any address-keyed structure so that those structures only grow at the
//! budget rate.

use crate::NodeAddr;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Sustained rate, in signals per second, at which one authenticated link peer
/// may induce this node to emit routing errors.
///
/// Bounds the reflection an admitted peer can aim at a victim it names, and
/// bounds how fast that peer can grow the per-destination limiter's map.
/// Raising it costs proportionally more reflected traffic per peer; lowering it
/// silences a hub peer that relays many sources through a genuine outage
/// sooner, which costs those sources their CoordsRequired and their
/// path-MTU feedback.
pub const PEER_ERROR_RATE_PER_SEC: u32 = 20;

/// Number of routing errors one link peer may induce back to back before the
/// sustained rate applies.
///
/// Sized so that an ordinary burst of unroutable traffic behind one peer still
/// signals promptly. Raising it lets a peer front-load a larger reflection;
/// lowering it makes a legitimate convergence burst arrive as a trickle.
pub const PEER_ERROR_BURST: u32 = 50;

/// Tokens are carried in thousandths so the refill of a sub-millisecond
/// interval is not rounded away.
const MILLI: u64 = 1000;

/// A peer whose bucket has refilled to full carries no state worth keeping, so
/// entries are dropped once per this interval to bound the map across peer
/// churn.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// One peer's token bucket.
struct Bucket {
    /// Remaining tokens, in thousandths of a signal.
    milli_tokens: u64,
    /// When `milli_tokens` was last brought up to date.
    last_refill: Instant,
}

/// Token-bucket budget for routing errors, keyed on the authenticated link
/// peer that induced them.
pub struct PeerErrorBudget {
    buckets: HashMap<NodeAddr, Bucket>,
    /// Refill rate in thousandths of a token per millisecond.
    milli_per_ms: u64,
    /// Bucket ceiling, in thousandths of a token.
    capacity: u64,
    last_sweep: Instant,
}

impl PeerErrorBudget {
    /// Create a budget at the shipped rate and burst.
    pub fn new() -> Self {
        Self::with_rate(PEER_ERROR_RATE_PER_SEC, PEER_ERROR_BURST)
    }

    /// Create a budget with an explicit sustained rate and burst.
    pub fn with_rate(per_sec: u32, burst: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            milli_per_ms: u64::from(per_sec),
            capacity: u64::from(burst) * MILLI,
            last_sweep: Instant::now(),
        }
    }

    /// Whether `peer` has a token to spend, without spending it.
    ///
    /// Separate from [`Self::commit`] so a signal that a later gate suppresses
    /// does not consume budget: an outage behind a high-fanout peer would
    /// otherwise spend that peer's whole budget on emissions the
    /// per-destination interval discards, silencing every other destination
    /// behind it.
    pub fn has_token(&mut self, peer: &NodeAddr, now: Instant) -> bool {
        self.refill(peer, now);
        self.buckets
            .get(peer)
            .is_some_and(|b| b.milli_tokens >= MILLI)
    }

    /// Spend one token for `peer`. Call only on the path that actually emits.
    pub fn commit(&mut self, peer: &NodeAddr, now: Instant) {
        self.refill(peer, now);
        if let Some(bucket) = self.buckets.get_mut(peer) {
            bucket.milli_tokens = bucket.milli_tokens.saturating_sub(MILLI);
        }
        self.sweep(now);
    }

    /// Bring `peer`'s bucket up to date, creating a full one on first sighting.
    fn refill(&mut self, peer: &NodeAddr, now: Instant) {
        let capacity = self.capacity;
        let milli_per_ms = self.milli_per_ms;
        let bucket = self.buckets.entry(*peer).or_insert(Bucket {
            milli_tokens: capacity,
            last_refill: now,
        });
        let elapsed_ms = now
            .saturating_duration_since(bucket.last_refill)
            .as_millis() as u64;
        if elapsed_ms > 0 {
            bucket.milli_tokens = (bucket.milli_tokens + elapsed_ms * milli_per_ms).min(capacity);
            bucket.last_refill = now;
        }
    }

    /// Drop full buckets, at most once per [`SWEEP_INTERVAL`].
    fn sweep(&mut self, now: Instant) {
        if now.saturating_duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        let capacity = self.capacity;
        let milli_per_ms = self.milli_per_ms;
        self.buckets.retain(|_, b| {
            let elapsed_ms = now.saturating_duration_since(b.last_refill).as_millis() as u64;
            b.milli_tokens + elapsed_ms * milli_per_ms < capacity
        });
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }
}

impl Default for PeerErrorBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    /// Spend one token per admitted emission.
    fn spend(budget: &mut PeerErrorBudget, peer: &NodeAddr, now: Instant) -> bool {
        if !budget.has_token(peer, now) {
            return false;
        }
        budget.commit(peer, now);
        true
    }

    #[test]
    fn a_peer_may_emit_its_full_burst_then_is_suppressed() {
        let mut budget = PeerErrorBudget::new();
        let now = Instant::now();
        let peer = addr(1);

        for i in 0..PEER_ERROR_BURST {
            assert!(spend(&mut budget, &peer, now), "burst signal {i} refused");
        }
        assert!(!spend(&mut budget, &peer, now));
    }

    #[test]
    fn an_exhausted_budget_refills_at_the_sustained_rate() {
        let mut budget = PeerErrorBudget::new();
        let start = Instant::now();
        let peer = addr(1);

        for _ in 0..PEER_ERROR_BURST {
            assert!(spend(&mut budget, &peer, start));
        }
        assert!(!spend(&mut budget, &peer, start));

        // One second of refill buys exactly the sustained rate back.
        let later = start + Duration::from_secs(1);
        for i in 0..PEER_ERROR_RATE_PER_SEC {
            assert!(
                spend(&mut budget, &peer, later),
                "refilled signal {i} refused"
            );
        }
        assert!(!spend(&mut budget, &peer, later));
    }

    #[test]
    fn one_peer_exhausting_its_budget_does_not_silence_another() {
        let mut budget = PeerErrorBudget::new();
        let now = Instant::now();
        let noisy = addr(1);
        let quiet = addr(2);

        for _ in 0..PEER_ERROR_BURST {
            assert!(spend(&mut budget, &noisy, now));
        }
        assert!(!spend(&mut budget, &noisy, now));
        assert!(spend(&mut budget, &quiet, now));
    }

    #[test]
    fn peeking_does_not_spend_a_token() {
        let mut budget = PeerErrorBudget::with_rate(1, 1);
        let now = Instant::now();
        let peer = addr(1);

        assert!(budget.has_token(&peer, now));
        assert!(budget.has_token(&peer, now));
        budget.commit(&peer, now);
        assert!(!budget.has_token(&peer, now));
    }

    #[test]
    fn full_buckets_are_dropped_by_the_sweep() {
        let mut budget = PeerErrorBudget::new();
        let start = Instant::now();
        for i in 0..50u8 {
            assert!(spend(&mut budget, &addr(i), start));
        }
        assert_eq!(budget.len(), 50);

        // Long enough for every bucket to have refilled to full.
        let later = start + SWEEP_INTERVAL + Duration::from_secs(1);
        assert!(spend(&mut budget, &addr(200), later));
        assert_eq!(budget.len(), 1);
    }
}
