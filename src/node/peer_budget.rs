//! Per-link-peer token budget.
//!
//! A budget limits how fast one authenticated link peer may make this node do
//! something on its behalf. Every field of a datagram is chosen by whoever sent
//! it, so a per-destination or per-source gate can be escaped by varying the
//! field it is keyed on. The one value an attacker cannot mint is the
//! authenticated link peer the frame arrived from, whose cardinality is bounded
//! by the peer table and by admission. Each budget is keyed on it.
//!
//! The routing-error instance bounds induced routing-error emissions (a transit
//! node synthesizes CoordsRequired, PathBroken or MtuExceeded in response to a
//! datagram it could not forward). It is consulted ahead of any address-keyed
//! structure so that those structures only grow at the budget rate.
//!
//! The coordinate-hint instance pays for the coordinate-cache space a link
//! peer's hints take, in units of cache weight. A newly seen peer starts it
//! empty, so a fresh link identity buys nothing, and a peer that stays
//! connected keeps what it accrues while quiet. Its buckets are dropped when
//! their peer leaves the peer table ([`PeerBudget::sweep_departed`]).

use crate::NodeAddr;
use crate::cache::ADDRS_PER_ENTRY;
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

/// Sustained rate, in units of coordinate-cache weight per second, at which one
/// authenticated link peer pays for the hints it writes.
///
/// A unit is one stored coordinate address, and an entry costs at least
/// [`ADDRS_PER_ENTRY`], so this is 64 new destinations a second of depth up to
/// sixteen, fewer when deeper. At this rate one peer needs about 781 seconds to
/// turn over the default cache's 800,000 units, more than the entry TTL, so it
/// cannot push out an honest entry that traffic keeps using. Lower places an
/// honest hub's new destinations in probation sooner; higher lets one peer turn
/// the cache over faster. The budget is per link peer, so an attacker holding
/// `k` links pays at `k` times this rate (about six seconds of main turnover at
/// 128 peers); admission and `max_peers` bound `k`. No measured basis for the
/// honest rate behind one hub peer.
pub const COORD_HINT_WEIGHT_PER_SEC: u32 = 64 * ADDRS_PER_ENTRY as u32;

/// The most coordinate-cache weight one link peer accrues while quiet.
///
/// 256 destinations of depth up to sixteen. A newly seen peer starts with
/// none ([`COORD_HINT_INITIAL_WEIGHT`]), so this is earned by four quiet
/// seconds, not bought by a new link identity, and kept while the peer stays
/// in the peer table. An attacker holding `k` links can spend `k` times this
/// at once, once each has accrued it. No measured basis.
pub const COORD_HINT_WEIGHT_BURST: u32 = 256 * ADDRS_PER_ENTRY as u32;

/// The coordinate-cache weight a newly seen link peer starts with.
///
/// Zero, so reconnecting under a fresh identity buys nothing: at the stranger
/// handshake rate a full first bucket would buy thousands of units a second.
pub const COORD_HINT_INITIAL_WEIGHT: u32 = 0;

/// Tokens are carried in thousandths so the refill of a sub-millisecond
/// interval is not rounded away.
const MILLI: u64 = 1000;

/// How often buckets are swept to bound the map across peer churn.
///
/// Where a newly seen peer starts full, a full bucket carries no state worth
/// keeping and is dropped. Where it starts below full, a full bucket is what
/// the peer accrued, so only the buckets of peers that have left are dropped.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// One peer's token bucket.
struct Bucket {
    /// Remaining tokens, in thousandths of a signal.
    milli_tokens: u64,
    /// When `milli_tokens` was last brought up to date.
    last_refill: Instant,
}

/// Token-bucket budget keyed on the authenticated link peer that is spending
/// it.
pub struct PeerBudget {
    buckets: HashMap<NodeAddr, Bucket>,
    /// Refill rate in thousandths of a token per millisecond.
    milli_per_ms: u64,
    /// Bucket ceiling, in thousandths of a token.
    capacity: u64,
    /// What a newly seen peer's bucket starts with, in thousandths of a token.
    initial: u64,
    last_sweep: Instant,
}

impl PeerBudget {
    /// Create a routing-error budget at the shipped rate and burst.
    pub fn new() -> Self {
        Self::with_rate(PEER_ERROR_RATE_PER_SEC, PEER_ERROR_BURST)
    }

    /// Create a budget with an explicit sustained rate and burst, where a
    /// newly seen peer starts with a full bucket.
    pub fn with_rate(per_sec: u32, burst: u32) -> Self {
        Self::with_initial(per_sec, burst, burst)
    }

    /// Create a budget where a newly seen peer starts with `initial` tokens
    /// (at most `burst`).
    ///
    /// A dropped bucket comes back at `initial`, and is dropped only when it
    /// holds at least that, so a peer gains nothing by leaving and returning.
    /// Below `burst`, a connected peer's full bucket is kept; the owner drops
    /// departed peers' buckets with [`Self::sweep_departed`].
    pub fn with_initial(per_sec: u32, burst: u32, initial: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            milli_per_ms: u64::from(per_sec),
            capacity: u64::from(burst) * MILLI,
            initial: u64::from(initial.min(burst)) * MILLI,
            last_sweep: crate::time::mono_now(),
        }
    }

    /// Create the budget link peers pay coordinate-cache hints from.
    pub fn coord_hints() -> Self {
        Self::with_initial(
            COORD_HINT_WEIGHT_PER_SEC,
            COORD_HINT_WEIGHT_BURST,
            COORD_HINT_INITIAL_WEIGHT,
        )
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

    /// Whole tokens `peer` has to spend, without spending any.
    pub fn available(&mut self, peer: &NodeAddr, now: Instant) -> u64 {
        self.sweep(now);
        self.refill(peer, now);
        self.buckets.get(peer).map_or(0, |b| b.milli_tokens / MILLI)
    }

    /// Spend `tokens` for `peer`. The caller spends only what
    /// [`Self::available`] said it could, so this never overspends.
    pub fn spend(&mut self, peer: &NodeAddr, tokens: u64, now: Instant) {
        self.refill(peer, now);
        if let Some(bucket) = self.buckets.get_mut(peer) {
            let cost = tokens.saturating_mul(MILLI);
            debug_assert!(cost <= bucket.milli_tokens, "spent more than available");
            bucket.milli_tokens = bucket.milli_tokens.saturating_sub(cost);
        }
        self.sweep(now);
    }

    /// Bring `peer`'s bucket up to date, creating one at the initial fill on
    /// first sighting.
    fn refill(&mut self, peer: &NodeAddr, now: Instant) {
        let capacity = self.capacity;
        let milli_per_ms = self.milli_per_ms;
        let initial = self.initial;
        let bucket = self.buckets.entry(*peer).or_insert(Bucket {
            milli_tokens: initial,
            last_refill: now,
        });
        let elapsed_ms = now
            .saturating_duration_since(bucket.last_refill)
            .as_millis() as u64;
        if elapsed_ms > 0 {
            bucket.milli_tokens = (bucket.milli_tokens + elapsed_ms * milli_per_ms).min(capacity);
            // Advance by the whole milliseconds credited, not to `now`, so the
            // part of a millisecond left over counts toward the next refill.
            bucket.last_refill += Duration::from_millis(elapsed_ms);
        }
    }

    /// Drop full buckets, at most once per [`SWEEP_INTERVAL`], where a newly
    /// seen peer starts full. A budget that starts peers below full keeps
    /// them: a full bucket there is a connected peer's accrued tokens, and its
    /// owner sweeps departed peers instead.
    fn sweep(&mut self, now: Instant) {
        if self.initial < self.capacity {
            return;
        }
        let capacity = self.capacity;
        self.sweep_where(now, |_, tokens| tokens >= capacity);
    }

    /// Drop the buckets of peers `present` says have left, at most once per
    /// [`SWEEP_INTERVAL`], keeping any that hold less than a newly seen peer
    /// starts with (dropping one would refill it).
    pub fn sweep_departed(&mut self, now: Instant, present: impl Fn(&NodeAddr) -> bool) {
        let initial = self.initial;
        self.sweep_where(now, |peer, tokens| !present(peer) && tokens >= initial);
    }

    /// Drop the buckets `drop` accepts, given each one's tokens (in
    /// thousandths) brought up to `now`, at most once per [`SWEEP_INTERVAL`].
    fn sweep_where(&mut self, now: Instant, drop: impl Fn(&NodeAddr, u64) -> bool) {
        if now.saturating_duration_since(self.last_sweep) < SWEEP_INTERVAL {
            return;
        }
        self.last_sweep = now;
        let capacity = self.capacity;
        let milli_per_ms = self.milli_per_ms;
        self.buckets.retain(|peer, b| {
            let elapsed_ms = now.saturating_duration_since(b.last_refill).as_millis() as u64;
            let tokens = (b.milli_tokens + elapsed_ms * milli_per_ms).min(capacity);
            !drop(peer, tokens)
        });
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }
}

impl Default for PeerBudget {
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
    fn spend(budget: &mut PeerBudget, peer: &NodeAddr, now: Instant) -> bool {
        if !budget.has_token(peer, now) {
            return false;
        }
        budget.commit(peer, now);
        true
    }

    #[test]
    fn a_peer_may_emit_its_full_burst_then_is_suppressed() {
        let mut budget = PeerBudget::new();
        let now = Instant::now();
        let peer = addr(1);

        for i in 0..PEER_ERROR_BURST {
            assert!(spend(&mut budget, &peer, now), "burst signal {i} refused");
        }
        assert!(!spend(&mut budget, &peer, now));
    }

    #[test]
    fn an_exhausted_budget_refills_at_the_sustained_rate() {
        let mut budget = PeerBudget::new();
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
        let mut budget = PeerBudget::new();
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
        let mut budget = PeerBudget::with_rate(1, 1);
        let now = Instant::now();
        let peer = addr(1);

        assert!(budget.has_token(&peer, now));
        assert!(budget.has_token(&peer, now));
        budget.commit(&peer, now);
        assert!(!budget.has_token(&peer, now));
    }

    #[test]
    fn full_buckets_are_dropped_by_the_sweep() {
        let mut budget = PeerBudget::new();
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

    #[test]
    fn a_budget_with_no_initial_fill_starts_a_new_peer_empty_and_refills_it() {
        let mut budget = PeerBudget::with_initial(1_000, 4_000, 0);
        let start = Instant::now();
        let peer = addr(1);
        assert_eq!(budget.available(&peer, start), 0);
        assert_eq!(
            budget.available(&peer, start + Duration::from_millis(250)),
            250
        );
        assert_eq!(
            budget.available(&peer, start + Duration::from_secs(60)),
            4_000
        );
    }

    #[test]
    fn spend_takes_exactly_the_tokens_it_is_given() {
        let mut budget = PeerBudget::with_initial(1, 100, 100);
        let now = Instant::now();
        let peer = addr(1);
        budget.spend(&peer, 37, now);
        assert_eq!(budget.available(&peer, now), 63);
        budget.spend(&peer, 0, now);
        assert_eq!(budget.available(&peer, now), 63);
        budget.spend(&peer, 63, now);
        assert_eq!(budget.available(&peer, now), 0);
    }

    #[test]
    fn a_departed_peers_bucket_is_swept_and_comes_back_at_the_initial_fill_not_full() {
        let mut budget = PeerBudget::with_initial(100, 100, 0);
        let start = Instant::now();
        let peer = addr(1);
        assert_eq!(budget.available(&peer, start), 0);

        // Gone long enough to refill to full, then a sweep drops the bucket.
        let later = start + SWEEP_INTERVAL + Duration::from_secs(1);
        budget.sweep_departed(later, |p| *p != peer);
        assert_eq!(budget.len(), 0, "the departed peer's bucket was swept");
        assert_eq!(budget.available(&peer, later), 0);
    }

    #[test]
    fn a_quiet_peer_keeps_the_burst_it_accrued_across_a_sweep() {
        let mut budget = PeerBudget::coord_hints();
        let start = Instant::now();
        let (hub, other) = (addr(1), addr(2));
        assert_eq!(budget.available(&hub, start), 0);
        assert_eq!(budget.available(&other, start), 0);
        let burst = u64::from(COORD_HINT_WEIGHT_BURST);
        assert_eq!(
            budget.available(&hub, start + Duration::from_secs(5)),
            burst
        );

        // Another peer's spend runs the sweep while the hub is still connected.
        let later = start + SWEEP_INTERVAL + Duration::from_secs(1);
        budget.spend(&other, 16, later);
        assert_eq!(
            budget.available(&hub, later),
            burst,
            "the quiet hub lost the burst it accrued"
        );
    }

    #[test]
    fn buckets_of_departed_peers_are_swept_without_a_spend() {
        let mut budget = PeerBudget::coord_hints();
        let start = Instant::now();
        // One frame each from 1,000 successive link identities, each gone
        // before the next arrives; nothing is paid. The owner sweeps departed
        // peers ahead of each read, as the hint path does.
        for i in 0..1_000u32 {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&i.to_le_bytes());
            let peer = NodeAddr::from_bytes(bytes);
            let now = start + (SWEEP_INTERVAL * 2) * i;
            budget.sweep_departed(now, |p| *p == peer);
            assert_eq!(budget.available(&peer, now), 0);
        }
        assert!(
            budget.len() <= 2,
            "{} buckets kept for departed peers",
            budget.len()
        );
    }

    #[test]
    fn a_departed_peer_holding_less_than_a_new_peer_starts_with_is_kept() {
        // Dropping it would hand the peer a refill on return.
        let mut budget = PeerBudget::with_initial(0, 100, 50);
        let start = Instant::now();
        let peer = addr(1);
        budget.spend(&peer, 40, start);
        let later = start + SWEEP_INTERVAL + Duration::from_secs(1);
        budget.sweep_departed(later, |_| false);
        assert_eq!(budget.available(&peer, later), 10);
    }

    #[test]
    fn the_routing_error_budget_still_drops_full_buckets_on_read() {
        let mut budget = PeerBudget::new();
        let start = Instant::now();
        assert!(spend(&mut budget, &addr(1), start));
        let later = start + SWEEP_INTERVAL + Duration::from_secs(1);
        let _ = budget.available(&addr(2), later);
        assert_eq!(budget.len(), 1, "only the reader's bucket is left");
    }

    #[test]
    fn the_routing_error_budget_still_starts_a_new_peer_full() {
        let mut budget = PeerBudget::new();
        assert_eq!(
            budget.available(&addr(1), Instant::now()),
            u64::from(PEER_ERROR_BURST)
        );
    }

    #[test]
    fn reads_a_millisecond_and_a_half_apart_accrue_the_configured_rate() {
        let mut budget = PeerBudget::with_initial(1_024, 1_000_000, 0);
        let peer = addr(7);
        let start = Instant::now();
        let _ = budget.available(&peer, start);
        for i in 1..=1_000u64 {
            let _ = budget.available(&peer, start + Duration::from_micros(1_500 * i));
        }
        // 1.5 s at 1,024 a second.
        let got = budget.available(&peer, start + Duration::from_micros(1_500_000));
        assert!(got >= 1_535, "accrued {got} of 1,536");
    }

    #[test]
    fn a_hub_relaying_sixty_four_destinations_a_second_accrues_the_coordinate_rate() {
        // One frame every 15.625 ms, two hint reads per frame.
        let mut budget = PeerBudget::coord_hints();
        let peer = addr(8);
        let start = Instant::now();
        let _ = budget.available(&peer, start);
        for i in 1..=64u64 {
            let t = start + Duration::from_micros(15_625 * i);
            let _ = budget.available(&peer, t);
            let _ = budget.available(&peer, t);
        }
        let got = budget.available(&peer, start + Duration::from_secs(1));
        assert_eq!(
            got,
            u64::from(COORD_HINT_WEIGHT_PER_SEC),
            "accrued in one second"
        );
    }
}
