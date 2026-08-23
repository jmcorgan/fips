//! Rate Limiting for FIPS Protocol
//!
//! Provides token bucket rate limiting for protecting against DoS attacks,
//! particularly on the Noise handshake path where msg1 processing involves
//! expensive cryptographic operations.
//!
//! ## Design
//!
//! - Token bucket algorithm with configurable burst and refill rate
//! - Global rate limit (not per-source, since UDP sources are spoofable)
//! - Applied before expensive DH operations in handshake processing
//!
//! ## Default Parameters
//!
//! - Burst capacity: 100 tokens (max concurrent handshakes)
//! - Refill rate: 10 tokens/second (sustained handshake rate)
//! - This allows handling burst traffic while limiting sustained attack impact
//!
//! ## Two buckets, and what the aggregate is
//!
//! Msg1 whose source matches an established link (rekey and restart
//! maintenance traffic) draws on its own bucket rather than competing with
//! stranger admission. It is *metered*, not exempted: an established-peer
//! carve-out is by construction keyed on source address, and the sentence
//! above about spoofable UDP sources is still true, so an off-path attacker
//! who can forge a live peer's `(transport_id, addr)` tuple reaches the
//! second bucket. Metering keeps that exposure bounded.
//!
//! The consequence, stated rather than left implicit: the node's total
//! admitted msg1 rate is the **sum** of the two buckets, not the stranger
//! bucket alone. At shipped defaults that is burst `100 + 128 = 228` and
//! `10.0 + 6.4 = 16.4` msg1/sec, of which the established half is only
//! reachable by a source that already matches a live link. Operators sizing
//! the handshake-crypto ceiling against a host should size against the sum.
//!
//! The concurrency limb (`max_pending`) is deliberately *not* split, so no
//! equivalent inflation happens there: one counter bounds simultaneous
//! in-flight handshake state whoever holds the slot.
//!
//! ## Why the session-setup limiter *is* keyed, when the msg1 limiter is not
//!
//! "Not per-source, since UDP sources are spoofable" is about the FMP link
//! layer, where the source is a transport address on an unauthenticated
//! datagram. [`SessionSetupRateLimiter`] sits a layer up and keys on
//! something different: the FMP link peer the datagram arrived over, which
//! the hop-by-hop Noise AEAD authenticates and whose population is bounded by
//! the peer table. Keying on the FSP `src_addr` instead would be the mistake
//! that sentence warns about, since that field is chosen by the sender and a
//! single sender can mint an unbounded number of distinct values.

use crate::NodeAddr;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Default burst capacity (max tokens).
pub const DEFAULT_BURST_CAPACITY: u32 = 100;

/// Default refill rate (tokens per second).
pub const DEFAULT_REFILL_RATE: f64 = 10.0;

/// Token bucket rate limiter.
///
/// Uses a classic token bucket algorithm where tokens are consumed for each
/// operation and refilled at a constant rate. When tokens are exhausted,
/// operations are rate-limited until tokens refill.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Maximum number of tokens (burst capacity).
    capacity: u32,
    /// Current number of available tokens (may be fractional during refill).
    tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket with default parameters.
    ///
    /// - Burst capacity: 100 tokens
    /// - Refill rate: 10 tokens/second
    pub fn new() -> Self {
        Self::with_params(DEFAULT_BURST_CAPACITY, DEFAULT_REFILL_RATE)
    }

    /// Create a token bucket with custom parameters.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens (burst capacity)
    /// * `refill_rate` - Tokens added per second
    pub fn with_params(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token.
    ///
    /// Returns `true` if a token was available and consumed, `false` if
    /// rate limited (no tokens available).
    pub fn try_acquire(&mut self) -> bool {
        self.try_acquire_n(1)
    }

    /// Try to consume n tokens.
    ///
    /// Returns `true` if n tokens were available and consumed, `false` if
    /// rate limited (insufficient tokens).
    pub fn try_acquire_n(&mut self, n: u32) -> bool {
        self.refill();

        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }

    /// Check if tokens are available without consuming them.
    #[cfg(test)]
    pub fn available(&mut self) -> bool {
        self.refill();
        self.tokens >= 1.0
    }

    /// Get the current number of available tokens.
    #[cfg(test)]
    pub fn tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    /// Get the capacity (max tokens).
    #[cfg(test)]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let elapsed_secs = elapsed.as_secs_f64();

        // Add tokens based on time elapsed
        self.tokens += elapsed_secs * self.refill_rate;

        // Cap at capacity
        if self.tokens > self.capacity as f64 {
            self.tokens = self.capacity as f64;
        }

        self.last_refill = now;
    }

    /// Reset to full capacity.
    #[cfg(test)]
    pub fn reset(&mut self) {
        self.tokens = self.capacity as f64;
        self.last_refill = Instant::now();
    }

    /// Time until the next token is available.
    ///
    /// Returns `Duration::ZERO` if tokens are available, otherwise the
    /// estimated time until one token will be available.
    #[cfg(test)]
    pub fn time_until_available(&mut self) -> std::time::Duration {
        self.refill();

        if self.tokens >= 1.0 {
            std::time::Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            let secs = needed / self.refill_rate;
            std::time::Duration::from_secs_f64(secs)
        }
    }
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Floor on the derived established-link refill rate, in tokens/second.
///
/// Covers the degenerate case of a very long (or effectively disabled)
/// rekey period, where a node must still admit restart msg1 at some rate.
pub const ESTABLISHED_RATE_FLOOR: f64 = 1.0;

/// Which bucket an inbound msg1 draws on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Msg1Class {
    /// No established link matches the source `(transport_id, addr)`.
    Stranger,
    /// The source matches an established link: rekey or restart traffic.
    EstablishedLink,
}

/// Why an inbound msg1 was refused by the limiter.
///
/// `start_handshake` refuses on either limb and the caller's log line is
/// blind to which without this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Msg1Refusal {
    /// The shared in-flight handshake count is at `max_pending`.
    PendingLimit,
    /// The class's token bucket is empty.
    RateLimit,
}

impl Msg1Refusal {
    /// Stable field value for structured logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Msg1Refusal::PendingLimit => "pending_limit",
            Msg1Refusal::RateLimit => "rate_limit",
        }
    }
}

impl std::fmt::Display for Msg1Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An in-flight handshake's pending slot, released on drop.
///
/// The slot is the limiter's concurrency limb. Releasing it by hand from
/// every exit path of a long handler is the shape that lets one path free
/// a slot belonging to a *different* handshake, silently lifting effective
/// concurrency above `max_pending` with no counter moving and no log
/// firing. Holding the release in `Drop` makes that structurally
/// impossible.
///
/// Worth knowing when reading `max_pending`: today the count cannot
/// exceed 1 in production. `start_handshake` is reached only from
/// `handle_msg1`, whose sole production caller awaits it to completion
/// inside `process_packet(&mut self)`, itself awaited serially in the rx
/// loop, so no two msg1 handlers are ever in flight at once. The
/// concurrency limb is therefore a structural invariant rather than a
/// limiter that currently binds, and `Msg1Refusal::PendingLimit` does not
/// fire in the field. The guard is what keeps that invariant true as the
/// handler grows exit paths, and what makes it safe for different msg1
/// classes to take slots on different terms.
///
/// The atomic is for `Send`-ness, not cross-thread coordination: the guard
/// is held across `.await` points inside `handle_msg1`, and a
/// `Rc<Cell<usize>>` would make every future containing it non-`Send`.
#[must_use = "binding the slot to a named local is what holds it; \
              dropping it immediately releases it straight away"]
#[derive(Debug)]
pub struct PendingHandshake {
    pending: Arc<AtomicUsize>,
}

impl Drop for PendingHandshake {
    fn drop(&mut self) {
        let _ = self
            .pending
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
    }
}

/// Derive the established-link bucket's parameters from configuration.
///
/// Every input is a value the operator already sets, so raising `max_peers`
/// moves this automatically rather than leaving a bare constant that nobody
/// revisits.
///
/// - **burst = `max_peers`.** The worst *legitimate* burst on this bucket is
///   every established peer re-handshaking at once (local restart, partition
///   heal), and that population is bounded by `max_peers` by construction, at
///   one token per msg1.
/// - **rate = `(max_peers / max(rekey_after_secs, 1)) * (1 + max_resends)`,**
///   floored at [`ESTABLISHED_RATE_FLOOR`]. The first factor is the
///   steady-state inbound rekey rate; the second is the worst case where
///   every attempt consumes its full retransmission budget.
///
/// `max_peers == 0` means unlimited, for which no peer-count-derived size
/// exists; the stranger bucket's own parameters are returned so an
/// unlimited-peers node gets a second bucket the same size as its first
/// rather than a bucket of one token.
///
/// `rekey.enabled` is deliberately ignored: restart and reconnect msg1 exist
/// regardless, and branching on it would make the disabled-rekey
/// configuration the under-provisioned one.
pub fn derive_established_bucket(
    max_peers: usize,
    rekey_after_secs: u64,
    max_resends: u32,
    stranger_burst: u32,
    stranger_rate: f64,
) -> (u32, f64) {
    if max_peers == 0 {
        return (stranger_burst, stranger_rate);
    }
    let burst = u32::try_from(max_peers).unwrap_or(u32::MAX);
    let period = rekey_after_secs.max(1) as f64;
    let rate = (max_peers as f64 / period) * (1.0 + f64::from(max_resends));
    (burst, rate.max(ESTABLISHED_RATE_FLOOR))
}

/// Rate limiter for handshake message 1 processing.
///
/// Combines token bucket rate limiting with connection counting to
/// protect against DoS attacks on the handshake path. The rate limb is
/// split by [`Msg1Class`]; the concurrency limb is shared (see the module
/// doc for why, and for what the aggregate rate becomes).
#[derive(Debug)]
pub struct HandshakeRateLimiter {
    /// Token bucket for stranger msg1.
    bucket: TokenBucket,
    /// Token bucket for established-link msg1 (rekey / restart).
    established: TokenBucket,
    /// Current count of pending inbound connections, shared with the
    /// outstanding [`PendingHandshake`] guards.
    pending: Arc<AtomicUsize>,
    /// Maximum pending inbound connections.
    max_pending: usize,
}

impl HandshakeRateLimiter {
    /// Create a handshake rate limiter with the given parameters.
    pub fn with_params(bucket: TokenBucket, established: TokenBucket, max_pending: usize) -> Self {
        Self {
            bucket,
            established,
            pending: Arc::new(AtomicUsize::new(0)),
            max_pending,
        }
    }

    /// Check if a new handshake of `class` can be started.
    ///
    /// Returns `true` if:
    /// - The class's token bucket has available tokens (rate limit not exceeded)
    /// - Pending connection count is below maximum
    ///
    /// Does NOT consume a token - call `start_handshake` for that.
    #[cfg(test)]
    pub fn can_start_handshake(&mut self, class: Msg1Class) -> bool {
        self.bucket_for(class).available()
            && self.pending.load(Ordering::Relaxed) < self.max_pending
    }

    /// Start a new handshake, consuming a token and taking a pending slot.
    ///
    /// The returned guard releases the slot when it drops. On refusal the
    /// [`Msg1Refusal`] says which limb refused.
    pub fn start_handshake(&mut self, class: Msg1Class) -> Result<PendingHandshake, Msg1Refusal> {
        if self.pending.load(Ordering::Relaxed) >= self.max_pending {
            return Err(Msg1Refusal::PendingLimit);
        }

        if !self.bucket_for(class).try_acquire() {
            return Err(Msg1Refusal::RateLimit);
        }

        self.pending.fetch_add(1, Ordering::Relaxed);
        Ok(PendingHandshake {
            pending: Arc::clone(&self.pending),
        })
    }

    fn bucket_for(&mut self, class: Msg1Class) -> &mut TokenBucket {
        match class {
            Msg1Class::Stranger => &mut self.bucket,
            Msg1Class::EstablishedLink => &mut self.established,
        }
    }

    /// Get the current pending connection count.
    #[cfg(test)]
    pub fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    /// Get a reference to the stranger token bucket.
    #[cfg(test)]
    pub fn bucket(&self) -> &TokenBucket {
        &self.bucket
    }

    /// Get a reference to the established-link token bucket.
    #[cfg(test)]
    pub fn established_bucket(&self) -> &TokenBucket {
        &self.established
    }

    /// Reset the rate limiter.
    ///
    /// Does not affect slots held by live [`PendingHandshake`] guards; they
    /// still decrement on drop, saturating at zero.
    #[cfg(test)]
    pub fn reset(&mut self) {
        self.bucket.reset();
        self.established.reset();
        self.pending.store(0, Ordering::Relaxed);
    }
}

/// How long a link peer's buckets are kept after its last setup message.
const SETUP_BUCKET_IDLE: Duration = Duration::from_secs(300);

/// One link peer's pair of session-setup buckets.
struct LinkBuckets {
    /// Setup messages that would create a new half-open session entry.
    stranger: TokenBucket,
    /// Setup messages naming a peer this node already has a session with:
    /// rekey and restart traffic, which creates no new entry.
    established: TokenBucket,
    /// Last time this peer was charged, for idle pruning.
    seen: Instant,
}

/// Rate limiter for inbound FSP SessionSetup messages, keyed on the link peer.
///
/// The setup path allocates a `SessionEntry` and sends a SessionAck for every
/// well-formed msg1 naming an address it has no entry for, and the address is
/// an envelope field the sender picks. Without a limiter one neighbour can
/// grow the session table at whatever rate it can transmit, and buy a routed
/// ack per entry to a destination it chooses.
///
/// **The key is the FMP link peer the datagram arrived over, never the FSP
/// `src_addr`.** The link peer is authenticated by the hop-by-hop Noise AEAD
/// and its population is bounded by the peer table; `src_addr` is chosen by
/// the sender, so keying on it would let one sender mint a fresh full bucket
/// per forged message. See the module doc for how this squares with the msg1
/// limiter being unkeyed.
///
/// Two buckets per link, for the same reason [`HandshakeRateLimiter`] has
/// two: a drained stranger bucket must not also stop an established peer's
/// rekey msg1 from arming. Suppressed rekey is quiet — nothing errors and no
/// session drops — so folding both classes into one bucket would let a
/// sprayer one hop away hold forward-secrecy rotation off for everything
/// behind that link with no signal but a flat `rekey_armed`.
///
/// Idle links are pruned lazily on the admit path. Pruning only ever relaxes
/// the limit, and it cannot be farmed: earning a fresh bucket costs a full
/// [`SETUP_BUCKET_IDLE`] of silence on that link, which at any sane sizing is
/// a far lower sustained rate than simply waiting for the bucket to refill.
pub struct SessionSetupRateLimiter {
    /// Per-link-peer buckets, created on first use.
    buckets: HashMap<NodeAddr, LinkBuckets>,
    /// Burst and refill rate for a new link's stranger bucket.
    stranger: (u32, f64),
    /// Burst and refill rate for a new link's established bucket.
    established: (u32, f64),
}

impl SessionSetupRateLimiter {
    /// Create a limiter whose per-link buckets take the given parameters.
    ///
    /// Each pair is `(burst, tokens per second)`.
    pub fn with_params(stranger: (u32, f64), established: (u32, f64)) -> Self {
        Self {
            buckets: HashMap::new(),
            stranger,
            established,
        }
    }

    /// Charge one setup message of `class` to `link_peer`.
    ///
    /// Returns `false` when the class's bucket for that link is empty, in
    /// which case the caller must drop the message before doing any work.
    pub fn try_admit(&mut self, link_peer: &NodeAddr, class: Msg1Class) -> bool {
        let now = Instant::now();
        let stranger = self.stranger;
        let established = self.established;
        let link = self
            .buckets
            .entry(*link_peer)
            .or_insert_with(|| LinkBuckets {
                stranger: TokenBucket::with_params(stranger.0, stranger.1),
                established: TokenBucket::with_params(established.0, established.1),
                seen: now,
            });
        link.seen = now;

        let admitted = match class {
            Msg1Class::Stranger => link.stranger.try_acquire(),
            Msg1Class::EstablishedLink => link.established.try_acquire(),
        };

        if admitted {
            self.buckets
                .retain(|_, link| now.duration_since(link.seen) < SETUP_BUCKET_IDLE);
        }
        admitted
    }

    /// Number of link peers currently holding buckets.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::with_params(10, 1.0);

        // Should have full capacity
        assert_eq!(bucket.capacity(), 10);
        assert!(bucket.tokens() >= 9.9); // Allow for timing

        // Consume all tokens
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }

        // Should be empty
        assert!(!bucket.try_acquire());
        assert!(!bucket.available());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::with_params(10, 100.0); // 100 tokens/sec

        // Drain completely
        for _ in 0..10 {
            bucket.try_acquire();
        }
        assert!(!bucket.available());

        // Wait for refill, measuring actual elapsed time to avoid sensitivity
        // to OS scheduler variance (sleep can overshoot by a large margin).
        let before = Instant::now();
        thread::sleep(Duration::from_millis(50));
        let elapsed_secs = before.elapsed().as_secs_f64();

        // Expected tokens = elapsed * rate, capped at capacity.
        // Allow ±20% tolerance around the actual elapsed time.
        let expected = (elapsed_secs * 100.0).min(10.0);
        let lo = (expected * 0.8).min(expected - 0.5).max(0.0);
        let hi = (expected * 1.2).max(expected + 0.5).min(10.0);

        let tokens = bucket.tokens();
        assert!(
            (lo..=hi).contains(&tokens),
            "tokens: {}, expected ~{:.2} (range {:.2}..={:.2})",
            tokens,
            expected,
            lo,
            hi
        );
    }

    #[test]
    fn test_token_bucket_try_acquire_n() {
        let mut bucket = TokenBucket::with_params(10, 1.0);

        // Acquire 5
        assert!(bucket.try_acquire_n(5));
        assert!(bucket.tokens() >= 4.9 && bucket.tokens() <= 5.1);

        // Acquire 5 more
        assert!(bucket.try_acquire_n(5));

        // Can't acquire more
        assert!(!bucket.try_acquire_n(1));
    }

    #[test]
    fn test_token_bucket_reset() {
        let mut bucket = TokenBucket::with_params(10, 1.0);

        // Drain
        for _ in 0..10 {
            bucket.try_acquire();
        }

        // Reset
        bucket.reset();

        // Should be full again
        assert!(bucket.tokens() >= 9.9);
    }

    #[test]
    fn test_token_bucket_time_until_available() {
        let mut bucket = TokenBucket::with_params(10, 10.0); // 10 tokens/sec

        // When full, should be zero
        assert_eq!(bucket.time_until_available(), Duration::ZERO);

        // Drain completely
        for _ in 0..10 {
            bucket.try_acquire();
        }

        // Should need ~100ms for one token at 10/sec
        let wait = bucket.time_until_available();
        assert!(wait.as_millis() >= 90 && wait.as_millis() <= 110);
    }

    fn test_limiter(bucket: TokenBucket, max_pending: usize) -> HandshakeRateLimiter {
        HandshakeRateLimiter::with_params(
            bucket,
            TokenBucket::with_params(1000, 100.0),
            max_pending,
        )
    }

    #[test]
    fn test_handshake_rate_limiter_basic() {
        let mut limiter = test_limiter(TokenBucket::new(), 100);

        assert!(limiter.can_start_handshake(Msg1Class::Stranger));
        assert_eq!(limiter.pending_count(), 0);

        // Start a handshake
        let slot = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        assert_eq!(limiter.pending_count(), 1);

        // Complete it
        drop(slot);
        assert_eq!(limiter.pending_count(), 0);
    }

    #[test]
    fn test_handshake_rate_limiter_max_pending() {
        let bucket = TokenBucket::with_params(1000, 100.0);
        let mut limiter = test_limiter(bucket, 3);

        // Start 3 handshakes
        let a = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        let _b = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        let _c = limiter.start_handshake(Msg1Class::Stranger).unwrap();

        // Fourth should fail (max pending)
        assert!(!limiter.can_start_handshake(Msg1Class::Stranger));
        assert_eq!(
            limiter.start_handshake(Msg1Class::Stranger).unwrap_err(),
            Msg1Refusal::PendingLimit
        );

        // Complete one
        drop(a);

        // Now should be able to start another
        assert!(limiter.can_start_handshake(Msg1Class::Stranger));
        assert!(limiter.start_handshake(Msg1Class::Stranger).is_ok());
    }

    #[test]
    fn test_handshake_rate_limiter_token_exhaustion() {
        let bucket = TokenBucket::with_params(5, 0.0); // No refill
        let mut limiter = test_limiter(bucket, 100);

        // Start 5 handshakes (exhausts tokens), releasing each immediately
        for _ in 0..5 {
            let slot = limiter.start_handshake(Msg1Class::Stranger).unwrap();
            drop(slot);
        }

        // Tokens exhausted, even though pending is 0
        assert_eq!(limiter.pending_count(), 0);
        assert!(!limiter.can_start_handshake(Msg1Class::Stranger));
        assert_eq!(
            limiter.start_handshake(Msg1Class::Stranger).unwrap_err(),
            Msg1Refusal::RateLimit
        );
    }

    #[test]
    fn test_handshake_rate_limiter_reset() {
        let mut limiter = test_limiter(TokenBucket::new(), 100);

        // Start some handshakes
        let _a = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        let _b = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        assert_eq!(limiter.pending_count(), 2);

        // Reset
        limiter.reset();

        assert_eq!(limiter.pending_count(), 0);
        assert!(limiter.bucket().tokens >= DEFAULT_BURST_CAPACITY as f64 - 0.1);
    }

    /// The pending slot is released by `Drop`, not by any reachable manual
    /// call, and the release saturates at zero rather than underflowing.
    #[test]
    fn pending_slot_releases_on_drop_and_saturates() {
        let mut limiter = test_limiter(TokenBucket::with_params(100, 100.0), 100);

        let outer = limiter.start_handshake(Msg1Class::Stranger).unwrap();
        {
            let _inner = limiter.start_handshake(Msg1Class::Stranger).unwrap();
            assert_eq!(limiter.pending_count(), 2);
        }
        assert_eq!(
            limiter.pending_count(),
            1,
            "inner guard released its own slot"
        );

        // A reset zeroes the counter while a guard is still live; the
        // guard's later drop must not underflow it.
        limiter.reset();
        assert_eq!(limiter.pending_count(), 0);
        drop(outer);
        assert_eq!(limiter.pending_count(), 0, "release saturates at zero");
    }

    /// The refusal reason discriminates the two limbs. This is what the
    /// `refused_by` log field in `handle_msg1` carries; the log line itself
    /// is not asserted here.
    #[test]
    fn refusal_reason_names_the_limb() {
        // Pending limb: max_pending 1, one live guard, tokens plentiful.
        let mut pending_bound = test_limiter(TokenBucket::with_params(1000, 100.0), 1);
        let _held = pending_bound.start_handshake(Msg1Class::Stranger).unwrap();
        assert_eq!(
            pending_bound
                .start_handshake(Msg1Class::Stranger)
                .unwrap_err(),
            Msg1Refusal::PendingLimit
        );

        // Rate limb: pending headroom, zero-capacity/zero-refill bucket.
        let mut rate_bound = test_limiter(TokenBucket::with_params(0, 0.0), 1000);
        assert_eq!(
            rate_bound.start_handshake(Msg1Class::Stranger).unwrap_err(),
            Msg1Refusal::RateLimit
        );

        assert_eq!(Msg1Refusal::PendingLimit.to_string(), "pending_limit");
        assert_eq!(Msg1Refusal::RateLimit.to_string(), "rate_limit");
    }

    /// The two classes draw on separate buckets: draining one leaves the
    /// other untouched.
    #[test]
    fn msg1_classes_draw_on_separate_buckets() {
        let mut limiter = HandshakeRateLimiter::with_params(
            TokenBucket::with_params(1, 0.0),
            TokenBucket::with_params(3, 0.0),
            1000,
        );

        drop(limiter.start_handshake(Msg1Class::Stranger).unwrap());
        assert_eq!(
            limiter.start_handshake(Msg1Class::Stranger).unwrap_err(),
            Msg1Refusal::RateLimit,
            "stranger bucket drained"
        );

        for _ in 0..3 {
            drop(
                limiter
                    .start_handshake(Msg1Class::EstablishedLink)
                    .expect("established bucket is independent of the stranger bucket"),
            );
        }
        assert_eq!(
            limiter
                .start_handshake(Msg1Class::EstablishedLink)
                .unwrap_err(),
            Msg1Refusal::RateLimit,
            "established bucket drains on its own terms"
        );
    }

    #[test]
    fn derive_established_bucket_from_shipped_defaults() {
        // max_peers 128, rekey.after_secs 120, handshake_max_resends 5.
        let (burst, rate) = derive_established_bucket(128, 120, 5, 100, 10.0);
        assert_eq!(burst, 128);
        assert!(
            (rate - 6.4).abs() < 1e-9,
            "expected 6.4 tokens/sec, got {rate}"
        );

        // Scales with max_peers rather than needing a revisit.
        let (burst, rate) = derive_established_bucket(512, 120, 5, 100, 10.0);
        assert_eq!(burst, 512);
        assert!(
            (rate - 25.6).abs() < 1e-9,
            "expected 25.6 tokens/sec, got {rate}"
        );
    }

    /// `after_secs = 0` must not divide by zero. It is clamped to 1s, which
    /// yields a *large* rate, not the floor — the floor binds at the other
    /// end, for a very long rekey period. Both ends are asserted here
    /// because the two are easy to conflate.
    #[test]
    fn derive_established_bucket_degenerate_rekey_periods() {
        let (burst, rate) = derive_established_bucket(128, 0, 5, 100, 10.0);
        assert_eq!(burst, 128);
        assert!(rate.is_finite(), "after_secs = 0 must not divide by zero");
        assert_eq!(
            rate,
            derive_established_bucket(128, 1, 5, 100, 10.0).1,
            "after_secs = 0 is clamped to 1s"
        );
        assert!(
            rate > ESTABLISHED_RATE_FLOOR,
            "a zero rekey period is the high end, not the floor"
        );

        // The floor binds for a very long / effectively disabled period.
        let (_, rate) = derive_established_bucket(1, 100_000, 5, 100, 10.0);
        assert_eq!(rate, ESTABLISHED_RATE_FLOOR);
    }

    /// `max_peers == 0` means unlimited. Deriving a burst from it would
    /// yield a zero- or one-token bucket, which is worse than the bug this
    /// second bucket exists to fix; the stranger parameters are reused.
    #[test]
    fn derive_established_bucket_unlimited_peers_reuses_stranger_params() {
        let (burst, rate) = derive_established_bucket(0, 120, 5, 100, 10.0);
        assert_eq!(burst, 100);
        assert_eq!(rate, 10.0);
    }

    fn addr(byte: u8) -> NodeAddr {
        NodeAddr::from_bytes([byte; 16])
    }

    #[test]
    fn setup_limiter_draining_one_link_leaves_another_links_budget_untouched() {
        let mut limiter = SessionSetupRateLimiter::with_params((2, 0.001), (2, 0.001));
        let noisy = addr(0x01);
        let quiet = addr(0x02);

        assert!(limiter.try_admit(&noisy, Msg1Class::Stranger));
        assert!(limiter.try_admit(&noisy, Msg1Class::Stranger));
        assert!(
            !limiter.try_admit(&noisy, Msg1Class::Stranger),
            "the noisy link's own bucket must run out"
        );
        assert!(
            limiter.try_admit(&quiet, Msg1Class::Stranger),
            "a second link peer must not share the first one's budget"
        );
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn setup_limiter_draining_the_stranger_bucket_still_admits_established_peer_setups() {
        let mut limiter = SessionSetupRateLimiter::with_params((1, 0.001), (1, 0.001));
        let link = addr(0x01);

        assert!(limiter.try_admit(&link, Msg1Class::Stranger));
        assert!(!limiter.try_admit(&link, Msg1Class::Stranger));
        assert!(
            limiter.try_admit(&link, Msg1Class::EstablishedLink),
            "rekey traffic must not be starved by a stranger flood on the \
             same link; suppressed rotation is silent and would show only as \
             a flat rekey_armed counter"
        );
    }
}

// ============================================================================
// Target-side: Lookup Signing Budget
//
// Homed here rather than in `proto::lookup::limits` because it is an
// `Instant`-based shell limiter, and the `proto` tree is `alloc`-based and
// clockless. On `maint` it lived in `src/node/discovery_rate_limit.rs`, which
// `master` dissolved into `proto/lookup/limits.rs`.
// ============================================================================

/// Signatures one link peer may buy in a burst before the refill paces it.
///
/// Sized for the case that actually produces a burst: a topology change
/// flushes correspondents' coordinate caches and they all look this node up
/// at once, through whichever few link peers lead here, each retrying on the
/// `node.discovery.attempt_timeouts_secs` ladder. Lowering this makes a
/// genuinely popular node intermittently unresolvable, which is the same
/// symptom as the flood it defends against; raising it raises the worst-case
/// signing burst one neighbour can force.
const DEFAULT_SIGN_BURST: f64 = 256.0;

/// Sustained signatures per second per link peer.
///
/// At the default eight or so link peers this caps the node near 256
/// signatures per second in the sustained case. The real cost of one
/// `Identity::sign` on this codebase has not been measured, so this number
/// is a bound rather than a tuned value; it is the one line to change if a
/// measurement says otherwise.
const DEFAULT_SIGN_RATE: f64 = 32.0;

/// Maximum age of an idle bucket before cleanup.
const SIGN_MAX_AGE: Duration = Duration::from_secs(300);

/// Token bucket per link peer for lookups this node answers about itself.
///
/// A min-interval limiter is the wrong shape here: a popular node receives
/// legitimate bursts of lookups for itself through the few link peers that
/// lead to it, and a min interval refuses all but the first of each burst.
/// A bucket absorbs the burst and paces the sustained rate.
pub struct LookupSignRateLimiter {
    buckets: HashMap<NodeAddr, SignBucket>,
    burst: f64,
    rate: f64,
}

struct SignBucket {
    /// Tokens remaining, at most `burst`.
    tokens: f64,
    /// When `tokens` was last refilled.
    updated: Instant,
}

impl LookupSignRateLimiter {
    /// Create with default burst and refill rate.
    pub fn new() -> Self {
        Self::with_params(DEFAULT_SIGN_BURST, DEFAULT_SIGN_RATE)
    }

    /// Create with a custom burst and refill rate.
    pub fn with_params(burst: f64, rate: f64) -> Self {
        Self {
            buckets: HashMap::new(),
            burst,
            rate,
        }
    }

    /// Spend one token for `from`, or report that its budget is exhausted.
    ///
    /// Returns true when the signature may be produced. A zero burst is
    /// read as "unlimited" rather than "refuse everything", so a
    /// misconfiguration cannot make this node unresolvable.
    pub fn should_sign(&mut self, from: &NodeAddr) -> bool {
        if self.burst <= 0.0 {
            return true;
        }
        let now = Instant::now();
        let burst = self.burst;
        let rate = self.rate;
        let bucket = self.buckets.entry(*from).or_insert(SignBucket {
            tokens: burst,
            updated: now,
        });
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        self.cleanup(now);
        true
    }

    /// Drop buckets untouched for longer than [`SIGN_MAX_AGE`]; a full
    /// bucket carries no state worth keeping.
    fn cleanup(&mut self, now: Instant) {
        self.buckets
            .retain(|_, b| now.duration_since(b.updated) < SIGN_MAX_AGE);
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.buckets.len()
    }
}

impl Default for LookupSignRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod sign_limiter_tests {
    use super::*;

    fn addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    // The `DiscoveryBackoff` and `DiscoveryForwardRateLimiter` tests that
    // accompanied this limiter in `src/node/discovery_rate_limit.rs` are not
    // repeated here: both types moved into `crate::proto::lookup::limits` as
    // `LookupBackoff` and `LookupForwardRateLimiter`, and all thirteen of those
    // cases live there, name for name, in `src/proto/lookup/tests/limits.rs`,
    // ported to the clockless millisecond API. Only the signing budget, which
    // is `Instant`-based and so stays in the shell, is exercised below.

    #[test]
    fn test_sign_budget_is_spent_per_peer_and_does_not_touch_another_peer() {
        let mut limiter = LookupSignRateLimiter::with_params(4.0, 0.0);
        for _ in 0..4 {
            assert!(limiter.should_sign(&addr(1)));
        }
        assert!(
            !limiter.should_sign(&addr(1)),
            "the burst is the whole budget when nothing refills it"
        );
        assert!(
            limiter.should_sign(&addr(2)),
            "one peer spending its budget must not spend another's"
        );
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn test_sign_budget_of_zero_burst_is_read_as_unlimited() {
        let mut limiter = LookupSignRateLimiter::with_params(0.0, 0.0);
        for _ in 0..1000 {
            assert!(limiter.should_sign(&addr(1)));
        }
        assert_eq!(limiter.len(), 0, "unlimited keeps no per-peer state");
    }
}
