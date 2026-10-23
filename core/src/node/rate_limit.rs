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

use crate::identity::NodeAddr;
use crate::time::{Clock, Duration, Instant as _};
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Default burst capacity (max tokens).
pub const DEFAULT_BURST_CAPACITY: u32 = 100;

/// Default refill rate (tokens per second).
pub const DEFAULT_REFILL_RATE: f64 = 10.0;

/// Token bucket rate limiter.
///
/// Uses a classic token bucket algorithm where tokens are consumed for each
/// operation and refilled at a constant rate. When tokens are exhausted,
/// operations are rate-limited until tokens refill.
///
/// Every method that refills takes `now`, a reading of the clock `C`; every
/// reading a bucket is given must come from that one clock.
pub struct TokenBucket<C: Clock> {
    /// Maximum number of tokens (burst capacity).
    capacity: u32,
    /// Current number of available tokens (may be fractional during refill).
    tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last time tokens were refilled.
    last_refill: C::Instant,
    _clock: PhantomData<fn() -> C>,
}

impl<C: Clock> Clone for TokenBucket<C> {
    fn clone(&self) -> Self {
        Self {
            capacity: self.capacity,
            tokens: self.tokens,
            refill_rate: self.refill_rate,
            last_refill: self.last_refill,
            _clock: PhantomData,
        }
    }
}

impl<C: Clock> fmt::Debug for TokenBucket<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenBucket")
            .field("capacity", &self.capacity)
            .field("tokens", &self.tokens)
            .field("refill_rate", &self.refill_rate)
            .field("last_refill", &self.last_refill)
            .finish()
    }
}

impl<C: Clock> TokenBucket<C> {
    /// Create a new token bucket with default parameters, full as of `now`.
    ///
    /// - Burst capacity: 100 tokens
    /// - Refill rate: 10 tokens/second
    pub fn new(now: C::Instant) -> Self {
        Self::with_params(DEFAULT_BURST_CAPACITY, DEFAULT_REFILL_RATE, now)
    }

    /// Create a token bucket with custom parameters, full as of `now`.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens (burst capacity)
    /// * `refill_rate` - Tokens added per second
    /// * `now` - The time the bucket starts refilling from
    pub fn with_params(capacity: u32, refill_rate: f64, now: C::Instant) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate,
            last_refill: now,
            _clock: PhantomData,
        }
    }

    /// Try to consume one token, refilling as of `now`.
    ///
    /// Returns `true` if a token was available and consumed, `false` if
    /// rate limited (no tokens available).
    pub fn try_acquire(&mut self, now: C::Instant) -> bool {
        self.try_acquire_n_at(1, now)
    }

    /// Try to consume n tokens, refilling as of `now`.
    ///
    /// Returns `true` if n tokens were available and consumed, `false` if
    /// rate limited (insufficient tokens).
    pub fn try_acquire_n(&mut self, n: u32, now: C::Instant) -> bool {
        self.try_acquire_n_at(n, now)
    }

    /// Try to consume n tokens, refilling as of `now`.
    fn try_acquire_n_at(&mut self, n: u32, now: C::Instant) -> bool {
        self.refill_at(now);

        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            true
        } else {
            false
        }
    }

    /// Check if tokens are available as of `now` without consuming them.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn available(&mut self, now: C::Instant) -> bool {
        self.refill_at(now);
        self.tokens >= 1.0
    }

    /// Get the number of tokens available as of `now`.
    #[cfg(test)]
    pub fn tokens(&mut self, now: C::Instant) -> f64 {
        self.refill_at(now);
        self.tokens
    }

    /// Get the capacity (max tokens).
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Refill tokens based on the time elapsed up to `now`.
    fn refill_at(&mut self, now: C::Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let elapsed_secs = elapsed.as_secs_f64();

        // Add tokens based on time elapsed
        self.tokens += elapsed_secs * self.refill_rate;

        // Cap at capacity
        if self.tokens > self.capacity as f64 {
            self.tokens = self.capacity as f64;
        }

        self.last_refill = now;
    }

    /// Reset to full capacity as of `now`.
    #[cfg(test)]
    pub fn reset(&mut self, now: C::Instant) {
        self.tokens = self.capacity as f64;
        self.last_refill = now;
    }

    /// Time from `now` until the next token is available.
    ///
    /// Returns `Duration::ZERO` if tokens are available, otherwise the
    /// estimated time until one token will be available.
    #[cfg(test)]
    pub fn time_until_available(&mut self, now: C::Instant) -> Duration {
        self.refill_at(now);

        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            let secs = needed / self.refill_rate;
            Duration::from_secs_f64(secs)
        }
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

impl fmt::Display for Msg1Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
pub struct HandshakeRateLimiter<C: Clock> {
    /// Token bucket for stranger msg1.
    bucket: TokenBucket<C>,
    /// Token bucket for established-link msg1 (rekey / restart).
    established: TokenBucket<C>,
    /// Current count of pending inbound connections, shared with the
    /// outstanding [`PendingHandshake`] guards.
    pending: Arc<AtomicUsize>,
    /// Maximum pending inbound connections.
    max_pending: usize,
}

impl<C: Clock> fmt::Debug for HandshakeRateLimiter<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeRateLimiter")
            .field("bucket", &self.bucket)
            .field("established", &self.established)
            .field("pending", &self.pending)
            .field("max_pending", &self.max_pending)
            .finish()
    }
}

impl<C: Clock> HandshakeRateLimiter<C> {
    /// Create a handshake rate limiter with the given parameters.
    pub fn with_params(
        bucket: TokenBucket<C>,
        established: TokenBucket<C>,
        max_pending: usize,
    ) -> Self {
        Self {
            bucket,
            established,
            pending: Arc::new(AtomicUsize::new(0)),
            max_pending,
        }
    }

    /// Check if a new handshake of `class` can be started at `now`.
    ///
    /// Returns `true` if:
    /// - The class's token bucket has available tokens (rate limit not exceeded)
    /// - Pending connection count is below maximum
    ///
    /// Does NOT consume a token - call `start_handshake` for that.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn can_start_handshake(&mut self, class: Msg1Class, now: C::Instant) -> bool {
        self.bucket_for(class).available(now)
            && self.pending.load(Ordering::Relaxed) < self.max_pending
    }

    /// Start a new handshake at `now`, consuming a token and taking a
    /// pending slot.
    ///
    /// The returned guard releases the slot when it drops. On refusal the
    /// [`Msg1Refusal`] says which limb refused.
    pub fn start_handshake(
        &mut self,
        class: Msg1Class,
        now: C::Instant,
    ) -> Result<PendingHandshake, Msg1Refusal> {
        if self.pending.load(Ordering::Relaxed) >= self.max_pending {
            return Err(Msg1Refusal::PendingLimit);
        }

        if !self.bucket_for(class).try_acquire(now) {
            return Err(Msg1Refusal::RateLimit);
        }

        self.pending.fetch_add(1, Ordering::Relaxed);
        Ok(PendingHandshake {
            pending: Arc::clone(&self.pending),
        })
    }

    fn bucket_for(&mut self, class: Msg1Class) -> &mut TokenBucket<C> {
        match class {
            Msg1Class::Stranger => &mut self.bucket,
            Msg1Class::EstablishedLink => &mut self.established,
        }
    }

    /// Get the current pending connection count.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    /// Get a reference to the stranger token bucket.
    #[cfg(test)]
    pub fn bucket(&self) -> &TokenBucket<C> {
        &self.bucket
    }

    /// Get a reference to the established-link token bucket.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn established_bucket(&self) -> &TokenBucket<C> {
        &self.established
    }

    /// Reset the rate limiter as of `now`.
    ///
    /// Does not affect slots held by live [`PendingHandshake`] guards; they
    /// still decrement on drop, saturating at zero.
    #[cfg(test)]
    pub fn reset(&mut self, now: C::Instant) {
        self.bucket.reset(now);
        self.established.reset(now);
        self.pending.store(0, Ordering::Relaxed);
    }
}

/// How long a link peer's buckets are kept after its last setup message.
const SETUP_BUCKET_IDLE: Duration = Duration::from_secs(300);

/// One link peer's pair of session-setup buckets.
struct LinkBuckets<C: Clock> {
    /// Setup messages that would create a new half-open session entry.
    stranger: TokenBucket<C>,
    /// Setup messages naming a peer this node already has a session with:
    /// rekey and restart traffic, which creates no new entry.
    established: TokenBucket<C>,
    /// Last time this peer was charged, for idle pruning.
    seen: C::Instant,
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
/// `SETUP_BUCKET_IDLE` of silence on that link, which at any sane sizing is
/// a far lower sustained rate than simply waiting for the bucket to refill.
pub struct SessionSetupRateLimiter<C: Clock> {
    /// Per-link-peer buckets, created on first use.
    buckets: BTreeMap<NodeAddr, LinkBuckets<C>>,
    /// Burst and refill rate for a new link's stranger bucket.
    stranger: (u32, f64),
    /// Burst and refill rate for a new link's established bucket.
    established: (u32, f64),
}

impl<C: Clock> SessionSetupRateLimiter<C> {
    /// Create a limiter whose per-link buckets take the given parameters.
    ///
    /// Each pair is `(burst, tokens per second)`.
    pub fn with_params(stranger: (u32, f64), established: (u32, f64)) -> Self {
        Self {
            buckets: BTreeMap::new(),
            stranger,
            established,
        }
    }

    /// Charge one setup message of `class` to `link_peer` at `now`.
    ///
    /// Returns `false` when the class's bucket for that link is empty, in
    /// which case the caller must drop the message before doing any work.
    pub fn try_admit(&mut self, link_peer: &NodeAddr, class: Msg1Class, now: C::Instant) -> bool {
        let stranger = self.stranger;
        let established = self.established;
        let link = self
            .buckets
            .entry(*link_peer)
            .or_insert_with(|| LinkBuckets {
                stranger: TokenBucket::with_params(stranger.0, stranger.1, now),
                established: TokenBucket::with_params(established.0, established.1, now),
                seen: now,
            });
        link.seen = now;

        let admitted = match class {
            Msg1Class::Stranger => link.stranger.try_acquire(now),
            Msg1Class::EstablishedLink => link.established.try_acquire(now),
        };

        if admitted {
            self.buckets
                .retain(|_, link| now.saturating_duration_since(link.seen) < SETUP_BUCKET_IDLE);
        }
        admitted
    }

    /// Number of link peers currently holding buckets.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
#[path = "tests/rate_limit.rs"]
mod tests;

// ============================================================================
// Target-side: Lookup Signing Budget
//
// Homed here rather than in `proto::lookup::limits` because it takes the
// host clock's instants, where the `proto` tree takes `u64` milliseconds. On
// `maint` it lived in `src/node/discovery_rate_limit.rs`, which `master`
// dissolved into `proto/lookup/limits.rs`.
// ============================================================================

/// Signatures one link peer may buy in a burst before the refill paces it.
///
/// Sized for the case that actually produces a burst: a topology change
/// invalidates correspondents' cached coordinates for this node and they all
/// look this node up at once, through whichever few link peers lead here,
/// each retrying on the `node.discovery.attempt_timeouts_secs` ladder. Lowering this makes a
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
pub struct LookupSignRateLimiter<C: Clock> {
    buckets: BTreeMap<NodeAddr, SignBucket<C>>,
    burst: f64,
    rate: f64,
}

struct SignBucket<C: Clock> {
    /// Tokens remaining, at most `burst`.
    tokens: f64,
    /// When `tokens` was last refilled.
    updated: C::Instant,
}

impl<C: Clock> LookupSignRateLimiter<C> {
    /// Create with default burst and refill rate.
    pub fn new() -> Self {
        Self::with_params(DEFAULT_SIGN_BURST, DEFAULT_SIGN_RATE)
    }

    /// Create with a custom burst and refill rate.
    pub fn with_params(burst: f64, rate: f64) -> Self {
        Self {
            buckets: BTreeMap::new(),
            burst,
            rate,
        }
    }

    /// Spend one token for `from` at `now`, or report that its budget is
    /// exhausted.
    ///
    /// Returns true when the signature may be produced. A zero burst is
    /// read as "unlimited" rather than "refuse everything", so a
    /// misconfiguration cannot make this node unresolvable.
    pub fn should_sign(&mut self, from: &NodeAddr, now: C::Instant) -> bool {
        if self.burst <= 0.0 {
            return true;
        }
        let burst = self.burst;
        let rate = self.rate;
        let bucket = self.buckets.entry(*from).or_insert(SignBucket {
            tokens: burst,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
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
    fn cleanup(&mut self, now: C::Instant) {
        self.buckets
            .retain(|_, b| now.saturating_duration_since(b.updated) < SIGN_MAX_AGE);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.buckets.len()
    }
}

impl<C: Clock> Default for LookupSignRateLimiter<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/rate_limit_sign.rs"]
mod sign_limiter_tests;
