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

use std::time::{Duration, Instant};

/// Default burst capacity (max tokens).
pub const DEFAULT_BURST_CAPACITY: u32 = 100;

/// Default refill rate (tokens per second).
pub const DEFAULT_REFILL_RATE: f64 = 10.0;

/// Maximum pending inbound connections.
pub const MAX_PENDING_INBOUND: usize = 1000;

/// Handshake timeout in seconds.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

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
    pub fn available(&mut self) -> bool {
        self.refill();
        self.tokens >= 1.0
    }

    /// Get the current number of available tokens.
    pub fn tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    /// Get the capacity (max tokens).
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Get the refill rate (tokens per second).
    pub fn refill_rate(&self) -> f64 {
        self.refill_rate
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
    pub fn reset(&mut self) {
        self.tokens = self.capacity as f64;
        self.last_refill = Instant::now();
    }

    /// Set a new capacity.
    pub fn set_capacity(&mut self, capacity: u32) {
        self.capacity = capacity;
        if self.tokens > capacity as f64 {
            self.tokens = capacity as f64;
        }
    }

    /// Set a new refill rate.
    pub fn set_refill_rate(&mut self, rate: f64) {
        self.refill_rate = rate;
    }

    /// Time until the next token is available.
    ///
    /// Returns `Duration::ZERO` if tokens are available, otherwise the
    /// estimated time until one token will be available.
    pub fn time_until_available(&mut self) -> Duration {
        self.refill();

        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            let secs = needed / self.refill_rate;
            Duration::from_secs_f64(secs)
        }
    }
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiter for handshake message 1 processing.
///
/// Combines token bucket rate limiting with connection counting to
/// protect against DoS attacks on the handshake path.
#[derive(Debug)]
pub struct HandshakeRateLimiter {
    /// Token bucket for rate limiting.
    bucket: TokenBucket,
    /// Current count of pending inbound connections.
    pending_count: usize,
    /// Maximum pending inbound connections.
    max_pending: usize,
}

impl HandshakeRateLimiter {
    /// Create a new handshake rate limiter with default parameters.
    pub fn new() -> Self {
        Self {
            bucket: TokenBucket::new(),
            pending_count: 0,
            max_pending: MAX_PENDING_INBOUND,
        }
    }

    /// Create with custom parameters.
    pub fn with_params(bucket: TokenBucket, max_pending: usize) -> Self {
        Self {
            bucket,
            pending_count: 0,
            max_pending,
        }
    }

    /// Check if a new handshake can be started.
    ///
    /// Returns `true` if:
    /// - Token bucket has available tokens (rate limit not exceeded)
    /// - Pending connection count is below maximum
    ///
    /// Does NOT consume a token - call `start_handshake` for that.
    pub fn can_start_handshake(&mut self) -> bool {
        self.bucket.available() && self.pending_count < self.max_pending
    }

    /// Start a new handshake, consuming a token and incrementing pending count.
    ///
    /// Returns `true` if the handshake was allowed, `false` if rate limited.
    pub fn start_handshake(&mut self) -> bool {
        if self.pending_count >= self.max_pending {
            return false;
        }

        if self.bucket.try_acquire() {
            self.pending_count += 1;
            true
        } else {
            false
        }
    }

    /// Mark a handshake as complete (successful or failed).
    ///
    /// Decrements the pending connection count.
    pub fn complete_handshake(&mut self) {
        if self.pending_count > 0 {
            self.pending_count -= 1;
        }
    }

    /// Get the current pending connection count.
    pub fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Get the maximum pending connections.
    pub fn max_pending(&self) -> usize {
        self.max_pending
    }

    /// Set the maximum pending connections.
    pub fn set_max_pending(&mut self, max: usize) {
        self.max_pending = max;
    }

    /// Get a reference to the token bucket.
    pub fn bucket(&self) -> &TokenBucket {
        &self.bucket
    }

    /// Get a mutable reference to the token bucket.
    pub fn bucket_mut(&mut self) -> &mut TokenBucket {
        &mut self.bucket
    }

    /// Reset the rate limiter.
    pub fn reset(&mut self) {
        self.bucket.reset();
        self.pending_count = 0;
    }
}

impl Default for HandshakeRateLimiter {
    fn default() -> Self {
        Self::new()
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

        // Wait for refill
        thread::sleep(Duration::from_millis(50)); // Should refill ~5 tokens

        // Should have tokens now
        let tokens = bucket.tokens();
        assert!(tokens >= 4.0 && tokens <= 6.0, "tokens: {}", tokens);
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

    #[test]
    fn test_handshake_rate_limiter_basic() {
        let mut limiter = HandshakeRateLimiter::new();

        assert!(limiter.can_start_handshake());
        assert_eq!(limiter.pending_count(), 0);

        // Start a handshake
        assert!(limiter.start_handshake());
        assert_eq!(limiter.pending_count(), 1);

        // Complete it
        limiter.complete_handshake();
        assert_eq!(limiter.pending_count(), 0);
    }

    #[test]
    fn test_handshake_rate_limiter_max_pending() {
        let bucket = TokenBucket::with_params(1000, 100.0);
        let mut limiter = HandshakeRateLimiter::with_params(bucket, 3);

        // Start 3 handshakes
        assert!(limiter.start_handshake());
        assert!(limiter.start_handshake());
        assert!(limiter.start_handshake());

        // Fourth should fail (max pending)
        assert!(!limiter.can_start_handshake());
        assert!(!limiter.start_handshake());

        // Complete one
        limiter.complete_handshake();

        // Now should be able to start another
        assert!(limiter.can_start_handshake());
        assert!(limiter.start_handshake());
    }

    #[test]
    fn test_handshake_rate_limiter_token_exhaustion() {
        let bucket = TokenBucket::with_params(5, 0.0); // No refill
        let mut limiter = HandshakeRateLimiter::with_params(bucket, 100);

        // Start 5 handshakes (exhausts tokens)
        for _ in 0..5 {
            assert!(limiter.start_handshake());
        }

        // Complete them all
        for _ in 0..5 {
            limiter.complete_handshake();
        }

        // Tokens exhausted, even though pending is 0
        assert!(!limiter.can_start_handshake());
        assert!(!limiter.start_handshake());
    }

    #[test]
    fn test_handshake_rate_limiter_reset() {
        let mut limiter = HandshakeRateLimiter::new();

        // Start some handshakes
        limiter.start_handshake();
        limiter.start_handshake();
        assert_eq!(limiter.pending_count(), 2);

        // Reset
        limiter.reset();

        assert_eq!(limiter.pending_count(), 0);
        assert!(limiter.bucket().tokens >= DEFAULT_BURST_CAPACITY as f64 - 0.1);
    }
}
