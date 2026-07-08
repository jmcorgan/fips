//! FSP session-rekey timing constants.
//!
//! Pure, runtime-agnostic bounds for the session-rekey lifecycle, relocated
//! from the async `node::handlers::rekey` shell. The shell resolves the clock
//! and pre-evaluates the timer predicates against these; the core reads only
//! the resulting plain-data snapshot fields.

/// Keep the previous session alive for this long after cutover.
pub(crate) const DRAIN_WINDOW_SECS: u64 = 10;

/// Suppress local rekey initiation for this long after receiving a peer's
/// rekey msg1.
pub(crate) const REKEY_DAMPENING_SECS: u64 = 30;

/// Liveness bound on how long the FSP rekey initiator holds the `current` +
/// `pending` state before cutting over to the new epoch.
///
/// This is NOT safety-critical: overlapping-epoch trial-decrypt covers any
/// skew between the two endpoints' cutovers. The timer only bounds how long the
/// initiator advertises the old K-bit. An opportunistic early cutover also
/// fires if the initiator authenticates a peer frame against its own `pending`
/// session (the responder cut over first).
pub(crate) const FSP_CUTOVER_DELAY_MS: u64 = 2000;
