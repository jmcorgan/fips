//! FMP connection-retry backoff timing.
//!
//! Pure, runtime-agnostic backoff math for the auto-connect retry scheduler.
//! The `Node`-coupled `schedule_*` / `process_pending_retries` async drivers
//! stay in the shell (`node::retry`) and pass the retry count in.

/// Calculate the backoff delay in milliseconds for the given retry count.
///
/// Uses exponential backoff: `base_interval_ms * 2^retry_count`, capped at
/// `max_backoff_ms`.
pub(crate) fn backoff_ms(retry_count: u32, base_interval_ms: u64, max_backoff_ms: u64) -> u64 {
    let multiplier = 1u64.checked_shl(retry_count).unwrap_or(u64::MAX);
    base_interval_ms
        .saturating_mul(multiplier)
        .min(max_backoff_ms)
}
