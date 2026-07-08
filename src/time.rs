//! Shell-side time seam: the process-monotonic millisecond clock the sans-IO
//! cores take as an injected `u64`.

use std::sync::LazyLock;
use std::time::Instant;

/// Monotonic millisecond clock for the MMP time seam.
///
/// The owned `proto::mmp` state takes injected `u64` milliseconds rather than
/// reading a clock. The shell reads this process-monotonic clock at each edge
/// and passes the value in; only deltas between two `mono_ms()` reads are ever
/// compared, so the (process-relative) epoch is immaterial.
pub(crate) fn mono_ms() -> u64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_millis() as u64
}
