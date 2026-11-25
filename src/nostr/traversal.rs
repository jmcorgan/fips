//! The wall clock the rendezvous reads, and the pieces of the punch the
//! shell's tests still reach by these paths.

use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
pub(super) use super::machine::punch::plan::{
    SourceRank, planned_remote_endpoints, rank_punch_source,
};
#[cfg(test)]
pub(super) use super::machine::punch::refusal::RefusalWarnGate;
#[cfg(test)]
pub(super) use super::machine::punch::{build_punch_packet, session_hash};

/// Current Unix time in milliseconds, read from the wall clock on every call.
///
/// This deliberately does not cache a start-of-process anchor and advance it
/// with a monotonic `Instant`. A monotonic clock does not advance while the host
/// is suspended, so an anchored value trails real time by the suspend duration
/// for the remaining life of the process. Every expiry computed from it is then
/// published already in the past, the relay drops the event as expired, and
/// traversal signalling fails until the daemon is restarted.
///
/// About half the consumers publish or serialize the value as an absolute
/// timestamp: the NIP-40 expiration tags on adverts and traversal signals, and
/// the `issuedAt`/`expiresAt` fields of offers and answers. The rest compare it
/// against timestamps on the same basis, including the peer-authored, signed
/// `created_at` of a received advert, so they need it to track real time too.
///
/// The interval-shaped consumers survive a step in the wall clock. A forward
/// step, which is what a resume produces, saturates the punch start delay to
/// zero so punching begins immediately; the attempt's own bounds are monotonic
/// `Instant` deadlines, so its length is unaffected. A backward step lengthens
/// that delay instead and can cost a single punch attempt, which retries.
/// Expiry-driven eviction from the replay window cannot admit a replay, because
/// the freshness window a replayed offer would also have to satisfy
/// (`signal_ttl_secs` plus `FRESHNESS_SKEW_TOLERANCE_MS` on each side, 240s
/// under the shipped defaults) is strictly narrower than the replay window
/// itself (`replay_window_secs`, 300s). `Config::validate` enforces
/// `signal_ttl_secs + 2 * FRESHNESS_SKEW_TOLERANCE_MS < replay_window_secs`, so
/// that margin can no longer be configured away.
///
/// Capacity never removes a live entry. When `note_session_seen` finds
/// `seen_sessions_max_entries` unexpired ids, it refuses the new offer and
/// records nothing, so a full cache costs new traversals until an entry
/// expires but never makes a recorded session replayable. The default is sized
/// so that refusal is not reached through the signal gate: the gate admits at
/// most its two sustained rates plus its two bursts (10/s and 40 signals at
/// the shipped constants, 3040 over a 300s replay window), below the default
/// of 4096.
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
