//! Deployed rekey timing constants.
//!
//! The drain window and dampening the deployed rekey code was written
//! against. The session rekey machine carries its own values in
//! `proto::rekey::Config`; the link layer's deployed rekey still reads these
//! for its drain ceiling and its cutover-age floor.

/// Keep the previous session alive for this long after cutover.
pub const DRAIN_WINDOW_SECS: u64 = 10;

/// Suppress local rekey initiation for this long after receiving a peer's
/// rekey msg1.
pub const REKEY_DAMPENING_SECS: u64 = 30;
