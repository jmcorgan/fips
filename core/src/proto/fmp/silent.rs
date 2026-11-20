//! The refusal in force for an identity whose link sessions ended without
//! one authenticated frame, as the msg1 refusal's log reads it.
//!
//! The record of those sessions, and the refusal it starts, are kept in the
//! settlement core's restart gates (`proto::settle::gates`); the node fills
//! the snapshot's refusal from them.

/// A refusal in force for one identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveBackoff {
    /// The startup epoch of the silent sessions counted; msg1s at another
    /// epoch are not refused. `None` when none of them carried one.
    pub epoch: Option<[u8; 8]>,
    /// Silent sessions counted in a row at that epoch.
    pub silent: u32,
    /// Milliseconds the refusal still has to run.
    pub remaining_ms: u64,
}
