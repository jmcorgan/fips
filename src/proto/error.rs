//! Protocol error types.

use thiserror::Error;

/// Errors related to protocol message handling.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid message type: 0x{0:02x}")]
    InvalidMessageType(u8),

    #[error("message too short: expected at least {expected}, got {got}")]
    MessageTooShort { expected: usize, got: usize },

    #[error("message too long: max {max}, got {got}")]
    MessageTooLong { max: usize, got: usize },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("malformed message: {0}")]
    Malformed(String),

    #[error("hop limit exceeded")]
    HopLimitExceeded,

    #[error("ttl expired")]
    TtlExpired,
}
