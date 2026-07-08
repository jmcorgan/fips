//! Protocol error types.

/// Errors related to protocol message handling.
#[derive(Debug)]
pub enum Error {
    /// Message type byte was not recognized.
    InvalidMessageType(u8),

    /// Message was shorter than the minimum expected length.
    MessageTooShort {
        /// Minimum number of bytes expected.
        expected: usize,
        /// Number of bytes actually present.
        got: usize,
    },

    /// Message exceeded the maximum allowed length.
    MessageTooLong {
        /// Maximum number of bytes allowed.
        max: usize,
        /// Number of bytes actually present.
        got: usize,
    },

    /// Signature failed to parse or verify.
    InvalidSignature,

    /// Protocol version byte was not supported.
    UnsupportedVersion(u8),

    /// Message was structurally malformed; the string names the field.
    Malformed(&'static str),

    /// Size class byte was out of range for this message.
    BadSizeClass {
        /// The size class value received.
        got: u8,
        /// The maximum (or required) size class.
        max: u8,
    },

    /// A tree coordinate failed to construct during decode.
    BadCoord(crate::proto::coord::CoordError),

    /// A bloom filter failed to construct during decode.
    BadBloom(crate::proto::bloom::BloomError),

    /// Hop limit was exceeded while forwarding.
    HopLimitExceeded,

    /// Time-to-live expired while forwarding.
    TtlExpired,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidMessageType(t) => write!(f, "invalid message type: 0x{t:02x}"),
            Error::MessageTooShort { expected, got } => {
                write!(
                    f,
                    "message too short: expected at least {expected}, got {got}"
                )
            }
            Error::MessageTooLong { max, got } => {
                write!(f, "message too long: max {max}, got {got}")
            }
            Error::InvalidSignature => write!(f, "invalid signature"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported protocol version: {v}"),
            Error::Malformed(m) => write!(f, "malformed message: {m}"),
            Error::BadSizeClass { got, max } => write!(f, "bad size class: {got} (max {max})"),
            Error::BadCoord(e) => write!(f, "bad coordinate: {e}"),
            Error::BadBloom(e) => write!(f, "bad bloom filter: {e}"),
            Error::HopLimitExceeded => write!(f, "hop limit exceeded"),
            Error::TtlExpired => write!(f, "ttl expired"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::BadCoord(e) => Some(e),
            Error::BadBloom(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::proto::coord::CoordError> for Error {
    fn from(e: crate::proto::coord::CoordError) -> Self {
        Error::BadCoord(e)
    }
}

impl From<crate::proto::bloom::BloomError> for Error {
    fn from(e: crate::proto::bloom::BloomError) -> Self {
        Error::BadBloom(e)
    }
}
