//! The machine's error. The shell maps each variant onto the
//! `BootstrapError` variant of the same name, with the same text, so every
//! caller and every log line reads as it did before the code moved here.

use alloc::string::String;

/// Why a machine step refused its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A peer's message broke the protocol; the text is the reason code.
    Protocol(String),
    /// A STUN server URL or exchange was unusable; the text says how.
    Stun(String),
    /// An overlay advert broke the content rules; the text says which.
    InvalidAdvert(String),
    /// A `nostr` primitive refused: a signature that does not verify, a
    /// payload that does not decrypt, a key that is not valid.
    Nostr(String),
    /// An event inside a traversal signal was not valid JSON for its type.
    EventParse(String),
}

impl core::fmt::Display for Error {
    /// The text `BootstrapError` gives the same case.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Protocol(reason) => write!(f, "protocol error: {reason}"),
            Error::Stun(reason) => write!(f, "stun failed: {reason}"),
            Error::InvalidAdvert(reason) => write!(f, "invalid overlay advert: {reason}"),
            Error::Nostr(reason) => write!(f, "nostr error: {reason}"),
            Error::EventParse(reason) => write!(f, "event parse error: {reason}"),
        }
    }
}

#[cfg(test)]
#[path = "tests/error.rs"]
mod tests;
