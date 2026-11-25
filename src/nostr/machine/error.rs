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
    /// The relays hold no current advert by this peer; the text is its npub.
    MissingAdvert(String),
    /// A peer was named by text that is not a NIP-19 npub.
    InvalidPeerNpub { npub: String, reason: String },
    /// An offer's session id was seen inside the replay window.
    Replay(String),
    /// The node has no room for another peer, so no traversal starts.
    Disabled,
    /// A peer's advert names no `udp:nat` endpoint; the text is its npub.
    MissingNatEndpoint(String),
    /// No relay we share with a peer can carry its signals; the text is its
    /// npub.
    MissingRelays(String),
    /// A peer's answer did not arrive within the signal lifetime; the text
    /// is its npub.
    SignalTimeout(String),
    /// A punch attempt adopted nothing in time; the text names the peer or
    /// the session.
    PunchTimeout(String),
    /// A socket could not be made; the text is the I/O error's.
    Io(String),
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
            Error::MissingAdvert(npub) => write!(f, "peer {npub} has no overlay advert"),
            Error::InvalidPeerNpub { npub, reason } => write!(f, "invalid npub '{npub}': {reason}"),
            Error::Replay(session) => write!(f, "replayed or duplicate session id: {session}"),
            Error::Disabled => write!(f, "bootstrap disabled"),
            Error::MissingNatEndpoint(npub) => {
                write!(f, "peer {npub} advert does not contain udp:nat endpoint")
            }
            Error::MissingRelays(npub) => write!(f, "peer {npub} has no usable traversal relays"),
            Error::SignalTimeout(npub) => {
                write!(f, "signal timeout waiting for answer from {npub}")
            }
            Error::PunchTimeout(peer) => write!(f, "traversal attempt timed out for {peer}"),
            Error::Io(error) => write!(f, "io error: {error}"),
        }
    }
}

#[cfg(test)]
#[path = "tests/error.rs"]
mod tests;
