//! What the UDP transport does with each datagram it receives, before FMP
//! sees it.
//!
//! FRC-1301 Section 6.1.1 reserves two four-byte prefixes on every UDP
//! binding instance for punch packets, which are not FMP frames and must be
//! discarded there. A subsystem that owns those packets registers a
//! [`Classifier`] with each instance; an instance with none registered uses
//! the default filter, which discards the reserved prefixes, so the rule holds
//! on every instance whether or not anything registered.

/// What happens to a received datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramClass {
    /// Handed to FMP.
    Fmp,
    /// Dropped silently, before FMP sees it.
    Discard,
}

/// A classifier a subsystem registers with a UDP transport instance. It is a
/// plain function so the receive loops and the per-peer drain threads can
/// carry it by copy.
pub type Classifier = fn(&[u8]) -> DatagramClass;

/// The class of `data` under `classifier`, or under the default filter when
/// none is registered.
pub(crate) fn classify(classifier: Option<Classifier>, data: &[u8]) -> DatagramClass {
    match classifier {
        Some(classify) => classify(data),
        None => default_class(data),
    }
}

/// The default filter: a punch packet is discarded, anything else goes to
/// FMP.
fn default_class(data: &[u8]) -> DatagramClass {
    if crate::nostr::is_punch_packet(data) {
        DatagramClass::Discard
    } else {
        DatagramClass::Fmp
    }
}

#[cfg(test)]
#[path = "tests/classify.rs"]
mod tests;
