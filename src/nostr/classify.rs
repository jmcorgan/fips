//! The punch-packet test, and the datagram classifier the Nostr rendezvous
//! registers with every UDP transport instance, so a late punch packet on
//! an adopted socket is dropped before FMP sees it.

pub use super::machine::punch::is_punch_packet;

/// The classifier the Nostr rendezvous registers with every UDP transport
/// instance: a punch packet is discarded before FMP sees it, anything else
/// goes to FMP.
pub fn classify_datagram(data: &[u8]) -> crate::transport::udp::DatagramClass {
    if is_punch_packet(data) {
        crate::transport::udp::DatagramClass::Discard
    } else {
        crate::transport::udp::DatagramClass::Fmp
    }
}
