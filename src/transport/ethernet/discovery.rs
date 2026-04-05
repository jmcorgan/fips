//! Ethernet LAN discovery via broadcast beacons.
//!
//! Beacon format (5 bytes total):
//! - Unified header (4 bytes): `[type:1][flags:1][length:2 LE]`
//! - Version (1 byte): discovery protocol version

use crate::transport::{DiscoveredPeer, TransportAddr, TransportId};
use std::sync::Mutex;

/// Discovery protocol version.
pub const DISCOVERY_VERSION: u8 = 0x01;

/// Frame type prefix for discovery announcement beacons.
pub const FRAME_TYPE_BEACON: u8 = 0x01;

/// Frame type prefix for FIPS data frames.
pub const FRAME_TYPE_DATA: u8 = 0x00;

/// Shared header size for all Ethernet frame types: type(1) + flags(1) + length(2).
pub const ETHERNET_HEADER_SIZE: usize = 4;

/// Beacon payload size: version(1).
pub const BEACON_PAYLOAD_SIZE: usize = 1;

/// Total beacon size: header(4) + payload(1).
pub const BEACON_SIZE: usize = ETHERNET_HEADER_SIZE + BEACON_PAYLOAD_SIZE;

/// Build a discovery announcement beacon payload.
pub fn build_beacon() -> [u8; BEACON_SIZE] {
    let mut buf = [0u8; BEACON_SIZE];
    buf[0] = FRAME_TYPE_BEACON;
    buf[1] = 0x00; // flags (reserved)
    buf[2..4].copy_from_slice(&(BEACON_PAYLOAD_SIZE as u16).to_le_bytes());
    buf[4] = DISCOVERY_VERSION;
    buf
}

/// Parse a discovery announcement beacon payload.
///
/// Returns true if the payload is a valid beacon, false otherwise.
pub fn parse_beacon(data: &[u8]) -> bool {
    if data.len() < BEACON_SIZE {
        return false;
    }
    if data[0] != FRAME_TYPE_BEACON {
        return false;
    }
    // flags byte data[1] accepted as any value for forward compatibility
    let length = u16::from_le_bytes([data[2], data[3]]);
    if length < 1 {
        return false;
    }
    data[4] == DISCOVERY_VERSION
}

/// Buffer for discovered peers, drained by `discover()`.
pub struct DiscoveryBuffer {
    transport_id: TransportId,
    peers: Mutex<Vec<DiscoveredPeer>>,
}

impl DiscoveryBuffer {
    /// Create a new empty discovery buffer.
    pub fn new(transport_id: TransportId) -> Self {
        Self {
            transport_id,
            peers: Mutex::new(Vec::new()),
        }
    }

    /// Add a discovered peer from a received beacon.
    pub fn add_peer(&self, src_mac: [u8; 6]) {
        let addr = TransportAddr::from_bytes(&src_mac);
        let peer = DiscoveredPeer::new(self.transport_id, addr);
        let mut peers = self.peers.lock().unwrap();
        peers.retain(|p| p.addr.as_bytes() != src_mac);
        peers.push(peer);
    }

    /// Drain all discovered peers since the last call.
    pub fn take(&self) -> Vec<DiscoveredPeer> {
        let mut peers = self.peers.lock().unwrap();
        std::mem::take(&mut *peers)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_parse_beacon() {
        let beacon = build_beacon();

        assert_eq!(beacon.len(), BEACON_SIZE);
        assert_eq!(beacon[0], FRAME_TYPE_BEACON);
        assert_eq!(beacon[1], 0x00); // flags
        assert_eq!(u16::from_le_bytes([beacon[2], beacon[3]]), 1); // length
        assert_eq!(beacon[4], DISCOVERY_VERSION);

        assert!(parse_beacon(&beacon));
    }

    #[test]
    fn test_parse_beacon_too_short() {
        assert!(!parse_beacon(&[0x01, 0x00, 0x01, 0x00]));
        assert!(!parse_beacon(&[]));
    }

    #[test]
    fn test_parse_beacon_wrong_type() {
        let mut beacon = build_beacon();
        beacon[0] = 0x00; // data frame, not beacon
        assert!(!parse_beacon(&beacon));
    }

    #[test]
    fn test_parse_beacon_wrong_version() {
        let mut beacon = build_beacon();
        beacon[4] = 0xFF;
        assert!(!parse_beacon(&beacon));
    }

    #[test]
    fn test_frame_type_prefix() {
        assert_eq!(FRAME_TYPE_DATA, 0x00);
        assert_eq!(FRAME_TYPE_BEACON, 0x01);
    }

    #[test]
    fn test_beacon_unified_header() {
        let beacon = build_beacon();
        assert_eq!(beacon[1], 0x00); // flags reserved, zero
        assert_eq!(u16::from_le_bytes([beacon[2], beacon[3]]), 1); // length field = 1
    }

    #[test]
    fn test_discovery_buffer() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        buffer.add_peer(mac);

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr.as_bytes(), &mac);
        assert!(peers[0].pubkey_hint.is_none());

        // Second take should be empty
        let peers = buffer.take();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_discovery_buffer_dedup() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        buffer.add_peer(mac);
        buffer.add_peer(mac); // same MAC again

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_beacon_size() {
        assert_eq!(BEACON_SIZE, 5);
    }
}
