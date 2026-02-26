//! Ethernet LAN discovery via broadcast beacons.
//!
//! Beacon format (34 bytes total):
//! - `0x01` (1 byte): frame type = discovery announcement
//! - `0x01` (1 byte): discovery protocol version
//! - x-only public key (32 bytes): node's Nostr identity

use crate::transport::{DiscoveredPeer, TransportAddr, TransportId};
use secp256k1::XOnlyPublicKey;
use std::sync::Mutex;

/// Discovery protocol version.
pub const DISCOVERY_VERSION: u8 = 0x01;

/// Frame type prefix for discovery announcement beacons.
pub const FRAME_TYPE_BEACON: u8 = 0x01;

/// Frame type prefix for FIPS data frames.
pub const FRAME_TYPE_DATA: u8 = 0x00;

/// Total beacon payload size: type(1) + version(1) + pubkey(32).
pub const BEACON_SIZE: usize = 34;

/// Build a discovery announcement beacon payload.
pub fn build_beacon(pubkey: &XOnlyPublicKey) -> [u8; BEACON_SIZE] {
    let mut buf = [0u8; BEACON_SIZE];
    buf[0] = FRAME_TYPE_BEACON;
    buf[1] = DISCOVERY_VERSION;
    buf[2..BEACON_SIZE].copy_from_slice(&pubkey.serialize());
    buf
}

/// Parse a discovery announcement beacon payload.
///
/// Returns the sender's public key, or None if the payload is invalid.
pub fn parse_beacon(data: &[u8]) -> Option<XOnlyPublicKey> {
    if data.len() < BEACON_SIZE {
        return None;
    }
    if data[0] != FRAME_TYPE_BEACON {
        return None;
    }
    if data[1] != DISCOVERY_VERSION {
        return None;
    }
    XOnlyPublicKey::from_slice(&data[2..34]).ok()
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
    pub fn add_peer(&self, src_mac: [u8; 6], pubkey: XOnlyPublicKey) {
        let addr = TransportAddr::from_bytes(&src_mac);
        let peer = DiscoveredPeer::with_hint(self.transport_id, addr, pubkey);
        let mut peers = self.peers.lock().unwrap();
        // Deduplicate by MAC address — keep the latest
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
    use secp256k1::{Secp256k1, SecretKey};

    fn test_pubkey() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let (xonly, _) = sk.public_key(&secp).x_only_public_key();
        xonly
    }

    #[test]
    fn test_build_parse_beacon() {
        let pubkey = test_pubkey();
        let beacon = build_beacon(&pubkey);

        assert_eq!(beacon.len(), BEACON_SIZE);
        assert_eq!(beacon[0], FRAME_TYPE_BEACON);
        assert_eq!(beacon[1], DISCOVERY_VERSION);

        let parsed = parse_beacon(&beacon).unwrap();
        assert_eq!(parsed, pubkey);
    }

    #[test]
    fn test_parse_beacon_too_short() {
        assert!(parse_beacon(&[0x01, 0x01]).is_none());
        assert!(parse_beacon(&[]).is_none());
    }

    #[test]
    fn test_parse_beacon_wrong_type() {
        let mut beacon = build_beacon(&test_pubkey());
        beacon[0] = 0x00; // data frame, not beacon
        assert!(parse_beacon(&beacon).is_none());
    }

    #[test]
    fn test_parse_beacon_wrong_version() {
        let mut beacon = build_beacon(&test_pubkey());
        beacon[1] = 0xFF;
        assert!(parse_beacon(&beacon).is_none());
    }

    #[test]
    fn test_frame_type_prefix() {
        assert_eq!(FRAME_TYPE_DATA, 0x00);
        assert_eq!(FRAME_TYPE_BEACON, 0x01);
    }

    #[test]
    fn test_discovery_buffer() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        let pubkey = test_pubkey();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        buffer.add_peer(mac, pubkey);

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr.as_bytes(), &mac);
        assert_eq!(peers[0].pubkey_hint, Some(pubkey));

        // Second take should be empty
        let peers = buffer.take();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_discovery_buffer_dedup() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        let pubkey = test_pubkey();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        buffer.add_peer(mac, pubkey);
        buffer.add_peer(mac, pubkey); // same MAC again

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);
    }
}
