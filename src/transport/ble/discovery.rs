//! BLE discovery via advertising and scanning.
//!
//! BLE advertisements carry a 128-bit FIPS service UUID for identification.
//! Post-forklift, advertisements are UUID-only (no identity material);
//! identity is exchanged during the Noise handshake.

use crate::transport::{DiscoveredPeer, TransportId};
use std::sync::Mutex;

use super::addr::BleAddr;

/// Buffer for discovered BLE peers, drained by `discover()`.
///
/// Follows the same pattern as Ethernet's `DiscoveryBuffer`: peers are
/// added from the scan loop and drained by the node's discovery polling.
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

    /// Add a discovered BLE peer.
    ///
    /// Deduplicates by device address — keeps the latest entry.
    pub fn add_peer(&self, addr: &BleAddr) {
        let ta = addr.to_transport_addr();
        let peer = DiscoveredPeer::new(self.transport_id, ta.clone());
        let mut peers = self.peers.lock().unwrap();
        // Deduplicate by address string
        let addr_str = addr.to_string_repr();
        peers.retain(|p| p.addr.as_str() != Some(addr_str.as_str()));
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
    use crate::transport::TransportAddr;

    fn test_addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    #[test]
    fn test_discovery_buffer_add_take() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        buffer.add_peer(&test_addr(1));

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);

        // Second take should be empty
        let peers = buffer.take();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_discovery_buffer_dedup() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        buffer.add_peer(&test_addr(1));
        buffer.add_peer(&test_addr(1)); // same address again

        let peers = buffer.take();
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_discovery_buffer_multiple_peers() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        buffer.add_peer(&test_addr(1));
        buffer.add_peer(&test_addr(2));
        buffer.add_peer(&test_addr(3));

        let peers = buffer.take();
        assert_eq!(peers.len(), 3);
    }

    #[test]
    fn test_discovery_buffer_transport_addr_format() {
        let buffer = DiscoveryBuffer::new(TransportId::new(1));
        buffer.add_peer(&test_addr(0x42));

        let peers = buffer.take();
        assert_eq!(
            peers[0].addr,
            TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:42")
        );
    }
}
