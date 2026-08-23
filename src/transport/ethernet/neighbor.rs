//! Ethernet LAN neighbor detection via broadcast beacons.
//!
//! Beacon format (5 bytes total):
//! - Unified header (4 bytes): `[type:1][flags:1][length:2 LE]`
//! - Version (1 byte): beacon protocol version

use crate::transport::{DiscoveredPeer, TransportAddr, TransportId};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Mutex;
use tracing::warn;

/// Beacon protocol version.
pub const BEACON_VERSION: u8 = 0x01;

/// Frame type prefix for neighbor beacon frames.
pub const FRAME_TYPE_BEACON: u8 = 0x01;

/// Frame type prefix for FIPS data frames.
pub const FRAME_TYPE_DATA: u8 = 0x00;

/// Shared header size for all Ethernet frame types: type(1) + flags(1) + length(2).
pub const ETHERNET_HEADER_SIZE: usize = 4;

/// Beacon payload size: version(1).
pub const BEACON_PAYLOAD_SIZE: usize = 1;

/// Total beacon size: header(4) + payload(1).
pub const BEACON_SIZE: usize = ETHERNET_HEADER_SIZE + BEACON_PAYLOAD_SIZE;

/// Build a neighbor beacon payload.
pub fn build_beacon() -> [u8; BEACON_SIZE] {
    let mut buf = [0u8; BEACON_SIZE];
    buf[0] = FRAME_TYPE_BEACON;
    buf[1] = 0x00; // flags (reserved)
    buf[2..4].copy_from_slice(&(BEACON_PAYLOAD_SIZE as u16).to_le_bytes());
    buf[4] = BEACON_VERSION;
    buf
}

/// Parse a neighbor beacon payload.
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
    data[4] == BEACON_VERSION
}

/// How many distinct source MACs the discovery buffer holds between drains.
///
/// Beacons are unauthenticated broadcast frames, so anything on the segment
/// can name as many source MACs as it likes; without a bound the buffer grows
/// with the flood rate, and it is not drained at all while the transport is
/// not operational. This caps it at roughly a thousand small structs, tens of
/// kilobytes. Raising it costs that much more memory per transport; lowering
/// it risks truncating discovery on a very large segment. A thousand distinct
/// beaconing FIPS neighbors within one tick is far outside anything a real
/// deployment produces.
const MAX_BUFFERED_PEERS: usize = 1024;

/// Buffer for discovered peers, drained by `discover()`.
pub struct NeighborBuffer {
    transport_id: TransportId,
    peers: Mutex<Buffered>,
}

/// Peers keyed by source MAC, plus the sighting order `take()` restores.
#[derive(Default)]
struct Buffered {
    by_mac: HashMap<[u8; 6], (u64, DiscoveredPeer)>,
    seq: u64,
    /// Beacons refused for want of room, cumulative and never reset.
    dropped: u64,
    /// Cumulative drop count that earns the next log record.
    warn_at: u64,
}

impl NeighborBuffer {
    /// Create a new empty neighbor buffer.
    pub fn new(transport_id: TransportId) -> Self {
        Self {
            transport_id,
            peers: Mutex::new(Buffered::default()),
        }
    }

    /// Add a discovered peer from a received beacon.
    ///
    /// Returns false when the beacon was refused because the buffer is full.
    /// A MAC already buffered is always refreshed, so a flood of new MACs
    /// cannot stop a known neighbor from being seen again.
    pub fn add_peer(&self, src_mac: [u8; 6]) -> bool {
        let mut buffered = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        buffered.seq += 1;
        let seq = buffered.seq;
        let full = buffered.by_mac.len() >= MAX_BUFFERED_PEERS;
        let peer = self.peer(src_mac);
        let stored = match buffered.by_mac.entry(src_mac) {
            // Refreshing moves the MAC to the end, as retain-then-push did.
            Entry::Occupied(mut slot) => {
                slot.insert((seq, peer));
                true
            }
            Entry::Vacant(slot) if !full => {
                slot.insert((seq, peer));
                true
            }
            Entry::Vacant(_) => false,
        };
        if !stored {
            buffered.dropped += 1;
        }
        stored
    }

    /// Drain all discovered peers since the last call, oldest sighting first.
    pub fn take(&self) -> Vec<DiscoveredPeer> {
        let mut buffered = self.peers.lock().unwrap_or_else(|e| e.into_inner());
        let mut ordered: Vec<(u64, DiscoveredPeer)> =
            buffered.by_mac.drain().map(|(_, entry)| entry).collect();
        // The reconcile layer spends a finite connect budget in this order, so
        // which neighbor gets dialed must not depend on hash iteration order.
        ordered.sort_unstable_by_key(|(seq, _)| *seq);
        // Rate-limited: the drop rate is whatever the flooder chooses, and one
        // record per drain would hand it the log volume too.
        if buffered.dropped >= buffered.warn_at.max(1) {
            warn!(
                transport_id = %self.transport_id,
                dropped = buffered.dropped,
                cap = MAX_BUFFERED_PEERS,
                "discovery buffer full, beacons from unseen neighbors refused"
            );
            buffered.warn_at = next_decade(buffered.dropped);
        }
        ordered.into_iter().map(|(_, peer)| peer).collect()
    }

    /// Beacons refused for want of room since this buffer was created.
    pub fn dropped(&self) -> u64 {
        self.peers.lock().unwrap_or_else(|e| e.into_inner()).dropped
    }

    /// Build the buffered peer record for one beacon.
    ///
    /// This line's beacon carries no key, so there is no pubkey hint to
    /// attach: the identity is learned from the handshake instead.
    fn peer(&self, src_mac: [u8; 6]) -> DiscoveredPeer {
        let addr = TransportAddr::from_bytes(&src_mac);
        DiscoveredPeer::new(self.transport_id, addr)
    }
}

/// Smallest power of ten strictly greater than `n`, saturating at `u64::MAX`.
fn next_decade(n: u64) -> u64 {
    let mut threshold = 1u64;
    while threshold <= n {
        match threshold.checked_mul(10) {
            Some(next) => threshold = next,
            None => return u64::MAX,
        }
    }
    threshold
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
        assert_eq!(beacon[4], BEACON_VERSION);

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
    fn test_neighbor_buffer() {
        let buffer = NeighborBuffer::new(TransportId::new(1));
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
    fn test_neighbor_buffer_dedup() {
        let buffer = NeighborBuffer::new(TransportId::new(1));
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

    /// Distinct MAC number `n`, for filling the buffer.
    fn nth_mac(n: usize) -> [u8; 6] {
        let bytes = (n as u64).to_be_bytes();
        [0x02, bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
    }

    #[test]
    fn discovery_buffer_stops_buffering_past_the_cap() {
        // The defect: an unauthenticated flood of source MACs grew the buffer
        // without bound. Fails against the uncapped Vec, which returns all of
        // them.
        let buffer = NeighborBuffer::new(TransportId::new(1));
        for n in 0..MAX_BUFFERED_PEERS + 50 {
            buffer.add_peer(nth_mac(n));
        }

        let peers = buffer.take();
        assert_eq!(peers.len(), MAX_BUFFERED_PEERS);
        // Drop-new keeps the earliest sightings.
        assert_eq!(peers[0].addr.as_bytes(), &nth_mac(0));
    }

    #[test]
    fn discovery_buffer_counts_dropped_beacons() {
        let buffer = NeighborBuffer::new(TransportId::new(1));
        for n in 0..MAX_BUFFERED_PEERS {
            assert!(buffer.add_peer(nth_mac(n)));
        }
        for n in MAX_BUFFERED_PEERS..MAX_BUFFERED_PEERS + 7 {
            assert!(!buffer.add_peer(nth_mac(n)));
        }

        assert_eq!(buffer.dropped(), 7);
    }

    #[test]
    fn discovery_buffer_repeat_beacon_from_a_full_buffer_still_refreshes() {
        let buffer = NeighborBuffer::new(TransportId::new(1));
        for n in 0..MAX_BUFFERED_PEERS + 50 {
            buffer.add_peer(nth_mac(n));
        }
        // A neighbor already buffered must not be refused by a full buffer.
        assert!(buffer.add_peer(nth_mac(0)));

        let peers = buffer.take();
        assert_eq!(peers.len(), MAX_BUFFERED_PEERS);
        assert_eq!(peers[peers.len() - 1].addr.as_bytes(), &nth_mac(0));
    }

    #[test]
    fn discovery_buffer_drain_preserves_last_seen_order() {
        // A regression pin on the map rewrite rather than a test of the
        // defect: retain-then-push already produced this order.
        let buffer = NeighborBuffer::new(TransportId::new(1));
        let a = [0xaa; 6];
        let b = [0xbb; 6];
        let c = [0xcc; 6];

        buffer.add_peer(a);
        buffer.add_peer(b);
        buffer.add_peer(c);
        buffer.add_peer(a);

        let macs: Vec<_> = buffer
            .take()
            .iter()
            .map(|p| p.addr.as_bytes().to_vec())
            .collect();
        assert_eq!(macs, vec![b.to_vec(), c.to_vec(), a.to_vec()]);
    }

    #[test]
    fn next_decade_steps_by_powers_of_ten() {
        assert_eq!(next_decade(0), 1);
        assert_eq!(next_decade(1), 10);
        assert_eq!(next_decade(9), 10);
        assert_eq!(next_decade(10), 100);
        assert_eq!(next_decade(u64::MAX), u64::MAX);
    }
}
