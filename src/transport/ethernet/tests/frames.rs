//! The per-frame receive rules and the destination check, without a socket.
//!
//! A MAC whose first octet has its low bit set is a group address (multicast
//! or broadcast). It is never a valid unicast sender, so a frame claiming one
//! as its source is dropped before dispatch, and nothing but the beacon itself
//! is sent to one.

use super::*;
use secp256k1::{Secp256k1, SecretKey};

/// A unicast source: the low bit of the first octet is clear.
const UNICAST: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

/// An IPv4 multicast group address.
const MULTICAST: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01];

/// The broadcast address.
const BROADCAST: [u8; 6] = [0xff; 6];

fn pubkey() -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
    sk.public_key(&secp).x_only_public_key().0
}

/// A data frame carrying `payload`: type, little-endian length, payload.
fn data_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![FRAME_TYPE_DATA];
    frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Run one frame through the dispatch with listening on, returning what it
/// delivered and the discovery buffer's contents afterwards.
fn dispatch(
    frame: &[u8],
    src: [u8; 6],
) -> (Option<ReceivedPacket>, Vec<DiscoveredPeer>, EthernetStats) {
    let neighbors = NeighborBuffer::new(TransportId::new(1));
    let stats = EthernetStats::new();
    let packet = dispatch_frame(frame, src, true, &neighbors, &stats, TransportId::new(1));
    (packet, neighbors.take(), stats)
}

#[test]
fn a_beacon_from_a_group_source_is_not_buffered() {
    for src in [MULTICAST, BROADCAST] {
        let (packet, buffered, stats) = dispatch(&build_beacon(&pubkey()), src);
        assert!(packet.is_none());
        assert_eq!(stats.snapshot().group_drops, 1, "the drop is counted");
        assert!(
            buffered.is_empty(),
            "a beacon from {} was buffered for dialing",
            format_mac(&src)
        );
    }
}

#[test]
fn a_data_frame_from_a_group_source_is_not_delivered() {
    for src in [MULTICAST, BROADCAST] {
        let (packet, _buffered, stats) = dispatch(&data_frame(b"payload"), src);
        assert_eq!(stats.snapshot().group_drops, 1, "the drop is counted");
        assert!(
            packet.is_none(),
            "a data frame from {} was delivered",
            format_mac(&src)
        );
    }
}

#[test]
fn a_group_destination_is_refused() {
    for dst in [MULTICAST, BROADCAST] {
        let result = parse_mac_addr(&TransportAddr::from_bytes(&dst));
        assert!(
            matches!(result, Err(TransportError::InvalidAddress(_))),
            "a send to {} was not refused: {result:?}",
            format_mac(&dst)
        );
    }
}

#[test]
fn a_beacon_from_a_unicast_source_is_buffered() {
    let (packet, buffered, stats) = dispatch(&build_beacon(&pubkey()), UNICAST);
    assert!(packet.is_none());
    assert_eq!(buffered.len(), 1, "the beacon was not buffered");
    assert_eq!(buffered[0].addr, TransportAddr::from_mac(UNICAST));
    assert_eq!(stats.snapshot().beacons_recv, 1);
    assert_eq!(stats.snapshot().group_drops, 0);
}

#[test]
fn a_data_frame_from_a_unicast_source_is_delivered() {
    let (packet, _buffered, _stats) = dispatch(&data_frame(b"payload"), UNICAST);
    let packet = packet.expect("the data frame was not delivered");
    assert_eq!(packet.remote_addr, TransportAddr::from_mac(UNICAST));
    assert_eq!(packet.data, b"payload");
}

#[test]
fn a_unicast_destination_is_accepted() {
    let mac = parse_mac_addr(&TransportAddr::from_bytes(&UNICAST)).unwrap();
    assert_eq!(mac, UNICAST);
}
