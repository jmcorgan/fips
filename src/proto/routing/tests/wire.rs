//! Tests for the routing error-signal wire PDUs (`CoordsRequired`,
//! `PathBroken`, `MtuExceeded`).

use super::util::make_coords;
use crate::proto::routing::{
    COORDS_REQUIRED_SIZE, CoordsRequired, MTU_EXCEEDED_SIZE, MtuExceeded, PathBroken,
};
use crate::testutil::make_node_addr;

#[test]
fn test_coords_required() {
    let err = CoordsRequired::new(make_node_addr(1), make_node_addr(2));

    assert_eq!(err.dest_addr, make_node_addr(1));
    assert_eq!(err.reporter, make_node_addr(2));
}

#[test]
fn test_path_broken() {
    let err = PathBroken::new(make_node_addr(2), make_node_addr(3))
        .with_last_coords(make_coords(&[2, 0]));

    assert_eq!(err.dest_addr, make_node_addr(2));
    assert_eq!(err.reporter, make_node_addr(3));
    assert!(err.last_known_coords.is_some());
}

#[test]
fn test_coords_required_encode_decode() {
    let err = CoordsRequired::new(make_node_addr(0xAA), make_node_addr(0xBB));

    let encoded = err.encode();
    // 4 prefix + 1 msg_type + 1 flags + 16 dest + 16 reporter = 38
    assert_eq!(encoded.len(), 4 + COORDS_REQUIRED_SIZE);
    // Check FSP prefix: phase 0x0, U flag
    assert_eq!(encoded[0], 0x00);
    assert_eq!(encoded[1], 0x04); // U flag
    // msg_type after prefix
    assert_eq!(encoded[4], 0x20);

    // decode after prefix + msg_type consumed
    let decoded = CoordsRequired::decode(&encoded[5..]).unwrap();
    assert_eq!(decoded.dest_addr, err.dest_addr);
    assert_eq!(decoded.reporter, err.reporter);
}

#[test]
fn test_path_broken_encode_decode_no_coords() {
    let err = PathBroken::new(make_node_addr(0xCC), make_node_addr(0xDD));

    let encoded = err.encode();
    // Check FSP prefix
    assert_eq!(encoded[0], 0x00);
    assert_eq!(encoded[1], 0x04); // U flag
    assert_eq!(encoded[4], 0x21); // msg_type

    let decoded = PathBroken::decode(&encoded[5..]).unwrap();
    assert_eq!(decoded.dest_addr, err.dest_addr);
    assert_eq!(decoded.reporter, err.reporter);
    assert!(decoded.last_known_coords.is_none());
}

#[test]
fn test_path_broken_encode_decode_with_coords() {
    let coords = make_coords(&[0xCC, 0xDD, 0xEE]);
    let err = PathBroken::new(make_node_addr(0x11), make_node_addr(0x22))
        .with_last_coords(coords.clone());

    let encoded = err.encode();
    let decoded = PathBroken::decode(&encoded[5..]).unwrap();

    assert_eq!(decoded.dest_addr, err.dest_addr);
    assert_eq!(decoded.reporter, err.reporter);
    assert_eq!(decoded.last_known_coords.unwrap(), coords);
}

#[test]
fn test_coords_required_decode_too_short() {
    assert!(CoordsRequired::decode(&[]).is_err());
    assert!(CoordsRequired::decode(&[0x00; 10]).is_err());
}

#[test]
fn test_path_broken_decode_too_short() {
    assert!(PathBroken::decode(&[]).is_err());
    assert!(PathBroken::decode(&[0x00; 20]).is_err());
}

#[test]
fn test_mtu_exceeded_encode_size() {
    let err = MtuExceeded::new(make_node_addr(0xAA), make_node_addr(0xBB), 1400);
    let encoded = err.encode();
    // 4 prefix + 36 body = 40
    assert_eq!(encoded.len(), 4 + MTU_EXCEEDED_SIZE);
}

#[test]
fn test_mtu_exceeded_encode_decode() {
    let err = MtuExceeded::new(make_node_addr(0xAA), make_node_addr(0xBB), 1400);

    let encoded = err.encode();
    // Check FSP prefix: phase 0x0, U flag
    assert_eq!(encoded[0], 0x00);
    assert_eq!(encoded[1], 0x04); // U flag
    // msg_type after prefix
    assert_eq!(encoded[4], 0x22);

    // decode after prefix + msg_type consumed
    let decoded = MtuExceeded::decode(&encoded[5..]).unwrap();
    assert_eq!(decoded.dest_addr, err.dest_addr);
    assert_eq!(decoded.reporter, err.reporter);
    assert_eq!(decoded.mtu, 1400);
}

#[test]
fn test_mtu_exceeded_decode_too_short() {
    assert!(MtuExceeded::decode(&[]).is_err());
    assert!(MtuExceeded::decode(&[0x00; 20]).is_err());
    assert!(MtuExceeded::decode(&[0x00; 34]).is_err()); // exactly 1 byte short
}

#[test]
fn test_mtu_exceeded_boundary_mtu_values() {
    for mtu in [0u16, 1280, 1500, u16::MAX] {
        let err = MtuExceeded::new(make_node_addr(1), make_node_addr(2), mtu);
        let encoded = err.encode();
        let decoded = MtuExceeded::decode(&encoded[5..]).unwrap();
        assert_eq!(decoded.mtu, mtu);
    }
}
