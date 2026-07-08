//! Tests for the discovery wire codec (`LookupRequest` / `LookupResponse`).

use super::util::{make_coords, signed_response};
use crate::proto::discovery::{LookupRequest, LookupResponse};
use crate::testutil::make_node_addr;

#[test]
fn test_lookup_request_forward() {
    let target = make_node_addr(1);
    let origin = make_node_addr(2);
    let coords = make_coords(&[2, 0]);

    let mut request = LookupRequest::new(123, target, origin, coords, 5, 0);

    assert!(request.can_forward());
    assert!(request.forward());
    assert_eq!(request.ttl, 4);
}

#[test]
fn test_lookup_request_ttl_exhausted() {
    let target = make_node_addr(1);
    let origin = make_node_addr(2);
    let coords = make_coords(&[2, 0]);

    let mut request = LookupRequest::new(123, target, origin, coords, 1, 0);

    assert!(request.forward());
    assert!(!request.can_forward());
    assert!(!request.forward());
}

#[test]
fn test_lookup_request_generate() {
    let target = make_node_addr(1);
    let origin = make_node_addr(2);
    let coords = make_coords(&[2, 0]);

    use rand::RngExt;
    let req1 = LookupRequest::new(rand::rng().random(), target, origin, coords.clone(), 5, 0);
    let req2 = LookupRequest::new(rand::rng().random(), target, origin, coords, 5, 0);

    // Random IDs should differ
    assert_ne!(req1.request_id, req2.request_id);
}

#[test]
fn test_lookup_response_proof_bytes() {
    let target = make_node_addr(42);
    let coords = make_coords(&[42, 1, 0]);
    let bytes = LookupResponse::proof_bytes(12345, &target, &coords);

    // 8 (request_id) + 16 (target) + 2 (count) + 3*16 (coords) = 74
    assert_eq!(bytes.len(), 74);
    assert_eq!(&bytes[0..8], &12345u64.to_le_bytes());
    assert_eq!(&bytes[8..24], target.as_bytes());

    // Verify coordinate encoding is present
    let count = u16::from_le_bytes([bytes[24], bytes[25]]);
    assert_eq!(count, 3); // 3 entries in coords
}

#[test]
fn test_lookup_request_encode_decode_roundtrip() {
    let target = make_node_addr(10);
    let origin = make_node_addr(20);
    let coords = make_coords(&[20, 0]);

    let mut request = LookupRequest::new(12345, target, origin, coords, 8, 1386);
    request.forward();

    let encoded = request.encode();
    assert_eq!(encoded[0], 0x30);

    let decoded = LookupRequest::decode(&encoded[1..]).unwrap();
    assert_eq!(decoded.request_id, 12345);
    assert_eq!(decoded.target, target);
    assert_eq!(decoded.origin, origin);
    assert_eq!(decoded.ttl, 7); // decremented by forward()
    assert_eq!(decoded.min_mtu, 1386);
}

#[test]
fn test_lookup_request_decode_too_short() {
    assert!(LookupRequest::decode(&[]).is_err());
    assert!(LookupRequest::decode(&[0u8; 42]).is_err());
}

#[test]
fn test_lookup_request_min_mtu_boundary_values() {
    let target = make_node_addr(10);
    let origin = make_node_addr(20);
    let coords = make_coords(&[20, 0]);

    for mtu_val in [0u16, 1386, u16::MAX] {
        let request = LookupRequest::new(100, target, origin, coords.clone(), 5, mtu_val);
        let encoded = request.encode();
        let decoded = LookupRequest::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.min_mtu, mtu_val);
    }
}

#[test]
fn test_lookup_response_encode_decode_roundtrip() {
    let target = make_node_addr(42);
    let coords = make_coords(&[42, 1, 0]);

    let response = signed_response(999, &target, &coords);

    // Default path_mtu should be u16::MAX
    assert_eq!(response.path_mtu, u16::MAX);

    let encoded = response.encode();
    assert_eq!(encoded[0], 0x31);

    let decoded = LookupResponse::decode(&encoded[1..]).unwrap();
    assert_eq!(decoded.request_id, 999);
    assert_eq!(decoded.target, target);
    assert_eq!(decoded.path_mtu, u16::MAX);
    assert_eq!(decoded.proof, response.proof);
}

#[test]
fn test_lookup_response_path_mtu_roundtrip() {
    let target = make_node_addr(42);
    let coords = make_coords(&[42, 1, 0]);

    let base = signed_response(999, &target, &coords);

    for mtu_val in [0u16, 1280, 1386, 9000, u16::MAX] {
        let mut response = base.clone();
        response.path_mtu = mtu_val;

        let encoded = response.encode();
        let decoded = LookupResponse::decode(&encoded[1..]).unwrap();
        assert_eq!(decoded.path_mtu, mtu_val);
    }
}

#[test]
fn test_lookup_response_path_mtu_not_in_proof_bytes() {
    // Verify that proof_bytes does NOT include path_mtu
    let target = make_node_addr(42);
    let coords = make_coords(&[42, 1, 0]);

    let bytes = LookupResponse::proof_bytes(12345, &target, &coords);

    // proof_bytes format: request_id(8) + target(16) + coords_encoding(2 + 3*16) = 74
    // No path_mtu(2) in here
    assert_eq!(bytes.len(), 74);
}

#[test]
fn test_lookup_response_decode_too_short() {
    assert!(LookupResponse::decode(&[]).is_err());
    assert!(LookupResponse::decode(&[0u8; 50]).is_err());
}
