//! Tests for the lookup wire codec (`LookupRequest` / `LookupResponse`).

use super::util::{make_coords, signed_response};
use crate::proto::lookup::{LookupRequest, LookupResponse};
use crate::testutil::make_node_addr;

#[test]
fn test_lookup_request_forward() {
    let target = make_node_addr(1);
    let origin = make_node_addr(2);

    let mut request = LookupRequest::new(123, target, origin, 5, 0);

    assert!(request.can_forward());
    assert!(request.forward());
    assert_eq!(request.ttl, 4);
}

#[test]
fn test_lookup_request_ttl_exhausted() {
    let target = make_node_addr(1);
    let origin = make_node_addr(2);

    let mut request = LookupRequest::new(123, target, origin, 1, 0);

    assert!(request.forward());
    assert!(!request.can_forward());
    assert!(!request.forward());
}

#[test]
fn test_lookup_request_generate() {
    let target = make_node_addr(1);
    let origin = make_node_addr(2);

    use rand::RngExt;
    let req1 = LookupRequest::new(rand::rng().random(), target, origin, 5, 0);
    let req2 = LookupRequest::new(rand::rng().random(), target, origin, 5, 0);

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

    let mut request = LookupRequest::new(12345, target, origin, 8, 1386);
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

    for mtu_val in [0u16, 1386, u16::MAX] {
        let request = LookupRequest::new(100, target, origin, 5, mtu_val);
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

#[test]
fn test_lookup_request_with_tlv_roundtrip() {
    let target = make_node_addr(10);
    let origin = make_node_addr(20);

    let request = LookupRequest::new(555, target, origin, 5, 1280)
        .with_tlv(1, vec![0xAA, 0xBB])
        .with_tlv(256, vec![0x01, 0x02, 0x03, 0x04]);

    let encoded = request.encode();
    let decoded = LookupRequest::decode(&encoded[1..]).unwrap();

    assert_eq!(decoded.request_id, 555);
    assert_eq!(decoded.min_mtu, 1280);
    assert_eq!(decoded.tlv_entries.len(), 2);
    assert_eq!(decoded.tlv_entries[0].field_num, 1);
    assert_eq!(decoded.tlv_entries[0].value, vec![0xAA, 0xBB]);
    assert_eq!(decoded.tlv_entries[1].field_num, 256);
    assert_eq!(decoded.tlv_entries[1].value, vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn test_lookup_request_tlv_forward_compat() {
    // Unknown field_nums should be preserved through decode → forward → encode.
    let target = make_node_addr(10);
    let origin = make_node_addr(20);

    let request =
        LookupRequest::new(777, target, origin, 5, 0).with_tlv(9999, vec![0xFF, 0xFE, 0xFD]);

    let encoded = request.encode();
    let mut decoded = LookupRequest::decode(&encoded[1..]).unwrap();

    // Simulate transit: forward then re-encode.
    decoded.forward();
    let re_encoded = decoded.encode();
    let final_decoded = LookupRequest::decode(&re_encoded[1..]).unwrap();

    assert_eq!(final_decoded.ttl, 4);
    assert_eq!(final_decoded.tlv_entries.len(), 1);
    assert_eq!(final_decoded.tlv_entries[0].field_num, 9999);
    assert_eq!(final_decoded.tlv_entries[0].value, vec![0xFF, 0xFE, 0xFD]);
}

#[test]
fn test_lookup_response_with_tlv_roundtrip() {
    let target = make_node_addr(42);
    let coords = make_coords(&[42, 1, 0]);

    let response = signed_response(999, &target, &coords)
        .with_tlv(1, vec![0xAA, 0xBB])
        .with_tlv(500, vec![0x01, 0x02, 0x03]);

    let encoded = response.encode();
    let decoded = LookupResponse::decode(&encoded[1..]).unwrap();

    assert_eq!(decoded.request_id, 999);
    assert_eq!(decoded.proof, response.proof);
    assert_eq!(decoded.tlv_entries.len(), 2);
    assert_eq!(decoded.tlv_entries[0].field_num, 1);
    assert_eq!(decoded.tlv_entries[0].value, vec![0xAA, 0xBB]);
    assert_eq!(decoded.tlv_entries[1].field_num, 500);
    assert_eq!(decoded.tlv_entries[1].value, vec![0x01, 0x02, 0x03]);
}

#[test]
fn test_lookup_response_tlv_forward_compat() {
    // Unknown field_nums preserved through decode → modify path_mtu → encode.
    let target = make_node_addr(42);
    let coords = make_coords(&[42, 1, 0]);

    let response = signed_response(999, &target, &coords).with_tlv(9999, vec![0xFF, 0xFE, 0xFD]);

    let encoded = response.encode();
    let mut decoded = LookupResponse::decode(&encoded[1..]).unwrap();

    // Simulate transit: modify path_mtu then re-encode.
    decoded.path_mtu = 1280;
    let re_encoded = decoded.encode();
    let final_decoded = LookupResponse::decode(&re_encoded[1..]).unwrap();

    assert_eq!(final_decoded.path_mtu, 1280);
    assert_eq!(final_decoded.tlv_entries.len(), 1);
    assert_eq!(final_decoded.tlv_entries[0].field_num, 9999);
    assert_eq!(final_decoded.tlv_entries[0].value, vec![0xFF, 0xFE, 0xFD]);
}
