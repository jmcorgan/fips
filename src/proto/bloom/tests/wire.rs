//! Tests for the bloom wire codec (`FilterAnnounce`).

use crate::proto::bloom::BloomFilter;
use crate::proto::bloom::FilterAnnounce;
use crate::proto::link::LinkMessageType;
use crate::testutil::make_node_addr;

#[test]
fn test_filter_announce_size_class() {
    let filter = BloomFilter::new();
    let announce = FilterAnnounce::new(filter.clone(), 100);

    // v1 defaults
    assert_eq!(announce.size_class, 1);
    assert_eq!(announce.hash_count, 5);
    assert!(announce.is_v1_compliant());
    assert!(announce.is_valid());
    assert_eq!(announce.filter_size_bytes(), 1024);
}

#[test]
fn test_filter_announce_with_size_class() {
    let filter = BloomFilter::with_params(2048 * 8, 7).unwrap();
    let announce = FilterAnnounce::with_size_class(filter, 100, 2);

    assert_eq!(announce.size_class, 2);
    assert_eq!(announce.hash_count, 7);
    assert!(!announce.is_v1_compliant());
    assert!(announce.is_valid());
    assert_eq!(announce.filter_size_bytes(), 2048);
}

#[test]
fn test_filter_announce_encode_decode_roundtrip() {
    let mut filter = BloomFilter::new();
    filter.insert(&make_node_addr(42));
    filter.insert(&make_node_addr(99));
    let announce = FilterAnnounce::new(filter, 500);

    let encoded = announce.encode().unwrap();
    // msg_type(1) + sequence(8) + hash_count(1) + size_class(1) + filter(1024)
    assert_eq!(encoded.len(), 1035);
    assert_eq!(encoded[0], LinkMessageType::FilterAnnounce.to_byte());

    // Decode strips msg_type (as dispatcher does)
    let decoded = FilterAnnounce::decode(&encoded[1..]).unwrap();
    assert_eq!(decoded.sequence, 500);
    assert_eq!(decoded.hash_count, 5);
    assert_eq!(decoded.size_class, 1);
    assert!(decoded.is_valid());
    assert!(decoded.is_v1_compliant());

    // Filter contents preserved
    assert!(decoded.filter.contains(&make_node_addr(42)));
    assert!(decoded.filter.contains(&make_node_addr(99)));
    assert!(!decoded.filter.contains(&make_node_addr(1)));
}

#[test]
fn test_filter_announce_decode_rejects_bad_size_class() {
    let filter = BloomFilter::new();
    let announce = FilterAnnounce::new(filter, 100);
    let mut encoded = announce.encode().unwrap();

    // Corrupt size_class byte (offset: 1 msg_type + 8 seq + 1 hash = 10)
    encoded[10] = 5; // invalid size_class > MAX_SIZE_CLASS

    let result = FilterAnnounce::decode(&encoded[1..]);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("invalid size_class")
    );
}

#[test]
fn test_filter_announce_decode_rejects_non_v1_size_class() {
    // Build a size_class=0 payload manually (valid range but not v1)
    let filter = BloomFilter::with_params(512 * 8, 5).unwrap();
    let announce = FilterAnnounce::with_size_class(filter, 100, 0);
    let encoded = announce.encode().unwrap();

    let result = FilterAnnounce::decode(&encoded[1..]);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("unsupported size_class")
    );
}

#[test]
fn test_filter_announce_decode_rejects_truncated() {
    let result = FilterAnnounce::decode(&[0u8; 5]);
    assert!(result.is_err());
}
