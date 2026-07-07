//! Tests for the `BloomFilter` data structure.

use crate::proto::bloom::{BloomError, BloomFilter, DEFAULT_FILTER_SIZE_BITS, DEFAULT_HASH_COUNT};
use crate::testutil::make_node_addr;

#[test]
fn test_bloom_filter_new() {
    let filter = BloomFilter::new();
    assert_eq!(filter.num_bits(), DEFAULT_FILTER_SIZE_BITS);
    assert_eq!(filter.hash_count(), DEFAULT_HASH_COUNT);
    assert_eq!(filter.count_ones(), 0);
    assert!(filter.is_empty());
}

#[test]
fn test_bloom_filter_insert_contains() {
    let mut filter = BloomFilter::new();
    let node1 = make_node_addr(1);
    let node2 = make_node_addr(2);

    assert!(!filter.contains(&node1));
    assert!(!filter.contains(&node2));

    filter.insert(&node1);

    assert!(filter.contains(&node1));
    // node2 might have false positive, but very unlikely with single insert
    assert!(!filter.is_empty());
}

#[test]
fn test_bloom_filter_multiple_inserts() {
    let mut filter = BloomFilter::new();

    for i in 0..100 {
        let node = make_node_addr(i);
        filter.insert(&node);
    }

    // All inserted items should be found
    for i in 0..100 {
        let node = make_node_addr(i);
        assert!(filter.contains(&node), "Node {} not found", i);
    }

    // Fill ratio should be reasonable
    let fill = filter.fill_ratio();
    assert!(fill > 0.0 && fill < 0.5, "Unexpected fill ratio: {}", fill);
}

#[test]
fn test_bloom_filter_merge() {
    let mut filter1 = BloomFilter::new();
    let mut filter2 = BloomFilter::new();

    let node1 = make_node_addr(1);
    let node2 = make_node_addr(2);

    filter1.insert(&node1);
    filter2.insert(&node2);

    filter1.merge(&filter2).unwrap();

    assert!(filter1.contains(&node1));
    assert!(filter1.contains(&node2));
}

#[test]
fn test_bloom_filter_union() {
    let mut filter1 = BloomFilter::new();
    let mut filter2 = BloomFilter::new();

    let node1 = make_node_addr(1);
    let node2 = make_node_addr(2);

    filter1.insert(&node1);
    filter2.insert(&node2);

    let union = filter1.union(&filter2).unwrap();

    assert!(union.contains(&node1));
    assert!(union.contains(&node2));
    // Original filters unchanged
    assert!(!filter1.contains(&node2));
    assert!(!filter2.contains(&node1));
}

#[test]
fn test_bloom_filter_clear() {
    let mut filter = BloomFilter::new();
    let node = make_node_addr(1);

    filter.insert(&node);
    assert!(!filter.is_empty());

    filter.clear();
    assert!(filter.is_empty());
    assert_eq!(filter.count_ones(), 0);
    assert!(!filter.contains(&node));
}

#[test]
fn test_bloom_filter_merge_size_mismatch() {
    let mut filter1 = BloomFilter::with_params(1024, 7).unwrap();
    let filter2 = BloomFilter::with_params(2048, 7).unwrap();

    let result = filter1.merge(&filter2);
    assert!(matches!(result, Err(BloomError::InvalidSize { .. })));
}

#[test]
fn test_bloom_filter_custom_params() {
    let filter = BloomFilter::with_params(1024, 5).unwrap();
    assert_eq!(filter.num_bits(), 1024);
    assert_eq!(filter.num_bytes(), 128);
    assert_eq!(filter.hash_count(), 5);
}

#[test]
fn test_bloom_filter_invalid_params() {
    // Not byte-aligned (1001 is not divisible by 8)
    assert!(matches!(
        BloomFilter::with_params(1001, 7),
        Err(BloomError::SizeNotByteAligned(1001))
    ));

    // Zero size
    assert!(matches!(
        BloomFilter::with_params(0, 7),
        Err(BloomError::SizeNotByteAligned(0))
    ));

    // Zero hash count
    assert!(matches!(
        BloomFilter::with_params(1024, 0),
        Err(BloomError::ZeroHashCount)
    ));
}

#[test]
fn test_bloom_filter_from_bytes() {
    let original = BloomFilter::new();
    let bytes = original.as_bytes().to_vec();

    let restored = BloomFilter::from_bytes(bytes, original.hash_count()).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_bloom_filter_estimated_count() {
    let mut filter = BloomFilter::new();

    // Empty filter
    assert_eq!(filter.estimated_count(f64::INFINITY), Some(0.0));

    // Insert some items
    for i in 0..50 {
        filter.insert(&make_node_addr(i));
    }

    // Estimate should be reasonably close to 50
    let estimate = filter.estimated_count(f64::INFINITY).unwrap();
    assert!(
        estimate > 30.0 && estimate < 100.0,
        "Unexpected estimate: {}",
        estimate
    );
}

#[test]
fn test_bloom_filter_equality() {
    let mut filter1 = BloomFilter::new();
    let mut filter2 = BloomFilter::new();

    assert_eq!(filter1, filter2);

    filter1.insert(&make_node_addr(1));
    assert_ne!(filter1, filter2);

    filter2.insert(&make_node_addr(1));
    assert_eq!(filter1, filter2);
}

#[test]
fn test_bloom_filter_from_bytes_empty() {
    let result = BloomFilter::from_bytes(vec![], 5);
    assert!(matches!(result, Err(BloomError::SizeNotByteAligned(0))));
}

#[test]
fn test_bloom_filter_from_bytes_zero_hash_count() {
    let result = BloomFilter::from_bytes(vec![0u8; 128], 0);
    assert!(matches!(result, Err(BloomError::ZeroHashCount)));
}

#[test]
fn test_bloom_filter_from_slice() {
    let mut original = BloomFilter::new();
    original.insert(&make_node_addr(42));
    let bytes = original.as_bytes();

    let restored = BloomFilter::from_slice(bytes, original.hash_count()).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn test_bloom_filter_insert_bytes_contains_bytes() {
    let mut filter = BloomFilter::new();
    let data1 = b"hello world";
    let data2 = b"goodbye";

    assert!(!filter.contains_bytes(data1));

    filter.insert_bytes(data1);
    assert!(filter.contains_bytes(data1));
    assert!(!filter.contains_bytes(data2));

    filter.insert_bytes(data2);
    assert!(filter.contains_bytes(data1));
    assert!(filter.contains_bytes(data2));
}

#[test]
fn test_bloom_filter_estimated_count_saturated() {
    // Create a small filter with all bits set
    let bytes = vec![0xFF; 8]; // all bits set
    let filter = BloomFilter::from_bytes(bytes, 3).unwrap();

    // Saturated filter returns None regardless of cap (defense in depth).
    // Previously returned f64::INFINITY.
    assert_eq!(filter.estimated_count(f64::INFINITY), None);
    assert_eq!(filter.estimated_count(0.05), None);
}

#[test]
fn test_bloom_filter_estimated_count_fpr_cap_boundary() {
    // Cap boundary: FPR = fill^k = 0.05 at k=5 ⇒ fill ≈ 0.5493
    // 1KB filter (8192 bits). 560 bytes of 0xFF = 4480 bits set =
    // fill 0.5469, FPR ≈ 0.04877 — just below cap.
    // 564 bytes of 0xFF = 4512 bits set = fill 0.5508, FPR ≈ 0.05060 —
    // just above cap.

    let mut below = vec![0x00u8; 1024];
    below[..560].fill(0xFF);
    let below_filter = BloomFilter::from_bytes(below, DEFAULT_HASH_COUNT).unwrap();
    assert!(
        below_filter.estimated_count(0.05).is_some(),
        "fill 0.5469 (FPR ≈ 0.049) must be accepted by cap 0.05"
    );

    let mut above = vec![0x00u8; 1024];
    above[..564].fill(0xFF);
    let above_filter = BloomFilter::from_bytes(above, DEFAULT_HASH_COUNT).unwrap();
    assert_eq!(
        above_filter.estimated_count(0.05),
        None,
        "fill 0.5508 (FPR ≈ 0.051) must be rejected by cap 0.05"
    );

    // Same above-cap filter with a looser cap is accepted.
    assert!(
        above_filter.estimated_count(0.10).is_some(),
        "fill 0.5508 (FPR ≈ 0.051) must be accepted by cap 0.10"
    );
}

#[test]
fn test_bloom_filter_default() {
    let default: BloomFilter = Default::default();
    let explicit = BloomFilter::new();
    assert_eq!(default, explicit);
}

#[test]
fn test_bloom_filter_debug_format() {
    let mut filter = BloomFilter::new();
    let debug = format!("{:?}", filter);
    assert!(debug.contains("BloomFilter"));
    assert!(debug.contains("8192"));
    assert!(debug.contains("hash_count"));

    // With some entries
    for i in 0..10 {
        filter.insert(&make_node_addr(i));
    }
    let debug = format!("{:?}", filter);
    assert!(debug.contains("fill_ratio"));
    assert!(debug.contains("est_count"));
}
