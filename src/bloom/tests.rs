use super::*;
use crate::NodeAddr;
use std::collections::HashMap;

fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

// ===== BloomFilter Tests =====

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
fn test_bloom_filter_merge_cross_size_fold() {
    // Merge a 2KB filter into a 1KB filter (fold the larger)
    let mut filter1 = BloomFilter::with_params(1024 * 8, 5).unwrap();
    let mut filter2 = BloomFilter::with_params(2048 * 8, 5).unwrap();

    let node1 = make_node_addr(1);
    let node2 = make_node_addr(2);
    filter1.insert(&node1);
    filter2.insert(&node2);

    filter1.merge(&filter2).unwrap();

    assert!(filter1.contains(&node1));
    assert!(filter1.contains(&node2));
    assert_eq!(filter1.num_bits(), 1024 * 8); // size unchanged
}

#[test]
fn test_bloom_filter_merge_cross_size_duplicate() {
    // Merge a 512B filter into a 2KB filter (duplicate the smaller)
    let mut filter1 = BloomFilter::with_params(2048 * 8, 5).unwrap();
    let mut filter2 = BloomFilter::with_params(512 * 8, 5).unwrap();

    let node1 = make_node_addr(1);
    let node2 = make_node_addr(2);
    filter1.insert(&node1);
    filter2.insert(&node2);

    filter1.merge(&filter2).unwrap();

    assert!(filter1.contains(&node1));
    assert!(filter1.contains(&node2));
    assert_eq!(filter1.num_bits(), 2048 * 8);
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

    // Byte-aligned but not word-aligned (24 bits = 3 bytes, not 8)
    assert!(matches!(
        BloomFilter::with_params(24, 5),
        Err(BloomError::SizeNotWordAligned(24))
    ));
}

#[test]
fn test_bloom_filter_from_bytes_not_word_aligned() {
    // 5 bytes = 40 bits, not a multiple of 64
    let result = BloomFilter::from_bytes(vec![0u8; 5], 5);
    assert!(matches!(result, Err(BloomError::SizeNotWordAligned(40))));

    // 8 bytes = 64 bits, should succeed
    assert!(BloomFilter::from_bytes(vec![0u8; 8], 5).is_ok());
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

    let restored = BloomFilter::from_slice(&bytes, original.hash_count()).unwrap();
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
fn test_bloom_filter_as_bytes_round_trip() {
    let mut original = BloomFilter::new();
    for i in 0..50 {
        original.insert(&make_node_addr(i));
    }

    let bytes = original.as_bytes();
    let restored = BloomFilter::from_bytes(bytes, original.hash_count()).unwrap();
    assert_eq!(original, restored);

    // Verify all inserted elements are still found
    for i in 0..50 {
        assert!(restored.contains(&make_node_addr(i)));
    }
}

#[test]
fn test_bloom_filter_as_words() {
    let filter = BloomFilter::new();
    // Default 8192 bits = 128 words
    assert_eq!(filter.as_words().len(), 128);
    assert_eq!(filter.num_words(), 128);
    assert!(filter.as_words().iter().all(|&w| w == 0));

    // Small filter: 64 bits = 1 word
    let small = BloomFilter::with_params(64, 3).unwrap();
    assert_eq!(small.as_words().len(), 1);
    assert_eq!(small.num_words(), 1);
}

#[test]
fn test_bloom_filter_xor_diff_and_apply() {
    let mut filter_a = BloomFilter::new();
    let mut filter_b = BloomFilter::new();

    // Insert different elements into each
    for i in 0..20 {
        filter_a.insert(&make_node_addr(i));
    }
    for i in 10..30 {
        filter_b.insert(&make_node_addr(i));
    }

    // Compute diff: applying diff to A should yield B
    let diff = filter_a.xor_diff(&filter_b).unwrap();

    let mut reconstructed = filter_a.clone();
    reconstructed.apply_diff(&diff).unwrap();
    assert_eq!(reconstructed, filter_b);
}

#[test]
fn test_bloom_filter_xor_diff_identical() {
    let mut filter = BloomFilter::new();
    for i in 0..10 {
        filter.insert(&make_node_addr(i));
    }

    // XOR of identical filters should be all zeros
    let diff = filter.xor_diff(&filter).unwrap();
    assert!(diff.is_empty());
    assert_eq!(diff.count_ones(), 0);
}

#[test]
fn test_bloom_filter_xor_diff_size_mismatch() {
    let filter_a = BloomFilter::with_params(1024, 5).unwrap();
    let filter_b = BloomFilter::with_params(2048, 5).unwrap();

    assert!(matches!(
        filter_a.xor_diff(&filter_b),
        Err(BloomError::InvalidSize { .. })
    ));
}

#[test]
fn test_bloom_filter_apply_diff_size_mismatch() {
    let mut filter = BloomFilter::new();
    let diff = BloomFilter::with_params(1024, 5).unwrap();

    assert!(matches!(
        filter.apply_diff(&diff),
        Err(BloomError::InvalidSize { .. })
    ));
}

// ===== Fold/Duplicate/Convert Tests =====

#[test]
fn test_bloom_filter_fold() {
    // 2KB filter → fold to 1KB
    let mut filter = BloomFilter::with_params(2048 * 8, 5).unwrap();
    for i in 0..50 {
        filter.insert(&make_node_addr(i));
    }

    let folded = filter.fold().unwrap();
    assert_eq!(folded.num_bits(), 1024 * 8);

    // All inserted elements must still be found (no false negatives)
    for i in 0..50 {
        assert!(
            folded.contains(&make_node_addr(i)),
            "Node {} not found after fold",
            i
        );
    }

    // Fill ratio should roughly double
    let original_fill = filter.fill_ratio();
    let folded_fill = folded.fill_ratio();
    assert!(
        folded_fill > original_fill * 1.5,
        "Fill ratio didn't increase enough"
    );
}

#[test]
fn test_bloom_filter_fold_to() {
    // 4KB → fold to 512B (3 folds)
    let mut filter = BloomFilter::with_params(4096 * 8, 5).unwrap();
    for i in 0..20 {
        filter.insert(&make_node_addr(i));
    }

    let folded = filter.fold_to(512 * 8).unwrap();
    assert_eq!(folded.num_bits(), 512 * 8);

    for i in 0..20 {
        assert!(folded.contains(&make_node_addr(i)));
    }
}

#[test]
fn test_bloom_filter_fold_at_minimum() {
    let filter = BloomFilter::with_params(512 * 8, 5).unwrap();
    assert!(matches!(filter.fold(), Err(BloomError::CannotFold(_))));
}

#[test]
fn test_bloom_filter_duplicate() {
    let mut filter = BloomFilter::with_params(1024 * 8, 5).unwrap();
    for i in 0..50 {
        filter.insert(&make_node_addr(i));
    }

    let duped = filter.duplicate().unwrap();
    assert_eq!(duped.num_bits(), 2048 * 8);

    // All elements still found at the larger size
    for i in 0..50 {
        assert!(
            duped.contains(&make_node_addr(i)),
            "Node {} not found after duplicate",
            i
        );
    }
}

#[test]
fn test_bloom_filter_duplicate_to() {
    let mut filter = BloomFilter::with_params(512 * 8, 5).unwrap();
    for i in 0..10 {
        filter.insert(&make_node_addr(i));
    }

    let duped = filter.duplicate_to(4096 * 8).unwrap();
    assert_eq!(duped.num_bits(), 4096 * 8);

    for i in 0..10 {
        assert!(duped.contains(&make_node_addr(i)));
    }
}

#[test]
fn test_bloom_filter_duplicate_at_maximum() {
    let filter = BloomFilter::with_params(32768 * 8, 5).unwrap();
    assert!(matches!(
        filter.duplicate(),
        Err(BloomError::CannotDuplicate(_))
    ));
}

#[test]
fn test_bloom_filter_duplicate_then_fold_round_trip() {
    let mut filter = BloomFilter::with_params(1024 * 8, 5).unwrap();
    for i in 0..30 {
        filter.insert(&make_node_addr(i));
    }

    // Duplicate to 2KB then fold back to 1KB should yield equivalent filter
    let duped = filter.duplicate().unwrap();
    let folded_back = duped.fold().unwrap();

    // The round-trip should be identical because duplication places
    // identical copies in both halves, and folding ORs them back
    assert_eq!(filter, folded_back);
}

#[test]
fn test_bloom_filter_convert_to() {
    let mut filter = BloomFilter::with_params(1024 * 8, 5).unwrap();
    for i in 0..20 {
        filter.insert(&make_node_addr(i));
    }

    // Same size → clone
    let same = filter.convert_to(1024 * 8).unwrap();
    assert_eq!(filter, same);

    // Larger → duplicate
    let larger = filter.convert_to(4096 * 8).unwrap();
    assert_eq!(larger.num_bits(), 4096 * 8);
    for i in 0..20 {
        assert!(larger.contains(&make_node_addr(i)));
    }

    // Smaller → fold
    let smaller = filter.convert_to(512 * 8).unwrap();
    assert_eq!(smaller.num_bits(), 512 * 8);
    for i in 0..20 {
        assert!(smaller.contains(&make_node_addr(i)));
    }
}

#[test]
fn test_bloom_filter_convert_to_invalid() {
    let filter = BloomFilter::with_params(1024 * 8, 5).unwrap();

    // Not a power of two
    assert!(matches!(
        filter.convert_to(1000 * 8),
        Err(BloomError::InvalidTargetSize(_))
    ));
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

// ===== Mixed-Size Integration Tests =====

#[test]
fn test_mixed_size_outgoing_filter_construction() {
    // Node at 1KB (size_class 1) with peers at different sizes
    let my_node = make_node_addr(0);
    let state = BloomState::new(my_node);
    // state defaults to size_class 1 (1KB)

    let peer_a = make_node_addr(10);
    let peer_b = make_node_addr(20);
    let peer_c = make_node_addr(30);

    // Peer A: 512B filter
    let mut filter_a = BloomFilter::with_params(512 * 8, 5).unwrap();
    filter_a.insert(&make_node_addr(100));

    // Peer B: 2KB filter
    let mut filter_b = BloomFilter::with_params(2048 * 8, 5).unwrap();
    filter_b.insert(&make_node_addr(200));

    // Peer C: 4KB filter
    let mut filter_c = BloomFilter::with_params(4096 * 8, 5).unwrap();
    filter_c.insert(&make_node_addr(250));

    let mut peer_filters = HashMap::new();
    peer_filters.insert(peer_a, filter_a);
    peer_filters.insert(peer_b, filter_b);
    peer_filters.insert(peer_c, filter_c);

    // Outgoing filter for peer_a should be 1KB (our size)
    // and should contain entries from peers B and C (converted)
    let outgoing = state.compute_outgoing_filter(&peer_a, &peer_filters);
    assert_eq!(outgoing.num_bits(), 1024 * 8); // our size class
    assert!(outgoing.contains(&my_node));
    assert!(outgoing.contains(&make_node_addr(200))); // from B (folded 2KB→1KB)
    assert!(outgoing.contains(&make_node_addr(250))); // from C (folded 4KB→1KB)
}

#[test]
fn test_native_size_routing_queries() {
    // Peer filters stored at native size work for contains() queries
    let mut filter_2kb = BloomFilter::with_params(2048 * 8, 5).unwrap();
    let target = make_node_addr(42);
    filter_2kb.insert(&target);

    // Query at native 2KB resolution
    assert!(filter_2kb.contains(&target));

    // After folding to 1KB, still found (but higher FPR)
    let folded = filter_2kb.fold().unwrap();
    assert!(folded.contains(&target));
}

// ===== BloomState Tests =====

#[test]
fn test_bloom_state_new() {
    let node = make_node_addr(0);
    let state = BloomState::new(node);

    assert_eq!(state.own_node_addr(), &node);
    assert!(!state.is_leaf_only());
    assert_eq!(state.sequence(), 0);
    assert_eq!(state.leaf_dependent_count(), 0);
}

#[test]
fn test_bloom_state_leaf_only() {
    let node = make_node_addr(0);
    let state = BloomState::leaf_only(node);

    assert!(state.is_leaf_only());
}

#[test]
fn test_bloom_state_leaf_dependents() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let leaf1 = make_node_addr(1);
    let leaf2 = make_node_addr(2);

    state.add_leaf_dependent(leaf1);
    state.add_leaf_dependent(leaf2);
    assert_eq!(state.leaf_dependent_count(), 2);

    assert!(state.remove_leaf_dependent(&leaf1));
    assert_eq!(state.leaf_dependent_count(), 1);

    assert!(!state.remove_leaf_dependent(&leaf1)); // already removed
}

#[test]
fn test_bloom_state_debounce() {
    let node = make_node_addr(0);
    let peer = make_node_addr(1);
    let mut state = BloomState::new(node);
    state.set_update_debounce_ms(500);

    state.mark_update_needed(peer);

    // Should send initially
    assert!(state.should_send_update(&peer, 1000));

    // Record send
    state.record_update_sent(peer, 1000);
    state.mark_update_needed(peer);

    // Should not send immediately (within debounce)
    assert!(!state.should_send_update(&peer, 1200));

    // Should send after debounce period
    assert!(state.should_send_update(&peer, 1600));
}

#[test]
fn test_bloom_state_sequence() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    assert_eq!(state.sequence(), 0);
    assert_eq!(state.next_sequence(), 1);
    assert_eq!(state.next_sequence(), 2);
    assert_eq!(state.sequence(), 2);
}

#[test]
fn test_bloom_state_pending_updates() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);

    assert!(!state.needs_update(&peer1));

    state.mark_update_needed(peer1);
    assert!(state.needs_update(&peer1));
    assert!(!state.needs_update(&peer2));

    state.mark_all_updates_needed(vec![peer1, peer2]);
    assert!(state.needs_update(&peer1));
    assert!(state.needs_update(&peer2));

    state.clear_pending_updates();
    assert!(!state.needs_update(&peer1));
    assert!(!state.needs_update(&peer2));
}

#[test]
fn test_bloom_state_base_filter() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let leaf = make_node_addr(1);
    state.add_leaf_dependent(leaf);

    let filter = state.base_filter();

    assert!(filter.contains(&node));
    assert!(filter.contains(&leaf));
    assert!(!filter.contains(&make_node_addr(99)));
}

#[test]
fn test_bloom_state_compute_outgoing_filter() {
    let my_node = make_node_addr(0);
    let mut state = BloomState::new(my_node);

    let leaf = make_node_addr(1);
    state.add_leaf_dependent(leaf);

    let peer1 = make_node_addr(10);
    let peer2 = make_node_addr(20);

    // Create peer filters
    let mut filter1 = BloomFilter::new();
    filter1.insert(&make_node_addr(100));
    filter1.insert(&make_node_addr(101));

    let mut filter2 = BloomFilter::new();
    filter2.insert(&make_node_addr(200));

    let mut peer_filters = HashMap::new();
    peer_filters.insert(peer1, filter1);
    peer_filters.insert(peer2, filter2);

    // Filter for peer1 should exclude peer1's contributions
    let outgoing1 = state.compute_outgoing_filter(&peer1, &peer_filters);
    assert!(outgoing1.contains(&my_node)); // self
    assert!(outgoing1.contains(&leaf)); // leaf dependent
    assert!(outgoing1.contains(&make_node_addr(200))); // from peer2
    // peer1's nodes may or may not be present (depends on split brain)

    // Filter for peer2 should exclude peer2's contributions
    let outgoing2 = state.compute_outgoing_filter(&peer2, &peer_filters);
    assert!(outgoing2.contains(&my_node));
    assert!(outgoing2.contains(&leaf));
    assert!(outgoing2.contains(&make_node_addr(100))); // from peer1
    assert!(outgoing2.contains(&make_node_addr(101))); // from peer1
}

#[test]
fn test_bloom_state_leaf_dependents_accessor() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let leaf1 = make_node_addr(1);
    let leaf2 = make_node_addr(2);

    state.add_leaf_dependent(leaf1);
    state.add_leaf_dependent(leaf2);

    let deps = state.leaf_dependents();
    assert!(deps.contains(&leaf1));
    assert!(deps.contains(&leaf2));
    assert!(!deps.contains(&make_node_addr(99)));
    assert_eq!(deps.len(), 2);
}

#[test]
fn test_bloom_state_record_sent_filter() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer = make_node_addr(1);
    let mut filter = BloomFilter::new();
    filter.insert(&make_node_addr(42));

    // Record a sent filter, then mark_changed_peers should detect no change
    // when the outgoing filter matches what was recorded
    state.record_sent_filter(peer, filter);

    // Compute what would be sent to peer (just our own node, no peer filters)
    let peer_filters = HashMap::new();
    let peer_addrs = vec![peer];
    state.mark_changed_peers(&make_node_addr(99), &peer_addrs, &peer_filters);

    // Outgoing filter (just self) differs from recorded (self + node 42),
    // so peer should be marked for update
    assert!(state.needs_update(&peer));
}

#[test]
fn test_bloom_state_remove_peer_state() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer = make_node_addr(1);

    // Populate all three internal maps for this peer
    state.mark_update_needed(peer);
    state.record_update_sent(peer, 1000);
    state.mark_update_needed(peer); // re-mark after send
    let filter = BloomFilter::new();
    state.record_sent_filter(peer, filter);

    assert!(state.needs_update(&peer));

    // Remove all peer state
    state.remove_peer_state(&peer);

    // Pending updates cleared
    assert!(!state.needs_update(&peer));

    // Debounce state cleared — should be able to send immediately
    state.mark_update_needed(peer);
    assert!(state.should_send_update(&peer, 0));

    // Sent filter cleared — mark_changed_peers should treat as "never sent"
    state.clear_pending_updates();
    let peer_filters = HashMap::new();
    let peer_addrs = vec![peer];
    state.mark_changed_peers(&make_node_addr(99), &peer_addrs, &peer_filters);
    assert!(state.needs_update(&peer)); // never sent → must send
}

#[test]
fn test_bloom_state_mark_changed_peers_never_sent() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);

    let peer_filters = HashMap::new();
    let peer_addrs = vec![peer1, peer2];

    // No filters ever sent — all peers should be marked
    state.mark_changed_peers(&make_node_addr(99), &peer_addrs, &peer_filters);

    assert!(state.needs_update(&peer1));
    assert!(state.needs_update(&peer2));
}

#[test]
fn test_bloom_state_mark_changed_peers_unchanged() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let peer_filters = HashMap::new();
    let peer_addrs = vec![peer1, peer2];

    // Compute and record what would be sent to each peer
    let outgoing1 = state.compute_outgoing_filter(&peer1, &peer_filters);
    let outgoing2 = state.compute_outgoing_filter(&peer2, &peer_filters);
    state.record_sent_filter(peer1, outgoing1);
    state.record_sent_filter(peer2, outgoing2);

    // Nothing changed — no peers should be marked
    state.mark_changed_peers(&make_node_addr(99), &peer_addrs, &peer_filters);

    assert!(!state.needs_update(&peer1));
    assert!(!state.needs_update(&peer2));
}

#[test]
fn test_bloom_state_mark_changed_peers_one_changed() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let peer_filters = HashMap::new();
    let peer_addrs = vec![peer1, peer2];

    // Record current outgoing filters for both peers
    let outgoing1 = state.compute_outgoing_filter(&peer1, &peer_filters);
    let outgoing2 = state.compute_outgoing_filter(&peer2, &peer_filters);
    state.record_sent_filter(peer1, outgoing1);
    state.record_sent_filter(peer2, outgoing2);

    // Now peer1 sends us a filter with new entries
    let mut inbound_from_peer1 = BloomFilter::new();
    inbound_from_peer1.insert(&make_node_addr(100));
    let mut updated_peer_filters = HashMap::new();
    updated_peer_filters.insert(peer1, inbound_from_peer1);

    // mark_changed_peers triggered by receiving from peer1
    state.mark_changed_peers(&peer1, &peer_addrs, &updated_peer_filters);

    // peer1 is excluded (it's the source), peer2's outgoing changed
    // (now includes peer1's entries via split-horizon)
    assert!(!state.needs_update(&peer1));
    assert!(state.needs_update(&peer2));
}

#[test]
fn test_bloom_state_mark_changed_peers_excludes_source() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer_filters = HashMap::new();
    let peer_addrs = vec![peer1];

    // peer1 is both the source and the only peer — should be skipped
    state.mark_changed_peers(&peer1, &peer_addrs, &peer_filters);

    assert!(!state.needs_update(&peer1));
}

// ===== Adaptive Sizing Tests =====

#[test]
fn test_adaptive_sizing_step_up() {
    let node = make_node_addr(0);
    let state = BloomState::new(node); // defaults: size_class=1, up=0.20, down=0.05

    // Above threshold → step up
    assert_eq!(state.evaluate_size_change(0.25), Some(2));
}

#[test]
fn test_adaptive_sizing_step_down() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);
    state.set_size_class(2);

    // Below threshold → step down
    assert_eq!(state.evaluate_size_change(0.03), Some(1));
}

#[test]
fn test_adaptive_sizing_deadband() {
    let node = make_node_addr(0);
    let state = BloomState::new(node);

    // In deadband → no change
    assert_eq!(state.evaluate_size_change(0.10), None);
    assert_eq!(state.evaluate_size_change(0.15), None);
}

#[test]
fn test_adaptive_sizing_at_max() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);
    state.set_size_class(crate::bloom::MAX_SIZE_CLASS);

    // Above threshold but at max → no change
    assert_eq!(state.evaluate_size_change(0.30), None);
}

#[test]
fn test_adaptive_sizing_at_min() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);
    state.set_size_class(crate::bloom::MIN_SIZE_CLASS);

    // Below threshold but at min → no change
    assert_eq!(state.evaluate_size_change(0.02), None);
}

// === Non-routing dependent tests ===

#[test]
fn test_non_routing_peer_included_as_dependent() {
    // When a non-routing peer connects, F adds it as a dependent.
    // The outgoing filter should include the non-routing peer's identity.
    let my_node = make_node_addr(0);
    let mut state = BloomState::new(my_node);

    let non_routing_peer = make_node_addr(5);
    state.add_leaf_dependent(non_routing_peer);

    let outgoing = state.compute_outgoing_filter(&make_node_addr(99), &HashMap::new());
    assert!(outgoing.contains(&my_node));
    assert!(outgoing.contains(&non_routing_peer));
}

#[test]
fn test_non_routing_dependent_removed_on_disconnect() {
    let my_node = make_node_addr(0);
    let mut state = BloomState::new(my_node);

    let non_routing_peer = make_node_addr(5);
    state.add_leaf_dependent(non_routing_peer);
    assert!(state.leaf_dependents().contains(&non_routing_peer));

    state.remove_leaf_dependent(&non_routing_peer);
    assert!(!state.leaf_dependents().contains(&non_routing_peer));

    // Filter no longer contains the peer
    let outgoing = state.compute_outgoing_filter(&make_node_addr(99), &HashMap::new());
    assert!(!outgoing.contains(&non_routing_peer));
}

#[test]
fn test_non_routing_filter_not_merged_into_outgoing() {
    // Even if a non-routing peer somehow has an inbound filter,
    // it should not be included in peer_filters passed to
    // compute_outgoing_filter (enforced at the Node level).
    // Here we verify that excluding a peer's filter from the map
    // means their entries don't appear in the outgoing filter.
    let my_node = make_node_addr(0);
    let state = BloomState::new(my_node);

    let full_peer = make_node_addr(10);
    let non_routing_peer = make_node_addr(20);

    let mut full_filter = BloomFilter::new();
    full_filter.insert(&make_node_addr(100));

    let mut nr_filter = BloomFilter::new();
    nr_filter.insert(&make_node_addr(200));

    // Only include the full peer's filter (simulating the Node-level exclusion)
    let mut peer_filters = HashMap::new();
    peer_filters.insert(full_peer, full_filter);
    // nr_filter deliberately NOT included

    let outgoing = state.compute_outgoing_filter(&make_node_addr(99), &peer_filters);
    assert!(outgoing.contains(&my_node));
    assert!(outgoing.contains(&make_node_addr(100))); // from full peer
    assert!(!outgoing.contains(&make_node_addr(200))); // non-routing excluded

    // But if non-routing peer is a dependent, its identity IS in the filter
    let mut state2 = BloomState::new(my_node);
    state2.add_leaf_dependent(non_routing_peer);
    let outgoing2 = state2.compute_outgoing_filter(&make_node_addr(99), &peer_filters);
    assert!(outgoing2.contains(&non_routing_peer)); // identity present
    assert!(!outgoing2.contains(&make_node_addr(200))); // but not their filter entries
}
