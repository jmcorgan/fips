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

    let restored =
        BloomFilter::from_bytes(bytes, original.hash_count()).unwrap();

    assert_eq!(original, restored);
}

#[test]
fn test_bloom_filter_estimated_count() {
    let mut filter = BloomFilter::new();

    // Empty filter
    assert_eq!(filter.estimated_count(), 0.0);

    // Insert some items
    for i in 0..50 {
        filter.insert(&make_node_addr(i));
    }

    // Estimate should be reasonably close to 50
    let estimate = filter.estimated_count();
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
