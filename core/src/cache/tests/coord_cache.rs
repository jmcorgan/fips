use alloc::format;
use alloc::vec::Vec;

use super::*;
use crate::cache::entry::VERIFIED_TTL_MS;

type CoordCache = super::CoordCache<crate::testutil::TestEntropy>;

fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}

#[test]
fn test_coord_cache_basic() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    let coords = make_coords(&[1, 0]);

    let _ = cache.insert(addr, coords.clone(), 0);

    assert!(cache.contains(&addr, 0));
    assert_eq!(cache.get(&addr, 0), Some(&coords));
    assert_eq!(cache.len(), 1);
}

#[test]
fn test_coord_cache_expiry() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    let coords = make_coords(&[1, 0]);

    let _ = cache.insert(addr, coords, 0);

    assert!(cache.contains(&addr, 500));
    assert!(!cache.contains(&addr, 1500));
}

#[test]
fn test_coord_cache_update() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);

    let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
    let _ = cache.insert(addr, make_coords(&[1, 2, 0]), 500);

    assert_eq!(cache.len(), 1);
    let coords = cache.get(&addr, 500).unwrap();
    assert_eq!(coords.depth(), 2);
}

#[test]
fn test_coord_cache_eviction() {
    let mut cache = CoordCache::new(2, 10000);

    let addr1 = make_node_addr(1);
    let addr2 = make_node_addr(2);
    let addr3 = make_node_addr(3);

    let _ = cache.insert(addr1, make_coords(&[1, 0]), 0);
    let _ = cache.insert(addr2, make_coords(&[2, 0]), 100);

    // Touch addr2 to make it more recent
    let _ = cache.get_and_touch(&addr2, 200);

    // Insert addr3, should evict addr1 (LRU)
    let _ = cache.insert(addr3, make_coords(&[3, 0]), 300);

    assert!(!cache.contains(&addr1, 300));
    assert!(cache.contains(&addr2, 300));
    assert!(cache.contains(&addr3, 300));
}

#[test]
fn test_coord_cache_evict_expired_first() {
    let mut cache = CoordCache::new(2, 100);

    let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
    let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

    // At time 150, addr1 is expired, addr2 is not
    let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 150);

    // addr1 should be evicted (expired), not addr2 (LRU but not expired)
    assert!(!cache.contains(&make_node_addr(1), 150));
    assert!(cache.contains(&make_node_addr(2), 150));
    assert!(cache.contains(&make_node_addr(3), 150));
}

#[test]
fn test_coord_cache_purge_expired() {
    let mut cache = CoordCache::new(100, 100);

    let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0); // expires at 100
    let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50); // expires at 150
    let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 200); // expires at 300

    assert_eq!(cache.len(), 3);

    let purged = cache.purge_expired(151); // both addr1 and addr2 expired

    // Entry 1 and 2 expired, entry 3 still valid
    assert_eq!(purged, 2);
    assert_eq!(cache.len(), 1);
    assert!(cache.contains(&make_node_addr(3), 151));
}

#[test]
fn test_coord_cache_stats() {
    let mut cache = CoordCache::new(100, 100);

    let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
    let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 50);

    let stats = cache.stats(150);

    assert_eq!(stats.entries, 2);
    assert_eq!(stats.max_entries, 100);
    assert_eq!(stats.expired, 1); // addr1 expired
    assert!(stats.avg_age_ms > 0);
}

#[test]
fn test_coord_cache_insert_with_ttl() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);

    let _ = cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);

    // Should expire at 200, not the default 1000
    assert!(cache.contains(&addr, 100));
    assert!(!cache.contains(&addr, 201));
}

#[test]
fn test_coord_cache_insert_with_ttl_update() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);

    let _ = cache.insert_with_ttl(addr, make_coords(&[1, 0]), 0, 200);
    let _ = cache.insert_with_ttl(addr, make_coords(&[1, 2, 0]), 100, 300);

    assert_eq!(cache.len(), 1);
    let coords = cache.get(&addr, 100).unwrap();
    assert_eq!(coords.depth(), 2);
    // New TTL: 100 + 300 = 400
    assert!(cache.contains(&addr, 399));
    assert!(!cache.contains(&addr, 401));
}

#[test]
fn test_coord_cache_get_and_touch_removes_expired() {
    let mut cache = CoordCache::new(100, 100);
    let addr = make_node_addr(1);

    let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
    assert_eq!(cache.len(), 1);

    // Entry expired at time 200
    let result = cache.get_and_touch(&addr, 200);
    assert!(result.is_none());
    // Entry should be removed from the map
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_coord_cache_get_entry() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);

    let _ = cache.insert(addr, make_coords(&[1, 0]), 500);

    let entry = cache.get_entry(&addr).unwrap();
    assert_eq!(entry.created_at(), 500);
    assert_eq!(entry.expires_at(), 1500);

    assert!(cache.get_entry(&make_node_addr(99)).is_none());
}

#[test]
fn test_coord_cache_remove() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);

    let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
    assert_eq!(cache.len(), 1);

    let removed = cache.remove(&addr);
    assert!(removed.is_some());
    assert_eq!(cache.len(), 0);

    // Removing again returns None
    assert!(cache.remove(&addr).is_none());
}

#[test]
fn test_coord_cache_clear_and_is_empty() {
    let mut cache = CoordCache::new(100, 1000);

    assert!(cache.is_empty());

    let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
    let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

    assert!(!cache.is_empty());

    cache.clear();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_coord_cache_default() {
    let cache = CoordCache::default();

    assert_eq!(cache.max_entries(), DEFAULT_COORD_CACHE_SIZE);
    assert_eq!(cache.default_ttl_ms(), DEFAULT_COORD_CACHE_TTL_MS);
    assert!(cache.is_empty());
}

#[test]
fn test_coord_cache_set_default_ttl() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);

    cache.set_default_ttl_ms(200);
    assert_eq!(cache.default_ttl_ms(), 200);

    let _ = cache.insert(addr, make_coords(&[1, 0]), 0);
    // New TTL applies: expires at 200
    assert!(cache.contains(&addr, 100));
    assert!(!cache.contains(&addr, 201));
}

#[test]
fn test_coord_cache_stats_empty() {
    let cache = CoordCache::new(100, 1000);
    let stats = cache.stats(0);

    assert_eq!(stats.entries, 0);
    assert_eq!(stats.max_entries, 100);
    assert_eq!(stats.expired, 0);
    assert_eq!(stats.avg_age_ms, 0);
}

// ===== Surgical invalidation tests =====

#[test]
fn test_invalidate_via_node_at_self_depth() {
    // Entry whose own NodeAddr (depth 0) is the invalidation target.
    let mut cache = CoordCache::new(100, 1000);
    let target = make_node_addr(1);

    let _ = cache.insert(target, make_coords(&[1, 0]), 0);
    assert_eq!(cache.len(), 1);

    let removed = cache.invalidate_via_node(&target);
    assert_eq!(removed, 1);
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_invalidate_via_node_interior() {
    // Entry whose ancestry contains the target in the interior of the path.
    let mut cache = CoordCache::new(100, 1000);
    let dest = make_node_addr(5);
    // Path: 5 -> 3 -> 1 -> 0 (root). Target 3 appears at depth 1.
    let _ = cache.insert(dest, make_coords(&[5, 3, 1, 0]), 0);

    let removed = cache.invalidate_via_node(&make_node_addr(3));
    assert_eq!(removed, 1);
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_invalidate_via_node_absent() {
    // Entry whose ancestry does NOT contain the target must be retained.
    let mut cache = CoordCache::new(100, 1000);
    let dest = make_node_addr(5);
    let _ = cache.insert(dest, make_coords(&[5, 3, 1, 0]), 0);

    let removed = cache.invalidate_via_node(&make_node_addr(99));
    assert_eq!(removed, 0);
    assert_eq!(cache.len(), 1);
    assert!(cache.contains(&dest, 0));
}

#[test]
fn test_invalidate_via_node_empty_cache() {
    let mut cache = CoordCache::new(100, 1000);
    let removed = cache.invalidate_via_node(&make_node_addr(1));
    assert_eq!(removed, 0);
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_invalidate_other_roots_current_root_kept() {
    let mut cache = CoordCache::new(100, 1000);
    // Entries rooted at addr(0)
    let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
    let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

    let removed = cache.invalidate_other_roots(&make_node_addr(0));
    assert_eq!(removed, 0);
    assert_eq!(cache.len(), 2);
}

#[test]
fn test_invalidate_other_roots_different_root_dropped() {
    let mut cache = CoordCache::new(100, 1000);
    // Three entries rooted at addr(0), one rooted at addr(9)
    let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
    let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);
    let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 0);
    let _ = cache.insert(make_node_addr(4), make_coords(&[4, 9]), 0);

    let removed = cache.invalidate_other_roots(&make_node_addr(0));
    assert_eq!(removed, 1);
    assert_eq!(cache.len(), 3);
    assert!(!cache.contains(&make_node_addr(4), 0));
    assert!(cache.contains(&make_node_addr(1), 0));
}

#[test]
fn test_invalidate_other_roots_all_match() {
    let mut cache = CoordCache::new(100, 1000);
    let _ = cache.insert(make_node_addr(1), make_coords(&[1, 0]), 0);
    let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 0);

    let removed = cache.invalidate_other_roots(&make_node_addr(0));
    assert_eq!(removed, 0);
    assert_eq!(cache.len(), 2);
}

#[test]
fn test_invalidate_other_roots_empty_cache() {
    let mut cache = CoordCache::new(100, 1000);
    let removed = cache.invalidate_other_roots(&make_node_addr(0));
    assert_eq!(removed, 0);
    assert_eq!(cache.len(), 0);
}

#[test]
fn a_hint_does_not_displace_a_live_verified_entry() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    let good = make_coords(&[1, 0]);
    let forged = make_coords(&[1, 2, 0]);

    cache.insert_verified(addr, good.clone(), 0);
    assert_eq!(cache.insert(addr, forged, 10), HintOutcome::Rejected);
    assert_eq!(
        cache.get(&addr, 10),
        Some(&good),
        "the verified value must survive the hint"
    );
}

#[test]
fn a_verified_write_displaces_a_hint() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    let hint = make_coords(&[1, 2, 0]);
    let good = make_coords(&[1, 0]);

    assert_eq!(cache.insert(addr, hint, 0), HintOutcome::Inserted);
    cache.insert_verified(addr, good.clone(), 10);
    assert_eq!(
        cache.get(&addr, 10),
        Some(&good),
        "a proof must be able to correct a poisoned entry"
    );
}

#[test]
fn verification_ages_out_so_a_stale_verified_entry_stops_refusing_hints() {
    let mut cache = CoordCache::new(100, u64::MAX / 4);
    let addr = make_node_addr(1);
    cache.insert_verified(addr, make_coords(&[1, 0]), 0);

    // Inside the window: refused.
    assert_eq!(
        cache.insert(addr, make_coords(&[1, 2, 0]), VERIFIED_TTL_MS),
        HintOutcome::Rejected
    );
    // One millisecond past it: accepted, so a destination that genuinely
    // moved is not locked out forever by a verification nobody renews.
    let moved = make_coords(&[1, 3, 0]);
    assert_eq!(
        cache.insert(addr, moved.clone(), VERIFIED_TTL_MS + 1),
        HintOutcome::Changed
    );
    assert_eq!(cache.get(&addr, VERIFIED_TTL_MS + 1), Some(&moved));
}

#[test]
fn ordinary_traffic_does_not_extend_the_verification_window() {
    // The entry TTL has to be long enough that the touches below keep the
    // entry alive; the test is about the verification clock, not expiry.
    let mut cache = CoordCache::new(100, VERIFIED_TTL_MS);
    let addr = make_node_addr(1);
    cache.insert_verified(addr, make_coords(&[1, 0]), 0);

    // Touch it repeatedly the way forwarding does, right up to the edge.
    for t in [100, 1000, 100_000, VERIFIED_TTL_MS] {
        let _ = cache.get_and_touch(&addr, t);
    }

    // The entry is alive but its verification has aged out on its own
    // clock, which is the whole point of keeping the two clocks separate.
    assert_eq!(
        cache.insert(addr, make_coords(&[1, 2, 0]), VERIFIED_TTL_MS + 1),
        HintOutcome::Changed,
        "refresh must not carry the verification forward"
    );
}

#[test]
fn eviction_prefers_an_unverified_victim_over_a_verified_one() {
    let mut cache = CoordCache::new(2, 1_000_000);
    let verified = make_node_addr(1);
    let hint = make_node_addr(2);
    let newcomer = make_node_addr(3);

    // The verified entry is the least recently used, so an unrestricted
    // LRU would take it. That is exactly the eviction an attacker would
    // drive to manufacture an empty slot.
    cache.insert_verified(verified, make_coords(&[1, 0]), 0);
    assert_eq!(
        cache.insert(hint, make_coords(&[2, 0]), 100),
        HintOutcome::Inserted
    );
    assert_eq!(
        cache.insert(newcomer, make_coords(&[3, 0]), 200),
        HintOutcome::Inserted
    );

    assert!(
        cache.contains(&verified, 200),
        "the verified entry must not be the eviction victim"
    );
    assert!(
        !cache.contains(&hint, 200),
        "the unverified entry should have been evicted instead"
    );
}

#[test]
fn a_cache_full_of_verified_entries_refuses_a_hint_rather_than_evicting_one() {
    let mut cache = CoordCache::new(2, 1_000_000);
    cache.insert_verified(make_node_addr(1), make_coords(&[1, 0]), 0);
    cache.insert_verified(make_node_addr(2), make_coords(&[2, 0]), 0);

    assert_eq!(
        cache.insert(make_node_addr(3), make_coords(&[3, 0]), 10),
        HintOutcome::Rejected
    );
    assert!(cache.contains(&make_node_addr(1), 10));
    assert!(cache.contains(&make_node_addr(2), 10));
}

#[test]
fn a_stated_write_replaces_a_live_verified_entry_whose_coordinates_differ() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    let moved = make_coords(&[1, 2, 0]);

    cache.insert_verified(addr, make_coords(&[1, 0]), 0);
    let placed = cache.insert_stated(addr, moved.clone(), 10, Funding::Uncharged);
    assert_eq!(placed.outcome, HintOutcome::Changed);
    let entry = cache.get_entry(&addr).unwrap();
    assert_eq!(
        entry.coords(),
        &moved,
        "the node's own statement must replace the lookup's"
    );
    assert!(
        !entry.is_verified(10),
        "the replacement is a hint and ends the verification window"
    );
}

#[test]
fn a_stated_write_that_does_not_name_its_key_yields_to_a_live_verified_entry() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    let good = make_coords(&[1, 0]);

    cache.insert_verified(addr, good.clone(), 0);
    let placed = cache.insert_stated(addr, make_coords(&[2, 0]), 10, Funding::Uncharged);
    assert_eq!(placed.outcome, HintOutcome::Rejected);
    let entry = cache.get_entry(&addr).unwrap();
    assert_eq!(entry.coords(), &good);
    assert!(
        entry.is_verified(10),
        "the verified entry must keep its window"
    );
}

#[test]
fn a_stated_write_of_the_verified_coordinates_leaves_the_entry_verified() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    let good = make_coords(&[1, 0]);

    cache.insert_verified(addr, good.clone(), 0);
    let placed = cache.insert_stated(addr, good.clone(), 10, Funding::Uncharged);
    assert_eq!(placed.outcome, HintOutcome::Rejected);
    assert!(cache.get_entry(&addr).unwrap().is_verified(10));
}

#[test]
fn a_stated_write_after_the_verification_lapses_is_an_ordinary_hint_write() {
    let mut cache = CoordCache::new(100, u64::MAX / 4);
    let addr = make_node_addr(1);
    cache.insert_verified(addr, make_coords(&[1, 0]), 0);

    let moved = make_coords(&[1, 3, 0]);
    let placed = cache.insert_stated(addr, moved.clone(), VERIFIED_TTL_MS + 1, Funding::Uncharged);
    assert_eq!(placed.outcome, HintOutcome::Changed);
    assert_eq!(cache.get(&addr, VERIFIED_TTL_MS + 1), Some(&moved));
}

#[test]
fn a_stated_write_deeper_than_the_entry_charge_replaces_a_verified_entry_through_eviction() {
    // Every coordinate of up to ADDRS_PER_ENTRY addresses is charged that
    // many, so only one deeper than that takes the growing update's path
    // through eviction rather than an update in place.
    let root = make_node_addr(0);
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    cache.insert_verified(addr, make_coords(&[1, 0]), 0);
    let deep = coords_of_len(addr, root, ADDRS_PER_ENTRY + 4);

    let placed = cache.insert_stated(addr, deep.clone(), 10, Funding::Uncharged);
    assert_eq!(placed.outcome, HintOutcome::Changed);
    assert_eq!(placed.added_weight, 4, "the growth beyond the old charge");
    let entry = cache.get_entry(&addr).unwrap();
    assert_eq!(entry.coords(), &deep);
    assert!(!entry.is_verified(10));
    assert_index_matches_map(&cache, "stated growing update with room");
}

#[test]
fn a_stated_write_that_finds_no_room_is_stored_and_leaves_the_other_verified_entry() {
    // Two entries fill both the entry bound and the address bound
    // (2 * ADDRS_PER_ENTRY), and the other entry is live-verified, so an
    // update deeper than ADDRS_PER_ENTRY finds nothing to evict.
    let root = make_node_addr(0);
    let (addr, other) = (make_node_addr(1), make_node_addr(2));
    let deep = coords_of_len(addr, root, ADDRS_PER_ENTRY + 4);

    // The fixture reaches the no-room branch: an ordinary hint is refused
    // there even over a hint, and a stated write is stored.
    let mut cache = CoordCache::new(2, 1_000_000);
    assert_eq!(
        cache.insert(addr, make_coords(&[1, 0]), 0),
        HintOutcome::Inserted
    );
    cache.insert_verified(other, make_coords(&[2, 0]), 0);
    assert_eq!(
        cache.insert(addr, deep.clone(), 10),
        HintOutcome::Rejected,
        "precondition: no room can be made"
    );
    let placed = cache.insert_stated(addr, deep.clone(), 10, Funding::Uncharged);
    assert_eq!(placed.outcome, HintOutcome::Changed);
    assert_eq!(cache.get(&addr, 10), Some(&deep));
    assert_index_matches_map(&cache, "stated growing update over a hint, no room");

    // Over a verified entry.
    let mut cache = CoordCache::new(2, 1_000_000);
    cache.insert_verified(addr, make_coords(&[1, 0]), 0);
    cache.insert_verified(other, make_coords(&[2, 0]), 0);
    let placed = cache.insert_stated(addr, deep.clone(), 10, Funding::Uncharged);
    assert_eq!(placed.outcome, HintOutcome::Changed);
    let entry = cache.get_entry(&addr).unwrap();
    assert_eq!(
        entry.coords(),
        &deep,
        "the statement must not be refused for room"
    );
    assert!(!entry.is_verified(10));
    assert!(
        cache.get_entry(&other).is_some_and(|e| e.is_verified(10)),
        "the other verified entry must stay, verified"
    );
    assert_eq!(
        cache.stored_weight,
        2 * ADDRS_PER_ENTRY as u64 + 4,
        "the statement is stored past the address bound"
    );
    assert_index_matches_map(
        &cache,
        "stated growing update over a verified entry, no room",
    );
}

#[test]
fn demote_keeps_the_value_and_lets_a_hint_replace_it() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    let real = make_coords(&[1, 0]);
    cache.insert_verified_with_path_mtu(addr, real.clone(), 10, 1400);
    assert_eq!(
        cache.insert(addr, make_coords(&[1, 2, 0]), 10),
        HintOutcome::Rejected
    );

    assert!(cache.demote(&addr));

    let entry = cache.get_entry(&addr).unwrap();
    assert_eq!(entry.coords(), &real);
    assert_eq!(entry.source(), crate::cache::CoordSource::Hint);
    assert!(!entry.is_verified(10));
    assert_eq!(
        entry.path_mtu(),
        Some(1400),
        "demote leaves the path MTU to its caller"
    );
    assert_eq!(
        cache.insert(addr, make_coords(&[1, 2, 0]), 11),
        HintOutcome::Changed
    );
}

#[test]
fn demote_of_an_absent_entry_reports_none() {
    let mut cache = CoordCache::new(100, 1000);
    assert!(!cache.demote(&make_node_addr(1)));
    assert!(cache.is_empty());
}

#[test]
fn clear_path_mtu_keeps_the_entry() {
    let mut cache = CoordCache::new(100, 1000);
    let addr = make_node_addr(1);
    cache.insert_verified_with_path_mtu(addr, make_coords(&[1, 0]), 10, 1400);

    cache.clear_path_mtu(&addr);

    let entry = cache.get_entry(&addr).unwrap();
    assert_eq!(entry.path_mtu(), None);
    assert!(entry.is_verified(10));
}

/// A distinct address per index, for fills larger than one byte can name.
fn minted_addr(tag: u8, val: u32) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&val.to_le_bytes());
    bytes[15] = tag;
    NodeAddr::from_bytes(bytes)
}

/// Coordinates for `addr` carrying `len` addresses in all: `addr`, then
/// `len - 2` minted ancestors, then `root`.
fn coords_of_len(addr: NodeAddr, root: NodeAddr, len: usize) -> TreeCoordinate {
    let mut path = Vec::with_capacity(len);
    path.push(addr);
    path.extend((0..len as u32 - 2).map(|i| minted_addr(0xd0, i)));
    path.push(root);
    TreeCoordinate::from_addrs(path).unwrap()
}

/// The most entries one eviction may visit, averaged over many inserts, for
/// eviction to count as cheap. Any constant independent of the cache size
/// would do; a scan of the cache visits tens of thousands.
const MAX_MEAN_EXAMINED_PER_INSERT: u64 = 8;

#[test]
fn eviction_at_capacity_examines_a_bounded_number_of_entries() {
    let mut cache = CoordCache::with_defaults();
    let root = make_node_addr(0);
    let capacity = DEFAULT_COORD_CACHE_SIZE as u32;
    for i in 0..capacity {
        let addr = minted_addr(0xfe, i);
        let _ = cache.insert(addr, coords_of_len(addr, root, 2), 1_000 + u64::from(i));
    }
    assert_eq!(cache.len(), DEFAULT_COORD_CACHE_SIZE);
    assert_eq!(
        cache.eviction_examined(),
        0,
        "filling to capacity must not evict"
    );

    let fresh = 1_000u32;
    let now = 1_000 + u64::from(capacity);
    for i in 0..fresh {
        let addr = minted_addr(0xfd, i);
        assert_eq!(
            cache.insert(addr, coords_of_len(addr, root, 2), now + u64::from(i)),
            HintOutcome::Inserted
        );
    }
    assert_eq!(cache.len(), DEFAULT_COORD_CACHE_SIZE);

    let mean = cache.eviction_examined() / u64::from(fresh);
    assert!(
        mean <= MAX_MEAN_EXAMINED_PER_INSERT,
        "each insert at capacity examined {mean} entries on average, \
         against a bound of {MAX_MEAN_EXAMINED_PER_INSERT}"
    );
}

#[test]
fn a_cache_filled_with_depth_seventy_hints_stays_within_its_address_budget() {
    let mut cache = CoordCache::with_defaults();
    let root = make_node_addr(0);
    let capacity = DEFAULT_COORD_CACHE_SIZE as u32;
    let mut newest = None;
    for i in 0..capacity {
        let addr = minted_addr(0xfe, i);
        let _ = cache.insert(addr, coords_of_len(addr, root, 71), 1_000 + u64::from(i));
        newest = Some(addr);
    }
    let newest = newest.unwrap();
    assert!(
        cache.contains(&newest, 1_000 + u64::from(capacity)),
        "the newest hint must be stored"
    );

    let budget = DEFAULT_COORD_CACHE_SIZE * ADDRS_PER_ENTRY;
    assert!(
        cache.stored_addrs() <= budget,
        "the cache stores {} coordinate addresses in {} entries, against \
         a budget of {budget}",
        cache.stored_addrs(),
        cache.len()
    );
}

#[test]
fn a_depth_five_fill_reaches_max_entries_with_nothing_evicted_early() {
    let mut cache = CoordCache::with_defaults();
    let root = make_node_addr(0);
    let capacity = DEFAULT_COORD_CACHE_SIZE as u32;
    for i in 0..capacity {
        let addr = minted_addr(0xfe, i);
        let _ = cache.insert(addr, coords_of_len(addr, root, 6), 1_000 + u64::from(i));
    }
    let now = 1_000 + u64::from(capacity);
    assert_eq!(cache.len(), DEFAULT_COORD_CACHE_SIZE);
    assert!(
        cache.contains(&minted_addr(0xfe, 0), now),
        "the first entry of an honest fill must still be present"
    );
    assert_eq!(cache.eviction_examined(), 0, "nothing may be evicted");
    assert_eq!(cache.stored_addrs(), DEFAULT_COORD_CACHE_SIZE * 6);
}

#[test]
fn a_touched_entry_survives_a_flood_of_new_keys() {
    let mut cache = CoordCache::new(1_000, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    for i in 0..1_000u32 {
        let addr = minted_addr(0xfe, i);
        let _ = cache.insert(addr, coords_of_len(addr, root, 2), 1_000 + u64::from(i));
    }
    let kept = minted_addr(0xfe, 0);
    let mut now = 3_000;
    for i in 0..5_000u32 {
        assert!(cache.get_and_touch(&kept, now).is_some(), "flood {i}");
        let addr = minted_addr(0xfd, i);
        let _ = cache.insert(addr, coords_of_len(addr, root, 2), now + 1);
        now += 2;
    }
    assert!(cache.contains(&kept, now));
    assert!(
        !cache.contains(&minted_addr(0xfe, 1), now),
        "an untouched entry should have been evicted by the flood"
    );
}

/// Assert every slot is filed under its own key in exactly the index its
/// place names, and that the indexes hold nothing else.
fn assert_index_matches_map(cache: &CoordCache, step: &str) {
    assert_eq!(
        cache.by_use.len() + cache.parked.len() + cache.probation.len(),
        cache.entries.len(),
        "{step}: index sizes do not add up to the map"
    );
    // A verified write is stored even when only live-verified entries
    // remain to evict, so only that can take main over its bound.
    assert!(
        cache.main_len() <= cache.max_entries
            || cache
                .entries
                .values()
                .filter(|slot| slot.place.segment() == Segment::Main)
                .all(|slot| slot.entry.source() == crate::cache::CoordSource::Verified),
        "{step}: main over its bound"
    );
    assert!(
        cache.probation.len() <= cache.probation_bound(),
        "{step}: probation over its bound"
    );
    for (addr, slot) in &cache.entries {
        let index = match slot.place {
            Place::ByUse => &cache.by_use,
            Place::Parked => &cache.parked,
            Place::Probation => &cache.probation,
        };
        assert_eq!(
            index.get(&slot.key),
            Some(addr),
            "{step}: {addr:?} is not filed under its key"
        );
    }
    // A shallower update leaves an entry's weight where it was.
    for slot in cache.entries.values() {
        let held = weight_of(slot.entry.coords());
        assert!(slot.weight >= held, "{step}: weight below held");
    }
    assert_eq!(
        cache.stored_weight,
        cache
            .entries
            .values()
            .filter(|slot| slot.place.segment() == Segment::Main)
            .map(|slot| slot.weight)
            .sum::<u64>(),
        "{step}: stored weight is not the sum over the main segment"
    );
    for (key, addr) in cache.by_use.iter() {
        let slot = cache
            .entries
            .get(addr)
            .expect("by_use names a missing entry");
        assert_eq!((slot.place, slot.key), (Place::ByUse, *key), "{step}");
    }
    for (key, addr) in cache.parked.iter() {
        let slot = cache
            .entries
            .get(addr)
            .expect("parked names a missing entry");
        assert_eq!((slot.place, slot.key), (Place::Parked, *key), "{step}");
    }
    for (key, addr) in cache.probation.iter() {
        let slot = cache
            .entries
            .get(addr)
            .expect("probation names a missing entry");
        assert_eq!((slot.place, slot.key), (Place::Probation, *key), "{step}");
    }
}

#[test]
fn the_eviction_index_matches_the_map_after_every_mutation() {
    let root = make_node_addr(0);
    let other_root = make_node_addr(9);
    let via = minted_addr(0xd0, 0);
    let mut cache = CoordCache::new(8, 1_000);
    let mut now = 10_000u64;
    let mut parked_seen = false;
    let mut expiry_seen = false;
    let mut probation_seen = false;
    let mut promoted_seen = false;

    // A verified entry that eviction will reach first, and so park.
    cache.insert_verified(
        minted_addr(1, 0),
        coords_of_len(minted_addr(1, 0), root, 2),
        now,
    );
    assert_index_matches_map(&cache, "insert_verified");
    cache.insert_verified_with_path_mtu(
        minted_addr(1, 1),
        coords_of_len(minted_addr(1, 1), root, 2),
        now,
        1400,
    );
    assert_index_matches_map(&cache, "insert_verified_with_path_mtu");

    // A pseudo-random mix of every mutator, checked after each step.
    let mut state = 0x2545_f491_u32;
    for step in 0..4_000u32 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        let addr = minted_addr(2, state % 24);
        now += u64::from(state % 7);
        let name = match (state >> 8) % 12 {
            0..=1 => {
                let len = 2 + (state >> 4) as usize % 30;
                let _ = cache.insert(addr, coords_of_len(addr, root, len), now);
                "insert"
            }
            2..=3 => {
                // Funding from none to enough for any write here, so new
                // keys land in both segments and probation keys get
                // promoted.
                let len = 2 + (state >> 4) as usize % 30;
                let funding = Funding::Upto(u64::from(state >> 20) % 48);
                let placed =
                    cache.insert_funded(addr, coords_of_len(addr, root, len), now, funding);
                probation_seen |= placed.segment == Segment::Probation;
                promoted_seen |= placed.segment == Segment::Main
                    && placed.added_weight >= ADDRS_PER_ENTRY as u64
                    && placed.outcome != HintOutcome::Inserted;
                "insert_funded"
            }
            4 => {
                let had = cache.get_entry(&addr).is_some_and(|e| e.is_expired(now));
                let _ = cache.get_and_touch(&addr, now);
                expiry_seen |= had;
                "get_and_touch"
            }
            5 => {
                cache.insert_verified(addr, coords_of_len(addr, root, 2), now);
                "insert_verified"
            }
            6 => {
                let _ = cache.remove(&addr);
                "remove"
            }
            7 => {
                let _ = cache.demote(&addr);
                "demote"
            }
            8 => {
                let _ = cache.purge_expired(now);
                "purge_expired"
            }
            9 => {
                let _ = cache.insert(addr, coords_of_len(addr, other_root, 2), now);
                let _ = cache.invalidate_other_roots(&root);
                "invalidate_other_roots"
            }
            10 => {
                let _ = cache.invalidate_via_node(&via);
                "invalidate_via_node"
            }
            _ => {
                if step % 500 == 499 {
                    cache.clear();
                    "clear"
                } else {
                    now += 2_000;
                    "time passes"
                }
            }
        };
        parked_seen |= !cache.parked.is_empty();
        assert_index_matches_map(&cache, &format!("step {step} ({name})"));
    }
    assert!(parked_seen, "the sequence never parked a verified entry");
    assert!(expiry_seen, "the sequence never expired an entry on touch");
    assert!(
        probation_seen,
        "the sequence never placed a key in probation"
    );
    assert!(
        promoted_seen,
        "the sequence never charged a whole key's weight on an update"
    );

    // Demote an entry that is parked, then let a parked entry's
    // verification lapse and be reached by eviction.
    cache.clear();
    cache.insert_verified(
        minted_addr(3, 0),
        coords_of_len(minted_addr(3, 0), root, 2),
        now,
    );
    cache.insert_verified(
        minted_addr(3, 1),
        coords_of_len(minted_addr(3, 1), root, 2),
        now,
    );
    for i in 0..8u32 {
        let addr = minted_addr(4, i);
        let _ = cache.insert(addr, coords_of_len(addr, root, 2), now + 1);
    }
    assert_eq!(cache.parked.len(), 2, "both verified entries were parked");
    assert!(cache.demote(&minted_addr(3, 0)));
    assert_index_matches_map(&cache, "demote of a parked entry");
    // A stated write deeper than the entry's charge over the still-parked
    // verified entry: it leaves `parked` through the growing update's path.
    let stated = minted_addr(3, 1);
    let placed = cache.insert_stated(
        stated,
        coords_of_len(stated, root, ADDRS_PER_ENTRY + 4),
        now + 1,
        Funding::Uncharged,
    );
    assert_eq!(placed.outcome, HintOutcome::Changed);
    assert_index_matches_map(&cache, "stated write over a parked entry");
    let lapsed = now + VERIFIED_TTL_MS + 1;
    let addr = minted_addr(5, 0);
    let _ = cache.insert(addr, coords_of_len(addr, root, 2), lapsed);
    assert_index_matches_map(&cache, "eviction after a verification lapsed");
}

#[test]
fn an_entry_whose_verification_lapsed_becomes_evictable() {
    let mut cache = CoordCache::new(2, u64::MAX / 4);
    let root = make_node_addr(0);
    let verified = make_node_addr(1);
    cache.insert_verified(verified, make_coords(&[1, 0]), 0);
    let _ = cache.insert(make_node_addr(2), make_coords(&[2, 0]), 10);
    // Inside the window the verified entry is parked and the hint goes.
    let _ = cache.insert(make_node_addr(3), make_coords(&[3, 0]), 20);
    assert!(cache.contains(&verified, 20));
    assert!(!cache.contains(&make_node_addr(2), 20));

    // Past it, the once-verified entry is the least recently used and so
    // is the victim.
    let after = VERIFIED_TTL_MS + 1;
    let newcomer = minted_addr(0xfe, 0);
    assert_eq!(
        cache.insert(newcomer, coords_of_len(newcomer, root, 2), after),
        HintOutcome::Inserted
    );
    assert!(
        !cache.contains(&verified, after),
        "an entry whose verification lapsed must become evictable"
    );
    assert!(cache.contains(&make_node_addr(3), after));
}

#[test]
fn entries_untouched_since_insertion_are_evicted_in_insertion_order() {
    let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    // One timestamp for all, and addresses whose order runs against the
    // insertion order, so only the sequence can explain the result.
    let now = 1_000;
    let addrs: Vec<NodeAddr> = (0..64u32).map(|i| minted_addr(0xfe, 1_000 - i)).collect();
    for addr in &addrs {
        let _ = cache.insert(*addr, coords_of_len(*addr, root, 2), now);
    }
    for i in 0..32u32 {
        let addr = minted_addr(0xfd, i);
        let _ = cache.insert(addr, coords_of_len(addr, root, 2), now);
    }
    for (i, addr) in addrs.iter().enumerate() {
        assert_eq!(
            cache.contains(addr, now),
            i >= 32,
            "entry {i} of the insertion order"
        );
    }
}

#[test]
fn a_growing_update_evicts_others_to_stay_within_the_address_budget() {
    // Room for four entries by count and 64 addresses by weight.
    let mut cache = CoordCache::new(4, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let addrs: Vec<NodeAddr> = (0..4u32).map(|i| minted_addr(0xfe, i)).collect();
    for (i, addr) in addrs.iter().enumerate() {
        let _ = cache.insert(*addr, coords_of_len(*addr, root, 2), 1_000 + i as u64);
    }
    assert_eq!(cache.stored_weight, 64);

    // The oldest entry grows to 40 addresses: it must not be its own
    // victim, and two others must go to make room for 24 more.
    assert_eq!(
        cache.insert(addrs[0], coords_of_len(addrs[0], root, 40), 2_000),
        HintOutcome::Changed
    );
    assert_eq!(
        cache.get(&addrs[0], 2_000).map(|c| c.entries().len()),
        Some(40)
    );
    assert!(!cache.contains(&addrs[1], 2_000));
    assert!(!cache.contains(&addrs[2], 2_000));
    assert!(cache.contains(&addrs[3], 2_000));
    assert!(cache.stored_weight <= 64);
    assert_index_matches_map(&cache, "growing update");
}

/// Fill `cache` to its address bound with depth-five hints (weight 16
/// each) under `root`, tagged `tag`, stamped from `start`.
fn fill_depth_five(cache: &mut CoordCache, root: NodeAddr, tag: u8, start: u64) {
    let mut i = 0u32;
    while cache.main_len() < cache.max_entries {
        let addr = minted_addr(tag, i);
        let _ = cache.insert(addr, coords_of_len(addr, root, 6), start + u64::from(i));
        i += 1;
    }
}

/// The sustained rate, in weight per second, the stand-in sender of the
/// budget tests here earns, matching the shipped per-peer hint budget. A
/// literal so that the cache's tests do not depend on the node layer that
/// owns the budget.
const SENDER_WEIGHT_PER_SEC: u64 = 64 * ADDRS_PER_ENTRY as u64;

#[test]
fn alternating_deep_and_shallow_updates_of_one_key_evict_no_more_than_the_senders_budget_allows() {
    let mut cache = CoordCache::with_defaults();
    let root = make_node_addr(0);
    fill_depth_five(&mut cache, root, 0xfe, 1_000);
    let mut now = 1_000 + DEFAULT_COORD_CACHE_SIZE as u64;
    let mut refill = 0u32;

    // A sender that starts empty and earns its rate per millisecond, as a
    // newly seen link peer does.
    let key = minted_addr(0xaa, 0);
    let mut milli = 0u64;
    let (mut evicted, mut paid_writes, mut growths_applied) = (0u64, 0u64, 0u64);
    let steps = 1_000u64;
    for i in 0..steps {
        now += 1;
        milli = (milli + SENDER_WEIGHT_PER_SEC).min(256 * ADDRS_PER_ENTRY as u64 * 1_000);
        let available = milli / 1_000;

        // An honest writer tops main back up to its bound in between, so
        // each growth has to evict to fit.
        while cache.main_len() < cache.max_entries
            && cache.stored_weight + ADDRS_PER_ENTRY as u64 <= cache.weight_bound()
        {
            let addr = minted_addr(0xfc, refill);
            let _ = cache.insert(addr, coords_of_len(addr, root, 6), now);
            refill += 1;
        }

        let len = if i % 2 == 0 { 3 } else { 71 };
        let in_main = cache.segment_of(&key) == Some(Segment::Main);
        let main_before = cache.main_len() as u64;
        let placed = cache.insert_funded(
            key,
            coords_of_len(key, root, len),
            now,
            Funding::Upto(available),
        );
        let joined = u64::from(!in_main && placed.segment == Segment::Main);
        evicted += main_before + joined - cache.main_len() as u64;
        assert!(placed.added_weight <= available, "write {i} overspent");
        milli -= placed.added_weight * 1_000;
        paid_writes += u64::from(placed.added_weight > 0);
        growths_applied += u64::from(len == 71 && placed.outcome == HintOutcome::Changed);
    }

    // Entries are evicted whole, so one paid write may free up to one entry
    // more than its charge covers.
    let earned = steps * SENDER_WEIGHT_PER_SEC / 1_000;
    let allowed = earned.div_ceil(ADDRS_PER_ENTRY as u64) + paid_writes;
    assert!(growths_applied > 0, "no growth was ever paid for");
    assert!(
        evicted <= allowed,
        "{steps} alternating updates evicted {evicted} main entries, against \
         an allowance of {allowed} for {earned} weight earned"
    );
}

#[test]
fn growing_updates_of_many_keys_evict_no_more_than_the_senders_budget_allows() {
    // Each key is charged once for its deepest form, so one key alternating
    // evicts at most once; a sender deepening many keys pays for each.
    let mut cache = CoordCache::with_defaults();
    let root = make_node_addr(0);
    fill_depth_five(&mut cache, root, 0xfe, 1_000);
    let mut now = 1_000 + DEFAULT_COORD_CACHE_SIZE as u64;
    let (mut refill, mut milli) = (0u32, 0u64);
    let (mut evicted, mut paid_writes) = (0u64, 0u64);
    let steps = 1_000u32;
    for i in 0..steps {
        now += 1;
        milli = (milli + SENDER_WEIGHT_PER_SEC).min(256 * ADDRS_PER_ENTRY as u64 * 1_000);
        let available = milli / 1_000;
        while cache.main_len() < cache.max_entries
            && cache.stored_weight + ADDRS_PER_ENTRY as u64 <= cache.weight_bound()
        {
            let addr = minted_addr(0xfc, refill);
            let _ = cache.insert(addr, coords_of_len(addr, root, 6), now);
            refill += 1;
        }

        // Deepen a key the honest fill put in main, newest first so the
        // eviction it causes does not take the next one.
        let key = minted_addr(0xfe, DEFAULT_COORD_CACHE_SIZE as u32 - 1 - i);
        if cache.segment_of(&key) != Some(Segment::Main) {
            continue;
        }
        let main_before = cache.main_len() as u64;
        let placed = cache.insert_funded(
            key,
            coords_of_len(key, root, 71),
            now,
            Funding::Upto(available),
        );
        evicted += main_before - cache.main_len() as u64;
        assert!(placed.added_weight <= available, "write {i} overspent");
        milli -= placed.added_weight * 1_000;
        paid_writes += u64::from(placed.added_weight > 0);
    }

    let earned = u64::from(steps) * SENDER_WEIGHT_PER_SEC / 1_000;
    let allowed = earned.div_ceil(ADDRS_PER_ENTRY as u64) + paid_writes;
    assert!(
        evicted <= allowed,
        "{steps} growing updates evicted {evicted} main entries, against \
         an allowance of {allowed} for {earned} weight earned"
    );
    assert!(paid_writes > 0, "no growth was ever paid for");
}

#[test]
fn a_growing_update_is_charged_its_added_weight() {
    let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let placed = cache.insert_funded(key, coords_of_len(key, root, 2), 10, Funding::Upto(16));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.segment),
        (HintOutcome::Inserted, 16, Segment::Main)
    );
    let placed = cache.insert_funded(key, coords_of_len(key, root, 40), 20, Funding::Upto(24));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.unfunded),
        (HintOutcome::Changed, 24, false)
    );
    assert_eq!(cache.stored_weight, 40);
}

#[test]
fn an_unpaid_growing_update_keeps_the_old_coordinates() {
    let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let old = coords_of_len(key, root, 2);
    let _ = cache.insert(key, old.clone(), 10);
    fill_depth_five(&mut cache, root, 0xfe, 20);
    let before = cache.len();

    let placed = cache.insert_funded(key, coords_of_len(key, root, 40), 30, Funding::Upto(23));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.unfunded),
        (HintOutcome::Rejected, 0, true)
    );
    assert_eq!(cache.get(&key, 30), Some(&old), "the old coordinates stay");
    assert_eq!(cache.len(), before, "an unpaid growth evicts nothing");
}

#[test]
fn a_same_weight_rewrite_of_an_existing_key_is_never_charged() {
    let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let _ = cache.insert(key, coords_of_len(key, root, 20), 10);

    // Same weight, different value; then a shrink.
    let moved = TreeCoordinate::from_addrs(
        core::iter::once(key)
            .chain((0..18u32).map(|i| minted_addr(0xc0, i)))
            .chain(core::iter::once(root))
            .collect(),
    )
    .unwrap();
    let placed = cache.insert_funded(key, moved.clone(), 20, Funding::Upto(0));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.unfunded),
        (HintOutcome::Changed, 0, false)
    );
    assert_eq!(cache.get(&key, 20), Some(&moved));
    let shallow = coords_of_len(key, root, 3);
    let placed = cache.insert_funded(key, shallow.clone(), 30, Funding::Upto(0));
    assert_eq!((placed.added_weight, placed.unfunded), (0, false));
    assert_eq!(cache.get(&key, 30), Some(&shallow));
    assert_eq!(cache.stored_weight, 20, "a shrink keeps the entry's charge");
}

#[test]
fn an_unpaid_rewrite_back_to_an_entrys_charged_depth_corrects_a_shallow_forgery() {
    let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let real = coords_of_len(key, root, 20);
    let placed = cache.insert_funded(key, real.clone(), 10, Funding::Upto(20));
    assert_eq!((placed.segment, placed.added_weight), (Segment::Main, 20));

    // A forged shallow rewrite from a peer with nothing to spend.
    let forged = coords_of_len(key, root, 3);
    let _ = cache.insert_funded(key, forged.clone(), 20, Funding::Upto(0));
    assert_eq!(cache.get(&key, 20), Some(&forged));

    // The honest coordinates, from a peer that also has nothing to spend.
    let placed = cache.insert_funded(key, real.clone(), 30, Funding::Upto(0));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.unfunded),
        (HintOutcome::Changed, 0, false)
    );
    assert_eq!(
        cache.get(&key, 30),
        Some(&real),
        "the forgery must not stick"
    );

    // Deeper than the entry was ever charged for still has to be paid.
    let placed = cache.insert_funded(key, coords_of_len(key, root, 21), 40, Funding::Upto(0));
    assert_eq!(
        (placed.outcome, placed.unfunded),
        (HintOutcome::Rejected, true)
    );
    assert_eq!(cache.get(&key, 40), Some(&real));
    assert_eq!(cache.stored_weight, 20);
}

#[test]
fn a_paid_new_key_main_has_no_room_for_goes_to_probation_and_evicts_nothing() {
    // Bound: 8 entries, 128 weight. One hint, then three verified entries
    // of weight 37 (verified writes are this node's own lookups), 127 in all.
    let mut cache = CoordCache::new(8, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let hint = minted_addr(0xaa, 0);
    let _ = cache.insert(hint, coords_of_len(hint, root, 2), 10);
    for i in 0..3u32 {
        let verified = minted_addr(0xbb, i);
        cache.insert_verified(verified, coords_of_len(verified, root, 37), 20);
    }
    assert_eq!(cache.stored_weight, 127);

    // A paid new key of weight 30 cannot fit in main even with the hint
    // gone, so it goes to probation, charged nothing, and still routes.
    let key = minted_addr(0xcc, 0);
    let placed = cache.insert_funded(key, coords_of_len(key, root, 30), 30, Funding::Upto(30));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.segment),
        (HintOutcome::Inserted, 0, Segment::Probation)
    );
    assert!(cache.contains(&key, 30), "the paid write left no route");
    assert!(
        cache.contains(&hint, 30),
        "a write main had no room for, and charged nothing, evicted a hint"
    );
    assert_eq!(cache.stored_weight, 127);
    assert_index_matches_map(&cache, "placed in probation for want of room");

    // A key that fits still evicts the hint to make room.
    let small = minted_addr(0xcc, 1);
    let placed = cache.insert_funded(small, coords_of_len(small, root, 2), 40, Funding::Upto(16));
    assert_eq!(placed.outcome, HintOutcome::Inserted);
    assert!(!cache.contains(&hint, 40));
    assert_index_matches_map(&cache, "room made");
}

#[test]
fn an_unpaid_write_evicts_only_probation_entries() {
    let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    fill_depth_five(&mut cache, root, 0xfe, 10);
    assert_eq!(cache.probation_bound(), 2);

    for i in 0..10u32 {
        let addr = minted_addr(0xaa, i);
        let placed = cache.insert_funded(addr, coords_of_len(addr, root, 2), 100, Funding::Upto(0));
        assert_eq!(
            (placed.outcome, placed.segment, placed.unfunded),
            (HintOutcome::Inserted, Segment::Probation, true)
        );
    }
    for i in 0..64u32 {
        assert!(cache.contains(&minted_addr(0xfe, i), 100), "main entry {i}");
    }
    assert_eq!(cache.probation_len(), 2);
    assert!(cache.contains(&minted_addr(0xaa, 9), 100));
    assert!(cache.contains(&minted_addr(0xaa, 8), 100));
    assert!(!cache.contains(&minted_addr(0xaa, 7), 100));
}

#[test]
fn a_probation_entry_is_not_promoted_by_get_and_touch() {
    let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let _ = cache.insert_funded(key, coords_of_len(key, root, 2), 10, Funding::Upto(0));
    for t in 11..100 {
        assert!(cache.get_and_touch(&key, t).is_some());
    }
    assert_eq!(cache.segment_of(&key), Some(Segment::Probation));
}

#[test]
fn a_paid_write_of_a_probation_key_promotes_it() {
    let mut cache = CoordCache::new(64, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let _ = cache.insert_funded(key, coords_of_len(key, root, 2), 10, Funding::Upto(0));

    // Fifteen units do not pay for a weight-16 key; sixteen do.
    let placed = cache.insert_funded(key, coords_of_len(key, root, 2), 20, Funding::Upto(15));
    assert_eq!(placed.segment, Segment::Probation);
    let placed = cache.insert_funded(key, coords_of_len(key, root, 2), 30, Funding::Upto(16));
    assert_eq!(
        (placed.segment, placed.added_weight),
        (Segment::Main, 16),
        "a write paying the whole weight promotes the key"
    );
    assert_eq!(cache.probation_len(), 0);

    // An uncharged write promotes too.
    let other = minted_addr(0xaa, 1);
    let _ = cache.insert_funded(other, coords_of_len(other, root, 2), 40, Funding::Upto(0));
    let _ = cache.insert(other, coords_of_len(other, root, 2), 50);
    assert_eq!(cache.segment_of(&other), Some(Segment::Main));
}

#[test]
fn probation_holds_its_entry_count_whatever_the_depth() {
    let mut cache = CoordCache::with_defaults();
    let root = make_node_addr(0);
    let bound = DEFAULT_COORD_CACHE_SIZE / PROBATION_SHARE_DIVISOR;
    for i in 0..5_000u32 {
        let addr = minted_addr(0xaa, i);
        let _ = cache.insert_funded(
            addr,
            coords_of_len(addr, root, 71),
            1_000 + u64::from(i),
            Funding::Upto(0),
        );
    }
    assert_eq!(cache.probation_len(), bound);
    assert_eq!(cache.len(), bound, "nothing reached main");
    assert_eq!(cache.stored_weight, 0);
}

#[test]
fn a_probation_entry_a_frame_used_survives_a_flood_of_unpaid_keys() {
    let mut cache = CoordCache::with_defaults();
    let root = make_node_addr(0);
    let used = minted_addr(0xab, 0);
    let idle = minted_addr(0xab, 1);
    let _ = cache.insert_funded(used, coords_of_len(used, root, 2), 1_000, Funding::Upto(0));
    let _ = cache.insert_funded(idle, coords_of_len(idle, root, 2), 1_000, Funding::Upto(0));

    // Five probation turnovers of unpaid keys, with a frame of the flow
    // using `used` every hundred of them.
    let mut now = 1_001;
    for i in 0..8_000u32 {
        if i % 100 == 0 {
            assert!(cache.get_and_touch(&used, now).is_some(), "flood {i}");
        }
        let addr = minted_addr(0xaa, i);
        let _ = cache.insert_funded(addr, coords_of_len(addr, root, 71), now, Funding::Upto(0));
        now += 1;
    }
    assert!(cache.contains(&used, now), "the entry in use must survive");
    assert!(!cache.contains(&idle, now), "the idle entry must not");
}

#[test]
fn a_promotion_is_charged_at_least_the_weight_probation_held() {
    let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let real = coords_of_len(key, root, 20);
    let _ = cache.insert_funded(key, real.clone(), 10, Funding::Upto(0));
    assert_eq!(cache.segment_of(&key), Some(Segment::Probation));

    // A shallow write that pays its own weight but not the held one stays
    // in probation, where the next honest write corrects it.
    let forged = coords_of_len(key, root, 3);
    let placed = cache.insert_funded(key, forged.clone(), 20, Funding::Upto(16));
    assert_eq!(
        (placed.segment, placed.added_weight),
        (Segment::Probation, 0)
    );
    assert_eq!(cache.get(&key, 20), Some(&forged));
    let _ = cache.insert_funded(key, real.clone(), 30, Funding::Upto(0));
    assert_eq!(cache.get(&key, 30), Some(&real));

    // Paying the held weight promotes it, charged that weight, so the
    // honest rewrite after a shallow promotion is free.
    let placed = cache.insert_funded(key, forged.clone(), 40, Funding::Upto(20));
    assert_eq!((placed.segment, placed.added_weight), (Segment::Main, 20));
    assert_eq!(cache.stored_weight, 20);
    let placed = cache.insert_funded(key, real.clone(), 50, Funding::Upto(0));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.unfunded),
        (HintOutcome::Changed, 0, false)
    );
    assert_eq!(cache.get(&key, 50), Some(&real));
    assert_index_matches_map(&cache, "promoted at the held weight");
}

/// An expired main entry that a drained link peer's frame would deepen is
/// replaced as a new key would be, so the frame's own next-hop lookup
/// finds a route, as it does for a key the cache never held.
#[test]
fn an_unpaid_deepening_of_an_expired_entry_still_leaves_a_route() {
    let mut cache = CoordCache::new(64, 1_000);
    let root = make_node_addr(0);
    let d = minted_addr(0xdd, 0);
    let placed = cache.insert_funded(d, coords_of_len(d, root, 17), 0, Funding::Upto(17));
    assert_eq!(placed.segment, Segment::Main);

    let later = 5_000;
    let control = minted_addr(0xdd, 1);
    let _ = cache.insert_funded(
        control,
        coords_of_len(control, root, 18),
        later,
        Funding::Upto(0),
    );
    assert!(
        cache.get_and_touch(&control, later).is_some(),
        "control: a never-seen key written unpaid routes from probation"
    );
    let placed = cache.insert_funded(d, coords_of_len(d, root, 18), later, Funding::Upto(0));
    assert_eq!(
        (placed.outcome, placed.segment, placed.unfunded),
        (HintOutcome::Inserted, Segment::Probation, true)
    );
    assert!(
        cache.get_and_touch(&d, later).is_some(),
        "the frame's next-hop lookup finds no route"
    );
    assert_eq!(cache.stored_weight, 0, "the expired entry's charge is gone");
    assert_index_matches_map(&cache, "expired entry replaced");
}

#[test]
fn a_hint_deeper_than_the_whole_address_bound_is_stored_alone() {
    let mut cache = CoordCache::new(1, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let d = minted_addr(0xde, 0);
    let outcome = cache.insert(d, coords_of_len(d, root, 20), 10);
    assert_eq!(outcome, HintOutcome::Inserted);
    assert!(cache.contains(&d, 10));

    // Another one replaces it, paid in full.
    let e = minted_addr(0xde, 1);
    let placed = cache.insert_funded(e, coords_of_len(e, root, 30), 20, Funding::Upto(30));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.segment),
        (HintOutcome::Inserted, 30, Segment::Main)
    );
    assert!(!cache.contains(&d, 20));
    assert_eq!(cache.stored_weight, 30);
    assert_index_matches_map(&cache, "one deep entry");
}

/// Main's room held by live-verified entries: four of weight 16 fill a
/// bound of 4 entries and 64 weight.
fn fill_verified(cache: &mut CoordCache, root: NodeAddr, count: u32, now: u64) {
    for i in 0..count {
        let addr = minted_addr(0xbb, i);
        cache.insert_verified(addr, coords_of_len(addr, root, 2), now);
    }
}

#[test]
fn a_growing_update_refused_for_want_of_room_keeps_the_entry() {
    let mut cache = CoordCache::new(4, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let old = coords_of_len(key, root, 2);
    let _ = cache.insert(key, old.clone(), 10);
    fill_verified(&mut cache, root, 3, 20);
    assert_eq!(cache.stored_weight, 64);

    let placed = cache.insert_funded(key, coords_of_len(key, root, 20), 30, Funding::Upto(100));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.unfunded),
        (HintOutcome::Rejected, 0, false)
    );
    assert_eq!(cache.get(&key, 30), Some(&old), "the entry stays as it was");
    assert_eq!(cache.segment_of(&key), Some(Segment::Main));
    assert_eq!(cache.stored_weight, 64);
    assert_index_matches_map(&cache, "growing update refused");
}

#[test]
fn a_promotion_refused_for_want_of_room_keeps_the_key_in_probation() {
    let mut cache = CoordCache::new(4, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let _ = cache.insert_funded(key, coords_of_len(key, root, 2), 10, Funding::Upto(0));
    fill_verified(&mut cache, root, 4, 20);

    let new = coords_of_len(key, root, 3);
    let placed = cache.insert_funded(key, new.clone(), 30, Funding::Upto(100));
    assert_eq!(
        (placed.outcome, placed.added_weight, placed.segment),
        (HintOutcome::Changed, 0, Segment::Probation)
    );
    assert_eq!(cache.get(&key, 30), Some(&new), "the key stays, updated");
    assert_eq!(cache.segment_of(&key), Some(Segment::Probation));
    assert_index_matches_map(&cache, "promotion refused");
}

#[test]
fn a_shallow_rewrite_in_probation_does_not_lower_the_weight_a_promotion_pays() {
    let mut cache = CoordCache::new(100, DEFAULT_COORD_CACHE_TTL_MS);
    let root = make_node_addr(0);
    let key = minted_addr(0xaa, 0);
    let real = coords_of_len(key, root, 20);
    let _ = cache.insert_funded(key, real.clone(), 10, Funding::Upto(0));

    // A peer with nothing to spend rewrites it shallow, then pays 16.
    let forged = coords_of_len(key, root, 3);
    let _ = cache.insert_funded(key, forged.clone(), 20, Funding::Upto(0));
    let placed = cache.insert_funded(key, forged.clone(), 30, Funding::Upto(16));
    assert_eq!(
        placed.segment,
        Segment::Probation,
        "promoted below the held depth"
    );

    // The honest coordinates through a drained hub still correct it.
    let _ = cache.insert_funded(key, real.clone(), 40, Funding::Upto(0));
    assert_eq!(cache.get(&key, 40), Some(&real));
    assert_index_matches_map(&cache, "probation charge kept");
}

#[test]
fn coord_cache_keys_its_map_from_its_entropy_source() {
    use core::hash::BuildHasher;

    use crate::testutil::FixedEntropy;
    use crate::utils::hash::KeyedHasher;

    let key = make_node_addr(7);
    let cache = super::CoordCache::<FixedEntropy<1>>::new(16, 1000);
    let hashed = cache.entries.hasher().hash_one(key);

    assert_eq!(hashed, KeyedHasher::new::<FixedEntropy<1>>().hash_one(key));
    assert_ne!(hashed, KeyedHasher::new::<FixedEntropy<2>>().hash_one(key));
}
