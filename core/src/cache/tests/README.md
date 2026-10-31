# Coordinate cache tests

Unit tests for the coordinate cache one level up. Each file is a child
module of the file it tests, so it sees that file's private items and its
tests are named after it.

- `mod.rs`: tests for `mod.rs` (`CacheStats` and `CacheError`), declared
  there as `#[cfg(test)] mod tests;`; names `cache::tests::...`.
- `coord_cache.rs`: tests for `coord_cache.rs` (`CoordCache` insertion,
  lookup, expiry, eviction, invalidation, and the hint and verification
  rules, including the stated write that a verified entry does not
  refuse (`insert_stated`); the eviction indexes and their consistency after every
  operation, the address bound, the probation segment and funded
  writes; and that the map's hasher is keyed from the cache's entropy
  source, `coord_cache_keys_its_map_from_its_entropy_source`), attached
  from there with
  `#[cfg(test)] #[path = "tests/coord_cache.rs"] mod tests;`; names
  `cache::coord_cache::tests::...`.
- `entry.rs`: tests for `entry.rs` (`CacheEntry` and its expiry),
  attached from there with `#[cfg(test)] #[path = "tests/entry.rs"] mod
  tests;`; names `cache::entry::tests::...`.
