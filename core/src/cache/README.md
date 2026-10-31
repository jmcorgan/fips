# core/src/cache

The coordinate cache: a map from node address to tree coordinates, so a
data packet can be routed without carrying its destination's
coordinates. Session setup and discovery fill it; the forwarding path
reads it for each routed packet, and session and probe handling read it
too.

The root crate re-exports it under `fips::cache` from `src/cache.rs`,
and names the cache through a type alias,
`fips::cache::CoordCache = fips_core::cache::CoordCache<OsEntropy>`, so
its callers name it as before.

## Files

- `mod.rs`: declares the submodules and re-exports their public items;
  `CacheError` and `CacheStats`.
- `coord_cache.rs`: `CoordCache`: insertion from hints, from hints a
  link peer pays for (`insert_funded`, with `Funding` and the `Placed`
  result), from the coordinates a session peer states for itself
  (`insert_stated`) and from verified lookups, lookup with and without refreshing
  an entry, invalidation, expiry and eviction; the default size (50,000
  entries) and TTL; the address bound (`ADDRS_PER_ENTRY`) and the
  probation segment (`PROBATION_SHARE_DIVISOR`, `Segment`);
  `HintOutcome`, what a hint write did.
- `entry.rs`: `CacheEntry`, one cached coordinate with its times, path
  MTU and source; `CoordSource` (`Verified` or `Hint`);
  `VERIFIED_TTL_MS`.
- `tests/`: the unit tests for the files here; its README describes it.

## Invariants

- **The map is keyed from the host's entropy source.** `CoordCache<E>`
  builds its map, a `utils::hash::HashMap`, with a hasher keyed from `E`
  at construction. A peer chooses the node addresses it sends, so a key
  it could predict would let it steer where entries land. Iteration
  order is random per process as a result, and two things follow it:
  which of several equally eligible entries eviction picks, and the row
  order of the cache snapshot the root crate reports. Neither may come
  to depend on address order.
- **Test hooks.** `eviction_examined`, `segment_of`, `probation_len` and
  `stored_addrs` let tests measure eviction work and read where entries
  are. They are gated `#[cfg(any(test, feature = "test-hooks"))]`, since
  the root crate's node tests read them.
- **Time is an argument.** Every method that needs the time takes
  `current_time_ms: u64`, in Unix milliseconds; nothing here reads a
  clock.
- **A hint never displaces a live verified entry.** A coordinate copied
  off a passing packet is a hint and is written with `insert`; one from
  a lookup whose proof was checked is written with `insert_verified`.
  A verified entry outranks hints for `VERIFIED_TTL_MS` from when it was
  verified, on a clock that use never refreshes. The entry's own TTL is
  extended by traffic, so if verification shared it a once-verified
  entry would refuse every hint forever, including the ones that carry a
  destination's real move. After the window the entry stays usable but
  a hint may replace it. The one exception is `insert_stated`, the write
  of coordinates a node states for itself in an authenticated message of
  a session with this node: when they begin with the address they are
  filed under and differ from the entry's, they replace a live verified
  entry, because a node that has moved knows its position better than a
  lookup made before the move. Coordinates that name another node yield
  as any hint does.
- **Eviction never makes room for a hint at a verified entry's
  expense.** When the main segment is full, eviction removes the least
  recently used entry that is not live-verified. If every entry is
  live-verified it removes nothing, and an uncharged hint is refused
  rather than the cache growing past its cap (a link peer's write goes
  to probation instead). Otherwise a flood of hints could age a verified
  entry into the eviction slot and then plant a value in the space it
  left. The refusal is for hints only: a verified write is stored even
  when every entry is live-verified, because `insert_verified` does not
  check whether `make_room` made room, so verified entries can take the
  main segment past its cap. A stated write (`insert_stated`) that
  deepens an existing entry is likewise stored when no room can be made,
  so it can take the main segment past its address bound, by at most one
  entry per session. Eviction orders by last use, not by expiry;
  an expired entry is removed when its key is written, when
  `get_and_touch` reads it, or by `purge_expired`.
- **Eviction finds its victim through ordered indexes, not a scan.**
  Entries eviction may take are kept in a `BTreeMap` by last use, and
  live-verified ones are parked by when their verification lapses, so an
  insert at capacity costs O(log n) amortised. Touching an entry does no
  index work; eviction restamps a stale key when it reaches one. Ties
  are broken by a per-cache insertion sequence, never by address, which
  a peer chooses. Every mutator keeps the indexes level with the map.
- **The main segment is bounded by entries and by stored addresses.**
  Each entry weighs its coordinate depth, at least `ADDRS_PER_ENTRY`,
  and the main segment holds at most `max_entries * ADDRS_PER_ENTRY`
  weight as well as `max_entries` entries; a write that would exceed
  either evicts until it fits.
- **An unpaid write never displaces a paid one.** A hint whose writer
  cannot pay its weight (`Funding`) goes to a probation segment on top
  of main, `max(1, max_entries / PROBATION_SHARE_DIVISOR)` entries,
  which evicts only its own least recently used entries. A paid write of
  a probation key promotes it to main; using an entry does not. An
  unpaid update that would deepen a main entry keeps the old
  coordinates.
