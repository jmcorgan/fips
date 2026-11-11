# core/src/utils

Small shared value types that the protocol cores name and that belong to
no one protocol. It mirrors the root crate's `utils` module, so an item
moved here keeps its path: `crate::utils::index::SessionIndex` resolves
the same way in both crates.

## Files

- `mod.rs`: declares the submodules.
- `hash.rs`: `HashMap`, `hashbrown`'s map with `KeyedHasher`, which
  builds SipHash-1-3 hashers under a 128-bit key drawn from the host's
  `EntropySource`. That is how `std` builds its own `HashMap`, which
  `alloc` lacks: the same table and the same keyed hash, so lookups cost
  the same, a peer that chooses the keys cannot predict the table's
  layout, and iteration order differs from process to process.
  `hashbrown`'s default hasher, `foldhash`, is not used because it is
  not keyed on targets without address-space randomization. `BTreeMap`
  needs no key, but it is several times slower per lookup and its order
  is the key order, which a peer choosing keys can steer; use it unless
  a peer chooses the keys and the map is looked up on a hot path.
- `index.rs`: `SessionIndex`, the 32-bit number a receiver chooses for a
  Noise session and its peer puts in every encrypted frame, so the
  receiver finds the session without a search. It converts to and from
  little-endian bytes and displays as eight hex digits. Beside it are
  `IndexAllocator<E>`, which draws random indices from the host's
  `EntropySource` and tracks which are in use in a `BTreeSet` (the node
  draws the values itself, and the set is touched per handshake and
  teardown, not per packet), and `IndexError`. There is one allocator
  per node, so an index is unique across the node, not per transport.
  The root crate re-exports all three under `utils::index`, with
  `IndexAllocator` an alias over its `OsEntropy`.
- `onlink.rs`: `OnLinkPrefixes`, the address prefixes of this node's
  own interfaces (address, prefix length and, when known, interface
  index), and the questions asked of them: whether an address is on one
  of this node's links, whether it is on a given interface, and whether
  two addresses share a link. IPv4-mapped IPv6 addresses are judged as
  IPv4, and a zero prefix length is discarded and counted. Beside it,
  `read_suspect`, which says whether a read produced a set that cannot
  be trusted. Reading the set from the system needs `getifaddrs`, so
  that stays in the root crate as `utils::onlink::read_system`, which
  re-exports both items at their old path.
- `tests/`: the unit tests for the files here; its README describes it.

## Invariants

- **A `KeyedHasher` is keyed from its entropy source.** `new::<E>()`
  draws all 16 key bytes from `E`; a fixed or zero key would give a peer
  a table layout it can predict and grind. Its `Debug` prints no key.
- **The allocator draws from its entropy source.** Every candidate
  index `IndexAllocator<E>::allocate` tries is four bytes from `E`, read
  little-endian; it never reads a random source of its own.
- **The byte order is wire format.** `to_le_bytes` and `from_le_bytes`
  are how the index appears in every encrypted frame header; they do not
  change on the deployed lines.
- **The field is private.** Code builds and reads an index through `new`
  and `as_u32`.
- **An empty prefix set holds nothing.** A caller that gates candidate
  addresses with an `OnLinkPrefixes` refuses every one when the set is
  empty, including the set a failed read yields (`failed()`, told apart
  from a read that found nothing by `read_failed()`).
