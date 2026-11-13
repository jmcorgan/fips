# core/src/utils/tests

Unit tests for the files one level up.

- `hash.rs`: tests for `hash.rs`, attached from there with
  `#[cfg(test)] #[path = "tests/hash.rs"] mod tests;` (names
  `utils::hash::tests::...`). They check that a `KeyedHasher` takes its
  key from the entropy source it is built with, and both of its 64-bit
  halves, not only the first.
- `index.rs`: tests for `index.rs`, attached from there with
  `#[cfg(test)] #[path = "tests/index.rs"] mod tests;`, so they keep
  their names (`utils::index::tests::...`). They check the byte
  round trip and the hex display, and the allocator: allocation, freeing,
  reserving, clearing and uniqueness, under `TestEntropy`, and that it
  draws its indices from its entropy source (under `FixedEntropy<1>`
  every draw is the same value, so the second allocation is exhausted).
- `onlink.rs`: tests for `onlink.rs`, attached from there with
  `#[cfg(test)] #[path = "tests/onlink.rs"] mod tests;` (names
  `utils::onlink::tests::...`). They check which addresses a set of
  prefixes holds (each family's ranges, IPv4-mapped addresses, a
  zero-length prefix discarded, the families kept apart, `share_link`
  and `contains_on`), and that a suspect read is reported. The test of
  the system read stays in the root crate, in `src/utils/tests/onlink.rs`.
