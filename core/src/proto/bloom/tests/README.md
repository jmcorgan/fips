# core/src/proto/bloom/tests

Unit tests for the bloom filter subsystem, declared from `bloom/mod.rs`
as `#[cfg(test)] mod tests;`.

- `mod.rs`: declares the test files.
- `core.rs`: `BloomFilter` operations and the false-positive estimate.
- `state.rs`: `BloomState`, the outgoing filter, the send debounce, the
  history of filters sent to each peer, the spacing of echo warnings and
  the once-per-peering MTU warning.
- `wire.rs`: the `FilterAnnounce` codec and its bounds.
