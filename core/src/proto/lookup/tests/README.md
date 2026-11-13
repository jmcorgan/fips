# core/src/proto/lookup/tests

Unit tests for mesh lookups, declared from `lookup/mod.rs` as
`#[cfg(test)] mod tests;`, with one exception noted below.

- `mod.rs`: declares the test files.
- `util.rs`: shared fixtures.
- `core.rs`: the planners, the classification of transit responses and the
  retry ladder in `poll_pending`.
- `forward_sender.rs`: a transit forward never goes back to the peer
  the request came from.
- `limits.rs`: the forward rate limiter and its bound.
- `wire.rs`: the request and response codecs.
- `core_dedup_eviction.rs`: the dedup cache capacity tests. It is not
  declared in `mod.rs`: `core.rs` attaches it with
  `#[cfg(test)] #[path = "tests/core_dedup_eviction.rs"] mod
  dedup_eviction_tests;`, so it reaches the policy's private items and
  its tests are named `proto::lookup::core::dedup_eviction_tests::...`.
