# core/src/proto/fsp/tests

Unit tests for the session layer, declared from `fsp/mod.rs` as
`#[cfg(test)] mod tests;`.

- `mod.rs`: declares the test files. The scan that keeps the deployed
  session rekey code out of the core is `rekey/tests/survivors.rs`, which
  covers both layers.
- `core.rs`: the coordinate and path-MTU reactions and the data
  transforms.
- `quorum.rs`: `LinkQuorum`.
- `wire.rs`: the session message and header codecs.
