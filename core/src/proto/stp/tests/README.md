# core/src/proto/stp/tests

Unit tests for the spanning tree, declared from `stp/mod.rs` as
`#[cfg(test)] mod tests;`.

- `mod.rs`: declares the test files.
- `util.rs`: shared fixtures, including `Signer`, a test signing key
  that signs declarations the way `Identity` does.
- `acks.rs`: delivery tracking for sent tree announces.
- `classify.rs`: the classification ladder.
- `coordinate.rs`: `TreeCoordinate` arithmetic and encoding.
- `limits.rs`: flap dampening and the parent hold-down.
- `state.rs`: parent evaluation and root election.
- `wire.rs`: the `TreeAnnounce` codec and its semantic checks.
