# core/src/proto/mmp/tests

Unit tests for the metrics protocol, declared from `mmp/mod.rs` as
`#[cfg(test)] mod tests;`.

- `mod.rs`: declares the test files.
- `algorithms.rs`: the estimators.
- `core.rs`: the `plan_*` decisions.
- `path_mtu.rs`: the path-MTU state machine.
- `state.rs`: the aggregates, the sampled and unsampled halves of a
  received frame, and `MmpMode`'s configuration spelling through
  `serde_yaml`; and that a link's rekey reset leaves exactly its listed
  carries different from a new state, by `MmpPeerState::fresh_diff` over a
  state `MmpPeerState::dirtied` built away from new in every field.
- `wire.rs`: the report codecs.
