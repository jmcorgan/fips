# core/src/proto/mmp/tests

Unit tests for the metrics protocol, declared from `mmp/mod.rs` as
`#[cfg(test)] mod tests;`.

- `mod.rs`: declares the test files.
- `algorithms.rs`: the estimators and the spin bit.
- `core.rs`: the `plan_*` decisions.
- `path_mtu.rs`: the path-MTU state machine.
- `state.rs`: the aggregates, and `MmpMode`'s configuration spelling
  through `serde_yaml`.
- `wire.rs`: the report codecs.
- `spin_rekey.rs`: the spin bit across a rekey cutover whose counters start
  again, for the link state and the session state.
- `rekey_reset.rs`: what a rekey reset leaves in a link's and a session's
  MMP state, compared with a fresh state of the same form and role by what
  the receiver reports, how the metrics judge the new session's reports,
  and how the spin bit acts on the first new frame; and what the reset
  keeps. The jitter grace the reset sets is tested in `state.rs`.
