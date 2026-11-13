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
- `owd_trend.rs`: the bound on the one-way delay detector's window, and the
  trend a receiver reports through `ReceiverState::record_recv` and
  `build_report`: the slope of one-way delay over receive time in µs/s, 0
  for a steady path at any frame spacing.
- `reorder_count.rs`: a receiver report's cumulative reorder count stops at
  its `u32` maximum instead of wrapping.
- `etx_trend.rs`: the smoothed ETX moves once per accepted receiver report,
  not again when the reverse delivery ratio is refreshed after it, and not
  on a stale report.
