# core/src/proto/mmp

The metrics protocol: per-link and per-session measurements (loss,
round-trip time, jitter, path MTU, delivery evidence), the reports
peers exchange, and the decisions about when to report, when a link is
alive and when to send a heartbeat. The root crate's MMP handlers send
and receive the reports and hold the configuration.

## Files

- `mod.rs`: declares the files, re-exports their public items and
  defines `MmpMode`, which the node configuration names.
- `core.rs`: the snapshot read traits, `MmpAction`, and the `plan_*`
  decisions.
- `state.rs`: `Mmp`, the reporting anchor, and the per-peer and
  per-session aggregates.
- `sender.rs`, `receiver.rs`, `metrics.rs`, `path_mtu.rs`: the sender,
  receiver, derived-metrics and path-MTU state machines.
- `delivery.rs`: whether a sent announce was delivered, inferred from
  the peer's receiver reports, and the bounded resends that follow.
- `algorithms.rs`: the estimators (jitter, smoothed RTT, dual EWMA,
  one-way-delay trend, ETX).
- `limits.rs`: tuning constants, including the smallest path MTU the
  node will act on.
- `wire.rs`: the link-layer and session-layer report codecs.
- `tests/`: the unit tests; its README describes it.

## Invariants

- **Time is a `u64` millisecond argument** in every state machine here.
- **Reports are untrusted.** A peer's report can lower a path MTU or
  claim loss; `limits.rs` sets how far such a claim is believed.
- **`MmpMode` spelling is configuration.** Its serde names (`full`,
  `lightweight`, `minimal`) are what operators write in the node
  configuration, so they do not change.
- **The report formats are wire format** and do not change on the
  deployed lines.
