# src/native/tests

Unit tests for the modules in `src/native/`, kept out of the source files.

- `registry.rs`: tests for ephemeral port allocation in `Registry`
  (`src/native/registry.rs`), declared from that file as
  `#[cfg(test)] #[path = "tests/registry.rs"] mod alloc_tests;`, so they are a
  child module of `registry` and can reach its private items. They compare
  ports the way a peer given two flows would, and check that the random start
  still finds the last free port and reports `NoPort` once none is left. The
  free port in that last check is the bottom of the span, taken and released
  over many rounds, so a probe that does not wrap fails it on almost every run.
  Two of them are statistical; each states its false-failure rate.
- `registry_share.rs`: tests for the per-peer share of the flow table in
  `Registry::deliver`, declared from `registry.rs` as
  `#[cfg(test)] #[path = "tests/registry_share.rs"] mod share_tests;`. One
  peer's inbound flows, pending and accepted, are held to a quarter of
  `max_flows`; flows this node opened to that peer do not count, and a refusal
  names the share rather than the node ceiling.
- `flows.rs`: the same bound end to end, declared from `mod.rs` as
  `mod flow_tests` under the inline suite's platform gate (Linux, FreeBSD,
  macOS). It drives the real request path with the debug `arrive` command
  through the harness in `mod.rs`'s inline block, whose `connect`, `ask`,
  `listen`, `accept`, `readable`, `arrival_from`, `limits` and `PEER` are
  `pub(super)` for it.

The registry tests borrow the fixtures `limits`, `key`, `peer`, `sink` and
`arrivals` from the inline `mod tests` block in `registry.rs`, which exports
them as `pub(super)`. `registry.rs` and `mod.rs` also carry older inline
`mod tests` blocks. New tests go here rather than into those blocks; the
inline blocks are not converted in passing.
