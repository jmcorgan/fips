# core/src/proto/probe/tests

Unit tests for the probe, declared from `probe/mod.rs` as
`#[cfg(test)] mod tests;`. They drive the stage machine with synthetic
timestamps and hand-built observations.

- `mod.rs`: declares the test files.
- `core.rs`: the stage machine and the budget derivation.
- `path.rs`: `describe_path`.
