# core/src/proto/fmp/tests

Unit tests for the FMP link layer, declared from `fmp/mod.rs` as
`#[cfg(test)] mod tests;`, with one exception noted below.

- `mod.rs`: declares the test files.
- `util.rs`: shared fixtures, among them a handshake outcome with a
  fresh key.
- `core.rs`: the `poll_*` decisions and the inbound msg1 classification;
  the rules a held peer's same-epoch msg1 meets are its link machine's,
  tested with the machine.
- `limits.rs`: the retry backoff.
- `silent.rs`: `SilentSessions` and the refusals it starts.
- `state.rs`: `ConnectionState`.
- `wire.rs`: the framing codec, through its public interface.
- `wire_private.rs`: tests of `wire.rs` that need its private items.
  It is not declared in `mod.rs`: `wire.rs` attaches it with
  `#[cfg(test)] #[path = "tests/wire_private.rs"] mod tests;`, so its
  tests are named `proto::fmp::wire::tests::...`.
