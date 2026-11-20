# core/src/proto/fmp/tests

Unit tests for the FMP link layer, declared from `fmp/mod.rs` as
`#[cfg(test)] mod tests;`, with one exception noted below.

- `mod.rs`: declares the test files.
- `util.rs`: shared fixtures: a stale connection's snapshot.
- `core.rs`: the `poll_timeouts` decision and the cross-connection
  tie-break; each handshake's classification is the settlement core's,
  tested with it.
- `limits.rs`: the retry backoff.
- `silent.rs`: the msg1 ephemeral digest, by which the settlement core's
  restart gates count silent sessions.
- `state.rs`: `ConnectionState`.
- `wire.rs`: the framing codec, through its public interface.
- `wire_private.rs`: tests of `wire.rs` that need its private items.
  It is not declared in `mod.rs`: `wire.rs` attaches it with
  `#[cfg(test)] #[path = "tests/wire_private.rs"] mod tests;`, so its
  tests are named `proto::fmp::wire::tests::...`.
