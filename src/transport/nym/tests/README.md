# Nym transport tests

Unit tests for `src/transport/nym/mod.rs`, kept out of the source file. A
file here holds tests of `mod.rs` on one topic and is declared from it as
`#[cfg(test)] #[path = "tests/<topic>.rs"] mod <topic>_tests;`, so it stays a
child module of `mod.rs` and can reach its private items.

- `connection.rs`, declared as `mod connection_tests`: the `has_connection`
  test hook, which the conformance rules and the settlement audit read the
  pool through. It reports a pooled connection and nothing else: a finished
  background connect is not one, and asking leaves it in the connecting map
  unpromoted. The transport dials a TCP destination through a mock SOCKS5
  proxy, built by `nym_via_mock_proxy` in `mod.rs`'s inline `mod tests` block.

`mod.rs` still carries an inline `mod tests` block. It predates the rule that
unit tests live in this directory, and is due to move here.
