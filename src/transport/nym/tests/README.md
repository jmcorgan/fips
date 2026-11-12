# Nym transport tests

Unit tests for files in `src/transport/nym/`, kept out of the source files.
Each file here is declared from its source file one level up with
`#[path = "tests/<file>.rs"]`, so it stays a child module of that file and
can reach its private items.

- `mtu.rs`: the receive bound when the two ends of a Nym connection are
  configured with different `mtu` values. Nym binds no listener, so the
  only mixed case is a Nym end that dials a FIPS TCP listener through its
  SOCKS5 proxy, here a mock on loopback with no Nym network. The Nym end
  reads the connection through the shared `proxied_receive_loop` in
  `src/transport/socks5/`, which must accept frames up to the fixed
  `RECV_CEILING` in `src/transport/framing.rs` rather than the local `mtu`.
  The test sends a frame between 1400 and 1500 bytes from a 1500 TCP
  listener to a 1400 Nym end and checks it is delivered without a receive
  error and without closing the connection. Declared from `mod.rs` as
  `#[cfg(test)] #[path = "tests/mtu.rs"] mod mtu_tests;`, on every platform.

`mod.rs` still carries an inline `mod tests` block. That block predates the
rule that unit tests live in this directory; a new test for `mod.rs` belongs
here.
