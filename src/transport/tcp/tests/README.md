# TCP transport tests

Unit tests for files in `src/transport/tcp/`, kept out of the source files.
Each file here is declared from its source file one level up with
`#[path = "tests/<file>.rs"]`, so it stays a child module of that file and
can reach its private items.

- `mss.rs`: the receive bound on connections whose kernel `TCP_MAXSEG` is
  below the configured `mtu`. It clamps the MSS on a raw socket on the far
  side and checks that a frame above the clamp but within the configured MTU
  is delivered without a receive error, for an accepted connection, a
  connect-on-send connection and a background connection. Declared from
  `mod.rs` as
  `#[cfg(all(test, target_os = "linux"))] #[path = "tests/mss.rs"] mod mss_tests;`:
  the whole file is Linux only, because the transport reads the MSS only on
  Linux and the file uses the `TCP_MAXSEG` socket option, so nothing in it
  builds on other platforms.
- `mtu.rs`: the receive bound when the two ends of a connection are
  configured with different `mtu` values. Two transports, one at 1400 and
  one at 1500, exchange a frame between the two values, sent by the larger
  end, and the test checks it is delivered without a receive error and
  without closing the connection, for an accepted connection, a
  connect-on-send connection and a background connection. A last test
  checks the edge: a frame of 65535 bytes, the largest any sender can
  admit, is delivered, and a frame claiming one byte more closes the
  connection. Declared from `mod.rs` as
  `#[cfg(test)] #[path = "tests/mtu.rs"] mod mtu_tests;`, on every platform.

`mod.rs` still carries an inline `mod tests` block. That block predates the
rule that unit tests live in this directory; a new test for `mod.rs` belongs
here.
