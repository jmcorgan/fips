# Tor transport tests

Unit tests for files in `src/transport/tor/`, kept out of the source files.
Each file here is declared from its source file one level up with
`#[path = "tests/<file>.rs"]`, so it stays a child module of that file and
can reach its private items.

- `mtu.rs`: the receive bound when the two ends of a Tor connection are
  configured with different `mtu` values. Every Tor connection is read
  through the shared `proxied_receive_loop` in `src/transport/socks5/`,
  which must accept frames up to the fixed `RECV_CEILING` in
  `src/transport/framing.rs` rather than the local `mtu`. A 1400 and a 1500
  end exchange a frame between the two values, sent by the larger end, and
  each test checks it is delivered without a receive error and without
  closing the connection: on the onion listener, on the dialling end, and
  on a Tor end that dials a FIPS TCP listener configured higher. Two Tor
  ends talk through a mock SOCKS5 proxy on loopback, with the onion
  listener in directory mode bound on loopback, so no Tor network is used.
  The last test is the control for the other half of the mixed link: a TCP
  listener configured lower delivers the larger frame from a Tor dialler.
  Declared from `mod.rs` as
  `#[cfg(test)] #[path = "tests/mtu.rs"] mod mtu_tests;`, on every platform.

`mod.rs` still carries an inline `mod tests` block. That block predates the
rule that unit tests live in this directory; a new test for `mod.rs` belongs
here.
