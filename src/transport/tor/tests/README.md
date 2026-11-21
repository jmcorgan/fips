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

- `control.rs`: the Tor control client in `control.rs` one level up, against
  a control port it cannot trust. Replies are read as bytes: a status code
  or separator that is not ASCII, or content that is not UTF-8, is a
  protocol error rather than a panic. The caps are tested at their edges: a
  line of exactly 8 KiB with its terminator is accepted and one byte more is
  refused, a reply just under 64 KiB is accepted and one over is refused,
  and 1024 data lines are accepted and 1025 refused. A port that never
  answers fails `authenticate` at the 30 s deadline, and, on Linux, a port
  whose accept queue is full fails `connect` at the 30 s deadline; both are
  measured on tokio's paused clock so the tests do not wait in real time.
  After a reply fails part-way, here over the line cap, every later query
  fails as out of step rather than reading the rest of that reply as its
  answer, while an error reply read in full leaves the client usable. Most
  tests read a canned reply through a client built over an in-memory
  buffer; the rest talk to a stand-in port on loopback that records what it
  is sent.
  Declared from `control.rs` as
  `#[cfg(test)] #[path = "tests/control.rs"] mod control_tests;`.

- `monitoring.rs`: the control-port monitoring task in `mod.rs`. A control
  port on loopback answers the first GETINFO 31 s late, past the reply
  deadline, and everything else at once. The test checks that the task
  opens one new connection and goes on to cache the port's true values,
  instead of reading each later reply as the answer to the query before it.
  It runs on tokio's paused clock.
  Declared from `mod.rs` as
  `#[cfg(test)] #[path = "tests/monitoring.rs"] mod monitoring_tests;`.

`mod.rs` and `control.rs` still carry inline `mod tests` blocks. Those blocks
predate the rule that unit tests live in this directory; a new test for
either file belongs here. The modules declared from this directory take
topic names (`mtu_tests`, `control_tests`, `monitoring_tests`) so they sit
beside the inline `tests` module.
