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
- `lane.rs`, declared from `mod.rs` as `mod lane_tests`: the path-message
  lane. A connection whose data queue is full still takes a path message;
  the writer sends a waiting path message before every frame still in the
  data queue; and a connection that has stopped draining refuses path
  messages once their own queue of `PATH_QUEUE_DEPTH` is full, so its path
  still fails. Each test dials a listener that does not read, with small
  socket buffers at both ends, and fills the data queue until the writer
  waits in `write_all`. Frames go through the transport handle's lane send,
  as the node's do.

The rules every connection-oriented transport keeps, among them the receive
bound when the two ends are configured with different `mtu` values, are
checked once for all of them in `src/transport/tests/conformance/`, TCP
included, rather than here.

`mod.rs` still carries an inline `mod tests` block. That block predates the
rule that unit tests live in this directory; a new test for `mod.rs` belongs
here.
