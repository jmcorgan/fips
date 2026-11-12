# SOCKS5 transport tests

Unit tests for the shared proxied-transport code in `src/transport/socks5/`,
the writer, receive loop and pool that the Tor and Nym transports both use,
kept out of the source files. Each file here is declared from a source file
one level up with `#[path = "tests/<file>.rs"]`, so it stays a child module
of that file.

- `lane.rs`, declared from `mod.rs` as `mod lane_tests`: the path-message
  lane on the shared writer, checked once through each transport, since
  each routes its own sends into that writer. A connection whose data queue
  is full still takes a path message; the writer sends a waiting path
  message before every frame still in the data queue; and a connection that
  has stopped draining refuses path messages once their own queue of
  `PATH_QUEUE_DEPTH` is full, so its path still fails. Each test dials,
  through the mock SOCKS5 proxy in `mock.rs`, a listener that does not read,
  and fills the data queue until the writer waits in `write_all`. Frames go
  through the transport handle's lane send, as the node's do.

`pool.rs` still carries an inline `mod tests` block. That block predates the
rule that unit tests live in this directory; a new test for the shared code
belongs here.
