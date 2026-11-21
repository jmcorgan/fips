# Tor transport tests

Unit tests for files in `src/transport/tor/`, kept out of the source files.
Each file here is declared from its source file one level up with
`#[path = "tests/<file>.rs"]`, so it stays a child module of that file and
can reach its private items.

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
  answer, while an error reply read in full leaves the client usable. On
  the sending side: a password with a line break never reaches the port as
  a second command, and is refused by `ControlAuth::from_config` without
  being echoed, as is an unknown `control_auth` string. Cookie
  authentication runs SAFECOOKIE: it succeeds against a port holding the
  cookie; against a port with the wrong cookie it stops after sending its
  nonce; against a port that refuses `AUTHCHALLENGE` it fails with no plain
  `AUTHENTICATE` fallback; and no port, stand-in or mock, ever receives the
  cookie's hex. A password sent to a non-loopback TCP peer logs one
  warning, and one sent over loopback logs none. A TCP connection to one of
  the host's own non-loopback addresses is recorded as remote; that test is
  skipped, with a message, on a host with no route and so no such address.
  Most parsing tests read a canned reply through a client built over an
  in-memory buffer; the rest talk to a stand-in port that records what it
  is sent, or to the SAFECOOKIE-capable mock in `mock_control.rs`.
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
topic names (`control_tests`, `monitoring_tests`) so they sit beside the
inline `tests` module.
