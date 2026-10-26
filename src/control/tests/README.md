# `src/control/tests/`

Unit tests for files in `src/control/` that keep their tests outside the
source file. Each file here is a child module of the source file it tests,
declared from that file as `#[cfg(test)] #[path = "tests/<file>.rs"] mod
<name>;`, so it can reach the source file's private items.

- `compose.rs` tests `../compose.rs` as module `tests`: how `fipsctl` and
  `fipstop` merge the IPv6 adapter's `show_status` keys into the node's
  reply. A key the node leaves out takes the adapter's value, a key the
  node answers keeps the node's, and with neither the keys show `disabled`,
  `-` and 0; keys the adapter adds beyond its three are not shown, a
  command the adapter has no part in is left alone, and `composes` asks
  the adapter for `show_status` only when the node left one of the keys
  out. Pure functions over JSON values, no socket.
- `queries.rs` tests `../queries.rs` as module `status_tests`: what a
  client shows for `show_status` now that the IPv6 adapter answers its own
  keys. The test node's reply with the adapter's merged in, whether the
  adapter's reply is the test node's own or a fixed one, equals
  `../snapshots/show_status_composed.json`, a byte copy of the node's
  fixture from before the keys moved; without the adapter it equals
  `show_status_fallback.json` (`disabled`, `-` and 0). The node's reply,
  on the loop and off it, carries none of the adapter's keys, and the
  node's socket answers `show_listening_sockets` as an unknown command.
  Uses the snapshot helpers of the inline `tests` module of `../queries.rs`.
- `serve.rs` tests `../mod.rs` as module `serve_tests`: `serve`, the
  connection loop the node's and the gateway's control sockets and the IPv6
  adapter's status socket share. A
  request line reaches the dispatcher with its command and parameters and is
  answered with one line, after which the stream is closed; a request over
  4096 bytes, an empty request and a line that is not a request are each
  answered with their error without reaching the dispatcher; a client that
  sends nothing is answered `read timeout` after five seconds; and a reply
  the client cannot take makes `serve` return `false`, which each caller
  logs. Runs over in-memory streams (`tokio::io::duplex`), with no socket.

## Rules

- Older tests in `src/control/` stay in their source files' inline
  `mod tests` blocks; new tests go here. A file that already has an inline
  `tests` module declares its file here under a different module name, as
  `../mod.rs` and `../queries.rs` do.
- The snapshot tests of `../queries.rs` and their fixtures stay where they
  are (`../snapshots/`); `queries.rs` here adds fixtures there.
