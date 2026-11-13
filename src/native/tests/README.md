# src/native/tests

Unit tests for the modules in `src/native/`, kept out of the source files.

- `registry.rs`: tests for ephemeral port allocation in `Registry`
  (`src/native/registry.rs`), declared from that file as
  `#[cfg(test)] #[path = "tests/registry.rs"] mod alloc_tests;`, so they are a
  child module of `registry` and can reach its private items. They compare
  ports the way a peer given two flows would, and check that the random start
  still finds the last free port and reports `NoPort` once none is left. The
  free port in that last check is the bottom of the span, taken and released
  over many rounds, so a probe that does not wrap fails it on almost every run.
  Two of them are statistical; each states its false-failure rate.
- `registry_share.rs`: tests for the per-peer share of the flow table in
  `Registry::deliver`, declared from `registry.rs` as
  `#[cfg(test)] #[path = "tests/registry_share.rs"] mod share_tests;`. One
  peer's inbound flows, pending and accepted, are held to a quarter of
  `max_flows`; flows this node opened to that peer do not count, and a refusal
  names the share rather than the node ceiling.
- `flows.rs`: the same bound end to end, declared from `mod.rs` as
  `mod flow_tests` under the inline suite's platform gate (Linux, FreeBSD,
  macOS). It drives the real request path with the debug `arrive` command
  through the harness in `mod.rs`'s inline block, whose `connect`, `ask`,
  `listen`, `accept`, `readable`, `arrival_from`, `limits` and `PEER` are
  `pub(super)` for it.

- `replies.rs`: the size of every refusal, declared from `mod.rs` as
  `mod reply_tests` under the same platform gate. A refusal can echo client
  text (an unknown command's name, or serde's reason quoting a parameter), and
  each one, with control characters or plain text at the full `MAX_COMMAND`
  line length, stays under 2048 bytes on the wire, macOS's send low-water mark
  for a local stream socket. A unit test checks `deny`'s clip against
  serde_json's own serialiser for every ASCII byte and for multibyte text, so
  the clip's escape-width table cannot drift from serde's unseen. One test
  runs the real serving loop (`serve_socket`, `call`, `send_line`, also
  `pub(super)` in the inline harness) and checks the connection still answers
  after a refusal.

Tests that drive the serving loop over a socket must write commands with
`send_line`, never a blocking `write_all`. The serving task runs on the test's
own current-thread runtime, so a blocking write of more than the socket holds
waits for a reader that cannot run. macOS holds 8192 bytes, less than a
`MAX_COMMAND` line, and a blocking write of one wedged the macOS suite while
Linux, holding about 200 KB, passed. `serve_socket` shrinks the client's send
room to about the macOS size on Linux too, and `bounded` puts a write timeout
on the client, so the same mistake fails on Linux within five seconds with a
named error.

`send_line` makes the client socket non-blocking for its write and puts it
back afterwards. Passing `MSG_DONTWAIT` to `send` instead is not enough: on
macOS that flag does not stop a send into a full buffer from sleeping, so the
send blocks just as a plain write does. Linux honours the flag, which is why
that version passed here and failed only on macOS.

The registry tests borrow the fixtures `limits`, `key`, `peer`, `sink` and
`arrivals` from the inline `mod tests` block in `registry.rs`, which exports
them as `pub(super)`. `registry.rs` and `mod.rs` also carry older inline
`mod tests` blocks. New tests go here rather than into those blocks; the
inline blocks are not converted in passing.
