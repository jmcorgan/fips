# BLE transport tests

Unit tests for files in `src/transport/ble/`, kept out of the source files.
A file named for a source file is that file's test module, declared from it
as `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`. A file named for a
topic holds tests of `mod.rs` on that topic, declared from `mod.rs` as
`#[cfg(test)] #[path = "tests/<topic>.rs"] mod <topic>_tests;`, as the TCP
transport's are. Either way it stays a child module of its source file and
can reach that file's private items.

- `recall.rs`: tests for `recall.rs`, the probe loop's bounded memory of
  link addresses: the bound on non-live addresses, eviction order, the age
  limit, and that live addresses are never dropped.
- `close.rs`, declared from `mod.rs` as `mod close_tests`: what a
  connection's writer may do to the pool once its entry has gone. A writer
  whose write fails removes the pool entry only if it is still its own, so a
  newer connection at the same address stays pooled, including the writer
  of a deliberately closed connection that is still finishing its queue;
  and the close itself returns without waiting for the writer. The file
  builds pool entries with the real writer task behind them, over mock
  stream pairs whose far end the test holds.

`pool.rs` and `mod.rs` still carry inline `mod tests` blocks. Those blocks
predate the rule that unit tests live in this directory, and are due to move
here; a test written for either file once they have moved belongs here.
