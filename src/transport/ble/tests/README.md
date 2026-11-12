# BLE transport tests

Unit tests for files in `src/transport/ble/`, kept out of the source files.
A file named for a source file is that file's test module, declared from it
as `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`. A file named for a
topic holds tests of `mod.rs` on that topic, declared from `mod.rs` as
`#[cfg(test)] #[path = "tests/<topic>.rs"] mod <topic>_tests;`. Either way it
stays a child module of its source file and can reach that file's private
items.

- `recall.rs`: tests for `recall.rs`, the probe loop's bounded memory of
  link addresses: the bound on non-live addresses, eviction order, the age
  limit, and that live addresses are never dropped.
- `close.rs`, declared from `mod.rs` as `mod close_tests`: what a channel's
  writer may do to the pool when its write fails. It removes its own channel
  and leaves the other channel at the address pooled. The file builds pool
  entries with the real writer task behind them, over mock stream pairs whose
  far end the test holds.
- `lane.rs`, declared from `mod.rs` as `mod lane_tests`: the path-message
  lane. A channel whose data queue is full still takes a path message; the
  writer sends a waiting path message before the data queued ahead of it;
  and a channel that has stopped draining refuses path messages once their
  own queue is full, so its path still fails. The file pools one channel
  with the real writer behind it, over a mock stream pair that holds one
  frame each way, so a far end the test does not read is a stalled link.

`pool.rs` and `mod.rs` still carry inline `mod tests` blocks. Those blocks
predate the rule that unit tests live in this directory, and are due to move
here; a test written for either file once they have moved belongs here.
