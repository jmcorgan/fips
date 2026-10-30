# Nostr rendezvous tests in their own files

This directory holds two kinds of test file.

- Child modules of `src/nostr/tests.rs`, which declares each as
  `mod <name>;`. Each is a child of `nostr::tests` and reaches the
  `pub(super)` items of the files in `src/nostr/` and the private helpers of
  `tests.rs` (such as `send_probe`). Most of the directory's unit tests are
  still in `tests.rs` itself; the files here each hold one behaviour's tests.
- The tests of one file in `src/nostr/`, declared from that file as
  `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so they are its
  child module and reach its private items.

Child modules of `tests.rs`:

- `notify_channels.rs`: the notify loop in `runtime.rs` logs a lag on
  either of its two channels and reads on, and ends only when a channel
  closes.
- `punch_recv_error.rs`: a punch attempt (`run_punch_attempt` in
  `traversal.rs`) is not ended early by a receive error on its socket. An
  attempt whose only target is a closed port runs to its timeout, on the
  socket as the runtime makes it and, on Linux, on a socket with
  `IP_RECVERR` set, where the port-unreachable is reported to `recv_from` as
  Windows reports it by default; on that Linux socket a peer's probe
  arriving after the reports is still adopted. A Windows-only test checks
  that a port-unreachable does not fail a receive on the traversal socket
  at all.
- `signal_lag.rs`: a traversal answer delivered ahead of a flood of
  advertisements twice the relay pool's notification channel size still
  reaches the traversal waiting for it, through the relay client's
  admission policy and the notify loop in `runtime.rs`.

Tests of one file:

- `signal_route.rs`, of `signal_route.rs`: the admission policy takes a
  traversal signal off the pool's channel and queues it on its own, once
  however many relays deliver it, and leaves every other event to the pool.
