# Nostr rendezvous tests in their own files

Test modules of `src/nostr/tests.rs`, which declares each as `mod <name>;`,
so each is a child of `nostr::tests` and reaches the `pub(super)` items of
the files in `src/nostr/` and the private helpers of `tests.rs` (such as
`send_probe`). Most of this directory's unit tests are still in `tests.rs`
itself; the files here each hold one behaviour's tests.

- `punch_recv_error.rs`: a punch attempt (`run_punch_attempt` in
  `traversal.rs`) is not ended early by a receive error on its socket. An
  attempt whose only target is a closed port runs to its timeout, on the
  socket as the runtime makes it and, on Linux, on a socket with
  `IP_RECVERR` set, where the port-unreachable is reported to `recv_from` as
  Windows reports it by default; on that Linux socket a peer's probe
  arriving after the reports is still adopted.
