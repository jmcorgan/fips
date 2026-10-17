# src/node/session

End-to-end (FSP) session state for the node: one `SessionEntry` per remote
endpoint, holding its Noise XK handshake or established session, the
current, pending and previous key slots used across a rekey, and the timers
that drive msg3 retransmission and the drain of the previous session.

- `mod.rs`: the session table types (`SessionEntry`, `EndToEndState`,
  `EpochSlot`), admission of half-open responder candidates, and the session
  clock aliases. The handlers that send and receive session messages
  live under `src/node/handlers/`, not here.
- `tests.rs`: unit tests for `mod.rs`, declared from it as
  `#[cfg(test)] #[path = "tests.rs"] mod overlapping_epoch_tests;` so they stay
  a child module that can reach private items and keep their test names.

Unit tests go in `tests.rs`, never in an inline `mod tests` block in
`mod.rs`.
