# src/peer/tests

Unit tests for files in `src/peer/`, kept out of the source files. Each file
here is a test module of the source file of the same name one level up,
declared from that file with `#[cfg(test)] #[path = "tests/<file>.rs"]`, so it
stays a child module of its source file and can reach that file's private
items.

- `active.rs`: tests for `ActivePeer` (`src/peer/active.rs`), declared from
  that file as `#[cfg(test)] #[path = "tests/active.rs"] mod tests;`, so they
  keep their test names. They cover the peer's link state: tree position and
  filter bookkeeping, decrypt failures charged to the original pair and
  started again by an authentic frame there, the replay counter, rekey
  jitter and msg1 resends, the pending, current and previous sessions across a cutover
  (held in the peer's link rekey machine, so every session a test peer holds
  authenticates one peer key, and its indices are leased outside any
  allocator), the replay window and the inner-header timestamp each cutover
  restarts, the withheld handshake diagnostics, the link MMP receive state
  and last accepted receiver report that a cross-connection move resets as a
  cutover does, and that the rekey dampening, the pending hold and the drain
  run on the peer clock, which `crate::time::advance` moves, and that a
  path's Dead time is stamped on that clock.
- `data.rs`: tests for `PeerData` (`src/peer/data.rs`), declared from that
  file as `#[cfg(test)] #[path = "tests/data.rs"] mod tests;`. They cover what
  a new record holds, read through `ActivePeer`, which is the only way in to a
  peer's record, for each of its constructors, and read from the record itself
  for the fields no accessor tells apart.
- `machine.rs`: tests for `PeerMachine` (`src/peer/machine.rs`), declared as
  `mod msg2_tests` because `machine.rs` already has an inline `tests` module.
  They cover an initial (IK) dial receiving a msg2 that does not authenticate:
  the machine refuses it and keeps the handshake, so the genuine msg2 still
  completes the session. They also cover the promotion an inbound leg asks
  for when a resend of its stored msg2 succeeds after a failed first send,
  and the legs that must not ask for one (not authorized, already
  established, or with the peer held on another link).

`machine.rs` and `mod.rs` still carry older inline `mod tests` blocks. New
tests go here rather than into those blocks; the inline blocks are not
converted in passing. Node-level tests of peer behaviour live in
`src/node/tests/`.
