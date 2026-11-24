# src/nostr/machine/traversal/tests

Unit tests of `src/nostr/machine/traversal/`, one file per source file. Each
is declared from its file as
`#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so it is the file's
child module and reaches its private items.

- `election.rs`, of `election.rs`: initiator election, outbound initiator
  dedup, and the replay cache's expiry and cap.
- `failures.rs`, of `failures.rs`: the per-npub failure streaks, the warning
  window, cooldowns, protocol-mismatch cooldowns, observed skew and the size
  cap.
- `gate.rs`, of `gate.rs`: the inbound signal rate limit, its refill, and the
  reserve kept for answers to this node's own traversals, on a test instant
  of whole milliseconds.

The runtime's use of these pieces is tested through the shell: the
dual-initiator and replay paths and `suppress_responder_for_own_initiator` in
`src/nostr/tests/mod.rs`, the seen-sessions memory's cap and floor in
`src/nostr/tests/seen_session_cap.rs` and `seen_session_floor.rs` (which also
read the signal gate's rate and burst constants), and the
node's failure, refetch and mismatch paths in `src/node/tests/`.
