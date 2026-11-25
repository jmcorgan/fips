# src/nostr/machine/traversal/tests

Unit tests of `src/nostr/machine/traversal/`, one file per source file. Each
is declared from its file as
`#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so it is the file's
child module and reaches its private items.

- `admission.rs`, of `admission.rs`: the global bound, a sender at its
  allowance refused while another is admitted, and a released slot reused
  with the idle sender forgotten; and, moved from the shell's wrapper when
  it went, one sender cannot take more than its allowance or deny another,
  several peers bootstrapping at once are all admitted, and an idle sender
  is reclaimed so the table cannot grow without bound.
- `election.rs`, of `election.rs`: initiator election, outbound initiator
  dedup, and the replay cache's expiry and cap.
- `failures.rs`, of `failures.rs`: the per-npub failure streaks, the warning
  window, cooldowns, protocol-mismatch cooldowns, observed skew and the size
  cap.
- `rules.rs`, of `rules.rs`: FRC-1601 Appendix C.5 (the offer and answer
  bodies, the answer's checks, the freshness table, the node-address
  ordering of a dual initiation and the replayed copy), and the text and
  warning class of each offer refusal.
- `gate.rs`, of `gate.rs`: the inbound signal rate limit, its refill, and the
  reserve kept for answers to this node's own traversals, on a test instant
  of whole milliseconds.

The rendezvous machine's use of these pieces is tested in
`machine/rendezvous/tests/traversal.rs`: the dual-initiator, re-send and
replay paths, the gate's view of the sessions, and whole traversals.
`suppress_responder_for_own_initiator` is also tested in
`src/nostr/tests/mod.rs`, the seen-sessions memory's cap and floor in
`src/nostr/tests/seen_session_cap.rs` and `seen_session_floor.rs` (which also
read the signal gate's rate and burst constants), and the node's failure,
refetch and mismatch paths in `src/node/tests/`.
