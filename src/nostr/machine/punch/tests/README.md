# src/nostr/machine/punch/tests

Unit tests of `src/nostr/machine/punch/`.

- `mod.rs` is `punch::tests`, declared from `punch/mod.rs` as
  `#[cfg(test)] mod tests;`, so it reaches the module's private items. It
  holds the codec's tests: `classify_punch_packet` ignores a datagram too
  short to parse and one for another session, acks a matching probe with its
  sequence, and takes a matching ack as the peer's answer.
- `refusal.rs`, of `refusal.rs` (declared there as
  `#[cfg(test)] #[path = "tests/refusal.rs"] mod tests;`): the refusal
  warning gate admits a stranger's first refused offer, stays quiet for the
  rest of the minute, and admits the next one a minute later with the count
  it suppressed.

- `attempt.rs`, of `attempt.rs`: the attempt on a test instant. An
  unplanned source is refused before it is acked; a planned target's probe
  is acked and adopted; an exact target is adopted at once, over a held
  remapped one; a remapped port is adopted when the settle passes, and a
  later one supersedes it without moving the settle; an attempt with nothing
  to adopt times out once and counts its receive errors; the rounds go to
  every target from the hinted start until the duration ends, at no less
  than 20 ms apart; and FRC-1601 Appendix C.7's packets.

The round trip of `build_punch_packet` and `parse_punch_packet` and punch
planning and vetting (`plan.rs`) are tested in `src/nostr/tests/mod.rs`, the
attempt on a real loopback socket through receive errors in
`src/nostr/tests/punch_recv_error.rs`, and whole attempts between two
machines in `machine/rendezvous/tests/traversal.rs`.
