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

The round trip of `build_punch_packet` and `parse_punch_packet`, punch
planning and vetting (`plan.rs`), and the punch loop that uses them are
tested in `src/nostr/tests/mod.rs` with the rest of the traversal, through
the shell's paths.
