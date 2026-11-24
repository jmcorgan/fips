# src/nostr/fixtures/frc1601

Test vectors published in FRC-1601 (Nostr rendezvous, version 1), Appendix C,
copied here so the unit tests can read them. They are published vectors, not
captures: they do not change with a library version.

- `c9.json`: the sample traversal signal of Appendix C.9, a kind 21059 wrap
  from node A to node B carrying the rumor of C.6, with the line breaks of the
  appendix's text removed. Its wrap key, NIP-44 nonces and signature
  randomness were drawn at random, so it cannot be rebuilt; it checks the
  opening steps. The test is in `src/nostr/machine/event/tests/signal.rs`.
