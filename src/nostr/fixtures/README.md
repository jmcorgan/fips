# src/nostr/fixtures

Recorded Nostr events that the unit tests of `src/nostr/` read. Nothing here
is compiled: the tests load each file with `include_str!` from a path built on
`CARGO_MANIFEST_DIR`, so a test file can move without breaking the path. They
live under `src/` because the published crate carries `src/` and not
`testing/`.

- `v044/`: the events nostr 0.44's code emits, one of each kind a node
  publishes or sends (the advert, the inbox relay list, an offer wrap and an
  answer wrap). The code built on a later nostr version must open and parse
  them, since they are what deployed nodes send. The README in `v044/`
  describes each file.

A new directory is added for another library version's events rather than
changing these.
