# src/nostr/machine/adverts/tests

Unit tests of `src/nostr/machine/adverts/`.

- `mod.rs` is `adverts::tests`, declared from `adverts/mod.rs` as
  `#[cfg(test)] mod tests;`. It holds the helpers the files below share:
  `ep`, a UDP endpoint, and `advert`, an advert body with our identifier and
  version.
- The tests of one file, declared from that file as
  `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so each is its
  file's child module and reaches its private items:
  - `cache.rs`, of `cache.rs`: admission and replacement, pruning, the size
    cap and the protection of configured and linked authors against a flood
    of new keys, the open-discovery candidates (drawn from a seeded entropy
    source) and the cache-full warning's latch (on a test instant).
  - `publisher.rs`, of `publisher.rs`: a change of local advert is reported,
    and the publish decision strips or keeps the relay and STUN lists, refuses
    a `udp:nat` advert without relays, and publishes nothing when there is no
    local advert or advertising is off.

The rules in `adverts/mod.rs` are tested in `src/nostr/tests/mod.rs`, with
the cache's lapse grace.
