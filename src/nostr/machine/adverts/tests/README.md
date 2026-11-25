# src/nostr/machine/adverts/tests

Unit tests of `src/nostr/machine/adverts/`.

- `mod.rs` is `adverts::tests`, declared from `adverts/mod.rs` as
  `#[cfg(test)] mod tests;`. It holds the helpers the files below share:
  `ep`, a UDP endpoint, and `advert`, an advert body with our identifier and
  version.
- The tests of one file, declared from that file as
  `#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so each is its
  file's child module and reaches its private items:
  - `assemble.rs`, of `assemble.rs`: each transport's precedence (external
    address, specific bind, learned address), the notes for a wildcard
    transport that cannot be advertised, the `udp:nat` relays and STUN
    servers, Tor, the `advertise` gate, and which transports need a learned
    address, in snapshot order.
  - `ingest.rs`, of `ingest.rs`: an expired advert is refused before it is
    parsed (seen through a counting decode), a forged advert (its content
    changed after signing, or a signature by another key than its
    `pubkey`) is refused as `Forged` before it is decoded, the FRC-1601
    C.2 advert and the nostr 0.44 fixture advert pass the signature check,
    an event without our `protocol` tag or over the content bound is
    refused before its signature is checked, an advert for another app and
    an oversized one are refused (the latter before decoding), a future
    `created_at` is clamped, the newest event is chosen only among the
    author's, our own advert's long lists are cut and named, and the
    validity horizon and the endpoint rule hold FRC-1601 Appendix C.3's
    and C.8's rows.
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
