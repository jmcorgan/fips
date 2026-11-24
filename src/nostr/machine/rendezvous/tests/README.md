# src/nostr/machine/rendezvous/tests

Tests of the rendezvous machine, stepped by hand. `mod.rs` is
`rendezvous::tests`, declared from `rendezvous/mod.rs` as
`#[cfg(test)] mod tests;`. It holds the harness: a machine for FRC-1601
Appendix C.1's node A, stepped at a scripted monotonic instant
(`TestInstant`) and Unix time, with randomness from `SeededEntropy`, and
helpers that pick actions out of what a step queued. Every assertion is on
the actions the machine queues.

- `startup.rs`: start subscribes to signals and adverts, then publishes the
  inbox relay list, then the advert; a failed subscribe is retried after 2 s,
  doubling to 60 s, under the same subscriptions; the inbox relay list is
  republished before it ages out of the 30-day lookup window, and is read
  back as this node's DM relays.
- `adverts.rs`: a relay's advert is cached and logged unless it is our own;
  a publish requested while one is in flight runs once after it; the advert
  is republished every refresh interval from start; a failed or timed-out
  publish is logged; a wildcard public UDP transport holds the publish until
  its address is learned, observed one transport at a time in snapshot
  order, and a learned address is kept for its time to live; start-up's
  request is answered only once the address is learned; the cache-full
  warning is released a minute after the cache drops below its cap; a
  shrunk protected set trims the cache at once; the public address is
  learned through the STUN client on an ephemeral socket, a failed bind
  leaves it unknown, and with no STUN servers no socket is bound; and a
  publish that reached no relay is logged and otherwise treated as sent; a
  learned address is observed again when it ages out, with no new
  snapshot; and the wildcard notes are logged once per assembly.
- `queries.rs`: a peer's endpoints from the cache or the newest fetched
  advert by the peer, and `MissingAdvert` when there is none; the
  stale-advert refetch's outcomes, with the streak reset queued before the
  reply; open discovery after a prune; and results for operations the
  machine no longer expects.
- `auth.rs`: a NIP-42 challenge is answered with a kind 22242 event signed
  by the node key at the step's time.
