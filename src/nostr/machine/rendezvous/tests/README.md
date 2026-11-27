# src/nostr/machine/rendezvous/tests

Tests of the rendezvous machine, stepped by hand. `mod.rs` is
`rendezvous::tests`, declared from `rendezvous/mod.rs` as
`#[cfg(test)] mod tests;`. It holds the harness: a machine for FRC-1601
Appendix C.1's node A, stepped at a scripted monotonic instant
(`TestInstant`) and Unix time, with randomness from `SeededEntropy`, and
helpers that pick actions out of what a step queued, and build a forged
advert (`forged_by`: a peer's advert whose content names other endpoints
than it was signed with). Every assertion is on
the actions the machine queues.

- `startup.rs`: start subscribes to signals and adverts, then publishes the
  inbox relay list, then the advert; a failed subscribe is retried after 2 s,
  doubling to 60 s, under the same subscriptions; the inbox relay list is
  republished before it ages out of the 30-day lookup window, and is read
  back as this node's DM relays.
- `adverts.rs`: a relay's advert is cached and logged unless it is our own;
  a forged advert on the stream is not cached, and is counted and logged,
  with a warning at each power of two;
  a publish requested while one is in flight runs once after it; the advert
  is republished every refresh interval from start; a failed or timed-out
  publish is logged; a wildcard public UDP transport holds the publish until
  its address is learned, observed one transport at a time in snapshot
  order, and a learned address is kept for its time to live; start-up's
  request is answered only once the address is learned; the cache-full
  warning is released a minute after the cache drops below its cap, and a
  minute after its entries expire with no input, so a second flood is
  warned again; a
  shrunk protected set trims the cache at once; the public address is
  learned through the STUN client on an ephemeral socket, a failed bind
  leaves it unknown, and with no STUN servers no socket is bound; and a
  publish that reached no relay is logged and otherwise treated as sent; a
  learned address is observed again when it ages out, with no new
  snapshot; and the wildcard notes are logged once per assembly.
- `queries.rs`: a peer's endpoints from the cache or the newest fetched
  advert by the peer, and `MissingAdvert` when there is none; a forged
  newer advert does not displace the genuine one in a fetch; the
  stale-advert refetch's outcomes, with the peer's failure streak reset in
  the step that replies, a forged newer advert not holding back a refresh,
  and an answer of a forged advert alone evicting; open discovery after a
  prune; and results for operations the machine no longer expects.
- `auth.rs`: a NIP-42 challenge is answered with a kind 22242 event signed
  by the node key at the step's time.
- `traversal.rs`: the responder refuses an oversized session id or nonce
  before remembering it, at the byte bound exactly; a full seen-sessions
  memory refuses a new offer, and a captured offer is still a replay after
  it fills; capacity off drops the next offer and capacity on admits it;
  a responder session that ends gives its admission slot back, so more
  offers than the bounds allow at once are all admitted one after another,
  and so does an offer dropped at capacity and a suppressed offer; a failed
  initiator closes its socket, and so does a responder whose punch runs out;
  the signal gate counts a traversal awaiting its answer from the session
  table; suppressing a peer's offer re-sends ours once, a failed re-send is
  tried again on the next suppression, and answering a peer's offer re-sends
  nothing; the offer to a peer configured in any case is addressed to its
  canonical npub and the initiator is registered under it; a forged newer
  inbox relay list does not change the relays the offer is sent to, and is
  counted; and a peer
  configured in upper case still loses the dual-initiation election to our
  initiator. Its second harness runs two machines (node A and node B) over a
  fake relay that carries their signals and a fake network with cone and
  symmetric NATs and a STUN server: a whole traversal through a cone NAT
  (with a stale answer that must not be taken for the one routed by the
  offer's nonce), through a symmetric NAT (adopted as a remapped port), and
  a dual initiation that ends in B's one session, with B's one re-send and
  A's own traversal timing out; and a punch that succeeds clears the
  failure cooldown for the peer, and publishes the status, on the
  initiator's end and on the responder's.
