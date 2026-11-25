# src/nostr/machine/traversal

What the node remembers about traversal attempts, its own and its peers', and
what it decides from that memory, including how many inbound signals it lets
through to decryption, the traversal sessions in hand, and the pure rules a
traversal follows. No locks, clocks or logging: the rendezvous machine owns
each piece, passes in the step's clock reading, and logs from the decision
it gets back.

## Files

- `mod.rs`: the module.
- `admission.rs`: `Admission`, the per-npub admission of inbound offers
  as counts. An offer takes a slot of its sender's allowance and one of the
  global bound, as a `SlotId`, and `release` gives both back; a sender is
  forgotten when its count reaches zero, so the table holds at most the
  global bound of senders. The per-sender check runs first, so a sender
  over its allowance never touches the global bound.
- `election.rs`: `Election`, the set of peers this node has an outbound
  traversal running to and the seen-sessions cache. It refuses a second
  outbound traversal to a peer that already has one; when both peers start
  a traversal to each other, it keeps the session the smaller `NodeAddr`
  initiated (`suppress_responder_for_own_initiator`, the node's usual
  tie-breaker); and it refuses an offer whose session id it has seen inside
  the replay window. A full cache refuses a new session id rather than
  forgetting a live one, so a copy of a still-fresh offer is always caught.
- `failures.rs`: `FailureState`, the per-npub failure record. It counts
  consecutive traversal failures, decides when a repeated failure is logged
  at warning level and when a peer enters its extended cooldown, flags the
  failure that crosses the streak threshold (the runtime then refetches the
  peer's advert), holds the long cooldown of a protocol mismatch apart from
  the transient one, keeps the last observed clock skew for `show peers`,
  and bounds the table, evicting the entries with the oldest failure first.
  Its four settings come from `Params`.
- `gate.rs`: `SignalGate`, the allowance for inbound traversal signals
  ahead of any decryption: one shared token bucket for every sender, since
  none is known before the first decrypt, and a reserve drawn only while
  this node has traversals of its own outstanding, so a flood cannot also
  shed the answers to them. It takes instants of any
  `fips_core::time::Instant` type; the shell passes its host clock's. Its
  rate and burst constants are `pub(crate)` so the seen-sessions tests can
  derive from them how many offers the gate admits in a replay window.
- `rules.rs`: the traversal's pure rules. The bound on an inbound offer's
  session id and nonce, and `RejectReason`, why an offer is refused, whose
  text is `BootstrapError`'s and which says whether the refusal is one relay
  lag cannot explain (logged at warning level). `peer_key` and
  `canonical_npub`, the one spelling of a peer's npub that state is keyed
  by; `short_npub` and `short_id` for log fields. `signal_relays`, which
  relays a signal goes to, kept to those the relay pool holds. Where a
  peer's inbox relay list is looked up and the fallback to our DM relays.
  The punch hint a node sends, and the skew from which an observed clock
  offset is noted at debug.
- `sessions.rs`: `Sessions`, the traversal sessions in hand, the
  initiator's and the responder's in one table, each a `Session` whose
  `Stage` names the step it is at and the operation it waits on. A session
  is found by the nonce an answer names (only while its offer is being
  published or is out), by its peer, by its socket or by its operation.
  `Resend` is the one re-send of an initiator's offer a dual initiation
  allows. A session keeps up to 64 datagrams that arrive between its
  observation and its punch attempt, for the attempt.
- `tests/`: this directory's unit tests.

## Rules for changing it

- A map keyed by something a peer chooses (the failure table's npubs, the
  seen-sessions cache's ids) is a `fips_core::utils::hash::HashMap` under a
  hasher the shell keys from the host's entropy; nothing decides by its
  iteration order. The initiator set is only tested for membership, so it is
  a `BTreeSet`.
- A constant a test outside the machine reads is `pub(crate)`, never
  `pub(in crate::nostr)`: the guard reads the latter as a `crate::` path
  outside the module.
- Methods take `&mut self`, and only the rendezvous machine calls them, in
  its steps.
