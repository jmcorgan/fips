# src/nostr/machine/traversal

What the node remembers about traversal attempts, its own and its peers', and
what it decides from that memory, including how many inbound signals it lets
through to decryption. No locks, clocks or logging: the shell's `runtime.rs`
holds each piece behind one `std::sync::Mutex`, passes in the clock reading
it took, and logs from the decision it gets back.

## Files

- `mod.rs`: the module.
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
- Methods take `&mut self`; the shell's accessor holds the lock for one call
  and never across an `.await` (the runtime binds a decision before any
  `match` whose arms await).
