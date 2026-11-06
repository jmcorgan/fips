# core/src/proto/bloom

Reachability bloom filters. Each node keeps a filter per peer saying
which destinations are reachable through that peer, merges them into
the filter it announces, and routes with them before it knows a
destination's coordinates. The root crate's tree and bloom handlers
decode announcements, call `BloomState`, and send what it returns.

## Files

- `mod.rs`: declares the files and re-exports their public items.
- `core.rs`: `BloomFilter`, the bit array with its insert, merge and
  query operations and its fill ratio and false-positive estimate.
- `state.rs`: `BloomState`, the per-peer inbound filters, the outgoing
  filter computation, the decision of when to send an update, and the
  history of filters sent to each peer.
- `limits.rs`: the filter size, the size classes and the hash count.
- `wire.rs`: `FilterAnnounce` and its codec.
- `tests/`: the unit tests; its README describes it.

## Invariants

- **Identical arithmetic everywhere.** The false-positive estimate uses
  `crate::proto::math::powi` and `libm::log` rather than `f64` methods,
  so every platform computes the same bits. The estimate feeds a reject
  comparison that nodes must agree on.
- **The filter size, hash count and hashing are wire format.** Nodes
  test each other's filters, so all three must match across the mesh.
- **Received filters are untrusted.** `FilterAnnounce::decode` rejects
  any size class but the v1 one, so a peer cannot choose the size of the
  filter this node stores for it.

## The sent-filter history and the child echo check

`BloomState` keeps the last `SENT_HISTORY` (four) distinct filters sent
to each peer, oldest dropped first; sending a kept filter again moves it
to the newest place rather than keeping it twice. `last_sent_filter`
returns the newest, and every reader that wants "what the peer was last
sent" (change detection, the announce delivery record, the control API
and the status snapshot) reads only that. `sent_history` returns all of
them, newest first, and only the root crate's child echo check reads it.
`forget_sent` (the peer restarted) and `remove_peer_state` (the peer was
removed) clear the whole history, so it is cleared wherever the newest
filter is, and by no other path.

The child echo check refuses a tree child's announce that returns a
filter this node sent it (`BloomFilter::echoes`, at
`node.bloom.child_echo_threshold`). It tests the announce against each
kept filter with the same bound, because a child whose view lags can
return an earlier filter, which may overlap the latest by less than the
bound. An echo of a filter older than the history still passes and is
stored, and because a refusal leaves the stored filter as it was
(FRC-1402 Section 4.6.2), it is kept until the child's next accepted
filter.

An independent filter crosses one comparison by chance with some
probability `p`; across the history the chance is at most `4p` (union
bound). Exact hypergeometric tails at the default threshold 0.8, for
the 8192-bit filter:

- At the fills of the root crate's healthy-path test (a child's honest
  subtree of 650 entries, 2696 set bits, fill 0.329, bound 0.866): against
  a sent filter of 4479 set bits the bound needs 3879 shared bits, more
  than the child's filter has, so `p` is 0; against one of 2700 set bits
  `p` is about 1e-1218.
- At the worst case the `ECHO_MIN_BITS` floor allows (a sent filter of 128
  set bits, a child's filter at the FPR cap's fill 0.7248): `p` is about
  1.3e-10, so across the history at most about 5e-10 per announce.

A refusal is counted every time, but logged at WARN only for the first
from a peer in each `ECHO_WARN_MS` (five minutes); the rest go to DEBUG.
`BloomState::warn_echo` decides, from a per-peer stamp the caller reads
on its monotonic clock; `remove_peer_state` clears the stamp.
