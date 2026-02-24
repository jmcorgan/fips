# FIPS Spanning Tree

This document describes the spanning tree algorithms and data structures
used by FIPS for coordinate-based routing. It is a supporting reference
for readers who want to understand the tree internals — for how the
spanning tree fits into the overall mesh operation, see
[fips-mesh-operation.md](fips-mesh-operation.md).

## What Is a Spanning Tree?

A spanning tree is a subset of the links in a mesh network that:

- **Reaches every node** — no node is disconnected
- **Contains no cycles** — there is exactly one path between any two nodes
- **Has a single root** — one distinguished node from which all paths descend
- **Assigns every non-root node exactly one parent** — creating a
  hierarchy from leaves to root

Because a tree has no cycles, any node's position can be described by
its path to the root. This path serves as a coordinate in a virtual
address space, enabling distance calculations and routing decisions
without global topology knowledge.

There is nothing special about the root node other than providing the
center of the coordinate system. Being root implies no additional
processing, routing, or operational burden — the root runs the same
protocol as every other node.

## Purpose

The FIPS spanning tree gives every node in the mesh a **coordinate** — its
ancestry path from itself to the root. These coordinates enable:

- Distance calculation between any two nodes without global topology
  knowledge
- Greedy routing where each hop reduces distance to the destination
- Loop-free forwarding guaranteed by strictly-decreasing distance

## Root Discovery

The root is the node with the **lexicographically smallest node_addr** among
all reachable nodes. There is no election protocol, no voting, no
negotiation — each node independently discovers the same root by
evaluating the TreeAnnounce messages from its peers and selecting the
minimum root.

When a node first joins the network with no peers, it is its own root. As
it connects to peers and receives their TreeAnnounce messages, it discovers
smaller node_addrs and converges to the global root.

If the network partitions, each segment independently discovers its own root
(the smallest node_addr in that segment). When segments rejoin, all nodes
discover the globally-smallest root through TreeAnnounce exchange and
reconverge to a single tree.

## Parent Selection

Parent selection and reselection is the primary means by which the mesh
self-organizes into an efficient routing structure. By having each node
choose the parent with the best measured link performance, packet
routing up and down the tree follows the best available path that
reduces distance to the destination.

Each node selects a single parent from among its direct peers. Parent
selection uses cost-weighted depth to balance tree depth against link
quality.

### Selection Criteria

1. **Find the smallest root** visible across all peers' TreeAnnounce messages
2. Compute **effective depth** for each candidate peer:
   `effective_depth = peer.depth + link_cost`, where
   `link_cost = etx * (1.0 + srtt_ms / 100.0)` using locally measured MMP
   metrics. When MMP metrics have not yet converged, `link_cost` defaults to
   1.0, preserving pure depth-based behavior as a graceful fallback.
3. Apply **hysteresis**: switch parents only when the best candidate's
   effective depth is significantly better than the current parent's:
   `best_eff_depth < current_eff_depth * (1.0 - parent_hysteresis)`
   (default `parent_hysteresis = 0.2`, requiring 20% improvement)

### Mandatory Switch Triggers

Two conditions bypass both hysteresis and the hold-down timer, triggering
immediate parent reselection:

1. **Parent loss**: Current parent is no longer in the peer set (link
   broken, peer disconnected)
2. **Better root**: A peer advertises a smaller root than the current
   tree's root — always switch regardless of effective depth

### Stability Mechanisms

- **Hold-down timer** (`hold_down_secs`, default 30s): After any parent
  switch, non-mandatory re-evaluation is suppressed to allow MMP metrics
  to stabilize on the new link. Mandatory switches (parent loss, root
  change) bypass the hold-down.
- **Periodic re-evaluation** (`reeval_interval_secs`, default 60s):
  Re-evaluates parent selection using current MMP link costs, independent
  of TreeAnnounce traffic. This catches link degradation after the tree
  has stabilized and TreeAnnounce gossip has stopped.
- **Flap dampening** (`flap_threshold` / `flap_window_secs` /
  `flap_dampening_secs`): If a node switches parents more than
  `flap_threshold` times (default 4) within `flap_window_secs` (default
  60s), an extended hold-down of `flap_dampening_secs` (default 120s) is
  imposed. This reduces TreeAnnounce storms from link flapping without
  delaying legitimate reconvergence. Mandatory switches (parent loss,
  root change) bypass dampening.
- **Local-only metrics**: Link costs use only locally measured MMP data
  (ETX and SRTT). No cumulative path costs are propagated, avoiding
  the trust problems inherent in self-reported cost metrics in a
  permissionless network.

### After Parent Change

When a node changes its parent:

1. Increment its own sequence number
2. Recompute its coordinates from the new ancestry path
3. Sign a new TreeAnnounce declaration
4. Announce to all peers
5. Flush the coordinate cache (cached coordinates are relative to the old
   position and may be invalid for routing)

## Coordinate Computation

A node's coordinate is its full ancestry path from itself to the root:

```text
coords(N) = [N, Parent(N), Parent(Parent(N)), ..., Root]
```

Coordinates are ordered self-to-root. For a node D at depth 4:

```text
coords(D) = [D, P1, P2, P3, Root]
```

The root's coordinate is simply `[Root]` (depth 0).

## Tree Distance

Tree distance between two nodes is the number of hops through their lowest
common ancestor (LCA). Because coordinates are ordered self-to-root, common
ancestry appears as a common suffix.

```text
tree_distance(a, b):
    lca_depth = longest_common_suffix_length(a.coords, b.coords)
    a_to_lca = len(a.coords) - lca_depth
    b_to_lca = len(b.coords) - lca_depth
    return a_to_lca + b_to_lca
```

Example: If A has coordinates `[A, X, Y, Root]` and B has coordinates
`[B, Z, Y, Root]`, the common suffix is `[Y, Root]` (length 2). Distance =
(4 - 2) + (4 - 2) = 4 hops.

The self-distance check in greedy routing uses this calculation: a packet is
forwarded to a peer only if the peer is strictly closer to the destination
than the current node.

## TreeAnnounce Processing

When a node receives a TreeAnnounce from peer P:

1. **Validate version**: Reject if version ≠ 0x01
2. **Verify signature**: Check P's declaration signature using P's known
   public key (established during Noise IK handshake)
3. **Verify identity**: Confirm the declaration's node_addr matches the
   sender's known identity
4. **Check freshness**: If `sequence ≤ stored sequence for P`, discard
   (stale or duplicate)
5. **Update peer state**: Store P's tree declaration and ancestry
6. **Evaluate parent selection**: Re-run parent selection with the updated
   peer state

### Propagation Rules

A node re-announces (propagates) only when its own state changes:

- **Root changed**: Always propagate — this is a significant topology event
- **Depth changed**: Always propagate — affects routing distance calculations
- **Sequence-only refresh**: Does NOT propagate beyond depth 1 — peers that
  receive a sequence-only update do not re-announce, because their own root
  and depth have not changed

This means TreeAnnounce cascades through the tree proportional to depth,
not network size. A change at depth D affects at most D nodes along the
branch, and each only re-announces to its peers.

### Rate Limiting

- **Minimum interval**: 500ms between announcements to the same peer
- **Coalescing**: If changes occur during cooldown, they are coalesced and
  sent as a single announcement after the cooldown expires
- **Convergence time**: A tree of depth D reconverges in roughly D × 0.5s
  to D × 1.0s

### Transitive Trust (v1)

In the v1 protocol, only the sender's outer signature on the TreeAnnounce
is verified. Ancestry entries beyond the direct peer (the sender's parent,
grandparent, etc.) are accepted on transitive trust through the
authenticated sender. The sender is a known, authenticated peer — if it
claims a particular ancestry, v1 trusts that claim.

Future protocol versions may add per-entry signatures in the ancestry chain
for stronger verification.

## Sequence Numbers and Timestamps

### Sequence Number

- Type: u64, monotonically increasing
- Incremented on each parent change
- Used for freshness: incoming TreeAnnounce with sequence ≤ stored sequence
  for that peer is discarded
- Higher sequence numbers always supersede lower ones

### Timestamp

- Type: u64, Unix seconds
- Advisory only — not used in any decision logic, as there is no way to
  verify its accuracy from peers

## Reconvergence

### Single Node Failure

When a node fails (link timeout or disconnect):

1. Nodes that had the failed node as their parent lose their parent
2. Parent loss triggers immediate reselection from remaining peers
3. Each affected node recomputes coordinates and announces
4. Changes cascade down the subtree proportional to depth

### Partition

When the network partitions:

1. Nodes in each segment lose peers across the partition boundary
2. If the root was in the other segment, affected nodes discover a new segment
   root (smallest node_addr in their segment)
3. Each segment reconverges independently

### Partition Merge

When two partitions rejoin:

1. Nodes at the boundary exchange TreeAnnounce messages with new peers
2. Both segments discover each other's root
3. The globally-smaller root wins; the other segment's nodes switch parents
4. Coordinate caches are flushed at switching nodes (stale cross-partition
   coordinates)
5. Bloom filters update within ~500ms per hop, restoring reachability
   information

## Bounded State

Each node's spanning tree state is O(P × D), where P is the number of
direct peers and D is the tree depth. This is NOT O(N) where N is the
network size.

What a node stores:

- Its own declaration (coordinates, sequence, timestamp, signature)
- Each peer's declaration and ancestry chain (P entries, each with D
  ancestry entries)

What a node does NOT know:

- Other subtrees branching off its ancestors
- Siblings of ancestors
- Nodes in distant parts of the network

Example: In a 1000-node network with depth 10 and 5 peers, a node stores
~50 ancestry entries — not 1000 routing table entries.

## Timing Parameters

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| PARENT_HYSTERESIS | 0.2 (20%) | Fractional improvement in effective depth required for same-root switch |
| HOLD_DOWN_SECS | 30s | Suppress non-mandatory re-evaluation after parent switch |
| REEVAL_INTERVAL_SECS | 60s | Periodic cost-based parent re-evaluation interval |
| FLAP_THRESHOLD | 4 | Parent switches in window before dampening engages |
| FLAP_WINDOW_SECS | 60s | Sliding window for counting parent switches |
| FLAP_DAMPENING_SECS | 120s | Extended hold-down duration when flap threshold exceeded |
| ANNOUNCE_MIN_INTERVAL | 500ms | Minimum between announcements to same peer |

## Implementation Status

| Feature | Status |
| ------- | ------ |
| Root discovery (smallest node_addr) | **Implemented** |
| Cost-based parent selection with hysteresis | **Implemented** |
| Hold-down timer after parent change | **Implemented** |
| Periodic cost-based parent re-evaluation | **Implemented** |
| Coordinate computation | **Implemented** |
| TreeAnnounce gossip | **Implemented** |
| Signature verification (outer) | **Implemented** |
| Sequence-based freshness | **Implemented** |
| Rate limiting (500ms per peer) | **Implemented** |
| Coord cache flush on parent change | **Implemented** |
| Flap dampening (extended hold-down on rapid switches) | **Implemented** |
| Per-ancestry-entry signatures | Future direction |

## References

- [fips-mesh-operation.md](fips-mesh-operation.md) — How the spanning tree
  fits into mesh routing
- [fips-wire-formats.md](fips-wire-formats.md) — TreeAnnounce wire format
- [spanning-tree-dynamics.md](spanning-tree-dynamics.md) — Convergence
  scenario walkthroughs
