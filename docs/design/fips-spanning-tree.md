# FIPS Spanning Tree

This document describes the spanning tree algorithms and data structures
used by FIPS for coordinate-based routing. It is a supporting reference
for readers who want to understand the tree internals — for how the
spanning tree fits into the overall mesh operation, see
[fips-mesh-operation.md](fips-mesh-operation.md).

## Purpose

The spanning tree gives every node in the mesh a **coordinate** — its
ancestry path from itself to the root. These coordinates enable:

- Distance calculation between any two nodes without global topology
  knowledge
- Greedy routing where each hop reduces distance to the destination
- Loop-free forwarding guaranteed by strictly-decreasing distance

## Root Election

The root is the node with the **lexicographically smallest node_addr** among
all reachable nodes. There is no election protocol, no voting, no
negotiation. Each node independently evaluates the TreeAnnounce messages
from its peers and selects the minimum root.

When a node first joins the network with no peers, it is its own root. As
it connects to peers and receives their TreeAnnounce messages, it discovers
smaller node_addrs and converges to the global root.

If the network partitions, each segment independently elects its own root
(the smallest node_addr in that segment). When segments rejoin, all nodes
discover the globally-smallest root through TreeAnnounce exchange and
reconverge to a single tree.

## Parent Selection

Each node selects a single parent from among its direct peers. Parent
selection follows these rules:

### Selection Criteria

1. **Find the smallest root** visible across all peers' TreeAnnounce messages
2. Among peers that can reach that root, prefer the one offering the
   **shallowest depth** (shortest path to root)
3. Apply the **depth improvement threshold**: switching parents requires the
   proposed parent to offer a path at least 1 hop shallower than the current
   parent (when the root is the same)

### Immediate Switch Triggers

Three conditions bypass the depth threshold and trigger immediate parent
reselection:

1. **Parent loss**: Current parent is no longer in the peer set (link
   broken, peer disconnected)
2. **Better root**: A peer advertises a smaller root than the current
   tree's root — always switch regardless of depth
3. **Depth improvement**: Same root, but the proposed parent offers depth
   at least `PARENT_SWITCH_THRESHOLD` (1 hop) better than the current parent

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
(3 - 2) + (3 - 2) = 2 hops.

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
- Used for stale detection, not versioning
- A root declaration is considered stale after `ROOT_TIMEOUT` (60 minutes)
  without refresh

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
2. If the root was in the other segment, affected nodes elect a new segment
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
| PARENT_SWITCH_THRESHOLD | 1 hop | Minimum depth improvement for same-root switch |
| ANNOUNCE_MIN_INTERVAL | 500ms | Minimum between announcements to same peer |
| ROOT_TIMEOUT | 60 min | Root declaration considered stale |
| TREE_ENTRY_TTL | 5–10 min | Individual entry expiration |

## Implementation Status

| Feature | Status |
| ------- | ------ |
| Root election (smallest node_addr) | **Implemented** |
| Parent selection with depth threshold | **Implemented** |
| Coordinate computation | **Implemented** |
| TreeAnnounce gossip | **Implemented** |
| Signature verification (outer) | **Implemented** |
| Sequence-based freshness | **Implemented** |
| Rate limiting (500ms per peer) | **Implemented** |
| Coord cache flush on parent change | **Implemented** |
| Root timeout enforcement | Planned |
| Tree entry TTL enforcement | Planned |
| Hold-down timer after parent change | Planned |
| Per-ancestry-entry signatures | Future direction |

## References

- [fips-mesh-operation.md](fips-mesh-operation.md) — How the spanning tree
  fits into mesh routing
- [fips-wire-formats.md](fips-wire-formats.md) — TreeAnnounce wire format
- [spanning-tree-dynamics.md](spanning-tree-dynamics.md) — Convergence
  scenario walkthroughs
