# FIPS Bloom Filters

This document describes the bloom filter data structures, parameters, and
mathematical properties used by FIPS for reachability-based candidate
selection. It is a supporting reference — for how bloom filters fit into
the overall routing system, see
[fips-mesh-operation.md](fips-mesh-operation.md).

## What Is a Bloom Filter?

A bloom filter is a space-efficient probabilistic data structure that
tests whether an element is a member of a set. It uses a bit array and
multiple hash functions to represent a set compactly, with one key
tradeoff:

- **No false negatives** — if the filter says "not present," the
  element is definitely not in the set
- **Possible false positives** — if the filter says "present," the
  element is *probably* in the set, but might not be

This makes bloom filters well-suited for routing: a definitive "no"
eliminates a peer from consideration, while a "maybe" simply means the
peer is worth checking. The false positive rate is controlled by the
filter size and number of hash functions relative to the number of
entries.

## Purpose

Each node maintains bloom filters summarizing which destinations are
reachable through each of its peers. When forwarding a packet, a node
checks its peers' filters to identify potential routing paths — typically
up or down the spanning tree, unless a mesh peer provides a shortcut
directly to the destination. The actual forwarding decision is made by
tree coordinate distance ranking.

Bloom filters answer a single question: "can peer P possibly reach
destination D?" The answer is either "no" (definitive) or "maybe"
(probabilistic — false positives are possible, false negatives are not).

## Filter Parameters

| Parameter | Value | Rationale |
| --------- | ----- | --------- |
| Size | 1 KB (8,192 bits) | Balance between accuracy and bandwidth |
| Hash functions (k) | 5 | Optimal at ~1,200 entries; good compromise for 800–1,600 range |
| Size class | 1 (v1 mandated) | `512 << 1 = 1024` bytes |

### Why k = 5

The optimal number of hash functions is k_opt = (m/n) × ln(2). For
m = 8,192 bits:

| n (entries) | k_opt | Rounded |
| ----------- | ----- | ------- |
| 800 | 7.1 | 7 |
| 1,200 | 4.7 | **5** |
| 1,600 | 3.5 | 4 |

k = 5 is optimal at n ≈ 1,200 and a practical compromise across the
800–1,600 range. The FPR penalty versus the per-n optimal k is under
1 percentage point throughout this range.

## False Positive Rate (FPR) Analysis

The false positive rate for a bloom filter with m bits, k hash functions,
and n entries is:

```text
FPR = (1 - e^(-kn/m))^k
```

With m = 8,192 bits and k = 5:

| n (entries) | Fill % | FPR | Impact |
| ----------- | ------ | --- | ------ |
| 200 | 11.5% | 0.002% | Negligible |
| 400 | 21.7% | 0.048% | Negligible |
| 800 | 38.6% | 0.86% | Negligible |
| 1,200 | 51.9% | 3.8% | Minor — occasional unnecessary candidate |
| 1,600 | 62.3% | 9.4% | Elevated |
| 2,400 | 78.3% | 27% | Poor — filter losing discrimination |
| 3,350 | 87% | 50% | Useless for candidate selection |

### Filter Occupancy Model

Filter entries are determined by **network size and tree position**, not
node degree. Under tree-only merge with split-horizon:

- **Upward filter** (to parent): contains the node's subtree — small
  for deep nodes, at most N for the root
- **Downward filter** (to a child): contains the complement of the
  child's subtree — approximately N × (b-1)/b entries for branching
  factor b

The worst-case filter is the downward direction from the root's child,
containing roughly N × (b-1)/b entries. Upward filters remain compact
even in large networks.

For a tree with branching factor b ≈ 5:

| Network size (N) | Worst-case n | FPR | Assessment |
| ----------------- | ------------ | --- | ---------- |
| 500 | 400 | 0.048% | Negligible |
| 1,000 | 800 | 0.86% | Good |
| 2,000 | 1,600 | 9.4% | Acceptable |
| 3,000 | 2,400 | 27% | Poor |
| 5,000 | 4,000 | 63% | Filter nearly useless |

Upward filters remain excellent: a depth-2 node in a 10,000-node tree
has a subtree of ~400 entries (FPR 0.048%).

### Saturation Behavior

At 50% FPR (n ≈ 3,350), the filter provides no better than coin-flip
discrimination and is effectively useless for candidate selection.
Full saturation (FPR > 99%) occurs around n ≈ 10,000.

Tree-only merge propagation mitigates saturation by limiting each filter's
content to tree-relevant entries. A node's outgoing filter to its parent
contains only its subtree; its outgoing filter to a child contains the
complement. Neither filter contains entries from mesh shortcuts' transitive
information. This keeps upward filters compact regardless of network size,
but downward filters grow proportionally with N.

## Per-Peer Filter Model

Each node maintains a separate outbound filter for each peer. The filter
for peer Q answers: "which destinations are reachable through me (but not
through Q itself)?"

### Filter Computation

The outbound filter for peer Q is computed by merging:

1. **This node's own identity** (node_addr)
2. **Leaf-only dependents** (if any — future direction)
3. **Tree peers' inbound filters except Q's** (tree-only merge with
   split-horizon exclusion)

Only filters from **tree peers** (parent and children in the spanning tree)
are merged into outgoing filter computation. Filters from non-tree mesh
peers are stored locally for routing queries but are not propagated
transitively. This prevents bloom filter saturation where mesh shortcuts
cause every node's filter to converge toward the full network.

### Split-Horizon Exclusion

The exclusion of Q's own inbound filter prevents echo loops. Without it,
a node would advertise back to Q the destinations it learned from Q,
creating a routing loop where Q thinks it can reach a destination through
this node, and this node thinks it can reach the same destination through Q.

Split-horizon is computed per-peer: the outbound filter for peer Q merges
all tree peer inbound filters except Q's.

### Directional Asymmetry

Because merge is restricted to tree peers, outgoing filters exhibit
directional asymmetry along tree edges:

- **Upward (child → parent)**: Contains the child's subtree — the child's
  own identity plus all entries merged from its children's filters
- **Downward (parent → child)**: Contains the complement — the parent's
  own identity plus entries from all other tree peers (siblings' subtrees
  and the parent's own parent direction)

Together, the upward and downward filters for a tree edge cover the entire
network with no overlap (excluding the node itself at the split point).

### Mesh Peer Filters

All peers — including non-tree mesh shortcuts — still **receive**
FilterAnnounce messages and **store** received filters locally. These
stored filters are consulted during routing (step 3 of `find_next_hop()`)
for single-hop shortcut discovery. However, mesh peer filters contain
only the mesh peer's own tree-propagated information, not transitive
entries from the broader network.

For a node with tree peers A, B and mesh peer C:

| Outbound to | Includes entries from |
| ----------- | -------------------- |
| A | Self + B's filter (tree-only merge, excluding A) |
| B | Self + A's filter (tree-only merge, excluding B) |
| C | Self + A's filter + B's filter (tree-only merge, C excluded as non-tree) |

## Filter Propagation

Filters propagate via **FilterAnnounce** messages exchanged between direct
peers. Each FilterAnnounce replaces the previous filter for that peer —
there is no incremental update.

### Update Triggers

Filter updates are event-driven, not periodic:

- Peer connects (new filter includes the new peer's reachability)
- Peer disconnects (filter must exclude the departed peer's entries)
- A peer's inbound filter changes (outbound filters to other peers must
  be recomputed)
- Local state changes (new identity, leaf-only dependent changes)

### Rate Limiting

Updates are rate-limited at 500ms minimum interval per peer to prevent
storms during topology changes. Multiple pending changes within the
cooldown period are coalesced into a single announcement.

### Propagation Scope

Filters propagate transitively through tree edges only. Since the spanning
tree is a connected subgraph covering all nodes, every reachable
destination still appears in at least one tree peer's filter at steady
state. New nodes propagate through the tree within O(depth × 500ms) where
depth is the tree depth.

Mesh shortcuts provide single-hop filter visibility (the mesh peer's own
filter) but do not contribute to transitive propagation. This bounds the
information in each filter to tree-relevant entries rather than the full
network.

## Filter Expiration

Bloom filters cannot remove individual entries (this is a fundamental
property of the data structure). Entries are expired through:

- **Peer disconnect**: The entire inbound filter for the departed peer is
  removed, and outbound filters are recomputed
- **Filter replacement**: Each FilterAnnounce completely replaces the
  previous filter for that peer
- **Implicit timeout**: If a peer becomes unresponsive, the MMP link
  liveness detector eventually declares the link dead and removes the
  peer, which triggers filter cleanup as a side effect of peer removal.
  There is no independent filter staleness timer.

## Membership Test

To test whether a node_addr is in a bloom filter:

```text
for i in 0..hash_count:
    bit_index = hash(node_addr, i) % filter_bits
    if not bits[bit_index]:
        return false    // Definitely not present
return true             // Maybe present (possible false positive)
```

Where `filter_bits = 8 × (512 << size_class)` — 8,192 for v1.

## Wire Format

FilterAnnounce messages are carried inside encrypted link-layer frames:

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x20 |
| 1 | sequence | 8 bytes LE | Monotonic counter for freshness |
| 9 | hash_count | 1 byte | Number of hash functions (5 in v1) |
| 10 | size_class | 1 byte | Filter size: `512 << size_class` bytes |
| 11 | filter_bits | 1,024 bytes | Bloom filter bit array (v1) |

**v1 total**: 1,035 bytes payload, 1,064 bytes with link encryption
overhead.

See [fips-wire-formats.md](fips-wire-formats.md) for the complete wire
format reference.

## Scale and Size Classes

### v1 Scale Limits

Coordinate-based tree distance checking ensures correct routing decisions
at all network sizes — bloom filters are an optimization that narrows the
set of peers considered, not a correctness requirement. As filters
saturate, routing still works; it just evaluates more candidates per hop.

With the v1 mandatory 1 KB filter (size_class 1):

- **Small networks (< 1,000 nodes)**: Both upward and downward filters
  are highly accurate (worst-case FPR < 1%). Filters effectively narrow
  candidates to the correct forwarding peer on the first try.

- **Medium networks (1,000–2,000 nodes)**: Upward filters remain
  excellent. Downward filters approach 10% FPR at the worst case
  (near-root nodes). The additional false positives add minor overhead
  to candidate evaluation but do not affect routing correctness.

- **Large networks (> 2,000 nodes)**: Downward filters lose most of
  their discrimination value. At N ≈ 5,000, downward filters for
  near-root nodes have ~63% FPR, providing little benefit over evaluating
  all peers. Upward filters remain compact and accurate at any scale.
  Routing correctness is unaffected — greedy tree distance still selects
  the right next hop — but the efficiency gain from bloom filter
  pre-selection diminishes.

### Size Class Table

| size_class | Bytes | Bits | Status |
| ---------- | ----- | ---- | ------ |
| 0 | 512 | 4,096 | Reserved |
| 1 | 1,024 | 8,192 | **v1 (MUST use)** |
| 2 | 2,048 | 16,384 | Reserved |
| 3 | 4,096 | 32,768 | Reserved |

FMP v1 mandates size_class = 1. Nodes MUST use size_class = 1 and MUST
reject FilterAnnounce messages with any other size_class. The size_class
field is reserved in the wire format to support future protocol versions
with larger default filter sizes.

### Scaling Strategy

The 1 KB filter becomes a practical limitation beyond ~2,000 nodes. The
size class mechanism provides the path forward: future FMP versions may
use larger default filters (size_class 2 or 3) to support larger networks
while remaining compatible with constrained nodes through folding.
Size_class 2 (2 KB, 16,384 bits) would roughly double the practical
network size limit.

The envisioned approach is that hub nodes near the root — which carry the
largest downward filters — would use larger size classes, while leaf nodes
and resource-constrained nodes continue with smaller filters. A node
receiving a filter larger than its own size class folds it down locally.
The mechanism by which heterogeneous filter sizes propagate through the
tree is a future design direction not specified in v1. See
[IDEA-0043](../../ideas/IDEA-0043-heterogeneous-filter-propagation.md).

### Folding

Larger filters can be **folded** to smaller sizes by OR-ing the two halves
together. A 2 KB filter folds to 1 KB by OR-ing the upper and lower
halves. This preserves the "maybe present" property (no false negatives
introduced) but increases the false positive rate.

The hash function design supports folding: membership tests at a smaller
size use `hash(item, i) % smaller_bit_count`, which maps to the same bit
positions that folding produces.

## Implementation Status

| Feature | Status |
| ------- | ------ |
| 1 KB bloom filter (size_class 1) | **Implemented** |
| 5 hash functions | **Implemented** |
| Split-horizon filter computation | **Implemented** |
| Tree-only merge propagation | **Implemented** |
| Directional asymmetry (subtree/complement) | **Implemented** |
| Per-peer filter maintenance | **Implemented** |
| Event-driven updates | **Implemented** |
| 500ms rate limiting | **Implemented** |
| FilterAnnounce gossip (all peers) | **Implemented** |
| Filter cardinality logging | **Implemented** |
| Size class negotiation | Future direction |
| Folding support | Future direction |
| Adaptive filter sizing | Future direction |

## References

- [fips-mesh-operation.md](fips-mesh-operation.md) — How bloom filters fit
  into routing
- [fips-wire-formats.md](fips-wire-formats.md) — FilterAnnounce wire format
- [fips-spanning-tree.md](fips-spanning-tree.md) — The coordinate system
  that bloom filter candidates are ranked by
