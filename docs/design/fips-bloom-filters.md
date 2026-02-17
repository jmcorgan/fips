# FIPS Bloom Filters

This document describes the bloom filter data structures, parameters, and
mathematical properties used by FIPS for reachability-based candidate
selection. It is a supporting reference — for how bloom filters fit into
the overall routing system, see
[fips-mesh-operation.md](fips-mesh-operation.md).

## Purpose

Each node maintains bloom filters summarizing which destinations are
reachable through each of its peers. Bloom filters provide **candidate
selection**: they narrow which peers are worth considering when forwarding
a packet to a given destination. The actual forwarding decision is made by
tree coordinate distance ranking.

Bloom filters answer a single question: "can peer P possibly reach
destination D?" The answer is either "no" (definitive) or "maybe"
(probabilistic — false positives are possible, false negatives are not).

## Filter Parameters

| Parameter | Value | Rationale |
| --------- | ----- | --------- |
| Size | 1 KB (8,192 bits) | Balance between accuracy and bandwidth |
| Hash functions (k) | 5 | Compromise between optimal k=7 for 800 entries and accommodating up to ~1,600 entries |
| Size class | 1 (v1 mandated) | `512 << 1 = 1024` bytes |

### Why k = 5

The optimal number of hash functions depends on the expected occupancy:

- At 800 entries (typical for moderate-degree nodes), optimal k ≈ 7
- At 1,600 entries (hub nodes), optimal k ≈ 4

k = 5 is a practical compromise that provides reasonable false positive
rates across the expected range of occupancy.

## False Positive Rate (FPR) Analysis

The false positive rate for a bloom filter with m bits, k hash functions,
and n entries is approximately:

```text
FPR ≈ (1 - e^(-kn/m))^k
```

With m = 8,192 bits and k = 5:

| Node Degree | Expected Entries | FPR | Impact |
| ----------- | ---------------- | --- | ------ |
| 5 (IoT) | 100–200 | ~0.02% | Negligible |
| 8 (typical) | 250–400 | ~0.3% | Negligible |
| 12 (well-connected) | 500–800 | ~2.4% | Minor — occasional unnecessary discovery |
| 20+ (hub) | 1,200–1,800 | 7.5–15% | Elevated — more false positive candidates |

At moderate network sizes, filters are highly accurate. At larger scales
(~1M nodes), hub nodes with many peers see elevated FPR. False positives
cause unnecessary candidate evaluation (and potentially unnecessary
discovery attempts) but do not affect routing correctness — the tree
distance calculation makes the actual forwarding decision.

### Saturation Behavior

A bloom filter with 8,192 bits and k = 5 saturates (FPR approaches 100%)
around 3,000–4,000 entries. Beyond this, every query returns "maybe" and the
filter provides no candidate selection value. Hub nodes approaching this
threshold effectively fall back to tree-distance-only routing.

## Per-Peer Filter Model

Each node maintains a separate outbound filter for each peer. The filter
for peer Q answers: "which destinations are reachable through me (but not
through Q itself)?"

### Filter Computation

The outbound filter for peer Q is computed by merging:

1. **This node's own identity** (node_addr)
2. **Leaf-only dependents** (if any — future direction)
3. **All other peers' inbound filters except Q's** (split-horizon exclusion)

### Split-Horizon Exclusion

The exclusion of Q's own inbound filter prevents echo loops. Without it,
a node would advertise back to Q the destinations it learned from Q,
creating a routing loop where Q thinks it can reach a destination through
this node, and this node thinks it can reach the same destination through Q.

Split-horizon is computed per-peer: the outbound filter for peer Q merges
all inbound filters except Q's. For a node with peers A, B, C:

| Outbound to | Includes entries from |
| ----------- | -------------------- |
| A | Self + B's filter + C's filter |
| B | Self + A's filter + C's filter |
| C | Self + A's filter + B's filter |

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

Filters propagate unboundedly — there is no TTL on filter propagation. At
steady state, every reachable destination appears in at least one peer's
filter. New nodes added to the network propagate through the entire mesh
within O(D × 500ms) where D is the network diameter.

## Filter Expiration

Bloom filters cannot remove individual entries (this is a fundamental
property of the data structure). Entries are expired through:

- **Peer disconnect**: The entire inbound filter for the departed peer is
  removed, and outbound filters are recomputed
- **Filter replacement**: Each FilterAnnounce completely replaces the
  previous filter for that peer
- **Implicit timeout**: If no FilterAnnounce is received from a peer within
  a threshold period, the peer's filter may be considered stale (tied to
  link liveness detection)

## Size Classes and Folding

### Size Class Table

| size_class | Bytes | Bits | Status |
| ---------- | ----- | ---- | ------ |
| 0 | 512 | 4,096 | Reserved |
| 1 | 1,024 | 8,192 | **v1 (MUST use)** |
| 2 | 2,048 | 16,384 | Reserved |
| 3 | 4,096 | 32,768 | Reserved |

v1 nodes MUST use size_class = 1 and MUST reject FilterAnnounce messages
with any other size_class.

### Folding (Forward Compatibility)

Larger filters can be **folded** to smaller sizes by OR-ing the two halves
together. A 2 KB filter folds to 1 KB by OR-ing the upper and lower
halves. This preserves the "maybe present" property (no false negatives
introduced) but increases the false positive rate.

Folding enables future protocol versions where hub nodes maintain larger
filters (lower FPR) while constrained nodes fold down to the mandated size.
A node receiving a larger filter folds it locally before use if needed.

The hash function design supports folding: membership tests at a smaller
size use `hash(item, i) % smaller_bit_count`, which maps to the same bit
positions that folding produces.

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

## Scale Considerations

### Small Networks (< 1,000 nodes)

Filters are very accurate (FPR < 1% for typical node degrees). Candidate
selection effectively identifies the correct forwarding peer on the first
try for most destinations.

### Medium Networks (1,000–100,000 nodes)

Filters remain accurate for typical nodes. Hub nodes (20+ peers) may see
elevated FPR but the tree distance ranking correctly selects the best
candidate regardless.

### Large Networks (> 100,000 nodes)

Hub nodes approach filter saturation. The filter still provides value
(some peers can be definitively excluded) but the candidate set grows
larger. The tree distance calculation becomes the primary routing
discriminator.

Future mitigation: hub nodes could use larger filters (size_class 2 or 3)
while constrained nodes fold to size_class 1. This requires protocol
negotiation not present in v1.

## Implementation Status

| Feature | Status |
| ------- | ------ |
| 1 KB bloom filter (size_class 1) | **Implemented** |
| 5 hash functions | **Implemented** |
| Split-horizon filter computation | **Implemented** |
| Per-peer filter maintenance | **Implemented** |
| Event-driven updates | **Implemented** |
| 500ms rate limiting | **Implemented** |
| FilterAnnounce gossip | **Implemented** |
| Size class negotiation | Future direction |
| Folding support | Future direction |
| Adaptive filter sizing | Future direction |

## References

- [fips-mesh-operation.md](fips-mesh-operation.md) — How bloom filters fit
  into routing
- [fips-wire-formats.md](fips-wire-formats.md) — FilterAnnounce wire format
- [fips-spanning-tree.md](fips-spanning-tree.md) — The coordinate system
  that bloom filter candidates are ranked by
