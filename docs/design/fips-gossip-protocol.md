# FIPS Gossip Protocol

This document specifies the wire formats and exchange rules for FIPS gossip
messages: TreeAnnounce, FilterAnnounce, and the discovery protocol
(LookupRequest/LookupResponse).

For conceptual background on how these protocols work:

- Spanning tree dynamics: [spanning-tree-dynamics.md](spanning-tree-dynamics.md)
- Routing design and bloom filter concepts: [fips-routing.md](fips-routing.md)

---

## 1. Message Type Summary

All gossip messages are link-layer messages, encrypted with per-peer Noise IK
session keys. They travel one hop (peer-to-peer), though their effects may
propagate further through subsequent gossip.

| Type | Purpose | Direction | Trigger |
|------|---------|-----------|---------|
| TreeAnnounce | Spanning tree state | Bidirectional | Peer connect, parent change, periodic |
| FilterAnnounce | Bloom filter reachability | Bidirectional | Peer connect, filter change |
| LookupRequest | Coordinate discovery | Flooded | Route cache miss |
| LookupResponse | Return coordinates | Routed back | LookupRequest reaches target |

---

## 2. TreeAnnounce

TreeAnnounce messages propagate spanning tree state between peers. Each node
announces its parent selection and ancestry, enabling peers to compute tree
coordinates and distances.

### 2.1 Wire Format

```text
TreeAnnounce (v1) {
    version: u8,                // Protocol version (0x01 for v1)
    sequence: u64,              // Monotonic, increments on parent change
    timestamp: u64,             // Unix timestamp (seconds)
    parent: NodeAddr,           // 16 bytes, truncated SHA-256(pubkey) of selected parent
    ancestry_count: u16,        // Number of ancestry entries
    ancestry: [AncestryEntry],  // Path from self to root
    signature: Signature,       // 64 bytes, outer signature over entire message
}

AncestryEntry (v1) {
    node_addr: NodeAddr,        // 16 bytes
    sequence: u64,              // That node's sequence number
    timestamp: u64,             // That node's timestamp
}
```

Note: v1 ancestry entries are 32 bytes each (no per-entry signature). See §2.7 Trust Model.

### 2.2 Field Semantics

**version**: Protocol version number. v1 = 0x01. Receivers MUST reject messages
with unrecognized version numbers to ensure forward compatibility.

**sequence**: Incremented each time the node changes its parent declaration.
Higher sequence numbers supersede lower ones for conflict resolution.

**timestamp**: Used for distributed consistency. A declaration is considered
stale if `now - timestamp > ROOT_TIMEOUT` (default 60 minutes for root).

**parent**: The node_addr of the selected parent. If `parent == self.node_addr`,
the node is declaring itself as root.

**ancestry**: The chain from this node up to the root. The first entry is this
node's own declaration, followed by parent, grandparent, etc. In v1, entries
carry only routing metadata (node_addr, sequence, timestamp) without per-entry
signatures. See §2.7 for the trust model.

### 2.3 Size Estimate

| Component | Size |
|-----------|------|
| version | 1 byte |
| sequence | 8 bytes |
| timestamp | 8 bytes |
| parent | 16 bytes |
| ancestry_count | 2 bytes |
| signature | 64 bytes |
| Per ancestry entry (v1) | 16 + 8 + 8 = 32 bytes |

For tree depth D (ancestry_count = D + 1): `100 + (D + 1) × 32` bytes payload.

| Tree Depth | Payload Size | With Link Overhead |
|------------|--------------|--------------------|
| 0 (root)   | 132 bytes    | 161 bytes          |
| 3          | 228 bytes    | 257 bytes          |
| 5          | 292 bytes    | 321 bytes          |
| 10         | 452 bytes    | 481 bytes          |

Note: v1 ancestry entries omit per-entry signatures (32 bytes vs 96 bytes in
the original design). See §2.7 for the rationale.

### 2.4 Exchange Rules

**On peer connection:**

1. After Noise IK handshake completes, both peers send TreeAnnounce
2. Each peer processes the received announcement (see §2.5)
3. If processing triggers a parent change, send updated TreeAnnounce to all peers

**On parent change:**

1. Increment sequence number
2. Update timestamp
3. Sign new declaration
4. Send TreeAnnounce to all peers

**Periodic refresh:**

1. Root refreshes every 30 minutes (prevents stale root detection)
2. Non-root nodes forward root refresh when received
3. Nodes may refresh their own declaration periodically (implementation choice)

### 2.5 Processing Rules

When receiving TreeAnnounce from peer P:

```text
1. Decode message; reject if version != 0x01
2. Verify P's declaration signature using P's known public key (from Noise IK)
3. Verify that declaration node_addr matches sender's identity
4. Check sequence freshness:
   - If sequence <= stored sequence for P: discard (stale)
5. Update peer P's tree state (declaration + ancestry)
6. Re-evaluate parent selection:
   - Find smallest root visible across all peers
   - Among peers reaching smallest root, prefer shallowest depth
   - Apply stability threshold to prevent flapping (depth improvement ≥ 1)
   - If parent changed: increment own sequence, sign, recompute coords, announce to all
```

Note: In v1, only the sender's declaration signature is verified (step 2).
Ancestry entries beyond the direct peer are accepted on trust. See §2.7.

### 2.6 Rate Limiting

To prevent announcement storms during reconvergence:

- Minimum interval between announcements to same peer: 500ms
- If change occurs during cooldown: mark pending, send after cooldown
- Coalesce multiple pending changes into single announcement

### 2.7 Trust Model (v1)

**v1 uses transitive trust**: each node verifies only its direct peer's
declaration signature. The peer's public key is known from the Noise IK
handshake, so verification is straightforward. Ancestry entries from nodes
beyond the direct peer are accepted on trust from the authenticated sender.

**Why transitive trust?** NodeAddr values are truncated SHA-256 hashes of
public keys — this mapping is intentionally one-way. To verify an ancestry
entry's signature, a node would need the entry's public key, but FIPS does not
distribute node_addr→pubkey mappings by design. Exposing these mappings would
enable traffic analysis, undermining a core privacy property.

**Limitation**: An adversarial interior node could fabricate ancestry chains,
potentially attracting traffic to itself (sinkhole attack) or manipulating tree
topology. This risk is mitigated by:

- **Authenticated peers have reputation cost**: Misbehaving nodes can be
  disconnected and blocked by their direct peers.
- **Multi-path observation**: Nodes receiving conflicting tree state from
  multiple peers can detect inconsistencies (future enhancement).

**Versioning**: The wire format includes a version byte (v1 = 0x01) to enable
future protocol evolution. A future version could introduce stronger ancestry
verification (e.g., zero-knowledge proofs of key ownership) without breaking
backward compatibility. Nodes MUST reject TreeAnnounce messages with
unrecognized version numbers.

---

## 3. FilterAnnounce

FilterAnnounce messages propagate Bloom filter reachability information. Each
node's filter indicates which destinations are reachable through it.

### 3.1 Wire Format

```text
FilterAnnounce {
    sequence: u64,              // For freshness/deduplication
    filter: BloomFilter,        // Variable size based on size_class
}

BloomFilter {
    hash_count: u8,             // Number of hash functions (5 for v1)
    size_class: u8,             // Filter size: bytes = 512 << size_class
    bits: [u8; 512 << size_class],  // Bit array (1024 bytes for v1)
}
```

### 3.2 Size Classes

Filter sizes are powers of 2 to enable folding (shrinking by ORing halves):

| size_class | Bits   | Bytes | Status              |
|------------|--------|-------|---------------------|
| 0          | 4,096  | 512   | Reserved (future)   |
| 1          | 8,192  | 1,024 | **v1 default**      |
| 2          | 16,384 | 2,048 | Reserved (future)   |
| 3          | 32,768 | 4,096 | Reserved (future)   |

**v1 protocol**: All nodes MUST use size_class=1 (1 KB filters). Nodes MUST
reject FilterAnnounce with size_class ≠ 1.

**Future versions**: Nodes may negotiate larger filters via capability exchange.
Receivers can fold larger filters down to their preferred size.

### 3.3 Field Semantics

**sequence**: Monotonic counter for this node's filter. Allows receivers to
detect stale or duplicate announcements.

**hash_count**: Number of hash functions used. v1 uses k=5, which is optimal
for 800-1,600 entries in a 1 KB filter.

**size_class**: Indicates filter size as `512 << size_class` bytes. Allows
forward-compatible extension to larger filters.

**bits**: The Bloom filter bit array. To test membership:

```text
for i in 0..hash_count:
    bit_index = hash(node_addr, i) % (8 * bits.len())
    if !bits[bit_index]: return false
return true  // "maybe present"
```

### 3.3 Filter Contents

A node's outgoing filter to peer Q contains:

1. This node's own node_addr
2. Node_ids of leaf-only dependents (nodes using this node as sole peer)
3. Entries merged from filters received from all other peers (not Q)

This split-horizon merge (excluding the destination peer's own filter from
the computation) prevents a node's entries from being echoed back to it,
providing loop prevention. Filters propagate transitively through the
network without any hop limit.

### 3.4 Exchange Rules

**On peer connection:**

1. After TreeAnnounce exchange, send FilterAnnounce
2. Filter contains current reachability view

**On filter change:**

Triggering events:

- Peer connects or disconnects
- Received filter changes outgoing filter
- Local state change (new leaf dependent, become gateway)

Rate limiting:

- Minimum interval between filter announcements: 500ms
- Debounce rapid changes into single announcement

**Processing received filter:**

```text
1. Store: peer_filters[P] = received.filter
2. Recompute outgoing filters for all other peers:
   - For each peer Q (Q != P):
     outgoing[Q] = merge(self_filter, peer_filters[all peers except Q])
   - If outgoing[Q] changed, send FilterAnnounce to Q
```

### 3.5 Filter Expiration

Bloom filters cannot remove individual entries. Expiration handled by:

- **Peer disconnect**: Remove that peer's filter entirely, recompute
- **Filter replacement**: Each FilterAnnounce replaces the previous one
- **Implicit timeout**: If no updates from peer within threshold, consider stale

---

## 4. LookupRequest

LookupRequest initiates coordinate discovery for destinations not covered by
local Bloom filters.

### 4.1 Wire Format

```text
LookupRequest {
    request_id: u64,            // Unique identifier for this request
    target: NodeAddr,             // 16 bytes, who we're looking for
    origin: NodeAddr,             // 16 bytes, who's asking
    origin_coords: Vec<NodeAddr>, // Origin's ancestry (for return path)
    ttl: u8,                    // Remaining propagation hops
    visited: CompactBloomFilter,// ~256 bytes, prevents loops
}

CompactBloomFilter {
    bits: [u8; 256],            // Smaller filter for visited set
    hash_count: u8,
}
```

### 4.2 Field Semantics

**request_id**: Randomly generated, used to match responses and detect
duplicates.

**target**: The node_addr being searched for.

**origin**: The node_addr of the original requester. Used for response routing.

**origin_coords**: The requester's current tree coordinates. Used by the target
for the first hop of response routing (via `find_next_hop`).

**ttl**: Propagation limit. Prevents unbounded flooding.

**visited**: Compact Bloom filter tracking nodes that have seen this request.
Prevents loops (revisiting a node on the same path). Note: does NOT prevent
convergent duplicates arriving via different paths — `request_id` dedup
(section 4.4) is required for that.

### 4.3 Propagation Rules

When receiving LookupRequest:

```text
1. Check request_id against recent-request cache - if present, drop (duplicate
   via convergent path). This is REQUIRED, not optional — the visited filter
   alone does not prevent duplicates arriving via different paths.
2. Add request_id to recent-request cache
3. Check visited filter - if self likely present, drop (already processed)
4. Add self to visited filter
5. Decrement TTL

6. Check if target is local:
   - If target == self.node_addr: generate LookupResponse
   - If target in local peer_filters: may respond on behalf (optional)

7. If TTL > 0 and not found locally:
   - Forward to peers not in visited filter
   - Optionally prioritize peers whose filter indicates target "maybe" present
```

The recent-request cache need only retain entries for a few seconds (long
enough for the flood to complete across the TTL scope) and is bounded by the
rate limit on incoming requests.

### 4.4 Rate Limiting

- Limit requests per origin per time window
- Limit total outstanding requests

---

## 5. LookupResponse

LookupResponse returns the target's coordinates to the requester.

### 5.1 Wire Format

```text
LookupResponse {
    request_id: u64,            // Echoes LookupRequest.request_id
    target: NodeAddr,             // 16 bytes, confirms who was found
    target_coords: Vec<NodeAddr>, // Target's ancestry (the key payload)
    proof: Signature,           // 64 bytes, target signs to prove existence
}
```

### 5.2 Field Semantics

**request_id**: Matches the original request, allowing requester to correlate.

**target**: Confirms the identity found.

**target_coords**: The target's current tree coordinates. This is the primary
payload — cached by the originator to enable routing to the target.

**proof**: Target's signature over `(request_id || target || target_coords)`.
Prevents malicious nodes from claiming reachability and blackholing traffic.

### 5.3 Routing

LookupResponse uses a two-phase routing mechanism:

```text
1. Response created at target (or node with target in filter)
2. First hop: target routes toward origin via find_next_hop
   (standard bloom filter → tree routing path)
3. Subsequent hops: reverse-path forwarding via recent_requests
   (each transit node recorded which peer sent the request)
4. Origin receives response, caches target_coords in RouteCache
```

The first hop from the target uses `find_next_hop(origin)` because
the target was not a transit node for the request (it was the
destination). All transit nodes that forwarded the request stored a
`(request_id → from_peer)` entry in `recent_requests`, enabling
reverse-path forwarding for the response.

### 5.4 Security

The proof signature is critical:

- Without it, any node could claim to be (or know) any target
- Requester verifies signature against target's known public key
- Invalid signatures cause response to be dropped

---

## 6. Message Type Codes

Within the link-layer message framing:

| Type Code | Message |
|-----------|---------|
| 0x10 | TreeAnnounce |
| 0x20 | FilterAnnounce |
| 0x30 | LookupRequest |
| 0x31 | LookupResponse |

These are carried inside the encrypted link-layer payload after Noise IK
handshake completion. See [fips-wire-protocol.md](fips-wire-protocol.md) §2.6
for the full link message type table.

---

## 7. Timing Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| ROOT_REFRESH_INTERVAL | 30 min | Root regenerates timestamp |
| ROOT_TIMEOUT | 60 min | Root declaration considered stale |
| TREE_ENTRY_TTL | 5-10 min | Individual entry expiration |
| ANNOUNCE_MIN_INTERVAL | 500 ms | Rate limit for announcements |
| LOOKUP_TTL | 64 | Discovery request propagation limit |
| LOOKUP_TIMEOUT | 10 sec | Time to wait for response |

---

## 8. Encoding

All multi-byte integers are little-endian. NodeAddr is 16 bytes (truncated SHA-256 hash).
Signatures are 64 bytes (secp256k1 Schnorr).

Variable-length fields (ancestry, coordinates) are prefixed with a 2-byte
length count indicating number of entries.

```text
Vec<T> encoding:
  count: u16 (little-endian)
  items: T[count]
```

---

## Appendix A: Detailed Packet Layouts

All gossip messages are link-layer messages carried inside encrypted frames
(discriminator 0x00). The layouts below show the plaintext structure after
link-layer decryption.

### A.1 TreeAnnounce (0x10)

Propagates spanning tree state between directly connected peers.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FULL PACKET (Link Layer + TreeAnnounce)                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    LINK LAYER FRAME (encrypted)                       │  │
│  ├───────────┬──────────────┬────────────┬───────────────────────────────┤  │
│  │ 0x00      │ receiver_idx │ counter    │ ciphertext + tag              │  │
│  │ 1 byte    │ 4 bytes LE   │ 8 bytes LE │ N + 16 bytes                  │  │
│  └───────────┴──────────────┴────────────┴───────────────────────────────┘  │
│                                            │                                │
│                    ┌───────────────────────┘                                │
│                    │ Decrypt                                                │
│                    ▼                                                        │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    TREE ANNOUNCE v1 (plaintext)                      │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ msg_type         │ 1 byte    │ 0x10                          │  │
│  │   1    │ version          │ 1 byte    │ 0x01 (v1)                     │  │
│  │   2    │ sequence         │ 8 bytes   │ u64 LE, monotonic counter     │  │
│  │  10    │ timestamp        │ 8 bytes   │ u64 LE, Unix seconds          │  │
│  │  18    │ parent           │ 16 bytes  │ NodeAddr of selected parent   │  │
│  │  34    │ ancestry_count   │ 2 bytes   │ u16 LE, number of entries     │  │
│  │  36    │ ancestry[0..n]   │ 32 × n    │ AncestryEntry array           │  │
│  │  ...   │ signature        │ 64 bytes  │ Schnorr sig over all above    │  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    ANCESTRY ENTRY v1 (32 bytes each)                 │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ node_addr        │ 16 bytes  │ Truncated SHA-256(pubkey)     │  │
│  │  16    │ sequence         │ 8 bytes   │ u64 LE, node's seq number     │  │
│  │  24    │ timestamp        │ 8 bytes   │ u64 LE, node's timestamp      │  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
│  Note: v1 entries omit per-entry signatures. Only the sender's outer        │
│  signature is verified (transitive trust model, see §2.7).                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Size calculation**: `1 + 1 + 8 + 8 + 16 + 2 + (depth × 32) + 64 = 100 + (depth × 32)` bytes

| Tree Depth | Payload Size | With Link Overhead |
|------------|--------------|--------------------|
| 0 (root)   | 132 bytes    | 161 bytes          |
| 3          | 228 bytes    | 257 bytes          |
| 5          | 292 bytes    | 321 bytes          |
| 10         | 452 bytes    | 481 bytes          |

**Concrete example** (node D at depth 3, ancestry = [D, P1, P2, Root]):

```text
PLAINTEXT BYTES (hex layout):
10                               ← msg_type = TreeAnnounce
01                               ← version = 1
05 00 00 00 00 00 00 00          ← sequence = 5
C3 B2 A1 67 00 00 00 00          ← timestamp (Unix seconds)
[16 bytes P1's node_addr]        ← parent
04 00                            ← ancestry_count = 4

ANCESTRY[0] - Self (D):
  [16 bytes D's node_addr]
  05 00 00 00 00 00 00 00        ← D's sequence
  C3 B2 A1 67 00 00 00 00        ← D's timestamp

ANCESTRY[1] - Parent (P1):
  [16 bytes P1's node_addr]
  0A 00 00 00 00 00 00 00        ← P1's sequence
  00 B0 A1 67 00 00 00 00        ← P1's timestamp

ANCESTRY[2] - Grandparent (P2):
  [16 bytes P2's node_addr]
  03 00 00 00 00 00 00 00        ← P2's sequence
  00 A0 A1 67 00 00 00 00        ← P2's timestamp

ANCESTRY[3] - Root:
  [16 bytes Root's node_addr]
  01 00 00 00 00 00 00 00        ← Root's sequence
  00 90 A1 67 00 00 00 00        ← Root's timestamp

[64 bytes D's outer signature]   ← signs entire message

Total payload: 1 + 1 + 8 + 8 + 16 + 2 + (4 × 32) + 64 = 228 bytes
```

### A.2 FilterAnnounce (0x20)

Propagates Bloom filter reachability information.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FILTER ANNOUNCE (0x20)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         WIRE FORMAT                                   │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ msg_type         │ 1 byte    │ 0x20                          │  │
│  │   1    │ sequence         │ 8 bytes   │ u64 LE, monotonic counter     │  │
│  │   9    │ hash_count       │ 1 byte    │ Number of hash functions (5)  │  │
│  │  10    │ size_class       │ 1 byte    │ Filter size: 512 << class     │  │
│  │  11    │ filter_bits      │ variable  │ 512 << size_class bytes       │  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
│  Size classes (powers of 2 for foldability):                                │
│    0 = 512 bytes (4,096 bits)   - Reserved for future                       │
│    1 = 1,024 bytes (8,192 bits) - v1 default                                │
│    2 = 2,048 bytes (16,384 bits) - Reserved for future                      │
│    3 = 4,096 bytes (32,768 bits) - Reserved for future                      │
│                                                                             │
│  v1 total payload: 1 + 8 + 1 + 1 + 1024 = 1035 bytes                        │
│  With link overhead: 1064 bytes                                             │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                         BLOOM FILTER STRUCTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  filter_bits[1024] (v1, size_class=1):                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ Byte 0    │ Byte 1    │ ... │ Byte 1023                            │    │
│  │ bits 0-7  │ bits 8-15 │     │ bits 8184-8191                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                             │
│  To test membership of node_addr:                                             │
│    filter_bits = 8 * (512 << size_class)  // 8192 for v1                    │
│    for i in 0..hash_count:                                                  │
│      bit_index = hash(node_addr, i) % filter_bits                             │
│      if !bits[bit_index]: return false                                      │
│    return true  // "maybe present"                                          │
│                                                                             │
│  Folding (for future heterogeneous sizes):                                  │
│    To shrink a filter by half, OR its two halves:                           │
│    small[i] = large[i] | large[i + small.len()]                             │
│    This increases FPR but preserves correctness (no false negatives).       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Concrete example** (v1 with size_class=1):

```text
PLAINTEXT BYTES:
20                               ← msg_type = FilterAnnounce
2A 00 00 00 00 00 00 00          ← sequence = 42
05                               ← hash_count = 5
01                               ← size_class = 1 (1 KB filter)
[1024 bytes of filter bits]      ← Bloom filter

Total: 1035 bytes
```

### A.3 LookupRequest (0x30)

Discovers tree coordinates for distant destinations.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LOOKUP REQUEST (0x30)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         WIRE FORMAT                                   │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ msg_type         │ 1 byte    │ 0x30                          │  │
│  │   1    │ request_id       │ 8 bytes   │ u64 LE, unique identifier     │  │
│  │   9    │ target           │ 16 bytes  │ NodeAddr being searched for     │  │
│  │  25    │ origin           │ 16 bytes  │ NodeAddr of requester           │  │
│  │  41    │ ttl              │ 1 byte    │ Remaining propagation hops    │  │
│  │  42    │ origin_coords_cnt│ 2 bytes   │ u16 LE                        │  │
│  │  44    │ origin_coords    │ 16 × n    │ Requester's ancestry          │  │
│  │  ...   │ visited_hash_cnt │ 1 byte    │ Hash functions for visited    │  │
│  │  ...   │ visited_bits     │ 256 bytes │ Compact bloom of visited nodes│  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Size calculation**: `1 + 8 + 16 + 16 + 1 + 2 + (depth × 16) + 1 + 256` bytes

| Origin Depth | Payload Size |
|--------------|--------------|
| 3            | 349 bytes    |
| 5            | 381 bytes    |
| 10           | 461 bytes    |

**Concrete example** (origin at depth 4):

```text
PLAINTEXT BYTES:
30                               ← msg_type = LookupRequest
[8 bytes request_id]             ← random unique ID
[16 bytes target node_addr]        ← who we're looking for
[16 bytes origin node_addr]        ← who's asking
40                               ← ttl = 64
04 00                            ← origin_coords_count = 4
[16 bytes] × 4                   ← origin's ancestry (64 bytes)
07                               ← visited hash_count = 7
[256 bytes visited bloom]        ← nodes that have seen this request

Total: 1 + 8 + 16 + 16 + 1 + 2 + 64 + 1 + 256 = 365 bytes
```

### A.4 LookupResponse (0x31)

Returns target's coordinates to the requester.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LOOKUP RESPONSE (0x31)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         WIRE FORMAT                                   │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ msg_type         │ 1 byte    │ 0x31                          │  │
│  │   1    │ request_id       │ 8 bytes   │ u64 LE, echoes request        │  │
│  │   9    │ target           │ 16 bytes  │ NodeAddr that was found         │  │
│  │  25    │ target_coords_cnt│ 2 bytes   │ u16 LE                        │  │
│  │  27    │ target_coords    │ 16 × n    │ Target's ancestry to root     │  │
│  │  ...   │ proof            │ 64 bytes  │ Target's signature            │  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
│  Proof signature covers: (request_id || target || target_coords)            │
│  Prevents malicious nodes from claiming reachability for any target.        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Size calculation**: `1 + 8 + 16 + 2 + (depth × 16) + 64` bytes

| Target Depth | Payload Size |
|--------------|--------------|
| 3            | 139 bytes    |
| 5            | 171 bytes    |
| 10           | 251 bytes    |

**Concrete example** (target at depth 5):

```text
PLAINTEXT BYTES:
31                               ← msg_type = LookupResponse
[8 bytes request_id]             ← echoed from request
[16 bytes target node_addr]        ← confirms who was found
05 00                            ← target_coords_count = 5
[16 bytes] × 5                   ← target's ancestry (80 bytes)
[64 bytes proof signature]       ← target signs to prove existence

Total: 1 + 8 + 16 + 2 + 80 + 64 = 171 bytes
```

### A.5 Message Flow Example

Complete lookup flow showing packet nesting:

```text
Source S wants to reach distant destination D (not in local filters)

1. S creates LookupRequest, sends to peer P1:

   UDP DATAGRAM
   ┌──────────────────────────────────────────────────────────────┐
   │ LINK FRAME (S→P1 encrypted)                                  │
   │ ┌──────┬────────────┬─────────┬─────────────────────────────┐│
   │ │ 0x00 │ P1_recv_idx│ counter │ ciphertext + tag            ││
   │ └──────┴────────────┴─────────┴─────────────────────────────┘│
   │                                │                             │
   │                    ┌───────────┘                             │
   │                    ▼                                         │
   │              ┌──────┬───────────────────────────────────┐    │
   │              │ 0x30 │ LookupRequest payload             │    │
   │              │      │ (target=D, origin=S, ttl=64, ...) │    │
   │              └──────┴───────────────────────────────────┘    │
   └──────────────────────────────────────────────────────────────┘

2. Request propagates through network, reaches D

3. D creates LookupResponse, routes back via find_next_hop + reverse-path:

   UDP DATAGRAM
   ┌──────────────────────────────────────────────────────────────┐
   │ LINK FRAME (D→Pn encrypted)                                  │
   │ ┌──────┬────────────┬─────────┬─────────────────────────────┐│
   │ │ 0x00 │ Pn_recv_idx│ counter │ ciphertext + tag            ││
   │ └──────┴────────────┴─────────┴─────────────────────────────┘│
   │                                │                             │
   │                    ┌───────────┘                             │
   │                    ▼                                         │
   │              ┌──────┬───────────────────────────────────┐    │
   │              │ 0x31 │ LookupResponse payload            │    │
   │              │      │ (target=D, coords=[D,P1,P2,Root]) │    │
   │              └──────┴───────────────────────────────────┘    │
   └──────────────────────────────────────────────────────────────┘

4. S receives response, caches D's coordinates, can now route directly
```

---

## References

- [spanning-tree-dynamics.md](spanning-tree-dynamics.md) - Tree protocol behavior
- [fips-routing.md](fips-routing.md) - Routing concepts and algorithms
- [fips-wire-protocol.md](fips-wire-protocol.md) - Link-layer framing
- [fips-session-protocol.md](fips-session-protocol.md) - End-to-end sessions
