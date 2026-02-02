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
TreeAnnounce {
    sequence: u64,              // Monotonic, increments on parent change
    timestamp: u64,             // Unix timestamp (seconds)
    parent: NodeId,             // 32 bytes, SHA-256(npub) of selected parent
    ancestry: Vec<AncestryEntry>,  // Path from self to root
    signature: Signature,       // 64 bytes, signs (sequence || timestamp || parent || ancestry)
}

AncestryEntry {
    node_id: NodeId,            // 32 bytes
    sequence: u64,              // That node's sequence number
    timestamp: u64,             // That node's timestamp
    signature: Signature,       // That node's signature over its declaration
}
```

### 2.2 Field Semantics

**sequence**: Incremented each time the node changes its parent declaration.
Higher sequence numbers supersede lower ones for conflict resolution.

**timestamp**: Used for distributed consistency. A declaration is considered
stale if `now - timestamp > ROOT_TIMEOUT` (default 60 minutes for root).

**parent**: The node_id of the selected parent. If `parent == self.node_id`,
the node is declaring itself as root.

**ancestry**: The chain from this node up to the root. The first entry is this
node's own declaration, followed by parent, grandparent, etc. Each entry is
signed by the declaring node, allowing verification of the entire chain.

### 2.3 Size Estimate

| Component | Size |
|-----------|------|
| sequence | 8 bytes |
| timestamp | 8 bytes |
| parent | 32 bytes |
| signature | 64 bytes |
| Per ancestry entry | 32 + 8 + 8 + 64 = 112 bytes |

For tree depth D: `112 + D * 112` bytes. At depth 10: ~1.2 KB.

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
1. Verify signature on sender's declaration
2. Verify signatures on all ancestry entries
3. For each entry in ancestry:
   - If entry.sequence > stored.sequence: update stored entry
   - If entry.sequence == stored.sequence && entry.timestamp > stored.timestamp: update
   - Otherwise: keep existing entry
4. Update peer P's record with new ancestry
5. Re-evaluate parent selection:
   - If better path to root available: change parent, announce to all peers
   - Apply stability threshold to prevent flapping
```

### 2.6 Rate Limiting

To prevent announcement storms during reconvergence:

- Minimum interval between announcements to same peer: 500ms
- If change occurs during cooldown: mark pending, send after cooldown
- Coalesce multiple pending changes into single announcement

---

## 3. FilterAnnounce

FilterAnnounce messages propagate Bloom filter reachability information. Each
node's filter indicates which destinations are reachable through it.

### 3.1 Wire Format

```text
FilterAnnounce {
    sequence: u64,              // For freshness/deduplication
    ttl: u8,                    // Remaining propagation hops
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

**ttl**: Remaining propagation depth. Starts at K (typically 2), decremented
each hop. At TTL=0, entries are not propagated further.

**hash_count**: Number of hash functions used. v1 uses k=5, which is optimal
for 800-1,600 entries in a 1 KB filter.

**size_class**: Indicates filter size as `512 << size_class` bytes. Allows
forward-compatible extension to larger filters.

**bits**: The Bloom filter bit array. To test membership:

```text
for i in 0..hash_count:
    bit_index = hash(node_id, i) % (8 * bits.len())
    if !bits[bit_index]: return false
return true  // "maybe present"
```

### 3.3 Filter Contents

A node's outgoing filter to peer Q contains:

1. This node's own node_id
2. Node_ids of leaf-only dependents (nodes using this node as sole peer)
3. Entries from filters received from other peers (not Q) with TTL > 0

This creates K-hop reachability scope. With K=2, entries propagate ~4 hops
before TTL exhaustion.

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
2. If received.ttl > 0:
   - Include entries in next announcement to other peers
   - Decrement TTL for propagated entries
3. Recompute own outgoing filters if changed
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
    target: NodeId,             // 32 bytes, who we're looking for
    origin: NodeId,             // 32 bytes, who's asking
    origin_coords: Vec<NodeId>, // Origin's ancestry (for return path)
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

**target**: The node_id being searched for.

**origin**: The node_id of the original requester. Used for response routing.

**origin_coords**: The requester's current tree coordinates. Enables greedy
routing of the response back to origin.

**ttl**: Propagation limit. Prevents unbounded flooding.

**visited**: Compact Bloom filter tracking nodes that have seen this request.
Prevents redundant processing and loops.

### 4.3 Propagation Rules

When receiving LookupRequest:

```text
1. Check visited filter - if self likely present, drop (already processed)
2. Add self to visited filter
3. Decrement TTL

4. Check if target is local:
   - If target == self.node_id: generate LookupResponse
   - If target in local peer_filters: may respond on behalf (optional)

5. If TTL > 0 and not found locally:
   - Forward to peers not in visited filter
   - Optionally prioritize peers whose filter indicates target "maybe" present
```

### 4.4 Rate Limiting

- Track recently seen request_ids, drop duplicates
- Limit requests per origin per time window
- Limit total outstanding requests

---

## 5. LookupResponse

LookupResponse returns the target's coordinates to the requester.

### 5.1 Wire Format

```text
LookupResponse {
    request_id: u64,            // Echoes LookupRequest.request_id
    target: NodeId,             // 32 bytes, confirms who was found
    target_coords: Vec<NodeId>, // Target's ancestry (the key payload)
    proof: Signature,           // 64 bytes, target signs to prove existence
}
```

### 5.2 Field Semantics

**request_id**: Matches the original request, allowing requester to correlate.

**target**: Confirms the identity found.

**target_coords**: The target's current tree coordinates. This is the primary
payload - enables greedy routing to the target.

**proof**: Target's signature over `(request_id || target || target_coords)`.
Prevents malicious nodes from claiming reachability and blackholing traffic.

### 5.3 Routing

LookupResponse uses greedy tree routing based on `origin_coords` from the
request:

```text
1. Response created at target (or node with target in filter)
2. Each hop forwards toward origin using tree distance
3. Origin receives response, caches target_coords
```

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
| 0x11 | FilterAnnounce |
| 0x12 | LookupRequest |
| 0x13 | LookupResponse |

These are carried inside the encrypted link-layer payload after Noise IK
handshake completion.

---

## 7. Timing Parameters

| Parameter | Default | Notes |
|-----------|---------|-------|
| ROOT_REFRESH_INTERVAL | 30 min | Root regenerates timestamp |
| ROOT_TIMEOUT | 60 min | Root declaration considered stale |
| TREE_ENTRY_TTL | 5-10 min | Individual entry expiration |
| FILTER_TTL_HOPS | 2 | Bloom filter propagation depth |
| ANNOUNCE_MIN_INTERVAL | 500 ms | Rate limit for announcements |
| LOOKUP_TTL | 8 | Discovery request propagation limit |
| LOOKUP_TIMEOUT | 5 sec | Time to wait for response |

---

## 8. Encoding

All multi-byte integers are little-endian. NodeId is 32 bytes (SHA-256 hash).
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
│  │                    TREE ANNOUNCE (plaintext)                          │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ msg_type         │ 1 byte    │ 0x10                          │  │
│  │   1    │ sequence         │ 8 bytes   │ u64 LE, monotonic counter     │  │
│  │   9    │ timestamp        │ 8 bytes   │ u64 LE, Unix seconds          │  │
│  │  17    │ parent           │ 32 bytes  │ NodeId of selected parent     │  │
│  │  49    │ ancestry_count   │ 2 bytes   │ u16 LE, number of entries     │  │
│  │  51    │ ancestry[0..n]   │ 112 × n   │ AncestryEntry array           │  │
│  │  ...   │ signature        │ 64 bytes  │ Schnorr sig over all above    │  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                    ANCESTRY ENTRY (112 bytes each)                    │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ node_id          │ 32 bytes  │ SHA-256(npub) of this node    │  │
│  │  32    │ sequence         │ 8 bytes   │ u64 LE, node's seq number     │  │
│  │  40    │ timestamp        │ 8 bytes   │ u64 LE, node's timestamp      │  │
│  │  48    │ signature        │ 64 bytes  │ Node's sig over its decl      │  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Size calculation**: `1 + 8 + 8 + 32 + 2 + (depth × 112) + 64` bytes

| Tree Depth | Payload Size | With Link Overhead |
|------------|--------------|-------------------|
| 1 (root)   | 227 bytes    | 256 bytes         |
| 3          | 451 bytes    | 480 bytes         |
| 5          | 675 bytes    | 704 bytes         |
| 10         | 1235 bytes   | 1264 bytes        |

**Concrete example** (node D at depth 3, ancestry = [D, P1, P2, Root]):

```text
PLAINTEXT BYTES (hex layout):
10                               ← msg_type = TreeAnnounce
05 00 00 00 00 00 00 00          ← sequence = 5
C3 B2 A1 67 00 00 00 00          ← timestamp (Unix seconds)
[32 bytes P1's node_id]          ← parent
04 00                            ← ancestry_count = 4

ANCESTRY[0] - Self (D):
  [32 bytes D's node_id]
  05 00 00 00 00 00 00 00        ← D's sequence
  C3 B2 A1 67 00 00 00 00        ← D's timestamp
  [64 bytes D's signature]

ANCESTRY[1] - Parent (P1):
  [32 bytes P1's node_id]
  0A 00 00 00 00 00 00 00        ← P1's sequence
  00 B0 A1 67 00 00 00 00        ← P1's timestamp
  [64 bytes P1's signature]

ANCESTRY[2] - Grandparent (P2):
  [32 bytes P2's node_id]
  03 00 00 00 00 00 00 00        ← P2's sequence
  00 A0 A1 67 00 00 00 00        ← P2's timestamp
  [64 bytes P2's signature]

ANCESTRY[3] - Root:
  [32 bytes Root's node_id]
  01 00 00 00 00 00 00 00        ← Root's sequence
  00 90 A1 67 00 00 00 00        ← Root's timestamp
  [64 bytes Root's signature]

[64 bytes D's outer signature]   ← signs entire message

Total payload: 1 + 8 + 8 + 32 + 2 + (4 × 112) + 64 = 563 bytes
```

### A.2 FilterAnnounce (0x11)

Propagates Bloom filter reachability information.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FILTER ANNOUNCE (0x11)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         WIRE FORMAT                                   │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ msg_type         │ 1 byte    │ 0x11                          │  │
│  │   1    │ sequence         │ 8 bytes   │ u64 LE, monotonic counter     │  │
│  │   9    │ ttl              │ 1 byte    │ Remaining propagation hops    │  │
│  │  10    │ hash_count       │ 1 byte    │ Number of hash functions (5)  │  │
│  │  11    │ size_class       │ 1 byte    │ Filter size: 512 << class     │  │
│  │  12    │ filter_bits      │ variable  │ 512 << size_class bytes       │  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
│  Size classes (powers of 2 for foldability):                                │
│    0 = 512 bytes (4,096 bits)   - Reserved for future                       │
│    1 = 1,024 bytes (8,192 bits) - v1 default                                │
│    2 = 2,048 bytes (16,384 bits) - Reserved for future                      │
│    3 = 4,096 bytes (32,768 bits) - Reserved for future                      │
│                                                                             │
│  v1 total payload: 1 + 8 + 1 + 1 + 1 + 1024 = 1036 bytes                    │
│  With link overhead: 1065 bytes                                             │
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
│  To test membership of node_id:                                             │
│    filter_bits = 8 * (512 << size_class)  // 8192 for v1                    │
│    for i in 0..hash_count:                                                  │
│      bit_index = hash(node_id, i) % filter_bits                             │
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
11                               ← msg_type = FilterAnnounce
2A 00 00 00 00 00 00 00          ← sequence = 42
02                               ← ttl = 2 (will propagate 2 more hops)
05                               ← hash_count = 5
01                               ← size_class = 1 (1 KB filter)
[1024 bytes of filter bits]      ← Bloom filter

Total: 1036 bytes
```

### A.3 LookupRequest (0x12)

Discovers tree coordinates for distant destinations.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LOOKUP REQUEST (0x12)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         WIRE FORMAT                                   │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ msg_type         │ 1 byte    │ 0x12                          │  │
│  │   1    │ request_id       │ 8 bytes   │ u64 LE, unique identifier     │  │
│  │   9    │ target           │ 32 bytes  │ NodeId being searched for     │  │
│  │  41    │ origin           │ 32 bytes  │ NodeId of requester           │  │
│  │  73    │ ttl              │ 1 byte    │ Remaining propagation hops    │  │
│  │  74    │ origin_coords_cnt│ 2 bytes   │ u16 LE                        │  │
│  │  76    │ origin_coords    │ 32 × n    │ Requester's ancestry          │  │
│  │  ...   │ visited_hash_cnt │ 1 byte    │ Hash functions for visited    │  │
│  │  ...   │ visited_bits     │ 256 bytes │ Compact bloom of visited nodes│  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Size calculation**: `1 + 8 + 32 + 32 + 1 + 2 + (depth × 32) + 1 + 256` bytes

| Origin Depth | Payload Size |
|--------------|--------------|
| 3            | 429 bytes    |
| 5            | 493 bytes    |
| 10           | 653 bytes    |

**Concrete example** (origin at depth 4):

```text
PLAINTEXT BYTES:
12                               ← msg_type = LookupRequest
[8 bytes request_id]             ← random unique ID
[32 bytes target node_id]        ← who we're looking for
[32 bytes origin node_id]        ← who's asking
08                               ← ttl = 8
04 00                            ← origin_coords_count = 4
[32 bytes] × 4                   ← origin's ancestry (128 bytes)
07                               ← visited hash_count = 7
[256 bytes visited bloom]        ← nodes that have seen this request

Total: 1 + 8 + 32 + 32 + 1 + 2 + 128 + 1 + 256 = 461 bytes
```

### A.4 LookupResponse (0x13)

Returns target's coordinates to the requester.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         LOOKUP RESPONSE (0x13)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         WIRE FORMAT                                   │  │
│  ├────────┬──────────────────┬───────────┬───────────────────────────────┤  │
│  │ Offset │ Field            │ Size      │ Description                   │  │
│  ├────────┼──────────────────┼───────────┼───────────────────────────────┤  │
│  │   0    │ msg_type         │ 1 byte    │ 0x13                          │  │
│  │   1    │ request_id       │ 8 bytes   │ u64 LE, echoes request        │  │
│  │   9    │ target           │ 32 bytes  │ NodeId that was found         │  │
│  │  41    │ target_coords_cnt│ 2 bytes   │ u16 LE                        │  │
│  │  43    │ target_coords    │ 32 × n    │ Target's ancestry to root     │  │
│  │  ...   │ proof            │ 64 bytes  │ Target's signature            │  │
│  └────────┴──────────────────┴───────────┴───────────────────────────────┘  │
│                                                                             │
│  Proof signature covers: (request_id || target || target_coords)            │
│  Prevents malicious nodes from claiming reachability for any target.        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Size calculation**: `1 + 8 + 32 + 2 + (depth × 32) + 64` bytes

| Target Depth | Payload Size |
|--------------|--------------|
| 3            | 203 bytes    |
| 5            | 267 bytes    |
| 10           | 427 bytes    |

**Concrete example** (target at depth 5):

```text
PLAINTEXT BYTES:
13                               ← msg_type = LookupResponse
[8 bytes request_id]             ← echoed from request
[32 bytes target node_id]        ← confirms who was found
05 00                            ← target_coords_count = 5
[32 bytes] × 5                   ← target's ancestry (160 bytes)
[64 bytes proof signature]       ← target signs to prove existence

Total: 1 + 8 + 32 + 2 + 160 + 64 = 267 bytes
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
   │              │ 0x12 │ LookupRequest payload             │    │
   │              │      │ (target=D, origin=S, ttl=8, ...)  │    │
   │              └──────┴───────────────────────────────────┘    │
   └──────────────────────────────────────────────────────────────┘

2. Request propagates through network, reaches D

3. D creates LookupResponse, routes back via greedy routing:

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
   │              │ 0x13 │ LookupResponse payload            │    │
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
