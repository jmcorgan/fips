# FIPS Routing Design

**Status**: Work in Progress

This document describes the routing architecture for FIPS, including Bloom
filter reachability, discovery protocol, greedy tree routing, and session
establishment.

## Overview

FIPS routing combines three mechanisms:

1. **Bloom filters**: Fast reachability lookup for nearby destinations (within
   K-hop scope)
2. **Discovery protocol**: Query-based lookup for distant destinations
3. **Greedy tree routing**: Coordinate-based forwarding using spanning tree
   position

The design separates discovery (finding where a destination is) from routing
(getting packets there). Bloom filters and discovery handle the former; tree
coordinates handle the latter.

## Design Goals

- Minimize per-packet overhead for data transfer
- Bounded state at each node (independent of network size)
- Efficient routing without global knowledge
- Graceful degradation for constrained devices
- Fast convergence on topology changes

## Network Scale Assumptions

| Scale | Nodes | Bloom Filter Role |
|-------|-------|-------------------|
| Small private network | 100-1,000 | Covers entire network |
| Modest public network | ~1,000,000 | Covers K-hop neighborhood |
| Internet-scale | Billions | Out of scope (requires different architecture) |

The primary design target is networks up to ~1M nodes.

## Node Participation Modes

### Full Participant

- Maintains Bloom filters for peer reachability
- Participates in spanning tree (can be selected as parent)
- Routes packets for other nodes
- Minimum viable device: ESP32-class (~500KB RAM)

### Leaf-Only

- Single peer handles all routing on its behalf
- No Bloom filter storage or processing
- Does not participate in spanning tree as potential parent
- Suitable for highly constrained devices (sensors, battery-powered nodes)

Leaf-only nodes appear as a single entry in their peer's Bloom filter. All
traffic tunnels through that peer.

---

## Part 1: Bloom Filter Design

### Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Filter size | 4 KB (32,768 bits) | Balances accuracy vs. memory |
| Hash functions | 7 | Near-optimal for expected fill ratio |
| Scope (K) | 2 | Effective ~4-hop reach with TTL propagation |

### False Positive Rates

| Nodes in Filter | FPR |
|-----------------|-----|
| 1,000 | ~0.05% |
| 2,000 | ~0.5% |
| 5,000 | ~1.3% |
| 10,000 | ~8% |

With K=2 and average degree d=8, expected nodes in scope ≈ d^(2K) ≈ 4,096.

### Filter Contents

Each node's filter contains Node IDs (and optionally gateway /64 prefixes)
that are reachable through that node. A Node ID is the SHA-256 hash of the
node's npub, truncated or used directly as the filter key.

### Per-Peer Filters

Each node maintains a Bloom filter for each peer direction:

```rust
peer_filters: HashMap<PeerId, BloomFilter>
```

The filter for peer P answers: "Which destinations are reachable through P?"

### Update Mechanism: Event-Driven

Filters are updated on events rather than periodic refresh:

**Triggering events:**

1. Peer connects — exchange current filters
2. Peer disconnects — remove their filter, recompute, notify other peers
3. Received filter changes outgoing filter — recompute, send updates
4. Local state change — new leaf dependent, become gateway, etc.

**Rate limiting:**

To prevent update storms, rate-limit or debounce updates:

```rust
const MIN_UPDATE_INTERVAL: Duration = Duration::from_millis(500);

fn maybe_send_update(&mut self, peer: PeerId) {
    if self.last_send_time[peer].elapsed() < MIN_UPDATE_INTERVAL {
        self.pending_update[peer] = true;
        return;
    }
    // ... send update
}
```

### Filter Announcement Message

```rust
struct FilterAnnounce {
    filter: BloomFilter,  // 4 KB
    ttl: u8,              // Remaining propagation hops
    sequence: u64,        // Freshness / deduplication
}
```

### Propagation Rules

When node N sends a FilterAnnounce to peer Q:

1. Include N's own Node ID
2. Include N's leaf-only dependents
3. Include entries from filters received from other peers (not Q) with TTL > 0

When node N receives FilterAnnounce from peer P:

1. Store: `peer_filters[P] = received.filter`
2. If `received.ttl > 0`: include P's filter contents in N's next announcement
   to other peers, with TTL decremented

### K-Hop Scope Emergence

With TTL starting at K=2:

- Entries propagate ~2K hops before stopping
- Each node's filter contains destinations within ~4-hop effective range
- Bounded by O(d^2K) entries regardless of total network size

### Expiration

Bloom filters cannot remove individual entries. Expiration is handled via:

- **Peer disconnect**: Remove that peer's filter entirely, recompute
- **Filter replacement**: Each FilterAnnounce replaces the previous one
- **Implicit timeout**: If no updates received from peer within threshold,
  consider their filter stale

---

## Part 2: Discovery Protocol

### Purpose

Discover the tree coordinates of distant destinations not covered by local
Bloom filters.

### When Used

- Destination not found in any peer's Bloom filter
- Route cache miss
- After cached route failure

### Message Formats

```rust
struct LookupRequest {
    request_id: u64,
    target: NodeId,              // Who we're looking for
    origin: NodeId,              // Who's asking
    origin_coords: Vec<NodeId>,  // Origin's ancestry (for return path)
    ttl: u8,                     // Propagation limit
    visited: BloomFilter,        // Prevent loops (compact, ~256 bytes)
}

struct LookupResponse {
    request_id: u64,
    target: NodeId,
    target_coords: Vec<NodeId>,  // Target's ancestry — the key payload
    proof: Signature,            // Target signs to prove existence
}
```

### Discovery Flow

```text
1. S wants to reach D, D not in any local filter
2. S checks route cache — miss
3. S creates LookupRequest with own coordinates, floods to peers
4. Request propagates (Bloom filters may help direct it)
5. Request reaches D (or node with D in filter)
6. D creates LookupResponse with its coordinates, signs it
7. Response routes back to S using S's coordinates (greedy)
8. S caches D's coordinates
9. S can now route to D using greedy tree routing
```

### Request Propagation

**Flood with TTL and visited filter:**

- Send to all peers not in `visited` filter
- Each hop decrements TTL, adds self to `visited`
- At TTL=0, stop propagating
- `visited` filter prevents redundant processing

**Bloom filter assistance (optional optimization):**

If a node's peer filter indicates "maybe" for the target, prioritize that
direction. Reduces flood scope when target is partially in range.

### Response Routing

Response uses greedy tree routing based on `origin_coords` from the request.
Each router forwards toward the origin using tree distance.

### Security

**Target signs response:**

```rust
struct LookupResponse {
    // ...
    proof: Signature,  // Sign(request_id || target || target_coords)
}
```

Without this, a malicious node could claim reachability for any target and
blackhole traffic. The signature proves the target authorized the route.

### Caching

Discovered coordinates are cached:

```rust
struct RouteCache {
    entries: HashMap<NodeId, CachedCoords>,
}

struct CachedCoords {
    coords: Vec<NodeId>,
    discovered_at: Timestamp,
    last_used: Timestamp,
}
```

- **Eviction**: LRU when cache full
- **Expiration**: TTL-based (coordinates may go stale if target moves in tree)
- **Invalidation**: On route failure, evict and re-discover

---

## Part 3: Tree Coordinates and Greedy Routing

### Tree Coordinates

A node's coordinates are its ancestry path from self to root:

```text
coords(N) = [N, Parent(N), Parent(Parent(N)), ..., Root]
```

Example: Node D at depth 4 has coordinates `[D, P1, P2, P3, Root]`.

### Tree Distance

Distance between two nodes is hops through their lowest common ancestor (LCA):

```rust
fn tree_distance(a_coords: &[NodeId], b_coords: &[NodeId]) -> usize {
    let lca_depth = longest_common_suffix_length(a_coords, b_coords);
    let a_to_lca = a_coords.len() - lca_depth;
    let b_to_lca = b_coords.len() - lca_depth;
    a_to_lca + b_to_lca
}
```

Note: Coordinates are ordered self-to-root, so common ancestry is a suffix.

### Greedy Routing Algorithm

```rust
fn greedy_next_hop(&self, dest_coords: &[NodeId]) -> PeerId {
    // Check if we are the destination
    if dest_coords[0] == self.node_id {
        return LOCAL_DELIVERY;
    }

    // Check if destination is a direct peer
    for peer in &self.peers {
        if peer.node_id == dest_coords[0] {
            return peer.id;
        }
    }

    // Forward to peer closest to destination
    self.peers
        .iter()
        .min_by_key(|p| tree_distance(&p.coords, dest_coords))
        .map(|p| p.id)
        .expect("no peers")
}
```

### Guaranteed Progress

Greedy routing makes progress as long as:

1. Tree is connected
2. Destination's coordinates are accurate
3. Current node is not the destination

Unlike DHT routing, greedy tree routing cannot get stuck in local minima if
the tree is properly formed.

### What Each Node Knows

| Information | Source |
|-------------|--------|
| Own coordinates | Spanning tree protocol (ancestry to root) |
| Each peer's coordinates | Exchanged on peering |
| Destination coordinates | From packet header (established via session) |

No global routing tables. Each node makes purely local decisions.

---

## Part 4: Session Establishment

### Session Purpose

Establish cached coordinate state along a path so that subsequent data packets
can omit coordinates, minimizing per-packet overhead.

### Session Lifecycle

```text
┌─────────────────────────────────────────────────────────────────┐
│  1. Discovery: S queries for D's coordinates                    │
│  2. Setup: S sends SessionSetup, routers cache coordinates      │
│  3. Data: Packets carry only addresses, routers use cache       │
│  4. Refresh: Periodic or on-demand to prevent cache expiry      │
│  5. Teardown: Implicit (cache expires) or explicit              │
└─────────────────────────────────────────────────────────────────┘
```

### Session Message Formats

```rust
/// Establishes cached state along path
struct SessionSetup {
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    src_coords: Vec<NodeId>,   // For return path caching
    dest_coords: Vec<NodeId>,  // For forward path routing
    flags: SessionFlags,
}

struct SessionFlags {
    request_ack: bool,         // Ask destination to confirm
    bidirectional: bool,       // Set up both directions
}

/// Confirms session establishment
struct SessionAck {
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,
    src_coords: Vec<NodeId>,   // Acknowledger's coords (for return caching)
}

/// Minimal data packet
struct DataPacket {
    flags: u8,
    hop_limit: u8,
    payload_length: u16,
    src_addr: Ipv6Addr,        // 16 bytes
    dest_addr: Ipv6Addr,       // 16 bytes
    payload: Vec<u8>,
}

/// Error when router cannot route (cache miss)
struct CoordsRequired {
    dest_addr: Ipv6Addr,
    reporter: NodeId,          // Which router had the miss
}
```

### Data Packet Overhead

| Field | Size |
|-------|------|
| flags | 1 byte |
| hop_limit | 1 byte |
| payload_length | 2 bytes |
| src_addr | 16 bytes |
| dest_addr | 16 bytes |
| **Total header** | **36 bytes** |

Comparable to IPv6 (40 bytes). No coordinates in data packets.

### Session Setup Flow

```text
S                       R1                      R2                      D
│                        │                       │                       │
│──SessionSetup─────────>│                       │                       │
│  (src_coords,          │──SessionSetup────────>│                       │
│   dest_coords)         │                       │──SessionSetup────────>│
│                        │                       │                       │
│                        │  cache:               │  cache:               │
│                        │  dest_addr→dest_coords│  dest_addr→dest_coords│
│                        │  src_addr→src_coords  │  src_addr→src_coords  │
│                        │                       │                       │
│<─────────────────────────────────────────────────────────SessionAck───│
│                        │                       │                       │
│══DataPacket═══════════>│══════════════════════>│══════════════════════>│
│  (addresses only)      │  (use cached coords)  │  (use cached coords)  │
```

### Router Behavior

```rust
impl Router {
    fn handle_session_setup(&mut self, setup: SessionSetup, from: PeerId) {
        // Cache coordinates for both directions
        self.coord_cache.insert(setup.dest_addr, CacheEntry {
            coords: setup.dest_coords.clone(),
            expires: now() + CACHE_TTL,
        });
        self.coord_cache.insert(setup.src_addr, CacheEntry {
            coords: setup.src_coords.clone(),
            expires: now() + CACHE_TTL,
        });

        // Forward toward destination
        let next = self.greedy_next_hop(&setup.dest_coords);
        self.forward(next, setup);
    }

    fn handle_data_packet(&mut self, packet: DataPacket, from: PeerId) {
        match self.coord_cache.get(&packet.dest_addr) {
            Some(entry) => {
                entry.last_used = now();
                let next = self.greedy_next_hop(&entry.coords);
                self.forward(next, packet);
            }
            None => {
                // Cache miss — request coordinates
                self.send_error(from, CoordsRequired {
                    dest_addr: packet.dest_addr,
                    reporter: self.node_id,
                });
            }
        }
    }
}
```

### Cache Management

```rust
struct CoordCache {
    entries: HashMap<Ipv6Addr, CacheEntry>,
    max_entries: usize,
}

struct CacheEntry {
    coords: Vec<NodeId>,
    created: Timestamp,
    last_used: Timestamp,
    expires: Timestamp,
}
```

**Eviction policy**: LRU (least recently used) when cache exceeds max_entries.

**Expiration**: Entries expire after TTL (e.g., 300 seconds). Can be refreshed
by:

- Subsequent SessionSetup
- SessionRefresh message (lightweight, just touches expiry)
- Data packet transit (optional: refresh on use)

### Handling Cache Eviction

When a router's cache entry is evicted mid-session:

```text
1. Data packet arrives, cache miss
2. Router sends CoordsRequired to packet source
3. Source receives error, re-sends SessionSetup (or packet with coords)
4. Path warms again, data flow resumes
```

From application perspective: brief latency spike, transparent recovery.

### Sender Behavior

```rust
impl Sender {
    fn send(&mut self, dest: Ipv6Addr, data: &[u8]) {
        if !self.session_established(dest) {
            // Need to establish session first
            let dest_coords = self.discover_or_cached(dest)?;
            self.send_session_setup(dest, &dest_coords);
            self.await_session_ack(dest)?;
        }

        self.send_data_packet(dest, data);
    }

    fn handle_coords_required(&mut self, err: CoordsRequired) {
        // Path went cold, re-establish
        self.mark_session_cold(err.dest_addr);
        self.send_session_setup(err.dest_addr, &self.cached_coords(err.dest_addr));
    }
}
```

---

## Part 5: Packet Type Summary

| Type | Purpose | Size | When Used |
|------|---------|------|-----------|
| FilterAnnounce | Bloom filter propagation | ~4.1 KB | Topology changes |
| LookupRequest | Discover coordinates | ~300 bytes | First contact with distant node |
| LookupResponse | Return coordinates | ~400 bytes | Reply to discovery |
| SessionSetup | Warm router caches | ~400-600 bytes | Before data transfer |
| SessionAck | Confirm session | ~300 bytes | Optional confirmation |
| DataPacket | Application data | 36 bytes + payload | Bulk of traffic |
| CoordsRequired | Request retransmit | ~50 bytes | Cache miss recovery |

---

## Part 6: Traffic Analysis

### Steady State (Stable Network)

- **Bloom filter traffic**: Near zero (event-driven, no changes)
- **Discovery traffic**: Rare (warm caches)
- **Session traffic**: Rare (established sessions)
- **Data traffic**: Minimal overhead (36-byte header)

### Network Churn

When nodes join/leave:

- Bloom filter updates propagate (bounded by K-hop scope)
- Affected sessions may need re-establishment
- Discovery queries for newly-joined nodes

### Per-Node Resource Requirements

| Resource | Full Participant | Leaf-Only |
|----------|------------------|-----------|
| Bloom filter storage | d × 4 KB (d = peer count) | None |
| Coordinate cache | 10K-100K entries | None |
| Route cache | 1K-10K entries | Minimal |
| Bandwidth (idle) | < 1 KB/sec | Near zero |

---

## Open Questions

1. **Coordinate compression**: Can tree coordinates be compressed for smaller
   SessionSetup messages? (e.g., delta encoding, shorter node ID representation)

2. **Multi-path routing**: How to handle multiple valid paths? Load balancing?
   Failover?

3. **Asymmetric paths**: S→D and D→S may traverse different routers. Is this
   acceptable or should paths be symmetric?

4. **Gateway /64 prefixes**: How do subnet prefixes interact with Bloom filters
   and discovery? One filter entry per gateway regardless of devices behind it?

5. **Cache sizing**: What's the right cache size for different node roles?
   Core nodes vs. edge nodes?

6. **Mobility**: When a node changes tree position (new parent), how quickly
   do sessions recover? Should nodes announce position changes?

---

## References

- [fips-design.md](fips-design.md) — Overall FIPS architecture
- [fips-transports.md](fips-transports.md) — Transport protocol characteristics
- [spanning-tree-dynamics.md](spanning-tree-dynamics.md) — Tree protocol details
