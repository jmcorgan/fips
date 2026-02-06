# FIPS Routing Design

This document describes the routing architecture for FIPS, including Bloom
filter reachability, discovery protocol, greedy tree routing, and routing
session establishment.

For wire formats and exchange rules, see [fips-gossip-protocol.md](fips-gossip-protocol.md).
For spanning tree dynamics and convergence, see [spanning-tree-dynamics.md](spanning-tree-dynamics.md).

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
| Filter size | 1 KB (8,192 bits) | Sized for expected occupancy with margin |
| Hash functions | 5 | Optimal for 800-1,600 entries at this size |
| Scope (K) | 2 | Effective ~4-hop reach with TTL propagation |

### Mathematical Foundation

**False Positive Rate (FPR):**

```text
FPR = (1 - e^(-kn/m))^k
```

Where m = bits, n = entries, k = hash functions.

**Optimal hash count:**

```text
k_opt = (m/n) × ln(2) ≈ 0.693 × (m/n)
```

For m=8,192 and expected n=800: k_opt ≈ 7. We use k=5 to accommodate higher
occupancy scenarios (up to ~1,600 entries) while maintaining acceptable FPR.

**Required bits for target FPR:**

```text
m = -1.44 × n × ln(p)
```

For 1% FPR: m ≈ 9.6n bits. For 5% FPR: m ≈ 6.2n bits.

### Expected Filter Occupancy

Filter occupancy depends on K-hop scope and node degree, **not** total network
size. The TTL mechanism bounds entries regardless of network scale.

**Nodes within h hops in a tree (branching factor b = d-1):**

```text
nodes_within_h_hops = (b^(h+1) - 1) / (b - 1)
```

For d=8 (b=7), K=2: each peer's 2-hop neighborhood ≈ 57 nodes.

**Outgoing filter to peer Q contains:**

- Self (1 entry)
- Entries from (d-1) other peers' filters, with overlap

**Expected occupancy by node degree:**

| Degree (d) | Expected Entries | Notes |
|------------|------------------|-------|
| 5 | 100-200 | Constrained/IoT |
| 8 | 250-400 | Typical node |
| 12 | 500-800 | Well-connected |
| 20+ | 1,200-1,800 | Hub node |

### False Positive Rates (1 KB filter, k=5)

| Entries | FPR | Scenario |
|---------|-----|----------|
| 200 | 0.02% | Low-degree node |
| 400 | 0.3% | Typical node |
| 800 | 2.4% | Well-connected |
| 1,200 | 7.5% | Hub node |
| 1,600 | 15% | Heavily loaded hub |

FPR above 5% triggers more LookupRequests but the discovery protocol handles
this gracefully. Hub nodes may benefit from larger filters in future protocol
versions (see §1.6).

### Size Classes (Forward Compatibility)

Filter sizes are powers of 2 to enable **folding** — a technique for shrinking
filters by ORing halves:

```rust
fn fold(filter: &[u8]) -> Vec<u8> {
    let half = filter.len() / 2;
    (0..half).map(|i| filter[i] | filter[i + half]).collect()
}
```

Folding preserves correctness (no false negatives) but increases FPR.

| size_class | Bits | Bytes | Status |
|------------|------|-------|--------|
| 0 | 4,096 | 512 | Reserved (future) |
| 1 | 8,192 | 1,024 | **Current default** |
| 2 | 16,384 | 2,048 | Reserved (future) |
| 3 | 32,768 | 4,096 | Reserved (future) |

**v1 protocol**: All nodes MUST use size_class=1. The field is present in the
wire format for forward compatibility.

**Future versions**: Nodes may negotiate larger filters. Receivers fold down
to their preferred size if sender's filter is larger. This allows hub nodes
to maintain higher precision while constrained nodes use smaller filters.

### Filter Contents

Each node's filter contains Node IDs (and optionally gateway /64 prefixes)
that are reachable through that node. A Node ID is the SHA-256 hash of the
node's npub, truncated or used directly as the filter key.

### Per-Peer Filters

Each node maintains a Bloom filter for each peer direction:

```rust
peer_filters: HashMap<NodeAddr, BloomFilter>
```

The filter for peer P answers: "Which destinations are reachable through P?"

### Update Mechanism: Event-Driven

Filters are updated on events rather than periodic refresh:

**Triggering events:**

1. Peer connects — exchange current filters
2. Peer disconnects — remove their filter, recompute, notify other peers
3. Received filter changes outgoing filter — recompute, send updates
4. Local state change — new leaf dependent, become gateway, etc.

Updates are rate-limited to prevent storms during reconvergence. See
[fips-gossip-protocol.md](fips-gossip-protocol.md) §3 for FilterAnnounce wire
format and exchange rules.

### Filter Contents

A node's outgoing filter to peer Q contains:

1. This node's own Node ID
2. Node IDs of leaf-only dependents
3. Entries from filters received from other peers (not Q) with TTL > 0

This creates K-hop reachability scope through TTL-based propagation.

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

For wire formats, see [fips-gossip-protocol.md](fips-gossip-protocol.md) §4-5.

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
- `visited` filter prevents loops (a packet revisiting a node on its own
  path), but does NOT prevent convergent duplicates — the same request
  arriving at a node via different paths with different visited filters.
  See [Known Limitation: Flood
  Convergence](#known-limitation-flood-convergence).

**Bloom filter assistance (optional optimization):**

If a node's peer filter indicates "maybe" for the target, prioritize that
direction. Reduces flood scope when target is partially in range.

### Response Routing

Response uses greedy tree routing based on `origin_coords` from the request.
Each router forwards toward the origin using tree distance.

### Security

The target signs the LookupResponse with a proof covering
`(request_id || target || target_coords)`. Without this signature, a malicious
node could claim reachability for any target and blackhole traffic. The
signature proves the target authorized the route.

### Caching

Discovered coordinates are cached:

```rust
struct RouteCache {
    entries: HashMap<NodeAddr, CachedCoords>,
}

struct CachedCoords {
    coords: Vec<NodeAddr>,
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
fn tree_distance(a_coords: &[NodeAddr], b_coords: &[NodeAddr]) -> usize {
    let lca_depth = longest_common_suffix_length(a_coords, b_coords);
    let a_to_lca = a_coords.len() - lca_depth;
    let b_to_lca = b_coords.len() - lca_depth;
    a_to_lca + b_to_lca
}
```

Note: Coordinates are ordered self-to-root, so common ancestry is a suffix.

### Greedy Routing Algorithm

```rust
fn greedy_next_hop(&self, dest_coords: &[NodeAddr]) -> NodeAddr {
    // Check if we are the destination
    if dest_coords[0] == self.node_addr {
        return LOCAL_DELIVERY;
    }

    // Check if destination is a direct peer
    for peer in &self.peers {
        if peer.node_addr == dest_coords[0] {
            return peer.node_addr;
        }
    }

    // Forward to peer closest to destination
    self.peers
        .iter()
        .min_by_key(|p| tree_distance(&p.coords, dest_coords))
        .map(|p| p.node_addr)
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

### Privacy Considerations

Intermediate routers can observe `src_addr` and `dest_addr` in transiting packets.
This enables traffic analysis (who is communicating with whom) but not content
inspection (the payload is end-to-end encrypted with session keys).

**Why source address is visible**: The source address is required for routers to
send error messages (CoordsRequired, PathBroken) back to the sender. This is a
deliberate design choice: rather than silently dropping unroutable packets and
relying on application-layer timeouts to detect failures, FIPS provides explicit
feedback that allows rapid route recovery. The tradeoff favors responsiveness
over metadata privacy.

**Partial mitigation**: FIPS addresses are derived from `SHA-256(pubkey)`, not the
npub itself. An observer learns that `fd12:3456:...` is communicating with
`fd78:9abc:...`, but cannot directly determine the Nostr identities without
additional information (e.g., DNS lookup correlation, prior knowledge of the
address-to-npub mapping).

**Alternative considered**: Onion routing (like Tor) hides routing metadata from
intermediate nodes but requires the sender to know the full path upfront and
prevents per-hop error feedback. FIPS prioritizes low-latency greedy routing
with explicit error signaling over metadata privacy.

---

## Part 4: Route Cache Management

> **Wire formats**: For session layer message wire formats (SessionSetup,
> SessionAck, DataPacket, CoordsRequired, PathBroken), see
> [fips-session-protocol.md](fips-session-protocol.md) §8.

### Route Cache Purpose

Intermediate routers cache coordinate mappings so that data packets can use
minimal headers (addresses only, no coordinates). This reduces per-packet
overhead from ~300 bytes to 38 bytes.

### Cache Lifecycle

```text
┌─────────────────────────────────────────────────────────────────┐
│  1. Discovery: S queries for D's coordinates                    │
│  2. Setup: S sends SessionSetup, routers cache coordinates      │
│  3. Data: Packets carry only addresses, routers use cache       │
│  4. Refresh: Periodic or on-demand to prevent cache expiry      │
│  5. Teardown: Implicit (cache expires) or explicit              │
└─────────────────────────────────────────────────────────────────┘
```

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
        // If packet carries coordinates, cache them
        if packet.flags & COORDS_PRESENT != 0 {
            if let (Some(src_coords), Some(dest_coords)) =
                (&packet.src_coords, &packet.dest_coords)
            {
                self.coord_cache.insert(packet.dest_addr, CacheEntry {
                    coords: dest_coords.clone(),
                    expires: now() + CACHE_TTL,
                });
                self.coord_cache.insert(packet.src_addr, CacheEntry {
                    coords: src_coords.clone(),
                    expires: now() + CACHE_TTL,
                });
            }
        }

        // Route using cache (now populated if coords were present)
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
                    reporter: self.node_addr,
                });
            }
        }
    }
}
```

### Cache Data Structure

```rust
struct CoordCache {
    entries: HashMap<Ipv6Addr, CacheEntry>,
    max_entries: usize,
}

struct CacheEntry {
    coords: Vec<NodeAddr>,
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

### Cache Miss Recovery

When a router's cache entry is evicted mid-session:

```text
1. Data packet arrives (minimal header), cache miss
2. Router sends CoordsRequired to packet source
3. Source marks route as cold
4. Source resends with COORDS_PRESENT flag set
5. Router caches coordinates from packet, forwards
6. After N successful packets, source clears flag
```

The crypto session remains active throughout—only routing state is refreshed.
From application perspective: one packet delayed, transparent recovery.

### Sender State Machine

```rust
impl Sender {
    fn send(&mut self, dest: Ipv6Addr, data: &[u8]) {
        if !self.session_established(dest) {
            // Need to establish crypto session first
            let dest_coords = self.discover_or_cached(dest)?;
            self.send_session_setup(dest, &dest_coords);
            self.await_session_ack(dest)?;
        }

        // Check route state
        let include_coords = self.route_state(dest) == RouteCold;
        self.send_data_packet(dest, data, include_coords);
    }

    fn handle_coords_required(&mut self, err: CoordsRequired) {
        // Route cache expired at intermediate router
        // Crypto session still valid - just need to re-warm route
        self.mark_route_cold(err.dest_addr);
        // Next send() will include coordinates
    }
}

enum RouteState {
    RouteWarm,  // Send minimal headers
    RouteCold,  // Include coordinates until warm
}
```

---

## Part 5: Packet Type Summary

| Type | Purpose | Size | When Used |
|------|---------|------|-----------|
| FilterAnnounce | Bloom filter propagation | ~1 KB | Topology changes |
| LookupRequest | Discover coordinates | ~300 bytes | First contact with distant node |
| LookupResponse | Return coordinates | ~400 bytes | Reply to discovery |
| SessionSetup | Warm router caches + crypto init | ~400-700 bytes | Before data transfer |
| SessionAck | Confirm session + crypto response | ~300-500 bytes | Session confirmation |
| DataPacket | Application data | 36 bytes + payload (minimal) | Bulk of traffic |
| DataPacket | With coordinates | ~300-500 bytes + payload | After CoordsRequired |
| CoordsRequired | Request coords in next packet | ~50 bytes | Cache miss recovery |

> **Note**: SessionSetup/SessionAck sizes vary based on coordinate depth and
> whether they carry crypto handshake payloads (combined establishment per
> [fips-session-protocol.md](fips-session-protocol.md) §3.4 and §5.1).

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
| Bloom filter storage | d × 1 KB (d = peer count) | None |
| Coordinate cache | 10K-100K entries | None |
| Route cache | 1K-10K entries | Minimal |
| Bandwidth (idle) | < 1 KB/sec | Near zero |

---

## Known Limitations

### Known Limitation: Flood Convergence

The visited Bloom filter in LookupRequest prevents **loops** (a packet
revisiting a node on its own path) but does not prevent **convergent
duplicates** — the same request arriving at a node via different paths, each
carrying a different visited filter.

Example: Source S floods to peers B and C. Both forward to node D. D receives
two copies — one with visited={S,B}, one with visited={S,C}. Neither copy's
visited filter contains D, so D processes both. This redundancy compounds at
every well-connected node in the flood path, and the destination may generate
multiple LookupResponses.

**Required fix**: Nodes MUST maintain a short-lived cache of recently-seen
`request_id` values (retention: a few seconds, bounded by request rate limit).
On receiving a LookupRequest, check this cache first and drop duplicates before
consulting the visited filter. This is referenced in the gossip protocol spec
(section 4.4, rate limiting) but needs to be elevated to a protocol
requirement, not an optimization.

### Known Limitation: Capacity-Blind Greedy Routing

Greedy routing selects the next hop by minimizing tree distance, which is
purely topological (hop count through the LCA). It does not account for link
capacity, latency, or loss.

This creates a problem when a topologically short but low-capacity link exists
alongside a longer but high-capacity path. Greedy routing will prefer the short
path, potentially saturating the slow link while the high-capacity path goes
underutilized.

**Proposed mitigation**: Each node locally measures the quality of its direct
peer links (RTT, bandwidth, loss) and applies a cost adjustment to the
forwarding decision:

```text
effective_distance(peer, dest) =
    tree_distance(peer, dest) × local_link_cost(peer)
```

This requires no protocol changes — link quality is measured locally, not
advertised. Self-reported cost claims are intentionally excluded from the
protocol to prevent adversarial traffic attraction (a node advertising
artificially low costs to become a transit point for surveillance or
disruption). Only locally-measured, first-hop metrics are used.

## Enhancement Opportunity: Discovery Path Accumulation

The LookupRequest flood naturally finds the lowest-latency path to the
destination — the first copy to arrive traveled the fastest route. Currently
this path information is discarded; only the destination's tree coordinates
survive in the LookupResponse.

### Concept

Each node forwarding a LookupRequest appends a signed path entry:

```text
PathEntry {
    node_addr: NodeAddr,        // 16 bytes, forwarding node
    signature: Signature,       // 64 bytes, signs
                                // (request_id || position || node_addr)
}
```

The destination includes the accumulated path in the LookupResponse alongside
the existing `target_coords`. Per-hop signatures prevent path fabrication — a
malicious node cannot insert fake hops or claim a path it didn't traverse.

### Potential Uses

**Source peer bias**: The source examines the first hop of the discovered path
to learn which of its direct peers leads to the empirically fastest route to
the destination. This biases forwarding for that destination toward that peer,
complementing tree distance and local link quality measurements. The source can
verify this directly since the first hop is a direct peer.

**Intermediate router hints**: Routers along the path can verify their own
position and adjacent hops (which should be direct peers). This gives them
empirical data about which peer directions lead toward specific destinations,
potentially informing their own forwarding decisions for future packets.

**Coordinate cache seeding**: Intermediate routers on the discovered path learn
about both endpoints before data traffic begins, enabling pre-warming of
coordinate caches and reducing CoordsRequired errors on the first data packets.

### Tradeoffs

- **Size overhead**: 80 bytes per hop in the LookupRequest. An 8-hop path adds
  640 bytes. Acceptable for a one-time discovery message, not suitable for data
  packets.
- **Staleness**: The path is a snapshot. Nodes may disconnect or links may
  degrade after discovery. The path should be treated as a hint, not a
  commitment. Greedy coordinate-based routing remains the primary forwarding
  mechanism.
- **Latency vs capacity**: The fastest flood path is the lowest-latency path,
  which is not necessarily the highest-capacity path. For bulk transfers, a
  slower but higher-bandwidth path may be preferable. The path signal is most
  useful for latency-sensitive traffic.

### Interaction with Request Deduplication

With strict `request_id` dedup at every node, the destination receives exactly
one request via the fastest path. If multiple candidate paths are desired (for
failover or load balancing), the destination could be exempted from dedup to
accept the first N arrivals, at the cost of generating multiple responses.

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

- [fips-intro.md](fips-intro.md) — Overall FIPS architecture
- [fips-gossip-protocol.md](fips-gossip-protocol.md) — Wire formats for TreeAnnounce, FilterAnnounce, Lookup
- [fips-session-protocol.md](fips-session-protocol.md) — Traffic flow, crypto sessions, terminology
- [fips-wire-protocol.md](fips-wire-protocol.md) — Link-layer transport and Noise IK handshake
- [fips-transports.md](fips-transports.md) — Transport protocol characteristics
- [spanning-tree-dynamics.md](spanning-tree-dynamics.md) — Tree protocol dynamics and convergence
