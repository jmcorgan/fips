# FIPS Routing Design

This document describes the routing architecture for FIPS, including Bloom
filter routing, greedy tree routing, discovery protocol, and routing session
establishment.

For wire formats and exchange rules, see [fips-gossip-protocol.md](fips-gossip-protocol.md).
For spanning tree dynamics and convergence, see [spanning-tree-dynamics.md](spanning-tree-dynamics.md).

## Overview

FIPS uses a layered routing strategy where each mechanism handles different
situations. In steady state, bloom filter routing handles the vast majority
of forwarding decisions.

### Next-Hop Selection (in priority order)

1. **Local delivery** — destination is self
2. **Direct peer** — destination is an authenticated peer
3. **Bloom filter routing** — one or more peers' bloom filters contain the
   destination; select the best candidate by `(link_cost, tree_distance,
   node_addr)`. Since filters propagate unboundedly through the network,
   every reachable destination eventually appears in at least one peer's
   filter. This is the **primary routing path** for most traffic.
4. **Greedy tree routing** — fallback when bloom filters haven't yet
   converged (transient condition during topology changes). Requires the
   destination's tree coordinates to be in the local coordinate cache,
   populated by a prior SessionSetup or LookupResponse.
5. **No route** — destination unreachable

### Role of Each Mechanism

- **Bloom filters**: Primary forwarding — tell each node which peer to
  send through for a given destination. Propagate unboundedly via
  split-horizon merge, so they cover the entire reachable network at
  steady state.
- **Greedy tree routing**: Fallback forwarding during convergence windows
  when bloom filters are incomplete. Also serves as tie-breaker among
  bloom filter candidates (closest tree distance wins).
- **Discovery protocol**: Populates the coordinate cache to enable greedy
  tree routing and to provide intermediate routers with coordinate data
  for more efficient path selection. Not required for basic reachability
  once bloom filters have converged.

## Design Goals

- Minimize per-packet overhead for data transfer
- Bounded state at each node (independent of network size)
- Efficient routing without global knowledge
- Graceful degradation for constrained devices
- Fast convergence on topology changes

## Network Scale Assumptions

| Scale | Nodes | Bloom Filter Role |
|-------|-------|-------------------|
| Small private network | 100-1,000 | Covers entire network with low FPR |
| Modest public network | ~1,000,000 | Covers entire network but FPR increases at hub nodes due to filter saturation |
| Internet-scale | Billions | Out of scope (requires different architecture) |

The primary design target is networks up to ~1M nodes. Since bloom filters
propagate unboundedly (no TTL), they converge to represent the entire
reachable network. At large scale, the fixed 1KB filter size means higher
false positive rates at well-connected hub nodes, which may trigger
unnecessary discovery queries but does not affect correctness.

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

| Parameter      | Value             | Rationale                                  |
|----------------|-------------------|--------------------------------------------|
| Filter size    | 1 KB (8,192 bits) | Sized for expected occupancy with margin   |
| Hash functions | 5                 | Optimal for 800-1,600 entries at this size |

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

Filter occupancy depends on network topology and node degree. In practice,
filters reach a natural equilibrium determined by the network's structure —
merging peer filters transitively means each filter converges to represent
the node's reachable neighborhood.

**Outgoing filter to peer Q contains:**

- Self (1 entry)
- Entries from (d-1) other peers' filters (excluding Q), with overlap

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

Since filters propagate unboundedly, hub nodes with many peers will have
higher occupancy (more entries merged from more peers). FPR above 5% means
bloom filter routing may occasionally select a peer that can't actually
reach the destination (false positive), requiring fallback to greedy tree
routing or error recovery. Hub nodes may benefit from larger filters in
future protocol versions (see §1.6).

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
3. Entries merged from filters received from all other peers (not Q)

Filters propagate transitively through the network. Each node merges all
inbound peer filters (excluding the destination peer) into its outgoing
filter — this split-horizon approach prevents a node's own entries from
being echoed back to it, providing loop prevention. Propagation is
unbounded; filters naturally converge as the Bloom filter's fixed size
limits information density.

### Expiration

Bloom filters cannot remove individual entries. Expiration is handled via:

- **Peer disconnect**: Remove that peer's filter entirely, recompute
- **Filter replacement**: Each FilterAnnounce replaces the previous one
- **Implicit timeout**: If no updates received from peer within threshold,
  consider their filter stale

---

## Part 2: Discovery Protocol

### Purpose

Discover the tree coordinates of a destination to enable greedy tree routing
and to populate coordinate caches at intermediate routers for more efficient
forwarding. In steady state, bloom filters handle reachability; discovery
provides the coordinate information that improves path selection quality.

### When Used

- During bloom filter convergence (destination not yet in any peer's filter)
- To populate coordinate caches for greedy tree routing (optimization)
- After cached route failure (coordinates may be stale)

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

Discovered coordinates are stored in the route cache (`RouteCache`):

```rust
struct RouteCache {
    entries: HashMap<NodeAddr, CachedCoords>,
    max_entries: usize,  // default: 10,000
}

struct CachedCoords {
    coords: TreeCoordinate,
    discovered_at: Timestamp,
    last_used: Timestamp,
}
```

- **Eviction**: LRU when cache full (no automatic TTL expiration)
- **Invalidation**: On route failure, evict and re-discover

This is distinct from the `CoordCache` used for session-populated
coordinates (see Part 4 for the full dual-cache architecture).

---

## Part 3: Tree Coordinates and Greedy Routing

Tree coordinates and greedy routing serve two roles:

1. **Fallback forwarding** during bloom filter convergence windows
2. **Tie-breaking** among bloom filter candidates — tree distance between
   a candidate peer and the destination helps select the best path when
   multiple peers advertise reachability

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

When used as a fallback (no bloom filter hits), greedy routing forwards to
the peer that minimizes tree distance to the destination. A self-distance
check ensures progress — the packet is only forwarded if the chosen peer is
strictly closer than the current node.

```rust
fn greedy_next_hop(&self, dest_coords: &TreeCoordinate) -> Option<NodeAddr> {
    if self.my_coords.root_id() != dest_coords.root_id() {
        return None; // different tree
    }

    let my_distance = self.my_coords.distance_to(dest_coords);

    // Find peer with minimum distance, tie-break by smallest node_addr
    let best = self.peer_ancestry.iter()
        .min_by(|(id_a, coords_a), (id_b, coords_b)| {
            coords_a.distance_to(dest_coords)
                .cmp(&coords_b.distance_to(dest_coords))
                .then_with(|| id_a.cmp(id_b))
        });

    match best {
        Some((peer_id, coords)) if coords.distance_to(dest_coords) < my_distance => {
            Some(*peer_id)
        }
        _ => None, // no peer is closer (local minimum)
    }
}
```

### Progress Guarantee

When the coordinate cache is populated, greedy routing makes progress as
long as:

1. Tree is connected
2. Destination's coordinates are accurate
3. A peer is closer to the destination than the current node

If no peer is closer (local minimum), routing returns `None` and the caller
generates a PathBroken error. In a properly formed tree this should not
occur, but the self-distance check provides a safety net.

### What Each Node Knows

| Information | Source |
|-------------|--------|
| Own coordinates | Spanning tree protocol (ancestry to root) |
| Each peer's coordinates | Exchanged on peering |
| Destination coordinates | From packet header (established via session) |

No global routing tables. Each node makes purely local decisions.

### Privacy Considerations

Intermediate routers can observe `src_addr` and `dest_addr` in the
SessionDatagram envelope of transiting packets. This enables traffic analysis
(who is communicating with whom) but not content inspection (the payload is
end-to-end encrypted with session keys).

**Why source address is visible**: The `src_addr` field in the SessionDatagram
is required for transit routers to send error signals (CoordsRequired,
PathBroken) back to the sender. When a transit router R cannot forward a
SessionDatagram `{src: S, dest: D}`, it creates a new SessionDatagram
`{src: R, dest: S}` carrying the error signal, and routes it toward S using
`find_next_hop(S)`. This is a deliberate design choice: rather than silently
dropping unroutable packets and relying on application-layer timeouts to detect
failures, FIPS provides explicit feedback that allows rapid route recovery.
The tradeoff favors responsiveness over metadata privacy.

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

## Part 4: Coordinate Cache Architecture

> **Wire formats**: For session layer message wire formats (SessionSetup,
> SessionAck, DataPacket, CoordsRequired, PathBroken), see
> [fips-session-protocol.md](fips-session-protocol.md) §8.

### Dual Cache Architecture

FIPS uses two coordinate caches with different lifecycles:

- **CoordCache** (session-populated): Stores coordinates learned from
  SessionSetup and SessionAck coordinate fields during session establishment.
  TTL-based expiration (300s). 50,000 entries max. Consulted first by
  `find_next_hop()`.

- **RouteCache** (discovery-populated): Stores coordinates learned from
  LookupResponse during discovery protocol completion. LRU eviction only
  (no automatic TTL). 10,000 entries max. Consulted as fallback when
  CoordCache misses.

Both caches store `TreeCoordinate` values (node_addr → coordinates). Neither
stores next-hop information — routing decisions are computed at lookup time by
`find_next_hop()` using the cached coordinates.

### Cache Purpose

The coordinate caches serve two functions:

1. **Greedy routing fallback** — when bloom filters haven't converged,
   cached coordinates enable tree-distance-based forwarding.
2. **Reduced packet overhead** — once coordinates are cached at intermediate
   routers, data packets can use minimal DataPacket headers (4 bytes inside
   a 34-byte SessionDatagram = 38 bytes total) rather than including full
   coordinates (~170 bytes total).

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

All messages are carried inside SessionDatagram envelopes that provide
`src_addr`, `dest_addr`, and `hop_limit` at the link layer.

```text
S                       R1                      R2                      D
│                        │                       │                       │
│──SessionDatagram──────>│                       │                       │
│  {src:S, dest:D,       │──SessionDatagram─────>│                       │
│   payload:SessionSetup │                       │──SessionDatagram─────>│
│   (src_coords,         │                       │                       │
│    dest_coords)}       │  cache:               │  cache:               │
│                        │  dest_addr→dest_coords│  dest_addr→dest_coords│
│                        │  src_addr→src_coords  │  src_addr→src_coords  │
│                        │                       │                       │
│<──────────────────────────────────────────SessionDatagram{SessionAck}──│
│                        │                       │                       │
│══SessionDatagram══════>│══════════════════════>│══════════════════════>│
│  {src:S, dest:D,       │  (use cached coords)  │  (use cached coords)  │
│   payload:DataPacket}  │                       │                       │
```

### Router Behavior

Transit routers process SessionDatagram envelopes. The envelope provides
`src_addr` and `dest_addr` for routing decisions and error signaling.

```rust
impl Router {
    /// Handle a SessionDatagram carrying a SessionSetup payload.
    /// Cache coordinates from the setup message for both directions.
    fn handle_session_setup(&mut self, dg: &SessionDatagram, setup: SessionSetup) {
        // Cache coordinates for both directions
        self.coord_cache.insert(dg.dest_addr, CacheEntry {
            coords: setup.dest_coords.clone(),
            expires: now() + CACHE_TTL,
        });
        self.coord_cache.insert(dg.src_addr, CacheEntry {
            coords: setup.src_coords.clone(),
            expires: now() + CACHE_TTL,
        });

        // Forward toward destination using find_next_hop
        if let Some(next) = self.find_next_hop(&dg.dest_addr) {
            self.forward(next, dg);
        }
    }

    /// Handle a SessionDatagram carrying a DataPacket payload.
    /// Addresses come from the SessionDatagram envelope (dg.src_addr, dg.dest_addr).
    fn handle_data_packet(&mut self, dg: &SessionDatagram, packet: DataPacket) {
        // If packet carries coordinates, cache them
        if packet.flags & COORDS_PRESENT != 0 {
            if let (Some(src_coords), Some(dest_coords)) =
                (&packet.src_coords, &packet.dest_coords)
            {
                self.coord_cache.insert(dg.dest_addr, CacheEntry {
                    coords: dest_coords.clone(),
                    expires: now() + CACHE_TTL,
                });
                self.coord_cache.insert(dg.src_addr, CacheEntry {
                    coords: src_coords.clone(),
                    expires: now() + CACHE_TTL,
                });
            }
        }

        // Route using find_next_hop (bloom filter → greedy tree → None)
        match self.find_next_hop(&dg.dest_addr) {
            Some(next) => self.forward(next, dg),
            None => {
                // Cannot route — send error back to source via src_addr
                self.send_error_to_source(dg, CoordsRequired {
                    dest_addr: dg.dest_addr,
                    reporter: self.node_addr,
                });
            }
        }
    }

    /// Send an error signal back to the source of a SessionDatagram.
    /// Creates a new SessionDatagram addressed to dg.src_addr.
    fn send_error_to_source(&self, dg: &SessionDatagram, error: impl LinkError) {
        let error_dg = SessionDatagram {
            src_addr: self.node_addr,  // We are the reporter
            dest_addr: dg.src_addr,     // Route back to original source
            hop_limit: 64,
            payload: error.encode(),    // CoordsRequired or PathBroken
        };
        // Route the error — if we can't reach source either, drop silently
        if let Some(next) = self.find_next_hop(&dg.src_addr) {
            self.forward(next, &error_dg);
        }
        // If find_next_hop returns None for source: drop silently.
        // No cascading errors.
    }
}
```

### Cache Data Structures

```rust
/// Session-populated coordinate cache (TTL-based).
struct CoordCache {
    entries: HashMap<NodeAddr, CacheEntry>,
    max_entries: usize,      // default: 50,000
    ttl_ms: u64,             // default: 300,000 (5 minutes)
}

struct CacheEntry {
    coords: TreeCoordinate,
    created_at: u64,         // Unix milliseconds
    last_used: u64,
    expires_at: u64,
}

/// Discovery-populated coordinate cache (LRU-based, no TTL).
struct RouteCache {
    entries: HashMap<NodeAddr, CachedCoords>,
    max_entries: usize,      // default: 10,000
}

struct CachedCoords {
    coords: TreeCoordinate,
    discovered_at: u64,
    last_used: u64,
}
```

**CoordCache eviction**: Expired entries removed first, then LRU when cache
exceeds max_entries. Entries expire after TTL (300 seconds). Refreshed by
subsequent SessionSetup/SessionAck or DataPacket with COORDS_PRESENT.

**RouteCache eviction**: Pure LRU when cache exceeds max_entries. No automatic
TTL expiration. Invalidated explicitly on route failure.

### Cache Miss Recovery

When a router's cache entry is evicted mid-session:

```text
1. SessionDatagram{src:S, dest:D, payload:DataPacket} arrives, router can't route
2. Router R creates SessionDatagram{src:R, dest:S, payload:CoordsRequired{dest:D}}
3. Router routes the error back to S using find_next_hop(S)
4. S receives CoordsRequired, marks route to D as "cold"
5. S resends with COORDS_PRESENT flag set in DataPacket
6. Routers cache coordinates from DataPacket, forward normally
7. After N successful packets, S clears the flag
```

The crypto session remains active throughout—only routing state is refreshed.
From application perspective: one packet delayed, transparent recovery.

If the router also cannot route to S (no bloom filter hit, no cached
coordinates for S), the error is dropped silently. No cascading errors are
generated. The source will eventually detect the loss via application-layer
timeout.

### Sender State Machine

```rust
impl Sender {
    fn send(&mut self, dest: NodeAddr, data: &[u8]) {
        if !self.session_established(dest) {
            // Need to establish crypto session first
            let dest_coords = self.discover_or_cached(dest)?;
            self.send_session_setup(dest, &dest_coords);
            self.await_session_ack(dest)?;
        }

        // Check route state
        let include_coords = self.route_state(dest) == RouteCold;
        let data_packet = DataPacket::new(data, include_coords);

        // Wrap in SessionDatagram for forwarding
        let dg = SessionDatagram {
            src_addr: self.node_addr,
            dest_addr: dest,
            hop_limit: 64,
            payload: data_packet.encode(),
        };
        self.forward_datagram(dg);
    }

    /// Handle CoordsRequired received inside a SessionDatagram addressed to us.
    /// The SessionDatagram.src_addr identifies the reporting router (informational).
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

All session-layer messages and error signals are carried inside a
SessionDatagram envelope (34 bytes: msg_type + src_addr + dest_addr +
hop_limit). Sizes below include the SessionDatagram header.

| Type | Purpose | Size | When Used |
|------|---------|------|-----------|
| FilterAnnounce | Bloom filter propagation | ~1 KB | Topology changes |
| LookupRequest | Discover coordinates | ~300 bytes | First contact with distant node |
| LookupResponse | Return coordinates | ~400 bytes | Reply to discovery |
| SessionDatagram+SessionSetup | Warm caches + crypto init | ~230-400 bytes | Before data transfer |
| SessionDatagram+SessionAck | Confirm session + crypto | ~100-200 bytes | Session confirmation |
| SessionDatagram+DataPacket | Application data | 38 bytes + payload (minimal) | Bulk of traffic |
| SessionDatagram+DataPacket | With coordinates | ~170 bytes + payload | After CoordsRequired |
| SessionDatagram+CoordsRequired | Coords needed signal | 68 bytes | Cache miss recovery |
| SessionDatagram+PathBroken | Routing failed signal | 68+ bytes | Greedy routing local minimum |

> **Note**: SessionSetup/SessionAck sizes vary based on coordinate depth and
> whether they carry crypto handshake payloads (combined establishment per
> [fips-session-protocol.md](fips-session-protocol.md) §3.4 and §5.1).

---

## Part 6: Traffic Analysis

### Steady State (Stable Network)

- **Bloom filter traffic**: Near zero (event-driven, no changes)
- **Discovery traffic**: Rare (warm caches)
- **Session traffic**: Rare (established sessions)
- **Data traffic**: Minimal overhead (38-byte header: 34 envelope + 4 DataPacket)

### Network Churn

When nodes join/leave:

- Bloom filter updates propagate through affected peers
- Affected sessions may need re-establishment
- Discovery queries for newly-joined nodes

### Per-Node Resource Requirements

| Resource | Full Participant | Leaf-Only |
|----------|------------------|-----------|
| Bloom filter storage | d × 1 KB (d = peer count) | None |
| CoordCache (session) | 50K entries, 300s TTL | None |
| RouteCache (discovery) | 10K entries, LRU | Minimal |
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

### Known Limitation: Capacity-Blind Routing

Both bloom filter candidate selection and greedy tree routing currently
select next hops without considering link quality. When multiple peers
can reach a destination, the selection is based on tree distance and
node address tie-breaking — purely topological metrics that ignore link
capacity, latency, and loss.

This creates a problem when a topologically short but low-capacity link
exists alongside a longer but high-capacity path. The routing algorithm
will prefer the topologically closer peer, potentially saturating a slow
link while a higher-capacity path goes underutilized.

**Proposed mitigation**: Each node locally measures the quality of its
direct peer links (RTT, bandwidth, loss) and incorporates this into a
`link_cost()` metric. The next-hop selection uses a composite ordering
of `(link_cost, tree_distance, node_addr)` — link quality takes priority
over topological distance.

The `link_cost()` interface is implemented (currently returning a constant),
ready to be populated with real measurements using an established link
quality algorithm (ETX, Babel composite metric, etc.).

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
