# FIPS Mesh Operation

This document describes how the FIPS mesh operates at the link layer — how
spanning tree, bloom filters, routing decisions, discovery, and error recovery
work together as a coherent system. It treats spanning tree and bloom filters
as black boxes (what they provide to routing) and focuses on how the pieces
interact.

For spanning tree algorithms and data structures, see
[fips-spanning-tree.md](fips-spanning-tree.md). For bloom filter parameters
and mathematics, see [fips-bloom-filters.md](fips-bloom-filters.md).

## Overview

FIPS mesh operation is entirely distributed. Each node makes forwarding
decisions using only local information: its direct peers, their spanning tree
positions, and their bloom filters. There are no routing tables pushed from
above, no link-state floods, and no distance-vector exchanges.

Two complementary mechanisms provide the information each node needs:

- **Spanning tree** gives every node a coordinate in the network — its
  ancestry path from itself to the root. These coordinates enable distance
  calculations between any two nodes without global topology knowledge.
- **Bloom filters** summarize which destinations are reachable through each
  peer. They provide candidate selection — narrowing which peers are worth
  considering for forwarding a given destination.

Together, they enable a routing decision process that is local, efficient,
and self-healing.

## Spanning Tree Formation and Maintenance

### What the Spanning Tree Provides

The spanning tree gives each node a **coordinate**: its ancestry path from
itself to the root, expressed as a sequence of node_addrs. These coordinates
enable:

- **Distance calculation**: The tree distance between two nodes is the number
  of hops from each to their lowest common ancestor (LCA). This provides a
  routing metric without any node knowing the full topology.
- **Greedy routing**: At each hop, forward to the peer that minimizes tree
  distance to the destination. The strictly-decreasing distance invariant
  guarantees loop-free forwarding.

### How the Tree Forms

Nodes self-organize into a spanning tree through distributed parent selection:

1. **Root election**: The node with the smallest node_addr becomes the root.
   No election protocol — this is a consequence of each node independently
   preferring lower-addressed roots.
2. **Parent selection**: Each node selects a single parent from among its
   direct peers based on which offers the best path to root (considering
   depth improvement threshold).
3. **Coordinate computation**: Once a node has a parent, its coordinate is
   computed from its ancestry path.

### How the Tree Maintains Itself

Nodes exchange **TreeAnnounce** messages with their direct peers (not
forwarded — peer-to-peer only). Each TreeAnnounce carries the sender's
current ancestry chain and a sequence number.

Changes cascade through the tree:

- A node that changes its parent recomputes its coordinates and announces to
  all peers
- Each receiving peer evaluates whether the change affects its own parent
  selection
- Only nodes that actually change their coordinates (root or depth changed)
  propagate further

TreeAnnounce propagation is rate-limited at 500ms minimum interval per peer.
A tree of depth D reconverges in roughly D×0.5s to D×1.0s.

### Partition Handling

If the network partitions, each segment independently elects its own root
(the smallest node_addr in the segment) and reconverges. When segments
rejoin, nodes discover the globally-smallest root through TreeAnnounce
exchange and reconverge to a single tree.

See [fips-spanning-tree.md](fips-spanning-tree.md) for algorithm details
and [spanning-tree-dynamics.md](spanning-tree-dynamics.md) for convergence
walkthroughs.

## Bloom Filter Gossip and Propagation

### What Bloom Filters Provide

Each node maintains a bloom filter per peer, answering: "can peer P possibly
reach destination D?" The answer is either "no" (definitive) or "maybe"
(probabilistic — false positives are possible).

This is **candidate selection**, not routing. Bloom filters identify which
peers are worth considering for a destination, but the actual forwarding
decision uses tree coordinate distance to rank those candidates.

### How Filters Propagate

Nodes exchange **FilterAnnounce** messages with direct peers. Each
FilterAnnounce replaces the previous filter for that peer — there is no
incremental update.

Filter computation uses **split-horizon exclusion**: the outbound filter
for peer Q is computed by merging the local node's own identity, its
leaf-only dependents (if any), and the filters received from all other
peers *except* Q. This prevents echo loops where a node advertises back
to Q the destinations it learned from Q.

Filters propagate unboundedly (no TTL). At steady state, every reachable
destination appears in at least one peer's filter.

### Update Triggers

Filter updates are event-driven, not periodic:

- Peer connects or disconnects
- A peer's incoming filter changes
- Local state changes (new identity, leaf-only dependent changes)

Updates are rate-limited at 500ms to prevent storms during topology changes.

### Scale Properties

At moderate network sizes, bloom filters are highly accurate. At larger
scales (~1M nodes), hub nodes with many peers may see elevated false positive
rates (7–15% for nodes with 20+ peers). False positives cause unnecessary
discovery attempts but do not affect routing correctness — the tree distance
calculation makes the actual forwarding decision.

See [fips-bloom-filters.md](fips-bloom-filters.md) for filter parameters,
FPR calculations, and size class folding.

## Routing Decision Process

At each hop, FMP makes a local forwarding decision using the `find_next_hop()`
priority chain. This is the core routing algorithm.

### Priority Chain

1. **Local delivery** — The destination node_addr matches the local node.
   Deliver to FSP above.

2. **Direct peer** — The destination is an authenticated neighbor. Forward
   directly. No coordinates or bloom filters needed.

3. **Bloom-guided candidate selection** — One or more peers' bloom filters
   contain the destination. Select the best candidate by composite key:
   `(link_cost, tree_distance, node_addr)`. This requires the destination's
   tree coordinates to be in the local coordinate cache.

4. **Greedy tree routing** — Fallback when bloom filters haven't converged
   for this destination. Forward to the peer that minimizes tree distance.
   Also requires destination coordinates.

5. **No route** — Destination unreachable. Generate an error signal
   (CoordsRequired or PathBroken) back to the source.

### The Coordinate Requirement

All multi-hop routing (steps 3–4) requires the destination's tree coordinates
to be in the local coordinate cache. Without coordinates, `find_next_hop()`
returns None immediately — bloom filters are never even consulted.

This creates two simultaneous convergence requirements for multi-hop routing:

1. **Bloom convergence**: Filters must propagate so peers advertise
   reachability
2. **Coordinate availability**: Destination coordinates must be cached at
   every transit node on the path

Both must be satisfied simultaneously. Bloom convergence without coordinates
causes a coordinate cache miss. Coordinates without bloom convergence falls
through to greedy tree routing (functional but suboptimal).

### Candidate Ranking

When bloom filters identify multiple candidate peers, they are ranked by a
composite key:

1. **link_cost** — Per-link quality metric. ETX is computed from bidirectional
   delivery ratios in MMP metrics but is not yet wired into `find_next_hop()`
   candidate ranking; link cost remains constant in the current implementation.
2. **tree_distance** — Coordinate-based distance to destination through this
   peer
3. **node_addr** — Deterministic tie-breaker

A peer with a bloom filter hit but no entry in the peer ancestry table
(missing TreeAnnounce) defaults to maximum distance and is effectively
invisible to routing.

### Loop Prevention

The routing decision enforces strict progress: a packet is only forwarded
to a peer that is strictly closer (by tree distance) to the destination than
the current node. This self-distance check prevents routing loops even with
stale coordinates, because each transit node evaluates using its own
freshly-computed coordinates.

If no peer is closer than the current node (a local minimum in the tree
distance metric), `find_next_hop()` returns None and the caller generates a
PathBroken error.

## Coordinate Caching

The coordinate cache maps `NodeAddr → TreeCoordinate` and is the critical
data structure for multi-hop routing. Without it, forwarding decisions cannot
be made.

### Unified Cache

The coordinate cache is a single unified cache. All sources — SessionSetup
transit, CP-flagged data packets, LookupResponse — write to the same cache.

### Population Sources

| Source | When | What |
| ------ | ---- | ---- |
| SessionSetup transit | Session establishment | Both src and dest coordinates |
| SessionAck transit | Session establishment | Both src and dest coordinates |
| CP-flagged data packet | Warmup or recovery | Both src and dest coordinates (cleartext) |
| LookupResponse | Discovery | Target's coordinates |

### Eviction

- **TTL-based**: Entries expire after 300s (configurable)
- **Refresh on use**: Active routing refreshes the TTL, keeping hot entries
  alive
- **LRU**: When full, least recently used entries are evicted first
- **Flush on parent change**: When the local node's tree parent changes, the
  entire cache is flushed. Parent changes mean the node's own coordinates
  have changed, making relative distance calculations with cached coordinates
  potentially invalid. Flushing is preferred over stale routing: the cost of
  re-discovery is lower than routing packets to dead ends.

### Cache and Session Timer Ordering

Timer values are ordered so that idle sessions tear down before transit
caches expire:

| Timer | Default | Purpose |
| ----- | ------- | ------- |
| Session idle | 90s | Session teardown |
| Coordinate cache TTL | 300s | Coordinate expiration |

When traffic stops, the session tears down at 90s. When traffic resumes, a
fresh SessionSetup re-warms transit caches (still within their 300s TTL).

## Discovery Protocol

Discovery resolves a destination's tree coordinates so that multi-hop routing
can proceed.

### When Discovery Is Needed

- First contact with a destination (no cached coordinates)
- After receiving CoordsRequired (transit node lost coordinates)
- After receiving PathBroken (coordinates may be stale)

### LookupRequest

The source creates a LookupRequest containing:

- **request_id**: Unique identifier for deduplication
- **target**: The node_addr being sought
- **origin**: The requester's node_addr
- **origin_coords**: The requester's current tree coordinates (so the
  response can route back)
- **TTL**: Bounds the flood radius

The request floods through the mesh: each node decrements TTL, adds itself
to a visited filter (preventing loops on a single path), and forwards to all
peers not in the visited filter. Bloom filters may help direct the flood
toward likely candidates.

**Deduplication**: Nodes maintain a short-lived request_id dedup cache to
drop convergent duplicates (the same request arriving via different paths).
This is a protocol requirement, not an optimization.

### LookupResponse

When the request reaches the target (or a node that has the target as a
direct peer), a LookupResponse is created containing:

- **request_id**: Echoed from the request
- **target**: The target's node_addr
- **target_coords**: The target's current tree coordinates
- **path_mtu**: Minimum MTU along the response path (transit-annotated,
  initialized to `u16::MAX` by the target)
- **proof**: Signature covering `(request_id || target || target_coords)` —
  authenticates that the response is genuine and the target holds the
  claimed tree position

The response routes back to the requester using reverse-path routing as the
primary mechanism: each transit node looks up the request_id in its
`recent_requests` table to find the peer that forwarded the original request,
and sends the response back through that peer. This ensures the response
follows the same path as the request. Greedy tree routing toward the
origin_coords is used only as a fallback if the reverse-path entry has
expired.

**Proof verification**: The source verifies the Schnorr proof upon receipt,
confirming that the target actually signed the response. The proof covers
`(request_id || target || target_coords)` — coordinates are included because
verification at the source confirms the target holds the claimed position.
The `path_mtu` field is excluded from the proof because it is a transit
annotation modified at each hop.

### Discovery Outcome

On receiving a LookupResponse, the source caches the target's coordinates.
Subsequent routing to that destination can proceed via the normal
`find_next_hop()` priority chain.

If discovery times out (no response), queued packets receive ICMPv6
Destination Unreachable.

## SessionSetup Self-Bootstrapping

SessionSetup is the mechanism that warms transit node coordinate caches
along a path, enabling subsequent data packets to route efficiently.

### How It Works

SessionSetup carries plaintext coordinates (outside the Noise handshake
payload, visible to transit nodes):

- **src_coords**: Source's current tree coordinates
- **dest_coords**: Destination's tree coordinates (learned from discovery)

As the SessionSetup transits each intermediate node:

1. The transit node extracts both coordinate sets
2. Caches `src_addr → src_coords` and `dest_addr → dest_coords` in its
   coordinate cache
3. Forwards the message using the cached destination coordinates

SessionAck returns along the reverse path, carrying both the responder's
and initiator's coordinates and warming caches in the other direction. This
ensures return-path transit nodes can route even when the reverse path
diverges from the forward path (e.g., after tree reconvergence).

### Result

After the handshake completes, the entire forward and reverse paths have
cached coordinates for both endpoints. Subsequent data packets use minimal
headers (no coordinates) and route efficiently through the warmed caches.

## Hybrid Coordinate Warmup (CP + CoordsWarmup)

The CP flag in the FSP common prefix and the standalone CoordsWarmup message
(0x14) together provide a hybrid cache-warming mechanism that complements
SessionSetup. See [fips-session-layer.md](fips-session-layer.md) for the
full warmup strategy.

Transit nodes parse the CP flag from the FSP header and extract source and
destination coordinates from the cleartext section between the header and
ciphertext — no decryption needed. This is the same caching operation
performed for SessionSetup coordinates. CoordsWarmup messages use the same
CP-flag format and are handled identically by transit nodes via the existing
`try_warm_coord_cache()` path.

## Error Recovery

When routing fails, transit nodes signal the source endpoint so it can take
corrective action.

### CoordsRequired

**Trigger**: A transit node receives a SessionDatagram but has no cached
coordinates for the destination. It cannot make a forwarding decision.

**Transit node action**:

1. Create a new SessionDatagram addressed back to the original source,
   carrying a CoordsRequired payload identifying the unreachable destination
2. Route the error via `find_next_hop(src_addr)`
3. If the source is also unreachable, drop silently (no cascading errors)

**Source recovery**:

1. Immediately send a standalone CoordsWarmup (0x14) message to re-warm
   transit caches along the path (rate-limited: at most one per destination
   per configurable interval, default 2s)
2. Reset CP warmup counter — subsequent data packets piggyback coordinates
   when possible, or trigger additional CoordsWarmup messages when
   piggybacking would exceed the transport MTU
3. Initiate discovery (LookupRequest flood) for the destination
4. When discovery completes, warmup counter resets again (covers timing gap)

The crypto session remains active throughout — only routing state is
refreshed.

### PathBroken

**Trigger**: A transit node has cached coordinates for the destination but
no peer is closer to the destination than itself (a local minimum in the
tree distance metric). The cached coordinates may be stale.

**Transit node action**: Same as CoordsRequired — generate error back to
source.

**Source recovery**:

1. Immediately send a standalone CoordsWarmup (0x14) message (rate-limited,
   same per-destination interval as CoordsRequired response)
2. Remove stale coordinates from cache
3. Initiate discovery for the destination
4. Reset CP warmup counter

### MtuExceeded

**Trigger**: A transit node receives a SessionDatagram but the total
packet size exceeds the next-hop link MTU. The packet cannot be forwarded
without fragmentation, which FIPS does not perform at the mesh layer.

**Transit node action**:

1. Create a new SessionDatagram addressed back to the original source,
   carrying an MtuExceeded payload identifying the destination, the
   reporting router, and the bottleneck MTU
2. Route the error via `find_next_hop(src_addr)`
3. Drop the original oversized packet

**Source recovery**: FSP uses the reported bottleneck MTU to adjust its
session-layer path MTU estimate (immediate decrease). The source can then
reduce payload sizes to fit within the discovered path MTU. MtuExceeded is
the reactive complement to the proactive `path_mtu` field in
SessionDatagram and LookupResponse — the proactive field tracks the
minimum MTU along the forward path, while MtuExceeded signals when an
actual packet exceeds the limit.

### Error Signal Rate Limiting

All three error types are rate-limited at transit nodes: maximum one error per
destination per 100ms. This prevents storms during topology changes when many
packets to the same destination hit the same routing failure simultaneously.

At the source side, CoordsWarmup responses to CoordsRequired/PathBroken are
independently rate-limited: at most one standalone CoordsWarmup per destination
per `coords_response_interval_ms` (default 2000ms, configurable). This
prevents amplification where a burst of error signals would generate a
corresponding burst of warmup messages.

Error signals (CoordsRequired, PathBroken, MtuExceeded) are handled
asynchronously outside the packet receive path, allowing the RX loop to
continue processing without blocking on discovery or session repair.

### Error Routing Limitation

Error signals route back to the source using `find_next_hop(src_addr)`. For
steady-state data packets (after the CP warmup window), the
transit node may lack cached coordinates for the source. If so, the error is
silently dropped.

This blind spot is partially addressed by CP warmup: transit
nodes receive source coordinates during the warmup phase. But after warmup
expires and transit caches for the source expire, errors may be lost. The
session idle timeout (90s) limits the window — if traffic stops long enough
for transit caches to fully expire, the session tears down and re-establishment
re-warms the path.

## Cold Start → Warm Cache → Steady State

### Cold Start

A new node or a node reaching a new destination goes through the following
sequence:

1. **DNS resolution** (IPv6 adapter only): Resolve `npub.fips` → populate
   identity cache with NodeAddr + PublicKey
2. **Session initiation attempt**: Fails because no coordinates are cached
   for the destination
3. **Discovery**: LookupRequest floods through the mesh; LookupResponse
   returns the destination's coordinates
4. **Session establishment**: SessionSetup carries coordinates, warming
   transit caches along the path
5. **Warmup**: First N data packets include CP flag, reinforcing transit
   caches

The first packet to a new destination always triggers this sequence. The
packet is queued (bounded) until the session is established.

### Warm Cache

After session establishment and warmup:

- Transit nodes have cached coordinates for both endpoints
- Bloom filters have converged for the destination
- Data packets use minimal headers (no coordinates)
- Routing decisions are fast: bloom candidate selection + distance ranking

### Steady State

In steady state, the mesh is mostly self-maintaining:

- TreeAnnounce gossip keeps the spanning tree current
- FilterAnnounce gossip keeps bloom filters current
- Coordinate caches are refreshed by active routing traffic
- Occasional cache misses trigger CP warmup or discovery, but these
  are rare when traffic is flowing

### Cache Expiry and Recovery

When traffic to a destination stops:

1. **Session idles out** (90s) — session torn down
2. **Coordinate caches expire** (300s) — transit nodes forget coordinates
3. **Bloom filters remain** — they have no TTL, so reachability information
   persists

When traffic resumes:

1. Identity cache: usually still populated (LRU, no TTL)
2. Session: new establishment required (full handshake)
3. Coordinates: discovery may be needed if cache has expired
4. SessionSetup re-warms transit caches on the new path

## Leaf-Only Operation *(future direction)*

Leaf-only operation is a planned optimization for resource-constrained nodes
(sensors, battery-powered devices). Not currently implemented.

### Concept

A leaf-only node connects to a single upstream peer that handles all routing
on its behalf:

- **No bloom filter storage or processing**: The upstream peer includes the
  leaf's identity in its own outbound bloom filters
- **No spanning tree participation**: The leaf does not offer itself as a
  potential parent to other nodes
- **Simplified routing**: All traffic tunnels through the upstream peer
- **Minimal resource usage**: Suitable for ESP32-class devices (~500KB RAM)

### Upstream Peer Responsibilities

The upstream peer:

- Includes the leaf's identity in its outbound bloom filters
- Forwards all traffic addressed to the leaf
- Handles discovery responses on behalf of the leaf
- Maintains the link session with the leaf

### What the Leaf Retains

Even as a leaf-only node, it still:

- Maintains its own Noise IK link session with the upstream peer
- Can establish end-to-end FSP sessions with arbitrary destinations
- Has its own identity (npub, node_addr)

The optimization is purely at the routing/mesh layer — the leaf delegates
routing decisions but retains its own end-to-end encryption and identity.

## Packet Type Summary

| Message | Typical Size | When | Forwarded? |
| ------- | ------------ | ---- | ---------- |
| TreeAnnounce | Variable (depth-dependent) | Topology changes | No (peer-to-peer) |
| FilterAnnounce | ~1 KB | Topology changes | No (peer-to-peer) |
| LookupRequest | ~300 bytes | First contact, recovery | Yes (flood) |
| LookupResponse | ~400 bytes | Response to discovery | Yes (greedy routed) |
| SessionDatagram + SessionSetup | ~232–402 bytes | Session establishment | Yes (routed) |
| SessionDatagram + SessionAck | ~170 bytes | Session confirmation | Yes (routed) |
| SessionDatagram + Data (minimal) | 106 bytes + payload | Bulk traffic | Yes (routed) |
| SessionDatagram + Data (with CP) | 106 + coords + payload | Warmup/recovery | Yes (routed) |
| SessionDatagram + CoordsRequired | 70 bytes | Cache miss error | Yes (routed) |
| SessionDatagram + PathBroken | 70+ bytes | Dead-end error | Yes (routed) |
| Disconnect | 2 bytes | Link teardown | No (peer-to-peer) |

See [fips-wire-formats.md](fips-wire-formats.md) for byte-level layouts.

## Privacy Considerations

Source and destination node_addrs are visible to every transit node (required
for forwarding decisions and error signal routing). FIPS prioritizes
low-latency greedy routing with explicit error signaling over metadata
privacy.

The node_addr is `SHA-256(pubkey)` truncated to 128 bits — a one-way hash.
Transit nodes learn which node_addr pairs are communicating but cannot
determine the actual Nostr identities (npubs) of the endpoints. An observer
can verify "does this node_addr belong to pubkey X?" but cannot enumerate
communicating identities from traffic alone.

Onion routing was considered and rejected because it requires the sender to
know the full path upfront (incompatible with self-organizing routing) and
prevents per-hop error feedback (incompatible with CoordsRequired/PathBroken
recovery).

## Implementation Status

| Feature | Status |
| ------- | ------ |
| Spanning tree formation | **Implemented** |
| TreeAnnounce gossip | **Implemented** |
| Bloom filter computation (split-horizon) | **Implemented** |
| FilterAnnounce gossip | **Implemented** |
| find_next_hop() priority chain | **Implemented** |
| Coordinate cache (unified, TTL + refresh) | **Implemented** |
| Flush coord cache on parent change | **Implemented** |
| LookupRequest/LookupResponse discovery | **Implemented** |
| SessionSetup self-bootstrapping | **Implemented** |
| Hybrid coordinate warmup (CP + CoordsWarmup) | **Implemented** |
| CoordsRequired recovery | **Implemented** |
| PathBroken recovery | **Implemented** |
| MtuExceeded recovery | **Implemented** |
| LookupResponse proof verification | **Implemented** |
| Discovery reverse-path routing | **Implemented** |
| Error signal rate limiting | **Implemented** |
| Leaf-only operation | Future direction |
| Link cost metrics (ETX) | Future direction |
| Discovery path accumulation | Future direction |

## References

- [fips-intro.md](fips-intro.md) — Protocol overview
- [fips-mesh-layer.md](fips-mesh-layer.md) — FMP specification
- [fips-spanning-tree.md](fips-spanning-tree.md) — Tree algorithms and data
  structures
- [fips-bloom-filters.md](fips-bloom-filters.md) — Filter parameters and math
- [fips-wire-formats.md](fips-wire-formats.md) — Wire format reference
- [spanning-tree-dynamics.md](spanning-tree-dynamics.md) — Convergence
  walkthroughs
