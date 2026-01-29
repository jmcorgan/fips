# FIPS Spanning Tree Protocol Dynamics

A detailed study of the gossip-based spanning tree protocol, focusing on
operational behavior under various mesh conditions. This document complements
[FIPS-DESIGN.md](FIPS-DESIGN.md) with step-by-step walkthroughs of protocol
dynamics rather than message formats and data structures.

The protocol is based on Yggdrasil v0.5's CRDT gossip design.

## Contents

1. [Core Concepts](#1-core-concepts)
2. [Single Node Startup](#2-single-node-startup)
3. [Node Joining an Existing Network](#3-node-joining-an-existing-network)
4. [Network Convergence](#4-network-convergence)
5. [Topology Changes and Reconvergence](#5-topology-changes-and-reconvergence)
6. [Partition Detection and Handling](#6-partition-detection-and-handling)
7. [Link Failure Detection](#7-link-failure-detection)
8. [Cost Metrics and Parent Selection](#8-cost-metrics-and-parent-selection)
9. [Steady State Behavior](#9-steady-state-behavior)
10. [Worked Examples](#10-worked-examples)

---

## 1. Core Concepts

### The CRDT Approach

The spanning tree is maintained as a distributed soft-state CRDT-Set. Each node
makes independent local decisions about parent selection, gossips these decisions
to peers, and the system converges to a consistent structure without coordination.

Key properties:

- **Consistency**: Two peered nodes eventually have identical views of their
  shared relevant portion of the tree
- **Atomicity**: Updates to a common ancestor are applied atomically across all
  peer records in the local routing table
- **Convergence**: The structure converges in time proportional to tree *depth*,
  not network *size*

### What Each Node Knows (Bounded State)

A node's TreeState contains only:

1. **Its own parent declaration** - who it has selected as parent
2. **Direct peer declarations** - each peer's parent selection
3. **Ancestry of peers** - the chain from each peer up to root

This is **O(P × D)** entries where P is peer count and D is tree depth—not O(N)
where N is network size. A node does *not* know about:

- Other subtrees branching off its ancestors
- Siblings of ancestors
- Nodes in distant parts of the network

This bounded state is sufficient to compute the node's own tree coordinates and
distances to any node whose coordinates it learns (via lookup responses).

**Example**: In a 1000-node network with tree depth 10, a node with 5 peers
maintains roughly 50 TreeState entries, not 1000.

### Root Election

The root is deterministic: the node with the lexicographically smallest node_id
among all reachable nodes. No explicit election protocol exists—each node
independently derives the same answer from its local TreeState.

### Announcement Timing (from Yggdrasil v0.5)

- Root timestamp refresh: every 30 minutes
- Root timeout: 60 minutes without refresh
- Peer keepalive: triggered by data activity, not periodic
- TTL on tree entries: implementation-specific, typically minutes

---

## 2. Single Node Startup

When a node starts with no peers, it bootstraps as a single-node network.

### Step-by-Step: Isolated Startup

```
Time T0: Node A starts
├── Generates or loads keypair (npub_A, nsec_A)
├── Computes node_id_A = SHA-256(npub_A)
├── Initializes empty TreeState
├── Sets parent = self (A is its own root)
├── Sets sequence = 1
└── Records timestamp = now

State after T0:
  TreeState_A = { (A, parent=A, seq=1, ts=T0) }
  Root_A = A
  Coordinate_A = [A]
```

At this point, node A is a fully functional single-node FIPS network. It can:

- Accept incoming peer connections
- Route packets to itself
- Respond to lookups for its own address

### What Triggers State Changes

While isolated, A's state only changes on:

1. **Periodic refresh**: A regenerates its announcement with incremented sequence
   and fresh timestamp (maintains liveness for future peers)
2. **Peer connection**: A new peer triggers gossip exchange (covered in Section 3)

---

## 3. Node Joining an Existing Network

When a new node connects to an existing network, a sequence of gossip exchanges
integrates it into the spanning tree.

### Step-by-Step: Node B Joins via Node A

**Initial state**: Network has nodes A (root), C, D, E. Node B is new.

```
Existing tree structure:
        A (root, smallest node_id)
       /|\
      C D E

B's initial state (before connecting):
  TreeState_B = { (B, parent=B, seq=1) }
  Root_B = B
```

**T1: B establishes link to D**

```
Link established B ←→ D

Immediate actions:
├── B sends TreeAnnounce to D:
│   └── Contains: B's declaration (parent=B, seq=1), B's ancestry (just B)
│
└── D sends TreeAnnounce to B:
    └── Contains: D's declaration (parent=A, seq=47), D's ancestry [D, A]
```

**T2: B processes D's announcement**

```
B receives D's TreeAnnounce:
├── Verifies signature on D's parent declaration
├── Verifies signature on A's self-declaration (from ancestry)
├── Merges into TreeState_B:
│   └── TreeState_B = { (B, parent=B, seq=1), (D, parent=A, seq=47), (A, parent=A, seq=203) }
│
├── Evaluates root:
│   └── Compares node_id_A vs node_id_B
│   └── If A < B: Root_B = A (A has smaller node_id)
│
└── Evaluates parent selection:
    └── Only peer is D
    └── D has path to new root A
    └── B selects D as parent
```

**T3: B updates its declaration**

```
B's state change:
├── parent_B = D (was: B)
├── sequence_B = 2 (incremented)
├── timestamp_B = T3
└── Signs new declaration

TreeState_B = { (B, parent=D, seq=2), (D, parent=A, seq=47), (A, parent=A, seq=203) }
Root_B = A
Coordinate_B = [B, D, A]
```

**T4: B announces to D**

```
B sends TreeAnnounce to D:
└── Contains: B's new declaration (parent=D, seq=2), ancestry [B, D, A]

D receives and merges:
├── TreeState_D now includes B's entry
├── D's coordinate unchanged: [D, A]
└── D can now route to B
```

**T5: D updates its bloom filter**:

```
D adds B's node_id to its bloom filter
D sends BloomUpdate to parent A

A merges D's bloom filter with its view of D's subtree
A now knows "B is reachable through D" (probabilistically)

This bloom filter update propagates toward root.
```

**Important**: D does NOT include B's declaration in TreeAnnounce to A. Tree
gossip only includes the sender's ancestry (path to root), not children. Most
nodes never learn B's declaration—they learn B is *reachable* via bloom filters.

### Convergence Time

B becomes fully routable when:

1. B has full ancestry (immediate, from D's first announcement)
2. B's bloom filter entry propagates toward root (O(depth) hops)

The propagation time is O(tree depth), not O(network size). In the example:

- B's coordinates are known immediately (B computes from D's ancestry)
- B's reachability propagates via bloom filter: D → A (1 hop to root)
- Any node wanting to reach B does a bloom filter lookup
- Total: 1-2 gossip rounds for B to be locatable

Note: Nodes A, C, E never add B to their TreeState. They can still route to B
by using bloom filter lookup to get B's coordinates, then greedy forwarding.

---

## 4. Network Convergence

Convergence is the process by which the spanning tree stabilizes into a
consistent structure. This does *not* mean all nodes have the same TreeState—
each node only knows its own ancestry and peers. Convergence means:

- All nodes agree on the root identity
- Each node has selected a stable parent
- Peered nodes have consistent views of their shared ancestry

### Initial Network Formation

When multiple isolated nodes connect simultaneously, the network must:

1. Elect a single root (determined by smallest node_id)
2. Form a loop-free tree structure
3. Propagate ancestry information along peer links

**Example: Three nodes connect simultaneously**

```
T0: Nodes A, B, C start isolated
    Each is its own root
    node_id ordering: A < B < C

T1: Links form: A ←→ B, B ←→ C

T2: Gossip round 1
    A sends to B: (A, parent=A)
    B sends to A: (B, parent=B)
    B sends to C: (B, parent=B)
    C sends to B: (C, parent=C)

T3: Processing round 1
    B learns A < B, adopts A as root, selects A as parent
    C learns B exists (but B still claims self as root)

T4: Gossip round 2
    B sends to A: (B, parent=A) — B has re-parented
    B sends to C: (B, parent=A), ancestry includes A

T5: Processing round 2
    C learns A (via B's ancestry), A < C
    C adopts A as root, selects B as parent

T6: Gossip round 3
    C sends to B: (C, parent=B)

T7: Converged state
    Root = A
    Tree: A ← B ← C
```

### Convergence Properties

**Consistency guarantee**: After gossip quiesces:

- All nodes agree on the identity of the root
- Each node has a stable parent selection
- Peered nodes have identical views of their shared ancestry (the CRDT property)
- Any two nodes can compute accurate distance via their coordinates

Nodes do *not* have global knowledge—a leaf node knows nothing about distant
subtrees. But any node can locate any other node via bloom filter lookup and
then route using coordinates.

**Convergence time**: Bounded by tree depth × gossip interval. For a tree of
depth D with gossip interval G:

- Worst case: D × G for root information to propagate to deepest leaf
- Typical case: Faster due to parallel gossip on multiple links

**No coordination required**: Convergence emerges from:

- Deterministic root election (smallest node_id)
- Deterministic merge rules (highest sequence wins)
- Eventually consistent gossip

### Partial Convergence States

During convergence, the network may temporarily have:

- **Multiple roots**: Different partitions with different root beliefs
- **Inconsistent coordinates**: Nodes computing distances from stale state
- **Routing failures**: Greedy routing may fail until coordinates stabilize

These are transient. The protocol guarantees eventual convergence, not instant
consistency.

---

## 5. Topology Changes and Reconvergence

When links are added or removed, the spanning tree must adapt. The CRDT design
ensures this happens without coordination.

### Link Addition

Adding a link can:

1. **Provide a better path to root** → parent change
2. **Connect previously separate partitions** → root change
3. **Have no structural effect** → just adds routing option

**Example: Better path discovered**

```
Before: A ← B ← C ← D (linear chain, A is root)
        D's coordinate: [D, C, B, A], depth 3

New link: A ←→ D established

D receives A's announcement directly:
├── A's ancestry: [A] (depth 0)
├── D evaluates: going through A gives depth 1 vs current depth 3
├── If improvement > stability threshold:
│   └── D re-parents to A
│   └── D's new coordinate: [D, A], depth 1

After: A is root
       ├── B (depth 1)
       │   └── C (depth 2)
       └── D (depth 1)
```

### Link Removal

Removing a link can:

1. **Remove parent** → must find new parent
2. **Partition the network** → separate root election
3. **Remove non-parent peer** → minimal impact

**Example: Parent link fails**

```
Before: A ← B ← C, B ← D
        C's parent is B

Link B ←→ C fails:
├── C detects link failure (see Section 7)
├── C's TreeState still contains B's entry (hasn't expired)
├── C has no peers with path to A
├── C becomes its own root temporarily
│
└── If C has other peers:
    └── C may discover path to A through them
    └── C re-parents to best available peer

└── If C is truly isolated:
    └── C remains its own root
    └── C is now a separate single-node network
```

### Reconvergence Dynamics

**Stability threshold**: To prevent flapping, a node only changes parent when:

```
improvement = current_cost - new_cost
if improvement > stability_threshold:
    change_parent()
```

This hysteresis prevents oscillation when two paths have similar costs.

**Sequence number advancement**: Each parent change increments the sequence
number. Nodes observing rapid sequence increases can detect instability and
may apply damping.

**Announcement suppression**: A node doesn't immediately announce every
transient state. Brief instability may resolve before announcement, reducing
gossip noise.

---

## 6. Partition Detection and Handling

Network partitions create isolated segments that must operate independently.

### How Partitions Form

A partition occurs when there's no path between two sets of nodes:

```
Before:
    A ← B ← C ← D ← E
    (A is root)

Link C ←→ D fails:

After:
    Partition 1: A ← B ← C
    Partition 2: D ← E (or E ← D, depending on node_ids)
```

### Partition Detection

Nodes detect they're partitioned when:

1. **Parent unreachable**: Direct link to parent fails
2. **Root unreachable**: No peer has path to current root
3. **Stale root timestamp**: Root's announcement exceeds timeout (60 min)

**Detection via gossip staleness**:

```
For each entry in TreeState:
    if now - entry.timestamp > TTL:
        expire(entry)

If root entry expires:
    re-evaluate root from remaining entries
```

### Independent Operation

Each partition operates as an independent network:

```
Partition 1 (nodes A, B, C):
├── Root = A (unchanged, A still reachable)
├── Tree structure unchanged
└── Routing works within partition

Partition 2 (nodes D, E):
├── Previous root A is unreachable
├── D and E exchange announcements
├── New root = min(node_id_D, node_id_E)
├── Tree forms between D and E
└── Routing works within partition
```

### Partition Healing

When connectivity is restored:

```
Link C ←→ D restored:

T1: C and D exchange TreeAnnounce
    C sends: root=A, ancestry [C, B, A]
    D sends: root=D (assuming D < E), ancestry [D]

T2: D processes C's announcement
    D learns about A
    If A < D: D adopts A as new root
    D selects C as parent (path to A)

T3: D announces to E
    E learns about A through D's new ancestry
    E re-evaluates and re-parents if needed

T4: Merged network
    Single root (A)
    All nodes reachable via unified tree structure
    (Each node still only knows its own ancestry, not global topology)
```

### Root Stability Across Partitions

A key design consideration: the root should be stable to minimize reconvergence.
If partition 2 elected a "temporary" root with a large node_id, healing is cheap—
that root immediately defers to the global root.

If by chance partition 2's root has a smaller node_id than partition 1's root,
healing causes partition 1 to reconverge to the new global root.

---

## 7. Link Failure Detection

Detecting failed links is critical for timely reconvergence.

### Detection Mechanisms

**Traffic-based detection** (Yggdrasil v0.5 approach):

```
On sending data to peer:
    set read_deadline = now + peer_timeout

On receiving data from peer:
    clear read_deadline

On deadline expiration:
    mark link as failed
    remove peer from active peers
    trigger reconvergence if peer was parent
```

This avoids dedicated keepalive traffic—normal protocol messages serve as
implicit heartbeats.

**Explicit keepalive** (for idle links):

```
If no traffic sent to peer in keepalive_interval:
    send Dummy message (type 0x00)
    expect acknowledgment within peer_timeout
```

### Failure Response

When a link failure is detected:

```
link_failed(peer):
    remove peer from active_peers

    if peer == current_parent:
        // Critical: lost path to root
        select_new_parent()
        if no_valid_parent_available:
            become_own_root()
        announce_to_all_peers()
    else:
        // Non-critical: lost a potential route
        // TreeState entries for peer will expire naturally
        // May trigger parent re-evaluation if peer was better path
```

### Timing Considerations

**Fast detection vs. stability tradeoff**:

- Short timeout: Quick failure detection, but transient issues cause flapping
- Long timeout: Stable under jitter, but slow to respond to real failures

**Typical values**:

```
peer_timeout: 10-30 seconds
keepalive_interval: peer_timeout / 3
gossip_interval: 1-5 seconds (or on-change)
tree_entry_ttl: 5-10 minutes
root_timeout: 60 minutes
```

### Asymmetric Failures

Links may fail asymmetrically (A can send to B, but not receive):

```
A → B: working
B → A: failed

B detects: no responses from A, marks link failed
A doesn't detect: still receiving from B

Resolution:
├── B stops sending to A
├── A eventually times out waiting for B's traffic
├── Both sides converge to "link failed" state
```

The protocol handles this through bidirectional timeout—both sides must
see traffic to consider the link alive.

---

## 8. Cost Metrics and Parent Selection

Parent selection determines tree structure and routing efficiency.

### Cost Components

**Latency** (primary metric):

```
cost_latency = round_trip_time_ms
```

Measured via protocol message exchange timing. Lower is better.

**Packet loss** (reliability):

```
cost_loss = 1 / (1 - loss_rate)
```

Transforms loss rate into multiplicative cost. 10% loss → cost 1.11, 50% loss → cost 2.

**Bandwidth** (capacity):

```
cost_bandwidth = reference_bandwidth / actual_bandwidth
```

Normalizes bandwidth to a reference value. Lower capacity → higher cost.

### Combined Cost

A weighted combination:

```
effective_cost = w_latency * cost_latency
               + w_loss * cost_loss
               + w_bandwidth * cost_bandwidth
```

Weights depend on application priorities. Real-time traffic weights latency
heavily; bulk transfer weights bandwidth heavily.

### Path Cost to Root

The cost to reach the root through a peer:

```
path_cost(peer) = link_cost(self, peer) + peer.path_cost_to_root
```

This is recursive—each node advertises its path cost to root, allowing
neighbors to compute their total path cost through that peer.

### Parent Selection Algorithm

```
select_parent():
    candidates = [p for p in peers if p.has_path_to_root]

    if not candidates:
        return self  // Become own root

    best = min(candidates, key=lambda p: path_cost(p))

    if current_parent is not None:
        current_cost = path_cost(current_parent)
        new_cost = path_cost(best)
        improvement = current_cost - new_cost

        if improvement < stability_threshold:
            return current_parent  // Stay with current

    return best
```

### Stability Threshold

Prevents flapping when paths have similar costs:

```
stability_threshold = base_threshold + current_cost * relative_threshold

Example:
    base_threshold = 5ms
    relative_threshold = 0.1 (10%)
    current_cost = 50ms

    threshold = 5 + 50 * 0.1 = 10ms

    New path must be >10ms better to trigger switch
```

### Cost Measurement

**Active probing**:

```
Every probe_interval:
    for peer in peers:
        send_probe(peer)
        record_send_time()

On probe_response:
    rtt = now - send_time
    update_latency_estimate(peer, rtt)
```

**Passive observation**:

```
On protocol_message_exchange:
    infer_rtt_from_request_response_timing()

On packet_loss_detected:
    update_loss_estimate()
```

**Exponential smoothing**:

```
estimate = alpha * new_sample + (1 - alpha) * estimate

alpha = 0.1-0.3 typical (higher = more responsive, less stable)
```

---

## 9. Steady State Behavior

Once converged, what does the network look like and how does it behave?

### Characteristics of Steady State

**Stable tree structure**:

- Single agreed-upon root
- Each node has exactly one parent
- No loops exist
- All nodes reachable from root

**Quiescent gossip**:

- Announcements only on periodic refresh (every few minutes)
- Delta encoding minimizes redundant information
- Bandwidth usage proportional to tree depth, not network size

**Consistent coordinates**:

- Every node knows its full path to root
- Distance calculations are accurate
- Greedy routing succeeds

### Steady State Gossip Pattern

```
Normal operation (no topology changes):

Root A: Refreshes timestamp every 30 minutes
        └── Gossips refresh to children

Each node: Forwards root's refresh when received
           └── Only sends if peer's view is stale

Typical gossip per node:
├── Receive refresh from parent (periodic)
├── Forward to children if needed
├── Send own refresh periodically (separate from root's)
└── No gossip if nothing changed and peer is up-to-date
```

### Expected Steady State Properties

**Gossip volume**:

```
Per link, per refresh cycle:
├── Root timestamp update: ~100 bytes
├── Own declaration (if changed): ~100 bytes
├── Delta of changed ancestors: varies
└── Total: O(100 bytes) to O(depth * 100 bytes)

For 1000-node network with depth ~10:
├── Each node sends O(1 KB) per refresh cycle
├── With 30-minute refresh: ~0.5 bytes/second per link
└── Negligible compared to application traffic
```

**Memory usage**:

```
Per node TreeState:
├── Own entry: ~100 bytes
├── Direct peers: ~100 bytes each
├── Ancestry entries: ~100 bytes each, O(depth) per peer
└── Total: O(peers * depth * 100 bytes)

For node with 5 peers, depth 10:
└── ~5 KB of tree state
```

**CPU usage**:

```
Per gossip message received:
├── Signature verification: O(ancestry_length)
├── TreeState merge: O(ancestry_length)
├── Parent re-evaluation: O(peers)
└── Total: O(peers + depth) per message

In steady state with infrequent updates:
└── Negligible CPU overhead
```

### Monitoring Steady State

Indicators the network has converged:

1. **Root stability**: Same root for multiple refresh cycles
2. **Parent stability**: No parent changes in recent interval
3. **Sequence number stability**: Sequence numbers increment slowly (refresh only)
4. **Routing success**: Greedy routing doesn't hit local minima

Warning signs of instability:

1. **Rapid sequence increments**: Node is flapping parents
2. **Multiple roots visible**: Partitions exist
3. **Stale entries**: Gossip isn't propagating
4. **Frequent path-broken**: Tree structure is inconsistent with reality

---

## 10. Worked Examples

### Example 1: Small Office Network

**Scenario**: Five nodes (A-E) in an office. A is the router with internet,
B-E are workstations. All connected via ethernet switch.

```
Physical topology (full mesh via switch):
    A ──── B
    │╲   ╱│
    │ ╲ ╱ │
    │  ╳  │
    │ ╱ ╲ │
    │╱   ╲│
    D ──── C ──── E

node_id ordering: A < C < B < E < D
```

**Tree formation**:

```
T0: All nodes start, each is own root

T1: Links established (all pairs discover each other)

T2: Gossip exchange
    Nodes learn about A through peer announcements
    B, C, D select A as parent (direct link)
    E learns about A via peers' ancestry

T3: Converged tree (assuming equal link costs):
        A (root)
       /│\
      B C D
        │
        E

    E selects C as parent (or any direct peer with path to A)
```

**Steady state**:

- A is root, refreshes every 30 min
- B, C, D are direct children of A
- E is child of C (one hop to A through C)
- Gossip: Each refresh cycle propagates through 2 levels

**Link failure scenario**:

```
Link A ←→ C fails:

T1: C detects (no traffic from A, deadline expires)
    C's current TreeState still has A as root (not expired)
    C has peers B, D, E (assuming full connectivity)

T2: C queries peers for path to A
    B and D both have direct path to A
    C selects B or D as new parent (based on cost)

T3: C announces new parent to all peers
    E receives, E's path to root now goes C → B → A (or C → D → A)

T4: Reconverged tree (if C selected B):
        A (root)
       /│
      B D
      │
      C
      │
      E
```

### Example 2: Mesh Network with Constrained Links

**Scenario**: Rural network with mixed connectivity. Some high-bandwidth
internet links, some low-bandwidth radio links.

```
Physical topology:
    A ═══════ B         (═══ = fiber, 1 Gbps)
    │         ║
    │(radio)  ║(fiber)
    │ 9600bps ║
    │         ║
    C ─────── D ═══════ E
      (DSL)     (fiber)
      1 Mbps

node_id ordering: B < A < D < E < C
```

**Cost calculation** (using bandwidth as primary):

```
Link costs (normalized to 1 Gbps = 1):
A ═ B: cost = 1
B ═ D: cost = 1
D ═ E: cost = 1
C — D: cost = 1000 (1 Mbps)
A ~ C: cost = 100000 (9600 bps)
```

**Tree formation with costs**:

```
Root = B (smallest node_id)

Parent selection:
├── A: peers are B (cost 1), C (cost 100000)
│   └── Selects B (much lower cost)
│
├── D: peers are B (cost 1), C (cost 1000), E (cost 1)
│   └── Selects B (direct, cost 1)
│
├── E: peer is D
│   └── Path to B: E → D → B, cost = 1 + 1 = 2
│   └── Selects D
│
└── C: peers are A (cost 100000), D (cost 1000)
    └── Path through A: 100000 + 1 = 100001
    └── Path through D: 1000 + 1 = 1001
    └── Selects D (much lower cost despite higher local cost)

Resulting tree:
        B (root)
       / \
      A   D
          |\
          E C
```

**Note**: C chooses D despite A being "closer" in hops, because total path
cost through D is lower.

**Radio link failure**:

```
If A ~ C radio fails:
└── No tree impact (C's parent is D, not A)
└── C loses a potential backup path, but current tree unchanged

If D — C DSL fails:
├── C loses parent
├── C's only remaining peer is A (radio)
├── C selects A as parent
├── C's path to root: C → A → B (cost 100001)
└── Tree reconverges with C as child of A
```

### Example 3: Network Partition and Healing

**Scenario**: Two office sites connected by a single WAN link.

```
Site 1:          WAN link           Site 2:
A ─── B ─────────────────────────── E ─── F
      │                                   │
      C                                   G

node_id ordering: A < E < B < F < C < G
```

**Normal operation**:

```
Root = A (global smallest)
Tree:
    A
    └── B
        ├── C
        └── E (via WAN)
            └── F
                └── G
```

**Partition (WAN fails)**:

```
T1: B ←→ E link fails
    B detects: E unreachable
    E detects: B unreachable

T2: Site 1 state:
    Root = A (still reachable)
    Tree unchanged for A, B, C
    E's entry in B's TreeState expires

T3: Site 2 state:
    E loses path to A
    E evaluates remaining peers: F
    F has no path to A either
    E compares: node_id_E < node_id_F
    E becomes new root for Site 2

T4: Site 2 reconverges:
    E (root)
    └── F
        └── G

Network is now two separate trees with roots A and E.
```

**Partition heals**:

```
T5: WAN link restored
    B ←→ E exchange announcements

T6: E receives B's announcement:
    B's ancestry: [A, B]
    E learns: A exists, node_id_A < node_id_E
    E adopts A as root
    E selects B as parent

T7: E announces to F:
    E's new ancestry: [E, B, A]
    F learns about A
    F re-parents (E is still valid parent, now with path to A)

T8: F announces to G:
    Similar propagation

T9: Merged network:
    A (root)
    └── B
        ├── C
        └── E
            └── F
                └── G
```

**Convergence time**: 4 gossip rounds (depth of Site 2's subtree is 3, plus
initial exchange).

---

## Summary

The gossip-based spanning tree protocol achieves distributed coordination
through:

1. **Deterministic root election** - Smallest node_id, no negotiation needed
2. **Local parent selection** - Each node independently chooses best path to root
3. **CRDT merge semantics** - Conflicts resolved by sequence number, then timestamp
4. **Bounded state** - O(peers × depth) entries per node, not O(network size)
5. **Depth-proportional convergence** - Scales with tree height, not node count
6. **Traffic-based failure detection** - No dedicated keepalive overhead
7. **Stability thresholds** - Hysteresis prevents flapping on similar-cost paths

Each node maintains only its own ancestry and direct peer information—not global
topology. Reachability to arbitrary destinations is provided by bloom filters
propagating up the tree, with coordinate discovery via lookup protocol.

The protocol handles partitions gracefully (independent operation), heals
automatically when connectivity returns, and adapts to heterogeneous link
costs to form efficient tree structures.

---

## References

### Yggdrasil Documentation

- [Yggdrasil v0.5 Release Notes](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html)
- [Ironwood Routing Library](https://github.com/Arceliar/ironwood)
- [The World Tree (Yggdrasil Blog)](https://yggdrasil-network.github.io/2018/07/17/world-tree.html)
- [Yggdrasil Implementation Overview](https://yggdrasil-network.github.io/implementation.html)

### Academic Foundations

#### Virtual Coordinate Routing

- Rao, A., Ratnasamy, S., Papadimitriou, C., Shenker, S., Stoica, I.
  ["Geographic Routing without Location Information"](https://people.eecs.berkeley.edu/~sylvia/papers/p327-rao.pdf).
  MobiCom 2003. *Established virtual coordinate routing using network topology.*

#### Greedy Embedding Theory

- Kleinberg, R.
  ["Geographic Routing Using Hyperbolic Space"](https://www.semanticscholar.org/paper/Geographic-Routing-Using-Hyperbolic-Space-Kleinberg/f506b2ddb142d2ec539400297ba53383d958abef).
  IEEE INFOCOM 2007. *Proved every connected graph has a greedy embedding in
  hyperbolic space; showed spanning trees enable coordinate assignment.*

- Cvetkovski, A., Crovella, M.
  ["Hyperbolic Embedding and Routing for Dynamic Graphs"](https://www.cs.bu.edu/faculty/crovella/paper-archive/infocom09-hyperbolic.pdf).
  IEEE INFOCOM 2009. *Dynamic embedding for nodes joining/leaving; introduced
  Gravity-Pressure routing for failure recovery.*

- Crovella, M. et al.
  ["On the Choice of a Spanning Tree for Greedy Embedding"](https://www.cs.bu.edu/faculty/crovella/paper-archive/networking-science13.pdf).
  Networking Science 2013. *Analysis of how tree structure affects routing stretch.*

- Bläsius, T. et al.
  ["Hyperbolic Embeddings for Near-Optimal Greedy Routing"](https://dl.acm.org/doi/10.1145/3381751).
  ACM Journal of Experimental Algorithmics 2020. *Achieved 100% success ratio
  with 6% stretch on Internet graph.*

#### Distributed Systems Primitives

- Shapiro, M., Preguiça, N., Baquero, C., Zawirski, M.
  "Conflict-free Replicated Data Types". SSS 2011.
  *Formal definition of CRDTs enabling coordination-free consistency.*

- Das, A., Gupta, I., Motivala, A.
  ["SWIM: Scalable Weakly-consistent Infection-style Process Group Membership"](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf).
  IPDPS 2002. *O(1) failure detection, O(log N) dissemination via gossip.*

- Kermarrec, A-M.
  ["Gossiping in Distributed Systems"](https://www.distributed-systems.net/my-data/papers/2007.osr.pdf).
  ACM SIGOPS Operating Systems Review 2007. *Framework for gossip-based
  protocols achieving O(log N) propagation.*
