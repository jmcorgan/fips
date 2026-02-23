# FIPS Spanning Tree Protocol Dynamics

A detailed study of the gossip-based spanning tree protocol, focusing on
operational behavior under various mesh conditions. This document complements
[fips-intro.md](fips-intro.md) with step-by-step walkthroughs of protocol
dynamics rather than message formats and data structures.

For wire formats, see [fips-wire-formats.md](fips-wire-formats.md) (TreeAnnounce section).
For spanning tree algorithms and data structures, see
[fips-spanning-tree.md](fips-spanning-tree.md). For how the spanning tree fits
into mesh routing, see [fips-mesh-operation.md](fips-mesh-operation.md).

The protocol is based on Yggdrasil v0.5's CRDT gossip design.

## Contents

1. [Core Concepts](#1-core-concepts)
2. [Single Node Startup](#2-single-node-startup)
3. [Node Joining an Existing Network](#3-node-joining-an-existing-network)
4. [Network Convergence](#4-network-convergence)
5. [Topology Changes and Reconvergence](#5-topology-changes-and-reconvergence)
6. [Partition Detection and Handling](#6-partition-detection-and-handling)
7. [Link Failure Detection](#7-link-failure-detection)
8. [Parent Selection](#8-parent-selection)
9. [Steady State Behavior](#9-steady-state-behavior)
10. [Worked Examples](#10-worked-examples)
11. [Known Limitations](#known-limitations)

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

The root is deterministic: the node with the lexicographically smallest node_addr
among all reachable nodes. No explicit election protocol exists—each node
independently derives the same answer from its local TreeState.

---

## 2. Single Node Startup

When a node starts with no peers, it bootstraps as a single-node network.

### Step-by-Step: Isolated Startup

```
Time T0: Node A starts
├── Generates or loads keypair (npub_A, nsec_A)
├── Computes node_addr_A = SHA-256(npub_A)
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

1. **Peer connection**: A new peer triggers gossip exchange (covered in Section 3)

---

## 3. Node Joining an Existing Network

When a new node connects to an existing network, a sequence of gossip exchanges
integrates it into the spanning tree.

### Step-by-Step: Node B Joins via Node A

**Initial state**: Network has nodes A (root), C, D, E. Node B is new.

```
Existing tree structure:
        A (root, smallest node_addr)
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
│   └── Compares node_addr_A vs node_addr_B
│   └── If A < B: Root_B = A (A has smaller node_addr)
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
D adds B's node_addr to its bloom filter
D sends FilterAnnounce to parent A

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
- Any node wanting to reach B does a bloom filter lookup for candidate selection
- Total: 1-2 gossip rounds for B to be locatable

Note: Nodes A, C, E never add B to their TreeState. They can still route to B
by using bloom filter lookup for candidate selection to get B's coordinates,
then coordinate-based greedy routing.

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

1. Elect a single root (determined by smallest node_addr)
2. Form a loop-free tree structure
3. Propagate ancestry information along peer links

**Example: Three nodes connect simultaneously**

```
T0: Nodes A, B, C start isolated
    Each is its own root
    node_addr ordering: A < B < C

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
subtrees. But any node can locate any other node via Bloom-guided candidate
selection and then route using tree coordinate distance.

**Convergence time**: Bounded by tree depth × gossip interval. For a tree of
depth D with gossip interval G:

- Worst case: D × G for root information to propagate to deepest leaf
- Typical case: Faster due to parallel gossip on multiple links

**No coordination required**: Convergence emerges from:

- Deterministic root election (smallest node_addr)
- Deterministic merge rules (highest sequence wins)
- Eventually consistent gossip

### Partial Convergence States

During convergence, the network may temporarily have:

- **Multiple roots**: Different partitions with different root beliefs
- **Inconsistent coordinates**: Nodes computing distances from stale state
- **Routing failures**: Coordinate-based greedy routing may fail until coordinates stabilize

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

**Stability threshold**: To prevent flapping, a node only changes parent when
the improvement exceeds cost-based hysteresis (`parent_hysteresis`, default
0.2 = 20% improvement required). A hold-down timer (`hold_down_secs`,
default 30s) further suppresses non-mandatory re-evaluation after a switch.
See §8 for details.

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
    Partition 2: D ← E (or E ← D, depending on node_addrs)
```

### Partition Detection

Nodes detect they're partitioned when:

1. **Parent unreachable**: Direct link to parent fails
2. **Root unreachable**: No peer has path to current root

**Detection via gossip staleness** (not currently implemented — see
[Known Limitations](#known-limitations)):

In principle, nodes would also detect partitions through root entry staleness:
if no fresh root announcements arrive within a timeout, the root is presumed
departed. This requires tracking root entry timestamps and enforcing expiration,
which is not yet implemented. Currently, only direct parent loss (case 1) and
absence of any peer with a path to root (case 2) trigger partition detection.

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
├── New root = min(node_addr_D, node_addr_E)
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
If partition 2 elected a "temporary" root with a large node_addr, healing is cheap—
that root immediately defers to the global root.

If by chance partition 2's root has a smaller node_addr than partition 1's root,
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

**Typical values** (see [fips-spanning-tree.md](fips-spanning-tree.md) for
current FIPS-specific parameters):

```
peer_timeout: 10-30 seconds
keepalive_interval: peer_timeout / 3
gossip_interval: on topology change (no periodic refresh)
tree_entry_ttl: not currently enforced (see Known Limitations)
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

## 8. Parent Selection

Parent selection determines tree structure and routing efficiency.

### Cost-Based Selection with Effective Depth

The implementation uses cost-weighted depth to balance tree depth against link
quality. Each candidate parent is evaluated by its **effective depth** — the
tree depth plus a local link cost penalty derived from MMP metrics.

**Algorithm** (`TreeState::evaluate_parent()` in `tree/state.rs`):

```
evaluate_parent(peer_costs: HashMap<NodeAddr, f64>):
    // 1. Find smallest root reachable through any peer
    smallest_root = min(peer.root for peer in peers_with_coords)

    if self == smallest_root and is_root:
        return None  // Already root, no change

    // 2. Compute effective depth for each candidate
    for each peer with peer.root == smallest_root:
        link_cost = peer_costs.get(peer) or 1.0  // default optimistic
        peer.effective_depth = peer.depth + link_cost

    best_peer = min(candidates, key=effective_depth, tiebreak=node_addr)

    if best_peer == current_parent:
        return None  // Already using best

    // 3. Mandatory switches — bypass hysteresis and hold-down
    if current_parent not in peers:
        return best_peer  // Parent lost
    if current_root != smallest_root:
        return best_peer  // Better root found

    // 4. Hold-down check — suppress non-mandatory switches
    if last_parent_switch + hold_down > now:
        return None  // Too soon after last switch

    // 5. Hysteresis — require significant improvement
    current_parent_eff = current_parent.depth + peer_costs.get(current_parent)
    if best_eff_depth < current_parent_eff * (1.0 - parent_hysteresis):
        return best_peer

    return None  // Not enough improvement
```

**Parameters**:

```
parent_hysteresis = 0.2    // 20% improvement required for same-root switch
hold_down_secs = 30        // Suppress re-evaluation after parent switch
reeval_interval_secs = 60  // Periodic re-evaluation independent of TreeAnnounce
```

**Link cost formula** (`ActivePeer::link_cost()` in `peer/active.rs`):

```
link_cost = etx * (1.0 + srtt_ms / 100.0)
```

Where ETX (Expected Transmission Count) comes from bidirectional MMP delivery
ratios and SRTT (Smoothed Round-Trip Time) from MMP timestamp-echo. When MMP
metrics have not yet converged, `link_cost` defaults to 1.0, preserving
depth-only behavior as a graceful fallback.

**What this means for tree structure**: The algorithm can prefer a deeper parent
with a better link over a shallower parent with a poor link, when the effective
depth difference is significant enough to overcome hysteresis. For example, a
fiber link at depth 2 (effective depth ≈ 3.01) beats a LoRa link at depth 1
(effective depth ≈ 7.32 with 500ms RTT and 5% loss). In homogeneous networks
where all links have similar quality, effective depth tracks tree depth closely
and the algorithm produces minimum-depth trees as before.

**Periodic re-evaluation**: `evaluate_parent()` is event-driven — called on
TreeAnnounce receipt or parent loss. After the tree stabilizes and TreeAnnounce
traffic stops, link degradation goes undetected. The periodic re-evaluation
timer (`reeval_interval_secs`) calls `evaluate_parent()` from the tick handler
with current MMP link costs, independent of TreeAnnounce traffic.

### Design Rationale: Local-Only Cost Metrics

The original design considered cumulative path costs (OSPF-style, where each
hop adds its link cost and the total is advertised in TreeAnnounce). This
approach was rejected for three independent reasons:

1. **Unverifiable self-reporting**: In a permissionless network, a node can
   claim any path cost. There is no mechanism for neighbors to verify that
   the reported cumulative cost is truthful. A malicious node advertising
   zero cost would attract traffic as a transit node.

2. **No shared metric semantics**: Different links measure different things.
   A LoRa link's 500ms RTT and a fiber link's 1ms RTT are both "round-trip
   time" but represent fundamentally different physical constraints.
   Accumulating them into a single path cost obscures per-hop information
   that is more useful when evaluated locally.

3. **Accumulation amplifies error**: Small measurement noise at each hop
   compounds across the path. A 5-hop path accumulates 5x the measurement
   error of a single hop, while providing no more actionable information
   than the local link cost to each candidate parent.

The local-only approach uses `link_cost = etx * (1.0 + srtt_ms / 100.0)`,
where both components are locally measured via MMP. The RTT weighting
addresses a blind spot in ETX alone: a clean-but-slow link (LoRa with 0%
loss) gets ETX = 1.0, identical to fiber. The SRTT factor distinguishes them
— a 500ms LoRa link gets cost ≈ 6.0 versus fiber at ≈ 1.01.

No wire format changes are required. TreeAnnounce messages continue to carry
depth (not cost), and each node independently evaluates its direct links
using trusted local measurements.

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

- TreeAnnounce messages sent only on topology changes, not periodically
- No periodic root refresh — the tree is maintained purely by change-driven gossip
- In a stable network, gossip traffic drops to zero
- Bandwidth usage proportional to tree depth, not network size

**Consistent coordinates**:

- Every node knows its full path to root
- Distance calculations are accurate
- Coordinate-based greedy routing succeeds

### Steady State Gossip Pattern

```
Normal operation (no topology changes):

Root A: No periodic announcements — announces only if topology changes
        └── Root does not refresh its timestamp periodically

Each node: Sends TreeAnnounce only when its own state changes
           └── Parent change, new peer, or peer departure

Typical gossip per node in steady state:
├── No periodic sends — tree gossip is entirely change-driven
├── Announce on parent selection change
├── Announce on peer link up/down
└── Zero gossip traffic when topology is stable
```

### Expected Steady State Properties

**Gossip volume**:

```
Per topology change event:
├── Own declaration update: ~100 bytes
├── Delta of changed ancestors: varies
└── Total: O(100 bytes) to O(depth * 100 bytes)

In steady state (no topology changes):
├── Zero gossip traffic — no periodic refreshes
├── Traffic resumes only when links change or nodes join/depart
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

1. **Root stability**: Same root over extended period
2. **Parent stability**: No parent changes in recent interval
3. **Sequence number stability**: Sequence numbers increment only on topology changes
4. **Routing success**: Coordinate-based greedy routing doesn't hit local minima

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

node_addr ordering: A < C < B < E < D
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

- A is root
- B, C, D are direct children of A
- E is child of C (one hop to A through C)
- No periodic gossip — TreeAnnounce only on topology changes

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

node_addr ordering: B < A < D < E < C
```

**Local link costs** (using `link_cost = etx * (1.0 + srtt_ms / 100.0)`):

```
Assumed MMP measurements after convergence:
A ═ B: fiber, 1ms RTT, 0% loss  → link_cost = 1.0 * (1 + 1/100)     ≈ 1.01
B ═ D: fiber, 1ms RTT, 0% loss  → link_cost = 1.0 * (1 + 1/100)     ≈ 1.01
D ═ E: fiber, 1ms RTT, 0% loss  → link_cost = 1.0 * (1 + 1/100)     ≈ 1.01
C — D: DSL, 20ms RTT, 2% loss   → link_cost = 1.04 * (1 + 20/100)   ≈ 1.25
A ~ C: radio, 500ms RTT, 5% loss→ link_cost = 1.11 * (1 + 500/100)  ≈ 6.66
```

**Tree formation with effective depth**:

```
Root = B (smallest node_addr, depth 0)

Parent selection (each node evaluates effective_depth = peer.depth + link_cost):
├── A: peers are B (depth 0, cost 1.01 → eff 1.01), C (depth ?, cost 6.66)
│   └── Selects B (lowest effective depth)
│
├── D: peers are B (depth 0, cost 1.01 → eff 1.01),
│      C (depth ?, cost 1.25), E (depth ?, cost 1.01)
│   └── Selects B (direct, lowest effective depth)
│
├── E: peer is D (depth 1, cost 1.01 → eff 2.01)
│   └── Selects D (only candidate)
│
└── C: peers are A (depth 1, cost 6.66 → eff 7.66),
       D (depth 1, cost 1.25 → eff 2.25)
    └── Selects D (eff 2.25 vs 7.66 — much lower)

Resulting tree:
        B (root, depth 0)
       / \
      A   D          (both depth 1)
          |\
          E C        (both depth 2)
```

**Note**: C chooses D despite both being at depth 1 — the DSL link to D
(eff 2.25) far beats the radio link to A (eff 7.66). With local-only costs,
each node evaluates only its direct link quality, not cumulative path cost.

**Radio link failure**:

```
If A ~ C radio fails:
└── No tree impact (C's parent is D, not A)
└── C loses a potential backup path, but current tree unchanged

If D — C DSL fails:
├── C loses parent (mandatory switch — bypasses hysteresis and hold-down)
├── C's only remaining peer is A (radio)
├── C selects A as parent (eff depth = 1 + 6.66 = 7.66)
└── Tree reconverges with C as child of A at depth 2
```

### Example 3: Network Partition and Healing

**Scenario**: Two office sites connected by a single WAN link.

```
Site 1:          WAN link           Site 2:
A ─── B ─────────────────────────── E ─── F
      │                                   │
      C                                   G

node_addr ordering: A < E < B < F < C < G
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
    E compares: node_addr_E < node_addr_F
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
    E learns: A exists, node_addr_A < node_addr_E
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

## Known Limitations

The following limitations exist in the current implementation relative to the
design described in this document. They are documented here to guide future
work.

### Root Timeout Not Enforced

The design specifies a 60-minute root timeout (§6 partition detection) after
which nodes should treat the root as departed and re-elect. The current
implementation does not track root entry timestamps or perform staleness
checks.

**Mitigation**: Heartbeat cascading significantly reduces the practical
impact. When the root disappears, its direct children detect the parent loss
(keepalive timeout), re-elect, and announce new coordinates. This cascades
down the tree — each level's children detect their parent's changed state and
re-evaluate. For the common case of root departure, the tree reconverges
without an explicit root timeout.

**Remaining gap**: If an intermediate node maintains a link to the root but
that link silently stops forwarding (no keepalive failure), nodes below it
would retain stale root state. This is an unusual failure mode — most link
failures are detected by keepalive timeouts. An explicit root timeout would
provide defense-in-depth for this edge case.

### Known Limitation: No TTL on Tree Entries

The design specifies a 5-10 minute TTL on tree entries (§8 timing
parameters). Peer entries in `TreeState` are never expired; they persist until
explicitly removed by peer disconnection.

**Impact**: Stale ancestry information from departed nodes remains in
`TreeState`, potentially affecting coordinate computation. In practice, this
is partially mitigated by parent loss handling, but entries for non-parent
peers that depart without a graceful disconnect will linger.

**Required fix**: Add a `last_seen` timestamp to peer entries in `TreeState`.
In `check_tree_state()`, expire entries older than `tree_entry_ttl`. When
entries expire, re-evaluate parent selection if the expired entry was the
current parent.

### Known Limitation: No Partition Detection

The design describes partition detection via gossip staleness (§6) where
nodes detect isolation when root announcements stop arriving and the root
entry eventually expires, triggering independent partition operation.

**Impact**: Without root timeout enforcement (see above), partitioned nodes
cannot detect that they've lost connectivity to the root. They continue with
stale coordinates rather than forming an independent partition with a local
root. This affects only the case where the path to root is broken at some
intermediate point — direct parent loss is handled correctly.

**Required fix**: Depends on root timeout implementation. Once root timeout
is enforced, partition detection follows naturally: a node whose root entry
expires and has no peer with a fresher root declaration is partitioned. It
becomes its own root and announces, allowing the partition to converge
independently.

### Known Limitation: Remaining Stability Gaps

The primary stability mechanisms are implemented:

- **Cost-based hysteresis** (`parent_hysteresis = 0.2`): requires 20%
  effective depth improvement to switch parents under the same root
- **Hold-down timer** (`hold_down_secs = 30`): suppresses non-mandatory
  re-evaluation after a parent switch, allowing MMP metrics to stabilize
- **Periodic re-evaluation** (`reeval_interval_secs = 60`): catches link
  degradation after tree stabilization independent of TreeAnnounce traffic
- **Flap dampening** (`flap_threshold = 4`, `flap_window_secs = 60`,
  `flap_dampening_secs = 120`): if a node switches parents more than 4
  times within 60s, an extended 120s hold-down is imposed. Mandatory
  switches (parent loss, root change) bypass dampening. The flap counter
  resets when the window expires naturally.

Remaining gaps:

- No sequence number advancement rate limiting
- No minimum stable state duration before re-announcing

**Impact**: These mechanisms compose to bound announcement traffic even
under rapid link flapping. The hold-down timer limits the rate of parent
switches (at most one non-mandatory switch per 30s), flap dampening
catches pathological patterns that persist beyond the hold-down window,
and per-peer rate limiting (500ms) bounds announcement frequency.

### Known Limitation: Integration Test Gaps

Unit tests for `TreeState` and `TreeCoordinate` are comprehensive, and basic
integration tests verify TreeAnnounce exchange and parent ancestry
propagation. However, the following failure scenarios lack test coverage:

- Root node failure and network-wide re-election
- Network partition formation and independent operation
- Partition healing and root convergence
- Stale entry cleanup (depends on TTL implementation)
- Parent flapping under rapid topology changes (flap dampening is
  implemented; integration test coverage is the remaining gap)

These tests are blocked on or related to the limitations above and should be
added as each limitation is resolved.

---

## Summary

The gossip-based spanning tree protocol achieves distributed coordination
through:

1. **Deterministic root election** - Smallest node_addr, no negotiation needed
2. **Cost-aware parent selection** - Each node independently chooses lowest effective depth to root using local link metrics
3. **CRDT merge semantics** - Conflicts resolved by sequence number, then timestamp
4. **Bounded state** - O(peers × depth) entries per node, not O(network size)
5. **Depth-proportional convergence** - Scales with tree height, not node count
6. **Traffic-based failure detection** - No dedicated keepalive overhead
7. **Stability thresholds** - Hysteresis, hold-down, and flap dampening prevent flapping on similar-cost paths

Each node maintains only its own ancestry and direct peer information—not global
topology. Reachability to arbitrary destinations is provided by Bloom-guided
candidate selection (bloom filters propagating up the tree), with coordinate
discovery via lookup protocol and coordinate-based greedy routing for forwarding.

The protocol handles partitions gracefully (independent operation), heals
automatically when connectivity returns, and adapts to heterogeneous link
costs to form efficient tree structures.

---

## References

### FIPS Internal Documentation

- [fips-spanning-tree.md](fips-spanning-tree.md) — Spanning tree algorithms and data structures
- [fips-mesh-operation.md](fips-mesh-operation.md) — How the spanning tree fits into mesh routing
- [fips-wire-formats.md](fips-wire-formats.md) — TreeAnnounce wire format

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
