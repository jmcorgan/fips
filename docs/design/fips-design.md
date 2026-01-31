# FIPS: Federated Interoperable Peering System

A distributed, decentralized network routing protocol for mesh nodes connecting
over arbitrary transports. Inspired by [Yggdrasil v0.5](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html)
but adapted for the Nostr ecosystem with multi-transport flexibility.

## Design Goals

1. **Nostr-native identity** - Use Nostr keypairs as node identities
2. **Transport agnostic** - Support IP, wireless, serial, onion, and other link types
3. **Self-organizing** - Automatic topology discovery and route optimization
4. **Privacy preserving** - Minimize metadata leakage across untrusted links
5. **Resilient** - Self-healing with graceful degradation
6. **Reuse Nostr primitives** - Leverage cryptographic primitives already in use in
   the Nostr ecosystem (secp256k1, Schnorr signatures, SHA-256) to simplify
   implementation and reduce dependency surface

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│              (Nostr clients, services, bridges)              │
├─────────────────────────────────────────────────────────────┤
│                      FIPS Router                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Identity   │  │  Spanning   │  │   Bloom Filter      │  │
│  │  (npub)     │  │    Tree     │  │   Routing Table     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  Transport Abstraction                       │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐    │
│  │  TCP   │ │  QUIC  │ │ Radio  │ │ Serial │ │ Onion  │    │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Identity System

### Node Identity

FIPS uses Nostr keypairs (secp256k1) directly as node identities. There is no need
for the clustering properties that Yggdrasil's Ed25519 bit-inversion scheme provides;
the spanning tree handles all routing structure.

Node addresses use an IPv6-compatible format to facilitate reuse of applications
designed for IP transports (e.g., binding to a FIPS address via a TUN interface).
This does not imply that peering over existing IPv4 or IPv6 networks is required—FIPS
supports arbitrary transports including radio, serial, and other non-IP links.
Nonetheless, it is anticipated that the majority of FIPS peers will connect via
the public Internet.

### Node ID and Address Derivation

```text
nostr_npub (secp256k1 x-only, 32 bytes)
    │
    ▼ SHA-256
node_id (32 bytes)
    │
    ▼ Truncate with prefix
fips_address (128 bits)
```

The full 32-byte `node_id` is used in protocol messages and bloom filters.
The truncated 128-bit address is used for IPv6 compatibility.

**Why hash the npub?** Secp256k1 public keys can be "ground" to achieve specific
prefixes more efficiently than brute force via modular addition (adding a known
value to the private key shifts the public key predictably). Hashing eliminates
this shortcut—targeting a specific node_id prefix requires full brute force
against SHA-256, making node ID grinding as expensive as the hash strength allows.

**Separation of concerns**: The nsec/npub keypair is used exclusively for
cryptographic operations (signing protocol messages, identity verification,
end-to-end encryption). The node_id derived from the npub is used only for
routing network traffic. This separation keeps cryptographic material out of
routing tables and packet headers.

### Address Format

FIPS addresses use the IPv6 Unique Local Address (ULA) prefix `fd00::/8`. This
provides 120 bits for the node_id hash while avoiding conflicts with global
unicast addresses that may be in use on underlying IPv6 transports.

```text
FIPS Address (128 bits):
┌────────┬────────────────────────────────────────────────────┐
│  0xfd  │  node_id[0:15]                                     │
│ 8 bits │  120 bits                                          │
└────────┴────────────────────────────────────────────────────┘
```

FIPS addresses are overlay identifiers, not routable IPv6 addresses. They never
appear in IPv6 headers on the underlying transport; the `fd` prefix simply ensures
no collision with addresses that may be legitimately in use on that transport.

### Identity Verification

FIPS uses two complementary signing mechanisms:

**General signing** is used for protocol messages (TreeAnnounce, LookupResponse,
etc.) where the signer is asserting authorship of data:

```text
signature = schnorr_sign(nsec, SHA256(message))
```

**Challenge-response authentication** is used during connection establishment
to prove a node controls the private key corresponding to its claimed npub.

### Peer Authentication Protocol

When two nodes establish a connection, they perform mutual authentication to
verify each other's identity. This prevents impersonation attacks where an
adversary claims to be a node it doesn't control.

> **Note**: This authentication protocol is not derived from Yggdrasil, which
> relies on transport-layer security (TLS/QUIC) for identity binding. FIPS
> requires an explicit application-layer protocol because it supports transports
> without built-in encryption or key exchange (radio links, serial connections).
> For initial implementation, peer authentication is always performed regardless
> of transport capabilities; this may be optimized in future versions.
>
> **Terminology note**: *Peer authentication* (this section) is hop-by-hop—it
> verifies that a direct peer is who they claim to be. This is distinct from
> *crypto sessions* (see [fips-protocol-flow.md](fips-protocol-flow.md) §6),
> which provide end-to-end authenticated encryption between source and
> destination using Noise KK. Both layers are necessary: peer auth secures the
> local link; crypto sessions secure the full path.

```text
Initiator (A)                                  Responder (B)
     │                                              │
     │───── AuthInit { a_npub, nonce_a } ─────────►│
     │                                              │
     │◄──── AuthChallenge { b_npub, nonce_b,       │
     │          sig_b(nonce_a | a_npub) } ─────────│
     │                                              │
     │───── AuthComplete {                          │
     │          sig_a(nonce_b | b_npub) } ────────►│
     │                                              │
   [A verifies B after msg 2]          [B verifies A after msg 3]
     │                                              │
     ▼                                              ▼
   Authenticated                              Authenticated
```

**Protocol flow:**

1. **AuthInit**: Initiator sends its npub and a 32-byte random nonce
2. **AuthChallenge**: Responder sends its npub, its own nonce, and a signature
   proving it controls its nsec (signing the initiator's nonce and npub)
3. **AuthComplete**: Initiator sends a signature proving it controls its nsec
   (signing the responder's nonce and npub)

After message 2, the initiator can verify the responder's identity. After
message 3, the responder can verify the initiator's identity. Both nodes have
now proven they control their claimed private keys.

### Crossing Connection Handling

When both nodes have each other as static peers, both may initiate authentication
simultaneously ("crossing hellos"). This is resolved using deterministic
tie-breaking based on npub ordering:

```text
A (lower npub)                             B (higher npub)
     │                                           │
     │─── AuthInit { a_npub, nonce_a } ────────►│
     │◄── AuthInit { b_npub, nonce_b } ─────────│  (crossing)
     │                                           │
  A < B: ignore B's init,               B > A: switch to responder,
  wait for challenge                    send AuthChallenge
     │                                           │
     │◄── AuthChallenge { b_npub, ... } ────────│
     │─── AuthComplete { ... } ────────────────►│
     │                                           │
     ▼                                           ▼
  Authenticated                            Authenticated
```

**Rules:**

- If a node receives AuthInit while its own AuthInit is pending to the same peer:
  - If local npub < remote npub: Continue as initiator, ignore incoming AuthInit
  - If local npub > remote npub: Abort own initiation, switch to responder role

This ensures exactly one handshake completes with minimal wasted effort.

### Authentication Message Structures

```rust
struct AuthInit {
    npub: [u8; 32],      // Initiator's public key (x-only)
    nonce: [u8; 32],     // Random challenge
}

struct AuthChallenge {
    npub: [u8; 32],      // Responder's public key (x-only)
    nonce: [u8; 32],     // Responder's challenge
    signature: [u8; 64], // sig(initiator_nonce || initiator_npub)
}

struct AuthComplete {
    signature: [u8; 64], // sig(responder_nonce || responder_npub)
}
```

### Signature Construction

Signatures are constructed with domain separation to prevent cross-protocol
signature reuse:

```text
digest = SHA256("fips-peer-auth-v1" || peer_nonce || peer_npub)
signature = schnorr_sign(nsec, digest)
```

**Domain separation**: The `"fips-peer-auth-v1"` prefix ensures that signatures
created for FIPS peer authentication cannot be replayed in other contexts (e.g.,
a Nostr event signature or FIPS crypto session). If the authentication protocol
is revised, the version string changes (e.g., `"fips-peer-auth-v2"`).

**Nonce freshness**: The 32-byte random nonce from the peer ensures that
signatures cannot be pre-computed. Each authentication attempt requires a
fresh signature over the peer's unique challenge.

**Binding to peer identity**: The signature includes the peer's npub, binding
the response to that specific peer. This prevents relay attacks where an
adversary forwards a challenge from one node and uses the response with another.

### Authentication Failure Handling

If authentication fails at any step:

- **Invalid signature**: Connection is terminated immediately
- **Wrong npub**: The node is not who it claimed to be; terminate
- **Expired timestamp**: Possible replay attack; terminate
- **Timeout**: Peer did not respond in time; terminate

Nodes should implement rate limiting on authentication attempts to prevent
denial-of-service attacks that exhaust computational resources through
repeated signature verifications.

### Post-Authentication State

After successful authentication, each node stores:

- The peer's verified npub and derived node_id
- The link over which the peer was authenticated
- Timestamp of successful authentication

This state is used for:

- Routing decisions (only forward to authenticated peers)
- TreeAnnounce signature verification (cached public key lookup)
- Session resumption on transient disconnections (within a timeout window)

---

## 2. Spanning Tree Protocol

### Background

A spanning tree is a subgraph of a mesh network that includes all nodes but
contains no cycles. It has the following properties:

- **Unique paths**: Exactly one path exists between any two nodes
- **N-1 edges**: A spanning tree with N nodes has exactly N-1 edges
- **Minimal connectivity**: Removing any edge disconnects the tree

A *minimum* spanning tree optimizes for some metric across all edges—typically
minimizing total cost, latency, or hop count. In FIPS, parent selection considers
link quality metrics, causing the tree to approximate a minimum spanning tree
with respect to those metrics.

In a distributed system, nodes construct a spanning tree by each selecting a
single parent. The result is a rooted tree where every node can reach every
other node by traversing toward their lowest common ancestor.

### Purpose

The spanning tree provides the routing backbone for FIPS. Unlike traditional
routing protocols that require global routing tables or centralized coordination,
the spanning tree creates a distributed structure that enables:

- **Destination lookup**: Finding the current location of any node by its node_id
- **Greedy forwarding**: Routing packets toward their destination without source routes
- **Multicast scope**: Limiting lookup broadcasts to relevant subtrees via bloom filters

### Design Criteria

1. **Minimal state**: Each node maintains only its parent selection and immediate
   peer information, not global topology
2. **Rapid convergence**: Topology changes propagate quickly through gossip
3. **Partition tolerance**: Isolated network segments form independent trees that
   merge when connectivity is restored
4. **Transport-aware**: Parent selection considers link quality, not just reachability
5. **Byzantine tolerance**: Malicious nodes cannot claim arbitrary tree positions
   without valid signatures

### Relationship to Yggdrasil

The spanning tree protocol is based on concepts proven in Yggdrasil v0.5 / Ironwood.
Deviations from that design are noted where applicable.

### Tree State

The spanning tree is maintained as a distributed data structure with CRDT
(Conflict-free Replicated Data Type) semantics. This provides eventual consistency
without requiring coordination: nodes can make local decisions about parent
selection, gossip updates to peers, and the system converges to a consistent
global view.

Each node selects exactly one parent (or itself if it believes it is root) and
has zero or more peers (direct connections over any transport). Through gossip,
each node learns about other nodes' parent selections, building a local view of
the tree.

Each peer's TreeAnnounce message includes its full ancestry—the chain of parent
selections from that peer up to the root. This means a node's TreeState contains:

- **Direct peers**: Their parent selections received directly
- **Ancestors of peers**: Every node on the path from each peer to the root

This ancestry information is essential for computing tree coordinates and the
distance metric used in greedy routing.

```text
TreeState = {
    (node_id, parent_id, sequence, signature, timestamp),
    (node_id, parent_id, sequence, signature, timestamp),
    ...
}
```

**Generating announcements**: A node generates a new TreeAnnounce when:

- It selects a new parent (including initial startup)
- A periodic refresh interval expires (to maintain liveness)
- It detects its parent has become unreachable

Each announcement contains the node's current parent selection, an incremented
sequence number, a timestamp, and a Schnorr signature over these fields. The
announcement also includes the node's full ancestry—the chain of parent
declarations from itself up to the current root.

**Processing received announcements**: When a node receives a TreeAnnounce from
a peer, it:

1. Verifies the signature on the sender's parent declaration
2. Verifies signatures on each entry in the ancestry chain
3. Validates that the ancestry forms a coherent path to a valid root
4. Merges each entry into its local TreeState

**Merge rules**: When merging an entry for a given node_id:

- Higher sequence number always wins
- On sequence tie, prefer the entry with the later timestamp
- On both tie, prefer lexicographically smaller parent_id (deterministic)
- Entries not refreshed within the TTL are expired and removed

These rules ensure all nodes converge to the same TreeState view despite
receiving updates in different orders.

### Root Election

The root of the spanning tree is the node with the lexicographically smallest
node_id among all nodes a given node can reach. This election is deterministic
and requires no explicit coordination—each node independently arrives at the
same conclusion from its local TreeState.

**Startup behavior**: A newly joined node initially considers itself the root
(parent = self). As it receives TreeAnnounce messages from peers, it discovers
nodes with smaller node_ids and adopts a new parent whose ancestry leads to
the smallest known node_id.

**Partition behavior**: If the network partitions, each isolated segment elects
its own root (the smallest node_id within that segment). When partitions merge,
nodes in the segment with the larger root discover the globally smaller root
and re-parent accordingly. The tree reconverges automatically.

### Parent Selection

Each node selects a parent that provides the best path to the current root,
considering both reachability and link quality. The parent must be a direct
peer—nodes cannot select non-peers as parents.

**Stability mechanism**: To prevent flapping during minor topology changes, a
node only changes its parent if the improvement exceeds a threshold. This
hysteresis ensures the tree remains stable under transient conditions.

**Selection criteria**:

1. The candidate parent must have a path to the current root
2. Among valid candidates, prefer the one with lowest effective cost
3. Only switch if the improvement exceeds the stability threshold

### Tree Coordinates

A node's coordinate is its path to root:

```text
Coordinate = [self_id, parent_id, ..., root_id]
```

Coordinates are ordered self-to-root, so common ancestry is a suffix. This
ordering is consistent across all FIPS documents.

**Distance metric**: Tree distance between two nodes is the sum of hops to their
lowest common ancestor (LCA). With self-to-root ordering, the LCA is found by
comparing coordinate suffixes:

```
dist(A, B) = depth(A) + depth(B) - 2 * depth(LCA(A, B))
```

### Gossip Efficiency

Two strategies reduce gossip bandwidth:

**Delta encoding**: A node tracks the last sequence number sent to each peer for
each ancestor. Subsequent announcements omit entries that haven't changed since
the last transmission to that peer. This optimization is always beneficial—it
reduces bandwidth without affecting convergence.

**Partial ancestry**: On severely constrained links, a node may send only its
immediate parent declaration, relying on transitive propagation through other
gossip paths to eventually deliver the full ancestry.

The tradeoff with partial ancestry is convergence speed. With full ancestry, the
recipient immediately knows the sender's complete tree coordinate, can compute
accurate distances, and can route packets right away. With parent-only, the
recipient must wait for the remaining ancestors to propagate through other paths
before routing works correctly. On high-bandwidth links, the extra bytes for full
ancestry are cheap and provide immediate usability. On a 300 bps radio link,
accepting slower convergence may be necessary to avoid transmitting a long chain
of ancestor entries.

### Cost Metrics

Parent selection and routing decisions depend on link cost metrics. The primary
metrics are:

- **Latency**: Round-trip time for the link
- **Packet loss**: Proportion of packets that fail to arrive
- **Bandwidth**: Available throughput capacity

These metrics combine into an effective cost used for parent selection and
routing decisions. The specific formula for combining metrics, the measurement
methodology, and the weighting of each factor are areas for future specification.

---

## 3. Bloom Filter Routing

### Yggdrasil Design

- 8192-bit bloom filter (1024 bytes)
- 8 hash functions per key
- False positive rate ~1/million for 200-node subtree
- Saturates in network core (acts as default route)

### Lookup Protocol

When a node needs to reach an unknown destination:

1. Create lookup packet with destination key
2. Forward to on-tree peers whose bloom filter contains the key
3. If multiple matches, send to all (multicast)
4. Destination responds with its current coordinates
5. Sender caches coordinate for direct routing

### FIPS Adaptations

**Tunable filter size**: Different deployments may need different tradeoffs:

| Scenario | Filter Size | Hash Functions | Target Nodes |
|----------|-------------|----------------|--------------|
| Small mesh (<100) | 2048 bits | 4 | 50 |
| Medium network | 8192 bits | 8 | 500 |
| Large network | 32768 bits | 12 | 2000 |

**Filter compression**: For low-bandwidth links (radio), use:

- Compressed bloom filter representation
- Hierarchical filters (subnet then node)
- Lazy propagation with invalidation

**Key transformation**: Allow filtering on npub prefixes for subnet routing:

```
filter.add(SHA256(npub)[0:8])  // 64-bit prefix for subnet
filter.add(SHA256(npub))       // Full key for node
```

---

## 4. Greedy Routing

### Algorithm

```
route(packet, destination):
    if destination == self:
        deliver(packet)
        return

    best_peer = None
    best_distance = tree_distance(self, destination)

    for peer in connected_peers:
        d = tree_distance(peer, destination)
        if d < best_distance:
            best_distance = d
            best_peer = peer

    if best_peer:
        forward(packet, best_peer)
    else:
        send_path_broken(packet.source)
```

### Path-Broken Recovery

When greedy routing fails (local minimum):

1. Send path-broken notification back to source
2. Source initiates bloom filter lookup for destination
3. On response, source caches new coordinates
4. Retry with updated routing information

---

## 5. Transport Abstraction Layer

FIPS is transport-agnostic. Transports are the physical or logical interfaces
over which FIPS communicates (UDP sockets, Ethernet NICs, Tor clients, etc.).
Links are connection instances to specific peers over a transport.

> **Note**: The Transport trait definition and detailed transport specifications
> are in [fips-architecture.md](fips-architecture.md). This section provides a
> conceptual overview. See [fips-transports.md](fips-transports.md) for transport
> characteristics and requirements.

### Transport Interface Concept

Each transport driver provides:

- **Identity**: Transport type identifier and configuration
- **Lifecycle**: Start/stop the transport interface
- **I/O**: Send/receive datagrams to/from transport-layer addresses
- **Discovery**: Find potential peers (transport-specific mechanism)
- **MTU**: Maximum packet size for this transport

Transports handle framing, fragmentation, and any transport-layer encryption
internally. The FIPS routing layer sees only FIPS packets.

### Transport Types

#### TCP/TLS Transport

Standard Yggdrasil-style IP peering with TLS encryption.

#### QUIC Transport

UDP-based with built-in encryption and multiplexing.

#### Radio Transport (LoRa, HF, VHF/UHF)

- Packet-based with size limits
- May support broadcast
- Often asymmetric (different TX/RX capabilities)
- Requires careful bandwidth management

#### Serial Transport (RS-232, USB, etc.)

- Point-to-point
- Framing protocol needed (SLIP, HDLC, etc.)
- Good for isolated node pairs

#### Onion Transport (Tor, I2P)

- High latency
- Strong anonymity properties
- Special handling for circuit setup

#### Bluetooth/BLE Transport

- Short range
- Discovery via scanning
- Pairing considerations

### Multi-Transport Routing

A single node may have multiple transports of different types:

```
┌─────────────────────────────────────────┐
│              FIPS Node                  │
│  ┌─────────────────────────────────┐   │
│  │         Router Core              │   │
│  └──────────┬──────────┬───────────┘   │
│             │          │               │
│      ┌──────┴────┐ ┌───┴─────┐        │
│      │    TCP    │ │  LoRa   │        │
│      │ Transport │ │Transport│        │
│      └────┬──────┘ └────┬────┘        │
└───────────┼─────────────┼──────────────┘
            │             │
       ┌────┴────┐  ┌─────┴────┐
       │Internet │  │  Radio   │
       │  Peers  │  │  Peers   │
       └─────────┘  └──────────┘
```

**Transport selection for forwarding**:

- Prefer transport with best path to destination
- Consider transport characteristics (don't send bulk over LoRa)
- Support explicit transport preferences in routing hints

---

## 6. Protocol Messages

### Wire Format

```
┌────────┬────────┬────────────────────────────────────┐
│ Type   │ Length │ Payload                            │
│ 1 byte │ 2 bytes│ Variable                           │
└────────┴────────┴────────────────────────────────────┘
```

### Message Types

| Type | Name | Description |
|------|------|-------------|
| 0x00 | Dummy | Keepalive/padding |
| 0x01 | TreeAnnounce | Spanning tree state |
| 0x02 | BloomUpdate | Bloom filter update |
| 0x03 | Lookup | Destination lookup request |
| 0x04 | LookupResponse | Coordinates for requested key |
| 0x05 | PathBroken | Route failure notification |
| 0x06 | SessionSetup | Routing session + crypto handshake init |
| 0x07 | SessionAck | Routing session ack + crypto response |
| 0x08 | CoordsRequired | Router cache miss notification |
| 0x09 | AuthInit | Peer authentication initiation |
| 0x0a | AuthChallenge | Peer authentication challenge + response |
| 0x0b | AuthComplete | Peer authentication completion |
| 0x10 | Traffic | Encrypted application data |
| 0x11 | TrafficAck | Delivery acknowledgement |

See [fips-routing.md](fips-routing.md) Part 4 for routing session details and
[fips-protocol-flow.md](fips-protocol-flow.md) §5-6 for combined establishment.

### TreeAnnounce

```
TreeAnnounce {
    sender: [u8; 32],        // npub
    sequence: u64,
    parent: [u8; 32],        // parent npub (self if root)
    ancestry_count: u8,
    ancestry: [(pubkey, seq, sig), ...],
    signature: [u8; 64],     // Schnorr signature
}
```

### BloomUpdate

```
BloomUpdate {
    sender: [u8; 32],
    link_id: u32,            // Which peer link this filter is for
    filter_size: u16,        // In bits
    filter: [u8; ...],       // Bloom filter bytes
    sequence: u64,
}
```

### Lookup / LookupResponse

```
Lookup {
    source: [u8; 32],
    destination: [u8; 32],
    ttl: u8,
    nonce: [u8; 16],
}

LookupResponse {
    destination: [u8; 32],
    nonce: [u8; 16],         // Echo from request
    coordinates: Vec<[u8; 32]>,  // Path to root [self, parent, ..., root]
    signature: [u8; 64],
}
```

---

## 7. Security Considerations

### Threat Model

- **Passive adversary**: Can observe traffic on controlled links
- **Active adversary**: Can inject, modify, or drop packets
- **Sybil attacks**: Can create many identities

### Mitigations

**Signature verification**: All protocol messages signed by sender's nsec.

**Replay protection**: Sequence numbers and timestamps on tree announcements.

**Sybil resistance**:

- Tree coordinate verification (can't claim arbitrary position)
- Optional proof-of-work for identity registration
- Web-of-trust integration with Nostr follows graph

**Traffic analysis**:

- Padding options for fixed-size packets
- Chaff traffic on idle links
- Onion routing mode for sensitive traffic

### Encryption

**Link encryption**: Each link type provides its own encryption:

- TCP: TLS 1.3
- QUIC: Built-in TLS
- Radio: Pre-shared key or public-key encryption

**End-to-end encryption**: FIPS provides a crypto session layer using the Noise
Protocol Framework with secp256k1. The Noise KK pattern provides mutual
authentication and forward secrecy in a single round-trip, since both parties
know each other's npub before initiating. Session keys are used with
ChaCha20-Poly1305 AEAD for all data packets; no per-packet signatures are
required (AEAD tag provides integrity and authenticity). See
[fips-protocol-flow.md](fips-protocol-flow.md) §6 for crypto session details.

> **Note**: Applications may use additional encryption (NIP-44) for
> application-layer privacy, but FIPS-layer encryption protects against
> intermediate router observation.

---

## 8. Open Questions

1. **Root stability**: How to prevent root flapping in large networks?
   Yggdrasil uses cost thresholds, but this may need tuning for heterogeneous links.

2. **Multi-path routing**: Should FIPS support simultaneous paths through different
   link types? Useful for redundancy and bandwidth aggregation.

3. **Bloom filter propagation on slow links**: How to handle 1KB filter updates
   over 300 bps radio links? Differential updates? Hierarchical filters?

4. **NAT traversal**: Yggdrasil relies on TCP for NAT punch-through. How do other
   transports handle this? (Not applicable to radio/serial)

5. **Incentives**: Should there be any incentive mechanism for relaying traffic?
   Or rely on reciprocal altruism?

6. **Nostr relay integration**: Can FIPS nodes announce themselves via Nostr relays?
   Use kind 10002-style relay lists for FIPS peer discovery?

7. **IPv6 integration**: Should FIPS addresses be routable IPv6, or use a private
   range with translation at gateways?

---

## References

### FIPS Design Documents

- [fips-protocol-flow.md](fips-protocol-flow.md) — Traffic flow, session terminology, crypto sessions
- [fips-routing.md](fips-routing.md) — Bloom filters, discovery, routing sessions
- [fips-architecture.md](fips-architecture.md) — Software architecture, configuration
- [fips-transports.md](fips-transports.md) — Transport protocol characteristics
- [spanning-tree-dynamics.md](spanning-tree-dynamics.md) — Tree protocol dynamics

### External References

- [Yggdrasil Network](https://yggdrasil-network.github.io/)
- [Yggdrasil v0.5 Release Notes](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html)
- [Ironwood Routing Library](https://github.com/Arceliar/ironwood)
- [Nostr Protocol](https://github.com/nostr-protocol/nips)
- [NIP-44 Encryption](https://github.com/nostr-protocol/nips/blob/master/44.md)
