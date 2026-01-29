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
> On transports that provide identity-binding encryption, this protocol may be
> skipped if the transport key is bound to the peer's npub.

```text
Initiator (A)                                  Responder (B)
     │                                              │
     │──────────── HELLO(npub_A) ─────────────────►│
     │                                              │
     │◄───────── CHALLENGE(npub_B, challenge_B) ───│
     │                                              │
     │── AUTH(challenge_A, response_A, response_B)─►│
     │                                              │
     │◄─────────── AUTH_ACK(response_A') ──────────│
     │                                              │
     ▼                                              ▼
   Authenticated                              Authenticated
```

**Protocol flow:**

1. **HELLO**: Initiator sends its npub to responder
2. **CHALLENGE**: Responder generates a 32-byte random challenge and sends it
   along with its own npub and a challenge for the initiator
3. **AUTH**: Initiator signs both challenges and sends both responses
4. **AUTH_ACK**: Responder verifies initiator's response to its challenge,
   then sends its response to the initiator's challenge

After successful mutual authentication, both nodes have proven they control
their claimed private keys.

### Challenge-Response Construction

The challenge response is constructed with domain separation to prevent
cross-protocol signature reuse:

```text
challenge = random(32)
timestamp = current_unix_time()
digest = SHA256("fips-auth-v1" || challenge || timestamp)
response = schnorr_sign(nsec, digest)
```

**Domain separation**: The `"fips-auth-v1"` prefix ensures that signatures
created for FIPS authentication cannot be replayed in other contexts (e.g.,
a Nostr event signature). If the authentication protocol is revised, the
version string changes (e.g., `"fips-auth-v2"`).

**Timestamp binding**: The timestamp is included in the signed digest and
transmitted alongside the response. The verifier checks that the timestamp
is within an acceptable window (e.g., ±5 minutes) to prevent replay attacks
where an attacker captures and later reuses a valid response.

**Nonce freshness**: The 32-byte random challenge ensures that even if an
attacker can predict the timestamp, they cannot pre-compute valid responses.
Each authentication attempt requires a fresh signature.

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
| 0x10 | Traffic | Encrypted application data |
| 0x11 | TrafficAck | Delivery acknowledgement |

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

**End-to-end encryption**: Application layer uses NIP-44 or similar for payload encryption.

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

- [Yggdrasil Network](https://yggdrasil-network.github.io/)
- [Yggdrasil v0.5 Release Notes](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html)
- [Ironwood Routing Library](https://github.com/Arceliar/ironwood)
- [Nostr Protocol](https://github.com/nostr-protocol/nips)
- [NIP-44 Encryption](https://github.com/nostr-protocol/nips/blob/master/44.md)
