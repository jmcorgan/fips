# FIPS: Federated Interoperable Peering System

## What is FIPS?

FIPS is a self-organizing mesh network that can operate over any transport
medium—radio, serial links, Tor, local networks, or the existing internet as
an overlay. The long-term goal is infrastructure that can function alongside
or ultimately replace dependence on the Internet.

Nodes in the mesh route traffic for each other using Nostr identities (npubs)
as network addresses. Applications can access the mesh through a native FIPS
datagram service, or through an IPv6 adaptation layer that presents each node
as an IPv6 endpoint for compatibility with existing IP-based applications.

## Why FIPS?

**Infrastructure independence**: The internet depends on centralized
infrastructure—ISPs, backbone providers, DNS, certificate authorities. FIPS
works over any transport that can carry packets: a LoRa radio link between
mountain towns, a serial cable between air-gapped systems, onion-routed
connections through Tor, or the existing internet as an overlay. When the
internet is unavailable, unreliable, or untrusted, the mesh still works.

**End-to-end security**: FIPS provides secure, authenticated, and encrypted
communication between any two nodes in the mesh, independent of the mix of
transports used along the routed path between them.

**Privacy by design**: Traffic flows through encrypted tunnels at every hop.
Intermediate nodes route packets but cannot read their contents. Metadata
exposure is limited to direct peers only.

**Zero configuration**: Nodes discover each other and build routing
automatically. Connect to one peer and you can reach the entire mesh. The
network self-heals around failures and adapts to changing topology.

**Self-sovereign identity**: FIPS nodes generate their own addresses, node IDs,
and security credentials without coordination with any central authority. The
identity system uses Nostr keypairs (secp256k1), so existing npub/nsec pairs
work directly.

## How It Works (Overview)

Each FIPS node selects which transports to use (Ethernet, radio links, internet
overlay, etc.) and which peer nodes to connect to. From these local peering
decisions, the distributed spanning tree and bloom filter propagation algorithms
self-organize reachability and path information throughout the mesh.

Nodes form a spanning tree rooted at a deterministically-elected node. Each
node knows its path to the root, enabling shortest-path routing to be
calculated between any two nodes (not necessarily through the root). Bloom filters propagate reachability information so nodes can find
each other. Traffic flows via greedy routing toward destinations, encrypted
end-to-end.

Nodes with multiple transports automatically bridge between networks—the same
routing logic works regardless of the underlying transport mix.

## Design Goals

1. **Nostr-native identity** - Use Nostr keypairs as node identities
2. **Transport agnostic** - Support IP, wireless, serial, onion, and other link types
3. **Self-organizing** - Automatic topology discovery and route optimization
4. **Privacy preserving** - Minimize metadata leakage across untrusted links
5. **Resilient** - Self-healing with graceful degradation
6. **Reuse Nostr primitives** - Leverage secp256k1, Schnorr signatures, and SHA-256

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│         (native FIPS API, or IPv6 via TUN adapter)          │
├─────────────────────────────────────────────────────────────┤
│                      FIPS Router                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Identity   │  │  Spanning   │  │   Bloom Filter      │  │
│  │  (npub)     │  │    Tree     │  │   Routing Table     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                  Transport Abstraction                       │
│  ┌────────┐ ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐  │
│  │  UDP   │ │ Ethernet │ │  WiFi  │ │ Radio  │ │ Onion  │  │
│  └────────┘ └──────────┘ └────────┘ └────────┘ └────────┘  │
└─────────────────────────────────────────────────────────────┘
```

Applications can use the native FIPS datagram service directly, or access the
mesh through an IPv6 adaptation layer (TUN device) for compatibility with
existing IP-based applications. The router handles discovery, routing, and
encryption transparently in either case.

See [fips-transports.md](fips-transports.md) for transport options and characteristics.

## Prior Work

FIPS builds on proven designs rather than inventing new cryptography or routing
algorithms.

**Routing**: The spanning tree coordinates, bloom filter discovery, and greedy
routing algorithms are adapted from [Yggdrasil v0.5](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html)
and its [Ironwood](https://github.com/Arceliar/ironwood) routing library. FIPS
adapts these for multi-transport operation and Nostr identity integration.

**Encryption**: Link and session encryption use the [Noise Protocol
Framework](https://noiseprotocol.org/), the same foundation used by WireGuard,
Lightning Network, and other production systems. FIPS uses the IK pattern for
link authentication and end-to-end sessions.

**Cryptographic primitives**: FIPS reuses Nostr's cryptographic stack—secp256k1
for keys, Schnorr signatures, SHA-256 for hashing, and ChaCha20-Poly1305 for
authenticated encryption. No novel cryptography.

**Session management**: The index-based session dispatch follows WireGuard's
approach, enabling O(1) packet routing without relying on source addresses.

---

## Identity System

FIPS uses Nostr keypairs (secp256k1) as node identities. The public key
identifies the node; the private key signs protocol messages and establishes
encrypted sessions.

The FIPS address (synonymous with the pubkey) is the primary means for
application-layer software to identify communication endpoints. The
bech32-encoded npub can be used interchangeably for user interface purposes.
The FIPS datagram service is exposed to the application layer either via a
native API to the FIPS node software, or through an IPv6 shim driver that
converts the node identity into an IPv6 address and provides DNS resolution
from npub to this address for traditional software.

### Node Address Derivation

The pubkey is hashed to derive a node_addr used for routing:

```
pubkey (secp256k1 x-only, 32 bytes)
  → SHA-256
  → node_addr (16 bytes)
  → truncate with prefix
  → IPv6 address (128 bits, fd::/8)
```

**Separation of concerns**: The keypair handles cryptographic operations (signing,
encryption). The node_addr derived from the pubkey handles routing. This keeps
cryptographic material out of routing tables and packet headers—the node_addr is
the only identifier used at the protocol level, and the pubkey cannot be derived
from it.

The one-way hash also provides privacy from intermediate routing nodes. Routers
see only node_addrs in packet headers—they can route traffic without learning
the Nostr identities of the endpoints. An observer can verify "does this
node_addr belong to pubkey X?" but cannot enumerate which pubkeys are
communicating by inspecting traffic. Only the endpoints, which complete the
Noise IK handshake, learn each other's pubkeys.

### Address Format

When using the IPv6 protocol adapter, FIPS addresses use the IPv6 Unique Local
Address (ULA) prefix `fd00::/8`, providing 120 bits from the node_addr hash.
These are overlay identifiers—they appear in the TUN interface for application
compatibility but are not routable on the underlying transport. The fd prefix
ensures no collision with addresses that may be in use on the transport network.
FIPS provides a local DNS service that maps npub bech32 names to IPv6 addresses
for this purpose.

### Identity Verification

The Noise Protocol Framework is used to mutually authenticate both peer-to-peer
link connections and end-to-end session traffic, proving each party controls
the private key for their claimed identity.

See [fips-wire-protocol.md](fips-wire-protocol.md) for the Noise IK handshake
and [fips-session-protocol.md](fips-session-protocol.md) for end-to-end
session establishment.

### Terminology: Addresses and Identifiers

FIPS uses several related but distinct identifiers at different protocol layers:

| Term                       | Layer               | Visible To     | Description                                                          |
|----------------------------|---------------------|----------------|----------------------------------------------------------------------|
| **FIPS address / pubkey**  | Application/Session | Endpoints only | 32-byte secp256k1 public key - the endpoint identity                 |
| **npub**                   | (encoding)          | Human readers  | Bech32 encoding of pubkey for display/config                         |
| **node_addr**              | Routing             | Routing nodes  | SHA-256(pubkey) truncated to 128 bits - cannot be reversed to pubkey |
| **link_addr**              | Transport           | Direct peers   | IP:port, MAC, .onion - transport-specific                            |
| **IPv6 address**           | IPv6 shim           | Applications   | fd::/8 derived from node_addr - optional compatibility               |

**Privacy property**: The pubkey (FIPS address / Nostr identity) is never exposed to
intermediate routing nodes. They see only the node_addr, a one-way hash. An observer
can verify "does this node_addr belong to pubkey X?" but cannot derive the pubkey from
traffic.

---

## Two-Layer Encryption

FIPS uses independent encryption at two layers:

| Layer       | Scope       | Pattern  | Purpose                                        |
|-------------|-------------|----------|------------------------------------------------|
| **Link**    | Hop-by-hop  | Noise IK | Encrypt all traffic on each link               |
| **Session** | End-to-end  | Noise IK | Encrypt application payload between endpoints  |

### Link Layer (Hop-by-Hop)

When two nodes establish a direct connection, they perform a Noise IK handshake.
This authenticates both parties and establishes symmetric keys for encrypting
all traffic on that link. Every packet between direct peers is encrypted—gossip
messages, routing queries, and forwarded session datagrams alike.

The IK pattern is used because outbound connections know the peer's npub from
configuration, while inbound connections learn the initiator's identity from
the first handshake message.

### Session Layer (End-to-End)

FIPS establishes end-to-end encrypted sessions between any two communicating
nodes using Noise IK, regardless of whether they are direct peers or separated
by intermediate routers. The initiator knows the destination's npub; the
responder learns the initiator's identity from the handshake—the same asymmetry
as link-layer connections.

Both layers always apply. For adjacent peers, application traffic is encrypted
twice: once by the session layer (end-to-end) and once by the link layer
(hop-by-hop). This uniform model means:

- No special case for "local peer" vs "remote destination"
- Topology changes (a direct peer becomes reachable only through intermediaries)
  don't affect sessions
- The link layer remains purely a transport concern

A packet from A to adjacent peer B:

1. A encrypts payload with A↔B session key
2. A wraps in SessionDatagram, encrypts with A↔B link key, sends to B
3. B decrypts link layer, then decrypts session layer to get payload

A packet from A to D through intermediate node B:

1. A encrypts payload with A↔D session key
2. A wraps in SessionDatagram, encrypts with A↔B link key, sends to B
3. B decrypts link layer, sees destination, re-encrypts with B↔D link key
4. D decrypts link layer, then decrypts session layer to get payload

Intermediate nodes can route based on destination address but cannot read
session-layer payloads.

FIPS session setup also warms up route caches along the path between the
endpoints, so that when application traffic flows the network is already ready.

See [fips-wire-protocol.md](fips-wire-protocol.md) for link encryption and
[fips-session-protocol.md](fips-session-protocol.md) for session encryption.

---

## Spanning Tree Protocol

The spanning tree is a subset of the full mesh network that connects all nodes,
forming a tree structure rooted at a deterministically-elected node. Each node
selects a single parent, and the resulting tree serves as the routing backbone.
This enables routing without global routing tables.

### Why a Spanning Tree?

A spanning tree has useful properties:

- **Unique paths**: Exactly one path exists between any two nodes
- **Minimal state**: Nodes only track their parent and immediate peers
- **Coordinates**: A node's position in the tree enables distance calculations

The tree provides structure for routing while bloom filters provide reachability
information. Together they enable efficient packet delivery without requiring
nodes to know the full network topology.

### Tree Coordinates

A node's coordinate is its path from itself to the root. The distance between
two nodes is the sum of hops from each to their lowest common ancestor (LCA).
This distance metric enables greedy routing: forward packets to the peer that
minimizes distance to the destination.

### Root Election

The root is the node with the lexicographically smallest node_addr among all
reachable nodes. This election is deterministic and requires no coordination—
each node independently examines its view of the network and reaches the same
conclusion.

The root provides a coordinate reference point but does not participate in
routing unless the paths from source and destination to the root share no
common ancestors (i.e., the root is their lowest common ancestor).

### Parent Selection

Each node selects a parent that provides the best path to root, considering:

- Reachability (the parent must have a path to root)
- Link quality (latency, packet loss, bandwidth)
- Stability (hysteresis prevents flapping on minor changes)

The parent must be a direct peer—nodes cannot select non-peers as parents.

### Tree Gossip

Nodes exchange TreeAnnounce messages containing their parent selection and
ancestry chain (path to root). When a node changes its parent, it announces the
change; peers propagate relevant updates. The tree converges through this
gossip without centralized coordination.

Changes propagate only as far as they need to—distantly connected nodes are
unaffected by local path changes and don't receive updates for them.

### Partition Handling

If the network partitions, each isolated segment elects its own root (the
smallest node_addr within that segment). When partitions merge, nodes in the
segment with the larger root discover the globally smaller root and re-parent.
The tree reconverges automatically.

See [fips-routing.md](fips-routing.md) for routing concepts,
[fips-gossip-protocol.md](fips-gossip-protocol.md) for message formats, and
[spanning-tree-dynamics.md](spanning-tree-dynamics.md) for convergence behavior.

---

## Bloom Filter Routing

Tree coordinates enable routing once you know a destination's position. Bloom
filters enable finding that position in the first place.

A bloom filter is a space-efficient probabilistic data structure that can test
whether an element is a member of a set. It may produce false positives (saying
an element is present when it isn't) but never false negatives. This makes it
ideal for routing: a node can quickly check if a destination might be reachable
through a given peer, with occasional false positives handled by backtracking.

### How It Works

Each node maintains bloom filters summarizing which node_addrs are reachable
through each of its peers. These filters propagate through the tree: a node
aggregates filters from its children and announces the combined filter to its
parent (and vice versa).

When a node needs to reach an unknown destination:

1. Check local bloom filters—which peers might be able to reach this node_addr?
2. Send a LookupRequest to peers whose filters indicate "maybe"
3. The request propagates through the tree toward matching subtrees
4. The destination responds with a LookupResponse containing its coordinates
5. The sender caches the coordinates and routes directly via greedy forwarding

Bloom filters have false positives (a filter may indicate "maybe" when the node
isn't actually reachable through that path) but no false negatives. Extra
queries are harmless; missing a reachable node is not.

### Filter Propagation

Filters propagate in the opposite direction from tree announcements:

- Tree state propagates upward (toward root) via ancestry chains
- Bloom filters propagate downward (toward leaves) via subtree aggregation

A node's filter contains all node_addrs reachable through its subtree. The root's
filter contains everyone; leaf nodes have empty outbound filters.

See [fips-routing.md](fips-routing.md) for bloom filter design and
[fips-gossip-protocol.md](fips-gossip-protocol.md) for FilterAnnounce format.

---

## Greedy Routing

Once a destination's tree coordinates are known, packets are forwarded using
greedy routing: at each hop, forward to the peer that minimizes tree distance
to the destination.

### The Algorithm

1. If I am the destination, deliver the packet locally
2. Calculate my tree distance to the destination
3. For each peer, calculate their tree distance to the destination
4. Forward to the peer with the smallest distance (must be less than mine)
5. If no peer is closer, routing has failed (local minimum)

### Path-Broken Recovery

Greedy routing can fail if the destination has moved or the cached coordinates
are stale. When this happens, the node that cannot make progress sends a
PathBroken notification back to the source. The source then initiates a fresh
bloom filter lookup to find the destination's current coordinates.

### Session Establishment

For efficiency, FIPS establishes routing sessions that cache coordinate
information at intermediate routers. The first packet (SessionSetup) carries
full coordinates; subsequent packets use cached state for minimal overhead.

See [fips-routing.md](fips-routing.md) for the complete routing design and
[fips-session-protocol.md](fips-session-protocol.md) for session establishment.

---

## Transport Abstraction

FIPS is transport-agnostic. The protocol operates identically whether peers
connect over UDP, Ethernet, LoRa radio, serial cables, or Tor hidden services.

### Transports and Links

A **transport** is a physical or logical interface: a UDP socket, an Ethernet
NIC, a Tor client, a radio modem. A **link** is a connection instance to a
specific peer over a transport.

```
┌─────────────────────────────────────────┐
│              FIPS Node                  │
│  ┌─────────────────────────────────┐   │
│  │         Router Core              │   │
│  └──────────┬──────────┬───────────┘   │
│             │          │               │
│      ┌──────┴────┐ ┌───┴─────┐        │
│      │    UDP    │ │  LoRa   │        │
│      │ Transport │ │Transport│        │
│      └────┬──────┘ └────┬────┘        │
└───────────┼─────────────┼──────────────┘
            │             │
       ┌────┴────┐  ┌─────┴────┐
       │Internet │  │  Radio   │
       │  Peers  │  │  Peers   │
       └─────────┘  └──────────┘
```

### Multi-Transport Bridging

A node with multiple transports automatically bridges between networks. Peers
from all transports feed into a single spanning tree; the router selects the
best path regardless of transport type. If one transport fails, traffic
automatically routes through alternatives.

### Transport Types

| Category | Examples | Characteristics |
|----------|----------|-----------------|
| Overlay | UDP/IP, TCP/TLS, QUIC, WebSocket | Internet connectivity, NAT considerations |
| Shared medium | Ethernet, WiFi, Bluetooth, LoRa | Broadcast/multicast discovery |
| Point-to-point | Serial, dialup | No discovery needed, static config |
| Anonymity | Tor, I2P | High latency, strong privacy |

UDP over IP is expected to be the most common transport for internet-connected
nodes. Radio transports enable connectivity where internet infrastructure is
unavailable.

See [fips-transports.md](fips-transports.md) for transport characteristics.

---

## Protocol Messages

FIPS uses a discriminator-based wire format for efficient message dispatch.

### Link Layer Messages

Exchanged between directly connected peers, encrypted with link session keys:

| Type | Name           | Purpose                                    |
|------|----------------|--------------------------------------------|
| 0x10 | TreeAnnounce   | Spanning tree state (parent, ancestry)     |
| 0x11 | FilterAnnounce | Bloom filter reachability update           |
| 0x12 | LookupRequest  | Query for node's tree coordinates          |
| 0x13 | LookupResponse | Response with coordinates and proof        |
| 0x40 | SessionDatagram| Carries end-to-end encrypted payloads      |

### Session Layer Messages

Carried inside SessionDatagram, encrypted end-to-end between source and
destination:

| Type | Name           | Purpose                                    |
|------|----------------|--------------------------------------------|
| 0x00 | SessionSetup   | Establish routing session with coordinates |
| 0x01 | SessionAck     | Acknowledge session establishment          |
| 0x10 | DataPacket     | Encrypted application data (IPv6 payload)  |
| 0x20 | CoordsRequired | Router cache miss—need fresh coordinates   |
| 0x21 | PathBroken     | Greedy routing failed—need re-lookup       |

See [fips-wire-protocol.md](fips-wire-protocol.md) for wire format details and
[fips-gossip-protocol.md](fips-gossip-protocol.md) for gossip message formats.

---

## Security Considerations

### Threat Model

FIPS assumes adversaries with varying capabilities:

- **Passive adversary**: Can observe traffic on links they control
- **Active adversary**: Can inject, modify, drop, or replay packets
- **Sybil adversary**: Can create many node identities

### Cryptographic Protections

**Link encryption**: Every peer connection uses Noise IK, providing mutual
authentication and forward secrecy. An observer on the underlying transport
sees only encrypted packets.

**End-to-end encryption**: Session-layer Noise IK encrypts payloads between
endpoints. Intermediate routers cannot read application data.

**Signature verification**: All protocol messages (TreeAnnounce, LookupResponse)
are signed. The full ancestry chain in TreeAnnounce includes signatures from
each node, preventing forged tree positions.

**Replay protection**: Sequence numbers and timestamps on announcements.
Counter-based nonces with sliding window for encrypted packets.

### Sybil Resistance

Creating many identities is cheap, but exploiting them is constrained:

- **Discretionary peering**: Node operators choose who to peer with. An attacker
  with many identities still needs real nodes to accept their connections.
- **Tree coordinate verification**: Nodes cannot claim arbitrary tree positions
  without valid signed ancestry chains from real nodes
- **Rate limiting**: Handshake rate limiting constrains how fast attackers can
  establish connections

### Metadata Exposure

Each entity in the network sees different information:

| Entity | Can See |
|--------|---------|
| Transport observer | Encrypted packets, timing, packet sizes |
| Direct peer | Your npub (identity), traffic volume, timing |
| Intermediate router | Source and destination node_addrs, packet size |
| Destination | Your npub (identity), payload content |

Intermediate routers see node_addrs, not npubs. Since node_addrs are derived from
pubkeys via one-way SHA-256 hash, routers cannot determine the actual identities
of the endpoints they route for.

The session layer hides payload content from intermediate routers. The link
layer hides everything from passive observers on the underlying transport.

---

## Conclusion

FIPS combines these elements into a cohesive system that achieves its design
goals:

- **Self-sovereign identity** through Nostr keypairs, with node_addrs providing
  routing-level privacy
- **Transport agnosticism** via the transport abstraction layer, enabling the
  same routing logic across UDP, Ethernet/WiFi, Tor, and other link types
- **Self-organization** through distributed spanning tree formation and bloom
  filter propagation, requiring no central coordination
- **Privacy preservation** with two-layer encryption that hides payloads from
  intermediate routers and hides everything from transport observers
- **Resilience** through automatic partition detection, re-election, and tree
  reconvergence when the network topology changes

The result is a mesh network where nodes can find and communicate with each
other securely, regardless of the underlying transport infrastructure, while
maintaining control over their own identities and peering relationships.

---

## References

### FIPS Design Documents

| Document | Description |
|----------|-------------|
| [fips-session-protocol.md](fips-session-protocol.md) | End-to-end session flow, Noise IK encryption |
| [fips-wire-protocol.md](fips-wire-protocol.md) | Link-layer transport, Noise IK handshake |
| [fips-gossip-protocol.md](fips-gossip-protocol.md) | TreeAnnounce, FilterAnnounce, Lookup formats |
| [fips-routing.md](fips-routing.md) | Bloom filters, discovery, greedy routing |
| [spanning-tree-dynamics.md](spanning-tree-dynamics.md) | Tree protocol dynamics and convergence |
| [fips-transports.md](fips-transports.md) | Transport protocol characteristics |
| [fips-architecture.md](fips-architecture.md) | Software architecture, configuration |

### External References

- [Yggdrasil Network](https://yggdrasil-network.github.io/)
- [Yggdrasil v0.5 Release Notes](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html)
- [Ironwood Routing Library](https://github.com/Arceliar/ironwood)
- [Nostr Protocol](https://github.com/nostr-protocol/nips)
- [Noise Protocol Framework](https://noiseprotocol.org/)
