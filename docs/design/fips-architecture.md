# FIPS Architecture

The protocol architecture, identity system, and two-layer encryption
model. For the higher-level "what is FIPS and why" framing, see
[fips-concepts.md](fips-concepts.md). For prior art and academic
citations, see [fips-prior-work.md](fips-prior-work.md).

## Protocol Architecture

FIPS is organized in three protocol layers, each with distinct
responsibilities and clean service boundaries. No layer depends on
the specifics of the layers above or below it — transport plugins
know nothing about sessions, the routing layer knows nothing about
application addressing, and applications know nothing about which
physical media carry their traffic. This separation means new
transports, protocol features, and application interfaces can be
added independently.

![Protocol Stack](diagrams/fips-protocol-stack.svg)

### Mapping to Traditional Networking

Readers familiar with the OSI model or TCP/IP networking may find it
helpful to see how FIPS concepts relate to traditional layers:

![OSI Mapping](diagrams/fips-osi-mapping.svg)

Note that FMP spans what would traditionally be separate link and
network layers. This is intentional — in a self-organizing mesh, the
same layer that authenticates peers also makes routing decisions,
because routing depends on authenticated peer state (spanning tree
positions, bloom filters).

### Layer Responsibilities

**Transport layer**: Delivers datagrams between endpoints over a
specific medium. Each transport type (UDP socket, Ethernet interface,
radio modem) implements the same abstract interface: send and receive
datagrams, report MTU. The transport layer knows nothing about FIPS
identities, routing, or encryption. It provides raw datagram delivery
to FMP above.

See [fips-transport-layer.md](fips-transport-layer.md) for the
transport layer specification.

**FIPS Mesh Protocol (FMP)**: Manages peer connections, authenticates
peers via Noise XX handshakes, and encrypts all traffic on each link.
FMP is where the mesh organizes itself — nodes exchange spanning tree
announcements and bloom filters with their direct peers, and FMP
makes forwarding decisions for transit traffic. FMP provides
authenticated, encrypted forwarding to FSP above.

See [fips-mesh-layer.md](fips-mesh-layer.md) for the FMP specification
and [fips-mesh-operation.md](fips-mesh-operation.md) for how FMP's
routing and self-organization work in practice.

**FIPS Session Protocol (FSP)**: Provides end-to-end authenticated
encryption between any two nodes, regardless of how many intermediate
hops separate them. FSP manages session lifecycle (setup, data
transfer, teardown), caches destination coordinates for efficient
routing, and handles the warmup strategy that keeps transit node
caches populated. Session dispatch uses index-based routing inspired
by [WireGuard](https://www.wireguard.com/), enabling O(1) packet
demultiplexing. FSP provides a datagram service to applications above.

See [fips-session-layer.md](fips-session-layer.md) for the FSP
specification.

**IPv6 adaptation layer**: Sits above FSP as a service on port 256,
adapting the FIPS datagram service for unmodified IPv6 applications.
Provides DNS resolution (npub → fd00::/8 address), identity cache
management, IPv6 header compression, MTU enforcement, and a TUN
interface. This is the primary way existing applications use the FIPS
mesh.

See [fips-ipv6-adapter.md](fips-ipv6-adapter.md) for the IPv6 adapter.

### Node Architecture

Application services sit at the top of the stack, dispatched by FSP
port number: the IPv6 TUN adapter (port 256) maps npubs to `fd00::/8`
addresses with header compression so unmodified IP applications can
use the network transparently, while the native datagram API
addresses destinations directly by npub.

![Node Architecture](diagrams/fips-node-architecture.svg)

The mesh routes application traffic across heterogeneous transports
transparently. A packet may traverse WiFi, Ethernet, UDP/IP, and Tor
links on its way from source to destination — the application never
needs to know which transports are involved. Each hop is independently
encrypted at the link layer, while a single end-to-end session
protects the payload across the entire path.

![Architecture Overview](diagrams/fips-architecture-overview.svg)

![Mesh Topology](diagrams/fips-mesh-topology.svg)

## Identity System

FIPS uses [Nostr](https://github.com/nostr-protocol/nips) keypairs
(secp256k1) as node identities. The public key identifies the node;
the private key signs protocol messages and establishes encrypted
sessions.

The public key (or its bech32-encoded npub form) is the primary means
for application-layer software to identify communication endpoints.
Internally, the protocol derives a `node_addr` (a 16-byte SHA-256 hash
of the pubkey) used as the routing identifier in packet headers, and
an IPv6 address derived from the node_addr for the TUN adapter.
Applications use the pubkey or npub; the routing layer uses node_addr;
unmodified IPv6 applications use the derived `fd00::/8` address. All
three are deterministically derived from the same keypair.

### FIPS Identity Handling

![Identity Derivation](diagrams/fips-identity-derivation.svg)

The pubkey is the node's cryptographic identity, used in Noise XX
handshakes for both link encryption and session encryption.
It is never exposed beyond the endpoints of an encrypted channel. The node_addr, a one-way
SHA-256 hash truncated to 16 bytes, serves as the routing identifier
in packet headers and bloom filters. Intermediate routers see only
node_addrs — they can forward traffic without learning the Nostr
identities of the endpoints. An observer can verify "does this
node_addr belong to pubkey X?" if they already know the pubkey, but
cannot enumerate communicating identities by inspecting traffic. The
IPv6 address prepends `fd` to the first 15 bytes of the node_addr,
providing a ULA overlay address for unmodified IP applications via the
TUN interface.

Below the FIPS identity layer, each transport uses its own native
addressing — IP:port or hostname:port addresses, MAC addresses,
.onion identifiers. These **link addresses** are opaque to everything
above FMP and discarded once link authentication completes.

### Identity Verification

The Noise Protocol Framework mutually authenticates both peer-to-peer
link connections (at FMP) and end-to-end session traffic (at FSP),
proving each party controls the private key for their claimed
identity.

See [fips-mesh-layer.md](fips-mesh-layer.md) for peer authentication
and [fips-session-layer.md](fips-session-layer.md) for end-to-end
session establishment.

Key rotation changes the node's identity — a new keypair produces a
new node_addr and IPv6 address, requiring all sessions to be
re-established. Migration mechanisms that allow a node to announce a
successor key are a future consideration.

## Two-Layer Encryption

FIPS uses independent encryption at two protocol layers:

| Layer | Scope | Pattern | Purpose |
| ----- | ----- | ------- | ------- |
| **FMP (Mesh)** | Hop-by-hop | Noise XX | Encrypt all traffic on each peer link |
| **FSP (Session)** | End-to-end | Noise XX | Encrypt application payload between endpoints |

### Link Layer (Hop-by-Hop)

When two nodes establish a direct connection, they perform a [Noise
XX](https://noiseprotocol.org/) handshake. This authenticates both
parties and establishes symmetric keys for encrypting all traffic on
that link. Every packet between direct peers is encrypted — gossip
messages, routing queries, and forwarded session datagrams alike.
Neither side requires prior knowledge of the other's static key —
both identities are revealed during the three-message handshake,
along with a protocol negotiation payload that enables rolling
upgrades.

### Session Layer (End-to-End)

FIPS establishes end-to-end encrypted sessions between any two
communicating nodes using Noise XX, regardless of how many hops
separate them. The same three-message XX pattern is used at both
layers — neither side reveals its identity until msg2 (responder) or
msg3 (initiator), providing mutual identity protection for traffic
traversing untrusted intermediate nodes.

A packet from A to D through intermediate nodes B and C:

1. A encrypts payload with A↔D session key (FSP)
2. A wraps in SessionDatagram, encrypts with A↔B link key (FMP),
   sends to B
3. B decrypts link layer, reads destination node_addr, re-encrypts
   with B↔C link key, forwards to C
4. C decrypts link layer, re-encrypts with C↔D link key, forwards
   to D
5. D decrypts link layer, then decrypts session layer to get payload

Intermediate nodes route based on destination node_addr but cannot
read session-layer payloads. Each hop strips one link encryption and
applies the next — the session-layer ciphertext passes through
untouched.

Both layers always apply, even between adjacent peers — a packet to a
direct neighbor is still encrypted twice. This uniform model means no
special cases for local vs remote destinations, and topology changes
(a direct peer becomes reachable only through intermediaries) don't
affect existing sessions.

See [fips-mesh-layer.md](fips-mesh-layer.md) for link encryption and
[fips-session-layer.md](fips-session-layer.md) for session encryption.

## Routing and Mesh Operation

Forwarding decisions are local. Each node combines spanning-tree
coordinates with peer bloom filters to choose a next hop, falling back
to greedy tree routing when bloom filters have not converged. Discovery
warms transit node caches with destination coordinates, and three
explicit error signals (CoordsRequired, PathBroken, MtuExceeded) drive
recovery when forwarding fails. The full routing decision process,
discovery protocol, and error-recovery integration view live in
[fips-mesh-operation.md](fips-mesh-operation.md).

## Transport Abstraction

FIPS treats the communication medium as a pluggable component. UDP,
TCP, raw Ethernet, Tor, BLE, and Nym all implement the same small
datagram interface (send, receive, report MTU) and feed peers into a
single FMP routing layer; radio and serial transports are in the
planned set. Nym (an outbound-only mixnet transport) and Tor are
privacy-oriented deployment modes rather than failover paths.
Multi-transport nodes bridge between networks transparently. The
transport-layer specification — including per-transport categories,
the trait surface, the connection model, and implementation status —
is in [fips-transport-layer.md](fips-transport-layer.md).

## Security

FIPS defends against four adversary classes (transport observers,
active transport attackers, intermediate routers, and adversarial
mesh nodes) through layered controls: hop-by-hop FMP link encryption,
end-to-end FSP session encryption with stronger initiator identity
protection, signed and replay-protected gossip, and rate-limited
handshake processing. The threat-model details and per-layer
mitigations are in [fips-mesh-layer.md](fips-mesh-layer.md), and the
operator-facing controls (default-deny baseline, peer ACLs,
filesystem permissions, cryptographic primitives) are consolidated in
[fips-security.md](fips-security.md) and
[../reference/security.md](../reference/security.md).

## MTU as a Cross-Cutting Concern

MTU is not owned by any single layer. The transport layer reports
per-link MTU, FMP carries `path_mtu` in SessionDatagram and
LookupResponse to track the minimum along a path, FSP echoes the
observed forward-path MTU back to the source, and the IPv6 adapter
enforces the resulting effective MTU at the TUN with ICMP Packet Too
Big and TCP MSS clamping. The unified design — encapsulation overhead
budget, proactive PMTUD, reactive MtuExceeded, and per-destination
storage — is in [fips-mtu.md](fips-mtu.md).

## Approaches Considered but Rejected

One design alternative evaluated and ruled out during the architecture
pass was onion routing, rejected because it requires the sender to
know the full path upfront (incompatible with self-organizing
routing) and prevents per-hop error feedback (incompatible with
CoordsRequired/PathBroken recovery). The canonical mention lives in
[fips-mesh-operation.md](fips-mesh-operation.md#privacy-considerations).
