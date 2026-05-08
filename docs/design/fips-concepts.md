# FIPS Concepts

A novice-friendly introduction to what FIPS is, why it exists, and the
mental model behind a self-organizing mesh. For the protocol stack,
identity system, and encryption walkthrough, see
[fips-architecture.md](fips-architecture.md). For prior art and
academic citations, see [fips-prior-work.md](fips-prior-work.md).

## What is FIPS?

FIPS is a self-organizing mesh network that can operate natively over a
variety of physical and logical media, such as local area networks,
Bluetooth, serial links, or the existing internet as an overlay. The
long-term goal is infrastructure that can function alongside or
ultimately replace dependence on the Internet itself. Systems running
FIPS establish peer connections, authenticate each other, and route
traffic for each other without any central authority or global topology
knowledge, and allow end-to-end encrypted sessions between any two
nodes regardless of how many hops separate them.

Nodes in the mesh route traffic for each other using Nostr identities
(npubs) as network addresses. Applications can access the mesh through
a native FIPS datagram service, or through an IPv6 adaptation layer
that presents each node as an IPv6 endpoint for compatibility with
existing IP-based applications.

## Why FIPS?

**Self-sovereign identity**: FIPS nodes generate their own addresses,
node IDs, and security credentials without coordination with any
central authority. These identities can be long-term fixed or may be
ephemeral, changed at any time. These identities are not visible to
the FIPS network itself — they are used only at the application layer
and for end-to-end session encryption.

**Infrastructure independence**: The internet depends on centralized
infrastructure — ISPs, backbone providers, DNS, certificate
authorities. FIPS works over any transport that can carry packets: a
serial connection, onion-routed connections through Tor, local area
networking, radio links between remote sites, or the existing internet
as an overlay. When the internet is unavailable, unreliable, or
untrusted, the mesh still works.

**Privacy by design**: FIPS provides secure, authenticated, and
encrypted communication between any two nodes in the mesh, independent
of the mix of transports used along the routed path between them.
Furthermore, the mesh itself is designed to minimize metadata exposure
— intermediate nodes route packets without learning the identities of
the endpoints.

**Zero configuration**: Nodes discover each other and build routing
automatically. Connect to one peer and you can reach the entire mesh.
The network self-heals around failures and adapts to changing topology.

## A Self-Organizing Mesh

Traditional networks are built top-down. A central authority assigns
addresses, configures routing tables, provisions hardware, and manages
the topology. If the authority disappears or the infrastructure fails,
the network fails with it. Nodes cannot reach each other without
infrastructure mediating the connection.

FIPS inverts this model. There is no central authority, no address
assignment service, no routing table pushed from above. Each node
generates its own identity from a cryptographic keypair. Each node
independently decides which peers to connect to and which transports
to use. From these local decisions alone, the network self-organizes:

- A **spanning tree** forms through distributed parent selection,
  giving every node a coordinate in the network without any node
  knowing the full topology
- **Bloom filters** propagate through gossip, so each node learns
  which peers can reach which destinations — again without global
  knowledge
- **Routing decisions** are made locally at each hop, using only the
  node's immediate peers and cached coordinate information

Each peer link and end-to-end session actively measures RTT, loss,
jitter, and goodput through a lightweight in-band Metrics Measurement
Protocol (MMP), providing operator visibility and a foundation for
quality-aware routing.

The result is a network that builds itself from the bottom up, heals
around failures automatically, and scales without central coordination.
Adding a node is as simple as connecting to one existing peer — the
network integrates the new node through its normal mesh protocols.

## Specific Design Goals

- **Nostr-native identity and cryptography** — Use Nostr keypairs as
  node identities and leverage secp256k1, Schnorr signatures, and
  SHA-256
- **Transport agnostic** — Support overlay, shared medium, and
  point-to-point transports transparently
- **Self-organizing** — Automatic topology discovery and route
  optimization
- **Privacy preserving** — Minimize metadata leakage across untrusted
  links
- **Resilient** — Self-healing with graceful degradation

Non-goals include:

- **Reliable delivery** — FIPS provides a best-effort datagram
  service; retransmission and ordering are left to applications or
  higher-layer protocols
- **Anonymity** — Direct peers learn each other's identity; FIPS
  minimizes metadata exposure but is not an anonymity network like Tor
- **Congestion control** — FIPS measures link quality but does not
  implement flow control or congestion avoidance at the mesh layer

## Where to Read Next

- [fips-architecture.md](fips-architecture.md) — protocol stack,
  identity system, two-layer encryption, MTU as a cross-cutting
  concern
- [fips-spanning-tree.md](fips-spanning-tree.md) — how the tree forms
  and reconverges
- [fips-bloom-filters.md](fips-bloom-filters.md) — how reachability
  information propagates
- [fips-mesh-operation.md](fips-mesh-operation.md) — how the pieces
  work together at runtime
- [fips-prior-work.md](fips-prior-work.md) — designs and protocols
  FIPS builds on
