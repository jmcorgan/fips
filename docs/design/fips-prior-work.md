# FIPS Prior Work and References

FIPS builds on proven designs rather than inventing new cryptography or
routing algorithms. Nearly every major design decision has deployed
precedent. This document collects the relevant prior art, organized by
the FIPS subsystem that draws on it, and gathers the academic and
standards references cited from the per-subsystem design docs.

## Spanning Tree Self-Organization

The idea that distributed nodes can build a spanning tree through
purely local decisions — each node selecting a parent based on
announcements from its neighbors — dates to the
[IEEE 802.1D Spanning Tree Protocol](https://en.wikipedia.org/wiki/Spanning_Tree_Protocol)
(STP, 1985). STP demonstrated that a network-wide tree emerges from a
simple deterministic rule (lowest bridge ID wins root election)
applied independently at each node. FIPS uses the same principle —
lowest node address determines the root — adapted from an Ethernet
bridging context to a general-purpose overlay mesh.

## Tree Coordinate Routing

The spanning tree coordinates, bloom filter candidate selection, and
greedy routing algorithms are adapted from
[Yggdrasil v0.5](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html)
and its [Ironwood](https://github.com/Arceliar/ironwood) routing
library. Yggdrasil's key insight was using the tree path from root to
node as a routable coordinate, enabling greedy forwarding without
global routing tables. FIPS adapts these algorithms for
multi-transport operation, Nostr identity integration, and constrained
MTU environments.

The theoretical foundation for greedy routing on tree embeddings draws
on [Kleinberg's work](https://www.cs.cornell.edu/home/kleinber/swn.pdf)
on navigable small-world networks, which showed that greedy forwarding
succeeds in O(log² n) steps when the network has hierarchical
structure. Thorup-Zwick compact routing schemes separately demonstrated
that sublinear routing state is achievable with bounded stretch,
motivating the use of tree coordinates rather than full routing tables.

## Split-Horizon Bloom Filter Propagation

FIPS distributes reachability information using bloom filters computed
with a split-horizon rule: when advertising to a peer, exclude that
peer's own contributions. This technique is borrowed from
distance-vector routing protocols —
[RIP](https://en.wikipedia.org/wiki/Routing_Information_Protocol)
(1988) and [Babel](https://www.irif.fr/~jch/software/babel/) use
split-horizon to prevent routing loops by not advertising a route back
to the neighbor it was learned from. FIPS applies the same principle
to probabilistic set advertisements rather than distance-vector tables.

## Cryptographic Identity as Network Address

FIPS nodes are identified by their Nostr public keys (secp256k1). The
network address *is* the cryptographic identity — there is no separate
address assignment or registration step.
[CJDNS](https://github.com/cjdelisle/cjdns) pioneered this approach in
overlay meshes, deriving IPv6 addresses from the double-SHA-512 of
each node's public key. Tor [.onion
addresses](https://spec.torproject.org/rend-spec-v3) and the IETF
[Host Identity Protocol](https://en.wikipedia.org/wiki/Host_Identity_Protocol)
(HIP) follow the same principle. FIPS uses Nostr's existing key
infrastructure rather than introducing a new identity scheme.

## Dual-Layer Encryption

FIPS encrypts traffic twice: FMP provides hop-by-hop link encryption
(protecting against transport-layer observers), while FSP provides
independent end-to-end session encryption (protecting against
intermediate FIPS nodes). This layered approach mirrors
[Tor](https://www.torproject.org/), where each relay peels one layer
of encryption (hop-by-hop) while the innermost layer protects
end-to-end payload. [I2P](https://geti2p.net/) uses a similar garlic
routing scheme with tunnel-layer and end-to-end encryption. Unlike Tor
and I2P, FIPS does not provide anonymity — its dual encryption
protects confidentiality and integrity rather than hiding traffic
patterns.

## Noise Protocol Framework

FIPS uses the [Noise Protocol Framework](https://noiseprotocol.org/)
at both protocol layers with the **Noise XX** handshake pattern. XX
requires no prior knowledge of the peer's static key — both
identities are revealed during a three-message handshake (responder
in msg2, initiator in msg3). This enables anonymous peer discovery on
shared-media transports and allows a protocol negotiation payload to
be exchanged alongside the handshake, supporting rolling protocol
upgrades without extra round trips.
[WireGuard](https://www.wireguard.com/) uses the related IK pattern
for VPN tunnels;
[Lightning Network](https://github.com/lightning/bolts/blob/master/08-transport.md)
uses XK for transport encryption.

Specific Noise references and adapted constructions:

- Perrin, T. ["The Noise Protocol Framework"](https://noiseprotocol.org/noise.html).
  Revision 34, 2018. *Framework for building crypto protocols using
  Diffie-Hellman key agreement and AEAD ciphers. FIPS uses the XX
  handshake pattern at both layers.*

- Donenfeld, J.A. ["WireGuard: Next Generation Kernel Network Tunnel"](https://www.wireguard.com/papers/wireguard.pdf).
  NDSS 2017. *Transport-independent cryptographic sessions bound to
  identity keys rather than network addresses; AEAD-only authentication
  model.*

## Index-Based Session Dispatch

FIPS uses locally-assigned 32-bit session indices to demultiplex
incoming packets to the correct cryptographic session in O(1) time,
without parsing source addresses or performing expensive lookups.
This directly follows
[WireGuard's](https://www.wireguard.com/papers/wireguard.pdf) receiver
index approach, where each peer assigns a random index during
handshake and the remote side includes it in every packet header.

## Replay Protection Over Unreliable Transports

FSP and FMP both use explicit per-packet counters with a sliding
bitmap window for replay protection — the standard DTLS approach,
chosen because implicit nonce counters desynchronize permanently under
UDP packet loss or reordering.

- Rescorla, E., Modadugu, N. [RFC 6347](https://datatracker.ietf.org/doc/html/rfc6347):
  "Datagram Transport Layer Security Version 1.2". 2012. *Explicit
  sequence numbers with sliding bitmap window for replay protection
  over unreliable transports.*

## Transport-Agnostic Overlay Mesh

FIPS is designed to operate over any datagram-capable transport — UDP,
raw Ethernet, Bluetooth, radio, serial — through a uniform transport
abstraction. Several mesh overlays have demonstrated transport-agnostic
design: [CJDNS](https://github.com/cjdelisle/cjdns) runs over UDP and
Ethernet, [Yggdrasil](https://yggdrasil-network.github.io/) supports
TCP and TLS transports, and [Tor](https://www.torproject.org/) can use
pluggable transports to tunnel through various media. FIPS extends
this pattern to shared-medium transports (radio, BLE) with
per-transport MTU and discovery capabilities.

## Metrics Measurement Protocol

MMP's design assembles well-established measurement techniques into a
unified per-link protocol. The SenderReport/ReceiverReport exchange
structure follows [RTCP](https://www.rfc-editor.org/rfc/rfc3550)
(RFC 3550), which uses the same report pairing for media stream
quality monitoring in RTP sessions. MMP's jitter computation uses the
RTCP interarrival jitter algorithm directly.

The smoothed RTT estimator uses the Jacobson/Karels algorithm
([RFC 6298](https://www.rfc-editor.org/rfc/rfc6298)), the same SRTT
computation used in TCP for retransmission timeout calculation since
1988. MMP derives RTT from timestamp-echo in ReceiverReports with
dwell-time compensation, rather than from packet round-trips.

The Expected Transmission Count (ETX) metric, computed from
bidirectional delivery ratios, was introduced by
[De Couto et al. (2003)](https://pdos.csail.mit.edu/papers/grid:mobicom03/paper.pdf)
for wireless mesh routing and is used in protocols including
[OLSR](https://en.wikipedia.org/wiki/Optimized_Link_State_Routing_Protocol)
and [Babel](https://www.irif.fr/~jch/software/babel/). FIPS computes
ETX per-link from MMP loss measurements for future use in candidate
ranking.

The CE (Congestion Experienced) echo flag provides hop-by-hop
[ECN](https://en.wikipedia.org/wiki/Explicit_Congestion_Notification)
signaling, following the TCP/IP ECN echo pattern (RFC 3168). Transit
nodes detect congestion via MMP loss/ETX metrics or kernel buffer
drops and set the CE flag on forwarded frames; destination nodes mark
ECN-capable IPv6 packets accordingly.

## Path MTU Discovery

FSP adapts RFC 1191 Path MTU Discovery for overlay networks. The
classic ICMP Packet Too Big mechanism is replaced by a transit-node
`min()` propagation in SessionDatagram and LookupResponse plus an
end-to-end PathMtuNotification echo back to the source.

- Mogul, J., Deering, S. [RFC 1191](https://datatracker.ietf.org/doc/html/rfc1191):
  "Path MTU Discovery". 1990. *End-to-end path MTU discovery; FSP
  adapts this for overlay networks using transit-node min()
  propagation.*

## Session Restart and Simultaneous Initiation

FSP's epoch-based peer restart detection mirrors IKEv2's
INITIAL_CONTACT notification, and its lowest-address-wins
simultaneous-initiation tie-breaker mirrors IKEv2's resolution rule.

- Kaufman, C., Hoffman, P., Nir, Y., Eronen, P., Kivinen, T.
  [RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296):
  "Internet Key Exchange Protocol Version 2 (IKEv2)". 2014.
  *Simultaneous initiation resolution (§2.8) and INITIAL_CONTACT peer
  restart detection (§2.4).*

## Hybrid Coordinate Warmup

FSP's hybrid coordinate warmup (CP flag piggybacking + standalone
CoordsWarmup) draws on Yggdrasil's approach of embedding coordinates
in session traffic to keep transit caches populated.

- [Yggdrasil Network](https://yggdrasil-network.github.io/).
  *Coordinate-based overlay routing with session traffic used to warm
  transit node coordinate caches.*

## Cryptographic Primitives

FIPS reuses [Nostr's](https://github.com/nostr-protocol/nips)
cryptographic stack — secp256k1 for identity keys, Schnorr signatures
for authentication, SHA-256 for hashing, and ChaCha20-Poly1305 for
authenticated encryption. This is the same primitive set used across
Bitcoin, Nostr, and a growing ecosystem of self-sovereign identity
systems. No novel cryptography is introduced.

## Spanning-Tree Dynamics: Foundations

The CRDT framing, gossip dissemination, failure detection, link
metrics, and route stability mechanisms in
[spanning-tree-dynamics.md](spanning-tree-dynamics.md) draw on a body
of academic and standards work, summarized below.

### Virtual Coordinate Routing

- Rao, A., Ratnasamy, S., Papadimitriou, C., Shenker, S., Stoica, I.
  ["Geographic Routing without Location Information"](https://people.eecs.berkeley.edu/~sylvia/papers/p327-rao.pdf).
  MobiCom 2003. *Established virtual coordinate routing using network
  topology.*

### Greedy Embedding Theory

- Kleinberg, R.
  ["Geographic Routing Using Hyperbolic Space"](https://www.semanticscholar.org/paper/Geographic-Routing-Using-Hyperbolic-Space-Kleinberg/f506b2ddb142d2ec539400297ba53383d958abef).
  IEEE INFOCOM 2007. *Proved every connected graph has a greedy
  embedding in hyperbolic space; showed spanning trees enable
  coordinate assignment.*

- Cvetkovski, A., Crovella, M.
  ["Hyperbolic Embedding and Routing for Dynamic Graphs"](https://www.cs.bu.edu/faculty/crovella/paper-archive/infocom09-hyperbolic.pdf).
  IEEE INFOCOM 2009. *Dynamic embedding for nodes joining/leaving;
  introduced Gravity-Pressure routing for failure recovery.*

- Crovella, M. et al.
  ["On the Choice of a Spanning Tree for Greedy Embedding"](https://www.cs.bu.edu/faculty/crovella/paper-archive/networking-science13.pdf).
  Networking Science 2013. *Analysis of how tree structure affects
  routing stretch.*

- Bläsius, T. et al.
  ["Hyperbolic Embeddings for Near-Optimal Greedy Routing"](https://dl.acm.org/doi/10.1145/3381751).
  ACM Journal of Experimental Algorithmics 2020. *Achieved 100%
  success ratio with 6% stretch on Internet graph.*

### Link Metrics

- De Couto, D., Aguayo, D., Bicket, J., Morris, R.
  "A High-Throughput Path Metric for Multi-Hop Wireless Routing".
  MobiCom 2003. *Introduced ETX (Expected Transmission Count) as a
  link quality metric for wireless mesh networks.*

### Routing Protocol Stability

- IEEE 802.1D. "IEEE Standard for Local and Metropolitan Area
  Networks: Media Access Control (MAC) Bridges". *Spanning Tree
  Protocol (STP) — root election via bridge ID, BPDU exchange.*

- Moy, J. [RFC 2328](https://datatracker.ietf.org/doc/html/rfc2328):
  "OSPF Version 2". 1998. *Link-state routing with cumulative path
  costs and SPF computation. FIPS's local-only cost approach is
  contrasted with OSPF's cumulative model in
  [spanning-tree-dynamics.md §8](spanning-tree-dynamics.md#8-parent-selection).*

### Distributed Systems Primitives

- Shapiro, M., Preguiça, N., Baquero, C., Zawirski, M.
  "Conflict-free Replicated Data Types". SSS 2011. *Formal definition
  of CRDTs enabling coordination-free consistency.*

- Das, A., Gupta, I., Motivala, A.
  ["SWIM: Scalable Weakly-consistent Infection-style Process Group Membership"](https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf).
  IPDPS 2002. *O(1) failure detection, O(log N) dissemination via
  gossip.*

- Kermarrec, A-M.
  ["Gossiping in Distributed Systems"](https://www.distributed-systems.net/my-data/papers/2007.osr.pdf).
  ACM SIGOPS Operating Systems Review 2007. *Framework for
  gossip-based protocols achieving O(log N) propagation.*

## FIPS Contributions

The protocol builds on these foundations and adds several new elements:

- Cost-aware parent selection using local-only link metrics
  (`effective_depth = depth + link_cost`), replacing Yggdrasil's
  depth-only selection
- Combined ETX + SRTT link cost formula with MMP-measured components
- Flap dampening with mandatory switch bypass
- Announcement suppression for transient state changes
- Tree-only bloom filter merge with split-horizon exclusion
- Hybrid coordinate warmup (CP flag piggybacking plus standalone
  CoordsWarmup) layered on top of SessionSetup self-bootstrapping
- Bloom-guided tree routing for discovery (vs. flooding)
- Reverse-path routing for LookupResponse via `recent_requests`

## External Reference Index

| Reference | Used by |
| --------- | ------- |
| [IEEE 802.1D STP](https://en.wikipedia.org/wiki/Spanning_Tree_Protocol) | spanning tree, root election |
| [Yggdrasil v0.5](https://yggdrasil-network.github.io/2023/10/22/upcoming-v05-release.html) | tree coordinates, greedy routing |
| [Ironwood](https://github.com/Arceliar/ironwood) | tree coordinates, candidate ranking |
| [Kleinberg, Small-world](https://www.cs.cornell.edu/home/kleinber/swn.pdf) | greedy routing on tree embeddings |
| [CJDNS](https://github.com/cjdelisle/cjdns) | cryptographic-identity-as-address |
| [Tor](https://www.torproject.org/) | onion address scheme, dual-layer encryption |
| [I2P](https://geti2p.net/) | dual-layer encryption (garlic routing) |
| [HIP](https://en.wikipedia.org/wiki/Host_Identity_Protocol) | identity-as-address |
| [Babel](https://www.irif.fr/~jch/software/babel/) | split-horizon, ETX |
| [RIP](https://en.wikipedia.org/wiki/Routing_Information_Protocol) | split-horizon |
| [Noise Framework](https://noiseprotocol.org/) | FMP and FSP XX handshakes |
| [WireGuard](https://www.wireguard.com/) | receiver-index dispatch, identity-bound sessions |
| [Lightning BOLT #8](https://github.com/lightning/bolts/blob/master/08-transport.md) | comparison reference |
| [QUIC (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000) | transport design |
| [RTCP (RFC 3550)](https://www.rfc-editor.org/rfc/rfc3550) | sender/receiver report structure, jitter algorithm |
| [TCP SRTT/RTO (RFC 6298)](https://www.rfc-editor.org/rfc/rfc6298) | Jacobson/Karels SRTT |
| [ECN (RFC 3168)](https://www.rfc-editor.org/rfc/rfc3168) | CE echo |
| [DTLS 1.2 (RFC 6347)](https://datatracker.ietf.org/doc/html/rfc6347) | replay window |
| [IKEv2 (RFC 7296)](https://datatracker.ietf.org/doc/html/rfc7296) | INITIAL_CONTACT, simultaneous-initiation tie-breaker |
| [PMTUD (RFC 1191)](https://datatracker.ietf.org/doc/html/rfc1191) | adapted PMTUD |
| [ETX paper, De Couto et al.](https://pdos.csail.mit.edu/papers/grid:mobicom03/paper.pdf) | ETX metric |
| [OLSR](https://en.wikipedia.org/wiki/Optimized_Link_State_Routing_Protocol) | ETX in mesh routing |
| [Nostr](https://github.com/nostr-protocol/nips) | identity stack |
