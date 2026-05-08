# FIPS Design

Architectural and protocol-level explanations for FIPS — the *why*
and the *how* behind the wire and the system. For wire formats and
configuration keys, see [reference/](../reference/). For task
recipes, see [how-to/](../how-to/). For end-to-end lessons, see
[tutorials/](../tutorials/).

## Reading Order

Start with [fips-concepts.md](fips-concepts.md) for the
novice-friendly framing of what FIPS is and why, then move to
[fips-architecture.md](fips-architecture.md) for the protocol stack,
identity model, and two-layer encryption walkthrough. From there,
follow the protocol stack from bottom to top. After the stack,
[fips-mesh-operation.md](fips-mesh-operation.md) explains how the
pieces work together at runtime. Cross-cutting and supporting
documents cover specific subsystems in detail.

### Foundations

| Document | Description |
| -------- | ----------- |
| [fips-concepts.md](fips-concepts.md) | What FIPS is, why it exists, mental model |
| [fips-architecture.md](fips-architecture.md) | Protocol stack, identity, two-layer encryption |
| [fips-prior-work.md](fips-prior-work.md) | Designs and protocols FIPS builds on |

### Protocol Stack

| Document | Description |
| -------- | ----------- |
| [fips-transport-layer.md](fips-transport-layer.md) | Transport layer: datagram delivery over arbitrary media |
| [fips-mesh-layer.md](fips-mesh-layer.md) | FIPS Mesh Protocol (FMP): peer authentication, link encryption, forwarding |
| [fips-session-layer.md](fips-session-layer.md) | FIPS Session Protocol (FSP): end-to-end encryption, sessions |
| [fips-ipv6-adapter.md](fips-ipv6-adapter.md) | IPv6 adaptation: TUN interface, DNS, MTU enforcement |

### Cross-Cutting

| Document | Description |
| -------- | ----------- |
| [fips-mmp.md](fips-mmp.md) | Metrics Measurement Protocol (link + session) |
| [fips-mtu.md](fips-mtu.md) | Path MTU model, encapsulation overhead, PMTUD |
| [fips-security.md](fips-security.md) | `fips0` interface threat model and default-deny baseline |

### Mesh Behavior

| Document | Description |
| -------- | ----------- |
| [fips-mesh-operation.md](fips-mesh-operation.md) | How the mesh operates: routing, discovery, error recovery |
| [fips-nostr-discovery.md](fips-nostr-discovery.md) | Optional Nostr-mediated peer discovery and UDP NAT hole-punch |
| [port-advertisement-and-nat-traversal.md](port-advertisement-and-nat-traversal.md) | Nostr-signaled port advertisement and UDP NAT-traversal protocol; generic, with FIPS as an example implementation |

### Deeper Dives

| Document | Description |
| -------- | ----------- |
| [fips-spanning-tree.md](fips-spanning-tree.md) | Spanning tree algorithms: root discovery, parent selection, coordinates |
| [fips-bloom-filters.md](fips-bloom-filters.md) | Bloom filter properties: FPR analysis, size classes, split-horizon |
| [spanning-tree-dynamics.md](spanning-tree-dynamics.md) | Spanning tree walkthroughs: convergence scenarios, worked examples |

### Adjacent Components

| Document | Description |
| -------- | ----------- |
| [fips-gateway.md](fips-gateway.md) | `fips-gateway` service: outbound (LAN-to-mesh) DNS-proxy + virtual-IP NAT and inbound (mesh-to-LAN) port-forwarding, sharing one nftables table |
