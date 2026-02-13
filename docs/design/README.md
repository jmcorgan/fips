# FIPS Design Documents

Protocol design specifications and analysis for the Federated Interoperable Peering System.

## Suggested Reading Order

Start with the high-level architecture, then work through session flow, routing
concepts, and finally the wire-level protocol details.

### 1. Introduction and Overview

| Document                                 | Description                                                 |
|------------------------------------------|-------------------------------------------------------------|
| [fips-intro.md](fips-intro.md)           | Protocol introduction: goals, concepts, architecture        |

### 2. Protocol Flow (How Traffic Works)

| Document                                             | Description                                               |
|------------------------------------------------------|-----------------------------------------------------------|
| [fips-session-protocol.md](fips-session-protocol.md) | End-to-end session flow, Noise IK encryption, terminology |

### 3. Routing (How Packets Find Their Way)

| Document                                               | Description                                                 |
|--------------------------------------------------------|-------------------------------------------------------------|
| [fips-routing.md](fips-routing.md)                     | Routing concepts: bloom filters, discovery, greedy routing  |
| [spanning-tree-dynamics.md](spanning-tree-dynamics.md) | Tree protocol behavior: convergence, partitions, recovery   |
| [fips-gossip-protocol.md](fips-gossip-protocol.md)     | Wire formats: TreeAnnounce, FilterAnnounce, Lookup messages |

### 4. Link Layer (How Peer Connections Work)

| Document                                       | Description                                                   |
|------------------------------------------------|---------------------------------------------------------------|
| [fips-wire-protocol.md](fips-wire-protocol.md) | Transport layer: Noise IK, session indices, roaming, security |
| [fips-transports.md](fips-transports.md)       | Transport-specific: UDP, Ethernet, Tor, radio characteristics |

## Implementation

| Document                                                         | Description                                                      |
|------------------------------------------------------------------|------------------------------------------------------------------|
| [fips-software-architecture.md](fips-software-architecture.md)   | Software architecture: entities, state machines, configuration   |
| [fips-tun-driver.md](fips-tun-driver.md)                         | TUN interface driver: reader/writer threads, ICMPv6, packet flow |
| [fips-state-machines.md](fips-state-machines.md)                 | Phase-based state machine pattern: peer lifecycle, transitions   |

## Document Cross-References

```text
                      fips-intro.md
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
    fips-session-protocol.md    fips-software-architecture.md
              │                         │
    ┌─────────┴─────────┐               ▼
    ▼                   ▼         fips-transports.md
fips-routing.md   fips-wire-protocol.md
    │       │
    ▼       ▼
spanning-tree-dynamics.md ←→ fips-gossip-protocol.md
```
