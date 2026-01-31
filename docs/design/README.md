# FIPS Design Documents

Protocol design specifications and analysis for the Federated Interoperable Peering System.

## Protocol Design

| Document                                               | Description                                                                            |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| [fips-design.md](fips-design.md)                       | Core protocol specification: goals, architecture, identity, addressing, spanning tree  |
| [fips-routing.md](fips-routing.md)                     | Routing architecture: Bloom filters, discovery protocol, session establishment         |
| [fips-transports.md](fips-transports.md)               | Transport protocol characteristics: UDP, Ethernet, Tor, radio, and other link types    |
| [spanning-tree-dynamics.md](spanning-tree-dynamics.md) | Detailed study of spanning tree gossip protocol behavior and convergence               |

## Implementation

| Document                                                   | Description                                                                             |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| [fips-architecture.md](fips-architecture.md)               | Software architecture: entities, state machines, transport abstractions, configuration  |
| [fips-architecture-review.md](fips-architecture-review.md) | Architecture review issues and resolution status                                        |
| [fips-tun-driver.md](fips-tun-driver.md)                   | TUN interface driver: reader/writer threads, ICMPv6, packet flow                        |
| [fips-state-machines.md](fips-state-machines.md)           | Phase-based state machine pattern: peer lifecycle, transitions, timeout handling        |
| [fips-protocol-flow.md](fips-protocol-flow.md)             | Protocol message flow: packet channel, event loop, dispatching                          |
