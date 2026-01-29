# FIPS Transport Protocols

FIPS nodes peer with each other over a variety of transport types. This document
explores the requirements and characteristics of different transport protocols
that FIPS can operate over.

## Terminology

- **Transport**: A physical or logical interface over which FIPS communicates
  (e.g., a UDP socket, Ethernet NIC, or Tor client)
- **Link**: A connection instance to a specific peer over a transport

This document describes transport-level characteristics. See
[fips-architecture.md](fips-architecture.md) for the Transport trait definition.

## Design Principles

FIPS is a Layer 3 (network) protocol. It exposes an IPv6 interface to local
applications, with an address deterministically derived from the node's npub.
This means existing UDP, TCP, and other IP-based applications work unmodified
over FIPS.

However, this IPv6-over-transport architecture requires care to avoid classic
encapsulation pitfalls. In particular, running TCP over a reliable transport
(like TCP/IP overlay) creates "TCP-over-TCP" where retransmission and congestion
control mechanisms at both layers interact adversely. FIPS prefers unreliable
transports for this reason.

FIPS treats underlying connectivity as abstract transports, regardless of
whether those transports are:

- True L2 protocols (Ethernet, Bluetooth)
- L4-over-L3 tunnels (UDP/IP) used as transport substrate for NAT traversal
- Application-layer overlays (Tor, I2P)

Each transport driver presents a uniform interface to the FIPS routing layer:
send/receive datagrams to/from a transport-layer peer address.

## Transport Characteristics

### Overlay Transports (L3/L4 Substrate)

These transports tunnel FIPS over an existing network layer, typically for
internet connectivity or anonymity. Overlay transports are expected to be the
majority in early deployments, but all depend on existing IP/Internet
infrastructure that FIPS is ultimately designed to replace.

| Transport | Encapsulation | Addressing | MTU | Latency | Reliability | Bandwidth | Discovery |
|-----------|---------------|------------|-----|---------|-------------|-----------|-----------|
| UDP/IP | UDP datagram | IP:port | 1280-1472 | 1-500ms | Unreliable | High | DNS-SD, Nostr |
| TCP/IP | Framed stream | IP:port | Stream | 10-500ms | Reliable | High | DNS-SD, Nostr |
| WebSocket | WS frames | URL | Stream | 10-500ms | Reliable | High | Nostr |
| Tor | TCP stream | .onion | Stream | 500ms-5s | Reliable | Low-Med | Static, Nostr |
| I2P | I2P datagram | Destination | ~32K | 1-10s | Unreliable | Low | I2P directory |

### Shared Medium Transports

These transports operate over broadcast or multicast-capable media where multiple
endpoints share the same physical or logical channel.

| Transport | Encapsulation | Addressing | MTU | Latency | Reliability | Bandwidth | Discovery |
|-----------|---------------|------------|-----|---------|-------------|-----------|-----------|
| Ethernet | EtherType frame | MAC | 1500 | <1ms | Unreliable | High | Multicast |
| WiFi Direct | 802.11 frame | MAC | 1500 | 1-10ms | Unreliable | High | Service discovery |
| DOCSIS (Cable) | DOCSIS frame | MAC | 1500 | 10-50ms | Unreliable | 1M-1G | N/A (uses IP) |
| Bluetooth Classic | L2CAP | BD_ADDR | 672-64K | 10-100ms | Reliable | 2-3 Mbps | Inquiry + SDP |
| BLE | L2CAP CoC/GATT | BD_ADDR | 23-517 | 10-30ms | Reliable | 125K-2M | GATT advertising |
| Zigbee | 802.15.4 frame | 16/64-bit | ~100 | 15-30ms | Reliable | 250 kbps | Network scan |
| LoRa | Raw packet | Device addr | 51-222 | 100ms-10s | Unreliable | 0.3-50 kbps | Beacons |

### Point-to-Point Transports

These transports connect exactly two endpoints with no shared medium or
addressing.

| Transport | Encapsulation | Addressing | MTU | Latency | Reliability | Bandwidth | Discovery |
|-----------|---------------|------------|----------|-----------|-------------|-----------|------------|
| Serial | SLIP/COBS frame | None (P2P) | 256-1500 | 1-100ms | Reliable | 9.6K-1M | Configured |
| Dialup | PPP frame | None (P2P) | 1500 | 100-200ms | Reliable | 33.6-56K | Configured |

### Notes

**MTU**: Minimum/maximum or typical range. FIPS must handle heterogeneous MTUs
across the mesh; the IPv6 minimum (1280) is a safe baseline for the FIPS
packet format.

**Latency**: Typical range from best-case to worst-case. Affects spanning tree
convergence and keepalive timing.

**Reliability**: Whether the link provides delivery guarantees. Unreliable
links may drop, reorder, or duplicate packets. FIPS must tolerate this at
the routing layer.

**Bandwidth**: Order of magnitude. Affects flow control and congestion
decisions, but FIPS routing itself is low-bandwidth (control plane only).

## Connection Model

Transports fall into two categories based on whether they require connection
establishment before data can be exchanged:

### Connectionless Transports

These transports can send datagrams to a peer address without prior setup.
Links are lightweight—just a `(transport_id, remote_addr)` tuple with implicit
"established" state.

| Transport | Notes |
|-----------|-------|
| UDP/IP | Stateless datagrams; NAT state is implicit |
| Ethernet | Send to MAC address directly |
| WiFi | Same as Ethernet (802.11 frame) |
| DOCSIS | Cable modem layer; uses IP in practice |
| LoRa | Raw packets to device address |
| I2P | Datagram mode (not streaming) |

### Connection-Oriented Transports

These transports require explicit connection setup before FIPS traffic can flow.
Links track real connection state and hold I/O handles. The link must complete
transport-layer connection before FIPS authentication can proceed.

| Transport | Connection Setup |
|-----------|------------------|
| TCP/IP | TCP handshake |
| WebSocket | HTTP upgrade + TCP |
| Tor | Circuit establishment (slow: 500ms-5s) |
| Bluetooth Classic | L2CAP connection |
| BLE | L2CAP CoC or GATT connection |
| Zigbee | Network join + binding |
| Serial | Physical connection (static) |
| Dialup | PPP negotiation |

### Implications for FIPS

**Link lifecycle**: Connectionless transports use a trivial link model (no state
machine). Connection-oriented transports require a real state machine:
`Connecting → Connected → Disconnected`. See
[fips-architecture.md](fips-architecture.md) for link lifecycle details.

**Startup latency**: Connection-oriented transports add latency before a peer
becomes usable. Tor is particularly slow (circuit setup). This affects peer
timeout configuration.

**Failure modes**: Connectionless links "fail" only when the transport itself
is down or the peer stops responding. Connection-oriented links can fail during
connection setup, adding more error handling paths.

**Framing**: Connection-oriented stream transports (TCP, WebSocket, Tor) require
length-prefix framing to delineate FIPS packets. Datagram transports have
natural packet boundaries.

## UDP/IP as Primary Internet Transport

For internet-connected nodes, UDP/IP is the recommended transport:

- **NAT traversal**: UDP hole punching enables peer connections through NAT
- **Firewall compatibility**: UDP outbound rarely blocked; stateful firewalls
  pass return traffic
- **No connection state**: Matches FIPS datagram model
- **Low overhead**: 8-byte UDP header is negligible
- **Avoids TCP-over-TCP**: As noted in Design Principles, unreliable transports
  avoid adverse interactions with application-layer TCP

Raw IP with a custom protocol number would be cleaner but is blocked by most
NAT devices and firewalls, limiting deployment to networks without NAT.

## Transport Driver Interface

> **Note**: The definitive Transport trait is defined in
> [fips-architecture.md](fips-architecture.md). This section provides a
> simplified conceptual view.

Each transport driver provides:

- `send(addr, data)` — Send a FIPS packet to a transport-layer address
- `recv()` — Receive a FIPS packet from any peer
- `mtu()` — Maximum FIPS packet size for this transport
- `discover()` — Find potential peers (transport-specific mechanism)

Transport drivers handle any necessary framing, fragmentation, or encryption
at the transport layer. The FIPS routing layer sees only FIPS packets.

## Topics for Further Design

- Framing protocols for stream-based transports (TCP, WebSocket)
- Transport-layer encryption requirements vs FIPS-layer encryption
- Congestion control and flow control per transport type
- Multi-path: using multiple transports to same peer
- Transport quality metrics for parent selection
