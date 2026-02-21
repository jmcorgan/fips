# FIPS Transport Layer

The transport layer is the bottom of the FIPS protocol stack. It delivers
datagrams between transport-specific endpoints over arbitrary physical or
logical media. Everything above — peer authentication, routing, encryption,
session management — is built on the services the transport layer provides.

## Role

A **transport** is a driver for a particular communication medium: a UDP
socket, an Ethernet interface, a serial line, a Tor circuit, a radio modem.
The transport layer's job is simple: accept a datagram and a transport
address, deliver the datagram to that address, and push inbound datagrams up
to the FIPS Mesh Protocol (FMP) above.

The transport layer deals exclusively in **transport addresses** — IP:port
tuples, MAC addresses, .onion identifiers, radio device addresses. These are
opaque to every layer above FMP. The mapping from transport address to FIPS
identity happens at the link layer after the Noise IK handshake completes.
The word "peer" belongs to the link layer and above; the transport layer
knows only about remote endpoints identified by transport addresses.

A single transport instance can serve multiple remote endpoints
simultaneously — a UDP socket exchanges datagrams with many remote
addresses, an Ethernet interface communicates with many MAC addresses on the
same segment. Each endpoint may become a separate FMP link, but the
transport layer itself maintains no per-endpoint state.

## Services Provided to FMP

The transport layer provides four services to the FIPS Mesh Protocol above:

### Datagram Delivery

Send and receive datagrams to/from transport addresses. The transport
handles all medium-specific details: socket management, framing for stream
transports, radio configuration. FMP sees only "send bytes to address" and
"bytes arrived from address."

Inbound datagrams are pushed to FMP through a channel. The transport spawns
a receive task that pushes arriving datagrams (along with the source
transport address and transport identifier) onto a bounded channel. FMP
reads from this channel and dispatches based on the source address and
packet content.

### MTU Reporting

Report the maximum datagram size for a given link. FMP needs this to
determine how much payload can fit in a single packet after link-layer
encryption overhead.

MTU is fundamentally a per-link property. A transport with a fixed MTU
(Ethernet: 1500, UDP configured at 1472) returns the same value for every
link — this is the degenerate case. Transports that negotiate MTU
per-connection (e.g., BLE ATT_MTU) report the negotiated value for each
link individually.

> **Implementation note**: The current transport trait exposes MTU as a
> transport-wide method (`fn mtu(&self) -> u16`). This works for UDP, where
> MTU is a static configuration value. Supporting per-link MTU for future
> transports will require extending this interface.

### Connection Lifecycle

For connection-oriented transports, manage the underlying connection: TCP
handshake, Tor circuit establishment, Bluetooth pairing. FMP cannot begin
the Noise IK handshake until the transport-layer connection is established.

Connectionless transports (UDP, raw Ethernet) skip this — datagrams can flow
immediately to any reachable address.

### Discovery (Optional)

Notify FMP when FIPS-capable endpoints are discovered on the local medium.
This is an optional capability — transports that don't support it simply
don't provide discovery events.

See [Discovery](#discovery) below for details.

## Transport Properties

Transports vary widely in their characteristics. FIPS operates over all of
them because the transport interface abstracts these differences behind a
uniform datagram service.

### Transport Categories

**Overlay transports** tunnel FIPS over an existing network layer, typically
for internet connectivity:

| Transport | Addressing | MTU | Reliability | Notes |
| --------- | ---------- | --- | ----------- | ----- |
| UDP/IP | IP:port | 1280–1472 | Unreliable | Primary internet transport |
| TCP/IP | IP:port | Stream | Reliable | Requires length-prefix framing |
| WebSocket | URL | Stream | Reliable | Browser-compatible |
| Tor | .onion | Stream | Reliable | High latency, strong anonymity |

**Shared medium transports** operate over broadcast- or multicast-capable
media:

| Transport | Addressing | MTU | Reliability | Notes |
| --------- | ---------- | --- | ----------- | ----- |
| Ethernet | MAC | 1500 | Unreliable | Raw AF_PACKET frames |
| WiFi | MAC | 1500 | Unreliable | Infrastructure mode = Ethernet |
| Bluetooth | BD_ADDR | 672–64K | Reliable | L2CAP |
| BLE | BD_ADDR | 23–517 | Reliable | Negotiated ATT_MTU |
| Radio | Device addr | 51–222 | Unreliable | Low bandwidth, long range |

**Point-to-point transports** connect exactly two endpoints:

| Transport | Addressing | MTU | Reliability | Notes |
| --------- | ---------- | --- | ----------- | ----- |
| Serial | None (P2P) | 256–1500 | Reliable | SLIP/COBS framing |
| Dialup | None (P2P) | 1500 | Reliable | PPP framing |

### Properties That Matter to FMP

**MTU**: Determines how much data FMP can pack into a single datagram after
accounting for link encryption overhead. Heterogeneous MTUs across the mesh
are normal — the IPv6 minimum (1280 bytes) is the safe baseline for FIPS
packet sizing.

**Reliability**: Whether the transport guarantees delivery. FIPS prefers
unreliable transports because running TCP application traffic over a reliable
transport creates TCP-over-TCP, where retransmission and congestion control
at both layers interact adversely. FIPS tolerates packet loss, reordering,
and duplication at the routing layer.

**Connection model**: Connectionless transports (UDP, raw Ethernet) allow
immediate datagram exchange. Connection-oriented transports (TCP, Tor, BLE)
require connection setup before FMP can begin the Noise IK handshake,
adding startup latency.

**Stream vs. datagram**: Datagram transports have natural packet boundaries.
Stream transports (TCP, WebSocket, Tor) require framing to delineate FIPS
packets within the byte stream. The FMP common prefix includes a payload
length field that provides this framing directly, replacing the need for a
separate length-prefix layer.

**Addressing opacity**: Transport addresses are opaque byte vectors. FMP
doesn't interpret them — it just passes them back to the transport when
sending. This means adding a new transport type with a novel address format
requires no changes to FMP or FSP.

## Connection Model

### Connectionless Transports

Datagrams can be sent to any reachable address without prior setup. Links
are lightweight — a transport address is sufficient to begin communication.

| Transport | Notes |
| --------- | ----- |
| UDP/IP | Stateless datagrams; NAT state is implicit |
| Ethernet | Send to MAC address directly |
| Radio | Raw packets to device address |

### Connection-Oriented Transports

Explicit connection setup is required before FIPS traffic can flow. The link
must complete transport-layer connection before FMP authentication can
proceed.

| Transport | Connection Setup |
| --------- | ---------------- |
| TCP/IP | TCP three-way handshake |
| WebSocket | HTTP upgrade + TCP |
| Tor | Circuit establishment (500ms–5s) |
| Bluetooth | L2CAP connection |
| BLE | L2CAP CoC or GATT connection |
| Serial | Physical connection (static) |

### Implications

**Link lifecycle**: Connectionless transports use a trivial link model.
Connection-oriented transports need a real state machine: Connecting →
Connected → Disconnected. Failure can occur during connection setup, adding
error handling paths that connectionless transports don't have.

**Startup latency**: Connection-oriented transports add delay before a peer
becomes usable. This ranges from milliseconds (TCP) to seconds (Tor
circuit). Peer timeout configuration must account for transport-specific
setup times.

**Framing**: Stream transports must delimit FIPS packets within the byte
stream. The FMP common prefix includes a payload length field that provides
integrated framing. Datagram transports preserve packet boundaries naturally.

## UDP/IP: The Primary Internet Transport

For internet-connected nodes, UDP/IP is the recommended transport:

- **No TCP-over-TCP**: UDP's unreliable delivery avoids the adverse
  interaction between application-layer TCP retransmission and transport-layer
  TCP retransmission
- **NAT traversal**: UDP hole punching enables peer connections through NAT
  without relay infrastructure
- **Low overhead**: 8-byte UDP header, no connection state
- **Matches FIPS model**: FIPS is datagram-oriented; UDP preserves this
  naturally without framing

Raw IP with a custom protocol number would be simpler but is blocked by most
NAT devices and firewalls, limiting deployment to networks without NAT.

### Socket Buffer Sizing

The default Linux UDP receive buffer (`net.core.rmem_default`, typically
212 KB) is insufficient for high-throughput forwarding. At ~85 MB/s, a 212 KB
buffer fills in ~2.5 ms; any stall in the async receive loop (decryption,
routing, forwarding overhead) causes the kernel to silently drop incoming
datagrams.

FIPS uses the `socket2` crate to configure socket buffers at bind time,
before the receive loop starts:

| Parameter        | Default | Description                          |
| ---------------- | ------- | ------------------------------------ |
| `recv_buf_size`  | 2 MB    | `SO_RCVBUF` — kernel receive buffer  |
| `send_buf_size`  | 2 MB    | `SO_SNDBUF` — kernel send buffer     |

Linux internally doubles the requested value (to account for kernel
bookkeeping overhead), so requesting 2 MB yields 4 MB actual buffer space.
The kernel silently clamps to `net.core.rmem_max` if the request exceeds it.

**Host requirement**: `net.core.rmem_max` and `net.core.wmem_max` must be
set to at least the requested buffer size on the host. For Docker containers,
this must be configured on the Docker host (containers share the host kernel).
Verify with:

```text
sysctl net.core.rmem_max net.core.wmem_max
```

Actual buffer sizes are logged at startup:

```text
UDP transport started local_addr=0.0.0.0:4000 recv_buf=4194304 send_buf=4194304
```

## Discovery

Discovery determines that a FIPS-capable endpoint is reachable at a given
transport address. It is distinct from raw transport-level endpoint
detection — a new TCP connection or UDP packet from an unknown source is not
discovery; a FIPS-specific announcement or response is.

Discovery is an optional transport capability. Transports that don't support
it (configured UDP endpoints, TCP) simply don't provide discovery events.
FMP handles both cases uniformly: with discovery, it waits for events then
initiates link setup; without discovery, it initiates link setup directly to
configured addresses.

### Local/Medium Discovery *(future direction)*

For transports where endpoints share a physical or link-layer medium — LAN
broadcast, radio, BLE — discovery uses beacon and query mechanisms:

- **Beacon**: A node periodically broadcasts its FIPS presence on the shared
  medium. Content is a FIPS-defined discovery frame carrying enough
  information to initiate a link. Non-FIPS endpoints ignore the frame.
- **Query**: A node broadcasts a one-shot solicitation. FIPS-capable nodes
  respond. Responses arrive on the same channel as beacon events.

Both produce the same result: "FIPS endpoint available at transport address
X." FMP does not need to distinguish beacons from query responses.

| Transport | Discovery | Notes |
| --------- | --------- | ----- |
| UDP (LAN) | Broadcast/multicast | On local network segment |
| Ethernet | Broadcast | Custom EtherType, ff:ff:ff:ff:ff:ff |
| Radio | Beacon | Shared RF channel, natural fit |
| BLE | Advertising | GATT service UUID |

### Nostr Relay Discovery *(future direction)*

For internet-reachable transports, a node publishes a signed Nostr event
containing its FIPS discovery information — public key and reachable
transport endpoints (UDP IP:port, TCP IP:port, .onion address). Other FIPS
nodes subscribing on the same relays learn about available peers.

Nostr relay discovery is not a transport — it is a discovery service that
feeds addresses to other transports. A node discovers via Nostr that a peer
is reachable at UDP 1.2.3.4:9735, then establishes the link over the UDP
transport.

Key properties:
- Identity is built in — Nostr events are signed, so discovery information
  is authenticated
- Relay selection acts as scoping — which relays a node publishes to and
  subscribes on determines its discovery neighborhood
- Can only advertise IP-reachable endpoints (not radio, BLE, serial)
- Higher latency than local discovery (relay propagation delays)

### Current State

> **Implemented**: Peer addresses come from YAML configuration. The
> transport trait's `discover()` method exists but returns an empty list for
> UDP. Transport-level discovery (beacon/query, Nostr relay) is not yet
> implemented.

## Transport Interface

The transport interface defines what every transport driver must provide.

### Trait Surface

```text
transport_id()    → TransportId       Unique identifier for this transport instance
transport_type()  → &TransportType    Static metadata (name, connection-oriented, reliable)
state()           → TransportState    Current lifecycle state
mtu()             → u16              Maximum datagram size
start()           → lifecycle         Bring transport up (bind socket, open device)
stop()            → lifecycle         Bring transport down
send(addr, data)  → delivery          Send datagram to transport address
discover()        → Vec<DiscoveredPeer>  Report discovered FIPS endpoints (optional)
```

### Receive Path

Rather than a synchronous receive method, transports use a channel-push
model. Each transport takes a sender handle at construction and spawns an
internal receive loop that pushes inbound datagrams onto the channel. The
node's main event loop reads from the corresponding receiver, which
aggregates datagrams from all active transports into a single stream.

Each inbound datagram carries:
- **transport_id** — which transport it arrived on
- **remote_addr** — the transport address of the sender
- **data** — the raw datagram bytes
- **timestamp** — arrival time

### Transport Metadata

Transport types carry static metadata that FMP can query:

```text
TransportType {
    name              "udp", "ethernet", "tor", etc.
    connection_oriented   bool
    reliable              bool
}
```

Predefined types exist for UDP, TCP, Ethernet, WiFi, Tor, and Serial.

### Transport Addresses

Transport addresses (`TransportAddr`) are opaque byte vectors. The transport
layer interprets them (e.g., UDP parses "ip:port" strings); all layers above
treat them as opaque handles passed back to the transport for sending.

### Transport State Machine

```text
Configured → Starting → Up → Down
                         ↓
                       Failed
```

Transports begin in `Configured` state with all parameters set. `start()`
transitions through `Starting` to `Up` (operational). `stop()` moves to
`Down`. Transport failures move to `Failed`.

## Implementation Status

| Transport | Status | Notes |
| --------- | ------ | ----- |
| UDP/IP | **Implemented** | Primary transport, async send/receive, configurable MTU |
| TCP/IP | Future direction | Requires stream framing, TCP-over-TCP concern |
| Ethernet | Future direction | AF_PACKET raw frames, EtherType TBD |
| WiFi | Future direction | Infrastructure mode = Ethernet driver |
| Tor | Future direction | High latency, .onion addressing |
| BLE | Future direction | ATT_MTU negotiation, per-link MTU |
| Radio | Future direction | Constrained MTU (51–222 bytes) |
| Serial | Future direction | SLIP/COBS framing, point-to-point |

## Design Considerations

### TCP-over-TCP Avoidance

Running TCP application traffic over a reliable transport (TCP, WebSocket)
creates a layering violation where retransmission and congestion control
operate at both levels. When the inner TCP detects loss (which may just be
transport-layer retransmission delay), it retransmits, creating more traffic
for the outer TCP, which may itself be retransmitting. This amplification
loop degrades performance severely under any packet loss.

FIPS prefers unreliable transports for this reason. When a reliable transport
must be used (e.g., Tor), applications should be aware of the performance
implications.

### Multi-Transport Operation

A node can run multiple transports simultaneously. Peers from all transports
feed into a single spanning tree and routing table. If one transport fails,
traffic automatically routes through alternatives. A node with both UDP and
Ethernet transports bridges between internet-connected and local-only
networks transparently.

Multiple links to the same peer over different transports are possible. FMP
manages these independently — each link has its own Noise session, its own
MTU, and its own liveness tracking.

### Transport Quality and Path Selection

Transport characteristics (latency, bandwidth, reliability) affect path
quality but are not currently factored into routing decisions. The spanning
tree parent selection uses a depth improvement threshold but does not
consider transport quality. This is a potential area for future optimization.

## References

- [fips-intro.md](fips-intro.md) — Protocol overview and layer architecture
- [fips-mesh-layer.md](fips-mesh-layer.md) — FMP specification (the layer above)
- [fips-wire-formats.md](fips-wire-formats.md) — Transport framing details
- [fips-software-architecture.md](fips-software-architecture.md) — Transport
  trait implementation details
