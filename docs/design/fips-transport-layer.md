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
or hostname:port addresses, MAC addresses, .onion identifiers, radio device addresses. These are
opaque to every layer above FMP. The mapping from transport address to FIPS
identity happens at the link layer after the Noise IK link handshake completes.
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

The transport trait exposes two MTU methods:

- `fn mtu(&self) -> u16` — Transport-wide default MTU
- `fn link_mtu(&self, addr: &TransportAddr) -> u16` — Per-link MTU for a
  specific remote address. The default implementation falls back to
  `mtu()`, so transports with uniform MTU (like UDP) need not override it.

FMP uses `link_mtu()` when computing path MTU for SessionDatagram
forwarding and LookupResponse transit annotation.

### Connection Lifecycle

For connection-oriented transports, manage the underlying connection: TCP
handshake, Tor circuit establishment, Bluetooth pairing. FMP cannot begin
the Noise IK link handshake until the transport-layer connection is
established.

Connection-oriented transports expose a non-blocking connect interface.
`connect(addr)` initiates the connection in a background task and returns
immediately. `connection_state(addr)` reports the current status:

```text
ConnectionState {
    None        No connection attempt in progress
    Connecting  Background task running
    Connected   Ready for send()
    Failed(msg) Error message from failed attempt
}
```

Connectionless transports (UDP, raw Ethernet) return `Connected`
immediately — no async work needed.

At the node level, `PendingConnect` entries track links waiting for
transport connection. `poll_pending_connects()` runs each tick, checks
`connection_state()`, and calls `start_handshake()` on success or
`schedule_retry()` on failure. This decouples transport-layer connection
(which may take seconds for Tor circuits) from the FMP event loop.

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
| UDP/IP | host:port | 1280–1472 | Unreliable | Primary internet transport |
| TCP/IP | host:port | Stream | Reliable | Requires length-prefix framing |
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
require connection setup before FMP can begin the Noise IK link handshake,
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

FIPS uses `socket2::Socket` wrapped in `tokio::io::unix::AsyncFd` for the
UDP receive path. This replaces `tokio::UdpSocket` and enables direct
`libc::recvmsg()` calls with ancillary data parsing — specifically the
`SO_RXQ_OVFL` socket option, which delivers a cumulative kernel receive
buffer drop counter on every received packet. The drop counter feeds into
the ECN congestion detection system (see
[fips-mesh-layer.md](fips-mesh-layer.md#ecn-congestion-signaling)).

Socket buffers are configured at bind time via `socket2`:

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
UDP transport started local_addr=0.0.0.0:2121 recv_buf=4194304 send_buf=4194304
```

## Ethernet: The Local Network Transport

For nodes on the same LAN segment, raw Ethernet provides a direct transport
without IP/UDP overhead — 28 bytes more FIPS payload per frame compared to
UDP (1500 vs 1472 MTU).

- **No IP dependency**: Operates below the IP layer. Nodes on the same
  Ethernet segment can communicate without IP addresses or routing
  infrastructure
- **Broadcast discovery**: Nodes discover each other via periodic beacon
  broadcasts on the shared medium, with no static peer configuration required
- **Higher MTU**: Standard Ethernet frames carry 1500 bytes of payload,
  yielding an effective FIPS MTU of 1499 after the frame type prefix
- **Matches FIPS model**: Like UDP, Ethernet is connectionless and
  unreliable — datagrams flow immediately to any MAC address on the segment

### Implementation

The Ethernet transport uses Linux AF_PACKET sockets in SOCK_DGRAM mode with
EtherType 0x2121. SOCK_DGRAM mode
lets the kernel handle Ethernet header construction and parsing — the
transport deals only with payloads and MAC addresses.

Data frames use a 3-byte header: a 1-byte frame type (`0x00`) followed by
a 2-byte little-endian payload length. The length field allows the receiver
to trim Ethernet minimum-frame padding that would otherwise corrupt AEAD
verification. Beacon frames (`0x01`) use only the 1-byte type prefix
(fixed 34-byte payload). Beacons and data share the same EtherType and
socket.

| Property | Value |
| -------- | ----- |
| EtherType | 0x2121 |
| Socket type | AF_PACKET SOCK_DGRAM |
| Data frame header | `[type:1][length:2 LE][payload]` |
| Beacon frame header | `[type:1][payload]` (fixed 34 bytes) |
| Effective MTU | Interface MTU - 3 (typically 1497) |
| Addressing | 6-byte MAC address |
| Platform | Linux only (`CAP_NET_RAW` required) |

### Beacon Discovery

Ethernet nodes discover peers via broadcast beacons sent to
ff:ff:ff:ff:ff:ff. Each beacon is a 34-byte frame containing the sender's
x-only public key. Receiving nodes extract the MAC source address from the
frame and the public key from the payload, then report the discovered peer
to FMP.

Four configuration flags control discovery behavior:

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `discovery` | true | Listen for beacons from other nodes |
| `announce` | false | Broadcast beacons periodically |
| `auto_connect` | false | Initiate handshakes to discovered peers |
| `accept_connections` | false | Accept inbound handshake attempts |

A typical discoverable node sets `announce: true`, `auto_connect: true`, and
`accept_connections: true`. A passive listener uses just `discovery: true` to
observe the network without announcing itself.

### WiFi Compatibility

WiFi interfaces in infrastructure (managed) mode work transparently for
unicast — the mac80211 subsystem handles frame translation between 802.11
and 802.3. Broadcast beacon discovery is unreliable in managed mode because
access points commonly isolate clients from each other's broadcast traffic.

Startup logging:

```text
Ethernet transport started name=eth0 interface=eth0 mac=aa:bb:cc:dd:ee:ff mtu=1499 if_mtu=1500
```

## TCP/IP: Firewall Traversal Transport

For networks where UDP is blocked but TCP port 443 is open, the TCP
transport provides an alternative path.

FIPS protocols (FMP, FSP, MMP) are all unreliable datagrams. Running them
over TCP introduces head-of-line blocking, which adds latency jitter. MMP
correctly measures this jitter, and cost-based parent selection naturally
penalizes TCP links (higher SRTT leads to higher link cost). ETX will be
1.0 over TCP since TCP handles retransmission.

### Architecture

Unlike UDP (one socket serves all peers), TCP requires one `TcpStream` per
peer. The transport maintains two pools: a `ConnectingPool` for background
connection attempts in progress, and an established connection pool
(`HashMap<TransportAddr, TcpConnection>`) for active connections, plus an
optional `TcpListener` for inbound connections.

| Property | Value |
| -------- | ----- |
| Addressing | host:port — IP address or DNS hostname |
| Default MTU | 1400 bytes |
| Per-link MTU | Derived from `TCP_MAXSEG` socket option |
| Framing | FMP header-based (zero overhead) |
| Connection model | Non-blocking connect, connect-on-send fallback, optional listener |
| Platform | Cross-platform (no `#[cfg]` gates) |

### FMP Header-Based Framing

TCP is a byte stream; FIPS packets need delineation. Rather than adding a
separate length-prefix layer, the TCP transport uses the existing 4-byte
FMP common prefix `[ver+phase:1][flags:1][payload_len:2 LE]` to determine
packet boundaries:

- **Phase 0x0 (established)**: remaining = 12 + payload_len + 16 (header + AEAD tag)
- **Phase 0x1 (msg1)**: remaining = payload_len (fixed at 110, total 114 bytes)
- **Phase 0x2 (msg2)**: remaining = payload_len (fixed at 65, total 69 bytes)
- **Unknown phase**: close connection (protocol error)

This provides zero framing overhead and built-in phase validation. The
stream reader is implemented in a separate module (`stream.rs`) for reuse
by the Tor transport.

### Connection Establishment

TCP connections use a non-blocking connect model. When FMP needs to reach
a configured peer address, the node calls `connect(addr)` on the transport,
which spawns a background tokio task to perform the TCP handshake and socket
configuration (TCP_NODELAY, keepalive, buffer sizes, TCP_MAXSEG query). The
call returns immediately without blocking the event loop.

The node tracks each pending connection in a `PendingConnect` entry. On
every tick, `poll_pending_connects()` calls `connection_state(addr)` to
check progress. When the transport reports `Connected`, the completed
connection is promoted to the established pool (stream split into
read/write halves, per-connection receive task spawned), and the node
initiates the Noise IK link handshake. If the transport reports `Failed`,
the node schedules a retry with exponential backoff.

As a fallback, `send(addr, data)` still performs synchronous
connect-on-send if no connection exists — this handles the case where a
send arrives before the node-level connect path runs. The non-blocking
path is the primary mechanism for configured peers.

### Session Independence

TCP connection loss does **not** tear down the FIPS peer. Noise keys, MMP
state, and FSP sessions are bound to the peer's npub, not the TCP
connection. The transport reconnects transparently via the non-blocking
connect path or connect-on-send fallback. MMP liveness timeout is the sole
authority for peer death.

### Connection Deduplication

Simultaneous outbound connections from both sides are resolved by the
existing cross-connection tie-breaker in `promote_connection`. The losing
TCP connection is closed via `Transport::close_connection(addr)`, which
removes it from the pool and aborts its receive task.

### Configuration

```yaml
transports:
  tcp:
    bind_addr: "0.0.0.0:8443"      # Listen address (omit for outbound-only)
    mtu: 1400                       # Default MTU
    connect_timeout_ms: 5000        # Outbound connect timeout
    nodelay: true                   # TCP_NODELAY (disable Nagle)
    keepalive_secs: 30              # TCP keepalive interval (0 = disabled)
    recv_buf_size: 2097152          # SO_RCVBUF (2 MB)
    send_buf_size: 2097152          # SO_SNDBUF (2 MB)
    max_inbound_connections: 256    # Resource protection limit
```

If `bind_addr` is configured, the transport accepts inbound connections.
Without it, the transport operates in outbound-only mode (no listener
socket is created).

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

### Local/Medium Discovery

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
transport endpoints (UDP host:port, TCP host:port, .onion address). Other FIPS
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

> **Implemented**: UDP and TCP peers are configured via YAML. Ethernet
> peers are discovered via beacon broadcast — the `discover()` trait
> method returns newly seen endpoints, and per-transport `auto_connect()`
> / `accept_connections()` policies control whether discovered peers are
> connected automatically or require explicit configuration. TCP has no
> discovery mechanism (peers are configured). Nostr relay discovery is
> not yet implemented.

## Transport Interface

The transport interface defines what every transport driver must provide.

### Trait Surface

```text
transport_id()        → TransportId         Unique identifier for this transport instance
transport_type()      → &TransportType      Static metadata (name, connection-oriented, reliable)
name()                → Option<&str>        Instance name (for multi-instance transports)
state()               → TransportState      Current lifecycle state
mtu()                 → u16                 Transport-wide default MTU
link_mtu(addr)        → u16                 Per-link MTU (defaults to mtu())
start()               → lifecycle           Bring transport up (bind socket, open device)
stop()                → lifecycle           Bring transport down
send(addr, data)      → delivery            Send datagram to transport address
connect(addr)         → ()                  Initiate non-blocking connection (connection-oriented only)
connection_state(addr)→ ConnectionState     Poll connection status (None/Connecting/Connected/Failed)
close_connection(addr)→ ()                  Close a specific connection (no-op for connectionless)
congestion()          → TransportCongestion  Local congestion indicators (optional)
discover()            → Vec<DiscoveredPeer> Report discovered FIPS endpoints (optional)
auto_connect()        → bool                Auto-connect discovered peers (default: false)
accept_connections()  → bool                Accept inbound handshakes (default: true)
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

### Congestion Reporting

Transports optionally report local congestion indicators via a
`TransportCongestion` struct, providing a transport-agnostic interface for
the node layer's ECN congestion detection:

```text
TransportCongestion {
    recv_drops: Option<u64>    Cumulative kernel-dropped packets (monotonic)
}
```

The node samples each transport's congestion state on a 1-second tick via
`sample_transport_congestion()`. `TransportDropState` tracks per-transport
drop deltas: when new drops appear (rising edge), the `dropping` flag is
set, and `detect_congestion()` in the forwarding path triggers CE marking
on all forwarded datagrams.

| Transport | Congestion Source | Mechanism |
| --------- | ----------------- | --------- |
| UDP | `SO_RXQ_OVFL` kernel drop counter | `recvmsg()` ancillary data on every packet |
| TCP | Not yet implemented | Returns `None` (TCP handles congestion internally) |
| Ethernet | Not yet implemented | Returns `None` |

### Transport Addresses

Transport addresses (`TransportAddr`) are opaque byte vectors. The transport
layer interprets them (e.g., UDP/TCP resolve "host:port" strings (IP fast path, DNS fallback with 60s cache for UDP)); all layers above
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
| UDP/IP | **Implemented** | Primary transport, AsyncFd/recvmsg, SO_RXQ_OVFL kernel drop detection |
| TCP/IP | **Implemented** | FMP header-based framing, non-blocking connect, per-connection MSS MTU |
| Ethernet | **Implemented** | AF_PACKET SOCK_DGRAM, EtherType 0x2121, beacon discovery, Linux only |
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
quality. The spanning tree parent selection factors in link quality through
cost-based effective depth (`effective_depth = depth + link_cost`), where
`link_cost` is derived from locally measured MMP metrics (ETX and SRTT).
This allows the tree to prefer lower-latency, lower-loss links when the
quality difference is significant. Link cost is not yet used in
`find_next_hop()` candidate ranking for data forwarding.

## References

- [fips-intro.md](fips-intro.md) — Protocol overview and layer architecture
- [fips-mesh-layer.md](fips-mesh-layer.md) — FMP specification (the layer above)
- [fips-wire-formats.md](fips-wire-formats.md) — Transport framing details
