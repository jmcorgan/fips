# FIPS Software Architecture

**Status**: Design Draft

This document describes the software architecture for a FIPS node implementation,
covering core entities, state machines, transport abstractions, and configuration.

---

## Overview

FIPS is a Layer 3 mesh routing protocol that provides IPv6 connectivity over
heterogeneous link types. A FIPS node exposes a TUN interface to local applications,
routes packets via a spanning tree topology, and uses Bloom filters for efficient
reachability lookup.

The architecture is event-driven with multiple focused state machines rather than
a single monolithic event handler. Control protocols are designed for eventual
consistency, tolerating packet loss without requiring acknowledgment/retry machinery.

---

## Core Entities

### Node

The top-level entity representing a running FIPS instance.

```
Node
├── identity: Identity              // cryptographic identity (npub/nsec)
├── config: Config                  // loaded configuration
├── tun: TunInterface               // IPv6 interface to local applications
├── tree_state: TreeState           // local view of spanning tree
├── coord_cache: CoordCache         // address → coordinates for routing
├── transports: HashMap<TransportId, Transport>
├── links: HashMap<LinkId, Link>
└── peers: HashMap<NodeAddr, Peer>
```

### Identity

Cryptographic identity using Nostr keys (secp256k1).

```
Identity
├── npub: PublicKey                 // public key (bech32: npub1...)
├── nsec: SecretKey                 // secret key (bech32: nsec1...)
├── node_addr: NodeAddr                 // SHA-256(pubkey) truncated, 16 bytes
└── address: FipsAddress            // IPv6 ULA derived from node_addr (fd::/8)
```

`NodeAddr` is the routing identifier, derived deterministically from `npub`.
Transport addresses and FIPS identity are fully decoupled.

### Protocol Layer Visibility

| Observer                      | Link Addr     | Node Addr    | FIPS Addr (pubkey) | Payload |
|-------------------------------|---------------|--------------|--------------------| --------|
| Transport (IP router, switch) | Yes           | No           | No                 | No      |
| FIPS routing node             | Last hop only | Yes (header) | No                 | No      |
| Destination endpoint          | Yes           | Yes          | Yes                | Yes     |

**Key insight**: Three independent encryption layers ensure:

- Passive transport observers see only encrypted blobs
- FIPS routing nodes see node_addrs but not pubkeys (FIPS addresses) or payload
- Only endpoints know each other's FIPS addresses (pubkeys) and can decrypt payload

### Transport

A physical or logical interface over which links can be established. Transports
are statically configured and exist for the lifetime of the node after startup.

```
Transport (trait)
├── transport_id: TransportId
├── transport_type: TransportType
├── config: TransportConfig
├── state: TransportState
├── mtu: u16
│
├── start() -> Result<()>
├── stop() -> Result<()>
├── send(addr: &TransportAddr, data: &[u8]) -> Result<()>
├── recv() -> Result<(TransportAddr, Vec<u8>)>
└── discover() -> Result<Vec<DiscoveredPeer>>
```

**Transport metadata (static per type):**

```
TransportType
├── name: &'static str              // "udp", "ethernet", "wifi", "tor"
├── connection_oriented: bool       // requires link establishment?
└── reliable: bool                  // delivery guaranteed by transport?
```

Transports handle framing, fragmentation, and any transport-layer encryption
internally. The FIPS routing layer sees only FIPS packets.

### Link

A communication channel to a specific remote endpoint over a transport. Links are
created on demand when connecting to a peer and torn down when the peer connection
terminates. Link lifecycle is driven by the peer lifecycle.

```
Link
├── link_id: LinkId
├── transport_id: TransportId
├── remote_addr: TransportAddr      // opaque, transport-specific
├── direction: Inbound | Outbound
├── state: LinkState                // trivial for connectionless, real for Tor
├── base_rtt: Duration              // hint from transport type
└── io: ...                         // connection handles for connection-oriented
```

For connectionless transports (UDP, Ethernet, WiFi), links are lightweight—just
`(transport_id, remote_addr)` with implicit "established" state (no connection
setup required).

For connection-oriented transports (Tor), links track real connection state and
hold I/O handles. The link must complete transport-layer connection setup before
FIPS session establishment can proceed.

**Link statistics (measured):**

```
LinkStats
├── packets_sent: u64
├── packets_recv: u64
├── bytes_sent: u64
├── bytes_recv: u64
├── last_recv: Timestamp
├── rtt_estimate: Duration          // measured from probes
├── loss_rate: f32                  // observed (meaningful for unreliable)
└── throughput_estimate: u64        // bytes/sec observed
```

### Peer

An authenticated remote FIPS node, reachable via a link.

```
Peer
├── node_addr: NodeAddr                 // routing identity
├── npub: PublicKey                 // cryptographic identity
├── link_id: LinkId                 // which link reaches this peer
├── state: PeerState                // lifecycle state
│
│  // Spanning tree
├── declaration: ParentDeclaration  // their latest
├── ancestry: Vec<NodeAddr>           // their path to root
│
│  // Bloom filter (inbound—what's reachable through them)
├── inbound_filter: BloomFilter
├── filter_sequence: u64
├── filter_received_at: Timestamp
├── pending_filter_update: bool     // we owe them an update
│
│  // Statistics
└── link_stats: LinkStats
```

**Peer/Link Lifecycle:**

Links and peers have a one-to-one mapping with coupled lifecycles:

1. **Outbound connection**: Desire to connect to a peer triggers link creation
   over the appropriate transport. For connection-oriented transports (Tor), the
   link goes through connection setup; for connectionless (UDP), it immediately
   becomes established. Once the link is ready, FIPS authentication proceeds.

2. **Inbound connection**: Incoming data on a transport creates a link, then
   authentication creates the peer.

3. **Peer references link**: An authenticated peer always references exactly one
   active link.

4. **Termination**: When a peer connection terminates, the associated link is
   torn down. For connectionless transports this is trivial cleanup; for
   connection-oriented transports this closes the underlying connection.

If the same remote node is reachable via multiple transports, that would be
multiple Peer entries (though for initial implementation, we assume single
transport per peer).

---

## Spanning Tree State

### Per-Node State

```
TreeState
├── my_declaration: ParentDeclaration
│   ├── node_addr: NodeAddr
│   ├── parent_id: NodeAddr           // self if root candidate
│   ├── sequence: u64               // monotonic
│   └── signature: Signature
├── my_coords: Vec<NodeAddr>          // [self, parent, grandparent, ..., root]
└── root: NodeAddr                    // elected root (smallest reachable node_addr)
```

### Per-Peer State

From each peer, we receive and store:

- Their `ParentDeclaration`
- Their `ancestry` (path from peer to root)

This provides their tree coordinates for routing decisions.

### Bounded State

Each node's TreeState contains O(P × D) entries, not O(N):

- P = direct peer count
- D = tree depth

A node knows only:

1. Its own parent declaration
2. Direct peers' parent declarations
3. Ancestry chains from each peer to root

Nodes do NOT know about other subtrees—only paths toward root.

---

## Bloom Filter State

### Per-Node State

```
BloomState
├── own_node_addr: NodeAddr             // always included in outgoing filters
├── leaf_dependents: HashSet<NodeAddr>  // leaf-only nodes we speak for
├── is_leaf_only: bool              // if true, no filter processing
└── update_debounce: Duration       // rate limit outgoing updates
```

### Per-Peer State

Stored on Peer:

- `inbound_filter`: what they advertise to us (1KB Bloom filter)
- `filter_sequence`: freshness/dedup
- `filter_received_at`: for staleness detection

### Computed (On-Demand)

Outgoing filter to peer Q is computed, not stored:

```
outbound_filter(Q) =
    own_node_addr
    ∪ leaf_dependents
    ∪ { entries from peer[P].inbound_filter for all P ≠ Q }
```

Recomputation is cheap (1KB filter, 5 hashes) so on-demand is preferred over
cache invalidation complexity.

---

## State Machines

### Transport Lifecycle

```
    Configured ──► Starting ──► Up ──► Down
                       │        │       │
                       v        v       │
                    Failed ◄────────────┘
```

- `Configured`: in config, not started
- `Starting`: initialization in progress (instant for UDP, slow for Tor)
- `Up`: ready for links
- `Down`: was up, now unavailable
- `Failed`: couldn't start

**Events:**

- `Start` (from config policy or API)
- `Started` / `StartFailed`
- `Shutdown`
- `TransportError`

**Cascading:** Transport down → all links over it disconnect → all peers on
those links disconnect.

### Link Lifecycle

**Connectionless transports (UDP, Ethernet, WiFi):**

Links are always implicitly "active"—no state machine needed. Link exists when
we have `(transport_id, remote_addr)`.

**Connection-oriented transports (Tor):**

```
Outbound:
    (connect requested) ──► Connecting ──► Connected ──► Disconnected
                                │                            ▲
                                v                            │
                             Failed ─────────────────────────┘

Inbound:
    (transport accepts) ──► Connected ──► Disconnected
```

- `Connecting`: establishing connection (circuit for Tor)
- `Connected`: ready for FIPS traffic
- `Disconnected`: was connected, now gone
- `Failed`: connection attempt failed

### Peer Lifecycle

The peer lifecycle uses Noise IK for authentication. Noise IK is a 2-message
handshake where the initiator knows the responder's static key. See
[fips-wire-protocol.md](fips-wire-protocol.md) §2 for wire format details.

```
                        ┌─────────────────────────────────────────┐
                        │              Disconnected               │
                        └─────────────────────────────────────────┘
                             │                           │
                  [outbound] │                           │ [inbound msg1]
                             ▼                           ▼
                  ┌──────────────────┐        ┌──────────────────┐
                  │    Connecting    │        │  ReceivedMsg1    │
                  │(conn-oriented)   │        │  (send msg2)     │
                  └──────────────────┘        └──────────────────┘
                             │                           │
              [link ready]   │                           │ [recv encrypted]
              [send msg1]    │                           │ [verify]
                             ▼                           │
                  ┌──────────────────┐                   │
                  │  AwaitingMsg2    │                   │
                  │  (sent msg1)     │                   │
                  └──────────────────┘                   │
                             │                           │
              [recv msg2]    │                           │
              [verify]       │                           │
                             ▼                           ▼
                        ┌─────────────────────────────────────────┐
                        │                 Active                  │
                        │    (tree gossip, filter exchange)       │
                        └─────────────────────────────────────────┘
                                            │
                                            │ [link down / timeout]
                                            ▼
                        ┌─────────────────────────────────────────┐
                        │              Disconnected               │
                        │         (retry if static peer)          │
                        └─────────────────────────────────────────┘
```

**State descriptions:**

- `Disconnected`: No active connection; for static peers, retry with backoff
- `Connecting`: Link establishment in progress (connection-oriented transports only)
- `ReceivedMsg1`: Inbound; received Noise IK msg1, sent msg2, awaiting first encrypted frame
- `AwaitingMsg2`: Outbound; sent Noise IK msg1, waiting for msg2
- `Active`: Authenticated; participating in tree gossip and filter exchange

**Crossing connection handling:**

When in `AwaitingMsg2` and we receive a msg1 from the same peer (both sides
initiated simultaneously):

- If local npub < remote npub: Ignore incoming msg1, remain initiator
- If local npub > remote npub: Switch to responder role, send msg2,
  transition to `ReceivedMsg1`

**Events:**

```
PeerEvent
├── Discovered { link_id, transport_addr, hint: Option<PublicKey> }
├── LinkConnected
├── LinkFailed { reason }
├── Msg1Received { noise_payload }
├── Msg2Received { noise_payload }
├── HandshakeComplete { npub, node_addr }
├── HandshakeFailed { reason }
├── TreeAnnounceReceived { declaration, ancestry }
├── FilterAnnounceReceived { filter, sequence, ttl }
├── Timeout { kind: TimeoutKind }
├── PacketReceived { ... }
└── LinkDisconnected { reason }
```

---

## Reference Transport Types

### UDP/IP

```
UdpTransport
├── bind_addr: SocketAddr           // e.g., 0.0.0.0:4000
├── socket: UdpSocket
└── state: TransportState

TransportAddr = SocketAddr          // IP:port
```

| Property | Value |
|----------|-------|
| Connection-oriented | No |
| Reliable | No |
| MTU | 1280-1472 |
| Latency | Low (1-500ms) |
| Scope | Internet |
| Discovery | DNS-SD, Nostr, static config |
| Privileges | None |
| NAT | Hole punching possible |

### Ethernet

```
EthernetTransport
├── interface: String               // "eth0"
├── socket: RawSocket               // AF_PACKET
├── local_mac: MacAddr
├── ethertype: u16                  // FIPS ethertype
└── state: TransportState

TransportAddr = MacAddr             // 6 bytes
```

| Property | Value |
|----------|-------|
| Connection-oriented | No |
| Reliable | No |
| MTU | 1500 |
| Latency | <1ms |
| Scope | Local segment |
| Discovery | Multicast |
| Privileges | CAP_NET_RAW |

### WiFi

```
WifiTransport
├── interface: String               // "wlan0"
├── socket: RawSocket
├── local_mac: MacAddr
├── mode: Infrastructure | AdHoc | Direct
└── state: TransportState

TransportAddr = MacAddr             // same as Ethernet
```

| Property | Value |
|----------|-------|
| Connection-oriented | No |
| Reliable | No |
| MTU | 1500 |
| Latency | 1-10ms |
| Scope | Local segment (or Direct group) |
| Discovery | Multicast, P2P service discovery |
| Privileges | CAP_NET_RAW |

Infrastructure and Ad-hoc modes behave like Ethernet. WiFi Direct has its own
service discovery mechanism.

### Tor Onion

```
TorTransport
├── tor_client: TorClient           // arti or external daemon
├── onion_service: Option<OnionService>
├── local_onion_addr: Option<OnionAddr>
└── state: TransportState

TransportAddr = OnionAddr           // "abc...xyz.onion:port"
```

| Property | Value |
|----------|-------|
| Connection-oriented | Yes |
| Reliable | Yes (stream) |
| MTU | Stream (framed) |
| Latency | 500ms-5s |
| Scope | Internet (anonymous) |
| Discovery | Nostr, static config |
| Privileges | None |
| Transport startup | Slow (30s-2min for Tor bootstrap) |

Tor links require framing (length-prefix) over the stream. The .onion address
is independent of FIPS npub—identity verified via FIPS auth after connecting.

### Transport Comparison

| Aspect | UDP | Ethernet | WiFi | Tor |
|--------|-----|----------|------|-----|
| Connection | No | No | No | Yes |
| Link state machine | Trivial | Trivial | Trivial | Real |
| Address type | IP:port | MAC | MAC | .onion:port |
| Startup time | Instant | Instant | Instant | 30s-2min |
| Base RTT hint | 50ms | 1ms | 5ms | 2s |
| Framing | Datagram | Datagram | Datagram | Length-prefix |

---

## Event-Driven Architecture

The system uses multiple focused state machines rather than one giant event
handler:

1. **Transport state machines** — one per transport instance
2. **Link state machines** — one per link (meaningful for connection-oriented)
3. **Peer state machines** — one per peer
4. **Spanning tree module** — reacts to peer events, emits announcements
5. **Bloom filter module** — reacts to peer/filter events, emits updates

**Event flow:**

```
Transport
    │
    ├──► DiscoveredPeer { transport_id, addr, hint }
    ├──► InboundConnection { transport_id, addr, io }  (connection-oriented)
    └──► PacketReceived { transport_id, addr, data }
              │
              v
           Link
              │
              ├──► LinkConnected { link_id }
              ├──► LinkDisconnected { link_id, reason }
              └──► FipsPacketReceived { link_id, packet }
                        │
                        v
                     Peer
                        │
                        ├──► AuthSuccess { peer_id }
                        ├──► TreeAnnounceReceived { peer_id, decl, ancestry }
                        └──► FilterAnnounceReceived { peer_id, filter, seq, ttl }
                                  │
                                  v
                           TreeState / BloomState
```

Timers drive keepalives, timeouts, and periodic refresh (debounced announcements).

---

## Protocol Self-Healing Design

Control protocols tolerate packet loss without ack/retry machinery:

### TreeAnnounce

- Monotonic sequence numbers (receiver keeps highest, ignores stale/dup)
- Full state (declaration + ancestry), not deltas
- Periodic refresh ensures convergence
- Lost announcement? Next one carries same or newer state

### FilterAnnounce

- Full filter replacement with sequence number
- Periodic refresh
- Debounced on rapid changes
- Lost announcement? Peer has stale filter until next update

### LookupRequest/LookupResponse

- Request-response pattern
- Lost request/response → sender times out, retries at application level

### SessionSetup/SessionAck

- Same as lookup—sender retries on timeout
- Lost setup → first data packet fails → triggers re-establishment

This gossip-style eventual consistency is simpler and avoids the complexity of
per-message reliability over unreliable links.

---

## Leaf-Only Operation

Leaf-only mode enables constrained devices (sensors, battery-powered nodes, mobile
devices) to participate in FIPS without the overhead of full mesh routing.

### Architectural Subset

A leaf-only node uses a minimal subset of the full architecture:

```
LeafOnlyNode
├── identity: Identity              // full (npub, nsec, node_addr, address)
├── config: Config                  // simplified
├── tun: TunInterface               // full (provides IPv6 to local apps)
├── transport: Transport            // one
├── link: Link                      // one
└── upstream_peer: Peer             // one (simplified)
```

### What's Required

| Component           | Usage                                    |
|---------------------|------------------------------------------|
| Identity            | Full—same cryptographic identity model   |
| TUN interface       | Full—provides IPv6 to local applications |
| Transport           | One instance (to reach upstream peer)    |
| Link                | One instance (to upstream peer)          |
| Peer                | One instance (upstream), with auth only  |
| Peer authentication | Full—must prove identity to upstream     |
| Packet send/receive | Full                                     |

### What's Not Required

| Component          | Reason                                           |
|--------------------|--------------------------------------------------|
| TreeState          | No tree participation; upstream handles routing  |
| ParentDeclaration  | Doesn't announce position to network             |
| Bloom filters      | Upstream peer handles reachability               |
| Filter computation | N/A                                              |
| CoordCache         | Doesn't route for others                         |
| Discovery protocol | Upstream peer handles lookups                    |
| Multiple peers     | Single upstream by design                        |
| Session caching    | Tunnels everything to upstream                   |
| Transit routing    | Never forwards for others                        |

### Simplified Peer Structure

The upstream peer entry for a leaf-only node:

```
UpstreamPeer (leaf-only)
├── node_addr: NodeAddr
├── npub: PublicKey
├── link_id: LinkId
├── state: PeerState                // auth lifecycle only
└── link_stats: LinkStats           // for keepalive/timeout

// NOT present:
// - declaration, ancestry (no tree participation)
// - inbound_filter, filter_* (no Bloom filters)
```

### Routing Behavior

```
Outbound (local app → network):
    TUN → upstream peer (unconditionally)

Inbound (network → local app):
    upstream peer → TUN (if dest == self)
    upstream peer → DROP (if dest ≠ self, never transit)
```

The leaf-only node doesn't make routing decisions—it tunnels everything to/from
its upstream peer.

### Upstream Peer Responsibilities

The upstream peer (a full participant) handles:

- Including leaf-only node in its Bloom filter
- Responding to LookupRequests for the leaf-only node
- Forwarding packets to/from the leaf-only node
- The leaf-only node appears as an entry in the upstream's `leaf_dependents` set

### State Machine (Simplified)

Only peer lifecycle matters:

```
    Configured ──► Connecting ──► Authenticating ──► Active ──► Disconnected
                       │               │                            │
                       v               v                            │
                    [fail] ─────────────────────────────────────────┘
```

No TreeAnnounce or FilterAnnounce processing in the Active state.

### Configuration (Leaf-Only Subset)

```
# Required
node.identity.nsec              # or auto-generated
node.leaf_only = true
node.tun.device
node.tun.mtu

# One transport
transport.udp.enabled = true    # or ethernet, wifi, tor
transport.udp.bind_addr

# One peer (the upstream)
peers[0].npub                   # required: upstream identity
peers[0].addresses[0].type      # transport type
peers[0].addresses[0].addr      # how to reach them
peers[0].connect_policy = auto_connect

# Timeouts
peer.auth.timeout
peer.keepalive.interval
peer.keepalive.timeout
peer.reconnect.*
```

Parameters NOT relevant to leaf-only operation:

```
tree.*                          # no tree participation
filter.*                        # no Bloom filters
discovery.*                     # upstream handles
session.*                       # no session caching
transport.*.discovery.*         # single configured peer
transport.*.auto_connect        # single configured peer
```

### Resource Comparison

| Resource            | Full Participant    | Leaf-Only |
|---------------------|---------------------|-----------|
| RAM (Bloom filters) | d × 4KB (d = peers) | 0         |
| RAM (coord cache)   | 10K-100K entries    | 0         |
| RAM (tree state)    | O(P × D) entries    | 0         |
| Bandwidth (idle)    | < 1 KB/sec          | Near zero |
| CPU (filter ops)    | Moderate            | None      |
| Peers               | Multiple            | One       |

### Use Cases

- **IoT sensors**: Send telemetry, receive commands
- **Mobile devices**: Battery/bandwidth constraints
- **Privacy-conscious**: Don't see others' traffic
- **Monitoring nodes**: Observe network, don't route
- **Embedded systems**: Limited RAM/CPU

---

## Node Startup Sequence

The startup sequence initializes components in dependency order:

```text
1. Load configuration
   ├── Parse config files (system, user, local)
   ├── Validate transport and peer configurations
   └── Merge with defaults

2. Initialize identity
   ├── Load nsec from config (or generate if absent)
   ├── Derive npub, node_addr, and FIPS address
   └── Log identity information

3. Initialize transports
   ├── Create transport instances from config
   └── Transports in Configured state

4. Start transports (begin listening)
   ├── Bind sockets, open interfaces
   ├── Transports transition to Up state
   └── Ready to accept inbound connections

5. Connect to static peers
   ├── For each configured peer with AutoConnect policy:
   │   ├── Create link via appropriate transport
   │   ├── Send AuthInit to initiate authentication
   │   └── On success: peer joins tree gossip
   └── Failed connections enter retry with backoff

6. Node operational
   ├── Participating in spanning tree (even with 0 peers)
   ├── Processing inbound connections
   └── Retrying unreachable static peers in background
```

**Notes:**

- Transports start listening (step 4) before outbound connections (step 5) to
  accept inbound connections from peers who have us configured
- The node is "operational" as soon as any peer authenticates successfully
- Static peer connection attempts continue in background with retry policy
- With 0 authenticated peers, the node considers itself a potential root

### Static Peer Retry Policy

When a static peer is unreachable or authentication fails:

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1s | First retry delay |
| Max delay | 300s | Cap on exponential backoff |
| Backoff factor | 2.0 | Multiplier per attempt |
| Jitter | ±25% | Randomization to avoid thundering herd |
| Max attempts | unlimited | Static peers retry indefinitely |

The retry timer resets to initial delay after a successful connection that
later disconnects.

### Inbound Connection Acceptance

For initial implementation, all inbound connections that successfully
authenticate are accepted. Future versions may add:

- Peer allowlists/blocklists
- Connection limits per transport
- Rate limiting on authentication attempts
- Reputation-based acceptance

---

## Configuration

### Peer Configuration

Peers are configured at the node level, separately from transports. For initial
implementation, only static peers with `AutoConnect` policy are supported;
discovery-based and on-demand peering are future enhancements.

```text
PeerConfig
├── npub: PublicKey                 // required: who is this
├── alias: Option<String>           // human-readable label
├── addresses: Vec<PeerAddress>     // how to reach them
└── connect_policy: ConnectPolicy   // AutoConnect for initial impl

PeerAddress
├── transport_type: TransportType   // "udp", "ethernet", "tor", etc.
├── addr: String                    // transport-specific, parsed by driver
└── priority: u8                    // preference order (lower = preferred)

ConnectPolicy
├── AutoConnect                     // connect on startup (initial impl)
├── OnDemand                        // connect when traffic needs routing (future)
└── Manual                          // wait for explicit API call (future)
```

**Example configuration (YAML):**

```yaml
node:
  peers:
    - npub: "npub1abc..."
      alias: "gateway"
      addresses:
        - transport: udp
          addr: "192.168.1.1:4000"
          priority: 1
        - transport: tor
          addr: "xyz...abc.onion:4000"
          priority: 2
      connect_policy: auto_connect
```

### Transport Configuration

```
TransportConfig
├── transport_type: TransportType
├── driver_config: DriverConfig     // type-specific
├── start_policy: StartPolicy
├── discovery_enabled: bool
└── auto_connect: bool              // auto-connect to discovered peers
```

### Discovery

Discovery is per-transport:

- Transports emit `DiscoveredPeer { addr, hint }` events
- Node matches against known peer configs or creates "unknown peer" entries
- Policy (`auto_connect`, per-peer `connect_policy`) determines action

---

## Configuration Reference (sysctl-style)

### Node Identity

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.identity.nsec` | string | (generated) | Secret key (nsec1... or hex) |

### TUN Interface

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.tun.device` | string | "fips0" | TUN device name |
| `node.tun.mtu` | u16 | 1280 | TUN interface MTU |

### Resource Limits

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limits.max_peers` | u32 | 128 | Maximum concurrent authenticated peers |
| `limits.max_transports` | u8 | 8 | Maximum configured transports |
| `limits.max_pending_auth` | u32 | 32 | Maximum connections awaiting authentication |
| `limits.max_pending_lookups` | u32 | 1000 | Maximum in-flight discovery lookups |
| `limits.memory_budget` | u64 | 0 | Soft memory limit in bytes (0 = unlimited) |

Limits are enforced at connection time. Exceeding `max_pending_auth` rejects new
inbound connections; exceeding `max_peers` prevents new outbound connections.
The `memory_budget` is advisory—implementations should shed load when approaching
the limit but need not enforce it strictly.

### Spanning Tree

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tree.announce.interval` | duration | 30s | Periodic TreeAnnounce refresh |
| `tree.announce.on_change` | bool | true | Immediate announce on parent change |
| `tree.parent.hold_time` | duration | 10s | Min time before switching parent |
| `tree.parent.hysteresis` | f32 | 0.1 | Cost improvement threshold to switch |

### Bloom Filters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filter.size_class` | u8 | 1 | Size class: 0=512B, 1=1KB, 2=2KB, 3=4KB |
| `filter.hash_count` | u8 | 5 | Number of hash functions |
| `filter.scope` | u8 | 2 | TTL for filter propagation (K) |
| `filter.refresh.interval` | duration | 60s | Periodic FilterAnnounce refresh |
| `filter.update.debounce` | duration | 500ms | Min interval between updates |
| `filter.stale.threshold` | duration | 300s | Consider peer's filter stale |

v1 protocol requires `size_class=1` (1 KB filters). The size_class field is
present in the wire format for forward compatibility with larger filters.

### Discovery Protocol

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `discovery.lookup.ttl` | u8 | 8 | Initial TTL for LookupRequest |
| `discovery.lookup.timeout` | duration | 10s | Timeout waiting for response |
| `discovery.lookup.retry_count` | u8 | 3 | Retries before giving up |
| `discovery.cache.max_entries` | u32 | 10000 | Route cache size |
| `discovery.cache.ttl` | duration | 300s | Cached coordinates expiry |

The discovery cache stores coordinates learned from LookupResponses for destinations
this node wants to reach. This is the primary cache for endpoint nodes.

### Routing Session Management

> **Terminology note**: These parameters configure *routing sessions*—hop-by-hop
> cached state at intermediate routers. For *crypto session* (end-to-end
> encryption) parameters, see the Crypto Session section below. See
> [fips-session-protocol.md](fips-session-protocol.md) §3 for crypto sessions
> and §5 for route cache warming.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `session.setup.timeout` | duration | 5s | SessionSetup ack timeout |
| `session.cache.max_entries` | u32 | 50000 | Coord cache size (per router) |
| `session.cache.ttl` | duration | 300s | Cached coordinates expiry |
| `session.refresh.interval` | duration | 240s | Proactive session refresh |

The session cache stores coordinates learned from SessionSetup packets passing through
this node as a transit router. Larger than discovery cache since routers see traffic
for many destinations. Both caches are part of Node.coord_cache; these parameters
configure the same underlying cache but are grouped by purpose.

### Crypto Session Management

> **Note**: Crypto sessions provide end-to-end authenticated encryption using
> Noise IK. See [fips-session-protocol.md](fips-session-protocol.md) §6 for details.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `crypto.session.max_entries` | u32 | 10000 | Max concurrent crypto sessions |
| `crypto.session.idle_timeout` | duration | 3600s | Expire idle sessions |
| `crypto.session.rekey_interval` | duration | 86400s | Rekey after this interval |
| `crypto.session.rekey_bytes` | u64 | 0 | Rekey after N bytes (0 = disabled) |

Crypto sessions are keyed by remote npub and survive transport changes. The
handshake is carried within SessionSetup/SessionAck messages (combined
establishment).

### Peer Defaults

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `peer.auth.timeout` | duration | 10s | Auth handshake timeout |
| `peer.auth.timeout_tor` | duration | 60s | Auth timeout for Tor links |
| `peer.keepalive.interval` | duration | 30s | Keepalive probe interval |
| `peer.keepalive.timeout` | duration | 90s | Declare peer dead after silence |
| `peer.reconnect.policy` | enum | backoff | none, immediate, backoff |
| `peer.reconnect.delay_initial` | duration | 1s | Initial reconnect delay |
| `peer.reconnect.delay_max` | duration | 300s | Maximum reconnect delay |
| `peer.reconnect.max_attempts` | u32 | 0 | 0 = unlimited |

### Transport: UDP

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transport.udp.enabled` | bool | true | Enable UDP transport |
| `transport.udp.bind_addr` | string | "0.0.0.0:4000" | Bind address |
| `transport.udp.discovery.enabled` | bool | true | Enable discovery |
| `transport.udp.discovery.dns_sd` | bool | false | Use DNS-SD discovery |
| `transport.udp.discovery.nostr_relays` | list | [] | Relays for peer discovery |
| `transport.udp.auto_connect` | bool | true | Connect to discovered peers |
| `transport.udp.base_rtt` | duration | 50ms | RTT hint for timeouts |

### Transport: Ethernet

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transport.ethernet.enabled` | bool | false | Enable Ethernet transport |
| `transport.ethernet.interface` | string | "eth0" | Interface name |
| `transport.ethernet.ethertype` | u16 | 0x88b5 | FIPS EtherType |
| `transport.ethernet.discovery.enabled` | bool | true | Enable multicast discovery |
| `transport.ethernet.discovery.multicast_addr` | string | "33:33:00:00:ff:05" | Discovery multicast MAC |
| `transport.ethernet.auto_connect` | bool | true | Connect to discovered peers |
| `transport.ethernet.base_rtt` | duration | 1ms | RTT hint for timeouts |

### Transport: WiFi

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transport.wifi.enabled` | bool | false | Enable WiFi transport |
| `transport.wifi.interface` | string | "wlan0" | Interface name |
| `transport.wifi.mode` | enum | infrastructure | infrastructure, adhoc, direct |
| `transport.wifi.discovery.enabled` | bool | true | Enable discovery |
| `transport.wifi.auto_connect` | bool | true | Connect to discovered peers |
| `transport.wifi.base_rtt` | duration | 5ms | RTT hint for timeouts |

### Transport: Tor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transport.tor.enabled` | bool | false | Enable Tor transport |
| `transport.tor.mode` | enum | embedded | embedded, external |
| `transport.tor.control_port` | string | "127.0.0.1:9051" | External daemon control |
| `transport.tor.onion_service.enabled` | bool | true | Publish onion service |
| `transport.tor.onion_service.port` | u16 | 4000 | Onion service port |
| `transport.tor.discovery.enabled` | bool | true | Enable discovery |
| `transport.tor.discovery.nostr_relays` | list | [] | Relays for peer discovery |
| `transport.tor.auto_connect` | bool | false | Connect to discovered peers |
| `transport.tor.base_rtt` | duration | 2s | RTT hint for timeouts |
| `transport.tor.startup_timeout` | duration | 180s | Tor bootstrap timeout |

### Adaptive Timeouts

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `timeout.adaptive.enabled` | bool | true | Use measured RTT for timeouts |
| `timeout.adaptive.rtt_multiplier` | f32 | 3.0 | Timeout = RTT × multiplier |
| `timeout.adaptive.min` | duration | 100ms | Minimum timeout |
| `timeout.adaptive.max` | duration | 60s | Maximum timeout |

### Leaf-Only Mode

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.leaf_only` | bool | false | Operate as leaf-only node |

---

## References

- [fips-intro.md](fips-intro.md) — Overall FIPS protocol design
- [fips-session-protocol.md](fips-session-protocol.md) — Traffic flow, session terminology, crypto sessions
- [fips-transports.md](fips-transports.md) — Transport protocol characteristics
- [fips-routing.md](fips-routing.md) — Routing, Bloom filters, discovery
- [spanning-tree-dynamics.md](spanning-tree-dynamics.md) — Tree protocol dynamics
