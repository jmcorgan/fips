# FIPS Software Architecture

This document describes the stable architectural decisions that guide the
FIPS codebase — the "why" behind the code's shape. It covers design
principles and patterns that are expected to remain stable as the
implementation evolves. For protocol behavior and wire formats, see the
protocol layer documents.

## Ownership and Entity Hierarchy

A FIPS node owns transports, which produce links, which authenticate into
peers:

```text
Node
├── Transports (HashMap<TransportId, TransportHandle>)
│   └── Each transport instance manages one communication medium
├── Links (HashMap<LinkId, Link>)
│   └── Each link is a connection to a remote endpoint over a transport
├── Peers (HashMap<NodeAddr, PeerSlot>)
│   └── Each peer is an authenticated remote FIPS node
├── TreeState — local view of the spanning tree
├── CoordCache — destination coordinates for routing
├── Sessions — end-to-end FSP sessions (HashMap by NodeAddr)
└── Identity — this node's cryptographic identity
```

**Key ownership rules**:

- A transport exists for the lifetime of the node (configured at startup)
- A link is created when connecting to a remote endpoint and destroyed when
  the connection terminates
- A peer is created when a link successfully authenticates (Noise IK
  handshake) and destroyed when the link goes down
- Links and peers have a one-to-one mapping with coupled lifecycles —
  peer teardown implies link teardown

## Event-Driven Execution Model

The node uses an async select loop as its main event loop, multiplexing
events from all sources into a single processing stream:

- **Transport events**: Inbound datagrams from all transports arrive via a
  shared mpsc channel
- **Timer events**: Periodic and one-shot timers for keepalive, stale peer
  detection, cache expiry, handshake timeouts
- **TUN events**: Outbound IPv6 packets from local applications
- **Control events**: Identity registrations from DNS, shutdown signals

Within the select loop, events are dispatched to focused handler functions
organized by concern (handshake processing, gossip handling, forwarding,
session management, timeout handling). Each handler operates on the node's
state directly — there is no separate message-passing between internal
components.

**Why a single select loop**: FIPS protocol operations frequently need to
read and modify multiple pieces of state (e.g., forwarding a packet reads
the coordinate cache, peer ancestry, and bloom filters simultaneously).
A single-threaded event loop avoids the complexity of locking and provides
deterministic ordering of state changes.

**Exceptions**: The TUN reader and writer run in separate blocking threads
because TUN I/O is blocking (kernel file descriptor). They communicate with
the main event loop via channels.

## Phase-Based State Machine Pattern

FIPS entities use a Rust enum-of-structs pattern for state machines where
each phase carries only the data relevant to that phase:

```rust
enum PeerSlot {
    Connecting(PeerConnection),   // handshake in progress
    Active(ActivePeer),           // authenticated, participating
}
```

Each variant holds a different struct with phase-appropriate fields. The
`PeerConnection` struct carries handshake state; `ActivePeer` carries tree
position, bloom filters, and link statistics. Transitioning between phases
consumes the old struct and produces the new one, making it impossible to
access handshake state after authentication is complete.

This pattern enforces at the type level that code handling an authenticated
peer cannot accidentally reference handshake state, and vice versa.

See [fips-state-machines.md](fips-state-machines.md) for a detailed
treatment of this pattern.

## Two-Layer Encryption Rationale

FIPS uses independent Noise IK encryption at two layers:

| Layer | Scope | What It Protects |
| ----- | ----- | ---------------- |
| FMP (mesh) | Hop-by-hop | All traffic on each peer link |
| FSP (session) | End-to-end | Application payload between endpoints |

**Why two layers instead of one**:

- **Link encryption** protects all traffic from passive observers on the
  underlying transport — including routing metadata (TreeAnnounce, bloom
  filters, discovery messages) that would otherwise be visible
- **Session encryption** protects application payloads from intermediate
  routing nodes, which must decrypt link encryption to read routing headers
- Both layers always apply. For adjacent peers, traffic is encrypted twice.
  This eliminates special cases ("local peer" vs. "remote destination") and
  means topology changes (a direct peer becomes multi-hop) don't affect
  sessions.

**Why the same pattern (Noise IK) at both layers**: Both layers need mutual
authentication with identity hiding for the initiator. Reusing the same
cryptographic stack (secp256k1, ChaCha20-Poly1305, SHA-256) simplifies the
implementation and reduces the number of cryptographic dependencies.

## Identity Model

FIPS uses three related but distinct identifiers at different layers:

```text
keypair (secp256k1)
    │
    ├── pubkey (32 bytes) — the endpoint identity, used in Noise handshakes
    │
    ├── node_addr = SHA-256(pubkey)[0..16] — routing identifier, visible to
    │   transit nodes, cannot be reversed to pubkey
    │
    └── IPv6 address = fd + node_addr[0..15] — overlay address for IPv6
        applications
```

**Privacy property**: Transit nodes see only node_addrs in packet headers.
They can forward traffic without knowing the Nostr identities of the
endpoints. An observer can verify "does this node_addr belong to pubkey X?"
but cannot enumerate communicating identities from traffic alone.

**Self-sovereign**: Nodes generate their own identities without coordination.
The identity system uses Nostr keypairs (secp256k1), so existing npub/nsec
pairs work directly.

## Protocol Self-Healing Design

FIPS control protocols are designed for eventual consistency, tolerating
packet loss without acknowledgment/retry machinery:

| Protocol | Self-Healing Property |
| -------- | --------------------- |
| TreeAnnounce | Full state with monotonic sequence; lost announcement recovered on next send |
| FilterAnnounce | Full filter replacement with sequence; stale filter recovered on next update |
| LookupRequest | Timeout-based retry at application level |
| SessionSetup | Timeout-based retry; lost setup triggers re-establishment on first data failure |
| CoordsRequired/PathBroken | Rate-limited, best-effort; lost error recovered by session idle timeout |

**Why no ack/retry**: FIPS operates over unreliable transports (primarily
UDP). Adding reliability to control messages would require per-message state,
retransmission timers, and acknowledgment tracking — complexity that gossip
protocols avoid by sending full state periodically. A lost TreeAnnounce is
simply replaced by the next one, which carries the same or newer state.

## Metrics Measurement Protocol

MMP is instantiated at two independent layers, each with its own
configuration and state:

- **Link layer**: One `MmpPeerState` per `ActivePeer`. Measures per-hop
  quality using the FMP counter and timestamp fields that already exist on
  every encrypted frame. No additional message overhead beyond periodic
  SenderReport/ReceiverReport exchanges.

- **Session layer**: One `MmpSessionState` per established `SessionEntry`.
  Measures end-to-end quality using the FSP counter and timestamp fields.
  Reports are encrypted and forwarded through every transit link.

Both instantiations use identical algorithms (SRTT, loss, jitter, dual EWMA,
OWD trend) but are configured independently via `node.mmp.*` and
`node.session_mmp.*`. This allows operators to run Full mode on links (low
overhead, single hop) while using Lightweight mode for sessions (reduces
bandwidth cost on transit links).

### Peer Display Names

The node maintains a `peer_aliases` map (`HashMap<NodeAddr, String>`) populated
from the `peers[].alias` field in configuration. All log output uses
`peer_display_name()` to show human-readable names (e.g., "node-b") instead
of truncated public keys, improving operator experience.

### Buffer Sizing Chain

Under high forwarding load, back-pressure propagates through:

1. **UDP socket receive buffer** (`transports.udp.recv_buf_size`, default 2 MB) —
   kernel-level buffer for incoming datagrams.
2. **Packet channel** (`node.buffers.packet_channel`, default 1024) — async
   channel from transport receive loop to the node's RX event loop.
3. **Processing** — decryption, routing decision, forwarding.

If the packet channel fills (RX loop can't keep up), the transport receive
loop blocks, and the kernel receive buffer absorbs bursts. If the kernel
buffer also fills, incoming datagrams are silently dropped
(`RcvbufErrors` in `/proc/net/snmp`). The 2 MB default socket buffer was
chosen to handle ~85 MB/s forwarding throughput without kernel drops.

## Bounded State Principle

FIPS nodes maintain state proportional to O(P × D), where P is the number
of direct peers and D is the tree depth — not O(N) where N is the network
size.

What each node stores:

| State | Size | Scope |
| ----- | ---- | ----- |
| Peer ancestry (TreeAnnounce) | P × D entries | Direct peers only |
| Bloom filters | P × 1 KB | One per peer |
| Coordinate cache | Configurable (50K default) | Destinations actively routed |
| Identity cache | Configurable (10K default) | IPv6 adapter only |
| Sessions | Configurable (10K default) | Active end-to-end sessions |

A node does not know about nodes in distant parts of the network. It knows
its direct peers, their tree positions, and the destinations it has recently
routed traffic to. This scales naturally: adding nodes to the network does
not increase the per-node state of existing nodes (except for a slight
increase in bloom filter occupancy).

## Transport Opacity

Transport addresses are opaque byte vectors above FMP. The transport layer
interprets them (e.g., UDP parses "ip:port" strings); all layers above treat
them as handles passed back to the transport for sending.

**Architectural boundary**: Adding a new transport type (e.g., BLE) requires
implementing the transport trait and potentially a new `TransportHandle`
variant. No changes to FMP, FSP, or any routing logic. The transport trait
defines the interface:

- `send(addr, data)` — send a datagram
- `mtu()` — maximum datagram size
- `start()` / `stop()` — lifecycle
- `discover()` — optional endpoint discovery

Inbound datagrams are pushed via a shared channel, aggregating all transports
into a single event stream for the main loop.

## Cache Architecture

### Unified Coordinate Cache

The coordinate cache maps `NodeAddr → TreeCoordinate`. It was originally two
separate caches (session-populated and discovery-populated) but was merged
into a single cache because both stored the same type of data and the
distinction was conceptual, not functional.

Key properties:

- **TTL-based expiration** (300s default) with **refresh on use** — active
  routing resets the TTL, keeping hot entries alive
- **LRU eviction** when full — least recently used entries are evicted first
- **Flush on parent change** — when the local node's tree parent changes,
  the entire cache is flushed because the node's own coordinates have
  changed, making cached distance calculations potentially invalid

### Identity Cache (LRU-Only)

The identity cache maps FIPS address prefix → (NodeAddr, PublicKey). The
mapping is deterministic (derived from public key) and never becomes stale,
so there is no TTL — only LRU eviction bounded by a configurable size.

This cache is needed only by the IPv6 adapter. The native FIPS API provides
the public key directly.

### Timer Ordering

Cache and session timers are ordered to ensure correct lifecycle behavior:

```text
Session idle timeout (90s) < Coordinate cache TTL (300s) ≤ DNS TTL (300s)
```

When traffic stops, the session tears down first (90s). When traffic
resumes, a fresh SessionSetup re-warms transit caches that are still within
their TTL (300s). This ordering prevents the case where a session outlives
its transit cache entries, which would cause routing failures.

## Receive Path Design

Transports use a channel-push model rather than a poll/receive method. Each
transport takes a sender handle (`PacketTx`) at construction and spawns an
internal receive loop that pushes inbound datagrams onto the channel. The
node's main select loop reads from the corresponding receiver.

**Why push, not poll**: Async Rust cannot express async methods on trait
objects (the `Transport` trait is synchronous). The channel-push model works
around this limitation: the concrete transport implementation (e.g.,
`UdpTransport`) spawns its own async receive task and pushes to a channel,
while the trait surface remains synchronous for `send()`, `mtu()`, etc.

The `TransportHandle` enum provides async dispatch for methods that need it
(like `send_async()`) without requiring dyn dispatch.

## References

- [fips-intro.md](fips-intro.md) — Protocol overview
- [fips-mesh-layer.md](fips-mesh-layer.md) — FMP specification
- [fips-session-layer.md](fips-session-layer.md) — FSP specification
- [fips-state-machines.md](fips-state-machines.md) — Phase-based state
  machine pattern
- [fips-configuration.md](fips-configuration.md) — YAML configuration
  reference
