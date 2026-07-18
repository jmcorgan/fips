# FIPS IPv6 Adapter

The IPv6 adapter sits above the FIPS Session Protocol (FSP) and adapts the
FIPS datagram service for unmodified IPv6 applications. It presents each FIPS
node as an IPv6 endpoint, so standard socket applications (SSH, HTTP, SCP)
can communicate over the mesh without modification.

## Role

The adapter bridges two worlds: IPv6 applications that address destinations by
IP address, and the FIPS mesh that addresses destinations by public key
(npub). The adapter handles the translation: DNS resolution from npub to
`fd00::/8` ULA (Unique Local Address) address, identity cache management so
FIPS can route IPv6 packets,
MTU enforcement so packets fit through the mesh, and the TUN interface that
connects to the kernel's IPv6 stack.

Applications that are FIPS-aware can bypass the adapter entirely and use the
native FIPS datagram API, addressing destinations directly by npub.

## DNS Integration

### The Problem

IPv6 addresses in the `fd00::/8` range are derived from public keys via a
one-way hash (SHA-256). Given only an IPv6 address, the public key cannot be
recovered — and without the public key, FIPS cannot compute the node_addr
needed for routing.

The identity cache must be populated *before* packets arrive at the TUN
interface, or they cannot be routed.

### DNS as Entry Point

DNS resolution serves as the "routing intent" signal. When an application
resolves `npub1xxx...xxx.fips`, the FIPS DNS service:

1. Extracts the npub from the `.fips` domain name
2. Derives the `fd00::/8` IPv6 address from the public key
3. Primes the identity cache with the mapping
   (IPv6 address prefix ↔ NodeAddr ↔ PublicKey)
4. Returns the IPv6 address to the application

When the application subsequently sends packets to that address, the identity
cache already contains the mapping needed for routing.

### DNS Name Format

```text
npub1xxxxxx...xxxxx.fips
```

The FIPS DNS server recognizes names ending in `.fips` and extracts the npub
for address derivation.

### Traffic Without Prior DNS Lookup

A packet may arrive at the TUN for an `fd00::/8` destination without a prior DNS
lookup — cached address, manual configuration, etc. Since the address derivation
is one-way, the npub cannot be recovered from the address alone.

FIPS returns ICMPv6 Destination Unreachable (Code 0: No route to destination)
for packets to unknown addresses. The identity cache must be populated before
traffic can be routed.

Known cache population mechanisms:

- **DNS lookup**: The primary path
- **Inbound traffic**: Authenticated sessions from other nodes populate the
  cache with their identity information

### Mesh-Interface Query Filter

The DNS responder is intended for local applications resolving `.fips`
names; queries arriving over the mesh interface itself are dropped. The
daemon records the index of the TUN interface at startup and compares
it against the arrival interface of each incoming UDP DNS query. When
they match — meaning the query came from another mesh node, not from a
local socket — the responder discards the query without replying.

The check is implemented in
[`is_mesh_interface_query`](../../src/upper/dns.rs) and prevents two
classes of misbehaviour: a peer asking the daemon to resolve `.fips`
names on its behalf (which would let one node use another as an
identity-cache priming proxy), and accidental query loops where a
misconfigured resolver forwards `.fips` queries back into the mesh.
Local applications binding to the host's loopback or non-mesh
interfaces are unaffected.

## IPv6 Address Derivation

FIPS addresses use the IPv6 Unique Local Address (ULA) prefix `fd00::/8`:

```text
Public Key (32 bytes)
    │
    ▼
SHA-256 → node_addr (16 bytes, truncated)
    │
    ▼
fd + node_addr[0..15] → IPv6 address (16 bytes)
```

The `fd` prefix places FIPS addresses in the IPv6 Unique Local Address (ULA)
space defined by RFC 4193. ULAs are the IPv6 equivalent of RFC 1918 private
addresses (10.x, 172.16.x, 192.168.x) — they are reserved for local use and
are not routable over the public Internet. This means FIPS overlay addresses
cannot conflict with native IPv6 traffic that may be present on the same host
or network, and they will not leak beyond the local system even if routing is
misconfigured. These are overlay identifiers — they appear in the TUN
interface for application compatibility but have no meaning outside the FIPS
mesh.

## Identity Cache

The derivation from public key to NodeAddr and IPv6 address is one-way
(SHA-256 truncation). Given a destination IPv6 address from an outbound packet
on the TUN interface, the adapter cannot recover the public key or NodeAddr
needed for FIPS routing. The identity cache provides the reverse lookup:
it maps the FIPS address prefix (15 bytes — the IPv6 address minus the `fd`
prefix) back to `(NodeAddr, PublicKey)`, allowing the adapter to route
IPv6 traffic into the mesh. This cache is needed only when using the IPv6
adapter; the native FIPS API provides the public key directly.

### Eviction Policy

The mapping is deterministic (derived from the public key) and never becomes
stale. The cache uses **LRU-only eviction** bounded by a configurable size
(default 10K entries). There is no TTL — entries are evicted only when the
cache is full and space is needed for a new entry. LRU-only eviction is
necessary because there is no other way for the FIPS router to recover the
routing identity from an IPv6 address, and IPv6 traffic for a destination may
arrive an arbitrarily long time after the DNS resolution that populated the
cache entry.

### Relationship to DNS TTL

The identity cache timeout must be longer than the DNS TTL to ensure that while
an application believes its DNS resolution is valid, the corresponding routing
entry remains present. The DNS TTL (default 300s) governs when applications
re-query; the identity cache (LRU, no TTL) is always available as long as the
entry hasn't been evicted by memory pressure.

## MTU Enforcement

The adapter sits at the boundary between the host's IPv6 stack and the
FIPS encapsulation budget. Its job is to keep IPv6 packets small
enough that they fit through the FIPS protocol envelope on every link
along the path. The cross-cutting MTU model — proactive
SessionDatagram `path_mtu` annotation, reactive MtuExceeded signals,
end-to-end PathMtuNotification echo, and per-destination MTU storage
— is documented in [fips-mtu.md](fips-mtu.md). What the adapter
contributes is the IPv6-specific overhead accounting and the TUN-side
enforcement integration.

### IPv6-Specific Overhead

For IPv6 traffic, FSP port multiplexing adds 4 bytes (port header)
while IPv6 header compression saves 33 bytes (40-byte header →
7-byte format + residual), yielding a net `FIPS_IPV6_OVERHEAD` of
77 bytes on top of the base `FIPS_OVERHEAD` (106 bytes) protocol
envelope. The full encapsulation breakdown lives in
[fips-mtu.md](fips-mtu.md#encapsulation-overhead).

### Effective IPv6 MTU

The effective IPv6 MTU visible to applications is:

```text
effective_ipv6_mtu = transport_mtu - FIPS_IPV6_OVERHEAD
```

For typical deployments:

| Transport MTU | Effective IPv6 MTU | Notes |
| ------------- | ------------------ | ----- |
| 1472 (UDP/Ethernet) | 1395 | Standard deployment |
| 1280 (UDP minimum) | 1203 | Below IPv6 minimum |

IPv6 mandates that every link support at least 1280 bytes. The minimum
transport path MTU for the IPv6 adapter is therefore:

```text
1280 + 77 = 1357 bytes
```

Transports with smaller MTUs (radio at ~250 bytes, serial at 256
bytes) cannot support the IPv6 adapter without some form of internal
fragmentation and reassembly. Otherwise, applications on those
transports must use the native FIPS datagram API.

### TUN-Side ICMP Packet Too Big

When an outbound packet at the TUN exceeds the effective IPv6 MTU,
the adapter generates an ICMPv6 Packet Too Big message and delivers
it back to the application via the TUN. This triggers the kernel's
Path MTU Discovery mechanism, which adjusts TCP segment sizes for
subsequent transmissions.

ICMP Packet Too Big generation is rate-limited per source address
(100ms interval) to prevent storms from applications sending many
oversized packets. The ICMP response is delivered locally back through
the TUN; no network traversal is needed, so delivery is reliable.

### TUN-Side TCP MSS Clamping

The adapter intercepts TCP SYN and SYN-ACK packets at the TUN
interface and clamps the Maximum Segment Size (MSS) option:

```text
clamped_mss = effective_ipv6_mtu - 40 (IPv6 header) - 20 (TCP header)
```

Clamping is applied in two places:

- **TUN reader** (outbound): Clamps MSS on outbound SYN packets
- **TUN writer** (inbound): Clamps MSS on inbound SYN-ACK packets

Together, these ensure both directions of a TCP connection use
appropriately sized segments from the start, avoiding the initial
oversized packet loss that would occur with ICMP Packet Too Big
alone. The conditional clamp (per-flow lookup with cold-flow
fallback) and the rationale for `max_mss` semantics are in
[fips-mtu.md](fips-mtu.md#tcp-mss-clamping).

### ICMP Rate Limiting

ICMPv6 error generation is rate-limited per source address using a
token bucket (100ms interval). This matches the standard ICMP rate
limiting approach and prevents amplification when an application sends
a burst of oversized packets.

## TUN Interface

The TUN device (`fips0`) is the mechanism that connects the adapter to the
kernel's IPv6 stack. It is an implementation detail of the adapter, not its
defining feature.

### Architecture

```text
Applications (sockets using fd00::/8 addresses)
       │
       ▼
Kernel IPv6 Stack (routing: fd00::/8 → fips0)
       │
       ▼
TUN Device (fips0)
    ├── Reader Thread (blocking I/O → packet processing)
    └── Writer Thread (mpsc queue → TUN writes)
```

### Reader Thread

The TUN reader receives raw IPv6 packets from applications and processes them:

1. Validate IPv6 header
2. Extract destination `fd00::/8` address
3. Look up identity cache — miss returns ICMPv6 Destination Unreachable
4. Retrieve NodeAddr and PublicKey from cache
5. Look up or establish FSP session
6. Compress IPv6 header: strip addresses and payload length, build format 0x00
   payload with residual fields (traffic class, flow label, next header, hop limit)
7. Prepend port header (src_port=256, dst_port=256)
8. Encrypt with session keys
9. Route through FMP toward destination

### Writer Thread

A single writer thread services an mpsc queue of outbound packets:

- Inbound mesh traffic on port 256 (IPv6 header reconstructed from session
  context + residual fields, then delivered as complete IPv6 packets)
- ICMPv6 error responses (Packet Too Big, Destination Unreachable)
- TCP MSS-clamped SYN-ACK packets

The queue-based design eliminates contention on TUN writes and cleanly
separates concerns. New packet sources can be added by cloning the sender
handle.

### Local Address Guarantee

The Linux kernel routing table processes rules in priority order:

1. **Local table**: Intercepts traffic to addresses assigned to this machine
2. **Main table**: Routes `fd00::/8` to the TUN device

This means every packet arriving at the TUN reader is guaranteed to be for a
*remote* FIPS destination. No "is this for me?" check is needed on the read
path.

### Configuration

The TUN block (`tun.*`) is documented in
[../reference/configuration.md](../reference/configuration.md).

### Privileges

TUN device creation requires `CAP_NET_ADMIN`. The shipped Debian
systemd unit runs the daemon as `root` by default; for the
alternative — running under a dedicated unprivileged service
account with the capability granted on the binary — see
[../how-to/run-as-unprivileged-user.md](../how-to/run-as-unprivileged-user.md).

### App-Owned TUN (embedded hosts)

On platforms where FIPS is embedded rather than run as a daemon — notably
Android, where the `VpnService` owns the TUN fd and the app has no
`CAP_NET_ADMIN` — FIPS does not create `fips0` itself. Instead the embedder owns
the fd and exchanges IPv6 packet bytes with FIPS over channels.

`Node::enable_app_owned_tun()` sets this up. It is called after `Node::new` and
before `start()` (and before the node is moved into a background task), mirroring
`control_read_handle()`, and returns two app-side channel ends:

- **app → mesh** — the embedder pushes IPv6 packets read from its fd into
  `app_outbound_tx`. These are drained by `run_rx_loop` into `handle_tun_outbound`
  and routed exactly as the Reader Thread's output would be.
- **mesh → app** — inbound mesh traffic on port 256 is reconstructed and written
  to the node's `tun_tx` (the same sink the Writer Thread reads); the embedder
  pulls from `app_inbound_rx` and writes to its fd.

With the channels installed, `start()` skips system-TUN creation (it gates on
`tun_tx` being unset), so FIPS does no `CAP_NET_ADMIN` operations.

Because packets enter via `app_outbound_tx` rather than the Reader Thread, they
**bypass `handle_tun_packet`** — the `fd00::/8` destination filter, the ICMPv6
Destination Unreachable for off-mesh dests (see [Reader Thread](#reader-thread)),
and the [TUN-Side TCP MSS Clamping](#tun-side-tcp-mss-clamping). The embedder is
therefore responsible for routing only `fd00::/8` to its TUN (so only mesh-bound
packets arrive) and for clamping TCP MSS on outbound SYNs.

## Implementation Status

| Feature | Status |
| ------- | ------ |
| TUN device creation and configuration | **Implemented** |
| IPv6 address assignment (netlink) | **Implemented** |
| TUN reader/writer threads | **Implemented** |
| ICMPv6 Destination Unreachable | **Implemented** |
| ICMPv6 Packet Too Big | **Implemented** |
| ICMP rate limiting (per-source) | **Implemented** |
| TCP MSS clamping (SYN + SYN-ACK) | **Implemented** |
| DNS service (.fips domain) | **Implemented** |
| DNS responder mesh-interface filter | **Implemented** |
| Port-based service multiplexing (port 256) | **Implemented** |
| IPv6 header compression (format 0x00) | **Implemented** |
| Per-destination route MTU (netlink) | Planned |
| Transit MTU error signal | **Implemented** |
| Path MTU tracking (SessionDatagram field) | **Implemented** |
| Path MTU notification (end-to-end echo) | **Implemented** |
| Endpoint fragmentation/reassembly | Transport drivers |

## Design Considerations

### Path MTU Discovery and No-Fragmentation Policy

Path MTU Discovery (proactive `path_mtu` annotation, reactive
MtuExceeded, end-to-end PathMtuNotification) and the no-fragmentation
policy that drives the design both live in the unified MTU treatment
at [fips-mtu.md](fips-mtu.md). The adapter is a consumer of that
model — its job is to enforce the resulting effective IPv6 MTU at the
TUN with ICMP Packet Too Big and TCP MSS clamping.

## References

- [fips-concepts.md](fips-concepts.md) — Protocol overview
- [fips-architecture.md](fips-architecture.md) — Layer architecture and
  identity model
- [fips-session-layer.md](fips-session-layer.md) — FSP (below the adapter)
- [fips-mtu.md](fips-mtu.md) — Unified path MTU model (proactive,
  reactive, hysteresis, no-fragmentation)
- [../reference/wire-formats.md](../reference/wire-formats.md) — FSP and
  SessionDatagram wire formats
- [../reference/configuration.md](../reference/configuration.md) — TUN
  configuration parameters
- [../how-to/run-as-unprivileged-user.md](../how-to/run-as-unprivileged-user.md)
  — privilege options for the daemon, including the unprivileged
  service-account path
