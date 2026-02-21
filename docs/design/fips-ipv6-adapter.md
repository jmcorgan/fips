# FIPS IPv6 Adapter

The IPv6 adapter sits above the FIPS Session Protocol (FSP) and adapts the
FIPS datagram service for unmodified IPv6 applications. It presents each FIPS
node as an IPv6 endpoint, so standard socket applications (SSH, HTTP, SCP)
can communicate over the mesh without modification.

## Role

The adapter bridges two worlds: IPv6 applications that address destinations by
IP address, and the FIPS mesh that addresses destinations by public key
(npub). The adapter handles the translation: DNS resolution from npub to
`fd::/8` address, identity cache management so FIPS can route IPv6 packets,
MTU enforcement so packets fit through the mesh, and the TUN interface that
connects to the kernel's IPv6 stack.

Applications that are FIPS-aware can bypass the adapter entirely and use the
native FIPS datagram API, addressing destinations directly by npub.

## DNS Integration

### The Problem

IPv6 addresses in the `fd::/8` range are derived from public keys via a
one-way hash (SHA-256). Given only an IPv6 address, the public key cannot be
recovered — and without the public key, FIPS cannot compute the node_addr
needed for routing.

The identity cache must be populated *before* packets arrive at the TUN
interface, or they cannot be routed.

### DNS as Entry Point

DNS resolution serves as the "routing intent" signal. When an application
resolves `npub1xxx...xxx.fips`, the FIPS DNS service:

1. Extracts the npub from the `.fips` domain name
2. Derives the `fd::/8` IPv6 address from the public key
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

A packet may arrive at the TUN for an `fd::/8` destination without a prior DNS
lookup — cached address, manual configuration, etc. Since the address derivation
is one-way, the npub cannot be recovered from the address alone.

FIPS returns ICMPv6 Destination Unreachable (Code 0: No route to destination)
for packets to unknown addresses. The identity cache must be populated before
traffic can be routed.

Known cache population mechanisms:

- **DNS lookup**: The primary path
- **Inbound traffic**: Authenticated sessions from other nodes populate the
  cache with their identity information

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

The `fd` prefix ensures no collision with addresses in use on the underlying
transport network. These are overlay identifiers — they appear in the TUN
interface for application compatibility but are not routable on the underlying
transport.

## Identity Cache

The identity cache maps the FIPS address prefix (15 bytes — the IPv6 address
minus the `fd` prefix) to `(NodeAddr, PublicKey)`. This cache is needed only
when using the IPv6 adapter; the native FIPS API provides the public key
directly.

### Eviction Policy

The mapping is deterministic (derived from the public key) and never becomes
stale. The cache uses **LRU-only eviction** bounded by a configurable size
(default 10K entries). There is no TTL — entries are evicted only when the
cache is full and space is needed for a new entry.

### Relationship to DNS TTL

The identity cache timeout must be longer than the DNS TTL to ensure that while
an application believes its DNS resolution is valid, the corresponding routing
entry remains present. The DNS TTL (default 300s) governs when applications
re-query; the identity cache (LRU, no TTL) is always available as long as the
entry hasn't been evicted by memory pressure.

## MTU Enforcement

FIPS encapsulation adds overhead to every packet. The adapter must ensure
that IPv6 packets from applications fit within the FIPS encapsulation budget
after all layers of wrapping.

### Encapsulation Overhead

| Layer | Overhead | Purpose |
| ----- | -------- | ------- |
| Link encryption | 37 bytes | 16-byte outer header + 5-byte inner header (timestamp + msg_type) + 16-byte AEAD tag |
| SessionDatagram body | 35 bytes | ttl + path_mtu + src_addr + dest_addr (msg_type counted in inner header) |
| FSP header | 12 bytes | 4-byte prefix + 8-byte counter (used as AEAD AAD) |
| FSP inner header | 6 bytes | 4-byte timestamp + 1-byte msg_type + 1-byte inner_flags (inside AEAD) |
| Session AEAD tag | 16 bytes | ChaCha20-Poly1305 tag on session-encrypted payload |
| **Data path total** | **106 bytes** | `FIPS_OVERHEAD` constant |

Coordinate piggybacking (CP flag) adds variable overhead: `2 + entries × 16`
per coordinate, with both src and dst coords sent. The send path skips the
CP flag if adding coords would exceed the transport MTU.

The `FIPS_OVERHEAD` constant (106 bytes) represents the fixed data path
overhead and is used for MTU calculations.

### Effective IPv6 MTU

The effective IPv6 MTU visible to applications is:

```text
effective_ipv6_mtu = transport_mtu - FIPS_OVERHEAD
```

For typical deployments:

| Transport MTU | Effective IPv6 MTU | Notes |
| ------------- | ------------------ | ----- |
| 1472 (UDP/Ethernet) | 1366 | Standard deployment |
| 1280 (UDP minimum) | 1174 | Below IPv6 minimum |

IPv6 mandates that every link support at least 1280 bytes. The minimum
transport path MTU for the IPv6 adapter is therefore:

```text
1280 + 106 = 1386 bytes
```

Transports with smaller MTUs (radio at ~250 bytes, serial at 256 bytes) cannot
support the IPv6 adapter — applications on those transports must use the
native FIPS datagram API.

### ICMP Packet Too Big

When an outbound packet at the TUN exceeds the effective IPv6 MTU, the adapter
generates an ICMPv6 Packet Too Big message and delivers it back to the
application via the TUN. This triggers the kernel's Path MTU Discovery (PMTUD)
mechanism, which adjusts TCP segment sizes for subsequent transmissions.

ICMP Packet Too Big generation is rate-limited per source address (100ms
interval) to prevent storms from applications sending many oversized packets.

The ICMP response is delivered locally (back through the TUN to the kernel) —
no network traversal is needed, so delivery is reliable.

### TCP MSS Clamping

The adapter intercepts TCP SYN and SYN-ACK packets at the TUN interface and
clamps the Maximum Segment Size (MSS) option:

```text
clamped_mss = effective_ipv6_mtu - 40 (IPv6 header) - 20 (TCP header)
```

This prevents TCP connections from negotiating segment sizes that would exceed
the FIPS path MTU. Clamping is applied in two places:

- **TUN reader** (outbound): Clamps MSS on outbound SYN packets
- **TUN writer** (inbound): Clamps MSS on inbound SYN-ACK packets

Together, these ensure both directions of a TCP connection use appropriately
sized segments from the start, avoiding the initial oversized packet loss
that would occur with ICMP Packet Too Big alone.

### ICMP Rate Limiting

ICMPv6 error generation is rate-limited per source address using a token bucket
(100ms interval). This matches the standard ICMP rate limiting approach and
prevents amplification when an application sends a burst of oversized packets.

## TUN Interface

The TUN device (`fips0`) is the mechanism that connects the adapter to the
kernel's IPv6 stack. It is an implementation detail of the adapter, not its
defining feature.

### Architecture

```text
Applications (sockets using fd::/8 addresses)
       │
       ▼
Kernel IPv6 Stack (routing: fd::/8 → fips0)
       │
       ▼
TUN Device (fips0)
    ├── Reader Thread (blocking I/O → packet processing)
    └── Writer Thread (mpsc queue → TUN writes)
```

### Reader Thread

The TUN reader receives raw IPv6 packets from applications and processes them:

1. Validate IPv6 header
2. Extract destination `fd::/8` address
3. Look up identity cache — miss returns ICMPv6 Destination Unreachable
4. Retrieve NodeAddr and PublicKey from cache
5. Look up or establish FSP session
6. Encrypt payload with session keys
7. Route through FMP toward destination

### Writer Thread

A single writer thread services an mpsc queue of outbound packets:

- Inbound mesh traffic (decrypted session payloads destined for local
  applications)
- ICMPv6 error responses (Packet Too Big, Destination Unreachable)
- TCP MSS-clamped SYN-ACK packets

The queue-based design eliminates contention on TUN writes and cleanly
separates concerns. New packet sources can be added by cloning the sender
handle.

### Local Address Guarantee

The Linux kernel routing table processes rules in priority order:

1. **Local table**: Intercepts traffic to addresses assigned to this machine
2. **Main table**: Routes `fd::/8` to the TUN device

This means every packet arriving at the TUN reader is guaranteed to be for a
*remote* FIPS destination. No "is this for me?" check is needed on the read
path.

### Configuration

```yaml
tun:
  enabled: true
  name: fips0
  mtu: 1280
```

### Privileges

TUN device creation requires `CAP_NET_ADMIN`. Options:

- Run as root
- Set capability: `sudo setcap cap_net_admin+ep ./target/debug/fips`
- Pre-created persistent TUN device

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
| Per-destination route MTU (netlink) | Planned |
| Transit MTU error signal | Planned |
| Path MTU tracking (SessionDatagram field) | **Implemented** |
| Path MTU notification (end-to-end echo) | **Implemented** |
| Endpoint fragmentation/reassembly | Future direction |

## Design Considerations

### Path MTU Discovery

Two complementary mechanisms support full PMTUD:

1. **Proactive**: The `path_mtu` field (2 bytes) in the SessionDatagram envelope
   is implemented at the FMP level. The source sets it to its outbound link MTU
   minus overhead; each transit node applies
   `min(current, own_outbound_mtu - overhead)`. The destination receives the
   forward-path minimum. PathMtuNotification is handled at the session layer;
   the destination sends the observed forward-path MTU back to the source,
   which applies it with decrease-immediate / increase-requires-3-consecutive
   hysteresis.

2. **Reactive**: When a transit node cannot forward a packet (MTU exceeded), it
   sends an error signal back to the source. This handles the in-flight gap
   between a path MTU decrease and the source learning via the echo.

Both are needed: proactive handles steady state; reactive handles the transient
window when oversized packets hit a new bottleneck before the source adapts.

### No Fragmentation

FIPS remains a pure datagram service with no fragmentation at transit nodes.
Session-layer encryption is end-to-end — the AEAD tag authenticates the entire
plaintext. Fragmenting encrypted datagrams would require either exposing
plaintext structure to transit nodes (unacceptable) or reassembly before
decryption (opens attack surface).

Endpoint-only fragmentation (fragment before session encryption, reassemble
after decryption) is a future direction that avoids these objections. Each
fragment would be independently encrypted and look like a normal data packet
to transit nodes.

## References

- [fips-intro.md](fips-intro.md) — Protocol overview and architecture
- [fips-session-layer.md](fips-session-layer.md) — FSP (below the adapter)
- [fips-wire-formats.md](fips-wire-formats.md) — FSP and SessionDatagram wire
  formats
- [fips-configuration.md](fips-configuration.md) — TUN configuration parameters
