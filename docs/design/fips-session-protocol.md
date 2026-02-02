# FIPS Session Protocol Flow

## Overview

This document captures design considerations for FIPS protocol message flow,
including peer discovery, authentication, tree announcements, and data routing.

---

## 1. Application-Initiated Traffic Flow

> **Note**: This section applies to traditional IP-based applications using the
> TUN interface. Applications using the native FIPS datagram service address
> destinations directly by npub, and routing proceeds from there without DNS.

Traffic flow begins at the application layer with a DNS query, which triggers
a cascade of events through the FIPS stack.

### 1.1 DNS as Entry Point

An application wants to send IPv6 traffic to another FIPS node, identified by
an npub. The flow:

1. **DNS Query**: Application queries the local FIPS DNS service for the npub
   mapping to an IPv6 address

2. **FIPS DNS service** performs two functions:
   - **Address derivation**: Converts the npub to an identity and derives the
     corresponding `fd::/8` IPv6 address
   - **Cache priming**: Stores the identity mapping (IPv6 address ↔ npub ↔ node_id)
     in the local FIPS routing cache

3. **DNS Response**: Returns the derived IPv6 address to the application

4. **Packet Transmission**: Application sends IPv6 packet to the returned address,
   which routes to the TUN interface via the `fd::/8` route

5. **TUN Processing**: When the packet arrives at the TUN, FIPS already has the
   cached mapping from the DNS lookup, enabling immediate routing decisions

6. **Note**: This identity cache is only necessary when using the FIPS IPv6 shim

### 1.2 Design Rationale

Using DNS as the trigger point ensures the routing cache is populated *before*
packets arrive. This avoids:

- Blocking packets while performing identity lookups
- Packet drops during cold-cache scenarios
- Complex async lookup machinery in the hot path

The DNS server acts as a "routing intent" signal - if an application queries
for a destination, it likely intends to send traffic there.

### 1.3 DNS Name Format

NPUBs are represented as DNS names in the format:

```text
npub1xxxxxx...xxxxx.fips
```

The FIPS DNS server recognizes names ending in `.fips` and extracts the npub
for address derivation.

### 1.4 Identity Cache Lifetime

The identity cache (IPv6 address ↔ npub ↔ node_id) has the following lifetime
semantics:

- **Configurable timeout**: Cache entries expire after a configured duration
- **Traffic refresh**: Timer resets to zero whenever traffic is sent to that
  destination (LRU-style keep-alive)
- **TTL relationship**: Cache timeout MUST be longer than DNS TTL

The TTL constraint ensures that while an application believes its DNS resolution
is valid (within TTL), the corresponding FIPS routing entry remains present.
Example: DNS TTL = 300s, Cache timeout = 600s.

```text
DNS query → cache entry created (timeout = 600s)
   ...traffic... → timeout reset to 600s
   ...traffic... → timeout reset to 600s
DNS TTL expires (300s) → app may re-query, but cache still valid
   ...no traffic for 600s...
Cache entry expires
```

### 1.5 Traffic Without Prior DNS Lookup

A packet may arrive at the TUN for an `fd::/8` destination without a prior
DNS lookup (cached address, manual configuration, etc.). Since address
derivation is one-way (SHA-256), the npub cannot be recovered from the address,
and without the npub we cannot determine the node_id needed for routing.

FIPS returns ICMPv6 Destination Unreachable (Code 0: No route to destination)
for packets to unknown addresses. The identity cache must be populated before
traffic can be routed.

Known cache population mechanisms:

- DNS lookup (primary path, described above)
- Inbound traffic from authenticated peers

---

## 2. TUN Reader Processing

After DNS resolution, the application sends an IPv6 datagram to the destination
address. The kernel routes it to the TUN interface (via the `fd::/8` route),
where the FIPS TUN reader receives it.

### 2.1 Packet Arrival

```text
Application
    │
    ▼
IPv6 datagram (src=local_addr, dst=target_addr)
    │
    ▼
Kernel routing table: fd::/8 → fips0
    │
    ▼
TUN reader receives raw IPv6 packet
```

### 2.2 TUN Reader Actions

On receiving a packet, the TUN reader:

1. **Validate IPv6 header**: Version = 6, payload length sane, etc.

2. **Extract destination address**: The `fd::/8` address from the IPv6 header

3. **Identity cache lookup**: Query cache for destination address
   - **Miss**: Return ICMPv6 Destination Unreachable (see §1.5)
   - **Hit**: Proceed with routing

4. **Retrieve routing identity**: Cache hit provides:
   - `npub`: The Nostr public key of the destination
   - `node_id`: SHA-256(npub), used for spanning tree routing

5. **Session lookup**: Check for existing FIPS session with destination npub
   - **Hit**: Use existing session for encryption/signing
   - **Miss**: Initiate session establishment (see §3)

6. **Route determination**: Using node_id, determine the next hop peer:
   - Check route cache for destination's spanning tree coordinates
   - If cache miss, initiate route discovery (see §4.4)
   - Select next hop via greedy routing toward destination coordinates

7. **Packet forwarding**: Encapsulate and send via appropriate transport:
   - Encrypt payload with session keys (end-to-end)
   - Wrap in link-layer frame for next hop peer
   - Encrypt with link keys and transmit via peer's transport

---

## 3. FIPS Sessions

A FIPS session represents a bidirectionally authenticated, encrypted channel
between two FIPS nodes.

### 3.1 Session Properties

Each session contains:

- **Peer identity**: The remote node's npub and node_id
- **Symmetric session keys**: Directional keys for encryption (send_key, recv_key)
- **Nonce counters**: Per-direction counters for replay protection

Payloads within a session are:

1. **Encrypted** with the session key (provides confidentiality)
2. **Authenticated** via AEAD tag (session keys bound to npub identities)

Authentication derives from the Noise IK handshake binding session keys to
both parties' static keys. See §6 for cryptographic details.

### 3.2 Session Establishment Trigger

When the TUN reader has a packet for a destination with no existing session:

```text
TUN reader
    │
    ├─► Identity cache lookup → node_id
    │
    ├─► Session lookup (by npub) → MISS
    │
    └─► Initiate session establishment
```

Packets that trigger session establishment are queued (with bounded buffer
management) and transmitted after the session is established.

### 3.3 Session Independence from Transport

FIPS sessions exist above the routing layer. A session between two npubs
survives:

- Transport failover (UDP → WiFi → back to UDP)
- Route changes (different intermediate hops)
- Transport address changes on either end (WiFi → LTE → WiFi)

The session is bound to **npub identities**, not transport addresses or routing
paths. This allows FIPS endpoints to roam over their transports as needed while
maintaining an established session.

### 3.4 Session Establishment Flow

FIPS uses Noise IK for session establishment. The initiator knows the
destination's npub; the responder learns the initiator's identity from the
handshake. This is the same asymmetry as link-layer connections.

The handshake is carried inside SessionSetup/SessionAck messages (see §5.1),
which also establish routing session state at intermediate nodes.

### 3.5 Simultaneous Session Initiation (Crossing Hellos)

When both nodes attempt to establish a session simultaneously, a deterministic
tie-breaker resolves the conflict using npub ordering:

- If local npub < remote npub: Continue as initiator, ignore incoming initiation
- If local npub > remote npub: Abort own initiation, switch to responder role

This ensures exactly one handshake completes with minimal wasted effort.

---

## 4. FIPS Mesh Routing

Below the session layer, all FIPS packets (session handshake messages, encrypted
payloads, control traffic) must be routed through the mesh to their destination.
See [fips-routing.md](fips-routing.md) for the full routing design.

### 4.1 Routing Overview

FIPS routing combines three mechanisms:

1. **Bloom filters**: Fast reachability lookup for nearby destinations
2. **Discovery protocol**: Query-based lookup for distant destinations
3. **Greedy tree routing**: Coordinate-based forwarding using spanning tree position

The routing layer maintains a route cache mapping `node_id → (coordinates,
next_hop_peer)`. Cache hits enable immediate greedy routing; cache misses
trigger route discovery via bloom filter queries or LookupRequest flooding.

### 4.2 Packet Handling During Discovery

Packets are queued (with bounded buffer) while route discovery is in progress
and transmitted once coordinates are obtained.

### 4.3 Route Cache Lifetime

Route cache entries:

- Expire after configurable timeout
- Refresh on successful packet delivery
- Invalidate when peer link goes down or spanning tree topology changes

---

## 5. Route Cache Warming

### 5.1 Initial Warming via Handshake

The crypto session handshake (SessionSetup/SessionAck) warms route caches at
intermediate routers as it transits. Each message carries the sender's
coordinates; routers extract and cache `(src_addr, dest_addr) → next_hop` for
both directions. After the handshake completes, data packets use minimal
36-byte headers and routers forward based on cached routes.

### 5.2 Cache Miss Recovery

When an intermediate router's cache entry expires or is evicted, it cannot
forward data packets (which carry only addresses, not coordinates). The router
returns a CoordsRequired error to the sender.

The crypto session remains valid—only the routing state is lost. Recovery uses
coords-on-demand: data packets include an optional coordinates field. When the
sender receives CoordsRequired:

1. Sender marks the route as "cold"
2. Subsequent data packets include coordinates (flag bit set)
3. Routers along the path cache coordinates as packets transit
4. Once route is warm again, sender clears the flag and resumes minimal headers

This avoids a full SessionSetup round-trip for what is purely a routing cache
refresh.

### 5.3 DataPacket Coordinate Flag

The DataPacket `flags` field includes a `COORDS_PRESENT` bit:

| Bit | Meaning                                              |
|-----|------------------------------------------------------|
| 0   | COORDS_PRESENT - coordinates follow the fixed header |

When set, the packet includes `src_coords` and `dest_coords` after the standard
header fields. Routers process these coordinates the same way as SessionSetup:
cache both directions and forward using greedy routing.

### 5.4 Sender State Machine

```text
        ┌──────────────┐
        │    WARM      │ ◄── Normal: send minimal headers
        └──────┬───────┘
               │ CoordsRequired received
               ▼
        ┌──────────────┐
        │    COLD      │ ◄── Send packets with coords
        └──────┬───────┘
               │ N packets sent successfully
               ▼
        ┌──────────────┐
        │    WARM      │
        └──────────────┘
```

The sender transitions back to WARM after sending a configurable number of
packets with coordinates (e.g., 3) without receiving CoordsRequired. This
provides confidence that caches along the path are populated.

---

## 6. Session-Layer Encryption

FIPS uses two independent Noise Protocol handshakes at different layers:

| Layer   | Scope       | Pattern  | Purpose                                   |
|---------|-------------|----------|-------------------------------------------|
| Link    | Hop-by-hop  | Noise IK | Authenticate peers, encrypt link          |
| Session | End-to-end  | Noise IK | Authenticate endpoints, encrypt payload   |

Both use `Noise_IK_secp256k1_ChaChaPoly_SHA256` with the same cryptographic
primitives, but with separate keys and sessions.

> **Privacy note**: Noise IK does not provide initiator anonymity if the
> responder's static key is compromised—an attacker who obtains the responder's
> nsec can decrypt the initiator's identity from captured handshake messages.
> Noise XK would protect initiator identity in this scenario, but requires an
> additional round-trip (3 handshake messages vs 2), increasing session setup
> from 3 packets to 4. Further deployment experience is needed to evaluate
> whether the privacy benefit justifies the latency cost.

### 6.1 Why Two Layers?

**Link encryption** protects against passive observers on each hop but allows
intermediate nodes to see routing information (destination address).

**Session encryption** protects the actual payload end-to-end. Intermediate
nodes forward opaque ciphertext without being able to read the contents.

### 6.2 Session Noise Handshake

The session-layer Noise IK handshake is carried inside `SessionSetup`/`SessionAck`
messages, which themselves travel through the link-encrypted channel:

```text
Initiator knows destination npub (from DNS lookup)
    │
    ▼
SessionSetup { coords, handshake_payload: Noise IK msg1 }
    │
    ▼  (travels through link-encrypted hops)
    │
Responder processes msg1, learns initiator identity
    │
    ▼
SessionAck { coords, handshake_payload: Noise IK msg2 }
    │
    ▼
Session keys established (independent of link keys)
```

### 6.3 Cryptographic Primitives

Both link and session layers use the same cryptographic stack:

| Component      | Choice              | Notes                      |
|----------------|---------------------|----------------------------|
| Curve          | secp256k1           | Nostr-native               |
| DH             | ECDH on secp256k1   | Standard EC Diffie-Hellman |
| Cipher         | ChaCha20-Poly1305   | AEAD, same as NIP-44       |
| Hash           | SHA-256             | Nostr-native               |
| Key derivation | HKDF-SHA256         | Standard Noise KDF         |

These choices prioritize compatibility with existing Nostr infrastructure.
Secp256k1 and SHA-256 are already used for Nostr identities, and
ChaCha20-Poly1305 matches NIP-44 encryption. Lightning's BOLT 8 provides a
proven reference for adapting Noise Protocol to secp256k1.

### 6.4 Handshake Integration with SessionSetup

The Noise handshake messages embed in SessionSetup/SessionAck:

```text
SessionSetup {
    // Routing portion (processed by routers)
    src_coords: Vec<NodeId>,
    dest_coords: Vec<NodeId>,
    src_addr: Ipv6Addr,
    dest_addr: Ipv6Addr,

    // Crypto portion (opaque to routers, processed by destination)
    handshake_payload: Vec<u8>,  // Noise IK message 1
}

SessionAck {
    // Routing portion
    src_coords: Vec<NodeId>,  // Responder's coordinates

    // Crypto portion
    handshake_payload: Vec<u8>,  // Noise IK message 2
}
```

### 6.5 Session Keys

After handshake completion, Noise produces two symmetric keys:

- `send_key`: For encrypting outbound packets
- `recv_key`: For decrypting inbound packets

These are used with ChaCha20-Poly1305 for all subsequent data packets.

### 6.6 Nonce Management

FIPS uses counter-based nonces for ChaCha20-Poly1305. Each side maintains a
64-bit send counter, incremented per packet. No coordination is needed since
keys are directional. The counter also enables replay detection by rejecting
packets with nonce ≤ last seen.

### 6.7 Forward Secrecy

The ephemeral keys (`e` in Noise notation) provide forward secrecy:

- Compromise of static keys (npub/nsec) doesn't reveal past session keys
- Each session has unique ephemeral keys
- Session keys derived from ephemeral-ephemeral DH (`ee`)

### 6.8 Reference: Lightning BOLT 8

Lightning's adaptation of Noise for secp256k1 (BOLT 8) provides a proven
reference implementation:

- Uses Noise XK pattern (different from our IK)
- Same secp256k1 + ChaCha20-Poly1305 + SHA-256 stack
- Handles the secp256k1 ECDH correctly
- Open source implementations available in multiple languages

FIPS can reference BOLT 8's cryptographic details while using the IK pattern.

### 6.9 Data Packet Authentication

**Decision**: Use AEAD authentication only (no per-packet signatures).

The Noise handshake binds session keys to both parties' static keys. After
handshake completion:

- Session keys are cryptographically tied to both npubs
- AEAD (ChaCha20-Poly1305) provides integrity and authenticity
- Only the holder of the session key can produce valid ciphertext
- Session keys can only be derived by holders of the corresponding nsecs

Per-packet signatures would add:

- 64 bytes overhead per packet
- Signing CPU cost (secp256k1 Schnorr)
- Verification CPU cost at receiver

Since Noise already provides authentication through key binding, signatures
are redundant. This matches WireGuard and Lightning's approach.

---

## 7. Peer Connection Establishment

Before any session-layer traffic can flow, nodes must establish authenticated
link-layer connections with their peers using Noise IK. See
[fips-wire-protocol.md](fips-wire-protocol.md) for the complete wire protocol
specification including handshake flow, session lifecycle, index management,
roaming support, and transport-specific considerations.

After successful Noise IK handshake:

1. **Link encrypted**: All subsequent messages use AEAD encryption
2. **TreeAnnounce exchange**: Both peers send their current spanning tree state
3. **FilterAnnounce exchange**: Both peers send their bloom filters
4. **Peer is Active**: Can now participate in routing and forwarding

The first TreeAnnounce from a new peer may trigger parent reselection if that
peer offers a better path to root. See [fips-gossip-protocol.md](fips-gossip-protocol.md)
for TreeAnnounce and FilterAnnounce wire formats.

---

## 8. Session Layer Wire Format

Session layer messages are carried inside `SessionDatagram` (type 0x40) at the
link layer. The session datagram is encrypted hop-by-hop with link keys, but
the inner payload is encrypted end-to-end with session keys.

### 8.1 Message Type Codes

| Type Code | Message        | Direction | Purpose                           |
|-----------|----------------|-----------|-----------------------------------|
| 0x00      | SessionSetup   | S → D     | Establish session + warm caches   |
| 0x01      | SessionAck     | D → S     | Confirm session establishment     |
| 0x10      | DataPacket     | Both      | Application data                  |
| 0x20      | CoordsRequired | R → S     | Router cache miss                 |
| 0x21      | PathBroken     | R → S     | Greedy routing failed             |

### 8.2 SessionSetup (0x00)

Establishes a crypto session and warms router coordinate caches along the path.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SESSION SETUP PACKET                                │
├────────┬──────────────────┬───────────┬─────────────────────────────────────┤
│ Offset │ Field            │ Size      │ Description                         │
├────────┼──────────────────┼───────────┼─────────────────────────────────────┤
│   0    │ msg_type         │ 1 byte    │ 0x00                                │
│   1    │ flags            │ 1 byte    │ Bit 0: REQUEST_ACK                  │
│        │                  │           │ Bit 1: BIDIRECTIONAL                │
│   2    │ src_addr         │ 16 bytes  │ Source fd::/8 address               │
│  18    │ dest_addr        │ 16 bytes  │ Destination fd::/8 address          │
│  34    │ src_coords_count │ 2 bytes   │ u16 LE, number of src coord entries │
│  36    │ src_coords       │ 32 × n    │ NodeId array (self → root)          │
│  ...   │ dest_coords_count│ 2 bytes   │ u16 LE, number of dest coord entries│
│  ...   │ dest_coords      │ 32 × m    │ NodeId array (dest → root)          │
│  ...   │ handshake_len    │ 2 bytes   │ u16 LE, Noise payload length        │
│  ...   │ handshake_payload│ variable  │ Noise IK msg1 (82 bytes typical)    │
└────────┴──────────────────┴───────────┴─────────────────────────────────────┘
```

**Example** (depth 3 source, depth 4 destination, with Noise handshake):

```text
┌──────┬───────┬──────────────────┬──────────────────┬───────┬─────────────┐
│ 0x00 │ 0x01  │ src_addr         │ dest_addr        │ 0x03  │ src_coords  │
│ type │ flags │ 16 bytes         │ 16 bytes         │ count │ 3 × 32 bytes│
├──────┴───────┴──────────────────┴──────────────────┴───────┴─────────────┤
│ 0x04  │ dest_coords   │ 0x52  │ handshake_payload                        │
│ count │ 4 × 32 bytes  │ len=82│ 82 bytes (Noise IK msg1)                 │
└───────┴───────────────┴───────┴──────────────────────────────────────────┘

Total: 1 + 1 + 16 + 16 + 2 + 96 + 2 + 128 + 2 + 82 = 346 bytes
```

### 8.3 SessionAck (0x01)

Confirms session establishment and completes the Noise handshake.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SESSION ACK PACKET                                 │
├────────┬──────────────────┬───────────┬─────────────────────────────────────┤
│ Offset │ Field            │ Size      │ Description                         │
├────────┼──────────────────┼───────────┼─────────────────────────────────────┤
│   0    │ msg_type         │ 1 byte    │ 0x01                                │
│   1    │ flags            │ 1 byte    │ Reserved                            │
│   2    │ src_addr         │ 16 bytes  │ Acknowledger's address              │
│  18    │ dest_addr        │ 16 bytes  │ Original sender's address           │
│  34    │ src_coords_count │ 2 bytes   │ u16 LE                              │
│  36    │ src_coords       │ 32 × n    │ Acknowledger's coords (for caching) │
│  ...   │ handshake_len    │ 2 bytes   │ u16 LE, Noise payload length        │
│  ...   │ handshake_payload│ variable  │ Noise IK msg2 (33 bytes typical)    │
└────────┴──────────────────┴───────────┴─────────────────────────────────────┘
```

### 8.4 DataPacket (0x10)

Carries encrypted application data (typically IPv6 payloads).

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DATA PACKET (Minimal Header)                           │
├────────┬──────────────────┬───────────┬─────────────────────────────────────┤
│ Offset │ Field            │ Size      │ Description                         │
├────────┼──────────────────┼───────────┼─────────────────────────────────────┤
│   0    │ msg_type         │ 1 byte    │ 0x10                                │
│   1    │ flags            │ 1 byte    │ Bit 0: COORDS_PRESENT               │
│   2    │ hop_limit        │ 1 byte    │ Decremented each hop                │
│   3    │ reserved         │ 1 byte    │ Alignment padding                   │
│   4    │ payload_length   │ 2 bytes   │ u16 LE                              │
│   6    │ src_addr         │ 16 bytes  │ Source fd::/8 address               │
│  22    │ dest_addr        │ 16 bytes  │ Destination fd::/8 address          │
│  38    │ payload          │ variable  │ Encrypted application data          │
└────────┴──────────────────┴───────────┴─────────────────────────────────────┘

Minimal header: 38 bytes (comparable to IPv6's 40 bytes)
```

When `COORDS_PRESENT` flag is set (route warming after CoordsRequired):

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DATA PACKET (With Coordinates)                           │
├────────┬──────────────────┬───────────┬─────────────────────────────────────┤
│ Offset │ Field            │ Size      │ Description                         │
├────────┼──────────────────┼───────────┼─────────────────────────────────────┤
│   0    │ msg_type         │ 1 byte    │ 0x10                                │
│   1    │ flags            │ 1 byte    │ 0x01 (COORDS_PRESENT)               │
│   2    │ hop_limit        │ 1 byte    │ Decremented each hop                │
│   3    │ reserved         │ 1 byte    │ Alignment padding                   │
│   4    │ payload_length   │ 2 bytes   │ u16 LE                              │
│   6    │ src_addr         │ 16 bytes  │ Source fd::/8 address               │
│  22    │ dest_addr        │ 16 bytes  │ Destination fd::/8 address          │
│  38    │ src_coords_count │ 2 bytes   │ u16 LE                              │
│  40    │ src_coords       │ 32 × n    │ Source coordinates                  │
│  ...   │ dest_coords_count│ 2 bytes   │ u16 LE                              │
│  ...   │ dest_coords      │ 32 × m    │ Destination coordinates             │
│  ...   │ payload          │ variable  │ Encrypted application data          │
└────────┴──────────────────┴───────────┴─────────────────────────────────────┘

With depth-4 coords both directions: 38 + 2 + 128 + 2 + 128 = 298 bytes header
```

### 8.5 CoordsRequired (0x20)

Sent by an intermediate router when it cannot forward a DataPacket due to
coordinate cache miss.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COORDS REQUIRED PACKET                               │
├────────┬──────────────────┬───────────┬─────────────────────────────────────┤
│ Offset │ Field            │ Size      │ Description                         │
├────────┼──────────────────┼───────────┼─────────────────────────────────────┤
│   0    │ msg_type         │ 1 byte    │ 0x20                                │
│   1    │ flags            │ 1 byte    │ Reserved                            │
│   2    │ dest_addr        │ 16 bytes  │ The address we couldn't route       │
│  18    │ reporter         │ 32 bytes  │ NodeId of reporting router          │
└────────┴──────────────────┴───────────┴─────────────────────────────────────┘

Total: 50 bytes
```

### 8.6 PathBroken (0x21)

Sent when greedy routing fails (no peer is closer to destination).

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PATH BROKEN PACKET                                  │
├────────┬──────────────────┬───────────┬─────────────────────────────────────┤
│ Offset │ Field            │ Size      │ Description                         │
├────────┼──────────────────┼───────────┼─────────────────────────────────────┤
│   0    │ msg_type         │ 1 byte    │ 0x21                                │
│   1    │ flags            │ 1 byte    │ Reserved                            │
│   2    │ dest_addr        │ 16 bytes  │ The unreachable destination         │
│  18    │ reporter         │ 32 bytes  │ NodeId of reporting router          │
│  50    │ last_coords_count│ 2 bytes   │ u16 LE                              │
│  52    │ last_known_coords│ 32 × n    │ Stale coords that failed            │
└────────┴──────────────────┴───────────┴─────────────────────────────────────┘
```

### 8.7 Full Packet Layout Example

A DataPacket from source S to destination D, transiting router R:

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                           UDP DATAGRAM                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              FIPS LINK LAYER (S→R encrypted)                          │  │
│  ├───────────┬──────────────┬────────────┬───────────────────────────────┤  │
│  │ 0x00      │ R's recv_idx │ counter    │ ciphertext + tag              │  │
│  │ 1 byte    │ 4 bytes LE   │ 8 bytes LE │ N + 16 bytes                  │  │
│  └───────────┴──────────────┴────────────┴───────────────────────────────┘  │
│                                            │                                │
│                    ┌───────────────────────┘                                │
│                    │ Decrypt with S↔R link keys                             │
│                    ▼                                                        │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              LINK MESSAGE (plaintext for R)                           │  │
│  ├───────────┬───────────────────────────────────────────────────────────┤  │
│  │ 0x40      │ SessionDatagram payload                                   │  │
│  │ msg_type  │ (routable by R, encrypted end-to-end)                     │  │
│  └───────────┴───────────────────────────────────────────────────────────┘  │
│                    │                                                        │
│                    ▼                                                        │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │              SESSION LAYER (S↔D encrypted)                            │  │
│  ├───────────┬───────┬──────────┬──────────┬─────────────────────────────┤  │
│  │ 0x10      │ flags │ hop_limit│ pay_len  │ src_addr     │ dest_addr    │  │
│  │ DataPacket│ 0x00  │ 64       │ 1400     │ 16 bytes     │ 16 bytes     │  │
│  ├───────────┴───────┴──────────┴──────────┴──────────────┴──────────────┤  │
│  │                                                                       │  │
│  │                    ENCRYPTED PAYLOAD (S↔D session keys)               │  │
│  │                    ┌─────────────────────────────────────────────┐    │  │
│  │                    │ IPv6 packet or application data             │    │  │
│  │                    │ (+ 16-byte AEAD tag)                        │    │  │
│  │                    └─────────────────────────────────────────────┘    │  │
│  │                                                                       │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

Router R can see: dest_addr (for routing decision)
Router R cannot see: payload contents (encrypted with S↔D keys)
```

### 8.8 Encoding Rules

- All multi-byte integers are **little-endian**
- NodeId is 32 bytes (SHA-256 hash of npub)
- IPv6 addresses are 16 bytes (network byte order)
- Variable-length coordinate arrays use 2-byte u16 count prefix

```text
Vec<NodeId> encoding:
  count: u16 (little-endian)
  items: [u8; 32] × count
```
