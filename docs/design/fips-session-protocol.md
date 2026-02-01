# FIPS Session Protocol Flow

## Overview

This document captures design considerations for FIPS protocol message flow,
including peer discovery, authentication, tree announcements, and data routing.

---

## 1. Application-Initiated Traffic Flow

Traffic flow begins at the application layer with a DNS query, which triggers
a cascade of events through the FIPS stack.

### 1.1 DNS as Entry Point

An application wants to send IPv6 traffic to another FIPS node, identified by
an npub. The flow:

1. **DNS Query**: Application queries a local FIPS DNS server for the npub
   (format TBD - perhaps `npub1xxx...xxx.fips` or similar)

2. **FIPS DNS Server** performs two functions:
   - **Address derivation**: Converts the npub to an identity and derives the
     corresponding `fd::/8` IPv6 address
   - **Cache priming**: Stores the identity mapping (IPv6 address ↔ npub ↔ node_id)
     in the local FIPS routing cache

3. **DNS Response**: Returns the derived IPv6 address to the application

4. **Packet Transmission**: Application sends IPv6 packet to the returned address,
   which routes to the TUN interface via the `fd::/8` route

5. **TUN Processing**: When the packet arrives at the TUN, FIPS already has the
   cached mapping from the DNS lookup, enabling immediate routing decisions

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

Authentication derives from the Noise KK handshake binding session keys to
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

- Transport failover (UDP → Tor → back to UDP)
- Route changes (different intermediate hops)
- Transport address changes on either end

The session is bound to **npub identities**, not transport addresses or routing
paths.

### 3.4 Session Establishment Flow

FIPS uses Noise KK for session establishment. Both parties know each other's
static keys: the initiator from DNS lookup, the responder from the source
address in the SessionSetup. The KK pattern provides mutual authentication
from the first message.

The handshake is carried inside SessionSetup/SessionAck messages (see §5.5),
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

## 5. Session Terminology

FIPS uses two distinct session concepts at different layers:

| Term                | Layer       | Purpose                      | Endpoints              |
|---------------------|-------------|------------------------------|------------------------|
| **Crypto Session**  | End-to-end  | Authentication + encryption  | Source ↔ Destination   |
| **Routing Session** | Hop-by-hop  | Cache coordinates at routers | Along the path         |

### 5.1 Crypto Session

- Established between two npub identities
- Provides confidentiality and authenticity via Noise KK
- Survives route changes and transport failover
- Keyed by: `(local_npub, remote_npub)`

### 5.2 Routing Session

- Warms coordinate caches at intermediate routers
- Enables minimal 36-byte data packet headers
- Must be re-established when router caches expire
- Keyed by: `(src_addr, dest_addr)` at each router

### 5.3 Combined Establishment

Both sessions are established together: the routing session setup carries the
crypto handshake, minimizing round-trips.

```text
1. Route discovery (if needed)
   └─► LookupRequest/Response → obtain destination coordinates

2. SessionSetup + Crypto Init
   └─► Source sends SessionSetup containing:
       - src/dest coordinates (for router caching)
       - Noise KK handshake initiation (for destination)
   └─► Routers cache coordinates as packet transits
   └─► Destination receives crypto init, begins handshake

3. SessionAck + Crypto Response
   └─► Destination sends SessionAck containing:
       - Its coordinates (for reverse path caching)
       - Noise KK handshake response
   └─► Routers cache reverse path
   └─► Source completes crypto handshake

4. Data flow
   └─► Encrypted payloads with minimal 36-byte headers
   └─► Both crypto session and routing session now active
```

SessionSetup and SessionAck messages carry both routing information (coordinates
for router caching) and crypto payload (handshake messages, opaque to routers).
Routers process the routing portion and forward; only endpoints process the
crypto portion.

---

## 6. Session-Layer Encryption

FIPS uses two independent Noise Protocol handshakes at different layers:

| Layer   | Scope       | Pattern  | Purpose                                   |
|---------|-------------|----------|-------------------------------------------|
| Link    | Hop-by-hop  | Noise IK | Authenticate peers, encrypt link          |
| Session | End-to-end  | Noise KK | Authenticate endpoints, encrypt payload   |

Both use `Noise_IK_secp256k1_ChaChaPoly_SHA256` with the same cryptographic
primitives, but with separate keys and sessions.

### 6.1 Why Two Layers?

**Link encryption** protects against passive observers on each hop but allows
intermediate nodes to see routing information (destination address).

**Session encryption** protects the actual payload end-to-end. Intermediate
nodes forward opaque ciphertext without being able to read the contents.

### 6.2 Session Noise Handshake

The session-layer Noise KK handshake is carried inside `SessionSetup`/`SessionAck`
messages, which themselves travel through the link-encrypted channel:

```text
Initiator knows destination npub (from DNS lookup)
    │
    ▼
SessionSetup { coords, handshake_payload: Noise KK msg1 }
    │
    ▼  (travels through link-encrypted hops)
    │
Responder processes msg1, learns initiator identity
    │
    ▼
SessionAck { coords, handshake_payload: Noise KK msg2 }
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
    handshake_payload: Vec<u8>,  // Noise KK message 1
}

SessionAck {
    // Routing portion
    src_coords: Vec<NodeId>,  // Responder's coordinates

    // Crypto portion
    handshake_payload: Vec<u8>,  // Noise KK message 2
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

- Uses Noise XK pattern (different from our KK)
- Same secp256k1 + ChaCha20-Poly1305 + SHA-256 stack
- Handles the secp256k1 ECDH correctly
- Open source implementations available in multiple languages

FIPS can reference BOLT 8's cryptographic details while using the KK pattern
appropriate for our mutual-knowledge scenario.

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

**Reconciliation note**: §3.1 mentions packets being "signed by source" -
this should be updated to reflect AEAD-only authentication.

---

## 7. Peer Connection Establishment

Before any of the traffic flows described above can occur, nodes must establish
authenticated peer connections using Noise IK. See [fips-design.md](fips-design.md)
§1 for full protocol details and [fips-architecture.md](fips-architecture.md)
for the startup sequence.

### 7.1 Connection Flow Summary (Noise IK)

All messages use TLV framing (see fips-design.md §6 Wire Format):

```text
┌────────┬────────┬────────────────────────────────────┐
│ Type   │ Length │ Payload                            │
│ 1 byte │ 2 bytes│ Variable                           │
└────────┴────────┴────────────────────────────────────┘
```

**Outbound (to static peer):**

```text
Config: npub + transport hint (e.g., "udp:192.168.1.1:4000")
    │
    ▼
Create link via transport
    │
    ▼
Send: [0x01][0x00 0x52][82-byte Noise msg1]
      Type=NoiseIKMsg1, Length=82
    │
    ▼
Recv: [0x02][0x00 0x21][33-byte Noise msg2]
      Type=NoiseIKMsg2, Length=33
    │
    ▼
Noise session established → link encrypted → begins tree gossip
```

**Inbound (peer connects to us):**

```text
Transport receives packet from unknown address
    │
    ▼
Parse TLV: Type=0x01 (NoiseIKMsg1)
    │
    ▼
Process msg1 → learn peer's identity from encrypted static key
    │
    ▼
Send: [0x02][0x00 0x21][33-byte Noise msg2]
    │
    ▼
Noise session established → link encrypted → begins tree gossip
```

### 7.2 Post-Authentication

After successful Noise handshake:

1. **Link encrypted**: All subsequent messages use AEAD encryption
2. **TreeAnnounce exchange**: Both peers send their current tree state
3. **FilterAnnounce exchange**: Both peers send their bloom filters
4. **Peer is Active**: Can now participate in routing and forwarding

The first TreeAnnounce from a new peer may trigger parent reselection if that
peer offers a better path to root.

---

## 8. Document Reconciliation

This section tracks items that need reconciliation with existing design docs
or earlier sections of this document.

### 8.1 Completed Updates (Session 47)

| Location                         | Status | Notes                                              |
|----------------------------------|--------|----------------------------------------------------|
| fips-design.md §1 Peer Auth      | ✓ Done | Replaced custom handshake with Noise IK            |
| fips-design.md §6 Messages       | ✓ Done | Split into LinkMessageType + SessionMessageType    |
| protocol.rs                      | ✓ Done | Removed Hello/Challenge/Auth/AuthAck types         |
| protocol.rs                      | ✓ Done | Added SessionDatagram for link-layer encapsulation |
| This document §6                 | ✓ Done | Updated to two-layer Noise IK architecture         |
| This document §7                 | ✓ Done | Updated connection flow for Noise IK               |

### 8.2 Previous Updates (Session 40)

| Location                         | Status | Notes                                               |
|----------------------------------|--------|-----------------------------------------------------|
| §3.1                             | ✓ Done | Updated to AEAD authentication                      |
| fips-routing.md Part 4           | ✓ Done | Renamed to "Routing Session Establishment"          |
| fips-routing.md SessionSetup/Ack | ✓ Done | Added `handshake_payload` for crypto handshake      |
| fips-design.md §7 Encryption     | ✓ Done | Updated to reference Noise instead of NIP-44        |
| fips-architecture.md Config      | ✓ Done | Renamed to "Routing Session", added "Crypto Session"|

### 8.3 Design Doc Alignment Summary

The following decisions from this document have been propagated:

1. **Two-layer architecture**: Link layer (Noise IK peer auth) and session layer
   (Noise KK end-to-end) operate independently with separate keys
2. **Session terminology** (§5.4): "Routing Session" vs "Crypto Session" distinction
   now consistent across all docs
3. **Combined establishment** (§5.5): SessionSetup/SessionAck carry optional
   `handshake_payload` for session-layer Noise KK handshake
4. **Message type split**: LinkMessageType for hop-by-hop, SessionMessageType for
   end-to-end (carried inside SessionDatagram)
