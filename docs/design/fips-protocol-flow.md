# FIPS Protocol Traffic Flow

Design discussion from Session 39.

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
DNS lookup. Scenarios:

- Application has cached/hardcoded address from previous session
- Manual configuration bypassing DNS
- Reply packets (covered separately - source already known from outbound)

Options for handling cold-cache outbound packets:

1. **Drop with ICMPv6**: Return Destination Unreachable, require DNS lookup
2. **Reverse derive**: Attempt to derive npub from address (not possible -
   address is hash of npub, not reversible)
3. **Query protocol**: Initiate network query to discover identity for address
4. **Hold and query**: Buffer packet while performing discovery

The address derivation is one-way (SHA-256), so reverse derivation is impossible.
Without the npub, we cannot determine the node_id needed for routing.

**Decision**: Return ICMPv6 Destination Unreachable (Code 0: No route to
destination) for packets to unknown addresses. The identity cache MUST be
populated through some mechanism before traffic can be routed.

Known cache population mechanisms:

- DNS lookup (primary path, described above)
- Inbound traffic from authenticated peers (described in §X)
- Additional mechanisms TBD as design progresses

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

6. **Route determination**: Using node_id, determine next hop (covered in §X)

7. **Packet forwarding**: Encapsulate and send via appropriate transport

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

The original packet that triggered session establishment must be handled:

- ~~**Option A**: Drop packet, let application retry (simple, may cause timeout)~~
- **Option B**: Queue packet, send after session established
- **Option C**: Send packet optimistically during handshake (may fail)

**Decision**: Either queue or optimistic send. Dropping is not acceptable as it
causes unnecessary latency and potential application timeouts.

Queuing is simpler to reason about but requires bounded buffer management.
Optimistic send (0-RTT style) improves latency but requires careful replay
protection.

### 3.3 Session Independence from Transport

FIPS sessions exist above the routing layer. A session between two npubs
survives:

- Transport failover (UDP → Tor → back to UDP)
- Route changes (different intermediate hops)
- IP address changes on either end

The session is bound to **npub identities**, not network addresses or transport
paths. This is similar to QUIC's connection migration but at the FIPS layer.

### 3.4 Session Establishment Flow

TBD - handshake protocol for mutual authentication and key exchange.

Considerations:

- Must work over unreliable transports (UDP)
- Must handle packet loss/reordering during handshake
- Should minimize round trips for latency
- Must bind session to both npub identities cryptographically

### 3.5 Simultaneous Session Initiation (Crossing Hellos)

When both nodes attempt to establish a session simultaneously, we have
"crossing hellos" - two handshakes in flight at once.

Options:

1. **Deterministic tie-breaker**: Lower npub (lexicographically) is always
   the "initiator." When a node receives an initiation from a higher npub
   while it has an outbound initiation pending to that same npub, it defers
   to the lower npub's handshake.

2. **Both complete, then deduplicate**: Let both handshakes run to completion.
   Both sides end up with the same session key (if protocol is designed for
   this). Discard the "extra" session state using tie-breaker.

3. **Detect and merge**: When receiving an initiation while one is pending,
   recognize the crossing and merge into a single handshake with contributions
   from both sides.

**Considerations**:

- Option 1 is simplest but may add latency (one side backs off)
- Option 2 wastes bandwidth but is robust
- Option 3 is elegant but complex to implement correctly

The npub comparison provides a consistent, globally-agreed ordering without
any coordination.

**Decision**: Option 1 - deterministic tie-breaker using npub ordering.

When a node detects a crossing hello (receives initiation while its own
initiation to the same peer is pending):

- If local npub < remote npub: Continue as initiator, ignore incoming initiation
- If local npub > remote npub: Abort own initiation, switch to responder role

This ensures exactly one handshake completes with minimal wasted effort. The
latency cost is bounded to one round-trip in the crossing case, which should
be rare.

---

## 4. FIPS Mesh Routing

Below the session layer, all FIPS packets (session handshake messages, encrypted
payloads, control traffic) must be routed through the mesh to their destination.

### 4.1 Routing Layer Entry Points

The routing layer handles packets from two sources:

1. **Session establishment**: Handshake packets for new sessions
2. **Session data**: Encrypted payloads over established sessions

Both require determining how to reach the destination node_id.

### 4.2 Route Cache

The routing layer maintains a route cache mapping:

```text
node_id → (coordinates, next_hop_peer)
```

Where:

- `coordinates`: The destination's spanning tree coordinates
- `next_hop_peer`: A direct peer for greedy forwarding toward those coordinates

### 4.3 Routing Decision Flow

When sending a packet to a destination node_id:

```text
Packet to send (dest = node_id)
    │
    ├─► Route cache lookup
    │     ├─► HIT: Coordinates known → greedy route via next_hop
    │     └─► MISS: Proceed to discovery
    │
    └─► Route discovery (see §4.4)
```

If the route cache has coordinates for the destination, greedy routing proceeds
immediately - no discovery needed.

### 4.4 Route Discovery Protocol

When the route cache has no entry for the destination, discovery must determine
how to reach node_id X.

**Discovery flow**:

```text
Route discovery for node_id X
    │
    ├─► Check peer bloom filters
    │     ├─► Match in peer P's filter → query P for coordinates
    │     └─► No match in any filter → proceed to flooding
    │
    └─► Send LookupRequest (flooding with TTL)
          └─► Await LookupResponse with coordinates
```

**Bloom filter role**: Bloom filters don't provide routes directly - they
indicate which peers *might* know about a destination. A bloom match triggers
a targeted query to that peer rather than blind flooding.

**LookupRequest flooding**: When no bloom filter matches, flood the query
through the spanning tree with bounded TTL. Nodes that know the destination
(have it in their bloom filter or route cache) respond with coordinates.

### 4.5 Packet Handling During Discovery

Packets arriving while route discovery is in progress:

- **Queue**: Buffer packets while discovery completes (bounded queue)
- **Drop with error**: Return to session layer, which may retry

**Decision needed**: Packet handling during route discovery?

### 4.6 Route Cache Population

Routes are learned through:

- Successful route discovery (explicit)
- Receiving packets from a source (reverse path learning)
- Spanning tree announcements (implicit reachability for nearby nodes)
- Bloom filter updates combined with coordinate queries

### 4.7 Route Cache Lifetime

Route cache entries should:

- Expire after configurable timeout
- Refresh on successful packet delivery
- Invalidate when peer link goes down
- Invalidate on spanning tree topology changes affecting the path

---

## 5. Terminology Reconciliation

The existing design docs ([fips-routing.md](design/fips-routing.md)) and this
document use "session" differently. This section clarifies the terminology.

### 5.1 Two Distinct Concepts

| Term | Layer | Purpose | Endpoints |
|------|-------|---------|-----------|
| **Crypto Session** (§3) | End-to-end | Authentication + encryption | Source ↔ Destination |
| **Routing Session** (existing doc §4) | Hop-by-hop | Cache coordinates at routers | Along the path |

**Crypto Session** (what §3 of this document describes):

- Established between two npub identities
- Provides confidentiality (encryption) and authenticity (signatures)
- Survives route changes and transport failover
- Keyed by: `(local_npub, remote_npub)`

**Routing Session** (what fips-routing.md §Part 4 describes):

- Warms coordinate caches at intermediate routers
- Enables minimal 36-byte data packet headers
- Must be re-established when router caches expire
- Keyed by: `(src_addr, dest_addr)` at each router

### 5.2 Relationship Between Sessions

These are complementary, not conflicting:

```text
┌─────────────────────────────────────────────────────────────────────┐
│  Crypto Session (end-to-end)                                        │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Routing Session (hop-by-hop cache state)                     │  │
│  │                                                               │  │
│  │  Source ──► Router1 ──► Router2 ──► ... ──► Destination      │  │
│  │            (cache)      (cache)                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  Encrypted payload travels inside routing session                   │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3 Establishment Order

**Option A: Sequential (Crypto first, then Routing)**

```text
1. Discover destination coordinates (LookupRequest/Response)
2. Establish crypto session (handshake for keys)
3. Send SessionSetup to warm router caches
4. Send encrypted data packets (minimal headers)
```

Pros: Clean separation, crypto session exists before any data flows
Cons: Additional round-trips before first data

**Option B: Combined (Routing carries Crypto handshake)**

```text
1. Discover destination coordinates (LookupRequest/Response)
2. Send SessionSetup carrying crypto handshake initiation
3. Routers cache coordinates; destination receives handshake
4. Destination responds with SessionAck + crypto response
5. Send encrypted data packets
```

Pros: Fewer round-trips, single establishment phase
Cons: Couples two concerns, SessionSetup becomes more complex

**Option C: Crypto-only (No Routing Session)**

```text
1. Discover destination coordinates
2. Establish crypto session
3. Every data packet carries full coordinates
```

Pros: Simplest, no router cache state
Cons: Larger packets (~400 bytes vs 36 bytes), more bandwidth

### 5.4 Recommended Terminology

To avoid confusion going forward:

| Use This | Instead Of | Meaning |
|----------|------------|---------|
| **Crypto session** | "FIPS session" | End-to-end authenticated encryption |
| **Routing session** | "Session" (from routing doc) | Router cache state for a flow |
| **Route discovery** | — | Finding destination coordinates |
| **Session setup** | — | Warming router caches (routing session) |

### 5.5 Decision: Option B - Combined Establishment

**Decision**: Use combined establishment where routing session setup carries
the crypto handshake.

```text
Combined Establishment Flow:

1. Route discovery (if needed)
   └─► LookupRequest/Response → obtain destination coordinates

2. SessionSetup + Crypto Init
   └─► Source sends SessionSetup containing:
       - src/dest coordinates (for router caching)
       - Crypto handshake initiation (for destination)
   └─► Routers cache coordinates as packet transits
   └─► Destination receives crypto init, begins handshake

3. SessionAck + Crypto Response
   └─► Destination sends SessionAck containing:
       - Its coordinates (for reverse path caching)
       - Crypto handshake response
   └─► Routers cache reverse path
   └─► Source completes crypto handshake

4. Data flow
   └─► Encrypted payloads with minimal 36-byte headers
   └─► Both crypto session and routing session now active
```

**Benefits of combined approach**:

- Single round-trip establishes both sessions
- Router caches warm as handshake transits
- No additional latency vs crypto-only
- Bidirectional routing session from the start (SessionAck warms return path)

**Message structure implications**:

SessionSetup and SessionAck messages must carry both:

- Routing information (coordinates for router caching)
- Crypto payload (handshake messages, opaque to routers)

Routers process the routing portion and forward; only endpoints process
the crypto portion.

---

## 6. Crypto Session Handshake

The crypto session uses the Noise Protocol Framework with secp256k1, aligning
with Nostr's cryptographic primitives.

### 6.1 Design Decision: Noise with secp256k1

**Decision**: Use Noise Protocol Framework adapted for secp256k1.

Rationale:

- Well-analyzed framework with formal security proofs
- Used successfully in WireGuard, Lightning (BOLT 8), Signal
- Lightning Network already adapted Noise for secp256k1 (precedent)
- Reuses Nostr's existing key infrastructure (npub/nsec)
- Provides forward secrecy via ephemeral keys

### 6.2 Pattern Selection

Since both parties know each other's static public key (npub) before the
handshake begins (from DNS lookup / identity cache), the **Noise KK** pattern
is appropriate:

```text
Noise_KK_secp256k1_ChaChaPoly_SHA256

KK:
  -> e, es, ss
  <- e, ee, se
```

**Message 1 (Initiator → Responder):**

- `e`: Initiator's ephemeral public key
- `es`: DH(initiator_ephemeral, responder_static)
- `ss`: DH(initiator_static, responder_static)

**Message 2 (Responder → Initiator):**

- `e`: Responder's ephemeral public key
- `ee`: DH(initiator_ephemeral, responder_ephemeral)
- `se`: DH(responder_ephemeral, initiator_static)

After both messages, both parties derive identical symmetric keys for
encryption in each direction.

### 6.3 Why KK (not IK or XX)

| Pattern | Knowledge | Messages | FIPS Fit |
|---------|-----------|----------|----------|
| **KK** | Both know both static keys | 1 RT | Best - we have npubs |
| IK | Initiator knows responder | 1 RT | Works but asymmetric |
| XX | Neither knows | 2 RT | Unnecessary overhead |

KK provides mutual authentication in a single round-trip since FIPS always
knows the peer's npub before initiating (from DNS/identity cache).

### 6.4 Cryptographic Primitives

Following Lightning's BOLT 8 adaptation:

| Component | Choice | Notes |
|-----------|--------|-------|
| Curve | secp256k1 | Nostr-native |
| DH | ECDH on secp256k1 | Standard EC Diffie-Hellman |
| Cipher | ChaCha20-Poly1305 | AEAD, same as NIP-44 |
| Hash | SHA-256 | Nostr-native |
| Key derivation | HKDF-SHA256 | Standard Noise KDF |

### 6.5 Handshake Integration with SessionSetup

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

### 6.6 Session Keys

After handshake completion, Noise produces two symmetric keys:

- `send_key`: For encrypting outbound packets
- `recv_key`: For decrypting inbound packets

These are used with ChaCha20-Poly1305 for all subsequent data packets.

### 6.7 Nonce Management

ChaCha20-Poly1305 requires unique nonces. Options:

1. **Counter-based**: Each side maintains a 64-bit send counter, incremented
   per packet. Nonce = counter (no coordination needed since keys are
   directional).

2. **Random nonces**: 96-bit random nonce per packet, included in header.
   Simpler but adds 12 bytes per packet.

**Recommendation**: Counter-based nonces (like WireGuard/Lightning). The
counter also enables replay detection - reject packets with nonce ≤ last seen.

### 6.8 Forward Secrecy

The ephemeral keys (`e` in Noise notation) provide forward secrecy:

- Compromise of static keys (npub/nsec) doesn't reveal past session keys
- Each session has unique ephemeral keys
- Session keys derived from ephemeral-ephemeral DH (`ee`)

### 6.9 Reference: Lightning BOLT 8

Lightning's adaptation of Noise for secp256k1 (BOLT 8) provides a proven
reference implementation:

- Uses Noise XK pattern (different from our KK)
- Same secp256k1 + ChaCha20-Poly1305 + SHA-256 stack
- Handles the secp256k1 ECDH correctly
- Open source implementations available in multiple languages

FIPS can reference BOLT 8's cryptographic details while using the KK pattern
appropriate for our mutual-knowledge scenario.

### 6.10 Data Packet Authentication

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

## 7. Document Reconciliation

This section tracks items that need reconciliation with existing design docs
or earlier sections of this document.

### 7.1 Pending Updates

| Location | Status | Notes |
|----------|--------|-------|
| §3.1 | ✓ Done | Updated to AEAD authentication |
| fips-routing.md §Part 4 | Pending | Clarify "Session" → "Routing Session" per §5.4 |

### 7.2 Design Doc Alignment

The following decisions in this document affect existing design docs:

1. **fips-routing.md**: "Session" → "Routing Session" terminology
2. **Combined establishment** (§5.5): SessionSetup carries crypto handshake
3. **Noise KK**: Replaces any unspecified handshake references
