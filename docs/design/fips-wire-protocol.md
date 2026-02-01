# FIPS Wire Protocol and Transport Layer Management

This document describes the FIPS wire protocol message flow at the transport level:
how peers establish and maintain cryptographic sessions with each other.

The transport layer provides the link-level communications path for a node to each
of its outbound and inbound peers, delivering an authenticated, encrypted, and
roaming-friendly peer-to-peer mesh connection over which both link-layer routing
control messages and end-to-end FIPS session layer data flow.

Topics include:

- Wire format with session indices for O(1) packet dispatch
- Handshake and session lifecycle
- Transport-layer roaming via index-based session lookup
- Security properties: rate limiting, replay protection, state machine strictness
- Adaptation to different transport types (UDP, TCP, Tor, Ethernet, radio)

---

## 1. Design Goals

### 1.1 Primary Goals

1. **Cryptographic authority**: A packet that properly decrypts is authentic,
   regardless of source address
2. **Roaming support**: Peers can change transport addresses (IP:port, etc.)
   without session interruption
3. **Efficient dispatch**: O(1) lookup for authenticated traffic, no trial
   decryption across multiple sessions
4. **DoS resistance**: Minimize resources consumed by unauthenticated traffic
5. **State machine correctness**: Strict validation prevents confusion attacks

### 1.2 WireGuard Influence

This design follows WireGuard's principle: source address is informational, not
authoritative. Only successful cryptographic verification establishes authenticity.
When a valid packet arrives from a different address than expected, the peer's
address is updated rather than the packet being rejected.

---

## 2. Wire Format

All FIPS link-layer packets use the following format:

```text
┌─────────────┬────────────────────────────────────────────────┐
│ Discriminator│ Type-Specific Payload                          │
│ 1 byte      │ Variable                                       │
└─────────────┴────────────────────────────────────────────────┘
```

The discriminator byte determines the payload format:

| Byte | Type | Payload Format |
|------|------|----------------|
| 0x00 | Encrypted frame | `[receiver_idx:4][counter:8][ciphertext+tag:N+16]` |
| 0x01 | Noise IK msg1 | `[sender_idx:4][noise_msg1:82]` |
| 0x02 | Noise IK msg2 | `[sender_idx:4][receiver_idx:4][noise_msg2:33]` |

### 2.1 Encrypted Frame (0x00)

Post-handshake encrypted packets:

```text
┌────────┬──────────────┬──────────┬───────────────────────────┐
│ 0x00   │ receiver_idx │ counter  │ ciphertext + AEAD tag     │
│ 1 byte │ 4 bytes LE   │ 8 bytes LE│ N + 16 bytes             │
└────────┴──────────────┴──────────┴───────────────────────────┘

Total overhead: 29 bytes (1 + 4 + 8 + 16)
```

- **receiver_idx**: Session index assigned by the receiver during handshake.
  Enables O(1) session lookup without relying on source address.
- **counter**: Monotonically increasing per-session, per-direction counter.
  Used as AEAD nonce and for replay detection.
- **ciphertext**: ChaCha20-Poly1305 encrypted payload.
- **tag**: 16-byte Poly1305 authentication tag.

The plaintext inside the encrypted frame begins with a message type byte,
followed by the message-specific payload (see fips-design.md §6 for message
types 0x10-0x4F).

### 2.2 Noise IK Message 1 (0x01)

Handshake initiation from the connecting party:

```text
┌────────┬─────────────┬─────────────────────────────────────────┐
│ 0x01   │ sender_idx  │ Noise IK message 1                      │
│ 1 byte │ 4 bytes LE  │ 82 bytes                                │
└────────┴─────────────┴─────────────────────────────────────────┘

Total: 87 bytes
```

- **sender_idx**: Index chosen by the initiator. This becomes the responder's
  `receiver_idx` when sending packets TO the initiator.
- **Noise msg1**: Standard Noise IK first message (ephemeral pubkey 33 bytes +
  encrypted static pubkey 33 + 16 bytes).

### 2.3 Noise IK Message 2 (0x02)

Handshake response from the responder:

```text
┌────────┬─────────────┬──────────────┬──────────────────────────┐
│ 0x02   │ sender_idx  │ receiver_idx │ Noise IK message 2       │
│ 1 byte │ 4 bytes LE  │ 4 bytes LE   │ 33 bytes                 │
└────────┴─────────────┴──────────────┴──────────────────────────┘

Total: 42 bytes
```

- **sender_idx**: Index chosen by the responder. This becomes the initiator's
  `receiver_idx` when sending packets TO the responder.
- **receiver_idx**: Echo of the initiator's `sender_idx` from msg1. Enables the
  initiator to match the response to their pending handshake.
- **Noise msg2**: Standard Noise IK second message (ephemeral pubkey 33 bytes).

### 2.4 Index Semantics

Each party in a session has two indices:

| Index | Chosen By | Used By | Purpose |
|-------|-----------|---------|---------|
| our_index | Us | Them | They include this in packets TO us |
| their_index | Them | Us | We include this in packets TO them |

After handshake completion:

- Initiator's `our_index` = initiator's `sender_idx` from msg1
- Responder's `our_index` = responder's `sender_idx` from msg2
- Each party's `their_index` = the other party's `sender_idx`

### 2.5 Index Properties

Indices MUST be:

1. **Random**: Unpredictable to prevent guessing attacks. Use cryptographically
   secure random generation.
2. **Unique per transport**: No two active sessions on the same transport may
   share the same `our_index`.
3. **Scoped to transport**: The tuple `(transport_id, receiver_idx)` identifies
   a session. The same index value may appear on different transports.

Indices SHOULD be:

4. **Rotated on rekey**: When a session rekeys, allocate new indices to prevent
   cross-session correlation.

---

## 3. Packet Dispatch

### 3.1 Overview

Packet dispatch follows a two-phase approach:

1. **Parse discriminator**: Determine packet type (O(1))
2. **Route by type**:
   - Encrypted (0x00): Index-based lookup, cryptographic verification
   - Handshake msg2 (0x02): Index-based lookup for pending outbound
   - Handshake msg1 (0x01): Rate-limited processing, create new state

### 3.2 Data Structures

```
Node:
    // === Authenticated sessions ===
    // Primary dispatch: our_index → NodeId
    peers_by_index: HashMap<(TransportId, u32), NodeId>

    // Peer data by identity
    peers: HashMap<NodeId, ActivePeer>

    // === Pending handshakes ===
    // Outbound: our sender_idx → connection state
    pending_outbound: HashMap<(TransportId, u32), PeerConnection>

    // Inbound: source address → connection state (before we know identity)
    pending_inbound_by_addr: HashMap<(TransportId, TransportAddr), PeerConnection>

    // === Resource management ===
    index_allocator: IndexAllocator
    msg1_rate_limiter: TokenBucket
```

### 3.3 Encrypted Frame Dispatch (0x00)

```
receive_encrypted(transport_id, source_addr, data):
    // Parse header (fail fast on malformed)
    if data.len() < 29:  // 1 + 4 + 8 + 16 minimum
        drop("too short")

    receiver_idx = u32_le(data[1..5])
    counter = u64_le(data[5..13])
    ciphertext = data[13..]

    // O(1) session lookup by index
    node_id = peers_by_index.get((transport_id, receiver_idx))
    if node_id is None:
        drop("unknown index")  // No crypto, minimal CPU cost

    peer = peers.get(node_id)

    // Replay check BEFORE decryption (cheap)
    if not peer.replay_window.check(counter):
        drop("replay or too old")

    // Decrypt (expensive, but only for valid-looking packets)
    plaintext = peer.session.decrypt(counter, ciphertext)
    if plaintext is Err:
        drop("decrypt failed")  // Corrupted or wrong key

    // === PACKET IS AUTHENTIC ===

    // Accept counter into replay window
    peer.replay_window.accept(counter)

    // Update address (ROAMING)
    peer.current_addr = source_addr

    // Update statistics
    peer.stats.record_recv(data.len())

    // Dispatch to message handler
    dispatch_link_message(node_id, plaintext)
```

**Key properties**:

- Unknown index rejected before any crypto (O(1) map lookup)
- Replay check before decryption (fast bitfield check)
- Source address updated on successful decrypt (roaming)
- Single decryption attempt per packet (no trial decryption)

### 3.4 Handshake Message 2 Dispatch (0x02)

```
receive_msg2(transport_id, source_addr, data):
    // Parse header
    if data.len() != 42:  // 1 + 4 + 4 + 33
        drop("wrong size")

    their_sender_idx = u32_le(data[1..5])
    our_receiver_idx = u32_le(data[5..9])
    noise_msg2 = data[9..42]

    // Lookup OUR pending handshake by our sender_idx
    key = (transport_id, our_receiver_idx)
    conn = pending_outbound.get(key)
    if conn is None:
        drop("no pending handshake")  // We didn't initiate this

    if conn.state != SentMsg1:
        drop("unexpected state")  // State machine violation

    // Process Noise msg2 (crypto cost paid here)
    result = conn.noise.read_msg2(noise_msg2)
    if result is Err:
        conn.state = Failed
        drop("handshake failed")

    // Handshake complete
    conn.their_index = their_sender_idx
    conn.source_addr = source_addr  // Update address

    // Promote to authenticated peer
    promote_connection(key)
```

**Key properties**:

- Lookup by OUR index (which we chose), not source address
- State machine enforced: msg2 only valid in SentMsg1 state
- Cannot be spoofed: requires responding to our ephemeral key

### 3.5 Handshake Message 1 Dispatch (0x01)

This is the primary attack surface for unauthenticated traffic.

```
receive_msg1(transport_id, source_addr, data):
    // === RATE LIMITING (before any processing) ===
    if not msg1_rate_limiter.try_acquire():
        drop("rate limited")

    // === CONNECTION LIMITS ===
    if pending_inbound_by_addr.len() >= MAX_PENDING_INBOUND:
        drop("too many pending")

    // Parse header
    if data.len() != 87:  // 1 + 4 + 82
        drop("wrong size")

    their_sender_idx = u32_le(data[1..5])
    noise_msg1 = data[5..87]

    // Check for existing connection from this address
    addr_key = (transport_id, source_addr)
    if pending_inbound_by_addr.contains(addr_key):
        // Could be retry or attack; existing state handles it
        drop("duplicate")

    // === CRYPTO COST PAID HERE ===
    result = NoiseHandshake::process_msg1(our_identity, noise_msg1)
    if result is Err:
        drop("invalid msg1")

    (peer_identity, handshake, msg2_payload) = result

    // === IDENTITY CHECKS ===

    // Check if this is a known peer reconnecting
    if peers.contains(peer_identity.node_id):
        // Existing peer from new address - handle reconnection
        handle_peer_reconnection(peer_identity, source_addr, ...)
        return

    // Optional: check allowlist/blocklist
    if not should_accept_peer(peer_identity):
        drop("not allowed")

    // === CREATE STATE ===
    our_index = index_allocator.allocate(transport_id)

    conn = PeerConnection {
        direction: Inbound,
        transport_id,
        our_index,
        their_index: their_sender_idx,
        state: ReceivedMsg1,
        noise: handshake,
        discovered_identity: peer_identity,
        source_addr,
        created_at: now(),
    }

    pending_inbound_by_addr.insert(addr_key, conn)

    // === SEND RESPONSE ===
    // [0x02][our_index:4][their_index:4][noise_msg2:33]
    msg2 = [0x02]
        ++ our_index.to_le_bytes()
        ++ their_sender_idx.to_le_bytes()
        ++ msg2_payload

    send_to_transport(transport_id, source_addr, msg2)
```

**Key properties**:

- Rate limiting BEFORE any parsing or crypto
- Connection limit caps memory usage
- Crypto cost (DH operations) only paid after rate limit passes
- Duplicate detection prevents state accumulation from retries
- Identity learned from msg1, checked against allowlist

### 3.6 Dispatch Summary

| Packet Type | Lookup Key | Crypto Before Dispatch? | Can Create State? |
|-------------|------------|------------------------|-------------------|
| Encrypted (0x00) | `(transport_id, receiver_idx)` | Yes (AEAD decrypt) | No |
| Msg2 (0x02) | `(transport_id, our_sender_idx)` | Yes (Noise) | No (existing state) |
| Msg1 (0x01) | `(transport_id, source_addr)` | Yes (Noise) | Yes (rate limited) |

---

## 4. Roaming

### 4.1 Definition

Roaming allows a peer to change their transport-layer address (IP:port for UDP,
connection handle for TCP, etc.) while maintaining their authenticated session.

### 4.2 Mechanism

When an encrypted packet (0x00) successfully decrypts:

1. The packet is authentic (AEAD tag verified with session keys)
2. Session keys are bound to peer identity via Noise handshake
3. Therefore, the sender is the authenticated peer, regardless of source address
4. Update `peer.current_addr` to the packet's source address

```
// After successful decryption
peer.current_addr = source_addr
```

Subsequent outbound packets to this peer use the updated address.

### 4.3 Transport Applicability

| Transport | Roaming Applicable? | Notes |
|-----------|--------------------|----|
| UDP | Yes | Source IP:port can change freely |
| TCP | Limited | Reconnection, not mid-session change |
| Tor | Limited | Circuit changes, onion address stable |
| Ethernet | Rare | MAC address typically stable |
| Radio | Yes | Node may move between base stations |

For connection-oriented transports (TCP, Tor), "roaming" manifests as
reconnection rather than mid-session address change. The index-based lookup
still applies: a new connection that produces a valid encrypted packet with
a known `receiver_idx` is accepted as the peer returning.

### 4.4 Security Consideration

Roaming enables an attacker who compromises session keys to redirect traffic.
However, session key compromise already allows full impersonation, so roaming
doesn't add attack surface. The session keys are the authority, not the address.

---

## 5. Replay Protection

### 5.1 Counter-Based Nonces

Each session maintains per-direction counters:

- **send_counter**: Incremented for each packet sent, used as AEAD nonce
- **recv_window**: Sliding window tracking received counters

### 5.2 Sliding Window

The receive window allows for UDP packet reordering while detecting replays:

```
ReplayWindow:
    top: u64           // Highest counter seen
    bitmap: [u64; 32]  // 2048-bit bitmap for window below top

check(counter) -> bool:
    if counter > top:
        return true  // New high, definitely not replay
    if counter + WINDOW_SIZE < top:
        return false  // Too old, outside window

    bit = (top - counter) as usize
    return not bitmap.test(bit)  // True if not seen

accept(counter):
    if counter > top:
        // Advance window
        shift = min(counter - top, WINDOW_SIZE)
        bitmap.shift_left(shift)
        bitmap.set(0)  // Mark new counter as seen
        top = counter
    else:
        bit = (top - counter) as usize
        bitmap.set(bit)
```

### 5.3 Window Size

A 2048-packet window (matching WireGuard) handles:

- Typical UDP reordering (tens of packets)
- Burst loss followed by retransmission
- Multi-path scenarios where packets take different routes

Packets older than the window are rejected. This bounds the memory for replay
state to O(1) per session regardless of session duration.

---

## 6. Rate Limiting

### 6.1 Purpose

Rate limiting protects against CPU exhaustion from msg1 processing. Each msg1
requires:

- Noise DH operations (~200μs on modern CPU)
- State allocation
- Response generation

An attacker flooding msg1 from spoofed addresses can exhaust CPU without the
rate limit.

### 6.2 Token Bucket Algorithm

```
TokenBucket:
    tokens: u32
    max_tokens: u32
    refill_rate: u32   // Tokens per second
    last_refill: Instant

try_acquire() -> bool:
    refill()
    if tokens > 0:
        tokens -= 1
        return true
    return false

refill():
    elapsed = now() - last_refill
    new_tokens = elapsed.as_secs() * refill_rate
    tokens = min(tokens + new_tokens, max_tokens)
    last_refill = now()
```

### 6.3 Recommended Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `max_tokens` | 100 | Burst capacity for legitimate connection storms |
| `refill_rate` | 10/sec | Sustained rate of new connections |
| `MAX_PENDING_INBOUND` | 1000 | Memory bound on pending handshakes |
| `HANDSHAKE_TIMEOUT` | 30 sec | Cleanup interval for stale handshakes |

These values should be configurable to accommodate different deployment
scenarios (high-traffic relays vs. leaf nodes).

### 6.4 Per-Source vs. Global

Rate limiting is **global** (not per-source) because:

- UDP source addresses are trivially spoofable
- Per-source limits don't protect against distributed attacks
- Global limit bounds total CPU regardless of attack distribution

The tradeoff is that a flooding attack can deny service to legitimate new
connections. Mitigations include:

- Higher limits for nodes expecting many connections
- Priority for configured/known peer addresses
- Optional proof-of-work extension (future)

---

## 7. State Machine Strictness

### 7.1 Valid State Transitions

```
PeerConnection states:
    Initial → SentMsg1       (outbound: we sent msg1)
    Initial → ReceivedMsg1   (inbound: we received msg1, sent msg2)
    SentMsg1 → Complete      (received valid msg2)
    ReceivedMsg1 → Complete  (received valid encrypted packet)
    * → Failed               (any error)

ActivePeer states:
    Connected → Stale        (no traffic for threshold)
    Stale → Connected        (valid traffic received)
    * → Disconnected         (explicit close or timeout)
```

### 7.2 Strict Validation

Each received packet is validated against expected state:

| Current State | Received | Valid? | Action |
|---------------|----------|--------|--------|
| No state | 0x00 (encrypted) | No | Drop (unknown index) |
| No state | 0x01 (msg1) | Yes | Create PeerConnection (rate limited) |
| No state | 0x02 (msg2) | No | Drop (no pending handshake) |
| SentMsg1 | 0x00 | No | Drop (not authenticated yet) |
| SentMsg1 | 0x01 | No | Drop (we're initiator, not responder) |
| SentMsg1 | 0x02 | Yes | Complete handshake |
| ReceivedMsg1 | 0x00 | Yes | First authenticated packet, promote |
| ReceivedMsg1 | 0x01 | No | Drop (duplicate initiation) |
| ReceivedMsg1 | 0x02 | No | Drop (we're responder, not initiator) |
| Authenticated | 0x00 | Yes | Normal encrypted traffic |
| Authenticated | 0x01 | See 7.3 | Peer reconnection |
| Authenticated | 0x02 | No | Drop (handshake already complete) |

### 7.3 Reconnection Handling

When msg1 arrives for an already-authenticated peer (identified by npub in the
decrypted static key), the new handshake is accepted alongside the existing
session. If the new handshake completes successfully within a timeout, it
replaces the old session; otherwise it is discarded.

This approach handles:

- Legitimate reconnection (network changed, process restarted)
- NAT rebinding (source port changed)
- Cross-connection resolution (both sides initiated simultaneously)

---

## 8. Index Management

### 8.1 Allocation

```
IndexAllocator:
    allocated: HashSet<(TransportId, u32)>
    rng: CryptoRng

allocate(transport_id) -> u32:
    loop:
        idx = rng.random_u32()
        key = (transport_id, idx)
        if not allocated.contains(key):
            allocated.insert(key)
            return idx

release(transport_id, idx):
    allocated.remove((transport_id, idx))
```

### 8.2 Rekey Index Rotation

When a session rekeys, new indices are allocated:

```
rekey(node_id):
    peer = peers.get(node_id)
    old_index = peer.our_index
    new_index = index_allocator.allocate(peer.transport_id)

    // Update index mapping
    peers_by_index.remove((peer.transport_id, old_index))
    peers_by_index.insert((peer.transport_id, new_index), node_id)

    // Release old index
    index_allocator.release(peer.transport_id, old_index)

    // Update peer
    peer.our_index = new_index
    peer.session.rekey()
    peer.replay_window.reset()

    // Exchange new indices via encrypted rekey message
    send_rekey_notification(peer)
```

Index rotation prevents correlation of sessions across rekey events by a
passive observer who can see the cleartext `receiver_idx`.

### 8.3 Index Exhaustion

With 32-bit indices and random allocation, birthday collision becomes likely
around 2^16 = 65536 active sessions per transport. For most deployments this
is far beyond expected peer counts. If index exhaustion becomes a concern:

- Use 64-bit indices (adds 4 bytes to all packets)
- Implement index recycling with reuse delay
- Partition index space by transport or peer class

---

## 9. Transport-Specific Considerations

### 9.1 UDP

UDP transport is expected to be the majority of deployments in the initial
stages of development.

**Address semantics**: `TransportAddr` is `SocketAddr` (IP:port string).

**Roaming**: Fully supported. Source address updated on valid decrypt.

**Connection model**: Connectionless. No connection state at transport layer.
"Links" are virtual tuples of `(transport_id, remote_addr)`.

**NAT considerations**: Source port may change due to NAT rebinding. Index-based
lookup handles this automatically. Hole punching for NAT traversal is a separate
concern (not covered here).

### 9.2 TCP

**Address semantics**: `TransportAddr` is the connection handle or remote
`SocketAddr` at connection time.

**Roaming**: Manifests as reconnection. When TCP connection breaks, peer may
reconnect from different address. The new connection's first packet should be
msg1 (new handshake) which will be recognized as an existing peer reconnecting.

**Connection model**: Connection-oriented. The transport maintains TCP
connection state. A "link" corresponds to a TCP connection.

**Framing**: TCP is stream-oriented. Requires length-prefix framing:

```
┌────────────┬───────────────────────────────────────────────┐
│ Length     │ FIPS Packet (as specified in §2)              │
│ 2 bytes BE │ Variable                                      │
└────────────┴───────────────────────────────────────────────┘
```

### 9.3 Tor

**Address semantics**: `TransportAddr` is onion address + port, or circuit ID.

**Roaming**: Limited. Onion address is stable but circuits may change. The
index-based lookup handles circuit changes transparently.

**Connection model**: Connection-oriented (Tor circuits). Similar to TCP for
framing and connection state.

**Privacy note**: Tor already provides transport encryption. Link-layer Noise
encryption is still applied for defense-in-depth and to maintain consistent
security model across transports.

### 9.4 Ethernet / WiFi

**Address semantics**: `TransportAddr` is MAC address.

**Roaming**: MAC addresses are typically stable. However, some devices randomize
MACs for privacy. Index-based lookup handles MAC changes.

**Connection model**: Connectionless (like UDP). Frames are independent.

**Broadcast**: Ethernet supports broadcast/multicast for discovery. This is
outside the scope of packet dispatch.

### 9.5 Radio (LoRa, etc.)

**Address semantics**: Transport-specific identifier (device ID, call sign, etc.).

**Roaming**: A node may be reachable through different base stations. Index-based
lookup handles this.

**MTU**: Radio often has small MTU (LoRa: ~250 bytes). Wire format overhead
(29 bytes for encrypted) is significant. Consider:

- Header compression for repeated fields
- Fragment/reassemble at transport layer
- Accept higher overhead as cost of security

---

## 10. Security Analysis

### 10.1 Attack Resistance Summary

| Attack | Mitigation | Section |
|--------|------------|---------|
| Connection exhaustion | Rate limit + connection limit | §6 |
| CPU exhaustion (msg1) | Rate limit before crypto | §6 |
| Replay | Counter + sliding window | §5 |
| State confusion | Strict state machine | §7 |
| Spoofed encrypted | Index lookup + AEAD | §3.3 |
| Spoofed msg2 | Index lookup + Noise binding | §3.4 |
| Address spoofing | Crypto authority, not address | §4 |
| Session correlation | Index rotation on rekey | §8.2 |

### 10.2 Unauthenticated Attack Surface

Only msg1 (0x01) can be sent by unauthenticated parties. All other packet types
require either:

- Known session index (encrypted frames)
- Response to our ephemeral key (msg2)

Msg1 processing is protected by:

- Global rate limit
- Connection count limit
- Handshake timeout cleanup
- Optional peer allowlist

### 10.3 Authenticated Peer Misbehavior

An authenticated peer can:

- Send malformed encrypted packets (fail AEAD, no effect)
- Send high-frequency traffic (rate limit at higher layer)
- Claim false tree coordinates (validated by signature)

The authentication layer establishes identity but doesn't grant trust. Higher
protocol layers apply additional policy.

### 10.4 Implementation Notes

1. **Constant-time comparison**: Use constant-time comparison for indices and
   counters to prevent timing side channels.

2. **Memory clearing**: Clear session keys and handshake state from memory
   after use to limit exposure window.

3. **Entropy**: Use cryptographically secure RNG for index allocation and
   ephemeral key generation.

4. **Error messages**: Avoid detailed error responses that could leak state
   information. Silent drop is preferred for invalid packets.

---

## 11. References

### Internal Documents

- [fips-design.md](fips-design.md) - Overall protocol design
- [fips-session-protocol.md](fips-session-protocol.md) - Session establishment flow
- [fips-architecture.md](fips-architecture.md) - Software architecture

### External References

- [WireGuard Protocol](https://www.wireguard.com/protocol/) - Index-based
  dispatch inspiration
- [Noise Protocol Framework](https://noiseprotocol.org/) - IK pattern
- [RFC 6479](https://tools.ietf.org/html/rfc6479) - IPsec anti-replay window

---

## Appendix A: Message Size Summary

| Packet Type | Size | Overhead |
|-------------|------|----------|
| Noise IK msg1 | 87 bytes | - |
| Noise IK msg2 | 42 bytes | - |
| Encrypted frame | N + 29 bytes | 29 bytes |
| Minimum encrypted | 30 bytes | (1 byte payload) |

For comparison:

- IPv6 header: 40 bytes
- WireGuard data: N + 32 bytes (type 4, idx 4, counter 8, tag 16)
- FIPS: slightly more compact due to 1-byte discriminator vs 4-byte type

---

## Appendix B: Example Packet Traces

### B.1 Outbound Connection

```
Node A (initiator) → Node B (responder)

A generates: sender_idx = 0x12345678
A sends msg1:
  [01] [78 56 34 12] [82 bytes noise_msg1]

B receives, processes msg1, generates: sender_idx = 0xABCDEF01
B sends msg2:
  [02] [01 EF CD AB] [78 56 34 12] [33 bytes noise_msg2]

A receives msg2, handshake complete.
A's our_index = 0x12345678, their_index = 0xABCDEF01
B's our_index = 0xABCDEF01, their_index = 0x12345678

A sends encrypted:
  [00] [01 EF CD AB] [00 00 00 00 00 00 00 00] [ciphertext+tag]
       ^ B's our_index (A's their_index)

B receives, looks up 0xABCDEF01 → finds session with A
B decrypts, updates A's address if changed
```

### B.2 Roaming Scenario

```
Initial: A connected from 10.0.0.1:4000, established session

A's network changes to 10.0.0.2:5000

A sends encrypted from new address:
  src=10.0.0.2:5000
  [00] [01 EF CD AB] [01 00 00 00 00 00 00 00] [ciphertext+tag]

B receives:
  1. Lookup index 0xABCDEF01 → finds A's session
  2. Decrypt succeeds
  3. Update A's address: 10.0.0.1:4000 → 10.0.0.2:5000

B's subsequent packets to A now go to 10.0.0.2:5000
```
