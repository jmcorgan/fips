# FIPS Wire Formats

This document is the comprehensive wire format reference for all three
protocol layers. It covers transport framing, link-layer message formats,
and session-layer message formats, with an encapsulation walkthrough showing
how application data is wrapped through each layer.

## Encoding Rules

- All multi-byte integers are **little-endian** (LE)
- NodeAddr is **16 bytes** — truncated SHA-256 hash of public key
- Signatures are **64 bytes** — secp256k1 Schnorr
- Variable-length arrays use a **2-byte u16 LE count prefix** followed by
  that many items
- Public keys are **33 bytes** — compressed secp256k1 (02/03 prefix + 32
  bytes)

## Transport Framing

### UDP

FIPS packets are carried directly in UDP datagrams. No additional framing is
needed — each UDP datagram contains exactly one FIPS link-layer packet.

### Stream Transports *(future direction)*

TCP, WebSocket, and Tor transports require length-prefix framing because
they provide a byte stream, not datagrams:

```text
┌────────────┬───────────────────────────────────┐
│ Length      │ FIPS Packet                       │
│ 2 bytes LE │ Variable                          │
└────────────┴───────────────────────────────────┘
```

## Link-Layer Formats

All link-layer packets begin with a **discriminator byte** that determines
the payload format.

### Discriminator Table

| Byte | Type | Description |
| ---- | ---- | ----------- |
| 0x00 | Encrypted frame | Post-handshake encrypted traffic |
| 0x01 | Noise IK msg1 | Handshake initiation |
| 0x02 | Noise IK msg2 | Handshake response |

### Encrypted Frame (0x00)

All post-handshake traffic between authenticated peers. Contains one
encrypted link-layer message.

```text
┌────────┬──────────────┬──────────┬───────────────────────────┐
│ 0x00   │ receiver_idx │ counter  │ ciphertext + AEAD tag     │
│ 1 byte │ 4 bytes LE   │ 8 bytes LE│ N + 16 bytes             │
└────────┴──────────────┴──────────┴───────────────────────────┘

Total overhead: 29 bytes (1 + 4 + 8 + 16)
Minimum frame: 30 bytes (1-byte plaintext)
```

| Field | Size | Description |
| ----- | ---- | ----------- |
| discriminator | 1 byte | 0x00 |
| receiver_idx | 4 bytes LE | Session index for O(1) lookup |
| counter | 8 bytes LE | Monotonic nonce, used as AEAD nonce and for replay detection |
| ciphertext | N bytes | ChaCha20 encrypted payload |
| tag | 16 bytes | Poly1305 authentication tag |

The **plaintext** inside the encrypted frame begins with a message type byte:

| Type | Message |
| ---- | ------- |
| 0x10 | TreeAnnounce |
| 0x20 | FilterAnnounce |
| 0x30 | LookupRequest |
| 0x31 | LookupResponse |
| 0x40 | SessionDatagram |
| 0x50 | Disconnect |

### Noise IK Message 1 (0x01)

Handshake initiation from connecting party.

```text
┌────────┬─────────────┬─────────────────────────────────────────┐
│ 0x01   │ sender_idx  │ Noise IK message 1                      │
│ 1 byte │ 4 bytes LE  │ 82 bytes                                │
└────────┴─────────────┴─────────────────────────────────────────┘

Total: 87 bytes
```

| Field | Size | Description |
| ----- | ---- | ----------- |
| discriminator | 1 byte | 0x01 |
| sender_idx | 4 bytes LE | Initiator's session index (becomes receiver's `receiver_idx`) |
| noise_msg1 | 82 bytes | Noise IK first message |

**Noise msg1 breakdown** (82 bytes):

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | ephemeral_pubkey | 33 bytes | Initiator's ephemeral key (compressed secp256k1) |
| 33 | encrypted_static | 33 bytes | Initiator's static key (encrypted with es key) |
| 66 | tag | 16 bytes | AEAD tag for encrypted_static |

Noise pattern: `→ e, es, s, ss`

### Noise IK Message 2 (0x02)

Handshake response from responder.

```text
┌────────┬─────────────┬──────────────┬──────────────────────────┐
│ 0x02   │ sender_idx  │ receiver_idx │ Noise IK message 2       │
│ 1 byte │ 4 bytes LE  │ 4 bytes LE   │ 33 bytes                 │
└────────┴─────────────┴──────────────┴──────────────────────────┘

Total: 42 bytes
```

| Field | Size | Description |
| ----- | ---- | ----------- |
| discriminator | 1 byte | 0x02 |
| sender_idx | 4 bytes LE | Responder's session index |
| receiver_idx | 4 bytes LE | Echo of initiator's sender_idx from msg1 |
| noise_msg2 | 33 bytes | Noise IK second message |

**Noise msg2 breakdown** (33 bytes):

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | ephemeral_pubkey | 33 bytes | Responder's ephemeral key (compressed secp256k1) |

Noise pattern: `← e, ee, se`

After msg2, both parties derive identical symmetric session keys.

### Index Semantics

Each party in a link session maintains two indices:

| Index | Chosen By | Used By | Purpose |
| ----- | --------- | ------- | ------- |
| our_index | Us | Them | They include this as `receiver_idx` in packets to us |
| their_index | Them | Us | We include this as `receiver_idx` in packets to them |

### Handshake Flow

```text
Initiator                                    Responder
─────────                                    ─────────
generates sender_idx
generates ephemeral keypair

         0x01 | sender_idx | noise_msg1
         ────────────────────────────────►

                                              validates msg1
                                              learns initiator's static key
                                              generates sender_idx
                                              generates ephemeral keypair

         0x02 | sender_idx | receiver_idx | noise_msg2
         ◄────────────────────────────────

validates msg2
derives session keys

═══════════════ HANDSHAKE COMPLETE ═══════════════

First encrypted frame:
         0x00 | receiver_idx | counter=0 | ciphertext+tag
         ────────────────────────────────►
```

## Link-Layer Message Types

These messages are carried as plaintext inside encrypted frames (0x00).

### TreeAnnounce (0x10)

Spanning tree state announcement, exchanged between direct peers only.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x10 |
| 1 | version | 1 byte | 0x01 (v1) |
| 2 | sequence | 8 bytes LE | Monotonic counter, increments on parent change |
| 10 | timestamp | 8 bytes LE | Unix seconds |
| 18 | parent | 16 bytes | NodeAddr of selected parent (self = root) |
| 34 | ancestry_count | 2 bytes LE | Number of AncestryEntry records |
| 36 | ancestry | 32 × n bytes | AncestryEntry array (self → root) |
| 36 + 32n | signature | 64 bytes | Schnorr signature over entire message |

**AncestryEntry** (32 bytes):

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | node_addr | 16 bytes | Node's routing identifier |
| 16 | sequence | 8 bytes LE | Node's sequence number |
| 24 | timestamp | 8 bytes LE | Node's Unix timestamp |

**Size**: `100 + (n × 32)` bytes, where n = `ancestry_count` (depth + 1,
includes self)

| Tree Depth | Payload | With Link Overhead |
| ---------- | ------- | ------------------ |
| 0 (root) | 132 bytes | 161 bytes |
| 3 | 228 bytes | 257 bytes |
| 5 | 292 bytes | 321 bytes |
| 10 | 452 bytes | 481 bytes |

### FilterAnnounce (0x20)

Bloom filter reachability update, exchanged between direct peers only.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x20 |
| 1 | sequence | 8 bytes LE | Monotonic counter for freshness |
| 9 | hash_count | 1 byte | Number of hash functions (5 in v1) |
| 10 | size_class | 1 byte | Filter size: `512 << size_class` bytes |
| 11 | filter_bits | variable | Bloom filter bit array |

**Size class table**:

| size_class | Bytes | Bits | Status |
| ---------- | ----- | ---- | ------ |
| 0 | 512 | 4,096 | Reserved |
| 1 | 1,024 | 8,192 | **v1 (MUST use)** |
| 2 | 2,048 | 16,384 | Reserved |
| 3 | 4,096 | 32,768 | Reserved |

**v1 payload**: 1,035 bytes (11 header + 1,024 filter).
With link overhead: 1,064 bytes.

### LookupRequest (0x30)

Coordinate discovery request, flooded through the mesh.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x30 |
| 1 | request_id | 8 bytes LE | Unique random identifier |
| 9 | target | 16 bytes | NodeAddr being sought |
| 25 | origin | 16 bytes | Requester's NodeAddr |
| 41 | ttl | 1 byte | Remaining hops (default 64) |
| 42 | origin_coords_cnt | 2 bytes LE | Number of coordinate entries |
| 44 | origin_coords | 16 × n bytes | Requester's ancestry (NodeAddr only) |
| 44 + 16n | visited_hash_cnt | 1 byte | Hash count for visited filter |
| 45 + 16n | visited_bits | 256 bytes | Compact bloom of visited nodes |

**Size**: `301 + (n × 16)` bytes, where n = origin depth + 1

| Origin Depth | Payload |
| ------------ | ------- |
| 3 | 349 bytes |
| 5 | 381 bytes |
| 10 | 461 bytes |

### LookupResponse (0x31)

Coordinate discovery response, greedy-routed back to requester.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x31 |
| 1 | request_id | 8 bytes LE | Echoes the request's ID |
| 9 | target | 16 bytes | NodeAddr that was found |
| 25 | target_coords_cnt | 2 bytes LE | Number of coordinate entries |
| 27 | target_coords | 16 × n bytes | Target's ancestry (NodeAddr only) |
| 27 + 16n | proof | 64 bytes | Schnorr signature over `(request_id \|\| target)` |

**Size**: `91 + (n × 16)` bytes

| Target Depth | Payload |
| ------------ | ------- |
| 3 | 139 bytes |
| 5 | 171 bytes |
| 10 | 251 bytes |

**Proof coverage**: Signs `(request_id || target)` only — coordinates are
excluded so the proof survives tree reconvergence during the lookup
round-trip.

### SessionDatagram (0x40)

Encapsulated session-layer payload for multi-hop forwarding.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x40 |
| 1 | src_addr | 16 bytes | Source NodeAddr |
| 17 | dest_addr | 16 bytes | Destination NodeAddr |
| 33 | hop_limit | 1 byte | Decremented each hop |
| 34 | payload | variable | Session-layer message |

**Fixed header**: 34 bytes (`SESSION_DATAGRAM_HEADER_SIZE`)

The payload is opaque to transit nodes — session-layer encrypted
independently of link encryption.

### Disconnect (0x50)

Orderly link teardown with reason code.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x50 |
| 1 | reason | 1 byte | Disconnect reason code |

**Reason codes**:

| Code | Name | Description |
| ---- | ---- | ----------- |
| 0x00 | Shutdown | Normal operator-requested stop |
| 0x01 | Restart | Restarting, may reconnect soon |
| 0x02 | ProtocolError | Protocol error encountered |
| 0x03 | TransportFailure | Transport failure |
| 0x04 | ResourceExhaustion | Memory or connection limit |
| 0x05 | SecurityViolation | Authentication or policy violation |
| 0x06 | ConfigurationChange | Peer removed from configuration |
| 0x07 | Timeout | Keepalive or stale detection timeout |
| 0xFF | Other | Unspecified reason |

## Session-Layer Message Types

These messages are carried as the payload of a SessionDatagram (0x40).

### SessionSetup (0x00)

Establishes a session and warms transit coordinate caches.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x00 |
| 1 | flags | 1 byte | Bit 0: REQUEST_ACK, Bit 1: BIDIRECTIONAL |
| 2 | src_coords_count | 2 bytes LE | Number of source coordinate entries |
| 4 | src_coords | 16 × n bytes | Source's ancestry (NodeAddr, self → root) |
| ... | dest_coords_count | 2 bytes LE | Number of dest coordinate entries |
| ... | dest_coords | 16 × m bytes | Destination's ancestry |
| ... | handshake_len | 2 bytes LE | Noise payload length |
| ... | handshake_payload | variable | Noise IK msg1 (82 bytes typical) |

**Example** (depth-3 source, depth-4 destination):

```text
SessionDatagram header: 34 bytes
SessionSetup payload: 1 + 1 + 2 + 48 + 2 + 64 + 2 + 82 = 202 bytes
Total: 236 bytes
```

### SessionAck (0x01)

Confirms session establishment, completes the Noise handshake.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x01 |
| 1 | flags | 1 byte | Reserved |
| 2 | src_coords_count | 2 bytes LE | Number of coordinate entries |
| 4 | src_coords | 16 × n bytes | Acknowledger's ancestry (for cache warming) |
| ... | handshake_len | 2 bytes LE | Noise payload length |
| ... | handshake_payload | variable | Noise IK msg2 (33 bytes typical) |

### DataPacket (0x10)

Encrypted application data with explicit replay protection counter.

**Minimal header** (COORDS_PRESENT = 0):

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x10 |
| 1 | flags | 1 byte | Bit 0: COORDS_PRESENT |
| 2 | counter | 8 bytes LE | Session encryption counter / replay nonce |
| 10 | payload_length | 2 bytes LE | Length of encrypted payload |
| 12 | payload | variable | Encrypted application data + 16-byte AEAD tag |

**Header size**: 12 bytes (`DATA_HEADER_SIZE`)

**With coordinates** (COORDS_PRESENT = 1):

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x10 |
| 1 | flags | 1 byte | 0x01 (COORDS_PRESENT) |
| 2 | counter | 8 bytes LE | Session encryption counter |
| 10 | payload_length | 2 bytes LE | Length of encrypted payload |
| 12 | src_coords_count | 2 bytes LE | Source coordinate entries |
| 14 | src_coords | 16 × n bytes | Source's ancestry |
| ... | dest_coords_count | 2 bytes LE | Dest coordinate entries |
| ... | dest_coords | 16 × m bytes | Destination's ancestry |
| ... | payload | variable | Encrypted application data |

### CoordsRequired (0x20)

Link-layer error signal — transit node lacks coordinates for destination.
Plaintext (not end-to-end encrypted), generated by transit nodes.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x20 |
| 1 | flags | 1 byte | Reserved |
| 2 | dest_addr | 16 bytes | NodeAddr we couldn't route to |
| 18 | reporter | 16 bytes | NodeAddr of reporting router |

**Payload**: 34 bytes. Wrapped in SessionDatagram: 68 bytes total.

### PathBroken (0x21)

Link-layer error signal — greedy routing reached a dead end. Plaintext,
generated by transit nodes.

| Offset | Field | Size | Description |
| ------ | ----- | ---- | ----------- |
| 0 | msg_type | 1 byte | 0x21 |
| 1 | flags | 1 byte | Reserved |
| 2 | dest_addr | 16 bytes | Unreachable NodeAddr |
| 18 | reporter | 16 bytes | NodeAddr of reporting router |
| 34 | last_coords_count | 2 bytes LE | Number of stale coordinate entries |
| 36 | last_known_coords | 16 × n bytes | Stale coordinates that failed |

## Encapsulation Walkthrough

A complete picture of how application data is wrapped through each layer.

### Application Data → Wire

Starting with an application sending a 1024-byte payload to a destination:

```text
Layer 4: Application data
    1024 bytes

Layer 3: Session encryption (FSP)
    DataPacket header (12 bytes) + encrypted payload (1024) + AEAD tag (16)
    = 1052 bytes

Layer 2: SessionDatagram envelope (FLP routing)
    msg_type (1) + src_addr (16) + dest_addr (16) + hop_limit (1) + payload (1052)
    = 1086 bytes

Layer 1: Link encryption (FLP per-hop)
    discriminator (1) + receiver_idx (4) + counter (8) + ciphertext (1086) + tag (16)
    = 1115 bytes

Layer 0: Transport
    UDP datagram containing 1115 bytes
```

### Overhead Budget

| Layer | Overhead | Component |
| ----- | -------- | --------- |
| Link encryption | 29 bytes | 1 discriminator + 4 index + 8 counter + 16 AEAD tag |
| SessionDatagram | 34 bytes | 1 type + 16 src + 16 dest + 1 hop_limit |
| DataPacket header | 12 bytes | 1 type + 1 flags + 8 counter + 2 length |
| Session AEAD tag | 16 bytes | Poly1305 tag on session-encrypted payload |
| **Minimal total** | **91 bytes** | |
| Coordinates (if present) | ~44 bytes | Varies with tree depth |
| **Worst case** | **135 bytes** | `FIPS_OVERHEAD` constant |

### At Each Transit Node

```text
1. Receive UDP datagram
2. Read discriminator (0x00) → encrypted frame
3. Look up (transport_id, receiver_idx) → session
4. Check replay window (counter)
5. Decrypt with link keys → plaintext link message
6. Read msg_type (0x40) → SessionDatagram
7. Read dest_addr → routing decision
8. Decrement hop_limit
9. Re-encrypt with next-hop link keys
10. Send via next-hop transport
```

Transit nodes see the SessionDatagram envelope (src_addr, dest_addr,
hop_limit) but cannot read the session-layer payload (encrypted with
endpoint session keys).

## Size Summary

### Handshake Messages

| Message | Size |
| ------- | ---- |
| Noise IK msg1 | 87 bytes |
| Noise IK msg2 | 42 bytes |

### Link-Layer Messages (inside encrypted frame)

| Message | Size | Notes |
| ------- | ---- | ----- |
| TreeAnnounce | 100 + 32n bytes | n = depth + 1 |
| FilterAnnounce | 1,035 bytes | v1 (1KB filter) |
| LookupRequest | 301 + 16n bytes | n = origin depth + 1 |
| LookupResponse | 91 + 16n bytes | n = target depth + 1 |
| Disconnect | 2 bytes | |

### Session-Layer Messages (inside SessionDatagram)

| Message | Typical Size | Notes |
| ------- | ------------ | ----- |
| SessionSetup | ~200 bytes | Depth-dependent |
| SessionAck | ~80 bytes | Depth-dependent |
| DataPacket (minimal) | 12 + payload bytes | Steady state |
| DataPacket (with coords) | 12 + ~130 + payload bytes | Warmup/recovery |
| CoordsRequired | 34 bytes | Fixed |
| PathBroken | 36 + 16n bytes | Includes stale coords |

### Complete Packet Sizes (link + session)

| Scenario | Wire Size | Notes |
| -------- | --------- | ----- |
| Encrypted frame minimum | 30 bytes | 1-byte plaintext |
| SessionDatagram + DataPacket (minimal) | 29 + 34 + 12 + payload + 16 | 91 + payload |
| SessionDatagram + DataPacket (with coords) | ~135 + payload | Worst case |
| SessionDatagram + SessionSetup | ~265 bytes | Depth-3, both dirs |
| SessionDatagram + CoordsRequired | 29 + 34 + 34 = 97 bytes | Including link overhead |

## References

- [fips-link-layer.md](fips-link-layer.md) — FLP behavioral specification
- [fips-session-layer.md](fips-session-layer.md) — FSP behavioral specification
- [fips-transport-layer.md](fips-transport-layer.md) — Transport framing
- [fips-mesh-operation.md](fips-mesh-operation.md) — How messages work together
- [fips-ipv6-adapter.md](fips-ipv6-adapter.md) — MTU enforcement
