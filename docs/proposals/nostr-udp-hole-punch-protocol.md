# Nostr-Signaled UDP Hole Punching Protocol

> **Status**: Implemented behind the `nostr-discovery` cargo feature.
> This proposal is retained as a protocol reference and will be
> superseded by a dedicated design document.

## Abstract

This document describes a protocol for establishing direct UDP connectivity between two peers behind NAT, using Nostr relays as the signaling channel and public STUN servers for reflexive address discovery. The protocol assumes a **responder** that advertises a UDP service via a Nostr replaceable event, and an **initiator** that discovers the responder and negotiates a direct UDP connection.

No WebRTC, DTLS, or ICE stack is required. The protocol operates at the raw UDP level, using Nostr solely for ephemeral signaling and STUN solely for reflexive address discovery.

---

## Terminology

- **Initiator**: The peer that discovers the responder's service advertisement and begins the connection process.
- **Responder**: The peer running a UDP service, which has published a replaceable event advertising its availability.
- **Reflexive address**: The public `IP:port` tuple as observed by a STUN server (i.e., the NAT's external mapping).
- **Punch socket**: The single UDP socket a peer uses for both STUN queries and subsequent hole-punching traffic within one connection attempt. This socket **must not** change between phases of that attempt.

### Socket lifecycle

This protocol assumes **per-peer, per-attempt punch sockets**:

- Each outbound traversal attempt creates a fresh UDP socket bound to `0.0.0.0:0`.
- That socket is owned by exactly one remote peer and exactly one traversal session.
- STUN, offer/answer metadata, punch packets, and the eventual adopted UDP transport all use that same socket for the lifetime of the attempt.
- If the attempt fails, the socket is discarded. A retry allocates a new socket and obtains a fresh reflexive address.
- The long-lived application UDP listener (for example, a fixed port such as `2121`) is **not** reused as the punch socket.

This choice avoids cross-peer state coupling and keeps NAT mappings, retry state, and adopted traversal transports isolated per peer.

---

## Nostr Event Kinds

| Purpose | Kind | Persistence |
|---|---|---|
| Service advertisement | `37195` (parameterized replaceable) | Persistent, updated by responder |
| Signaling messages | `21059` (ephemeral gift-wrap) | Ephemeral, not stored by relays |

The service advertisement uses kind `37195`, an application-specific parameterized replaceable event in the NIP-01 replaceable range `30000–39999`. The digits visually spell `FIPS` (7=F, 1=I, 9=P, 5=S). The replaceable semantics let the responder update the advert in place under the same `d` tag. Signaling messages use ephemeral gift-wrapped events (kind `21059`, combining NIP-59 gift wrap with the ephemeral kind range `20000–29999`) to avoid relay storage.

---

## Phase 0: Service Advertisement (Responder)

The responder publishes a parameterized replaceable event advertising its UDP service. This event is long-lived and updated as the responder's parameters change.

```json
{
  "kind": 37195,
  "pubkey": "<responder_pubkey>",
  "created_at": <timestamp>,
  "tags": [
    ["d", "fips-overlay-v1"],
    ["protocol", "<application_protocol_name>"],
    ["version", "<protocol_version>"],
    ["relays", "wss://relay1.example.com", "wss://relay2.example.com"],
    ["stun", "stun.l.google.com:19302", "stun1.l.google.com:19302"],
    ["expiration", "<timestamp + TTL>"]
  ],
  "content": "<optional NIP-44 encrypted application-specific parameters>",
  "sig": "<signature>"
}
```

### Tag semantics

- **`d`**: Namespaced identifier. `fips-overlay-v1` scopes this to FIPS overlay endpoint adverts.
- **`protocol`**: Application protocol name for filtering (e.g., `myapp-file-sync`).
- **`version`**: Protocol version string for compatibility checking.
- **`relays`**: One or more relay URLs where the responder subscribes for incoming signaling messages. The initiator **must** send signaling events to at least one of these relays.
- **`stun`**: STUN server(s) both peers should use. Using the same STUN server improves the chance that NAT mappings are allocated from similar port ranges, though this is not strictly required.
- **`expiration`** (NIP-40): Optional. Allows the advertisement to expire if the responder goes offline without explicitly deleting it.
- **`content`**: Optional application-specific parameters (e.g., supported features, capabilities, public encryption keys for the application layer). Encrypted with NIP-44 if privacy is required, or plaintext if the parameters are non-sensitive.

The responder should update this event (same `d` tag, new `created_at`) whenever its parameters change, and publish a kind `5` deletion event (NIP-09) when it goes offline permanently.

Current in-tree defaults:

- `node.discovery.nostr.advert_ttl_secs = 3600` (1 hour)
- `node.discovery.nostr.advert_refresh_secs = 1800` (30 minutes)

---

## Phase 1: Discovery (Initiator)

The initiator queries one or more relays for the responder's service advertisement:

```json
["REQ", "<sub_id>", {
  "kinds": [37195],
  "authors": ["<responder_pubkey>"],
  "#d": ["fips-overlay-v1"]
}]
```

If the responder's pubkey is not known in advance, the initiator can discover peers by filtering on the `protocol` tag:

```json
["REQ", "<sub_id>", {
  "kinds": [37195],
  "#protocol": ["<application_protocol_name>"]
}]
```

Upon receiving the advertisement, the initiator extracts the relay list and any
advertised STUN metadata. In the current in-tree implementation, advertised
STUN entries are informational only; outbound STUN is driven by the initiator's
own configured allowlist.
The current in-tree STUN parser handles IPv4 and IPv6 mapped-address
responses. Offer/answer local-address candidates include active private
non-loopback interface addresses (RFC1918 IPv4 and IPv6 ULA) plus probed local
egress addresses.

---

## Phase 2: STUN Binding (Initiator)

Before sending any signaling message, the initiator binds a UDP socket and performs a STUN Binding Request:

1. Bind a fresh UDP socket to `0.0.0.0:0` (OS-assigned port). This becomes the **punch socket** for this peer and this traversal attempt.
2. Send a STUN Binding Request (RFC 8489) to one of the initiator's locally configured STUN servers.
3. Parse the Binding Response and extract the `XOR-MAPPED-ADDRESS` attribute — this is the initiator's reflexive address.
4. Record the reflexive address and local interface candidates for the same
   punch-socket port.

**Critical**: The punch socket must remain open and must be reused for all subsequent protocol phases of the same attempt. Closing or rebinding it invalidates the NAT mapping.

---

## Phase 3: Signaling — Offer (Initiator → Responder)

The initiator constructs a signaling message containing its reflexive address and sends it to the responder as an ephemeral NIP-44 encrypted, NIP-59 gift-wrapped event.

### Signaling payload (JSON, before encryption)

```json
{
  "app": "<app-namespace>",
  "eventKind": 21059,
  "type": "offer",
  "sessionId": "<random_hex_32>",
  "issuedAt": <unix_millis>,
  "expiresAt": <unix_millis>,
  "nonce": "<random_nonce>",
  "senderNpub": "<initiator_npub>",
  "recipientNpub": "<responder_npub>",
  "reflexiveAddress": {"protocol":"udp","ip":"<ip>","port":<port>},
  "localAddresses": [{"protocol":"udp","ip":"<ip1>","port":<port>}],
  "stunServer": "<host>:<port>",
  "app_params": { ... }
}
```

- **`sessionId`**: A random 32-character hex string identifying this connection attempt. Both peers use this to correlate signaling messages belonging to the same session.
- **`reflexiveAddress`**: The initiator's reflexive address as reported by STUN.
- **`localAddresses`**: Candidate local interface addresses for the same socket
  port. Useful if both peers happen to share a private subnet (the responder
  can attempt direct local paths in parallel).
- **`stunServer`**: Which STUN server the initiator used, so the responder can use the same one if desired.
- **`issuedAt`/`expiresAt`**: Freshness window. The responder should reject stale offers since the NAT mapping may have expired.
- **`app_params`**: Optional application-specific handshake parameters.

### Wrapping and delivery

1. Encrypt the JSON payload using NIP-44 to the responder's pubkey.
2. Wrap in a NIP-59 gift-wrap event using an ephemeral kind (`21059`).
3. Add an `expiration` tag (NIP-40) set to `now + 120s`.
4. Publish to the relay(s) listed in the responder's service advertisement.

```json
{
  "kind": 21059,
  "pubkey": "<ephemeral_sender_pubkey>",
  "created_at": <timestamp>,
  "tags": [
    ["p", "<responder_pubkey>"],
    ["expiration", "<timestamp + 120>"]
  ],
  "content": "<NIP-44 encrypted gift-wrap containing the offer>",
  "sig": "<signature>"
}
```

The initiator also opens a subscription on the same relay(s) to listen for the responder's answer:

```json
["REQ", "<sub_id>", {
  "kinds": [21059],
  "#p": ["<initiator_pubkey>"],
  "since": <now - 5>
}]
```

---

## Phase 4: Signaling — Answer (Responder → Initiator)

The responder maintains a standing subscription on its advertised relay(s):

```json
["REQ", "<sub_id>", {
  "kinds": [21059],
  "#p": ["<responder_pubkey>"],
  "since": <now - 5>
}]
```

Upon receiving and decrypting an offer, the responder:

1. Validates the timestamp (rejects if older than 60 seconds).
2. Validates the `session_id` is not a replay of a previously seen session.
3. Binds its own fresh **punch socket** to `0.0.0.0:0`.
4. Performs a STUN Binding Request using one of the responder's locally configured STUN servers.
5. Extracts its own reflexive address.
6. Constructs and sends an answer:

### Signaling payload (JSON, before encryption)

```json
{
  "app": "<app-namespace>",
  "eventKind": 21059,
  "type": "answer",
  "sessionId": "<same sessionId from offer>",
  "issuedAt": <unix_millis>,
  "expiresAt": <unix_millis>,
  "nonce": "<random_nonce>",
  "senderNpub": "<responder_npub>",
  "recipientNpub": "<initiator_npub>",
  "inReplyTo": "<offer_nonce>",
  "accepted": true,
  "reflexiveAddress": {"protocol":"udp","ip":"<ip>","port":<port>},
  "localAddresses": [{"protocol":"udp","ip":"<ip1>","port":<port>}],
  "stunServer": "<host>:<port>",
  "app_params": { ... }
}
```

This is encrypted and gift-wrapped identically to the offer, but addressed to the initiator's pubkey and published to the same relay(s).

Implementations should also bind the JSON sender/recipient identity fields to
the actual Nostr pubkeys that delivered the gift-wrapped events, rather than
treating those JSON fields as independently trustworthy.

**Immediately after publishing the answer**, the responder begins Phase 5 (punching) without waiting for confirmation that the initiator received it. Time is critical — the NAT mappings are decaying.

---

## Phase 5: Hole Punching

Both peers now know each other's reflexive address and local-address
candidates. Both begin sending UDP packets from their punch socket.

### Procedure

1. Both peers send punch packets every **200ms** across planned target paths:
   - reflexive-to-reflexive
   - private-subnet local-address paths (when subnet-compatible)
   - mixed local/reflexive fallbacks
2. Each punch packet contains a fixed magic header to distinguish it from stray traffic:

```
Bytes 0–3:   0x4E505443  ("NPTC" — Nostr P2P Tunnel Connect)
Bytes 4–7:   sequence number (u32, big-endian, starting at 0)
Bytes 8–23:  first 16 bytes of SHA-256(session_id)
```

3. Upon receiving a valid punch packet (magic header matches, session hash matches), the peer records the source address as the confirmed peer address and sends an **acknowledgment punch**:

```
Bytes 0–3:   0x4E505441  ("NPTA" — Nostr P2P Tunnel Ack)
Bytes 4–7:   echoed sequence number from the received punch
Bytes 8–23:  first 16 bytes of SHA-256(session_id)
```

4. Upon receiving an acknowledgment, the peer considers the hole punched and transitions to the application protocol.

### Timeout

If no valid punch packet is received within **10 seconds**, the attempt has failed. Possible causes include symmetric NAT on one or both sides, firewall interference, or stale reflexive addresses. The initiator may retry with a fresh STUN query, a fresh punch socket, and a new offer, or fall back to an application-level relay.

### LAN optimization

If both peers advertise compatible private-subnet candidates (e.g.,
`192.168.1.x`), they should simultaneously attempt punching via both reflexive
and local-address paths. The first path to complete wins.

---

## Phase 6: Application Protocol Handoff

Once both peers have exchanged acknowledgments, the connection is established. The punch socket for that attempt is now a live UDP channel between the two peers. From this point:

- The application protocol takes over the socket.
- The Nostr signaling channel is no longer needed for this session.
- Both peers should send application-level keepalive packets at least every **15 seconds** to prevent the NAT mapping from expiring.

---

## Phase 7: Cleanup

After the hole punch succeeds (or fails), both peers perform cleanup:

1. **Close the relay subscription** used for signaling.
2. **Publish a kind `5` deletion event** (NIP-09) referencing any signaling events they published, requesting relays delete them:

```json
{
  "kind": 5,
  "tags": [
    ["e", "<event_id_of_offer_or_answer>"]
  ],
  "content": "session concluded"
}
```

3. Because the signaling events used an ephemeral kind (`21059`) with an `expiration` tag, well-behaved relays will discard them automatically even without explicit deletion.

If the responder is going offline permanently, it should also delete its kind `37195` service advertisement.

---

## Security Considerations

### Authentication

The offer and answer are NIP-44 encrypted and NIP-59 gift-wrapped, ensuring that only the intended recipient can decrypt the signaling payload. The Nostr signatures authenticate both peers by their pubkeys.

However, once the UDP hole is punched, the raw UDP channel has **no inherent authentication or encryption**. The application layer is responsible for establishing its own security (e.g., Noise Protocol handshake, DTLS, or application-level encryption keyed from the Nostr identity).

### Replay protection

The `session_id` and `timestamp` fields protect against replay attacks on the signaling layer. The responder must track recently seen `session_id` values and reject duplicates within a window.

### Metadata exposure

Even though signaling content is encrypted, the gift-wrap metadata reveals that the initiator's ephemeral pubkey contacted the responder's pubkey at a particular time, through a particular relay. The service advertisement (kind `37195`) is public and reveals the responder's pubkey and that it is running a particular service.

If metadata privacy is required, the `content` of the service advertisement can be encrypted (requiring the initiator to already know the responder's pubkey), and both peers can use ephemeral Nostr identities rather than their long-term keys.

### NAT mapping integrity

If the time between STUN discovery and hole-punch initiation exceeds the NAT's mapping timeout, the reflexive address becomes stale. Both peers should complete the entire signaling exchange within **60 seconds** of their respective STUN queries. Relay latency is the primary risk factor here.

---

## Relay Requirements

This protocol works best with relays that:

- Support ephemeral event kinds (`20000–29999`) and do not persist them.
- Honor NIP-40 expiration tags and garbage-collect expired events.
- Deliver events with low latency (sub-second WebSocket push).
- Support NIP-09 deletion requests.

Relays that do not support ephemeral kinds will store the signaling events as regular events. While the encrypted content remains opaque, this is wasteful and exposes metadata unnecessarily. Operators deploying this protocol at scale should run or select relays known to handle ephemeral events correctly.

---

## Failure Modes

| Failure | Symptom | Mitigation |
|---|---|---|
| Symmetric NAT (one side) | Punch timeout | Retry with port prediction heuristics, or fall back to relay/TURN |
| Symmetric NAT (both sides) | Punch timeout | Application-level relay required |
| Relay latency > 60s | Stale reflexive address | Use low-latency relays; consider self-hosted relay |
| Relay does not support ephemeral kinds | Signaling events persist | Use NIP-40 expiration + NIP-09 deletion as fallback |
| Responder offline | No answer received | Initiator times out after configurable period (e.g., 30s) |
| STUN server unreachable | No reflexive address | Fall back to alternate STUN server; fail if none reachable |
| Firewall blocks outbound UDP | STUN fails entirely | Protocol cannot proceed; application must use TCP/WebSocket fallback |

---

## References

- **RFC 8489** — Session Traversal Utilities for NAT (STUN)
- **RFC 8445** — Interactive Connectivity Establishment (ICE)
- **RFC 4787** — NAT Behavioral Requirements for Unicast UDP
- **NIP-01** — Basic Nostr protocol flow
- **NIP-09** — Event deletion request
- **NIP-40** — Expiration timestamp
- **NIP-44** — Versioned encryption
- **NIP-59** — Gift wrap
- **NIP-78** — Application-specific data
