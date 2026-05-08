# Nostr Event Reference

The Nostr-protocol surface FIPS uses for discovery and signaling. For
the design of the discovery runtime and the rationale behind these
event shapes, see
[../design/fips-nostr-discovery.md](../design/fips-nostr-discovery.md).
For operator activation recipes, see
[../how-to/enable-nostr-discovery.md](../how-to/enable-nostr-discovery.md).

FIPS uses three Nostr event kinds:

| Kind | Name | Encryption | Storage | Purpose |
| ---- | ---- | ---------- | ------- | ------- |
| 37195 | Overlay advert | None (signed only) | Replaceable | Publish reachable transport endpoints |
| 21059 | Traversal signaling | NIP-44 inside NIP-59 gift wrap | Ephemeral | Carry `TraversalOffer`/`TraversalAnswer` payloads |
| 10050 | NIP-17 inbox relay list | None (signed only) | Replaceable | Tell dialers where to publish offers |

All three are signed with the node's FIPS identity key (the same
secp256k1 keypair Nostr uses); there is no separate Nostr key.

## Kind 37195 — Overlay Advert

A parameterized replaceable event in the application-defined
replaceable range `30000–39999` (the digits visually spell `FIPS`:
7=F, 1=I, 9=P, 5=S). Each node has a single in-place-updatable advert
under its identity.

### Tags

- `d` — fixed to the literal `fips-overlay-v1` (the application
  identifier baked into the binary). Together with `pubkey`, this
  identifies the unique replaceable event slot.
- `protocol` — the configured `node.discovery.nostr.app` value
  (default `fips-overlay-v1`). Distinct from the `d` tag so the
  application string can evolve without breaking the replaceable
  event slot.
- `version` — protocol version string (currently `"1"`).
- `expiration` — NIP-40 expiration timestamp set to now +
  `node.discovery.nostr.advert_ttl_secs` (default 3600 seconds).
  Conforming relays stop serving the event after this time.

### Content

The event content is a JSON document shaped as `OverlayAdvert`:

```json
{
  "identifier": "fips-overlay-v1",
  "version": 1,
  "endpoints": [
    {"transport": "udp", "addr": "203.0.113.45:2121"},
    {"transport": "tor", "addr": "xxxxx.onion:8443"},
    {"transport": "udp", "addr": "nat"}
  ],
  "signalRelays": ["wss://relay.damus.io", "wss://nos.lol"],
  "stunServers": ["stun:stun.l.google.com:19302"]
}
```

Field semantics:

| Field | Type | Description |
| ----- | ---- | ----------- |
| `identifier` | string | Application namespace; must match the `d` tag. |
| `version` | integer | Advert schema version (currently 1). |
| `endpoints` | array | List of transport endpoints. Each is `{transport, addr}` where `transport` is `"udp"`, `"tcp"`, or `"tor"`, and `addr` is `"host:port"`, `".onion:port"`, or the literal `"nat"` (for UDP NAT-punch). |
| `signalRelays` | array? | Optional. Relays the publisher prefers for offer/answer signaling. Present only when at least one endpoint is `udp:nat`. |
| `stunServers` | array? | Optional. STUN servers the publisher uses for reflexive discovery. Present only when at least one endpoint is `udp:nat`. Informational — peers do not use these to choose their own STUN targets. |

### Signature scope

The Nostr event signature covers the standard Nostr event ID
(serialized `[0, pubkey, created_at, kind, tags, content]`), so the
content JSON, tags, kind, and timestamp are all bound to the signing
identity.

### Replacement and deletion

Because kind 37195 is replaceable, publishing a new advert replaces
the prior one in the same `(pubkey, d-tag)` slot. To withdraw an
advert without publishing a successor, the node publishes a NIP-9
kind 5 delete event referencing the prior advert.

## Kind 21059 — Traversal Signaling

An ephemeral event (kinds in the 20000–29999 range are not stored by
conforming relays). Used to deliver gift-wrapped, NIP-44-encrypted
`TraversalOffer` and `TraversalAnswer` payloads between dialer and
responder during a UDP NAT hole-punch.

### Encryption envelope

The wire shape is the standard NIP-59 gift wrap:

1. **Rumor** — the unsigned `TraversalOffer`/`TraversalAnswer`
   payload (JSON), authored by the actual sender's identity.
2. **Seal** — a kind 13 event whose content is the rumor
   NIP-44-encrypted to the recipient's pubkey, signed by the sender.
3. **Gift wrap** — a kind 21059 event whose content is the seal
   NIP-44-encrypted to the recipient under an ephemeral key, signed
   by that ephemeral key. The outer `pubkey` of the kind 21059 event
   is the ephemeral identity, not the sender's real identity.

Only the intended recipient can decrypt the wrap to recover the seal,
and only the recipient can decrypt the seal to recover the rumor.

### Wrapped payloads

The `TraversalOffer` carries:

- `type` — message-type tag.
- `sessionId` — unique identifier correlating offer and answer.
- `senderNpub` / `recipientNpub` — bech32-encoded pubkeys, repeated
  inside the encrypted payload (the outer wrap pubkey is ephemeral).
- `issuedAt` / `expiresAt` — Unix-ms timestamps; `expiresAt` is
  `issuedAt + signal_ttl_secs * 1000`.
- `nonce` — random per-offer value.
- `reflexiveAddress` — `{protocol, ip, port}` observed via STUN, or
  `null` if STUN failed or returned no usable address.
- `localAddresses` — array of `{protocol, ip, port}` private
  candidates, populated when `share_local_candidates` is enabled.
- `stunServer` — the STUN server actually used (informational).

The `TraversalAnswer` echoes `sessionId` and carries:

- `type`, `senderNpub`, `recipientNpub`, `issuedAt`, `expiresAt`,
  `nonce` — same shape as the offer.
- `inReplyTo` — the offer's event id.
- `accepted` — boolean; false when the responder has no usable
  addresses.
- `reflexiveAddress` and `localAddresses` — the responder's
  candidates, in the same shape as the offer.
- `stunServer` — informational.
- `punch` — a `PunchHint { startAtMs, intervalMs, durationMs }`
  telling both sides when to begin probing and how aggressively.
  Absent on rejected offers.
- `reason` — optional rejection string when `accepted` is false.
- `offerReceivedAt` — optional responder wall-clock (Unix ms) at
  the moment it received the offer; the initiator uses this to
  derive a clock-skew estimate.

### Relay selection

Dialer publishes offers to the recipient's NIP-17 inbox relays (kind
10050) when available; otherwise to the local
`node.discovery.nostr.dm_relays` list. The responder publishes the
answer back through the same relay channel.

## Kind 10050 — NIP-17 Inbox Relay List

A standard NIP-17 event used by FIPS to advertise which relays this
node prefers for receiving direct-message-style signaling — for FIPS,
the gift-wrapped traversal offers (kind 21059).

This is **NIP-17** (`kind 10050`, inbox relays for DM delivery), not
NIP-65 (`kind 10002`, general read/write relay list). The two serve
different purposes:

- Kind 10002 (NIP-65) — general read/write relays for ordinary event
  publication and subscription.
- Kind 10050 (NIP-17) — relays the recipient prefers for receiving
  DM-shaped (NIP-59 wrapped) events.

FIPS publishes its own kind 10050 on startup so dialers can discover
where to send traversal offers. When dialing a peer, FIPS first
fetches the peer's kind 10050 from the peer's `advert_relays`; on
fetch failure it falls back to the local `dm_relays` list.

### Tags

Standard NIP-17 form: each relay is encoded as an `r` tag whose
single value is the relay URL.

```text
["r", "wss://relay.damus.io"]
["r", "wss://nos.lol"]
```

### Content

Empty per NIP-17.

## See also

- [../design/fips-nostr-discovery.md](../design/fips-nostr-discovery.md)
  — discovery runtime design and the five activation scenarios
- [../how-to/enable-nostr-discovery.md](../how-to/enable-nostr-discovery.md)
  — operator recipes
- [../tutorials/resolve-peers-via-nostr.md](../tutorials/resolve-peers-via-nostr.md),
  [../tutorials/advertise-your-node.md](../tutorials/advertise-your-node.md),
  [../tutorials/open-discovery.md](../tutorials/open-discovery.md)
  — hand-held tutorial walkthroughs of the three capabilities
- [../design/port-advertisement-and-nat-traversal.md](../design/port-advertisement-and-nat-traversal.md)
  — generic protocol reference (event tags, NIP usage, on-the-wire
  offer/answer schema), with FIPS values as worked examples
- [security.md](security.md) — how the FIPS identity key signs both
  adverts and Noise handshakes
