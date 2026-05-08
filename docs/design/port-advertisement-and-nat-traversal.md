# Port Advertisement and NAT Traversal via Nostr

## Abstract

This document describes two related-but-independent mechanisms that an
application protocol can build on top of Nostr relays:

1. **Port advertisement.** A node publishes a parameterized replaceable
   event describing the application protocol it speaks, the version, and
   the endpoint(s) at which it can be reached. Other nodes discover the
   advert by querying relays.
2. **NAT traversal.** When the advertised endpoint indicates that the
   responder is behind NAT, the two peers exchange ephemeral
   gift-wrapped offer/answer events through Nostr relays, run STUN
   against a public server to learn their reflexive addresses, and
   coordinate UDP hole punching so they can exchange application traffic
   over a direct UDP path.

The two mechanisms compose naturally — an advert that includes a
`<protocol>:nat` endpoint signals "reach me by running the traversal
protocol" — but they are independently useful. An advert with only
public-IP endpoints needs no traversal. A pair of peers that already
know each other's pubkeys but want to coordinate a traversal can do so
without ever publishing a public advert.

The protocol described here is generic. Any application protocol can
adopt it by picking its own kind number, `d`-tag scope, and endpoint
schema. [FIPS](https://github.com/jmcorgan/fips) (the Free
Internetworking Peering System) is used throughout the document as an
example implementation; FIPS-specific values appear in clearly marked
example blocks and do not affect the generic protocol shape.

No WebRTC, DTLS, or ICE stack is required. The protocol operates at
the raw UDP level, using Nostr solely for ephemeral signaling and STUN
solely for reflexive address discovery.

---

## Terminology

- **Application protocol.** The protocol that runs on top of the
  punched UDP channel after this document's procedures complete.
- **Initiator.** The peer that discovers the responder's advert and
  begins the traversal exchange.
- **Responder.** The peer that publishes a service advertisement and
  is willing to be dialled.
- **Reflexive address.** The public `IP:port` tuple that a STUN server
  observes for a UDP socket — i.e., the NAT's external mapping for
  that socket.
- **Punch socket.** The single UDP socket a peer uses for STUN, for
  the offer/answer exchange's address fields, for the punch packets
  themselves, and for the application traffic that follows. The same
  socket must be used across all phases of one traversal attempt.

### Socket lifecycle

The protocol assumes **per-peer, per-attempt punch sockets**:

- Each outbound traversal attempt allocates a fresh UDP socket bound
  to `0.0.0.0:0` (OS-assigned port).
- That socket is owned by exactly one remote peer and exactly one
  traversal session.
- STUN, the offer/answer reflexive-address fields, the punch packets,
  and the eventual adopted application transport all share that
  socket for the lifetime of the attempt.
- If the attempt fails, the socket is discarded. A retry allocates a
  new socket and obtains a fresh reflexive address.
- A long-lived application listener (for example, a fixed UDP port
  shared across peers) must **not** be reused as the punch socket —
  doing so couples NAT mappings and retry state across peers.

This rule is not optional: closing or rebinding the socket between
phases invalidates the NAT mapping that the rest of the protocol
depends on.

---

## Part 1: Service Advertisement

### Event shape

The advert is a NIP-01 parameterized replaceable event whose kind
falls in the application-defined replaceable range
`30000–39999`. The event carries:

- A `d` tag scoping the advert (so the same pubkey can publish
  multiple distinct adverts under different scopes).
- A `protocol` tag carrying the application protocol's name, used as
  a discovery filter for peers that don't already know the
  responder's pubkey.
- A `version` tag carrying the application protocol version.
- An optional `expiration` tag (NIP-40) so a relay garbage-collects
  the advert when the responder goes offline without explicitly
  deleting it.
- An optional `relays` tag listing relays where the responder
  subscribes for incoming signaling messages (used by Part 2).
- An optional `stun` tag listing STUN servers the responder
  recommends.
- A `content` field carrying the application-specific payload —
  typically the endpoint set, capability flags, and any encryption
  keys the application layer needs. The content may be plaintext or
  NIP-44-encrypted; encryption requires the consumer to already know
  the responder's pubkey.

The replaceable semantics let the responder update the advert in
place under the same `d` tag. A NIP-09 deletion event removes the
advert when the responder permanently retires.

```json
{
  "kind": <application-specific>,
  "pubkey": "<responder_pubkey>",
  "created_at": <unix_seconds>,
  "tags": [
    ["d", "<application-defined-scope>"],
    ["protocol", "<application_protocol_name>"],
    ["version", "<protocol_version>"],
    ["relays", "wss://relay1.example.com", "wss://relay2.example.com"],
    ["stun", "stun.l.google.com:19302"],
    ["expiration", "<unix_seconds + ttl>"]
  ],
  "content": "<application payload, optionally NIP-44 encrypted>",
  "sig": "<signature>"
}
```

### Endpoint schema

The `content` field is application-defined. Its structure typically
includes a list of endpoints describing how the responder can be
reached. Endpoint entries should distinguish:

- **Direct public endpoints** (transport + address + port) where any
  initiator can connect without traversal.
- **NAT-mapped endpoints** that signal "I can be reached by running
  the traversal protocol against this transport on my pubkey."
- **Anonymity-network endpoints** (e.g. Tor onion services) where
  the addressing scheme implies its own connection semantics.

#### FIPS example: kind 37195 advertisement

FIPS uses **kind `37195`** (the digits visually spell `FIPS` —
7=F, 1=I, 9=P, 5=S). The `d` tag is hardcoded to
`fips-overlay-v1`; the configurable `app` value populates the
separate `protocol` tag, scoping adverts within a relay set
without splitting them across multiple `d`-tag streams.

The advert content is a JSON document carrying a list of endpoint
entries, each shaped as `{transport, addr}`. The transport string
takes one of:

- `udp:host:port` — direct public UDP endpoint.
- `udp:nat` — NAT-mapped UDP endpoint; reach via Part 2 traversal.
- `tcp:host:port` — direct public TCP endpoint, for peers whose
  networks filter outbound UDP. Public-only; there is no
  `tcp:nat` analogue.
- `tor:<onion>:<port>` — Tor onion-service endpoint.

FIPS publishes the advert with `expiration` set to `now +
advert_ttl_secs` (default 1 hour) and refreshes it every
`advert_refresh_secs` (default 30 minutes).

### Public-IP discovery on advertisement

A responder behind a NAT or wildcard-bound to a non-routable address
needs to determine what external address to put in its advert. The
responder uses a fixed precedence:

1. An operator-supplied external address override (FIPS:
   `transports.{udp,tcp}.external_addr`) wins.
2. A non-wildcard `local_addr` is used directly.
3. For a wildcard-bound UDP listener with an explicit "publish this"
   flag (FIPS: `public: true`), the runtime queries STUN against
   the configured servers and publishes the reflexive address.
4. For a wildcard-bound TCP listener, no STUN equivalent exists.
   Implementations should refuse to silently advertise an unreachable
   endpoint; FIPS emits a loud WARN and omits the endpoint.

This precedence keeps adverts honest: an endpoint that appears in
the published content is one the responder believes is reachable.

### Discovery (consumer side)

A consumer queries one or more relays for an advert it can act on.
Two filter shapes are typical:

By author, when the responder's pubkey is already known:

```json
["REQ", "<sub_id>", {
  "kinds": [<advert_kind>],
  "authors": ["<responder_pubkey>"],
  "#d": ["<application-defined-scope>"]
}]
```

By application protocol, for "open discovery" of any peer running
the same application:

```json
["REQ", "<sub_id>", {
  "kinds": [<advert_kind>],
  "#protocol": ["<application_protocol_name>"]
}]
```

Adverts whose `protocol` tag does not match the consumer's expected
value, or whose `expiration` tag has elapsed, are rejected at
validation. Consumers cache adverts in memory keyed by author npub
and respect the embedded expiration.

#### FIPS example: discovery filters

The FIPS daemon issues both filter shapes: by-author for peers it
intends to dial directly, and by-`#protocol` when an operator has
opted into open discovery against the same application namespace.
Cached adverts persist until their `expiration` lapses; a periodic
prune drops expired entries.

---

## Part 2: NAT Traversal

The traversal protocol coordinates UDP hole punching between two
peers via gift-wrapped Nostr signaling. It is invoked when the
initiator decides to dial a NAT-mapped endpoint advertised by the
responder.

### Signaling event shape

Signaling messages are ephemeral kinds in the range `20000–29999`,
NIP-44-encrypted to the recipient, and NIP-59 gift-wrapped so the
outer event is signed by an ephemeral keypair rather than the
sender's long-term identity. The wrap carries a `p` tag pointing at
the recipient's pubkey and an NIP-40 `expiration` tag bounding how
long the relay should retain it.

#### FIPS example: signaling kind 21059

FIPS signaling uses **kind `21059`**. Wraps are addressed by `p`
tag and published to the responder's NIP-17 inbox relay list (kind
`10050`) when one is available, falling back to the local
`dm_relays` configuration otherwise. Each side publishes its own
inbox relay list on startup so dialers can discover it.

### Phase 1: Initiator STUN binding

Before constructing any signaling message, the initiator:

1. Allocates a fresh UDP punch socket bound to `0.0.0.0:0`.
2. Sends a STUN Binding Request (RFC 8489) to one of its locally
   configured STUN servers.
3. Parses the Binding Response, extracts the
   `XOR-MAPPED-ADDRESS` attribute, and records that as its
   reflexive address. Other STUN attributes are ignored.
4. Records local-candidate addresses for the same socket port:
   active private non-loopback interface addresses (RFC1918 IPv4,
   IPv6 ULA) and probed local egress addresses.

The punch socket must remain open across all subsequent phases.
Closing or rebinding it discards the NAT mapping.

### Phase 2: Initiator sends offer

The initiator constructs an offer payload containing its reflexive
address, its local-candidate addresses, an opaque session
identifier, freshness timestamps, and any application-specific
parameters. The payload is NIP-44-encrypted to the responder's
pubkey, wrapped with NIP-59, and published to the responder's
signaling relays. The initiator also subscribes by `p` tag on
those relays to receive the answer.

```json
{
  "type": "offer",
  "sessionId": "<random_hex_32>",
  "issuedAt": <unix_millis>,
  "expiresAt": <unix_millis>,
  "nonce": "<random_nonce>",
  "senderNpub": "<initiator_npub>",
  "recipientNpub": "<responder_npub>",
  "reflexiveAddress": {"protocol":"udp","ip":"<ip>","port":<port>},
  "localAddresses": [{"protocol":"udp","ip":"<ip>","port":<port>}],
  "stunServer": "<host>:<port>",
  "app_params": { ... }
}
```

- `sessionId` is a random identifier correlating offer and answer.
- `reflexiveAddress` is the address STUN observed in Phase 1.
- `localAddresses` enables a same-LAN fast path when both peers
  happen to share a private subnet.
- `stunServer` is informational, recording which server the
  initiator used.
- `issuedAt` / `expiresAt` bound the freshness window — the
  responder rejects stale offers, since a NAT mapping that has not
  been refreshed in tens of seconds may already be gone.

### Phase 3: Responder validates and answers

The responder maintains a standing `p`-tagged subscription on its
advertised signaling relays. On receiving an offer:

1. Decrypts the wrap and recovers the offer payload.
2. Validates freshness (rejects if outside the configured window;
   see *Skew tolerance* below).
3. Rejects replays — if the `sessionId` is in a recently-seen
   cache, drop the offer.
4. Allocates its own punch socket (`0.0.0.0:0`) and runs its own
   STUN query.
5. Constructs an answer payload that echoes `sessionId`, carries
   the responder's reflexive and local addresses, includes a
   `PunchHint { startAtMs, intervalMs, durationMs }` telling both
   sides when to begin probing and how aggressively, and is
   wrapped, encrypted, and published the same way as the offer.

```json
{
  "type": "answer",
  "sessionId": "<same as offer>",
  "issuedAt": <unix_millis>,
  "expiresAt": <unix_millis>,
  "nonce": "<random_nonce>",
  "senderNpub": "<responder_npub>",
  "recipientNpub": "<initiator_npub>",
  "inReplyTo": "<offer_event_id>",
  "accepted": true,
  "reflexiveAddress": {"protocol":"udp","ip":"<ip>","port":<port>},
  "localAddresses": [{"protocol":"udp","ip":"<ip>","port":<port>}],
  "stunServer": "<host>:<port>",
  "punch": {"startAtMs": <ms>, "intervalMs": <ms>, "durationMs": <ms>},
  "offerReceivedAt": <unix_millis>,
  "app_params": { ... }
}
```

If the responder has no usable addresses, it returns
`accepted: false` with an explanatory `reason` and no `punch`.

The optional `offerReceivedAt` field carries the responder's
wall-clock at the moment the offer arrived. The initiator can
combine its own `T1` (offer-publish time), `T2 = offerReceivedAt`,
`T3` (answer's `issuedAt`), and `T4` (answer-receive time) into the
NTP-style estimate `((T2 − T1) + (T3 − T4)) / 2`, giving a per-peer
clock-skew measurement that's useful for tuning freshness windows
and for telemetry.

**Immediately after publishing the answer**, the responder begins
Phase 4 punching without waiting for any acknowledgement that the
initiator received the answer. NAT mappings are decaying and time
is the binding constraint.

The responder must bind the inner JSON `senderNpub` /
`recipientNpub` fields to the actual Nostr pubkeys that delivered
the gift wrap, rather than treating those JSON fields as
independently trustworthy. The wrap pubkey is the authentication
ground-truth.

### Phase 4: Hole punching

Both peers now know each other's reflexive and local addresses.
Both begin sending UDP packets from their respective punch sockets:

1. Send punch packets every **`intervalMs`** (typically 200 ms)
   across each planned target path:
   - reflexive-to-reflexive
   - private-subnet local-address paths (when subnet-compatible)
   - mixed local/reflexive fallbacks
2. Each punch packet carries a fixed magic header so transit and
   peer code can distinguish it from stray UDP traffic:

   ```text
   Bytes 0–3:   <PROBE_MAGIC>          (application-defined u32)
   Bytes 4–7:   sequence number        (u32, big-endian, starting at 0)
   Bytes 8–23:  first 16 bytes of SHA-256(sessionId)
   ```

3. On receiving a valid punch packet (magic matches, session-id
   hash matches), the peer records the source address as the
   confirmed peer address and replies with an acknowledgement
   packet under a different magic value:

   ```text
   Bytes 0–3:   <ACK_MAGIC>            (application-defined u32)
   Bytes 4–7:   echoed sequence number
   Bytes 8–23:  first 16 bytes of SHA-256(sessionId)
   ```

4. On receiving an acknowledgement, the peer considers the path
   punched and transitions to Phase 5.

If both peers advertised compatible local-subnet candidates, the
local-address path will typically punch through faster than the
reflexive path. The first path to acknowledge wins.

### Phase 5: Application protocol takeover

Once the path has acknowledged in both directions:

- The application protocol takes over the punch socket.
- The signaling subscription can be closed.
- The application is responsible for sending keepalive traffic at
  least every 15 seconds to refresh the NAT mapping. A flow that
  goes idle longer risks losing its mapping and having to retraverse.

### Phase 6: Cleanup

After the attempt completes (success or failure):

1. Close the relay subscription used for signaling.
2. Optionally publish a NIP-09 deletion event referencing any
   signaling events the peer published. Because the wraps were
   ephemeral kinds with NIP-40 expiration tags, well-behaved relays
   will discard them automatically without explicit deletion.
3. Discard the per-attempt punch socket if the attempt failed; a
   retry must allocate a new socket and a fresh reflexive address.

If the responder is going offline permanently it should also
delete its kind-37195 (or equivalent) advert.

### Timeouts and retries

- If the initiator publishes an offer and receives no answer
  within a configured window (e.g. 10 s from offer publish), the
  attempt has failed. Causes: responder offline, advert stale,
  responder relay unreachable.
- If the answer arrives but no valid punch acknowledgement is
  observed within `durationMs` (typically 10 s), the attempt has
  failed. Causes: symmetric NAT on either side, firewall
  interference, stale reflexive addresses.

The initiator may retry with a fresh STUN query, a fresh punch
socket, and a new offer. Repeated failures against the same
responder should be suppressed by the application layer; see
*Application-specific failure handling* below.

---

## Security

### Authentication

Offer and answer payloads are NIP-44-encrypted to the recipient and
NIP-59 gift-wrapped, so only the intended recipient can decrypt.
Authentication of the sender comes from the inner-wrap signature
(the rumour signed by the sender's long-term identity inside the
NIP-59 seal), **not** from the outer wrap signature (which is the
ephemeral pubkey).

The inner JSON `senderNpub` / `recipientNpub` fields must be bound
to the actual signing pubkey of the inner rumour. Treating those
JSON fields as independently trustworthy is a vulnerability —
implementations must compare them against the unwrapped signature.

Once the UDP path is punched, the raw UDP channel has **no inherent
authentication or encryption**. The application layer is responsible
for establishing its own security on the punched channel — for
example, a Noise Protocol handshake keyed from the Nostr identity,
or an application-specific authenticated-encryption layer. FIPS
runs its FMP Noise XX handshake immediately after adoption; the
identity proven by the Noise handshake is the same Nostr pubkey
that signed the inner offer/answer rumour, so a man-in-the-middle on
the relay cannot impersonate the responder.

### Replay protection

The `sessionId` and `issuedAt` / `expiresAt` fields together
defeat replays at the signaling layer. The responder must keep a
bounded cache of recently-seen `sessionId` values and reject
duplicates within the freshness window.

### Skew tolerance

Strict freshness checks fail under modest clock skew between
peers. Implementations should accept offers and answers whose
timestamps are off by a small absolute amount (FIPS uses ±60 s),
and feed observed skew into a per-peer estimate for telemetry and
tuning. Outright rejection should be reserved for grossly stale or
future-dated messages.

### Metadata exposure

Even though signaling content is encrypted, the gift-wrap metadata
reveals that the initiator's ephemeral pubkey contacted the
responder's pubkey at a particular time, through a particular
relay. The advert itself is public and reveals the responder's
pubkey and the application protocol it speaks.

If metadata privacy is required, the advert content can be
encrypted (consumers must already know the responder's pubkey),
both peers can use ephemeral Nostr identities rather than their
long-term keys, and the operator can run a private relay.

### NAT mapping integrity

If too much wall-clock time elapses between STUN discovery and the
hole-punch attempt, the reflexive address goes stale. Both peers
should complete the entire signaling exchange within tens of
seconds of their respective STUN queries. Relay latency is the
primary risk factor. Implementations targeting flaky relays should
prefer relays known to deliver ephemeral events sub-second.

---

## Relay requirements

The protocol works best with relays that:

- Support ephemeral event kinds (`20000–29999`) and do not persist
  them.
- Honor NIP-40 `expiration` tags and garbage-collect expired
  events.
- Deliver events with low latency (sub-second WebSocket push).
- Support NIP-09 deletion requests.

Relays that do not support ephemeral kinds will store the
signaling events as regular events. The encrypted content remains
opaque, but persisted wraps are wasteful and expose metadata
unnecessarily. Operators deploying this protocol at scale should
prefer relays that handle ephemeral kinds correctly, or run their
own.

---

## Failure modes

| Failure | Symptom | Mitigation |
| --- | --- | --- |
| Symmetric NAT (one side) | Punch timeout | Retry with port-prediction heuristics; otherwise fall back to a relay or different transport |
| Symmetric NAT (both sides) | Punch timeout | Application-level relay required |
| Relay latency > 60 s | Stale reflexive address | Use low-latency relays; consider self-hosted relay |
| Relay does not support ephemeral kinds | Signaling events persist | Use NIP-40 expiration + NIP-09 deletion as fallback |
| Responder offline | No answer received | Initiator times out after configurable period |
| Stale advert (responder no longer up) | Offer reaches no listener | Application-level failure suppression (see below) |
| STUN server unreachable | No reflexive address | Fall back to alternate STUN server; fail if none reachable |
| Firewall blocks outbound UDP | STUN fails entirely | NAT-traversal does not apply; reachable peers are limited to those that publish a non-UDP transport (e.g. TCP) and accept inbound |

### Application-specific failure handling

Repeated traversal failures against the same responder are common
in practice — the responder may be offline, the advert may be
stale, or the responder may be on a network that doesn't admit
incoming UDP. A naive implementation that retries on every dial
attempt floods the relay layer and the operator's logs.

Implementations should layer per-peer suppression on top of the
basic retry. The shape of that suppression is application-specific.

#### FIPS example: failure suppression

FIPS layers the following suppression machinery on the basic retry
loop:

- **Per-npub WARN log rate-limit** (`warn_log_interval_secs`,
  default 5 minutes). Subsequent failures inside the window log
  at debug level instead.
- **Per-npub consecutive-failure counter and extended cooldown.**
  After `failure_streak_threshold` (default 5) consecutive
  failures, the per-peer retry deadline is pushed past
  `extended_cooldown_secs` (default 30 minutes). Open-discovery
  sweeps consult the cooldown so they don't immediately re-enqueue
  the same peer.
- **Stale-advert eviction on streak transition.** When a peer
  hits the failure-streak threshold, the daemon actively
  re-fetches its advert from the configured advert relays. If the
  advert has been removed or replaced, the cache entry is evicted
  and the streak resets; if the advert is unchanged, the cooldown
  applies.
- **Per-peer skew estimate.** The NTP-style skew computed from
  `offerReceivedAt` is recorded so consistently-skewed peers don't
  trip the freshness check on every attempt.
- **Bounded failure-state cache** (`failure_state_max_entries`,
  default 4096) with LRU eviction so the suppression machinery
  itself does not grow unbounded.

These knobs are documented in
[FIPS configuration reference](https://github.com/jmcorgan/fips/blob/master/docs/reference/configuration.md)
under `node.discovery.nostr`.

---

## References

- **RFC 8489** — Session Traversal Utilities for NAT (STUN)
- **RFC 8445** — Interactive Connectivity Establishment (ICE)
- **RFC 4787** — NAT Behavioral Requirements for Unicast UDP
- **NIP-01** — Basic Nostr protocol flow
- **NIP-09** — Event deletion request
- **NIP-17** — Inbox relay list (kind `10050`) for direct-message
  routing
- **NIP-40** — Expiration timestamp
- **NIP-44** — Versioned encryption
- **NIP-59** — Gift wrap
- **NIP-78** — Application-specific data
