# FIPS Nostr-Mediated Discovery and NAT Traversal

Nostr-mediated discovery lets FIPS nodes find each other, and if
necessary, punch through UDP NAT, using public Nostr relays as the
signaling channel. A node publishes its reachable transport endpoints to
a small set of relays under its own Nostr identity (which is also its
FIPS identity), and peers resolve those endpoints at dial time by npub.
For peers behind UDP NAT, the same relay channel carries an encrypted
offer/answer exchange, and STUN supplies the reflexive address used for
a coordinated hole-punch.

Nostr discovery is unconditionally compiled into the `fips` binary on
every supported platform and ships in every stock packaging artifact
(`.deb`, AUR, systemd tarball, OpenWrt `.ipk`, macOS `.pkg`, Windows
`.zip`). It is runtime-opt-in: the YAML configuration defaults to
disabled (`node.discovery.nostr.enabled: false`), so the discovery
runtime stays dormant — and opens no relay connections — until an
operator flips the flag. Default relay and STUN-server lists ship in
the config; both are optional overrides. When disabled, nodes behave
exactly as before: only the static `peers[]` addresses are used.

## Role

The feature adds three capabilities on top of FIPS's static peer model:

- **Advertising.** A node publishes the transport endpoints it wants
  peers to use (direct UDP, direct TCP, a Tor onion, or the special
  `udp:nat` rendezvous token) as a signed Nostr event. The advert is
  anchored to the node's FIPS identity key — a peer that knows the npub
  knows the advert is authentic.
- **Lookup.** When dialing a configured peer marked `via_nostr`, or any
  peer in `policy: open` mode, the node fetches that peer's advert from
  the configured relays and appends the advertised endpoints to its
  dial list. Static addresses are always tried first.
- **UDP NAT hole-punch.** When both sides of a connection have UDP NAT
  endpoints, the advert carries enough information to run a STUN-based
  offer/answer exchange over encrypted ([NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md))
  Nostr events. Each side observes its reflexive address via STUN,
  exchanges candidate pairs through the relay, and both sides send UDP
  probes at a shared punch time. On the first successful probe, the
  punch socket is handed to FMP and becomes a normal UDP transport.

## When to use it

- **You run a public node** and want peers who know your npub to reach
  you without you distributing an address list out-of-band.
- **You want to reach a peer behind UDP NAT** without deploying a relay
  or running Tor on both sides. The peer advertises `udp:nat` and you
  dial by npub.
- **You want zero-touch peer discovery** within a known application
  namespace (`policy: open`), subject to an admission budget.
- **You want to advertise a Tor onion** so peers don't need to know the
  `.onion` address out-of-band.

Skip the feature when every peer is already reachable through a stable
static address (a LAN mesh, a pre-configured test bed, or a deployment
where operators distribute `peers[]` blocks directly). The feature adds
relay dependencies, STUN round-trips for NAT cases, and a small ambient
background of relay traffic; none of that is useful when you already
know where peers are.

## Scenarios and configuration

For end-to-end operator recipes — each of the five activation scenarios
(advertise a directly-reachable UDP node, advertise a Tor onion node,
look up a configured peer by npub without advertising, NAT hole-punch
between two configured peers, and open discovery within an `app`
namespace) — see
[../how-to/enable-nostr-discovery.md](../how-to/enable-nostr-discovery.md).
The full configuration knob tables, per-transport keys, and startup
validation rules live in
[../reference/configuration.md](../reference/configuration.md) under
`node.discovery.nostr.*`. The Kind 37195 advert event format is in
[../reference/nostr-events.md](../reference/nostr-events.md). The rest
of this document covers the design of the discovery runtime itself.

## Under the covers

The rest of this document describes how the feature works inside the
node. For the generic protocol shape (event tags, NIP usage, on-the-
wire offer/answer schema, failure-suppression machinery), see
[port-advertisement-and-nat-traversal.md](port-advertisement-and-nat-traversal.md).

### Overview

The discovery runtime is a background task group started during node
initialization when `nostr.enabled` is true. It maintains a single
`nostr-sdk` client connected to the union of `advert_relays` and
`dm_relays`, and runs four loops: advert publication, advert
subscription (for open discovery and cache warming), DM subscription
(for incoming offers and answers), and a periodic advert-cache prune.
Discovery has no CLI surface; all operations are driven by the
configuration and by connection attempts made by the rest of the node.

```text
                    +-----------------------+
                    |   Discovery runtime   |
                    +-----------------------+
                       |       |       |
        advert publish |       | DM sub (offers, answers)
                       |       |
                       v       v
              +-------------------------+
              |   Nostr relay pool      |  (advert_relays ∪ dm_relays)
              +-------------------------+
                       ^       ^
    advert fetch/cache |       | encrypted signaling
                       |       |
   +----------------+  |       |  +--------------------+
   | connect_peer   |--+       +->|  offer / answer    |
   |  (node side)   |             |  handler           |
   +----------------+             +--------------------+
           |                                |
           v                                v
      +---------+                    +--------------+
      |  STUN   |<-- same socket --->|  UDP punch   |
      +---------+                    +--------------+
                                            |
                                            v
                                   adopt_established_traversal()
                                            |
                                            v
                                      FMP IK handshake
                                      on adopted socket
```

### Phase 1 — Advertisement

Adverts are published as Nostr kind `37195` parameterized replaceable
events (FIPS-specific, in the application-defined replaceable range
`30000–39999`; the digits visually spell `FIPS` — 7=F, 1=I, 9=P, 5=S).
The `d` tag is hardcoded to the wire-format identifier
`fips-overlay-v1` (or `fips-overlay-v1-next` on the `next` branch),
so each node has a single, in-place-updatable advert under its
identity. The configurable `app` value populates a separate
`protocol` tag, which scopes adverts within a relay set without
splitting them across multiple `d`-tag streams. The event is signed
with the node's FIPS identity key; there is no separate Nostr key. A
NIP-40 `expiration` tag is set to now + `advert_ttl_secs`, and a
`version` tag carries the protocol version. The advert content is a
JSON document shaped as `OverlayAdvert` (see
[../reference/nostr-events.md](../reference/nostr-events.md) for the
schema).

Publication happens on startup, again whenever the set of advertised
endpoints changes (for example, when a Tor onion hostname first
becomes available), and on a refresh timer every `advert_refresh_secs`.
If the `advertise` flag is turned off, the previous advert event is
deleted using a NIP-9 kind 5 delete event. Advert publication is
fan-out: the same event is sent to every relay in `advert_relays` with
no explicit failover — relay redundancy is implicit.

For a UDP or TCP transport with `public: true`, the address advertised
follows a fixed precedence: an operator-supplied `external_addr` wins;
otherwise a non-wildcard bound `local_addr` is used directly;
otherwise — only for UDP — the runtime asks `stun_servers` for the
reflexive address of the bound socket and advertises that. TCP has no
STUN equivalent, so wildcard-bound TCP without `external_addr`
produces a loud WARN and the endpoint is omitted from the advert.

### Phase 2 — Lookup

When the node decides to dial a peer that is eligible for Nostr
resolution (a `via_nostr` peer, or any peer under `policy: open`), it
issues a Nostr REQ filtered by `author = peer_pubkey`, `kind = 37195`,
`#d = fips-overlay-v1`. The fetch is time-bounded (~2 s) and runs
against all configured `advert_relays` in parallel. The first valid
advert wins; adverts whose `protocol` tag does not match the local
`app` value are rejected at validation.

Results are kept in an in-memory cache keyed by author npub. Cache
entries carry the advert's expiration time; a periodic prune drops
expired entries, and an LRU-by-expiry eviction enforces
`advert_cache_max_entries`. A parallel long-lived subscription on the
advert relays populates the cache passively, so open-discovery
candidates do not require per-dial fetches.

On cache hit, advert endpoints are appended to the peer's static
address list with lower priority; the static list is tried first.

### Phase 3 — Offer/Answer signaling

For any endpoint shaped as `udp:nat`, dialing triggers an
offer/answer exchange before the first packet is sent. Signaling events
are Nostr kind `21059` (ephemeral, not stored by conforming relays),
gift-wrapped per [NIP-59](https://github.com/nostr-protocol/nips/blob/master/59.md)
and encrypted with [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md),
so only the intended recipient can decrypt the payload.

The initiator performs STUN first (see Phase 4), then builds a
`TraversalOffer` containing:

- A unique `sessionId` and a random `nonce` (used to correlate the
  answer).
- Its reflexive address (if STUN succeeded).
- Its list of local (private) addresses for same-LAN paths.
- The STUN server it used, for informational reporting only.
- An `expiresAt` equal to now + `signal_ttl_secs`.

The offer is sealed to the recipient's npub and published to the peer's
preferred signaling relays — the node first tries to resolve the peer's
NIP-17 DM relay list (kind 10050), and falls back to `dm_relays` if
the inbox-relays fetch fails. Each side also publishes its own inbox
relay list on startup so dialers can discover it.

On the receiving side, an inbound semaphore bounds concurrent offer
processing at `max_concurrent_incoming_offers`. When the semaphore is
full, the offer is dropped with a warn log; this is the primary guard
against offer-spam from a misbehaving or compromised relay. A
`sessionId` replay cache (bounded by `seen_sessions_max_entries`, with
entries valid for `replay_window_secs`) rejects duplicates.

The responder runs its own STUN query and replies with a
`TraversalAnswer` carrying its reflexive and local addresses plus a
`PunchHint { startAtMs, intervalMs, durationMs }` that tells both sides
when to begin probing and how aggressively. If the responder has no
usable addresses at all, it replies with `accepted: false` and a
`reason` string.

### Phase 4 — UDP hole-punch

Each side runs STUN (parsing XOR-MAPPED-ADDRESS from the response, all
other attributes ignored) on the *same* UDP socket it will later use
for punching and for the adopted FMP transport. This is critical: NAT
state is per-socket, so the punch has to reuse the socket that taught
the NAT about this binding.

Given its own reflexive + local addresses and the peer's, each side
builds a candidate-pair plan that tries, in priority order:

1. **Reflexive ↔ reflexive.** The classic STUN path. Tried first because
   it is the only candidate that's reliable across arbitrary network
   topologies — host candidates from one peer that happen to be
   reachable from the other (via a corporate VPN, a Tailscale subnet
   route, or overlapping private address space) will succeed at the
   socket layer in the punch but fail in the FMP handshake when the
   return path doesn't match.
2. **LAN ↔ LAN.** If both sides share a /24 prefix, same-subnet private
   addresses are likely reachable directly. Only fires when both peers
   shared local host candidates (which requires `share_local_candidates`
   to be enabled — off by default).
3. **Mixed.** Reflexive on one side, local on the other — catches
   hairpin and one-side-public scenarios.

At `startAtMs` both sides begin sending 24-byte probe packets on the
candidate pair(s) at `intervalMs` cadence for up to `durationMs`. A
probe carries a 4-byte magic (`NPTC`), a 4-byte sequence, and the
first 16 bytes of `SHA256(sessionId)`; both sides can compute the same
session hash independently from the public `sessionId`, so no shared
secret is needed on the punch path itself. On receiving a valid probe,
a side replies with an `NPTA` ack. The first valid probe or ack seen
from the far side records the working remote address and completes the
attempt.

On timeout (`attempt_timeout_secs` as overall bound,
`punch_duration_ms` as probe window), both sides issue NIP-9 deletes
for their offer and answer events and report failure up to the
discovery runtime's `BootstrapEvent::Failed` channel.

### Phase 5 — Adoption

On success, the discovery runtime emits `BootstrapEvent::Established`
carrying the session id, the punch socket, and the learned remote
address. `adopt_established_traversal()` in the node lifecycle takes
the socket, registers it with the UDP transport layer as a new
transport instance, and calls `initiate_connection()` with the peer's
FIPS identity as the expected remote. FMP's Noise XX handshake runs on
the same socket — there is no "promote link" step between punch and
handshake; the punch socket *is* the FMP socket.

From that moment on, the connection is a normal FMP link and is
subject to the usual liveness (MMP heartbeats), rekey, and removal
behavior. A link-dead event does not re-enter the discovery runtime
automatically; reconnection relies on `auto_reconnect` and the same
dial path that triggered the original punch.

### Auto-connect semantics

Discovery does not itself initiate connections. It only supplies
addresses. Dial attempts originate from the existing peer-connection
machinery:

- **Configured peers** (`peers[]` with `connect_policy: auto_connect`)
  are dialed on startup and on retry. When `via_nostr` is set, advert
  endpoints are appended to the dial list with lower priority than
  static entries.
- **Open discovery peers** are assembled from the advert cache, fenced
  by the peer ACL, and enqueued into a bounded retry queue sized by
  `open_discovery_max_pending`. There is no event-driven
  "connect on every advert" — a peer re-enters the queue only when its
  prior attempt has drained.
- **Manual dials** (`fipsctl connect`) can target any configured peer
  and use the same dial path, including Nostr resolution if configured.

### Rate limits and safeguards

| Mechanism | Default | What it prevents | Behavior at limit |
| --- | --- | --- | --- |
| Offer semaphore (`max_concurrent_incoming_offers`) | 16 | CPU and memory exhaustion from offer spam on DM relays. | Warn log, offer dropped. |
| Advert cache (`advert_cache_max_entries`) | 2048 | Memory growth from ambient advert traffic under `policy: open`. | LRU-by-expiry eviction. |
| Seen-sessions (`seen_sessions_max_entries`) | 2048 | Replay of stale `sessionId` values. | Oldest entry evicted. |
| Signal TTL (`signal_ttl_secs`) | 120 s | Indefinite in-flight offers on relays. | Expired offers rejected at validation. |
| Open discovery queue (`open_discovery_max_pending`) | 64 | Unbounded retry queue under ambient advert load. | New candidates skipped until the queue drains. |
| Punch window (`punch_duration_ms`) | 10 s | Endless probe traffic after one side has given up. | Attempt declared failed; sockets discarded. |
| Failure-streak threshold (`failure_streak_threshold`) | 5 | Repeated traversal attempts against a peer that keeps failing. | Peer enters extended cooldown. |
| Extended cooldown (`extended_cooldown_secs`) | 1800 s | Tight retry loops after a failure streak. | Per-peer suppression for the cooldown window. |
| WARN log throttle (`warn_log_interval_secs`) | 300 s | Log floods from a peer that fails on every attempt. | One WARN per peer per interval; the rest demote to debug. |
| Failure-state cap (`failure_state_max_entries`) | 4096 | Memory growth from per-peer failure tracking. | LRU eviction. |

The load-shedding mechanisms (`max_concurrent_incoming_offers` and the
failure-streak / extended-cooldown pair) are deliberately conservative
so that a misbehaving relay cannot flood the node with offers and a
chronically unreachable peer cannot keep the traversal pipeline
saturated. The remaining rows are capacity bounds.

Adverts also undergo a stale-advert sweep: cached entries whose
`expiresAt` has passed are evicted on the periodic prune tick. Inbound
signaling tolerates ±60 s of clock skew between sender and receiver,
and the runtime maintains an NTP-style skew estimate per remote so
that consistently-skewed relays don't trip the freshness check.

### Relay model

All configured relays (advert + DM) are opened on a single
`nostr-sdk::Client` at startup. Publication is fan-out: the same event
is sent to every relay in the target list, with no explicit retry or
relay selection. Redundancy is implicit — a downed relay simply means
its copy of the advert or signal is unavailable, while other relays
still serve the same data.

For signaling specifically, the node prefers the recipient's NIP-17
DM relays when available (the recipient publishes its DM relay list as
a kind 10050 event to its own DM relays on startup) and falls back to
the local `dm_relays` list otherwise. This keeps the common case
off the sender's DM relays when those are different from the
recipient's, at the cost of one extra NIP-17 fetch per offer.

There is no per-relay rate limiting or health check. The relay model
assumes that an operator chooses relays they trust to be best-effort
available and that outright misbehavior is handled at the offer
semaphore and replay-cache layers downstream.

## Security and threat model

- **Relay operators can observe metadata.** They see which npubs
  publish adverts, to whom offers are sent, and the timing of that
  traffic. The *contents* of offer and answer events are
  NIP-59/NIP-44 sealed — only the intended recipient decrypts them.
  Adverts are public by design.
- **STUN servers see the node's public IP and port.** Only the STUN
  servers listed in the node's own `stun_servers` are ever contacted
  for reflexive discovery. Peer-advertised STUN values are
  informational; a malicious peer cannot steer this node to a
  chosen STUN target. See the doc comment on
  `node.discovery.nostr.stun_servers`.
- **The FIPS identity key signs adverts.** Compromise of
  `fips.key` is compromise of the node's Nostr identity — an attacker
  can publish adverts on behalf of the node. The recovery path is
  the same as for any identity compromise: rotate the key and
  re-advertise. There is no separate Nostr keypair to rotate
  independently.
- **Tor advertising leaks timing via clearnet relays.** When a
  Tor-only node advertises its onion address, the advert itself is
  published on clearnet WebSocket relays. Operators who want full
  unlinkability between the advertising identity and the node's
  IP must route relay traffic through Tor as well — for example by
  running `fips` inside a network namespace with a Tor SOCKS
  proxy as its only egress, or by pointing `advert_relays` and
  `dm_relays` at onion relay endpoints.
- **Open discovery accepts anyone publishing on the same `app`.**
  Admission control is the peer ACL, not the discovery layer. Verify
  the ACL before enabling `policy: open`, and consider using a
  non-default `app` value to scope visibility.
- **Nothing about discovery bypasses FMP.** A successful punch yields
  a UDP socket with a claimed remote identity. That identity is not
  trusted until FMP's Noise XX handshake completes. A peer whose
  advert says "I am npub X at 1.2.3.4:5678" but whose FMP handshake
  presents a different static key is rejected at the mesh layer.

## See also

- [../how-to/enable-nostr-discovery.md](../how-to/enable-nostr-discovery.md)
  — operator activation recipes grouped under three capabilities
  (resolve, advertise, open) across five scenarios.
- [../tutorials/resolve-peers-via-nostr.md](../tutorials/resolve-peers-via-nostr.md),
  [../tutorials/advertise-your-node.md](../tutorials/advertise-your-node.md),
  and [../tutorials/open-discovery.md](../tutorials/open-discovery.md)
  — hand-held walkthroughs of the three capabilities, in
  pedagogical order.
- [../reference/configuration.md](../reference/configuration.md) — full
  configuration reference, including all surrounding keys elided from
  the scenarios above.
- [../reference/nostr-events.md](../reference/nostr-events.md) — Kind
  37195 (overlay advert), Kind 21059 (gift-wrapped traversal
  signaling), Kind 10050 (NIP-17 inbox relay list).
- [../reference/security.md](../reference/security.md) — consolidated
  security reference, including how the FIPS identity key signs both
  adverts and Noise handshakes.
- [fips-transport-layer.md](fips-transport-layer.md) — UDP, TCP, and
  Tor transport mechanics; the punch socket is adopted as a normal
  UDP transport after handoff.
- [fips-mesh-layer.md](fips-mesh-layer.md) — FMP Noise XX handshake
  that runs on the adopted socket.
- [port-advertisement-and-nat-traversal.md](port-advertisement-and-nat-traversal.md)
  — generic protocol reference (event tags, NIP usage, on-the-wire
  offer/answer schema, failure-suppression machinery), with the
  FIPS-specific values called out as worked examples.
