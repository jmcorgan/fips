# FIPS Path MTU and Encapsulation Overhead

MTU is a cross-cutting concern in FIPS. No single layer owns it: the
transport reports per-link MTU, FMP propagates `path_mtu` along
forward and reverse paths, FSP echoes the observed path MTU end-to-end
back to the source, and the IPv6 adapter enforces the resulting
effective MTU at the TUN interface. This document is the canonical
home for the unified MTU model.

For operator-facing diagnostic recipes (interpreting `MtuExceeded`
counters, tuning IPv6 application MSS, troubleshooting cold-flow
oversize), see the relevant how-to under `docs/how-to/`.

## The MTU Problem in FIPS

A FIPS path can traverse heterogeneous link types — UDP/IP (1280
default, IPv6 minimum), Ethernet (interface MTU − 3, typically 1497),
BLE (negotiated ATT_MTU per link), Tor stream (1400 default), radio
(51–222) — within a single end-to-end session.
The minimum MTU along the path determines the largest datagram a
session can deliver. Several properties make this harder than in
classic IP networks:

- **No fragmentation.** FIPS does not fragment at transit nodes (see
  [No fragmentation policy](#no-fragmentation-policy)). A datagram
  that exceeds the next-hop link MTU is dropped, and the source is
  signaled.
- **Forward/reverse path asymmetry.** After tree reconvergence the
  return path may diverge from the forward path, so the bottleneck
  on each direction can differ.
- **First-flow race.** The very first SessionDatagram races
  destination discovery — the source has not yet learned the path MTU
  but must pick a payload size for the queued packet.
- **Variable per-link MTU.** Some transports (BLE, TCP via
  `TCP_MAXSEG`) report different MTUs for different links rather than
  a single transport-wide value.

The unified MTU model below combines proactive and reactive
mechanisms to converge on a working effective MTU within the first
few packets of a session, then maintain it across topology changes.

## Encapsulation Overhead

The byte budget for a FIPS-encapsulated packet:

| Layer | Overhead | Purpose |
| ----- | -------- | ------- |
| Link encryption | 37 bytes | 16-byte outer header + 5-byte inner header (timestamp + msg_type) + 16-byte AEAD tag |
| SessionDatagram body | 35 bytes | ttl + path_mtu + src_addr + dest_addr (msg_type counted in inner header) |
| FSP header | 12 bytes | 4-byte prefix + 8-byte counter (used as AEAD AAD) |
| FSP inner header | 6 bytes | 4-byte timestamp + 1-byte msg_type + 1-byte inner_flags (inside AEAD) |
| Session AEAD tag | 16 bytes | ChaCha20-Poly1305 tag on session-encrypted payload |
| **Protocol envelope** | **106 bytes** | `FIPS_OVERHEAD` constant — the base payload budget for any service |

`FIPS_OVERHEAD = 106` is the constant the rest of the system reasons
about. Coordinate piggybacking via the CP flag adds variable extra
overhead — `2 + entries × 16` bytes per coordinate, with both source
and destination coordinates carried — and the send path skips the CP
flag if adding coords would exceed the transport MTU.

Service-specific overheads layer on top of `FIPS_OVERHEAD`:

| Service | Overhead | Note |
| ------- | -------- | ---- |
| DataPacket port header | +4 bytes | Always present for port-multiplexed services |
| IPv6 compression | −33 bytes | 40-byte IPv6 header → 7-byte format + residual |
| **IPv6 effective overhead** | **77 bytes** | `FIPS_IPV6_OVERHEAD` constant |

See [fips-ipv6-adapter.md](fips-ipv6-adapter.md) for the IPv6
compression scheme that lets the adapter reach `FIPS_IPV6_OVERHEAD`.

## Per-Link MTU Reporting

Each transport implements two MTU methods on its trait:

- `mtu() -> u16` — Transport-wide default MTU.
- `link_mtu(addr: &TransportAddr) -> u16` — Per-link MTU for a
  specific remote address. The default implementation falls back to
  `mtu()`, so transports with uniform MTU (UDP, raw Ethernet) need
  not override it.

FMP uses `link_mtu()` when it needs to reason about a specific
outbound link — typically for `path_mtu` annotation in
SessionDatagram and LookupResponse. Per-transport defaults:

| Transport | Default MTU | Per-link MTU source |
| --------- | ----------- | ------------------- |
| UDP | 1280 (IPv6 minimum) | uniform (`mtu()` fallback) |
| Ethernet | interface MTU − 3 (typically 1497) | uniform |
| TCP | 1400 | derived from `TCP_MAXSEG` per connection |
| Tor | 1400 | uniform |
| BLE | 2048 default; negotiated ATT_MTU per link | per-link (overrides `mtu()`) |

For TCP, the per-connection `TCP_MAXSEG` query lets FMP discover the
actual MSS the kernel negotiated for each connection, rather than
assuming a single value across all TCP peers.

## Proactive PMTUD: SessionDatagram path_mtu

Every SessionDatagram and LookupResponse carries a 2-byte `path_mtu`
field. The source initializes it to its outbound link MTU; each
transit node applies `min(current, link_mtu(next_hop))` before
forwarding. The destination receives the forward-path minimum.

For SessionDatagram, the receiver of the forward-path minimum is the
session-layer destination, which then echoes the value back to the
source via PathMtuNotification (see
[End-to-end echo](#end-to-end-echo-pathmtunotification)).

For LookupResponse, the receiver is the original requester, and the
annotation is reverse-path-only: the LookupResponse path is the
return path of the lookup, so the annotated `path_mtu` reflects what
the requester can use to reach the discovered destination over the
discovered path.

Because the field is initialized by the source and mins as it travels,
it converges to the bottleneck without any additional probing. The
first SessionDatagram on a fresh session may carry an over-estimate
(the source has not yet been told a smaller min), which is what makes
the reactive MtuExceeded path necessary.

## Reactive PMTUD: MtuExceeded

When a transit node receives a SessionDatagram whose total wire size
exceeds the next-hop `link_mtu`, it cannot forward without
fragmentation. Instead:

1. The transit node generates a SessionDatagram addressed back to the
   source carrying an `MtuExceeded` payload (msg_type 0x22). The
   payload identifies the destination, the reporting router, and the
   bottleneck MTU.
2. The error is routed via `find_next_hop(src_addr)`. If the source
   is also unreachable, the error is dropped silently (no cascading
   errors).
3. The original oversized packet is dropped.

The source's FSP layer applies the reported bottleneck immediately —
unlike the increase case (see hysteresis below), decrease is always
take-the-lower-value because the original packet has already been
dropped. The source can then reduce payload sizes on subsequent
SessionDatagrams.

MtuExceeded is the reactive complement to the proactive `path_mtu`
field. The proactive field tracks the minimum along the forward path
under steady-state convergence; MtuExceeded handles the in-flight gap
when an oversized packet hits a new bottleneck (forward path shifted,
peer's outbound MTU dropped, BLE renegotiated) before the source has
adapted.

Error generation is rate-limited at 100ms per destination at the
transit node to prevent storms during topology changes.

## End-to-End Echo: PathMtuNotification

PathMtuNotification (msg_type 0x13, session-layer) provides
end-to-end path MTU feedback, adapting RFC 1191 Path MTU Discovery
for overlay networks — the transit-node `min()` propagation replaces
ICMP Packet Too Big.

Mechanism:

1. The source sets `path_mtu` in each SessionDatagram envelope to its
   outbound link MTU.
2. Each transit node applies `min(current, transport.link_mtu(addr))`
   before forwarding.
3. The destination receives the forward-path minimum and sends a
   PathMtuNotification (2-byte body: `u16 LE path_mtu`) back to the
   source.
4. The source applies the notification with hysteresis:
   - **Decrease**: immediate (take lower value).
   - **Increase**: requires 3 consecutive higher-value notifications
     spanning at least 2 × notification interval.
5. Notifications are sent on first measurement, on any decrease, and
   periodically at `max(10s, 5 × SRTT)`.

The hysteresis on increase prevents oscillation when the path MTU
fluctuates around a boundary; the immediate decrease prevents
delivering oversized packets after a path has narrowed.

PathMtuNotification is wrapped in a session-layer encrypted message
and travels back to the source via the session's normal forwarding
path. It is part of the session-layer MMP report stream's traffic
budget and (along with SenderReport and ReceiverReport) does not
reset the session idle timer.

## Per-Destination MTU Storage

Two storage locations track per-destination MTU, serving different
consumers:

- **Session-canonical** (`MmpSessionState.path_mtu`, type
  `PathMtuState`). Holds the running end-to-end path MTU for an
  established FSP session. Updated by both `PathMtuNotification`
  (proactive, end-to-end echo) and reactive `MtuExceeded` from
  transit routers. Read by the session layer when constructing
  outbound `SessionDatagram` envelopes.

- **TCP-clamp mirror** (`path_mtu_lookup`, a
  `HashMap<FipsAddress, u16>` on the Node). Read by the
  TUN-side TCP MSS clamp (`per_flow_max_mss` in
  `src/upper/tun.rs`) at first-SYN time so outbound TCP flows
  are clamped to the per-destination MTU rather than a generic
  ceiling. Written from four sites, all using tighter-only
  semantics — the clamp is never loosened:
  - Discovery's `LookupResponse` handler — reverse-path
    annotated value carried back by the discovery target.
  - `seed_path_mtu_for_link_peer` when a peer is promoted to
    an active link, seeding with the new link's `link_mtu`
    so traffic to that peer immediately uses the per-link
    value rather than a generic default.
  - The reactive `MtuExceeded` handler, mirroring the
    bottleneck reported by a transit router.
  - The proactive `PathMtuNotification` handler, mirroring
    the new effective end-to-end value so a fresh TCP flow
    benefits immediately from PMTU knowledge the session has
    already acquired.

All four writers apply the same tighter-only rule, so the mirror
converges to the smallest MTU any signal has reported for that
destination and a subsequent looser observation cannot widen it.

## TCP MSS Clamping

The IPv6 adapter intercepts TCP SYN and SYN-ACK packets at the TUN
interface and clamps the Maximum Segment Size (MSS) option to:

```text
clamped_mss = effective_ipv6_mtu - 40 (IPv6 header) - 20 (TCP header)
```

Clamping is applied in two places:

- **TUN reader** (outbound): clamps MSS on outbound SYN packets
- **TUN writer** (inbound): clamps MSS on inbound SYN-ACK packets

Together these ensure both directions of a TCP connection use
appropriately-sized segments from the start, avoiding the initial
oversized-packet loss that would occur if the adapter relied on ICMP
Packet Too Big alone.

Clamping is **conditional**: when `per_flow_max_mss` already has an
entry for the flow, that entry is used; otherwise the clamp falls
back to a ceiling derived from the most pessimistic effective IPv6
MTU the adapter knows about (1143 with the typical 1280 transport
floor). The fallback handles cold-flow first-SYN traffic — the very
first SYN of a flow may arrive before the MMP path-MTU echo and any
per-flow lookup has been populated, so the conservative ceiling
prevents the SYN-ACK chain from negotiating a too-large MSS that
would later drop.

The adapter integrates with the MTU subsystem rather than owning it.
The "why we clamp and what `max_mss` means" lives here in the MTU
design; the "how the clamp is implemented at the TUN" lives in the
[IPv6 adapter](fips-ipv6-adapter.md#tcp-mss-clamping) doc.

## ICMP Packet Too Big

When an outbound packet at the TUN exceeds the effective IPv6 MTU,
the adapter generates an ICMPv6 Packet Too Big message and delivers
it back to the application via the TUN. This triggers the kernel's
Path MTU Discovery mechanism for non-TCP traffic and for any TCP flow
where MSS clamping was insufficient.

ICMPv6 Packet Too Big generation is rate-limited per source address
(100ms interval) to prevent storms from applications sending many
oversized packets. The ICMP response is delivered locally back
through the TUN; no network traversal is needed, so delivery is
reliable.

## No Fragmentation Policy

FIPS does not perform fragmentation at transit nodes:

- **Why no transit fragmentation.** Session-layer encryption is
  end-to-end — the AEAD tag authenticates the entire plaintext.
  Fragmenting an encrypted SessionDatagram would require either
  exposing plaintext structure to transit nodes (unacceptable) or
  reassembling before decryption (opens an attack surface — a transit
  node could replay or withhold fragments to influence reassembly).
- **Why no source-side fragmentation.** The source doesn't need
  fragmentation because the proactive `path_mtu` field plus the
  reactive MtuExceeded signal converge on a working size within the
  first few packets. Applications that need oversized payloads run
  TCP over the IPv6 adapter, which has its own segmentation under
  MSS clamping.

Some transports may perform fragmentation and reassembly internally
(e.g., BLE L2CAP) and can advertise a larger virtual MTU than the
physical medium supports — this is transparent to FIPS.

## Operational Considerations

Diagnosing MTU-related symptoms (handshakes succeed but bulk
transfers stall, ssh hangs after `Welcome` banner, sporadic
`MtuExceeded` spikes during topology changes) requires inspecting
per-link MTU, per-session MTU, and the per-destination
`path_mtu_lookup` table. See
[../how-to/diagnose-mtu-issues.md](../how-to/diagnose-mtu-issues.md)
for the operator recipes. The relevant control-socket queries are
`fipsctl show sessions` (per-session MTU), `fipsctl show transports`
(per-link MTU), and `fipsctl show identity-cache` (with adapter MTU
context).

## See also

- [fips-transport-layer.md](fips-transport-layer.md) — the `mtu()` /
  `link_mtu()` trait surface and per-transport defaults
- [fips-mesh-layer.md](fips-mesh-layer.md) — SessionDatagram and the
  MtuExceeded error signal
- [fips-session-layer.md](fips-session-layer.md) — session-layer
  PathMtuNotification echo, applied with hysteresis
- [fips-ipv6-adapter.md](fips-ipv6-adapter.md) — TUN-side ICMPv6 PTB
  generation, MSS clamping integration, IPv6-specific overhead table
- [../reference/wire-formats.md](../reference/wire-formats.md) —
  SessionDatagram, LookupResponse, MtuExceeded, PathMtuNotification
  byte layouts
