# Metrics Measurement Protocol (MMP)

The Metrics Measurement Protocol provides per-link and per-session
quality metrics — SRTT, loss, jitter, goodput, ETX, and one-way delay
trend — using only counter and timestamp fields already present in
the FMP and FSP wire formats. No additional probing traffic is
required. The same algorithms and report message format are used at
both layers; only the routing scope and configuration namespace
differ.

This document is the canonical home for the MMP design. For the
link-layer instance's role inside FMP, see
[fips-mesh-layer.md](fips-mesh-layer.md). For the session-layer
instance's role inside FSP, see
[fips-session-layer.md](fips-session-layer.md). For the byte-level
SenderReport and ReceiverReport layouts, see
[../reference/wire-formats.md](../reference/wire-formats.md).

## Two Layers, One Protocol

MMP runs at two layers:

- **Link-layer MMP**: One instance per active FMP peer link. Reports
  are exchanged peer-to-peer between direct neighbors and measure the
  quality of that single hop.
- **Session-layer MMP**: One instance per established FSP session.
  Reports are encrypted end-to-end and forwarded through every transit
  link, measuring end-to-end quality independent of hop count.

The algorithms (SRTT estimation, jitter computation, loss inference,
ETX) are identical at both layers. The differences are configuration
namespace, report intervals, and routing scope. See
[Layer Differences](#layer-differences) below.

## Metrics Tracked

MMP computes the following metrics from the per-frame counter and
timestamp fields:

- **SRTT** — Smoothed round-trip time (Jacobson/RFC 6298, α=1/8).
  Derived from timestamp-echo in ReceiverReports with dwell-time
  compensation.
- **Loss rate** — Bidirectional loss inferred from counter gaps.
  Tracked as both instantaneous (per-interval) and long-term EWMA.
- **Jitter** — Interarrival jitter (RFC 3550 algorithm) in
  microseconds.
- **Goodput** — Bytes per second of payload data (excludes MMP
  reports).
- **OWD trend** — One-way delay trend (µs/s, signed). Indicates
  congestion buildup before loss occurs.
- **ETX** — Expected Transmission Count, computed from bidirectional
  delivery ratios. Used in cost-based parent selection via
  `link_cost = etx * (1.0 + srtt_ms / 100.0)`, and in bloom-filter
  candidate ranking inside `find_next_hop()` (the same `link_cost`
  is the primary key when choosing among bloom-filter peers, with
  tree distance as the tie-breaker).
- **Dual EWMA trends** — Short-term (α=1/4) and long-term (α=1/32)
  trend indicators for both RTT and loss, enabling change detection.

Session-layer MMP additionally tracks the observed forward-path MTU;
see [fips-mtu.md](fips-mtu.md) for the end-to-end path-MTU mechanism.

## Operating Modes

MMP supports three modes:

| Mode | Reports Exchanged | Metrics Available |
| ---- | ----------------- | ----------------- |
| **Full** (default) | SenderReport + ReceiverReport | All metrics including RTT, loss, jitter, goodput, OWD trend |
| **Lightweight** | ReceiverReport only | Loss (from counter gaps), jitter, OWD trend. No RTT. |
| **Minimal** | None | CE echo flags only. No computed metrics. |

The mode is configured per layer (`node.mmp.mode` and
`node.session_mmp.mode`).

## Report Scheduling

Reports are sent at RTT-adaptive intervals computed as
`clamp(2 × SRTT, low, high)`. A cold-start interval is used until SRTT
has converged.

| Layer | Adaptive bounds | Cold-start |
| ----- | --------------- | ---------- |
| Link | `[1s, 5s]` | 200 ms (first 5 samples) |
| Session | `[500ms, 10s]` | 1 s |

The session-layer bounds are higher because session reports are
encrypted and forwarded through every transit link, so bandwidth cost
is proportional to path length.

## RTT Measurement

SRTT is derived exclusively from timestamp-echo in ReceiverReports
with dwell-time compensation, applied via the Jacobson/Karels
algorithm (RFC 6298, α = 1/8). This is the sole SRTT source at both
layers.

## ECN Congestion Signaling

The CE (Congestion Experienced) flag (bit 1 in the FMP flags byte)
provides hop-by-hop congestion signaling through the mesh. Transit
nodes detect congestion on outgoing links and set CE on forwarded
packets; once set, the flag stays set for all subsequent hops to the
destination.

**Congestion detection** triggers on any of:

- Outgoing link MMP loss rate ≥ `node.ecn.loss_threshold` (default 5%)
- Outgoing link MMP ETX ≥ `node.ecn.etx_threshold` (default 3.0)
- Kernel receive buffer drops detected on any local transport (via
  `SO_RXQ_OVFL` on UDP)

**CE relay**: The forwarding path computes
`outgoing_ce = incoming_ce || local_congestion`. Once CE is set on a
packet, it remains set for the rest of the forward path.

**IPv6 ECN-CE marking**: When a CE-flagged DataPacket arrives at its
final destination, the IPv6 Traffic Class ECN bits are marked CE
(0b11) before TUN delivery — but only for ECN-capable packets (ECT(0)
or ECT(1)). Not-ECT packets are never marked per RFC 3168. The host
TCP stack then echoes ECE in ACKs, triggering sender cwnd reduction
through standard congestion control.

**Session-layer tracking**: The `ecn_ce_count` field in MMP
ReceiverReports tracks CE-flagged packets received per link, providing
end-to-end visibility into congestion propagation.

ECN signaling is a link-layer mechanism. Session-layer MMP only
observes the CE counter as part of the report stream; CE marking is
not generated end-to-end. Tuning parameters live under `node.ecn.*`
in [../reference/configuration.md](../reference/configuration.md).

## Send Failure Backoff (Session Layer Only)

When a session MMP report cannot be delivered (destination unreachable,
no route), the sender applies exponential backoff to the probe
interval — a standard distributed-systems pattern for transient
failure handling:

- Each consecutive failure doubles the interval: 2x, 4x, 8x, 16x, 32x
- Backoff caps at 32x the base interval (5 consecutive failures)
- A successful send resets to the normal SRTT-based interval
- Debug logging is suppressed after 3 consecutive failures; a summary
  is logged when the destination becomes reachable again

This prevents wasted CPU and log noise when a session's remote
endpoint has departed the network but the local session has not yet
timed out. Link-layer MMP has no equivalent — link-layer reports are
peer-to-peer over an authenticated link, so delivery failure is
indistinguishable from link death and the link-liveness mechanism
takes over.

## Layer Differences

| Aspect | Link layer | Session layer |
| ------ | ---------- | ------------- |
| Routing scope | Peer-to-peer (one hop) | End-to-end (forwarded through every hop) |
| Configuration namespace | `node.mmp.*` | `node.session_mmp.*` |
| Report bounds | `[1s, 5s]` | `[500ms, 10s]` |
| Cold-start interval | 200 ms (first 5 samples) | 1 s |
| Bandwidth cost | One link | Proportional to path length |
| Send-failure backoff | Not applicable | Yes |
| Path-MTU echo | Not applicable | PathMtuNotification (see [fips-mtu.md](fips-mtu.md)) |
| Idle-timeout interaction | None | Reports do **not** reset session idle timer |

## Idle Timeout Interaction (Session Layer Only)

MMP reports (SenderReport, ReceiverReport) and PathMtuNotification do
**not** reset the session idle timer. Only application data
(DataPacket, type 0x10) resets `last_activity`. This ensures sessions
with no application traffic tear down after
`node.session.idle_timeout_secs` (default 90s), while MMP continues
providing measurement data up to the teardown moment.

## Operator Logging

Both layers emit periodic metrics at info level. The interval is
`node.mmp.log_interval_secs` for link-layer (default 30s) and
`node.session_mmp.log_interval_secs` for session-layer (default 30s).

Link-layer:

```text
MMP link metrics peer=node-b rtt=2.3ms loss=0.2% jitter=0.1ms goodput=76.0MB/s tx_pkts=1234 rx_pkts=5678
```

Session-layer:

```text
MMP session metrics session=npub1tdwa...84le rtt=4.3ms loss=0.6% jitter=0.2ms goodput=71.3MB/s mtu=1472 tx_pkts=1234 rx_pkts=5678
```

Teardown logs include final SRTT, loss rate, jitter, ETX, goodput,
and cumulative tx/rx packet and byte counts.

## See also

- [fips-mesh-layer.md](fips-mesh-layer.md) — link-layer MMP integration
  inside FMP
- [fips-session-layer.md](fips-session-layer.md) — session-layer MMP
  integration inside FSP
- [fips-mtu.md](fips-mtu.md) — PathMtuNotification, the session-only
  end-to-end path-MTU echo
- [../reference/wire-formats.md](../reference/wire-formats.md) —
  SenderReport (0x01 / 0x11) and ReceiverReport (0x02 / 0x12) byte
  layouts
- [../reference/configuration.md](../reference/configuration.md) —
  full `node.mmp.*`, `node.session_mmp.*`, and `node.ecn.*` knob tables
