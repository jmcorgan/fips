# Diagnose MTU Issues

MTU symptoms in FIPS look like ordinary network failures: handshakes
succeed but bulk transfers hang, ssh connects but stalls after the
banner, an HTTP request times out on the first response. This guide
walks through the diagnostic surfaces that FIPS exposes so you can
distinguish a real MTU problem from its frequent imposters
(bufferbloat, transport saturation, transient packet loss).

For the underlying model — encapsulation overhead, proactive vs
reactive PMTUD, the per-destination MTU storage layout — read
[../design/fips-mtu.md](../design/fips-mtu.md) first.

## Symptom map

| Application symptom | Likely cause |
| ------------------- | ------------ |
| `iperf3 -c <host.fips>` control socket closes immediately after `Connecting to host`. | Forward-path MTU smaller than the negotiated MSS on the control connection. |
| `ssh user@<host.fips>` shows the SSH banner then hangs forever. | First post-banner exchange exceeds the path MTU; SYN MSS clamp did not engage in time, or the path narrowed mid-session. |
| `curl http://<host.fips>/` connects, then times out before the first response byte. | Same shape as the SSH-banner case, applied to the first server-to-client large packet. |
| Throughput bursts then drops to zero, recovers, drops again, in seconds-long cycles. | Bufferbloat masquerading as MTU failure — usually the upload of the underlay link is saturated. See [Distinguishing bufferbloat](#distinguishing-bufferbloat-from-mtu-drops). |
| `MtuExceeded` counters tick up under topology change but settle in seconds. | Normal: the reactive MTU mechanism doing its job. No action needed. |
| `MtuExceeded` counters tick continuously under steady state. | Forward-path MTU smaller than what the source learned via `path_mtu` echo. After `mmp.path_mtu` has settled, this is a bug — see [File a bug](#file-a-bug). |

The first three are MTU candidates; the fourth is usually not. The
fifth is benign. The sixth is the bug shape worth filing.

## Diagnostic toolkit

### `fipsctl show sessions`

The authoritative end-to-end MTU for an established session:

```sh
fipsctl show sessions | jq '.sessions[] | {display_name, state, mmp: .mmp.path_mtu}'
```

`mmp.path_mtu` is the value the session-layer MMP currently believes
is in force end-to-end. It updates on each PathMtuNotification echo
from the destination — immediately on decrease, with hysteresis on
increase. A field that starts at `1280` (the IPv6 floor) and then
climbs to a higher value as echoes arrive is healthy; one that
oscillates between two values may indicate a flapping path.

### `fipsctl show transports`

Per-transport MTU. The `mtu` field reports the transport-wide
default; for BLE, individual links may have a smaller negotiated
ATT_MTU.

```sh
fipsctl show transports | jq '.transports[] | {type, mtu}'
```

### `fipsctl show cache`

The coordinate cache carries reverse-path-annotated MTU per
destination — the freshest "what fit on the way back from the
discovery target" estimate, consulted before the session has any
PathMtuNotification feedback.

```sh
fipsctl show cache | jq '.entries[] | {display_name, depth, path_mtu}'
```

Entries without a `path_mtu` field are pre-discovery or were
populated through a path that did not annotate the MTU.

### `fipsctl show peers`

Per-peer link state, including the link-layer MMP metrics. Useful
mostly for ruling out underlying loss (loss rate near zero, SRTT
sane) before chasing an MTU explanation.

```sh
fipsctl show peers | jq '.peers[] | {display_name, mmp: .mmp}'
```

### Trace logging

Module-scoped trace logging on the TUN reader and the MMP handler
shows the per-packet decisions. The `tracing` macros default the
target to the emitting module path, so the filter targets are the
fully-qualified module paths under the `fips` crate.

```sh
sudo systemctl edit fips
# Add:
# [Service]
# Environment=RUST_LOG=info,fips::upper::tun=trace,fips::node::handlers::mmp=debug
sudo systemctl restart fips
sudo journalctl -u fips -f
```

### tcpdump on `fips0`

Capturing on the TUN reveals the IPv6 packets the daemon hands the
kernel and vice-versa. Two important caveats live in the design doc
and are worth restating here:

- TX direction (outbound from a local app): tcpdump sees the packet
  **before** the daemon's TCP MSS clamp at the TUN boundary. The
  packet may be larger than the daemon will let leave the node.
- RX direction (inbound to a local app): tcpdump sees the packet
  **after** the daemon's MSS clamp on inbound SYN-ACKs. The clamp
  fires only when `max_mss < kernel-natural-MSS`; otherwise it is a
  silent no-op.

```sh
sudo tcpdump -ni fips0 -w /tmp/fips0.pcap port 22 or port 80
# in another terminal, reproduce the symptom, then Ctrl-C
```

Open the pcap in Wireshark and check segment sizes against what the
session's `path_mtu` reports.

## Distinguishing bufferbloat from MTU drops

WAN bufferbloat (sustained upload saturation on a cable or DSL link)
produces a retransmit signature that looks remarkably like
oversized-packet drops. Both manifest as long stalls in TCP flows,
both clear when you stop pushing data, both can ramp the loss-rate
counter without obvious cause.

Two ways to disambiguate:

1. **Saturate the underlay first.** Run a reference upload outside
   FIPS (`iperf3 -c <internet-target>`) until it stabilises, then
   measure latency to the underlay's first hop with a separate `ping`.
   If RTT shoots up by hundreds of ms during the upload, the
   underlay buffer is the culprit, not FIPS MTU. Apply CAKE / fq_codel
   on the underlay router before continuing.

2. **Watch the FIPS counters during the symptom.** A real MTU
   problem ticks `MtuExceeded` (visible in `fipsctl show routing`'s
   `error_signals` block) and shifts the session's `mmp.path_mtu`
   downward. Bufferbloat ticks loss rate and RTT but leaves
   `path_mtu` and `MtuExceeded` alone.

If both signatures fire together, you have both problems.

## Cold-flow first-SYN

The MMP echo populates path-MTU state only after the first
end-to-end exchange, but the TUN reader has to size the very first
SYN before any echo has arrived. The cold-flow ceiling is the
1143-byte conservative fallback derived from the 1280-byte IPv6
floor. The first SYN may therefore be smaller than what the path
ultimately supports; once MMP echoes arrive, subsequent flows use
the larger learned value.

If the first SYN of a flow is still oversized relative to the path,
the receiving transit node generates an `MtuExceeded`, the source
shrinks immediately, and the next packet of the flow fits. This is
expected for one round trip; it becomes a problem only if it
persists.

## Fixes

The operator's choices, in rough order of preference:

### Pin a per-transport MTU floor in config

If a known link in the path has a small MTU that discovery does not
pick up promptly (e.g., a Tor hop with an unusually tight cap), set
a transport-level MTU floor on the relevant `transports.*` block.
See [../reference/configuration.md](../reference/configuration.md)
for the per-transport MTU keys.

### Tune host UDP buffers

For UDP transports specifically, undersized kernel buffers can drop
oversized datagrams in a way that looks identical to MTU failure.
See [tune-udp-buffers.md](tune-udp-buffers.md).

### Accept the floor on intrinsically small links

Tor and BLE link MTUs are properties of the medium, not tunables.
For sessions that cross those links, the path MTU will be small; the
fix is to design applications around it (smaller TCP windows, fewer
large RTTs) rather than fight the transport.

### File a bug

The bug shape worth filing is session `mmp.path_mtu` itself
oscillating, or `MtuExceeded` ticking *within* an established
session after `mmp.path_mtu` has settled. The TCP-clamp mirror
(`path_mtu_lookup`) is now updated on every successful proactive
`PathMtuNotification` apply (tighter-only) as well as by the
reactive `MtuExceeded` handler, so a steady-state divergence
between the per-session `mmp.path_mtu` and the mirror used for
new TCP flows is itself a defect, not an expected behavior.

Capture `fipsctl show sessions`, `fipsctl show cache`, `fipsctl
show routing` (for the `error_signals` block), and a tcpdump from
`fips0` covering the symptom window. See
[../design/fips-mtu.md](../design/fips-mtu.md#per-destination-mtu-storage)
for the per-destination MTU storage layout.

## See also

- [../design/fips-mtu.md](../design/fips-mtu.md) — encapsulation
  overhead, the proactive `path_mtu` field, the reactive
  `MtuExceeded` mechanism, MSS clamping, the no-fragmentation
  policy.
- [../design/fips-mmp.md](../design/fips-mmp.md) — what the MMP
  metrics mean and how they are computed.
- [../design/fips-ipv6-adapter.md](../design/fips-ipv6-adapter.md) —
  TUN-side ICMPv6 PTB generation and the MSS clamp.
- [tune-udp-buffers.md](tune-udp-buffers.md) — host sysctl recipes
  that rule out kernel-buffer drops as a confounder.
