# Tune the FIPS Data-Plane Worker Pools

The FIPS data plane spreads its hot-path crypto and UDP I/O across
dedicated OS-thread worker pools rather than running everything on the
async runtime. The default pool sizing and queue behaviour are sized
for the common case — a multi-core host with a handful to a few hundred
peers — and most deployments never need to touch them. This guide is
for the cases that do: throughput investigations, A/B comparisons
against the in-line path, macOS send-path tuning, and very large mesh
scale where one-thread-per-peer becomes a concern.

Every knob here is a runtime environment variable read once at startup,
so you set it in the unit file (or your shell before launching the
daemon) and restart `fips` for it to take effect. None of them live in
`fips.yaml`. For the design context — why the data plane is structured
as per-stage worker pools and per-peer connected sockets — see
[../design/fips-transport-layer.md](../design/fips-transport-layer.md).

## Why this matters

The receive and send paths each pass packets through a pipeline of
stages: socket read, AEAD seal/open, routing, and socket write. When
one stage can't keep up, packets back up behind it. The worker pools
let independent flows run those stages in parallel across cores, and
the send path has an explicit backpressure escalation so a saturated
egress doesn't spin a core or hide the bottleneck behind unbounded
queue latency.

When **not** to tune: if throughput is acceptable and the per-stage
perf profiler (below) shows no single stage dominating, leave the
defaults alone. The defaults already scale the pools to the host's
core count.

## When to reach for the perf profiler first

Before changing any pool sizing, turn on the profiler so you are tuning
against measured per-stage cost rather than guessing.

| Env var | Default | What it does |
| ------- | ------- | ------------ |
| `FIPS_PERF` | unset (off) | Enables the per-stage runtime perf profiler. Set to `1` or `true`. |
| `FIPS_PIPELINE_TRACE` | unset (off) | Alias for `FIPS_PERF`; either variable enables tracing. Set to `1` or `true`. |
| `FIPS_PERF_INTERVAL_SECS` | `5` | Print interval, in seconds, for the per-stage breakdown. Clamped to a minimum of 1. |

With profiling on, the daemon logs a periodic per-stage line
(`[pipe Ns] ...`) showing packets-per-second and per-stage latency
distribution. The stage with the largest queue-wait or per-packet cost
is the one to tune. Profiling adds a small per-packet timestamp cost,
so enable it for an investigation, not in steady-state production.

## Worker pool sizing

The encrypt pool seals FMP frames and issues the batched UDP sends; the
decrypt pool opens inbound frames off the receive loop. Both default to
the host's available parallelism (effectively the CPU count).

| Env var | Default | What it does |
| ------- | ------- | ------------ |
| `FIPS_ENCRYPT_WORKERS` | `num_cpus` | Number of encrypt-pool OS threads. Each handles AEAD seal plus the batched send (`sendmmsg(2)` / `UDP_GSO`) for one shard of the hash-by-destination dispatch. Clamped to a minimum of 1. |
| `FIPS_DECRYPT_WORKERS` | `num_cpus` | Number of decrypt-pool OS threads. Set to `0` to disable the pool entirely and fall back to in-line decrypt inside the receive loop (`rx_loop`). Any non-zero value spawns the shard-owned pool. |

These pools are spawned on Unix only; the worker issues raw-fd send
calls that have no portable equivalent.

**Hash-by-destination, not round-robin.** A single TCP-shaped flow is
pinned to one encrypt worker so wire ordering is preserved; additional
workers only light up under multi-flow load. This means raising
`FIPS_ENCRYPT_WORKERS` does nothing for a single-flow benchmark — it
only helps when many destinations are in play concurrently.

**Failure / observability mode.** If the profiler shows the AEAD seal
or send stage as the bottleneck while cores sit idle under multi-flow
load, more encrypt workers may help. On the receive side, if decrypt is
the dominant stage, confirm the decrypt pool is actually running
(`FIPS_DECRYPT_WORKERS=0` would force the slower in-line path; the
daemon logs `FIPS_DECRYPT_WORKERS=0 → in-line decrypt in rx_loop` when
disabled). The in-line path exists primarily as an A/B baseline, not as
a production tuning.

## Per-peer connected UDP

By default each established UDP peer gets its own `connect(2)`-ed socket
rather than sharing the wildcard listen socket. This lets the kernel
demux inbound datagrams by 4-tuple and lets the send path skip the
per-datagram destination lookup.

| Env var | Default | What it does |
| ------- | ------- | ------------ |
| `FIPS_CONNECTED_UDP` | `1` (on) | Activates the per-peer `connect(2)`-ed UDP socket on Linux and macOS. Set to `0` to fall back to the shared wildcard listen socket for all peers. Accepts `1`/`true`/`yes`/`on` and `0`/`false`/`no`/`off`. |
| `FIPS_MACOS_CONNECTED_UDP` | `1` (on) | macOS-only override that takes precedence over `FIPS_CONNECTED_UDP` on Darwin. If unset, the macOS path falls through to `FIPS_CONNECTED_UDP`, then defaults to on. Same accepted values. |

**Failure / observability mode.** Disable connected UDP (`=0`) as a
quick A/B if you suspect the per-peer socket path is implicated in a
send or demux problem, or as the large-mesh escape hatch described in
the scaling note below. Disabling it also removes the per-peer
descriptor cost — see
[tune-file-descriptors.md](tune-file-descriptors.md) for the FD budget
the connected-UDP path drives.

## Send-path backpressure

When the kernel's UDP egress queue fills (Darwin returns `ENOBUFS` in
tight bursts; Linux signals `EWOULDBLOCK`), the send worker must decide
whether to retry, sleep, or drop the datagram. Pure spin-retry can burn
a core, defeat the loss signal TCP relies on, and hide the real
bottleneck behind worker-queue latency. The escalation is **yield →
sleep → drop**, gated by two counters of consecutive full-queue events.

| Env var | Default (macOS) | Default (Linux/other) | What it does |
| ------- | --------------- | --------------------- | ------------ |
| `FIPS_SEND_BACKPRESSURE_SLEEP_AFTER` | `4` | `0` (disabled) | After this many consecutive over-threshold sends, the producer starts sleeping instead of yielding. `0` disables the sleep gate (yield only). A clean send resets the counter. |
| `FIPS_SEND_BACKPRESSURE_SLEEP_MICROS` | `100` | `1` | Sleep duration, in microseconds, applied once the `SLEEP_AFTER` threshold is crossed. Clamped to a minimum of 1. |
| `FIPS_SEND_BACKPRESSURE_DROP_AFTER` | `256` | `0` (disabled) | After this many consecutive full-queue events, the worker drops the current bulk-data datagram instead of retrying. `0` disables dropping, so bulk data retries indefinitely. Control frames are never dropped — they keep retrying regardless. |

The escalation order matters: `DROP_AFTER` is the hard ceiling checked
first, then `SLEEP_AFTER` decides sleep-vs-yield below it. On Linux the
defaults leave both gates off, so the path yields and retries; the
sleep/drop machinery is primarily a Darwin Wi-Fi mitigation, but the
knobs are honoured on every Unix.

**Interaction with pool sizing.** These thresholds and the encrypt
worker count are two ends of the same pressure. Too few encrypt workers
push more traffic through each worker's send loop and trip backpressure
sooner; loosening the backpressure gates without adding worker capacity
just moves the queue depth around. Tune them together, and watch the
profiler's `UdpSendBackpressure` / `UdpSendBackpressureSleep` event
counts to see how often the gates fire.

## macOS-specific send tuning

Darwin's UDP send path has no `sendmmsg`/`GSO` batch primitive, so the
macOS send loop is shaped differently from Linux and exposes several
extra knobs. These are all no-ops on Linux. They exist for
NIC/Wi-Fi-specific A/B testing on Apple hardware; the defaults reflect
the tuning that measured best on a MacBook Wi-Fi-to-Ethernet path.

| Env var | Default | What it does |
| ------- | ------- | ------------ |
| `FIPS_MACOS_ORDERED_SENDER` | off (`false`) | Opts in to the ordered-sender per-flow handoff, which parallelizes one peer's AEAD while preserving UDP order. It regressed the measured path, so the default keeps packets on the worker chosen by send target. Accepts the usual on/off spellings; any value other than `0`/`false`/`no`/`off` turns it on. |
| `FIPS_MACOS_WORKER_STRIDE` | `1` | How many packets a hot worker drains before the next worker is signalled. `1` is one-packet round-robin (max parallelism, max wakeups); short strides let a worker drain a local batch first. Clamped to 1–64. |
| `FIPS_MACOS_WORKER_BATCH` | `8` | Max datagrams a worker drains per wake. Larger batches become a tight burst of `send`/`sendto` calls; a previous default of 32 could trigger TCP collapse on Wi-Fi. Clamped to 1–64. |
| `FIPS_MACOS_SEND_FLOW_IDLE_MS` | `120000` (120 s) | Idle timeout, in milliseconds, before a per-flow sender entry is reclaimed. Clamped to a minimum of 10000 (10 s). |
| `FIPS_MACOS_SEND_PACE_MBPS` | `0` (off) | Send-pacing rate cap, in Mbps. `0` or unset disables pacing. When set, the worker paces egress to this rate using a token bucket. |
| `FIPS_MACOS_SEND_PACE_BURST_BYTES` | `65536` (64 KB) | Token-bucket burst size, in bytes, for the pacer. Only meaningful when `FIPS_MACOS_SEND_PACE_MBPS` is set. |
| `FIPS_MACOS_NET_SERVICE_TYPE` | off (kernel default) | Sets the Darwin UDP socket QoS class via `SO_NET_SERVICE_TYPE`. Accepts `be`, `bk`, `sig`, `vi`, `vo`, `rv`, `av`, `rd`, `vpn`/`oam`, and `off`/`none`/`default`. Measured sends regressed under several QoS markings, so the default leaves the socket at the kernel default; an invalid value logs a warning and falls back to off. |

**Failure / observability mode.** Reach for these only on macOS, only
when the profiler points at the send stage, and change one at a time —
the interactions between stride, batch, and pacing are NIC- and
radio-specific, which is exactly why they are runtime knobs rather than
fixed constants.

## Massive-mesh scaling note

The per-peer connected-UDP path spawns **one OS thread per established
UDP peer** — the receive-drain worker for that peer's socket. At
ordinary mesh degree this is fine and buys the demux and send-path wins
above. At very large single-node mesh scale, however, the thread count
grows linearly with peer count and can become the binding resource
(thread memory, scheduler pressure) before CPU or bandwidth does. When
you hit that regime, `FIPS_CONNECTED_UDP=0` is the escape hatch: it
collapses all peers back onto the shared wildcard socket, trading the
per-peer demux/send optimisation for a flat thread and descriptor
footprint. Treat this as a deliberate large-scale lever, not a default.

## See also

- [tune-udp-buffers.md](tune-udp-buffers.md) — host sysctls
  (`net.core.rmem_max` / `wmem_max`) so the UDP sockets aren't clamped.
  These interact with the worker pools under burst: the receive socket
  buffer is the first place packets queue, and the decrypt worker
  channel (capacity 32768 jobs per shard) is the second. If a burst
  exceeds steady-state drain, packets either pile up against the socket
  buffer ceiling (raise `rmem_max`) or against the worker channel
  (add decrypt workers). Size both together rather than one in
  isolation.
- [tune-file-descriptors.md](tune-file-descriptors.md) — the per-peer
  connected-UDP socket and its drain worker are the amplifier behind the
  `3·P` file-descriptor budget; raise `RLIMIT_NOFILE` accordingly.
- [../design/fips-transport-layer.md](../design/fips-transport-layer.md)
  — transport design, the connection model behind per-peer connected
  UDP, and the socket-buffer-sizing rationale.
