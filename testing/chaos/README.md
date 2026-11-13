# Stochastic Network Simulation

Automated network testing for FIPS. Generates random or explicit
topologies, spins up Docker containers, and applies configurable
stressors (network impairment, link flaps, traffic generation, node
churn) over a timed simulation run. Scenarios cover general stress and
node churn, discovery over sparse topologies, spanning-tree and
bloom-propagation regression, transport-specific validation (UDP, TCP,
Ethernet), and ECN/congestion testing. Logs are collected and analyzed
automatically.

## Prerequisites

- Docker with the compose plugin
- Rust toolchain (for building the FIPS binary)
- Python 3 with `pyyaml` and `jinja2` packages

## Quick Start

```bash
./testing/scripts/build.sh
./testing/chaos/scripts/chaos.sh churn-mixed
```

## Available Scenarios

### General stress and churn

Random topologies with increasing stressor intensity. All three enable
netem mutation, link flaps, iperf traffic, node churn and bandwidth
tiers, and differ in transport mix, density, and whether the peer set
itself churns. Each takes a `--nodes N` override, so the node counts
below are defaults rather than fixed sizes.

| Scenario         | Nodes | Topology         | Duration | Peer churn |
| ---------------- | ----- | ---------------- | -------- | ---------- |
| churn-mixed      | 20    | erdos_renyi      | 600s     | --         |
| maelstrom        | 20    | erdos_renyi      | 600s     | yes        |
| maelstrom-sparse | 50    | random_geometric | 600s     | yes        |

- **churn-mixed**: Mixed transports on one mesh (60% UDP, 20% Ethernet, 20%
  TCP). Netem mutates 30% of links every 20-45s between normal and degraded
  policies; link flaps (max 3 down, 10-30s, connectivity protected); node
  churn (max 5 down, 30-90s, partitions allowed); bandwidth tiers
  (1/10/100/1000 Mbps). Carries baseline assertions, so a run in which the
  mesh never formed cannot report success. Local CI runs it as
  `churn-mixed --nodes 10 --duration 120`, which is the invocation its
  thresholds are calibrated for.
- **maelstrom**: The same stressors plus peer-level topology mutation
  (connect/disconnect every 8-12s) and ephemeral identities on half the
  nodes. It sets the test-only `test_coord_ttl_secs: 10`, which the image
  `testing/scripts/build.sh` builds honours (its binaries carry the
  `test-overrides` feature), so coordinate cache entries expire during the
  run. A daemon built without that feature ignores the key with a warning in
  its log and keeps entries 300 s, the least lifetime `coord_ttl_secs` can
  set. Tests re-convergence when the peer set and the identities behind it
  both move.
- **maelstrom-sparse**: 50-node sparse random geometric graph (radius 0.20,
  roughly 3-4 peers per node), which forces multi-hop routing and heavy
  discovery use. It sets the same test-only `test_coord_ttl_secs: 10`, so
  transit-warmed entries expire and nodes rediscover rather than coast on the
  cache; a daemon built without the `test-overrides` feature keeps them 300 s
  as for maelstrom.

### Spanning-tree and bloom propagation

Explicit topology with an induced parent flap. **No runner invokes this
scenario.** It was retired from both the local and the cloud runner and is
hand-run only; the files remain in the tree and the retirement is recorded as a
coverage gap rather than as a migration to other tests.

| Scenario    | Nodes | Topology | Duration | What it tests                   |
| ----------- | ----- | -------- | -------- | ------------------------------- |
| bloom-storm | 6     | explicit | 180s     | Bloom rate under sustained flap |

- **bloom-storm**: Six-node depth-4 mesh. The two candidate uplinks at depth 2
  swap netem delay (5ms against 100ms) every 4s with parent-flap dampening
  disabled, so the node switches parents each round. Asserts a ceiling on the
  `stats.bloom.sent` delta per node over the trailing 30s, and a floor of 10
  parent switches so a harness that never produced a real switch cannot pass
  trivially. `scenarios/bloom-storm.README.md` carries the bug-class
  description and the threshold derivation.

### Cost-based parent selection — retired, now sans-IO unit tests

The cost-selection scenarios (cost-avoidance, depth-vs-cost, bottleneck-parent,
cost-reeval, cost-stability, mixed-technology) were retired on 2026-07-23.
Their subject was the pure `TreeState::evaluate_parent` decision — which parent
wins on `effective_depth = depth + link_cost`, when periodic re-evaluation
switches, and when hysteresis suppresses a flap. A Docker mesh could not test
that reliably: the root is whichever node holds the smallest `NodeAddr`, MMP
costs take several measurement windows to settle, and hold-down plus hysteresis
timing all confound the outcome (a deterministic `link_swap` attempt still
produced zero periodic switches in a full run).

That logic is now covered by deterministic sans-IO unit tests in
`core/src/proto/stp/tests/state.rs` (`test_effective_depth_*`, `test_hysteresis_*`,
`test_cost_*`), which run in the cargo quartet on every commit and can each be
shown to fail by breaking the cost or hysteresis logic.

### Transport-specific

Explicit topologies exercising non-UDP transports.

| Scenario      | Nodes | Transport      | Shape | Duration | Netem | Link Flaps | What it tests                              |
| ------------- | ----- | -------------- | ----- | -------- | ----- | ---------- | ------------------------------------------ |
| ethernet-only | 4     | Ethernet       | Ring  | 30s      | yes   | --         | AF_PACKET transport with beacon discovery  |
| ethernet-mesh | 6     | UDP + Ethernet | Mesh  | 120s     | yes   | yes        | Mixed UDP/Ethernet, netem mutation + flaps |
| tcp-mesh      | 6     | UDP + TCP      | Mesh  | 120s     | yes   | yes        | Mixed UDP/TCP, netem mutation + flaps      |
| dual-path-flap | 2    | Ethernet + UDP | Pair  | 180s     | yes   | yes        | Two paths; netem flaps of the cable, K-timeout switch |
| dual-udp-flap | 2     | UDP + UDP      | Pair  | 180s     | yes   | yes        | Two interface-bound UDP paths; the same flaps |
| dual-path-carrier | 2 | Ethernet + UDP | Pair  | 180s     | yes   | scheduled  | Two paths; the cable taken down at one end; signalled switch in 1 s |
| forward-only  | 2     | UDP + UDP      | Pair  | 160s     | yes   | scheduled  | Two UDP paths; the active one fails one way, under load |
| loaded-standby | 2    | Ethernet + UDP | Pair  | 105s     | yes   | scheduled  | Standby starved under load, then the cable lost; Dead standby probed at once |
| two-bound-udp | 2     | UDP lanes      | Pair  | 120s     | yes   | --         | Two bound UDP instances per end on one subnet; acks cross |
| two-bound-udp-bulk | 2 | UDP lanes     | Pair  | 120s     | yes   | --         | The same under uncapped traffic; no frame refused as a replay |
| steady-dual-path | 2  | Ethernet + UDP | Pair  | 300s     | yes   | --         | Two healthy near-equal paths; no churn (calibration) |
| dead-grace-long | 2   | Ethernet + UDP | Pair  | 780s     | yes   | scheduled  | By hand: the cable down past the 600 s grace |

- **ethernet-only**: 4-node ring on raw Ethernet (AF_PACKET). Peers discovered
  via beacons, not static config. Minimal netem (1-5ms delay).
- **ethernet-mesh**: Mirrors `tcp-mesh` topology but with Ethernet instead of
  TCP. UDP edges use static config; Ethernet edges use beacon discovery. The
  only scenario that asserts datagram delivery over Ethernet: its `delivery`
  assertion pings to and from n04, whose only edges are Ethernet, at two
  payload sizes, and checks that n04 has no peer on another transport.
- **tcp-mesh**: 6-node mesh with 4 UDP and 3 TCP edges. Both transports use
  static peer config. Netem mutation (30% fraction, every 20-40s) and link
  flaps (1 link max, 10-20s down).
- **dual-path-flap**: two nodes joined by a raw-Ethernet veth and by UDP over
  the bridge (`[n01, n02, ethernet+udp]`), multipath on. Only the cable
  flaps, by 100% netem loss with carrier kept, so neither end has a signal:
  each must move the link to the bridge within the K-timeout bound (1300 ms,
  `switch_latency` at each end), under the same session (`max_promotions`,
  `max_dials`), without a stall in traffic, and move back after the
  restore. `paths_live` is the control that the cable was a second path.
- **dual-udp-flap**: the all-IP twin (`[n01, n02, udp-veth+udp]`): a veth
  carrying IP with an interface-bound UDP instance at each end, plus UDP
  over the bridge. The veth address is a configured candidate that the
  link's path machine makes a second path; the flaps and assertions are
  dual-path-flap's.
- **dual-path-carrier**: dual-path-flap's pair, with the cable taken down
  administratively on a schedule (`ip link set down` at n01, then n02, then
  n01). The downed end loses presence and closes the path to its peer; the
  far end loses carrier. Each end must switch within 1 s, the bound with
  a signal, and within 500 ms (`signalled_ms`). The far end's probes to the
  downed address, a path that carried the link, are held to the node's
  re-check and then the draft's floor (`path_floor`), and with
  the capture on and tx counters of its own veth they are the figures the
  draft's question 4 asks for (`figures.json`).
- **forward-only**: dual-udp-flap's pair, under scheduled bidirectional
  load, with the veth failing in one direction: n02's frames dropped at
  n01's veth ingress for 30 s, then n01's at n02's. Neither end has a
  signal. The end that hears nothing must switch within the K-timeout
  bound (1300 ms); the dropped sender has 2600 ms (`sender_ms`), since it
  still receives its peer's data and holds its probe verdicts until that
  data stops, which is when the peer switches away.
  `reverse_heard` is the control that the step stayed one-directional:
  the undropped direction delivered to its end (against a capture) and
  neither end's neighbour entry failed. It counts the undropped end's
  path messages in the step's second half, or from its last one when the
  half holds none, since a Dead path's interval can grow longer than
  the half. Probes to the stopped address are held to the floor, after the
  re-check where the path carried the link, and counted against the capture
  at the far ingress.
- **loaded-standby**: the cable and a bridge half delayed 2 s each way,
  under bidirectional load for 40 s until the standby is Dead at both ends,
  then the cable taken down at n01. With nothing Live each end must probe
  its acked Dead standby at once (draft 5.7) and bring it back: `rescue`
  checks the probe, within 60 ms of the active path leaving Live, and the
  standby Live within 5 s, with no peer removed. Its control is that the
  standby was Dead, not merely Suspect, before the cut. The delay is sized
  to the replay window of 8192: measured on the development host, the
  containers' frame rate had a tenth percentile of 12405 frames/s, and 2 s
  leaves the control working on a host half as fast.
- **two-bound-udp**: one veth pair carrying two lanes (`[n01, n02, udp-veth,
  {lanes: 2}]`), an interface-bound UDP instance on each lane at each end,
  all on port 2122, no bridge. Once the link is up the runner binds n02's
  neighbour entries for n01's lane addresses each to the other lane's MAC,
  so every answer to n01's probe on one lane arrives on the other. A node
  must credit an answer by the path it echoes, not the instance it arrived
  on: all four lane pairs Live at n01, none going Suspect after, and the
  sentinel address no host answers never Live (`lanes`, `paths_live` with
  `configured`). The control is a frame captured on a lane addressed to
  the other lane's address. Traffic is light, capped at 8 Mbit/s: at the
  generator's uncapped rate the crossed listen socket overflows, so a lane
  would go Suspect for load rather than for the crediting rule.
- **two-bound-udp-bulk**: the same two lanes with the rate cap removed and
  `lanes` left out, since the crossed listen socket still overflows at that
  rate. The check is `max_replay_refusals: {max_total: 0, min_nodes: 2}`.
  Under load the bulk lane's receive queue fills to its buffer and a probe
  on the idle lane is read ahead of it, so the link's frames arrive out of
  order by up to one full queue. The replay window covers that, so no frame
  may be refused, on a node whose decrypt workers refuse what falls behind
  it. The receive loop's hold on the thread is guarded by the polling tests
  in `src/node/tests/decrypt_replay.rs`, not by this suite.
- **steady-dual-path**: the churn calibration. A cable (`role: preferred`,
  through `transport_overrides`) and a bridge path, both 1 to 3 ms, nothing
  flapped, light traffic, 300 s. A healthy pair meets once, switches at
  most twice (each end onto the cable), never dials its live peer, and
  holds the cable as a second path. `ethernet-churn` stays in local CI as
  the interface-binding regression it was added for.
- **dead-grace-long**: run by hand, in neither runner. dual-path-carrier's
  pair with the cable down at n01 for 660 s, past the far end's 600 s
  `PATH_DEAD_GRACE`: the probes and bytes to the downed address over a
  whole grace, all held to the floor after the re-check of the path that
  carried the link (about 53 by that arithmetic), the path discarded with
  `why=Grace`, and the recovery after the return.

### Congestion and ECN

Scenarios testing ECN congestion signaling and transport-level congestion
detection.

| Scenario           | Nodes | Topology | Duration | What it tests                                              |
| ------------------ | ----- | -------- | -------- | ---------------------------------------------------------- |
| congestion-stress  | 10    | Tree     | 120s     | CE marking under kernel drops and MMP loss detection       |
| ecn-ab-on / ecn-ab-off | 6 | Tree     | 120s     | A/B throughput comparison: ECN enabled vs disabled          |

- **congestion-stress**: 10-node tree with 1 Mbps egress bandwidth caps,
  5-10% netem loss, and heavy iperf3 traffic. Ingress policing (1000 kbps)
  and small `recv_buf_size` (4 KB) trigger both MMP loss detection and
  `SO_RXQ_OVFL` kernel socket drops. Validates end-to-end CE propagation:
  transit nodes detect congestion, set CE flag, destinations receive
  CE-marked packets, `ecn_ce_count` reported in MMP.
- **ecn-ab-on / ecn-ab-off**: Paired scenarios with identical conditions
  (6-node tree, 10 Mbps egress, 1000 kbps ingress policing, 10ms link
  delay, 8 KB recv buffer) differing only in `ecn.enabled`.
  `ecn-ab-compare.sh` runs both and prints a side-by-side of throughput
  and congestion counters. It is a manual tool, not a test: it asserts
  nothing and no runner invokes it. The "+10.2% recv throughput with ECN
  enabled" figure once recorded here is not reproducible from anything on
  disk — the script read a fixed `sim-results/ecn-ab-on/` path while the
  runner has written timestamped directories since 2026-03-20, and no
  ecn-ab result directory survives. The path bug is fixed; the figure is
  left out until a run produces one.

### Ingress Traffic Control

Scenarios can include `ingress` configuration to simulate upstream bandwidth
bottlenecks using tc ingress policing:

```yaml
ingress:
  enabled: true
  tiers_kbps: [1000]         # per-peer rate limit in kbps
  burst_bytes: 10000         # policer burst allowance
```

Per-peer u32 filters on the ingress qdisc (`parent ffff:`) rate-limit
inbound packets. Combined with small `recv_buf_size`, this reliably triggers
`SO_RXQ_OVFL` kernel socket drops for congestion detection testing.

### iperf3 JSON Capture

Traffic sessions capture iperf3 results using `--json` output. Results are
collected per-session from containers and saved as `iperf3-results.json` in
the scenario output directory, enabling automated throughput analysis across
scenario runs. Each result also carries the receiver's own intervals
(`server_output_json`, from `--get-server-output` against a server started
with `--json`), which count what arrived; `max_stall` reads those, not the
client's, which count what the sender wrote. With `traffic.udp_mbps` set, each
session also runs a constant-rate UDP stream to the container's second
iperf3 server (port 5202), saved as `iperf3-udp-results.json`; a
`max_stall` with `stream: udp` holds its ceiling on those streams and
reports the TCP sessions' figure beside it, since a TCP receiver can stay
silent after a path switch for as long as its sender's retransmission
timer runs. The stream's client writes a line per event (`--json-stream`), so
one whose file is still empty 5 s after it started never got going: a lost
start datagram does that, since iperf3 does not retry it. It is started once
more for the time left, and the check's message counts every restart in the
run, since the seconds before it are not measured, including one whose stream
the run killed at its end. A second empty file fails the check, and
so does a stream that cannot be read, whose message gives what its file held.

## CLI Options

| Option            | Description                          |
| ----------------- | ------------------------------------ |
| `-v`, `--verbose` | Enable debug logging                 |
| `--seed N`        | Override the scenario's random seed  |
| `--duration secs` | Override the scenario's duration     |
| `--nodes N`       | Override the scenario's node count   |
| `--subnet CIDR`   | Override the simulation's subnet     |
| `--list`          | List available scenarios             |

The scenario argument accepts either a name (`churn-mixed`) or a file
path (`scenarios/churn-mixed.yaml`). `--list` prints the names that
resolve.

## Scenario YAML Format

Annotated example based on `churn-mixed.yaml`:

```yaml
scenario:
  name: "churn-mixed"
  seed: 42                          # fixes topology and tiers; runtime events still vary with timing
  duration_secs: 600                # total simulation time

topology:
  num_nodes: 20
  algorithm: erdos_renyi            # or random_geometric, chain, explicit
  params:
    p: 0.3                          # algorithm-specific parameter
  ensure_connected: true            # retry until graph is connected
  subnet: "172.20.0.0/16"
  ip_start: 10                      # first node gets .10
  transport_mix:                    # fraction of edges per transport
    udp: 0.6
    ethernet: 0.2
    tcp: 0.2

netem:
  enabled: true
  default_policy:
    delay_ms: { min: 5, max: 50 }
    jitter_ms: { min: 1, max: 10 }
    loss_pct: { min: 0, max: 2 }
  mutation:
    interval_secs: { min: 20, max: 45 }  # re-roll interval
    fraction: 0.3                         # fraction of links mutated
    policies:                             # named policy profiles
      normal:
        delay_ms: [5, 20]
        loss_pct: [0, 1]
      degraded:
        delay_ms: [50, 100]
        jitter_ms: [10, 30]
        loss_pct: [3, 8]

link_flaps:
  enabled: true
  interval_secs: { min: 30, max: 60 }
  max_down_links: 3
  down_duration_secs: { min: 10, max: 30 }
  protect_connectivity: true        # never partition the graph

traffic:
  enabled: true
  max_concurrent: 10
  interval_secs: { min: 0, max: 30 }
  duration_secs: { min: 5, max: 90 }
  parallel_streams: 4
  # rate_mbps: 8                    # cap each stream (iperf3 -b); uncapped by default
  # udp_mbps: 1                     # a constant-rate UDP stream beside each session

node_churn:
  enabled: true
  interval_secs: { min: 60, max: 90 }
  max_down_nodes: 5
  down_duration_secs: { min: 30, max: 90 }
  protect_connectivity: false       # partitions allowed

bandwidth:
  enabled: true                     # per-link HTB rate limiting
  tiers_mbps: [1, 10, 100, 1000]   # each link randomly assigned a tier

assertions:                         # evaluated after the run
  baseline:
    min_nodes_reporting: 10
    max_roots: 6
    min_nodes_parented: 4
    min_sessions: 10

logging:
  rust_log: "debug"
  output_dir: "./sim-results"
```

The assertion thresholds in the shipped file are calibrated against
recorded runs at the invocation CI uses, and the file's own comments say
what they were derived from. Read those before retuning them.

A `delivery` assertion checks the data plane rather than the tree. It runs
at teardown, after flapped links and stopped nodes are restored, and pings
each pair at each payload size until `min_replies` replies arrive or
`deadline_secs` passes:

```yaml
assertions:
  delivery:
    pairs: [[n04, n06], [n06, n04]]   # [src, dst] node ids
    payload_bytes: [0, 1200]          # ICMPv6 echo payload sizes, 0-1400
    min_replies: 3                    # default 3
    deadline_secs: 60                 # default 60, per pair and size
    require_transport: ethernet       # optional, with transport_node:
    transport_node: n04               # fail if n04 has no peers, or any
                                      # peer on another transport
```

A two-path suite asserts on the path switch executor's lines and the
path machine's debug lines, which `testing/chaos/sim-assert-test.py` tests
against planted input:

```yaml
assertions:
  path_switches: {min_total: 4, per_flap: 4, extra: 2}  # or max_total
  switch_latency: {max_ms: 1300, each_end: true}  # signalled_ms: tighter;
                                    # sender_ms: a oneway down's dropped sender
  max_promotions: {per_node: 1}     # a second promotion is a re-peering
  max_dials: 0                      # no dial after a node's first promotion
  max_stall: {max_secs: 2}          # longest zero-byte run at a receiver;
                                    # stream: udp holds the UDP streams instead
  paths_live: {min: 2}              # paths Live per node, original included
```

`max_kernel_drops` reads the final congestion snapshot instead. It is a
ceiling on the share of frames the kernel dropped at each node's Ethernet
socket because the receive buffer was full, as dropped / (received +
dropped), and fails a node that reports no count at all:

```yaml
assertions:
  max_kernel_drops: {max_pct: 1, min_nodes: 2}  # min_nodes: how many nodes
                                                # must report an Ethernet count
```

`max_replay_refusals` reads the same snapshot: the replays each node refused
from each peer since it was promoted, on the inline path and in the decrypt
workers. It fails a node that reports no count at all:

```yaml
assertions:
  max_replay_refusals: {max_total: 0, min_nodes: 2}  # min_nodes: how many
                                                     # nodes must report one
```

`active_timeouts` is a report and fails nothing. It counts `Live -> Suspect
why=Timeout` on a node's active path that falls outside the K-timeout bound
after a down at that node, which `path_switches` cannot see, and prints each
one with each node's largest `Task wait` around it (`not kept` for a log with
no such line):

```yaml
assertions:
  active_timeouts: {}               # within_ms: the bound, default 1300
```

Two more read a path's own timeline (`sim/paths.py`), for a path that has
stopped answering:

```yaml
assertions:
  path_floor: true        # draft 5.6: probes to a stopped path, 1, 1, 2, 4 s ...;
                          # 1 s for 30 s first if the path carried the link
  discovery_limit: true   # at most 8 probes per Probing episode
```

`path_floor` places each stop at the path's Dead entry and ends it on an
answer, the peer's probe reviving it, or its release; it allows 50 ms for
log-stamp error and exempts the two probes the draft does: the early probe
when the peer clears `ACTIVE`, and the probe Section 5.7 requires at once
when the active path fails with nothing Live (each in `sim/paths.py`, with
how it is recognised). A stop of a path that carried the link takes the
node's re-check instead (`PATH_DEAD_RECHECK_SPAN`): its probes may go every
1 s while they go before 30 s after the path's silence clock started, and
the gap doubles from there, with the one extra 1 s gap the node's own
recurrence gives after the span (`least_gaps`). A stop carried the link when
the path was the active path at its Dead entry, or when it last left Live
since its previous stop, so a second stop with no Live between does not take
it again. The silence clock is read as the node keeps it, from the first
probe after the path's latest answer; the lines carry no probe ids, so an
answer that came too late to count for the node still counts here, which can
start the clock later than the node did. It refuses a
stop it cannot place: one whose Dead entry came more than 60 s
(`PATH_SILENCE_MAX`) after the path's first unanswered probe. Every run with
path lines writes `figures.json` beside `analysis.txt` and a "Path figures"
section in it: each stop's probes, bytes and gaps, each scheduled down's
probes, captures and recovery at each end, the switch latencies, announce
resends, and the peer's reorder count across each switch. A scheduled down
can `capture: [n02]` on that end's veth for its window, and read
`counters: [n02]`, that veth's `tx_packets` and `tx_dropped`, just before
the down and just after the restore; with carrier off a frame the far end
sends is counted there but never reaches the capture's tap.

`switch_latency` measures from the stamp each flap takes inside the
container, in the same shell as the command that makes it. `sender_ms`
replaces `max_ms` for one end of each `oneway` down, its `from` end, whose
own sends are dropped; the other end and both ends of any other down keep
`max_ms`. Loading refuses it in a scenario with no `oneway` down. An end at
which the down's path (the veth, by the other end's veth address or MAC) did
not carry the link when it went down is not measured: its next switch is not
one the down caused, so the run fails on that precondition, naming the end,
the down and the address the link was on. `paths_live`
and `max_dials` read `debug` lines, so a scenario declaring them must set
`fips::node::handlers::path=debug` and `fips::node::lifecycle=debug` in
`logging.rust_log`; loading refuses it otherwise.

`transport_overrides: {ethernet: {...}, udp-veth: {...}, udp: {...}}` is
merged into every generated transport instance of that kind after the
harness injects it, which `fips_overrides`, merged before, cannot reach.

A scenario can also script timed steps beside the random managers, at
offsets in seconds from the end of warmup (`sim/schedule.py`):

```yaml
schedule:
  # admin: `ip link set dev <veth> down` at `end`, then up after `secs`;
  # presence goes at that end and carrier at the other. Ethernet edges only.
  - {at: 20, down: [n01, n02], mode: admin, end: n01, secs: 15}
  # netem (the default): 100% loss both ways, as a random flap.
  - {at: 60, down: [n01, n02], secs: 15}
  # iperf3 from the first node to the second.
  - {at: 10, load: [n01, n02], secs: 50, streams: 4, bidir: true}
  # oneway: n02's IPv4 frames dropped at n01's veth ingress (ARP passes);
  # both ends' neighbour entries are read before the drop is lifted.
  - {at: 90, down: [n01, n02], mode: oneway, from: n02, to: n01, secs: 30}
```

Each down is stamped inside the container in the same shell as its
command, like a random flap, so `switch_latency` reads both. A step whose
command fails ends the run `NOT SCORED` (exit 4) rather than scoring a down
that did not happen. `admin` is refused with `node_churn`, whose restart
brings the veth back up, and on a `udp-veth` edge, whose interface-bound UDP
reports neither carrier nor presence; `oneway` is refused with `node_churn`
too, and needs a veth edge. `reverse_heard: true` checks each `oneway`
step on a `udp-veth` edge that captures at its `from` end.

## Topology Algorithms

| Algorithm        | Parameters           | Description                                             |
| ---------------- | -------------------- | ------------------------------------------------------- |
| random_geometric | radius (default 0.5) | Place nodes in unit square, connect pairs within radius |
| erdos_renyi      | p (default 0.3)      | Include each edge independently with probability p      |
| chain            | --                   | Linear chain: n01--n02--...--nN                         |
| explicit         | adjacency list       | Hardcoded edges with optional per-edge transport type   |

When `ensure_connected` is true (default), the generator retries up to
50 times to produce a connected graph.

### Directed Outbound Configs

The config generator assigns each static-config edge (UDP or TCP) to
exactly one node for outbound connection using a BFS spanning tree rooted
at the lowest node ID. Tree edges are assigned parent-to-child; non-tree
edges are assigned from the lower node ID to the higher. This eliminates
the dual-connect race condition where both sides initiate simultaneously,
and creates a clear "owning side" for each link — relevant for
auto-reconnect testing. Ethernet edges are excluded from static config
since they use beacon discovery.

### Dual edges: two paths between one pair

An explicit adjacency entry may name one of two dual transports, which join
the pair twice so that it holds two paths under one session:

- `ethernet+udp`: raw Ethernet on a veth pair, found by beacon, and UDP
  over the bridge, dialled from static config.
- `udp-veth+udp`: UDP bound to a veth pair (`interface:`, port 2122), and
  UDP over the bridge, dialled from static config.

`udp-veth` on its own is a single edge carried by UDP over a dedicated veth.
With a fourth element, `[n01, n02, udp-veth, {lanes: 2}]`, the veth pair
carries lanes: macvlan interfaces `vl<k>-<node>` in bridge mode on each end,
lane `k` of the lower id `10.222.e.{2k+1}` and of the higher `10.222.e.{2k+2}`,
each with its own bound UDP instance. The veths are NOARP and each end's
entries for the other's lanes are fixed, so lane 0 does not answer ARP for
every address; both nodes take `rp_filter=0` and `arp_ignore=0`. The
dialler lists every pair of its lane and the peer's lane, and a sentinel at
`10.222.e.250` no host answers. A node holds at most one laned edge, and
lanes do not run with node churn.
Each `udp-veth` edge is numbered in sorted edge order, and edge `k` is
`10.222.k.0/24`: the lower node id is `.1`, the higher `.2`. Each end runs
an interface-bound UDP instance named after its veth, and a node that has
one names its bridge instance `main`, so its static peers qualify the
bridge half as `udp/main`.

The bridge half of a dual edge is the dialled one and carries link-up; the
veth half becomes a second path through the link's path machine. The
dialler of a dual edge is chosen as for any static edge, and a dual edge's
peer entry carries a `priority` on each address (the bridge first); no
other edge writes one. The edge's ordinary netem policy applies to the
veth half; `netem.bridge_policy` sets the bridge half's, and
`link_flaps.only_transport` (`ethernet`, `udp-veth`, ...) confines flaps to
edges of that transport, a dual edge counting as its veth half.

## Output

Results written to `sim-results/` (configurable via
`logging.output_dir`):

- `status.txt` -- How the run ended, plus the scenario, the seed and the
  container names it used; one `key=value` per line
- `analysis.txt` -- Summary: panics, errors, sessions, metrics
- `metadata.txt` -- Seed, node count, edges, adjacency list
- `runner.log` -- Orchestration events (topology, netem, churn, traffic) with timestamps
- `fips-node-nXX.log` -- Per-node log output

The `status` field reads:

- `completed` -- ran for its configured duration
- `interrupted` -- a signal cut the run short, so the artifacts are real
  but describe less time than the scenario asked for
- `aborted` -- the run raised part way through; same caveat, and
  `runner.log` carries the traceback
- `setup-failed` -- the containers never started
- `teardown-failed` -- the mesh ran but its logs or analysis could not be
  produced

A run whose setup raised after its containers started (`aborted`, exit 4)
evaluates no assertions. The mesh never finished forming, so a verdict would
score a mesh that was never built. Its node logs are still collected and
analysed, and in place of the assertion verdicts it prints, and writes to
`assertions.txt`, one line naming the exception that ended setup:

```text
NOT SCORED: run aborted in setup (VethSetupError: <first line of message>)
```

The parenthesis is the exception's class and the first line of its message,
such as `host command timed out 2 times, 90s each: ip link set ...`. It says
what raised, not whose fault it was: a stalled host command and a node
container that died during setup (which fails the interface checks) both end
here, so `runner.log` and the node logs decide which.

A `setup-failed` directory holds `runner.log` and `status.txt` and nothing
else. Nothing is harvested, because container names are global to the host
and reading them after a failed setup describes whichever run holds them
now. So `analysis.txt` in a result directory is proof that this scenario's
own mesh existed. A directory with no `status.txt` was written before this
was the case and says nothing either way.

Exit codes:

- `0` -- Ran to completion, no panics, every assertion passed
- `1` -- The scenario file could not be loaded, or a second interrupt
  arrived while the first was being handled
- `2` -- Panics found in the collected node logs. Also what the argument
  parser exits with when it rejects the command line, before any run starts
- `3` -- A post-run assertion failed
- `4` -- Setup, warmup, the simulation loop or teardown raised, so the run
  did not complete; `runner.log` carries the traceback

Codes 2 and 3 describe what a mesh that ran did. Code 4 says there is
nothing to describe, and takes precedence over both. Code 2 is dual-use:
a run that never started cannot have panicked, so read it together with
whether `runner.log` exists.

A run stopped by a signal exits on this same ladder rather than one of its
own: what it collected before stopping is still worth reporting, and
`status.txt` says it was cut short. `chaos.sh` reports 130 for a Ctrl-C of
its own accord.

## Veth host commands

Ethernet edges are veth pairs made and placed by `ip` commands run in
short-lived helper containers on the host's network namespace
(`sim/veth.py`). Each attempt is bounded by `HOST_CMD_TIMEOUT_SECS`, 90 s.
A timeout kills only the docker client, so the helper, which has a unique
name, has its state logged and is removed with `docker rm -f`. The link is
then looked for: if the command took effect it is not repeated, and
otherwise it is tried once more. A retry that fails is checked the same way,
since a helper that started late may have done the work. Both attempts timing
out aborts setup. `runner.log` carries the helper's state and where the link
was, which is the evidence for why a command stalled.

`veth-host-test.sh` tests this against a stand-in docker
(`veth-host-test/`), with no containers. Both CI runners run it: the GitHub
CI parity job and `ci-local.sh`'s guards. It takes about a minute and a half,
most of it a 31 s stall at the real bound.

## Creating Custom Scenarios

1. Copy an existing scenario from `scenarios/`.
2. Adjust topology size, algorithm, and stressor parameters.
3. Run with `./testing/chaos/scripts/chaos.sh path/to/custom.yaml`.

## Docker labels

Every docker object the simulation creates for itself carries the CI labels
from `run_labels()` in `sim/naming.py`: the generic
`com.corganlabs.fips-ci=1` and the run label
`com.corganlabs.fips-ci.run=<FIPS_CI_RUN_ID>` (`manual` for a hand run). The
runner's network claim and the privileged `ip` helper that `sim/veth.py`
starts for Ethernet edges both take them from there, so a run's teardown can
reap the helper even when the image it starts has no run label.
`testing/check-ci-labels.py` reads the docker commands these files build as
Python lists and fails one that creates a container, network or volume
without the run label (its rule 5).
