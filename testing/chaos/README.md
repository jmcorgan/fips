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
  nodes, with `coord_ttl_secs: 10` so coordinate cache entries expire during
  the run. Tests re-convergence when the peer set and the identities behind
  it both move.
- **maelstrom-sparse**: 50-node sparse random geometric graph (radius 0.20,
  roughly 3-4 peers per node), which forces multi-hop routing and heavy
  discovery use. The short coordinate TTL expires transit-warmed entries, so
  nodes must rediscover rather than coast on the cache.

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
`src/proto/stp/tests/state.rs` (`test_effective_depth_*`, `test_hysteresis_*`,
`test_cost_*`), which run in the cargo quartet on every commit and can each be
shown to fail by breaking the cost or hysteresis logic.

### Transport-specific

Explicit topologies exercising non-UDP transports.

| Scenario      | Nodes | Transport      | Shape | Duration | Netem | Link Flaps | What it tests                              |
| ------------- | ----- | -------------- | ----- | -------- | ----- | ---------- | ------------------------------------------ |
| ethernet-only | 4     | Ethernet       | Ring  | 30s      | yes   | --         | AF_PACKET transport with beacon discovery  |
| ethernet-mesh | 6     | UDP + Ethernet | Mesh  | 120s     | yes   | yes        | Mixed UDP/Ethernet, netem mutation + flaps |
| tcp-mesh      | 6     | UDP + TCP      | Mesh  | 120s     | yes   | yes        | Mixed UDP/TCP, netem mutation + flaps      |

- **ethernet-only**: 4-node ring on raw Ethernet (AF_PACKET). Peers discovered
  via beacons, not static config. Minimal netem (1-5ms delay).
- **ethernet-mesh**: Mirrors `tcp-mesh` topology but with Ethernet instead of
  TCP. UDP edges use static config; Ethernet edges use beacon discovery.
- **tcp-mesh**: 6-node mesh with 4 UDP and 3 TCP edges. Both transports use
  static peer config. Netem mutation (30% fraction, every 20-40s) and link
  flaps (1 link max, 10-20s down).

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
scenario runs.

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
  seed: 42                          # deterministic RNG seed
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

## Creating Custom Scenarios

1. Copy an existing scenario from `scenarios/`.
2. Adjust topology size, algorithm, and stressor parameters.
3. Run with `./testing/chaos/scripts/chaos.sh path/to/custom.yaml`.
