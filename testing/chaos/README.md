# Stochastic Network Simulation

Automated network testing for FIPS. Generates random or explicit
topologies, spins up Docker containers, and applies configurable
stressors (network impairment, link flaps, traffic generation, node
churn) over a timed simulation run. Scenarios cover general stress
testing, cost-based parent selection, mixed link technologies
(fiber/Bluetooth/WiFi), and transport-specific validation (UDP, TCP,
Ethernet). Logs are collected and analyzed automatically.

## Prerequisites

- Docker with the compose plugin
- Rust toolchain (for building the FIPS binary)
- Python 3 with `pyyaml` and `jinja2` packages

## Quick Start

```bash
./testing/chaos/scripts/build.sh
./testing/chaos/scripts/chaos.sh smoke-10
```

## Available Scenarios

### General stress tests

Random topologies with increasing stressor intensity.

| Scenario | Nodes | Topology         | Duration | Netem | Link Flaps | Traffic | Node Churn | Bandwidth |
| -------- | ----- | ---------------- | -------- | ----- | ---------- | ------- | ---------- | --------- |
| smoke-10 | 10    | random_geometric | 60s      | --    | --         | --      | --         | --        |
| chaos-10 | 10    | random_geometric | 120s     | yes   | yes        | yes     | --         | --        |
| churn-10 | 10    | random_geometric | 600s     | yes   | yes        | yes     | yes        | --        |
| churn-20 | 20    | erdos_renyi      | 600s     | yes   | yes        | yes     | yes        | yes       |

- **smoke-10**: Baseline sanity check. No stressors, just verify tree convergence.
- **chaos-10**: Network degradation (5-50ms delay, 0-2% loss), link flaps (max 2
  down, 10-30s), and iperf traffic (max 3 concurrent). Netem mutates 30% of
  links every 15-30s between normal and degraded policies.
- **churn-10**: Extended run with node churn (1 node down at a time, 30-90s).
  Tests tree re-convergence after node departure/rejoin.
- **churn-20**: Aggressive scale test. Erdos-Renyi topology, up to 5 nodes down
  simultaneously, bandwidth tiers (1/10/100/1000 Mbps), `protect_connectivity`
  disabled (partitions allowed).

### Cost-based parent selection

Explicit topologies with heterogeneous link types (fiber, Bluetooth, WiFi) to
test that the spanning tree selects optimal parents based on link cost.

| Scenario          | Nodes | Shape           | Link types               | Duration | What it tests                                                       |
| ----------------- | ----- | --------------- | ------------------------ | -------- | ------------------------------------------------------------------- |
| cost-avoidance    | 4     | Diamond         | Fiber + Bluetooth        | 120s     | n04 picks fiber parent (n03) over Bluetooth parent (n02)            |
| depth-vs-cost     | 4     | Linear tree     | Fiber + Bluetooth        | 120s     | Cost tradeoff: depth vs. Bluetooth link quality                     |
| bottleneck-parent | 10    | Tree with BT    | Fiber + Bluetooth        | 120s     | n06 avoids Bluetooth bottleneck via n02, picks fiber via n03        |
| cost-mixed-7node  | 7     | Multi-type tree | Fiber + Bluetooth + WiFi | 180s     | n06 prefers fiber (n03) over WiFi (n04)                             |
| cost-reeval       | 4     | Diamond         | Fiber (mutated)          | 180s     | Periodic re-evaluation triggers parent switch (reeval_interval=15s) |
| cost-stability    | 4     | Diamond         | WiFi (all)               | 180s     | Hysteresis prevents flapping when costs vary within 20% band        |

- **cost-avoidance**, **depth-vs-cost**: Minimal scenarios validating the core
  cost formula. Bluetooth (L2CAP) links use 15-40ms delay and 2-8% loss;
  fiber uses 1-5ms delay and 0-1% loss.
- **bottleneck-parent**: Larger topology where some nodes have both fiber and
  Bluetooth paths to choose from, and one node (n09) is stuck with Bluetooth
  (no alternative).
- **cost-mixed-7node**: Three link technologies in one mesh. Traffic enabled.
- **cost-reeval**: Netem mutation (50% fraction, every 12-18s) degrades random
  links. FIPS override sets `reeval_interval_secs=15` so periodic re-evaluation
  catches cost asymmetry. Look for `trigger=periodic` in logs.
- **cost-stability**: All links are WiFi. Mutation swings costs between
  `slightly_better` and `slightly_worse` — within the hysteresis band. Expect
  ≤ 5 parent switches over 180s.

### Mixed-technology

Larger explicit topologies combining multiple link technologies.

| Scenario         | Nodes | Link types               | Duration | Netem mutation | What it tests                                    |
| ---------------- | ----- | ------------------------ | -------- | -------------- | ------------------------------------------------ |
| mixed-technology | 10    | Fiber + Bluetooth + WiFi | 180s     | 20%/30-60s     | Tree convergence across heterogeneous link types |

### Transport-specific

Explicit topologies exercising non-UDP transports.

| Scenario      | Nodes | Transport      | Shape | Duration | Netem | Link Flaps | What it tests                              |
| ------------- | ----- | -------------- | ----- | -------- | ----- | ---------- | ------------------------------------------ |
| ethernet-only | 4     | Ethernet       | Ring  | 90s      | yes   | --         | AF_PACKET transport with beacon discovery  |
| ethernet-mesh | 6     | UDP + Ethernet | Mesh  | 120s     | yes   | yes        | Mixed UDP/Ethernet, netem mutation + flaps |
| tcp-only      | 4     | TCP            | Ring  | 90s      | yes   | --         | TCP transport with static peer config      |
| tcp-chain     | 4     | TCP            | Chain | 90s      | yes   | --         | TCP multi-hop routing through chain        |
| tcp-mesh      | 6     | UDP + TCP      | Mesh  | 120s     | yes   | yes        | Mixed UDP/TCP, netem mutation + flaps      |

- **ethernet-only**: 4-node ring on raw Ethernet (AF_PACKET). Peers discovered
  via beacons, not static config. Minimal netem (1-5ms delay).
- **ethernet-mesh**: Mirrors `tcp-mesh` topology but with Ethernet instead of
  TCP. UDP edges use static config; Ethernet edges use beacon discovery.
- **tcp-only**: 4-node ring using TCP on port 443. Tests connect-on-send,
  FMP framing over TCP, and reconnection. Netem enabled (1-10ms delay, 0-1%
  loss).
- **tcp-chain**: 4-node linear chain, all TCP. Tests multi-hop routing over
  TCP-only mesh.
- **tcp-mesh**: 6-node mesh with 4 UDP and 3 TCP edges. Both transports use
  static peer config. Netem mutation (30% fraction, every 20-40s) and link
  flaps (1 link max, 10-20s down).

## CLI Options

| Option            | Description                          |
| ----------------- | ------------------------------------ |
| `-v`, `--verbose` | Enable debug logging                 |
| `--seed N`        | Override the scenario's random seed  |
| `--duration secs` | Override the scenario's duration     |
| `--list`          | List available scenarios             |

The scenario argument accepts either a name (`churn-10`) or a file
path (`scenarios/churn-10.yaml`).

## Scenario YAML Format

Annotated example based on `churn-10.yaml`:

```yaml
scenario:
  name: "churn-10"
  seed: 42                          # deterministic RNG seed
  duration_secs: 600                # total simulation time

topology:
  num_nodes: 10
  algorithm: random_geometric       # or erdos_renyi, chain
  params:
    radius: 0.5                     # algorithm-specific parameter
  ensure_connected: true            # retry until graph is connected
  subnet: "172.20.0.0/24"
  ip_start: 10                      # first node gets .10

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
  max_down_links: 2
  down_duration_secs: { min: 10, max: 30 }
  protect_connectivity: true        # never partition the graph

traffic:
  enabled: true
  max_concurrent: 3
  interval_secs: { min: 10, max: 30 }
  duration_secs: { min: 5, max: 15 }
  parallel_streams: 4

node_churn:
  enabled: true
  interval_secs: { min: 60, max: 180 }
  max_down_nodes: 1
  down_duration_secs: { min: 30, max: 90 }
  protect_connectivity: true        # never kill the last path

bandwidth:
  enabled: false                    # per-link HTB rate limiting
  tiers_mbps: [1, 10, 100, 1000]   # each link randomly assigned a tier

logging:
  rust_log: "debug"
  output_dir: "./sim-results"
```

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

- `analysis.txt` -- Summary: panics, errors, sessions, metrics
- `metadata.txt` -- Seed, node count, edges, adjacency list
- `runner.log` -- Orchestration events (topology, netem, churn, traffic) with timestamps
- `fips-node-nXX.log` -- Per-node log output

Exit code 0 on success, 2 if panics detected.

## Creating Custom Scenarios

1. Copy an existing scenario from `scenarios/`.
2. Adjust topology size, algorithm, and stressor parameters.
3. Run with `./testing/chaos/scripts/chaos.sh path/to/custom.yaml`.
