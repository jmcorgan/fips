# Transport-Medium Change Lab

A node whose network attachment moves under it — WLAN to LAN, Wi-Fi to
cellular — while its peers stay where they are.

```text
  node-a ──┬── mc-primary ───┐
           │                 ├── router ── mc-far ── node-b
           └── mc-secondary ─┘
```

`node-a` is multi-homed with two equally usable paths to the router. `node-b`
sits beyond the router and is reachable **only** through it. That last part
carries the whole design: because `node-b` is off-link, the route to it
follows `node-a`'s *default* route, which is what the suite moves. Put
`node-b` on a bridge shared with `node-a` and the directly-connected route
wins, the source address never changes, and there is nothing left to test.

Both of `node-a`'s interfaces stay **up** throughout. Nothing is unplugged.
The only thing that changes is which of them the default route points at,
which is what makes this a medium change rather than a link failure — and
which is why link-state watching alone does not see it.

## Running

```bash
./testing/medium-change/scripts/test.sh
# or
./testing/ci-local.sh --only medium-change
```

## What it asserts

Traffic returning after the move is a weak signal: a peering that was torn
down by the liveness timeout and rebuilt by a re-dial also ends with traffic
flowing. The suite therefore checks *continuity*, from `fipsctl show peers` on
both nodes:

| Observation | Meaning |
| ----------- | ------- |
| `link_id` unchanged on node-a | the link was never rebuilt |
| `authenticated_at_ms` unchanged on node-a | no second handshake ran |
| `transport_addr` changed on node-b | the far side re-pinned to the new source |
| longest ping gap within budget | the data plane genuinely carried through |

The third is what stops the first two from passing vacuously on a topology
where nothing actually moved.

Phases 1 and 2 move the route in each direction, since the two are not
symmetric — one direction leaves the old interface holding an address the
routing table has abandoned, the other returns to it.

## Before each move

No phase moves the route until two things hold, each waited for with a
deadline rather than assumed after a fixed sleep:

- node-a's connected UDP socket to node-b is pinned to the path the phase
  starts from, read from `/proc/net/udp` inside node-a. The node opens that
  socket on a tick after the link comes up, and it is the socket a move
  strands. A move made before it exists goes out through the wildcard socket,
  which follows the route by itself, and tests nothing.
- the ping has collected 5 replies, so the data plane was carrying traffic
  when the route moved.

Both print how long they took. The baseline line also gives the time of the
first reply and of the fifth, and the fifth's `icmp_seq`, which shows how
many requests went unanswered first. A fifth reply later than 3 s, the fixed
window the baseline used to be, is printed as a slow start, so a slow start is
visible in a green log.

Every gap is measured from the last reply before the move, so an outage
before the move is not charged to it.

## The negative control

Phase 3 repeats the move with `node.netmon.enabled: false` and **requires**
the outage. If traffic survives with detection off, this topology is not
exercising the code path and every assertion above is vacuous — so the suite
fails rather than passing quietly.

This is deliberate. A regression test that has never been seen to fail is a
claim, not a test, and the claim is cheap to make and expensive to trust.

## Diagnosing a failure

On a failure the suite prints node-a's routes and UDP socket table, every
phase's ping log, and both nodes' whole logs.

To look at the control's baseline over many restarts, run Phase 3 repeatedly
and keep everything:

```bash
MC_CONTROL_RUNS=40 MC_KEEP_DIR=/tmp/mc-diag \
MC_RUST_LOG=debug ./testing/medium-change/scripts/test.sh
```

Each run restarts node-a, and each phase's ping log is kept as
`<phase>.ping.log` beside both nodes' logs. Read the reply times against the
session and link lines in the node logs.

## Knobs

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `MC_MAX_GAP_SECS` | `5` | longest tolerated break in traffic across a move |
| `MC_CONTROL_DARK_SECS` | `12` | how long the control must stay dark |
| `MC_BASELINE_DEADLINE_SECS` | `15` | longest wait for 5 replies before a move |
| `MC_PIN_DEADLINE_SECS` | `15` | longest wait for the socket to be pinned |
| `MC_CONTROL_RUNS` | `1` | how many times Phase 3 runs |
| `MC_KEEP_DIR` | unset | keep every ping log and both node logs here |
| `MC_RUST_LOG` | unset | replaces both nodes' `RUST_LOG` |
| `MC_PRIMARY_PREFIX` | `172.31.60` | first access path `/24` |
| `MC_SECONDARY_PREFIX` | `172.31.61` | second access path `/24` |
| `MC_FAR_PREFIX` | `172.31.62` | far segment `/24` |
| `MC_EXTRA_COMPOSE` | unset | extra compose overlays, colon-separated |

The gap budget sits far below the 30 s liveness timeout on purpose: a pass
must mean the move was absorbed, not that the reaper was quick.

## Running two of these at once

The three prefixes above are fixed defaults, and two runs that both take them
do not both get them: docker refuses the second with `Pool overlaps with other
one on this address space`, and the suite fails at topology start having tested
nothing. The compose project name is unique per run, so the containers and the
networks get distinct *names* — it is only the address pools that are shared.

`testing/ci-local.sh` avoids that by claiming a free `/24` per network under
`10.42.0.0/16` before it starts the lab, letting docker's own `network create`
be the arbiter of who owns what, and pointing compose at the result with
`docker-compose.external-net.yml` via `MC_EXTRA_COMPOSE`. It exports the
claimed prefixes as the three `MC_*_PREFIX` variables, so everything the suite
renders from them follows.

Nothing else applies that overlay. The GitHub matrix runs one job per runner
and the README invocation above is a single lab, so both keep the fixed
defaults and the addresses in this document stay literal. If you want to run
two by hand on one host, set the three prefixes yourself.
