# Transport-Medium Change Lab

A node whose network attachment moves under it — WLAN to LAN, Wi-Fi to
cellular — while its peers stay where they are.

```
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

## The negative control

Phase 3 repeats the move with `node.netmon.enabled: false` and **requires**
the outage. If traffic survives with detection off, this topology is not
exercising the code path and every assertion above is vacuous — so the suite
fails rather than passing quietly.

This is deliberate. A regression test that has never been seen to fail is a
claim, not a test, and the claim is cheap to make and expensive to trust.

## Knobs

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `MC_MAX_GAP_SECS` | `5` | longest tolerated break in traffic across a move |
| `MC_CONTROL_DARK_SECS` | `12` | how long the control must stay dark |
| `MC_PRIMARY_PREFIX` | `172.31.60` | first access path `/24` |
| `MC_SECONDARY_PREFIX` | `172.31.61` | second access path `/24` |
| `MC_FAR_PREFIX` | `172.31.62` | far segment `/24` |

The gap budget sits far below the 30 s liveness timeout on purpose: a pass
must mean the move was absorbed, not that the reaper was quick.
