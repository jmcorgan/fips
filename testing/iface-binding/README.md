# Dynamic Interface Binding

Two FIPS daemons whose **only** transports are bound to network interfaces,
exercised against a veth pair the harness creates, downs, deletes and recreates
underneath them while they run.

```
node-a                                     node-b
  lab   ve-lab0     required  ── veth ──   ve-lab0     required
  dock  fips-dock0  optional               fips-dock0  optional
```

`ve-lab0` does not exist when the daemons start. `fips-dock0` never exists at
all, on any host, ever — it is the negative control for `optional: true`.

## What it asserts

| | Behavior |
| - | -------- |
| (a) | A daemon whose only interface is missing **starts**, reports the transport `absent`, and reports `Degraded` — it does not exit on `NoTransports`, and it does not skip the transport for the life of the process |
| (b) | The interface appears; both daemons bind it with no restart, `Degraded` clears, and they discover and peer over it |
| (c) | The interface goes down and comes back; presence and health follow it in **both** directions, and the rebind is counted |
| (d) | The interface is deleted outright and recreated; both daemons rebind and re-peer — the case the old ENXIO beacon-socket reopen half-covered |
| (e) | An `optional` interface that never appears logs at `info` and never moves node health |
| | Absence is logged **once on the edge**, not once per retry |

Health is asserted through `fipsctl show status` (`state`), presence through
`fipsctl show transports` (the per-transport `interface` block: `presence`,
`policy`, `binds`, `since_secs`).

## Running

```sh
./test.sh                 # builds the image first
./test.sh --skip-build    # reuse an existing image
./test.sh --keep-up       # leave the containers running for inspection
```

Via the local CI runner:

```sh
./testing/ci-local.sh --only iface-binding
```

## Notes

The containers run under `FIPS_TEST_MODE=default`, **not** `chaos`. The chaos
entrypoint waits up to 30 s for every configured Ethernet interface before
starting the daemon — which is exactly the workaround this mechanism retires.
The daemon has to do its own waiting here or the suite proves nothing.

Every `ip link` operation on the host network stack runs inside a short-lived
privileged container sharing the host network and PID namespaces, for the
reason [chaos/sim/veth.py](../chaos/sim/veth.py) documents: on macOS the
containers live in the Docker VM, so ip(8) run on the macOS host could never
reach them, while on Linux the shared namespaces make it identical to running
ip(8) directly.
