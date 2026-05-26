# FIPS mesh-reliability lab

<!-- markdownlint-disable MD013 -->

Local reproduction infrastructure for chronic CI integration-test
flakiness. The goal: turn "happens occasionally on GitHub Actions" into
"reproduces deterministically under controlled local pressure," then fix
on bedrock instead of bumping timeouts.

## Quick start

Prerequisites — same as `testing/ci-local.sh`:

- Docker daemon reachable.
- `fips-test:latest` and `fips-test-app:latest` Docker images built. The
  easiest way to (re)build them is to run `testing/ci-local.sh
  --build-only` once after a fresh checkout or after touching the
  daemon source — the lab itself does not rebuild between reps.
- Python 3 with `pyyaml` and `jinja2` installed for the chaos suites
  (`pip3 install --user pyyaml jinja2`).
- `stress-ng` on the host for pressure profiles other than `idle`
  (`sudo apt-get install stress-ng`).

Simplest invocation — single rekey rep on the idle profile (no CPU
pressure), output under a timestamped subdir of `runs/`:

```bash
bash testing/mesh-lab/run-loop.sh rekey
```

Twenty reps under the github-runner-equivalent pressure profile (the
canonical Phase 1 acceptance-gate shape for the rekey Phase 5
flake class):

```bash
bash testing/mesh-lab/run-loop.sh rekey --reps 20 --profile github-runner-equivalent
```

The harness writes per-rep diagnostics to
`<runs-base>/runs/<timestamp>/rep-NN/` (raw logs, container state,
exit codes) and a per-rep `summary.json` plus an aggregated
`<runs-base>/runs/<timestamp>/summary.json` at the end. Where
`<runs-base>` lands is controlled by the `FIPS_MESH_LAB_RUNS_DIR`
environment variable (see below); by default it is the in-tree
`testing/mesh-lab/` directory. Raw artifacts are gitignored — they're
big and per-developer. The `summary.json` shape is compact so triage
doesn't require holding the raw log stream.

## Suites supported

Initial target set:

- `rekey`, `rekey-accept-off`, `rekey-outbound-only` — rekey-suite
  Phase 5 post-second-rekey connectivity flake class.
- `nat-lan` — two-node NAT-traversal handshake-completion flake class.
- `bloom-storm` — chaos scenario; covers the `bloom_send_rate`
  per-node ceiling exceedance class (single node spiking above the
  ceiling while peers stay well under). Note that
  chaos uses its own python sim runner (not docker-compose), so the
  mesh-lab `compose-resource-limits.yml` and `compose-trace.yml`
  overrides do not apply to this suite; per-rep evidence comes from
  the captured `test-output.log` and the parsed `signature.json`
  (which extracts the `bloom_send_rate` and `min_parent_switches`
  assertion outcomes plus per-node delta distribution).

Adding more is straightforward — see the `dispatch_suite` function in
[run-loop.sh](run-loop.sh).

## Pressure profiles

Defined in [pressure-profiles.sh](pressure-profiles.sh):

- `idle` — no pressure. Baseline; should produce zero failures on a
  healthy mesh.
- `light` — placeholder. Will be calibrated.
- `github-runner-equivalent` — placeholder. Will be calibrated to
  approximate the headroom an `ubuntu-latest` GitHub runner has while
  also juggling four parallel package-build workflows (estimate:
  2-core / ~7 GiB total, so 1 stress-ng worker + memory ballast). The
  initial calibration target: this profile must reproduce the rekey
  Phase 5 flake class at ≥20% rate over 20 reps with mechanism-match.
- `heavy` — placeholder. Worst-case pressure for stall-finding work.

## Environment-variable knobs

The harness reads three optional environment variables that shape what
each rep does, set them in the invoking shell:

- **`FIPS_MESH_LAB_NETEM`** — netem argument string (e.g.
  `"delay 10ms 5ms 25% loss 1%"`). When set, the harness runs
  `tc qdisc add dev eth0 root netem <args>` inside each fips-node
  container after `compose up`. Bridge-level qdisc on the docker
  network does *not* shape inter-container traffic (Linux bridges
  forward port-to-port without packets traversing the bridge
  interface's egress qdisc), so per-container egress is the correct
  injection point.

- **`FIPS_MESH_LAB_TRACE`** — when set to any non-empty value, the
  harness layers a suite-specific trace-RUST_LOG compose override
  on top of the base stack. Module sets are per-suite:
  - rekey / rekey-accept-off / rekey-outbound-only — `rekey`,
    `handshake`, `forwarding`, `session`, `encrypted`, `mmp`
    (via `compose-trace.yml`).
  - nat-lan — `discovery::nostr`, `transport::udp`,
    `node::lifecycle`, `handlers::handshake`, `handlers::forwarding`
    (via `compose-trace-nat.yml`, picked up by
    `testing/nat/scripts/nat-test.sh` through the
    `FIPS_NAT_EXTRA_COMPOSE` env-var hook).
  - bloom-storm — no compose override applies; chaos uses its own
    python sim runner.

  Use only when capturing primary failure-moment evidence for
  mechanism investigation — log volume increases substantially.
  Without this knob, daemon logs only capture state transitions and
  not per-datagram forwarding decisions, which makes evidence
  collection for routing-state stalls effectively impossible.

- **`FIPS_BLOOM_STORM_CPUSET`** — comma-separated CPU set for the
  bloom-storm dispatch's container-pinning sidecar (default
  `0,1`). The sidecar polls for `fips-*` containers as the chaos
  sim spawns them and applies `docker update --cpuset-cpus <set>`
  to each, mimicking the 2-core constraint of a GHA
  `ubuntu-latest` runner. Set to a wider set (e.g. `0,1,2,3`) to
  relax, or to the empty string to disable the sidecar entirely.
  Only applies to the `bloom-storm` suite; other suites ignore it.

- **`FIPS_NAT_LAN_CPUSET`** — comma-separated CPU set for the
  nat-lan dispatch's container-pinning sidecar (default `0,1`).
  Same shape as `FIPS_BLOOM_STORM_CPUSET`, but the sidecar polls
  for `fips-nat-lan-*` containers and applies the cpuset as the
  compose-up creates them. The mesh-lab
  `compose-resource-limits.yml` overlay is rekey-family
  service-name-specific (services `rekey-*` / `rekey-accept-off-*`
  / `rekey-outbound-only-*`), so it does NOT constrain the nat-lan
  containers; the sidecar fills that gap. Only applies to the
  `nat-lan` suite; other suites ignore it.

- **`FIPS_MESH_LAB_TRACE_TREE`** — when set to any non-empty value,
  layers `compose-trace-tree.yml` over the rekey-family compose stack
  to bump `RUST_LOG` to trace level on `fips::node::tree`,
  `fips::tree`, `fips::node::handlers::mmp`, and
  `fips::node::handlers::handshake`. Distinct from
  `FIPS_MESH_LAB_TRACE` (rekey/forwarding/session/encrypted at trace);
  targeted at tree-partition race investigation during multi-peer
  startup. Mutually exclusive with `FIPS_MESH_LAB_TRACE` in practice —
  both env vars layer their overlay, but the second one's per-service
  environment replaces the first's. Only applies to the rekey-family
  suites.

- **`FIPS_MESH_LAB_NO_RESOURCE_LIMITS`** — when set to any non-empty
  value, omits the `compose-resource-limits.yml` overlay for rekey-family
  runs. Default behaviour keeps the overlay engaged so rekey-family lab
  reps stay pressure-matched to a GHA `ubuntu-latest` runner. Set this
  for unconstrained characterization where the goal is to surface a race
  or scheduling artefact rather than reproduce CI pressure. Only applies
  to the rekey-family suites; other suites ignore it.

- **`FIPS_MESH_LAB_RUNS_DIR`** — root directory for harness output
  (the `runs/<timestamp>/` tree). When unset, the harness falls back
  to an in-tree path under `testing/mesh-lab/` and prints a warning
  to stderr naming the variable and the fallback location. Set this
  to a path outside the source tree (e.g. `/var/tmp/fips-mesh-lab`
  or a path on a separate disk) to keep gigabyte-scale per-rep
  artefacts out of the checkout.

Example:

```bash
FIPS_MESH_LAB_TRACE=1 \
FIPS_MESH_LAB_RUNS_DIR=/var/tmp/fips-mesh-lab \
    bash testing/mesh-lab/run-loop.sh rekey-accept-off \
    --reps 20 --profile github-runner-equivalent
```

## Recipes

`recipes/<flake-id>.yaml` files are commit-pinned reproduction recipes
the harness consumes. Each recipe declares the source SHA, the suite,
the pressure profile, the rep count, and the expected mechanism-match
rate, so a future operator can confirm "yes the lab still reproduces
this flake at the documented rate" with one command. None exist yet —
they're authored as concrete reproductions surface.

## How this differs from `testing/ci-local.sh`

`ci-local.sh` runs each suite exactly once in sequence (chaos
scenarios in parallel up to a job slot count), produces a pass/fail
matrix, and is the canonical "did anything regress" gate. The
mesh-lab runs the *same* per-suite test scripts (it does not
reimplement them) but in a loop, with deliberate host pressure
applied, and with rich per-rep diagnostic capture. They share the
Docker images and the test scripts.

When in doubt, debug a single suite via `ci-local.sh --only <suite>`
first to confirm the suite is healthy on idle, then graduate to the
mesh-lab when you want to chase a flake.
