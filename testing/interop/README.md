# Mixed-Version Interop Test Harness

A CI lab harness for **mixed-version interoperability** testing. It runs an
N-node full mesh where nodes run **different builds** of the FIPS daemon, and
checks that every pair of versions interoperates — FMP link, FSP session,
connectivity, and rekey survival — without a failure a same-version pair
would not have.

## What it tests

The static/rekey suites bake one binary set for all nodes, so they only ever
test a version against itself. This harness breaks that assumption: each node
runs an image built from its own git ref. The harness then looks for
**interop regressions** — places where two *different* versions fail to
interoperate:

- FMP handshake failures across versions
- `unknown FMP version` drops
- FSP / FMP AEAD decrypt failures
- replay storms / decryption-failure threshold crossings
- link or session teardowns
- asymmetric connectivity drops
- rekey (FMP link + FSP session) that completes within a version but stalls
  or breaks across versions

Every failure is **attributed to a specific version pair**, classified
same-version vs MIXED. The summary states whether failures are
mixed-version-only (a genuine interop regression), both mixed and same
(general instability), or same-version-only (a build is unstable even
against itself).

## The node-spec

The harness is parameterized by a **node-spec**: a multiset of image slots,
of size >= 2. Each slot is one of `a`, `b`, `c`, and the same slot may appear
more than once. The slots resolve to the three images built by
`build-images.sh`:

| Slot | Role                | Intended ref                     |
| ---- | ------------------- | -------------------------------- |
| `a`  | version under test  | the branch tip / commit to vet   |
| `b`  | parent / comparison | parent commit on the same branch |
| `c`  | release baseline    | latest release tag               |

`build-images.sh` is **unchanged** — it always builds exactly three images
from three refs. A node-spec like `a a b c` resolves to the *same* three
images; only the mesh topology grows.

### Node identity vs image slot

Node identity and image slot are **separate**:

- A spec entry is a slot letter.
- Node id = `<slot><ordinal>`, ordinal counting occurrences of that slot,
  1-based.
- Container name = `<name>-<nodeid>`, `fips-interop-<nodeid>` by default
  (see [Running several meshes on one host](#running-several-meshes-on-one-host)).
- IPv4 = `<subnet>.1<index>`, `172.30.0.1<index>` by default, index =
  0-based position in the spec (`.10`, `.11`, `.12`, ...).
- Each node maps to its image slot: `a1`, `a2` → `fips-interop:a`.
- A pair is **same-version** iff the two nodes' slots resolve to the same
  built SHA (read from `.build/refs.env`); else **MIXED**.

Two same-slot nodes get **distinct identities** — `derive_keys.py` is keyed
by node id, so `a1` and `a2` are different npubs even though they run the
same binary.

### Example specs

| Node-spec | Node ids        | Pairs                                            |
| --------- | --------------- | ------------------------------------------------ |
| `a b c`   | `a1 b1 c1`      | 3 pairs, all MIXED — today's triangle (default). |
| `a a b c` | `a1 a2 b1 c1`   | 6 pairs: `a1↔a2` **same** + 5 MIXED.             |
| `a a a`   | `a1 a2 a3`      | 3 pairs, all **same** — a same-version flake rig.|

### Why the `a a b c` control topology matters

The triangle `a b c` has *no same-version pair* — every pair is mixed, so
under packet loss you cannot tell an interop regression from generic loss
noise. The `a a b c` spec adds a **control arm**: the `a1↔a2` pair runs
identical binaries. Under a netem stress loop:

- a failure on a mixed pair the control pair does **not** share → an interop
  regression;
- a failure both the mixed pairs and the control pair share → loss-induced
  instability, not version-specific.

That control pair is what makes a stress run *interpretable*. It is the
default node-spec for `interop-stress.sh`.

The `a a a` spec is the degenerate case: all-same-version, used purely as a
**flake rig** — exercising a single build against itself under loss to find
loss-induced instability with no version variable at all.

## Files

| File                    | Purpose                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `build-images.sh`       | Build `fips-interop:a/b/c`, one Docker image per git ref.       |
| `generate-configs.sh`   | Generate per-node configs, the generated compose, manifests.    |
| `interop-test.sh`       | Test driver: bring up, converge, rekey, analyze, attribute.     |
| `interop-stress.sh`     | Netem stress loop: N reps, pass rate, mixed-vs-same attribution.|
| `names.sh`              | Run name, image repository, subnet and their paths (sourced).  |
| `checks.sh`             | Log and capture readers, multipath checks and their controls.  |
| `capture-entry.sh`      | Multipath mode: start packet captures, then the entrypoint.    |
| `README.md`             | This document.                                                 |

Generated at runtime: `generated-configs/` (per-node configs +
`docker-compose.generated.yml` + `nodes.env` + `npubs.env`), `.build/`,
`.stress-runs/`. The root for these three is selected by the
`FIPS_INTEROP_RUNS_DIR` environment variable — see
[Scratch directory location](#scratch-directory-location) below.

The static `docker-compose.yml` is gone — the compose file is now generated
per node-spec into `generated-configs/docker-compose.generated.yml`.

## How per-node images work

`build-images.sh <ref-a> <ref-b> <ref-c>` (unchanged — always three refs):

1. For each ref, `git worktree add --detach` a temp checkout of the repo.
2. `cargo build --release` the four binaries (`fips`, `fipsctl`, `fipstop`,
   `fips-gateway`) in that worktree.
3. Copy the binaries into a build context alongside the shared
   `testing/docker/Dockerfile` (and `entrypoint.sh`, `resolv.conf`).
4. `docker build` it, tagging `fips-interop:<slot>` and labelling the image
   with its ref + short SHA.
5. Remove the temp worktree (done per-ref so peak disk stays at one worktree).

It also writes `.build/refs.env`, recording each slot's ref and the short SHA
of the commit it resolves to (an annotated tag is peeled to its commit). The
driver reads it to know which pairs are mixed-version. (If absent, it falls
back to the image labels.)

## How to run it

### Build the images (once per ref set)

```bash
cd /dpool/src/clabs/nostr/fips
bash testing/interop/build-images.sh <ref-a> <ref-b> <ref-c>
```

Example: `A` = tip of `fix/fsp-rekey-overlapping-epoch`, `B` = `maint`,
`C` = release tag `v0.3.0`:

```bash
bash testing/interop/build-images.sh fix/fsp-rekey-overlapping-epoch maint v0.3.0
```

### Run a single mesh

```bash
bash testing/interop/interop-test.sh [node-spec...]
```

`node-spec` defaults to `a b c` (the original triangle). Examples:

```bash
bash testing/interop/interop-test.sh                # a b c   — 3-node triangle
bash testing/interop/interop-test.sh a a b c        # 4-node, one control pair
bash testing/interop/interop-test.sh a a a          # 3-node same-version flake rig
```

The driver regenerates configs automatically whenever the requested
node-spec differs from the one on disk, so changing the spec just works.
A run takes a few minutes (driven by `REKEY_AFTER_SECS`, default 35, times
two rekey cycles).

### Run the netem stress loop

```bash
FIPS_INTEROP_NETEM="delay 10ms 5ms 25% loss 2%" \
  bash testing/interop/interop-stress.sh [--reps N] [node-spec...]
```

- `--reps N` — repetitions (default 10).
- `node-spec` — default `a a b c` (the control topology).
- Reps run **serially** — the harness uses fixed container names and a fixed
  Docker network, so two reps must never overlap.
- If `FIPS_INTEROP_NETEM` is unset the script warns (a stress run normally
  wants netem) but still runs a clean baseline loop.

Each rep invokes `interop-test.sh` with netem set and captures its full
output and exit code; a rep passes iff `interop-test.sh` exits 0. Every rep
runs with `FIPS_INTEROP_KEEP_UP=1`, because whether it failed is known only
after the driver exits: the loop saves a failed rep's per-node logs and then
tears the mesh down itself, including when the loop is interrupted.
Artifacts land in `testing/interop/.stress-runs/<UTC-timestamp>/`:

- `rep-NN/driver.log` — full driver output for every rep.
- `rep-NN/docker-<container>.log` — per-container `docker logs` for **failed**
  reps only. The expected containers come from the generated manifest, and
  the loop prints `harvest: k of n per-node logs written` for each failed
  rep. A log that could not be read or came back empty counts as missing.
- `summary.txt` — the aggregate report.

The aggregate report gives reps run, passed/failed counts and an integer
pass rate, then tallies — across all failed reps — connectivity failures by
pair kind (mixed vs same), and a verdict:

- **mixed pairs only, never the control pair** → interop-regression signal;
- **both mixed and same pairs** → loss-induced general instability;
- **same-version control pair only** → the build is unstable against itself.

`interop-stress.sh` exits **1** for the interop-regression signal and **3**
when a failed rep's per-node logs are incomplete (the run's diagnostics are
missing; a regression keeps exit 1). A sub-100% pass rate under loss is
expected and is not by itself a failure, so every other outcome exits 0.

### Options

| Variable                     | Effect                                            |
| ---------------------------- | ------------------------------------------------- |
| `FIPS_INTEROP_NETEM`         | tc-netem string applied to each container's eth0, e.g. `"delay 10ms 5ms 25% loss 1%"`. Passed through `interop-stress.sh` to `interop-test.sh`. |
| `REKEY_AFTER_SECS`           | Rekey interval for generated configs (default 35).|
| `CONTROL_MAX_ATTEMPTS`       | Control windows Phase 1b measures before Phase 5b abstains (default 3). |
| `FIPS_INTEROP_KEEP_UP`       | `1` = leave containers running after the test. The stress loop sets it for every rep and tears down itself. |
| `FIPS_INTEROP_KEEP_WORKTREES`| `1` = keep `build-images.sh` worktrees (debug).   |
| `FIPS_INTEROP_RUNS_DIR`      | Root for the three scratch dirs — see [Scratch directory location](#scratch-directory-location). |
| `FIPS_INTEROP_NAME`          | Run name (default `fips-interop`); see below.     |
| `FIPS_INTEROP_IMAGE`         | Image repository (default: the run name).         |
| `FIPS_INTEROP_SUBNET`        | Mesh `/24`, three octets (default `172.30.0`).    |
| `FIPS_INTEROP_SUBNET2`       | Multipath mode's second `/24` (default `172.30.1`). |
| `FIPS_CI_RUN_ID`             | Run label on the multipath mode's control and hand-back containers, the ones it starts outside compose (default `manual`). |

The netem hook reuses the flake-lab mechanism (`docker exec ... tc qdisc` on
each container's `eth0`) — host-side bridge qdisc does not shape
inter-container port-to-port traffic, so the impairment must live inside the
containers.

### Scratch directory location

The three scratch dirs the harness writes — `.build/` (per-ref build
contexts and `refs.env`), `generated-configs/` (per-node configs +
generated compose + manifests), and `.stress-runs/` (stress-loop
artefacts) — are rooted under `FIPS_INTEROP_RUNS_DIR` when that
environment variable is set. With

```bash
export FIPS_INTEROP_RUNS_DIR=/var/lib/fips-interop
```

all three land under `/var/lib/fips-interop/`, and the source tree
stays clean.

When `FIPS_INTEROP_RUNS_DIR` is unset, each harness script falls back
to writing under `testing/interop/` itself and prints a one-line
stderr warning naming the variable. The in-tree paths are
`.gitignore`d, so accidentally running without the variable does not
dirty the checkout — but pointing the variable outside the source
tree is recommended, so lab runs do not interleave with the source
working copy at all.

### Running several meshes on one host

By default every run uses the containers `fips-interop-<node>`, the
compose project `fips-interop`, the images `fips-interop:a/b/c` and the
subnet `172.30.0.0/24`, so two runs on one host replace each other. Three
variables, read by every script through `names.sh`, keep runs apart:

- `FIPS_INTEROP_NAME` names the run: its containers are `<name>-<node>`,
  its compose project is `<name>`, and its generated configs (and stress
  artefacts) live in `runs/<name>/` under the runs directory instead of at
  its top.
- `FIPS_INTEROP_IMAGE` names the image repository, `<image>:a/b/c`. It
  defaults to the run name, and a repository other than `fips-interop`
  keeps its build worktrees and `refs.env` in `.build/images/<image>/`.
  Build once under one repository and point several named runs at it.
- `FIPS_INTEROP_SUBNET` sets the mesh `/24`. The driver checks it against
  every Docker network and host route before it starts the mesh.

```bash
export FIPS_INTEROP_RUNS_DIR=/var/lib/fips-interop FIPS_INTEROP_IMAGE=lab
bash testing/interop/build-images.sh HEAD HEAD~1 v0.5.3
FIPS_INTEROP_NAME=lab-one FIPS_INTEROP_SUBNET=172.29.110 \
    bash testing/interop/interop-test.sh a b c &
FIPS_INTEROP_NAME=lab-two FIPS_INTEROP_SUBNET=172.29.112 \
    bash testing/interop/interop-test.sh a a c
```

The default containers, images, subnet and paths are the ones the
harness has always used, but the default compose project is now
`fips-interop` where it used to be the directory name,
`generated-configs`, so the default mesh network is now
`fips-interop_fips-interop-net` instead of
`generated-configs_fips-interop-net`. A mesh still up from the harness
before this change (left by `FIPS_INTEROP_KEEP_UP=1`, or by a killed
run) is not removed by the driver's `compose down`, and its network
holds `172.30.0.0/24`, so the driver stops at the subnet check. Bring
that mesh down with the old harness's `compose down` before the first
run of this one. That run rewrites the compose file under the new
project name; after it, the old mesh comes down only by naming its
project:

```bash
docker compose -p generated-configs \
    -f "$FIPS_INTEROP_RUNS_DIR/generated-configs/docker-compose.generated.yml" \
    down --volumes --remove-orphans
```

## The multipath mode (manual)

`interop-test.sh --multipath a c` runs a node with multipath enabled
(`a1`, slot `a`) against a release that does not implement it (`c1`,
slot `c`, built from `v0.5.3` or whichever ref the slot holds), and
checks what the multipath draft promises such a peer. It is run by hand
and is not part of local CI or GitHub CI.

```bash
export FIPS_INTEROP_RUNS_DIR=/var/lib/fips-interop FIPS_INTEROP_IMAGE=mp
bash testing/interop/build-images.sh HEAD v0.5.3 v0.5.3
FIPS_INTEROP_NAME=mp-req FIPS_INTEROP_SUBNET=172.29.110 \
  FIPS_INTEROP_SUBNET2=172.29.111 \
  bash testing/interop/interop-test.sh --multipath a c
FIPS_INTEROP_NAME=mp-cfg FIPS_INTEROP_SUBNET=172.29.112 \
  FIPS_INTEROP_SUBNET2=172.29.113 \
  bash testing/interop/interop-test.sh --multipath=config a c
FIPS_INTEROP_NAME=mp-hour FIPS_INTEROP_SUBNET=172.29.114 \
  FIPS_INTEROP_SUBNET2=172.29.115 \
  bash testing/interop/interop-test.sh --probe-hour a c
```

The three may run at once, each under its own name and subnet pair. A
short run takes about 15 minutes, the hour run about 70.

**What changes in the mesh.** The generator adds a second network
(`FIPS_INTEROP_SUBNET2`, default `172.30.1`) for every slot `a` and slot
`c` node, as `eth1`, and names the first network `eth0`. Slot `a` gets a
second UDP transport, `mp2`, bound to `eth1` on port 2122, with
`node.path.enabled: true`; its peer addresses name `udp/main`. Slot `c`'s
configuration is what the default mode writes. The candidate for the old
node's second address comes from `fipsctl connect <c1> <addr> udp/mp2`
once the link is up (`--multipath`, `--multipath=request`), or from a
configured address on a peer entry the new node does not dial
(`--multipath=config`, `connect_policy: manual`): a configured second
address on an `auto_connect` entry is dialled at startup and would put
handshakes on the old node's second interface.

**The captures.** Both containers run under `capture-entry.sh` instead of
the image's entrypoint directly: it waits for each interface, starts one
`tcpdump -U --immediate-mode` per interface (`eth1`, and `eth0` with a
128-byte snap length on `c1`) writing to `<run-base>/captures/`, and
execs the image's entrypoint only when each is listening, so the
captures cover the daemon's startup and survive the container being
killed. Each start writes new files. The daemon's binary and
configuration are untouched; the container's entrypoint and one mount
are not.

**The phases** (after the usual Phases 0 to 8):

- **M0** runs every check below on planted logs and captures and fails
  the run unless each gives its expected verdict. `bash
  testing/interop/checks.sh --controls <image> <dir>` runs them alone.
- **Pre** checks each capture started before its daemon, the addresses
  on `eth0` and `eth1`, and that `mp2` is up on `eth1`.
- **M1** (request) checks the old node got no capability probe in the
  40 s before the candidate, and that the connect reply held it without
  a dial.
- **M2** checks, at 310 s from link-up, 1 to `capability_bound 310` = 6
  probes discarded at the old node, no PathAck or PathClose, every
  unknown type a probe; every probe sent on the original path at 27
  bytes, seen on the old node's `eth0`, and spaced at or above the
  draft's floors; `smoothed_loss` in the old node's receiver reports
  present and 0; one path in `fipsctl path show`; and no FIPS frame (any
  UDP datagram but the control, or an ARP request for the old node's
  second address) on either second interface, nor a send or dial line to
  the second network (the log witness).
- **M3** (short runs) kills the old node with SIGKILL, waits for the new
  node's link-dead removal (and, in the request run, its re-dial),
  restarts it and checks the relink, the outage's quiet second
  interface, and the new link's probes: none in the request run, whose
  candidate went with the old link, and at most 4 in the first 60 s in
  the configured run.
- **M4** (`--probe-hour`) counts the probes over 3610 s against
  `capability_bound 3610` = 12, reports their gaps and the bytes the old
  node received.
- **C1, C2, M5** send a marked datagram (UDP 40999 to 40999, which
  nothing listens on) across the second network; each capture must count
  it once, so its zero was a live capture's.

Each count reads the daemon logs through `count_log_pattern`,
`matching_lines` or `counted_lines`; an unreadable log or capture is
*not established*, which fails the run. A zero read from a log line
counts only once that line has been seen in the run: the old node's
discard line at least once, the new node's probe send line at least as
often as the old node's discards, and each node's `Connection
initiated` at least once on the first network.

## How to read the output

The driver runs nine phases (0 to 8), plus 1b and 5b when data-plane
streams are on:

| Phase | Check                                                            |
| ----- | ---------------------------------------------------------------- |
| 0     | Bring up the mesh (+ optional netem).                            |
| 1     | All nodes reach N-1 authenticated peers; all directed pairs ping over `fips0` (the definitive FSP-session check). |
| 2     | First FMP rekey cutover completes within the timeout (the count is role-blind: builds before v0.5.2 log a responder's cutover with the same line). |
| 3     | All pairs still ping after the first rekey.                      |
| 4     | Wait out a second rekey cycle.                                   |
| 5     | All pairs still ping after the second rekey.                     |
| 6     | Per-node / per-pair interop log analysis.                        |
| 7     | Every node's mesh-size estimate within ±25% of N after warmup, and every node lists all its direct peers in every poll round, warmup included (one isolated round in which a node cannot be asked is tolerated). |
| 8     | Whole-run log health (the global negative checks below).         |

When data-plane streams are on (`--topology`, or `FIPS_INTEROP_STREAMS`),
Phase 1b measures stream loss over a quiet control window and Phase 5b
compares the loss across the rekey window against it. A control window
counts only if no FMP rekey cutover happened during it and the cutover
count could be read on every node. Otherwise Phase 1b waits for the
cutovers to settle and re-measures, up to `CONTROL_MAX_ATTEMPTS` times (default
3). If no attempt is clean, Phase 5b prints `ABSTAIN` for every stream and
returns no verdict, and the summary says so. The stress loop reports in how
many reps Phase 5b abstained and in how many it re-measured.

Phase 6 is the interop-specific part. It reports:

- **Rekey machinery exercised** — both FMP and FSP rekey cutovers fired.
- **Per-pair interop summary** — each unordered pair, classified
  same-version vs MIXED, with whether it stayed healthy through Phase 6.

Phase 8 runs the global health checks last, so they cover the whole run,
the Phase 7 warmup included: panics, `ERROR` lines, `unknown FMP version`
drops, link teardowns (`MMP link teardown`, which the generated config
makes visible by setting `fips::node::handlers::mmp` to debug), decrypt
failures, handshake failures, rekey-msg2 failures. Any non-zero count is
broken down per node, attributed to a specific build.

The final verdict lists every failure attributed to a specific
`x[ref@sha] <-> y[ref@sha]` pair or build, then states the attribution:

- **mixed-version only** → a genuine interop regression.
- **both mixed and same** → general instability, not version-specific.
- **same-version only** → a build is unstable even against itself.

Exit code is `0` only if every check passed and no per-pair failure was
recorded; non-zero otherwise, with a diagnostic dump (peer/link snapshots and
interop-relevant log tails for all nodes).

## CI integration

The harness is self-contained and slots into `.github/workflows/ci.yml`
alongside the existing `integration` matrix suites. A future matrix entry
would, per push to a PR branch:

1. Resolve the three refs — e.g. `A = github.sha`,
   `B = git rev-parse github.sha^`, `C = $(git describe --tags --abbrev=0)` or
   a pinned release tag.
2. `bash testing/interop/build-images.sh "$A" "$B" "$C"`.
3. `bash testing/interop/interop-test.sh a a b c` for the control topology,
   or `interop-stress.sh` for a loss sweep.
4. On failure, upload the diagnostic dump (or `.stress-runs/`) as an artifact.

The three `cargo build --release` passes are the cost driver; on a CI runner
this suite is heavier than the single-image suites. Reasonable options are to
run it only on release branches / tags, gate it behind a label, or cache the
`fips-interop:c` (release) image since the release tag rarely moves.

Until then the harness runs on demand locally — the same way the flake-lab is
used today.
