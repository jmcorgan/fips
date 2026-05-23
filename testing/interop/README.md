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
- replay storms / excessive-decrypt-failure removals
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
| `c`  | release baseline    | latest release tag (`v0.3.0`)    |

`build-images.sh` is **unchanged** — it always builds exactly three images
from three refs. A node-spec like `a a b c` resolves to the *same* three
images; only the mesh topology grows.

### Node identity vs image slot

Node identity and image slot are **separate**:

- A spec entry is a slot letter.
- Node id = `<slot><ordinal>`, ordinal counting occurrences of that slot,
  1-based.
- Container name = `fips-interop-<nodeid>`.
- IPv4 = `172.30.0.1<index>`, index = 0-based position in the spec
  (`.10`, `.11`, `.12`, ...).
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

It also writes `.build/refs.env`, recording each slot's ref and SHA. The
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
output and exit code; a rep passes iff `interop-test.sh` exits 0. Artifacts
land in `testing/interop/.stress-runs/<UTC-timestamp>/`:

- `rep-NN/driver.log` — full driver output for every rep.
- `rep-NN/docker-<container>.log` — per-container `docker logs` for **failed**
  reps only.
- `summary.txt` — the aggregate report.

The aggregate report gives reps run, passed/failed counts and an integer
pass rate, then tallies — across all failed reps — connectivity failures by
pair kind (mixed vs same), and a verdict:

- **mixed pairs only, never the control pair** → interop-regression signal;
- **both mixed and same pairs** → loss-induced general instability;
- **same-version control pair only** → the build is unstable against itself.

`interop-stress.sh` exits **non-zero only** for the interop-regression
signal. A sub-100% pass rate under loss is expected and is not by itself a
failure, so every other outcome exits 0.

### Options

| Variable                     | Effect                                            |
| ---------------------------- | ------------------------------------------------- |
| `FIPS_INTEROP_NETEM`         | tc-netem string applied to each container's eth0, e.g. `"delay 10ms 5ms 25% loss 1%"`. Passed through `interop-stress.sh` to `interop-test.sh`. |
| `REKEY_AFTER_SECS`           | Rekey interval for generated configs (default 35).|
| `FIPS_INTEROP_KEEP_UP`       | `1` = leave containers running after the test.    |
| `FIPS_INTEROP_KEEP_WORKTREES`| `1` = keep `build-images.sh` worktrees (debug).   |
| `FIPS_INTEROP_RUNS_DIR`      | Root for the three scratch dirs — see [Scratch directory location](#scratch-directory-location). |

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

## How to read the output

The driver runs six phases:

| Phase | Check                                                            |
| ----- | ---------------------------------------------------------------- |
| 0     | Bring up the mesh (+ optional netem).                            |
| 1     | All nodes reach N-1 authenticated peers; all directed pairs ping over `fips0` (the definitive FSP-session check). |
| 2     | First FMP rekey cutover completes within the timeout.            |
| 3     | All pairs still ping after the first rekey.                      |
| 4     | Wait out a second rekey cycle.                                   |
| 5     | All pairs still ping after the second rekey.                     |
| 6     | Per-node / per-pair interop log analysis.                        |

Phase 6 is the interop-specific part. It reports:

- **Global health** — panics, `ERROR` lines, `unknown FMP version` drops,
  link teardowns, decrypt failures, handshake failures, rekey-msg2 failures.
  Any non-zero count is broken down per node, attributed to a specific build.
- **Rekey machinery exercised** — both FMP and FSP rekey cutovers fired.
- **Per-pair interop summary** — each unordered pair, classified
  same-version vs MIXED, with whether it stayed healthy through the run.

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
