# FIPS Testing

Integration and simulation test harnesses for FIPS, using Docker
containers running the full protocol stack.

## Test Harnesses

### [static/](static/) -- Static Docker Network

Fixed topologies with manual scripts for building, config generation,
connectivity tests (ping, iperf), and network impairment (netem).
Useful for deterministic debugging and validating specific topology
configurations.

| Topology    | Nodes | Transport | Description                      |
| ----------- | ----- | --------- | -------------------------------- |
| mesh        | 5     | UDP       | Sparse mesh, 6 links, multi-hop  |
| chain       | 5     | UDP       | Linear chain, max 4-hop paths    |
| rekey       | 5     | UDP       | Rekey integration test topology  |

### [tor/](tor/) -- Tor Transport Integration

End-to-end Tor transport testing with Docker containers running real
Tor daemons. Requires internet access for Tor bootstrapping.

| Scenario       | Description                                              |
| -------------- | -------------------------------------------------------- |
| socks5-outbound | Outbound SOCKS5 connections through Tor to clearnet peer |
| directory-mode  | Inbound via HiddenServiceDir onion service (co-located)  |

### [nat/](nat/) -- NAT Traversal Lab

Real Docker NAT traversal tests for the Nostr/STUN bootstrap path,
using router containers with `iptables`-based NAT, a local Nostr relay,
and a local STUN responder.

| Scenario  | Description                                                  |
| --------- | ------------------------------------------------------------ |
| cone      | Two NATed peers establish a UDP traversal path               |
| symmetric | UDP traversal fails under symmetric NAT, TCP fallback wins   |
| lan       | Peers on the same LAN prefer local addresses over reflexive  |

The lan scenario also publishes a malformed overlay advert to the relay once
the peers are up, and requires both daemons to survive it and keep their
link. The same lab runs `stun-faults` in every run, and
`nostr-open-discovery`, the open-discovery startup scenario, only when named
(`ci-local.sh --only nostr-open-discovery`).

### [chaos/](chaos/) -- Stochastic Simulation

Automated network testing with configurable node counts, topology
algorithms (random geometric, Erdos-Renyi, chain, explicit), and fault
injection (netem mutation, link flaps, traffic generation, node churn,
scheduled steps). 19 scenarios covering general stress and node churn,
discovery over sparse topologies, spanning-tree and bloom-propagation
regression, transport-specific validation (UDP, TCP, Ethernet),
ECN/congestion testing, and multipath: two paths between a pair of
nodes, one failed by netem loss, by an interface taken down or in one
direction, with the switch, the probes to the stopped path and the
standby's rescue asserted. Scenarios are defined in YAML and executed
via a Python harness that manages the full lifecycle: topology
generation, Docker orchestration, fault scheduling, log collection, and
analysis.

### [interop/](interop/) -- Mixed-Version Interop Harness

On-demand harness that runs an N-node full mesh from a node-spec where
each node can run a different build of the FIPS daemon, then attributes
every FMP/FSP/rekey/connectivity failure to a specific version pair
(same-version vs MIXED). Used to catch interop regressions between
builds, not as a per-commit CI gate; not part of `ci-local.sh`.

### [mesh-lab/](mesh-lab/) -- Mesh Reliability Lab

On-demand harness that runs a chosen integration suite N times under a
configurable host-pressure profile (idle / light / github-runner-
equivalent / heavy via `stress-ng`), per-container netem impairment,
and optional trace-level RUST_LOG, capturing per-rep diagnostics and a
mechanism-match summary across the run. Used for statistical reliability
characterization of known flake classes under calibrated stress, not as
a per-commit gate; not part of `ci-local.sh`.

### [sidecar/](sidecar/) -- Network Sidecar Isolation

FIPS running as a sidecar container that owns the network namespace of
a companion application container, with iptables/ip6tables rules
confining the app to the mesh. `scripts/test-sidecar.sh` boots a
three-node chain of such pairs and asserts both connectivity and
isolation. Run by hand only: no CI runs it, since static-chain asserts the
same multi-hop path and the isolation rules are the test image's own
(`ci-local.sh`'s header says why).

### [firewall/](firewall/) -- nftables Baseline

End-to-end exercise of the production `fips0` nftables baseline at
`packaging/common/fips.nft`, covering the default-deny, conntrack and
drop-in semantics.

### [iface-binding/](iface-binding/) -- Dynamic Interface Binding

Two nodes whose only transports are interface-bound, started before the
interface they name exists. Asserts the boot race (the daemon comes up
`Degraded` and binds when the interface appears, with no restart), the flap
(down/up in both directions), destroy-and-recreate, that an `optional`
interface's absence never moves node health, and that absence is logged once
on the edge rather than once per retry.

### [acl-allowlist/](acl-allowlist/) -- Peer ACL Enforcement

Six nodes with per-node allowlist files mounted at the runtime ACL
paths, exercising insiders, outsiders and allowed remotes at once to
check which peer pairs are admitted and which are rejected. Run by hand
only; retired from both CI runners as redundant with the unit and
in-process ACL tests (see `ci-local.sh`).

### [openwrt/](openwrt/) -- OpenWrt Maintainer Scripts

Runs the OpenWrt package scripts and the `fips-gateway` init script
under busybox `ash` against stubbed init scripts and `uci`, and checks
what the real `build-apk.sh` and `build-ipk.sh` package. Its firewall
scenarios run in pinned OpenWrt rootfs images with the real `uci`, `fw4`
and `nft`, and include a check that `fips-mesh-setup` leaves `fips.yaml`,
the `fips` init script and the running daemon alone. No router, opkg or
apk-tools is involved. Part of both CI runners as `openwrt-scripts`.

### [tarball-install/](tarball-install/) -- systemd Tarball Upgrade

Runs the systemd tarball's `install.sh` twice in a Debian 12 systemd
container, the second time as an upgrade, with stub binaries. Checks
that the units running before the upgrade (fips, fips-dns and
fips-gateway, in three combinations) are the ones running after it.
Part of both CI runners as `tarball-install`.

### [native-api/](native-api/) -- Native Datagram API

Checks the experimental native datagram API: a client process opens a
flow to a remote pubkey over a Unix socket, receives a file descriptor,
and exchanges datagrams on it with no TUN device and no IPv6 emulation.

### [medium-change/](medium-change/) -- Transport-Medium Change

A multi-homed node whose default route moves between two live access paths
while mesh traffic is in flight, with the far peer reachable only through a
router so the path to it actually follows that default route. Asserts the
peering survives without a re-handshake (`link_id` and `authenticated_at_ms`
unchanged). It runs two rounds. With multipath off, the far side must re-pin
to the new source address. With multipath on, the far side may keep sending
to either address, and Phase 4 then takes down the interface it sends to:
it must switch to the other address within the K-timeout bound (1300 ms)
under the same session.

Includes a negative control that runs the same move with
`node.netmon.enabled: false` and requires the outage, so a topology that
has stopped exercising the bug fails rather than passing quietly.

### [dns-resolver/](dns-resolver/) -- `fips-dns-setup` Backends

Runs `fips-dns-setup` against each supported Linux resolver backend in
systemd containers, verifying backend detection, generated config and
teardown, plus an end-to-end scenario that resolves a `.fips` name
through the configured backend. The end-to-end scenarios run the
binaries from a Debian package: `--deb PATH` supplies one, and without
it the suite builds one through `packaging/debian/build-deb-container.sh`.

### [deb-install/](deb-install/) -- Debian Package Install

Installs the built `.deb` in systemd containers for each
target distro and verifies unit enablement, conffile placement and
end-to-end `.fips` resolution as a user would meet it. GitHub CI also
installs the arm64 package on ubuntu22 on an arm64 runner, a leg the
local run cannot have and the parity check reports as GitHub-only.

### [rpm-install/](rpm-install/) -- RPM Package Install

Installs the `fips-mesh` package in systemd containers and checks what an
operator meets on AlmaLinux 9 and Fedora: unit state after install (enabled,
not started), file placement and ownership, end-to-end `.fips` resolution, and
an erase with `fips-dns` stopped, where `%postun` alone must remove the DNS
drop-ins and restart systemd-resolved, and `/etc/fips` must survive. A `no-resolver` scenario pins what a stock EL9 host gets, where no
resolver backend applies: `fips-dns.service` reports active having configured
nothing, the saved backend is `none`, and the node itself works. An `upgrade`
scenario upgrades a running daemon in place and requires that the transaction
does not wait on the restart, that the daemon comes back on the new package,
and that a host which never enabled the gateway does not acquire it.

The package under test is built the way the release builds it: binaries
recovered from the container-built `.deb` and packaged with
`build-rpm-container.sh --no-build`, the path nothing else exercises. `--deb
PATH` supplies that `.deb`, as `ci-local.sh` and the GitHub job do; `--rpm
PATH` tests a package as given.

Each scenario image holds the package, so its tag carries the run's suffix, as
the container names do, and the scenario removes it when it ends;
`check-image-scoping.sh` fails on an unsuffixed `fips-rpm-test` tag. The dnf
steps that set a scenario up, the packaging tools and the image's packages, go
through `packaging/rpm/dnf-bounded.sh`, which bounds each attempt and prints
its time and mirrors. The AlmaLinux metadata is downloaded once per run: the
packaging steps share one dnf cache under `.cache/dnf`, always written as the
user running the suite and never reused across runs, and each EL9 image starts
from its metadata files and downloads only packages. The image keeps its
repository metadata, and the install, erase and upgrade read it rather than
fetching it again.

Those per-attempt bounds do not add up to anything a CI step can hold, so the
whole setup also runs inside one network budget, `DNF_BUDGET` (1800 s by
default; the GitHub job sets 1800 s under a 40-minute step, `ci-local.sh` 1200
s under its 1800 s limit). The clock starts at the first step that reaches a
mirror and is handed down as `FIPS_CI_DEADLINE`: every attempt is bounded by
the time left, no retry starts that cannot finish, and a setup that runs out
fails with a line naming the step and the budget, above dnf-bounded's report
of the mirrors, while the CI step still has time to report it. The image
build receives the deadline as a build secret, so it does not change the
image's cache key.

A retry after a repository's metadata failed to load leaves out the mirror
that served it: dnf 4 does not move on to another mirror when `repomd.xml`
fails to parse, so without that one broken mirror at the top of the list fails
every attempt within seconds. dnf-bounded fetches the repository's mirror list
inside the budget, drops every mirror that has failed for it, and points the
remaining attempts at the rest; a repository it cannot do that for (a metalink,
or a list it cannot fetch) is retried as it is, and its report says why.
`budget-test.sh` tests the budget and the mirror exclusion with dnf stubbed, in
about forty seconds. Both CI runners run it: GitHub's ci-parity job, and
`ci-local.sh` just before rpm-install, at tier 2 and up.

### [boringtun/](boringtun/) -- WireGuard Throughput Baseline

Two userspace WireGuard peers running Cloudflare BoringTun, measured
with `iperf3`, as a comparison baseline for FIPS tunnel throughput.

### [ble/](ble/) -- BLE L2CAP Spike

Standalone cargo project (`ble_spike`) that validates the `bluer` API
assumptions behind the `BleIo` trait against real adapters on two
machines. Not a Docker harness.

### [package-isolation/](package-isolation/) -- Package Build Isolation

Builds two marked trees in the package build container, in turn and
together, sharing a target volume, and checks that each package holds
its own tree's code and revision. Run by hand when changing the package
build; not part of `ci-local.sh` or GitHub CI.

## Shared helpers (`lib/`)

The suites source shell helpers from [`lib/`](lib/). Among them,
[`lib/docker-run.sh`](lib/docker-run.sh) provides `run_container`, a detached
container start that passes the run labels itself, retries a start the Docker
daemon refuses (three attempts, 2 s apart), and reports a start that never
succeeds as an `INFRASTRUCTURE:` line naming Docker's error, so a daemon
refusal under side load is not read as FIPS failing to start. Its hermetic
test, [`lib/docker-run-test.sh`](lib/docker-run-test.sh), runs in local CI's
guards and in GitHub CI's ci-parity job. `lib/` also holds the hermetic tests
of `ci-local.sh` itself, which run the same way:
[`lib/ci-args-test.sh`](lib/ci-args-test.sh) for its options and
[`lib/ci-plan-test.sh`](lib/ci-plan-test.sh) for its plan check (Tiers,
below).

## Running CI locally (`ci-local.sh`)

[`ci-local.sh`](ci-local.sh) runs the full local CI pipeline — build,
clippy, unit tests, and the integration suites (including the chaos
scenarios) — mirroring the GitHub `ci.yml` integration matrices. Run
`./ci-local.sh --help` for the full option list and `--list` for the
available suites. Every run starts with a parity check that verifies the
local suite set covers the same work as the GitHub matrix, per scenario for
chaos, per distro for deb-install and per scenario for rpm-install, across
every job that carries a
matrix, and that every build, lint, guard and unit-test step GitHub runs is a
stage of `--tier 2` and the reverse, by the check's table of GitHub steps and
local results; a divergence fails the run. A name proves nothing about a
command, so each mapped step must also run the command fragments the check
lists for it, taken from what `ci-local.sh` runs for its result, in real
command text (not a comment or an echo), and each kind of integration leg
must reach a step that runs its suite's script. Each of these steps must be
able to fail and must run: a `|| true` or `|| echo`, an `exit 0`, a command
behind `:` or `if false`, a pipe with no pipefail, `--no-run`, a
constant-false `if:` or a `continue-on-error:` fails the check. No step in
any workflow a push or a pull request starts may run the explorers (the
core's `slow-explorers` feature, the root crate's `explorers` feature, or
`FIPS_MUTATION_EXPLORERS`), counting values a matrix supplies. Matching by
fragment does not parse the shell, so review still has to read a CI change.
The only exceptions are what one
runner cannot do, listed by name in the check: the Android, macOS and Windows
jobs, the build job's native release builds on its arm64, macOS and Windows
legs, and nextest's retry-flake report on GitHub, the zig cross-checks
locally. On Linux the release build is the `.deb` on both runners: GitHub's
`deb-package` job, and `deb-build` locally, and the check fails if the build
job's own release build runs on its `ubuntu-latest` leg too. GitHub runs the
same check as its own `ci-parity` job.
`--check-parity` runs it alone (see [check-ci-parity.sh](check-ci-parity.sh)),
and [`lib/ci-parity-test.sh`](lib/ci-parity-test.sh), another guard, plants
each kind of divergence in a scratch copy to show the check fails on it.

### Tiers (`--tier`, `--plan`)

`--tier 1|2|3` (or `FIPS_CI_TIER`) runs one fixed set of stages, the set the
internal builder runs for each kind of commit:

- **Tier 1, every branch push:** the guards, the build stage with the
  bare-metal build and the cross-target check, the unit tests with the core
  run without its slow suites, the known-defect lane, the profiling rerun and
  its audit reach, the release compile, and the root tests. No mutation lane
  and no integration suites.
- **Tier 2, trunk tips and landing candidates:** tier 1, with the `.deb`
  built at the start of the build stage, the core's slow suites, the
  mutation lane, the musl unit tests and every integration suite but the
  nightly-only chaos scenarios, with the chaos runner's veth host-command
  test run just before the chaos suites and the RPM network budget test just
  before rpm-install. This is the set GitHub's `ci.yml` runs too, though it
  runs those two tests among its guards.
- **Tier 3, the nightly run of each trunk tip:** tier 2, the explorers (on
  next the core half alone, and so not the mutation lane's explorer lines;
  see below), and the nightly extras: a batch of every CI chaos scenario,
  three runs each, the same batch of the nightly-only chaos scenarios
  (`dual-udp-flap`, `two-bound-udp-bulk`, `churn-mixed-10` and
  `congestion-stress`, which no tier 1 or tier 2 run and no GitHub job
  takes), and the long scenarios no other run takes (`dead-grace-long`,
  `maelstrom`, `maelstrom-sparse`). `--with-tor` adds the Tor suites. The
  parity check lists the nightly-only scenarios as an exception, since
  GitHub CI has no nightly run.

No tier a push starts runs the explorers. Under a tier the root tests run in
a container, the environment switches (`FIPS_CI_BAREMETAL`,
`FIPS_CI_SLOW_TESTS`, `FIPS_CI_ROOT_TESTS`) are ignored, and an option that
changes what runs is refused with exit 2; only `-j`, `--plan` and, at tier 3,
`--with-tor` combine with it.

Tier 3 is too long for one builder slot, so it also comes in parts, each run
alone on a fresh checkout by `--tier 3 --part <name>`:

- `testing/ci-local.sh --tier 2`: tier 2, guards and build stage included.
- `testing/ci-local.sh --tier 3 --part core-explorers`: `core-explorers`.
- `testing/ci-local.sh --tier 3 --part root-explorers`: `root-explorers` and
  `mutations-explorers`, on a tree that builds the real-node explorer. Next
  does not, so there it is refused with exit 2, as `--explorers=root` is.
- `testing/ci-local.sh --tier 3 --part chaos`: `build-integration`, the
  chaos batch and the long scenarios (with `--with-tor`, the Tor suites).

Together they record exactly what `--tier 3` records (on next, tier 2 and
the core explorer and chaos parts), and
[`lib/ci-plan-test.sh`](lib/ci-plan-test.sh) holds them to that: no result of
tier 3 is missing from every part, no part lists a result tier 3 does not,
and no two parts share a result but `build-integration`, which the chaos
part builds for itself. The on-demand explorer job is the explorer parts,
which on next is the core part alone. A part runs no guards and no build
stage, since the nightly's tier 2 part runs those on the same tree; a part
whose plan lists nothing of its own exits 1, and the chaos part fails
before building when it has no scenario. A single explorer half streams
its output as it runs. `-j` and `--plan` combine with any part,
`--with-tor` only with `chaos`. A builder can test a tree for parts with
`testing/ci-local.sh --tier 3 --part chaos --plan`, which exits 0 on a tree
that has them and 2 on one that does not.

`--tier <n> --plan` prints the results a green run of that tier records, in
order, and exits without running anything. It reads the same switches and
suite arrays the run does, and a green tier run is held to it: if the
results recorded differ from the plan, less a stage skipped for want of
something on the host, the run fails with `plan-match` naming each
difference. [`lib/ci-plan-test.sh`](lib/ci-plan-test.sh), one of the guards,
plants results to show that check passes the plan and fails on a missing or
an extra result.

The musl stage (`musl-tests`, tiers 2 and 3) runs `cargo test --lib --target
x86_64-unknown-linux-musl`, as GitHub's musl job does. A host without that
Rust target or `musl-gcc` (the `musl-tools` package) skips it, prints why,
and lists it under the summary as skipped; it is not counted against the
plan.

### The release build and the `.deb`

No run makes a plain `cargo build --release` of its own. Where an integration
suite that uses the package will run (tier 2 and above, a default run with
no tier, or `--only` of `dns-resolver`, `deb-install` or `rpm-install`), the
build stage builds the `.deb` right after `nft-syntax`, in the pinned
container (`packaging/debian/build-deb-container.sh`), records it as
`deb-build`, and writes it to `deploy/fips_<version>_<arch>.deb` in the
checkout, with `deploy/ci-deb.txt` holding its sha256 and path. Every later
stage that needs it takes that one package: dns-resolver, deb-install,
rpm-install, and the mutation lane, whose normal-build fence reads the
package's `fips`. A failed package build stops the run there, as the release
build did. The integration build is the run's other release-profile build,
and the release compile (`release-test-compile`) runs under the
`integration` profile, which inherits `release` unchanged, so it shares that
build's dependencies; a tree that does not compile is caught by the lints
and unit tests rather than by a build stage of its own at tier 1. `--rerun`
has no build stage, so there the first package suite builds the package.

### A commit's kept artifacts (`FIPS_CI_ARTIFACT_DIR`)

With `FIPS_CI_ARTIFACT_DIR=<dir>`, which the internal builder sets, a run of
a clean tree keeps what it built for the integration stage under its commit:
the two test images, tagged `fips-test:commit-<sha>` and
`fips-test-app:commit-<sha>` and labelled `com.corganlabs.fips-ci.commit`,
the integration binaries in `<dir>/<sha>/bin`, and the `.deb` in
`<dir>/<sha>/deb`. A later run of the same commit in a fresh worktree with
the same variable (a re-run, a red retry, `--rerun`, or the nightly's chaos
part after the commit's tier 2) reuses them and skips the integration build,
the image builds and the package build, logging `reused ...`. Each is
created only when absent, never replaced, and only from a clean build of
exactly that commit; a reuse checks the label, the image's `fips` against
the kept one and the package's version against the commit, and builds
instead on any mismatch. The suites still start the run's own per-run
images, built from the commit tags with the run's own label, so the teardown
of the run that kept them leaves a reusing run's images alone. Two runs of
one commit that both keep: the one whose binaries are kept is the only one
whose images are tagged. The teardown never removes a commit tag
(`ci-cleanup.sh`); pruning them and `<dir>` is the builder's. Unset, or on a
tree with uncommitted changes, nothing is kept or reused.

### Base images

Every base image a CI image builds from, and every third-party image a suite
runs (the Tor relay, strfry, busybox), is pinned by its multi-arch index
digest, so two runs of one tree build on the same bases and a result that
stands for another run of the same tree stands on what that run would have
used. The suite scripts that build from an inline Dockerfile take their
pins from [`base-images.env`](base-images.env), which also says how to move
one; the Dockerfiles carry the same pins literally. The guard
[`check-base-pins.sh`](check-base-pins.sh) (`base-pins`, every tier, and
GitHub's ci-parity job) fails on a base without a digest, after showing on
planted fixtures that it can; `check-base-pins.sh --current` prints each
pin beside the digest the registry serves now.

### An apt proxy for image builds (`FIPS_CI_APT_PROXY`)

A host with an apt cache sets `FIPS_CI_APT_PROXY=http://<host>:<port>`, and
every image build a CI run makes passes it to `docker build` or `docker
compose build` as the `http_proxy` build argument, from
[`lib/build-proxy.sh`](lib/build-proxy.sh): the test image, the root tests'
image, the package builder, the install and resolver suites' images, the NAT
and medium-change lab images, and the mdns and native-api images. Docker
predefines that argument, so no Dockerfile declares it, and it is not
written into the image, so no running container has it; it is never
exported and never given to `docker run`, so cargo, rustup and the test
containers' own traffic do not go through the proxy. Only plain-http
fetches use it; HTTPS fetches go direct. That is apt's mirrors, but also
any plain-http dnf or apk mirror the Fedora, AlmaLinux and Alpine images
fetch from, so the proxy must pass those through rather than serve apt
alone. Unset or empty, it changes nothing. GitHub never sets it.

### What only GitHub runs

GitHub additionally runs the library tests on macOS and Windows, and on
**musl** in every run (built for the musl target and run natively); the musl
leg exists because interface presence is built on `getifaddrs`/`ifa_flags`,
which musl reimplements independently, and OpenWrt is a musl target. A local
run certifies musl only at tier 2 or 3, and never the other two. Both runners
also run the root library tests once more with the root crate's optional
features (`--features profiling,test-overrides`) enabled. GitHub's
`core-baremetal` job also builds the `no_std` core for two bare-metal targets
on every push; a local run does that at every tier, or with `--baremetal` or
`FIPS_CI_BAREMETAL=1`. GitHub's Linux test job also runs fips-core's slow test
suites (among them the guard-switch meta-tests, behind the core's
`slow-tests` feature) on every push; a local run does that at tiers 2 and 3,
or with `--slow-tests` or `FIPS_CI_SLOW_TESTS=1`. Every other platform's test
run skips them.

The explorers, every test that walks a state space (the core's
`slow-explorers` feature and the root crate's `explorers`), run in no CI run
started by a push, on either runner: only the nightly run, `--tier 3`, and a
run with `--explorers` take them. `--explorers` runs, after the unit tests,
exactly the tests each feature adds to its crate's library, the two halves
side by side, recorded as `core-explorers` and `root-explorers`;
`--explorers=core` or `=root` runs one half. Each half's names come from the
two builds' own test lists, and an empty difference fails the half rather than
passing on no tests. They take hours: on the incus builder the core's whole
test run with `slow-explorers` took 123 minutes with the host shared
(2026-11-15), against under six for the same run with `slow-tests` alone on
core-vm. The core half also runs fips-core's two guard-switch meta-tests
again in the explorers' build, the one place the rows whose tests are
explorers run. With the root half, the mutation lane runs again as a stage of
its own, `mutations-explorers`: built with the root crate's `explorers`
feature, it runs only its lines whose test is a root explorer
(`FIPS_MUTATION_EXPLORERS=only`), which the plain lane skips.

Next builds no real-node explorer: its handshake is XX and the explorer is
written for master's IK, so the module is under `#[cfg(any())]`
(`src/node/tests/settle/explore/README.md`) and the root crate's `explorers`
feature adds no test. On next, `--explorers` and tier 3 therefore run the
core half alone, `--explorers=root` and `--part root-explorers` are refused
(`ROOT_EXPLORER` in `ci-local.sh`), and neither tier 3 nor any part records
`root-explorers` or `mutations-explorers`. Next's mutation manifest has no
line whose test is a root explorer, so the plain lane skips nothing.

The Linux and musl legs also create an address-less dummy interface
(`fips-probe0`) and pass its name to the tests as
`FIPS_TEST_ADDRLESS_IFACE`. That is the one assumption the interface-binding
mechanism rests on that no ordinary test can reach: loopback has addresses, so
probing it asks whether `getifaddrs` works rather than whether it reports an
interface that has none — which is exactly what `fips-mesh0` and `fips-ap0`
are on OpenWrt. Local CI makes the same interface at every tier, in the root
tests' container (`root-tests/addrless-iface.sh`), and runs that test there
against the glibc binary and, at tiers 2 and 3, the musl one. Set the
variable by hand to run the assertion against an interface you have created;
leave it unset and the assertion does not run.

### Ignored tests and the known-defect lane

An ignored test runs nowhere unless something runs it on purpose.
[`ignored-tests.txt`](ignored-tests.txt) lists every one, with the reason
class it is ignored under: `environment` (needs root, a namespace, hardware
or a permission the unit-test lane lacks), `benchmark`, `long-running`,
`helper`, or `known-defect` (asserts the correct behaviour and fails today).
[`check-ignored-tests.py`](check-ignored-tests.py), one of the static guards,
reds on an `#[ignore]` without a reason, an ignored test with no entry, and an
entry that names no ignored test. It reads the sources, so it sees tests every
platform compiles, but it cannot resolve module paths.

[`known-defect-lane.sh`](known-defect-lane.sh) runs in the unit-test stage,
here and on GitHub. It runs each `known-defect` test and expects it to fail
at its own assertion of the defect: one that passes reds the lane, so the
change that fixes a defect also removes its ignore and its inventory line,
and the test gates from then on. It also lists the ignored tests of each
library test binary and reds on one the inventory does not name under its
full path. Tests the host does not compile, such as the macOS hardware tests
on Linux, are checked only by the static guard.

A failing run counts as the defect only when the test's own first panic
message line starts with `defect:`. A test marks the assertion that states
the behaviour under test that way, and its setup checks with
`precondition:`. A known-defect test that fails at a `precondition:` check,
or at anything unmarked (a bare `unwrap()`, a shared helper's plain
`expect`, an overflow), reds the lane: it has stopped showing its defect.
The classifier is [`lib/test-verdict.sh`](lib/test-verdict.sh), shared with
the mutation lane. Before any inventory entry, the lane checks itself: it
runs the classifier's fixture test,
[`lib/test-verdict-test.sh`](lib/test-verdict-test.sh), and five planted
`helper` tests in `node::tests::settle::lane`, and exits 1 with `lane
self-check:` if any is classified other than its name says.

A known-defect test that predates the marker and lives in a file the change
adding it could not edit (inline tests in a production source file) is
pinned instead: the lane's `PINNED` list names it with the `file:line` of its
own defect assertion, and an unmarked failure at that line counts as still
failing. An unmarked failure at any other line is still a problem, and the
self-check shows both outcomes on a planted test. Giving such a test's
message the `defect:` prefix removes its pin.

Each test runs under a timeout (`FIPS_KNOWN_DEFECT_TIMEOUT`, default 120 s).
A test the timeout kills is a problem, not a test that still fails: it never
reached an assertion, so a known-defect test that hangs in its setup is not
taken for one failing at its defect. No current entry is a hang; a defect
whose only symptom is a hang would need its own explicit allowance in the
lane, as `PINNED` allows an unmarked line. `FIPS_KNOWN_DEFECT_INVENTORY`
points the lane at another inventory file, for trying it against an edited
copy.

### What `next` leaves off (`check-carried.py`)

This line takes `master` by merge, and a merge can drop a test, a switch or
a known-defect entry without anything going red: the suite stays green
because the test is no longer there. [`check-carried.py`](check-carried.py),
a static guard that lives on `next` only, reads the test names, the
`faults!` switches of `core/src/faults.rs` and the `known-defect` entries of
`ignored-tests.txt` at the `master` commit last merged, and the same in the
work tree. It reds on any of them that is neither here nor listed in
[`left-off-next.txt`](left-off-next.txt), and on an entry that has gone
stale either way: the item is on `next` now, or gone from that `master`
commit. A name `master` holds in several files is counted: each copy `next`
lacks needs an entry naming its file, and a copy that moved to another file
on `next` still counts as carried. Each entry carries a class: `no-site`
(the code is not on `next`), `next-rule` (the code is, under `next`'s rule),
`replaced` with the test that stands for it here, or `open`, which passes,
is printed on every run, and is settled by the next merge. The check cannot
say that a reason is true; a merge's review does.

The merged commit is the second parent of the newest merge on `HEAD`'s
first-parent line, never a branch name: the internal builder's checkout and
a development checkout with unpushed trunks both have a `master` behind the
merge. The check prints that commit and the merge's subject. Only test
files a build reaches are read: it starts at the targets of each package's
`Cargo.toml` and follows `mod` declarations as rustc resolves them,
`#[path]` included. A file a merge drops from the module tree by losing its
`mod` line, left in place, reads as absent, and the check also names any
tracked file that holds a test and that no declaration reaches. A module
under `#[cfg(any())]`, such as the real-node explorer here, reads as absent,
since nothing builds it. Copies are counted rather than matched by path, so a
copy dropped in one file while another of its name is added elsewhere is not
seen; a test written by a macro is not seen either; and only tracked files
are read, so a stray untracked copy cannot pass for a carried test. A crash
exits 2, never a verdict. It runs in `ci-local.sh`'s static guards and not
in GitHub CI, whose shallow checkout holds no merge and whose pull-request
checkout is a merge with the pull request's head, not `master`. Before
reading the tree it runs a self-test over planted repositories, so a green
run has also shown it can fail; `--self-test` runs that alone.

### The mutation lane (`mutations/run.sh`)

[`mutations/`](mutations/) holds breaks that each put back the shape a
real defect took, or make the smallest change that fixes a known defect,
and [`mutations/run.sh`](mutations/run.sh), which runs the tests
[`mutations/manifest.txt`](mutations/manifest.txt) names for each break one
per process and classifies each run with
[`lib/test-verdict.sh`](lib/test-verdict.sh). A break is a switch, a
variant of `Fault` in `core/src/faults.rs` behind `node_fault!(Name)` and
turned on by `FIPS_NODE_FAULTS`, and every line runs against one build. A
new break is a switch, never a patch. A `red` line holds only at the
test's assertion of the behaviour the break breaks (its `defect:`
assertion, or an anchor for a test that predates the marker); a
`pass` line holds when the test passes. Every named test must also pass
with no switch. Before any line, a preflight checks that every switch has a
manifest line and a site, a fence requires the switches to be absent
from a normal build of `fips` (here, the `fips` in the run's `.deb`), and a
self-check on two planted switches
shows the script tells a red test from a green one. It runs in the
unit-test stage, here (recorded as `mutations`) and in GitHub CI's Linux
job, after the known-defect lane. On a host whose build has no BLE
transport the lines behind `ble_available` are skipped and counted. It
prints each break's wall time and the total.

### The live audit's reach (`check-audit-reach.py`)

In a debug test build every node entry that can change a per-peer map audits
the maps on its way out (`src/node/settle/audit.rs`), except on a node a test
wrote past the map writers, which it skips for the rest of the test. A test
helper that marks a node it need not would turn the audit off in every test
that uses it, with the suite still green. So the unit-test stage that runs
the root lib suite as threads in one process (`unit-tests-profiling` here,
the optional-features step in GitHub CI) sets `FIPS_AUDIT_REACH` to a file,
into which each audit writes one row per test thread, node and outcome, and
[`check-audit-reach.py`](check-audit-reach.py) then counts the (test, node)
pairs (recorded here as `audit-reach`). It exits 1 when fewer than 97.0% of
the pairs that reach an audit are audited, or fewer than 2300 are, and 2 on
an empty or unreadable file. The floors are constants at the top of the
script; lowering one is an edit a review sees. Under nextest a test's
thread does not name it, so the check does not read nextest runs.

### The open-file limit and `fd-peak.py`

Every command in the unit-test stage runs under the open-file soft limit
[`unit-fd-limit.sh`](unit-fd-limit.sh) prints (`UNIT_FD_LIMIT` in
`ci-local.sh`; each unprivileged test step of GitHub CI's Linux job reads the
same script): 512 on a runner of up to 48 test threads (`RUST_TEST_THREADS`,
or else the CPU count), and 8 more for each thread past 48. With one bound on
every runner, a leak, or a test that needs far more descriptors than the
rest, reds everywhere rather than only on the host whose limit is lowest.
512 sits under the 1024 a Linux service or login gets by default.

The root lib suite is the heaviest, run as threads in one process with as
many tests at once as there are test threads. Its settlement explorer tests
(`src/node/tests/settle/explore`) each run many walks of real nodes side by
side, each walk with a runtime of its own, so before the walks were bounded
the peak grew with the host: more test threads let more of those tests run
together. A 20-CPU builder reached 511 and failed five tests with "Too many
open files". The walks are now held to 16 at once per process (`WALKS_AT_ONCE`),
so the explorer holds at most 16 walks' worth on any host (93 descriptors at
most in one test alone, and about 180 if all 16 were TCP walks), and the
rest of the peak is a few descriptors per test thread from the other tests.
Measured 2026-11-15 on core-vm (12 CPUs, under side load),
`cargo test -p fips-mesh --lib --features profiling,test-overrides` at each
`RUST_TEST_THREADS`, read from the `fd-peak:` report:

| Test threads | Before the bound | After |
| --- | --- | --- |
| 12 | 401 | 160 |
| 24 | 511, 9 tests failed | 252 |
| 24, explorer tests skipped | 201 | 206 |
| 48 | not run | 341 |

So 512 leaves twice the 24-thread peak and half again the 48-thread one.
Past 48 threads the remaining growth, at most about 8 descriptors per added
thread in these runs, is what the limit's growth covers.

[`fd-peak.py`](fd-peak.py) wraps the stage's whole-workspace test run and
its optional-features run. It runs the command unchanged and passes its exit
status on, and while it runs it counts the open descriptors of each test
binary the command starts. At the end it prints, on `fd-peak:` lines, each
binary's highest count, when it was reached, and what the descriptors were
then: by kind, sockets by protocol, and the most frequent file paths. A run
that hits the limit then says what filled it, and a green run says how close
it came. It is a measurement, not a check: it samples every 2 ms, so a
shorter burst can be missed, though the limit itself still catches one.

### Root-only tests (`root-tests.sh`)

The unit tests that need root and network namespaces are `#[ignore]`d, so the
ordinary unit-test runs skip them; they are `environment` entries in
`ignored-tests.txt`. [`root-tests.sh`](root-tests.sh) is the one place that
lists the `--ignored` filters that run them and how many tests each filter must
pass:

```text
testing/root-tests.sh <bin>
```

`<bin>` is the built `fips-mesh` library test executable (cargo's `fips` lib
target). The script builds nothing and needs no cargo or git, and it never
calls `sudo`: it must already run as root. GitHub's Linux job builds the binary
as the runner user and runs the script under `sudo`. `ci-local.sh --tier`
runs it as uid 0 in a container of the image in
[`root-tests/`](root-tests/), with the permissions below and no network,
recorded as `root-tests`; the run needs docker and no `sudo`, because the
internal builder runs every pushed branch and will not give pushed code
passwordless `sudo`. `ci-local.sh --root-tests` (or `FIPS_CI_ROOT_TESTS=1`)
without a tier runs it under `sudo -n` instead, for a run by hand; it is off
by default.

Two more steps of GitHub's root and fixture jobs run in the same container
under a tier: [`root-tests/privileged.sh`](root-tests/privileged.sh), the
Ethernet and socket-buffer tests with `FIPS_TEST_PRIVILEGED=1`
(`privileged-bind`), and [`root-tests/addrless-iface.sh`](root-tests/addrless-iface.sh),
the address-less dummy interface and the test that reads it, against the
glibc binary (`addrless-iface`) and, at tiers 2 and 3, the musl one
(`addrless-iface-musl`). One privileged test, which reads
`net.core.rmem_max` from the host's own network namespace, runs on GitHub
only; the script names it. `--root-tests` without a tier runs
`privileged.sh` under `sudo -n` too.

Each filter group passes only when the binary exits 0 and libtest reports
exactly the group's count passed, since a filter that matches nothing still
reports `ok`. Every group runs, and the last line is the verdict: `PASS`
(exit 0), `FAIL` with the number of failed groups (exit 1: a test failed, or a
count did not match), or `ERROR` with the reason (exit 2: it could not run).

In a container the script needs uid 0, the `NET_ADMIN` and `SYS_ADMIN`
capabilities, `/dev/net/tun`, an AppArmor profile that allows the namespace
mount (Docker's default refuses it; `--security-opt apparmor=unconfined`), and
a writable `/proc/sys` (`--security-opt systempaths=unconfined`). Before any
test runs it creates a probe namespace, writes a sysctl inside it and deletes
it, and checks `/dev/net/tun`, so a missing permission is an `ERROR` naming it
rather than a run of failing tests.

### Cross-target compile check

`--cross-check` adds a stage to the build that compiles the crate and all its
test, example and bench targets for macOS, Windows and FreeBSD
(`x86_64-apple-darwin`, `x86_64-pc-windows-gnu`, `x86_64-unknown-freebsd`),
recording one result per target as `cross-check-<target>`. Everything else in
the run compiles for the Linux host only, so without it a Unix-only item used
without a `cfg` gate passes local CI and first fails on GitHub's macOS, Windows
or FreeBSD jobs. [`cross-check/check.sh`](cross-check/check.sh) runs
`cargo check --workspace --all-targets --target <target>` for each, with
`zig cc` as the C compiler for the crates that build C, and can be run on its
own, for all targets or for the ones named.

The stage is off by default, because it needs `zig` (0.16.0; found on `PATH`,
or named by `ZIG`). It also needs the three Rust targets for the pinned
toolchain; a missing one is installed with `rustup target add`, which needs the
rustup download server the first time. The targets are not listed in
`rust-toolchain.toml`, which would make every cargo call in the repository fetch
them, the package builds included. When the stage is asked for, a missing
`zig`, or a target that cannot be installed, fails the run with a message
naming it. All three targets build in `target/cross-check/`, reused between
runs.

The check is deliberately local-only: GitHub CI builds and tests on real
macOS, Windows and FreeBSD runners instead.

### Shell-script lint (`check-shellcheck.sh`)

[`check-shellcheck.sh`](check-shellcheck.sh) lints the shell scripts the
OpenWrt packages ship and the CI scripts it lists, recorded as `shellcheck`.
`ci-local.sh`, `ci.yml` and the OpenWrt package workflow all run it with the
shellcheck version that [`install-shellcheck.sh`](install-shellcheck.sh) pins,
not the host's or the runner image's, because versions report the same finding
under different codes. `install-shellcheck.sh <dir>` downloads the release
tarball, checks it against a pinned SHA-256 and leaves the binary at
`<dir>/shellcheck`; `check-shellcheck.sh` runs the binary named by
`SHELLCHECK`, or the `shellcheck` on `PATH` when it is unset. `ci-local.sh`
keeps the tarball in `${XDG_CACHE_HOME:-~/.cache}/fips-ci/shellcheck/`, so a
host needs the network only for its first run. If the pinned binary cannot be
installed the stage fails rather than falling back to the host's shellcheck.
The FreeBSD package workflow lints `pfsense-install-smoke.sh` with the same
pinned binary.

### Per-run isolation and the `FIPS_CI_RUN_ID` override

Every invocation derives a **run id** and scopes all of its Docker
resources to it, so two simultaneous runs on the same host (for example,
one per git worktree, or an operator testing by hand while CI is in
flight) never collide:

- **Compose projects** are named `fipsci_<run-id>_<suite>`, so
  container, network, and volume names are all prefixed per run.
- **Build images** are tagged `fips-test:<run-id>` and
  `fips-test-app:<run-id>`, exported as `FIPS_TEST_IMAGE` /
  `FIPS_TEST_APP_IMAGE`, and **every** compose file and suite script reads
  those. The run does not write `fips-test:latest` at all: a bridge back to
  that shared mutable name would let a consumer that had been missed keep
  working while resolving whichever concurrent run wrote the tag last.
  `:latest` stays the hand-build name, produced by
  `testing/scripts/build.sh`, and remains the default every consumer falls
  back to when the variables are unset.
- **The build context** is a per-run copy at `testing/docker-<run-id>/`,
  exported as `FIPS_BUILD_CONTEXT`. It is absolute because compose resolves
  a relative build context against the compose file's own directory rather
  than the working directory. `testing/docker/` is the hand-run context and
  a CI run does not write to it. Without this, two runs race on the contents
  of one directory and either can build a correctly-per-run-tagged image
  from the other's binaries.
- **The image's binaries** come from the integration build, which
  `testing/scripts/build.sh`, local CI and GitHub CI's build job all run:
  `cargo build --profile integration`, with `--features test-overrides`
  and `--bins --examples`. The `test-overrides` feature honours test-only
  configuration keys such as the maelstrom scenarios'
  `node.cache.test_coord_ttl_secs`, and the `integration` profile builds in
  `target/integration`, so no package script, which reads `target/release`,
  can pick one up. `build.sh` no longer refreshes `target/release`.
- Each parallel chaos child gets a unique, non-overlapping `/24` in
  `10.30.x` (via the sim `--subnet` override). `10.30.x` sits outside
  Docker's default address pool and the fixed-subnet suites' `172.x`
  ranges, so neither a sibling chaos child nor an auto-assigned network
  can swallow a pinned subnet.

By default the run id is `<short-git-sha>-<random>` — the SHA portion
records *what code* a container is testing, the random suffix keeps
simultaneous runs of the same SHA disjoint. Override it for a
reproducible, attach-by-name debug session:

```sh
FIPS_CI_RUN_ID=mydebug ./ci-local.sh --only static-mesh
# containers are named fipsci_mydebug_static_fips-node-a, etc.
```

`--rerun <suite>` is the fast path for the same debugging: the integration
build and that one suite, with no guards, lints or unit tests. It prints
a banner saying it is not a full local CI verdict.

### Preemption-safety and exit codes

`ci-local.sh` is safe to cancel mid-run. A signal trap tears down *every*
compose project the run started (not just the current suite) and reaps
any in-flight parallel chaos children, bounded by a `timeout` so a stuck
`compose down` cannot wedge the trap. Exit codes distinguish a cancelled
run from a failing one:

| Code | Meaning |
| ---- | ------- |
| `0`  | all stages passed |
| `1`  | one or more stages failed |
| `130` | interrupted by SIGINT — cancelled, not a failure |
| `143` | terminated by SIGTERM — cancelled, not a failure |

A preempting CI worker (the push-triggered, CI-gated build pipeline that
kills an in-flight run when a newer same-branch tip arrives) maps
`130`/`143` → *cancelled* (discard, do not record a failing commit), `0`
→ green, any other non-zero → red.

### Cleaning up leftover resources

Every CI-created container, network, and volume carries the label
`com.corganlabs.fips-ci=1`. If a run is hard-killed (SIGKILL, OOM, crash)
and leaves resources behind, reap them with:

```sh
./ci-local.sh --reap        # or: ./ci-cleanup.sh
```

[`ci-cleanup.sh`](ci-cleanup.sh) force-removes everything bearing the CI
label or a `fipsci_` compose-project prefix; it is safe to run when there
is nothing to reap and safe to run repeatedly. Pass `--project-prefix` to
scope the sweep to a single run.

It also removes the chaos simulation's leftover host-namespace veth
interfaces (`vh…a`/`vh…b`), the one resource it touches that is neither a
docker object nor labelled — a host interface can carry neither a label
nor a compose project, so it is matched by name shape alone. That makes
the reach here asymmetric with everything above, and worth stating
plainly:

- A bare `chaos.sh` run's **containers** survive a broad reap. Its
  compose project is not `fipsci_`, and the simulation labels only the
  network, not the services.
- A bare `chaos.sh` run's **veth interfaces do not.** An unscoped reap
  deletes them while they are in use, severing the Ethernet links of a
  live simulation and leaving its containers running.

So do not run a broad `--reap` while a bare simulation is up. Scope the
interface sweep with `--veth-suffixes` (which is what `ci-local.sh`'s own
teardown passes) or wait for the simulation to finish. `--project-prefix`
does not help here: it scopes only the compose-project sweep.
