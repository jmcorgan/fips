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

### [chaos/](chaos/) -- Stochastic Simulation

Automated network testing with configurable node counts, topology
algorithms (random geometric, Erdos-Renyi, chain, explicit), and fault
injection (netem mutation, link flaps, traffic generation, node
churn). 10 scenarios covering general stress and node churn, discovery
over sparse topologies, spanning-tree and bloom-propagation regression,
transport-specific validation (UDP, TCP, Ethernet), and ECN/congestion
testing. Scenarios are
defined in YAML and executed via a Python harness that manages the full
lifecycle: topology generation, Docker orchestration, fault scheduling,
log collection, and analysis.

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
isolation.

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
what the real `build-apk.sh` and `build-ipk.sh` package. No router,
opkg or apk-tools is involved. Part of both CI runners as
`openwrt-scripts`.

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
unchanged) and that the far side re-pins to the new source address.

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
its time and mirrors. The image keeps its repository metadata, and the
install, erase and upgrade read it rather than fetching it again.

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

## Running CI locally (`ci-local.sh`)

[`ci-local.sh`](ci-local.sh) runs the full local CI pipeline — build,
clippy, unit tests, and the integration suites (including the chaos
scenarios) — mirroring the GitHub `ci.yml` integration matrices. Run
`./ci-local.sh --help` for the full option list and `--list` for the
available suites. Every run starts with a parity check that verifies the
local suite set covers the same work as the GitHub matrix, per scenario for
chaos, per distro for deb-install and per scenario for rpm-install, across
every job that carries a
matrix; a divergence fails the run. GitHub
runs the same check as its own `ci-parity` job. `--check-parity` runs it
alone (see [check-ci-parity.sh](check-ci-parity.sh)).

Note that `ci-local.sh` covers the integration suites and the glibc unit
tests. GitHub additionally runs the library tests on macOS, Windows and
**musl** (built for the musl target and run natively); the musl
leg exists because interface presence is built on `getifaddrs`/`ifa_flags`,
which musl reimplements independently, and OpenWrt is a musl target. A local
green run does not certify those three. Both runners also run the root
library tests once more with the root crate's optional features
(`--features profiling,test-overrides`) enabled.
GitHub's `core-baremetal` job also builds the `no_std` core for two
bare-metal targets on every push; a local run does that only with
`--baremetal` or `FIPS_CI_BAREMETAL=1`.
GitHub's Linux test job also runs fips-core's slow test suite (the
guard-switch meta-test, behind the core's `slow-tests` feature) on every push;
a local run does that only with `--slow-tests` or `FIPS_CI_SLOW_TESTS=1`.
Every other platform's test run skips it.

The Linux and musl legs also create an address-less dummy interface
(`fips-probe0`) and pass its name to the tests as
`FIPS_TEST_ADDRLESS_IFACE`. That is the one assumption the interface-binding
mechanism rests on that no ordinary test can reach: loopback has addresses, so
probing it asks whether `getifaddrs` works rather than whether it reports an
interface that has none — which is exactly what `fips-mesh0` and `fips-ap0`
are on OpenWrt. Set the variable by hand to run the assertion locally against
an interface you have created; leave it unset and the assertion does not run.

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
here and on GitHub. It runs each `known-defect` test and expects it to fail:
one that passes reds the lane, so the change that fixes a defect also removes
its ignore and its inventory line, and the test gates from then on. It also
lists the ignored tests of each library test binary and reds on one the
inventory does not name under its full path. Each test runs under a timeout
(`FIPS_KNOWN_DEFECT_TIMEOUT`, default 120 s) that counts as still failing,
since a defect can be a hang; a fixed test slower than the timeout would
therefore not be noticed. Tests the host does not compile, such as the macOS
hardware tests on Linux, are checked only by the static guard.

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
as the runner user and runs the script under `sudo`; `ci-local.sh
--root-tests` (or `FIPS_CI_ROOT_TESTS=1`) does the same under `sudo -n`,
recorded as `root-tests`, and is off by default because the internal builder
runs `ci-local.sh` without `sudo` and is to run the script itself in a
container.

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
