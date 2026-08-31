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
check which peer pairs are admitted and which are rejected.

### [native-api/](native-api/) -- Native Datagram API

Checks the experimental native datagram API: a client process opens a
flow to a remote pubkey over a Unix socket, receives a file descriptor,
and exchanges datagrams on it with no TUN device and no IPv6 emulation.

### [dns-resolver/](dns-resolver/) -- `fips-dns-setup` Backends

Runs `fips-dns-setup` against each supported Linux resolver backend in
systemd containers, verifying backend detection, generated config and
teardown, plus an end-to-end scenario that resolves a `.fips` name
through the configured backend.

### [deb-install/](deb-install/) -- Debian Package Install

Installs the built `.deb` in privileged systemd containers for each
target distro and verifies unit enablement, conffile placement and
end-to-end `.fips` resolution as a user would meet it.

### [boringtun/](boringtun/) -- WireGuard Throughput Baseline

Two userspace WireGuard peers running Cloudflare BoringTun, measured
with `iperf3`, as a comparison baseline for FIPS tunnel throughput.

### [ble/](ble/) -- BLE L2CAP Spike

Standalone cargo project (`ble_spike`) that validates the `bluer` API
assumptions behind the `BleIo` trait against real adapters on two
machines. Not a Docker harness.

## Running CI locally (`ci-local.sh`)

[`ci-local.sh`](ci-local.sh) runs the full local CI pipeline — build,
clippy, unit tests, and the integration suites (including the chaos
scenarios) — mirroring the GitHub `ci.yml` integration matrix. Run
`./ci-local.sh --help` for the full option list and `--list` for the
available suites. Every run starts with a parity check that verifies the
local suite set covers the same work as the GitHub matrix, per scenario for
chaos and per distro for deb-install; a divergence fails the run. GitHub
runs the same check as its own `ci-parity` job. `--check-parity` runs it
alone (see [check-ci-parity.sh](check-ci-parity.sh)).

Note that `ci-local.sh` covers the integration suites and the glibc unit
tests. GitHub additionally runs the library tests on macOS, Windows and
**musl** (built for the musl target and run natively), and a `--features
profiling` pass; the musl
leg exists because interface presence is built on `getifaddrs`/`ifa_flags`,
which musl reimplements independently, and OpenWrt is a musl target. A local
green run does not certify those four.

The Linux and musl legs also create an address-less dummy interface
(`fips-probe0`) and pass its name to the tests as
`FIPS_TEST_ADDRLESS_IFACE`. That is the one assumption the interface-binding
mechanism rests on that no ordinary test can reach: loopback has addresses, so
probing it asks whether `getifaddrs` works rather than whether it reports an
interface that has none — which is exactly what `fips-mesh0` and `fips-ap0`
are on OpenWrt. Set the variable by hand to run the assertion locally against
an interface you have created; leave it unset and the assertion does not run.

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
