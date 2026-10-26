# Firewall Baseline Test

End-to-end exercise of the production fips0 nftables baseline at
`packaging/common/fips.nft`. Closes the v0.3.0 audit gap that the
default-deny + conntrack + drop-in semantics had no integration coverage.

## What this exercises

The `fips.nft` baseline polices ONLY the fips0 mesh interface and
implements default-deny inbound. This suite asserts the four behaviors
documented in the file's header are actually true on a live mesh:

- **(a)** Unallowed inbound on fips0 is **dropped**
- **(b)** Outbound-initiated flows get their reply via the
  `ct state established,related accept` rule
- **(c)** ICMPv6 echo-request is **accepted** (ping6 reachability)
- **(d)** A drop-in `.nft` file under `/etc/fips/fips.d/` adds an
  allowlisted port and that port is **accepted**

A drop-counter check after case (a) confirms the connection was
actively DROP'd by the fips chain (not silently unrouted).

- **(e)** The file's chain is scoped by `iifname != $fips_if return`, so
  a table scoped to an interface that is not the TUN polices nothing on
  it. The suite loads the production file with its interface name
  rewritten to `notfips0`, asserts that node-a then reaches the case-(a)
  port and that the `show_listening_sockets` reply of node-b's IPv6
  adapter status socket (`control-ipv6tun.sock`, beside the control
  socket) reports `firewall_active: false`, then reloads the real file
  and asserts the port is dropped again and the reply reads `true`. The
  reply is read once with the real file loaded before the rewrite, so an
  adapter socket that does not answer fails the case instead of passing
  it.

## Files

- `test.sh`: the suite; starts the two nodes and runs cases (a) to (e).
- `generate-configs.sh`: writes the node configs and the drop-in.
- `docker-compose.yml`: the two-node topology.
- `table-check.sh`: `table_has`, sourced by `test.sh`; reports whether a
  container's `inet fips` table contains a given rule.
- `table-check-test.sh`: hermetic cases for `table_has`, run as a guard by
  `ci-local.sh` and by GitHub CI.

`table_has` captures the whole `nft list table` output before matching it.
Piping `docker exec` straight into `grep -q` under `pipefail` fails a rule
that is present: `grep` exits at its match, the exec client still writing the
rest of the listing takes SIGPIPE, and the pipeline reports failure. It
returns 2 when the listing cannot be read, so case (e) tells "the rule is
absent" apart from "the table could not be listed". `table-check-test.sh`
replaces `docker` with a stand-in that pauses after the matching line, which
is the race's shape, and fails against the piped form.

## Topology

Two FIPS nodes peered over UDP on a Docker bridge network:

| Container               | Hostname | Firewall |
|-------------------------|----------|----------|
| `fips-fw-container-a`   | `host-a` | none (probe) |
| `fips-fw-container-b`   | `host-b` | `fips.nft` + drop-in |

The bridge network requests no subnet, so docker assigns one from its own
address pool and two concurrent runs never contend for a fixed range. No
node's IPv4 address is therefore known before startup, and the generated peer
stanzas address each other by docker hostname, resolved through the
container's dnsmasq to docker's embedded DNS. The firewall assertions
themselves are unaffected: they run over the fips0 overlay, whose addresses
are derived from the node npubs.

`node-b` mounts the production `packaging/common/fips.nft` read-only at
`/etc/fips/fips.nft`, plus a drop-in at `/etc/fips/fips.d/services.nft`
containing `tcp dport 22 accept`. `node-a` is unfirewalled and serves
as the probe origin.

Both containers run the unified test image's `default` mode, which
starts dnsmasq + sshd (port 22) + iperf3 + python http.server on
port 8000 + the FIPS daemon.

## fips-firewall.service activation

The production unit's ExecStart is:

```text
ExecStart=/usr/sbin/nft -f /etc/fips/fips.nft
```

The unified test image does not run systemd, so `test.sh` invokes the
same `nft -f` command directly inside `node-b` after fips0 is up and
peering has converged. The deb-install harness covers the systemd
unit-enablement path under real systemd separately.

## Run

Build the Linux binaries and test image:

```bash
./testing/scripts/build.sh --no-docker
```

Run the suite:

```bash
./testing/firewall/test.sh
```

`test.sh` regenerates fixtures automatically before starting Docker.
Use `--skip-build` to reuse the existing release binaries and the
existing test image: the suite then neither builds nor pulls the image
named by `FIPS_TEST_IMAGE` (default `fips-test:latest`), so that image
must already exist. Use `--keep-up` to leave the containers running for
inspection.

## Expected output shape

```text
=== Generating firewall fixtures
=== Starting firewall harness
=== Waiting for fips0 on both nodes
=== Waiting for peer convergence
=== Resolving fips0 addresses
  node-a: fd97:...
  node-b: fd97:...
=== Activating fips-firewall on fips-fw-container-b
PASS: fips-fw-container-b: fips.nft baseline + drop-in loaded
=== Case (c): ICMPv6 echo-request to firewalled node
PASS: (c) ICMPv6 ping node-a → node-b accepted
=== Case (a): unallowed inbound TCP/8000 from node-a → node-b
PASS: (a) inbound TCP/8000 dropped (curl rc=28, timed out as expected)
=== Case (b): node-b initiates outbound TCP, expects reply via conntrack
PASS: (b) outbound from node-b got HTTP 200 via conntrack reply path
=== Case (d): drop-in allowlisted TCP/22 from node-a → node-b
PASS: (d) drop-in allowlisted TCP/22 reachable
=== Drop counter incremented (case a should have ticked it)
PASS: drop counter = N (case a was actually dropped, not just unrouted)
=== Case (e): fips.nft scoped to an interface that is not the TUN
PASS: (e) table scoped to notfips0 does not police fips0: TCP/8000 reachable
PASS: (e) listener report shows the firewall as not policing the TUN
PASS: fips-fw-container-b: fips.nft baseline + drop-in loaded
PASS: (e) real fips.nft reloaded: TCP/8000 dropped and the report shows the firewall active
=== Firewall integration test passed
```

## Inspect the loaded ruleset

```bash
docker exec fips-fw-container-b nft list table inet fips
```

## Stop and clean up

```bash
docker compose -f testing/firewall/docker-compose.yml down
```

## Generated fixture location

`testing/firewall/generated-configs/` (gitignored), or
`generated-configs<suffix>/` when `FIPS_CI_NAME_SUFFIX` is set, which is how
concurrent runs keep their fixtures apart.
