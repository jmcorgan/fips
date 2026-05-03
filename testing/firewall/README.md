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

## Topology

Two FIPS nodes peered over UDP on a Docker bridge network:

| Container               | Hostname | docker IPv4   | Firewall |
|-------------------------|----------|---------------|----------|
| `fips-fw-container-a`   | `host-a` | 172.32.0.10   | none (probe) |
| `fips-fw-container-b`   | `host-b` | 172.32.0.11   | `fips.nft` + drop-in |

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
Use `--skip-build` to reuse the existing release binaries. Use
`--keep-up` to leave the containers running for inspection.

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
PASS: (a) inbound TCP/8000 blocked (curl rc=28)
=== Case (b): node-b initiates outbound TCP, expects reply via conntrack
PASS: (b) outbound from node-b got HTTP 200 via conntrack reply path
=== Case (d): drop-in allowlisted TCP/22 from node-a → node-b
PASS: (d) drop-in allowlisted TCP/22 reachable
=== Drop counter incremented (case a should have ticked it)
PASS: drop counter = N (case a was actually dropped, not just unrouted)
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

`testing/firewall/generated-configs/` (gitignored).
