# NAT Lab Harness

Real Docker-based NAT traversal integration tests for the mainline
FIPS Nostr/STUN bootstrap path.

This harness spins up:

- two FIPS nodes
- a local Nostr relay
- a local STUN server
- one or two Linux router containers performing NAT with `iptables`

For the NAT scenarios, the node LAN interfaces are not attached to
Docker bridge networks. The harness creates explicit `veth` pairs and
moves them into the node and router namespaces after `docker compose up`
so every packet must traverse the router namespace.

It covers three scenarios:

- `cone`: both peers behind explicit namespace/veth full-cone emulation, UDP traversal succeeds
- `symmetric`: both peers behind symmetric-style NAT, UDP traversal fails, TCP fallback succeeds
- `lan`: both peers share a LAN subnet, LAN targets are preferred over reflexive addresses

## NAT model notes

The harness does not rely on plain Docker `MASQUERADE` for the cone case.

- `cone`
  - uses explicit full-cone emulation in the router namespace
  - outbound UDP is `SNAT`ed to the router WAN address while preserving the source port
  - inbound UDP to the router WAN address is `DNAT`ed back to the single LAN host regardless of remote source
- `symmetric`
  - uses UDP `MASQUERADE --random-fully`
  - outbound mappings may be port-randomized and are only reopened by matching conntrack state

This distinction matters because plain `MASQUERADE` is convenient source NAT, but it does not by itself model the "accept from any remote once mapped" behavior expected from a full-cone NAT.

## Prerequisites

- Docker with Compose support
- locally built `fips-test:latest`

Build the test image with:

```bash
./testing/scripts/build.sh
```

## Run

Run all scenarios:

```bash
./testing/nat/scripts/nat-test.sh
```

Run one scenario:

```bash
./testing/nat/scripts/nat-test.sh cone
./testing/nat/scripts/nat-test.sh symmetric
./testing/nat/scripts/nat-test.sh lan
```

## Layout

- `docker-compose.yml`
  - relay/STUN/WAN topology plus container definitions
- `node/`
  - node bootstrap wrapper that waits for the injected veth interface
    (`IFACE_WAIT_SECS`)
- `router/`
  - NAT router image and `iptables` setup
- `stun/`
  - minimal STUN binding responder
- `relay/`
  - local `strfry` config. The relay image's strfry build is pinned by digest
    in `docker-compose.yml` (`STRFRY_IMAGE`); bump it there deliberately.
- `scripts/generate-configs.sh`
  - derives ephemeral identities and writes per-scenario FIPS configs
- `scripts/setup-topology.sh`
  - injects and configures the NAT LAN `veth` pairs in the container
    namespaces; see "Start order and interface waits"
- `scripts/nat-test.sh`
  - boots the lab, waits for convergence, and asserts the resulting path
- `scripts/nostr-relay-test.sh`
  - exercises the Nostr overlay advert publish/consume round-trip, including
    rejection of a malformed advert event
- `scripts/stun-faults-test.sh`
  - cycles the daemon through STUN drop, delay and outage faults and asserts
    graceful behavior at each step
- `scripts/nostr-open-discovery-test.sh`
  - opt-in: seeds the relay with adverts from fresh keys (the `nostr-seed`
    service, publishing with `testing/lib/nostr-publish.py`), then starts one
    node with `policy: open` and no configured peers, and requires it to cache
    every seeded advert within 10 s of its notify loop starting. Run it with
    `./testing/ci-local.sh --only nostr-open-discovery`; neither local CI's
    default run nor GitHub CI runs it

## Start order and interface waits

The `cone` and `symmetric` starts run in this order:

1. `docker compose up -d` starts the relay, STUN, both routers and both nodes.
   The routers have only their WAN interface and the nodes have none
   (`network_mode: none`).
2. Each entrypoint then waits for the interface the harness will give it:
   a node for an IPv4 address on `eth0` (`node/entrypoint.sh`), a router
   for `eth1` (`router/entrypoint.sh`).
3. `scripts/setup-topology.sh` wires the pairs one after the other. For
   each pair it checks that both containers are still running, then runs
   one helper container (the router image, `--net=host --pid=host`) that
   deletes any stale interfaces, creates the `veth` pair and moves each end
   into its container's namespace. It then renames and addresses the ends
   with `docker exec`, which is what ends both waits.

The interface waits are bounded by `IFACE_WAIT_SECS`, 120 s by default and
set in each entrypoint rather than in `docker-compose.yml`. The relay and
STUN waits in the node entrypoint keep their own `WAIT_TIMEOUT_SECS`
(30 s). The interface bound covers harness setup, not product behaviour:
starting a container has been measured at 3 to 15 s at a time while other
labs start on the same Docker daemon, and the earlier 30 s bound with five
helper containers per pair was overrun often enough to fail the suite.

When a wait does run out, the container says so in its log and exits, and
`setup-topology.sh` fails with `<container> exited (code N) before its
interface was moved`, followed by the end of that container's log.

## Assertions

- `cone`
  - both nodes connect
  - connected transport is UDP
  - active link remote addresses are on the WAN NAT subnet

- `symmetric`
  - NAT bootstrap does not establish a UDP link
  - fallback converges
  - connected transport is TCP via router-published WAN addresses

- `lan`
  - both nodes connect
  - connected transport is UDP
  - active link remote addresses stay on the shared LAN subnet
