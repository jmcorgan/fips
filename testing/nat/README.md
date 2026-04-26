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
- `router/`
  - NAT router image and `iptables` setup
- `stun/`
  - minimal STUN binding responder
- `relay/`
  - local `strfry` config
- `scripts/generate-configs.sh`
  - derives ephemeral identities and writes per-scenario FIPS configs
- `scripts/setup-topology.sh`
  - injects and configures the NAT LAN `veth` pairs in the container namespaces
- `scripts/nat-test.sh`
  - boots the lab, waits for convergence, and asserts the resulting path

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
