# Docker Network Test Harness

Multi-node integration test for FIPS using Docker containers. Two topologies
are provided: a sparse mesh (5 nodes, 6 links) and a linear chain (5 nodes,
4 links). Both exercise the full FIPS stack including TUN devices, DNS
resolution, peer link encryption, spanning tree construction, and
discovery-driven multi-hop routing.

## Prerequisites

- Docker with the compose plugin
- Rust toolchain (for building the FIPS binary)

## Quick Start

Build the binary and copy it to the docker context:

```bash
./scripts/build.sh
```

### Mesh Topology

```bash
docker compose --profile mesh build
docker compose --profile mesh up -d
./scripts/ping-test.sh mesh      # 20/20 expected
docker compose --profile mesh down
```

### Chain Topology

```bash
docker compose --profile chain build
docker compose --profile chain up -d
./scripts/ping-test.sh chain     # 6/6 expected
docker compose --profile chain down
```

## Mesh Topology

![Mesh Topology](docker-mesh-topology.svg)

Five nodes with 6 bidirectional UDP links forming a sparse, fully connected
graph. Not all nodes are direct peers — non-adjacent pairs require
discovery-driven multi-hop routing to establish end-to-end sessions.

The spanning tree is rooted at node A, which has the lexicographically
smallest `NodeAddr` (the first 16 bytes of `SHA-256(pubkey)`). Tree edges
are highlighted in blue in the diagram above.

The ping test exercises all 20 directed pairs (5 nodes x 4 targets each),
covering both direct-peer and multi-hop paths.

| Link | Type |
|------|------|
| A — D | tree edge (D's parent is A) |
| A — E | tree edge (E's parent is A) |
| C — D | tree edge (C's parent is D) |
| B — C | tree edge (B's parent is C) |
| D — E | non-tree link |
| C — E | non-tree link |

## Chain Topology

![Chain Topology](docker-chain-topology.svg)

Five nodes in a linear chain: A — B — C — D — E. Each node peers only with
its immediate neighbors. Multi-hop communication (e.g., A to E) requires the
discovery protocol to find routes through intermediate nodes.

The ping test covers:

- Adjacent hops: A→B, B→C (1 hop each)
- Multi-hop: A→C (2 hops), A→D (3 hops), A→E (4 hops)
- Reverse: E→A (4 hops)

## Node Identities

All nodes use deterministic test keys (not for production use).

| Node | npub | FIPS IPv6 Address | Docker IP |
|------|------|-------------------|-----------|
| A | `npub1sjlh2c3...` | `fd69:e08d:65cc:3a6b:...` | 172.20.0.10 |
| B | `npub1tdwa4vj...` | `fd8e:302c:287e:b48d:...` | 172.20.0.11 |
| C | `npub1cld9yay...` | `fdac:a221:4069:5044:...` | 172.20.0.12 |
| D | `npub1n9lpnv0...` | `fdb6:8411:a191:6d48:...` | 172.20.0.13 |
| E | `npub1wf8akf8...` | `fded:7dee:d386:a546:...` | 172.20.0.14 |

## Container Configuration

- **Base image**: debian:bookworm-slim
- **Capabilities**: `CAP_NET_ADMIN` (for TUN device creation)
- **Devices**: `/dev/net/tun` mapped into each container
- **DNS**: FIPS built-in resolver on `127.0.0.1:53`
- **Transport**: UDP on port 4000, MTU 1280
- **TUN**: `fips0` interface, MTU 1280

Each node resolves `<npub>.fips` DNS names to FIPS IPv6 addresses via its
local DNS responder, which primes the identity cache for session establishment.

## Troubleshooting

**Stale images after code changes**: Docker compose may cache old layers.
Force a clean rebuild:

```bash
docker compose --profile mesh build --no-cache
```

**Check node logs**:

```bash
docker logs fips-node-a
docker logs -f fips-node-c    # follow
```

**Verify DNS resolution inside a container**:

```bash
docker exec fips-node-a dig AAAA npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le.fips @127.0.0.1
```

**Verify binary is up to date**: Compare hashes between the local build and
the binary inside the container:

```bash
md5sum examples/docker-network/fips
docker exec fips-node-a md5sum /usr/local/bin/fips
```

**Increase convergence time**: If tests fail intermittently, the 5-second
convergence wait in `ping-test.sh` may be insufficient. Edit the `sleep`
value at the top of the script.
