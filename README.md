# FIPS: Free Internetworking Peering System

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-alpha%20(0.1.0)-yellow.svg)](#status--roadmap)

A distributed, decentralized network routing protocol for mesh nodes
connecting over arbitrary transports.

> **Status: Alpha (0.1.0)**
>
> FIPS is under active development. The protocol and APIs are not stable.
> Expect breaking changes. See [Status & Roadmap](#status--roadmap) below.

## Overview

FIPS is a self-organizing mesh network that operates natively over a variety
of physical and logical media — local area networks, Bluetooth, serial links,
radio, or the existing internet as an overlay. Nodes generate their own
identities, discover each other, and route traffic without any central
authority or global topology knowledge.

FIPS uses Nostr keypairs (secp256k1/schnorr) as native node identities,
making every Nostr user a potential network participant. Nodes address each
other by npub, and the same cryptographic identity used in the Nostr ecosystem
serves as both the routing address and the basis for end-to-end encrypted
sessions across the mesh.

## Why

DNS is a single point of control. 

Domain seizures, DNS poisoning, and registrar suspensions are routinely used to take services offline, often without due process.

| Project | Approach | Limitation |                                                                                                                                  
  |---------|----------|------------|                                                                                                                                
  | Tor .onion | Key hash → address | Internet-only overlay |                                                                                                          
  | CJDNS | Key → `fc00::/8` IPv6 | Internet-only overlay |                                                                                                          
  | Yggdrasil | Key → `200::/7` IPv6 | Internet-only overlay |                                                                                                         
                                                                  
All three eliminate DNS. But all three require the internet underneath. If the infrastructure goes down, they go down with it.

FIPS eliminates DNS the same way — public key is your address — but doesn't depend on the internet to function. The [FIPS transport layer](https://github.com/jmcorgan/fips/blob/master/docs/design/fips-transport-layer.md) is pluggable: UDP today, and also designed for radio/Bluetooth/serial. The mesh routes traffic without any central infrastructure.

FIPS uses [nostr](https://fiatjaf.com/nostr.html) keypairs as node identity, making it a potential physical transport layer for the Nostr ecosystem — carrying relay traffic over mesh links when the internet is unavailable.


## Features

- **Self-organizing mesh routing** — spanning tree coordinates and bloom
  filter candidate selection, no global routing tables
- **Multi-transport** — UDP/IP overlay today; designed for Ethernet,
  Bluetooth, serial, radio, and Tor
- **Noise encryption** — hop-by-hop link encryption plus independent
  end-to-end session encryption
- **Nostr-native identity** — secp256k1 keypairs as node addresses, no
  registration or central authority
- **IPv6 adaptation** — TUN interface maps npubs to fd00::/8 addresses for
  unmodified IP applications
- **Metrics Measurement Protocol** — per-link RTT, loss, jitter, and goodput
  measurement
- **Operator visibility** — `fipsctl` control socket interface for runtime
  inspection of peers, links, sessions, tree state, and metrics
- **Zero configuration** — sensible defaults; a node can start with no config
  file, though peer addresses are needed to join a network

## Quick Start

### Requirements

- Rust 1.85+ (edition 2024)
- Linux (TUN interface requires `CAP_NET_ADMIN` or root)

### Build

```
git clone https://github.com/jmcorgan/fips.git
cd fips
cargo build --release
```

### Run

```
# Start with default search paths (see below):
sudo ./target/release/fips

# With an explicit configuration file:
sudo ./target/release/fips -c fips.yaml
```

Without `-c`, the node searches for `fips.yaml` in these locations
(highest priority first, values from later files override earlier ones):

1. `./fips.yaml` (current directory)
2. `~/.config/fips/fips.yaml` (user config)
3. `/etc/fips/fips.yaml` (system)

If no config file is found, the node starts with defaults (ephemeral
identity, default ports, no peers).

A minimal two-node setup (each node points at the other):

```yaml
# node-a.yaml                          # node-b.yaml
node:                                  # node:
  identity:                            #   identity:
    nsec: "nsec1aaa..."                #     nsec: "nsec1bbb..."
transports:                            # transports:
  udp:                                 #   udp:
    bind_addr: "0.0.0.0:4000"          #     bind_addr: "0.0.0.0:4000"
peers:                                 # peers:
  - npub: "npub1bbb..."                #   - npub: "npub1aaa..."
    addresses:                         #     addresses:
      - transport: udp                 #       - transport: udp
        addr: "10.0.0.2:4000"          #         addr: "10.0.0.1:4000"
```

The `nsec` field accepts bech32 (`nsec1...`) or hex-encoded secret keys.
Omit it entirely for an ephemeral identity that changes each restart.

See [docs/design/fips-configuration.md](docs/design/fips-configuration.md) for
the full configuration reference.

### Test Connectivity

FIPS includes a built-in DNS resolver (enabled by default, port 5354)
that maps `.fips` names to fd00::/8 IPv6 addresses derived from each
node's public key. Configure your system to send `.fips` queries to it.

With systemd-resolved:

```
sudo resolvectl dns fips0 127.0.0.1:5354
sudo resolvectl domain fips0 ~fips
```

Or manually in `/etc/resolv.conf` (routes all DNS through FIPS for
`.fips` names only if your resolver supports conditional forwarding;
otherwise this sets it as a general nameserver):

```
nameserver 127.0.0.1
options port:5354
```

Once DNS is configured, ping a peer by npub:

```
ping6 npub1bbb....fips
```

Any IPv6-capable application can reach FIPS nodes this way — `ping6`,
`ssh`, `curl`, etc.

### Inspect

While a node is running, use `fipsctl` to inspect its state:

```
fipsctl show status       # Node status overview
fipsctl show peers        # Authenticated peers
fipsctl show links        # Active links
fipsctl show tree         # Spanning tree state
fipsctl show sessions     # End-to-end sessions
fipsctl show bloom        # Bloom filter state
fipsctl show mmp          # MMP metrics summary
fipsctl show cache        # Coordinate cache stats
fipsctl show connections  # Pending handshake connections
fipsctl show transports   # Transport instances
fipsctl show routing      # Routing table summary
```

`fipsctl` communicates with the node via a Unix domain control socket
(enabled by default). All queries are read-only. Use `-s <path>` to
override the socket path.

### Multi-node Testing

See [testing/](testing/) for Docker-based integration test harnesses including
static topology tests and stochastic chaos simulation.

## Documentation

Protocol design documentation is in [docs/design/](docs/design/), organized as
a layered protocol specification. Start with
[fips-intro.md](docs/design/fips-intro.md) for the full protocol overview.

## Project Structure

```
src/          Rust source (library + fips/fipsctl binaries)
docs/design/  Protocol design specifications
testing/      Docker-based integration test harnesses
```

## Status & Roadmap

FIPS is at **v0.1.0 (alpha)**. The core protocol works end-to-end over
UDP/IP overlays but has not been tested beyond small meshes.

### What works today

- Spanning tree construction with greedy coordinate routing
- Bloom filter discovery for finding nodes without global state
- Noise IK (link layer) and Noise XK (session layer) encryption
- IPv6 TUN adapter with DNS resolution of `.fips` names
- Per-link metrics (RTT, loss, jitter, goodput)
- Runtime inspection via `fipsctl`
- Docker-based integration and chaos testing

### Near-term priorities

- Peer discovery via Nostr relays (bootstrap without static peer lists)
- Additional transports (Ethernet, Tor)
- Improved routing resilience under churn
- Security audit of cryptographic protocols
- CI pipeline and published crate

### Longer-term

- Mobile platform support
- Bandwidth-aware routing and QoS
- Protocol stability and versioned wire format

## License

MIT — see [LICENSE](LICENSE).
