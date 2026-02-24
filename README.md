# FIPS: Free Internetworking Peering System

A distributed, decentralized network routing protocol for mesh nodes
connecting over arbitrary transports.

> **Status: Experimental / Pre-release**
>
> FIPS is under active development. The protocol and APIs are not stable.
> Expect breaking changes.

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
- **Zero configuration** — sensible defaults; a node can run with no config
  file

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
# With default configuration (ephemeral identity, default ports):
sudo ./target/release/fips

# With a configuration file:
sudo ./target/release/fips -c fips.yaml
```

See [docs/design/fips-configuration.md](docs/design/fips-configuration.md) for
the full configuration reference.

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
benches/      Criterion benchmarks
```

## License

MIT — see [LICENSE](LICENSE).
