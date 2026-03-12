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
allowing users to generate their own persistent or ephemeral node addresses.
Nodes address each other by npub, and the same cryptographic identity serves
as both the routing address and the basis for end-to-end encrypted sessions
across the mesh.

FIPS allows existing TCP/IP based network software to use the FIPS mesh
network by generating a local IP address from the node npub and tunnelling
IP packets to other endpoints transparently knowing only their npub. Native
FIPS-aware applications do not need this IP tunneling or emulation capability.

All traffic over the FIPS mesh is encrypted and authenticated both
hop-to-hop between peers and independently end-to-end between FIPS
endpoints.

## Features

- **Self-organizing mesh routing** — spanning tree coordinates and bloom
  filter candidate selection, no global routing tables
- **Multi-transport** — UDP, TCP, and Ethernet today; designed for
  Bluetooth, serial, radio, and Tor
- **Noise encryption** — hop-by-hop link encryption plus independent
  end-to-end session encryption, with periodic rekey for forward secrecy
- **Nostr-native identity** — secp256k1 keypairs as node addresses, no
  registration or central authority
- **IPv6 adaptation** — TUN interface maps npubs to fd00::/8 addresses for
  unmodified IP applications; static hostname mapping (`/etc/fips/hosts`)
- **Metrics Measurement Protocol** — per-link RTT, loss, jitter, and goodput
  measurement
- **ECN congestion signaling** — hop-by-hop CE flag relay with RFC 3168 IPv6
  marking, transport kernel drop detection
- **Operator visibility** — `fipsctl` CLI and `fipstop` TUI dashboard for
  runtime inspection of peers, links, sessions, tree state, and metrics
- **Zero configuration** — sensible defaults; a node can start with no config
  file, though peer addresses are needed to join a network

## Building

```bash
git clone https://github.com/jmcorgan/fips.git
cd fips
cargo build --release
```

Requires Rust 1.85+ (edition 2024) and Linux with TUN support.

## Installation

After building, choose one of the following methods to install.

### Debian / Ubuntu (.deb)

Requires [cargo-deb](https://crates.io/crates/cargo-deb):

```bash
cargo install cargo-deb
cargo deb
sudo dpkg -i target/debian/fips_*.deb
```

This installs the daemon, CLI tools, systemd units, and a default
configuration. Edit `/etc/fips/fips.yaml` before starting:

```bash
sudo nano /etc/fips/fips.yaml
sudo systemctl start fips
```

The service is enabled at boot automatically. To use `fipsctl` and
`fipstop` without sudo, add your user to the `fips` group:

```bash
sudo usermod -aG fips $USER    # log out and back in to take effect
```

Remove with `sudo dpkg -r fips` (preserves config) or
`sudo dpkg -P fips` (removes everything including identity keys).

### Generic Linux (systemd tarball)

```bash
./packaging/systemd/build-tarball.sh
tar xzf deploy/fips-*-linux-*.tar.gz
cd fips-*-linux-*/
sudo ./install.sh
```

See [packaging/systemd/README.install.md](packaging/systemd/README.install.md)
for the full installation and configuration guide.

## Configuration

The default configuration file is installed at `/etc/fips/fips.yaml`:

```yaml
# FIPS Node Configuration

node:
  identity:
    # By default, a new ephemeral keypair is generated on each start.
    # Uncomment persistent to keep the same identity across restarts;
    # on first start a keypair is saved to fips.key/fips.pub next to
    # this config file (mode 0600/0644).
    # persistent: true
    #
    # Or set an explicit key (overrides persistent):
    # nsec: "nsec1..."

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"
  port: 5354

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

  tcp:
    # Accepts inbound connections. No static outbound peers.
    bind_addr: "0.0.0.0:8443"

  # Ethernet transport — uncomment and set your interface name.
  # ethernet:
  #   interface: "eth0"
  #   discovery: true
  #   announce: true
  #   auto_connect: true
  #   accept_connections: true

peers:
  # Static peers for bootstrapping (UDP or TCP):
  - npub: "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98"
    alias: "fips-test-node"
    addresses:
      - transport: udp
        addr: "217.77.8.91:2121"
    connect_policy: auto_connect
```

See [docs/design/fips-configuration.md](docs/design/fips-configuration.md)
for the full reference.

## Usage

### DNS Resolution

FIPS includes a DNS resolver (enabled by default, port 5354) that maps
`.fips` names to fd00::/8 IPv6 addresses. With systemd-resolved:

```bash
sudo resolvectl dns fips0 127.0.0.1:5354
sudo resolvectl domain fips0 ~fips
```

Then reach any FIPS node by npub with standard IPv6 tools:

```bash
ping6 npub1bbb....fips
ssh   npub1bbb....fips
```

### Monitoring

Use `fipsctl` to query a running node:

```bash
fipsctl show status       # Node status overview
fipsctl show peers        # Authenticated peers
fipsctl show links        # Active links
fipsctl show tree         # Spanning tree state
fipsctl show sessions     # End-to-end sessions
fipsctl show transports   # Transport instances
fipsctl show routing      # Routing table summary
```

`fipstop` provides an interactive TUI dashboard with live-updating
views of node status, peers, links, sessions, tree state, transports,
and routing:

```bash
fipstop                   # connect to local daemon
fipstop -r 1              # 1-second refresh interval
```

### Service Management

```bash
sudo systemctl start fips
sudo systemctl stop fips
sudo systemctl restart fips
sudo journalctl -u fips -f
```

### Testing

See [testing/](testing/) for Docker-based integration test harnesses
including static topology tests and stochastic chaos simulation.

## Documentation

Protocol design documentation is in [docs/design/](docs/design/), organized as
a layered protocol specification. Start with
[fips-intro.md](docs/design/fips-intro.md) for the full protocol overview.

## Project Structure

```
src/          Rust source (library + fips/fipsctl/fipstop binaries)
packaging/    Debian, systemd tarball, and shared packaging files
docs/design/  Protocol design specifications
testing/      Docker-based integration test harnesses
```

## Status & Roadmap

FIPS is at **v0.1.0 (alpha)**. The core protocol works end-to-end over
UDP, TCP, and Ethernet but has not been tested beyond small meshes.

### What works today

- Spanning tree construction with greedy coordinate routing
- Bloom filter discovery for finding nodes without global state
- Noise IK (link layer) and Noise XK (session layer) encryption
- Periodic Noise rekey with forward secrecy (FMP + FSP)
- Persistent node identity with key file management
- IPv6 TUN adapter with DNS resolution of `.fips` names
- Static hostname mapping (`/etc/fips/hosts`) with auto-reload
- Per-link metrics (RTT, loss, jitter, goodput) and mesh size estimation
- ECN congestion signaling (hop-by-hop CE relay, IPv6 CE marking, kernel drop detection)
- UDP, TCP, and Ethernet transports
- Runtime inspection via `fipsctl` and `fipstop`
- Docker-based integration and chaos testing

### Near-term priorities

- Peer discovery via Nostr relays (bootstrap without static peer lists)
- Additional transports (Bluetooth, Tor)
- Improved routing resilience under churn
- Security audit of cryptographic protocols

### Longer-term

- Mobile platform support
- Bandwidth-aware routing and QoS
- Protocol stability and versioned wire format
- Published crate

## License

MIT — see [LICENSE](LICENSE).
