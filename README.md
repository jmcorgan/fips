# FIPS: Free Internetworking Peering System

![banner](docs/logos/fips_banner.png)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-v0.5.0--dev-green.svg)](#status--roadmap)

A self-organizing encrypted mesh network built on Nostr identities,
capable of operating over arbitrary transports without central
infrastructure.

> FIPS is under active development. The protocol and APIs are not
> yet stable. See [Status & roadmap](#status--roadmap) below.

## What FIPS does

A machine running FIPS becomes a node in the mesh with a
self-generated cryptographic identity (a Nostr keypair). There are
two equally-supported deployment modes.

**As an overlay** on top of existing IP networks, FIPS lets your
node reach any other FIPS node wherever it sits — behind a NAT, on
a different ISP, on a phone over cellular, on a laptop with only
Bluetooth in range, or behind a Tor onion. The mesh forwards IPv6
traffic transparently and end-to-end encrypted, with no central VPN
concentrator or coordinating server.

**Ground up** over raw Ethernet, WiFi, or Bluetooth, FIPS provides
a complete permissionless network without any pre-existing IP
infrastructure, ISP, or DNS. Any node that joins the link gets
routable IPv6 addresses, peer discovery, and a path to every other
node automatically.

Either way, existing networking software runs over it unchanged —
SSH, HTTP servers, file transfer, anything IPv6-native works the
same way it would on a local network.

## Features

- **Self-organizing mesh routing.** Spanning-tree coordinates with
  bloom-filter-guided discovery; no global routing tables, no
  flooding.
- **Multi-transport.** UDP, TCP, Ethernet, Tor, and Bluetooth (BLE
  L2CAP) ship today; transports compose on a single mesh and a
  node may run several at once.
- **Two-layer encryption.** Noise XX both hop-by-hop (peer links)
  and end-to-end (mesh sessions), with periodic rekey for forward
  secrecy and protocol negotiation in the handshake.
- **Nostr-native identity.** secp256k1 / schnorr keypairs as node
  addresses; self-generated, no registration, no central authority.
- **IPv6 adapter.** A TUN interface maps each remote npub to an
  `fd00::/8` address, so unmodified IPv6 software reaches mesh
  peers as `<npub>.fips`. Built-in `.fips` DNS resolver, with
  optional static name mapping via `/etc/fips/hosts`.
- **Nostr-mediated discovery and NAT traversal.** Peers publish
  endpoint adverts on public Nostr relays, exchange candidates via
  NIP-59 gift-wrapped offers and answers, and establish direct
  paths through NATs using STUN-assisted hole punching.
- **LAN gateway.** Optional `fips-gateway` service folds an entire
  unmodified LAN into the mesh: outbound (LAN clients reach mesh
  destinations through a DNS-allocated virtual IPv6 pool and
  nftables NAT) and inbound (LAN-side services exposed to the mesh
  through 1:1 port forwards).
- **Per-link metrics.** RTT, loss, jitter, and goodput on every
  hop, plus mesh-size estimation, via the Metrics Measurement
  Protocol.
- **ECN congestion signaling.** Hop-by-hop CE-flag relay with RFC
  3168 IPv6 marking and transport kernel-drop detection.
- **Mesh-interface security baseline.** Optional default-deny
  nftables policy for `fips0` shipped as a packaged conffile
  (`/etc/fips/fips.nft`) with an operator drop-in directory
  (`/etc/fips/fips.d/`) and a disabled-by-default
  `fips-firewall.service`. The baseline polices only the mesh
  interface, leaving Docker, Tor, and the host firewall untouched.
- **Operator visibility.** `fipsctl` CLI for control and inspection
  with time-series stats history queryable for any metric,
  `fipstop` TUI for live status with inline sparkline dashboards,
  and a JSON-line control socket on each binary for direct
  programmatic access.
- **Reproducible builds** with toolchain pinning and
  `SOURCE_DATE_EPOCH`.

## Quick start

The shortest path on Debian / Ubuntu:

```bash
git clone https://github.com/jmcorgan/fips.git
cd fips
cargo install cargo-deb
cargo deb
sudo dpkg -i target/debian/fips_*.deb
sudo systemctl start fips
```

This installs the daemon, CLI tools (`fipsctl`, `fipstop`), the
optional `fips-gateway` service, systemd units, and a default
`/etc/fips/fips.yaml` you can edit before starting.

For macOS, Windows, OpenWrt, the systemd tarball, or a from-source
build, see [docs/getting-started.md](docs/getting-started.md) for
the full multi-platform installation guide.

To join a live mesh and reach your first peer, follow the new-user
tutorial progression starting at
[docs/tutorials/join-the-test-mesh.md](docs/tutorials/join-the-test-mesh.md).

### Building from source

```bash
cargo build --release
```

Requires Rust 1.94.1+ (edition 2024). Linux, macOS, and Windows are
supported; transport availability varies by platform.

| Transport | Linux | macOS | Windows | OpenWrt |
|-----------|:-----:|:-----:|:-------:|:-------:|
| UDP       |   ✅  |   ✅  |    ✅   |   ✅    |
| TCP       |   ✅  |   ✅  |    ✅   |   ✅    |
| Ethernet  |   ✅  |   ✅  |    ❌   |   ✅    |
| Tor       |   ✅  |   ✅  |    ✅   |   ✅    |
| BLE       |   ✅  |   ❌  |    ❌   |   ❌    |

On Linux, a source build requires `libclang` — the LAN gateway's
nftables bindings are generated by `bindgen` at build time, which
needs `libclang.so` on the build host. Install it before building
(`sudo apt install libclang-dev` on Debian / Ubuntu); without it the
build fails inside the `rustables` crate with an "Unable to find
libclang" error. This is a build-time prerequisite only — it is not a
runtime dependency, and the pre-built `.deb` artifacts do not need it.

BLE is optional and, on Linux, requires BlueZ and libdbus
(`sudo apt install bluez libdbus-1-dev` on Debian / Ubuntu). It is
gated on a build-script probe — install the dependencies first and
the `cargo build` line above picks it up. The OpenWrt ipk omits
BLE because libdbus is not available on the target.

## Documentation

`docs/` is organised by reader purpose:

- **[Tutorials](docs/tutorials/)** — hand-held walk-throughs from
  a fresh install through to a participating mesh node, plus
  advanced deployments (gateway on OpenWrt, hosting services,
  ground-up two-device mesh).
- **[How-to guides](docs/how-to/)** — operator recipes for
  specific tasks: firewall activation, Nostr discovery, Tor onion
  service, Bluetooth peering, LAN gateway deployment and
  troubleshooting, MTU diagnostics, host aliases, persistent
  identity, unprivileged-user setup, UDP buffer tuning.
- **[Reference](docs/reference/)** — `fips.yaml` configuration,
  wire formats, control-socket protocol, CLI references for each
  binary, security posture matrix, Nostr events catalog, transport
  statistics inventory.
- **[Design](docs/design/)** — protocol-level architecture and
  layer specifications. Start with
  [fips-concepts.md](docs/design/fips-concepts.md) for the framing,
  then [fips-architecture.md](docs/design/fips-architecture.md) for
  the protocol stack.

If you want to contribute, see [CONTRIBUTING.md](CONTRIBUTING.md)
and [testing/README.md](testing/README.md).

## Examples

- **[examples/sidecar-nostr-relay/](examples/sidecar-nostr-relay/)** —
  Run a [strfry](https://github.com/hoytech/strfry) Nostr relay
  reachable exclusively over the FIPS mesh. The relay container
  shares the FIPS sidecar's network namespace and is isolated from
  the host network.
- **[examples/k8s-sidecar/](examples/k8s-sidecar/)** — Run FIPS as
  a Kubernetes Pod sidecar. The sidecar creates `fips0` in the
  Pod's shared network namespace so every other container in the
  Pod gets mesh access without modification.
- **[examples/wireguard-sidecar-macos/](examples/wireguard-sidecar-macos/)** —
  Reach the FIPS mesh from a macOS host through a local Docker
  container over a WireGuard tunnel. Only traffic destined for
  `fd00::/8` transits the sidecar; regular internet traffic
  continues to use the host network.

## Project structure

```text
src/          Rust source: library + fips, fipsctl, fipstop, fips-gateway binaries
docs/         Documentation: tutorials, how-to, reference, design
packaging/    Debian, macOS .pkg, Windows ZIP, OpenWrt ipk, AUR, systemd tarball
examples/     Deployment examples (Nostr relay, K8s sidecar, macOS WireGuard)
testing/      Docker-based integration test harnesses + chaos simulation
```

## Status & roadmap

FIPS is at **v0.5.0-dev** on the `next` branch.
[v0.3.0](https://github.com/jmcorgan/fips/releases/tag/v0.3.0)
has shipped from `master`; this development line carries
wire-format-breaking work for v0.5.0 — unified Noise XX handshake
at both layers, FMP node profiles, slimmer MMP reports, and an
extensible bloom-filter encoding — that will not interoperate with
v0.2.x or v0.3.x peers. The core protocol works end-to-end over
UDP, TCP, Ethernet, Tor, and Bluetooth on a small live mesh of
deployed nodes. See the CHANGELOG `## Breaking` section for the
full list of v0.5.0 wire-format changes in flight.

### What works today

- Spanning-tree construction with greedy coordinate routing.
- Bloom-filter-guided destination discovery (no flooding,
  single-path with retry).
- Two-layer Noise XX encryption (hop-by-hop at the link layer and
  end-to-end at the session layer) with periodic hitless rekey for
  forward secrecy at both layers and protocol negotiation in the
  handshake.
- Persistent or ephemeral node identity with key-file management.
- IPv6 TUN adapter with built-in `.fips` DNS resolver and
  multi-backend auto-configuration (systemd dns-delegate,
  systemd-resolved, dnsmasq, NetworkManager).
- Static hostname mapping (`/etc/fips/hosts`) with auto-reload.
- Per-link metrics (RTT, loss, jitter, goodput) and mesh size
  estimation.
- ECN congestion signaling (hop-by-hop CE relay, IPv6 CE marking,
  kernel-drop detection).
- UDP, TCP, Ethernet, Tor, and BLE transports (BLE via L2CAP CoC
  with per-link MTU negotiation).
- Nostr-mediated overlay endpoint discovery and UDP hole punching
  for NAT traversal.
- LAN gateway (`fips-gateway`) with both outbound (LAN-to-mesh)
  and inbound (mesh-to-LAN port-forwarding) modes.
- Peer ACL: per-npub allow / deny admission control at the link
  layer; opt-in mesh-firewall baseline at `fips0` ingress.
- Runtime inspection and peer management via `fipsctl` and
  `fipstop`.
- Reproducible builds with toolchain pinning and
  `SOURCE_DATE_EPOCH`.
- Linux (Debian, systemd tarball, OpenWrt, AUR), macOS (`.pkg`),
  and Windows (ZIP, service) packaging.
- Docker-based integration and chaos testing.

### Near-term priorities

- Native API for FIPS-aware applications (npub:port addressing
  without the IPv6-shim path).
- Security audit of the cryptographic protocols.

### Longer-term

- Mobile platform support.
- Bandwidth-aware routing and QoS.
- Protocol stability and a versioned wire format.
- Published crate.

## License

MIT — see [LICENSE](LICENSE).
