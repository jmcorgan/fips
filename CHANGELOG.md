# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-12

### Added (Initial Release)

#### Session Layer (FSP)

- End-to-end encrypted datagram service between mesh nodes addressed by Nostr npub
- Noise XK sessions with mutual authentication, replay protection, and forward secrecy
- Automatic session rekeying with configurable time/message thresholds and drain window for in-flight packets
- Port multiplexing for multiple services over a single session
- Session-layer metrics: sender/receiver reports with RTT, jitter, delivery ratio, and burst loss tracking
- Passive RTT measurement via spin bit

#### IPv6 Adapter

- IPv6 adapter interface allowing tunneling TCP/IPv6 through FIPS mesh
  for traditional IP applications (TUN interface)
- DNS resolver allowing IP applications to reach nodes by npub.fips name
- Host-to-npub static mappings: resolve `hostname.fips` via host map
  populated from peer config aliases and `/etc/fips/hosts` file

#### Mesh Layer (FMP)

- Self-organized core mesh routing protocol with adaptive least cost forwarding
- Noise IK hop-by-hop link encryption with mutual authentication and replay protection between peer nodes
- Distributed spanning tree construction with cost-based parent selection and adaptive reconfiguration
- Destination route discovery via bloom filter-based directed search protocol
- Path MTU discovery with per-link MTU tracking and MtuExceeded error signaling
- Link-layer MMP: SRTT, jitter, one-way delay trends, packet loss, and ETX metrics
- Link-layer heartbeat with configurable liveness timeout for dead peer detection
- Epoch-based peer restart detection
- Automatic link rekeying with K-bit epoch coordination and drain window
- Static peer auto-reconnect with exponential backoff
- Multi-address peers with transport priority-based failover
- Msg1 rate limiting for handshake DoS protection

#### Mesh Peer Transports

- UDP overlay transport with inbound and static outbound peer configuration
- TCP overlay transport with listening port and static outbound peer support
- Ethernet/WiFi transport (MAC address based, no IP stack) with optional automatic peer discovery and auto-connect

#### Operator Tooling

- Ephemeral or persistent node identity with key file management
- Unix domain control socket for runtime observability
- `fipsctl` CLI tool for control socket interaction and node management
- Comprehensive node and transport statistics via control socket
- `fipstop` TUI monitoring tool with real-time session, peer, and transport configuration and metrics display

#### Packaging and Deployment

- Debian/Ubuntu `.deb` packaging via cargo-deb
- Systemd service packaging with tarball installer
- OpenWRT package with opkg feed and init script
- Docker sidecar deployment for containerized services
- Build version metadata: git commit hash, dirty flag, and target triple
  embedded in all binaries via `--version`

#### Testing and CI

- Comprehensive unit and integration tests covering all protocol layers and transports
- Docker test harness with static and stochastic topologies
- Chaos testing with simulated severe network conditions: latency, packet loss, reordering, and peer churn
- CI with GitHub Actions: x86_64 and aarch64, integration test matrix, nextest JUnit reporting
- Local CI runner script (`testing/ci-local.sh`)

#### Project

- Design documentation suite covering all protocol layers
- CHANGELOG.md following Keep a Changelog format
- Repository mirrored to [ngit](https://gitworkshop.dev/npub1y0gja7r4re0wyelmvdqa03qmjs62rwvcd8szzt4nf4t2hd43969qj000ly/relay.ngit.dev/fips)
