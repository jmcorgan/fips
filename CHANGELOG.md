# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Breaking

Wire-format breaking changes for v0.4.0. All nodes in a mesh must
run the same major version — these changes are not backward compatible
with v0.2.x peers.

### Changed

#### Noise XX Handshake (FMP and FSP)

- FMP link handshake switched from Noise IK (2 messages) to Noise XX
  (3 messages). Neither side requires prior knowledge of the peer's
  static key. Responder identity revealed in msg2, initiator in msg3.
  FMP wire version incremented to 1.
- FSP session handshake switched from Noise XK to Noise XX. Same
  3-message flow with post-handshake identity verification using
  x-only key comparison (parity-independent for npub compatibility).
- Protocol negotiation payload added to XX msg2/msg3 for both layers:
  format byte, packed version min/max, 64-bit feature bitfield, and
  forward-compatible TLV extensions. Enables rolling protocol upgrades
  in future releases.
- FMP msg1 reduced from 106 to 33 bytes (ephemeral key only, no
  encrypted static key or DH products).

#### FMP Node Profiles

- Node profile enum (Full, NonRouting, Leaf) advertised in FMP feature
  bitfield bits 0-2. At least one side of a link must be Full.
- MMP report flow gated by wants/provides bits (bits 3-6): reports
  only sent when the sender can provide and the receiver wants them.
- Non-routing nodes receive bloom filters (one-way) but do not send
  them; the full peer inserts their identity as a leaf dependent.
- Leaf nodes enforce single-peer constraint with no tree, bloom, or
  transit participation.

#### MMP Report Format

- Spin bit removed. Reclaims FMP flags bit 2 and FSP inner flags
  bit 0. Superseded by MMP receiver report timestamp echo for RTT.
- SenderReport reduced from 48 to 20 bytes (3 fields: interval
  packets/bytes sent, cumulative packets sent).
- ReceiverReport reduced from 68 to 54 bytes (10 fields retained;
  removed max/mean burst loss and interval recv counters).
- Both report types use extensibility header: `[format_version:1]
  [total_length:2 LE]` replacing reserved bytes. Decoders skip
  unknown trailing bytes for forward compatibility.

#### Discovery Wire Format

- Dropped `origin_coords` from LookupRequest (saves 2 + 16*depth
  bytes per request). Reverse-path routing via `recent_requests` is
  the primary response mechanism.
- `min_mtu` field wired up in LookupRequest: transit nodes skip peers
  whose link MTU is below the request's minimum.
- TLV extension section added to LookupRequest and LookupResponse
  after fixed fields. Transit nodes forward TLV bytes verbatim.

#### Shared-Media Beacons

- Ethernet frame header unified to 4 bytes `[type][flags][length:2
  LE]` for all frame types. Beacons reduced from 34 to 5 bytes
  (pubkey stripped — identity learned from XX handshake).
- BLE pre-handshake pubkey exchange removed. Cross-probe tie-breaker
  eliminated (unnecessary with XX).

#### Bloom Filter Wire Format

- FilterAnnounce gains flags byte (delta bit), `base_seq` field, and
  RLE-compressed payload for XOR-diff delta compression.
- New FilterNack message type (0x21) for out-of-sequence delta
  recovery (triggers full retransmit).
- Filter size decoupled from FMP negotiation: announced dynamically in
  filter updates. Bit 7 and TLV field 1 removed from handshake.
- Variable filter sizes (512 bytes to 32 KB) with adaptive sizing
  based on outgoing fill ratio (step-up at 20%, step-down at 5%).

## [Unreleased]

### Added

#### Platform Support

- Windows platform support: wintun TUN device, TCP control socket on
  `localhost:21210` (in place of the Unix domain socket), Windows
  Service lifecycle (`--install-service`, `--uninstall-service`,
  `--service`), ZIP packaging with PowerShell install/uninstall scripts,
  and CI build/test matrix entry
  ([#45](https://github.com/jmcorgan/fips/pull/45))
- macOS platform support: native `utun` TUN interface management, raw
  Ethernet transport via BPF, `.pkg` packaging with launchd plist and
  uninstall script, x86_64 cross-compile from arm64, and CI build/unit
  test jobs
- `gateway` Cargo feature flag gates the optional Linux-only
  `rustables` dependency so macOS and Windows builds never pull in
  nftables bindings

#### Outbound LAN Gateway

- New `fips-gateway` binary that lets unmodified LAN hosts reach FIPS
  mesh destinations via DNS-allocated virtual IPs and kernel nftables
  NAT. Virtual-IP pool (`fd01::/112` by default) with state-machine
  lifecycle and TTL-based reclamation; conntrack-backed session
  tracking; proxy NDP on the LAN interface; control socket at
  `/run/fips/gateway.sock` with `show_gateway` and `show_mappings`;
  fipstop Gateway tab with pool gauge and mappings table; design doc
  at `docs/design/fips-gateway.md`; integration test harness
- Gateway packaging: systemd service unit with `After=fips.service`,
  Debian and AUR package entries, OpenWrt procd init with dnsmasq
  forwarding, proxy NDP, RA route advertisements, and IPv6 forwarding
  sysctls. Gateway enabled by default on OpenWrt

#### Nostr-Mediated Discovery and NAT Traversal

- Optional overlay-discovery and NAT-hole-punching path behind the
  `nostr-discovery` cargo feature. Nodes publish signed overlay adverts
  as Nostr kind `37195` parameterized replaceable events listing
  reachable transport endpoints to a configurable set of public relays,
  and consume peer adverts to populate fallback addresses for
  `via_nostr` peers or, under `policy: open`, for non-configured peers
  within a budget cap. The kind value is FIPS-specific: `37195` sits in
  the application-defined replaceable range `30000–39999`, and the
  digits visually spell `FIPS` (7=F, 1=I, 9=P, 5=S)
- STUN-assisted UDP hole punching for `addr: "nat"` UDP endpoints. STUN
  reflexive observation, gift-wrap (NIP-59) offer/answer signaling, and
  candidate-pair punch planner (LAN-private + reflexive paths attempted in
  parallel). Successful punches hand the live socket into the standard
  FIPS UDP transport via a bootstrap-handoff API
- New `node.discovery.nostr.*` configuration tree with operator-tunable
  resource caps, replay tracking, and punch timing; new `peers[].via_nostr`
  and per-transport `advertise_on_nostr` / `public` flags. Cross-field
  validation at startup catches mis-configured combinations
- Docker NAT lab covering cone, symmetric (TCP-fallback), and LAN
  scenarios, wired into the integration CI matrix

#### Examples

- macOS WireGuard sidecar: run FIPS in a local Docker container and
  route `.fips` traffic from the macOS host through a WireGuard tunnel
  to the container's `fips0` interface. Only traffic destined for
  `fd00::/8` transits the sidecar; regular internet traffic continues
  to use the host network
  ([#51](https://github.com/jmcorgan/fips/pull/51))

#### Bluetooth Transport

- Bluetooth Low Energy (BLE) L2CAP Connection-Oriented Channel transport
  with per-link MTU negotiation, behind the `ble` Cargo feature flag
  (default-on, Linux only, requires BlueZ)
- BLE peer discovery via continuous scan/probe with cooldown-based
  deduplication (`probe_cooldown_secs`, default 30s)
- Continuous BLE advertising for reliable L2CAP connectivity
- Cross-probe tie-breaker using deterministic NodeAddr comparison
- Connection pool with configurable capacity and eviction

#### DNS

- Multi-backend `.fips` DNS configuration: a detection script
  configures whichever resolver is available, in priority order:
  systemd dns-delegate (systemd >= 258), systemd-resolved via
  `resolvectl`, standalone dnsmasq, NetworkManager with the dnsmasq
  plugin. Teardown reads the recorded backend from
  `/run/fips/dns-backend` and reverses only what was applied
  ([#58](https://github.com/jmcorgan/fips/pull/58),
  fixes [#52](https://github.com/jmcorgan/fips/issues/52))

#### Operator Configuration

- `node.log_level` config field (case-insensitive, default `info`)
  replaces the hardcoded `RUST_LOG=info` previously baked into
  systemd units and the OpenWrt procd init script. The daemon now
  loads config before initializing tracing so the configured level
  takes effect; `RUST_LOG` still overrides when set

#### Operator Tooling

- `fipsctl show identity-cache` lists every cached node identity
  (npub, IPv6 address, display name, LRU age) alongside the
  configured cache capacity
- `fipsctl show peers` extended with per-peer security signals
  (replay suppression count, consecutive decrypt failures), Noise
  session counters, session indices, and rekey lifecycle state
- `fipsctl show sessions` extended with handshake resend count
  during establishment and rekey/session health fields when
  established (session start, K-bit epoch, coords warmup remaining,
  drain state)
- `fipsctl show cache` now includes individual coordinate cache
  entries (tree coordinates, depth, path MTU, age). The top-level
  count field was renamed from `entries` to `count` for clarity
- `fipsctl show routing` expands `pending_lookups` from a count to
  per-target detail (attempt, age, last sent), adds pending TUN
  packet queue depth, and adds per-peer connection retry state
  ([#42](https://github.com/jmcorgan/fips/pull/42),
  [@osh](https://github.com/osh))

#### Documentation

- Pre-implementation proposal for NAT traversal using Nostr relays
  as the signaling channel and STUN for reflexive address discovery
  (`docs/proposals/`)

#### Packaging and Deployment

- Linux release artifact workflow: builds x86_64 and aarch64 tarballs
  and `.deb` packages on `v*` tag push, with SHA-256 checksums
- AUR publish workflow for tagged stable releases
- Arch Linux AUR packaging for `fips` (release) and `fips-git`
  (development) packages with sysusers.d/tmpfiles.d integration
  ([#21](https://github.com/jmcorgan/fips/pull/21),
  [@dskvr](https://github.com/dskvr))

### Changed

- MMP link-layer report intervals retuned for constrained transports:
  steady-state floor raised from 100ms to 1000ms, ceiling from 2000ms
  to 5000ms. Cold-start uses a 200ms floor for the first 5 SRTT samples
  before switching to steady-state. Reduces BLE overhead ~10× while
  keeping reports well above the EWMA convergence threshold.
  Session-layer intervals unchanged
- 35 info-level log messages demoted to debug (handshake
  cross-connection mechanics, periodic MMP telemetry, TUN/transport
  shutdown, retry scheduling). Info output now focuses on
  operator-relevant state changes: lifecycle events, peer promotions,
  session establishment, parent switches, transport start/stop
- **Breaking (control socket JSON):** `show_cache` response field
  `entries` has changed type from a `u64` count to an array of entry
  objects; a new `count` field carries the previous scalar value.
  `show_routing` response field `pending_lookups` has changed type
  from a `u64` count to an array of per-target lookup objects.
  External consumers parsing these fields as numbers must be
  updated. In-tree `fipstop` is adjusted to the new schema. The
  control socket interface is still pre-1.0 and not covered by
  stability guarantees
- Discovery rate limiting retuned to be less aggressive at cold start.
  The previous defaults (30s base post-failure suppression, doubling
  to a 300s cap, with reset only on parent change / new peer / first
  RTT / reconnection) reliably outlasted initial mesh convergence: a
  single timed-out lookup during bloom-filter propagation suppressed
  any retry for 30s while none of the reset triggers fired on a
  stable post-handshake topology. The suppression window dictated
  effective time-to-converge instead of bounding repeat traffic.
  Replaces the single-lookup-with-internal-retry model
  (`timeout_secs`/`retry_interval_secs`/`max_attempts`) with a
  per-attempt timeout sequence in
  `node.discovery.attempt_timeouts_secs` (default `[1, 2, 4, 8]`).
  Each attempt sends a fresh `LookupRequest` with a new `request_id`,
  which lets successive attempts take different forwarding paths as
  the bloom and tree state evolve. The destination is declared
  unreachable only after the full sequence is exhausted (15s total
  at the default). Disables post-failure suppression by default
  (`backoff_base_secs`/`backoff_max_secs` now both `0`); operators
  with chatty apps generating repeat lookups against unreachable
  destinations can opt back in
- Validate bloom filter fill ratio on FilterAnnounce ingress.
  Inbound FilterAnnounce messages whose derived false-positive
  rate exceeds `node.bloom.max_inbound_fpr` (new config field,
  default 0.05) are rejected silently on the wire, logged at WARN,
  and counted in a new `bloom.fill_exceeded` counter. A
  rate-limited WARN also fires if our own outgoing filter's FPR
  exceeds the cap. `BloomFilter::estimated_count` now takes
  `max_fpr` and returns `Option<f64>`, returning `None` for
  saturated filters; this propagates through `compute_mesh_size`
  into `estimated_mesh_size` (already `Option<u64>`)

### Fixed

- Control socket path detection in fipsctl and fipstop now checks for
  the `/run/fips/` directory instead of the socket file inside it, so
  users not yet in the `fips` group get a clear "Permission denied"
  error instead of a misleading "No such file" fallback to
  `$XDG_RUNTIME_DIR` ([#30](https://github.com/jmcorgan/fips/issues/30),
  reported by [@Sebastix](https://github.com/Sebastix))
- OpenWrt ipk build excluded BLE feature that requires D-Bus, which is
  unavailable on OpenWrt targets
- IPv6 routing policy rule added at TUN setup to protect `fd00::/8`
  from interception by Tailscale's table 52 default route
- Bloom filter routing no longer swallows traffic when no bloom
  candidate is strictly closer than the current node. `find_next_hop`
  now falls through to greedy tree routing in that case instead of
  returning `NoRoute`, which previously caused dropped packets in
  topologies where the tree parent was closer but not a bloom
  candidate
- Auto-connect peers now reconnect after a graceful `Disconnect`
  notification from the remote side. `handle_disconnect` previously
  removed the peer without scheduling a reconnect, orphaning the
  entry on a clean upstream shutdown; the other removal paths
  (link-dead, decrypt failure, peer restart) already scheduled
  reconnect ([#60](https://github.com/jmcorgan/fips/issues/60),
  reported by [@SwapMarket](https://github.com/SwapMarket))
- `fipsctl connect` now rejects FIPS mesh (`fd00::/8`) addresses for
  `udp`, `tcp`, and `ethernet` transports with a clear error message
  instead of echoing success while the daemon silently failed the
  bind with `EAFNOSUPPORT`
  ([#61](https://github.com/jmcorgan/fips/issues/61),
  reported by [@SwapMarket](https://github.com/SwapMarket))
- Rekey msg1 on non-accepting transports (e.g. UDP holepunch) was
  rejected at the top of `handle_msg1()`, which broke rekey handshakes
  on established links and produced repeated "dual rekey initiation"
  log floods. The gate now only blocks truly new inbound handshakes
  from unknown addresses; rekey and restart msg1s for established
  peers are processed normally
  ([#47](https://github.com/jmcorgan/fips/issues/47),
  [#49](https://github.com/jmcorgan/fips/pull/49))
- `fipstop` now uses `ratatui::try_init()` instead of `ratatui::init()`,
  so terminal initialization failures (e.g. Docker on macOS Sequoia,
  or environments without a usable tty) produce a clean error message
  instead of a hard crash
- Tighten TreeAnnounce ancestry validation to match the spanning
  tree specification. The receive path now verifies that the
  ancestry is structurally consistent with the signed parent
  declaration before mutating tree state.
- Fix DNS resolution on Ubuntu 22 with systemd-resolved. The DNS
  responder now binds `::` (dual-stack) instead of `127.0.0.1` so
  systemd-resolved's interface-scoped routing via fips0 reaches
  it. DNS queries are accepted only from the localhost.
- Make the tree ancestry acceptance unit test deterministic.
  `test_tree_announce_validate_semantics_accepts_valid_non_root`
  generated a random signing identity while pinning the fixed root
  to `node_addr[0] = 0x01`; about 2 in 256 random identities were
  numerically smaller than the claimed root, triggering
  `AncestryRootNotMinimum`. The test now regenerates the identity
  until its `node_addr` is strictly larger than both the fixed
  parent and root.
- Responder now sends an encrypted `Disconnect` frame on the
  newly-established Noise session when rejecting a peer in
  `handle_msg3`, before tearing down. Under Noise XX the responder
  only learns the initiator's identity from msg3, so by the time an
  inbound-handshake policy check can reject, the initiator has
  already received msg2 and promoted its side of the peering. Without
  an explicit notification the initiator would keep the "connected"
  state until link-dead timeout fired, producing the
  `acl-allowlist` CI failure on the `next` branch. The notification
  allows the initiator's existing `handle_disconnect` path to clean
  up within one RTT.

## [0.2.0] - 2026-03-22

### Added

#### Operator Tooling

- `fipsctl connect` and `disconnect` commands for runtime peer
  management via control socket, with hostname resolution from
  `/etc/fips/hosts`

#### IPv6 Adapter

- Pre-seed identity cache from configured peer npubs at startup, so TUN packets can be dispatched immediately without waiting for handshake completion ([@v0l](https://github.com/v0l))

#### Mesh Peer Transports

- New Tor transport with SOCKS5 and directory-mode onion service for anonymous inbound and outbound peering
- DNS hostname support in peer addresses for UDP and TCP transports
- Non-blocking transport connect for connection-oriented transports (TCP, Tor)

#### Packaging and Deployment

- Reproducible build infrastructure: Rust toolchain pinning via
  `rust-toolchain.toml`, `SOURCE_DATE_EPOCH` in CI and packaging
  scripts, deterministic archive timestamps
- Top-level packaging Makefile for unified build across formats
- Kubernetes sidecar deployment example with Nostr relay demo
- Nostr release publishing in OpenWrt package workflow
- SHA-256 hash output in CI build and OpenWrt workflows

#### Testing and CI

- Maelstrom chaos scenario with dynamic topology mutation and
  ephemeral node identities via connect/disconnect commands
- Consolidated Docker test harness infrastructure

### Changed

- Discovery protocol: replace flooding with bloom-filter-guided tree
  routing. Includes originator retry (T=0/T=5s/T=10s), exponential
  backoff after timeouts and bloom misses, and transit-side per-target
  rate limiting. Removed 257-byte visited bloom filter from LookupRequest wire format. *This is a breaking change; nodes running versions prior to this release will not be compatible.*

### Fixed

- DNS responder returned NXDOMAIN for A queries on valid `.fips` names,
  causing resolvers to give up without trying AAAA. Now returns NOERROR
  with empty answers for non-AAAA queries on resolvable names.
  (#9, reported by [@alopatindev](https://github.com/alopatindev))
- Stale end-to-end session left in session table after peer removal blocked session re-establishment on reconnect — `remove_active_peer` now cleans up `self.sessions` and `self.pending_tun_packets`. (#5, [@v0l](https://github.com/v0l))
- `schedule_reconnect` reset exponential backoff to zero on each link-dead
  cycle instead of preserving accumulated retry count.
  (#5, [@v0l](https://github.com/v0l))
- FMP/FSP rekey dual-initiation race on high-latency links (Tor): both
  sides' timers fired simultaneously, both msg1s crossed in flight, each
  side's responder path destroyed the initiator state. Fixed with
  deterministic tie-breaker (smaller NodeAddr wins as initiator).
- Parent selection SRTT gate bypass: `evaluate_parent` used default cost
  1.0 for peers filtered out by `has_srtt()`, defeating the MMP eligibility
  gate. Now skips unmeasured candidates when any peer has cost data.
- FSP rekey cutover race: initiator cut over before responder received msg3,
  causing AEAD failures. Fixed by deferring initiator cutover by 2 seconds.
- MMP metric discontinuity after rekey: receiver state carried stale
  counters across rekey, inflating reorder counts and jitter. Fixed via
  `reset_for_rekey()`.
- Auto-connect peers exhausted `max_retries` on initial connection failures
  and were permanently abandoned. Now retry indefinitely with exponential
  backoff capped at 300 seconds.
- Control socket permissions: non-root users couldn't connect. Daemon now
  chowns socket and directory to `root:fips` group at bind time.
- Post-rekey jitter spikes: old-session frames arriving via the drain window
  produced 2,000–7,000ms jitter spikes that corrupted the EWMA estimator.
  Added a 15-second grace period after rekey cutover that suppresses jitter
  updates until drain-window frames have flushed. (#10)
- ICMPv6 Packet Too Big source was set to the local FIPS address, which
  Linux ignores (loopback PTB check). Now uses the original packet's
  destination so the kernel honors the PMTU update.
  (#16, [@v0l](https://github.com/v0l))
- Reverse delivery ratio used lifetime cumulative counters instead of
  per-interval deltas, making ETX unresponsive to recent loss. (#14)
- MMP delta guards used `prev_rr > 0` to detect first report, conflating
  it with a legitimate zero counter. Replaced with `has_prev_rr`. (#14)

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
