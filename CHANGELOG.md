# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Breaking

Wire-format breaking changes for v0.5.0. All nodes in a mesh must
run the same major version — these changes are not backward compatible
with v0.3.x peers.

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

#### Nostr-Discovery Advert Namespace

- Default Nostr-discovery advert namespace bumped from
  `fips-overlay-v1` to `fips-overlay-v1-next` on the `next` branch.
  Master continues to publish under `fips-overlay-v1`. Effect: a
  stock `next`-branch daemon's open-discovery sweep no longer
  discovers `master` peers, and vice versa — eliminating the
  cross-version retraversal storms that arise when both sides
  punched a UDP socket via Nostr but cannot complete an FMP
  handshake. Operators who genuinely want cross-branch reach (e.g.
  during a coordinated rolling upgrade) can override per-daemon
  via `node.discovery.nostr.app` in `fips.yaml`. The
  `protocol_mismatch_cooldown_secs` defense-in-depth on master is
  the safety net against any peer that bypasses this default
  (config override, future fork, static-peer config).

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

## [0.3.0] - 2026-05-11

### Added

#### Mesh Layer (FMP)

- Overlay-discovery and NAT-hole-punching path (opt-in via
  `node.discovery.nostr.enabled`). Nodes publish signed overlay adverts
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
- One-shot startup advert sweep for Nostr open-discovery. On daemon
  startup under `node.discovery.nostr.policy: open`, after a short
  settle delay (`startup_sweep_delay_secs`, default 5s) the cached
  overlay-advert table is iterated once and recent adverts (newer
  than `startup_sweep_max_age_secs`, default 3600s) are queued for
  outbound retry, modulo the same skip-filters as the per-tick sweep
  (configured peer, already connected, retry-pending, connecting).
  Closes the gap where peers learned only through relay backlog at
  startup were not dialed until they republished.
- Diagnostic logging on the open-discovery sweep. Each `queued retry`
  now logs at info-level with the peer short-npub and advert age,
  and a one-line summary (cached count, queued count, per-reason
  skip counts) is emitted on every startup sweep and on any per-tick
  sweep that queues at least one retry. Operator-facing visibility
  into what the auto-dial path is doing.

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
- MIPS atomic ABI support: `std::sync::atomic` replaced with
  `portable_atomic` so 32-bit MIPS targets without native atomics
  link cleanly
  ([#62](https://github.com/jmcorgan/fips/pull/62),
  [@andrewheadricke](https://github.com/andrewheadricke)).

#### Mesh Peer Transports

- Bluetooth Low Energy (BLE) L2CAP Connection-Oriented Channel
  transport (Linux only, requires BlueZ): per-link MTU negotiation,
  continuous scan/probe peer discovery with cooldown-based
  deduplication, continuous advertising, deterministic NodeAddr
  cross-probe tie-breaker, and a configurable connection pool with
  eviction.
- `transports.udp.outbound_only` (default `false`). When true, the UDP
  transport binds a kernel-assigned ephemeral port (`0.0.0.0:0`) instead
  of the configured `bind_addr`, refuses inbound handshakes, and is
  never advertised on Nostr regardless of `advertise_on_nostr`. Use
  this to participate in the mesh as a pure client — initiate outbound
  links without exposing an inbound listener on a known port.
  Implements the long-form fix for `udp.bind_addr: "127.0.0.1:..."`
  not actually working as a workaround (Linux pins the loopback source
  IP, dropping outbound flows to external peers at the routing layer)
- `transports.udp.accept_connections` (default `true`). Mirrors the
  Ethernet/BLE knob; setting to `false` produces a "client" posture
  (initiate outbound, refuse inbound msg1 from new addresses). The
  Node-level handshake gate carves out msg1 from peers already
  established on this transport so rekey continues to work. Affects
  every transport via the `Transport` trait
- Startup validation now rejects `transports.udp[*].bind_addr` set to a
  loopback address when at least one peer has a non-loopback UDP
  address. Replaces the silent "peer link won't establish" failure
  mode where Linux's source-address routing check dropped outbound
  flows from the loopback-bound socket. `outbound_only: true` is
  exempt from the check (it overrides `bind_addr` to `0.0.0.0:0`)

#### Security

- Mesh-interface nftables baseline (Linux). Ships `/etc/fips/fips.nft`
  as a documented operator conffile and `fips-firewall.service`
  (disabled by default) for default-deny inbound on the `fips0` mesh
  interface. Operators enable explicitly with
  `systemctl enable --now fips-firewall.service`. Drop-ins in
  `/etc/fips/fips.d/*.nft`. See `docs/fips-security.md`.
- Peer access control list enforcement: optional
  `/etc/fips/peers.allow` and `/etc/fips/peers.deny` files
  (TCP-Wrappers style) gate outbound connect, inbound msg1, and
  outbound msg2 against npub, hex pubkey, host alias, or `ALL`.
  Files are reloaded automatically on mtime change. New
  `fipsctl acl show` query reports the effective rule set
  ([#50](https://github.com/jmcorgan/fips/pull/50),
  [@alexxie16](https://github.com/alexxie16)).

#### LAN Gateway

- New `fips-gateway` binary that lets unmodified LAN hosts reach FIPS
  mesh destinations via DNS-allocated virtual IPs and kernel nftables
  NAT. Virtual-IP pool (`fd01::/112` by default) with state-machine
  lifecycle and TTL-based reclamation; conntrack-backed session
  tracking; proxy NDP on the LAN interface; control socket at
  `/run/fips/gateway.sock` with `show_gateway` and `show_mappings`;
  fipstop Gateway tab with pool gauge and mappings table; design doc
  at `docs/design/fips-gateway.md`; integration test harness
- Inbound mesh port forwarding on `fips-gateway`: new
  `gateway.port_forwards` config (list of `{ listen_port, proto,
  target }` entries, IPv6 targets only) installs prerouting DNAT
  rules so mesh peers can reach a configured host:port on the
  gateway's LAN. A LAN-side masquerade is added when any forwards
  are configured so replies flow back through conntrack.
- Gateway packaging: systemd service unit with `After=fips.service`,
  Debian and AUR package entries, OpenWrt procd init with dnsmasq
  forwarding, proxy NDP, RA route advertisements, and IPv6 forwarding
  sysctls. Gateway enabled by default on OpenWrt
- `fips-gateway` DNS upstream probe now retries up to 5 times with a
  1-second per-attempt timeout and a 1-second delay between attempts
  (~10 second worst-case wait), instead of a single 3-second hard-fail.
  Covers the cold-boot race where the daemon's TUN is up (the systemd
  ExecStartPre wait gates on that) but the DNS responder is still
  binding `[::1]:5354`. Without retry the gateway exited and relied on
  `Restart=on-failure` for recovery (5-second blip + spurious error
  log line per cycle); with retry the gateway recovers gracefully
  without a unit restart

#### IPv6 Adapter

- Overhauled `.fips` DNS handling for systemd-based hosts. The
  default `dns.bind_addr` is `::1` (IPv6 loopback) and the setup
  script picks one of five backends in priority order: a global
  drop-in at `/etc/systemd/resolved.conf.d/fips.conf`, the systemd
  dns-delegate path, `resolvectl` per-link, standalone dnsmasq, or
  NetworkManager's dnsmasq plugin. Teardown reverses only what was
  applied. New `testing/dns-resolver/` harness exercises every
  backend across Debian 12, Debian 13, Ubuntu 22.04, Ubuntu 24.04,
  and Ubuntu 26.04
  ([#58](https://github.com/jmcorgan/fips/pull/58),
  fixes [#52](https://github.com/jmcorgan/fips/issues/52),
  [#77](https://github.com/jmcorgan/fips/issues/77)).

#### Operator Tooling

- `node.log_level` config field (case-insensitive, default `info`)
  replaces the hardcoded `RUST_LOG=info` previously baked into
  systemd units and the OpenWrt procd init script. The daemon now
  loads config before initializing tracing so the configured level
  takes effect; `RUST_LOG` still overrides when set
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
- Historical node and per-peer statistics: in-memory time-series
  rings on the daemon, surfaced through new control-socket queries,
  `fipsctl stats` subcommands, and a `fipstop` Graphs tab with
  btop-style sparklines
  ([#64](https://github.com/jmcorgan/fips/pull/64)).
- `fipstop` Node tab now carries a "Listening on fips0" panel
  (right-half of the Traffic block) that lists local IPv6 listening
  sockets reachable from the mesh interface, paired with the
  `inet fips` baseline filter classification for each (proto, port).
  Rows render in default White (`OPEN` — the chain has a canonical
  unrestricted accept rule), DarkGray (`filt` — chain falls through
  to `counter drop`), or DarkGray with a `?` State suffix (`filt?` —
  the chain references the port but with matchers the panel cannot
  fully decompose, e.g. saddr filters or jumps). When the
  `fips-firewall.service` is not active, the panel renders a yellow
  banner reminding the operator that all listeners are
  mesh-exposed. Wildcard binds (`local_addr == ::`) carry a `*`
  suffix in the Process column. Powered by a new
  `show_listening_sockets` control query (Linux-only).

#### Packaging and Deployment

- Arch Linux AUR packaging for `fips` (release) and `fips-git`
  (development) packages with sysusers.d/tmpfiles.d integration
  ([#21](https://github.com/jmcorgan/fips/pull/21),
  [@dskvr](https://github.com/dskvr))
- `packaging/debian/fips-gateway.service` now waits up to 30 seconds
  for the daemon's `fips0` TUN to appear before exec'ing the gateway
  binary (`ExecStartPre` poll loop). Eliminates the cold-boot race
  where `fips-gateway` exits with `fips0 interface not found` and
  recovers via `Restart=on-failure`, producing a 5-second blip and a
  spurious error log line per restart cycle. If `fips0` never appears
  within 30 seconds, the existing error path runs as before
- `packaging/debian/build-deb.sh` now auto-derives a per-commit Debian
  Version field for dev builds (Cargo.toml version ending in `-dev`)
  using the form `<base>~dev+git<YYYYMMDD>.<sha>[.dirty]-1`, e.g.
  `0.3.0~dev+git20260429.6def31b-1`. Each commit produces a uniquely-
  comparable Version string so `apt install ./*.deb` and
  `ansible.builtin.apt: deb:` no longer silently no-op when one dev
  build is installed on top of another. The `~dev` marker sorts
  pre-`0.3.0` so a tagged release supersedes any prior dev .deb.
  Tagged release builds (no `-dev` in Cargo.toml) keep the clean
  `<version>-1` form. Operator override via `--version` still wins

#### Examples

- macOS WireGuard sidecar: run FIPS in a local Docker container and
  route `.fips` traffic from the macOS host through a WireGuard tunnel
  to the container's `fips0` interface. Only traffic destined for
  `fd00::/8` transits the sidecar; regular internet traffic continues
  to use the host network
  ([#51](https://github.com/jmcorgan/fips/pull/51))

#### Documentation

- `docs/design/port-advertisement-and-nat-traversal.md` documents
  how nodes find each other through Nostr relays and the
  STUN-assisted UDP hole punch

### Changed

- Noise session ChaCha20-Poly1305 backend switched from RustCrypto's
  `chacha20poly1305` to `ring 0.17`. ring wraps BoringSSL's
  hand-tuned ChaCha20-Poly1305 implementation, dispatching to NEON
  on aarch64 and AVX2 / AVX-512 on x86_64 — typically 3-5 GB/s/core
  vs the ~600-800 MB/s/core RustCrypto soft path on the same
  hardware. Wire format unchanged: ChaCha20-Poly1305 is
  byte-deterministic for a given `(key, nonce, plaintext, aad)`,
  so any correct AEAD produces identical ciphertext and a mixed
  pre-swap / post-swap mesh interoperates without protocol
  awareness. The keyed AEAD is now cached on `CipherState` instead
  of being re-derived per packet (the cached Poly1305 key state is
  the actual perf win); `EndToEndState` grew from ~600 B to
  ~1.5 KB as a consequence and is annotated
  `#[allow(clippy::large_enum_variant)]` since boxing would re-add
  a per-packet indirection on every encrypt/decrypt. aarch64
  measurements (Apple Silicon docker, two nodes): TCP 1-stream
  437 → 1097 Mbps (~2.5×); UDP at 1000 Mbit goes from
  599 Mbps / 40 % loss to lossless line-rate; 3-node ping under
  load 7.68 ms avg / 215 ms max → 0.72 ms / 3.6 ms max as the
  relay path stops being crypto-bound
  ([#80](https://github.com/jmcorgan/fips/pull/80),
  [@mmalmi](https://github.com/mmalmi))
- Linux UDP receive path uses `recvmmsg(2)` with a 32-packet batch
  in place of single-packet `recvmsg(2)`. A single `readable()`
  wakeup drains up to 32 datagrams in one syscall before yielding
  back to the reactor, eliminating the per-packet scheduler-hop +
  futex cost that previously capped inbound rate at one event per
  scheduler quantum independent of CPU. `SO_RXQ_OVFL` is sampled
  once per batch from the cmsg chain of `msgs[0]` and surfaced
  through `AsyncUdpSocket::recv_batch` so the 1Hz
  `sample_transport_congestion()` detector continues to feed the
  per-transport `dropping` flag. macOS / Windows fall through to
  the per-packet path; `recvmmsg` is Linux-specific
  ([#81](https://github.com/jmcorgan/fips/pull/81),
  [@mmalmi](https://github.com/mmalmi))
- `Node::run_rx_loop` drains up to 256 additional ready items via
  `try_recv()` after each `tokio::select!` await fires on
  `packet_rx` / `tun_outbound_rx`, in a tight inner loop before
  yielding. Previously the select cost a full scheduler hop +
  futex per packet, capping throughput at one event per scheduler
  quantum with the worker near-idle. `biased` ordering keeps
  data-plane branches priority over tick / control / DNS under
  sustained load; the 256 cap is empirically tuned to keep the
  worker on a busy stream between yield points (≈ 400 KB of
  contiguous traffic) while still bounding the inner loop so a
  flood on one branch can't starve the periodic tick or control
  socket. Pairs with the UDP `recvmmsg` change above
  ([#81](https://github.com/jmcorgan/fips/pull/81),
  [@mmalmi](https://github.com/mmalmi))
- `PeerIdentity::pubkey_full()` now precomputes the parity-aware
  full public key at construction in `from_pubkey`. Previously the
  method fell through to a secp256k1 EC point parse (`fe_sqrt` +
  `fe_mul` + `ge_set_xo_var`) on every call when the full key
  wasn't passed at construction (i.e. for every peer constructed
  from an npub or x-only key) — ~6% of per-packet CPU on the
  bulk-data send path for a value that never changed after
  construction. The same EC point parse already runs at
  construction inside `NodeAddr::from_pubkey`, so the cost is paid
  once where it would be paid anyway
  ([#81](https://github.com/jmcorgan/fips/pull/81),
  [@mmalmi](https://github.com/mmalmi))
- Cargo feature flags `tui`, `ble`, `gateway`, and
  `nostr-discovery` removed; subsystem inclusion is now driven by
  platform `cfg` gates so plain `cargo build` compiles everything
  available on the target
  ([#79](https://github.com/jmcorgan/fips/pull/79))
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
- The `docs/` tree is reorganised so readers can find content by
  what they're trying to do: tutorials for new users, how-to guides
  for specific tasks, reference material for configuration and
  protocol details, and design discussion for architectural
  background. New top-level `getting-started.md` and per-section
  landing pages anchor the entry points. Content was reconciled
  against current source: protocol layer details, wire-format
  diagrams, configuration knobs, and CLI references were brought
  back into agreement with the implementation. Gateway feature-set
  documentation was rewritten end-to-end.
- Test coverage was substantially expanded for the new release
  surface (discovery state machine, control-socket query handlers,
  decrypt-failure thresholds, STUN parser, gateway, NAT traversal,
  packaging install paths) alongside CI-side hardening for the new
  Windows and macOS platforms.
- Gateway `dns.listen` source default changed from `[::]:53` to
  `[::1]:5353` to match the canonical deployment model (a host
  already serving DHCP/DNS to a LAN segment, where port 53 is
  taken by the existing resolver and `.fips` queries are forwarded
  to the gateway over loopback). The OpenWrt ipk previously
  overrode this in its packaged config; the override is now
  redundant and has been dropped. Operators on a host without a
  pre-existing resolver on port 53 can opt back into the wildcard
  bind by setting `dns.listen: "[::]:53"` explicitly. The new
  default binds IPv6 loopback only — forwarders that reach the
  gateway over IPv4 loopback need an explicit IPv4 listen address.
- Generic systemd install tarball brought to feature parity with
  the `.deb` and AUR packages. The tarball now ships the
  `fips-gateway` binary with its (operator-opt-in)
  `fips-gateway.service`, a `fips-firewall.service` unit with the
  `/etc/fips/fips.nft` mesh-interface nftables baseline (also
  opt-in), an `/etc/fips/fips.d/` operator drop-in directory for
  per-service nft rules, and the multi-backend `fips-dns-setup` /
  `fips-dns-teardown` helpers. `install.sh` and `uninstall.sh`
  handle the new units and conffile (preserve-on-upgrade for
  `fips.nft`, like `fips.yaml`). `README.install.md` documents
  the gateway, firewall, and DNS-routing services. Closes the
  longest-standing parity gap for non-Debian / non-Arch systemd
  Linux distros (Fedora, RHEL/CentOS, openSUSE, etc.) installing
  from the release-distribution tarball.

### Fixed

- Generic systemd install tarball: `install.sh` now correctly
  resolves the `fips-dns-setup` and `fips-dns-teardown` helpers
  from the tarball staging directory. Previously the script
  referenced them at `${SCRIPT_DIR}/../common/`, a path that
  exists only in the source-repo layout, not in the extracted
  tarball. Bug latent since the multi-backend DNS helpers
  landed in `7260ad2`; only manifested when operators ran
  `install.sh` from an extracted tarball rather than from a
  source checkout.

- Adopted NAT-traversed UDP transports inherit the primary listener's
  MTU and buffer config. `Node::adopt_established_traversal`
  constructed the adopted UDP transport with `UdpConfig::default()`
  (MTU 1280, default recv/send buffer sizes, default accept/advertise
  flags) regardless of the operator's primary `[transports.udp]`
  listener. Operators who set the primary MTU higher (e.g. 1500 on
  a known-clean LAN path) silently dropped full-sized tunnel
  datagrams over the NAT-traversed link with no log explaining why
  throughput collapsed. Lookup now tries `transport_name` first (so
  multiple named listeners pick up inheritance from the matching
  one) and falls back to the unnamed `Single` listener; bind /
  external-address fields are cleared since the adopted socket is
  already bound. The 1280 default was deliberately the IPv6 minimum
  (the only value guaranteed across arbitrary middlebox paths);
  with this change, operators who raise the primary MTU accept the
  tradeoff that NAT-traversed flows initially attempt the higher
  MTU and may black-hole on tighter paths until reactive
  `MtuExceeded` recovery kicks in
  ([#83](https://github.com/jmcorgan/fips/pull/83),
  [@mmalmi](https://github.com/mmalmi))
- TreeAnnounce ancestry on self-root transitions. When a node had
  no smaller-NodeAddr peer to use as a parent, the spanning-tree
  state correctly promoted it to root, but the ancestry it
  advertised on the next `TreeAnnounce` still referenced its
  previous parent's path. Receiving peers rejected the announce
  with `invalid ancestry: advertised root X is not the minimum
  path entry Y`, blocking mesh transit on any path that needed to
  traverse the node. The self-root transition is now detected
  explicitly in `TreeState::become_root` and the advertised
  ancestry rebuilt to start from self. The MMP receive handler
  surfaces the same path so stale ancestry inherited across
  reconnect is corrected eagerly rather than waiting for the next
  observation tick
  ([#82](https://github.com/jmcorgan/fips/pull/82),
  [@mmalmi](https://github.com/mmalmi))
- Auto-connect retry refetches the cached overlay advert
  unconditionally before each retry attempt, not only when
  `fetch_advert` returns zero endpoints (`NoTransportForType`).
  The much more common stale-cache failure was: cache returned an
  endpoint that *looked* valid (the address learned before the
  peer's NAT rebound), the dial succeeded at the IP layer, the
  handshake timed out, MMP fired, the next retry hit the same
  cached endpoint, looped forever — no `NoTransportForType` ever
  fired because the cache had data, just dead data. Refetch now
  runs unconditionally before each retry attempt (one Filter query
  against `advert_relays` with a 2s per-attempt timeout, bounded
  by the retry backoff cadence). Keeps the retry loop pinned to
  relay ground truth instead of whatever the cache happened to
  learn at startup
  ([#82](https://github.com/jmcorgan/fips/pull/82),
  [@mmalmi](https://github.com/mmalmi))
- Stale overlay-advert eviction on `NoTransportForType`. Mirrors
  the existing stale-advert sweep that ran from the
  `BootstrapEvent::Failed` (NAT-traversal-streak) path, but covers
  the case where `initiate_peer_connection` / a retry tick returns
  `NodeError::NoTransportForType` — the cache had no addresses for
  the peer at all. A fire-and-forget `refetch_advert_for_stale_check`
  against the peer's npub re-fetches kind `37195` from
  `advert_relays`; if the relay has a newer advert it replaces the
  cached entry, if it has nothing it evicts the entry. Either way
  the next retry tick goes to fresh data instead of looping on the
  same dead endpoint. Resolves a deployment regression where a
  macOS daemon's view of a Linux peer would flap after NAT rebind
  with no recovery short of a daemon restart
  ([#82](https://github.com/jmcorgan/fips/pull/82),
  [@mmalmi](https://github.com/mmalmi))
- Schedule retry on startup peer-init failure. When
  `initiate_peer_connections()` ran at boot, an address-resolution
  failure (no operational transport for the configured transport
  types, all addresses unreachable, NAT rebind invalidating cached
  endpoints) was logged and silently forgotten — the peer entry
  stayed in a dead state forever, accepting incoming pings but
  unable to answer them, until the daemon was manually restarted.
  Now mirrors the `BootstrapEvent::Failed` path: on a startup
  peer-init error, parse the peer's npub and call `schedule_retry`
  so the peer recovers without operator intervention
  ([#82](https://github.com/jmcorgan/fips/pull/82),
  [@mmalmi](https://github.com/mmalmi))
- Default control-socket path resolution: daemon and client tools now
  use a shared resolver, eliminating a divergence where `fipsctl` /
  `fipstop` could connect to a socket the daemon never bound (notably
  on dev runs with `XDG_RUNTIME_DIR` set, or after a prior packaged
  install left a root-owned `/run/fips` behind). Canonical order is
  `/run/fips` → `$XDG_RUNTIME_DIR/fips/` → `/tmp/fips-<name>`. The
  `/run/fips` arm is selected by directory existence; the kernel
  enforces actual access at `connect(2)` time, surfacing a clear
  `EACCES` for users not yet in the `fips` group rather than silently
  steering them to a path the daemon never bound. `XDG_RUNTIME_DIR` is
  validated as an existing directory before being used so stale
  post-logout values are treated as missing. The deployed fleet is
  unaffected: packaged configs set `node.control.socket_path`
  explicitly.
- UDP transport with `advertise_on_nostr: true` + `public: true` +
  a wildcard `bind_addr` (e.g. `0.0.0.0:2121`) is now advertised
  with its STUN-discovered public IPv4 instead of being silently
  dropped from the published Kind 37195 advert. Previously the
  advert builder filtered the wildcard out (since `0.0.0.0` is
  not a valid endpoint), but emitted no log explaining what
  happened — operators saw the daemon up, both flags set, and
  no UDP endpoint in the advert. The fix runs a one-shot STUN
  observation against an ephemeral socket on the daemon's
  configured `stun_servers` and combines the reflexive IPv4 with
  the configured listener port for the advert (`udp:<eip>:<port>`).
  Successful STUN observations are cached per-transport for one
  `advert_refresh_secs` cycle (default 30 min) so we don't re-STUN
  every refresh. Failed observations are cached for only 60s, so
  a transient STUN flake at startup retries within ~a minute and
  grows the advert with UDP as soon as STUN starts working —
  rather than waiting the full 30-min cycle. Per-server STUN
  response timeout is 5s for the advert-publish path (vs. 2s for
  the latency-sensitive per-traversal path), giving slow
  first-call STUN time to complete without giving up. On STUN
  failure, the wildcard-bind path still skips, but now logs a
  loud `warn!` pointing at the operator-side fixes (set
  `external_addr`, bind to a specific IP, or ensure `stun_servers`
  reachable). Restores zero-config public-IP autodiscovery on
  AWS EIP / GCP / Azure setups where binding to the public IP
  directly is impossible (1:1 NAT)
- New `external_addr` field on `transports.udp.*` and
  `transports.tcp.*` for explicit advertise-as override. Accepts
  either a bare IP (`"198.51.100.1"` — the configured `bind_addr`
  port is appended) or a full `host:port`
  (`"198.51.100.1:8443"`). Takes precedence over both the bound
  address and any STUN-derived autodiscovery. Required for TCP
  on cloud-NAT setups (AWS EIP, GCP/Azure external IPs) where
  binding to the public IP directly fails with `EADDRNOTAVAIL`
  (the EIP isn't on a host interface). Optional but useful for
  UDP as a deterministic alternative to STUN — operators who
  want to skip STUN egress (or whose STUN is blocked) can
  specify it explicitly. Without `external_addr`, TCP with a
  wildcard `bind_addr` + `advertise_on_nostr: true` now logs a
  loud `warn!` pointing at the two fixes instead of silently
  skipping
- Nostr-discovery now tolerates ±60s of clock skew on offer/answer
  freshness checks so a responder whose wall clock leads the
  initiator's by less than that no longer silently rejects every
  offer. Previously, a public-test daemon with un-NTP'd peers (or
  long uptime — `now_ms()` anchors to `SystemTime` once at startup,
  then advances monotonically; post-startup NTP step adjustments
  don't propagate) would see ~100% signal-timeout rate against
  skewed peers, indistinguishable from "peer is offline." New
  optional `offerReceivedAt` field on the answer payload lets the
  initiator log per-peer NTP-style skew estimates (DEBUG when ≥30s)
  for operator visibility. Backward-compatible — older responders
  that don't fill the field still produce valid answers
- Nostr-discovery NAT-traversal failure suppression: per-npub
  consecutive-failure counter triggers a 30-min extended cooldown
  after 5 failures, preventing the daemon from hammering Nostr
  relays with offers to peers that have gone away. WARN log lines
  rate-limited to one per peer per 5 min (subsequent failures
  emit DEBUG with `consecutive_failures` + remaining `cooldown_secs`).
  Threshold-crossing also fires a one-shot active re-check of the
  peer's Kind 37195 advert against `advert_relays`; absent →
  evict cache; newer → refresh + reset streak; same → cooldown
  stands. New `failure_streak_threshold`, `extended_cooldown_secs`,
  `warn_log_interval_secs`, `failure_state_max_entries` config
  fields under `node.discovery.nostr`. Per-peer state visible in
  `fipsctl show peers` JSON under `nostr_traversal`
- Tor onion adverts published over Nostr overlay discovery now
  include the public-facing port (`<onion>.onion:<port>`) instead of
  just the bare onion hostname. The publisher previously emitted a
  bare onion that the parser refused (`expected host:port`),
  producing a persistent retry-fail loop on any peer whose Tor
  advert was the only entry in the discovery cache. New
  `transports.tor.advertised_port` config field (default `443`,
  matching the Tor `HiddenServicePort` convention) controls the
  advertised port; operators with non-default virtual ports can
  override.
- TCP-over-FIPS reliability on mesh paths with mixed transport
  MTUs (e.g. a UDP-1280 hop in the picker set) improved. Three
  interlocking changes: `Node::transport_mtu()` is now deterministic
  across restarts (min across operational transports rather than
  insertion-order-dependent); the TCP MSS clamp at the TUN boundary
  reads per-destination path MTU instead of a single global ceiling;
  and reactive `MtuExceeded` from forwarders is mirrored back into
  the TUN-side `path_mtu_lookup` so later flows pick up forward-path
  bottlenecks without re-discovery. Windows TUN reader receives the
  same per-destination plumbing.
- Proactive end-to-end `PathMtuNotification` now mirrors into the
  TUN-side `path_mtu_lookup` (TCP MSS clamp store), parallel to the
  reactive `MtuExceeded` mirror that already existed. Previously the
  proactive handler only updated the session-canonical
  `MmpSessionState.path_mtu`; on stable long-lived paths where the
  destination's echo had tightened the session MTU but no transit
  router had emitted a fresh `MtuExceeded` (because all current
  traffic was already sized by the tighter session value), new TCP
  flows opened in that window kept getting clamped by the staler
  discovery-time value. The proactive mirror closes that gap with
  the same tighter-only semantics — never loosens the clamp.
- Nostr-discovered peers running an FMP-protocol version we cannot
  speak no longer trigger an indefinite retraversal storm. Open-
  discovery NAT-traversal succeeds at the UDP layer regardless of
  protocol version, so the daemon would adopt the punched socket,
  drop every incoming packet at `Unknown FMP version`, idle out
  after 31s, and re-fire the full STUN-offer-answer-punch sequence
  ~30s later — every minute, forever, against peers the handshake
  literally cannot complete with. The rx loop now detects mismatched-
  version packets arriving on adopted bootstrap transports, reverse-
  maps to the originating npub, and applies a long structural
  cooldown to the discovery layer's `failure_state` so the next
  open-discovery sweep skips the peer until either side upgrades.
  One-shot WARN per fresh observation; subsequent mismatches inside
  the cooldown window are silent. New `protocol_mismatch_cooldown_secs`
  config field under `node.discovery.nostr` (default 86400 = 24h),
  separate from the transient-failure `extended_cooldown_secs`.
- `fipstop` now uses `ratatui::try_init()` instead of `ratatui::init()`,
  so terminal initialization failures (e.g. Docker on macOS Sequoia,
  or environments without a usable tty) produce a clean error message
  instead of a hard crash
- Spanning-tree updates that change only the internal path between
  root and leaf — without changing the root or the depth — now
  propagate to leaves correctly. Previously a leaf could continue
  routing against a stale internal path until the parent or depth
  also changed.

## [0.2.1] - 2026-05-11

### Added

- Linux release artifact workflow: builds x86_64 and aarch64 tarballs
  and `.deb` packages on `v*` tag push, with SHA-256 checksums
- AUR publish workflow for tagged stable releases

### Changed

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
- Tighten TreeAnnounce ancestry validation to match the spanning
  tree specification. The receive path now verifies that the
  ancestry is structurally consistent with the signed parent
  declaration before mutating tree state.
- Make the tree ancestry acceptance unit test deterministic.
  `test_tree_announce_validate_semantics_accepts_valid_non_root`
  generated a random signing identity while pinning the fixed root
  to `node_addr[0] = 0x01`; about 2 in 256 random identities were
  numerically smaller than the claimed root, triggering
  `AncestryRootNotMinimum`. The test now regenerates the identity
  until its `node_addr` is strictly larger than both the fixed
  parent and root.

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
