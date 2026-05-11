# FIPS v0.3.0

**Released**: 2026-05-11

v0.3.0 is the testing-and-polishing release on the v0.2.x wire format.
It widens the platform reach of FIPS from Linux-only to Linux, macOS,
Windows, and OpenWrt; adds two large new mesh capabilities (Nostr-mediated
peer discovery with UDP NAT traversal, and the `fips-gateway` LAN bridge);
ships a default-deny security baseline for the mesh interface; introduces
mesh-peer access control; substantially speeds up session-layer crypto and
the Linux receive path; and tightens packaging across every supported
distribution channel.

v0.3.0 is wire-compatible with v0.2.x. Mixed meshes interoperate; there
is no flag-day upgrade.

v0.3.0 also rolls forward all changes from the v0.2.1 maintenance
release. The sections below cover the cumulative v0.2.0 → v0.3.0
delta; the per-section intros call out which entries first shipped
in v0.2.1.

## At a glance

- 123 commits since v0.2.0 (109 non-merge), spanning 307 files with
  +44,186 / -4,078 lines.
- 10 committers plus 3 issue reporters across feature work, fixes,
  packaging, and reviews.
- 5 new GitHub Actions CI workflows (Linux Package, macOS Package,
  Windows Package, OpenWrt Package, AUR Publish) plus expanded
  integration matrices (gateway, NAT-cone, NAT-symmetric, NAT-LAN,
  rekey-accept-off, `.deb` install across Debian 12/13 + Ubuntu
  22/24/26, multi-backend `.fips` DNS resolver across the same five
  distros).
- The long-standing systemd-resolved DNS-responder silent-drop is
  closed end-to-end.
- Pre-1.0 control-socket JSON schema change for two query fields;
  see [Upgrade notes](#upgrade-notes).

## What's new

### Mesh discovery and NAT traversal

Previously, two FIPS nodes could only become peers if they had a way
to find each other beforehand: a configured address, a shared LAN
segment, or a Bluetooth radio range. v0.3.0 introduces a Nostr-based
overlay-discovery channel that lets nodes find each other through any
public Nostr relay set, plus a STUN-assisted UDP hole-punching path
that connects peers across most consumer NATs.

Each participating node publishes a signed overlay advert as a Nostr
**Kind 37195** parameterized replaceable event. (The kind sits in the
application-defined replaceable range and the digits visually spell
*FIPS*: 7=F, 1=I, 9=P, 5=S.) The advert lists reachable transport
endpoints (UDP, TCP, Tor) and is consumed by other nodes to populate
fallback addresses for `via_nostr` peers. Under `policy: open`, the
advert cache is also dialed for non-configured peers within a budget
cap.

When both peers are behind NAT, the daemon coordinates a UDP hole
punch using NIP-59 gift-wrap signaling for the offer/answer exchange
and STUN for reflexive address discovery. A candidate-pair punch
planner attempts LAN-private and reflexive paths in parallel; on
success the live socket is handed into the standard FIPS UDP transport
via a bootstrap-handoff API.

Operators turn this on with `node.discovery.nostr.enabled: true` and
the configured relay set. `policy: open` adds best-effort dialing of
non-configured peers seen on the relays. New `peers[].via_nostr` and
per-transport `advertise_on_nostr` / `public` flags control what each
endpoint contributes to the published advert. Cross-field validation
runs at startup to catch mis-configured combinations early.

A Docker NAT lab covering cone, symmetric, and LAN scenarios is wired
into the integration CI matrix. A daemon-side failure-suppression
layer (per-npub cooldown after consecutive failures, ±60s clock-skew
tolerance, rate-limited WARN logs) keeps relay traffic well-mannered
when peers come and go from the open discovery cache. A separate
structural cooldown (`protocol_mismatch_cooldown_secs`, default 24h)
suppresses retraversal when a punched peer turns out to be running an
FMP version this daemon cannot handshake with: the punch completes at
the UDP layer, the rx loop spots the version-mismatched packet,
reverse-maps to the originating npub, and removes the peer from the
next sweep until either side upgrades.

The auto-connect retry loop pins itself to relay ground truth. Each
retry attempt refetches the cached overlay advert against the
configured `advert_relays` (one filter query, 2s timeout) before
dialing, so a peer whose NAT rebound to a fresh endpoint is recovered
on the next retry rather than looping on a stale cached address.
`NoTransportForType` triggers a fire-and-forget re-fetch that either
replaces or evicts the cache entry. A startup peer-init failure (no
operational transport, all addresses unreachable) now schedules a
retry instead of leaving the peer in a dead state until the daemon is
restarted. Adopted NAT-traversed UDP transports inherit the operator's
primary `[transports.udp]` listener config (MTU, recv/send buffer
sizes) instead of falling back to the 1280 IPv6-minimum default.

### Cross-platform reach

FIPS now ships first-class binaries for **Linux, macOS, Windows, and
OpenWrt**.

- **macOS** support uses the native `utun` TUN interface, raw
  Ethernet via BPF, a `.pkg` installer with a launchd plist and
  uninstall script, and an x86_64 cross-compile from arm64 build
  hosts. A new CI matrix entry runs build and unit-test jobs on
  macOS hosts.
- **Windows** support uses [wintun](https://www.wintun.net/) for the
  TUN device, a TCP control socket on `localhost:21210` (replacing
  the Unix domain socket Linux and macOS use), Windows Service
  lifecycle (`fips.exe --install-service`, `--uninstall-service`,
  `--service`), and a ZIP package with PowerShell install/uninstall
  scripts.
- **MIPS** atomic-ABI portability lets the daemon build for 32-bit
  MIPS targets (`mips`, `mipsel`, MIPS32r2) by routing through
  `portable_atomic`. This unblocks OpenWrt deployments on
  consumer-grade MIPS routers.
- **OpenWrt** packaging gets a procd init with dnsmasq forwarding,
  proxy NDP, RA route advertisements, and IPv6 forwarding sysctls.
  The `fips-gateway` is enabled by default in the OpenWrt build.

### FIPS gateway

The new `fips-gateway` binary lets unmodified LAN hosts reach FIPS
mesh destinations without running the FIPS daemon themselves. Two
flows ship together:

- **Outbound (LAN -> mesh)**: a virtual-IP pool (default
  `fd01::/112`) is allocated on demand from `.fips`-name DNS lookups.
  A state-machine lifecycle, conntrack-backed session tracking, proxy
  NDP on the LAN interface, and TTL-based reclamation handle the
  bookkeeping. A LAN host that resolves `peer.fips` gets a virtual
  address it can reach over IP, and the gateway translates the flow
  to the mesh.
- **Inbound (mesh -> LAN)**: new `gateway.port_forwards` config
  installs prerouting DNAT rules so mesh peers can reach a configured
  `host:port` on the gateway's LAN. A LAN-side masquerade is added
  automatically when any forwards are configured, so replies flow
  back through conntrack.

A dedicated control socket at `/run/fips/gateway.sock` exposes
`show_gateway` and `show_mappings`. `fipstop` adds a Gateway tab with
a pool gauge and mappings table.

The gateway's `dns.listen` source default is now `[::1]:5353`,
matching the canonical deployment model: the gateway sits on a host
already serving DHCP and DNS to a LAN segment (an OpenWrt AP, a Linux
router), port 53 there is taken by the existing resolver, and `.fips`
queries are forwarded to the gateway over loopback. The OpenWrt ipk
previously overrode the prior `[::]:53` source default in its packaged
config; that override is now redundant and has been dropped.
Operators on a host without a pre-existing resolver on port 53 can
opt back into the wildcard bind by setting `dns.listen: "[::]:53"`
explicitly. The new default binds IPv6 loopback only, so forwarders
that reach the gateway over IPv4 loopback need an explicit IPv4
listen address.

The cold-boot startup race between `fips.service` and
`fips-gateway.service` is handled by a systemd `After=fips.service`
ordering, an `ExecStartPre` poll loop that waits up to 30 seconds for
the `fips0` interface to appear, and a DNS upstream probe in the
gateway itself that retries up to 5 times with 1-second backoff.

Packaging covers systemd, Debian, AUR, and OpenWrt. The full design
is in [`docs/design/fips-gateway.md`](../design/fips-gateway.md).

### Mesh-interface security baseline

The FIPS mesh is a flat layer-3 segment. Every authenticated peer can
route packets to every other peer's `fips0` address. Peer identity is
authenticated end-to-end by the FMP and FSP Noise handshakes, but
identity is not authorization. A service on a mesh host that binds to
a wildcard address is, by default, reachable from every peer in the
mesh.

v0.3.0 ships an opt-in default-deny baseline that closes this gap on
Linux:

- **`/etc/fips/fips.nft`** is installed as a documented operator
  conffile. It defines a single `inet fips` nftables table with one
  chain hooked at `input`, default-denies inbound traffic on
  `fips0`, and is a no-op for every other interface.
- **`fips-firewall.service`** loads it. The unit ships **disabled by
  default**; activation is an explicit
  `systemctl enable --now fips-firewall.service`.
- Per-service allowances live in **`/etc/fips/fips.d/*.nft`**
  drop-ins that the baseline includes.

Choosing opt-in keeps the mesh quick to bring up for evaluation while
giving operators a documented, packaged path to lock it down for
production. The full design (threat model, rule layout, conntrack
handling, drop-in mechanism, and the rationale for a conffile rather
than an auto-loaded package side-effect) is in
[`docs/design/fips-security.md`](../design/fips-security.md).

`fipstop`'s Node tab gains a **"Listening on fips0" panel** that
surfaces the answer to the operational question "what services on
this host are reachable from the mesh, and what does the firewall
currently say about each of them?" The panel lists every IPv6
listening socket bound to either the wildcard address or this node's
`fd00::/8` address, paired with its classification against the
running `inet fips` baseline chain: `OPEN` (canonical accept rule),
`filt` (falls through to drop), or `filt?` (referenced with matchers
the panel cannot fully decompose, e.g. saddr filters or jumps). When
`fips-firewall.service` is inactive, a yellow banner above the table
reminds the operator that every listener is mesh-exposed; wildcard
binds carry a trailing `*` in the Process column. The classifier is
built on a new `show_listening_sockets` control query (Linux-only),
which is also useful from `fipsctl` for scripting.

### Peer access control

Operators can now restrict which mesh peers a node will form direct
links with. Optional `/etc/fips/peers.allow` and `/etc/fips/peers.deny`
files (TCP-Wrappers style) match against npub, hex pubkey, host
alias, or `ALL`. Enforcement runs at three points:

1. Outbound connect (before dialing).
2. Inbound msg1 (the first FMP handshake message from a new peer).
3. Outbound msg2 (the response).

Files reload automatically on mtime change; a new `fipsctl acl show`
query reports the effective rule set. A six-node Docker integration
harness (`testing/acl/`) exercises allowlist and denylist patterns
end-to-end.

**Important scope distinction**: peer ACLs are an FMP-layer
restriction. They control who can establish a *direct link* with this
node. They do **not** control session-layer (FSP) reachability through
the mesh. A node that denies peer X with an ACL can still receive FSP
traffic from X relayed via other peers.

### Bluetooth Low Energy transport (experimental, Linux)

A new BLE L2CAP Connection-Oriented Channel transport lets FIPS nodes
peer over Bluetooth Low Energy without any IP infrastructure in
between. The transport handles per-link MTU negotiation, continuous
scan/probe peer discovery with cooldown-based deduplication,
continuous advertising, deterministic NodeAddr cross-probe
tie-breaker, and a configurable connection pool with eviction.

This transport is **experimental in v0.3.0**. It is implemented and
functional on Linux (BlueZ via `bluer`), but the reliability follow-up
logic (probe cooldown, cross-probe tie-breaker, pubkey timeout,
continuous advertising semantics, probe-promotion, fail-fast send) is
not yet behaviorally tested in CI. Its maturity path is field-driven;
please file issues with field reports. macOS BLE support is in
development as a separate track and is not part of v0.3.0.

### UDP transport profiles

The UDP transport gains posture flags organized around deployment
patterns:

- **Public-facing inbound nodes**: `bind_addr: "0.0.0.0:2121"`,
  `accept_connections: true` (default), `public: true` for advert
  publication. v0.3.0 adds STUN-based public-IP autodiscovery so
  cloud nodes (AWS EIP, GCP, Azure 1:1 NAT) advertise the right
  address even when the public IP isn't on a host interface.
- **Ephemeral leaf nodes**: `outbound_only: true` binds an ephemeral
  port (`0.0.0.0:0`), refuses inbound msg1, and is never advertised
  on Nostr regardless of `advertise_on_nostr`. Use this for client
  postures that should connect outbound only, without exposing an
  inbound listener on a known port.
- **General-purpose nodes**: `accept_connections: false` mirrors the
  Ethernet/BLE knob without changing the bind address. The Node-level
  handshake gate carves out msg1 from peers already established on
  this transport so rekey continues to work.

Startup validation now rejects `bind_addr` set to a loopback address
when at least one peer has a non-loopback UDP address, closing a
silent-failure trap from v0.2.0 where Linux's source-address routing
check would drop outbound flows from the loopback-bound socket.

A new `external_addr` field on `transports.udp.*` and
`transports.tcp.*` lets operators specify the advertise-as address
explicitly. This is useful for UDP as a deterministic alternative to
STUN, and required for TCP on cloud-NAT setups (where binding to the
public IP fails with `EADDRNOTAVAIL` because the IP isn't on a host
interface).

### `.fips` DNS resolver overhaul

The IPv6 adapter's `.fips` name resolution has been rebuilt around
the constraints of contemporary systemd-based hosts. The default
`dns.bind_addr` is now `::1` (IPv6 loopback), and a setup script
picks one of five backends in priority order:

1. systemd-resolved global drop-in
   (`/etc/systemd/resolved.conf.d/fips.conf`).
2. systemd dns-delegate (per-link configuration handed off to
   systemd-resolved).
3. `resolvectl` per-link configuration.
4. Standalone `dnsmasq`.
5. NetworkManager's dnsmasq plugin.

Teardown reverses only what setup applied, recorded in a state file
at `/run/fips/dns-backend`. A new `testing/dns-resolver/` harness
exercises every backend across Debian 12, Debian 13, Ubuntu 22.04,
Ubuntu 24.04, and Ubuntu 26.04, so a regression in any of the five
backends shows up in CI rather than in the field.

This overhaul resolves the long-standing silent-drop case where the
`resolvectl dns fips0 [<fips0_addr>]:5354` target collided with the
daemon's mesh-interface filter on certain systemd-resolved
deployments (typically Ubuntu 22 with systemd 249's interface-scoped
routing).

### Operator tooling additions

A handful of additions land in `fipsctl`, `fipstop`, and the daemon's
configuration surface:

- **`node.log_level`** config field replaces the hardcoded
  `RUST_LOG=info` previously baked into systemd units and the
  OpenWrt procd init. The daemon now loads config before
  initializing tracing so the configured level takes effect.
  `RUST_LOG` still overrides when set.
- **`fipsctl show identity-cache`** is a new query that lists every
  cached node identity (npub, IPv6 address, display name, LRU age)
  alongside the configured cache capacity.
- **`fipsctl show peers / sessions / cache / routing`** are
  substantially extended: per-peer security signals (replay
  suppression count, consecutive decrypt failures), Noise session
  counters, session indices, rekey lifecycle state, handshake resend
  counts, K-bit epoch, coords-warmup remaining, drain state, per-peer
  retry state, per-target lookup detail (attempt, age, last sent),
  and pending TUN packet queue depth.
- **Historical statistics**: in-memory time-series rings on the
  daemon (1-second × 3600 fast, 1-minute × 1440 slow) cover per-node
  and per-peer metrics. New `show_stats_*` control-socket queries, a
  `fipsctl stats list / peers / history` subcommand with Unicode
  sparkline rendering, and a `fipstop` Graphs tab with btop-style
  sparklines surface them to the operator.

### Performance

Two independent perf threads land in v0.3.0: a session-layer crypto
backend swap, and a Linux receive-path overhaul.

**Session-layer crypto backend.** The ChaCha20-Poly1305 backend used
by every FIPS Noise session (end-to-end FSP traffic and link-layer
FMP traffic alike) has been swapped from RustCrypto's
`chacha20poly1305` crate to `ring 0.17`. ring wraps BoringSSL's
hand-tuned ChaCha20-Poly1305 implementation, which dispatches to NEON
on aarch64 and AVX2 / AVX-512 on x86_64. Typical throughput is in the
3-5 GB/s/core range, versus the ~600-800 MB/s/core RustCrypto soft
path on the same hardware.

Wire format is unchanged. ChaCha20-Poly1305 is byte-deterministic for
a given `(key, nonce, plaintext, aad)`, so any correct AEAD
implementation produces identical ciphertext. A mixed mesh with some
nodes pre-swap and some post-swap interoperates without protocol
awareness; v0.3.0 can roll out across a mesh in any order.

Measurements on an aarch64 Apple Silicon docker target:

- Two-node TCP single-stream: 437 -> 1097 Mbps (about 2.5×).
- Two-node UDP at 1000 Mbit: 599 Mbps with 40% loss -> lossless at
  line rate.
- Three-node ping under bulk-traffic load: 7.68 ms avg / 215 ms max
  -> 0.72 ms / 3.6 ms max as the relay path stops being crypto-bound.

No operator-visible action is required; the swap is internal to the
session layer.

**Linux UDP receive path.** The Linux UDP receive path now uses
`recvmmsg(2)` with a 32-packet batch in place of single-packet
`recvmsg(2)`. A single `readable()` wakeup drains up to 32 datagrams
in one syscall before yielding back to the reactor, eliminating the
per-packet scheduler-hop and futex cost that previously capped
inbound rate at one event per scheduler quantum independent of CPU.
`SO_RXQ_OVFL` is sampled once per batch and surfaced through
`AsyncUdpSocket::recv_batch` so the existing 1Hz transport-congestion
detector continues to feed the per-transport `dropping` flag. macOS
and Windows fall through to the per-packet path; `recvmmsg` is
Linux-specific.

**Inner rx-loop drain batching.** `Node::run_rx_loop` drains up to
256 additional ready items via `try_recv()` after each
`tokio::select!` await fires on the packet and TUN-outbound branches,
in a tight inner loop before yielding. Previously the select cost a
full scheduler hop and futex per packet, capping throughput at one
event per scheduler quantum with the worker near-idle. `biased`
ordering keeps data-plane branches priority over tick / control / DNS
under sustained load; the 256 cap keeps the worker on a busy stream
between yield points (about 400 KB of contiguous traffic) while still
bounding the inner loop so a flood on one branch cannot starve the
periodic tick or control socket.

**Eager `pubkey_full` precompute.** `PeerIdentity::pubkey_full()`
precomputes the parity-aware full secp256k1 public key at
construction in `from_pubkey`. Previously the method fell through to
an EC point parse on every call when the full key wasn't passed at
construction (i.e. for every peer constructed from an npub or x-only
key), about 6% of per-packet CPU on the bulk-data send path for a
value that never changed after construction. The same parse already
runs at construction inside `NodeAddr::from_pubkey`, so the cost is
paid once where it would be paid anyway.

These three changes are a coordinated set: the syscall batching
removes the per-packet kernel cost, the inner-loop drain removes the
per-packet scheduler cost, and the pubkey-cache change removes the
per-packet crypto-derivation cost. Like the AEAD swap, they are all
internal and require no operator action.

### Examples

- **macOS WireGuard companion** ([#51](https://github.com/jmcorgan/fips/pull/51)):
  run FIPS in a local Docker container and route `.fips` traffic
  from the macOS host through a WireGuard tunnel to the container's
  `fips0`. Only traffic destined for `fd00::/8` transits the
  companion; regular internet traffic continues to use the host
  network. Persistent FIPS and WireGuard key material is generated
  on first run.

### Documentation

- **`docs/design/port-advertisement-and-nat-traversal.md`**
  documents how nodes find each other through Nostr relays and the
  STUN-assisted UDP hole punch.
- **`docs/design/fips-gateway.md`** documents the gateway's virtual
  IP pool, lifecycle, control surface, and packaging.
- **`docs/design/fips-security.md`** documents the mesh-interface
  security posture, threat model, default-deny baseline, and drop-in
  workflow.
- **`CONTRIBUTING.md`** has been expanded with build prerequisites,
  Rust toolchain setup, and first-build steps.

The `docs/` tree has been reorganized end-to-end into four sections
(*tutorials / how-to / reference / design*) with a new
[`docs/getting-started.md`](../getting-started.md) and per-section
landing pages. Content was reconciled against current source:
protocol-layer details, wire-format diagrams, configuration knobs,
and CLI references were brought back into agreement with the
implementation. See [Documentation pointers](#documentation-pointers)
below for entry points by reader intent.

## Behavior changes worth flagging

These default-config changes affect every operator on upgrade, even
those with no explicit configuration. Two items below — bloom-filter
fill-ratio validation and TreeAnnounce ancestry validation — first
shipped in v0.2.1 and roll forward into v0.3.0; the rest are
v0.3.0-net-new.

- **Discovery rate-limiting** has been retuned to be less aggressive
  at cold start. v0.2.0 used a single-lookup-with-internal-retry
  model where a timed-out lookup during bloom-filter propagation
  could suppress retries for 30 seconds while none of the reset
  triggers fired on a stable post-handshake topology. v0.3.0
  replaces this with a per-attempt timeout sequence
  (`node.discovery.attempt_timeouts_secs`, default `[1, 2, 4, 8]`,
  15s total). Each attempt sends a fresh `LookupRequest` with a new
  `request_id`, letting successive attempts take different
  forwarding paths as the bloom and tree state evolve. Post-failure
  suppression is **off by default**; operators with chatty
  applications can opt back in via `backoff_base_secs` /
  `backoff_max_secs`.
- **MMP report intervals** are retuned for constrained transports.
  The steady-state floor moves from 100ms to 1000ms, the ceiling
  from 2000ms to 5000ms, with a cold-start phase running 200ms for
  the first 5 SRTT samples. This reduces BLE overhead by roughly
  10× while keeping reports well above the EWMA convergence
  threshold. Session-layer MMP intervals are unchanged.
- **Bloom filter fill-ratio validation** runs on every inbound
  `FilterAnnounce`. Filters whose derived false-positive rate
  exceeds `node.bloom.max_inbound_fpr` (default 0.05) are rejected
  silently on the wire, logged at WARN, and counted in a new
  `bloom.fill_exceeded` counter. A rate-limited WARN also fires
  when the local outgoing filter exceeds the cap.
- **TreeAnnounce ancestry validation** is now run before tree-state
  mutation, enforcing ancestry-self-match, root-single-entry,
  parent-second-entry, and root-is-minimum-NodeAddr. Non-conforming
  announces are rejected with a WARN. Mixed v0.2.0 / v0.2.1 / v0.3.0
  meshes may produce WARN log lines on the v0.2.1+ side until all
  peers upgrade; behavior is correct, log noise only.
- **Log noise reduction**: 35 info-level log messages have been
  demoted to debug (handshake cross-connection mechanics, periodic
  MMP telemetry, TUN/transport shutdown, retry scheduling). The
  default `RUST_LOG` in systemd units is now `info`, where it
  previously ran at `debug`. Operator-visible info output now
  focuses on lifecycle events, peer promotions, session
  establishment, parent switches, and transport start/stop.

## Notable bug fixes

These pre-existing v0.2.0 bugs are worth singling out because they
either affected real-world deployments or produced misleading
operator experiences. The CHANGELOG has the exhaustive list; this is
the operator-relevant subset. Four items below first shipped in
v0.2.1 and roll forward into v0.3.0: auto-connect Disconnect-reconnect,
`fipsctl connect` mesh-address rejection, `fd00::/8` routing
protection from Tailscale interception, and bloom-filter routing
greedy-tree fallback. The control-socket path-detection fix landed
in v0.2.1 as well, and the unified resolver below is the v0.3.0
refactor that builds on it.

- **DNS responder silent-drop on systemd-resolved** is fixed: the
  responder no longer drops queries on Ubuntu 22 / Debian 13 and
  similar deployments where systemd applies interface-scoped
  routing. Default bind moves to `::1`; new global drop-in backend
  available ([#52](https://github.com/jmcorgan/fips/issues/52),
  [#77](https://github.com/jmcorgan/fips/issues/77)).
- **Auto-connect peers reconnect after a graceful Disconnect.**
  Previously, a clean upstream shutdown left the auto-connect peer
  orphaned; only the link-dead, decrypt-fail, and peer-restart
  paths scheduled a reconnect
  ([#60](https://github.com/jmcorgan/fips/issues/60), reported by
  [@SwapMarket](https://github.com/SwapMarket)).
- **`fipsctl connect` rejects FIPS mesh addresses** (`fd00::/8`)
  for `udp`, `tcp`, and `ethernet` transports with a clear error
  message, instead of echoing success while the daemon silently
  failed the bind with `EAFNOSUPPORT`
  ([#61](https://github.com/jmcorgan/fips/issues/61), reported by
  [@SwapMarket](https://github.com/SwapMarket)).
- **Default control-socket path resolution unified.** Daemon and
  client tools now share a single resolver, eliminating a divergence
  where `fipsctl` / `fipstop` could connect to a socket the daemon
  never bound (notably on dev runs with `XDG_RUNTIME_DIR` set, or
  after a prior packaged install left a root-owned `/run/fips`
  behind). Canonical order is
  `/run/fips` -> `$XDG_RUNTIME_DIR/fips/` -> `/tmp/fips-<name>`. The
  `/run/fips` arm is selected by directory existence; the kernel
  enforces actual access at `connect(2)` time, so users not yet in
  the `fips` group get a clear `EACCES` rather than a silent path
  mismatch and a misleading `No such file` fallback to
  `$XDG_RUNTIME_DIR`. `XDG_RUNTIME_DIR` is validated as an existing
  directory before being used so stale post-logout values are
  treated as missing. The deployed fleet is unaffected: packaged
  configs set `node.control.socket_path` explicitly
  ([#30](https://github.com/jmcorgan/fips/issues/30), reported by
  [@Sebastix](https://github.com/Sebastix)).
- **`fd00::/8` routing protected from Tailscale interception.** The
  daemon installs an IPv6 routing-policy rule
  (`ip -6 rule to fd00::/8 lookup main priority 5265`) at TUN
  setup, so Tailscale's table 52 default route can no longer divert
  mesh traffic.
- **TCP-over-FIPS reliability on mixed-MTU paths** is markedly
  improved. Four interlocking changes ship together:
  `Node::transport_mtu()` is now deterministic across daemon
  restarts (min across operational transports rather than
  insertion-order-dependent); the TCP MSS clamp at the TUN boundary
  reads per-destination path MTU instead of a single global ceiling;
  reactive `MtuExceeded` from forwarders is mirrored back into the
  TUN-side `path_mtu_lookup` so later flows pick up forward-path
  bottlenecks without re-discovery; and the proactive end-to-end
  `PathMtuNotification` echoed by the destination is mirrored into
  the same TUN-side store. Without that fourth piece, on long-lived
  stable paths where the destination's echo had tightened the
  session MTU but no transit router had emitted a fresh
  `MtuExceeded`, new TCP flows opened in that window were clamped by
  the staler discovery-time value. The proactive mirror uses the
  same tighter-only semantics as the reactive mirror, so it never
  loosens the clamp. The Windows TUN reader receives the same
  per-destination plumbing.
- **Bloom filter routing greedy-tree fallback.** `find_next_hop` no
  longer returns `NoRoute` when the bloom candidate set is non-empty
  but no candidate is strictly closer than the current node; it
  falls through to greedy tree routing instead. Previously, this
  caused dropped packets in topologies where the tree parent was
  closer but not a bloom candidate.
- **`fipstop` graceful tty-init failure.** `ratatui::try_init()`
  produces a clean error message instead of a hard crash when
  terminal initialization fails (Docker on macOS Sequoia, ttyless
  environments).
- **TreeAnnounce ancestry on self-root transitions.** When a node
  had no smaller-NodeAddr peer to use as a parent, the spanning-tree
  state correctly promoted it to root, but the ancestry advertised
  on the next `TreeAnnounce` still referenced its previous parent's
  path. Receiving peers rejected the announce as
  `invalid ancestry: advertised root X is not the minimum path entry
  Y`, blocking mesh transit on any path that needed to traverse the
  node. The self-root transition is now detected explicitly in
  `TreeState::become_root` and the advertised ancestry rebuilt to
  start from self; the MMP receive handler corrects stale ancestry
  inherited across reconnect eagerly rather than waiting for the
  next observation tick.
- **Spanning-tree internal-path updates** that change only the
  internal path between root and leaf (without changing the root or
  the depth) now propagate to leaves correctly. Previously, a leaf
  could continue routing against a stale internal path until the
  parent or depth also changed.

## Upgrade notes

Operator-actionable items when moving from v0.2.x to v0.3.0:

- **Control socket JSON schema (breaking, pre-1.0).**
  - `show_cache` response field `entries` has changed type from a
    `u64` count to an array of entry objects. The previous scalar
    value is now in a new `count` field.
  - `show_routing` response field `pending_lookups` has changed
    type from a `u64` count to an array of per-target lookup
    objects.
  - External tooling parsing these fields as numbers must be
    updated. In-tree `fipstop` is adjusted to the new schema. The
    control-socket interface remains pre-1.0 and is not covered by
    stability guarantees.

- **Cargo feature flags removed.** `tui`, `ble`, `gateway`, and
  `nostr-discovery` are gone. Subsystem inclusion is now driven by
  platform `cfg` gates, so plain `cargo build` compiles everything
  available on the target without `--features` invocations.
  Source-build tooling that passed any of these features should be
  updated to omit them.

- **Discovery rate-limiting defaults changed.** Post-failure
  suppression is **off by default**
  (`node.discovery.backoff_base_secs: 0`, `backoff_max_secs: 0`).
  Operators relying on the prior 30s base / 300s cap behavior must
  set those fields explicitly. The per-attempt sequence
  (`attempt_timeouts_secs`, default `[1, 2, 4, 8]`) now governs
  cold-start lookup behavior.

- **`.fips` DNS bind address default changed.** The default
  `dns.bind_addr` is now `::1`. Operators with explicit overrides
  of this field should review them; many existing overrides were
  workarounds for the silent-drop bug that this release fixes
  properly.

- **Gateway `dns.listen` source default changed.** The
  `fips-gateway` `dns.listen` default is now `[::1]:5353` (was
  `[::]:53`), matching the canonical deployment model where a
  pre-existing resolver on the host already owns port 53. The
  OpenWrt ipk previously overrode this in its packaged config; the
  override is now redundant and has been dropped. Operators on a
  host without a pre-existing resolver on port 53 can opt back into
  the wildcard bind by setting `dns.listen: "[::]:53"` explicitly.
  The new default binds IPv6 loopback only, so forwarders that
  reach the gateway over IPv4 loopback need an explicit IPv4 listen
  address.

- **systemd unit log level.** The shipped systemd units no longer
  hardcode `RUST_LOG=info`; the daemon's effective log level is
  driven by `node.log_level` (default `info`). `RUST_LOG`, when
  set, still overrides.

- **UDP transport `bind_addr` validation.** Startup now rejects a
  `bind_addr` set to a loopback address when at least one peer has
  a non-loopback UDP address. Operators who configured a loopback
  UDP bind as a workaround should switch to `outbound_only: true`
  for the same effect, plus the correct semantics (kernel-assigned
  ephemeral port, refuses inbound, never advertised).

- **Tor advert port.** If the Tor `HiddenServicePort` virtual port
  isn't 443, set `transports.tor.advertised_port` to match. The
  default is 443 and matches the conventional virtual-port choice.

## Documentation pointers

v0.3.0 ships a `docs/` tree reorganized into four sections
(*tutorials / how-to / reference / design*). A new top-level
[`docs/getting-started.md`](../getting-started.md) and per-section
landing pages anchor the entry points.

Entry points by reader intent:

- **New users**: [`docs/getting-started.md`](../getting-started.md)
  and [`docs/tutorials/`](../tutorials/) cover guided introductions
  for bringing up your first node, joining the test mesh,
  advertising a node over Nostr, hosting a service, deploying a
  gateway, walking through the IPv6 adapter, and resolving peers
  via Nostr.
- **Operators with a specific task**:
  [`docs/how-to/`](../how-to/) holds task-driven guides for enabling
  Nostr discovery, deploying the gateway, troubleshooting the
  gateway, deploying a Tor onion, hosting aliases, persistent
  identity, running unprivileged, setting up a Bluetooth peer,
  enabling the mesh firewall, tuning UDP buffers, and diagnosing
  MTU issues.
- **Reference lookups**: [`docs/reference/`](../reference/) holds
  the config field reference, control-socket query reference, the
  `fips`, `fipsctl`, `fipstop`, and `fips-gateway` CLI references,
  and the protocol diagram set.
- **Architectural background**: [`docs/design/`](../design/) holds
  design rationale for FIPS as a whole, FMP and FSP, the spanning
  tree, bloom-filter discovery, transports, the IPv6 adapter, the
  Nostr discovery layer, and the gateway.
- **Security**: [`docs/design/fips-security.md`](../design/fips-security.md)
  documents the mesh-interface security baseline, threat model, and
  drop-in workflow.

## Getting v0.3.0

- **Linux x86_64 / aarch64**: `.deb` and tarball at the
  [v0.3.0 release page](https://github.com/jmcorgan/fips/releases/tag/v0.3.0).
- **Arch Linux**: `fips` from the AUR.
- **macOS**: `.pkg` at the v0.3.0 release page.
- **Windows**: ZIP at the v0.3.0 release page.
- **OpenWrt**: `.ipk` at the v0.3.0 release page.
- **From source**: `cargo build --release` from a checkout of the
  v0.3.0 tag.

The full per-commit changelog lives in
[`CHANGELOG.md`](../../CHANGELOG.md). Issues and discussion at
[github.com/jmcorgan/fips](https://github.com/jmcorgan/fips).

## Contributors

Thanks to everyone who contributed code, packaging work, bug reports,
or reviews to this release.

**Code and packaging**:

- [@jcorgan](https://github.com/jmcorgan): release shepherd, Nostr
  discovery / NAT traversal, `fips-gateway`, ACL infrastructure,
  packaging, security baseline, BLE follow-ups.
- [@Origami74](https://github.com/Origami74): macOS platform support,
  from-source Docker companion build and `fipstop` terminal-init
  handling, gateway co-development, OpenWrt BLE-feature build fix,
  AUR-workflow follow-ups.
- [@jodobear](https://github.com/jodobear): Linux release-artifact
  workflow and target-aware build scripts, CONTRIBUTING.md
  expansion, rekey integration-test stabilization.
- [@tidley](https://github.com/tidley): Nostr-mediated overlay
  discovery and UDP NAT traversal
  ([#53](https://github.com/jmcorgan/fips/pull/53)).
- [@alexxie16](https://github.com/alexxie16): peer ACL enforcement
  ([#50](https://github.com/jmcorgan/fips/pull/50)),
  macOS WireGuard companion example
  ([#51](https://github.com/jmcorgan/fips/pull/51)),
  follow-up ([#67](https://github.com/jmcorgan/fips/pull/67)).
- [@osh](https://github.com/osh): diagnostic queries for security
  validation and mesh debugging
  ([#42](https://github.com/jmcorgan/fips/pull/42)).
- [@OceanSlim](https://github.com/0ceanSlim): Windows platform
  support ([#45](https://github.com/jmcorgan/fips/pull/45)).
- [@mmalmi](https://github.com/mmalmi): ring AEAD backend
  ([#80](https://github.com/jmcorgan/fips/pull/80)),
  hot-path drain batching + recvmmsg + eager pubkey_full
  ([#81](https://github.com/jmcorgan/fips/pull/81)),
  TreeAnnounce self-root ancestry + overlay-advert retry hygiene
  ([#82](https://github.com/jmcorgan/fips/pull/82)),
  NAT-traversal MTU inheritance
  ([#83](https://github.com/jmcorgan/fips/pull/83)).
- [@dskvr](https://github.com/dskvr): initial Arch Linux AUR
  packaging ([#21](https://github.com/jmcorgan/fips/pull/21)) and
  the AUR publish workflow.
- [@SatsAndSports](https://github.com/SatsAndSports): rekey
  message-1 admit fix on non-accepting transports
  ([#49](https://github.com/jmcorgan/fips/pull/49)),
  TreeAnnounce semantic validation, gateway test image fix
  ([#69](https://github.com/jmcorgan/fips/pull/69)).
- [@andrewheadricke](https://github.com/andrewheadricke): MIPS
  atomic-ABI portability via `portable_atomic`
  ([#62](https://github.com/jmcorgan/fips/pull/62)).
- [@sh1ftred](https://github.com/sh1ftred): Arch packaging namcap
  fixes ([#63](https://github.com/jmcorgan/fips/pull/63)).
- [@oleksky](https://github.com/oleksky): macOS WireGuard companion
  collaboration on [#51](https://github.com/jmcorgan/fips/pull/51).

**Issue reports that drove fixes in this release**:

- [@deavmi](https://github.com/deavmi): MIPS daemon build support
  ([#26](https://github.com/jmcorgan/fips/issues/26)).
- [@Sebastix](https://github.com/Sebastix): fipsctl/fipstop
  control-socket path detection
  ([#30](https://github.com/jmcorgan/fips/issues/30)).
- [@SwapMarket](https://github.com/SwapMarket): auto-connect
  reconnect after graceful disconnect
  ([#60](https://github.com/jmcorgan/fips/issues/60)) and
  fipsctl mesh-address rejection
  ([#61](https://github.com/jmcorgan/fips/issues/61)).
