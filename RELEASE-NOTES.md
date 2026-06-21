# FIPS v0.4.0

**Released**: 2026-06-21 (provisional)

v0.4.0 is the throughput-and-observability release on the v0.3.x wire
format. It adds two new ways for nodes to find and reach each other (the
Nym mixnet transport and opt-in mDNS LAN discovery), overhauls the data
plane for higher single-node throughput and lower per-packet CPU, moves
the entire operator read surface off the data-plane hot path so
observability stays responsive under load, ships a reworked `fipstop`
TUI, and hardens FMP and FSP rekey to be hitless under packet loss in
both directions. It also folds in the accumulated mesh-convergence,
admission-control, and packaging fixes from the maintenance line.

v0.4.0 is wire-compatible with v0.3.0. Mixed meshes interoperate; there
is no flag-day upgrade. A deployed v0.3.0 node and an upgraded v0.4.0
node peer, rekey, and route normally, so you can roll the upgrade out
across a mesh in any order.

## At a glance

- New outbound Nym mixnet transport with a single-container demo and a
  new mixnet-relay example.
- Opt-in mDNS / DNS-SD discovery on the local link.
- Data-plane overhaul: off-task encrypt and decrypt worker pools, GSO,
  connected-UDP send path, copy-avoidance on receive, batched macOS
  receive.
- The full `show_*` read surface now serves off the receive loop, so
  `fipsctl` and `fipstop` stay responsive on loaded nodes; a new
  counter-only `show_metrics` query enables a Prometheus scraper at no
  hot-path cost.
- Reworked `fipstop` TUI on a machine-verified render-snapshot base.
- Rekey is now hitless under loss and reordering in both directions.
- New packaging targets: an OpenWrt `.apk` for OpenWrt 25+ and a Nix
  flake for reproducible from-source builds on Nix/NixOS.
- Six route-class transit counters partition forwarded traffic by its
  tree relationship to the next hop, visible via `show_routing` and
  `show_status`.

## What's new

### Nym mixnet transport

FIPS can now peer over the [Nym](https://nymtech.net/) mixnet for
metadata-resistant connectivity. The new `transports.nym` transport
makes outbound connections through a `nym-socks5-client` SOCKS5 proxy
that you run alongside the daemon (for example as a service running
alongside the fips daemon, or as a sidecar container). The transport
waits at startup for the nym-socks5-client to become ready before giving
up.

This is a privacy and anonymity deployment mode chosen for its own
properties. It mixes your FIPS traffic into the Nym cover-traffic
network so that link-level observers cannot correlate which mesh peers
are talking. A new `examples/sidecar-nostr-mixnet-relay/` demonstrates a
FIPS-reachable Nostr relay peered across the mixnet end to end, and a
single-container demo ships with the transport.

Enable it by adding a `transports.nym` instance and pointing it at your
running nym-socks5-client. See the transports reference for the field
set.

### mDNS LAN discovery

Nodes on a shared local link can now find each other with zero address
configuration. The opt-in `node.discovery.lan` path runs an mDNS /
DNS-SD responder and browser: each node advertises a FIPS service record
on the link and adopts the peers it discovers. This complements the
existing Nostr-mediated overlay discovery for the common case where the
peers are simply on the same LAN.

Turn it on with `node.discovery.lan.enabled: true`. `service_type` and
`scope` tune the advertised service record and which interfaces
participate. Discovery on the local link needs no relay and no STUN.

### Data-plane throughput overhaul

The receive and send paths were reworked for higher single-node
throughput and lower per-packet CPU, building on the v0.3.0
crypto-backend swap:

- **Off-task encrypt and decrypt.** Per-peer encrypt and decrypt now run
  on dedicated worker tasks rather than inline on the receive loop, so a
  single busy peer no longer serializes the whole node's crypto.
- **GSO and connected-UDP send.** The Linux send path uses generic
  segmentation offload and a connected-UDP socket where available,
  cutting syscall overhead on bulk flows.
- **Copy-avoidance on receive.** The receive hot path avoids buffer
  copies it previously made per packet.
- **Batched macOS receive.** macOS gains a `recvmsg_x` batched receive,
  mirroring the Linux `recvmmsg` batching from v0.3.0.
- **Shared immutable-state context and an atomic metric registry.**
  Immutable per-node state moved into a single shared context, and
  counters live in an atomic metric registry that the new `show_metrics`
  query reads without touching the hot path.

These are all internal to the data plane and require no operator action.

### Observability off the hot path

Every read-only control query now renders from a snapshot published once
per tick into a lock-free `ArcSwap`, served from the control accept task
instead of round-tripping the data-plane receive loop. This covers
`show_status`, `show_stats_*`, `show_peers`, `show_sessions`,
`show_links`, `show_connections`, `show_transports`, `show_mmp`,
`show_tree`, `show_bloom`, `show_cache`, `show_routing`,
`show_identity_cache`, `show_acl`, `show_listening_sockets`, and the new
`show_metrics`. Only the mutating `connect` and `disconnect` commands
still reach the loop.

The practical effect: on a loaded node where the receive loop was busy,
`fipsctl` and `fipstop` queries previously stalled or timed out (the
five-second query pattern operators saw). They now answer promptly
regardless of data-plane load. Per-entity snapshots reuse unchanged rows
by pointer, so the per-tick publish cost stays bounded as peer and
session counts grow.

A new **`show_metrics`** query (surfaced as `fipsctl stats metrics`)
returns a counter-only snapshot of every metric family. It is the
enabler for a Prometheus scraper that pulls node counters at no hot-path
cost.

Six **route-class transit counters** partition transit-forwarded packets
by their tree relationship to the chosen next hop — tree-up, tree-down,
tree-down-cross, cross-link descend, cross-link ascend, and direct-peer
— and the six classes sum to `forwarded_packets`. They surface through
`show_routing` and `show_status`, and the `fipstop` routing tab is
reorganized so its two columns separate own/endpoint traffic from
forwarded/transit traffic with the tree-down-cross line visually flagged.

### Reworked fipstop TUI

`fipstop` gets a rendering, navigation, and read-surface overhaul on a
machine-verified base: a render-snapshot harness asserts the exact text
grid and per-cell style of every view against canned control-socket
output. New daemon-resolved fields surface through the snapshots,
including effective persistence, root and is-root state, a
per-transport-type peer-count map, per-peer effective depth, the root
npub, and the last-sent uptree filter fill ratio with the subtree size
estimate.

A separate fix clears a garbled-screen problem on startup and stray
bytes on quit, most visible over SSH and inside tmux: startup now forces
a full repaint before the first draw, and quit stops and joins the
stdin-poll thread before restoring the terminal, so post-raw-mode
keystrokes no longer echo onto the restored screen.

### Rekey reliability

FMP and FSP session rekey are now hitless under packet loss and
reordering in both directions:

- Inbound frames are authenticated against the pending session before
  the K-bit cutover promotes it, so a spoofed or stale frame cannot
  derail a rekey in progress.
- Rekey message-1 retransmission is bounded, and the link-dead heartbeat
  is rekey-aware so an in-flight rekey is not mistaken for a dead link.
- FSP session rekey holds connectivity across the rekey window under
  loss and reordering.
- Dual-initiation races (both peers starting a rekey at once on a
  high-latency link) are desynchronized with symmetric jitter so the two
  sides converge on one session rather than fighting.
- An exhausted retransmission-budget abort, an expected and self-limiting
  outcome on lossy or high-latency links, is logged at debug rather than
  warn.

The net operator takeaway: rekey completes cleanly without dropping
traffic, even on lossy or high-latency links, and the log no longer
cries wolf when a rekey gives up and retries.

### New packaging targets

- **OpenWrt `.apk`.** A new `.apk` package targets OpenWrt 25+, where
  apk-tools is the mandatory package manager; the existing `.ipk`
  continues to cover OpenWrt 24.x and earlier. It is built SDK-free,
  reusing the `.ipk` cross-compile and installed-filesystem payload, and
  releases publish `.apk` artifacts and checksums alongside `.ipk`. Like
  the `.ipk`, the package is unsigned and installed with
  `apk add --allow-untrusted`.
- **Nix flake.** A `flake.nix` at the project root builds all four
  binaries (`fips`, `fipsctl`, `fips-gateway`, `fipstop`) from source on
  Nix/NixOS, pinning the exact toolchain and wiring the native build
  dependencies so no host setup is needed beyond Nix with flakes
  enabled. It exposes `nix build`, `nix run`, a `nix develop` dev shell,
  and `nix flake check`, with `flake.lock` committed for reproducibility.

## Behavior changes worth flagging

These affect operators on upgrade.

- **Bloom filter antipoison cap raised.** `node.bloom.max_inbound_fpr`
  moves from 0.05 to 0.10, accepting filters with a higher derived
  false-positive rate before rejecting them. This reduces spurious
  filter rejections on larger meshes while keeping the antipoison
  protection in place.
- **TCP inbound cap honors `max_connections`.** The TCP inbound accept
  ceiling now resolves from explicit per-transport
  `max_inbound_connections`, then node-wide
  `node.limits.max_connections`, then the built-in default of 256.
  Previously the TCP inbound ceiling was hardwired to 256 and ignored
  `max_connections`, so raising it had no effect on inbound TCP.
- **Static host aliases hot-reload.** `/etc/fips/hosts` now reloads on
  mtime change once per tick rather than only at startup, so display
  names in `fipsctl` and `fipstop` reflect edits without a daemon
  restart. The peer ACL reloads through the same lock-free snapshot
  mechanism.
- **Quieter logs on busy public-mesh nodes.** Routine per-peer
  connection-lifecycle and capacity-cap events, no-route session-datagram
  drops, and exhausted rekey-budget aborts are demoted to debug, so
  genuinely notable info and warn lines are no longer drowned out.
- **More visible drops.** Receive-path silent rejections now flow
  through typed reject-reason counters, and discovery counts requests
  dropped when the dedup cache is full (`req_dedup_cache_full`, visible
  via `show_routing`). Drops that were previously silent are now
  countable.
- **Tor connect-refused accounting.** The Tor transport increments its
  `connect_refused` statistic (the "Refused" line in `fipstop`) on an
  actively-refused SOCKS5 connect, instead of recording every connect
  failure as a generic SOCKS5 error.

## Notable bug fixes

The CHANGELOG has the exhaustive list. This is the operator-relevant
subset of fixes for behavior that shipped in v0.3.0.

- **Symmetric peer teardown on manual disconnect.** A manual
  `fipsctl disconnect` now sends the peer a scoped Disconnect so both
  ends tear down and re-handshake cleanly. Previously a manual
  disconnect tore down only the local side, leaving the peer with a
  stale session that was never re-adopted as a child and whose bloom
  filter was never re-recorded.
- **Gateway holds long-lived and DNS-cached mappings.** `fips-gateway`
  no longer drops a virtual-IP mapping while traffic is still flowing.
  The mapping TTL clock previously advanced only on DNS re-query, so a
  busy long-lived or DNS-cached client could have its mapping reclaimed
  mid-flow. The tick now refreshes the mapping whenever conntrack reports
  active sessions and recovers a draining mapping to active when traffic
  resumes; only genuinely idle mappings drain.
- **Accurate mesh-size estimate under filter overlap.** The mesh-size
  estimator now estimates the cardinality of the OR-union of self plus
  every connected peer's inbound filter, instead of summing per-filter
  cardinalities of tree peers. Summing assumed the filters were disjoint,
  so a stale or oversized parent filter or a routing loop inflated the
  reported mesh size and a tree rebalance flapped the count. OR-union
  deduplicates overlap, equals the old result in the disjoint case, and
  removes the estimate's dependence on tree-declaration cache freshness.
- **Single-uplink node reattaches within a round-trip.** A node with one
  tree peer, which has periodic parent re-evaluation disabled, was left
  self-rooted and unreachable if its one-shot attaching TreeAnnounce was
  lost, until the next periodic re-broadcast. Tree-position exchange is
  now self-healing on the receive path: a node that hears an announce
  advertising a strictly worse root echoes its own declaration back,
  provoking the better-rooted peer to re-push its real position
  immediately.
- **macOS self-connections work end to end (#117).** Traffic a macOS
  node sends to its own `<npub>.fips` address is now delivered locally
  for full TCP/UDP, not just `ping6`. The point-to-point `utun` egresses
  self-addressed packets into the daemon with an unfinished transport
  checksum (macOS offloads it on the `lo0` loopback route), so
  re-injecting them verbatim made the local stack drop every segment the
  MSS-clamp rewrite did not happen to fix and self-connections
  half-opened and hung. The hairpin path now recomputes the TCP/UDP
  checksum before re-injection. Linux was unaffected.

## Upgrade notes

Operator-actionable items moving from v0.3.0 to v0.4.0:

- **Wire-compatible, no flag day.** v0.4.0 peers with v0.3.0. Upgrade
  nodes in any order. During a rolling upgrade you may see some log lines
  on the upgraded side as it interacts with not-yet-upgraded peers;
  behavior is correct, log noise only.
- **Bloom antipoison cap default changed.** `node.bloom.max_inbound_fpr`
  now defaults to 0.10 (was 0.05). If you set this explicitly, review
  whether you still want the old value.
- **New optional config surfaces.** `transports.nym` (outbound Nym
  mixnet) and `node.discovery.lan` (mDNS LAN discovery) are both opt-in
  and off by default. Adding them is the only way to turn the new paths
  on.
- **TCP inbound cap.** If you relied on the old hardwired 256 inbound-TCP
  ceiling, note it now honors `max_inbound_connections` then
  `node.limits.max_connections` then 256.
- **New observability query.** `fipsctl stats metrics` (the
  `show_metrics` control query) returns a counter-only snapshot suitable
  for a scraper.

## Getting v0.4.0

- **Linux x86_64 / aarch64**: `.deb` and tarball at the
  [v0.4.0 release page](https://github.com/jmcorgan/fips/releases/tag/v0.4.0).
- **Arch Linux**: `fips` from the AUR.
- **macOS**: `.pkg` at the v0.4.0 release page.
- **Windows**: ZIP at the v0.4.0 release page.
- **OpenWrt**: `.ipk` (OpenWrt 24.x and earlier) or `.apk` (OpenWrt 25+)
  at the v0.4.0 release page.
- **From source**: `cargo build --release` from a checkout of the v0.4.0
  tag (Rust 1.94.1 per `rust-toolchain.toml`; `libclang-dev` is a
  required Linux build prerequisite).
- **Nix / NixOS**: `nix build .#fips` from a checkout of the v0.4.0 tag
  builds the binaries from source with the pinned toolchain and no manual
  prerequisites (see the Nix section of `packaging/README.md`).

The full per-commit changelog lives in
[`CHANGELOG.md`](../../CHANGELOG.md). Issues and discussion at
[github.com/jmcorgan/fips](https://github.com/jmcorgan/fips).

## Contributors

Thanks to everyone who contributed code, packaging work, bug reports, or
reviews to this release.

- [@jcorgan](https://github.com/jmcorgan): release shepherd, high-level
  design, control read plane, rekey hardening, admission, bug fixes,
  testing, packaging, PR coordination, and issue resolution.
- [@mmalmi](https://github.com/mmalmi): opt-in mDNS LAN discovery and
  data-plane performance work.
- [@Origami74](https://github.com/Origami74): macOS packaging and
  website coordination.
- [@dskvr](https://github.com/dskvr): AUR packaging.
- [@oleksky](https://github.com/oleksky): Nym mixnet transport and the
  single-container mixnet demo.
