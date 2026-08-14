# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Breaking

Wire-format breaking changes for v0.6.0. All nodes in a mesh must
run the same major version — these changes are not backward compatible
with v0.4.x or earlier peers.

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
- A rekey is now declared explicitly in msg3, by a negotiation TLV naming
  the session it replaces, instead of being inferred from session age. A
  rekey and a fresh dial both arrive as a new msg1 on a new link, and the
  fact that separates them is internal to the initiator, so nothing on the
  wire carried it: a message-count-triggered rekey fires on a young
  session, so a real rekey landed below the age floor, was resolved as a
  cross-connection, and left the two ends of the link on different session
  indices. The marker uses the index the receiver allocated, so the
  receiver can match it against its own, and the shell resolves it to
  none, matching or mismatched. A mismatched marker resends msg2 rather
  than rejecting, because the initiator has already installed its pending
  session and will cut over on its own timer while the reject path sends
  nothing back. The age floor and the session-age snapshot are gone.

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

### Added

- `node.rate_limit.established_handshake_burst` and
  `node.rate_limit.established_handshake_rate`, the parameters of the new
  established-link msg1 token bucket. Both are optional; omitting them (the
  normal case) derives the bucket from `node.limits.max_peers`,
  `node.rekey.after_secs` and `node.rate_limit.handshake_max_resends`, so
  raising the peer limit sizes the bucket automatically. An explicit zero
  burst or a non-positive rate is rejected at config validation rather than
  silently refusing all rekey traffic.

- The receive-path `RejectReason` classification (shipped in 0.4.0) is
  additionally wired into the Noise XX handshake cluster
  (msg1/msg2/msg3) and the rekey-initiator outbound sites on `next`.

- OpenWrt 802.11s open-mesh backhaul: router-to-router radio links with FIPS
  providing all encryption, authentication and routing over bare L2 neighbor
  links. The mesh runs open with `mesh_fwding 0`, since SAE would duplicate the
  Noise layer and force ath10k raw mode, and FIPS's spanning tree is the
  routing layer. `fips-mesh-setup` is an opt-in UCI helper creating a per-radio
  mesh point (`radio0` to `fips-mesh0`, `radio1` to `fips-mesh1`, with a
  free-index fallback and a collision guard); radio setup stays opt-in because
  a package must not commandeer radios on install. A dual-band router gets one
  instance per radio, and FIPS treats the two paths as failover rather than
  multipath: cross-connection resolution keeps one active link per peer and the
  second band stands by, re-establishing after keepalive timeout. The shipped
  `fips.yaml` carries the `mesh0`/`mesh1` Ethernet-transport entries commented
  out, so a stock install that never creates them logs no per-boot
  interface-missing warning; the helper uncomments the matching block when it
  creates the interface and re-comments it on remove (#123).

- OpenWrt open `!FIPS` access SSID, stacked on the mesh backhaul above: every
  FIPS router broadcasts the same open SSID, forming one standard ESS that
  phones and laptops save once and roam between natively, with the Noise
  handshake as the only security layer. The leading `!` sorts it to the top of
  alphabetically ordered network pickers, and the encryption type must be
  uniform across routers or clients treat the ESS as different saved networks.
  `fips-ap-setup` is an opt-in UCI helper creating the `fips-ap0` open AP on an
  isolated network with a static ULA /64 and RA-only odhcpd addressing —
  stateless SLAAC with no DHCP, the minimum that satisfies Android's
  provisioning check — behind a locked-down `fips_ap` firewall zone with no
  path to `br-lan` or the WAN, reaching only ICMPv6, mDNS and the FIPS
  transports. There is no internet by design, so phones keep cellular as their
  default route (#126).

- Android-ready core: the daemon's desktop transports and TUN operations are
  gated by `target_os` rather than by Cargo features, so a plain `cargo build`
  compiles for every target with no flags and Android self-excludes the raw
  Ethernet transport as Windows already did. `Node::enable_app_owned_tun()`
  gives an embedder that owns the TUN file descriptor — an Android
  `VpnService`, for instance — a channel pair for exchanging IPv6 packet bytes
  with FIPS instead of FIPS creating a system TUN device, and `start()` then
  performs no system-TUN or `CAP_NET_ADMIN` operations. Packets entering this
  way bypass `handle_tun_packet`, so the embedder must push only
  `fd00::/8`-destined packets and clamp TCP MSS on outbound SYNs. Desktop
  builds are unchanged and no Cargo features are introduced.

- `Node::dns_local_addr()`, the DNS companion to the app-owned TUN seam above.
  An embedder whose resolver is pointed into the tunnel has no system socket
  aimed at the built-in `.fips` responder, so the accessor reports the address
  read back off the bound socket: `dns.port = 0` therefore yields the
  kernel-assigned port, and it returns `Some` only while the responder is up.
  Read it once, after `start()` returns and before the node is moved into a
  background task; it is not a liveness feed (#136).

- A bounded graceful-shutdown drain phase, controlled by the new
  `node.drain_timeout_secs` (default 2s). On the shutdown signal the node
  broadcasts Disconnect to all peers and then keeps serving for that window,
  exiting early once all peers are gone, so in-flight traffic settles and peers
  observe the disconnect before the transports close, where previously teardown
  was immediate. The published node state gains a `Draining` variant visible
  via control queries during the window. The immediate stop path used by
  non-daemon callers is unchanged.

- FreeBSD support for the daemon, `fipsctl`, and `fipstop`: native TUN
  datapath (TUNSIFHEAD address-family framing, kernel-assigned `tunN`
  device name as with `utun` on macOS), clean service teardown,
  `/usr/local/etc/fips` config search path, and `/var/run/fips`
  control-socket default (both shared with macOS). The `hosts`,
  `peers.allow` / `peers.deny` and `fipsctl keygen` defaults follow the
  same `/usr/local/etc/fips` layout as macOS — see the corresponding
  entry under Fixed, which describes that move and its startup warning.
  `fips-gateway` remains Linux-only. Native `.pkg` packaging under
  `packaging/freebsd/`
  (`make freebsd`) with rc.d services, a `fips` control-socket group,
  service stop/restart across `pkg upgrade`, and `.fips` DNS integration
  for `local_unbound`/`unbound`/`dnsmasq`. mDNS LAN discovery works via
  `mdns-sd` 0.20 (`socket-pktinfo` 0.4.1, the first release that builds
  on FreeBSD). Daemon logs now disable ANSI color when stdout is not a
  terminal (all platforms).
- An optional tick-body profiler behind the new `profiling` Cargo feature,
  **off by default**. When enabled, `fipsctl profile tick on [--dir PATH]` /
  `off` / `status` starts and stops a capture at runtime with no restart. Each
  capture writes one tab-separated file (default `/var/log/fips`, capped at
  32 MB) carrying, per ten-second interval, the exact count, max and total for
  every step of the rx-loop tick arm, the whole-tick span, and gauges for ticks,
  peer count, the gap between successive tick-arm entries and the resulting
  arm-starvation delay. With the feature off the instrumentation macro is a pure
  pass-through, so a default build contains no timing code on the tick path.
  `LogsDirectory=fips` was added to the packaged systemd units so the capture
  directory is created and cleaned up declaratively.

- `SECURITY.md`, stating a private channel for vulnerability reports, what a
  useful report contains, what a reporter can expect back and on what timing,
  and which branches receive fixes. The repository previously documented no
  reporting channel at all, so someone with a finding had to guess at an
  address or open a public issue.

- `node.rate_limit.established_handshake_burst` and
  `node.rate_limit.established_handshake_rate`, the parameters of the new
  established-link msg1 token bucket. Both are optional; omitting them (the
  normal case) derives the bucket from `node.limits.max_peers`,
  `node.rekey.after_secs` and `node.rate_limit.handshake_max_resends`, so
  raising the peer limit sizes the bucket automatically. An explicit zero
  burst or a non-positive rate is rejected at config validation rather than
  silently refusing all rekey traffic.

- `packaging/debian/build-deb.sh --features <list>` builds the `.deb` with a
  Cargo feature list, which is how an instrumented package is produced for a
  measurement run. The auto-derived dev Version gains a matching `+<features>`
  marker, so a feature build and a default build of the same commit are no
  longer indistinguishable: without it the two carry byte-identical versions,
  an install of one over the other is an apt no-op, and the running node offers
  no way to tell which one it has. The marker sorts above the unmarked build, so
  installing a feature build is an upgrade and reverting to the default build is
  a downgrade — revert with `dpkg -i` rather than `apt install`. `--features` is
  refused together with `--no-build`, which would stamp the marker onto binaries
  the features never reached.

### Changed

- `node.rekey.enabled` now means "initiate rekeys" and nothing else. The
  responder half of the establish decision was also gated on it, and once the
  rekey is declared in the msg3 negotiation payload that flag was the only
  thing that could divert a msg3 whose marker matched the session we hold — it
  diverted it to a msg2 resend while the initiator had already installed its
  pending session and would cut over on its own timer regardless. A pair
  configured with the flag true on one end and false on the other therefore
  parted company at the initiator's cutover and carried no traffic in either
  direction until the link-dead timer. Removing that gate exposed a second
  reading of the same flag: the rekey poll returned early when rekey was
  disabled, and its drain-expiry arm is the only thing that releases a demoted
  session and its index, so a node that does not initiate but now accepts a
  rekey would have pinned the previous session and its allocator index
  forever. The trigger and the polled cutover stay gated on the flag; the
  drain no longer is.

- Node health is determined at start completion instead of unconditionally
  reaching a single running state. **Zero transports up is now fatal**: the
  node tears down cleanly and the daemon exits with an error, where it
  previously came up and served nothing. Any configured optional child that
  failed to start — a transport beyond the first, Nostr, mDNS, TUN, DNS, or a
  worker pool — leaves the node degraded but serving, with a warning naming
  what failed, and all configured children up is full health. A child the node
  was never asked to run does not count against it. The published node state
  gains `Degraded` and `Failed`, both visible via control queries, with
  degraded operational and failed not. Exit detection for the DNS task, the two
  TUN threads, mDNS and Nostr also re-evaluates health at runtime, so a child
  that dies after a healthy start now shows as degraded; transports and worker
  pools expose no runtime-exit signal yet and are unchanged.

- A connected UDP socket that cannot open now names the syscall that failed and
  the address it was operating on, the local address for `bind` and the peer
  address for `connect`. Both paths previously returned a bare OS error that
  the caller wrapped identically, so a field report of `Address already in use`
  could not be attributed to either, and the two have entirely different
  causes: on Linux a UDP `connect(2)` to a 4-tuple another socket already holds
  returns `EADDRINUSE`, which is not the same fault as `bind` refusing the
  local address. A node at roughly 245 peers was emitting this three times a
  second across nine peers with no way to diagnose it.

- Connected UDP peer drains now batch macOS receives with `recvmsg_x(2)`,
  matching the wildcard UDP receive path instead of issuing one `recv(2)`
  syscall per queued datagram.
- Routing next-hop selection now visits borrowed peers and coordinates instead
  of allocating candidate snapshots for each forwarded packet.

- Inbound msg1 is classified before it is rate limited, and rekey or restart
  msg1 arriving on a link belonging to a promoted peer now draws on its own
  token bucket instead of competing with stranger admission for a single
  shared one. On a node with many peers the shared bucket refused a large
  share of ordinary rekey traffic: a field node at roughly 245 peers refused
  8753 msg1 in 25 minutes, and 159 of the 201 distinct sources were peers it
  already held sessions with. On the XX handshake path the classifier keys on
  promotion state rather than on the presence of an address-map entry, because
  msg1 creates such an entry for a still-pending inbound connection before any
  identity is known; a still-handshaking stranger therefore stays in the
  stranger class for its whole lifetime, retransmits included. Nodes upgrade
  with no config change. The `Msg1 rate limited` log line now reports which
  limb refused, the pending count or the token bucket, which it previously did
  not distinguish.

- Rekey timer jitter is enabled on next's XX FMP rekey path
  (`REKEY_JITTER_SECS = 15` at `src/node/mod.rs`), matching the
  IK-line behavior on maint/master. It had been temporarily set to
  `0` on next because variable-interval rekeys exposed three XX
  rekey-path defects that left the two endpoints on divergent Noise
  sessions; those defects are fixed (see `### Fixed`), so the
  per-session signed jitter over `[-15, +15]` seconds is restored.
  `node.rekey.after_secs` is the nominal interval rather than a floor;
  mean is preserved.
- On the XX FMP handshake, an over-cap inbound connection is rejected
  solely by the late `promote_connection` check, and the resulting
  `MaxPeersExceeded` rejection is logged at debug rather than warn so a
  saturated node under sustained inbound pressure does not emit WARN
  spam for these expected policy rejections. There is no early cap gate:
  on XX the peer's identity is not known until the third handshake
  message, by which point Msg1, Msg2, and Msg3 have all crossed the
  wire, so an early gate would save no wire bytes and would govern
  exactly the same net-new-peer set as the late check. The known-peer /
  cross-connection bypass — which also covers peers the node is itself
  dialing, e.g. configured `auto_connect` peers — is handled by that
  late check, since those peers return earlier via the cross-connection
  paths and are not subject to the cap.
- The Ethernet transport's per-interface `discovery` flag was renamed to
  `listen` (`transports.ethernet.*`) to match the symmetric `announce`
  (transmit) / `listen` (receive) neighbor-beacon vocabulary. The old
  `discovery:` key is still accepted via a serde alias, so deployed configs
  continue to load unchanged; `Config::to_yaml()` re-emits it under the
  canonical `listen:` name. Update your `fips.yaml` to `listen:`.

- The mesh-lookup control-metrics family is now emitted under the key
  `lookup` in `fipsctl stats metrics` and `show routing`. The former key
  `discovery` is still emitted as a deprecated alias carrying identical
  counters; update dashboards and alerts to read `lookup`.
- The overloaded `node.discovery.*` config table was split into
  `node.lookup.*` (mesh-lookup scalars: `ttl`, `attempt_timeouts_secs`,
  `recent_expiry_secs`, `backoff_base_secs`, `backoff_max_secs`,
  `forward_min_interval_secs`) and `node.rendezvous.*` (peer rendezvous:
  `nostr.*`, `lan.*`). A deployed `node.discovery:` block still loads and is
  folded into the new tables with a one-time deprecation warning; migrate your
  `fips.yaml` to the new keys.

- Config validation now rejects two `node.rekey` settings that appear to
  disable the trigger and in fact fire it continuously. `after_messages` of
  zero makes the message-count arm true on every poll, because the trigger
  compares the counter with greater-or-equal. `after_secs` at or below the
  per-session jitter bound is the same trap on the timer arm: each session
  offsets the interval by a random value within plus or minus that bound, so a
  smaller interval saturates to zero on a negative draw and rekeys on sight,
  for roughly half of sessions. Both are checked whether or not rekey is
  enabled, so switching it on later cannot surface the error at a surprising
  moment, and neither gains an upper bound — a very large value remains the
  supported way to disable one arm. A config carrying either setting now fails
  to load instead of starting a node that rekeys constantly.

- Peer bloom filters are computed for every recipient in one prefix and suffix
  union sweep rather than rebuilt per recipient. Announcing to R peers
  previously did R full map builds and R by T merges; at 240 peers that was
  20.6 ms per tick, roughly half the tick body, with a median per-interval
  maximum of 34.5 ms. The result is exactly equal rather than approximately:
  merging is a bytewise OR, so regrouping the unions cannot change it. The
  trade-off, measured rather than assumed, is that the sweep does its full work
  regardless of how many peers are ready, so a tick announcing to one or two
  peers now costs about twice what it did; break-even is around three ready
  peers. Cadence, the debounce, the sequence rule and the fill-ratio cap are
  unchanged.

- Each peer's npub is derived once at construction instead of once per tick.
  The per-tick stats snapshot ran a bech32 encode for every tracked peer, and a
  second one for the common peer with no hosts-file entry and no alias, since
  the display-name fallback bottoms out in the same encode: 14.1 ms per tick at
  240 peers. The display name itself is deliberately not cached, because the
  alias map and the host map both mutate at runtime.

- The peer-retry tick no longer awaits the Nostr advert refetch. It ran inline
  on the 1-second rx-loop tick, awaiting a fetch with a 2-second timeout for
  each due peer and discarding the result; with up to sixteen due peers the
  timeouts stacked, and field profiling measured single 2.00 s stalls as the
  common case and a worst tick of 12.4 s against a 1 s period, delaying every
  other rx-loop arm by as much as 4.2 s. The refetch is now spawned, so a dial
  uses the advert cached at that moment and the refreshed one lands for that
  peer's next retry.

- The `Adopted NAT traversal socket` log line now carries the transport id and
  the local address alongside the peer npub. Without the local address an
  operator cannot join a host socket table against adoption events, and without
  the transport id several peers sharing one adopted transport are
  indistinguishable from several separate adopted transports.

- `SessionDatagram::decrement_ttl` and `SessionDatagram::can_forward` now match
  the forwarder's IP hop-limit semantics: `decrement_ttl` decrements first and
  reports false when the result is zero, and `can_forward` is true only at a
  TTL of 2 or more.

### Deprecated

- The `discovery` metric-family key (control-socket JSON). It is dual-emitted
  alongside the new `lookup` key during a migration window and will be removed.
  Migrate dashboards/alerts from `discovery.*` to `lookup.*`.
- The `node.discovery.*` config table. Its keys were split into `node.lookup.*`
  (mesh-lookup) and `node.rendezvous.*` (peer rendezvous). A legacy
  `node.discovery:` block still applies for now with a deprecation warning and
  will be removed; migrate to `node.lookup.*` / `node.rendezvous.*`.
- The Ethernet `transports.ethernet.discovery` flag, renamed to
  `transports.ethernet.listen`. The old key is still accepted via a serde
  alias and will be removed at the v2 cutover; migrate to `listen`.

### Fixed

- A leaf-profile node no longer self-elects as tree root. A leaf holding the
  smallest node address elected itself, but its peers refuse a non-full node as
  a parent, so it formed an isolated second root and partitioned the mesh: a
  multi-hop session from the leaf to a non-adjacent full node then failed,
  because the far node could not route a handshake reply back into the leaf's
  separate coordinate tree. A leaf now attaches under its full upstream and
  holds that subtree's coordinate for its own routing; it never announces that
  coordinate, reaching peers via the ones carried on its session frames, and
  the upstream already advertises it in the upstream's bloom filter.
  `Node::with_identity` also derives the node profile, leaf-only flag and bloom
  state from the config as `Node::new` does, where it previously hardcoded the
  full profile and silently dropped a configured leaf or non-routing profile.

- Every XX handshake reject arm now releases the session index and the link it
  holds. The msg2 self-connect drop and the msg3 reject arms disposed of a leg
  without returning what that leg had allocated, so each rejected handshake
  leaked an index and a link entry. One arm is deliberately not fixed like the
  others: its index comes from the receiver field of the incoming header, which
  the peer supplies, so freeing it unconditionally would let a hostile peer
  release an index belonging to an unrelated live session, trading a memory
  leak for a remote session teardown. That arm frees only after a
  transport-blind predicate establishes the index is not claimed elsewhere.
  The outbound ACL-reject arm also regains the reschedule call its dial-gate
  sibling makes, so a configured peer no longer drops off the dial schedule.

- The packaged macOS daemon now recreates and binds its control socket at
  `/var/run/fips/control.sock` instead of falling through to the shared
  `/tmp/fips-control.sock` path after boot. The previous fallback also made the
  root daemon attempt to chown `/tmp` itself to the `fips` group because socket
  setup unconditionally changed the parent directory. A privileged macOS
  process now selects the private runtime path before its leaf exists, clients
  follow it once created, and socket setup changes ownership and mode only for
  a private parent directory it creates or recognizes as a canonical FIPS
  runtime directory.

- A SessionDatagram carrying a truncated inner FSP payload no longer panics the
  forwarding path. The coordinate-cache warm path sliced the inner payload at
  the full 12-byte header offset while guarding only with the 4-byte common
  prefix parser, so an inner payload of 4 to 11 bytes with phase 0x0 and the
  Coords Present flag set indexed past the end of the slice. Because the
  receive loop is the process's main future, the panic terminated the daemon
  rather than a task, and under the packaged systemd unit the node restarted
  into the same frame. The warm path now applies the same
  `FspEncryptedHeader` guard the local-delivery path already used, which
  additionally means a malformed frame carrying a non-zero protocol version or
  the Unencrypted flag alongside Coords Present is dropped rather than having
  its body read as coordinates. Any peer that had completed a link handshake
  could trigger this, and admission is default-open. Frames rejected by that
  guard are now counted in the forwarding statistics as
  `warm_malformed_packets` and `warm_malformed_bytes`, visible over the control
  socket and on the fipstop Routing State pane, so a node being fed malformed
  frames is distinguishable from a quiet one at the default log level. The
  count is not a packet drop: the frame is still delivered or forwarded, and
  only the coordinate-cache warm attempt is abandoned. The existing debug log
  now also carries the frame's protocol version and flags, which separate a
  short frame from a bad-version or Unencrypted-flagged one.

- Flap dampening can now engage more than once in the lifetime of a node.
  The arming check tested whether a dampening deadline had ever been set
  rather than whether one was still in effect, so the first episode
  disarmed the mechanism permanently: a node in a second flap storm went on
  switching parents under hold-down alone, and neither the `flap_dampened`
  counter nor the "Flap dampening engaged" warning fired again, so the
  storm was invisible to anyone watching that counter. A lapsed episode is
  now retired explicitly, clearing both the deadline and the switch
  counter, so a second episode requires a fresh threshold of switches
  within one window rather than re-engaging on the first switch after
  lapse. Hold-down was unaffected throughout and continued to limit
  discretionary switching, which is why the practical effect at shipped
  settings was lost visibility and a lost escalation tier rather than
  unrestrained flapping. Every path that can engage an episode now reports
  it, including a re-engagement during parent-loss recovery, which was
  previously silent. The warning names which path armed the episode
  (`trigger`) and how long discretionary parent switching stays suppressed
  (`dampening_secs`), using the same `trigger` values as the parent-switch
  logs beside it, so the two can be read together.

- A `node.tree.flap_dampening_secs` large enough to overflow the monotonic
  clock no longer panics the node when dampening engages; the value is
  capped at one year, beyond which an episode is indistinguishable from
  permanent.

- The maintainer address published in package metadata no longer bounces. The
  crate authors field, the Debian package maintainer and upstream contact,
  both AUR PKGBUILD maintainer lines and the FreeBSD package manifest carried
  an address that no longer accepts mail, so the contact of record in every
  artifact we ship was unreachable.

- Nostr NAT traversal signals are now sent only to relays the client pool
  actually holds. A signal is addressed to the merge of the peer's NIP-17 inbox
  relays, the relays its advert nominates for signaling, and our own DM relays,
  but the pool is built once at startup from the configured relays and the send
  is rejected outright, before anything is contacted, if any single URL in that
  list is outside it. One unconfigured relay anywhere in the merge therefore
  killed the whole attempt, including the sends to relays both sides shared. On
  a public node in open mode this made discovery non-functional: 309 traversal
  attempts, 290 explicit failures, zero successes, every failure on `relay not
  found`. Configured peers were unaffected, since they run a matching relay
  set. Comparison is on the normalized relay URL rather than the raw string, so
  a configured relay spelled with a trailing slash or different host case is
  not discarded. Two smaller fixes ride along: the responder resolves its
  relays before binding a socket and running STUN, rather than spending a STUN
  round trip and holding an offer slot only to find it has nowhere to answer,
  and it gained the empty-relay-list guard the initiator already had.

- A failed log write can no longer panic the thread or task that logged. The
  subscriber was built with the default internal-error reporting, which sends a
  failed write to `eprintln!`, and that macro panics when stderr has also
  failed. The shipped supervisor configurations make that a single condition
  rather than two: the macOS plist points both standard streams at one
  unrotated file, and the systemd units route both to journald, so one full
  disk fails both sinks together. In the daemon a crypto worker was the case
  that mattered — it logs a warning on send backpressure, and a worker that
  dies takes its share of the peer space with it permanently, while the panic
  message is discarded along the same broken path. In `fips-gateway`, which
  built its subscriber the same way, the casualty is a spawned task: the DNS
  resolver, the control accept loop or the pool tick, none of which is observed
  until shutdown, so the process would keep running and reporting healthy with
  mesh name resolution or lease expiry and NAT cleanup silently stopped.

- macOS: `peers.allow`, `peers.deny`, and the `hosts` file are now read
  from `/usr/local/etc/fips/`, matching the install layout the macOS
  packaging ships (`packaging/macos/`). The default-path constants were
  hardcoded to `/etc/fips/...` with only a `#[cfg(unix)]` / `#[cfg(windows)]`
  split, so on macOS the daemon looked in a directory that does not exist:
  `load_file` / `load_hosts_file` hit their `NotFound` no-op arm and silently
  returned an empty ACL / empty host map. A populated `peers.deny` therefore
  reported `effective_mode: "default_open"` and `enforcement_active: false`
  via `fipsctl acl show`, and host-file aliases went unloaded, with no error
  or warning. The default constants now follow the platform's packaging —
  `/usr/local/etc/fips/` on macOS, `/etc/fips/` on Linux and other Unix
  for the ACL files, and `/etc/fips/` on Linux and `%ProgramData%\fips\`
  on Windows for the hosts file — and are pinned by platform-gated unit
  tests so the layout cannot silently drift again. At startup the daemon
  warns once if any of these files exist at the old `/etc/fips/` location
  but not at the current default. Linux and Windows behavior is unchanged.
  **macOS users with existing files in `/etc/fips/` should move them to
  `/usr/local/etc/fips/`.**

- macOS: `fipsctl keygen` now writes `fips.key` / `fips.pub` to
  `/usr/local/etc/fips/` by default, matching the install layout the macOS
  packaging ships. The default output directory was hardcoded to
  `/etc/fips` for all Unix, but the daemon derives its identity key paths
  from the config file's directory — `/usr/local/etc/fips/fips.yaml` on
  macOS — so a generated identity landed where the daemon never reads it
  and the node silently kept an ephemeral identity. Linux and other Unix
  keep `/etc/fips`, Windows is unchanged, and the values are pinned by
  platform-gated unit tests.

- macOS: the system-wide config search path now includes
  `/usr/local/etc/fips/fips.yaml` in addition to `/etc/fips/fips.yaml`,
  matching the install layout the macOS packaging ships. Previously only
  `/etc/fips/fips.yaml` was probed, so a bare `fips` run without `--config`
  skipped the installed config and derived identity key paths from a
  non-existent directory. `/etc/fips/fips.yaml` is still probed first so
  existing installs keep working. Both the macOS entry in the search path
  and the directory `fipsctl keygen` writes to read the shared
  `SYSTEM_CONFIG_DIR` constant, so the two cannot drift apart. The
  launchd-installed daemon was unaffected (it always passes `--config`).
  Linux and Windows behavior is unchanged. Because the daemon derives the
  identity key directory from whichever config file loaded last, a macOS host
  carrying `fips.yaml` at both locations would have resolved `fips.key` to the
  new directory, found none, and under `persistent` generated a fresh
  identity — silently changing its npub, routing address and mesh IPv6. The
  daemon now adopts a key stranded at `/etc/fips/fips.key` and warns to move
  it, instead of generating one. The fallback is confined to keys resolved
  from the system config directory, so a run using `./fips.yaml` or a user
  config is never redirected to a system key.

- Nostr NAT traversal no longer breaks after the host suspends. The traversal
  clock cached a Unix timestamp once at startup and advanced it with a
  monotonic `Instant`, which does not tick while a machine is asleep, so after
  a suspend the daemon's idea of the time trailed real time by the suspend
  duration for the rest of the process lifetime. Every NIP-40 expiration it
  computed was therefore published already in the past: relays dropped the
  offers as expired, the initiator logged a signal timeout waiting for an
  answer, and traversal stayed broken until the daemon was restarted. The
  clock now reads the wall clock on every call. This is not macOS-specific,
  though a laptop that sleeps is where it is easiest to hit; any host that
  suspends or hibernates was affected. Reported in
  [#128](https://github.com/jmcorgan/fips/issues/128).

- XX FMP rekey no longer diverges under timer jitter, which unblocked
  re-enabling the rekey jitter on next (`REKEY_JITTER_SECS = 15`; see
  `### Changed`). With jitter the two directions of a link rekey close
  together in time, and three defects specific to the XX three-message
  rekey state machine could each leave the endpoints committed to
  different Noise sessions — silent session divergence that starved the
  receiver into ~50% post-rekey ping loss and a 30-second heartbeat
  link-dead teardown (tree parent loss, routing failure) while every
  crypto, transport, and link-state gate stayed green. All three are
  fixed:
  - The K-bit-flip handler promoted whatever pending session existed the
    instant the header bit flipped, which under interleaved rekeys could
    be a stale pending from an earlier epoch. It now trial-decrypts the
    inbound frame against the pending session and promotes only on an
    authenticated decrypt, delivering that plaintext through the
    canonical path and leaving the pending untouched otherwise — the
    same cutover discipline used on FSP.
  - The FMP rekey msg3 was sent once, so a lost datagram left the
    responder without the new session. The msg3 payload is now retained
    and retransmitted over the existing link until a peer frame
    authenticates against the pending or post-cutover current session,
    abandoning after the configured handshake-resend budget. Per-link
    rekeys are also serialized: a new rekey does not start while one
    awaits cutover or is still retransmitting msg3.
  - The `handle_msg3` cross-connection and rekey-responder paths were
    partitioned by a fixed 30-second session-age threshold, but a rekey
    resets the session-age clock, so under jitter a rekey-aged msg3 was
    frequently under 30 seconds and got swallowed by the
    initial-handshake cross-connection branch, which discarded the
    peer's rekey session with no pending slot while the peer cut over to
    it anyway. The cross-connection branch is now bounded by the same
    jitter-aware session-age floor the rekey responder uses, so the two
    paths partition with no overlap. At zero jitter the floor equals the
    previous 30-second constant, so default-cadence behavior is
    unchanged.
- XX rekey dual-initiation race that broke six pair-directions
  post-rekey when both endpoints initiated rekey simultaneously.
  The `handle_msg3` tie-breaker only fired when `rekey_in_progress`
  was still true, but XX's three-message handshake lets both sides
  clear that flag (via `set_pending_session`) before either's msg3
  lands. The drop-on-pending-session guard then silently discarded
  the peer's msg3, each side cut over to its own initiator session,
  and the link broke asymmetrically. The tie-breaker now also fires
  when `pending_new_session().is_some()`, applying the same
  smaller-NodeAddr resolution rule. Mirrored to the FSP rekey msg1
  path for symmetry.
- `SessionDatagram` hop-limit handling now follows IP semantics. Delivery to
  the addressed node is no longer TTL-gated, and a forwarder decrements before
  deciding rather than after, so a datagram that would leave with a TTL of zero
  is dropped instead of transmitted. Previously the TTL check ran ahead of the
  local-delivery test, so a datagram addressed to this node that arrived with
  TTL 0 was dropped, and a forwarder receiving a transit datagram at TTL 1
  transmitted it at TTL 0 for the next hop to discard, wasting one transmission
  per expiring datagram. The reachable radius is unchanged, because the two
  behaviors compensated exactly: a path of `h` links still delivers for any
  source TTL of `h` or more. During a rolling upgrade, an unupgraded forwarder
  feeding an upgraded destination delivers one hop further than either version
  does on its own; no version mix delivers less far. The `TtlExhausted` reject
  counter now charges at the node that makes the decision rather than at the
  hop after it.

### Security

- The peer static key is verified on both FMP handshake paths, not only at
  rekey. Under Noise XX the static is learned during the handshake rather than
  pinned in advance, and neither path that learns one checked it against what
  we already knew, so an attacker able to observe and inject on path could
  substitute their own identity on a fresh dial and on an established link. On
  a fresh dial we recorded who we meant to reach and then overwrote it with
  whoever answered without comparing the two, so an attacker who raced the real
  peer to msg2 became the peer — promotion, the ACL check and the peer registry
  all ran on the answering identity — and the intended node was never reached.
  On an established link a rekey msg2 was matched to its peer only by the
  session index we had put in the cleartext msg1 header, so anyone who saw that
  header could answer with their own static and take the link over at cutover.
  Both are now compared before anything is committed, with the dial-time
  expectation held in a field that has no setter so the handshake cannot
  overwrite it. Anonymous dials still promote whoever answers, which is what
  shared-media discovery means.

- The influence a remote party has over path MTU is now bounded, and the
  per-destination path MTU cache has a way back. The `path_mtu` field is an
  unsigned per-hop transit annotation carried outside the signed proof, and the
  `MtuExceeded` and `PathBroken` signals arrive unencrypted with no sender
  check, so any forwarder — or anyone who can reach the node — could lower it,
  and it was accepted with no minimum. A single `MtuExceeded` carrying a very
  small value drove a session's path MTU to zero, after which every packet to
  that destination was answered with an ICMPv6 Packet Too Big instead of being
  sent: a blackhole that lasted until the daemon restarted. The same value
  reached the SYN-time TCP MSS clamp, where anything at or below 137 saturates
  to a segment size of zero and the band just above it yields single digits.
  Values below an actionable minimum are now ignored rather than applied or
  stored, at the three places a remote value is acted on: the path MTU state
  machine, the reactive `MtuExceeded` write, and the discovery response, whose
  coordinates are still cached so refusing the annotation cannot become a way
  to deny discovery. The MSS clamp additionally refuses to write a zero. Each
  of the three refusals logs a warning and increments its own counter in the
  error-signal family, so an operator can tell them apart without scraping
  logs: they carry different meanings, one being an authenticated peer inside
  an established session, one an unencrypted signal anyone able to reach the
  node can send at will, and one a verified discovery response whose unsigned
  annotation a forwarder on the reverse path rewrote. Because those three
  refusals are the only way a remote value reaches the per-destination store,
  the SYN-time clamp does not apply the minimum a second time when it reads
  that store: a small value there is one the node derived from its own outgoing
  link, which is exact rather than suspect, and BLE in particular negotiates a
  link MTU per connection that lands under the minimum routinely. The clamp
  refuses only a stored value admitting no TCP payload byte at all, at 137 or
  below, where the segment size saturates to zero and the clamp would be
  skipped entirely; it logs that at trace rather than warn, since it sits on
  the per-packet path, and the peer's link promotion reports it once instead.
  A stored per-destination path MTU is released when the path is invalidated by
  a `PathBroken` report, by session idle expiry, or by handshake timeout, and
  the link MTU read from the local transport is reseeded in its place, so a
  directly connected peer does not lose its own measurement along with the
  remote claim. Locally derived MTUs are not subject to the minimum, at the
  seed or at the clamp. Legitimate narrow paths are unaffected: adaptation to
  hops well below the IPv6 minimum, which the mesh does use, continues to work.

- A session setup message naming an already-established peer no longer replaces
  that peer's session. The handler did this whenever `node.rekey.enabled` was
  false: it ran a fresh responder handshake and overwrote the entry, discarding
  the live keys. The message carries no authenticator and its source address is
  an envelope field, so anyone able to reach a node could name an established
  peer and take that session down, repeatedly, and hold it down by repeating
  the message. The established case now always arms the handshake alongside the
  running session and adopts the new keys only after a msg3 whose authenticated
  static key matches the key the session was opened with, which is the check
  the rekey path already applied; a peer that genuinely restarted still
  re-establishes, and a forged setup leaves the session carrying traffic. This
  changes no wire format and adds no configuration: a node with rekey disabled
  already answered such a message, it simply destroyed the session afterwards.

- The session drain sweep and the cut-over that retires an old key epoch now
  run whether or not periodic rekey is enabled. Both sat behind the
  periodic-rekey gate, so a node with rekey disabled that adopted new keys held
  the superseded ones for the life of the session.

- A session rekey armed by a peer's setup message is now abandoned if the
  matching msg3 never arrives, rather than persisting for the life of the
  session. A stuck one made the node treat a later genuine setup message as a
  simultaneous initiation and drop it, which would otherwise have turned the
  fix above into a lasting block on re-establishment for roughly half of peer
  pairs. Only the armed handshake expires, and only it: a rekey that completed
  is the key epoch the peer has already moved to, since it exists only because
  a msg3 carrying that peer's authenticated key arrived and the sender of that
  msg3 promotes the new epoch on an unconditional two-second timer. Expiring
  those keys on any timer would drop every later frame from that peer, so they
  are now held until the peer's own frame promotes them, a newer completed
  rekey replaces them, or the session goes away. What the wait does bound is
  precedence, not the keys: a completed rekey outranks a fresh setup message
  from that peer only until it has waited a full idle timeout, after which the
  setup is answered normally, so a peer that restarted while we held such a
  session is no longer refused for as long as our own sends keep the session
  from idling out. The handshake timeout logs at INFO, since it costs nothing,
  and a completed session displaced by a newer one at WARN, since that does
  throw away keys the peer may hold. Session counters record the arming of a
  handshake by a setup message, each of the three ways such a message is
  refused, and each displaced session, so a node under a sustained spray of
  setup messages shows a rate rather than nothing; the per-message log lines
  stay at DEBUG because an unauthenticated sender can drive them at line rate.
  These counters are not yet readable through the control socket.

- Traversal punch targets taken from a peer's offer or answer are now
  filtered and bounded. A rendezvous-enabled node previously punched every
  address a signed offer named, including loopback, link-local, multicast,
  broadcast, unspecified and CGNAT addresses, and placed no limit on how
  many candidates one offer could carry. Any npub could
  therefore have a node emit a burst of UDP packets at addresses of the
  sender's choosing, carrying the node's own source address. Candidates in
  the never-routable ranges are now rejected, IPv4-mapped IPv6 forms are
  canonicalized before the check so they cannot slip past it, candidates
  with port 0 are dropped, private-range candidates are punched only when
  they share a /24 with one of our own addresses (which is what same-LAN
  traversal already required of its own path), and the planned target list
  is capped at eight. A peer's reflexive address is checked against the
  never-routable ranges but not against the /24 rule, so a deployment whose
  STUN server sits inside the private network keeps working. A malformed
  address in a peer's signal now drops that one candidate instead of
  failing the whole traversal. A node also records what it declined: one
  log record per planning attempt carries how many candidates the peer
  offered, how many were planned, the count refused in each class and one
  sample address, at warning level for the shapes no honest peer produces
  and at debug level for the routine off-subnet case. Same-LAN and
  reflexive traversal are otherwise unaffected.

- Traversal offers and answers dated in the future are now rejected. The
  freshness check measured a message's age with a saturating subtraction, which
  yields zero for any timestamp ahead of the local clock, so the age test could
  not fail for a future-dated signal and no other term bounded the issue time
  from above. A signal claiming to be issued arbitrarily far in the future was
  accepted as strictly fresh, which voided the property that the freshness
  window is narrower than the session-id replay window (300s by default) and
  left the replay cache as the sole defence against a captured offer being
  replayed. Forward-dating is now tolerated only up to the same 60s of clock
  skew already allowed in the other direction, and a signal accepted under that
  grace reports the skew outcome, so the existing clock-skew log fires for a
  peer whose clock is ahead just as it does for one whose clock is behind. The
  declared expiry timestamp is also no longer trusted beyond the issue time plus
  the configured TTL, so a sender cannot widen its own acceptance window by
  inflating that field. A single timestamp is now acceptable over at most the
  signalling TTL plus 60s on each side, 240s under the shipped defaults.
  Rejections are also now distinguishable in the log: a stale signal and a
  future-dated one no longer share one reason string, and the inbound-offer
  path, whose only surface was an unattributed debug line below the default log
  level, now names the peer and the session and warns for the rejection classes
  that relay delivery lag cannot produce (future-dated, identity-mismatch and
  malformed offers), leaving an ordinary stale offer quiet. As with the existing
  inbound rate-limit warning, an unauthenticated remote peer can drive that
  line. A failure of our own offer's freshness during answer validation is
  reported against the offer rather than mislabelled as the answer's, and the
  tolerated-acceptance log now carries the issue and expiry stamps and no longer
  attributes the acceptance to clock skew, since a peer configured with a longer
  signalling TTL than ours now reaches it too.

- The FSP session address is now bound to the peer key the Noise handshake
  authenticated, on both the initial and the rekey path. The responder recorded
  a session under the source address carried in the datagram without ever
  checking that address against the static key it had just authenticated, so a
  peer could complete a genuine handshake while claiming another node's
  address, and the identity cache, the session map and the address the IPv6
  shim reconstructs on delivery would all attribute its traffic to the node it
  named. The address is now derived from the authenticated key at the point it
  first becomes available in msg3, and a mismatch drops the half-open session
  without recording either the identity or the session. The rekey responder
  needed its own check: it returns before that code is reached and never read
  the peer's static key at all, so a rekey could complete under an established
  session with a different key than the one that opened it. It now requires the
  key to be unchanged and abandons the rekey while leaving the existing session
  intact, rather than tearing the session down, which would have handed an
  attacker a way to kill established sessions. Both comparisons are on x-only
  keys, because a stored key may carry a synthesized parity while the handshake
  learns the true point. The two rejections are counted separately in the
  session reject statistics.

- The dependency lockfile is refreshed past a set of advisories against the
  pinned `nostr` 0.44.3 and `nostr-relay-pool` 0.44.1, both of which were also
  yanked. `nostr` moves to 0.44.8 and `nostr-relay-pool` to 0.44.3; the
  requirements in `Cargo.toml` already admitted both, so this is a lockfile
  change and no code changed with it. The advisories that matter here are the
  relay-pool ones, RUSTSEC-2026-0224 and RUSTSEC-2026-0232, which describe
  forged events bypassing signature validation and unverified relay events
  being processed: that is the path this node learns peer adverts on, and it
  performs no independent verification of its own, so the exposure was a
  misattributed advert rather than the denial of service the advisory summaries
  lead with. RUSTSEC-2026-0231 (auth-challenge memory exhaustion) is on the
  same path, and RUSTSEC-2026-0216 and RUSTSEC-2026-0227 reach the NIP-44
  decryption of relay-supplied content. The remaining advisories in that set
  cover NIP-04, NIP-46, NIP-50, NIP-60, NIP-98 and the wallet parsers, none of
  which this code calls. The refresh was taken over the whole lockfile rather
  than the two crates alone, which additionally clears RUSTSEC-2026-0204 in
  `crossbeam-epoch` and leaves no yanked crate in the tree; `cargo audit` now
  reports no vulnerability, against twelve before. Four warnings remain and are
  not fixable by a version move: `instant` and `paste` are unmaintained, `lru`
  0.16.4 carries an unsoundness advisory, and `nostr-relay-pool` itself is now
  marked unmaintained.

- The gateway DNS forwarder now validates an upstream answer before it becomes
  a NAT mapping. It previously accepted whatever datagram arrived: the upstream
  query reused the client's own transaction ID, the upstream socket was
  wildcard-bound and never connected, the receive discarded the sender, neither
  the response ID nor the question section was compared against what was asked,
  and the returned address was not checked against the mesh prefix. Because the
  extracted address is installed as a DNAT rule that carries no interface
  constraint, a forged answer redirected traffic rather than only poisoning a
  lookup. The upstream query now carries a random transaction ID, the socket is
  connected so the kernel drops foreign sources, a response must match on ID,
  question and type or it is discarded while the receive continues against the
  original deadline, and the address goes through the validating parser with a
  non-mesh answer refused before any allocation. One deliberate behaviour
  change: the validation sits before the rcode check, so an upstream answering
  FORMERR or REFUSED with an empty question section now yields SERVFAIL rather
  than having its rcode relayed. Checking after the rcode would admit a forged
  NXDOMAIN. Connecting the socket also means a dead upstream surfaces
  ECONNREFUSED immediately instead of stalling for five seconds.

- Private key writes no longer follow a symlink, and the key file's mode is
  enforced rather than merely requested. The single write path opened with
  create and truncate and no `O_NOFOLLOW`, so a symlink planted at the key path
  was followed and its target overwritten, and it supplied the mode only
  through `open(2)`, which the kernel honours on creation and ignores
  otherwise, so a `fips.key` that already existed at 0644 stayed 0644 through
  every rewrite. That second half needs no attacker: one `chmod`, or a restore
  that did not preserve modes, leaves the key readable indefinitely. Both
  writers now share an open helper carrying `O_NOFOLLOW`, and the private key
  has its mode applied to the open descriptor before any secret bytes are
  written. The public key keeps create-time mode instead, since forcing it
  would reopen an operator-tightened `fips.pub` on every start. On Windows
  neither protection applies and the file inherits the parent directory's
  ACLs; that exclusion is deliberate and recorded at both writers.

- An accepted inbound TCP connection no longer holds a slot indefinitely
  without sending anything. The cap was tested at accept and the pool insert
  and counter bump followed with no read in between, while the frame reader's
  reads carried no deadline, so an unauthenticated remote held a slot by
  connecting and staying silent. Pool keys are `ip:port`, so N sockets from one
  address took N slots, and at the 256 default that locked out inbound peering
  for as long as the sockets stayed open. The first frame on an inbound
  connection now has a deadline, as a module constant rather than a new
  configuration key, and the onion listener gets the same treatment for the
  same accept-then-count ordering. Separately, the node's handshake reaper tore
  down session state without closing the transport connection, so a peer that
  sent msg1 and then stalled was forgotten by the node while its socket and
  slot survived; the reaper now closes the connection too. **What this does not
  close**: the deadline covers the first frame only, so a peer that sends one
  well-formed frame and then goes silent still holds its slot. Closing that
  needs a rolling idle deadline.

- Every GitHub Action is pinned to a commit SHA, and the OpenWrt packaging
  workflow verifies the helper binary it downloads. No reference in the
  repository was pinned before: all sixty-six named a mutable tag and one named
  a branch, including the jobs holding the AUR deploy key, the jobs with
  release write scope, and the packaging jobs that run with a signing key in
  the environment. Sixty-two are now full commit SHAs with the original tag
  retained as a trailing comment. Four are left unpinned and justified in one
  place: two actions read the tool to install from the ref name itself, so a
  SHA would hand them a hex string where a toolchain name belongs. A guard
  enforces the form on every sweep, treats an unreadable tree as an error
  rather than a pass, and documents what it does not cover. The sharper hole
  was not the tags: the OpenWrt workflow fetched a helper binary from a release
  URL with no verification at all, in two jobs holding a signing key. That
  download now checks a per-architecture pinned SHA-256, with the hash
  provenance recorded honestly, upstream publishing no checksum document.

- The three routing signals (`CoordsRequired`, `PathBroken`, `MtuExceeded`) are
  no longer acted on unless this node has itself bound the destination address
  they name, either by initiating a session toward it or by completing the
  Noise handshake that binds an address to a peer's static key. These signals
  carry no end-to-end authentication, so until now any admitted mesh member
  could send one naming any address and have its effects applied: a path-MTU
  clamp written for an arbitrary address, a cached-coordinate flush for an
  arbitrary address, and a discovery and warmup cycle for an arbitrary address.
  The `MtuExceeded` case was the sharpest, because its write into the
  address-keyed path-MTU lookup that the TUN reader consults at TCP MSS clamp
  time sat outside the session guard and so required no session, no peer
  relationship and no prior state at all. A half-open session created by an
  inbound handshake that has not yet proved its address does not admit these
  signals, so a forged session opening cannot be used to unlock them. Signals
  from a genuine on-path forwarder are unaffected: the reporter may be any node
  at any distance. This does not make the sender authentic, which nothing
  short of a wire format change can do. Rejected signals are counted as
  unknown-session rejections, and additionally on four new error-signal
  counters visible through `show routing`, `show metrics` and the fipstop
  routing pane: `unbound_coords`, `unbound_broken` and `unbound_mtu` give the
  refused count per signal type, against the existing per-type arrival
  counters as the denominator, and `unbound_forged` counts the subset whose
  claimed source and destination pairing no honest forwarder could produce.
  The drop log line now carries the signal type and the refusal class.

## [0.4.1] - 2026-07-19

### Changed

- `node.bloom.max_inbound_fpr` default raised from `0.10` to `0.20`. The
  cap rejects inbound `FilterAnnounce` whose FPR (`fill^k`) exceeds it. On
  the fixed 1 KB / k=5 filter, `0.10` corresponds to fill 0.631 (~1,630
  reachable entries), and the busiest nodes' aggregates had again begun to
  reach it as the mesh grew. `0.20` (fill 0.7248, ~2,114 entries) restores
  headroom without materially weakening the antipoison gate: a saturated or
  poisoned filter is ~100% FPR and still rejected. This is the second raise
  of this cap in two releases; the fixed 1 KB filter is the underlying
  constraint, and the structural remedy is the v2 filter work rather than a
  further raise. A node running this default accepts announcements that a
  v0.4.0 node drops, so during a rolling upgrade the two versions can
  disagree about mesh size.
- Bloom filter probing computes its SHA-256 digest once per operation
  rather than once per hash function. All k indices were already derived
  from a single digest, but the digest was recomputed inside the
  per-function loop, so every insert and membership test hashed the same
  bytes `hash_count` times (5x at the default). Output is bit-for-bit
  identical; this is the hottest path in packet forwarding and mesh-size
  estimation.
- Identity operations reuse one shared `secp256k1` context instead of
  constructing a fresh one at every sign, verify, and key-derive site.
  Each construction allocated a context and ran randomization and blinding
  table setup. Behavior is unchanged: the same API calls are made, only the
  context lifetime differs, and the shared context still performs the
  standard construction-time blinding.

### Fixed

- Spanning tree: the coordinate cache is now invalidated when the parent
  link is lost through peer removal. That path reparents or self-roots the
  node but omitted the invalidation every other position-change path
  performs, so cached entries for downstream destinations kept the node's
  now-stale coordinate prefix. Because routing access refreshes an entry's
  TTL, an actively routed stale entry never self-expired and was corrected
  only by a fresh insert.
- Discovery: applying a `LookupResponse` now keeps the tighter of the
  cached and received `path_mtu` rather than overwriting unconditionally.
  A looser estimate arriving in a later response could clobber a tighter
  value already learned from a reactive `MtuExceeded` or
  `PathMtuNotification`, loosening a clamp that had been correctly
  tightened.

### Removed

- The `parent_switched` spanning-tree metric counter. It was incremented on
  the line immediately before `parent_switches` at every site and never
  independently, so the two were always identical. `parent_switches`
  remains as the sole counter. Consumers reading `parent_switched` from the
  control socket or `fipstop` should use `parent_switches`.

## [0.4.0] - 2026-06-27

### Added

#### Transports (Nym, mDNS LAN discovery)

- Nym mixnet transport (`transports.nym`) for outbound peer links
  tunneled through a local `nym-socks5-client` SOCKS5 proxy into the
  Nym mixnet, as a privacy transport alongside Tor. Outbound-only and
  not platform-gated, it reuses the existing FMP framing and adds no new
  crate dependencies. A single-container example
  (`examples/sidecar-nostr-mixnet-relay/`) demonstrates FIPS peering
  across the mixnet end to end.
- Opt-in mDNS / DNS-SD LAN discovery for sub-second pairing of peers on
  the same local link, without a relay or NAT-traversal roundtrip.
  Disabled by default; operators enable it with
  `node.discovery.lan.enabled: true`. Configurable service type and an
  optional `node.discovery.lan.scope` that isolates discovery to peers
  sharing the same private-network scope. The advertised UDP port is
  chosen from a non-bootstrap operational UDP transport using a stable
  selector, so it is deterministic across restarts.

#### Admission / peer-list management

- `Node::update_peers` for runtime peer-list refresh, returning an
  `UpdatePeersOutcome` summarizing added, removed, and retained peers.
  Re-derives active peer connections from a new peer configuration
  without dropping links to peers that remain in the set.
  `PeerAddress` gains a `seen_at_ms` recency field (with
  `with_seen_at_ms`) used to prefer more recently observed addresses.

#### Data-plane / metrics / observability

- Typed `RejectReason` classification for receive-path silent-rejection
  sites across the node. Each rejection-and-return path now passes a
  typed reason to `NodeStats::record_reject`, which routes it to a
  per-subsystem counter, so operators can see what is being rejected
  through stats counters rather than by scraping debug logs. New
  `HandshakeStats`, `SessionStats`, and `MmpStats` sub-stats join the
  existing `TreeStats`, `BloomStats`, `DiscoveryStats`, and
  `ForwardingStats`, and `TreeStats::ancestry_invalid` is now
  incremented from the `TreeAnnounce::validate_semantics` rejection
  site that was previously silent. Several handshake, MMP, tree, and
  discovery rejection paths that had no counter at all are now counted,
  including the `send_lookup_response` no-route drop
  (`DiscoveryStats::resp_no_route`).
- Internal atomic metric registry (`Arc<MetricsRegistry>`) that shadows
  the plain-`u64` `NodeStats` counters, written alongside them and
  validated by a whole-struct debug-build parity check. Covers the
  forwarding receive counters, the full discovery counter family, and the
  tree, bloom, congestion, and error-signal counter families, with
  the hottest counters cache-line padded. Behavior-neutral:
  `NodeStats` remains the serving path. Groundwork for sampling metrics
  without contending the receive loop.
- `fipsctl stats metrics`, backed by a new counter-only `show_metrics`
  control query that dumps the atomic metric registry as flat counter
  name/value pairs. Serves a Prometheus-style scraper that samples node
  counters without contending the receive loop.
- `pool_inbound` and `pool_outbound` counters on the TCP and Tor
  transport stats (`TcpStats`, `TorStats`). Per-direction accounting
  is updated at every pool-insert and receive-loop-exit site, plus on
  transport stop and on send-failure-driven removal. Surfaces through
  `TcpStatsSnapshot` and `TorStatsSnapshot` for `show_transports`.

#### Spanning-tree / mesh-size / routing

- Six route-class transit counters that partition transit-forwarded
  packets by their tree relationship to the chosen next hop: tree-up
  (peer is our ancestor), tree-down (peer is our descendant and the
  destination is within its subtree), tree-down-cross (peer is our
  descendant but the destination is outside its subtree), cross-link
  descend (lateral peer, destination within its subtree), cross-link
  ascend (lateral peer, destination outside its subtree), and
  direct-peer. The six classes sum to `forwarded_packets` (asserted by a
  unit test) and are computed from tree coordinates at the transit
  chokepoint, so error-signal routing callers are excluded. They surface
  through the forwarding stats snapshot via `show_routing` and
  `show_status`.
- Discovery now counts `LookupRequest`s dropped when the dedup cache is
  full. A saturated `recent_requests` cache
  (`MAX_RECENT_DISCOVERY_REQUESTS`) previously dropped requests
  silently; a new `DiscoveryStats::req_dedup_cache_full` counter (typed
  reject reason `DiscoveryReject::ReqDedupCacheFull`) makes the drop
  visible through `show_routing`.

#### Packaging & deployment

- OpenWrt `.apk` packaging (`packaging/openwrt-apk/`, `make apk`) for
  OpenWrt 25+, where apk-tools is the mandatory package manager (the
  existing `.ipk` continues to cover OpenWrt 24.x and earlier). Built
  SDK-free: it reuses the `.ipk` cross-compile (`cargo-zigbuild`) and the
  shared installed-filesystem payload, and assembles the package with
  `apk mkpkg` from apk-tools 3.0.5 built from source — no OpenWrt SDK
  image. A `build-apk` CI job (aarch64, x86_64) builds and structurally
  verifies the package; releases now publish `.apk` artifacts and
  checksums alongside `.ipk`. Packages are unsigned, installed with
  `apk add --allow-untrusted`, matching the `.ipk` posture.
- Nix flake (`flake.nix` at the project root) for reproducible
  from-source builds on Nix/NixOS. Builds all four binaries (`fips`,
  `fipsctl`, `fips-gateway`, `fipstop`), pins the exact toolchain from
  `rust-toolchain.toml` via fenix, and wires the build-time native
  dependencies (`libclang` for `bindgen`, plus `dbus` and `pkg-config`),
  so it needs no host setup beyond Nix with flakes enabled. Flake inputs
  are lock-pinned (`flake.lock` committed) for reproducibility, and the
  flake exposes `nix build`, `nix run`, a `nix develop` dev shell with the
  pinned toolchain, and `nix flake check`. The flake produces binaries
  (and a NixOS `packages.<system>.fips` output); the systemd/service
  integration that the `.deb`/tarball installers provide is handled
  through the NixOS configuration instead.

#### Docs & contributor tooling

- [`PR-REVIEW.md`](PR-REVIEW.md) — the 13-criteria PR review checklist
  the maintainer runs against every incoming PR, published at the
  repo root so contributors can run the same pass on their own change
  (directly or by handing the document to a coding agent) before
  opening. Linked from `CONTRIBUTING.md` under "Submitting pull
  requests" and "Further reading". Running the checklist before
  opening surfaces problems that would otherwise come back as review
  comments, saving a round trip.
- [`docs/how-to/tune-file-descriptors.md`](docs/how-to/tune-file-descriptors.md)
  — an operator how-to for raising `RLIMIT_NOFILE`. A busy node opens
  roughly three file descriptors per established UDP peer (a
  `connect()`-ed socket plus a 2-FD drain self-pipe), so the default
  1024 soft limit is exhausted near 320 peers, after which further
  admission, handshakes, and discovery fail with `EMFILE`. The guide
  documents the per-peer FD budget and symptom, the systemd
  (`LimitNOFILE` drop-in) and OpenWrt (procd `nofile`) procedures to
  raise the limit, and how to verify the per-peer ratio stays bounded.
  Linked from the how-to index.

### Changed

#### FMP/FSP rekey reliability

- `complete_rekey_msg2` now returns the remote peer's startup epoch
  alongside the new Noise session, so the rekey path can detect a peer
  restart and clear stale session state.

#### NAT traversal / Nostr discovery

- Nostr discovery startup is now non-blocking. `Node::start` no
  longer waits for relay connect, subscribe, or initial advert
  publish before returning. A slow or unreachable relay no longer
  holds node startup hostage; local transports come up immediately
  and the relay path catches up asynchronously in background tasks.
  Subscribe retries with exponential backoff (2 s base, 60 s cap),
  publish attempts time out at 10 s, and the new tasks are aborted
  cleanly on `Node::stop`.

#### Spanning-tree / mesh-size / routing

- Active-peer path selection now sorts address candidates by recency
  (`seen_at_ms`), preferring the most recently observed address when
  racing concurrent path probes.
- Per-tick work budgets bound the connection churn done in a single
  node tick: `MAX_DISCOVERY_CONNECTS_PER_TICK`,
  `MAX_RETRY_CONNECTIONS_PER_TICK`, and
  `MAX_PARALLEL_PATH_CANDIDATES_PER_PEER`. Work beyond a tick's budget
  is deferred to the next tick rather than discarded.

#### Admission / peer caps

- `node.bloom.max_inbound_fpr` default raised from `0.05` to `0.10`. The
  cap rejects inbound `FilterAnnounce` whose FPR (`fill^k`) exceeds it. On
  the fixed 1 KB / k=5 filter, `0.05` corresponds to fill 0.549 (~1,300
  reachable entries) and had begun rejecting the busiest nodes' aggregates
  as the mesh approached that size. `0.10` (fill 0.631, ~1,630 entries)
  restores headroom toward the fixed-filter capacity limit without
  materially weakening the antipoison gate: a saturated or poisoned filter
  is ~100% FPR and still rejected.
- TCP inbound connection cap now honors `node.limits.max_connections`.
  The per-transport TCP inbound accept ceiling was hardwired to 256 and
  never read `max_connections`, so raising it was a silent no-op for
  inbound TCP. The effective cap now resolves with precedence: explicit
  per-transport `max_inbound_connections`, then node-wide
  `max_connections`, then the built-in default of 256. Established peers
  remain bounded node-wide by `add_connection`.

#### Data-plane / worker-pool / metrics / observability

- The control-socket read surface is now served off the `rx_loop`.
  Every pure-read `show_*` query — `show_status`, the `show_stats_*`
  family, `show_listening_sockets`, the new `show_metrics`,
  `show_tree`/`show_bloom`/`show_cache`/`show_routing`/
  `show_identity_cache`, `show_peers`/`show_sessions`/`show_links`/
  `show_connections`/`show_transports`/`show_mmp`, and `show_acl` — now
  renders in the control accept task from ArcSwap-published read
  snapshots instead of round-tripping the data-plane receive loop; only
  the mutating `connect`/`disconnect` commands still reach the loop.
  This removes the head-of-line coupling where a busy or slow `rx_loop`
  could time out `fipsctl` and `fipstop` observability (the five-second
  query pattern operators saw on loaded nodes). Per-entity snapshots
  reuse unchanged rows by pointer, so per-tick publish cost stays
  bounded as peer/session count grows. New daemon-resolved fields
  surface through the snapshots: effective persistence, root/is-root,
  and a per-transport-type peer-count map in `show_status`; per-peer
  `effective_depth` in `show_peers`; `root_npub` in `show_tree`; and the
  last-sent uptree filter fill ratio and subtree estimate in
  `show_bloom`.
- `fipstop` TUI overhaul: reworked rendering, navigation model, and the
  control read surface it draws from, surfacing the new daemon-resolved
  snapshot fields above. Built on a ratatui `TestBackend`
  render-snapshot harness that asserts the text grid and per-cell
  style of every `ui::draw_*` against canned `show_*` JSON.
- Steady-state log noise reduced on saturated public-mesh nodes.
  Routine per-peer connection-lifecycle and capacity-cap events are
  demoted from info/warn to debug — FMP K-bit cutover promotion,
  connection-promoted-to-active-peer (a redundant duplicate
  promotion line removed), peer-restart-detected, peer-removed-and-
  cleaned-up, the TCP `max_inbound_connections`-reached rejection, and
  the congestion-CE-flag line — so genuinely notable info/warn lines
  are no longer drowned out. An exhausted FMP-msg1 / FSP-msg3 rekey
  retransmission-budget abort (an expected, self-limiting outcome on
  lossy or high-latency links) is likewise demoted from warn to debug.
- macOS UDP receive path now batches up to 32 datagrams per kernel
  wakeup via `recvmsg_x(2)`, matching the Linux `recvmmsg(2)`
  amortization shape introduced in v0.3.0. Previously macOS fell
  through to single-packet `recv_from`, capping inbound rate on
  Apple builds with the same per-syscall + per-task-wakeup overhead
  Linux had already eliminated. `recvmsg_x` is an xnu-private syscall
  declared via `unsafe extern "C"` against a local repr(C)
  `msghdr_x`; same approach used by `quinn-udp`. Same
  `(count, kernel_drops)` contract as the Linux path, with
  `kernel_drops` always 0 on macOS (no `SO_RXQ_OVFL` equivalent).
  Bench numbers on aarch64-apple-darwin (100B payloads, 3 s
  windows): 1 sender 1.09x, 2 senders 1.72x, 4 senders 1.56x,
  8 senders 1.46x.
- Receive hot path: removed two per-packet copies. New borrowed
  `SessionDatagramRef` decoder is used in the forwarding handler so
  local delivery and coordinate-cache warming no longer allocate or
  copy the session payload; the owned `SessionDatagram` is materialized
  only when re-encoding for the next hop. Owned `SessionDatagram::
  decode` is reimplemented as `Ref::decode + into_owned`, so the two
  decoders cannot drift. On Linux + macOS the `recvmmsg` / `recvmsg_x`
  receive loop now moves each filled slot buffer into `ReceivedPacket`
  via `mem::replace` instead of cloning it, and `TransportAddr` is
  formatted directly from the `SocketAddr` without an intermediate
  `String`. Focused decode bench: ref 1.6 ns/op vs owned 34.7 ns/op
  (21.4x).
- Quieted non-Linux test-build warnings from intentionally
  platform-specific code: the nftables firewall parser
  (`#[allow(dead_code)]` now gated to non-Linux targets where the
  parser is compiled but unused), the macOS `utun` address-family
  helper and the long TUN reader entry point (narrow allowances),
  and a macOS Ethernet test module's clippy struct-layout lint
  (rewritten MAC-copy loop, explicit layout annotation). No
  behavioral change; the goal is to keep `cargo test` and
  `cargo clippy` clean on cross-platform builds so unrelated
  warning fixes don't get bundled into behavioral PRs.
- Data-plane: AEAD encrypt and AEAD decrypt now run on per-shard
  worker-pool threads (`std::thread` + `crossbeam_channel`), off the
  rx_loop. Hash-by-destination dispatch pins each TCP flow to one
  worker so wire ordering is preserved; per-worker `sendmmsg(2)`
  batches up to 32 outbound packets per syscall, with UDP_GSO
  (`UDP_SEGMENT`) when the batch is uniform-sized — the same kernel
  primitive WireGuard's in-kernel module and Cloudflare's userspace
  BoringTun use to hit multi-Gbps single-stream rates. On Linux +
  macOS each established UDP peer also gets a dedicated `connect(2)`-
  ed kernel socket bound to the same wildcard listen port via
  `SO_REUSEPORT`, so the kernel caches per-packet route + neighbor
  lookup and the worker sends with `msg_name = NULL`. The receive
  side mirrors: per-shard thread-local `HashMap` owns each session's
  recv cipher + replay window, replacing the previous shared
  `RwLock`. Sessions are re-registered with the decrypt pool on
  K-bit flip and rekey cutover, and unregistered on rekey drain
  completion and peer removal so the per-shard tables stay bounded.
  New `crossbeam-channel = "0.5"` dependency. Worker counts default
  to `num_cpus`; both pools are overridable via
  `FIPS_ENCRYPT_WORKERS` and `FIPS_DECRYPT_WORKERS` (the latter
  accepts `0` to disable the pool and fall back to in-line decrypt
  in rx_loop). Per-peer connected UDP can be disabled via
  `FIPS_CONNECTED_UDP=0`. Optional per-stage timing reporter
  available via `FIPS_PERF=1` (or `FIPS_PIPELINE_TRACE=1`); detailed
  knob documentation is a follow-up at
  `docs/how-to/tune-worker-pools.md`. Bench (5 × 15 s × 1 stream
  medians, Linux x86_64, docker-bridge mesh): A→D 1379→2708 Mbps
  (1.96×), A→E 1394→2663 Mbps (1.91×), E→A 1406→2624 Mbps (1.87×);
  RTT +0.11–0.19 ms from the worker queue handoff. Windows
  continues on the existing tokio-based send/recv path. Two issues in
  the off-rx_loop drain path are resolved as part of the overhaul: the
  per-peer drain worker is now detached on `Drop` rather than joined
  synchronously (a synchronous join from the runtime thread could wedge
  the whole daemon when a peer was removed with an in-flight worker),
  and the connected-UDP drain no longer busy-spins on a poll error
  (#106).

#### Transports & config

- Static host aliases in `/etc/fips/hosts` now hot-reload on mtime
  change instead of only at daemon startup, so `fipsctl`/`fipstop`
  display names reflect edits without a restart. The peer ACL and host
  map both reload once per node tick through a new lock-free
  `Reloadable` snapshot.
- Sidecar example (`examples/sidecar-nostr-relay`): `udp.mtu` is now
  overridable via the `FIPS_UDP_MTU` environment variable, defaulting to
  1472 (preserving prior behavior). Plumbed through `docker-compose.yml`
  and documented in the README env-var table. Annotated the static-CI
  node template `mtu: 1472` literal with the same Docker-bridge
  rationale and a pointer at the daemon's 1280 default.

#### Packaging & deployment

- The Debian package no longer ships `/etc/fips/fips.yaml` as a dpkg
  conf-file. The default configuration is installed as an example at
  `/usr/share/fips/fips.yaml.example`, and `postinst` seeds
  `/etc/fips/fips.yaml` (mode 600) from it only when the file does not
  already exist — so a configuration-management-rendered or
  operator-edited config is never prompted for or clobbered on
  upgrade, removing the need for a `dpkg-divert` workaround.
  `fips.service` gains `ConditionPathExists=/etc/fips/fips.yaml`. The
  example is placed under `/usr/share/fips`, deliberately outside
  `/usr/share/doc`, which minimal and container installs path-exclude
  (so the install-time seed source is never dropped).
- openwrt: the `.apk` package now defaults `ethernet.wan` to the
  OpenWrt 25 DSA port name `wan`; the `.ipk` package keeps `eth0` for
  OpenWrt 24 and earlier.

#### CI & test-harness reliability

- CI and release-publish workflows hardened:
  - `ci.yml` declares a top-level `concurrency` block keyed on
    `(workflow, ref)` with `cancel-in-progress: true`. Force-pushes
    and rapid successive pushes to the same ref now retire any
    in-flight run rather than letting superseded and current-tip runs
    both burn runner minutes.
  - `aur-publish.yml` rewritten to fetch the upstream source tarball
    and compute its `b2sum` in CI, then patch `pkgver` and the
    `b2sums` SKIP placeholder in `PKGBUILD` in-place. Previously
    `updpkgsums: true` downloaded the tarball into the AUR working
    tree, where it was rejected by AUR's 488 KiB max-blob hook —
    silently no-op'ing the v0.3.0 stable AUR push. `fips.sysusers` /
    `fips.tmpfiles` asset b2sums are recomputed in the same step to
    stay in sync with the local files. `workflow_dispatch` gains a
    tag input so historical release tags can be re-published
    manually, and `continue-on-error: true` is dropped so future
    regressions surface in CI.
  - New `aur-publish-git.yml` workflow for the `fips-git` VCS
    PKGBUILD, triggered on master pushes touching `PKGBUILD-git` or
    companion files plus `workflow_dispatch`. `pkgver` is computed at
    build time by the PKGBUILD's `pkgver()` function, so this workflow
    is not tied to release tags.
  - Tag-triggered `package-*` release-build workflows remain
    untouched.
- Local and GitHub CI integration coverage brought into parity, and
  the Rust toolchain selection given a single source of truth:
  - The `admission-cap` integration suite, previously run only by
    `ci-local.sh`, now also runs as a GitHub `ci.yml` matrix leg, so a
    regression in it turns the GitHub gate red rather than depending on
    a developer remembering to run local CI. A new
    `testing/check-ci-parity.sh` (wired as `ci-local.sh
    --check-parity`) diffs the two runners' integration-suite sets and
    fails on unexpected drift; the deliberate local-only (live-Tor)
    and granularity-only differences are documented in a comment block
    atop both runners.
  - CI and packaging jobs now select the toolchain with
    `actions-rust-lang/setup-rust-toolchain` (which reads
    `rust-toolchain.toml`) instead of `dtolnay/rust-toolchain@stable`.
    The pinned channel already overrode the installed stable, so each
    job downloaded an unused toolchain and logged a misleading `rustc`
    version; the single-source action removes the waste and the
    confusion. Existing cache steps are kept (`cache: false` on the
    new action) and `RUSTFLAGS` is left untouched so no global
    `-D warnings` is newly imposed. The OpenWrt nightly Tier-3 leg
    keeps `@nightly`.

#### Docs & contributor tooling

- Overhauled `CONTRIBUTING.md`: replaced generic Rust-template framing
  with a FIPS-specific entry point covering the four-layer
  architecture, branch model and PR-target selection, structured bug
  reporting, scope discipline and local-CI requirements, an AI coding
  assistant policy, and project communication channels. Added
  `docs/branching.md` as the long-form companion covering the release
  workflow, version conventions, and merge-direction rationale.

### Fixed

#### FMP/FSP rekey reliability

- FMP link-layer rekey is now reliable under packet loss, bringing it up
  to the FSP session layer's rekey discipline. The rekey msg1
  retransmission driver was previously uncapped and never abandoned, so a
  rekey that never completed resent msg1 forever; it now uses a bounded
  retransmission budget (`handshake_max_resends` with exponential
  backoff) and abandons the rekey cycle cleanly once the budget is
  exhausted, mirroring the FSP rekey msg3 driver. With the cap in place
  the link-dead heartbeat is rekey-aware: `check_link_heartbeats` no
  longer reaps a link that is still actively carrying rekey-handshake
  traffic, while a genuinely dead link is still reaped once the budget
  abandons. At the K-bit cutover the receiver now authenticates an
  inbound frame against the pending session before promoting it, instead
  of promoting on the bare header K-bit; under jitter a node could
  otherwise promote a stale pending session, leaving the two endpoints on
  different keys and silently dropping traffic until the link died — the
  same failure class already closed on FSP, now closed on FMP.
- FSP session rekey is now hitless under packet loss and reordering.
  Previously, a rekey could leave the two endpoints holding different
  key sets for a brief window — if a handshake message was lost in
  transit one side rotated keys while the other did not, and traffic
  sealed in one key epoch reached a peer still on the other epoch and
  failed to decrypt, producing bursts of AEAD decryption failures and
  dropped connectivity until a later rekey reconverged the pair. The
  receive path now trial-decrypts each frame against every live key
  epoch (current, pending, and the draining previous session) for the
  duration of the rekey transition, so no rotation ordering and no
  packet reordering can cause a decryption failure. The previous-epoch
  slot is retained as long as the peer keeps using it, with its drain
  deadline anchored on the last frame the peer authenticates against
  it rather than a fixed wall-clock timer, so a peer that did not
  receive the new keys is not stranded by a silent permanent decrypt
  failure. The lost-handshake case is closed by retransmitting the
  third rekey handshake message until the peer is confirmed on the
  new keys, with a bounded retry budget after which the rekey cycle
  is cleanly abandoned and retried. There are no FSP decryption
  failures across a rekey under lossy, jittery links.
- ±15s symmetric jitter is applied per session to the FMP and FSP rekey
  timer trigger, eliminating the steady-state dual-initiation race in
  symmetric-start meshes (previously the smaller-NodeAddr tie-breaker
  resolved correctness only after every cycle's collision).
  `node.rekey.after_secs` becomes the nominal interval rather than a
  floor; the mean is preserved.
- A stale FSP (session-layer) session is now cleared when a peer
  restart is detected during FMP rekey or cross-connection promotion.
  Previously the old session could linger after the peer came back
  with a new startup epoch, leaving the session-layer map out of sync
  with the freshly promoted peer.

#### NAT traversal / Nostr discovery

- Two nodes that each `auto_connect` to the other no longer stall their
  Nostr-mediated NAT-traversal handshake. Each side ran both an
  initiator and a responder traversal session, binding a separate UDP
  socket per session, and adopted only the first `Established` event; if
  the two sides adopted mismatched sessions, each sent its Noise msg1 to
  a peer port the peer had already stopped draining and both handshakes
  hung until the adoption budget expired. The responder now elects a
  single session deterministically — it declines an incoming offer only
  when it also has an in-flight outbound initiator for the same peer and
  its own NodeAddr is smaller — so one matching socket pair survives on
  both ends and the peer's redundant initiator times out harmlessly.
  One-sided (asymmetric) `auto_connect` has no co-active initiator and is
  never suppressed, so connectivity is preserved.
- NAT-traversal cross-init adoption is now deterministic under
  simultaneous dual-initiation. Previously, when two peers'
  Nostr-mediated UDP punches completed within the same scheduling
  window, each side's bootstrap-completion event arrived with an
  in-flight handshake already recorded against the other peer (each
  side had received an inbound msg1 from the other's pre-punch
  outbound attempt). The deduplication skip then fired on both
  sides, neither installed the fresh traversal socket as canonical,
  and the 45-second peer-adoption budget expired with both nodes
  stuck waiting for an adoption that never happened. The handler now
  applies the same deterministic NodeAddr tie-breaker the codebase
  already uses for rekey dual-initiation and cross-connection
  resolution: the smaller NodeAddr wins as adopter, tears down its
  in-flight handshake state, and proceeds with adoption; the larger
  NodeAddr keeps the skip semantics, and its in-flight outbound is
  reconciled by the cross-connection logic when the winner's fresh
  msg1 arrives over the adopted socket. The dual cross-init stall is
  eliminated; cross-init NAT-traversal completes in well under a
  second even under host CPU contention.
- Nostr-discovered NAT-traversal events (`BootstrapEvent::Established`
  and `BootstrapEvent::Failed`) for peers that are already connected
  or actively handshaking are now short-circuited at the
  `poll_nostr_discovery` dispatch sites before any cooldown
  bookkeeping or fallback retry scheduling runs. Stale `Failed` events
  previously poisoned the per-peer failure-state cooldown of healthy
  peers and could trigger redundant retraversal attempts via
  `schedule_retry` / `try_peer_addresses`; stale `Established`
  handoffs could attempt to adopt a second socket against a live
  connection. A defense-in-depth guard was added to
  `adopt_established_traversal` so the same invariant holds if a
  future caller bypasses the outer dispatch check. As a side benefit,
  narrows a cooldown-poisoning vector previously available to an
  attacker injecting stale failure events for an active peer.
- Nostr discovery now filters unroutable direct UDP/TCP advert
  endpoints. Publisher and validator retain only endpoints that parse as
  concrete socket addresses with routable IPs and nonzero ports;
  `udp:nat` rendezvous endpoints and Tor endpoints pass through
  unchanged. Adverts that collapse to zero usable endpoints after
  filtering are rejected with a clear "missing publicly routable
  endpoints" error. Before this change, misconfigured nodes could
  publish RFC1918, loopback, link-local, CGNAT 100.64/10, IPv6 ULA,
  or IPv6 link-local endpoints into Nostr discovery, and consumers
  would cache and dial them; in mixed LAN/VPN/NAT environments, that
  could prefer a misleading one-way private path over the intended
  `udp:nat` bootstrap.

#### Admission / peer caps

- TCP and Tor `max_inbound_connections` admission cap is now compared
  against the per-direction inbound count (`pool_inbound`) rather than
  the combined pool size. Outbound connect-on-send connections share
  the same pool data structure but no longer consume slots against the
  operator-facing inbound cap. The configuration field name and
  operator semantics are preserved; only the cap-check comparison and
  accounting change. Operators with mixed outbound + inbound
  deployments no longer see legitimate inbound peers rejected once
  outbound connections fill the pool past the configured cap.
- Outbound connection initiation now honors the `node.limits.max_peers`
  cap that was previously only checked on inbound msg1 admission. Four
  paths gated: auto-reconnect retries (`process_pending_retries`),
  Nostr-mediated discovery's `BootstrapEvent::Established` adoption, and
  both sides of the Nostr-mediated NAT-traversal punch (offer initiation
  in the runtime's outgoing path, offer acceptance in the responder's
  incoming-offer handler). At saturation, a node now performs zero
  outbound work on these paths; only existing peer maintenance and
  overlay-advert refresh continue. The inbound gate at
  `handshake.rs:1114` is unchanged. Introduces a shared
  `Node::outbound_admission_check()` helper so the invariant is
  grep-able and unit-testable.
- Inbound `handle_msg1` now silent-drops at `node.limits.max_peers`
  saturation *before* building/sending Msg2, instead of replying with
  Msg2 and then rejecting at `promote_connection`. Adds an early cap
  check positioned after identity verification (so the
  reconnect / cross-connection bypass for known peers still fires) and
  before index allocation + Msg2 wire send. The late cap check inside
  `promote_connection` is intentionally retained as
  defense-in-depth. Wire savings observed in a 45 s tcpdump at
  saturation: ~3.6 cap-denials/s × Msg2 (~104 B + AEAD compute) each.
  Bigger win is cleaner peer-side semantics — no fake-completed
  handshake whose subsequent data frames fail decryption on this side.

#### Spanning-tree / mesh-size / routing

- The mesh-size estimator (`compute_mesh_size`) no longer over-counts
  under filter overlap. It previously summed the per-filter cardinality
  of the parent and each child filter, which assumes the filters are
  perfectly disjoint; a stale or oversized parent filter or a routing
  loop inflated the reported mesh size to several times the true value,
  and dropping the parent on a tree rebalance collapsed the upward leg
  and flapped the count (the symptom operators saw as the size
  nearly-but-not-exactly doubling during rebalancing). The estimator now
  computes the cardinality of the OR-union over self plus every
  connected peer's inbound filter, dropping the parent/child tree gating
  entirely. OR is idempotent, so any overlap is deduplicated — the
  result equals the old sum in the disjoint case, stays correct under
  overlap, damps the parent-switch flap, and removes the estimate's
  dependence on tree-declaration cache freshness. The per-peer 500 ms
  rate-limiter and overall recompute cadence are unchanged.
- Spanning-tree state distribution is now eventually-consistent.
  Previously every `send_tree_announce_to_all` call site fired only
  on a local state-change event (parent switch, self-root promotion,
  ancestry change, peer promotion, parent loss). Once a partition
  latched — for example, a parent-switch announce lost in transit
  via the brief cross-init handshake swap window where one peer's
  outbound session is about to become the loser session and the
  receiver has no matching decrypt-worker entry — no node's state
  changed again, so no node ever re-broadcast. The existing 60-second
  `check_periodic_parent_reeval` short-circuited silently on no-change
  (it was a re-evaluation, not a re-broadcast), and production-side
  healing depended on incidental link churn (NAT keepalive refresh,
  MMP timeout, peer re-promotion after a transport blip). The
  function now ends with an unconditional `send_tree_announce_to_all`
  on the no-change branch, alongside the existing switch and
  self-promote arms; receivers coalesce by sequence comparison
  (`ParentDeclaration::is_fresher_than`) and short-circuit at the
  `if !updated` gate in `handle_tree_announce`, so same-sequence
  repeats drop silently with no cascade. The per-peer 500 ms
  rate-limiter is well below this 60-second cadence and does not
  suppress the heartbeat broadcast. `BASELINE_CONVERGENCE_TIMEOUT`
  in `testing/static/scripts/rekey-test.sh` is bumped from 60 to 65
  so any partition healed by the periodic broadcast at T+60 lands
  inside the convergence window; `wait_for_full_baseline` early-exits
  on PASS, so successful reps see no extra wall-clock.
- A single-uplink node stranded out of the tree now re-attaches within
  a round-trip instead of waiting for the periodic re-broadcast cadence.
  A node with one tree peer has periodic parent re-evaluation disabled,
  so a lost one-shot attaching `TreeAnnounce` left it self-rooted and
  unreachable until the next periodic re-broadcast
  (`reeval_interval_secs` later). Tree-position exchange is now
  self-healing on the receive path: when an accepted `TreeAnnounce`
  advertises a root strictly worse (higher NodeAddr; election is
  smallest-wins) than our own, we echo our current declaration back to
  that peer, provoking the better-rooted peer to re-push its real
  position immediately. The echo fires only in that one direction and is
  bounded by the existing per-peer rate limiter.
- Coord cache invalidation made surgical at parent-position-change
  and root-change sites. Replaces the previous unconditional
  `CoordCache::clear()` calls with two targeted methods:
  `invalidate_via_node(node_addr)` (drops entries whose cached
  ancestry contains the changed node, used at parent-switch /
  become-root / loop-detection sites) and `invalidate_other_roots`
  (drops entries from a different tree, used at root-change sites).
  The previous global flush left `find_next_hop` returning `None`
  for every non-direct-peer destination after every parent switch
  until the cache passively re-warmed; surgical invalidation
  preserves entries that remain correct across the topology change.
  Peer-removal retains the original "no invalidation" behavior
  (`find_next_hop` already recomputes against the current peer set
  every call, and Discovery handles "no route" on demand).
- `rx_loop` tick-arm stall under convergence-phase mesh pressure
  is eliminated. Previously, the tick body's per-peer `check_*`
  loops (heartbeats, bloom announces, MMP reports, tree announces)
  called `transport.send` directly for every active peer. For
  TCP/Tor peers whose pool entry was not yet established,
  `send_async` fell through to a synchronous connect-on-send
  branch that wrapped `TcpStream::connect` in
  `tokio::time::timeout(connect_timeout_ms, …)` — 5 seconds by
  default — and blocked the entire tick body for the duration per
  unreachable peer. Under post-restart convergence on a high-peer
  mesh, this cascaded into multi-second tick stalls; the same
  mechanism also starved the master-only per-tick control-snapshot
  republish and pushed `fipsctl show *` queries onto an mpsc
  fallback that was itself queued behind the wedged `rx_loop`,
  producing the five-second `fipsctl` head-of-line pattern
  operators observed on loaded nodes. The send path now gates on
  `transport.connection_state(addr)` before sending: proceed only
  when `Connected`; on `None`, kick off a non-blocking background
  `connect` (idempotent — deduplicates against the connecting
  pool, spawns the timeout-bounded `TcpStream::connect` inside its
  own tokio task) and fail this send fast with a clear
  `transport connection not ready` error. A subsequent tick
  retries once the pool has an entry. The existing reconnect
  lifecycle (heartbeat-dead detection in `check_link_heartbeats`,
  scheduled retries via `process_pending_retries`, background-
  connect polling via `poll_pending_connects`) is unchanged.
  The connect-on-send branch in `transport.send_async` itself
  remains in place for code paths that legitimately need
  synchronous connect (e.g., explicit operator-driven
  `fipsctl connect`); the tick path just no longer trips it.

#### Data-plane / metrics / observability

- The Tor transport now increments its `connect_refused` statistic (the
  "Refused" line in fipstop) when a SOCKS5 connection is actively
  refused, instead of recording every connect failure as a generic
  SOCKS5 error. The counter previously stayed at zero.
- MMP sender metrics now ignore duplicate or regressed receiver reports
  before updating RTT, loss, goodput, or ETX. Receiver reports also
  suppress timestamp echo when dwell time overflows, so stale reports
  cannot inflate SRTT.
- Reject-reason counters no longer double-count now that the rollout's
  interim direct increments are removed. Six discovery counters
  (`req_decode_error`, `req_duplicate`, `req_ttl_exhausted`,
  `resp_decode_error`, `resp_identity_miss`, `resp_proof_failed`), six
  bloom counters (`decode_error`, `invalid`, `non_v1`, `unknown_peer`,
  `stale`, `fill_exceeded`), and five forwarding reject packet counters
  (`decode_error_packets`, `ttl_exhausted_packets`,
  `drop_no_route_packets`, `drop_mtu_exceeded_packets`,
  `drop_send_error_packets`) were each incremented both by a direct bump
  and again through the typed reject dispatch. The redundant direct
  increments are removed — for the forwarding family the two calls are
  collapsed into a single byte-aware reject entry point — so each counter
  (and, for forwarding, its byte tally) counts once per event.
- Transport-layer mutex poisoning no longer cascades. Ten
  `Mutex::lock().unwrap()` sites across the UDP, BLE, and Ethernet
  transports would turn a single panic (poisoning the mutex) into a
  cascade of panics on every subsequent lock. Each is replaced with
  `lock().unwrap_or_else(|e| e.into_inner())`, recovering the guarded
  data with no new dependency and no call-graph change; four
  `local_addr.unwrap()` calls on the UDP start/adopt paths get a
  provably-safe sentinel fallback. The critical sections are short,
  locally-scoped, and not reachable from peer input, so this is
  robustness hardening, not a remotely-triggerable fix.

#### Peer lifecycle / gateway

- A manual `fipsctl disconnect` now notifies the peer so teardown is
  symmetric. Previously a manual disconnect tore down only the local
  side and sent the peer nothing, so the peer kept its session and never
  re-emitted its tree and filter announcements; on reconnect it was
  never re-adopted as a child and its bloom filter was never recorded.
  The local side now sends the disconnected peer a scoped `Disconnect`
  (the same message graceful shutdown sends), so both ends tear down and
  re-handshake cleanly on the next connection.
- `fips-gateway` no longer drops long-lived or DNS-cached client
  mappings while traffic is still flowing. The virtual-IP pool's TTL
  clock advanced only on DNS re-query, never on traffic, and the mapping
  TTL is wired equal to the DNS TTL, so an in-use mapping was forced to
  drain at TTL and reclaimed at the first zero-conntrack tick — breaking
  long-lived, bursty, or DNS-cached clients. The tick now refreshes the
  mapping's last-referenced time whenever conntrack reports active
  sessions, and recovers a draining mapping to active (with a fresh
  grace window) when traffic resumes; only genuinely idle mappings
  drain.

#### macOS self-traffic / resolver

- Self-addressed mesh traffic is now delivered locally on macOS instead
  of being dropped, for both `ping6` and full TCP/UDP. The point-to-point
  `utun` interface egresses self-addressed traffic into the daemon, which
  previously pushed it onto the mesh outbound path where it was dropped
  for lack of a route to self; such packets are now hairpinned back to
  the TUN for inbound delivery. macOS first routes self-addressed packets
  as loopback (a `LOCAL` route via `lo0`), which leaves their transport
  TX checksum offloaded and unfinished, so re-injecting them verbatim
  made the local stack drop every segment whose checksum MSS clamping did
  not happen to rewrite (the SYN and SYN-ACK got through, but the bare
  ACK, data, and FIN were dropped, so connections to a node's own
  `<npub>.fips` service half-opened and hung). The hairpin path now
  recomputes the TCP/UDP checksum before re-injection, so full
  self-connections — not just `ping6` — to a node's own `<npub>.fips`
  address work. Linux was unaffected (the kernel already loops
  self-traffic via `lo`). (#117)
- macOS `.fips` name resolution now works on a fresh install: the
  shipped resolver shim points at `::1`, matching the daemon's default
  IPv6 DNS listener, instead of `127.0.0.1`. The mismatched shim
  (`nameserver 127.0.0.1` while the daemon listens on `::1`) broke
  `getaddrinfo` for `.fips` on every macOS install since the resolver
  was introduced.

#### CI & test-harness reliability

- Node-level multi-node tests no longer flake under parallel CPU load.
  They previously delivered handshake packets over real localhost UDP,
  whose kernel receive buffer could overflow and drop a packet when many
  tests ran concurrently, panicking the large-network convergence tests.
  A `cfg(test)`-only loopback `TransportHandle` variant now delivers
  packets directly between nodes over an unbounded in-process channel, so
  there is no socket buffer to overflow, and the previously-quarantined
  large-network tests run in the default suite again. The shipping daemon
  build is unaffected (the variant is test-gated).
- Integration suites that wait for the mesh to converge no longer
  false-fail under concurrent CI load. The rekey, static-mesh, and
  sidecar suites replace a fixed wall-clock baseline timeout (and a blind
  sleep) with a progress-aware wait that polls the suite's own pairwise
  pings, returns as soon as every pair is reachable, extends its deadline
  while the reachable-pair count is still climbing, and gives up only
  when progress stalls.
- Rekey integration test (`testing/static/scripts/rekey-test.sh`) no
  longer false-fails on GitHub runners under packet loss and CPU
  contention. Phase 1, Phase 3, and Phase 5 strict per-pair pings retry
  up to 4 attempts (configurable via `MAX_PING_ATTEMPTS` /
  `PING_RETRY_DELAY`) — under 1% per-direction loss, single-shot 20-pair
  ping_all misses ~33% per phase from ICMP noise alone, and the
  4-attempt retry brings that floor to ~3.2e-6 per phase; the
  `wait_for_full_baseline` convergence loop stays single-shot so retries
  there cannot conflate transient ping loss with still-converging routing
  state. Phase 1 baseline-convergence headroom is bumped from 36s to 60s
  to eliminate the intermittent Phase 1 timeout that previously required
  a `gh run rerun --failed`, and a post-second-rekey settle window is
  added in Phase 5 (mirroring Phase 3's 12-second pattern) to close the
  post-rekey per-pair-ping flake from convergence exceeding the per-ping
  5-second timeout. Test scaffold only; no daemon code changes, and the
  success path is unchanged because the wait loops return as soon as all
  20 pairs converge.
- ACL-allowlist integration test (`testing/acl-allowlist/test.sh`):
  converted `assert_log_contains` from a one-shot `docker logs | grep`
  snapshot into a bounded poll with the same wait-with-timeout shape
  as `wait_for_peers_exact`. Absorbs the millisecond-to-second
  variance in the XX-handshake cross-connection tie-breaker: the
  inbound-handshake-context rejection can land tens of milliseconds
  after the test's previous one-shot grep gave up, producing a
  pre-existing flake on CI. Success-path cost is unchanged — the helper
  returns as soon as the pattern appears.

#### Packaging & deployment

- AUR packaging: the `fips` and `fips-git` PKGBUILDs now install the
  `fips-dns-setup` and `fips-dns-teardown` helpers into
  `/usr/lib/fips/`, matching the Debian package. The AUR `package()`
  step previously omitted them, so `fips-dns.service` failed to
  start on Arch installs ("Unable to locate executable
  `/usr/lib/fips/fips-dns-setup`", #98). The PKGBUILDs additionally
  opt out of the debug split package and declare the `*-debug`
  variant as a conflict, so a stale debug build cannot own installed
  files across a package switch.
- macOS package build: the `.pkg` architecture is now derived from
  the Cargo `--target` triple instead of the build host's
  `uname -m`. The arm64 and x86_64 release legs build on the same
  Apple-silicon runner, so `uname -m` named both outputs
  `fips-0.3.0-macos-arm64.pkg`; the release job's `merge-multiple`
  artifact download then interleaved the two identically named
  files into a single corrupt xar archive, and no x86_64 package
  reached the release at all. (This shipped as the broken v0.3.0
  macOS `.pkg`, GitHub #102.) The release workflow now also asserts
  the arch-named file is present and carries a SHA-256 integrity
  chain from the build runner through to `gh release upload`, so a
  recurrence fails CI instead of publishing.

#### fipstop

- `fipstop` no longer renders a garbled screen on startup or leaves
  stray bytes on quit, most visible over SSH and inside tmux. Startup
  forces a full repaint (`terminal.clear()`) before the first draw so
  prior alternate-screen contents no longer show through; quit gives the
  stdin-poll thread a stop flag and joins it before restoring the
  terminal, so post-raw-mode keystrokes or terminal query responses no
  longer echo onto the restored screen.

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
