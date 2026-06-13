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

### Fixed

- MMP sender metrics now ignore duplicate or regressed receiver reports
  before updating RTT, loss, goodput, or ETX. Receiver reports also
  suppress timestamp echo when dwell time overflows, so stale reports
  cannot inflate SRTT.

### Added

- Nym mixnet transport (`transports.nym`) for outbound peer links
  tunneled through a local `nym-socks5-client` SOCKS5 proxy into the
  Nym mixnet, as a privacy transport alongside Tor. Outbound-only and
  not platform-gated, it reuses the existing FMP framing and adds no new
  crate dependencies. A single-container example
  (`examples/sidecar-nostr-mixnet-relay/`) demonstrates FIPS peering
  across the mixnet end to end.
- Typed `RejectReason` classification for receive-path silent-rejection
  sites across the node. Each rejection-and-return path now passes a
  typed reason to `NodeStats::record_reject`, which routes it to a
  per-subsystem counter, so operators can see what is being rejected
  through stats counters rather than by scraping debug logs. New
  `HandshakeStats`, `SessionStats`, and `MmpStats` sub-stats join the
  existing `TreeStats`, `BloomStats`, `DiscoveryStats`, and
  `ForwardingStats`, and `TreeStats::ancestry_invalid` is now
  incremented from the `TreeAnnounce::validate_semantics` rejection
  site that was previously silent. The Noise XX handshake cluster
  (msg1/msg2/msg3) and the rekey-initiator outbound sites are wired in
  addition to the shared clusters. Several handshake, MMP, tree, and
  discovery rejection paths that had no counter at all are now counted,
  including the `send_lookup_response` no-route drop
  (`DiscoveryStats::resp_no_route`). Existing
  direct counters at the bloom / discovery / forwarding sites are
  retained alongside the new dispatch while the rollout is in progress;
  a later change collapses the duplicate increment.
- Internal atomic metric registry (`Arc<MetricsRegistry>`) that shadows
  the plain-`u64` `NodeStats` counters, written alongside them and
  validated by a whole-struct debug-build parity check. Covers the
  forwarding receive counters, the full discovery counter family, and the
  tree, bloom, congestion, and error-signal counter families so far, with
  the hottest counters cache-line padded. Behavior-neutral:
  `NodeStats` remains the serving path. Groundwork for sampling metrics
  without contending the receive loop.
- `Node::update_peers` for runtime peer-list refresh, returning an
  `UpdatePeersOutcome` summarizing added, removed, and retained peers.
  Re-derives active peer connections from a new peer configuration
  without dropping links to peers that remain in the set.
  `PeerAddress` gains a `seen_at_ms` recency field (with
  `with_seen_at_ms`) used to prefer more recently observed addresses.
- Opt-in mDNS / DNS-SD LAN discovery for sub-second pairing of peers on
  the same local link, without a relay or NAT-traversal roundtrip.
  Disabled by default; operators enable it with
  `node.discovery.lan.enabled: true`. Configurable service type and an
  optional `node.discovery.lan.scope` that isolates discovery to peers
  sharing the same private-network scope. The advertised UDP port is
  chosen from a non-bootstrap operational UDP transport using a stable
  selector, so it is deterministic across restarts.
- `pool_inbound` and `pool_outbound` counters on the TCP and Tor
  transport stats (`TcpStats`, `TorStats`). Per-direction accounting
  is updated at every pool-insert and receive-loop-exit site, plus on
  transport stop and on send-failure-driven removal. Surfaces through
  `TcpStatsSnapshot` and `TorStatsSnapshot` for `show_transports`.
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

- `complete_rekey_msg2` now returns the remote peer's startup epoch
  alongside the new Noise session, so the rekey path can detect a peer
  restart and clear stale session state.
- Active-peer path selection now sorts address candidates by recency
  (`seen_at_ms`), preferring the most recently observed address when
  racing concurrent path probes.
- Per-tick work budgets bound the connection churn done in a single
  node tick: `MAX_DISCOVERY_CONNECTS_PER_TICK`,
  `MAX_RETRY_CONNECTIONS_PER_TICK`, and
  `MAX_PARALLEL_PATH_CANDIDATES_PER_PEER`. Work beyond a tick's budget
  is deferred to the next tick rather than discarded.
- Nostr discovery startup is now non-blocking. `Node::start` no
  longer waits for relay connect, subscribe, or initial advert
  publish before returning. A slow or unreachable relay no longer
  holds node startup hostage; local transports come up immediately
  and the relay path catches up asynchronously in background tasks.
  Subscribe retries with exponential backoff (2 s base, 60 s cap),
  publish attempts time out at 10 s, and the new tasks are aborted
  cleanly on `Node::stop`.
- `node.bloom.max_inbound_fpr` default raised from `0.05` to `0.10`. The
  cap rejects inbound `FilterAnnounce` whose FPR (`fill^k`) exceeds it. On
  the fixed 1 KB / k=5 filter, `0.05` corresponds to fill 0.549 (~1,300
  reachable entries) and had begun rejecting the busiest nodes' aggregates
  as the mesh approached that size. `0.10` (fill 0.631, ~1,630 entries)
  restores headroom toward the fixed-filter capacity limit without
  materially weakening the antipoison gate: a saturated or poisoned filter
  is ~100% FPR and still rejected.
- Sidecar example (`examples/sidecar-nostr-relay`): `udp.mtu` is now
  overridable via the `FIPS_UDP_MTU` environment variable, defaulting to
  1472 (preserving prior behavior). Plumbed through `docker-compose.yml`
  and documented in the README env-var table. Annotated the static-CI
  node template `mtu: 1472` literal with the same Docker-bridge
  rationale and a pointer at the daemon's 1280 default.
- Overhauled `CONTRIBUTING.md`: replaced generic Rust-template framing
  with a FIPS-specific entry point covering the four-layer
  architecture, branch model and PR-target selection, structured bug
  reporting, scope discipline and local-CI requirements, an AI coding
  assistant policy, and project communication channels. Added
  `docs/branching.md` as the long-form companion covering the release
  workflow, version conventions, and merge-direction rationale.
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
- Rekey timer jitter is enabled on next's XX FMP rekey path
  (`REKEY_JITTER_SECS = 15` at `src/node/mod.rs`), matching the
  IK-line behavior on maint/master. It had been temporarily set to
  `0` on next because variable-interval rekeys exposed three XX
  rekey-path defects that left the two endpoints on divergent Noise
  sessions; those defects are fixed (see `### Fixed`), so the
  per-session signed jitter over `[-15, +15]` seconds is restored.
  `node.rekey.after_secs` is the nominal interval rather than a floor;
  mean is preserved.
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
  continues on the existing tokio-based send/recv path.

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

### Fixed

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
- Six discovery counters (`req_decode_error`, `req_duplicate`,
  `req_ttl_exhausted`, `resp_decode_error`, `resp_identity_miss`,
  `resp_proof_failed`) no longer double-count. Each was incremented both
  by a direct bump and again through the typed reject dispatch; the
  redundant direct increment is removed, so each counts once per event.
- Six bloom counters (`decode_error`, `invalid`, `non_v1`,
  `unknown_peer`, `stale`, `fill_exceeded`) no longer double-count. Each
  was incremented both by a direct bump and again through the typed
  reject dispatch; the redundant direct increment is removed, so each
  counts once per event.
- Five forwarding reject packet counters (`decode_error_packets`,
  `ttl_exhausted_packets`, `drop_no_route_packets`,
  `drop_mtu_exceeded_packets`, `drop_send_error_packets`) no longer
  double-count. Each was incremented both by the byte-aware outcome
  recorder and again through the typed reject dispatch; the two calls are
  collapsed into a single byte-aware reject entry point, so packets and
  bytes each count once per event.
- A stale FSP (session-layer) session is now cleared when a peer
  restart is detected during FMP rekey or cross-connection promotion.
  Previously the old session could linger after the peer came back
  with a new startup epoch, leaving the session-layer map out of sync
  with the freshly promoted peer.

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
  never suppressed, so connectivity is preserved. (Distinct from the
  cross-init adoption tie-breaker below, which dedups two simultaneous
  punches but does not stop each node from running redundant
  initiator + responder sessions.)
- FMP link-layer rekey is now reliable under packet loss, bringing it up
  to the FSP session layer's rekey discipline:
  - The rekey msg1 retransmission driver was uncapped and never
    abandoned, so a rekey that never completed resent msg1 forever. It
    now uses a bounded retransmission budget (`handshake_max_resends`
    with exponential backoff) and abandons the rekey cycle cleanly once
    the budget is exhausted, mirroring the FSP rekey msg3 driver. With
    the cap in place the link-dead heartbeat is rekey-aware:
    `check_link_heartbeats` no longer reaps a link that is still
    actively carrying rekey-handshake traffic, while a genuinely dead
    link is still reaped once the budget abandons.
  - At the K-bit cutover the receiver now authenticates an inbound frame
    against the pending session before promoting it, instead of
    promoting on the bare header K-bit. Under jitter a node could
    otherwise promote a stale pending session, leaving the two endpoints
    on different keys and silently dropping traffic until the link died
    — the same failure class already closed on FSP, now closed on FMP.
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
- TCP and Tor `max_inbound_connections` admission cap is now compared
  against the per-direction inbound count (`pool_inbound`) rather than
  the combined pool size. Outbound connect-on-send connections share
  the same pool data structure but no longer consume slots against the
  operator-facing inbound cap. The configuration field name and
  operator semantics are preserved; only the cap-check comparison and
  accounting change. Operators with mixed outbound + inbound
  deployments no longer see legitimate inbound peers rejected once
  outbound connections fill the pool past the configured cap.
- `PeerRecvDrain::drop` no longer calls `std::thread::join` on the
  worker thread. The drain worker uses `packet_tx.blocking_send(...)`
  on a tokio mpsc Sender, which internally parks the worker in
  `tokio::block_on` on the same `current_thread` runtime that drives
  `rx_loop`. Joining synchronously from inside `remove_active_peer`
  (which runs on the runtime thread, the runtime's sole driver)
  produced a circular wait: rx_loop blocked in libc futex via
  `Thread::join`, the worker unable to observe the stop flag because
  the runtime that polls it is the very thread now blocked joining
  it, and all other peer-drain workers parked on the same runtime
  via `block_on`. Full daemon wedge, fipsctl unresponsive, SIGTERM
  ignored. Trigger was peer-removal via the 30-s link-dead-timeout
  cleanup path with any in-flight worker, with statistical likelihood
  amplified by aggressive multi-npub-from-one-NAT reconnect patterns
  but not bounded to them. Fix: detach the std::thread (drop the
  `JoinHandle` without joining); the stop flag + self-pipe write
  already signal the worker to exit; the kernel-level `libc::poll()`
  inside the drain loop sees the wake, checks the flag, exits, and
  the OS reclaims the thread state independently.
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
- Mesh-size estimator (`compute_mesh_size`) no longer double-counts the
  parent's bloom cardinality during the transient cache window after a
  local parent-switch. Symptom: `fipsctl show status` / fipstop displayed
  mesh size nearly-but-not-exactly doubling during tree rebalancing.
  Fix: explicit parent-skip at the head of the children loop, making the
  disjoint-subtree invariant structural rather than dependent on
  `peer_declaration` cache freshness. Per-peer 500 ms rate-limiter and
  overall recompute cadence are unchanged.
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
- Nostr discovery: filter unroutable direct UDP/TCP advert endpoints.
  Publisher and validator now retain only endpoints that parse as
  concrete socket addresses with routable IPs and nonzero ports.
  `udp:nat` rendezvous endpoints and Tor endpoints pass through
  unchanged. Adverts that collapse to zero usable endpoints after
  filtering are rejected with a clear "missing publicly routable
  endpoints" error. Before this change, misconfigured nodes could
  publish RFC1918, loopback, link-local, CGNAT 100.64/10, IPv6 ULA,
  or IPv6 link-local endpoints into Nostr discovery, and consumers
  would cache and dial them; in mixed LAN/VPN/NAT environments, that
  could prefer a misleading one-way private path over the intended
  `udp:nat` bootstrap.
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
- Rekey integration test (`testing/static/scripts/rekey-test.sh`):
  Phase 1, Phase 3, and Phase 5 strict per-pair pings now retry up
  to 4 attempts (configurable via `MAX_PING_ATTEMPTS` /
  `PING_RETRY_DELAY`). Under low-level packet loss (1% per
  direction), single-shot 20-pair ping_all misses with probability
  ~33% per phase from ICMP noise alone, masking the routing-state
  signal the asserts target. The 4-attempt retry brings that floor
  to ~3.2e-6 per phase. The `wait_for_full_baseline` convergence
  loop itself stays single-shot — retries there would conflate
  transient ping loss with still-converging routing state. Test
  scaffold only; no daemon code changes.
- Apply ±15s symmetric jitter per session to the FMP and FSP rekey
  timer trigger. Eliminates the steady-state dual-initiation race
  in symmetric-start meshes; previously the smaller-NodeAddr
  tie-breaker resolved correctness after every cycle's collision.
  `node.rekey.after_secs` becomes the nominal interval rather than
  a floor; mean is preserved.
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
- Rekey integration test (`testing/static/scripts/rekey-test.sh`):
  bumped Phase 1 baseline-convergence headroom from 36s to 60s.
  Eliminates the intermittent GitHub-runner Phase 1 timeout that
  previously required `gh run rerun --failed`. Cost on the success
  path is unchanged because the wait loop returns as soon as all 20
  pairs converge.
- Rekey integration test (`testing/static/scripts/rekey-test.sh`):
  added a post-second-rekey settle window in Phase 5, mirroring
  Phase 3's existing 12-second pattern. Closes the intermittent
  GitHub-runner Phase 5 per-pair-ping flake caused by post-rekey
  routing convergence exceeding the per-ping 5-second timeout under
  runner CPU contention. Cost on the success path is a fixed 12s per
  suite run.
- ACL-allowlist integration test (`testing/acl-allowlist/test.sh`):
  converted `assert_log_contains` from a one-shot `docker logs | grep`
  snapshot into a bounded poll with the same wait-with-timeout shape
  as `wait_for_peers_exact`. Absorbs the millisecond-to-second
  variance in the XX-handshake cross-connection tie-breaker: the
  inbound-handshake-context rejection can land tens of milliseconds
  after the test's previous one-shot grep gave up, producing a
  pre-existing flake on next-branch CI. Success-path cost is
  unchanged — the helper returns as soon as the pattern appears.
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
