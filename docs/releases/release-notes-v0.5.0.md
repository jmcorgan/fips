# FIPS v0.5.0

**Released**: 2026-08-30

v0.5.0 is a feature release, the first since v0.4.0. It adds two new
supported platforms, a new way for applications to use the mesh, and a set
of smaller additions across transports, diagnostics and packaging. It also
renames part of the configuration surface, carries four fixes for bugs that
shipped in earlier releases, and adds four security fixes specific to this
line.

**Upgrading.** Nodes upgrade in any order. A v0.5.0 node and a v0.4.x node
peer, rekey and route normally, so there is no flag day and no coordination.
If you are coming from v0.4.1 or earlier, read the v0.4.2 notes too: v0.5.0
contains that release, and most of this cycle's security work is in it.

## Platform support

A port to FreeBSD, on x86_64, has been made, with a native package. The
daemon, `fipsctl` and `fipstop` build and run there; `fips-gateway` stays
Linux-only. One thing this paves the way for is to create FIPS native
support in FreeBSD-based firewall appliances, such as OPNsense and pfSense.

Android support is officially provided in this release, but for use as an
embedded crate in other applications rather than as a standalone daemon.
Android applications own the TUN adapter, and the FIPS crate provides a Rust
API to send and receive packets over the mesh. The Bluetooth LE transport is
now supported on Android, and is interoperable with Linux.

## Native API for datagrams

The FIPS mesh sends datagrams between cryptographic endpoints, and the main
way this has been used up until now has been to emulate an IPv6 network
adapter and tunnel IPv6 packets over it. This has allowed existing IPv6
applications to use the mesh without any changes.

The native datagram API lets an application written to it communicate
directly over the mesh, addressing a peer by public key and exchanging
datagrams on a file descriptor. It bypasses the local IP stack and the
emulated IPv6 adapter entirely. How nodes peer with each other does not
change, and nothing on the wire changes.

## Other changes

OpenWrt gains an 802.11s mesh between routers and the open `!FIPS` client
SSID, both opt-in. The Bluetooth LE transport is refactored so Linux and
Android share one implementation with a backend for each. A peer address may
name which instance of a transport it belongs to, so a node running several
listeners of one type can be dialled on the right one.

`fipsctl` gains two subcommands: `probe`, which reports in five stages
whether one target is reachable and where the attempt stopped, and
`address`, which derives a node's mesh address from a key file with no
daemon running. Shutdown now drains before it closes, and an optional
profiler measures where the maintenance tick spends its time.

The Nix flake gains a NixOS module and an overlay, so a flake consumer
enables the daemon with one line rather than hand-rolling a systemd unit.

## FreeBSD details

The `.pkg` is published on the release page. No aarch64 artifact is produced
and that combination is not verified here.

FreeBSD follows the macOS install layout: `/usr/local/etc/fips` for config,
`hosts`, `peers.allow`, `peers.deny` and `fipsctl keygen` output, and
`/var/run/fips` for the control socket. Packaging under `packaging/freebsd/`
builds through `make freebsd` and ships rc.d services, a `fips`
control-socket group, service stop and restart across `pkg upgrade`, and
`.fips` DNS integration for `local_unbound`, `unbound` and `dnsmasq`. mDNS
LAN discovery works, by way of an `mdns-sd` bump to 0.20 that picks up the
first `socket-pktinfo` release building on FreeBSD.

Two changes here reach every platform. That `mdns-sd` bump applies to all
targets, and the daemon now disables ANSI color in its logs when stdout is
not a terminal.

Contributed by [@fr34aky](https://github.com/fr34aky)
([#129](https://github.com/jmcorgan/fips/pull/129)).

## The native datagram API

The API is off by default and its surface may still change, so it ships for
client authors to build against and report back on.

The wire needs no change and gets none. Every FSP data packet has carried a
port pair inside its AEAD envelope since v0.2.0, and port 256 is simply the
IPv6 shim, so what was missing was a way for a program to ask for a port of
its own and be handed the traffic.

The x-only public key is the address, and an npub is that key written in
bech32, so converting between them is a local encoding rather than a lookup
or a name service. The 16-byte node address that travels on the wire is a
truncated hash of the key, does not invert, and appears nowhere a client can
see.

The API is a direct, best-effort interface to FSP, the session protocol the
mesh already speaks. FSP authenticates and encrypts end to end, and it
delivers datagrams on a best-effort basis: no acknowledgement, no
retransmission, no ordering guarantee and no flow control between the two
ends. A program that needs any of those builds them itself, or runs an
ordinary reliable protocol over the `fips0` adapter instead.

The interface style is deliberately close to Berkeley sockets. A program
calls `connect` for a flow to a public key and a port, or `bind` for a port
to receive flows on, and from there uses ordinary socket calls on the
descriptor it holds.

A listener is a descriptor. The daemon writes one message per arrival to it,
carrying the new flow's descriptor and the peer's address, so `poll`,
`select` and `epoll` work on a listener and accepting is a `recvmsg`. There
is no accept command and no reject command: refusing a flow is closing the
descriptor you were handed.

The Rust surface mirrors `std::net`, with `FipsStream::connect`,
`FipsListener::bind`, `incoming`, `accept`, `io::Result` and an errno
mapping rather than a bespoke error type, plus `set_nonblocking`, `AsFd` and
four deadline methods under the names and signatures `std::net` uses for the
same jobs.

**One rule has no counterpart in Berkeley sockets and a client author must
know it: the v1 wire carries no half-close.** Nothing peer-driven ever
closes a flow, so a server written to read until the flow ends waits for a
signal that cannot arrive.

The listener uses `SOCK_SEQPACKET` on Linux and `SOCK_DGRAM` on macOS and
FreeBSD; both keep the message boundaries the API's contract with its
clients rests on. macOS does not implement `SOCK_SEQPACKET` for `AF_UNIX` at
all. FreeBSD accepts the constant and returns a socket that is not an
atomic-record socket, so consecutive messages coalesce and a zero-length
message is dropped rather than delivered; both were measured on the FreeBSD
15.1 image rather than reasoned about. The three kernels signal a closed
peer differently and were measured too, so the receive path treats a Darwin
or FreeBSD `ECONNRESET` as end of file alongside the `POLLHUP` and zero-byte
read that Linux gives.

Contributed by [@jmcorgan](https://github.com/jmcorgan) (Johnathan
Corgan).

Start with [the walkthrough](../tutorials/native-api-walkthrough.md), then
[how to write a client](../how-to/write-a-native-api-client.md); [the
reference](../reference/native-api.md) carries the full surface.

## OpenWrt

Two capabilities land together here, and the second is stacked on the first.
Both arrive as opt-in helpers: a package must not commandeer a router's
radios on install, so neither runs unless you run it.

### 802.11s mesh backhaul

FIPS can now be the encryption and routing layer over router-to-router radio
links. The mesh runs **open**, with `mesh_fwding 0`: SAE would duplicate the
Noise layer and force ath10k into raw mode, and the FIPS spanning tree is
the routing layer, so the 802.11s link is deliberately left as a bare L2
neighbor link and FIPS provides all encryption, authentication and routing
over it.

`fips-mesh-setup` is a UCI helper that creates a mesh point per radio:
`radio0` becomes `fips-mesh0`, `radio1` becomes `fips-mesh1`, with a
free-index fallback and a collision guard. A dual-band router gets one
instance per radio, and FIPS treats the two paths as **failover rather than
multipath**: cross-connection resolution keeps one active link per peer and
the second band stands by, re-establishing after keepalive timeout.

The shipped `fips.yaml` carries the matching `mesh0` and `mesh1`
Ethernet-transport entries commented out, so a stock install that never
creates the interfaces logs no per-boot interface-missing warning. The
helper uncomments the block when it creates the interface and re-comments it
on remove. Two silent non-peering causes found in the field are surfaced by
the helper's warnings: a radio left on `auto` channel, and a `sta` interface
dragging the radio to its upstream access point's channel.

Contributed by [@Origami74](https://github.com/Origami74)
([#123](https://github.com/jmcorgan/fips/pull/123)). The full procedure
is in
[the 802.11s backhaul how-to](../how-to/set-up-80211s-mesh-backhaul.md).

### The open `!FIPS` access SSID

Stacked on that backhaul, every FIPS router can broadcast the same open
`!FIPS` SSID, forming one standard ESS that phones and laptops save once and
roam between natively, with the Noise IK handshake as the only security
layer. The leading `!` sorts it to the top of alphabetically ordered network
pickers. The encryption type must be uniform across routers or clients treat
the ESS as separate saved networks.

`fips-ap-setup` creates the `fips-ap0` open access point on an isolated
network. IPv6 is a static ULA /64 announced by router advertisement, so
addressing is stateless SLAAC with DHCPv6 off; IPv4 is a DHCPv4 lease out of
a fixed `10.21.<N>.0/24`, deliberately identical on every router so a
roaming client's lease stays valid. Both sit behind a locked-down `fips_ap`
firewall zone with no path to `br-lan` or the WAN, passing only DHCPv4,
ICMPv6, mDNS and the FIPS transports. There is no internet by design, so
phones keep cellular as their default route, and the addressing is what an
Android client's connectivity check needs to stay associated. The helper
also uncomments the `node.rendezvous.lan` block, since a phone app cannot
open raw Ethernet sockets and DNS-SD is how it finds the daemon.

Contributed by [@Origami74](https://github.com/Origami74)
([#126](https://github.com/jmcorgan/fips/pull/126)). The full procedure
is in
[the open access SSID how-to](../how-to/set-up-open-access-ssid.md).

## Bluetooth LE peering

The BLE transport has been refactored so the code common to Linux and
Android is implemented once, with a separate backend for each platform. Most
of the work is contributed. The transport compiles on every glibc Linux
target and on Android, and is excluded on musl; the gate is `ble_available`,
and a platform with no concrete backend now fails the build rather than
compiling a transport that starts, reports itself up and never peers.

A peer is recognised by node identity rather than by its link address.
Resolvable private addresses rotate continually and modern phones use them
by default, so every rotation presented as a brand-new device and none of
the already-connected guards could tell.

The L2CAP PSM is now decided by the backend. BlueZ is the exception in
letting an application choose the PSM it binds: Android and macOS both
return an OS-assigned one that cannot be requested, and before a connection
exists there is no channel on which to be told it. So `listen` reports the
PSM it actually bound, the advertisement carries it alongside the 128-bit
FIPS service UUID, and a dialer takes it from the scan, falling back to the
configured value for a peer that advertises none.

Probe retry is bounded. A discovered address that failed to connect was
re-dialled every cooldown for the life of the process, and because BLE
hardware caps concurrent connections at roughly four to ten, a handful of
unreachable peers starved discovery of everything behind them. Failing
addresses now back off by powers of two and the retry book itself is capped,
so rotating private addresses cannot grow it without bound. Each connect
outcome has its own counter and structured log line carrying the role, the
outcome, the PSM dialled and how long the peer took to conclude, which is
what distinguishes a peer out of range from one being dialled at the wrong
PSM.

Inbound handshakes run off the accept loop, eight in flight, aborting the
oldest at the bound. The exchange previously ran inline, so a peer that
connected and then said nothing held the loop for the full 5-second deadline
and the effective inbound concurrency was one.

## Node and transport control

### Shutdown now drains before it closes

On the shutdown signal the node broadcasts Disconnect to all peers and then
keeps serving for a bounded window, exiting early once all peers are gone.
The window is the new `node.drain_timeout_secs`, default 2 seconds. Teardown
was previously immediate.

Under systemd or launchd this shows up as a stop taking up to two seconds
longer than it used to. If your service manager has a short stop timeout, or
you have tooling that expects the process to be gone immediately, that is
the thing to check. Setting `node.drain_timeout_secs: 0` restores the old
behaviour. The immediate stop path used by non-daemon callers is unchanged.

### A peer address may name a transport instance

A peer address may name which instance of a transport it belongs to, as
`transport: "udp/aware"`, where the part after the slash is the key the
transport was configured under. A node running several instances of one type
could not be told them apart by a dialer: both bind wildcard sockets, so the
address-family test matched either and selection fell through to the lowest
transport id. One socket carried every dial and the other never carried
traffic. A bare type is unqualified and matches any instance, which is what
every existing configuration and caller produces, so nothing changes for a
node that does not use the syntax. A qualified name is never substituted
with a different instance, since that is the wrong-lane dial the syntax
exists to prevent, and the configuration validator rejects a name that no
configured transport answers to rather than letting the address be skipped
invisibly at every dial.

## Diagnostics

### `fipsctl probe`

For one target, where it sits in the spanning tree relative to this node and
whether this node can actually reach it. Five stages report separately,
`bloom`, `discovery`, `path`, `session` and `rtt`, because one verdict
covering several findings is what sends an operator to the source: "no
peer's filter claims this address" says the mesh has never heard of the
target, while "a filter claimed it and nothing answered" says the opposite.
The probe opens an FSP session, waits for one MMP receiver report to yield a
round-trip time, and tears down only what it opened; a session that existed
before the probe started is left alone. The path it prints is the
least-common-ancestor walk computed from the two sets of coordinates. That
is the worst-case fallback route, not necessarily the route a packet takes:
a cut-through between peers can deliver in fewer hops, so the tree distance
is an upper bound. Nothing here changes the wire format. `--json` emits
exactly one document at the end, so a script parsing the report does not
have to skip past progress output.

### `fipsctl address`

`fipsctl address [npub|hostname]` prints a node's `fd00::/8` mesh
address and nothing else, without contacting the daemon. With no argument it
derives the local node's address from `fips.key` in the default key
directory, falling back to the world-readable `fips.pub` beside it; `--key
PATH` names a key or public key file elsewhere. This lets an installer or an
image build write a mesh address into a config file at a point where no node
is running and none can be, and keeps the derivation in one place rather
than reimplemented by whatever needs it.

### Maintenance tick profiling

The rx-loop tick arm runs twenty-five unconditional housekeeping steps on
one runtime thread and is polled last, so anything slow in it holds inbound
packets, TUN traffic and control commands behind it. A new tick-body
profiler measures that, on a live node, with no restart.

It lives behind the new `profiling` Cargo feature and is **off by default**.
With the feature off, the instrumentation macro is a pure pass-through, so a
default build carries no timing code on the tick path. With it on, `fipsctl
profile tick on [--dir PATH]`, `off` and `status` start and stop a capture
at runtime. Each capture writes one tab-separated file, by default under
`/var/log/fips` and capped at 32 MB, carrying per ten-second interval the
exact count, max and total for every step, the whole-tick span, and gauges
for ticks, peer count, the gap between successive tick-arm entries and the
resulting arm-starvation delay.

Getting an instrumented build installed is supported directly:
`packaging/debian/build-deb.sh --features <list>` builds the `.deb` with a
Cargo feature list, and the auto-derived dev Version gains a matching
`+<features>` marker so a feature build and a default build of the same
commit are no longer indistinguishable. The marker sorts above the unmarked
build, so installing a feature build is an upgrade and reverting to the
default build is a downgrade: **revert with `dpkg -i`, not `apt install`.**
The packaged systemd units gained `LogsDirectory=fips` so the capture
directory is created and cleaned up declaratively.

## Packaging and deployment

### The NixOS module and overlay

The flake now exposes a NixOS module and an overlay, so a flake consumer
enables the daemon with one line instead of hand-rolling a systemd unit.
`overlays.default` adds `pkgs.fips`; `nixosModules.default` provides
`services.fips.*` with `enable`, `package`, `configFile`, `openFirewall`
(UDP 2121 and TCP 8443) and `dns.enable`, which routes `.fips` to
`[::1]:5354` through systemd-resolved declaratively rather than with setup
and teardown scripts. `packaging/nixos/README.md` carries a full consumer
`flake.nix`. Contributed by [@Origami74](https://github.com/Origami74)
(Arjen).

## For app and embedding developers

FIPS can now be embedded in an application, and that is how Android is
supported: as an embedded crate rather than as a standalone daemon. There is
no Android daemon artifact and no host-app integration guide. What ships is
a library surface that compiles for Android and a pair of entry points for
an app that owns its own tunnel.

The daemon's desktop transports and TUN operations are now gated by
`target_os` rather than by Cargo features, so a plain `cargo build` compiles
for every target with no flags, and Android self-excludes the raw Ethernet
transport exactly as Windows already did. No Cargo features are introduced
and desktop builds are unchanged.

`Node::enable_app_owned_tun()` gives an embedder that owns the TUN file
descriptor, an Android `VpnService` for instance, a channel pair for
exchanging IPv6 packet bytes with FIPS, instead of FIPS creating a system
TUN device. `start()` then performs no system-TUN and no `CAP_NET_ADMIN`
operations. Packets entering this way bypass `handle_tun_packet`, so **the
embedder must push only `fd00::/8` destined packets and must clamp TCP MSS
on outbound SYNs**.

`Node::dns_local_addr()` is the DNS companion. An embedder whose resolver is
pointed into the tunnel has no system socket aimed at the built-in `.fips`
responder, so the accessor reports the address read back off the bound
socket: `dns.port = 0` therefore yields the kernel-assigned port. It returns
`Some` only while the responder is up. Read it once, after `start()` returns
and before the node is moved into a background task; it is not a liveness
feed.

Both contributed by [@Origami74](https://github.com/Origami74)
([#127](https://github.com/jmcorgan/fips/pull/127),
[#136](https://github.com/jmcorgan/fips/pull/136)). CI cross-compiles the
library for `aarch64-linux-android` and runs clippy against it, which is a
compile gate. Nothing executes on Android in CI.

`Node::enable_app_owned_udp_fd()` is a third such entry point. Some hosts
associate a socket with one interface or network and steer inbound traffic
by that association rather than by destination address, and the socket
option that corrects it depends on host state FIPS has no basis to reason
about, so the descriptor goes to whoever does. One descriptor arrives per
UDP transport that binds, labelled with the instance name it was configured
under, so an embedder running several listeners can tell them apart. FIPS
keeps owning the socket. Unix only, since the Windows UDP backend has no
descriptor.

## Upgrade notes

This section is the operator-actionable list. Everything in it applies
to every platform.

### A node with no working transport now fails to start

Node health is determined once startup completes, instead of every node
unconditionally reaching a single running state. **Zero transports up is
now fatal**: the node tears down cleanly and the daemon exits with an
error. Previously such a node came up, reported itself running, and
served nothing.

```sh
fipsctl show transports
```

On the running v0.4.x node, that lists every transport instance with its
state. If it lists none, or lists none in an up state, that node will
fail to start on v0.5.0 and the fix is a working transport, not a
rollback. The common causes are a `transports:` block where every entry
is commented out, and an Ethernet transport naming an interface that
does not exist on the box, which logs an interface-missing warning and
does not come up.

A node with at least one transport up, and some other configured child
that failed, comes up **degraded and serving**, with a warning naming
what failed. That covers a second or later transport, Nostr, mDNS, TUN,
DNS, and the worker pools. A child you never asked the node to run does
not count against it.

### Three new node states are visible through the control socket

`Degraded`, `Failed` and `Draining` join the published node state and
show up in control queries. `Degraded` is operational, `Failed` is not.
If you have a monitor that matches the node state string exactly, teach
it the three new values before you upgrade.

Exit detection also re-evaluates health at runtime for the DNS task, the
two TUN threads and mDNS, so a child that dies after a healthy start now
shows as degraded rather than staying green.

### The `node.discovery.*` config table is split

`node.discovery.*` carried two unrelated things: the scalars that govern
mesh lookup, and the settings that govern peer rendezvous. They are now
separate tables.

- `node.lookup.*` takes the mesh-lookup scalars: `ttl`,
  `attempt_timeouts_secs`, `recent_expiry_secs`, `backoff_base_secs`,
  `backoff_max_secs`, `forward_min_interval_secs`.
- `node.rendezvous.*` takes peer rendezvous: `nostr.*` and `lan.*`.

**A deployed `node.discovery:` block still loads.** It is folded into
the new tables at startup and behaves identically, with a one-time
deprecation warning on the `fips::config` target naming the moves. The
legacy block will be removed at the v2 cutover, so migrate your
`fips.yaml` rather than leaving it.

Two of these keys are ones you may have adopted only one release ago. If
you are coming from v0.4.2, then
`node.discovery.nostr.max_concurrent_offers_per_npub` and
`node.discovery.nostr.signal_ttl_secs` are now
`node.rendezvous.nostr.max_concurrent_offers_per_npub` and
`node.rendezvous.nostr.signal_ttl_secs`.

One further rename, in the same vocabulary: the Ethernet transport's
per-interface `discovery` flag is now `listen`, pairing with the
existing `announce` flag as receive and transmit. The old `discovery:`
key is still accepted through a serde alias, so deployed configs load
unchanged, but a config the daemon re-emits will carry `listen:`.

Every shipped sample, guide and reference now teaches the new spelling.
**One exception is worth knowing about on OpenWrt**: `/etc/fips/fips.yaml`
is an opkg conffile there, so upgrading a router keeps its existing copy
and the new sample is never installed. A router upgraded from an earlier
release will still show the old commented `discovery:` examples in its
config file. Nothing breaks, since the old key parses, but the file on
the router is not the file in the package.

### Tracing targets moved, so `RUST_LOG` filters go blind rather than error

The internal restructuring moved modules, and tracing targets follow
module paths, so the targets moved with them:

- `fips::discovery::nostr::*` is now `fips::nostr::*`
- mDNS is now `fips::mdns::*`
- `fips::tree` is now `fips::proto::stp`
- `fips::bloom` is now `fips::proto::bloom`
- `fips::protocol` is now `fips::proto::*`
- the mesh-lookup subsystem moves from `fips::discovery` to
  `fips::proto::lookup`

An existing `RUST_LOG` filter naming an old target still parses. It
simply stops matching. The symptom is missing log lines rather than an
error, and a filter that has gone blind looks exactly like a subsystem
that has gone quiet, so update `RUST_LOG` settings, journal-watch
recipes and log-scraping alerts as part of the upgrade. Four targets are
named explicitly in the source rather than derived from a module path
and are unaffected: `fips::config`, `fips::instr`,
`fips::node::handlers::handshake` and `fips::node::handlers::rekey`.

### The `discovery` metric family is now `lookup`

The mesh-lookup control-metrics family is emitted under the key `lookup`
in `fipsctl stats metrics` and `show routing`. The former `discovery`
key is still emitted as a deprecated alias carrying identical counters
during the migration window, and will be removed. Point dashboards and
alerts at `lookup.*`.

`fipstop`'s Routing State pane follows: its `Discovery Requests` and
`Discovery Responses` sections are now `Lookup Requests` and `Lookup
Responses`. The counters are unchanged, so an operator who knows the
pane by its old labels is reading the same numbers under new names.

### The first handshake resend no longer follows its config key

`node.rate_limit.handshake_resend_interval_ms` no longer governs the
**first** outbound handshake resend, which is now armed from a hardcoded
1000 ms constant in the peer state machine. The key still governs the
second and later resends, alongside
`node.rate_limit.handshake_resend_backoff` and
`node.rate_limit.handshake_max_resends`. The constant equals the shipped
default of 1000, so a deployment that never overrode the key sees no
change. A deployment that raised or lowered it will find the first
resend still firing at 1000 ms.

## For library consumers

**These changes are source-breaking for code that depends on the `fips`
crate.** Nothing about the behaviour of the shipped binaries changes,
nothing on the wire changes, and an operator who runs the packaged
daemon and tools is unaffected. If you do not build against the crate,
skip this section.

The protocol layers were restructured into sans-IO cores with the I/O
kept in a thin shell. The consequence for the public surface:

- The crate-root modules `bloom`, `discovery`, `mmp`, `protocol` and
  `tree` are gone. The protocol cores moved into an internal `proto`
  module and are reached through crate-root re-exports: tree types
  through `proto::stp`, bloom types through `proto::bloom`, and the FSP,
  STP, lookup, routing and FMP wire types through their matching
  `proto::*` submodules. `PromotionResult` and `cross_connection_winner`
  come from `proto::fmp` rather than from `peer`.
- The crate-root `HandshakeState`, `PeerConnection`, `PeerSlot` and
  `ProtocolError` re-exports are removed. **The `HandshakeState` removed
  here is the peer connection-phase enum, not the Noise handshake type
  of the same name**, which is untouched and still lives at
  `fips::noise::HandshakeState`.
- `ProtocolError` is replaced by `fips::Error`. Its `Malformed` variant
  now carries a `&'static str` rather than a `String`, and it gained
  `BadSizeClass`, `BadCoord` and `BadBloom` variants, so the diagnostic
  text changed with it.
- `PeerSlot` and the `PeerConnection` resend API were unused and are
  deleted.
- `Node::connections()` is now `pub(crate)` and yields the internal peer
  machine rather than a `PeerConnection`. A consumer that walked links
  through it should use `Node::peers()`, `Node::get_peer()` and
  `Node::peer_count()` over `ActivePeer`, all of which remain public.

Two new crate-root modules, `nostr` and `mdns`, own peer rendezvous and
LAN discovery, and the crate root gains the `is_punch_packet` helper and
the `CoordError`, `MtuExceeded`, `COORDS_REQUIRED_SIZE` and
`MTU_EXCEEDED_SIZE` exports.

## Data plane and diagnostics

- **Batched macOS receives on connected UDP peer drains.** The connected
  UDP path now uses `recvmsg_x(2)`, matching the wildcard UDP receive
  path instead of issuing one `recv(2)` syscall per queued datagram.
  Contributed by Martti Malmi ([@mmalmi](https://github.com/mmalmi),
  [#135](https://github.com/jmcorgan/fips/pull/135)).
- **Allocation-free next-hop selection.** Routing next-hop selection
  visits borrowed peers and coordinates instead of allocating candidate
  snapshots for each forwarded packet. Contributed by Martti Malmi
  ([@mmalmi](https://github.com/mmalmi),
  [#134](https://github.com/jmcorgan/fips/pull/134)).
- **A connected UDP socket that cannot open now names the syscall and
  the address.** The local address for `bind`, the peer address for
  `connect`. Both paths previously returned a bare OS error that the
  caller wrapped identically, so a field report of `Address already in
  use` could not be attributed to either, and the two have entirely
  different causes. A node at roughly 245 peers was emitting this three
  times a second across nine peers with no way to diagnose it.
- **The sub-floor path-MTU refusal warning carries its correlator.** The
  warning raised when a lookup response carries a path MTU below the
  actionable floor now names the request it refused, as a `request_id`
  field on the log line. Only the log line changes: the response is
  still accepted, the coordinates are still cached, the sub-floor value
  is still discarded, and the same counter is still charged.

## Notable bug fixes

This release carries four fixes for bugs that shipped in previous
releases. Every other fix in the range either shipped in v0.4.2
or repairs something that was introduced and corrected within this
development cycle, and never reached a released version. The CHANGELOG
has the complete list.

- **The macOS control socket lands in `/var/run/fips`, not `/tmp`.** The
  packaged macOS daemon now recreates and binds its control socket at
  `/var/run/fips/control.sock`. A privileged macOS process selects that
  private runtime path before its leaf exists, so bind creates it, and
  clients follow once it is there. Socket setup now changes ownership
  and mode only for a private parent directory it creates or recognizes
  as a canonical FIPS runtime directory. Previously the packaged daemon
  fell through to the shared `/tmp/fips-control.sock` path after every
  boot, and because socket setup changed the parent directory
  unconditionally, the root daemon also took group ownership of `/tmp`
  itself. Contributed by
  [@erskingardner](https://github.com/erskingardner)
  ([#138](https://github.com/jmcorgan/fips/pull/138)).

- **`fipsctl disconnect` now closes the transport connection, not only
  the peer.** It notified the peer and freed every node-side structure,
  sessions, indices, links, address mapping, tree and bloom state, and
  never touched the transport, so on a connection-oriented transport
  (TCP, Tor, Nym, BLE) the pool entry, the socket and its inbound-slot
  accounting outlived the peer the node had just forgotten, until the
  far end closed or the receive loop errored. An operator who
  disconnected a peer to free a slot did not free the slot. UDP,
  Ethernet and loopback are unaffected, their `close_connection` being
  the connectionless no-op. Still not addressed: `disconnect` reports
  `peer not found` for an identity that is only mid-handshake.
- **`fipsctl connect` now tries the address it was given for a peer the
  node is already connected to**, instead of reporting success without
  doing anything. The command built an ephemeral peer configuration and
  handed it to the ordinary dial path, which returns success the moment
  the peer is already held, so an operator moving a peer onto a freshly
  provisioned link had no way to make the node use it: the peer stayed
  where it first authenticated until that path died. The address is now
  tried as an alternate path alongside the live one, so promotion
  happens only after the alternate handshake authenticates and a wrong
  address cannot displace a healthy link. The response gains an additive
  `refreshed` field. `connect` stays ephemeral: the peer is not written
  to configuration and gets no auto-reconnect.
- **A path MTU measured on one link no longer clamps a peer that has
  moved to another.** Every writer of the per-destination path-MTU cache
  keeps the smaller of the existing and incoming value, which is right
  while a peer stays put, but the entry was keyed by destination alone.
  A peer first reached over a narrow link stayed clamped to that link's
  ceiling for the lifetime of the process: when it later became
  reachable over a wider transport, the re-seed saw a tighter existing
  value and declined, and traffic kept running at the old ceiling with
  nothing reporting it, because the clamp was doing exactly what it was
  told. The node now records which transport last seeded each
  destination and treats a seed from a different one as authoritative.

## Security

**Most of this cycle's security content shipped in v0.4.2, which v0.5.0
contains**: session and handshake authentication hardening, path MTU
bounding, routing-signal gating, private key material protection and
clearing, gateway DNS answer validation, the supply-chain work, and the
nineteen further fixes from two security reports received during the release
cycle. If you are upgrading from v0.4.1 or earlier, all of that arrives with
this release, and the `[0.4.2]` section of the CHANGELOG is where it is
enumerated.

**Four items are specific to this line**, because the code they touch
exists only here.

An inbound onion connection no longer leaks its inbound slot. The Tor
accept loop spawned the per-connection receive task before inserting the
pool entry and bumping the counter, so a remote that reset immediately
let the receive task reach its cleanup first: the removal found nothing,
the decrement never fired, and the increment landed with nothing left to
undo it. Enough of those and `max_inbound` rejected every further onion
connection while the pool was visibly empty. The readiness barrier the
TCP accept loop already used is now applied here too.

The `--dir` given to `profile tick on` is confined to `/var/log/fips`
when the daemon runs as root. The control socket is reachable by the
`fips` group, which the security model treats as strictly weaker than
root, and the directory travelled from the socket into a root
`create_dir_all` with no validation. This affects only a
`--features profiling` build; the subcommand is absent from a stock
package. The capture sink also no longer writes over whatever is already
at its path, and capture files are created private to their owner.

Two further defects were found while merging the v0.4.2 security work up
into this line, and they were already present here in a different shape
than on the maintenance line: the socket-bind policy, which this line had
centralized across three sockets rather than one, and a shared
per-address rate limiter that swept its whole map on every admission with
no ceiling. Fixing them here reaches further than the original fixes did.

One piece of supply-chain hygiene does belong to this release. The
workflow files and composite actions that exist only on this line are
now pinned to full commit SHAs, so the whole `.github` tree is pinned or
explicitly justified: 75 action references, 71 pinned to a
40-character commit SHA with the mandatory version comment, and 4 left
on mutable tags by explicit allowance. Nine of those were pinned here,
in files that arrived through the merge on mutable tags because the
original pinning sweep was authored on a branch that never carried them.

Security reports have a private channel; see
[`SECURITY.md`](../../SECURITY.md).

## Known limitations

### A zero-length datagram before a close is reported as the close

This affects the experimental native datagram API only.

A peer that closes its half of a flow leaves `POLLHUP` latched, and the flag
stays set while its messages are still queued. The receive path therefore asks
`FIONREAD` as well: bytes still queued prove a further message is waiting, so a
client that sends an empty datagram, then a message, then closes has both
delivered.

**One case has no answer.** A zero-length datagram that is the last message
before a close is indistinguishable from the close itself. Reading it drains the
queue, and a zero-length message contributes no bytes for `FIONREAD` to report.
Measured on Linux 6.8: a socket in that state is identical to a drained one in
`revents`, in `FIONREAD`, under `MSG_PEEK` and in the `recvmsg` return.

Do not give a zero-length payload a meaning of its own on this API. Carry a
one-byte discriminator, and let the zero-byte read mean end of file. Separating
the two needs a payload that is never zero bytes on the wire, which is a
protocol change and is not in this release.

## Getting v0.5.0

- **Linux x86_64 / aarch64**: `.deb` and tarball at the
  [v0.5.0 release page](https://github.com/jmcorgan/fips/releases/tag/v0.5.0).
- **Arch Linux**: `fips` from the AUR.
- **macOS**: `.pkg` at the v0.5.0 release page.
- **Windows**: ZIP at the v0.5.0 release page.
- **FreeBSD (x86_64)**: `.pkg` at the v0.5.0 release page. New this
  release; see the FreeBSD section of `packaging/README.md`.
- **OpenWrt**: `.ipk` (OpenWrt 24.x and earlier) or `.apk` (OpenWrt 25+)
  at the v0.5.0 release page. Both carry the `fips-mesh-setup` and
  `fips-ap-setup` helpers.
- **From source**: `cargo build --release` from a checkout of the v0.5.0
  tag (Rust 1.94.1 per `rust-toolchain.toml`; `libclang-dev` is a
  required Linux build prerequisite).
- **Nix / NixOS**: `nix build .#fips` from a checkout of the v0.5.0 tag
  builds the binaries from source with the pinned toolchain and no
  manual prerequisites (see the Nix section of `packaging/README.md`).

There is no Android daemon artifact. Android is supported as an
embedded crate, described above.

The full per-commit changelog lives in
[`CHANGELOG.md`](../../CHANGELOG.md). Issues and discussion at
[github.com/jmcorgan/fips](https://github.com/jmcorgan/fips).

## Contributors

Thanks to everyone who contributed code, packaging work, bug reports, or
reviews to this release. Twenty of this release's commits came from
outside the project, and they carry several of the capabilities an
operator meets first.

- [@Origami74](https://github.com/Origami74) (Arjen): the OpenWrt
  802.11s mesh backhaul
  ([#123](https://github.com/jmcorgan/fips/pull/123)), the open `!FIPS`
  access SSID ([#126](https://github.com/jmcorgan/fips/pull/126)), the
  Android-ready core with the app-owned TUN interface
  ([#127](https://github.com/jmcorgan/fips/pull/127)), and
  `dns_local_addr()` for embedders
  ([#136](https://github.com/jmcorgan/fips/pull/136)). Also the
  per-instance transport addressing that lets a peer address name which
  listener it belongs to, the app-owned UDP socket interface beside it, and
  the `connect`, `disconnect` and path-MTU fixes, all carried in through
  the platform integration branch rather than a numbered pull request.
  Also the NixOS flake module and overlay, the UDP `sin6_scope_id`
  receive fix, and most of the Bluetooth LE rework: packet-boundary
  recovery, identity-based peer recognition, the bounded probe retry and
  the embedder-supplied Android radio backend, with the build gate that
  decides where the transport exists. Fifteen commits, and the two
  largest new operator capabilities in the release.
- Martti Malmi ([@mmalmi](https://github.com/mmalmi)): allocation-free
  routing next-hop selection
  ([#134](https://github.com/jmcorgan/fips/pull/134)) and batched macOS
  connected-UDP receives
  ([#135](https://github.com/jmcorgan/fips/pull/135)). Two commits.
- [@fr34aky](https://github.com/fr34aky): FreeBSD support, covering the
  daemon, the TUN datapath, `.fips` DNS integration and native pkg
  packaging ([#129](https://github.com/jmcorgan/fips/pull/129)), and the
  L2CAP PSM interface for Bluetooth LE with its BlueZ implementation. Two
  commits, and a new supported platform.
- [@erskingardner](https://github.com/erskingardner) (Jeff Gardner): the
  control-socket runtime directory fix
  ([#138](https://github.com/jmcorgan/fips/pull/138)). One commit, and a
  first contribution to FIPS.
- [@jmcorgan](https://github.com/jmcorgan) (Johnathan Corgan): release
  shepherd; the sans-IO protocol restructuring, the per-peer control
  machine, the peering reconciler, node lifecycle, health and drain, the
  tick profiler, the lookup and rendezvous naming split, and the
  integration and review of the contributed work above, plus the
  native datagram API and the `fipsctl probe` diagnostic.
  174 commits.
