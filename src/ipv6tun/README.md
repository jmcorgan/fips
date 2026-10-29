# src/ipv6tun

The IPv6 adapter: everything that lets ordinary IPv6 applications on the host
use the mesh. It owns the TUN device and its reader and writer threads, the
`.fips` DNS responder, the ICMPv6 errors the host is owed, the TCP MSS clamp,
the IPv6 header compression on the mesh's IPv6 port (FSP port 256), and the
adapter's own status socket. At run time the node reaches it in two places:
the link (`link.rs`) and the handles in `lifecycle.rs`. Other code in the
tree also uses its types, constants and functions that hold no adapter
state: the MTU arithmetic, the fragmentation and held-SYN clamp the node
applies at the send, the configuration sections, the status and listening
reports, and the DNS responder's socket helpers. Relation to the
rest of the tree lists every caller from outside the module, and what the
module uses in turn.

The adapter takes packets from the host in one of two ways:

- **System TUN**: the node creates the device (`fips0` by default, from
  `tun.name`), and the reader thread reads each packet the host sends it.
  Those packets get the `fd00::/8` filter, the hairpin of a packet addressed
  to the node itself and the MSS clamp before the checks every packet gets.
- **App-owned TUN** (`Node::enable_app_owned_tun`): an embedder that owns the
  device, such as an Android `VpnService`, pushes packets in and reads packets
  out over two channels. Its packets get only the shared checks: no
  `fd00::/8` filter, no hairpin and no MSS clamp in either direction, except
  that a SYN-flagged segment the node held while its session was set up is
  clamped when the node releases it, as on a system TUN.

Both share everything after that point: the decision functions, the link, the
queue toward the host and the DNS responder.

## How it is built

The adapter separates deciding from doing. A **decision module** takes what it
decides on, the time included, and returns what to do; it reads no clock and
touches no channel, thread, socket or OS call. A **driver** carries the
decisions out: the TUN threads, the handles the node drives, the DNS task and
the platform setup code. `tests/mod.rs` enforces the split (see Invariants).

Decision modules:

- `config.rs`: `TunConfig` and `DnsConfig` (the `tun` and `dns` sections) and
  how a later configuration file's section merges into an earlier one.
- `core.rs`: the adapter's own copy of what the node tells it over the link:
  payload limits turned into IPv6 terms, the keys the node can route to by
  address prefix, and the keys the DNS responder handed out.
- `exthdr.rs`: walks a packet's IPv6 extension headers to its upper-layer
  header, for the ICMPv6 error checks and the MSS clamp.
- `icmp.rs`: builds Destination Unreachable and Packet Too Big (RFC 4443) and
  returns them; Packet Too Big is rate limited per source at a time the caller
  gives, and Destination Unreachable by a token bucket whose burst and rate
  are named here. Re-exports the MTU names from `mtu.rs` so their public paths
  stay.
- `icmp_rate_limit.rs`: the per-source Packet Too Big limiter, judged at a
  given time (`check`). Its public `should_send` reads the clock for callers
  outside the adapter and is the one clock read the guard allows.
- `inbound.rs`: rebuilds a packet a peer delivered (`unpack`) and marks it
  Congestion Experienced when the datagram was (`mark_ce`).
- `ipv6_frag.rs`: IPv6 fragmentation of a host's packet of at most 1280
  bytes for a path under 1280 (`can_fragment`, `fragment_for_path`), and the
  MTU a Packet Too Big reports (`packet_too_big_mtu`: 1280 for a packet over
  1280 on such a path). It walks the extension headers itself rather than
  through `exthdr.rs`, because it asks a different question (which headers
  may go into fragments, and how long they are through the upper layer).
- `ipv6_shim.rs`: IPv6 header compression and decompression for port 256.
- `mss.rs`: the node-wide MSS ceiling the TUN threads share, the
  per-destination ceiling (`flow_ceiling`, which the node's re-clamp of a held
  SYN shares), and the one clamp function both TUN writers and the reader
  call.
- `mtu.rs`: the MTU arithmetic: the IPv6 MTU and TCP MSS a path carries, from
  a transport MTU or from the payload limit the node publishes.
- `outbound.rs`: the host path's decisions. `from_tun` for a packet the system
  TUN reader read, `outbound` for the checks every packet gets, `answer` for a
  datagram the node refused. Each returns what to send (`FromTun`, `Host`,
  `Owed`) rather than sending it. Three more work on a datagram the node
  holds: `can_split` and `split` rebuild its packet, fragment it with
  `ipv6_frag.rs` and compress each fragment, and `reclamp` clamps a held SYN
  again by the path the node knows at release.
- `tcp_mss.rs`: finds and rewrites the MSS option in a TCP SYN, behind any
  Hop-by-Hop, Routing and Destination Options headers, updating the checksum
  for the bytes it rewrites.

Drivers:

- `tun.rs`: the TUN device on each platform, its reader and writer threads,
  and `answer_oversize` and `answer_unreachable`, the only places on the host
  path that read the clock and lock the ICMPv6 limiters: the Packet Too Big
  limiter and the Destination Unreachable token bucket.
- `lifecycle.rs`: start and stop of the TUN and DNS children, the `Handles`
  the node drives (`outbound`, `answer`, `deliver`), the task that applies the
  node's link messages (`run_link`), and the delivery outcome (`Delivery`).
- `link.rs`: the link's messages and channel ends: `MeshLink` (the adapter's
  end), `HostLink` (the node's), `FromMesh`, `Datagram`, `Refusal`, `Deliver`
  and `PeerKey`.
- `queue.rs`: `TunTx`, the bounded queue of packets toward the host.
- `dns.rs`: the `.fips` responder: its socket and receive loop, and, in the
  same file, its per-query decisions (`Answering::receive`, `answer` and the
  screens they use). Because the decisions share the file with the socket, the
  guard counts `dns.rs` as a driver and does not scan it.
- `status.rs`: what the adapter reports about itself, and the status socket
  it answers on beside the node's control socket.
- `listening.rs`, `firewall_state.rs`: the facts behind `fipstop`'s listening
  panel: sockets reachable on the TUN, and how the loaded `inet fips` firewall
  treats each. Linux only.
- `bsdnet.rs` (macOS, FreeBSD) and `winnet.rs` (Windows): interface and route
  setup by direct kernel or IP Helper calls, deciding what is benign by error
  code.

`tests/` holds the adapter's tests; `src/ipv6tun/tests/README.md` describes
each file.

## Relation to the rest of the tree

The design is `docs/design/fips-ipv6-adapter.md`.

The node's side of the run-time seam is in `src/node`:

- **The link** (`link.rs`). `handlers/host_link.rs` answers the adapter's
  `Attach`, sends it `FromMesh` messages such as `Attached`, and handles
  each `Datagram` it sends. `lifecycle/supervisor.rs` holds the node's end
  (`HostLink`) and the receivers (`DatagramRx`, `LearnedRx`) until
  `dataplane/rx_loop.rs` takes them to drain the adapter's datagrams and
  learned keys (`Learned`). `handlers/session.rs` hands the adapter refusals
  and deliveries (`Refusal`, `Deliver`), and `identities.rs` and
  `path_mtu.rs` push the keys the node knows and its path MTUs
  (`FromMesh::KnownKey`, `FromMesh::PathMtu`). The node names the remote end
  of each of these, of a held packet and of a path-MTU seed by `PeerKey`, so
  `handlers/handshake.rs`, `handlers/lookup.rs`, `handlers/timeout.rs` and
  `mod.rs` use it too.
- **The handles** (`lifecycle.rs`). `Node::new` and `Node::with_identity` in
  `mod.rs` build `Handles` from `adapter_settings`, which turns the node's
  configuration into `config::Settings` and the peer aliases into
  `config::Alias`; `lifecycle/supervisor.rs` holds them. `lifecycle/` starts
  and stops the TUN and DNS children through them, the receive loop and the
  handlers drive them for each packet (`outbound`, `answer`, `deliver`),
  `dataplane/rx_loop.rs` and `lifecycle/supervisor.rs` take a child's exit
  (`Exit`, `ExitRx`), and `handlers/session.rs` reads what became of a
  delivery (`Delivery`). The
  `Node` methods `tun_state`, `tun_name`, `tun_tx`, `enable_app_owned_tun`
  and `dns_local_addr` read or install through them, with the TUN types
  `tun.rs` exports (`TunState`, `TunTx`, `TunOutboundTx`, and `TunError`
  behind `NodeError::Tun`).

Everything else from outside the module uses a type, a constant or a
function that holds no adapter state, so it adds no run-time crossing:

- **MTU arithmetic** (`mtu.rs`, and `IPV6_MIN_MTU` from `mss.rs` through
  `tun.rs`). The node calls the adapter's functions so that each figure has
  one definition. `src/node/mod.rs` derives the node's effective IPv6 MTU
  (`effective_ipv6_mtu`), the MSS ceiling it publishes (`mss_ceiling`) and
  how far the bound transports fall short of the IPv6 minimum, which it
  warns about; `handlers/host_link.rs` starts its MTU feed at the IPv6
  minimum. `handlers/lookup.rs` calls `mss_ceiling` on a link MTU to warn
  when a link leaves no room for a TCP payload byte; the warning stays in
  the node because it fires on every link seed and logs the raw link MTU,
  where the adapter is sent only a payload limit. `src/config/transport.rs`
  sets the default UDP MTU to `IPV6_MIN_MTU + FIPS_IPV6_OVERHEAD`.
- **Fragmentation and the held-SYN clamp** (`outbound.rs`). The node judges
  each datagram by its own limits and holds it while a session is set up, so
  it applies these where it decides, passing the datagram's key and its own
  address: `handlers/host_link.rs` calls `outbound::can_split` at its two
  refusal sites (the node-wide limit and an established session's path MTU),
  and `handlers/session.rs` calls `outbound::split` in `send_tun_packet`,
  which sends a datagram whole or as fragments, and `outbound::reclamp` when
  it flushes the datagrams held for a new session. All three hold no adapter
  state; the re-clamp reads the node's own path MTU map, not the adapter's
  copy, which can trail it.
- **Configuration** (`config.rs`, `link.rs`). `src/config/mod.rs` embeds
  `TunConfig` and `DnsConfig` as the `tun` and `dns` sections, and
  `src/lib.rs` re-exports both at the crate root. `src/config/node.rs`
  grants the adapter its port (`IPV6_PORT`) by default, and
  `src/config/mod.rs` refuses any other grant of that port while the TUN is
  enabled.
- **Status and the listening panel** (`status.rs`, `listening.rs`,
  `firewall_state.rs`). `src/control/queries.rs` keeps
  `show_listening_sockets` for library callers by calling
  `status::listening`, and `src/control/mod.rs` re-exports `listening` and
  `firewall_state` so `fips::control::listening` and
  `fips::control::firewall_state` keep working. `src/control/compose.rs`
  merges the status socket's answer into the node's for `fipsctl` and
  `fipstop`; it names the adapter's keys itself and imports nothing from
  the module.
- **DNS socket helpers** (`dns.rs`). The gateway's resolver in
  `src/gateway/dns.rs` (Linux only) uses six of the responder's functions,
  so that it refuses a query arriving on the mesh interface and keeps a
  reply to a mesh source out of the mesh as the responder does:
  `set_recv_pktinfo_v6` and `recv_with_pktinfo` learn the interface a query
  arrived on, `is_mesh_interface_query` judges it, and `wildcard_bind`,
  `reply_path` and `send_reply` send the reply on the right path.

Tests outside the module reach further, for example into `icmp.rs`,
`ipv6_shim.rs`, `mss.rs`, `core.rs`, `inbound.rs`, `status.rs` and the
responder's `handle_dns_packet`, from `src/node/tests`, `src/gateway/tests`,
`src/control/tests` and the `#[cfg(test)]` helpers in `src/node`. Those uses
are not part of the seam.

The other way, outside its tests the module uses from the rest of the crate
and from `fips-core`:

- **Identity types**: `Ipv6Address`, `NodeAddr`, `PeerIdentity`,
  `IdentityError` and `identity::IPV6_ADDRESS_PREFIX` from the crate, and
  `PeerKey` and `NodePrefix` from `fips_core::identity`, for the addresses
  it derives and the keys the link names.
- **Framing sizes**: `proto::framing::{FIPS_OVERHEAD, payload_limit}` and
  `proto::fsp::wire::FSP_PORT_HEADER_SIZE`, from which `mtu.rs` and
  `core.rs` derive every MTU and MSS figure.
- **Time and rate limiting**: `time::HostClock`, `fips_core::time::Clock`
  and `fips_core::node::rate_limit::TokenBucket`, in `tun.rs` and
  `lifecycle.rs`: the clock the two ICMPv6 limiters are judged at, and the
  Destination Unreachable token bucket itself.
- **DNS**: `dnsmsg` (message parsing and screening, and `clamp_ttl` in
  `config.rs`), `hosts` (`HostMap`, `HostMapReloader`,
  `DEFAULT_HOSTS_PATH`) and `utils::onlink::OnLinkPrefixes`, in `dns.rs`
  and `lifecycle.rs`.
- **The status socket**: `config::ipv6tun_socket` for its path,
  `control::protocol::{Request, Response}` and `control::serve` for the
  control socket's framing, and `utils::sockbind` to bind and remove it, in
  `status.rs`.

## Invariants

These must not change without a deliberate decision, and most are pinned by
tests or compile-time checks.

**On the wire** (no wire change is allowed on `master` or `maint`):

- The adapter's datagrams use FSP port 256 (`link.rs`, `IPV6_PORT`).
- The compressed header format is format `0x00` as `ipv6_shim.rs` describes
  it: the original bytes 0 to 3, next header and hop limit kept; addresses and
  payload length dropped and rebuilt from the session.
- `FIPS_OVERHEAD` is 106 and `FIPS_IPV6_OVERHEAD` is 77, each asserted at
  compile time. Every MTU, MSS and Packet Too Big figure follows from them.

**The seam:**

- Link messages carry only owned values: integers, flags, byte strings and
  `PeerKey`s, never node state behind a reference or a lock. A remote end is
  named by its x-only key, never by a node address or an `fd00::/8` prefix;
  the adapter derives addresses itself. `tests/link.rs` checks the message
  fields against an allow-list.
- The order the host sees is the order the node made: link messages down one
  channel in sending order, and refusals and deliveries handed over in line
  where the node decides them. Datagrams and learned keys go up on separate
  bounded channels, so a burst of datagrams never holds a key registration
  back.

**Decisions and drivers:**

- No decision module names a runtime item: async code or the async runtime,
  channels or the link's channel ends, threads, clock reads, OS calls, I/O
  through `std::io` or `std::fs`, sockets, a lookup through `ToSocketAddrs`,
  or a driver module. `icmp_rate_limit.rs` may read the clock exactly
  once, in `should_send`. Every module declared in `mod.rs` must be listed as
  a decision module or a driver in `tests/mod.rs`, so a new module is never
  left unscanned. The scan checks names, not types, so an item reached under
  a name not on its lists passes.

**Host-visible behaviour:**

- The queue toward the host is bounded at `node.buffers.host_channel` packets
  and a send never waits: a full queue drops the packet, counts it in
  `TunTx::dropped()` and logs "Host not reading; dropping packets toward it"
  at the first drop and at each doubling. Only a reader that has gone is an
  error.
- A closed queue toward the host stops the system TUN reader only when it was
  hairpinning a packet or answering one addressed outside the mesh; a closed
  datagram channel to the node always stops it.
- A packet from the host whose source is not the node's own address never
  reaches the mesh, on either path: the receiver would rebuild it with that
  address as its source. The shared step answers it with Destination
  Unreachable code 5, or with nothing when its source is unspecified or
  multicast. The system TUN reader answers a destination outside `fd00::/8`,
  hairpins a packet to the node and clamps a SYN before that step, so a
  foreign-source packet to an off-mesh destination is answered code 0.
- The Packet Too Big limiter counts a source whether or not a TUN queue is up
  to take the answer.
- Every Destination Unreachable the host is sent draws on one token bucket for
  the adapter, shared by the reader and the handles: a burst of 10, then 10 a
  second (RFC 4443 Section 2.4 (f)). A token is spent whether or not a TUN
  queue is up.
- A SYN is clamped before the checks every packet gets, so a datagram carries
  the clamped segment and an ICMPv6 answer quotes it.
- A SYN-flagged segment held while its session is set up is clamped again
  when the node releases it, by the path MTU known then, on either path. The
  clamp only lowers.
- A packet of at most 1280 bytes over the IPv6 MTU of a path under 1280 is
  sent as IPv6 fragments rather than answered with a Packet Too Big, which
  the host would ignore; a packet over 1280 on such a path is answered with
  a Packet Too Big reporting 1280.
- The DNS responder hands a resolved identity to the node before it sends the
  reply, so the host's first packet to that name finds the key, and re-reads
  the hosts file only for a query that passes its screen. `tests/dns.rs` pins
  both orders.

**What operators and other programs read:**

- Log lines keep their text, level and target (`fips::ipv6tun::*`, with the
  MSS clamp's per-destination trace lines under `fips::ipv6tun::mss`), since
  operators filter on targets and tests match the text
  (`testing/check-log-strings.py` checks that every matched string still
  exists).
- The `tun` and `dns` configuration keys and their meaning, the status
  socket's path (derived from the control socket's) and the keys it answers,
  and the public paths under `fips::ipv6tun` (including the re-exports in
  `icmp.rs` and `tun.rs`) are interfaces; a change to any of them is a
  breaking change and goes in the changelog as one.

**Tests**: new tests go in `tests/`, never in an inline `mod tests { ... }`
block. A file module's tests are declared from the file as
`#[cfg(test)] #[path = "tests/<file>.rs"] mod <name>;`, so they keep access to
its private items. Several files still carry older inline test modules; those
move only as a change of their own, not in passing.
