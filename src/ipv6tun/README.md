# src/ipv6tun

The IPv6 adapter: everything that lets ordinary IPv6 applications on the host
use the mesh. It owns the TUN device and its reader and writer threads, the
`.fips` DNS responder, the ICMPv6 errors the host is owed, the TCP MSS clamp,
the IPv6 header compression on the mesh's IPv6 port (FSP port 256), and the
adapter's own status socket. The node reaches it through one seam, the link
(`link.rs`), and through the start and stop handles in `lifecycle.rs`.

The adapter takes packets from the host in one of two ways:

- **System TUN**: the node creates the device (`fips0` by default, from
  `tun.name`), and the reader thread reads each packet the host sends it.
  Those packets get the `fd00::/8` filter, the hairpin of a packet addressed
  to the node itself and the MSS clamp before the checks every packet gets.
- **App-owned TUN** (`Node::enable_app_owned_tun`): an embedder that owns the
  device, such as an Android `VpnService`, pushes packets in and reads packets
  out over two channels. Its packets get only the shared checks: no
  `fd00::/8` filter, no hairpin and no MSS clamp in either direction.

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
- `icmp.rs`: builds Destination Unreachable and Packet Too Big (RFC 4443) and
  returns them; Packet Too Big is rate limited per source at a time the caller
  gives. Re-exports the MTU names from `mtu.rs` so their public paths stay.
- `icmp_rate_limit.rs`: the per-source Packet Too Big limiter, judged at a
  given time (`check`). Its public `should_send` reads the clock for callers
  outside the adapter and is the one clock read the guard allows.
- `inbound.rs`: rebuilds a packet a peer delivered (`unpack`) and marks it
  Congestion Experienced when the datagram was (`mark_ce`).
- `ipv6_shim.rs`: IPv6 header compression and decompression for port 256.
- `mss.rs`: the node-wide MSS ceiling the TUN threads share, the
  per-destination ceiling, and the one clamp function both TUN writers and the
  reader call.
- `mtu.rs`: the MTU arithmetic: the IPv6 MTU and TCP MSS a path carries, from
  a transport MTU or from the payload limit the node publishes.
- `outbound.rs`: the host path's decisions. `from_tun` for a packet the system
  TUN reader read, `outbound` for the checks every packet gets, `answer` for a
  datagram the node refused. Each returns what to send (`FromTun`, `Host`,
  `Owed`) rather than sending it.
- `tcp_mss.rs`: finds and rewrites the MSS option in a TCP SYN.

Drivers:

- `tun.rs`: the TUN device on each platform, its reader and writer threads,
  and `answer_oversize`, the only place on the host path that reads the clock
  and locks the Packet Too Big limiter.
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

`tests/` holds the adapter's tests; `tests/README.md` describes each file.

## Relation to the rest of the tree

The node's side of the seam is in `src/node`: `handlers/host_link.rs` builds
the link, `dataplane/rx_loop.rs` drains the adapter's datagrams and learned
keys, `handlers/session.rs` hands the adapter refusals and deliveries, and
`lifecycle/` and `lifecycle/supervisor.rs` start and stop the children
through `lifecycle.rs`. `src/control/compose.rs` merges the status socket's
answer into the node's for `fipsctl` and `fipstop`, and
`config::ipv6tun_socket` derives that socket's path. The design is
`docs/design/fips-ipv6-adapter.md`.

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
  channels or the link's channel ends, threads, clock reads, OS calls,
  sockets or a driver module. `icmp_rate_limit.rs` may read the clock exactly
  once, in `should_send`. Every module declared in `mod.rs` must be listed as
  a decision module or a driver in `tests/mod.rs`, so a new module is never
  left unscanned. The scan checks names, not types, and does not cover I/O
  through `std::io` or a lookup through `ToSocketAddrs`.

**Host-visible behaviour:**

- The queue toward the host is bounded at `node.buffers.host_channel` packets
  and a send never waits: a full queue drops the packet, counts it in
  `TunTx::dropped()` and logs "Host not reading; dropping packets toward it"
  at the first drop and at each doubling. Only a reader that has gone is an
  error.
- A closed queue toward the host stops the system TUN reader only when it was
  hairpinning a packet or answering one addressed outside the mesh; a closed
  datagram channel to the node always stops it.
- The Packet Too Big limiter counts a source whether or not a TUN queue is up
  to take the answer.
- A SYN is clamped before the checks every packet gets, so a datagram carries
  the clamped segment and an ICMPv6 answer quotes it.
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
