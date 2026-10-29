# `src/ipv6tun/tests/`

Unit tests for files in `src/ipv6tun/` that keep their tests outside the source
file. Most files here are a child module of the source file they test,
declared from that file as
`#[cfg(test)] #[path = "tests/<file>.rs"] mod <name>;`, so they can reach the
source file's private items. Two are not:

- `mod.rs` is the module for the adapter's directory tests, those of the adapter
  as a whole rather than of one file, declared from `../mod.rs` as
  `#[cfg(test)] mod tests;`. It declares `scan.rs`. It checks that the adapter's
  decision modules (`config.rs`, `core.rs`, `exthdr.rs`, `icmp.rs`,
  `icmp_rate_limit.rs`, `inbound.rs`, `ipv6_frag.rs`, `ipv6_shim.rs`, `mss.rs`,
  `mtu.rs`, `outbound.rs`, `tcp_mss.rs`) read no clock and reach no async
  runtime, channel, thread, OS, I/O, socket or name lookup: a scan of each one's
  source, without its comments, literals and test-only items, finds no async
  code, runtime, channel or link channel end, thread, clock read (called or
  passed as a function), OS call, path through `std::io` or `std::fs`, socket,
  lookup through `ToSocketAddrs`, or path through one of the adapter's driver
  modules, renamed or not. The limiter's public `should_send` is the one clock
  read allowed. Every module `../mod.rs` declares must be listed as a decision
  module or a driver, and only one; lines planted in a copy of `outbound.rs`
  show the scan finds each kind of item, and ignores one in a comment, a literal
  or a test-only item while still finding one a feature build compiles. It is a
  check of names, not types: an item reached under a name not on its lists
  passes. The DNS responder's query decisions are not scanned, because they
  share `dns.rs` with its sockets, which makes it a driver.
- `scan.rs` is its helper module (`tests::scan`) for the tests that read the
  adapter's own source as text: where an identifier, a string or char literal
  (raw strings included), or a bracketed group ends. It tests no file.

The others:

- `dns.rs` tests `../dns.rs` as module `reply_tests`: where the DNS
  responder sends a reply to a mesh source address (`fd00::/8`) when no strict
  pin to the arrival interface is known to hold, and how it recognises a
  query from the mesh when the mesh interface's index is unknown (by the
  node's own mesh address, or on Windows by a remote mesh source). It covers
  the pure decisions (`reply_path`, `returns_by`, `mesh_query`), the
  destination address the receive path reports, and, in root
  network-namespace tests, the replies themselves, including with a mesh
  interface that carries no address (`ForgedSourceNetns::with_addressless_mesh`)
  and one known residual case pinned as a test. It also pins the receive
  loop's order (`run_responder`, on the IPv6 loopback with no mesh side): a
  resolved identity is handed to the node before the reply is sent, so no
  reply arrives while the identity sink holds it; and the hosts file is
  re-read only for a query that passes the screen, not for a datagram the
  screen drops or a query it refuses. The loop takes two synchronous steps
  for each datagram, tested without a socket: the first
  (`Answering::receive`) names a query from the mesh, which the loop drops,
  or returns what the screen made of the datagram with the path a reply
  takes, without reading the host map; the second (`answer`) answers a query
  that passed, with the host map, and returns the reply and any identity it
  resolved. It also covers which names the responder answers, judged by wire
  label (a single label holding a dot is not under `fips`), and how a hosts
  file that cannot be read keeps the names last read, is read again on the
  next query, and is logged once per run of failures.
- `core.rs` tests `../core.rs`: that the payload limits the node publishes
  give the same TCP MSS ceiling as the transport MTU they come from, for
  every MTU, and the same IPv6 MTU from 110 bytes up (below 110 no IPv6
  packet fits either way, and the limit reports 33); the state before any
  attach; how each message from the node changes the shared state; and the
  key map: known keys in, forgotten keys out, a key the DNS responder learned
  after the node decided to forget it kept, and an attach starting it empty;
  and the address companion of the key map following it through the same
  changes and a prefix that changes hands, with the address of a key the
  adapter does not hold hashed from the key.
- `mtu.rs` tests `../mtu.rs`: each function (`effective_ipv6_mtu`,
  `mss_ceiling`, `ipv6_mtu`, `tcp_mss`) against a literal copy of its earlier
  definition at every `u16` input, the FSP payload limit against the
  adapter's earlier seed expression at every input, and the known answers
  at the inputs the call sites pass, including the default UDP MTU.
- `mss.rs` tests `../mss.rs`: the per-destination TCP MSS ceiling
  (`per_flow_max_mss`) falls back to the IPv6-minimum ceiling, capped by the
  node-wide one, for an address with no stored path, one outside `fd00::/8`
  and a slice of the wrong length; it takes the smaller of the node-wide
  ceiling and the stored path's, for each destination on its own; it falls
  back again where a stored MTU leaves no room for a payload byte, while a
  locally seeded MTU below the actionable floor, and one at that floor, clamp
  by their own arithmetic; and its fallback trace logs under the target
  `fips::ipv6tun::mss`. The shared clamp the TUN writers and reader call
  (`clamp`) clamps a SYN by the stored path to its source for a packet toward
  the host and to its destination for one from it, leaves a packet too short
  to hold its source unclamped, and does not clamp a segment that is not a
  SYN; a SYN-ACK from the mesh behind a Hop-by-Hop header is clamped to the
  ceiling a plain one gets. The ceiling itself (`flow_ceiling`), which the
  node's re-clamp of a held SYN shares, is pinned by literal values: the
  conservative ceiling with no entry or an entry that leaves no payload
  byte, the path's MSS otherwise, each capped by the node-wide one.
- `exthdr.rs` tests `../exthdr.rs`: the extension header walk finds the
  upper-layer header behind each header it steps over (Hop-by-Hop, Routing,
  Destination Options, Authentication, a first Fragment) and behind a chain
  of them, at the offset where it starts, marked sealed behind an
  Authentication or Fragment header; it stops at ESP, No Next Header and an
  unknown header; a later fragment names its protocol and no header; and a
  chain that runs past the packet is reported as truncated, not read past.
- `icmp.rs` tests `../icmp.rs` as module `answer_tests`: the functions that
  build the answers the adapter owes the host and return them rather than
  send them. Destination Unreachable (`unreachable`) is built from our address
  for a packet owed an ICMPv6 error and not for one from a multicast source.
  An ICMPv6 error of each type, or a Redirect, behind each extension header
  chain draws neither Destination Unreachable nor Packet Too Big, while an
  Echo Request behind the same chains draws both; a later fragment of an
  ICMPv6 message draws neither and one of UDP both; and a packet whose
  extension headers run past its end draws neither. Packet Too Big is never
  built with a multicast or unspecified source: not by `too_big` for a packet
  to a multicast group, and not by the builder given such a source.
  Packet Too Big (`too_big`) is judged by the per-source limiter at the time
  given: an answer with no TUN queue up still counts against its source, so
  one to the same source within the interval is held back, and one at the end
  of the interval is built. The older tests of the builders stay in the
  file's inline `tests` module.
- `icmp_rate_limit.rs` tests `../icmp_rate_limit.rs` as module `clock_tests`:
  the Packet Too Big limiter judged at exact times through the check that
  takes the time (`check`), rather than by sleeping. A source is held back
  for the whole interval after a send and allowed again once it has passed,
  to the millisecond, with the default interval and a custom one; an attempt
  held back does not restart the interval; and an entry is dropped by the
  first allowed check at its maximum age and kept by one just short of it.
  The older tests of the wrapper that reads the clock (`should_send`) stay in
  the file's inline `tests` module.
- `outbound.rs` tests `../outbound.rs` as module `host_tests`, on the
  values the host half's decisions return rather than on what a channel
  received: the host half turns a packet to a key the adapter holds into a
  datagram carrying the compressed packet, answers a packet to a prefix no
  key names with Destination Unreachable and one over the published limit
  with Packet Too Big, both built from the packet itself; and every refusal
  the node hands back is answered byte for byte as the packet the host sent
  would have been when the host sent it from our address. A compressed
  payload keeps neither the source address, the destination's first byte
  nor the length field, so a packet from a foreign source is answered as if
  sent from ours, and one to a destination outside `fd00::/8` or with a
  wrong length field (which only an embedder that owns the TUN can send) is
  quoted as rebuilt. A packet the host sends from a source other than our
  address, outside the mesh or in it, is answered on both paths with
  Destination Unreachable code 5 and never becomes a datagram, whether its
  destination names a held key or not; one from the unspecified address or a
  multicast source gets nothing; and the refusal is logged at debug with the
  source. An oversized packet to a destination outside `fd00::/8` draws no
  Packet Too Big: one to a multicast group draws nothing, and one to a
  unicast address outside the mesh Destination Unreachable, as at any size.
  The system TUN reader's decision (`from_tun`) answers a
  destination outside `fd00::/8` itself, hairpins a packet to us with its
  checksum finished, and clamps a SYN to the stored path before the checks
  every packet from the host gets, which a packet an embedder sends gets
  alone, and a SYN behind a Hop-by-Hop header is clamped to the stored path
  as a plain one is, with its checksum still valid, and handed to the mesh
  clamped; a packet that is not IPv6 gets nothing on either path, even when
  its bytes read as our address or a held key's; and a refusal of several
  payloads is owed one answer each, in order. For a datagram the node holds:
  a compressed 1280-byte payload splits (`split`) into compressed fragments
  that each fit the payload limit and reassemble to the packet, and neither
  `split` nor `can_split` splits one whose limit carries 1280 or whose packet
  is over 1280; the held-SYN re-clamp (`reclamp`) clamps a SYN behind a
  Destination Options header with its checksum valid and leaves one behind a
  Fragment header byte for byte; and a refusal, or a packet to an unknown
  destination, over 1280 on a limit under 1280 is told 1280.
- `ipv6_frag.rs` tests `../ipv6_frag.rs` as module `tests`: which packets
  the ingress node splits into IPv6 fragments for a path under 1280 and
  which it leaves to a Packet Too Big (one that fits, one over 1280, a
  malformed one, an MTU too small for ten fragments, a Hop-by-Hop or
  Routing header, headers through the upper-layer one that would not fit
  in the first fragment, a later host-made fragment whose inner header is
  Hop-by-Hop, Routing or Fragment, a host-made fragment near the offset
  limit), that the fragments fit the MTU and reassemble to the original,
  how many fragments a 1280-byte packet becomes, that a host-made fragment
  is split under its own identification, offset and final M flag, and the
  MTU a Packet Too Big reports for a packet over 1280. Pure functions, no
  I/O.
- `tcp_mss.rs` tests `../tcp_mss.rs` as module `chain_tests`: a SYN behind
  Hop-by-Hop, Routing or Destination Options headers, alone or chained, is
  clamped to the same ceiling as a plain one (RFC 9293 Section 3.7.1) and
  keeps a valid checksum; one behind an Authentication, Fragment, ESP or
  unknown header is left exactly as it came; one whose MSS is within the
  ceiling is left alone; the checksum stays valid with the MSS value at an
  odd offset; and for a SYN with no extension header the clamp writes the
  same bytes as rewriting the option and recomputing the whole checksum, as
  it did before.
  The older tests stay in the file's inline `tests` module.
- `inbound.rs` tests `../inbound.rs`: the CE marking sets the ECN bits of an
  ECN-capable packet, leaves a Not-ECT packet unmarked, and leaves a packet
  too short to hold a Traffic Class unchanged; a delivered packet is rebuilt
  from the sender to us and marked CE only when its datagram arrived marked;
  and a payload that is not a compressed packet is not delivered.
- `link.rs` tests `../link.rs`: a peer key names the address its node
  address has and holds its key and nothing else, the link's peer key is the
  identity module's `PeerKey` (fips-core, `identity/key.rs`) rather than a
  type of its own, and every message field is of a type allowed to cross the
  link. The last is a scan of the source of
  `../link.rs` itself that skips comments, attributes, and string and char
  literals (raw strings included), then reads every struct and enum whatever
  its visibility, with named, tuple and unit fields; forged definitions of
  each shape, of one placed after a literal holding a lone quote, and of one
  placed after an attribute whose literal holds an unbalanced bracket, show
  the scan refuses a node address, and the scan is shown to read the
  messages it checks, with their fields, the delivery to the host among
  them. The scanner's handling of literals and brackets is in `scan.rs`.
- `queue.rs` tests `../queue.rs`: a full queue toward the host drops and
  counts what it cannot hold without waiting, a queue with room again takes
  packets and its clones share one count, a queue whose reader has gone is
  an error that counts nothing, and a full queue warns at the first drop and
  at each doubling, with the count, under the target
  `fips::ipv6tun::queue`. A sender formats for debugging with its drop
  count.
- `tun.rs` tests `../tun.rs` as module `name_tests`: TUN startup never
  deletes, downs or takes over an existing interface named `tun.name`. A
  link of any kind but TUN is refused and left untouched, a TUN another
  process holds is an error, and an unheld persistent TUN is reopened,
  including one an earlier node left configured by exiting without stopping.
  It also covers the `fd00::/8` policy rule (priority 5265) startup adds:
  both teardown paths (`shutdown_tun_interface` and `TunDevice::shutdown`)
  remove it, startup replaces an older version's rule rather than adding
  beside it, and a rule left by an exit without stop does not send another
  routing table's ULA traffic out the default route. It covers the pure kind
  decision (`existing_link_verdict`) and, in root network-namespace tests,
  `TunDevice::create` and teardown themselves. Create reports
  `Ipv6Disabled` when the kernel would refuse IPv6 on the device: the pure
  checks (`stack_off`, `disabled_on`) are tested without root against a copy
  of the sysctl tree in a temporary directory (a kernel with no `net/ipv6`,
  and a device whose own `disable_ipv6` is set, whether by `conf/default` or
  on its own, while `all` and `default` alone decide nothing), and namespace
  tests show create refusing a new TUN under `conf/default` and a persistent
  one with its own knob set (keeping that link, same index and kind, with
  its MTU already set to the configured one), and succeeding with `all` set
  and `default` cleared and on a persistent TUN whose own knob is clear
  under `all` and `default`. The tests of the reader's packet handler need
  no root: the reader clamps a SYN by the stored path to
  its destination before handing it to the mesh; a closed queue toward the
  host ends the reader when it was to hairpin a packet or answer one addressed
  outside the mesh, and not when it was to answer a mesh destination with
  Destination Unreachable or Packet Too Big; and a closed datagram channel to
  the node ends it. A hundred packets read in a row, to a destination outside
  the mesh or to one no key names, draw the Destination Unreachable burst and
  no more than the bucket refills meanwhile; and the bucket, judged at given
  times, lets ten go at once, one more a tenth of a second later, and no more
  than ten after a long quiet spell.
- `status.rs` tests `../status.rs`: the listening-sockets panel's reply. A
  loaded `inet fips` table that polices another interface than the TUN is
  reported as no firewall, every listener unfiltered, and one that polices
  the TUN classifies each listener by its rules. It also covers the
  adapter's status: after each TUN and DNS start, stop and exit the
  published status equals what the node's facades read from the handles,
  the drop count is read from the current queue when asked, the status
  socket answers `show_status` with its four keys and an unknown command as
  unknown, the panel reads the configured TUN name while no TUN is up
  (including one other than `fips0`) and the name of the TUN that is up
  over the configured one, a named TUN is rendered by its name, and on
  Windows the listener binds on loopback. The status socket's own use of
  that name, and the startup warning about a table scoped to another
  interface, are covered end to end by case (f) of `testing/firewall`.
- `lifecycle.rs` tests `../lifecycle.rs`: each child exit is reported once,
  after a panic or a return, and not after an abort; the DNS responder's task
  reports on the exit channel the start opened, the one `exits` returned;
  the panic line logs under the target
  `fips::ipv6tun::lifecycle` with the child it names; and what each exit
  takes back when the node hands it over: a TUN thread's nothing, the DNS
  responder's its published address, with its task left for the teardown;
  and the TUN device takes the address the node's attach gave, not the seed
  the handles were built with. It also covers how the handles answer the host
  on the app-owned path and for a refusal: the Packet Too Big limiter counts a
  refusal's source while no TUN queue is up, so a second refusal from it once
  a queue is up is held back, and two oversize packets from one source in a
  row are answered with one Packet Too Big; a hundred undeliverable packets
  on the app-owned path, a hundred from a foreign source, and a refusal of a
  hundred held packets each draw the Destination Unreachable burst and no
  more than the bucket refills meanwhile; and the host path the handles
  build for the TUN reader draws on their bucket, so tokens it spends are
  gone for the handles' answers.
- `firewall_state.rs` tests `../firewall_state.rs` (Linux only) as module
  `target_tests`: the warning about a firewall that polices another
  interface than the TUN keeps the `fips::control::firewall_state` target it
  had before the module moved here, and a table that polices the TUN draws
  no warning.

- `bsdnet.rs` tests `../bsdnet.rs` (macOS and FreeBSD only) as module `tests`:
  the routing message layout and socket-address padding, the kernel's error
  codes surfacing for calls it refuses (an unknown sysctl name or interface,
  a route add the kernel rejects), and, as root, a route added twice through
  one interface being accepted, one present through another interface being
  refused with the other interface named, a TUN device created twice in turn
  coming up with its address, MTU and `fd00::/8` route both times and going
  down at shutdown with its other flags kept, and a configured device set up
  a second time accepting its own address and route.
- `winnet.rs` tests `../winnet.rs` (Windows only) as module `tests`: IP
  Helper's Win32 codes surfacing for an interface that does not exist, a
  stop with no `FIPS` adapter present succeeding, and, as Administrator, a
  route and an address added twice on the loopback interface being
  accepted, the loopback's IPv6 MTU being changed through its interface
  row, and a Wintun adapter created twice in turn coming up with its
  address, MTU and `fd00::/8` route (this one needs `wintun.dll` on the DLL
  search path).

## Rules

- Older tests in `src/ipv6tun/` stay in their source files' inline `mod tests`
  blocks; new tests go here. A file that already has an inline `tests` module
  declares its file here under a different module name.
- The network-namespace tests, and the macOS and FreeBSD tests that change
  routes or create a device, need root. They are `#[ignore]`d, so the normal
  test run skips them; build with `cargo test --lib --no-run` and run the test
  binary under `sudo` with `--ignored`. `testing/root-tests.sh` runs the
  Linux `tun.rs` and `dns` namespace tests that way, called under `sudo` by
  the Linux unit-test job and by local CI with `--root-tests`; the FreeBSD
  package workflow and the macOS unit-test job run the `bsdnet` tests, with
  `--include-ignored`, and the Windows unit-test job, whose runner is
  elevated, the `winnet` ones. Local CI runs no others. They share the
  namespace harness (`ForgedSourceNetns`) with the inline tests in
  `../dns.rs`, which exposes it as `pub(super)`. The generic parts, running a
  setup command (`testutil::run_ok`) and running code inside a named namespace
  (`testutil::in_netns`), are crate-wide in `src/testutil.rs` for any
  namespace test.
- `TunDevice::create` makes its device, and reads links, in the calling
  thread's network namespace, so the TUN tests run it inside
  `testutil::in_netns` on a current-thread runtime built in that closure.
- Anything the responder reads at reply time (its route probe, the interface
  prefixes) is read in the calling thread's network namespace. A namespace
  test therefore runs the responder on a thread inside the node namespace
  (`spawn_responder`), not on the test's own runtime, and checks that the
  probe sees that namespace.
