# `src/ipv6tun/tests/`

Unit tests for files in `src/ipv6tun/` that keep their tests outside the source
file. Each file here is a child module of the source file it tests, declared
from that file as `#[cfg(test)] #[path = "tests/<file>.rs"] mod <name>;`, so it
can reach the source file's private items.

- `dns.rs` tests `../dns.rs` as module `reply_tests`: where the DNS
  responder sends a reply to a mesh source address (`fd00::/8`) when no strict
  pin to the arrival interface is known to hold, and how it recognises a
  query from the mesh when the mesh interface's index is unknown (by the
  node's own mesh address, or on Windows by a remote mesh source). It covers
  the pure decisions (`reply_path`, `returns_by`, `mesh_query`), the
  destination address the receive path reports, and, in root
  network-namespace tests, the replies themselves, including with a mesh
  interface that carries no address (`ForgedSourceNetns::with_addressless_mesh`)
  and one known residual case pinned as a test.
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
- `outbound.rs` tests `../outbound.rs` as module `host_tests`: the host half
  turns a packet to a key the adapter holds into a datagram carrying the
  compressed packet, answers a packet to a prefix no key names with
  Destination Unreachable and one over the published limit with Packet Too
  Big, both built from the packet itself; and every refusal the node hands
  back is answered byte for byte as the packet the host sent would have been
  when the host sent it from our address. A compressed payload keeps neither
  the source address, the destination's first byte nor the length field, so
  a packet from a foreign source is answered as if sent from ours, and one
  to a destination outside `fd00::/8` or with a wrong length field (which
  only an embedder that owns the TUN can send) is quoted as rebuilt.
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
  them.
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
  `TunDevice::create` and teardown themselves.
- `status.rs` tests `../status.rs`: the listening-sockets panel's reply. A
  loaded `inet fips` table that polices another interface than the TUN is
  reported as no firewall, every listener unfiltered, and one that polices
  the TUN classifies each listener by its rules. It also covers the
  adapter's status: after each TUN and DNS start, stop and exit the
  published status equals what the node's facades read from the handles,
  the drop count is read from the current queue when asked, the status
  socket answers `show_status` with its four keys and an unknown command as
  unknown, the panel reads the configured TUN name while no TUN is up, a
  named TUN is rendered by its name, and on Windows the listener binds on
  loopback.
- `lifecycle.rs` tests `../lifecycle.rs`: each child exit is reported once,
  after a panic or a return, and not after an abort; the DNS responder's task
  reports on the exit channel the start opened, the one `exits` returned;
  the panic line logs under the target
  `fips::ipv6tun::lifecycle` with the child it names; and what each exit
  takes back when the node hands it over: a TUN thread's nothing, the DNS
  responder's its published address, with its task left for the teardown;
  and the TUN device takes the address the node's attach gave, not the seed
  the handles were built with.
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
  binary under `sudo` with `--ignored`. The FreeBSD package workflow and the
  macOS unit-test job run the `bsdnet` tests that way, with
  `--include-ignored`, and the Windows unit-test job, whose runner is
  elevated, the `winnet` ones. They share the namespace harness
  (`ForgedSourceNetns`) with the inline tests in `../dns.rs`, which exposes it
  as `pub(super)`. The generic parts, running a setup command
  (`testutil::run_ok`) and running code inside a named namespace
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
