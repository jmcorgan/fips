# Build a Mesh from the Ground Up

The earlier tutorials in this progression rode existing IP — your
daemon reached `test-us01` over the public internet through your
ISP, your ISP's upstream, and however many hops separate you from
the test node. That is the *overlay* deployment mode of FIPS:
useful, but not the new ground.

This tutorial is about the other mode. Two devices, a wire (or a
radio link) between them, no IP between them, and FIPS daemons on
each end. The two daemons discover each other over the raw link,
peer over Noise, and bring up an end-to-end mesh with addressing,
naming, and reachability — all from layer 2 up. There is no DHCP,
no router, no upstream. The mesh is the network.

This is the deployment mode FIPS was designed for. Overlay mode
exists because riding existing IP is a useful convenience; the
ground-up mode is what FIPS uniquely enables.

> **The two modes are not exclusive.** A node can carry overlay
> peers and ground-up peers at the same time — different transports
> on the same daemon. If you have already worked through
> [join-the-test-mesh](join-the-test-mesh.md), the static peer to
> `test-us01` you configured there can stay in place; the Ethernet
> peer you add in this tutorial sits alongside it. Traffic flows
> through whichever path is shortest by mesh metric, and a node on
> one side can reach a node on the other through your machine
> acting as a bridge between the two.

## What you'll build

```text
   ┌──────────────────────┐    raw Ethernet frames   ┌──────────────────────┐
   │   node A             │  ─────────────────────── │   node B             │
   │   npub1aaa…          │   EtherType 0x2121       │   npub1bbb…          │
   │   fips0  fd97:..:A   │   no IP between them     │   fips0  fd97:..:B   │
   └──────────────────────┘                          └──────────────────────┘
            │                                                 │
            │       a single Ethernet cable                   │
            │       (or both NICs on the same                 │
            │       unmanaged switch — no DHCP,               │
            │       no router, no IP at all)                  │
            └─────────────────────────────────────────────────┘
```

Two machines, each running `fips`, joined by a physical Ethernet
link. After the worked example:

- The two daemons have discovered each other via L2 beacons on
  the link, peered over Noise XX, and brought up an FMP link.
- Each `fips0` adapter has a routable mesh address; each can
  ping the other by `<npub>.fips`.
- Nothing between the two machines speaks IP. The link carries
  raw FIPS frames at EtherType `0x2121`.

The whole exercise should take about twenty minutes if you have
the hardware ready.

## Why ground-up

Most networking tutorials assume IP is already there: an address
arrived from DHCP, a default gateway routes you onward, DNS
resolves names. FIPS does not need any of that. Two devices and
a way to deliver bytes between them at layer 2 is enough — FIPS
supplies the rest:

- **Identity**: each daemon has an npub (the same kind you saw
  in the overlay tutorials). Nothing in the ground-up case
  depends on a network identity from a router; the npub is the
  identity.
- **Addressing**: the `fips0` adapter takes an `fd97:...` ULA
  derived from the npub. No DHCP. No SLAAC. The address is
  cryptographically tied to the identity.
- **Neighbor detection**: each daemon broadcasts a small beacon on the
  link advertising its npub; the other daemon's listener picks
  it up and dials in over the same link.
- **Routing**: the FIPS mesh layer builds its own spanning tree
  across whatever links it has. Add a third node (peered to
  either A or B) and traffic reaches it transparently.

The point is not that ground-up replaces overlay. It's that
overlay is one of two modes the same daemon supports, and
ground-up is what unlocks the use cases overlay cannot —
ad-hoc local meshes, partitioned networks, situations where
no IP infrastructure exists or can be relied on.

## Prerequisites

Two devices (call them **node A** and **node B**) and a way to
join them at layer 2:

- Ethernet (the worked example): a direct cable between two
  modern NICs (auto-MDI/MDIX handles crossover for you), or
  both machines on a small unmanaged switch with no DHCP
  server. USB-Ethernet dongles work; a typical "USB-to-RJ45"
  adapter is fine on either end. The link does **not** need
  to be the machine's primary network interface — a second
  NIC dedicated to the mesh is the cleanest setup.
- WiFi (a one-line variation, covered later): both machines
  associated to a common AP that has client (station)
  isolation **off**.
- Bluetooth LE (a separate worked example via a how-to,
  covered later): two BLE-capable Linux hosts within roughly
  10 metres line of sight.

On both nodes:

- `fips` installed and running, per [getting-started](../getting-started.md).
- A persistent identity from
  [persistent-identity](persistent-identity.md). Ephemeral
  identities work, but on each restart the npub regenerates
  and you'll have to re-check `fipsctl show peers` to see the
  new identity. Persistent makes the lesson stick.
- The daemon running with `CAP_NET_RAW` (the shipped systemd
  unit runs as root and gets this for free; running
  interactively from a user account requires `setcap` —
  noted at the relevant step below).

You do **not** need:

- An IP address on the chosen interface. The Ethernet
  transport opens a raw socket directly; the kernel does not
  need to assign an IP to the NIC.
- A default route. The mesh routes itself.
- DNS resolution between the machines via any external
  service. The local `.fips` resolver supplies names from
  the npubs the daemons exchange.

## Step 1: Identify the link interface on each node

On each node, list the network interfaces and pick the one that
sits on the link between the two machines. If it's a dedicated
NIC for the mesh, that NIC has no other purpose; if it's a
USB-Ethernet dongle, plug it in first so the kernel names it.

```sh
ip link show
```

Pick out the interface name. Common forms:

- `enp3s0`, `eno1` — built-in NICs under predictable naming.
- `eth0` — older or container-style naming.
- `enxAABBCCDDEEFF` — USB-Ethernet dongles often appear under
  this MAC-derived form.

Bring the interface up if it isn't:

```sh
sudo ip link set dev <interface> up
```

Confirm:

```sh
ip -br link show <interface>
```

You want `UP` and `LOWER_UP` in the flags. The interface does
not need an IP address — `LOWER_UP` indicates the NIC sees
carrier (cable plugged into something at the other end), and
that is all the Ethernet transport needs.

For the rest of the tutorial we'll write the chosen interface
as `<eth>`. Substitute the actual name on each node when you
run the commands. Note that node A and node B may have
different interface names — that is normal.

> **No IP needed.** If your chosen interface has an address
> from a previous DHCP lease, leave it alone or remove it with
> `sudo ip addr flush dev <eth>` — the FIPS Ethernet transport
> uses raw `AF_PACKET` sockets that bypass the IP stack
> entirely. The interface needs to be `up` and `LOWER_UP`,
> nothing more.

## Step 2: Configure the Ethernet transport on each node

Edit `/etc/fips/fips.yaml` on **both** nodes. Under
`transports:`, add an `ethernet:` block. The key settings are
the four neighbor flags — both nodes must opt in to all four,
and they default to off:

```yaml
transports:
  ethernet:
    interface: "<eth>"        # the name from Step 1
    announce: true            # broadcast our beacon on the link
    listen: true              # listen for beacons (default; shown for clarity)
    auto_connect: true        # dial peers we discover
    accept_connections: true  # accept dial-ins from peers we discover
```

Each flag does one thing:

- `announce: true` — emit a small beacon every
  `beacon_interval_secs` (default 30s) carrying our npub.
- `listen: true` — listen for incoming beacons; populate a
  candidate-peer list keyed by source MAC and observed npub.
- `auto_connect: true` — when we see a beacon from an npub
  we have not yet peered with, initiate the outbound Noise
  handshake.
- `accept_connections: true` — when a remote npub initiates
  the handshake on this transport, complete it.

If only one node sets `announce`, the other won't see it; if
only one side sets `auto_connect` or `accept_connections`, the
roles are asymmetric and the link won't establish unless both
are configured. The cleanest pattern for a ground-up tutorial
is "all four flags on both ends."

> **Multiple Ethernet links.** If a node has more than one
> physical interface that participates in the mesh, configure
> each one as a *named instance* under `ethernet:`:
>
> ```yaml
> transports:
>   ethernet:
>     lan:
>       interface: "eth0"
>       announce: true
>       listen: true
>       auto_connect: true
>       accept_connections: true
>     dongle:
>       interface: "enx00aabbccddee"
>       announce: true
>       # ...
> ```
>
> Each named instance runs its own socket and neighbor state.
> A single ground-up link only needs the flat form shown
> first; named instances become useful when the same node
> bridges multiple physical segments.

## Step 3: Grant the daemon permission to open raw sockets

The Ethernet transport opens an `AF_PACKET` `SOCK_DGRAM` socket
bound to the chosen interface. That requires `CAP_NET_RAW`.

If you installed FIPS via the Debian package and run via the
shipped systemd unit, the daemon runs as root and has
`CAP_NET_RAW` already — there is nothing to do here. Skip to
Step 4.

If you are running the daemon interactively as your user (a
from-source / development setup), grant the capability once on
the binary:

```sh
sudo setcap CAP_NET_RAW,CAP_NET_ADMIN+ep "$(which fips)"
```

`CAP_NET_ADMIN` is what the daemon needs for the `fips0` TUN
adapter regardless; `CAP_NET_RAW` is the ground-up addition.
The `setcap` invocation only needs to be repeated when the
binary is replaced.

## Step 4: Restart the daemon on each node

```sh
sudo systemctl restart fips
```

Or, if running interactively, restart your `fips` invocation
in whichever way you started it.

Watch the startup logs for the Ethernet transport coming up:

```sh
sudo journalctl -u fips -f --since="1 minute ago"
```

Look for landmarks like:

- A line indicating the Ethernet transport opened the chosen
  interface and started its receive loop.
- Periodic outbound beacon messages (one per
  `beacon_interval_secs` window).
- After the second beacon round on the *other* node, an
  inbound beacon parsed and a candidate-peer entry created.
- Once each side dials, a Noise handshake completion log
  message naming the remote npub.

Beacon interval defaults to 30s, so the first peering can take
up to a minute (one beacon window per side, plus handshake).
Lower the interval for the tutorial if you want faster
feedback:

```yaml
transports:
  ethernet:
    # ...
    beacon_interval_secs: 10  # minimum allowed
```

## Step 5: Verify the link

On either node:

```sh
sudo fipsctl show peers
```

Expect one entry whose `npub` matches the **other** node and
whose `addresses` line shows `transport: ethernet`. Your
existing overlay peers (if any from earlier tutorials) appear
alongside it. Each peer has its own row, and the link status
columns show whether the Noise session is up.

```sh
sudo fipsctl show transports
```

Confirms that the Ethernet transport is running and shows the
beacon counters incrementing. Both `beacons_sent` and
`beacons_received` should be non-zero if the link is healthy.

## Step 6: Reach the other node by name

On node A, ping node B by `.fips` name. Get node B's npub
from its `fipsctl show status` output (it's the persistent
identity you established earlier), then:

```sh
ping6 npub1bbb…long-string….fips
```

Expect ICMPv6 echo replies. The path is:

1. The local `.fips` resolver translates the npub-form name
   into an `fd97:...` mesh address (cryptographically derived
   from the npub on both ends — the resolver does the
   computation locally, with no network round trip).
2. The kernel routes the packet via `fips0`.
3. The FIPS daemon accepts it from the TUN, looks up the
   mesh route, and hands it to the FMP link to node B.
4. The Ethernet transport on node A frames the FMP packet as
   a raw EtherType `0x2121` Ethernet frame addressed to node
   B's MAC, learned from B's beacons.
5. Node B's daemon receives the frame, peels off the
   Ethernet/FIPS framing, and the packet emerges on node B's
   `fips0`.
6. The kernel on node B sees an inbound ICMPv6 echo and
   replies, and the same path runs in reverse.

If you have a hosts file with shortnames configured (see
[host-aliases](../how-to/host-aliases.md)), substitute the
shortname for the full npub form.

## Step 7: Try a forward composition

If node A also has the `test-us01` overlay peer from
[join-the-test-mesh](join-the-test-mesh.md), node B can
reach `test-us01` *through* node A — even though node B has
no direct internet path of its own:

On node B:

```sh
ping6 npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98.fips
```

The packet leaves B's `fips0`, traverses the Ethernet link to
A, gets forwarded by A across the overlay UDP transport to
`test-us01`, and the reply comes back the same way.

This is the composition the chapter intro flagged: the two
deployment modes coexist on a single daemon. Node A is
participating in the test mesh via the internet *and* in your
local Ethernet mesh. From node B's perspective, the test mesh
is reachable. From `test-us01`'s perspective, B is reachable.
The mesh handles the rest.

## Variations

### WiFi (AP mode), same shape as Ethernet

Replace `<eth>` with the WiFi interface name (typically
`wlan0` or `wlp3s0`) on each node. The WiFi NIC is presented
as an Ethernet-class interface to the kernel by the
`mac80211` abstraction; the FIPS Ethernet transport opens
the same `AF_PACKET` socket on it. No FIPS-side configuration
change beyond the interface name.

What you do need on the AP side:

- Both nodes associated to the same SSID.
- **Client (station) isolation must be OFF** on the AP.
  Most consumer routers ship with it off; many guest
  networks and "secure" enterprise APs ship with it on.
  When client isolation is on, the AP refuses to forward
  station-to-station frames — the broadcast beacons never
  arrive at the other node, and neighbor detection fails silently.
  If beacons aren't crossing, this is the first thing to
  check.

There is no FIPS-specific configuration for WiFi versus
Ethernet on the daemon side; the choice is purely the
adapter name.

### Bluetooth LE (experimental but works)

BLE is a separate transport (`transports.ble.*`) with its own
neighbor-detection model — L2CAP advertisements rather than raw L2
broadcasts. The shape of the tutorial is the same (advertise +
scan + auto-connect + accept), but the prerequisites are
different: BlueZ, `bluetoothd`, an HCI adapter, and the
`bluetooth` group or capability set.

The full operator recipe is in
[../how-to/set-up-bluetooth-peer.md](../how-to/set-up-bluetooth-peer.md).
Mark this transport as experimental: it works in most
configurations but the BLE stack has more variability than
Ethernet — adapter quirks, BlueZ version differences, and the
shorter range all matter.

The BLE transport is **Linux-only** at present; macOS and
Windows builds skip it.

## What you've learned

- **Ground-up is the new ground.** FIPS does not need any IP
  infrastructure between two devices to mesh them. A wire (or
  a radio link), `CAP_NET_RAW`, and a few config flags on each
  end are sufficient. The mesh supplies its own identity,
  addressing, discovery, and routing.
- **Neighbor detection is a four-flag opt-in.** `announce`, `listen`,
  `auto_connect`, and `accept_connections` each control one
  thing; both ends must agree before a link will form.
- **The two modes coexist.** Overlay peers and ground-up peers
  ride the same daemon — same FMP link layer, same FSP session
  layer, same `fips0` adapter. A node can be a bridge between
  the two without any extra plumbing.
- **No IP on the link.** The Ethernet transport bypasses the
  kernel IP stack via `AF_PACKET`. Whether the interface has
  an IP address is irrelevant; whether it has carrier is what
  matters.
- **Names work the same way.** `<npub>.fips` resolves locally
  via the cryptographically-derived ULA. The resolver does
  not care whether the destination is reached over Ethernet,
  UDP overlay, or some hop chain combining both.

## Troubleshooting

- **No beacons received.** On either node, `sudo fipsctl show
  transports` should show `beacons_received` incrementing
  every `beacon_interval_secs` once the other node is also
  running. If it stays at zero:
  - Confirm the chosen interface is `LOWER_UP` (carrier
    present).
  - Confirm the other node is announcing (its `beacons_sent`
    should be non-zero).
  - On WiFi: confirm AP client isolation is off.
  - On a switch: confirm the switch is unmanaged or that
    EtherType `0x2121` is not being filtered. Most consumer
    switches forward all EtherTypes; managed switches
    sometimes don't.
- **Beacons received but no peer entry.** The handshake is
  failing. Tail logs (`journalctl -u fips`) for Noise
  handshake errors. Common causes: peer ACL active and not
  including the remote npub (out of scope for this tutorial,
  but check `/etc/fips/peers.allow` if you have set one);
  daemon's clock drift large enough to fail freshness
  checks (rare).
- **Daemon won't start with the Ethernet transport.** Likely
  a permissions error. Check `journalctl -u fips` for an
  `EPERM` or "operation not permitted" message; if running
  interactively, confirm the binary has `CAP_NET_RAW`
  (`getcap "$(which fips)"`).
- **Beacons in both directions, peers entries on both sides,
  but ping6 times out.** The handshake completed but the FSP
  session is not flowing data. Check `fipsctl show peers`'s
  link status columns — if the FMP link is healthy but FSP
  is not, the mesh-layer side is fine and the issue is one
  layer up. The
  [reach-mesh-services § Troubleshooting](reach-mesh-services.md#troubleshooting)
  section covers symptoms at this level.
- **`AF_PACKET` socket bind fails on a kernel-protected
  interface.** Some hardened kernels (`grsec`, certain
  containers, certain VMs) restrict raw-socket access even
  with `CAP_NET_RAW`. The daemon log will name the failing
  syscall. The fix is host-side: relax the restriction or
  pick a different interface.

## What's next

You now have the second deployment mode of FIPS in your
hands. From here:

- **Add a third node.** Bring up a third machine on the same
  Ethernet segment, configure it identically, and watch all
  three nodes form a mesh. The FIPS spanning tree picks a
  root and routing converges within a few beacon intervals.
- **Mix transports.** Add an overlay peer (per
  [join-the-test-mesh](join-the-test-mesh.md)) to one of
  your ground-up nodes; the local mesh now reaches the test
  mesh through that node, and vice versa.
- **Host services.** Anything you do on `fips0` with overlay
  peers — bind an HTTP server (per
  [host-a-service](host-a-service.md)), reach a service via
  the daemon's IPv6 adapter (per
  [reach-mesh-services](reach-mesh-services.md)) — works
  identically on a ground-up mesh. The data plane is the
  same.

For more depth on the link-layer machinery:

- [../reference/transports.md § Ethernet](../reference/transports.md)
  — full Ethernet transport reference (counter inventory,
  per-instance configuration, MTU model).
- [../reference/configuration.md § Ethernet](../reference/configuration.md#ethernet-transportsethernet)
  — every configuration key and its default.
- [../how-to/set-up-bluetooth-peer.md](../how-to/set-up-bluetooth-peer.md)
  — operator recipe for the BLE variant.
- [../design/fips-transport-layer.md](../design/fips-transport-layer.md)
  — the design doc that describes the per-link MTU model and
  why each transport is treated as link-layer rather than
  network-layer.
