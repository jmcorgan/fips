# Join the FIPS Test Mesh

In this tutorial you will connect your FIPS daemon to a public
test peer over UDP, watch the link come up, and reach the peer's
mesh address from your machine. By the end you will have seen one
complete end-to-end flow — config, handshake, live link, traffic
— for a real peer somewhere out on the public internet.

The whole exercise should take about ten minutes. If you have
already worked through [getting-started.md](../getting-started.md)
and have the `fips` daemon running on your host, you have
everything you need.

## What you'll build

```text
   ┌────────────────────┐         UDP/IPv4         ┌──────────────────────┐
   │   your fips node   │ ──────────────────────── │      test-us01       │
   │   ephemeral npub   │  test-us01.fips.network  │  npub1qmc3...zel98   │
   │   fips0  fd97:..:Y │           :2121          │   fips0  fd97:..:T   │
   └────────────────────┘                          └──────────────────────┘
```

Your daemon will peer with one of the public test nodes the
project maintains. `test-us01` has a stable DNS name, listens on
UDP/2121, and is reachable from any network that permits arbitrary
outbound UDP.

> **Peer vs. node.** In FIPS terminology, a *peer* is a node
> you have a direct link to — same Noise XX handshake, same
> transport socket. A *node* is any participant on the mesh,
> whether you peer with it directly or reach it through one or
> more hops via your peer's connections. Peering is a local
> configuration choice; reachability is mesh-wide. One good peer
> connects you to everyone the rest of the mesh connects to.

After the link to `test-us01` establishes, your daemon's `fips0`
adapter can reach `test-us01` itself and — through `test-us01`'s
connections — any other node on the test mesh, exactly as if you
had a direct connection to each of them.

> **About the test mesh.** The project maintains a small roster
> of public test nodes (`test-us01` through `test-uk01`) intended
> for new-user on-ramps and integration testing. They accept
> inbound peering from arbitrary npubs without prior coordination.
> A future reference doc will list the full roster; for this
> tutorial you only need `test-us01` as your peer, and `test-us02`
> later on as a second mesh destination to demonstrate
> forwarding.

## Step 1: Confirm the daemon is running

```sh
sudo systemctl status fips
```

Expect `active (running)`. If it is not running, the
[getting-started](../getting-started.md) guide covers installation
and service management. While you're checking, note your daemon's
current npub:

```sh
sudo fipsctl show status
```

Look for the `npub` field. With the default ephemeral-identity
config, this regenerates on every restart — that is fine for the
tutorial. `test-us01` admits any inbound npub.

## Step 2: Add a static peer to the daemon config

Edit `/etc/fips/fips.yaml`. Find the line that reads `peers: []`
and replace it with:

```yaml
peers:
  - npub: "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98"
    alias: "test-us01"
    addresses:
      - transport: udp
        addr: "test-us01.fips.network:2121"
    connect_policy: auto_connect
```

What each field does:

- `npub` — the canonical Nostr public key of `test-us01`. This is
  who your daemon will mutually authenticate with over Noise XX.
- `alias` — a short name your daemon will use when referring to
  this peer in logs and `fipsctl show peers` output. Optional.
- `addresses` — one or more transport endpoints. UDP on the
  published hostname and port is the most direct path.
- `connect_policy: auto_connect` — your daemon initiates an
  outbound connection rather than waiting for the peer to reach
  in.

## Step 3: Restart the daemon

```sh
sudo systemctl restart fips
```

Watch the daemon's journal as it comes back up and dials the
peer:

```sh
sudo journalctl -u fips -f
```

Within a few seconds you should see lines mentioning:

- An outbound connection attempt to `test-us01` or
  `test-us01.fips.network:2121`
- A handshake completion (a "Noise XX link handshake complete"
  style line, or "peer authenticated" with the test-us01 npub)
- An MMP / link metrics entry naming `test-us01`

If the handshake does not complete within roughly 30 seconds, jump
to [Troubleshooting](#troubleshooting) below.

## Step 4: Verify the link

```sh
sudo fipsctl show peers
```

Expect one entry whose `alias` is `test-us01`. Useful fields:

- `connectivity` — should be active / authenticated.
- `transport_addr` — the resolved UDP endpoint your daemon is
  using to reach `test-us01`.
- `transport_type` — `udp`.
- `mmp.srtt_ms` — appears once the first MMP report has been
  exchanged. This is your round-trip time to `test-us01`.

The transport view confirms your UDP listener and the peer
mapping:

```sh
sudo fipsctl show transports
```

## Step 5: Ping your peer

`test-us01`'s mesh address derives from its npub. Address it as
`<npub>.fips` and your daemon's local DNS responder will translate
that to its `fd97:...` mesh address.

First see the resolved address:

```sh
dig npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98.fips AAAA +short
```

You should see one `fd97:...` line.

Now ping it:

```sh
ping6 -c 4 npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98.fips
```

Expect four replies. The first packet may take noticeably longer
than subsequent ones — that round trip includes destination
discovery, FSP session establishment, and the proactive path-MTU
probe. After that, the RTT settles to a steady value reflecting
the path between your host and `test-us01`.

This confirms the direct link works. So far, though, you have only
reached the peer you configured. The next step demonstrates the
mesh-wide reach that peering buys you.

## Step 6: Reach a different node through the mesh

`test-us02` is another public test node. You did **not** add it
to your `peers:` block — your daemon has no direct link to it.
But because `test-us01` participates in the same mesh and has its
own connections to other nodes, your daemon can reach `test-us02`
through `test-us01` without any additional configuration.

```sh
ping6 -c 4 npub10yffd020a4ag8zcy75f9pruq3rnghvvhd5hphl9s62zgp35s560qrksp9u.fips
```

Same form, different npub. Expect replies. The packets travel
from your daemon to `test-us01` over the direct UDP link, then
onward through `test-us01` (and possibly other test-mesh nodes)
to reach `test-us02`'s `fips0` adapter. Replies retrace the path.

This is the central FIPS guarantee: **peering is local, but
reachability is mesh-wide.** You only need one good peer to talk
to everyone else they (transitively) talk to.

If the `test-us02` ping fails while the `test-us01` ping
succeeded, the test mesh's routing between those two nodes is
momentarily unhealthy — try again in a minute, or pick a different
test node from the roster. The link to your peer is unaffected.

## What you've learned

You now have a single FIPS node connected to one peer in the
public test mesh, with reach to every node that mesh routes you
to. You have seen:

- **Identity.** Your daemon's ephemeral keypair authenticated to
  `test-us01` over Noise XX without either side trusting anyone in
  advance.
- **Transports.** A UDP socket on your host carries
  authenticated, encrypted mesh frames to your peer. No central
  server, no VPN concentrator.
- **Peering vs. reachability.** You configured one peer
  (`test-us01`) and got reach to a second node (`test-us02`) for
  free, through the mesh. The same shape extends to every other
  node `test-us01` can reach.
- **Naming.** The local `.fips` resolver translated npub-form
  hostnames into their `fd97:...` mesh addresses with no external
  DNS traffic.
- **End-to-end.** ICMPv6 traffic over the FIPS data plane reached
  both destinations and came back, end-to-end encrypted along
  every link layer in the path.

> **By the way: shortnames.** Those long `npub1...fips`
> destinations are the canonical addresses, but the installer
> ships an `/etc/fips/hosts` file with shortname entries for
> the public test mesh, so `test-us01.fips` and
> `test-us02.fips` resolve to the same addresses without
> typing 80 characters of bech32. You can add your own entries
> too. See
> [../how-to/host-aliases.md](../how-to/host-aliases.md). The
> rest of the tutorials use shortnames where they're available.

## Troubleshooting

If the handshake does not complete:

- **Outbound UDP may be blocked.** Some networks filter
  arbitrary outbound UDP or block return traffic. From a
  UDP-filtered network you cannot reach peers that only
  publish UDP endpoints — your reachable peers are limited
  to those that accept incoming TCP (outbound TCP is
  typically allowed even on networks that block UDP). The
  test-mesh nodes publish a TCP endpoint on port 443 for
  exactly this case; replace the `udp` entry in the peer's
  `addresses:` block with the TCP equivalent:

  ```yaml
  addresses:
    - transport: tcp
      addr: "test-us01.fips.network:443"
  ```

  Restart the daemon and re-check `fipsctl show peers`. The
  link will be slower than UDP but is the supported transport
  for restrictive egress environments.
- **Confirm the testnode is reachable at the IP layer.** Run
  `dig +short test-us01.fips.network` to confirm DNS, then
  `nc -uvz test-us01.fips.network 2121` to confirm UDP
  reachability.
- **Confirm your config parsed.** `sudo journalctl -u fips -n 50`
  near the daemon-start time will show config-load lines and any
  parse errors.
- **Time skew.** A heavily skewed system clock can make
  signature validation fail. `timedatectl status` should show
  the system clock as synchronized.

## What's next

These are the natural follow-on tutorials in the new-user
progression. Some are still being written and will appear
alongside this one in the [tutorials/](.) directory.

- **Make your node's identity persistent.**
  [persistent-identity](persistent-identity.md) walks through
  pinning the daemon to a stable Nostr keypair so your npub
  does not change across restarts — the prerequisite for other
  operators adding you to their `peers:` blocks.

- **Resolve peers via Nostr.**
  [resolve-peers-via-nostr](resolve-peers-via-nostr.md) is the
  smallest useful step toward Nostr-mediated discovery:
  configure a peer by npub alone and let the daemon look up
  the current endpoint from public relays. The first of three
  tutorials covering Nostr discovery; the others —
  [advertise-your-node](advertise-your-node.md) and
  [open-discovery](open-discovery.md) — round out the
  publish and ambient-consume sides.

- **Trace a connection end-to-end.**
  [ipv6-adapter-walkthrough](ipv6-adapter-walkthrough.md) walks
  the data path from a `.fips` DNS query through session setup
  to the far-side TUN adapter, using `fipstop` and `fipsctl` to
  observe each step.

- **Reach services on other mesh nodes.**
  [reach-mesh-services](reach-mesh-services.md) generalizes the
  `ping6` you just ran to any IPv6-capable tool — `nc`,
  `traceroute6`, `curl`, `ssh` — addressed by `<npub>.fips`.
  The point is that the FIPS data plane is just IPv6;
  applications don't need to know they're on a mesh.

- **Host a service of your own.**
  [host-a-service](host-a-service.md) walks through bringing up
  a small HTTP server bound to `fips0` so mesh nodes can reach
  it, with a deliberate exposure decision (mesh-only vs every
  interface), the mesh firewall, and a brief signpost to the
  separate, unrelated peer ACL (which controls who may peer
  with your node, not what they can reach on your `fips0`).

- [ground-up-mesh](ground-up-mesh.md) — Bring up two devices on
  a shared physical link — Ethernet, WiFi, or Bluetooth — with
  no pre-existing IP infrastructure. The second deployment mode
  of FIPS, coexisting on the same daemon as the overlay peer to
  `test-us01` you just configured.

For "what just happened, in detail":

- [../design/fips-architecture.md](../design/fips-architecture.md) —
  the protocol stack and the two-layer encryption model.
- [../design/fips-mesh-layer.md](../design/fips-mesh-layer.md) —
  Noise XX link encryption, hop-by-hop forwarding.
- [../design/fips-session-layer.md](../design/fips-session-layer.md)
  — end-to-end Noise XX, session lifecycle.
- [../design/fips-ipv6-adapter.md](../design/fips-ipv6-adapter.md) —
  the TUN, the local DNS responder, MTU enforcement.
