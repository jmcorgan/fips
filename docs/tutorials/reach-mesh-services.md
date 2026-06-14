# Reach Services on Other Mesh Nodes

In [join-the-test-mesh](join-the-test-mesh.md) you used `ping6`
to reach `test-us01` and `test-us02` by their `.fips` names.
This tutorial generalizes that to any IPv6-capable tool you
already use — `nc`, `traceroute6`, `curl`, `ssh`, `scp`,
anything — and gets you comfortable with the daemon's IPv6
adapter, which makes the FIPS mesh look like an ordinary IPv6
network to applications that already know how to use IPv6.

The whole exercise should take about ten minutes.

## What you'll do

You'll ping a mesh node (recap), attempt a TCP connection to it
with `nc`, and trace the packet path with `traceroute6` — all
by hostname. By the end you will have driven three different
IPv6 tools at a mesh address and seen each one work the same
way it works on the regular internet.

> **An IPv6 adapter for a non-IPv6 mesh.** The FIPS network
> itself routes blobs of data between npub-addressed nodes;
> on its own it has nothing to do with IPv6. The daemon
> includes an *IPv6 adapter* that presents the mesh as an
> ordinary IPv6 interface (`fips0`), so existing IP software
> works without modification. The kernel routes packets to
> it, applications open IPv6 sockets through it, and the
> adapter handles encapsulating each packet and routing it
> through the mesh to the matching adapter on the other side.
> Any tool that speaks IPv6 works unchanged.

The IPv6 adapter is currently the main way operators use the
FIPS network, which is why most of the new-user progression is
about it. Native applications can use the mesh without going
through IPv6 at all, but that is out of scope for this tutorial.

## Addressing a mesh node

Throughout this tutorial — and any time you reach across the
mesh — use a node's `.fips` hostname directly. There are two
forms:

- **`<npub>.fips`** — the canonical form. Every node has one,
  always. This is the long bech32 npub with `.fips` appended.
- **`<shortname>.fips`** — the convenience form, *if* you (or
  the package) have an entry for the node in
  `/etc/fips/hosts`. The installer ships entries for the
  public test mesh, so `test-us01.fips` works on a fresh
  install.

These are real hostnames as far as your kernel is concerned.
Pass them to any IPv6-capable tool — `ping6`, `nc`, `curl`,
`ssh`, `traceroute6`, anything — the same way you would pass a
hostname on the public internet. There is no separate
"resolve to address first" step you ever need to perform; if
the tool takes a hostname, it accepts a `.fips` hostname.

> **Where the address comes from.** Every FIPS node's mesh
> address is the first 16 bytes of SHA-256 of its public key,
> with the leading byte replaced by `0xfd` (the `fd00::/8` ULA
> prefix). The remaining bytes are hash output, so an address
> like `fd97:...` is per-node — the `97` is part of the hash,
> not a fixed prefix shared across nodes. Names of the form
> `<npub>.fips` and any shortname mapped in `/etc/fips/hosts`
> are aliases for that address. The daemon's local DNS
> responder hands the answer back to your kernel without ever
> talking to a remote DNS server.

## Step 1: Ping a mesh node (recap)

```sh
ping6 -c 4 test-us01.fips
```

You did this in [join-the-test-mesh](join-the-test-mesh.md).
Four replies, RTT in the tens of milliseconds (depending on
where you are relative to `test-us01`). Nothing new — but it
confirms the mesh data plane is healthy before you try
anything else.

## Step 2: Attempt a TCP connection

`ping6` proves ICMPv6 reaches the destination. To prove TCP
reaches it, use `nc` (netcat) to attempt a connection to a port.
Pick any port — whether it has a service listening or not, the
attempt proves the data plane carries your TCP segments
end-to-end:

```sh
nc -6 -vz test-us01.fips 22 2>&1
```

You will see one of two outcomes:

```text
Connection to test-us01.fips 22 port [tcp/ssh] succeeded!
```

or:

```text
nc: connect to test-us01.fips port 22 (tcp) failed: Connection refused
```

Both are good. The first means a service is listening on that
port and accepted your TCP handshake. The second means your TCP
SYN reached the remote node's kernel, which sent back a TCP RST
because no service was bound — and that RST traveled all the way
back through the mesh to your `nc` process.

> **What a `Connection refused` proves.** A connection-refused
> response is *not* a network failure. It means the destination
> host is alive and reachable, the TCP stack on the far end
> processed your SYN, and the reply made it home. Compare with
> what you would get if the address were unreachable:
> `Network is unreachable` or a timeout. Either of the two
> outcomes above demonstrates a working end-to-end TCP path.

If the port you tried happens to have a service, attach `-`
instead of `-z` and you can read the banner directly:

```sh
nc -6 -v test-us01.fips 22
```

The remote node's SSH banner, if any, will print on the next
line. Type `Ctrl-C` to disconnect — you have not authenticated,
just banner-grabbed.

If `nc` is not installed, the same demonstration works with
`curl` against TCP/80:

```sh
curl -6 -v --connect-timeout 5 http://test-us01.fips/ 2>&1 | head
```

The TCP connection result is in the first few lines of `curl`'s
verbose output. The HTTP response code is irrelevant — what
matters is whether the connection itself succeeded.

## Step 3: Trace the path

`traceroute6` shows the IPv6 hops between you and a
destination:

```sh
traceroute6 -n test-us02.fips
```

You will see exactly one line — `test-us02`'s mesh address.
That is the only IPv6 hop between your `fips0` and
`test-us02`'s `fips0`, even though at the FIPS-mesh layer
your packet is being forwarded through your peer `test-us01`
on the way to `test-us02`. The mesh-layer forwarding is
invisible to `traceroute6` because it lives below the IPv6
adapter.

> **Two layers, two ideas of "hop".** The FIPS mesh routes
> blobs between npub-addressed nodes and can pass through
> several intermediate peers — your packet to `test-us02` is
> handed off to `test-us01` first. The IPv6 adapter, sitting
> on top of that, presents every reachable mesh node as a
> direct IPv6 neighbor: one hop, on a flat fabric. From
> `traceroute6`'s perspective the multi-hop FIPS path is
> hidden — it sees only the source and destination IPv6
> adapters. To see what's happening at the mesh layer, see
> [ipv6-adapter-walkthrough](ipv6-adapter-walkthrough.md),
> which traces one `ssh` request from DNS query to far-side
> TUN with `fipstop` and `fipsctl` running alongside.

If `traceroute6` is not installed, `mtr` and other IPv6 path
tools produce the same single-hop result. The single-hop
behavior is a property of the IPv6 adapter, not of the tool.

## What you've learned

You have driven three IPv6 tools at mesh nodes you reach over
the mesh, all by `.fips` hostname, and they all worked the same
way they work everywhere else:

- **Addressing.** `<npub>.fips` is the canonical hostname for
  any node; `<shortname>.fips` is the convenience form when
  `/etc/fips/hosts` has an entry. Use these in any tool that
  takes an IPv6 hostname — there is no separate resolution
  step you ever need to perform.
- **Reachability.** `ping6` confirms the remote node's `fips0`
  answers ICMPv6 echo from your `fips0`.
- **TCP.** `nc` confirms TCP segments traverse the mesh and the
  far side responds (whether with a banner, a refusal, or a
  service of its own).
- **Path.** `traceroute6` shows exactly one IPv6 hop to any
  reachable mesh node, because the multi-hop FIPS-mesh-layer
  forwarding lives below the IPv6 adapter and is invisible
  to IPv6 tooling.

The conceptual takeaway is the one in the callout at the top:
the daemon's IPv6 adapter takes care of presenting the FIPS
mesh as ordinary IPv6 to every tool you already know. To
consume any service hosted on any mesh node — SSH, HTTP, file
transfer, custom protocols — you use the IPv6 client you
would use anywhere else. The hostname looks unusual
(`<npub>.fips`), but the API surface is unchanged.

## Troubleshooting

If a tool reports "Network is unreachable" or hangs:

- **Confirm the link is healthy.**
  `sudo fipsctl show peers` should show `test-us01` with active
  connectivity. If the link to your direct peer is down, nothing
  past it is reachable.
- **Confirm `fips0` is up.** `ip -6 addr show fips0` should show
  one `fd97:...` address. If `fips0` is missing, the daemon did
  not bring up the TUN — verify the daemon is running with the
  privileges it needs. The default is to run as root; if you
  dropped privileges per
  [../how-to/run-as-unprivileged-user.md](../how-to/run-as-unprivileged-user.md),
  re-check that the `setcap` and systemd override survived your
  last package upgrade.
- **Confirm the name resolves.** If `ping6 test-us01.fips`
  fails with `unknown host` or `Name or service not known`,
  the system resolver is not consulting the daemon's `.fips`
  responder. The installer wires this up automatically; the
  "Reaching mesh nodes by name" section of
  [../getting-started.md](../getting-started.md) describes
  what the wiring looks like and how to confirm it.

If `nc` or `curl` reports a timeout (rather than a refusal or
success), the destination node is unreachable from your
daemon — possible mesh-routing transient. Try again, or ping
first: if `ping6` succeeds but TCP times out, it is the
specific port being filtered on the destination, not a path
problem.

## What's next

- [host-a-service](host-a-service.md) — Bring up a small HTTP
  server on your node, bind it to `fips0` so it is mesh-only,
  and confirm another mesh node (or your own machine) can
  reach it through the same data plane you just exercised.
  Covers bind-interface choice and the mesh firewall.

For "what's actually in those packets":

- [../design/fips-architecture.md](../design/fips-architecture.md)
  — the protocol stack and the two-layer encryption model.
- [../design/fips-mesh-layer.md](../design/fips-mesh-layer.md) —
  Noise XX link encryption, hop-by-hop forwarding.
- [../design/fips-session-layer.md](../design/fips-session-layer.md)
  — end-to-end Noise XX between source and destination.

For the trace-it-yourself version of the path you just
exercised, see
[ipv6-adapter-walkthrough](ipv6-adapter-walkthrough.md), which
walks one `ssh` from DNS query through session setup to the
far-side TUN with `fipstop` and `fipsctl` running alongside.
