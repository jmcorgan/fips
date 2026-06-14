# Host a Service of Your Own

In [reach-mesh-services](reach-mesh-services.md) you used
ordinary IPv6 tools to reach services on other mesh nodes. This
tutorial flips the direction. You will bring up a small HTTP
server on your machine, make a deliberate choice about which
interface it binds to, and turn on the mesh firewall to keep
the exposure to what you intended. By the end you will have
hosted your first peer-reachable service and made an informed
decision about who can reach it.

The whole exercise should take about twenty minutes. You should
have already worked through
[persistent-identity](persistent-identity.md) so that the npub
your service is reachable at does not change between restarts.

## What you'll build

```text
   ┌──────────────────────────────────────────┐
   │  your fips node                          │
   │                                          │
   │   python3 -m http.server                 │
   │      --bind <fips0-addr> 8080            │
   │                       │                  │
   │                       ▼                  │
   │   fips0  fd97:….:Y  ◀─── port 8080 open  │
   └────────────┬─────────────────────────────┘
                │
                │  reachable as
                │     http://<your-npub>.fips:8080/
                ▼
   any mesh peer that can route to <your-npub>.fips
```

You will have:

- A single-page HTTP server bound to `fips0` only — not the
  public internet, not your LAN, just the mesh.
- The mesh firewall baseline active, default-deny on `fips0`
  inbound, with one explicit drop-in that allows TCP/8080.
- A clear understanding of which interface choice corresponds
  to which audience.

## Why bind interface matters

The single most important decision when hosting a service is
**which interface (and therefore which audience) the service is
exposed to**. This is true for every IPv6 service, not just
FIPS — but FIPS makes it stark because your machine often has
several interfaces with very different exposure profiles.

> **Bind interface = exposure surface.** A typical FIPS host
> has at least two distinct audiences:
>
> - `fips0` (`fd97:…`, reachable as `<your-npub>.fips`) —
>   reachable only from FIPS peers that have a working link to
>   your node. Bound by Noise authentication and (optionally)
>   the peer ACL.
> - `eth0` / `wlan0` (your LAN address) — reachable from anyone
>   on your local network segment, with no FIPS auth in the
>   way.
>
> When you run a server, the `--bind` argument decides which of
> these audiences sees the service. Binding to a *specific*
> address opts in to one audience. Binding to `[::]` or
> `0.0.0.0` opts in to **all** of them at once — including any
> you forgot you had.
>
> **Audit what's already listening.** Bringing up `fips0` adds
> a new audience to every service on this host that was already
> bound to `0.0.0.0` or `[::]`. SSH, your web server, a database
> — if any of them was listening on all interfaces before you
> joined the mesh, they are now reachable from mesh peers too.
> A quick `ss -tulnp` will show you everything currently
> listening and on which addresses. The mesh firewall (Step 5
> below) is one way to bring those exposures back under explicit
> control; rebinding the affected services to a specific
> non-mesh address is another.

There is nothing FIPS-specific about this rule; it applies to
SSH, web servers, databases, anything. FIPS just gives you the
option of "mesh peers only" as a distinct audience, which most
hosts otherwise don't have.

## Step 1: Find your node's mesh address

You need the `fd97:...` address assigned to your `fips0`
adapter. Two equivalent ways to get it:

```sh
ip -6 addr show fips0
```

Look for the `inet6 fd97:...` line. The address up to the `/`
is what you want.

Or via the daemon:

```sh
sudo fipsctl show status
```

The JSON has an `ipv6_addr` field — that is your address.

For the rest of this tutorial we will write the address as
`<your-fips0-addr>`. Substitute the actual `fd97:...` value
when you run the commands. Save it to a shell variable for
convenience:

```sh
FIPS0_ADDR=$(ip -6 addr show fips0 | awk '/inet6 fd97:/ {print $2}' | cut -d/ -f1)
echo "$FIPS0_ADDR"
```

You should also know your npub from
[persistent-identity](persistent-identity.md):

```sh
NPUB=$(sudo cat /etc/fips/fips.pub)
echo "$NPUB"
```

`<your-npub>.fips` and `<your-fips0-addr>` are two names for
the same destination.

## Step 2: Bring up an HTTP server bound to fips0

Make a small directory with one file in it so the server has
something to serve:

```sh
mkdir -p /tmp/mesh-demo
echo '<h1>Hello from the mesh</h1>' > /tmp/mesh-demo/index.html
cd /tmp/mesh-demo
```

Start a Python HTTP server bound to your `fips0` address:

```sh
python3 -m http.server --bind "$FIPS0_ADDR" 8080
```

Leave the server running. The terminal will show:

```text
Serving HTTP on fd97:... port 8080 (http://[fd97:...]:8080/) ...
```

Two things to notice:

- The "Serving HTTP on …" line names your `fd97:...` address
  explicitly. Python is binding only to that one address.
- The default would have been `0.0.0.0` — which is **not**
  what you want here. Without `--bind`, the server would be
  reachable from your LAN and any public IP this host has,
  not just from the mesh.

## Step 3: Verify the service locally

Open a second terminal. From the same host, fetch the page:

```sh
curl -6 "http://[$FIPS0_ADDR]:8080/"
```

Expect:

```text
<h1>Hello from the mesh</h1>
```

Now fetch it by name. Both forms should work:

```sh
curl -6 "http://${NPUB}.fips:8080/"
```

The daemon's local DNS responder turned the npub-form name into
the `fd97:...` address, and the request landed at your HTTP
server.

> **What just happened.** The kernel routed your local request
> via the loopback path because the destination address is
> assigned to one of your own interfaces. You exercised the
> client side (DNS, IPv6 socket open, HTTP request) and the
> server side (HTTP listener, response). What you have not yet
> verified is reachability *from another mesh node*. That is
> the next concern.

If you have `fipstop` available, open it now in another terminal
and switch to the **Node** tab. The right-half of the Traffic
block — the **Listening on fips0** panel — should list a `tcp`
row at port 8080 with a `python(<pid>)` Process column. The State
column reads `OPEN` because the firewall has not been turned on
yet; everything bound to `fips0` is currently mesh-reachable. The
yellow banner above the panel says
"fips-firewall.service inactive — all listeners exposed". Both
signals will flip in the next two steps.

## Step 4: Reachability from a mesh node

Any mesh node — a direct peer, or a node several hops away —
reaches your service the same way you reached `test-us01` in
[reach-mesh-services](reach-mesh-services.md): it looks up
`<your-npub>.fips`, gets back your `fd97:...` address, opens
a TCP connection to it, and the FIPS data plane carries the
packets across the mesh to you. From the remote host the curl
looks identical to yours:

```sh
curl -6 "http://${NPUB}.fips:8080/"
```

If you have a second machine on the mesh — or you can ask
another operator to try it — this is the moment to confirm.
A node that can already `ping6 ${NPUB}.fips` should also be
able to fetch your page. If it can ping but the curl times
out, jump to [Troubleshooting](#troubleshooting) — but most
likely the firewall step in this tutorial has not happened
yet, so a remote attempt right now will succeed straight
through to your HTTP server.

That is the problem. With no firewall in place, *any* mesh
node that can route to you — your direct peers, and every node
beyond them in the mesh — can reach port 8080. You have not
yet made a deliberate decision about whether you want that.
The rest of this tutorial replaces the implicit "every port
with a listener is reachable" with an explicit "only the ports
I have opened are reachable, optionally only from specific
mesh nodes." That is the firewall's job, and it is the only
mechanism in play in the rest of this tutorial.

(There is a separate, unrelated control called the *peer ACL*
that decides which npubs may establish a peer connection with
your node at the transport layer. It is not part of the
firewall and does not affect what is described below; Step 7
is a brief signpost to it.)

## Step 5: Activate the mesh firewall baseline

FIPS ships a default-deny nftables baseline at
`/etc/fips/fips.nft` that restricts inbound traffic on `fips0`
to ICMPv6 echo and conntrack replies. The baseline is **not**
enabled by default — activation is an explicit step the
operator has to take.

Activate it:

```sh
sudo systemctl enable --now fips-firewall.service
```

This loads the table immediately and arranges for it to load
on every subsequent boot. Confirm:

```sh
sudo nft list table inet fips
```

You will see one chain named `inbound` hooked at `input`,
roughly:

```text
table inet fips {
    chain inbound {
        type filter hook input priority filter; policy accept;
        iifname != "fips0" return
        ct state established,related accept
        icmpv6 type echo-request accept
        counter packets 0 bytes 0 drop
    }
}
```

The chain admits ICMPv6 echo (so `ping6` from any mesh node
still works) and conntrack replies (so your *outbound*
connections still get their replies back). Everything else
inbound on `fips0` hits the final `counter ... drop`.

> **What this changed.** Your HTTP server is still running and
> still reachable *from this same host* (same-host traffic to
> `fd97:...` goes via the loopback path, which has
> `iifname != "fips0"` and short-circuits at the first rule).
> But any mesh node trying to reach `fd97:...:8080` now has its
> TCP SYN dropped before it can reach your server. From the
> remote end the connection times out.

The fipstop panel reflects the change immediately: the yellow
"firewall inactive" banner disappears, the panel title becomes a
plain "Listening on fips0", and your `tcp 8080 python(<pid>)` row
flips to **DarkGray** with `filt` in the State column. Every
other row also goes DarkGray — none of them have an explicit
accept rule yet, and the chain falls through to `counter drop`.

So the firewall is in the right shape but in the wrong state
for our purpose: we *want* mesh nodes to reach port 8080. The
next step opens that one port.

## Step 6: Open port 8080 via a drop-in

Drop-ins live under `/etc/fips/fips.d/` with the `.nft`
suffix. Each file is included into the `inbound` chain at the
marked point and may contain any nftables rule lines valid in
that context.

Create one for your HTTP service:

```sh
sudo tee /etc/fips/fips.d/http-mesh-demo.nft >/dev/null <<'EOF'
tcp dport 8080 accept
EOF
```

Reload the firewall:

```sh
sudo systemctl reload-or-restart fips-firewall.service
```

Confirm the rule is live:

```sh
sudo nft list table inet fips
```

The `inbound` chain now contains your `tcp dport 8080 accept`
rule between the conntrack rule and the final `counter drop`.

A curl from any mesh node will now reach the HTTP server. The
path is: remote node's mesh data plane → forwarded across the
mesh → your direct peer's link to you → `fips0` ingress →
`inbound` chain → matches `tcp dport 8080 accept` → delivered
to the HTTP server.

In the fipstop panel, your `tcp 8080 python(<pid>)` row flips
back to **default White** with `OPEN` in the State column on the
next poll tick. No other row changes — they remain DarkGray
`filt` because you have only opened this one port. The panel
doubles as a security screen for the rest of the tutorial: any
service whose row reads `OPEN` is mesh-reachable, anything
DarkGray is filtered. If you later add a saddr-restricted
drop-in (covered just below), the row will land at `filt?`
rather than `OPEN`, signalling that the rule exists but is
source-scoped — the panel deliberately does not classify
restricted accepts as fully open.

If you only want to expose the service to a *specific* node
or set of nodes, source-filter the rule. The address filter
applies to the mesh-source address as it arrives on `fips0`,
which is the originating node's address — not necessarily a
direct peer. Replace the drop-in contents with something like:

```nft
ip6 saddr fd97:1234:5678:9abc:def0:1234:5678:9abc tcp dport 8080 accept
```

The source address is the node's mesh address, which it
publishes in its `fips.pub` (and which you can resolve from
its npub). For multiple nodes, use a set:

```nft
ip6 saddr {
    fd97:1111:2222:3333:4444:5555:6666:7777,
    fd97:8888:9999:aaaa:bbbb:cccc:dddd:eeee
} tcp dport 8080 accept
```

For the worked example, leave the drop-in unfiltered — any
mesh node that can route to you can fetch your page.

## Step 7: A note on the peer ACL

The firewall you just configured is the only control in scope
for this tutorial. There is a separate, optional control
called the *peer ACL* that you may run across in other docs;
it is unrelated to the firewall and worth a sentence here only
so you do not confuse the two.

The peer ACL decides which npubs may establish a peer
connection with your node at the transport layer. It does not
look at ports, drop-ins, or `fips0` traffic. You do not need
it for this tutorial.

For when you do:

- [../how-to/enable-nostr-discovery.md](../how-to/enable-nostr-discovery.md)
  — operator recipe.
- [../reference/security.md § Peer ACL](../reference/security.md#peer-acl)
  — file format, evaluation order, alias handling.

## Step 8: Stop the server and tidy up

When you are done, stop the HTTP server in the first terminal
with `Ctrl-C`. The drop-in stays in place; remove it if you
do not want port 8080 reachable after the demo:

```sh
sudo rm /etc/fips/fips.d/http-mesh-demo.nft
sudo systemctl reload-or-restart fips-firewall.service
```

The `fips-firewall.service` itself can stay enabled —
default-deny on `fips0` is a sensible posture even with no
extra services running. To turn it back off:

```sh
sudo systemctl disable --now fips-firewall.service
```

## What you've learned

- **Bind interface = audience.** Binding to a specific address
  opts in to one audience; binding to wildcard
  (`0.0.0.0` / `[::]`) opts in to *all* of them, including
  ones you forgot you had. For mesh-only exposure, bind to
  your `fd97:...` address. The fipstop **Listening on fips0**
  panel marks wildcard binds with a trailing `*` after the
  process name as a reminder that the bind is not
  fips0-specific.
- **Same-host loopback is misleading.** A local curl to your
  own `fd97:...` address goes via the loopback path, not
  through `fips0` ingress. To actually verify mesh-side
  reachability you need a second machine, or to read what
  the firewall is doing in `nft list table inet fips`.
- **The mesh firewall is opt-in.** `fips-firewall.service` is
  not enabled by default. Once it is enabled, `fips0` is
  default-deny except for ICMPv6 echo and conntrack replies.
- **Ports open via drop-ins.** Each file under
  `/etc/fips/fips.d/*.nft` adds rules into the `inbound`
  chain. Source-filter with `ip6 saddr` to scope a port to
  specific mesh nodes.
- **Two independent controls at two different layers.** The
  firewall is a layer-3 filter on `fips0`: it controls which
  TCP/UDP ports are reachable and (optionally) which mesh
  source addresses may reach them. The peer ACL is a
  transport-layer admission filter on Noise handshakes: it
  controls which npubs may become direct peers of your node.
  They are unrelated — the ACL does not touch fips0 traffic,
  and the firewall does not look at npubs.

You now have the mental model for hosting any IPv6 service
behind a deliberate exposure policy. The mechanics generalize:
SSH on port 22, a database on port 5432, a custom protocol on
its own port — same `--bind` rule, same drop-in shape.

## Troubleshooting

- **A remote mesh node cannot reach the service after the
  firewall reload.** Check the drop-in syntax with
  `sudo nft -c -f /etc/fips/fips.nft` before reloading; a
  syntax error in any drop-in causes the whole table to fail
  to load and the previous rules persist. Then
  `sudo nft list table inet fips` to confirm your
  `tcp dport 8080 accept` rule is present in the `inbound`
  chain.
- **Local curl works, remote curl times out.** The packet is
  reaching `fips0` ingress and being dropped by the baseline.
  Either your drop-in did not load (see above) or it has a
  source filter that excludes the remote node's address.
- **Local curl fails after binding to fips0.** Double-check
  that your `FIPS0_ADDR` matches the address shown in
  `ip -6 addr show fips0`. The Python server message also
  echoes the bound address — confirm it starts with `fd97:`,
  not `127.0.0.1` or `::`.
- **`Address already in use` from Python.** Another process
  holds port 8080. Pick a different port (`8081`, `9000`, …)
  for both the `python3 -m http.server` invocation and the
  drop-in.
- **Watch the firewall counter to confirm drops.** The
  `counter ... drop` line at the bottom of the chain
  increments on every dropped inbound packet. After a remote
  mesh node attempts to reach a port you have not opened,
  `sudo nft list table inet fips` will show the counter
  packet count rising.
- **Use fipstop to spot-check listener and filter state.** The
  Listening on fips0 panel on the Node tab shows every
  fips0-reachable listener and its current filter state. A row
  staying `filt` after you expected `OPEN` usually means the
  drop-in failed to load (a syntax error in any file under
  `/etc/fips/fips.d/` aborts the whole reload, leaving the
  previous ruleset in place) or the drop-in carries a source
  filter and now reads `filt?` rather than `OPEN`.

## What's next

- [ground-up-mesh.md](ground-up-mesh.md) — Bring up two devices
  on a shared physical link — Ethernet, WiFi, or Bluetooth —
  with no pre-existing IP infrastructure between them. The
  second deployment mode of FIPS, where the mesh is the
  network rather than an overlay on top of one. Coexists with
  overlay peers; the same daemon carries both.

For more depth on the firewall and ACL surface:

- [../how-to/enable-mesh-firewall.md](../how-to/enable-mesh-firewall.md)
  — operator recipes for the baseline, drop-in patterns,
  and how to fold the baseline into an existing
  `nftables.conf`.
- [../reference/security.md](../reference/security.md) —
  consolidated security reference: nftables baseline rules,
  drop-in format, peer ACL semantics, default exposures by
  transport, threat-resistance matrix.
- [../design/fips-security.md](../design/fips-security.md) —
  threat model, why the baseline is opt-in, the metadata-
  privacy posture.

If you want to host a service that is *not* on a FIPS node — say,
an existing HTTP server on a regular LAN box — and expose it to
mesh peers through a `fips-gateway`, that's the inbound
port-forward mode: the gateway runs a mesh-side listener on `fips0`
and forwards to a LAN target. The operator recipe is at
[../how-to/deploy-gateway.md#inbound-port-forwarding](../how-to/deploy-gateway.md#inbound-port-forwarding);
a hand-held walk-through on an OpenWrt AP is at
[deploy-fips-gateway.md](deploy-fips-gateway.md) under "Advanced"
in [README.md](README.md).
