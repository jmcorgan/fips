# Deploy a `fips-gateway` on an OpenWrt AP

In every other tutorial in this set you put FIPS *on* the host that
needs to talk to the mesh. This one is the exception. Here you stand
up a `fips-gateway` on an OpenWrt access point so the unmodified LAN
behind it — phones, laptops, smart-home gear — can reach mesh
destinations by `<npub>.fips` without any FIPS software of their own,
and so a service running on a LAN box can be exposed to mesh peers
through a port forward. Two halves, one binary, one config.

This is **advanced** material. It assumes you have already worked
through [join-the-test-mesh](join-the-test-mesh.md) on some other
machine, you understand what `<npub>.fips` means, and now you want to
fold an existing LAN into the mesh from the edge router rather than
installing FIPS on every device. The whole exercise should take about
forty-five minutes.

## What you'll build

```text
   ┌──────────────────────────────────────────────────────────────┐
   │  OpenWrt access point                                        │
   │                                                              │
   │   br-lan        ┌──────────────┐   fips0   ┌──────────────┐  │
   │   (LAN side) ◀──│ fips-gateway │──────────▶│ fips daemon  │  │
   │                 │  (service)   │           │              │──┼─▶  mesh
   │                 │              │  fd97:..  │  fd97:..     │  │
   │                 │  fd01::/112  │           │              │  │
   │                 │  pool        │           │              │  │
   │                 └──────┬───────┘           └──────────────┘  │
   │                        │                                     │
   │                        ▼                                     │
   │                  nftables NAT                                │
   │                  (inet fips_gateway)                         │
   └─────────────────┬────────────────────────────────────────────┘
                     │ br-lan
                     ▼
   ┌──────────────────────────────────────────────┐
   │  LAN clients (phones, laptops, smart-home)   │
   │                                              │
   │  no FIPS install — just IPv6 + DNS           │
   │   ▲                                          │
   │   │  curl http://test-us01.fips/             │
   │   └────── DNS to dnsmasq ──▶ gateway DNS     │
   │                                              │
   └──────────────────────────────────────────────┘
```

By the end you will have:

- An OpenWrt AP whose LAN clients can fetch `http://test-us01.fips/`
  with no FIPS software installed on them.
- An inbound port forward exposing one LAN service to the mesh as
  `<your-gateway-npub>.fips:<port>`.
- An understanding of which LAN-side glue OpenWrt automates for you
  (DNS forwarding, RA route, IPv6 prefix) and which the operator owns
  (port forwards, mesh firewall).

## Why an OpenWrt AP

The gateway has very specific dependencies on the box it runs on. It
needs to own DNS for the LAN, it needs to advertise an IPv6 route to
the LAN, it needs a stable LAN-side interface, and it needs to be the
default IPv6 router for the segment. An OpenWrt-based access point
already does all of those things — it runs `dnsmasq`, it runs
`odhcpd` for IPv6 RA, it owns `br-lan`, and clients are already using
it as their gateway. The OpenWrt ipk leans into that: the `gateway:`
block in `/etc/fips/fips.yaml` is pre-populated, and the
`/etc/init.d/fips-gateway` init script wires up the LAN-side glue
automatically when you start the service.

On a non-OpenWrt host the same integration is manual; that path is
covered by [../how-to/deploy-gateway.md](../how-to/deploy-gateway.md).

## Prerequisites

- An OpenWrt 22.03+ AP serving DHCP and DNS to a wired or wireless
  LAN segment.
- The FIPS ipk installed and a working FIPS daemon on the AP. If you
  haven't done that yet, follow
  [../../packaging/openwrt-ipk/README.md](../../packaging/openwrt-ipk/README.md)
  for the install, then come back here.
- The AP joined to the mesh — at least one healthy peer link. If it
  isn't, work through [join-the-test-mesh](join-the-test-mesh.md) on
  the AP first.
- Root SSH to the AP. Every command in this tutorial runs on the AP.
- A LAN client (phone, laptop) to test the outbound half from.

## Step 1: Verify the FIPS daemon is up

Confirm the daemon is running, the TUN is up, and at least one mesh
peer is reachable:

```sh
service fips status
ip -6 addr show fips0
fipsctl show peers
```

You should see:

- `service fips status` reports `running`.
- `fips0` exists and has one `inet6 fd97:...` address. That is the
  AP's mesh-side identity.
- `fipsctl show peers` lists at least one peer with active
  connectivity (not `idle` / not zero bytes).

Confirm the AP can resolve a known mesh node by name:

```sh
ping6 -c 2 test-us01.fips
```

If any of these fail, fix the daemon side first — the gateway is a
separate service that runs alongside a working daemon, not a
substitute for one.

## Step 2: Inspect the pre-populated gateway config

The OpenWrt ipk ships `/etc/fips/fips.yaml` with the `gateway:` block
already filled in. View the relevant section:

```sh
sed -n '/^gateway:/,$p' /etc/fips/fips.yaml
```

You will see roughly:

```yaml
gateway:
  enabled: true
  pool: "fd01::/112"            # virtual IP range (up to 65535 addresses)
  lan_interface: "br-lan"       # LAN-facing interface for proxy NDP
  dns:
    upstream: "[::1]:5354"      # FIPS daemon DNS resolver (matches daemon default)
    ttl: 60                     # DNS TTL and mapping lifetime (seconds)
  pool_grace_period: 60         # seconds after last session before reclaiming
```

Three things to notice:

- `pool: "fd01::/112"` — the virtual-IP CIDR the gateway hands out
  to LAN clients. 65 536 addresses, the gateway's hard cap. Pick a
  different `fdXX::/N` prefix if `fd01::/112` collides with anything
  on your network.
- `lan_interface: "br-lan"` — the OpenWrt LAN bridge. The gateway
  installs proxy-NDP entries on this interface so LAN clients can
  ARP-equivalent for pool addresses.
- No `dns.listen` line — the source default `[::1]:5353` is exactly
  what OpenWrt wants. The gateway listens on IPv6 loopback only;
  dnsmasq, which owns LAN port 53, forwards `.fips` queries to it.
  The init script wires up that forwarding; you don't bind to a LAN
  address yourself.

For the full reference, see
[../reference/configuration.md § Gateway](../reference/configuration.md#gateway-gateway).

## Step 3: Enable and start fips-gateway

The service is shipped disabled — enable it once and start it:

```sh
service fips-gateway enable
service fips-gateway start
```

Behind that single command, the init script
(`/etc/init.d/fips-gateway`) does five things:

1. **Loads gateway sysctls.** `net.ipv6.conf.all.proxy_ndp=1` and
   `net.ipv6.conf.all.forwarding=1` from
   `/etc/sysctl.d/fips-gateway.conf`.
2. **Reconfigures dnsmasq via UCI** so `.fips` queries arriving at
   the LAN's port 53 are forwarded to the gateway's loopback
   listener on port 5353 instead of going straight to the daemon's
   resolver on port 5354. (Dnsmasq still owns 53; the gateway sits
   in front of the daemon for `.fips` only.)
3. **Adds a global-scope IPv6 prefix** to `br-lan`. Without a
   non-ULA address on the local interface, Android and Chrome
   suppress AAAA queries entirely — they assume the LAN has no
   real IPv6 and don't bother. The init script adds a small
   benchmarking-range prefix to convince them otherwise.
4. **Adds an RA route for the virtual pool.** A UCI `route6` entry
   under `dhcp` tells `odhcpd` to advertise the pool CIDR via Router
   Advertisement (RFC 4191), so LAN clients learn how to reach pool
   addresses automatically. No per-client static routes needed.
5. **Spawns `fips-gateway` under procd** with `--config
   /etc/fips/fips.yaml`, with crash-respawn.

Verify it is running:

```sh
service fips-gateway status
logread | grep fips-gateway | tail
```

Expect a `running` status and a startup log line of the form
`fips-gateway 0.x.y starting`, followed by entries for DNS bind, NAT
table install, and pool initialisation.

> **What just changed on the LAN.** The AP is now offering two
> things it wasn't offering a moment ago: AAAA records under `.fips`
> that resolve to virtual IPs in `fd01::/112`, and a route to that
> CIDR in its Router Advertisements. Existing LAN clients pick both
> up the next time they re-resolve a name and the next time `odhcpd`
> sends an RA, respectively. No reboot required on the client side.

## Step 4: Test the outbound half from a LAN client

Before bringing a LAN client into the picture, confirm from the AP
itself that the mesh side is still healthy after the gateway start:

```sh
ping6 -c 2 test-us01.fips
```

This isolates the router-to-mesh path before involving the LAN
segment. If this fails, the troubleshooting target is the daemon /
mesh side, not the gateway-to-client side. If it succeeds and the
LAN-client test below fails, the target is the LAN segment —
`proxy_ndp`, the RA pool route, or DNS forwarding through dnsmasq.

Now from a phone or laptop on the AP's LAN — anything that does IPv6
and DNS, with no FIPS software installed — try one of the public test
mesh nodes:

```sh
dig test-us01.fips AAAA
ping6 -c 4 test-us01.fips
curl -6 http://test-us01.fips/
```

Expectations:

- `dig` returns an AAAA in `fd01::...`, **not** `fd97:...`. The
  `fd01:` address is the gateway's virtual-IP allocation; the LAN
  client never sees the raw mesh address.
- `ping6` succeeds. ICMPv6 echo travels through the NAT pipeline and
  back.
- `curl` fetches the page (whatever the test mesh is currently
  serving on `test-us01`).

> **What just happened end to end.** Your client asked dnsmasq for
> `test-us01.fips`. Dnsmasq forwarded the query to the gateway's
> loopback listener on port 5353. The gateway forwarded the query on
> to the daemon's resolver on port 5354. The daemon answered with
> `test-us01`'s mesh address (`fd97:...`). The gateway allocated a
> virtual IP from `fd01::/112`, installed nftables DNAT/SNAT/
> masquerade rules pinning that virtual IP to the mesh address,
> installed a proxy-NDP entry on `br-lan` so the client could resolve
> the virtual IP at the link layer, and returned the virtual IP in
> the AAAA reply. Your client then routed traffic to the virtual IP
> via the RA-advertised pool route, the AP's kernel rewrote the
> destination to the mesh address, and the daemon's adapter carried
> the packets across the mesh. Return traffic followed conntrack
> back. The client never knew the mesh existed.

## Step 5 (optional): Inspect the gateway state

The gateway exposes its own control socket separate from the daemon's.
Two useful queries:

```sh
echo '{"command":"show_gateway"}'  | nc -U /run/fips/gateway.sock
echo '{"command":"show_mappings"}' | nc -U /run/fips/gateway.sock
```

`show_gateway` reports pool utilisation, the DNS listen address,
uptime, and the conntrack/NAT counters. `show_mappings` lists each
allocated virtual IP, the mesh address it points at, the DNS name
that triggered the allocation, and the mapping's lifecycle state
(`Allocated`, `Active`, `Draining`).

For the full command catalog and JSON shapes, see
[../reference/control-socket.md § Gateway Command Catalog](../reference/control-socket.md#gateway-command-catalog).
The same data is rendered visually in the **Gateway** tab of
[`fipstop`](../reference/cli-fipstop.md).

If you want to see the kernel rules the gateway installed:

```sh
nft list table inet fips_gateway
```

You will see DNAT, SNAT, and masquerade chains populated with one
rule per active mapping.

## Step 6 (Optional): Add an inbound port-forward for a LAN service

The outbound half is the steady-state use of a gateway. The inbound
half — exposing a LAN service to mesh peers — is a separate decision,
configured per service under `gateway.port_forwards[]`.

For the worked example, run a one-page static web server on the AP
itself, bound to its `br-lan` address, and expose it to the mesh
through a port-forward. Anything would do — the point of the exercise
is the port-forward, not the service. We use what is already on the
AP: `busybox httpd`. In a real deployment the LAN-side target would
typically be a separate host (a NAS, a home server, a dev box on the
LAN); the rule shape is identical.

Find the AP's `br-lan` IPv6 address and save it for the rest of the
step:

```sh
BR_LAN_ADDR=$(ip -6 addr show br-lan \
  | awk '/inet6 fd|inet6 2/ && !/scope link/ {print $2}' \
  | head -1 | cut -d/ -f1)
echo "$BR_LAN_ADDR"
```

Pick from the global-scope benchmarking prefix the init script added
in Step 3, or your own ULA if `br-lan` has one — anything except a
link-local `fe80::/10` address.

Set up a one-file docroot and start a foreground `busybox httpd`
bound to that LAN address on port 8000:

```sh
mkdir -p /tmp/mesh-demo
echo '<h1>Hello from the mesh-gateway demo</h1>' > /tmp/mesh-demo/index.html
busybox httpd -f -p "[${BR_LAN_ADDR}]:8000" -h /tmp/mesh-demo
```

Leave it running in this shell. Open a second SSH session on the AP
to add the port-forward.

Edit `/etc/fips/fips.yaml`. Inside the existing `gateway:` block,
add a `port_forwards:` list:

```yaml
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: "br-lan"
  dns:
    upstream: "[::1]:5354"
    ttl: 60
  pool_grace_period: 60
  port_forwards:
    - listen_port: 8080
      proto: tcp
      target: "[<BR_LAN_ADDR>]:8000"
```

Substitute the real address for `<BR_LAN_ADDR>`. The IPv6 form
(`[addr]:port`) is required — IPv4 targets are rejected at config
load.

Restart the gateway so it re-reads the config:

```sh
service fips-gateway restart
```

From any *other* mesh node, fetch the demo page through the gateway
using the AP's npub:

```sh
# on the AP, get the npub:
NPUB=$(cat /etc/fips/fips.pub)
echo "$NPUB"
```

Then on the remote mesh node:

```sh
curl -6 "http://${NPUB}.fips:8080/"
```

Expect:

```text
<h1>Hello from the mesh-gateway demo</h1>
```

The connection landed on the gateway's `fips0` ingress on TCP/8080,
nftables DNAT rewrote the destination to `[BR_LAN_ADDR]:8000`,
LAN-side masquerade rewrote the source so `busybox httpd` saw a
LAN-routable address, and the response retraced via conntrack.

> **What you exposed.** With the port-forward active, every mesh
> peer that can route to your AP can hit `${NPUB}.fips:8080/` and
> reach this service. That is exactly what the inbound half is
> for — but if you want to scope visibility to a specific subset
> of peers, the FIPS mesh firewall is the layer that does it; see
> [../how-to/enable-mesh-firewall.md](../how-to/enable-mesh-firewall.md).
> The port-forward rule and the firewall rule are independent: the
> port-forward installs the rewrite; the firewall decides who is
> allowed to reach the listen port.

## Step 7: Tidy up

In the first shell, stop `busybox httpd` with `Ctrl-C`. The demo
docroot at `/tmp/mesh-demo` can stay — it is wiped on reboot — or
remove it now (`rm -rf /tmp/mesh-demo`).

If you want to keep the outbound half but withdraw the inbound
forward, remove the `port_forwards:` entry from `/etc/fips/fips.yaml`
and `service fips-gateway restart`. The mesh-side listener disappears
and so does the corresponding nftables rule.

To turn the gateway off entirely:

```sh
service fips-gateway stop
service fips-gateway disable
```

The init script's `stop_service` handler reverses the LAN-side
integration on the way out: dnsmasq's `.fips` forwarder is pointed
back at the daemon's port 5354, the RA route for the pool is
withdrawn from `odhcpd`, and the global-scope IPv6 prefix on
`br-lan` is removed. The LAN reverts to the state it was in before
you ran `service fips-gateway start` in Step 3.

The daemon and the rest of `/etc/fips/` are untouched. Existing mesh
peering on the AP itself continues to work.

## What you've learned

- **The gateway is a niche feature for a niche box.** Most FIPS
  hosts run the daemon and reach the mesh directly. The gateway
  exists so an AP can fold an entire unmodified LAN behind it into
  the mesh in one place.
- **Two halves of the same binary.** Outbound mode hands LAN clients
  virtual IPs and NATs them onto the mesh; inbound mode listens on
  `fips0` and forwards to LAN targets. They share one nftables
  table, one control socket, and one config block, but each half
  has its own use case.
- **OpenWrt does the LAN-side glue for you.** The init script
  reconfigures dnsmasq, installs the RA route, adds the global IPv6
  prefix, and loads sysctls. On a non-OpenWrt host that integration
  is manual — see [../how-to/deploy-gateway.md](../how-to/deploy-gateway.md).
- **Inbound forwards stay manual on every distro.** The
  `port_forwards[]` block is uniform across hosts, and on every
  distro you still own the decision of which LAN target to expose
  and on which mesh-side port.
- **The mesh firewall is a separate decision.** Opening a port
  forward on the gateway side does not open it on the firewall
  side; if `fips-firewall.service` is enabled, you still need a
  drop-in that admits the listen port.

## Troubleshooting

If something doesn't work as described above, the operator-recipe
guide [../how-to/troubleshoot-gateway.md](../how-to/troubleshoot-gateway.md)
groups the common failures by symptom:

| Symptom | Where to look |
| ------- | ------------- |
| LAN client gets `fd97:...`, not `fd01:...` | DNS path: dnsmasq still pointing at port 5354. See "DNS queries fail". |
| `dig` succeeds with a pool address but `ping6` times out | Pool route or proxy NDP. See "Virtual IP unreachable from client". |
| `ping6` works but TCP times out | NAT pipeline or mesh-side firewall. See "Ping works but TCP does not". |
| Gateway service won't start | "No gateway section in configuration" recipe. |
| Inbound `curl` hits the listen port but never reaches the LAN target | Mesh-side firewall first, then the port-forward rule. |

The first thing the troubleshoot guide does in any of these cases is
ask the gateway directly via `show_gateway` and `show_mappings`. If
the mapping you expect is not there, the failure is on the DNS path;
if it is there in `state: Active` but traffic still fails, the
failure is downstream.

## What's next

- [../how-to/deploy-gateway.md](../how-to/deploy-gateway.md) —
  Manual deployment on a non-OpenWrt Linux host. Same gateway,
  same config, but you wire up dnsmasq/Unbound/etc. yourself,
  install a pool route per LAN client (or via your own RA daemon),
  and manage the systemd unit instead of the procd init script.
- [../design/fips-gateway.md](../design/fips-gateway.md) — The
  design doc: NAT pipeline (DNAT, SNAT, masquerade, inbound DNAT),
  virtual-IP pool lifecycle (Allocated -> Active -> Draining ->
  reclaimed), DNS resolution flow, conntrack integration.
- [../reference/configuration.md § Gateway](../reference/configuration.md#gateway-gateway)
  — Every field of the `gateway:` block, including the conntrack
  timeout overrides not used in this tutorial.
- [../reference/cli-fips-gateway.md](../reference/cli-fips-gateway.md)
  — The `fips-gateway` binary's CLI options, exit codes, and
  environment variables.
