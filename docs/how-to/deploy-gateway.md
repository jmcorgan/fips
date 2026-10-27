# Deploy `fips-gateway` (Manual Linux-Host Setup)

`fips-gateway` is a separate service that runs alongside the FIPS
daemon and bridges a non-FIPS LAN to the FIPS mesh in two
independent directions: **outbound** (LAN clients reach mesh
services through DNS proxy + virtual-IP NAT) and **inbound** (mesh
peers reach LAN services through 1:1 port forwards on `fips0`).
This guide covers the **manual Linux-host** deployment path —
wiring DNS forwarding, route distribution, and firewall integration
on a server or non-OpenWrt router by hand.

> **Running OpenWrt?** Use the
> [tutorial](../tutorials/deploy-fips-gateway.md) instead. The OpenWrt
> ipk ships with the `gateway:` block pre-populated and the init
> script automates dnsmasq forwarding, RA route distribution, and the
> global IPv6 prefix on `br-lan`. The OpenWrt path is the canonical
> deployment of this feature; this how-to is the secondary path for
> operators with a different LAN-edge box (a Linux server already
> serving DHCP/DNS, a custom router distribution, etc.).

For the gateway design (NAT pipeline, virtual IP pool lifecycle, DNS
resolution flow), see [../design/fips-gateway.md](../design/fips-gateway.md).
For the full `gateway.*` configuration block, see the
[Gateway section](../reference/configuration.md#gateway-gateway) of
the configuration reference. For the `fips-gateway` binary's CLI
flags, see [../reference/cli-fips-gateway.md](../reference/cli-fips-gateway.md).

## The two halves

The gateway exposes two independent features that share a common
control plane (the same binary, the same nftables table `inet
fips_gateway`, the same control socket `/run/fips/gateway.sock`, the
same `gateway.*` config block). You can configure either half on its
own or both together.

- **Outbound gateway** (LAN → mesh). Non-FIPS LAN workstations resolve
  `<npub>.fips` names against the gateway's DNS listener and receive
  AAAA answers from the gateway's virtual-IP pool. Outbound traffic
  to those addresses is DNAT'd to the real mesh address and SNAT'd
  (masqueraded) onto `fips0` under the gateway's mesh identity. The
  audience is unmodified LAN clients.

- **Inbound gateway** (mesh → LAN). A static `(listen_port, proto)
  → [target_addr]:target_port` table — configured in
  `gateway.port_forwards[]` — exposes selected LAN services to the
  mesh as `<gateway-npub>.fips:<listen_port>`. Mesh peers connect to
  the gateway's mesh address; the gateway DNATs to the LAN target
  and masquerades on the LAN side so return traffic flows through
  conntrack. The audience is mesh peers reaching a service that
  happens to live on this LAN.

The two halves are independent. Configure the outbound half if you
want LAN clients to *reach* the mesh; configure the inbound half if
you want mesh peers to *reach into* the LAN; configure both if you
want both.

## Common gateway-host setup

Both halves require the same host preparation. Work through this
section first, then jump to whichever half (or both) you need.

### FIPS daemon prerequisites

The gateway runs alongside a `fips` daemon on the same host:

- The daemon must be running with the TUN adapter enabled (the
  interface `tun.name` names, `fips0` by default, must exist). The
  gateway takes the name from `tun.name` in the configuration it
  loads, so point the two at the same file.
- The daemon's DNS resolver must be enabled (`dns.enabled: true`,
  default) and reachable from `fips-gateway`. By default that means
  `[::1]:5354` (IPv6 loopback). The gateway's default
  `dns.upstream` matches this; a v4 upstream like `127.0.0.1:5354`
  cannot reach a daemon bound on `[::1]:5354` because Linux IPv6
  sockets bound to explicit `::1` do not accept v4-mapped traffic.

If the daemon is not yet running with these features, set up the
daemon first — see [persistent-identity.md](persistent-identity.md)
and [../reference/configuration.md](../reference/configuration.md).

### Kernel sysctls

```sh
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.proxy_ndp=1
```

`forwarding` lets the host route IPv6 packets between the LAN
interface and `fips0`. `proxy_ndp` lets the gateway answer Neighbor
Solicitation requests for virtual-pool addresses so LAN clients can
resolve their link-layer addresses (only relevant for the outbound
half, but harmless if you only run the inbound half).

Persist via a drop-in:

```sh
sudo tee /etc/sysctl.d/60-fips-gateway.conf <<'EOF'
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.all.proxy_ndp = 1
EOF
sudo sysctl --system
```

### Capability

`fips-gateway` requires `CAP_NET_ADMIN` to manage its nftables table
(`inet fips_gateway`) and proxy-NDP entries. The packaged systemd
unit (`fips-gateway.service`) runs as root, which satisfies this. For
non-package installs, set the file capability:

```sh
sudo setcap cap_net_admin+ep /usr/bin/fips-gateway
```

### Pool route

At startup `fips-gateway` adds `local <pool-cidr> dev lo` to the
local routing table. This tells the kernel to accept packets
destined for pool addresses as locally-owned, enabling the NAT
processing path. The route is cleaned up on shutdown. You do not
need to install it manually; if you see "destination unreachable"
errors for pool addresses on the gateway host, verify the route is
present:

```sh
ip -6 route show table local | grep <pool-cidr>
```

### Minimum configuration

In `/etc/fips/fips.yaml`, populate the `gateway` block with at minimum
`enabled: true`, `pool`, and `lan_interface`:

```yaml
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: "enp3s0"
```

Pick a pool CIDR that does **not** overlap with any address space in
use on the LAN. The gateway routes the whole prefix to itself, so a
name whose mesh address (in `fd00::/8`) lies inside it cannot be
reached and gets `SERVFAIL`; a `/112` makes that vanishingly unlikely.
The `/112` size yields 65 535 usable
addresses, the most the pool uses whatever the CIDR width. The
gateway holds at most 1000 live mappings at once and admits new
names at up to 10 per second after a burst of 50. At 1000 live
mappings, a new name replaces the oldest mapping that has never
carried traffic, and gets `SERVFAIL` only when every mapping has
carried traffic; a new name beyond the rate limit gets `SERVFAIL`.

This minimum config is enough to start the gateway. The `dns.*` block
is optional and defaults to `listen: "[::1]:5365"` and
`upstream: "[::1]:5354"`. The full block — including `dns.*`,
`pool_grace_period`, `conntrack.*`, and `port_forwards[]` — is
documented in
[../reference/configuration.md#gateway-gateway](../reference/configuration.md#gateway-gateway).

### Start the service

```sh
sudo systemctl enable --now fips-gateway
```

Verify the unit came up:

```sh
sudo systemctl status fips-gateway
sudo journalctl -u fips-gateway -e
```

The startup log will report `Gateway config loaded`,
`DNS upstream is reachable`, `Created nftables table 'fips_gateway'`,
and finally `fips-gateway running`. The gateway itself waits up to
30 s for the TUN named by `tun.name` to appear, which covers the
cold-boot race where the daemon is still bringing up its TUN.

## Configure the outbound half

The outbound half lets LAN clients resolve `.fips` names and reach
mesh destinations. Three operator decisions are involved: pool CIDR,
DNS listen address, and how LAN clients learn the route to the pool
and the resolver address.

### Choose the pool CIDR

```yaml
gateway:
  pool: "fd01::/112"
```

Constraints:

- Must not overlap with any LAN-side IPv6 prefix already in use.
- A name whose mesh address (in `fd00::/8`) lies inside the pool
  prefix gets `SERVFAIL`, since the gateway routes the whole prefix to
  itself; a `/112` makes that vanishingly unlikely.
- `/112` is the practical width — wider just wastes address space
  because the pool never uses more than 65 535 addresses. Narrower is
  fine if you want a smaller pool; one narrower than `/118` (1023
  usable addresses) runs out before the 1000-mapping ceiling is
  reached, and one smaller than 1000 + 10 x (TTL + grace) addresses
  (2,200 at the defaults, so any pool narrower than a `/116`) can be
  exhausted by one LAN host naming new names; the gateway warns at
  start. After a crash or a kill (not a clean stop or restart), a pool
  with fewer than 512 free addresses (a `/119` or narrower, or a `/118`
  with more than about 500 addresses in use) refuses every new name for
  the DNS TTL plus the grace period, 2 minutes at the defaults, while it
  waits out answers the previous run may have given.

### Choose the DNS listen address

```yaml
gateway:
  dns:
    listen: "[::1]:5365"
    upstream: "[::1]:5354"
    ttl: 60
```

Common cases:

- **Another resolver on the host (the canonical case):** the default
  `listen: "[::1]:5365"` is loopback-only on an unprivileged port,
  so it never conflicts with dnsmasq, systemd-resolved, or BIND
  holding 53. Configure the existing resolver to forward `.fips`
  queries to `[::1]:5365` and you are done — this is what the
  OpenWrt ipk does automatically. On OpenWrt the init script reads
  `gateway.dns.listen` and points dnsmasq at whatever port it sets.
- **No other resolver on the host:** set `listen: "[::]:53"`
  explicitly and LAN clients can query the gateway directly. Queries
  that arrive on `fips0` are not answered, so a wildcard listen does
  not serve the mesh; this includes a local resolver that forwards to
  the gateway's `fips0` address, so forward to loopback or a LAN
  address instead.
- **systemd-resolved is on port 53:** the default already side-steps
  this — leave the listen address at `[::1]:5365` and configure the
  stub or a small forwarder to delegate `.fips` to the gateway. If
  you would rather have the gateway on 53 directly, disable the
  systemd stub listener (`DNSStubListener=no` in
  `/etc/systemd/resolved.conf`) and switch `listen` to `"[::]:53"`.
  See
  [troubleshoot-gateway.md](troubleshoot-gateway.md#port-conflict-on-the-dns-listen-port).
- **Bind on the LAN address only:** `listen: "192.168.1.1:53"`
  exposes the resolver only to LAN clients, not loopback.

The gateway returns `REFUSED` for any non-`.fips` query — clients
that point at it directly need a fallback resolver, or you should
front it with a stub forwarder.

### Distribute the route to LAN clients

Each LAN client must route the gateway's pool CIDR to the gateway's
LAN-side IPv6 address. Three options, in order of preference for
production:

- **RA Route Information Option** (RFC 4191). If the LAN's RA daemon
  (`radvd`, `dnsmasq --enable-ra`, OpenWrt's `odhcpd`) supports
  publishing route options, configure it to advertise the pool CIDR
  with the gateway as next-hop. Clients pick this up automatically.

- **Static route on the LAN router**. If clients route through a
  central LAN router, add a static route entry there — the router
  then handles forwarding to the gateway. The exact syntax depends
  on the router OS.

- **Per-host static route** (testing or single-client deployments):

  ```sh
  sudo ip -6 route add fd01::/112 via fe80::<gateway-link-local>%<iface>
  # or, if the gateway has a stable global LAN address:
  sudo ip -6 route add fd01::/112 via <gateway-lan-addr>
  ```

### Distribute the resolver to LAN clients

LAN clients also need to send `.fips` queries to the gateway. Two
patterns:

- **Forward `.fips` from the LAN's main resolver.** If the LAN runs
  Pi-hole, Unbound, dnsmasq, or systemd-resolved as the central
  resolver, configure a conditional forward for `fips.`. Unbound
  example:

  ```text
  forward-zone:
      name: "fips."
      forward-addr: <gateway-lan-addr>@53
  ```

  dnsmasq example:

  ```text
  server=/fips/<gateway-lan-addr>
  ```

  Clients keep their existing DNS settings; only `.fips` queries are
  diverted.

- **Point clients directly at the gateway.** Simpler for testing,
  but the gateway returns `REFUSED` for non-`.fips` queries, so each
  client must also have a fallback resolver configured.

### Verify the outbound path

From a LAN client:

```sh
dig @<gateway-lan-addr> hostname.fips AAAA
# Expect an AAAA from the pool CIDR

ping6 hostname.fips
# Should succeed via the gateway
```

If either step fails, see
[troubleshoot-gateway.md](troubleshoot-gateway.md#outbound-half-diagnostics).

## Configure the inbound half

The inbound half exposes a LAN-side service to mesh peers. Configured
under `gateway.port_forwards[]`:

```yaml
gateway:
  port_forwards:
    - listen_port: 8080
      proto: tcp
      target: "[fd12:3456::10]:80"
    - listen_port: 2222
      proto: tcp
      target: "[fd12:3456::20]:22"
    - listen_port: 5353
      proto: udp
      target: "[fd12:3456::10]:53"
```

Field reference:

- `listen_port` — port on the gateway's `fips0` mesh-side address
  that mesh peers connect to. Must be non-zero. Each
  `(listen_port, proto)` pair must be unique across the list (the
  same port on TCP and UDP is allowed; the same port twice on the
  same proto is rejected at config-load time).
- `proto` — `tcp` or `udp`.
- `target` — IPv6 LAN destination as `[addr]:port`. IPv4 targets are
  rejected at parse time by the YAML deserializer (the field is
  typed `SocketAddrV6`). If the LAN host is reachable only by IPv4,
  put a small IPv6-aware reverse proxy in front of it on the gateway
  itself.

### Worked example: HTTP and DNS

Suppose the gateway runs on a LAN with an HTTP server at
`[fd12:3456::10]:80` and a recursive resolver at
`[fd12:3456::10]:53`, and you want mesh peers to reach them as
`<gateway-npub>.fips:8080` (HTTP) and `<gateway-npub>.fips:5353`
(DNS). Add to the gateway's `fips.yaml`:

```yaml
gateway:
  port_forwards:
    - listen_port: 8080
      proto: tcp
      target: "[fd12:3456::10]:80"
    - listen_port: 5353
      proto: udp
      target: "[fd12:3456::10]:53"
```

Reload:

```sh
sudo systemctl restart fips-gateway
```

From any mesh peer (the host name `gateway` is whatever the gateway's
npub maps to in the local `hosts` file or via Nostr advert):

```sh
curl http://gateway.fips:8080/
dig @gateway.fips -p 5353 example.com A
```

Each mesh-side request enters `fips0` on the listen port, gets DNAT'd
to the LAN target, and the LAN-side masquerade rule rewrites the
source to the gateway's LAN address so return traffic flows back
through conntrack.

### Compose with the mesh firewall

The mesh firewall baseline (`/etc/fips/fips.nft`, see
[enable-mesh-firewall.md](enable-mesh-firewall.md)) has two chains. Its
`inbound` chain, on the `input` hook, polices traffic addressed to the
gateway itself, and the drop-ins under `/etc/fips/fips.d/*.nft` are
included there. A port forward never reaches it: the gateway rewrites a
forwarded connection's destination to the LAN target in its `prerouting`
chain, so the kernel routes the packet through the `forward` hook to the
LAN. The baseline's `forward` chain sees it there, and accepts every
port-forwarded connection from the mesh unless a drop-in under
`/etc/fips/fips.d/forward/` refuses it. With the baseline loaded and no
forward drop-in, every mesh node that can reach the gateway can reach
every configured port forward, and a `fips.d/*.nft` rule such as
`ip6 saddr <addr> tcp dport 8080 accept` has no effect on it.

To restrict who can use a port forward, add a file ending in `.nft` to
`/etc/fips/fips.d/forward/` (create the directory if it is missing). Its
lines are included into the `forward` chain after replies are accepted
and before port-forwarded connections are. For each forward you
restrict, write one line that accepts the nodes allowed to use it and one
that drops everyone else. For the worked example above, allowing one
mesh node to use both forwards:

```nft
# /etc/fips/fips.d/forward/port-forwards.nft
# Rules see the packet after the gateway rewrote its destination: match the
# target address and port, not listen_port. Replace the example mesh address
# with the allowed node's; `fipsctl address` on that node prints it.
ip6 daddr fd12:3456::10 tcp dport 80 ip6 saddr { fd97:1111:2222:3333:4444:5555:6666:7777 } accept
ip6 daddr fd12:3456::10 tcp dport 80 counter drop
ip6 daddr fd12:3456::10 udp dport 53 ip6 saddr { fd97:1111:2222:3333:4444:5555:6666:7777 } accept
ip6 daddr fd12:3456::10 udp dport 53 counter drop
```

A forward with no lines stays open to the mesh. Keep each forward's
accept and drop lines in one file: the files are included in
alphabetical order and the first matching rule decides, so an accept in
a later file for a forward an earlier file already drops never matches.
Write addresses out rather than with `define`; every drop-in is read
into one ruleset, and two files that define the same name make the whole
load fail.

Reload the firewall to apply it:

```sh
sudo systemctl reload-or-restart fips-firewall.service
```

The drop counters show refused connections:

```sh
sudo nft list chain inet fips forward
```

A refused connection times out on the peer rather than being reset.
Connections from the mesh that the gateway did not translate, and LAN
clients' own connections out to the mesh and their replies, pass the
chain unchanged. A drop in any chain on the `forward` hook is final, so
the order of this table against the gateway's own `inet fips_gateway`
table does not matter.

Two cases from earlier releases. If you load a restriction table of your
own, such as `inet fips_port_forwards` from `/etc/fips/port-forwards.nft`
through a `fips-firewall.service` drop-in, it keeps working for the same
reason; to move to the packaged chain, write its accept rules in the
form above, then remove the service drop-in and delete that table. If
you kept an edited `/etc/fips/fips.nft` when upgrading, your file has no
`forward` chain and forward drop-ins are not loaded until you merge in
the packaged one; `sudo nft list chain inet fips forward` fails until
then.

On OpenWrt the packaged firewall zone already passes port forwards
through fw4's forward chain; restrict them there with a `src fips`
rule matching the target's port instead (see
`packaging/openwrt-ipk/README.md`).

### Verify the inbound path

From a mesh peer (any FIPS node):

```sh
curl -v http://<gateway-npub>.fips:8080/
```

A successful response confirms the full path: mesh ingress on
`fips0`, DNAT to the LAN target, LAN-side masquerade, and conntrack-
tracked return. If it fails, see
[troubleshoot-gateway.md](troubleshoot-gateway.md#inbound-half-diagnostics).

## Operate and verify

`fips-gateway` exposes its own control socket at
`/run/fips/gateway.sock`, separate from the daemon's
`/run/fips/control.sock`. There is no `fipsctl gateway` subcommand —
talk to it directly:

```sh
echo '{"command":"show_gateway"}' | sudo nc -U /run/fips/gateway.sock
echo '{"command":"show_mappings"}' | sudo nc -U /run/fips/gateway.sock
```

`show_gateway` returns pool counters (`pool_total`, `pool_allocated`,
`pool_active`, `pool_draining`, `pool_free`), `nat_mappings`,
`dns_listen`, `uptime_secs`, and the active config snapshot.
`show_mappings` returns the per-allocation list with virtual IP, mesh
address, npub-derived `node_addr`, dns name, state (`Allocated`,
`Active`, `Draining`), session count, and ages. For the full schema
see [../reference/control-socket.md#gateway-command-catalog](../reference/control-socket.md#gateway-command-catalog).

The journal is the other primary signal:

```sh
sudo systemctl status fips-gateway
sudo journalctl -u fips-gateway -e
```

Expect `MappingCreated`/`MappingRemoved` debug lines as DNS-driven
allocations come and go (run with `--log-level debug` to see them),
and `Final pool status` on shutdown. Errors in adding NAT rules or
proxy-NDP entries surface here.

## See also

- [../tutorials/deploy-fips-gateway.md](../tutorials/deploy-fips-gateway.md) —
  the canonical, package-driven OpenWrt deployment path.
- [../design/fips-gateway.md](../design/fips-gateway.md) — gateway
  design, NAT pipeline, virtual IP pool lifecycle, security
  considerations.
- [Gateway section](../reference/configuration.md#gateway-gateway) of
  the configuration reference — full `gateway.*` block.
- [../reference/cli-fips-gateway.md](../reference/cli-fips-gateway.md) —
  `fips-gateway` binary CLI flags.
- [Gateway command catalog](../reference/control-socket.md#gateway-command-catalog)
  in the control-socket reference — JSON schema for `show_gateway`
  and `show_mappings`.
- [troubleshoot-gateway.md](troubleshoot-gateway.md) — diagnostic
  recipes grouped by half.
- [enable-mesh-firewall.md](enable-mesh-firewall.md) — mesh-firewall
  baseline and drop-ins (needed when exposing inbound ports).
