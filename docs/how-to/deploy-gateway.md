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
  `fips0` interface must exist).
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
use on the LAN or in the mesh (the FIPS mesh occupies `fd00::/8`;
pick a different `fdXX::/N`). The `/112` size yields 65 536 virtual
IPs, which is the gateway's hard cap regardless of CIDR width.

This minimum config is enough to start the gateway. The `dns.*` block
is optional and defaults to `listen: "[::]:53"` and
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
and finally `fips-gateway running`. The unit's `ExecStartPre` waits up
to 30 s for `fips0` to appear, which covers the cold-boot race where
the daemon is still bringing up its TUN.

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

- Must not overlap with `fd00::/8` (the FIPS mesh address space).
- Must not overlap with any LAN-side IPv6 prefix already in use.
- `/112` is the practical width — wider just wastes address space
  because the pool is hard-capped at 65 536 entries. Narrower is
  fine if you want a smaller pool, but you'll reject DNS lookups
  faster under churn.

### Choose the DNS listen address

```yaml
gateway:
  dns:
    listen: "[::]:53"
    upstream: "[::1]:5354"
    ttl: 60
```

Common cases:

- **No other resolver on the host:** `listen: "[::]:53"` is the
  default and works.
- **systemd-resolved is on port 53:** either disable its stub
  listener (`DNSStubListener=no` in
  `/etc/systemd/resolved.conf`) or move the gateway to a different
  port (e.g., `[::]:5353`) and put a forwarder on 53 that delegates
  `.fips` to the gateway. See
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

`gateway.port_forwards[]` opens *mesh-side* listeners on `fips0`. If
the host's mesh firewall is enabled (see
[enable-mesh-firewall.md](enable-mesh-firewall.md)), inbound TCP/UDP
on `fips0` for these ports must be permitted in the baseline or via
a drop-in. The default baseline allows established/related and
ICMPv6 only, so without an explicit allow rule, mesh peers will see
TCP RSTs or silent drops on the listen port.

A typical drop-in for the worked example:

```nft
# /etc/fips/fips.d/gateway-inbound.nft
tcp dport 8080 accept
udp dport 5353 accept
```

Reload the firewall:

```sh
sudo systemctl reload-or-restart fips-firewall.service
```

If the inbound half doesn't need access control beyond the listen
port itself, no source filter is needed. To restrict to specific
mesh peers, follow the `ip6 saddr <addr> tcp dport <port> accept`
pattern from the firewall guide.

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
