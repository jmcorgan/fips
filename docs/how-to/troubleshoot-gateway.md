# Troubleshoot `fips-gateway`

Diagnostic recipes for `fips-gateway`, grouped by which half of the
gateway is failing. For gateway design and deployment, see
[../design/fips-gateway.md](../design/fips-gateway.md) and
[deploy-gateway.md](deploy-gateway.md). For OpenWrt-specific
deployment problems, see the
[OpenWrt deployment tutorial](../tutorials/deploy-fips-gateway.md);
most of the recipes below apply on OpenWrt as well, but paths and
service names differ.

## Inspect gateway state via the control socket

Before digging into nftables or conntrack, ask the gateway directly
whether it has the mapping or session you expect. `fips-gateway`
exposes a separate control socket (`/run/fips/gateway.sock`) with its
own command set; there is no `fipsctl gateway` subcommand — talk to
the socket directly with `nc -U`. Each request is a single line of
JSON terminated with a newline; the connection is closed after one
response.

Pool summary, listen address, NAT counters, uptime, and the loaded
config snapshot:

```sh
echo '{"command":"show_gateway"}' | sudo nc -U /run/fips/gateway.sock
```

Per-mapping virtual-IP state (allocated, active, draining):

```sh
echo '{"command":"show_mappings"}' | sudo nc -U /run/fips/gateway.sock
```

If either command returns `gateway not yet initialized`, the gateway
is still in early startup; wait a moment and retry. If a mapping you
expect is not in the list, the DNS path didn't allocate it — fall
through to the outbound DNS recipes below. If the mapping exists in
`state: Active` but mesh traffic still fails, the problem is
downstream of the allocation (firewall, route, masquerade); see the
recipes that follow.

For the full command catalog and JSON shapes, see
[../reference/control-socket.md#gateway-command-catalog](../reference/control-socket.md#gateway-command-catalog).

## Common (either-half) issues

These break both halves at once because they affect the gateway
process itself or the shared NAT machinery.

### "No gateway section in configuration"

`fips-gateway` is normally launched by the systemd unit shipped with
the package:

```sh
sudo systemctl restart fips-gateway
sudo journalctl -u fips-gateway -e
```

The unit reads the standard FIPS config search paths (typically
`/etc/fips/fips.yaml`). If the unit logs "no gateway section in
configuration" or "Gateway section exists but is not enabled", confirm
the section is present and `enabled: true`:

```sh
grep -A1 '^gateway:' /etc/fips/fips.yaml
```

For one-off debugging outside systemd, run the binary directly and
point it at a specific config file:

```sh
sudo fips-gateway --config /etc/fips/fips.yaml --log-level debug
```

This is useful to capture stderr in a terminal, but the systemd unit
is the supported entry point in production. See
[../reference/cli-fips-gateway.md](../reference/cli-fips-gateway.md)
for the full flag list.

### Port conflict on the DNS listen port

Symptom: gateway fails to start with "address already in use" on
the configured `gateway.dns.listen` address.

The default `[::1]:5353` is loopback-only on an unprivileged port and
should not collide with any standard resolver. If you have overridden
`dns.listen` to bind port 53 (or a LAN-side address) and another DNS
server (systemd-resolved, dnsmasq, BIND) is already bound there,
identify it:

```sh
sudo ss -tulnp | grep ':53'
```

Two options:

- **Stay on the loopback default.** Drop the override and let the
  gateway use `[::1]:5353`. Configure the existing resolver to
  forward `.fips` queries to it (the canonical OpenWrt deployment
  works this way out of the box).

- **Relocate the conflicting resolver.** Move it to a different port
  (or disable it if not needed) and let the gateway bind 53.
  Practical for systemd-resolved (set `DNSStubListener=no` in
  `/etc/systemd/resolved.conf`); rarely worth it for production
  resolvers.

### IPv6 forwarding disabled

Symptom: gateway exits at startup with
"IPv6 forwarding is disabled. Enable with: sysctl -w
net.ipv6.conf.all.forwarding=1".

The gateway is completely non-functional without forwarding — packets
cannot traverse the NAT pipeline. Enable it:

```sh
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

Persist via the drop-in shown in
[deploy-gateway.md](deploy-gateway.md#kernel-sysctls). The same
section lists `proxy_ndp`, which is also required for the outbound
half.

### nftables table missing or not loaded

Symptom: `show_gateway` reports an active gateway but
`nft list table inet fips_gateway` errors with "No such file or
directory".

The table is created by the gateway at startup and rebuilt atomically
on every mapping change and on every `set_port_forwards` call. If the
table is missing while the gateway claims to be running, something
else (a host firewall script, a `nft flush ruleset` from another
service) deleted it after creation. Restart the gateway to recreate
it:

```sh
sudo systemctl restart fips-gateway
```

If a peer service is repeatedly clobbering the table, switch that
service to use `add table` / `flush table <name>` for its own table
rather than `flush ruleset`, which destroys every table on the host.

### Control socket permission errors

Symptom: `nc -U /run/fips/gateway.sock` fails with "Permission
denied" or "No such file or directory".

The socket is owned by root with mode `0770` (group `fips`). Either
run `nc` as root (`sudo nc -U ...`) or add your user to the `fips`
group and re-login. If the file does not exist at all, the gateway
either failed to start (check `journalctl -u fips-gateway`) or
failed to bind the socket and continued without it (the warning
`Failed to bind gateway control socket — continuing without it` is
in the journal in that case).

## Outbound-half diagnostics

Symptoms in this section all involve a LAN client trying to reach a
mesh destination through the gateway and failing.

### DNS queries fail

Symptom: LAN clients get `SERVFAIL` or no response when querying
`.fips` names; or the gateway log shows DNS upstream timeouts.

**Step 1.** Verify the daemon resolver is running and reachable from
the gateway host:

```sh
dig @::1 -p 5354 hostname.fips AAAA
```

If this returns no answer or fails, the FIPS daemon's DNS resolver is
not running or not enabled. Check that the daemon config has
`dns.enabled: true` (the default) and the daemon is healthy:
`fipsctl show status`.

**Step 2.** Verify the gateway is listening on its DNS port:

```sh
sudo ss -tulnp | grep -E ':(53|5353)\b'
```

If nothing is listening on the configured `dns.listen` address, the
gateway either failed to start or is bound to a different address.
Check the gateway log: `sudo journalctl -u fips-gateway -e`.

**Step 3.** Verify the LAN client can reach the gateway's DNS port:

```sh
# from the LAN client
dig @<gateway-lan-addr> hostname.fips AAAA
```

If this hangs, the LAN-side firewall is blocking DNS, or the LAN
route to the gateway is missing.

### Ping works but TCP does not

Symptom: `ping6 <virtual-ip>` succeeds from a LAN client, but TCP
connections (SSH, HTTP) hang or time out.

This usually means the `fips0`-side masquerade rule is missing or
misconfigured. Inspect the gateway's nftables table:

```sh
sudo nft list table inet fips_gateway
```

In the `postrouting` chain, look for a rule matching
`oifname "fips0"` with a `masquerade` verdict. Without masquerade,
the destination mesh node sees a source address (from the virtual
pool) it cannot route replies to, and return packets are
black-holed.

If the rule is missing, restart the gateway — the table is rebuilt
atomically on every mapping change and on startup.

### Connection timeout to a virtual IP

Symptom: any traffic to a virtual pool address times out, including
ping.

**Step 1.** Verify IPv6 forwarding is still enabled:

```sh
sysctl net.ipv6.conf.all.forwarding
# Expect: net.ipv6.conf.all.forwarding = 1
```

**Step 2.** Verify the pool route exists:

```sh
ip -6 route show table local | grep <pool-cidr>
```

If the route is missing, the kernel does not recognize pool
addresses as locally-owned and drops the packets before NAT can
process them. The gateway adds this route at startup; if it's
missing, check the gateway log for startup errors.

**Step 3.** Verify the destination mesh address actually exists in
the FIPS daemon's identity cache:

```sh
fipsctl show identity-cache | grep <fd00-mesh-addr>
```

If the entry is missing, the DNS-side mapping never primed the
identity cache, which means the daemon resolver did not actually
resolve the `.fips` name. Re-test the DNS path:

```sh
dig @::1 -p 5354 hostname.fips AAAA
```

### Virtual IP unreachable from a LAN client

Symptom: client cannot reach the virtual IP at all (no ping, no
ARP/ND response).

**Step 1.** Verify the client has a route to the pool via the
gateway:

```sh
# from the LAN client
ip -6 route get <virtual-ip>
```

The output should show the gateway as the next-hop. If it shows
something else (or "unreachable"), fix the LAN-side route — see
[deploy-gateway.md](deploy-gateway.md#distribute-the-route-to-lan-clients).

**Step 2.** On the gateway, verify proxy NDP entries exist for
allocated virtual IPs:

```sh
ip -6 neigh show proxy
```

If proxy NDP entries are missing, the gateway cannot answer Neighbor
Solicitation requests for virtual IPs on the LAN, so clients cannot
resolve the link-layer address and packets never leave the client's
NIC.

The gateway adds these entries when a mapping is created (i.e., when
a `.fips` DNS query allocates a virtual IP). If they're absent,
trigger a DNS query first:

```sh
dig @<gateway-lan-addr> hostname.fips AAAA
```

Then re-check `ip -6 neigh show proxy`.

**Step 3.** Verify `proxy_ndp` is enabled in the kernel:

```sh
sysctl net.ipv6.conf.all.proxy_ndp
# Expect: net.ipv6.conf.all.proxy_ndp = 1
```

If 0, enable it (see
[deploy-gateway.md](deploy-gateway.md#kernel-sysctls)).

## Inbound-half diagnostics

Symptoms in this section all involve a mesh peer trying to reach a
LAN-side service through the gateway and failing.

### Mesh peer can't reach `<gateway-npub>.fips:<listen_port>`

Walk the path from the mesh-side ingress to the LAN target:

**Step 1.** Verify the port-forward rule is loaded. On the gateway:

```sh
sudo nft list table inet fips_gateway
```

Look in the `prerouting` chain for a rule of the form

```text
iif "fips0" meta nfproto ipv6 meta l4proto <tcp|udp> \
    <th> dport <listen_port> dnat ip6 to [<target_addr>]:<target_port>
```

and, in the `postrouting` chain, a rule of the form

```text
iif "fips0" oif "<lan_interface>" meta nfproto ipv6 masquerade
```

The port-forward DNAT and the LAN-side masquerade come from
`gateway.port_forwards[]` and the active `lan_interface` setting.
The masquerade is emitted only when at least one port-forward exists.
If either rule is missing, restart the gateway — the table is rebuilt
atomically on config load.

**Step 2.** Verify the mesh firewall is not blocking the listen
port. If `fips-firewall.service` is enabled, the default baseline
drops everything inbound on `fips0` except established/related and
ICMPv6. Add an explicit allow rule under `/etc/fips/fips.d/`:

```nft
# /etc/fips/fips.d/gateway-inbound.nft
tcp dport <listen_port> accept
```

(See [enable-mesh-firewall.md](enable-mesh-firewall.md) for the
full drop-in pattern, including source-address restrictions.)
Without an allow rule, mesh peers see TCP RSTs (the firewall drops
on the way in) or silent UDP loss.

**Step 3.** Verify the LAN target is reachable from the gateway
itself:

```sh
ping6 <target_addr>
curl -v http://[<target_addr>]:<target_port>/   # for TCP HTTP
```

If the target is unreachable from the gateway, the DNAT rule will
fire but the inner connection attempt will fail. Fix LAN-side
routing or the target service before going further.

**Step 4.** Verify conntrack is tracking the inbound flow. Try the
connection from a mesh peer once:

```sh
curl -v http://<gateway-npub>.fips:<listen_port>/
```

Then on the gateway:

```sh
sudo conntrack -L | grep -E '<listen_port>|<target_port>'
```

You should see a flow tuple in both directions (orig and reply) with
the mesh peer's source on `fips0` and the gateway's LAN address as
the masqueraded source on the LAN side. No conntrack entry suggests
the prerouting DNAT didn't match — recheck step 1.

**Step 5.** Check the gateway log for nftables or rule install
errors:

```sh
sudo journalctl -u fips-gateway -e | grep -E 'port_forward|nftables'
```

A "Failed to install port-forward rules" log line at startup means
the rule batch was rejected by netlink — usually a transient
condition during a config edit, but persistent failures warrant
inspecting the rule with `nft -d`.

### Config rejected: IPv4 target

Symptom: `fips-gateway` exits at startup with a deserialization
error referencing `port_forwards[N].target` and an invalid IPv6
literal.

The `target` field is typed as `SocketAddrV6` and rejects IPv4
literals at parse time:

```yaml
# fails at config load
- listen_port: 8080
  proto: tcp
  target: "192.168.1.10:80"
```

Either re-address the LAN service to be reachable on IPv6, or front
it with a small IPv6-aware reverse proxy on the gateway and point
the `target` at that proxy.

### Config rejected: zero or duplicate listen_port

Symptom: `fips-gateway` exits at startup with
"Invalid gateway.port_forwards: …".

`validate_port_forwards()` enforces:

- `listen_port` must be non-zero.
- The pair `(listen_port, proto)` must be unique across the list
  (the same port on TCP and UDP simultaneously is allowed; the same
  port twice on the same proto is not).

Fix the offending entry and reload.

## See also

- [../tutorials/deploy-fips-gateway.md](../tutorials/deploy-fips-gateway.md) —
  canonical OpenWrt deployment.
- [../design/fips-gateway.md](../design/fips-gateway.md) — gateway
  design, NAT pipeline, virtual IP pool lifecycle, security
  considerations.
- [deploy-gateway.md](deploy-gateway.md) — manual Linux-host setup.
- [Gateway section](../reference/configuration.md#gateway-gateway) of
  the configuration reference — full `gateway.*` block.
- [../reference/cli-fips-gateway.md](../reference/cli-fips-gateway.md) —
  `fips-gateway` binary CLI flags.
- [Gateway command catalog](../reference/control-socket.md#gateway-command-catalog)
  in the control-socket reference — JSON schema for `show_gateway`
  and `show_mappings`.
- [enable-mesh-firewall.md](enable-mesh-firewall.md) — mesh-firewall
  baseline and drop-ins.
