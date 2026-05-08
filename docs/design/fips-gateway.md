# FIPS Gateway

The FIPS gateway lets unmodified IPv6 hosts on a LAN exchange traffic
with the mesh without running any FIPS software themselves. It is a
niche feature — most operators will never enable it. The gateway
runs most conveniently on a system that is already providing network
services (DHCP, DNS, RA) to a LAN segment, since hosts on that
segment already get IP assignment and a default route from that box.
The canonical example is an OpenWrt-based WiFi access point: every
client that associates with the AP already has the AP as default
router and DNS server, which is exactly the placement the gateway
needs. The OpenWrt ipk ships with the `gateway:` block of
`/etc/fips/fips.yaml` pre-populated and the integration glue
(dnsmasq forwarding, RA route for the virtual pool, global-scope
IPv6 prefix on `br-lan`) automated by the init script —
[`packaging/openwrt-ipk/files/etc/init.d/fips-gateway`](https://github.com/jmcorgan/fips/blob/master/packaging/openwrt-ipk/files/etc/init.d/fips-gateway).
The operator only needs to enable and start the service. Running the
gateway on a non-OpenWrt LAN-edge host (a Linux router/server, for
example) is technically possible but requires manual integration:
distributing a route to the virtual-IP pool, wiring DNS forwarding so
LAN clients send `.fips` queries to the gateway, configuring sysctls
and capabilities. That path is supported but tedious; it is the
secondary path.

The feature has two halves that share common machinery and have
their own unique parts.

The **outbound half** carries traffic from LAN to mesh. A non-FIPS
LAN workstation resolves `<npub>.fips` (or a `.fips` host alias) via
the gateway's DNS proxy, which returns a virtual IPv6 address from a
managed pool. The kernel routes the LAN packet to that virtual IP via
a route to the pool CIDR (RA-advertised, statically distributed, or
on-link via the default route). The gateway runs nftables NAT so the
packet appears on the mesh as if it had originated from the gateway's
own FIPS identity: prerouting DNAT rewrites the destination from the
virtual IP to the real `fd00::/8` mesh address, and postrouting
masquerade rewrites the source from the LAN host's address to the
gateway's `fips0` address. Return traffic follows the conntrack
reverse path back to the originating LAN host, with postrouting SNAT
restoring the virtual IP as source so the client sees a response from
the address it connected to.

The **inbound half** carries traffic from mesh to LAN. A
configuration entry in `gateway.port_forwards[]` exposes a LAN
service (`host:port`) on a port of the gateway's mesh-side `fips0`
address. Mesh peers reach it as `<gateway-npub>.fips:<listen_port>`.
A prerouting DNAT rule keyed on `(iif=fips0, l4proto, dport)`
rewrites the destination to the LAN target; a LAN-side masquerade in
postrouting rewrites the mesh peer's source so the LAN target sees a
reachable LAN address and conntrack steers replies back through the
gateway. This is the inverse of port-forwarding on a conventional NAT
router.

The two halves are independent and can be configured separately.
Inbound port-forwards work without any outbound configuration (just
a port-forward list and the table); outbound works without any
inbound forwards. They share the same nftables table, the same
binary, the same control socket, and the same atomic-rebuild
strategy. That shared machinery is what makes them halves of one
feature rather than two separate features.

## Architecture

### The `fips-gateway` Service

The gateway is a separate binary, [`fips-gateway`](https://github.com/jmcorgan/fips/blob/master/src/bin/fips-gateway.rs),
not part of the FIPS daemon. It reads the same `/etc/fips/fips.yaml`
the daemon reads (via `--config`, or the standard search path), but
acts on the `gateway.*` block. It needs `CAP_NET_ADMIN` to install
nftables rules, manage proxy NDP entries, and add the pool route.
The CLI is documented in
[../reference/cli-fips-gateway.md](../reference/cli-fips-gateway.md).

The gateway connects to the daemon indirectly. The outbound half
forwards `.fips` DNS queries to the daemon's built-in resolver
(default `[::1]:5354`); the daemon resolves the name to a mesh
address and primes its identity cache as a side effect. The inbound
half does not require any daemon plumbing at all — packets that
arrive on `fips0` after the daemon's TUN injection path are matched
by the nftables rules on `fips0` ingress. There is no shared memory,
no IPC channel, and no startup ordering coupling beyond "the daemon's
DNS responder must be reachable before the gateway starts serving
LAN queries", which the gateway enforces with a bounded reachability
probe at startup.

### nftables Table Layout

All gateway rules live in a single nftables table, `inet
fips_gateway`, with two chains:

- `prerouting` — `type nat hook prerouting priority dstnat (-100)`,
  for both LAN→mesh DNAT (per virtual-IP mapping) and mesh→LAN DNAT
  (per port-forward).
- `postrouting` — `type nat hook postrouting priority srcnat (100)`,
  for both the always-on `oifname fips0` masquerade, the per-mapping
  return-path SNAT, and (when any port-forward is configured) the
  LAN-side masquerade for inbound traffic.

The table is rebuilt atomically on every change. The rebuild
sequence — delete the existing table (ignore `ENOENT` on first
call), then create a new table with chains and the full rule set in
a single netlink batch — avoids reliance on kernel rule-handle
tracking, which the rustables crate does not expose. The table stays
small (one always-on masquerade plus two rules per active outbound
mapping plus one rule per inbound forward, with one extra masquerade
when any forward is present), so rebuilds are cheap.

### Control Socket

`fips-gateway` exposes a Unix-domain control socket at
`/run/fips/gateway.sock` (`root:fips`, mode `0770`) with two
commands: `show_gateway` and `show_mappings`. The protocol is the
same line-delimited JSON used by the daemon's control socket. The
shapes are documented in the
[Gateway command catalog](../reference/control-socket.md#gateway-command-catalog).
There is no `fipsctl gateway` subcommand; clients (including
`fipstop`'s gateway view) talk to the socket directly.

### Diagram

```text
                           LAN clients
                              │
        DNS query (.fips)     │     IPv6 packet
        for outbound          │     to virtual IP
                              │     or mesh peer
                              ▼
            ┌───────────────────────────────────┐
            │           fips-gateway            │
            │                                   │
            │  ┌──────────────┐  ┌───────────┐  │
            │  │   DNS proxy  │  │  Virtual  │  │
            │  │ ([::1]:5353) │─▶│  IP pool  │  │
            │  │   .fips only │  │ (state    │  │
            │  └──────┬───────┘  │  machine) │  │
            │         │          └─────┬─────┘  │
            │         │                │        │
            │  forward to              │ pool   │
            │  daemon resolver         │ events │
            │  ([::1]:5354)            ▼        │
            │         │          ┌───────────┐  │
            │         │          │   NAT     │  │
            │         │          │  manager  │  │
            │         │          │ (rebuild  │  │
            │         │          │  inet     │  │
            │         │          │  fips_    │  │
            │         │          │  gateway) │  │
            │         │          └─────┬─────┘  │
            │         │                │        │
            │         │          ┌─────▼─────┐  │
            │         │          │   net     │  │
            │         │          │  setup    │  │
            │         │          │ (proxy    │  │
            │         │          │  NDP, lo  │  │
            │         │          │  route)   │  │
            │         │          └───────────┘  │
            │         │                         │
            │         │   control socket        │
            │         │   /run/fips/            │
            │         │   gateway.sock          │
            └─────────┼─────────────────────────┘
                      │
                      ▼
              FIPS daemon resolver
              ([::1]:5354)
                      │
                      ▼
                fips0 TUN interface
                      │
                      ▼
                  the mesh
```

The DNS proxy and the virtual IP pool are exclusive to the outbound
half. The NAT manager and the kernel-side machinery (nftables table,
`fips0` and LAN interfaces, conntrack) are shared. The inbound half
contributes per-port-forward rules to the same table without
involving the DNS proxy or the pool.

## The Outbound Half (LAN → Mesh)

### DNS Resolution Flow

1. A LAN client sends a DNS query to the gateway's listener (default
   `[::1]:5353`, configurable via `gateway.dns.listen`). The default
   is loopback-only on an unprivileged port: the canonical deployment
   has another resolver on the host (dnsmasq, systemd-resolved, BIND)
   holding port 53 and forwarding `.fips` queries to the gateway over
   loopback. Operators on a host without a pre-existing resolver on
   53 can override the listen value to `"[::]:53"` to let LAN clients
   query the gateway directly.
2. If the question is not for a `.fips` domain, the gateway replies
   `REFUSED`. The proxy is intentionally narrow — it does not resolve
   public DNS, and the LAN's primary resolver should hold port 53 on
   the gateway host (the OpenWrt init script wires dnsmasq to forward
   `.fips` queries to the loopback listener automatically).
3. The gateway forwards the query to the daemon resolver
   (`gateway.dns.upstream`, default `[::1]:5354`). The daemon must
   match: an IPv6 socket bound to `[::1]` does not accept v4-mapped
   traffic, so a `127.0.0.1:5354` upstream cannot reach a daemon
   bound on `[::1]:5354`.
4. If the daemon is unreachable or times out (5 s), the gateway
   replies `SERVFAIL`. If the daemon returns `NXDOMAIN` or a
   non-`AAAA` answer, the gateway forwards the response unchanged.
5. The gateway extracts the AAAA (`fd00::/8`) record from the
   daemon's response. This resolution primes the daemon's identity
   cache as a side effect — a prerequisite for `fips0` routing,
   because the daemon needs the cache entry to map the mesh address
   back to a `NodeAddr` for forwarding.
6. The gateway allocates a virtual IP from the pool for that mesh
   address (idempotent: an existing mapping is reused and its TTL
   refreshed).
7. If a new mapping was created, the pool emits `MappingCreated`,
   which the main loop turns into `add_mapping` calls on the NAT
   manager and `add_proxy_ndp` on the network setup.
8. The gateway returns an `AAAA` response containing the virtual IP,
   with the configured TTL (default 60 s).

### Virtual IP Pool

The pool allocates IPv6 addresses from a configured CIDR (default
`fd01::/112`). Each address maps to one mesh destination, keyed by
`NodeAddr` rather than by hostname — different `.fips` aliases for
the same node share a virtual IP. Address 0 (the network-equivalent)
is reserved; the rest are allocatable. The pool is capped at 2^16
addresses regardless of prefix length, to bound memory.

The pool tracks state per address:

```text
Allocated ──→ Active ──→ Draining ──→ Free
    │                                  ▲
    └──────────────────────────────────┘
        (TTL expired, no sessions)
```

| State | Meaning |
| ----- | ------- |
| Allocated | DNS query created the mapping; no NAT sessions yet. |
| Active | Conntrack reports at least one session for this virtual IP. |
| Draining | TTL has expired; sessions may still be in progress, or grace period is running after sessions ended. |
| Free | Reclaimed and available for new allocations. |

Transitions:

- **Allocated → Active**: conntrack sessions count goes above zero.
- **Allocated → Free**: TTL expires before any session is ever
  observed.
- **Active → Draining**: TTL expires (sessions may or may not still
  be present).
- **Draining → Free**: session count is zero and the grace period
  has elapsed since draining began.

Timing:

- **TTL** (`gateway.dns.ttl`, default 60 s) is both the DNS TTL
  returned to the client and the mapping's idle lifetime. Repeated
  DNS queries for the same destination refresh the
  `last_referenced` timestamp.
- **Grace period** (`gateway.pool_grace_period`, default 60 s) is
  the dwell time after the last session ends before the address is
  recycled. It prevents immediate reuse from confusing hosts with
  cached DNS responses.
- **Tick interval**: the pool re-evaluates state every 10 s.

Active session counts come from `/proc/net/nf_conntrack`: an entry
counts as a session if its original destination is the virtual IP.

If the pool is exhausted, new DNS queries return `SERVFAIL`.
Existing mappings are never evicted prematurely — the correctness of
in-flight sessions takes precedence over fresh allocations.

### NAT Pipeline (Outbound)

Three rule classes in `inet fips_gateway` together implement the
LAN→mesh path:

**Prerouting DNAT (per mapping)** rewrites the destination from the
virtual IP to the corresponding mesh address:

```text
match:  nfproto ipv6 && ip6 daddr == <virtual_ip>
action: dnat to <mesh_addr>
```

After DNAT, the kernel routes the packet through `fips0` via the
standard routing table.

**Postrouting masquerade (`oifname fips0`)** rewrites the source of
all traffic exiting via `fips0` to the gateway's own `fips0` address:

```text
match:  oifname == "fips0"
action: masquerade
```

This rule is critical. Without it, LAN client source addresses (for
example `fd02::20` from the LAN's RA-advertised prefix, or virtual
addresses from another forwarding domain) would appear as the source
on the mesh. Those addresses are meaningless to mesh nodes, so
return traffic would be black-holed. Masquerade ensures all mesh
traffic appears to originate from the gateway's own FIPS identity.

**Postrouting SNAT (per mapping)** rewrites the source of return
traffic from the mesh address back to the virtual IP:

```text
match:  nfproto ipv6 && ip6 saddr == <mesh_addr>
action: snat to <virtual_ip>
```

Without it, the LAN client would see replies from the raw
`fd00::/8` mesh address rather than from the virtual IP it had
originally connected to, breaking application-layer assumptions about
the destination address.

### Network Requirements (Outbound)

The gateway host needs IPv6 forwarding enabled
(`net.ipv6.conf.all.forwarding=1`), proxy NDP enabled on the LAN
interface, `CAP_NET_ADMIN` for `fips-gateway`, and a `local
<pool-cidr> dev lo` route so the kernel accepts packets to the pool
as locally owned and runs them through the NAT chains. LAN clients
need a route to the pool via the gateway and DNS resolution that
forwards `.fips` queries there. On OpenWrt the init script handles
all of this; on other Linux hosts the operator handles it manually.
Full setup is documented in
[../how-to/deploy-gateway.md](../how-to/deploy-gateway.md).

## The Inbound Half (Mesh → LAN)

### Configuration Shape

Inbound port-forwards live in `gateway.port_forwards[]`. Each entry
is a triple:

| Field | Type | Notes |
| ----- | ---- | ----- |
| `listen_port` | `u16` | Port on the gateway's `fips0` address. Must be non-zero. |
| `proto` | `tcp` \| `udp` | Match protocol. |
| `target` | `[ipv6]:port` | LAN destination. IPv4 targets are rejected at parse time by `SocketAddrV6`. |

Validation runs at startup and on every config reload:
`(listen_port, proto)` must be unique across the list, and zero
listen ports are rejected. Forwards are independent of outbound
configuration: a gateway with no `pool` consumers can still expose
inbound services (the pool route and DNS proxy still run, since they
are part of the same binary, but they sit idle).

### NAT Pipeline (Inbound)

For each port-forward, a single prerouting DNAT rule matches
mesh-originated traffic landing on the gateway's `fips0` address
and rewrites it to the LAN target:

```text
match:  iifname == "fips0" && nfproto ipv6
        && l4proto == <tcp|udp> && th dport == <listen_port>
action: dnat to <target_ip>:<target_port>
```

The match clause is deliberately narrow:

- **`iifname == "fips0"`** restricts the rule to traffic that
  arrived from the mesh. LAN-side ingress is never subject to
  inbound forwarding.
- **`nfproto ipv6`** is enforced both here and at config-load time
  (`SocketAddrV6` rejects IPv4 targets); FIPS is IPv6-only end to
  end.
- **`l4proto + dport`** narrows the match to one
  `(listen_port, proto)` pair per rule. Unique-tuple validation
  ensures no two rules contend for the same packet.

When *any* port-forward is configured, a single LAN-side masquerade
is added to postrouting:

```text
match:  iifname == "fips0" && oifname == <lan_interface>
        && nfproto ipv6
action: masquerade
```

Without this rule, the LAN target would attempt to reply directly to
the mesh peer's `fd00::/8` source address, which is not reachable on
the LAN. Masquerade rewrites the source to the gateway's LAN-side
address so the target sees a reachable peer and conntrack routes
the reply back through the gateway.

This LAN-side masquerade is independent of the `oifname fips0`
masquerade in the outbound pipeline; the two have disjoint match
clauses (different `iifname`/`oifname` combinations) and coexist
without interaction when both directions are active.

### Independence From Outbound

The inbound half does not require:

- A virtual-IP pool. Mesh peers connect directly to the gateway's
  own `fips0` address, which the FIPS daemon already owns.
- DNS resolution. Mesh peers reach the gateway as
  `<gateway-npub>.fips:<port>` using their own resolver (or a
  numeric mesh address); the gateway's DNS proxy is not in the path.
- A daemon-side identity cache for the LAN target. The target is a
  LAN-side IPv6 address, not a mesh address; no `fd00::/8` lookup
  happens for it.

A gateway configured with port-forwards but with no LAN clients ever
issuing `.fips` DNS queries will have an empty pool and zero
outbound mappings, but its inbound forwards work normally. The
inverse is also true: a gateway that serves only outbound LAN→mesh
traffic has zero entries in the port-forwards list and no LAN-side
masquerade.

## Atomic Table Rebuild (Common)

Both halves contribute rules to the same `inet fips_gateway` table,
and that table is rebuilt as one unit on every state change —
mapping added, mapping removed, port-forwards updated. The rebuild
sequence is:

1. Delete the existing table in its own batch (ignore `ENOENT`).
2. In a fresh batch: add the table; add the `prerouting` and
   `postrouting` chains; add the always-on `oifname fips0`
   masquerade; add per-mapping DNAT/SNAT rules for every active
   pool entry; add per-port-forward DNAT rules; add the LAN-side
   masquerade if any port-forwards exist.
3. Send the batch as a single netlink transaction.

The rustables crate does not expose rule-handle tracking, so
incremental update of individual rules is not available. Atomic
rebuild was chosen for simplicity and correctness: it eliminates an
entire class of partial-update inconsistency bugs at the cost of
repeating the (cheap) rule construction on every change. The total
rule count is bounded by the pool capacity (2 per mapping, capped
at 2^16) and the port-forward count, both of which are small in
practice.

## Configuration Reference

The full `gateway.*` block — pool CIDR, LAN interface, DNS
listen/upstream/TTL, pool grace period, conntrack timeouts, and
inbound port-forwards — is documented in the
[Gateway section](../reference/configuration.md#gateway-gateway)
of the configuration reference. The same block governs both halves;
fields specific to one half (`pool`, `dns.*` for outbound;
`port_forwards[]` for inbound) are simply unused when the other
half is not in play.

## Operations and Troubleshooting

- [../tutorials/deploy-fips-gateway.md](../tutorials/deploy-fips-gateway.md)
  — end-to-end walkthrough on OpenWrt.
- [../how-to/deploy-gateway.md](../how-to/deploy-gateway.md) —
  recipe for non-OpenWrt Linux hosts and inbound-port-forwarding
  configuration.
- [../how-to/troubleshoot-gateway.md](../how-to/troubleshoot-gateway.md)
  — diagnostic recipes (DNS failures, ping working but TCP not,
  conntrack inspection, pool exhaustion, port-53 conflicts,
  port-forward verification).
- [../reference/cli-fips-gateway.md](../reference/cli-fips-gateway.md)
  — command-line interface.
- [../reference/control-socket.md](../reference/control-socket.md#gateway-command-catalog)
  — `show_gateway` and `show_mappings` commands.

## Security Considerations

### Outbound

- **LAN trust boundary.** The DNS listener and the virtual-IP pool
  are reachable by every host on the LAN. Any LAN host that can
  resolve `.fips` and route to the pool CIDR can reach mesh
  destinations. There is no per-client authentication; access
  restriction is a network-level concern, enforced with firewall
  rules on the LAN interface or on the gateway host itself.
- **Identity masking.** All outbound LAN traffic appears on the
  mesh under the gateway's own FIPS identity. Mesh nodes cannot
  determine which LAN host originated a connection. This provides
  privacy for LAN hosts but means the gateway's reputation covers
  all of its clients — and that abusive behavior from one LAN host
  is attributed to the gateway, not to the host.
- **Plaintext between client and gateway.** Traffic between the LAN
  client and the gateway is unencrypted at the IP layer. FIPS
  encryption (FSP) protects the segment between the gateway and the
  destination mesh node; application-layer encryption (TLS, SSH,
  Noise) is the only thing that provides true end-to-end protection
  through the gateway.
- **Pool addresses are ephemeral.** Virtual IPs are allocated
  dynamically and recycled. They are not authenticated and not
  bound to client identity — a LAN host connecting to a virtual IP
  is trusting the gateway's recent DNS response.
- **DNS upstream trust.** The outbound half's correctness depends
  on the FIPS daemon's resolver returning honest `fd00::/8`
  answers; a compromised daemon could redirect LAN clients to
  arbitrary mesh nodes.

### Inbound

- **Port exposure.** Each entry in `port_forwards[]` exposes the
  matched `(listen_port, proto)` on the gateway's mesh-side
  address to every reachable mesh peer. Inbound port-forwards are
  not gated by any peer ACL beyond what FMP normally enforces;
  treat them with the same care as a public-internet port forward.
- **Mesh peer trust.** The LAN target sees connections that have
  been masqueraded to the gateway's LAN address. The target cannot
  distinguish one mesh peer from another, and there is no
  authenticated peer identity available to the LAN target — any
  application-layer authentication or rate-limiting must run on
  the target itself.
- **Return-path masquerade exposes the gateway's LAN address.**
  The LAN-side masquerade rewrites the mesh peer's source to the
  gateway's LAN address. A malicious or buggy LAN target can use
  this to send unsolicited traffic back at the gateway, or to
  probe other LAN hosts via the gateway's network position; LAN
  segmentation (VLANs, host firewalls) is the right control.

### Common

- **No client identity verification.** The gateway authenticates
  neither LAN clients nor mesh peers beyond what the underlying
  layers already do — `fips0` ingress carries an FSP-authenticated
  payload, the LAN side is whoever the LAN admits.

## References

- [fips-ipv6-adapter.md](fips-ipv6-adapter.md) — IPv6 adapter and
  TUN interface design.
- [fips-architecture.md](fips-architecture.md) — protocol layer
  architecture.
- [fips-concepts.md](fips-concepts.md) — protocol overview.
- [../reference/configuration.md](../reference/configuration.md) —
  configuration reference.
- [../reference/cli-fips-gateway.md](../reference/cli-fips-gateway.md)
  — `fips-gateway` CLI.
- [../reference/control-socket.md](../reference/control-socket.md) —
  control-socket protocol and command catalog.
- [../how-to/deploy-gateway.md](../how-to/deploy-gateway.md) —
  gateway host and LAN client setup.
- [../how-to/troubleshoot-gateway.md](../how-to/troubleshoot-gateway.md)
  — diagnostic recipes.
- [../tutorials/deploy-fips-gateway.md](../tutorials/deploy-fips-gateway.md)
  — OpenWrt walkthrough.
