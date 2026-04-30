# FIPS Mesh-Interface Security

This document describes the operator-facing security posture of the
`fips0` mesh interface on Linux: the threat model, the default-deny
nftables baseline shipped as `/etc/fips/fips.nft`, how to enable it,
and how to extend it with per-host allowances.

The baseline is a documented operator conffile, not an auto-loaded
package side-effect. Activation is an explicit one-liner. The
rationale for that design and the operator workflow follow.

## Threat Model for `fips0`

The mesh is a flat layer-3 segment. Every authenticated peer on the
mesh can route packets to every other peer's `fips0` address. Identity
on the mesh is the peer's npub — the FMP link layer authenticates that
identity with Noise IK and the FSP session layer authenticates
endpoints with Noise XK — but identity is **not** authorization.
Knowing who sent a packet does not, by itself, decide whether the
local host should accept it.

That means: any service on a mesh host that binds to a wildcard
address (`0.0.0.0`, `[::]`, or any IPv6 address that includes the
`fips0` interface in its scope) is reachable from every peer in the
mesh by default. There is no NAT, no perimeter firewall, no
"local-only" address space between you and an arbitrary peer. The
mesh is closer to a shared LAN than to the public internet.

Compare to the corresponding internet trust assumptions:

| Surface | Public internet | FIPS mesh (no baseline) |
|---|---|---|
| Reachability from arbitrary peer | Mediated by NAT, firewalls, ISPs | Direct |
| Default identity | None | Peer npub (authenticated) |
| Default authorization | None | None |
| Accidental exposure cost | Low (NAT hides you) | High (every peer sees you) |

The third row is the gap this document closes. The default-deny
baseline removes "accidental exposure" from the failure modes an
operator has to think about.

## The Default-Deny Baseline

The shipped baseline is `/etc/fips/fips.nft`. It defines a single
nftables table, `inet fips`, with one chain hooked at `input`. The
chain:

1. Returns immediately for any packet not arriving on `fips0`. This
   makes the table a no-op for every other interface — Docker, Tor,
   the host's main filter table, OPNsense, anything.
2. Accepts packets that conntrack identifies as `established` or
   `related`. Replies to outbound flows initiated from the mesh host
   come back; ICMPv6 errors related to existing flows (Packet Too
   Big, Destination Unreachable) come back.
3. Accepts ICMPv6 echo-request, so `ping6` reachability tests work.
4. Includes operator drop-ins from `/etc/fips/fips.d/*.nft`. An empty
   directory is fine — the include glob simply matches nothing.
5. Falls through to `counter drop`. Every dropped packet increments
   the counter, visible via `nft list table inet fips`.

Outbound from `fips0` is unrestricted. The baseline is concerned only
with what the mesh host accepts, not what it sends.

The file is a documented dpkg conffile. Operator edits to
`/etc/fips/fips.nft` are preserved across upgrades, the same way
edits to `/etc/fips/fips.yaml` and `/etc/fips/hosts` are preserved.
If the packaged baseline is ever updated upstream, dpkg prompts the
operator on upgrade rather than silently overwriting local changes.

The canonical artifact is the file itself; read it for the inline
documentation that the rest of this document references.

## Loading the Baseline

The package ships `fips-firewall.service`, a systemd oneshot unit
that runs `nft -f /etc/fips/fips.nft` on start and removes the
`inet fips` table on stop. It is **not** enabled by default. To
activate the baseline:

```sh
sudo systemctl enable --now fips-firewall.service
```

This loads the table now and arranges for it to load on every
subsequent boot. To disable and tear it down:

```sh
sudo systemctl disable --now fips-firewall.service
```

To reload after editing `/etc/fips/fips.nft` or adding a drop-in
under `/etc/fips/fips.d/`:

```sh
sudo systemctl reload-or-restart fips-firewall.service
```

(or equivalently `sudo nft -f /etc/fips/fips.nft`, since the file is
idempotent — it begins with `add table inet fips; flush table inet
fips;` so re-running it replaces the live ruleset atomically.)

### Why no auto-load on package install

The `postinst` script does **not** enable `fips-firewall.service`.
This is deliberate. Quietly mutating host firewall state on package
install is hostile on every axis that matters: it surprises operators
who already have their own nftables ruleset, it can collide with
podman/Docker/OPNsense integrations even though the early-return
makes it technically safe, and it converts an explicit security
decision into an invisible one. The mesh-interface filter belongs to
the operator, not to the package's `postinst`.

The activation gesture is one short, well-formed command. The
rationale is documented in the file's inline header and in this
document. That is enough; auto-loading would trade discoverability
for no real gain.

### Coexistence with other firewalls

The `inet fips` table only matches packets arriving on `fips0`.
Anything else returns from the chain on the first rule. Specifically:

- **Docker / containerd** install nftables rules in the `ip` and `ip6`
  families and operate on `docker0`, `br-*`, and `veth*`
  interfaces. They do not touch `fips0`. The two tables coexist
  without interference.
- **Tor** runs in user space and does not install firewall rules. The
  baseline is independent of Tor's onion-service and SOCKS listeners.
- **OPNsense** is an upstream perimeter device. The baseline runs on
  the local host and applies only to traffic that has already reached
  the host's `fips0` interface. They do not interact.
- **The host's main `/etc/nftables.conf`** typically defines a
  separate `inet filter` table. nftables allows multiple tables in
  the same family to coexist; both run in parallel at hook
  `input`/priority 0 and the `iifname != "fips0" return` rule keeps
  the `inet fips` table from interfering with anything outside the
  mesh interface.
- **`inet fips_gateway`**, when `fips-gateway` is running, manages
  DNAT/SNAT on the LAN-facing interface to translate virtual IPs to
  mesh addresses. It is a separate concern owned by the gateway
  binary and is unrelated to this baseline. See the section below.

If you prefer to fold the baseline into your existing
`/etc/nftables.conf` instead of using the systemd unit, you can:

```nft
# in /etc/nftables.conf
include "/etc/fips/fips.nft"
```

In that case do not enable `fips-firewall.service` — let the host's
main nftables setup own the loading. The two are mutually exclusive.

## Operator Extension via `/etc/fips/fips.d/*.nft`

The baseline drops everything inbound on `fips0` except conntrack
replies and ICMPv6 echo. To open specific services to specific peers,
drop a file into `/etc/fips/fips.d/` ending in `.nft`. Each file is
included inline into the `inbound` chain at the marked point and may
contain any nftables rule lines valid in that context.

Reload after editing:

```sh
sudo systemctl reload-or-restart fips-firewall.service
# or:  sudo nft -f /etc/fips/fips.nft
```

Common patterns follow.

### Allow inbound SSH from a specific peer

```nft
# /etc/fips/fips.d/ssh-from-bastion.nft
ip6 saddr fd97:1234:5678:9abc:def0:1234:5678:9abc tcp dport 22 accept
```

The source filter is the peer's mesh address. To find a peer's mesh
address, look in their `fips.pub` (which contains the npub) and
derive the `fd97:...` address from it, or query the running daemon:

```sh
fipsctl show identity-cache
fipsctl show peers
```

### Allow inbound HTTP from one /64 of peers

If you operate a logical group of peers under a shared address
prefix, source-filter by the prefix:

```nft
# /etc/fips/fips.d/http-from-cluster.nft
ip6 saddr fd97:1234:5678:9abc::/64 tcp dport 80 accept
```

The mesh address space is `fd00::/8`, so `/64` filters carve out
manageable subgroups. Plan your prefixes before deploying many peers.

### Allow inbound DNS broadly

Some services need to be reachable from any mesh peer (a public DNS
resolver, a public bootstrap node):

```nft
# /etc/fips/fips.d/dns-public.nft
udp dport 53 accept
tcp dport 53 accept
```

Omit the source filter only when the service is intended to be
universally reachable on the mesh. The baseline's purpose is to make
"universally reachable" an explicit decision rather than the default.

### Multiple peers, one service

```nft
# /etc/fips/fips.d/git-from-trusted.nft
ip6 saddr {
    fd97:1111:2222:3333:4444:5555:6666:7777,
    fd97:8888:9999:aaaa:bbbb:cccc:dddd:eeee
} tcp dport 9418 accept
```

Set syntax keeps multi-peer rules readable and is more efficient than
a chain of individual rules.

## Drop Visibility and Debugging

The baseline counter increments on every dropped packet. Inspect it:

```sh
sudo nft list table inet fips
```

Look for the `counter packets N bytes M drop` line at the bottom of
the `inbound` chain. A non-zero counter means peers are sending
traffic that hits the default-deny — usually benign (probes,
neighbor discovery) but occasionally a misconfigured drop-in.

To see which packets are being dropped, uncomment the `log` line
near the bottom of `/etc/fips/fips.nft`:

```nft
log prefix "fips drop: " level info limit rate 10/minute
```

Reload:

```sh
sudo nft -f /etc/fips/fips.nft
```

Then tail the kernel log:

```sh
sudo journalctl -k -f -g "fips drop:"
```

The rate-limit prevents flooding the journal under sustained probing.
Adjust the rate, log level, or prefix as needed for the situation.
Re-comment the rule when you are done; production hosts do not need
the log line on by default.

## Coexistence with `inet fips_gateway`

When `fips-gateway` is running, it manages a separate nftables
table, `inet fips_gateway`, containing the DNAT and masquerade rules
that translate between the gateway's virtual-IP pool and mesh
addresses on the LAN-facing interface. That table is created and
torn down by the gateway binary at runtime and is not an operator
artifact in the same sense as `inet fips`.

The two tables do not interfere:

- `inet fips` filters inbound on `fips0`.
- `inet fips_gateway` performs NAT on the LAN interface.

They operate on different interfaces and at different hook points
(`input` filter vs. `prerouting`/`postrouting` NAT). Both can be
loaded simultaneously on a gateway host, and that is the intended
deployment shape. See `docs/design/fips-gateway.md` for the gateway
table's structure.

## What the Baseline Does Not Cover

The baseline is one half of a defense-in-depth posture. It is
explicitly not:

- **Outbound filtering.** Anything the mesh host originates on
  `fips0` is unrestricted. If you need to constrain what the host
  can send to the mesh, add rules to a separate chain hooked at
  `output` — out of scope for the baseline.
- **Application-layer authorization.** The baseline decides whether
  a packet reaches a service. It does not decide whether the peer
  npub on the other end is allowed to use that service. That is the
  application's responsibility (e.g., an `authorized_keys` file for
  SSH, an ACL in the application's configuration).
- **ACL on the mesh handshake.** The FMP Noise IK handshake currently
  authenticates the peer's npub but does not consult an allowlist
  before establishing a link. A peer with a known npub can connect
  and become a routing peer regardless of operator intent. Mesh-
  level ACLs are tracked under IDEA-0047 / PR #50 and are a separate
  concern from the inbound packet filter described here.
- **Compromised peers.** A peer whose key has been stolen or whose
  host has been taken over is, by mesh-level identity, still that
  peer. Source-address filtering in drop-ins limits damage, but the
  baseline cannot revoke trust on its own.

Treat the baseline as removing the "wide-open by default" failure
mode. Higher-layer authorization decisions are the operator's and
the application's, the same as on any other shared network.

## Future Work

The current baseline is Linux-only. Parallel work for other targets:

- **macOS PF baseline.** macOS uses Packet Filter (PF), inherited
  from OpenBSD. PF maps cleanly onto the same conceptual model as
  nftables: stateful inspection (`keep state` ≈ `ct state
  established,related`), default policy, anchor-based modular rule
  loading. A `packaging/macos/fips.pf` will land alongside the
  Linux baseline with the same posture: documented asset, no
  auto-load, operator opts in via launchd. The macOS interface name
  is `utunN` rather than `fips0`, so the rule template needs runtime
  substitution or a PF interface group assigned at TUN bring-up;
  this is being worked through with the macOS port.
- **OpenWrt fw4 path.** OpenWrt's fw4 already drives nftables under
  the hood, but rules go into `/etc/nftables.d/` includes or UCI
  entries in `/etc/config/firewall`, not a free-standing
  `fips.nft`. The ipk will ship a layout-compatible variant or
  document the operator setup separately, decided when the OpenWrt
  packaging is updated.
- **Cross-OS gateway abstraction.** `fips-gateway` is currently
  Linux-only because `src/gateway/nat.rs` uses the `rustables`
  netlink API directly. macOS gateway support requires a PF-backed
  equivalent behind a shared backend trait. This is a larger lift
  than the static baseline and is tracked separately under the same
  IDEA thread.

When those land, this document will grow per-OS sections describing
each baseline's load mechanism and extension points. The threat
model and the operator-extension principle are the same on every OS;
only the filter syntax and the activation gesture differ.
