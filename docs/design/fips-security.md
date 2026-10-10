# FIPS Mesh-Interface Security

This document describes the threat model and design rationale for the
operator-facing security posture of the `fips0` mesh interface on Linux
and on OpenWrt. On a general Linux host, the default-deny nftables
baseline shipped as `/etc/fips/fips.nft` is the artifact discussed
below; for the operator activation steps and drop-in extension recipes,
see [enable-mesh-firewall.md](../how-to/enable-mesh-firewall.md).

There, the baseline is a documented operator conffile, not an
auto-loaded package side-effect. Activation is an explicit one-liner.
The rationale for that design follows. OpenWrt is different: the router
already runs a zone firewall, and the package gives `fips0` a
default-deny zone of its own at install (see
[OpenWrt: a zone, set up at install](#openwrt-a-zone-set-up-at-install)).

## Threat Model for `fips0`

The mesh is a flat layer-3 segment. Every mesh node that can route to
you can deliver packets to your `fips0` address — your direct peers
forward traffic from non-peer mesh nodes onto your `fips0` the same
way any router forwards transit traffic. Identity on the mesh is the
originating node's npub — the FMP link layer authenticates direct
peers with Noise IK and the FSP session layer authenticates session
endpoints with Noise XK — but identity is **not** authorization.
Knowing who sent a packet does not, by itself, decide whether the
local host should accept it.

That means: any service on a mesh host that binds to a wildcard
address (`0.0.0.0`, `[::]`, or any IPv6 address that includes the
`fips0` interface in its scope) is reachable from every mesh node
that can route to you by default, not only from your direct peers.
There is no NAT, no perimeter firewall, no "local-only" address
space between you and an arbitrary mesh node. The mesh is closer
to a shared LAN than to the public internet.

Compare to the corresponding internet trust assumptions:

| Surface | Public internet | FIPS mesh (no baseline) |
|---|---|---|
| Reachability from arbitrary mesh node | Mediated by NAT, firewalls, ISPs | Direct |
| Default identity | None | Originating node's npub (authenticated) |
| Default authorization | None | None |
| Accidental exposure cost | Low (NAT hides you) | High (every mesh node sees you) |

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

## Why no auto-load on package install

On a general Linux host, the `postinst` script does **not** enable
`fips-firewall.service`. This is deliberate. Quietly mutating host
firewall state on package install is hostile on every axis that
matters: it surprises operators
who already have their own nftables ruleset, it can collide with
podman/Docker/OPNsense integrations even though the early-return
makes it technically safe, and it converts an explicit security
decision into an invisible one. The mesh-interface filter belongs to
the operator, not to the package's `postinst`.

The activation gesture is one short, well-formed command. The
rationale is documented in the file's inline header and in this
document. That is enough; auto-loading would trade discoverability
for no real gain.

## OpenWrt: a zone, set up at install

A router is different. It already runs a zone firewall (fw4), every
interface is expected to sit in a zone, and an interface left out of
every zone meets the firewall's default policy, which accepts input on
stock OpenWrt 22.03. So the OpenWrt package does configure the firewall
at install: it gives `fips0` a zone of its own, `fips`, with the inbound
posture `fips.nft` gives a Linux host, expressed in fw4's terms. Unlike
`fips.nft`, which has only an input hook, the zone also governs forwarding.

- Inbound connections from FIPS peers to the router are refused (input
  REJECT, where `fips.nft` drops), except replies to the router's own
  connections, related ICMPv6, echo-request, and fips-gateway's port
  forwards.
- Outbound traffic from the router into the mesh is unrestricted
  (output ACCEPT).
- Forwarding into the mesh is allowed from the `lan` zone, which is the
  gateway's path, and from any zone the operator gives a forwarding to
  `fips`. OpenWrt's stock rules also accept ICMPv6 from `wan` into every
  zone; a second packaged include refuses it into `fips0`. fips-gateway
  translates only traffic that arrives on its LAN interface and drops
  new traffic from its other interfaces into the mesh, so a port forward
  in another zone, whose translated flows fw4 accepts in that zone's
  forward chain, does not open the mesh to it.
- Forwarding from the mesh is refused except for the gateway's port
  forwards.

The port forwards are DNAT rules in fips-gateway's own nftables table,
so the package installs a small fw4 include that accepts them in the
zone, after the zone's own rules. A rule with `src fips` can therefore
restrict them, and opening a port to FIPS peers is likewise a `src fips`
rule; `src_ip` takes a peer's mesh address. Once created, the zone is
the operator's: the package creates it only while no zone holds `fips0`
and never rewrites it. The OpenWrt package README describes the zone
and how to change it.

If the firewall fails to reload during an upgrade, the package blocks
new connections from `fips0` in the loaded ruleset until the firewall
reloads cleanly, and says so.

## Coexistence with other firewalls

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
deployment shape. See [fips-gateway.md](fips-gateway.md) for the
gateway table's structure.

## What the Baseline Does Not Cover

The baseline is one half of a defense-in-depth posture. It is
explicitly not:

- **Outbound filtering.** Anything the mesh host originates on
  `fips0` is unrestricted. If you need to constrain what the host
  can send to the mesh, add rules to a separate chain hooked at
  `output` — out of scope for the baseline.
- **Application-layer authorization.** The baseline decides whether
  a packet reaches a service. It does not decide whether the
  originating mesh node's npub is allowed to use that service. That
  is the application's responsibility (e.g., an `authorized_keys`
  file for SSH, an ACL in the application's configuration).
- **ACL on the mesh handshake.** The FMP Noise IK handshake
  authenticates the peer's npub and, on both inbound and outbound
  paths, consults the peer ACL (`peers.allow` / `peers.deny`) before
  promoting the connection. The ACL evaluates in TCP-Wrappers order:
  an `allow` match permits, otherwise a `deny` match rejects,
  otherwise the connection is permitted. A strict allowlist posture
  therefore requires an explicit `ALL` entry in `peers.deny`; a
  populated `peers.allow` alone does not turn the ACL into a strict
  allowlist. Mesh-level ACLs are a separate concern from the inbound
  packet filter described here; see the peer ACL section in
  [../reference/security.md](../reference/security.md).
- **Compromised peers.** A peer whose key has been stolen or whose
  host has been taken over is, by mesh-level identity, still that
  peer. Source-address filtering in drop-ins operates on the source
  mesh address of inbound traffic regardless of whether that source
  is a direct peer or a multi-hop mesh node, and so can limit damage
  from a known-compromised mesh address; but the baseline cannot
  revoke trust on its own.

Treat the baseline as removing the "wide-open by default" failure
mode. Higher-layer authorization decisions are the operator's and
the application's, the same as on any other shared network.

## Future Work

The baseline covers Linux and OpenWrt; macOS and the cross-OS gateway
still lack one. Parallel work for those targets:

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
- **Cross-OS gateway abstraction.** `fips-gateway` is currently
  Linux-only because `src/gateway/nat.rs` uses the `rustables`
  netlink API directly. macOS gateway support requires a PF-backed
  equivalent behind a shared backend trait. This is a larger lift
  than the static baseline and is tracked separately under the same
  cross-OS thread.

When those land, this document will grow per-OS sections describing
each baseline's load mechanism and extension points. The threat
model and the operator-extension principle are the same on every OS;
only the filter syntax and the activation gesture differ.

## See also

- [enable-mesh-firewall.md](../how-to/enable-mesh-firewall.md) — operator
  activation steps, drop-in recipes, drop visibility and debugging
- [../reference/security.md](../reference/security.md) — consolidated
  security reference (cryptographic primitives, peer ACL format,
  filesystem permissions, default network exposures)
- [fips-gateway.md](fips-gateway.md) — `fips-gateway` service and the
  separate `inet fips_gateway` table
