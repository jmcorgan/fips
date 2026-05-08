# Enable the Mesh-Interface Firewall

FIPS ships a default-deny nftables baseline at `/etc/fips/fips.nft` that
restricts inbound traffic on the `fips0` mesh interface to conntrack
replies and ICMPv6 echo. The baseline is **not** enabled by default — see
[../design/fips-security.md](../design/fips-security.md) for the threat
model and the rationale behind keeping activation explicit. This guide
covers the operator steps to load the baseline, extend it with per-host
allowances, and inspect drops.

## Activate the baseline

The package ships `fips-firewall.service`, a systemd oneshot that runs
`nft -f /etc/fips/fips.nft` on start and removes the `inet fips` table
on stop. To activate:

```sh
sudo systemctl enable --now fips-firewall.service
```

This loads the table now and arranges for it to load on every subsequent
boot. To disable and tear it down:

```sh
sudo systemctl disable --now fips-firewall.service
```

To reload after editing `/etc/fips/fips.nft` or adding a drop-in under
`/etc/fips/fips.d/`:

```sh
sudo systemctl reload-or-restart fips-firewall.service
```

The file is idempotent — it begins with `add table inet fips; flush
table inet fips;` so re-running it replaces the live ruleset atomically.
Equivalently:

```sh
sudo nft -f /etc/fips/fips.nft
```

## Folding the baseline into the host's main nftables

If you prefer to load the baseline from your existing
`/etc/nftables.conf` rather than via the systemd unit, include it
directly:

```nft
# in /etc/nftables.conf
include "/etc/fips/fips.nft"
```

In that case do **not** enable `fips-firewall.service` — the host's main
nftables setup owns the loading. The two paths are mutually exclusive.

## Extend with per-host allowances via drop-ins

The baseline drops everything inbound on `fips0` except conntrack
replies and ICMPv6 echo. To open specific services to specific mesh
nodes, drop a file into `/etc/fips/fips.d/` ending in `.nft`. Each
file is included inline into the `inbound` chain at the marked point
and may contain any nftables rule lines valid in that context.

Reload after editing:

```sh
sudo systemctl reload-or-restart fips-firewall.service
# or:  sudo nft -f /etc/fips/fips.nft
```

### Allow inbound SSH from a specific mesh node

```nft
# /etc/fips/fips.d/ssh-from-bastion.nft
ip6 saddr fd97:1234:5678:9abc:def0:1234:5678:9abc tcp dport 22 accept
```

The source filter is the node's mesh address. To find a node's mesh
address, look in their `fips.pub` (which contains the npub) and derive
the `fd97:...` address from it, or query the running daemon:

```sh
fipsctl show identity-cache
fipsctl show peers
```

### Allow inbound DNS broadly

Some services need to be reachable from any mesh node (a public DNS
resolver, a public bootstrap node):

```nft
# /etc/fips/fips.d/dns-public.nft
udp dport 53 accept
tcp dport 53 accept
```

Omit the source filter only when the service is intended to be
universally reachable on the mesh. The baseline's purpose is to make
"universally reachable" an explicit decision rather than the default.

### Multiple nodes, one service

```nft
# /etc/fips/fips.d/git-from-trusted.nft
ip6 saddr {
    fd97:1111:2222:3333:4444:5555:6666:7777,
    fd97:8888:9999:aaaa:bbbb:cccc:dddd:eeee
} tcp dport 9418 accept
```

Set syntax keeps multi-node rules readable and is more efficient than a
chain of individual rules.

## Verify with fipstop

`fipstop`'s Node tab carries a **Listening on fips0** panel
(right-half of the Traffic block) that pairs each local IPv6
listener with its current baseline-filter classification. After
adding or editing a drop-in and reloading, this is the fastest
way to confirm the rule landed correctly without manually
parsing `nft list table inet fips`.

| Panel state | Reading |
| ----------- | ------- |
| Service row in **default White** with `OPEN` in the State column | The chain has a canonical, unrestricted accept rule for this (proto, port). The service is reachable from any mesh node. |
| Service row in **DarkGray** with `filt` | No matching accept rule; the chain falls through to `counter drop`. The service is not reachable from the mesh. |
| Service row in **DarkGray** with `filt?` | A rule references the port but uses matchers the panel cannot fully decompose (saddr filter, jump, daddr filter). The intent is operator-defined; inspect with `sudo nft list table inet fips` to see the actual rule. |
| **Yellow banner** above the panel: "fips-firewall.service inactive — all listeners exposed" | The `inet fips` table is not loaded. Every listener is mesh-reachable (subject only to whatever ACL you have at the peer layer). |

A common workflow when extending the baseline is to keep `fipstop`
open on the Node tab in one terminal while editing
`/etc/fips/fips.d/` in another. After each
`sudo systemctl reload-or-restart fips-firewall.service`, the panel
re-classifies on the next poll tick and the affected row's State
column flips. A row staying `filt` after you expected `OPEN`
usually means the drop-in failed to load (syntax error in any file
under `/etc/fips/fips.d/` aborts the whole reload) or carries a
saddr filter that triggers `filt?` rather than `OPEN`.

The classifier is conservative: it recognizes only the canonical
unrestricted shapes (`tcp dport N accept`, `udp dport N accept`,
`dport { ... } accept`, `dport A-B accept`). Source-restricted
accepts intentionally render as `filt?` rather than `OPEN` —
the panel is a security screen, and any rule that varies by
source is an operator decision the panel will not silently bless
as fully open.

## Inspect drops

The baseline counter increments on every dropped packet. Inspect it:

```sh
sudo nft list table inet fips
```

Look for the `counter packets N bytes M drop` line at the bottom of the
`inbound` chain. A non-zero counter means mesh nodes are sending
traffic that hits the default-deny — usually benign (probes, neighbor
discovery) but occasionally a misconfigured drop-in.

To see which packets are being dropped, uncomment the `log` line near
the bottom of `/etc/fips/fips.nft`:

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

## See also

- [../design/fips-security.md](../design/fips-security.md) — threat
  model, baseline design, and coexistence with other firewalls
- [../reference/security.md](../reference/security.md) — consolidated
  security reference
