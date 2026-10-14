# Diagnose Reachability

"Can this node reach that one, by what route, and if not, why not?" is
a question about a path, and most of `fipsctl show` answers questions
about links. `fipsctl show peers` lists the nodes this one has a direct,
authenticated link to. A destination reached through a relay or any
other forwarding node never appears there, and the peer row of the relay
that carries its traffic says nothing about where that traffic went.
This guide starts from the path-shaped question and works back to the
link that explains the answer.

For the probe's full output and its JSON report, see
[`fipsctl probe`](../reference/cli-fipsctl.md#probe-target) in the
reference.

## Start with `fipsctl probe`

```sh
fipsctl probe <npub-or-hostname>
```

The probe runs five stages in order and reports a verdict for each, so
the first stage that fails tells you where to look:

| Stage that fails | What it means | Where to look next |
| ---------------- | ------------- | ------------------ |
| **bloom** | No LookupRequest went out. Read the reason: the mesh may not know the address, or this node may have held the request back. | See the reasons below. On a miss, see [Check that you have the right npub](#check-that-you-have-the-right-npub), then [Check the target's own link](#check-the-targets-own-link). |
| **discovery** | A peer's filter claims the address, but no LookupResponse came back. | The target, or a node between you, is not answering. A filter can claim an address nobody holds any more, so check the npub as for a bloom miss. Run the probe from the forwarding node (for example the relay) to split the path. |
| **path** | No next hop could be selected, or the two nodes are in different spanning trees. | Different trees means a real partition. Otherwise this stage is a local computation that contacts nothing, and a session can still succeed; read the session stage before acting on it. |
| **session** | The route was found but the end-to-end Noise handshake did not complete. | Traffic is lost in one direction. A rerolled identity rarely shows up here; see below. |
| **rtt** | The session is up but no round-trip time was measured. | Read the reason: most of them are not loss. |

A failed stage prints a short explanation after its verdict, and
`--json` carries the same finding as the stage's `reason`. The ones
that change what you do next:

| Stage | `reason` | The CLI prints | What to do |
| ----- | -------- | -------------- | ---------- |
| bloom | `bloom_miss` | no peer filter holds this address | The mesh has not heard of the target: it is down, partitioned, or no longer the node you think it is. |
| bloom | `backoff_suppressed` | held down by lookup backoff | This node's own lookup backoff is holding the request back after a recent failure. Wait and probe again. |
| bloom | `no_tree_peers` | claimed, but no tree peer to ask | This node has nobody to ask. Check its own links with `fipsctl show peers`. |
| path | `disjoint_trees` | different spanning-tree roots | The two nodes are in separate spanning trees: a real partition. |
| path | `no_next_hop` | no next hop toward this target | Local preview only; read the session stage. |
| session | `handshake_timeout` | gave up waiting for the handshake to complete | Traffic is lost in one direction, or the coordinates are cached for an identity the target no longer holds (below). |
| rtt | `no_report` | no receiver report of any kind within the budget | Loss or congestion on the path. Retry; see [diagnose-mtu-issues.md](diagnose-mtu-issues.md) if bulk traffic also stalls. |
| rtt | `sub_millisecond` | reports arrived but every sample measured under 1 ms | Not loss: expected on loopback and same-host meshes. |
| rtt | `no_echo` | reports arrived but none carried a usable timestamp echo | Not loss: the session works, the measurement did not. |
| rtt | `bad_timestamp_echo` | receiver reports carried timestamp echoes that failed arithmetic validation | An anomaly worth investigating. |

A node that came back under a new npub usually fails at bloom or
discovery, not at session: a LookupResponse is signed by the target,
so no node can answer for an npub whose key it does not hold. The
handshake is reached with a rerolled identity only when this node
still has coordinates cached for the old address.

The probe exits 0 only when the overall verdict is `ok`; `partial`
(for example, a session came up but no round-trip time was measured),
`failed` and `cancelled` exit 1. A failed path stage on its own does
not fail the verdict. The exit status makes the probe usable in a
script or a health check.

When the probe succeeds, the stage block leaves out the path row, and
the route appears in the `path:` section below the block. Its `route`
line shows the tree walk from this node, through the least common
ancestor, to the target, and its `next hop` line names the peer this
node would send through. That is the "via" a peer listing does not
show. It is a computed route rather than a traceroute: only the first
hop is contacted, and the real path can be shorter than the tree
distance when a crosslink cuts through.

## Peers versus sessions

Two listings answer different questions:

- `fipsctl show peers` lists **links**: nodes this one talks to
  directly. A laptop that dials a single relay has one peer, the relay,
  however many nodes it reaches through it.
- `fipsctl show sessions` lists **end-to-end sessions**: the
  destinations this node is exchanging traffic with, wherever they are.

```sh
fipsctl show sessions | jq '.sessions[] | {display_name, npub, state, stats}'
```

A destination you can ping but that is missing from `show peers` is
reached through a forwarding node, which is the expected shape when
nodes dial a relay. Look for it in `show sessions` instead.

## Check that you have the right npub

A node with `node.identity.persistent: false`, the default, generates
a new identity on every start. It logs no warning when it does, only an
`info` line, `Using ephemeral identity (new keypair each start)`. Each
restart gives it a new npub, a new mesh address and a new `.fips` name
target. To the rest of the mesh it is a different node: hosts entries
and ACL entries that name the old npub stop matching, names resolve to
an address nobody answers on, and the node's handshakes reach its peers
from a key they have never seen.

On the node itself, check whether its identity survives a restart, and
compare the npub it runs as with the one the rest of the mesh expects:

```sh
fipsctl show status | jq '{npub, persistent}'
```

`persistent: false` means every restart rerolls the npub. Set
`node.identity.persistent: true` to keep the identity from the next
start on; see [persistent-identity.md](persistent-identity.md). An
ephemeral node never writes its private key, so an identity it has
already lost cannot be recovered and the other nodes have to be told
the new npub. (`persistent` also reads `true` when the config sets an
`nsec`, since that identity survives a restart too. It reflects the
config, not the outcome: a node set to `persistent: true` that cannot
write its key file runs ephemeral anyway and says so in a warning that
its npub "will change on every start".)

One case can be recovered. A node that had a `fips.key` and was
started ephemeral logs a warning that an identity key file "was found
in ephemeral mode and moved aside", and leaves `fips.key.unused`
beside the config. Set `node.identity.persistent: true` and move the
file back to `fips.key` to get the old identity back.

On every other node, the npub to check is the one in the hosts file
(`/etc/fips/hosts`, or `/usr/local/etc/fips/hosts` on macOS and FreeBSD)
and in `peers.allow`. `fipsctl address <name>` prints the mesh address a
hostname resolves to, so it is quick to compare with the address the
node really has.

## Check the target's own link

A destination is reachable only while it has a link into the mesh. When
the target dials a relay, its link to the relay is the one that has to
be up, and the relay's ACL decides whether it may be. The probe from
your node cannot see that link; check it on the relay:

```sh
# on the relay
fipsctl show peers | jq -r '.peers[] | "\(.display_name) \(.npub) \(.connectivity)"'
fipsctl acl show
journalctl -u fips | grep 'Rejected peer by ACL'
```

`Rejected peer by ACL` with the target's npub means the relay is
refusing the target's link, so the target is unreachable through it
however reachable its IP address is. Add the npub to the relay's
`peers.allow`.

The peer ACL only governs links. It decides which nodes may link
directly to this one, not which destinations this node can reach
through others or which nodes can reach it through a relay.

## Check which unknown nodes can link to you

`fipsctl acl show` reports the ACL in force:

| `effective_mode` | Peers named in neither file |
| ---------------- | --------------------------- |
| `default_open` | allowed (no ACL entries loaded) |
| `allow_all` | allowed: `ALL` in `peers.allow` admits every peer, including any listed in `peers.deny` |
| `allowlist` | allowed: an allowlist on its own does not deny anyone |
| `denylist` | allowed |
| `allow_then_deny` | allowed |
| `deny_all`, `allow_then_deny_all` | denied |

`default_decision` gives the same answer in one word. The files follow
TCP Wrappers ordering, so a node with no ACL files, or only a
`peers.allow`, accepts a link from any npub that completes a handshake.
To accept only the nodes you name, list them in `peers.allow` and put
`ALL` in `peers.deny`. The evaluation order and the file format are in
[security.md](../reference/security.md#peer-acl).

Accepting a link from an npub this node does not recognise leaves
nothing in the log at the default `info` level. `Peer promoted to
active` is logged only for links this node dialled; an accepted
inbound link logs `Connection promoted to active peer` at `debug`. List
the inbound links and compare them with the npubs you expect:

```sh
fipsctl show peers | jq -r '.peers[] | select(.direction=="inbound") | "\(.display_name) \(.npub)"'
```

## Check name resolution separately

When `fipsctl probe <npub>` succeeds but `ssh host.fips` hangs, the mesh
is fine and the problem is the system resolver. The daemon's DNS
responder listens on `[::1]:5354` by default.

- **macOS**: `/etc/resolver/fips` must read `nameserver ::1` and
  `port 5354`. The v0.3.0 macOS package shipped
  `nameserver 127.0.0.1`, where nothing listens, and a resolver file
  written by hand from old instructions has the same problem. It has
  been observed not to fail fast: mDNSResponder swallows the timeout, so
  `.fips` names quietly fail to resolve while a query sent straight to
  the daemon works. Reinstall the package or correct the file, then run
  `sudo killall -HUP mDNSResponder`.
- **Linux with systemd-resolved**: `resolvectl query host.fips` should
  answer through the `.fips` routing that `fips-dns` sets up. That
  alone does not prove applications use it: when `/etc/resolv.conf`
  lists nameservers directly instead of pointing at the
  systemd-resolved stub, `resolvectl` answers and everything else
  bypasses the routing
  ([#151](https://github.com/jmcorgan/fips/issues/151)). Check that
  `getent ahosts host.fips` also answers; if it does not, make
  `/etc/resolv.conf` point at the stub (normally a symlink to
  `/run/systemd/resolve/stub-resolv.conf`).

`dig @::1 -p 5354 AAAA host.fips` asks the daemon directly. If that
answers and the system lookup does not, the problem is the resolver
configuration and not the mesh.
