# Open Discovery: Find Peers Without Configuration

After
[advertise-your-node](advertise-your-node.md), your daemon
publishes its endpoint on Nostr and other open-discovery nodes
on the test mesh have already started dialing you. This
tutorial flips the symmetry: turn your own daemon into a
consumer of every advert in the namespace, so any operator
who's publishing becomes a candidate peer of yours.

The whole exercise should take about ten minutes. After it,
you'll be a full participant in the ambient
`fips-overlay-v1` namespace — publishing your own advert
*and* discovering everyone else's.

## What you'll build

```text
   ┌─────────────────────────────────────────────────────┐
   │  Nostr relays — fips-overlay-v1 namespace           │
   │   adverts from: test-us01..uk01, others             │
   └────────────────┬─────────────────────────▲──────────┘
                    │                         │
                    │ subscribe to all         │ your own
                    │ adverts in namespace     │ advert
                    │                         │
                    ▼                         │
   ┌────────────────────────────────────────────────────┐
   │  your fips daemon (policy: open)                   │
   │                                                    │
   │  peers list grows ambient as adverts arrive:       │
   │     test-us01     ← was static                     │
   │     test-us03     ← inbound (was already there)    │
   │     test-de01, test-es01, test-uk01, test-us04...  │
   │     plus any other publisher in the namespace      │
   └────────────────────────────────────────────────────┘
```

You will change one thing in `/etc/fips/fips.yaml`: under
`discovery.nostr`, set `policy: open` (the default is
`configured_only`). After restart, the daemon subscribes to
every Kind 37195 advert in the `fips-overlay-v1` namespace and
queues the publishers for outbound connection attempts.

## How open discovery works

> **Discovery policy.** `discovery.nostr.policy` decides what
> the daemon does with incoming advert data. Two values:
>
> - `configured_only` (the default): the daemon only consumes
>   adverts for peers it has explicitly listed with
>   `via_nostr: true`. This is what you've been running
>   through the previous two Nostr tutorials.
> - `open`: the daemon subscribes to every advert in the
>   configured `app` namespace. Any publisher becomes a
>   candidate peer, no `peers:` list entry needed.

Switching the policy doesn't disturb anything that was already
working:

> **Open is additive, not exclusive.** Switching to
> `policy: open` doesn't replace your static peers — both
> mechanisms run in parallel. Configured peers stay in your
> `peers:` block and continue to be dialed via their static
> addresses or `via_nostr` lookups; open-discovered peers
> stack on top from the ambient namespace. You can run open
> discovery with a populated `peers:` list (the path this
> tutorial walks, since you're keeping `test-us01`), with
> `peers: []` for pure ambient discovery, or with a long
> `peers:` list and open layered on top to broaden reach.

The namespace is what scopes who's visible to whom:

> **The namespace is the scope.** `discovery.nostr.app`
> defaults to `fips-overlay-v1` — the namespace the public
> test mesh uses. Setting a different value (e.g.,
> `app: "my-experiment.v1"`) carves out a private discovery
> set: only nodes that share your `app` value find each
> other. For this tutorial we stay on the default and join
> the public namespace.

Open discovery is best-effort by design — not every
discovered peer will connect:

> **Best-effort, by design.** Many discovered peers will fail
> to connect — they may be offline, behind incompatible NAT,
> running a different protocol version, or have peer ACLs
> that reject you. That's normal for ambient discovery;
> connection attempts are best-effort and rate-limited by
> `open_discovery_max_pending` (default 64). Your peer list
> grows over time as candidates land in the cache, not all
> at once on restart.

The peer ACL is the admission-control surface, separate from
discovery:

> **Open is admission-free under your peer ACL.** Open
> discovery does not bypass the peer ACL — every candidate
> still has to pass it. By default the ACL accepts everyone,
> so any publisher in the namespace becomes a connection
> candidate. If you rely on a non-default ACL for admission
> control, verify it is set the way you want *before*
> enabling `policy: open`. See
> [../reference/security.md](../reference/security.md) for
> the ACL format.

## Step 1: Confirm your starting state

You should be coming out of
[advertise-your-node](advertise-your-node.md) with:

- Persistent identity, advertising enabled
  (`discovery.nostr.advertise: true`), UDP advertising on
  Nostr (`transports.udp.advertise_on_nostr: true`).
- A static `test-us01` peer entry that the daemon dials
  outbound; possibly an inbound `test-us03` peer (the
  open-discovery test mesh node that dialed in after seeing
  your advert).

Capture the current peer count for comparison:

```sh
sudo fipsctl show peers | grep -c 'npub'
```

You'll likely see 1 (just `test-us01`) up to a handful, depending
on how many open-discovery test mesh nodes have already dialed
you.

## Step 2: Switch the discovery policy to `open`

Open `/etc/fips/fips.yaml` and find the `discovery.nostr`
block. Add (or change) the `policy` line:

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true
      policy: open
```

That's the only change. Notes on what you don't have to touch:

- **You don't have to drop the `peers:` block.** Static peers
  and open-discovered peers coexist; static entries get
  priority for direct dialing, open-discovered ones are
  layered on top.
- **You don't have to set `app`.** The default
  `fips-overlay-v1` is the namespace the public test mesh
  uses; staying with the default is what gets you discovered.
- **You don't have to set `open_discovery_max_pending`.** The
  default of 64 is plenty for a tutorial; only tune it if you
  see the daemon log
  `open-discovery: max-pending reached, deferring`.

Save the file.

## Step 3: Restart and let discovery populate

```sh
sudo systemctl restart fips
```

Give the daemon a minute or two. Open discovery doesn't fire
all at once — the daemon subscribes to the relays, accumulates
adverts as they arrive (or as relays return historical
events), and queues each publisher for a dial attempt.

## Step 4: Inspect the discovered peer list

```sh
sudo fipsctl show peers
```

You should see considerably more entries than before:

- `test-us01` — still there, still using the configured
  static dial path.
- `test-us03` — same as before (the open-discovery test
  mesh node that dials you when it sees your advert).
- `test-us04`, `test-de01`, `test-es01`, `test-uk01` — the
  other test mesh nodes; your daemon picked their adverts up
  from the namespace and dialed them.
- Plus any other operator publishing on `fips-overlay-v1`
  (community nodes, other operators' experiments).

Each entry has its own `connectivity` state. Some will be
`active` (handshake completed). Some will show as
`connecting` and may transition to `failed` shortly after —
that's normal; the publisher might be offline, the advert
might be stale, or NAT traversal failed for that pair.

To get a list of just the active links:

```sh
sudo fipsctl show peers | jq '.peers[] | select(.connectivity == "active") | .npub'
```

The peer count will continue to drift over time as adverts
expire and new ones arrive. This is steady-state behavior,
not a transient.

## Step 5: Confirm the mesh-wide reach

You can now reach any of the discovered nodes the same way
you reached `test-us01` and `test-us02` in
[join-the-test-mesh](join-the-test-mesh.md). Pick one of the
new test mesh nodes from the peer list and ping it by its
shortname:

```sh
ping6 -c 4 test-uk01.fips
```

(`test-uk01` is the United Kingdom test node; the installer's
`/etc/fips/hosts` entry resolves it to the corresponding npub.
Substitute any active peer's shortname or full
`<npub>.fips`.)

Expect four replies. The packet path may go through your
direct link to that peer (if the open-discovery dial succeeded
and the link is up) or via a test-mesh forwarder (if the
direct link is down but the destination is still reachable
through the mesh). Either way, the npub-as-name addressing
works the same way.

## What you've learned

- **Open discovery is the consume side of full ambient
  participation.** With `policy: open` plus advertising, your
  daemon both publishes its advert *and* consumes everyone
  else's in the namespace.
- **The namespace defines the scope.** Everyone publishing
  with the same `app` value finds each other; different
  namespaces are isolated discovery sets.
- **Best-effort means failure is normal.** Many discovered
  peers won't actually connect; that's expected and
  rate-limited by `open_discovery_max_pending`.
- **Static and open coexist.** Configured peers keep working
  with their own dial paths; open-discovered peers stack on
  top.
- **The peer ACL still gates everything.** Open is
  admission-free relative to discovery, not relative to your
  ACL — the ACL is what you'd use to restrict who can connect
  if you don't want a fully open posture.

## Custom namespaces for private experiments

If you want to use FIPS open discovery for a private set of
nodes — colleagues, a workshop cohort, a specific deployment
— set a custom `app` value:

```yaml
discovery:
  nostr:
    enabled: true
    advertise: true
    policy: open
    app: "my-team.experiment-1"
```

All nodes participating in the experiment use the same
`app` string. Pick something distinctive — short identifiers
risk colliding with other operators' experiments. Once your
nodes use a custom `app`, they no longer find or are found
by the public test mesh (the public mesh uses
`fips-overlay-v1`).

## Troubleshooting

If your peer list doesn't grow past the inbound peers from
the previous tutorial:

- **Wait.** Open discovery accumulates adverts; the first
  pass after restart can take a couple of minutes to populate
  on a new subscription.
- **Verify the namespace.** With `app:` unset, the daemon
  uses `fips-overlay-v1`. If you set a custom `app:` for an
  experiment, your daemon is in a different namespace than
  the public test mesh and will only find peers using the
  same value.
- **Check relay reachability.** Open discovery is a
  subscription rather than one-shot queries — if the
  WebSocket connection to the relays is failing repeatedly,
  no adverts arrive. Look for relay-connection errors in
  `sudo journalctl -u fips -n 200`.
- **`policy: open` typo.** YAML accepts and ignores unknown
  values silently. If `fipsctl show status` (or the daemon's
  startup log) shows `policy: configured_only`, the YAML
  didn't parse the new value — re-check spelling and
  indentation.

If too many peers are appearing and you want to dial down:

- **Lower `open_discovery_max_pending`.** Default 64; setting
  it to e.g. 16 caps in-flight connection attempts. Adverts
  beyond that wait in a queue.
- **Use a custom `app`.** Move to a private namespace where
  only nodes you're coordinating with publish.
- **Use the peer ACL.** See
  [../reference/security.md](../reference/security.md) for
  the ACL format if you want explicit allow/deny rules.

## What's next

- **Reach services on other mesh nodes.**
  [reach-mesh-services](reach-mesh-services.md) drives `nc`,
  `traceroute6`, `curl`, and `ssh` at peers by `.fips` name —
  any of the open-discovered peers in your list, or any node
  you reach through them.

- **Host a service of your own.**
  [host-a-service](host-a-service.md) brings up an HTTP server
  addressable as `<your-npub>.fips`, bound to `fips0` so the
  exposure is mesh-only, behind the mesh firewall.

- [ground-up-mesh](ground-up-mesh.md) — Bring up two devices on
  a shared physical link (Ethernet, WiFi, or Bluetooth) with no
  pre-existing IP infrastructure. The second deployment mode of
  FIPS, a parallel to the overlay-on-internet path the
  Nostr-discovery tutorials covered.

For the operator-style scenario reference covering all five
shapes of Nostr discovery side-by-side:

- [../how-to/enable-nostr-discovery.md](../how-to/enable-nostr-discovery.md)
  § Capability 3 — open discovery configuration knobs.

For the wire format and discovery design:

- [../reference/nostr-events.md](../reference/nostr-events.md)
  — Kind 37195 advert format and the `app` namespace tag.
- [../design/fips-nostr-discovery.md](../design/fips-nostr-discovery.md)
  — discovery runtime design, security and threat model.
