# Resolve Peer Addresses via Nostr

After
[persistent-identity](persistent-identity.md), your daemon has
a stable npub and is peered with `test-us01` over a hard-coded
UDP address (`test-us01.fips.network:2121`). That static
address works fine until `test-us01` moves to a new IP, swaps
ports, or starts publishing additional endpoints you'd want to
reach. The npub is stable; the set of network endpoints behind
it may not be.

This tutorial shows the smallest useful step toward Nostr-
mediated discovery: keep the peer entry but drop its address,
let your daemon ask public Nostr relays for the peer's current
endpoint, and verify the link still works. You will not be
publishing anything yourself yet — this is the consume-only
case.

The whole exercise should take about ten minutes.

## What you'll build

```text
                        ┌──────────────────────────┐
                        │  Nostr relays            │
                        │   relay.damus.io         │
                        │   nos.lol                │
                        │   offchain.pub           │
                        └────────────▲─────────────┘
   "what's test-us01's                │ signed advert
    current address?"                 │ (Kind 37195)
                                      │ from test-us01
   ┌───────────────────────┐          │
   │   your fips daemon    │ ─────────┘
   │   peers:              │
   │     - test-us01 npub  │ ─── dial resolved UDP ──▶ test-us01
   │       via_nostr: true │
   └───────────────────────┘
```

You'll change two things in `/etc/fips/fips.yaml`:

- Add a `node.discovery.nostr` block that turns the consume-
  side of Nostr discovery on.
- Edit the existing `test-us01` peer entry to drop its hard-
  coded `addresses:` block and add `via_nostr: true`.

After restart, the daemon will fetch `test-us01`'s current
advert from the relays, use the endpoint listed there, and
peer normally.

## How Nostr discovery resolves an address

Every FIPS daemon with `node.discovery.nostr.advertise: true`
publishes a signed Nostr event (Kind 37195) listing the
transport endpoints it is willing to accept connections on.
The event is signed by the daemon's secret key, so anyone
who has the corresponding npub can verify the advert really
came from that node.

`test-us01` runs with `advertise: true`. Its current advert is
visible to any Nostr client.

> **Identity is stable; endpoints are not.** A peer's npub is
> a long-lived identifier — it is who they are. Their UDP
> address, port, or transport choice is metadata that may
> change. Nostr discovery lets you bind your peer entry to the
> npub and lets the relay tell your daemon the current
> endpoint at dial time.

There are two halves to this — consuming adverts (looking up
peers by npub) and publishing adverts (being lookup-able). This
tutorial covers only the consume half.

> **Consume vs. publish.** This tutorial enables only the
> *consume* side: your daemon queries relays to resolve peers
> by npub. It does not publish an advert of its own — others
> still cannot find you by your npub yet. The next tutorial
> (`advertise-your-node`) handles the publish side.

## Step 1: Confirm your starting state

You should currently have:

- A persistent npub from
  [persistent-identity](persistent-identity.md). Confirm:

  ```sh
  sudo fipsctl show status | grep '"npub"'
  ```

- A working static peering with `test-us01`. Confirm:

  ```sh
  sudo fipsctl show peers
  ```

  Expect `test-us01` listed with `connectivity` active and a
  `transport_addr` of roughly `test-us01.fips.network:2121`.

If either of those isn't true, finish the previous two
tutorials first; the Nostr discovery layer is built on top of
that working state.

## Step 2: Enable the consume side of Nostr discovery

Open `/etc/fips/fips.yaml` and add a `discovery` block under
`node:`:

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: false
```

Two knobs, one job each:

- `enabled: true` turns on the Nostr discovery runtime — the
  daemon connects to a default relay set
  (`wss://relay.damus.io`, `wss://nos.lol`,
  `wss://offchain.pub`) and is now able to query and consume
  adverts.
- `advertise: false` keeps the publish side off. Your daemon
  will not publish an advert of its own at this stage. The
  default is `true`, so we are setting it explicitly to
  disable advertising for this consume-only tutorial. The next
  tutorial flips it back on.

## Step 3: Switch the peer entry to `via_nostr`

Find the `peers:` block you added during
[join-the-test-mesh](join-the-test-mesh.md) and change it from
this:

```yaml
peers:
  - npub: "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98"
    alias: "test-us01"
    addresses:
      - transport: udp
        addr: "test-us01.fips.network:2121"
    connect_policy: auto_connect
```

to this:

```yaml
peers:
  - npub: "npub1qmc3cvfz0yu2hx96nq3gp55zdan2qclealn7xshgr448d3nh6lks7zel98"
    alias: "test-us01"
    via_nostr: true
    connect_policy: auto_connect
```

What changed: the `addresses:` list is gone, replaced by
`via_nostr: true`. The npub stays — it is what the daemon
matches against the advert publisher's pubkey.

Save the file.

## Step 4: Restart the daemon

```sh
sudo systemctl restart fips
sudo systemctl status fips
```

The status output should show `active (running)` within a
couple of seconds. The Nostr discovery runtime starts alongside
the rest of the daemon, fetches `test-us01`'s advert from the
default relays, and uses the endpoint listed there to dial.

The resolution itself happens at debug-log level, so you will
not see it in the default-level journal. The user-facing way to
confirm everything worked is `fipsctl show peers` in the next
step. (To watch the resolution in the journal, run the daemon
manually with `RUST_LOG=fips::discovery::nostr=debug`; not
necessary for this tutorial.)

## Step 5: Verify the resolved endpoint

```sh
sudo fipsctl show peers
```

`test-us01` should appear with `connectivity` active and a
`transport_addr` reflecting the address that was resolved from
the advert — `test-us01.fips.network:2121` at time of writing. That field
is the strong signal: nothing in your config gave the daemon
that IP, yet there it is.

You can confirm independently that the address came from the
advert. The advert is a public Nostr event — anyone can fetch
it. With the `nak` Nostr CLI installed:

```sh
nak req -k 37195 -d "fips-overlay-v1" \
    -a 06f11c31227938ab98ba982280d2826f66a063f9efe7e342e81d6a76c677d7ed \
    --limit 1 wss://relay.damus.io
```

(That hex pubkey is the same identity as
`npub1qmc3...zel98` — Nostr filters take hex.) The `content`
field of the returned event lists the `endpoints` array; one
of its entries should match what `fipsctl show peers` is
using. That is what your daemon just did, signed and verified
by the Nostr layer.

## Step 6: Confirm reachability still works

```sh
ping6 -c 4 test-us01.fips
```

Expect four replies, exactly as in
[join-the-test-mesh](join-the-test-mesh.md) (which used the
full npub form). Nothing about the data plane has changed;
only the way you discovered the endpoint to dial.

## What you've learned

- **Adverts are signed.** Every Nostr discovery advert is
  signed by the publisher's secret key, so the address you
  resolved through a public relay is trustworthy in the same
  sense the peer's npub is.
- **`via_nostr` replaces a static address.** A peer entry
  with no `addresses:` block and `via_nostr: true` directs
  the daemon to look the endpoint up at dial time.
- **The relay set is small and public.** Three default
  relays today; the daemon round-robins queries across them.
  No central FIPS infrastructure is involved.
- **Static and Nostr can mix.** You replaced the static
  address with `via_nostr` here, but you could have kept both
  — when both are present, static endpoints are tried first
  and Nostr-resolved endpoints are appended as a fallback.
  Useful when you want a fast-path direct dial but a
  resilient fallback.

## Troubleshooting

If the link does not come up:

- **No advert on the relays.** If the peer's daemon is
  offline or has `advertise: false`, no advert exists for
  your daemon to consume. Verify with `nak` (Step 5) — if the
  query returns nothing, that is the problem and it is on the
  peer's side. Re-add the static `addresses:` entry as a
  fallback while you wait for the peer to come back up.
- **Relay reachability.** `Connected to relay` lines should
  appear for at least one of the three default relays. If
  none do, your network may be filtering outbound WebSocket
  traffic or DNS for those hostnames. Check the journal for
  TLS/DNS errors.
- **Stale cache.** The daemon caches resolved endpoints
  briefly. If a peer's advert changes mid-session and you
  hit a stale entry, restart the daemon to force a fresh
  query.
- **Persistent identity not on.** If the journal shows
  `Using ephemeral identity (new keypair each start)`, the
  daemon falls back to ephemeral and the consume-side may
  not behave as expected. Re-check
  [persistent-identity](persistent-identity.md) Step 2.

## What's next

- **Advertise your own node.**
  [advertise-your-node](advertise-your-node.md) publishes your
  daemon's UDP endpoint on Nostr so other operators can add
  you to their `peers:` list with `via_nostr: true` and reach
  you the way you just reached `test-us01`. Includes a short
  final section on `udp:nat`, the best-effort hole-punching
  path for nodes without a directly reachable UDP endpoint.

- **Discover peers with no prior configuration.**
  [open-discovery](open-discovery.md) switches your daemon to
  `policy: open` so the ambient namespace itself populates
  your peer list — no static `peers:` entries required (the
  static ones can stay too; the two mechanisms run in
  parallel).

For the operator-style scenario reference covering all five
shapes of Nostr discovery side-by-side (consume-only,
publish-direct, publish-Tor, NAT traversal, open):

- [../how-to/enable-nostr-discovery.md](../how-to/enable-nostr-discovery.md)
  — five scenarios with minimal YAML fragments.

For the design and security model:

- [../design/fips-nostr-discovery.md](../design/fips-nostr-discovery.md)
  — discovery runtime architecture, advert format, threat
  model.

For the wire-format details:

- [../reference/nostr-events.md](../reference/nostr-events.md)
  — Kind 37195 advert format, Kind 21059 traversal signaling,
  Kind 10050 inbox-relay list.
