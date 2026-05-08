# Advertise Your Node on Nostr

After
[resolve-peers-via-nostr](resolve-peers-via-nostr.md) your
daemon can look up a peer's current endpoint by npub. This
tutorial flips it around: you publish a signed advert listing
your own endpoint(s), so any other operator who knows your
npub can dial you the same way you dialed `test-us01`.

The whole exercise should take about ten minutes if you have
a public IP or full-cone home NAT. A short final section
covers the alternative path for symmetric-NAT networks.

## What you'll build

```text
   ┌───────────────────────┐
   │   your fips daemon    │
   │   persistent npub     │
   └──────────┬────────────┘
              │ signed advert (Kind 37195)
              │   { udp:<your-public-ip>:2121, ... }
              │ refreshes every 30 min
              ▼
   ┌──────────────────────────────────────────┐
   │ Nostr relays                             │
   │   relay.damus.io / nos.lol / offchain.pub│
   └──────────────────────┬───────────────────┘
                          │
                          │ "what's <your-npub>'s endpoint?"
                          │
              ┌───────────┴───────────┐
              │  another fips daemon  │
              │  knows your npub,     │
              │  via_nostr: true      │
              └───────────────────────┘
```

You will change two things in `/etc/fips/fips.yaml`:

- Flip `discovery.nostr.advertise` from `false` to `true`.
- Add `advertise_on_nostr: true` and `public: true` under
  `transports.udp`.

After restart, your daemon publishes a Kind 37195 event tied
to your npub, listing the UDP endpoint other peers should
dial.

## How advertising works

> **Adverts are signed Nostr events.** Every advert is a Kind
> 37195 event signed by your daemon's secret key. Anyone
> reading it can verify the advert really came from the npub
> claiming the endpoint. The advert is the `(npub → current
> endpoints)` mapping, signed and published.

The advert lists transports the daemon is willing to expose,
and only those:

> **Endpoints are opt-in per transport.** Only transports
> with `advertise_on_nostr: true` are listed in your advert.
> Transports without that flag stay private — they still
> work for peers who reach you via static config, but they
> won't appear in your published advert.

For UDP specifically, the daemon needs to know what IP and
port to put in the advert:

> **Determining the advertised endpoint (wildcard-bound UDP).**
> With UDP bound to a wildcard like `0.0.0.0:2121`, the daemon
> doesn't know its own public IP at startup. You have two ways
> to tell it what to put in the advert:
>
> - `public: true` — daemon does a one-shot STUN observation
>   against the configured STUN servers and uses the reflexive
>   IPv4 it learns. Right when your public IP is dynamic or
>   you'd rather not pin it in config. Works for nodes with a
>   directly-bound public IP and for nodes behind full-cone
>   NAT (most home routers).
> - `external_addr: "<ip>[:<port>]"` — explicit override.
>   Right when you already know your public IP — a static
>   residential IP, an Elastic IP behind 1:1 NAT, a cloud
>   instance whose advertised port differs from the bind
>   port — and you don't want to depend on STUN reachability.
>   Required for TCP on cloud setups where binding directly
>   to the public IP returns `EADDRNOTAVAIL`.
>
> If you bind UDP to a specific public IP rather than
> `0.0.0.0`, neither flag is needed — the daemon advertises
> whatever it's bound to.

Adverts don't sit on the relays forever:

> **TTL and refresh.** Adverts have a 1-hour expiration
> (NIP-40 `expiration` tag) and the daemon re-publishes every
> 30 minutes. If your daemon goes offline, your advert decays
> from caches in roughly an hour and consumers stop trying.

## Step 1: Confirm your starting state

You should be coming out of
[resolve-peers-via-nostr](resolve-peers-via-nostr.md) with:

- A persistent npub (`fipsctl show status | grep '"npub"'`).
- Nostr discovery in consume-only mode
  (`discovery.nostr.enabled: true`,
  `discovery.nostr.advertise: false`).
- A peer entry for `test-us01` with `via_nostr: true` and no
  static address. `fipsctl show peers` shows the link
  established.

If any of those isn't true, finish the previous tutorials
first.

Capture your npub now — you'll need it for the verification
step:

```sh
sudo fipsctl show status | grep '"npub"'
```

Copy the value.

## Step 2: Enable advertising in the config

Open `/etc/fips/fips.yaml` and change two things.

**Change 1: flip `advertise` to `true`.** Find the
`discovery.nostr` block under `node:` and set:

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true
```

(The previous tutorial set `advertise: false`; you're flipping
that bit now.)

**Change 2: add the UDP advert flags.** Find the `udp:` block
under `transports:`. The wildcard-bind default
(`0.0.0.0:2121`) means the daemon needs help knowing what to
advertise — pick one of the two approaches from the callout
above.

If you want STUN auto-discovery (works for full-cone NATs and
nodes with a directly-bound public IP):

```yaml
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    public: true
```

If you already know your public IP (e.g., a static residential
IP or a cloud Elastic IP behind 1:1 NAT) and want to skip the
STUN dependency:

```yaml
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    external_addr: "203.0.113.45:2121"
```

Replace `203.0.113.45:2121` with your actual public IP and
port. The bare-IP form `external_addr: "203.0.113.45"` is also
accepted; the daemon combines it with the bind port. You may
set both `public: true` and `external_addr` together — the
explicit override wins, with STUN as a logging cross-check.

`advertise_on_nostr: true` is the bit that says "include this
transport in my published advert" — common to both paths.

Save the file.

## Step 3: Restart the daemon

```sh
sudo systemctl restart fips
sudo systemctl status fips
```

Status should show `active (running)`. Within a few seconds the
daemon will:

1. Run a one-shot STUN observation against the default STUN
   servers to learn its public IP.
2. Build a Kind 37195 advert listing
   `udp:<public-ip>:2121` (and any other transports you have
   `advertise_on_nostr: true` on).
3. Sign the advert with the daemon's nsec.
4. Publish it to the three default advert relays.
5. Schedule a refresh every 30 minutes.

If STUN fails (for example, if the network blocks outbound
UDP/3478), the daemon emits a WARN line in the journal and
suppresses the UDP entry from the advert rather than publishing
a wrong address. The link to `test-us01` from the previous
tutorial keeps working regardless — only the publish side is
gated on STUN.

Quick sanity check on the journal:

```sh
sudo journalctl -u fips -n 200 | grep -iE 'STUN|advert|warn' | head -20
```

If you see `WARN` lines mentioning STUN or wildcard-bind
fallthrough, jump to [Troubleshooting](#troubleshooting); the
rest of the tutorial assumes the publish succeeded.

## Step 4: Verify your advert is on the network

The advert is a public Nostr event — anyone, including you,
can fetch it. With the `nak` Nostr CLI installed, query the
relays for adverts published by your npub:

```sh
nak req -k 37195 -d "fips-overlay-v1" \
    -a $(nak decode <your-npub> | jq -r .pubkey) \
    --limit 1 wss://relay.damus.io
```

Replace `<your-npub>` with the npub you copied in Step 1. The
inner `nak decode` converts your bech32 npub to the hex pubkey
the relay filter expects.

Expect one event back. The interesting fields:

- `pubkey` — your npub in hex form.
- `tags` — includes `["d","fips-overlay-v1"]` (the namespace),
  `["protocol","fips-overlay-v1"]`, and an `["expiration", …]`
  tag set ~1 hour in the future.
- `content` — JSON listing the `endpoints` array. You should
  see one entry like:

  ```json
  {"transport":"udp","addr":"<your-public-ip>:2121"}
  ```

That `<your-public-ip>` is what STUN learned. Confirm it
matches what you'd expect for your network — for a home node,
it should be your residential IP, not a `192.168.x.x` LAN
address.

## Step 5: Watch for inbound connections

Your advert is now consumable by any FIPS daemon running open
discovery on the same `fips-overlay-v1` namespace. The public
test mesh nodes do exactly this — they subscribe to all
adverts in the namespace and try to dial new publishers.

Within a minute or two of restart, run:

```sh
sudo fipsctl show peers
```

In addition to your configured `test-us01` peer, you may see
an entry for `test-us03` (the open-discovery test mesh node).
It will have `connectivity` active and its own
`transport_addr`. This peering appeared without you
configuring anything — the test-mesh open-discovery node saw
your advert, dialed the endpoint, and Noise XX established
the link.

If no inbound peers appear, that's not necessarily a failure
of advertising — it just means no one has consumed your advert
*and* dialed back yet. The advert is on the relays regardless,
verifiable in Step 4.

## What you've learned

- **Adverts are publish + sign.** Every running FIPS daemon
  with `advertise: true` publishes a signed advert; reading it
  is one Nostr event lookup.
- **Endpoint inclusion is per-transport.** Only the transports
  you set `advertise_on_nostr: true` on appear in the advert.
- **`public: true` invokes STUN.** Wildcard-bound UDP with
  `public: true` runs a one-shot STUN observation to learn
  its public IP.
- **Refresh is automatic.** Adverts re-publish every 30
  minutes; consumers cache them with a 1-hour staleness
  bound.
- **The publish side stands alone.** Once your advert is on
  the relays, peers can dial you whether you're advertising
  to them specifically or not. The test mesh's open-discovery
  nodes will pick you up automatically.

## If you're behind symmetric NAT

`public: true` + STUN works on most home and office NATs (the
full-cone variety) and on nodes with a directly-bound public
IP. It does *not* work on symmetric NAT, where the NAT mapping
is keyed on (source-port, destination-host) so the IP/port
your STUN server saw isn't the IP/port a different peer would
see.

For symmetric-NAT networks the alternative is `udp:nat` mode,
which advertises a placeholder `udp:nat` endpoint along with
the daemon's signaling-relay and STUN-server lists, and
performs UDP hole-punching at dial time. Both sides need to be
running matching configs and at least one side needs a
non-symmetric NAT for the punch to succeed; symmetric on both
sides is not reliably traversable and will time out.

The minimal config switch:

```yaml
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    public: false                 # ← was true; change to false
```

And add the signaling/STUN block under `discovery.nostr`:

```yaml
discovery:
  nostr:
    enabled: true
    advertise: true
    dm_relays:
      - "wss://relay.damus.io"
      - "wss://nos.lol"
    stun_servers:
      - "stun:stun.l.google.com:19302"
      - "stun:stun.cloudflare.com:3478"
```

For the full setup including peer-side config and the punch-
duration knob, see
[../how-to/enable-nostr-discovery.md § Capability 2c](../how-to/enable-nostr-discovery.md#sub-scenario-2c-udp-hole-punching-for-nodes-behind-nat).

Separately from NAT considerations, FIPS supports running a
node behind a Tor onion service as a deployment shape in its
own right — chosen for the privacy, anonymity, and
censorship-resistance properties it brings, not as a fallback
when UDP or TCP fail. If those properties are an independent
goal for your node, see
[../how-to/enable-nostr-discovery.md § Sub-scenario 2b](../how-to/enable-nostr-discovery.md#sub-scenario-2b-tor-onion-node)
and
[../how-to/deploy-tor-onion.md](../how-to/deploy-tor-onion.md).

## Troubleshooting

If your advert doesn't appear on the relays:

- **STUN failed.** Check the journal for WARN lines mentioning
  STUN or wildcard-bind. The most common causes are outbound
  UDP/3478 blocked or DNS for `stun.l.google.com` failing.
  Try: `dig stun.l.google.com` and
  `nc -uvz stun.l.google.com 19302` to verify reachability.
- **Wrong public IP advertised.** If `nak` shows your advert
  with a non-public address (e.g., `10.x.x.x` or
  `192.168.x.x`), STUN didn't see your real public IP — likely
  you're behind a CGNAT that NATs your STUN traffic too, or a
  corporate firewall that proxies it. Switch to the
  `external_addr` form from Step 2 with your actual public
  IP, or replace `public: true` with the bound interface IP
  directly under `bind_addr`.

- **Relay reachability.** `nak req` against a relay you can
  reach but no events return — possibly the publish failed
  silently because the daemon couldn't connect to that
  specific relay. Try the other two:

  ```sh
  nak req ... wss://nos.lol
  nak req ... wss://offchain.pub
  ```

- **`advertise_on_nostr` typo.** YAML is case-sensitive and
  silently ignores unknown keys. If `nak` returns no advert at
  all, double-check the spelling on the UDP block and that
  `discovery.nostr.advertise: true` is also set.

## What's next

- **Open discovery.**
  [open-discovery](open-discovery.md) flips the consume side
  symmetric — switch your daemon to `policy: open` and watch
  your peer list populate from the ambient
  `fips-overlay-v1` namespace, the same mechanism
  `test-us03` is using right now to find you.

- **Host a service of your own.**
  [host-a-service](host-a-service.md) walks through bringing up
  an HTTP server addressable as `<your-npub>.fips`, the same
  way the connecting node now reaches `test-us01`. The natural
  follow-on now that other operators can dial you by npub.

For the operator-style scenario reference covering all five
shapes of Nostr discovery side-by-side (consume-only,
publish-direct, publish-Tor, NAT traversal, open):

- [../how-to/enable-nostr-discovery.md](../how-to/enable-nostr-discovery.md)

For the wire-format and discovery design:

- [../reference/nostr-events.md](../reference/nostr-events.md)
  — Kind 37195 advert format, Kind 21059 traversal signaling.
- [../design/fips-nostr-discovery.md](../design/fips-nostr-discovery.md)
  — discovery runtime design, security and threat model.
