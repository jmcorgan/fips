# Enable Nostr-Mediated Discovery and NAT Traversal

Nostr-mediated discovery lets FIPS nodes find each other (and punch
through UDP NAT) using public Nostr relays as the signaling channel.
The feature ships in every stock packaging artifact but is **off by
default** — it activates when an operator sets
`node.discovery.nostr.enabled: true` and provides a relay list. See
[../design/fips-nostr-discovery.md](../design/fips-nostr-discovery.md)
for the design and rationale; see
[../reference/configuration.md](../reference/configuration.md) for the
full knob inventory.

Nostr discovery provides three independent capabilities. They can be
enabled separately; most deployments end up using two or three of
them together.

1. **Resolve a known peer's address by npub.** Your daemon consumes
   adverts from the relays to look up the current network endpoint
   for a peer you have configured by npub. You don't have to know
   their IP / port / transport in advance.
2. **Publish your own endpoint so others can resolve you.** Your
   daemon publishes a signed advert listing the transports it will
   accept connections on. Has two sub-shapes depending on your
   network topology: UDP (using NAT traversal if needed) or TCP.
   Running a Tor onion service is a separate deployment mode,
   covered in its own section below.
3. **Discover peers without prior configuration.** Your daemon
   subscribes to all adverts on a chosen application namespace and
   treats any publisher as a connection candidate. The most
   permissive posture; useful for ambient mesh participation.

Each capability is covered below as one or more scenarios with the
minimal YAML fragment that enables it. Only keys relevant to Nostr
discovery are shown; surrounding node, transport, TUN, DNS, and peer
configuration follows the usual shape.

All scenarios assume `node.identity` is set to a persistent key — an
ephemeral identity would invalidate any advert the moment the node
restarts. See [persistent-identity.md](persistent-identity.md) for
the persistent-key setup.

For hand-held walkthroughs of each capability, see the
[resolve-peers-via-nostr](../tutorials/resolve-peers-via-nostr.md),
[advertise-your-node](../tutorials/advertise-your-node.md),
and [open-discovery](../tutorials/open-discovery.md)
tutorials.

## Capability 1: Resolve a known peer's address by npub

The node does not publish any advert of its own. It only consumes
adverts for peers it has explicitly listed with `via_nostr: true`.
This is the right shape for a client that wants Nostr-mediated
resolution without becoming a rendezvous target itself.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: false
      policy: configured_only

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "npub1peer..."
    alias: "remote-node"
    via_nostr: true
    connect_policy: auto_connect
```

What this achieves: dial endpoints for this peer are taken from
the peer's published Nostr advert. `configured_only` is the
default — it is shown here for clarity.

> **Note:** You can also supply a static address alongside
> `via_nostr: true` (for example, while testing, or as a
> known-good fallback if the advert is stale). Add an `addresses`
> block to the peer entry; static addresses are tried first on
> dial and Nostr-resolved endpoints are appended as additional
> candidates.

## Capability 2: Publish your own endpoint so others can resolve you

This capability has three sub-scenarios depending on the network
shape your node sits behind.

### Sub-scenario 2a: UDP (using NAT traversal if needed)

The node has a public IP (or a stable port-forward) and binds UDP on
a known port. It publishes `udp:host:port` to the advert relays. Any
peer that knows this node's npub and has Nostr discovery enabled can
dial it without knowing the address out-of-band.

When UDP is wildcard-bound (`0.0.0.0:2121`, the default), the daemon
needs help knowing what IP to put in the advert. There are two ways:
STUN auto-discovery (`public: true`) or an explicit override
(`external_addr`). Both are first-class options; pick the one that
fits the deployment.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    public: true                  # ← STUN auto-discovery
```

Or, when the public IP is known up front (static residential IP,
cloud Elastic IP behind 1:1 NAT, etc.):

```yaml
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    external_addr: "203.0.113.45:2121"   # ← explicit
```

`external_addr` accepts a bare IP (combined with the bind port) or a
full `host:port`. Setting both `public: true` and `external_addr`
together is allowed — the explicit override wins, with STUN as a
logging cross-check. If UDP is bound directly to a public IP rather
than to a wildcard, neither flag is needed; the daemon advertises
the bound endpoint.

What this achieves: the node publishes a single
`udp:<public-ip>:2121` endpoint to the three default advert relays
(`wss://relay.damus.io`, `wss://nos.lol`, `wss://offchain.pub`).

What the other side needs: either a static `addresses` entry for this
peer, or a peer entry with `via_nostr: true` and an empty (or
omitted) `addresses` list — the advert-resolved endpoint will be used
at dial time. Static and Nostr-resolved addresses can also be
combined: when both are present, static addresses are tried first and
Nostr-resolved endpoints are appended as fallback.

#### When the node is behind NAT

If this node doesn't have a stable public UDP endpoint, advertise
`udp:nat`. The daemon runs the STUN + offer/answer exchange with
the peer and punches through the NAT to establish a direct UDP
link. The peer can either have a public endpoint of its own or
also be behind NAT — both shapes work, as long as at least one
side has a NAT type compatible with hole-punching.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true
      dm_relays:                       # overrides the default three-relay
        - "wss://relay.damus.io"        # set with two for demonstration;
        - "wss://nos.lol"               # omit this block to keep the defaults
      stun_servers:
        - "stun:stun.l.google.com:19302"
        - "stun:stun.cloudflare.com:3478"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    public: false

peers:
  - npub: "npub1peer..."
    alias: "nat-peer"
    addresses:
      - transport: udp
        addr: "nat"
    via_nostr: true
    connect_policy: auto_connect
```

What this achieves: the node publishes a `udp:nat` endpoint plus its
signaling relays in the advert. When either side initiates, an
encrypted offer is sealed to the peer's npub, a matching answer
comes back, and both sides punch at the negotiated time. On success,
the punch socket is adopted as an FMP UDP transport and Noise XX
proceeds normally.

> **Validation:** `advertise_on_nostr: true` with `public: false` on
> UDP requires `dm_relays` and `stun_servers` to be non-empty. Both
> ship with non-empty defaults (three relays and three STUN servers
> respectively), so the default config passes. The node fails
> startup only if the operator has explicitly emptied either list —
> a `udp:nat` advert without signaling relays or STUN servers is
> unreachable by construction.

Works best with full-cone NAT on at least one side. Symmetric NAT on
both sides is not reliably traversable with this protocol and will
time out after `punch_duration_ms`.

### Sub-scenario 2b: TCP

The node has a public IP (or a stable port-forward) and accepts
inbound TCP. It publishes `tcp:host:port` to the advert relays.

TCP endpoints exist to serve peers whose networks filter outbound
UDP (corporate LANs, restrictive guest WiFi). NAT traversal does
not apply: the publishing node is publicly reachable on TCP, and
the dialing peer's network only needs to permit outbound TCP to
the advertised port.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true

transports:
  tcp:
    bind_addr: "0.0.0.0:8443"
    advertise_on_nostr: true
    external_addr: "203.0.113.45:8443"
```

`external_addr` is typically required on cloud setups (AWS Elastic
IP, etc.) where binding directly to the public IP returns
`EADDRNOTAVAIL`. When TCP is bound directly to a public IP, the
override is unnecessary.

What this achieves: the node publishes a `tcp:<public-ip>:8443`
endpoint to the advert relays. Peers with Nostr discovery enabled
dial by npub without out-of-band address exchange.

### Tor onion node

A separate deployment mode for nodes that want anonymity and
censorship-resistance properties on the data plane. Functionally
this still uses Capability 2 (publishing an endpoint to advert
relays) — the difference is that the published endpoint is a Tor
hidden service rather than a public IP.

The node runs a Tor onion service in directory mode (Tor-managed
`HiddenServiceDir`) and advertises the `.onion` address. Peers dial
via their local Tor SOCKS5 proxy without ever knowing the onion
string out-of-band. For the Tor daemon side of this setup, including the inbound-mode
trade-offs and the `torrc` directives each requires, see
[deploy-tor-onion.md](deploy-tor-onion.md).

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true

transports:
  tor:
    mode: directory
    socks5_addr: "127.0.0.1:9050"
    directory_service:
      hostname_file: "/var/lib/tor/fips/hostname"
      bind_addr: "127.0.0.1:8444"
    advertise_on_nostr: true
```

What this achieves: the node publishes a `tor:<hash>.onion:8443`
endpoint alongside any other advertised transports. The advert itself
is still published over clearnet WebSocket relays — Tor protects the
data plane, not the discovery plane. See the security and threat
model section in
[../design/fips-nostr-discovery.md](../design/fips-nostr-discovery.md#security-and-threat-model)
for the trade-off and how to route relay traffic through Tor as well.

## Capability 3: Discover peers without prior configuration

Under `policy: open`, any node that publishes an advert under the
same `app` namespace becomes a candidate. Discovered peers are queued
for connection attempts subject to `open_discovery_max_pending`.

```yaml
node:
  identity:
    persistent: true
  discovery:
    nostr:
      enabled: true
      advertise: true
      policy: open
      open_discovery_max_pending: 64
      app: "my-experiment.v1"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    advertise_on_nostr: true
    public: true

peers: []
```

What this achieves: peers are discovered entirely through ambient
advert traffic on the configured relays. Setting a non-default `app`
value (replacing `fips-overlay-v1`) scopes the discovery set to
participants who opt into the same experiment and avoids being joined
to unrelated overlays that happen to share the default namespace.

> **Scope warning:** Open discovery is an admission-free mode. Any
> node that publishes on the same `app` name and passes the peer-ACL
> check becomes a connection candidate. If you rely on peer ACLs for
> admission control, verify that list is set correctly before
> enabling this mode. See
> [../reference/security.md](../reference/security.md) for the peer
> ACL format.

## See also

- [../tutorials/resolve-peers-via-nostr.md](../tutorials/resolve-peers-via-nostr.md)
  — hand-held walkthrough of capability 1
- [../tutorials/advertise-your-node.md](../tutorials/advertise-your-node.md)
  — hand-held walkthrough of capability 2 (publish, plus a
  short section on `udp:nat` NAT traversal)
- [../tutorials/open-discovery.md](../tutorials/open-discovery.md)
  — hand-held walkthrough of capability 3 (open ambient
  discovery, the additive policy: open mode)
- [../design/fips-nostr-discovery.md](../design/fips-nostr-discovery.md)
  — discovery runtime design, security model
- [../reference/configuration.md](../reference/configuration.md) —
  full `node.discovery.nostr.*` and per-transport
  `advertise_on_nostr`/`public` table
- [../reference/nostr-events.md](../reference/nostr-events.md) — Kind
  37195 advert format, Kind 21059 traversal signaling, Kind 10050
  inbox relay list
- [deploy-tor-onion.md](deploy-tor-onion.md) — Tor daemon-side setup
  for advertising onion endpoints
