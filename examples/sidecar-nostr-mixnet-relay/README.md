# FIPS over a Mixnet — Single-Container Demo (Nym)

An isolated environment demonstrating how FIPS peer traffic can travel
through a **mixnet** — a network that hides traffic patterns by routing
each packet through several relays with cover traffic and timing
obfuscation. The mixnet here is [Nym](https://nym.com/), but the FIPS side
is transport-agnostic: it just sees a SOCKS5 proxy, so any mixnet exposing
one would slot in the same way.

**Everything runs in one Docker container**: the FIPS daemon, the mixnet
proxy (`nym-socks5-client`), a [strfry](https://github.com/hoytech/strfry)
Nostr relay behind nginx, and dnsmasq.

```
┌────────────────────────── one container ───────────────────────────┐
│                                                                    │
│  nginx :80 ──► strfry :7777          (Nostr relay, fips0-only)     │
│                                                                    │
│  fips daemon ── transports.nym ──► nym-socks5-client :1080         │
│      │                                   │                         │
│      ▼                                   ▼ Sphinx packets          │
│   fips0 (TUN, fd00::/8)           Nym gateway ► 3 mix hops ►       │
│                                   network requester ► peer (TCP)   │
│                                                                    │
│  iptables: direct route to the peer is DROPped — the FIPS link     │
│  can only exist through the mixnet.                                │
└────────────────────────────────────────────────────────────────────┘
```

How the pieces interlock:

- The FIPS **nym transport** dials peers through a local SOCKS5 proxy; the
  proxy routes each TCP stream through the mixnet (gateway → 3 mix hops →
  network requester), which performs the final TCP connection to the peer.
  The peer address must therefore be a **TCP endpoint** — find public peers
  at <https://join.fips.network/>.
- The `nym-socks5-client` is started by the entrypoint **only when the
  generated FIPS config contains a `transports.nym` block**
  (`FIPS_PEER_TRANSPORT=nym`), and always **before** the FIPS daemon, so
  the proxy is listening by the time FIPS dials.
- In nym mode, iptables **drops the direct route to the peer**: if the peer
  handshake completes, the traffic provably went through the mixnet.

## Quick start

```bash
# 1. Generate a node identity (any machine with fipsctl, or reuse one):
fipsctl keygen

# 2. Put the nsec into the environment:
export FIPS_NSEC=<your-nsec>

# 3. Build and run (native image; FIPS compiles for your host's arch):
docker compose up --build
```

Watch the logs: the entrypoint auto-discovers a Nym service provider,
bootstraps the SOCKS5 client (`Nym SOCKS5 proxy ready …`), and only then
starts FIPS. After the mixnet handshake completes (can take 30–120 s):

```bash
docker compose exec fips fipsctl show transports   # nym transport: up
docker compose exec fips fipsctl show peers        # test-us03: active
```

## Switching transport: mixnet ↔ direct (TCP/UDP)

The single knob is `FIPS_PEER_TRANSPORT` in `.env` (or an inline override).
It selects how FIPS reaches the peer **and** whether the mixnet proxy runs
at all — the two are always in sync.

```bash
# Default — through the Nym mixnet (anonymized, ~1-2 s RTT):
FIPS_PEER_TRANSPORT=nym  docker compose up -d        # or just `docker compose up -d`

# Direct TCP (no mixnet, ~50-300 ms RTT). The nym client is NOT started:
FIPS_PEER_TRANSPORT=tcp  docker compose up -d

# Direct UDP — also point FIPS_PEER_ADDR at the peer's UDP endpoint:
FIPS_PEER_TRANSPORT=udp  FIPS_PEER_ADDR=54.183.70.180:2121  docker compose up -d
```

What changes under the hood for each value:

| `FIPS_PEER_TRANSPORT` | nym client | FIPS config block | peer endpoint used | direct route to peer |
| --- | --- | --- | --- | --- |
| `nym` (default) | started, before FIPS | `transports.nym` | `FIPS_PEER_ADDR` (TCP) via SOCKS5 | **firewalled off** |
| `tcp` | not started | `transports.tcp` | `FIPS_PEER_ADDR` (TCP) direct | allowed |
| `udp` | not started | `transports.udp` | `FIPS_PEER_ADDR` (UDP `:2121`) direct | allowed |

To **switch back to a direct link**, set the value to `tcp` (no other change)
or `udp` (and swap `FIPS_PEER_ADDR` to the `:2121` endpoint), then re-run
`docker compose up -d`. To **return to the mixnet**, set it back to `nym`.
Persist your choice by editing `.env` instead of prefixing the command.
The same node can be compared both ways — direct shows ~50-300 ms RTT,
the mixnet ~1-2 s, which is the visible signature that traffic is routing
through the Sphinx mix hops.

## Verifying the traffic really crosses the mixnet

```bash
# The direct route to the peer is dropped — the only way packets reach
# the peer is via the nym-socks5-client:
docker compose exec fips iptables -L OUTPUT -v -n   # DROP rule for peer IP

# Mixnet activity (Sphinx packet flow) in the nym client output:
docker compose logs fips | grep -i nym

# End-to-end data plane across the mesh. FIPS addresses every node by its
# key as <npub>.fips (each npub maps into fd00::/8); short names like
# `test-us03` are only local aliases for the peer you configured. Pick a
# node you are NOT directly linked to — grab a current npub from
# https://join.fips.network/ — so the ICMPv6 echo routes over the mixnet
# to your peer and then hop-by-hop across the mesh to the target:
docker compose exec fips ping6 -c3 <peer-npub>.fips

# A reply while the direct route is DROPped proves the traffic crossed the
# mixnet; the seconds-range RTT is the Sphinx path's signature, and a few
# extra hundred ms over reaching your own peer is the added mesh hops (a
# direct, non-mixnet connection would be ~30 ms).
```

The Nostr relay answers only over the FIPS mesh (fd00::/8) and on the
container's loopback — inbound eth0 traffic, including the host's port-80
mapping, is dropped by the isolation rules. Check it from inside:

```bash
docker compose exec fips curl -s -H "Accept: application/nostr+json" http://127.0.0.1/
```

## Configuration (.env)

| Variable | Default | Meaning |
| --- | --- | --- |
| `FIPS_NSEC` | *(required)* | Node identity, `fipsctl keygen` |
| `FIPS_PEER_NPUB` | test-us03's npub | Peer to dial; empty = standalone |
| `FIPS_PEER_ADDR` | `54.183.70.180:443` | **TCP** endpoint in nym/tcp mode (use `:2121` for udp) |
| `FIPS_PEER_TRANSPORT` | `nym` | `nym` \| `tcp` \| `udp` — see "Switching transport" above |
| `NYM_SERVICE_PROVIDER` | *(auto)* | Network requester; empty = pick the best-scored from [harbourmaster](https://harbourmaster.nymtech.net/) |
| `NYM_CLIENT_ID` | `fips-nym-client` | Nym client identity (kept in the `nym-data` volume) |

With `FIPS_PEER_TRANSPORT=tcp` or `udp` the nym client is **not started at
all** and FIPS connects directly — useful as a baseline comparison.

## Troubleshooting

- **`could not auto-discover a Nym service provider`** — the harbourmaster
  API was unreachable or returned no providers; pick one manually from
  <https://harbourmaster.nymtech.net/> and set `NYM_SERVICE_PROVIDER`.
- **Slow or failing mixnet bootstrap** — service providers and gateways
  vary in quality. Delete the client state and retry with another provider:
  `docker compose down -v && NYM_SERVICE_PROVIDER=<other> docker compose up`.
  (The provider is baked into the client state at init; changing it
  requires wiping the `nym-data` volume.)
- **Peer never becomes active** — confirm the peer's TCP endpoint is
  reachable from the open internet (the network requester dials it from
  the Nym exit side, not from your machine).
- **Never run this image under emulation** — the image builds native for
  a reason: under Rosetta/qemu, the FIPS daemon's ChaCha20-Poly1305
  assembly (ring/BoringSSL) silently fails AEAD on larger frames; bloom
  filter announces are dropped and multi-hop routing never converges,
  while small control traffic keeps working — a maddeningly subtle
  failure mode. Only the embedded amd64 `nym-socks5-client` (Nym ships no
  other arch) runs emulated on Apple Silicon, which it tolerates.

## Notes

- The container's lifecycle follows the FIPS daemon; strfry, nginx and the
  nym client run as background processes inside the same container and are
  restarted with it (`restart: unless-stopped`).
- SSH (port 22, no auth) and tools like `tcpdump`, `nak`, `iperf3` are
  inside the image for poking around — this is a demo image, do not expose
  it beyond your machine.
