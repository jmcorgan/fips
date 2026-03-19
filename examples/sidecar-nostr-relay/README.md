# FIPS Nostr Relay Sidecar

Runs a [strfry](https://github.com/hoytech/strfry) Nostr relay reachable
exclusively over the FIPS mesh. The relay container shares the FIPS
sidecar's network namespace and is isolated from the host network by
iptables — it can only be reached via the node's `.fips` name.

## How to Run

### 1. Build the FIPS binaries

From the repo root, compile FIPS for Linux and copy the binaries into the
Docker build context:

```bash
cd examples/sidecar-nostr-relay
./scripts/build.sh
```

Cross-compilation from macOS is supported via `cargo-zigbuild`.

### 2. Set your node identity

The relay needs a unique FIPS identity. Generate one with:

```bash
fipsctl keygen
```

Then set it in `.env`:

```bash
# .env
FIPS_NSEC=nsec1...   # paste your nsec here
```

`FIPS_NSEC` is required — the container will refuse to start without it.

### 3. Start the stack

```bash
docker compose up -d
```

This starts two containers that share a network namespace:

- **fips** — FIPS daemon + dnsmasq. Owns the namespace, creates `fips0`.
- **app** — strfry relay + nginx. Joins the namespace via `network_mode: service:fips`.

### 4. Verify

```bash
# FIPS node is up and has a mesh address:
docker exec sidecar-nostr-relay-fips-1 fipsctl show status

# Relay is listening (should show nginx on :80 and strfry on :7777):
docker exec sidecar-nostr-relay-fips-1 ss -tlnp

# Peer link to the public node is established:
docker exec sidecar-nostr-relay-fips-1 fipsctl show peers

# Or check the logs:
docker compose logs -f
```

### 5. Connect to the relay

Your node's npub (and therefore its `.fips` name) is derived from its keypair:

```bash
docker exec sidecar-nostr-relay-fips-1 fipsctl show status
```

Connect from any FIPS-peered client using the node's npub:

```
ws://npub1xxxx.fips:80
```

## Security Model

The sidecar pattern enforces strict network isolation on the app container:

- **No IPv4 access**: iptables blocks all eth0 traffic except FIPS UDP
  transport (port 2121) and TCP transport (port 443). The app container
  cannot reach the Docker bridge, the host network, or any IPv4 address.
- **No IPv6 on eth0**: ip6tables blocks all IPv6 traffic on eth0. The app
  container cannot use link-local or any Docker-assigned IPv6 addresses.
- **FIPS mesh only**: The only routable network path is through `fips0`
  (`fd::/8`). All application traffic traverses the FIPS mesh with
  end-to-end encryption.
- **Loopback allowed**: `lo` is unrestricted for inter-process communication
  within the shared namespace.

This means the app container treats the FIPS mesh as its sole network. Even
if the application is compromised, it cannot bypass the mesh or communicate
with the transport layer directly.

## Architecture

```text
┌───────────────────────────────────────────────────┐
│ Shared network namespace                          │
│                                                   │
│ ┌───────────────┐    ┌──────────────────────────┐ │
│ │ fips-sidecar  │    │ fips-app                 │ │
│ │               │    │                          │ │
│ │ fips daemon   │    │ your workload            │ │
│ │ fipsctl       │    │                          │ │
│ │ dnsmasq       │    │                          │ │
│ └───────────────┘    └──────────────────────────┘ │
│                                                   │
│ Interfaces:                                       │
│   lo    — loopback (unrestricted)                 │
│   eth0  — Docker bridge (iptables: FIPS only)     │
│   fips0 — FIPS TUN (fd::/8, unrestricted)         │
└───────────────────────────────────────────────────┘
```

The FIPS sidecar owns the network namespace and creates the `fips0` TUN
interface. The app container joins via `network_mode: service:fips` and
sees the same interfaces. The entrypoint script applies iptables rules
before launching the FIPS daemon:

**IPv4 rules** (iptables):

- ACCEPT on `lo` (both directions)
- ACCEPT UDP sport/dport 2121 on `eth0` (FIPS UDP transport)
- ACCEPT TCP dport 443 / sport 443 on `eth0` (FIPS TCP transport)
- DROP everything else on `eth0`

**IPv6 rules** (ip6tables):

- ACCEPT on `lo` (both directions)
- ACCEPT on `fips0` (both directions)
- DROP everything on `eth0`

### DNS Resolution

DNS inside the container is handled by dnsmasq (127.0.0.1:53):

- `.fips` queries are forwarded to the FIPS daemon's built-in DNS resolver
  (127.0.0.1:5354), which resolves npub-based names to `fd::/8` addresses
- All other queries are forwarded to Docker's embedded DNS (127.0.0.11)

The `resolv.conf` mount points the container's resolver at 127.0.0.1,
where dnsmasq handles the routing.

## Build

```bash
cd examples/sidecar-nostr-relay
./scripts/build.sh
```

This compiles FIPS for Linux, copies the binaries into the Docker context,
and builds the sidecar and app images. Cross-compilation from macOS is
supported via `cargo-zigbuild`.

## Run with Peers

To connect the sidecar to an existing mesh, provide the peer's npub and
transport address:

```bash
FIPS_PEER_NPUB=npub1... \
FIPS_PEER_ADDR=203.0.113.10:2121 \
FIPS_PEER_ALIAS=gateway \
docker compose up -d
```

Verify the peer link:

```bash
docker exec sidecar-nostr-relay-fips-1 fipsctl show peers
docker exec sidecar-nostr-relay-fips-1 fipsctl show links
```

## Verify Connectivity and Isolation

From the app container:

```bash
# Ping a mesh node by npub (resolves via .fips DNS):
docker exec sidecar-nostr-relay-app-1 ping6 -c3 npub1xxxx.fips

# Fetch a web page from a mesh node over FIPS:
docker exec sidecar-nostr-relay-app-1 curl -6 "http://npub1xxxx.fips:8000/"

# Docker bridge is blocked — this should fail:
docker exec sidecar-nostr-relay-app-1 ping -c1 -W2 172.20.0.13

# Loopback is allowed:
docker exec sidecar-nostr-relay-app-1 ping -c1 127.0.0.1
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FIPS_NSEC` | *(required)* | Node secret key (hex or nsec1 bech32) |
| `FIPS_PEER_NPUB` | *(empty)* | Peer's npub to connect to |
| `FIPS_PEER_ADDR` | *(empty)* | Peer's transport address (e.g. `203.0.113.10:2121`) |
| `FIPS_PEER_ALIAS` | `peer` | Human-readable peer name |
| `FIPS_UDP_BIND` | `0.0.0.0:2121` | UDP transport bind address |
| `FIPS_TCP_BIND` | `0.0.0.0:8443` | TCP transport bind address |
| `FIPS_PEER_TRANSPORT` | `udp` | Peer transport type (`udp` or `tcp`) |
| `FIPS_TUN_MTU` | `1280` | TUN interface MTU |
| `FIPS_NETWORK` | `fips-sidecar-net` | Docker network name (set to join external network) |
| `FIPS_SUBNET` | `172.20.1.0/24` | Docker network subnet |
| `FIPS_IPV4` | `172.20.1.20` | Sidecar's IPv4 address on the Docker network |
| `RUST_LOG` | `info` | FIPS log level |

## Troubleshooting

**`FIPS_NSEC is required`** — The `FIPS_NSEC` environment variable is not
set. Either add it to `.env` or pass it on the command line. Generate a
random key with: `openssl rand -hex 32`

**`fips0` interface not appearing** — The FIPS daemon needs `/dev/net/tun`
and `NET_ADMIN` capability. Check that the compose file includes both:

```yaml
cap_add:
  - NET_ADMIN
devices:
  - /dev/net/tun:/dev/net/tun
```

**No peer connection established** — Verify the peer address is reachable
from the sidecar container (`docker exec sidecar-nostr-relay-fips-1 ping -c1 <peer-ip>`).
If joining an external Docker network, ensure `FIPS_NETWORK`, `FIPS_SUBNET`,
and `FIPS_IPV4` match the target network. Check logs with
`docker logs sidecar-nostr-relay-fips-1`.

**DNS not resolving `.fips` names** — Verify dnsmasq is running:
`docker exec sidecar-nostr-relay-fips-1 pgrep dnsmasq`. Check that `resolv.conf` is
mounted (should contain `nameserver 127.0.0.1`). Verify the FIPS DNS
resolver is listening: `docker exec sidecar-nostr-relay-fips-1 dig @127.0.0.1 -p 5354 <npub>.fips AAAA`.

**iptables errors in entrypoint** — The sidecar container requires
`NET_ADMIN` capability for iptables. Without it, the isolation rules
cannot be applied and the entrypoint will fail.

## Production Considerations

**Secrets management**: The default `.env` contains a hardcoded nsec for
development. In production, use Docker secrets, a vault, or inject the key
via a secure CI/CD pipeline. Never commit production keys to version control.

**Logging**: Set `RUST_LOG` to control log verbosity (`debug`, `info`,
`warn`, `error`). For production, configure the Docker logging driver with
size limits:

```yaml
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"
```

**Resource limits**: Add memory and CPU constraints in the compose file:

```yaml
deploy:
  resources:
    limits:
      memory: 256M
      cpus: "0.5"
```

**Multiple peers**: The entrypoint supports a single peer via environment
variables. For multiple peers, mount a custom `fips.yaml` directly:

```yaml
volumes:
  - ./my-fips.yaml:/etc/fips/fips.yaml:ro
```

**Health checks**: Add a Docker health check using `fipsctl`:

```yaml
healthcheck:
  test: ["CMD", "fipsctl", "show", "status"]
  interval: 30s
  timeout: 5s
  retries: 3
```
