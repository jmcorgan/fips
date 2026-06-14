# FIPS Kubernetes Sidecar

Run FIPS as a sidecar container in a Kubernetes Pod, injecting the FIPS mesh
network interface into every other container in the Pod. All containers in
the Pod share the same network namespace, so once the sidecar creates `fips0`
it is immediately visible to the app container(s) without any further
configuration.

## Quick Start

```bash
# 1. Build the sidecar image
cd examples/k8s-sidecar
./scripts/build.sh --tag fips-k8s-sidecar:latest

# 2. Push to your registry (replace with your own)
docker tag fips-k8s-sidecar:latest registry.example.com/fips-k8s-sidecar:latest
docker push registry.example.com/fips-k8s-sidecar:latest

# 3. Create the identity secret
kubectl create secret generic fips-identity \
  --from-literal=nsec=$(openssl rand -hex 32)

# 4. Deploy
kubectl apply -f pod.yaml
```

## How It Works

In Kubernetes, all containers in a Pod share the same network namespace. The
fips sidecar:

1. Generates `/etc/fips/fips.yaml` from environment variables.
2. Rewrites `/etc/resolv.conf` to route `.fips` DNS through dnsmasq (which
   forwards `.fips` names to the FIPS daemon's built-in DNS resolver and
   everything else to the original cluster DNS).
3. Applies `iptables` isolation rules so that the pod's physical interface
   (`eth0`) only carries FIPS transport traffic.
4. Starts dnsmasq and then `exec`s the FIPS daemon.

The app container starts concurrently and immediately sees `lo`, `eth0`, and
`fips0`. DNS for `<npub>.fips` names resolves to `fd00::/8` addresses via the
dnsmasq → FIPS daemon pipeline.

```text
┌────────────────────────────────────────────────────┐
│ Kubernetes Pod (shared network namespace)           │
│                                                     │
│ ┌─────────────────┐   ┌───────────────────────────┐│
│ │  fips (sidecar) │   │  app container(s)         ││
│ │                 │   │                           ││
│ │  fips daemon    │   │  your workload            ││
│ │  fipsctl        │   │  sees: lo, eth0, fips0    ││
│ │  dnsmasq        │   │                           ││
│ └─────────────────┘   └───────────────────────────┘│
│                                                     │
│ Interfaces:                                         │
│   lo    — loopback (unrestricted)                   │
│   eth0  — pod CNI interface (iptables: FIPS only)   │
│   fips0 — FIPS TUN (fd00::/8, unrestricted)           │
└────────────────────────────────────────────────────┘
```

## Network Isolation

`FIPS_ISOLATE` controls whether the sidecar locks down `eth0`:

| Value | Behaviour |
|---|---|
| `false` **(default)** | `fips0` is added alongside normal cluster networking. `eth0` continues to work — services, DNS, other pods, and the internet are all reachable as normal. Application traffic to FIPS mesh peers uses `fips0`. |
| `true` | All traffic on `eth0` is dropped except FIPS transport (UDP 2121). The app container can **only** communicate via `fips0`. Use this for deployments where the workload must never bypass the mesh. |

> **Common gotcha**: if you deploy the sidecar and find that services or
> other pods are suddenly unreachable, check that `FIPS_ISOLATE` is not
> set to `true`. The mesh-only mode is intentionally strict and will break
> normal cluster connectivity.

## Requirements

| Requirement | Notes |
|---|---|
| `NET_ADMIN` capability | Required for TUN creation and iptables |
| `/dev/net/tun` | HostPath volume mount (see `pod.yaml`) |
| Linux kernel ≥ 4.9 | Standard on all current distributions |
| No gVisor / kata-containers | Requires real kernel TUN support |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `FIPS_NSEC` | *(required)* | Node secret key (hex or nsec1 bech32) |
| `FIPS_PEER_NPUB` | *(empty)* | Single peer npub |
| `FIPS_PEER_ADDR` | *(empty)* | Single peer transport address (`host:port`) |
| `FIPS_PEER_ALIAS` | `peer` | Single peer alias |
| `FIPS_PEER_TRANSPORT` | `udp` | Single peer transport type |
| `FIPS_PEERS_JSON` | *(empty)* | JSON array of peer objects (overrides single-peer vars). **Note**: the included parser handles simple host:port addresses only; IPv6 addresses with brackets may not parse correctly. |
| `FIPS_UDP_BIND` | `0.0.0.0:2121` | UDP transport bind address |
| `FIPS_UDP_PORT` | *(from `FIPS_UDP_BIND`)* | UDP port for iptables rules |
| `FIPS_TCP_BIND` | *(disabled)* | TCP transport bind address |
| `FIPS_TUN_NAME` | `fips0` | TUN interface name |
| `FIPS_TUN_MTU` | `1280` | TUN MTU |
| `FIPS_ISOLATE` | `false` | Apply iptables isolation (blocks all eth0 traffic except FIPS transport) |
| `FIPS_POD_IFACE` | `eth0` | Pod physical interface name |
| `FIPS_REWRITE_DNS` | `true` | Rewrite `/etc/resolv.conf` |
| `RUST_LOG` | `info` | FIPS log level |

### Multiple Peers

Use `FIPS_PEERS_JSON` to configure more than one peer:

```yaml
- name: FIPS_PEERS_JSON
  value: |
    [
      {"npub":"npub1abc...","alias":"gw1","addr":"203.0.113.10:2121","transport":"udp"},
      {"npub":"npub1def...","alias":"gw2","addr":"198.51.100.5:2121","transport":"udp"}
    ]
```

Each object supports the keys: `npub` (required), `addr` (required),
`alias`, `transport`, `priority`.

Alternatively, mount a hand-crafted `fips.yaml` and set `FIPS_NSEC` to
anything (the mount takes precedence because the entrypoint writes to
`/etc/fips/fips.yaml` which is then overridden by the volume):

```yaml
volumes:
  - name: fips-config
    configMap:
      name: my-fips-config
containers:
  - name: fips
    volumeMounts:
      - name: fips-config
        mountPath: /etc/fips/fips.yaml
        subPath: fips.yaml
```

### JSON Parsing Limitations

`FIPS_PEERS_JSON` supports parsing with a simple awk-based parser. It handles common `host:port` addresses but does not support IPv6 addresses with brackets (e.g., `[::1]:2121`) or values containing embedded commas/colons. For complex configs, install `jq` in the container and modify the entrypoint, or use a mounted `fips.yaml`.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | Builds the sidecar image |
| `entrypoint.sh` | Generates config, rewrites DNS, applies iptables, starts fips |
| `pod.yaml` | Example Pod manifest (single app container + fips sidecar) |
| `scripts/build.sh` | Compiles FIPS and builds the Docker image |

## Troubleshooting

**`FIPS_NSEC is required`** — The secret was not injected. Verify the
`secretKeyRef` name and key match the secret you created with `kubectl
create secret`.

**`fips0` not visible in app container** — Check that the fips sidecar
started successfully: `kubectl logs <pod> -c fips`. The sidecar must start
and run the daemon before `fips0` appears. Add a startup probe or
`postStart` lifecycle hook to your app container if you need to wait.

**iptables errors** — The `NET_ADMIN` capability and `/dev/net/tun` volume
mount are both required. Verify they are present in the Pod spec.

**`.fips` DNS not resolving** — Check that `FIPS_REWRITE_DNS=true` and that
dnsmasq started: `kubectl exec <pod> -c fips -- pgrep dnsmasq`. Verify the
FIPS DNS listener: `kubectl exec <pod> -c fips -- fipsctl show status`.

**CNI uses a different interface name** — Set `FIPS_POD_IFACE` to match your
CNI's interface name (e.g. `ens3`, `net1` for Multus secondary interfaces).

**gVisor / kata-containers** — These sandboxed runtimes intercept syscalls
and do not support `AF_PACKET` or `/dev/net/tun` in the same way as a
standard kernel. Use a standard RuntimeClass for FIPS sidecar pods.
