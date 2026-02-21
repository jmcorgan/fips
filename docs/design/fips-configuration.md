# FIPS Configuration

FIPS uses YAML-based configuration with a cascading multi-file priority system.
All parameters have sensible defaults; a node can run with no configuration file
at all (it will generate an ephemeral identity and listen on default addresses).

## Configuration Loading

### Search Paths

When started without the `-c` flag, FIPS searches for `fips.yaml` in these
locations, lowest to highest priority:

| Priority | Path | Purpose |
|----------|------|---------|
| 1 (lowest) | `/etc/fips/fips.yaml` | System-wide defaults |
| 2 | `~/.config/fips/fips.yaml` | User preferences |
| 3 | `~/.fips.yaml` | Legacy user config |
| 4 (highest) | `./fips.yaml` | Deployment-specific overrides |

All found files are loaded and merged in priority order. Values from higher
priority files override those from lower priority files. This allows a system
administrator to set site-wide defaults in `/etc/fips/fips.yaml` while
individual deployments override specific values in `./fips.yaml`.

### CLI Option

```text
fips -c /path/to/config.yaml
```

When `-c` is specified, only that file is loaded (search paths are skipped).

### Partial Configuration

Every field has a built-in default. A configuration file only needs to specify
values that differ from defaults. For example, a minimal config might contain
only the identity and peer list, inheriting all other defaults.

## YAML Structure

The configuration is organized into five top-level sections:

```yaml
node:        # Node behavior, protocol parameters, and tuning
tun:         # TUN virtual interface
dns:         # DNS responder for .fips domain
transports:  # Network transports (UDP, future: TCP, Tor)
peers:       # Static peer list
```

All tunable protocol parameters live under `node.*`, organized as sysctl-style
dotted paths. The top-level sections (`tun`, `dns`, `transports`, `peers`)
handle infrastructure concerns only.

## Node Parameters (`node.*`)

### Identity (`node.identity.*`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.identity.nsec` | string | *(generate random)* | Hex-encoded secret key. If omitted, an ephemeral identity is generated on each start. |

### General

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.leaf_only` | bool | `false` | Leaf-only mode: node does not forward traffic or participate in routing |
| `node.tick_interval_secs` | u64 | `1` | Periodic maintenance tick interval (retry checks, timeout cleanup, tree refresh) |
| `node.base_rtt_ms` | u64 | `100` | Initial RTT estimate for new links before measurements converge |
| `node.heartbeat_interval_secs` | u64 | `10` | Heartbeat send interval per peer for liveness detection |
| `node.link_dead_timeout_secs` | u64 | `30` | No-traffic timeout before a peer is declared dead and removed |

### Resource Limits (`node.limits.*`)

Controls capacity for connections, peers, and links.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.limits.max_connections` | usize | `256` | Max handshake-phase connections |
| `node.limits.max_peers` | usize | `128` | Max authenticated peers |
| `node.limits.max_links` | usize | `256` | Max active links |
| `node.limits.max_pending_inbound` | usize | `1000` | Max pending inbound handshakes |

### Rate Limiting (`node.rate_limit.*`)

Handshake rate limiting protects against DoS on the Noise IK handshake path.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.rate_limit.handshake_burst` | u32 | `100` | Token bucket burst capacity |
| `node.rate_limit.handshake_rate` | f64 | `10.0` | Tokens per second refill rate |
| `node.rate_limit.handshake_timeout_secs` | u64 | `30` | Stale handshake cleanup timeout |
| `node.rate_limit.handshake_resend_interval_ms` | u64 | `1000` | Initial handshake message resend interval |
| `node.rate_limit.handshake_resend_backoff` | f64 | `2.0` | Resend backoff multiplier (1s, 2s, 4s, 8s, 16s with defaults) |
| `node.rate_limit.handshake_max_resends` | u32 | `5` | Max resends per handshake attempt |

### Retry / Backoff (`node.retry.*`)

Connection retry with exponential backoff.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.retry.max_retries` | u32 | `5` | Max connection retry attempts |
| `node.retry.base_interval_secs` | u64 | `5` | Base backoff interval |
| `node.retry.max_backoff_secs` | u64 | `300` | Cap on exponential backoff (5 minutes) |

Auto-reconnect (triggered by MMP link-dead removal) uses the same backoff
parameters but bypasses `max_retries`, retrying indefinitely. See
`peers[].auto_reconnect` below.

### Cache Parameters (`node.cache.*`)

Controls caching of tree coordinates and identity mappings.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.cache.coord_size` | usize | `50000` | Max entries in coordinate cache |
| `node.cache.coord_ttl_secs` | u64 | `300` | Coordinate cache entry TTL (5 minutes) |
| `node.cache.identity_size` | usize | `10000` | Max entries in identity cache (LRU, no TTL) |

### Discovery Protocol (`node.discovery.*`)

Controls flood-based node discovery (LookupRequest/LookupResponse).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.discovery.ttl` | u8 | `64` | Hop limit for LookupRequest flood |
| `node.discovery.timeout_secs` | u64 | `10` | Lookup completion timeout |
| `node.discovery.recent_expiry_secs` | u64 | `10` | Dedup cache expiry for recent request IDs |

### Spanning Tree (`node.tree.*`)

Controls tree construction and parent selection.

| Parameter                              | Type  | Default | Description                                      |
|----------------------------------------|-------|---------|--------------------------------------------------|
| `node.tree.announce_min_interval_ms`   | u64   | `500`   | Per-peer TreeAnnounce rate limit                 |
| `node.tree.parent_switch_threshold`    | usize | `1`     | Min depth improvement required to switch parents |

### Bloom Filter (`node.bloom.*`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.bloom.update_debounce_ms` | u64 | `500` | Debounce interval for filter update propagation |

Bloom filter size (1 KB), hash count (5), and size classes are protocol
constants and not configurable.

### Session / Data Plane (`node.session.*`)

Controls end-to-end session behavior and packet queuing.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.session.default_ttl` | u8 | `64` | Default SessionDatagram TTL |
| `node.session.pending_packets_per_dest` | usize | `16` | Queue depth per destination during session establishment |
| `node.session.pending_max_destinations` | usize | `256` | Max destinations with pending packets |
| `node.session.idle_timeout_secs` | u64 | `90` | Idle session timeout; established sessions with no application data for this duration are removed. MMP reports (SenderReport, ReceiverReport, PathMtuNotification) do not count as activity |
| `node.session.coords_warmup_packets` | u8 | `5` | Number of initial data packets per session that include the CP flag for transit cache warmup; also the reset count on CoordsRequired/PathBroken receipt |
| `node.session.coords_response_interval_ms` | u64 | `2000` | Minimum interval (ms) between standalone CoordsWarmup responses to CoordsRequired/PathBroken signals per destination |

The anti-replay window size (2048 packets) is a compile-time constant and not
configurable.

### Link-Layer MMP (`node.mmp.*`)

Metrics Measurement Protocol for per-peer link measurement. See
[fips-mesh-layer.md](fips-mesh-layer.md) for behavioral details.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.mmp.mode` | string | `"full"` | Operating mode: `full` (sender + receiver reports), `lightweight` (receiver reports only), or `minimal` (spin bit + CE echo only, no reports) |
| `node.mmp.log_interval_secs` | u64 | `30` | Periodic operator log interval for link metrics |
| `node.mmp.owd_window_size` | usize | `32` | One-way delay trend ring buffer size |

### Session-Layer MMP (`node.session_mmp.*`)

Metrics Measurement Protocol for end-to-end session measurement. Configured
independently from link-layer MMP because session reports are routed through
every transit link, consuming bandwidth proportional to path length.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.session_mmp.mode` | string | `"full"` | Operating mode: `full`, `lightweight`, or `minimal` |
| `node.session_mmp.log_interval_secs` | u64 | `30` | Periodic operator log interval for session metrics |
| `node.session_mmp.owd_window_size` | usize | `32` | One-way delay trend ring buffer size |

### Internal Buffers (`node.buffers.*`)

Channel sizes affecting throughput and memory. Primarily useful for performance
tuning under high load or on memory-constrained devices.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.buffers.packet_channel` | usize | `1024` | Transport to Node packet channel capacity |
| `node.buffers.tun_channel` | usize | `1024` | TUN to Node outbound channel capacity |
| `node.buffers.dns_channel` | usize | `64` | DNS to Node identity channel capacity |

## TUN Interface (`tun.*`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `tun.enabled` | bool | `false` | Enable TUN virtual interface |
| `tun.name` | string | `"fips0"` | Interface name |
| `tun.mtu` | u16 | `1280` | Interface MTU (IPv6 minimum) |

## DNS Responder (`dns.*`)

Resolves `<npub>.fips` queries to FIPS IPv6 addresses. Resolution is pure
computation (npub to public key to address); resolved identities are registered
with the node for routing.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `dns.enabled` | bool | `false` | Enable DNS responder |
| `dns.bind_addr` | string | `"127.0.0.1"` | Bind address |
| `dns.port` | u16 | `5354` | Listen port |
| `dns.ttl` | u32 | `300` | AAAA record TTL in seconds |

The `dns.ttl` value should not exceed `node.cache.coord_ttl_secs` to avoid
stale address mappings.

## Transports (`transports.*`)

### UDP (`transports.udp.*`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transports.udp.bind_addr` | string | `"0.0.0.0:4000"` | UDP bind address and port |
| `transports.udp.mtu` | u16 | `1280` | Transport MTU |
| `transports.udp.recv_buf_size` | usize | `2097152` | UDP socket receive buffer size in bytes (2 MB). Linux kernel doubles the requested value internally. Host `net.core.rmem_max` must be >= this value. |
| `transports.udp.send_buf_size` | usize | `2097152` | UDP socket send buffer size in bytes (2 MB). Host `net.core.wmem_max` must be >= this value. |

## Peers (`peers[]`)

Static peer list. Each entry defines a peer to connect to.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `peers[].npub` | string | *(required)* | Peer's Nostr public key (npub-encoded) |
| `peers[].alias` | string | *(none)* | Human-readable name for logging |
| `peers[].addresses[].transport` | string | *(required)* | Transport type (`udp`) |
| `peers[].addresses[].addr` | string | *(required)* | Transport address (e.g., `"10.0.0.2:4000"`) |
| `peers[].addresses[].priority` | u8 | `100` | Address priority (lower = preferred) |
| `peers[].connect_policy` | string | `"auto_connect"` | Connection policy: `auto_connect`, `on_demand`, or `manual` |
| `peers[].auto_reconnect` | bool | `true` | Automatically reconnect after MMP link-dead removal (exponential backoff, unlimited retries) |

## Minimal Example

A typical node configuration enabling TUN, DNS, and a single peer:

```yaml
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"
  port: 53

transports:
  udp:
    bind_addr: "0.0.0.0:4000"
    mtu: 1197

peers:
  - npub: "npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le"
    alias: "node-b"
    addresses:
      - transport: udp
        addr: "172.20.0.11:4000"
    connect_policy: auto_connect
```

All `node.*` parameters use their defaults. To override specific values, add
only the relevant sections:

```yaml
node:
  identity:
    nsec: "..."
  limits:
    max_peers: 64
  retry:
    max_retries: 10
    max_backoff_secs: 600
  cache:
    coord_size: 100000
```

## Complete Reference

The full YAML structure with all defaults:

```yaml
node:
  identity:
    nsec: null                       # hex secret key (null = generate ephemeral)
  leaf_only: false
  tick_interval_secs: 1
  base_rtt_ms: 100
  heartbeat_interval_secs: 10
  link_dead_timeout_secs: 30
  limits:
    max_connections: 256
    max_peers: 128
    max_links: 256
    max_pending_inbound: 1000
  rate_limit:
    handshake_burst: 100
    handshake_rate: 10.0
    handshake_timeout_secs: 30
    handshake_resend_interval_ms: 1000
    handshake_resend_backoff: 2.0
    handshake_max_resends: 5
  retry:
    max_retries: 5
    base_interval_secs: 5
    max_backoff_secs: 300
  cache:
    coord_size: 50000
    coord_ttl_secs: 300
    identity_size: 10000
  discovery:
    ttl: 64
    timeout_secs: 10
    recent_expiry_secs: 10
  tree:
    announce_min_interval_ms: 500
    parent_switch_threshold: 1
  bloom:
    update_debounce_ms: 500
  session:
    default_ttl: 64
    pending_packets_per_dest: 16
    pending_max_destinations: 256
    idle_timeout_secs: 90
    coords_warmup_packets: 5
    coords_response_interval_ms: 2000
  mmp:
    mode: full                       # full | lightweight | minimal
    log_interval_secs: 30
    owd_window_size: 32
  session_mmp:
    mode: full                       # full | lightweight | minimal
    log_interval_secs: 30
    owd_window_size: 32
  buffers:
    packet_channel: 1024
    tun_channel: 1024
    dns_channel: 64

tun:
  enabled: false
  name: "fips0"
  mtu: 1280

dns:
  enabled: false
  bind_addr: "127.0.0.1"
  port: 5354
  ttl: 300

transports:
  udp:
    bind_addr: "0.0.0.0:4000"
    mtu: 1280
    recv_buf_size: 2097152           # 2 MB (kernel doubles to 4 MB actual)
    send_buf_size: 2097152           # 2 MB

peers:                               # static peer list
  # - npub: "npub1..."
  #   alias: "node-b"
  #   addresses:
  #     - transport: udp
  #       addr: "10.0.0.2:4000"
  #       priority: 100
  #   connect_policy: auto_connect
  #   auto_reconnect: true           # reconnect after link-dead removal
```
