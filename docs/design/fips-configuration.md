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
transports:  # Network transports (UDP, Ethernet, Bluetooth, Tor, ...)
peers:       # Static peer list
```

### Control Socket (`node.control.*`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.control.enabled` | bool | `true` | Enable the control socket |
| `node.control.socket_path` | string | *(auto)* | **Linux:** Socket file path. Default: `$XDG_RUNTIME_DIR/fips/control.sock`, then `/run/fips/control.sock` (if root), then `/tmp/fips-control.sock`. **Windows:** TCP port number (default: `21210`); the control socket listens on `localhost` at this port. |

The control socket provides access to node state and runtime management
via the `fipsctl` command-line tool. In addition to read-only status
queries, `fipsctl connect` and `fipsctl disconnect` enable runtime peer
management. See the project [README](../../README.md#inspect) for the
command list.

On Linux, the control socket is a Unix domain socket with filesystem
permissions (mode 0770, group `fips`). On Windows, it is a TCP listener
on localhost. TCP does not provide filesystem-level ACLs, so any local
user can connect to the control port.

> **Security note (Windows):** The TCP control socket on Windows is a
> known limitation. Any process running on the local machine can connect
> to the control port and issue commands, including `disconnect`,
> `connect`, and `inject-config`. This is acceptable for single-user
> workstations but may be inappropriate for shared machines. Future
> improvements may include named pipe support (with Windows ACLs) or an
> authentication token mechanism. On shared Windows systems, consider
> using firewall rules to restrict access to the control port.

All tunable protocol parameters live under `node.*`, organized as sysctl-style
dotted paths. The top-level sections (`tun`, `dns`, `transports`, `peers`)
handle infrastructure concerns only.

## Node Parameters (`node.*`)

### Identity (`node.identity.*`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.identity.nsec` | string | *(none)* | Secret key in nsec (bech32) or hex format. If omitted, behavior depends on `persistent`. |
| `node.identity.persistent` | bool | `false` | Persist identity across restarts via key file. |

Identity resolution follows a three-tier priority:

1. **Explicit `nsec`** in config — always used when present, regardless of `persistent`
2. **Persistent key file** — when `persistent: true` and no `nsec`, loads from `fips.key`
   adjacent to the config file; if no key file exists, generates a new keypair and saves it
3. **Ephemeral** — when `persistent: false` (default) and no `nsec`, generates a fresh
   keypair on each start

Key files (`fips.key` with mode 0600, `fips.pub` with mode 0644) are written adjacent
to the highest-priority config file for operator visibility, even in ephemeral mode.

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

Controls bloom-guided node discovery (LookupRequest/LookupResponse).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.discovery.ttl` | u8 | `64` | Hop limit for LookupRequest forwarding |
| `node.discovery.attempt_timeouts_secs` | array&lt;u64&gt; | `[1, 2, 4, 8]` | Per-attempt timeouts. Each entry is the deadline for one `LookupRequest` before sending the next attempt with a fresh `request_id`. Length determines total attempt count; default gives 4 attempts and a 15s total budget |
| `node.discovery.recent_expiry_secs` | u64 | `10` | Dedup cache expiry for recent request IDs |
| `node.discovery.backoff_base_secs` | u64 | `0` | Optional post-failure suppression base in seconds; doubles per consecutive failure. `0` disables (default) — the per-attempt sequence is the only retry pacing |
| `node.discovery.backoff_max_secs` | u64 | `0` | Cap on optional post-failure backoff |
| `node.discovery.forward_min_interval_secs` | u64 | `2` | Transit-side rate limiting: minimum interval between forwarded lookups for the same target |

#### Nostr Overlay Discovery (`node.discovery.nostr.*`)

Optional Nostr-mediated overlay discovery. This layer publishes replaceable
endpoint adverts (`fips-overlay-v1`), consumes advert-derived endpoint
fallbacks for configured peers, and can optionally discover non-configured
peers (`policy: open`). `udp:nat` remains the trigger for NAT traversal
offer/answer + punch-through, after which the established UDP socket is handed
into the normal FIPS transport/session stack.
Inbox-relay discovery falls back to the local DM relay list if remote relay
metadata cannot be fetched.
This support is compiled behind the crate feature `nostr-discovery`; builds
without that feature ignore `udp:nat` bootstrap configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.discovery.nostr.enabled` | bool | `false` | Enable Nostr-mediated overlay discovery |
| `node.discovery.nostr.policy` | string | `"configured_only"` | Advert discovery policy: `disabled`, `configured_only`, `open` |
| `node.discovery.nostr.open_discovery_max_pending` | usize | `64` | Max open-discovery peers queued in outbound retry/connection state at once |
| `node.discovery.nostr.max_concurrent_incoming_offers` | usize | `16` | Max concurrent inbound traversal offers processed at once (rate limit against offer spam) |
| `node.discovery.nostr.advert_cache_max_entries` | usize | `2048` | Max cached overlay adverts retained from relay traffic |
| `node.discovery.nostr.seen_sessions_max_entries` | usize | `2048` | Max seen-session IDs retained for replay detection |
| `node.discovery.nostr.advertise` | bool | `true` | Publish local endpoint adverts |
| `node.discovery.nostr.advert_relays` | list[string] | `["wss://relay.damus.io", "wss://nos.lol", "wss://offchain.pub"]` | Relays used for service adverts |
| `node.discovery.nostr.dm_relays` | list[string] | `["wss://relay.damus.io", "wss://nos.lol", "wss://offchain.pub"]` | Relays used for encrypted signaling events |
| `node.discovery.nostr.stun_servers` | list[string] | `["stun:stun.l.google.com:19302", "stun:stun.cloudflare.com:3478", "stun:global.stun.twilio.com:3478"]` | STUN servers used for local reflexive address discovery |
| `node.discovery.nostr.app` | string | `"fips-overlay-v1"` | Traversal application namespace and advert identifier suffix |
| `node.discovery.nostr.signal_ttl_secs` | u64 | `120` | Signaling TTL in seconds |
| `node.discovery.nostr.attempt_timeout_secs` | u64 | `10` | Overall traversal attempt timeout in seconds |
| `node.discovery.nostr.replay_window_secs` | u64 | `300` | Replay tracking retention window in seconds |
| `node.discovery.nostr.punch_start_delay_ms` | u64 | `2000` | Delay before punch traffic starts |
| `node.discovery.nostr.punch_interval_ms` | u64 | `200` | Interval between punch packets |
| `node.discovery.nostr.punch_duration_ms` | u64 | `10000` | How long to keep punching before failure |
| `node.discovery.nostr.advert_ttl_secs` | u64 | `3600` | Advert TTL in seconds |
| `node.discovery.nostr.advert_refresh_secs` | u64 | `1800` | How often adverts are refreshed in seconds |

If `stun_servers` is omitted, the built-in default list above is used. If it is
specified in YAML, the configured list fully overrides the defaults.
Initiators use only this local list for outbound STUN queries; peer-advertised
STUN values are published for diagnostics/interoperability but are not used as
arbitrary egress targets.
The built-in advert and DM relay defaults point at widely-operated public
relays (Damus, nos.lol, Primal) as best-effort endpoints; operators are
encouraged to override them with their own relay preferences for production
deployments.
Advert freshness is enforced semantically: events with expired NIP-40
`expiration` tags are dropped, and adverts are also bounded by a created-at
staleness window derived from `advert_ttl_secs` (with a grace multiplier).
The current in-tree STUN parser handles IPv4 and IPv6 mapped-address
attributes. Local traversal candidates include active non-loopback private
interface addresses (RFC1918 IPv4 and IPv6 ULA) plus probed local egress
addresses for the punch socket port.
During punching, compatible private-subnet candidates and reflexive candidates
are attempted in parallel; the first successful path wins.

### Spanning Tree (`node.tree.*`)

Controls tree construction and parent selection.

| Parameter                              | Type  | Default | Description                                      |
|----------------------------------------|-------|---------|--------------------------------------------------|
| `node.tree.announce_min_interval_ms`   | u64   | `500`   | Per-peer TreeAnnounce rate limit                 |
| `node.tree.parent_hysteresis`          | f64   | `0.2`   | Cost improvement fraction required for same-root parent switch (0.0–1.0) |
| `node.tree.hold_down_secs`             | u64   | `30`    | Suppress non-mandatory re-evaluation after parent switch |
| `node.tree.reeval_interval_secs`       | u64   | `60`    | Periodic cost-based parent re-evaluation interval (0 = disabled) |
| `node.tree.flap_threshold`             | u32   | `4`     | Parent switches in window before dampening engages  |
| `node.tree.flap_window_secs`           | u64   | `60`    | Sliding window for counting parent switches          |
| `node.tree.flap_dampening_secs`        | u64   | `120`   | Extended hold-down duration when flap threshold exceeded |

### Bloom Filter (`node.bloom.*`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.bloom.update_debounce_ms` | u64 | `500` | Debounce interval for filter update propagation |

Bloom filter size (1 KB), hash count (5), and size classes are protocol
constants and not configurable.

### ECN Signaling (`node.ecn.*`)

Controls hop-by-hop ECN (Explicit Congestion Notification) signaling. When
enabled, transit nodes detect congestion on outgoing links (via MMP loss/ETX
metrics or kernel buffer drops) and set the CE flag on forwarded FMP frames.
Destination nodes mark ECN-capable IPv6 packets with CE before TUN delivery
per RFC 3168, enabling end-host TCP congestion control to react.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.ecn.enabled` | bool | `true` | Enable ECN congestion signaling (CE flag relay and local congestion detection) |
| `node.ecn.loss_threshold` | f64 | `0.05` | MMP loss rate threshold for CE marking (0.0–1.0). When the outgoing link's loss rate meets or exceeds this value, forwarded packets are CE-marked. |
| `node.ecn.etx_threshold` | f64 | `3.0` | MMP ETX threshold for CE marking (≥1.0). When the outgoing link's ETX meets or exceeds this value, forwarded packets are CE-marked. |

Congestion detection triggers on any of: outgoing link loss ≥ `loss_threshold`,
outgoing link ETX ≥ `etx_threshold`, or kernel receive buffer drops detected on
any local transport. CE is relayed hop-by-hop: once set on any hop, the flag
stays set for all subsequent hops to the destination.

### Rekey (`node.rekey.*`)

Controls periodic Noise rekey for forward secrecy. When enabled, both FMP
(link-layer IK) and FSP (session-layer XK) sessions perform fresh Diffie-Hellman
key exchanges after a time or message count threshold, whichever comes first.
A 10-second drain window keeps the old session active for decryption during
cutover.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `node.rekey.enabled` | bool | `true` | Enable periodic Noise rekey on all links and sessions |
| `node.rekey.after_secs` | u64 | `120` | Initiate rekey after this many seconds on a session |
| `node.rekey.after_messages` | u64 | `65536` | Initiate rekey after this many messages sent on a session |

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
| `dns.enabled` | bool | `true` | Enable DNS responder |
| `dns.bind_addr` | string | `"127.0.0.1"` | Bind address |
| `dns.port` | u16 | `5354` | Listen port |
| `dns.ttl` | u32 | `300` | AAAA record TTL in seconds |

The `dns.ttl` value should not exceed `node.cache.coord_ttl_secs` to avoid
stale address mappings.

### Host Mapping

The DNS resolver checks a host map before falling back to direct npub
resolution, enabling names like `gateway.fips` instead of `npub1...fips`.
The host map is populated from two sources:

1. **Peer aliases** — the `alias` field on configured peers in `peers:`.
2. **Hosts file** — `/etc/fips/hosts`, one `hostname npub1...` per line.
   Blank lines and `#` comments are allowed.

The hosts file is auto-reloaded on modification (mtime change) without
restarting the daemon. Hostnames are case-insensitive.

## Transports (`transports.*`)

### UDP (`transports.udp.*`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transports.udp.bind_addr` | string | `"0.0.0.0:2121"` | UDP bind address and port |
| `transports.udp.mtu` | u16 | `1280` | Transport MTU |
| `transports.udp.recv_buf_size` | usize | `2097152` | UDP socket receive buffer size in bytes (2 MB). Linux kernel doubles the requested value internally. Host `net.core.rmem_max` must be >= this value. |
| `transports.udp.send_buf_size` | usize | `2097152` | UDP socket send buffer size in bytes (2 MB). Host `net.core.wmem_max` must be >= this value. |
| `transports.udp.advertise_on_nostr` | bool | `false` | Include this UDP transport in Nostr endpoint adverts |
| `transports.udp.public` | bool | `false` | If advertised: `true` publishes direct `host:port`; `false` publishes `udp:nat` rendezvous |

### Ethernet (`transports.ethernet.*`)

Ethernet transport sends raw frames via AF_PACKET SOCK_DGRAM sockets.
Requires `CAP_NET_RAW` or running as root. Linux only.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | string | *(required)* | Network interface name (e.g., `"eth0"`, `"enp3s0"`) |
| `ethertype` | u16 | `0x2121` | EtherType |
| `mtu` | u16 | *(auto)* | Override MTU. Default: interface MTU minus 3 (for frame type + length prefix) |
| `recv_buf_size` | usize | `2097152` | Socket receive buffer size in bytes (2 MB) |
| `send_buf_size` | usize | `2097152` | Socket send buffer size in bytes (2 MB) |
| `discovery` | bool | `true` | Listen for discovery beacons from other nodes |
| `announce` | bool | `false` | Broadcast announcement beacons on the LAN |
| `auto_connect` | bool | `false` | Auto-connect to discovered peers |
| `accept_connections` | bool | `false` | Accept incoming connection attempts from discovered peers |
| `beacon_interval_secs` | u64 | `30` | Announcement beacon interval in seconds (minimum 10) |

**Named instances.** Multiple Ethernet interfaces can be configured by
using named sub-keys instead of flat parameters:

```yaml
transports:
  ethernet:
    lan:
      interface: "eth0"
      discovery: true
      announce: true
    backbone:
      interface: "eth1"
      announce: false
```

Each named instance operates independently with its own socket and
discovery state. The instance name is used in log messages and the
`name()` method on the Transport trait.

### TCP (`transports.tcp.*`)

TCP transport enables firewall traversal on networks that block UDP but
allow TCP (e.g., port 443). Uses FMP header-based framing with zero
overhead.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transports.tcp.bind_addr` | string | *(none)* | Listen address (e.g., `"0.0.0.0:8443"`). If omitted, outbound-only mode. |
| `transports.tcp.mtu` | u16 | `1400` | Default MTU. Per-connection MTU derived from `TCP_MAXSEG` when available. |
| `transports.tcp.connect_timeout_ms` | u64 | `5000` | Outbound connect timeout in milliseconds |
| `transports.tcp.nodelay` | bool | `true` | `TCP_NODELAY` (disable Nagle for low latency) |
| `transports.tcp.keepalive_secs` | u64 | `30` | TCP keepalive interval in seconds (0 = disabled) |
| `transports.tcp.recv_buf_size` | usize | `2097152` | Socket receive buffer size in bytes (2 MB) |
| `transports.tcp.send_buf_size` | usize | `2097152` | Socket send buffer size in bytes (2 MB) |
| `transports.tcp.max_inbound_connections` | usize | `256` | Maximum simultaneous inbound connections |

**Named instances.** Like other transports, multiple TCP instances can
be configured with named sub-keys:

```yaml
transports:
  tcp:
    public:
      bind_addr: "0.0.0.0:443"
    internal:
      bind_addr: "10.0.0.1:8443"
      max_inbound_connections: 64
```

### Tor (`transports.tor.*`)

Tor transport routes FIPS traffic through the Tor network for anonymity.
Requires an external Tor daemon providing a SOCKS5 proxy. Three modes:
`socks5` for outbound-only, `control_port` for outbound + monitoring,
`directory` for outbound + inbound via Tor-managed onion service.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transports.tor.mode` | string | `"socks5"` | Tor access mode: `socks5` (outbound only), `control_port` (outbound + monitoring), or `directory` (outbound + inbound onion service) |
| `transports.tor.socks5_addr` | string | `"127.0.0.1:9050"` | SOCKS5 proxy address (host:port) |
| `transports.tor.connect_timeout_ms` | u64 | `120000` | Connect timeout in milliseconds. Tor circuits take 10–60s. |
| `transports.tor.mtu` | u16 | `1400` | Default MTU |
| `transports.tor.control_addr` | string | `"/run/tor/control"` | Tor control port address: Unix socket path or host:port. Used in `control_port` mode; optional in `directory` mode for monitoring. |
| `transports.tor.control_auth` | string | `"cookie"` | Control port authentication: `"cookie"`, `"cookie:/path/to/cookie"`, or `"password:<secret>"`. |
| `transports.tor.cookie_path` | string | `"/var/run/tor/control.authcookie"` | Path to Tor control cookie file. Used when `control_auth` is `"cookie"`. |
| `transports.tor.max_inbound_connections` | usize | `64` | Maximum inbound connections via onion service. |
| `transports.tor.directory_service.hostname_file` | string | `"/var/lib/tor/fips_onion_service/hostname"` | Path to Tor-managed hostname file containing the `.onion` address. |
| `transports.tor.directory_service.bind_addr` | string | `"127.0.0.1:8443"` | Local bind address for the listener that Tor forwards inbound connections to. Must match `HiddenServicePort` target in `torrc`. |

**Named instances.** Like other transports, multiple Tor instances can
be configured with named sub-keys for different SOCKS5 proxy endpoints.

**Directory mode** (recommended for production). Tor manages the onion
service via `HiddenServiceDir` in `torrc`. FIPS reads the `.onion`
address from the hostname file and binds a local TCP listener. This
enables Tor's `Sandbox 1` (seccomp-bpf). If `control_addr` is also
set, the transport connects to the control port for daemon monitoring
(non-fatal on failure).

**Control port mode.** Connects to the Tor daemon's control port for
monitoring only (bootstrap status, circuit health, traffic stats).
No inbound connections. Both `control_addr` and `control_auth` are
required.

### UDP + Tor Bridge Example

A node bridging clearnet (UDP) and anonymous (Tor) portions of the mesh:

```yaml
node:
  identity:
    persistent: true

tun:
  enabled: true

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    mtu: 1472
  tor:
    socks5_addr: "127.0.0.1:9050"

peers:
  - npub: "npub1abc..."
    alias: "clearnet-peer"
    addresses:
      - transport: udp
        addr: "203.0.113.5:2121"
  - npub: "npub1def..."
    alias: "anonymous-peer"
    addresses:
      - transport: tor
        addr: "abc123...xyz.onion:2121"
```

### Tor Directory Mode Example

A node accepting inbound connections via Tor-managed onion service
(recommended for production — enables Sandbox 1):

```yaml
node:
  identity:
    persistent: true

tun:
  enabled: true

transports:
  tor:
    mode: "directory"
    socks5_addr: "127.0.0.1:9050"
    control_addr: "/run/tor/control"    # optional, for monitoring
    control_auth: "cookie"
    directory_service:
      hostname_file: "/var/lib/tor/fips/hostname"
      bind_addr: "127.0.0.1:8444"

peers:
  - npub: "npub1abc..."
    alias: "tor-peer"
    addresses:
      - transport: tor
        addr: "abcdef...xyz.onion:8443"
```

Requires a corresponding `torrc`:

```text
HiddenServiceDir /var/lib/tor/fips
HiddenServicePort 8443 127.0.0.1:8444
```

### BLE (`transports.ble.*`)

Bluetooth Low Energy transport using L2CAP Connection-Oriented Channels.
Requires BlueZ and the `ble` Cargo feature flag (default-on). Linux only;
guarded by `#[cfg(target_os = "linux")]`. Communicates with BlueZ via D-Bus
using the `bluer` crate.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `transports.ble.adapter` | string | `"hci0"` | HCI adapter name |
| `transports.ble.psm` | u16 | `0x0085` (133) | L2CAP Protocol/Service Multiplexer |
| `transports.ble.mtu` | u16 | `2048` | Default MTU. Actual MTU is negotiated per-link during L2CAP connection setup. |
| `transports.ble.max_connections` | usize | `7` | Maximum concurrent BLE connections |
| `transports.ble.connect_timeout_ms` | u64 | `10000` | Outbound connect timeout in milliseconds |
| `transports.ble.advertise` | bool | `true` | Broadcast BLE beacon advertisements for peer discovery |
| `transports.ble.scan` | bool | `true` | Listen for BLE beacon advertisements from other nodes |
| `transports.ble.auto_connect` | bool | `false` | Automatically connect to discovered peers |
| `transports.ble.accept_connections` | bool | `true` | Accept incoming L2CAP connections |
| `transports.ble.probe_cooldown_secs` | u64 | `30` | Cooldown before re-probing the same BLE address |

**Address format.** BLE peer addresses use the form
`"adapter/device_address"` — for example, `"hci0/AA:BB:CC:DD:EE:FF"`.

**Advertising and scanning.** When `advertise` is enabled, the transport
advertises the FIPS service UUID continuously so that nearby nodes can
discover and connect via L2CAP. When `scan` is enabled, the transport
continuously scans for other FIPS nodes' advertisements. Discovered
peers are probed immediately (L2CAP connect + pubkey exchange) with a
cooldown (`probe_cooldown_secs`) to prevent rapid re-probing of the same
address. If two nodes probe each other at the same time (cross-probe),
a deterministic tie-breaker based on NodeAddr comparison ensures only
one connection is established.

**Connection pool.** The `max_connections` parameter limits the number of
concurrent BLE connections. When the pool is full, the least-recently-used
connection is evicted to make room for new connections.

### BLE Example

A node using BLE for local mesh discovery alongside UDP for internet peers:

```yaml
node:
  identity:
    persistent: true

tun:
  enabled: true

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
  ble:
    adapter: "hci0"
    advertise: true
    scan: true
    auto_connect: true
    accept_connections: true

peers:
  - npub: "npub1abc..."
    alias: "internet-peer"
    addresses:
      - transport: udp
        addr: "203.0.113.5:2121"
    connect_policy: auto_connect
```

BLE peers on the local radio range are discovered automatically via
beacons — no static peer entries needed. Internet peers still require
explicit configuration.

## Peers (`peers[]`)

Static peer list. Each entry defines a peer to connect to.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `peers[].npub` | string | *(required)* | Peer's Nostr public key (npub-encoded) |
| `peers[].alias` | string | *(none)* | Human-readable name for logging |
| `peers[].addresses[].transport` | string | *(required)* | Transport type: `udp`, `tcp`, `ethernet`, `tor`, or `ble` |
| `peers[].addresses[].addr` | string | *(required)* | Transport address. UDP/TCP: `"host:port"` (IP or DNS hostname). Ethernet: `"interface/mac"` (e.g., `"eth0/aa:bb:cc:dd:ee:ff"`). BLE: `"adapter/device_address"` (e.g., `"hci0/AA:BB:CC:DD:EE:FF"`). Tor: `".onion:port"` or `"host:port"` |
| `peers[].addresses[].priority` | u8 | `100` | Address priority (lower = preferred) |
| `peers[].connect_policy` | string | `"auto_connect"` | Connection policy: `auto_connect`, `on_demand`, or `manual` |
| `peers[].auto_reconnect` | bool | `true` | Automatically reconnect after MMP link-dead removal (exponential backoff, unlimited retries) |
| `peers[].via_nostr` | bool | `false` | Append Nostr advert-derived endpoints after static addresses for this peer |

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
    bind_addr: "0.0.0.0:2121"
    mtu: 1472

peers:
  - npub: "npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le"
    alias: "node-b"
    addresses:
      - transport: udp
        addr: "172.20.0.11:2121"
    connect_policy: auto_connect
```

### Mixed UDP + Ethernet Example

A node bridging internet peers (UDP) and a local Ethernet segment with
beacon discovery:

```yaml
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

tun:
  enabled: true

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    mtu: 1472
  ethernet:
    interface: "eth0"
    discovery: true
    announce: true
    auto_connect: true
    accept_connections: true

peers:
  - npub: "npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le"
    alias: "internet-peer"
    addresses:
      - transport: udp
        addr: "203.0.113.5:2121"
    connect_policy: auto_connect
```

Ethernet peers on the local segment are discovered automatically via
beacons — no static peer entries needed. Internet peers still require
explicit configuration.

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
    nsec: null                       # secret key in nsec or hex (null = depends on persistent)
    persistent: false                # true = load/save fips.key; false = ephemeral each start
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
    attempt_timeouts_secs: [1, 2, 4, 8]
    recent_expiry_secs: 10
    backoff_base_secs: 0
    backoff_max_secs: 0
    forward_min_interval_secs: 2
  tree:
    announce_min_interval_ms: 500
    parent_hysteresis: 0.2              # cost improvement fraction for parent switch
    hold_down_secs: 30                  # suppress re-evaluation after switch
    reeval_interval_secs: 60            # periodic cost-based re-evaluation (0 = disabled)
    flap_threshold: 4                    # parent switches before dampening
    flap_window_secs: 60                 # sliding window for flap detection
    flap_dampening_secs: 120             # extended hold-down on flap
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
  ecn:
    enabled: true                    # ECN congestion signaling (CE flag relay)
    loss_threshold: 0.05             # MMP loss rate threshold for CE marking (5%)
    etx_threshold: 3.0               # MMP ETX threshold for CE marking
  rekey:
    enabled: true                    # periodic Noise rekey for forward secrecy
    after_secs: 120                  # rekey interval (seconds)
    after_messages: 65536            # rekey after N messages sent
  control:
    enabled: true
    socket_path: null                # null = auto ($XDG_RUNTIME_DIR → /run/fips → /tmp fallback)
  buffers:
    packet_channel: 1024
    tun_channel: 1024
    dns_channel: 64

tun:
  enabled: false
  name: "fips0"
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"
  port: 5354
  ttl: 300

transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    mtu: 1280
    recv_buf_size: 2097152           # 2 MB (kernel doubles to 4 MB actual)
    send_buf_size: 2097152           # 2 MB
  # ethernet:                        # uncomment to enable (requires CAP_NET_RAW)
  #   interface: "eth0"              # required: network interface name
  #   ethertype: 0x2121              # default EtherType
  #   mtu: null                      # null = interface MTU - 3 (typically 1497)
  #   recv_buf_size: 2097152         # 2 MB
  #   send_buf_size: 2097152         # 2 MB
  #   discovery: true                # listen for beacons
  #   announce: false                # broadcast beacons
  #   auto_connect: false            # connect to discovered peers
  #   accept_connections: false      # accept inbound handshakes
  #   beacon_interval_secs: 30       # beacon interval (min 10)
  # tcp:                             # uncomment to enable TCP transport
  #   bind_addr: "0.0.0.0:8443"     # listen address (omit for outbound-only)
  #   mtu: 1400                      # default MTU
  #   connect_timeout_ms: 5000       # outbound connect timeout
  #   nodelay: true                  # TCP_NODELAY
  #   keepalive_secs: 30             # keepalive interval (0 = disabled)
  #   recv_buf_size: 2097152         # 2 MB
  #   send_buf_size: 2097152         # 2 MB
  #   max_inbound_connections: 256   # resource protection limit
  # tor:                             # uncomment to enable Tor transport
  #   mode: "socks5"                 # "socks5", "control_port", or "directory"
  #   socks5_addr: "127.0.0.1:9050" # SOCKS5 proxy address
  #   connect_timeout_ms: 120000    # connect timeout (120s for Tor circuits)
  #   mtu: 1400                     # default MTU
  #   # monitoring (control_port mode, or optional in directory mode):
  #   # control_addr: "/run/tor/control"   # Unix socket or host:port
  #   # control_auth: "cookie"             # "cookie" or "password:<secret>"
  #   # cookie_path: "/var/run/tor/control.authcookie"
  #   # directory mode (inbound via Tor-managed onion service):
  #   # directory_service:
  #   #   hostname_file: "/var/lib/tor/fips/hostname"
  #   #   bind_addr: "127.0.0.1:8444"
  #   # max_inbound_connections: 64
  # ble:                              # uncomment to enable BLE transport (Linux only, requires BlueZ)
  #   adapter: "hci0"                 # HCI adapter name
  #   psm: 0x0085                     # L2CAP PSM (133)
  #   mtu: 2048                       # default MTU (negotiated per-link)
  #   max_connections: 7              # max concurrent BLE connections
  #   connect_timeout_ms: 10000       # outbound connect timeout
  #   advertise: true                 # broadcast BLE beacons
  #   scan: true                      # listen for BLE beacons
  #   auto_connect: false             # connect to discovered peers
  #   accept_connections: true         # accept incoming L2CAP connections
  #   probe_cooldown_secs: 30         # cooldown before re-probing same address

peers:                               # static peer list
  # - npub: "npub1..."
  #   alias: "node-b"
  #   addresses:
  #     - transport: udp
  #       addr: "10.0.0.2:2121"
  #       priority: 100
  #   connect_policy: auto_connect
  #   auto_reconnect: true           # reconnect after link-dead removal
```
