# Transport Statistics Reference

Per-transport statistics counter inventories. Counters are exposed
through the daemon control socket (`fipsctl show transports`) and the
`fipstop` operator UI. For the transport-layer design (services
provided to FMP, transport categories, the trait surface, connection
model), see
[../design/fips-transport-layer.md](../design/fips-transport-layer.md).

All transports report counters via `fipsctl show transports`; the
tables below are source-extracted from each transport's `stats.rs`
module.

## UDP

| Counter | Description |
| ------- | ----------- |
| `packets_sent` / `bytes_sent` | Successful sends |
| `packets_recv` / `bytes_recv` | Successful receives |
| `send_errors` / `recv_errors` | Send/receive failures |
| `mtu_exceeded` | Packets rejected for MTU violation |
| `kernel_drops` | Kernel `SO_RXQ_OVFL` drop count (feeds ECN congestion detection) |

## TCP

| Counter | Description |
| ------- | ----------- |
| `packets_sent` / `bytes_sent` | Successful sends |
| `packets_recv` / `bytes_recv` | Successful receives |
| `send_errors` / `recv_errors` | Send/receive failures |
| `mtu_exceeded` | Packets rejected for MTU violation |
| `connections_established` | Successful outbound connections |
| `connections_accepted` | Accepted inbound connections |
| `connections_rejected` | Rejected inbound connections (limit exceeded) |
| `connect_timeouts` | Connection timeout count |
| `connect_refused` | Connection refused count |

## Ethernet

| Counter | Description |
| ------- | ----------- |
| `frames_sent` / `frames_recv` | Successful frame send/receive |
| `bytes_sent` / `bytes_recv` | Byte counters |
| `send_errors` / `recv_errors` | Send/receive failures |
| `beacons_sent` / `beacons_recv` | Peer-discovery beacon traffic |
| `frames_too_short` | Frames below minimum length, dropped |
| `frames_too_long` | Frames above transport MTU, dropped |

## Tor

| Counter | Description |
| ------- | ----------- |
| `packets_sent` / `bytes_sent` | Successful sends |
| `packets_recv` / `bytes_recv` | Successful receives |
| `send_errors` / `recv_errors` | Send/receive failures |
| `connections_established` | Successful SOCKS5 connections |
| `connect_timeouts` | Connection timeout count |
| `connect_refused` | Connection refused count |
| `socks5_errors` | SOCKS5 protocol errors |
| `mtu_exceeded` | Packets rejected for MTU violation |
| `connections_accepted` | Accepted inbound connections via onion service |
| `connections_rejected` | Rejected inbound connections (limit exceeded) |
| `control_errors` | Tor control port errors |

## Bluetooth

| Counter | Description |
| ------- | ----------- |
| `packets_sent` / `bytes_sent` | Successful L2CAP CoC sends |
| `packets_recv` / `bytes_recv` | Successful L2CAP CoC receives |
| `send_errors` / `recv_errors` | Send/receive failures |
| `mtu_exceeded` | Packets rejected for MTU violation |
| `connections_established` | Successful outbound L2CAP connections |
| `connections_accepted` | Accepted inbound L2CAP connections |
| `connections_rejected` | Rejected inbound (limit exceeded) |
| `connect_timeouts` | Connection timeout count |
| `pool_evictions` | Connection-pool entries evicted |
| `advertisements_sent` | BLE advertisements emitted |
| `scan_results` | BLE scan results observed |

## See also

- [../design/fips-transport-layer.md](../design/fips-transport-layer.md)
  — transport-layer design, trait surface, per-transport sections
- [configuration.md](configuration.md) — `transports.*` configuration
  blocks
- [../how-to/tune-udp-buffers.md](../how-to/tune-udp-buffers.md) —
  host-side `net.core.rmem_max` / `net.core.wmem_max` setup for UDP
- [../how-to/deploy-tor-onion.md](../how-to/deploy-tor-onion.md) —
  Tor `directory` mode operator setup
- [../how-to/set-up-bluetooth-peer.md](../how-to/set-up-bluetooth-peer.md)
  — Linux BLE peer config
