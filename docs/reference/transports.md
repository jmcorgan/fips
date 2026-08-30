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
| `pool_inbound` | Current inbound connections held in the connection pool (gauge) |
| `pool_outbound` | Current outbound connections held in the connection pool (gauge) |

## Ethernet

| Counter | Description |
| ------- | ----------- |
| `frames_sent` / `frames_recv` | Successful frame send/receive |
| `bytes_sent` / `bytes_recv` | Byte counters |
| `send_errors` / `recv_errors` | Send/receive failures |
| `beacons_sent` / `beacons_recv` | Peer-discovery beacon traffic |
| `beacons_dropped` | Received beacons the discovery buffer had no room for |
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
| `pool_inbound` | Current inbound connections held in the connection pool (gauge) |
| `pool_outbound` | Current outbound connections held in the connection pool (gauge) |

## Nym

| Counter | Description |
| ------- | ----------- |
| `packets_sent` / `bytes_sent` | Successful sends |
| `packets_recv` / `bytes_recv` | Successful receives |
| `send_errors` / `recv_errors` | Send/receive failures |
| `mtu_exceeded` | Packets rejected for MTU violation |
| `connections_established` | Successful SOCKS5 connections through `nym-socks5-client` |
| `connect_timeouts` | Connection timeout count |
| `socks5_errors` | SOCKS5 protocol errors |

Nym is outbound-only (no inbound listener), so there are no
`connections_accepted` / `connections_rejected` counters.

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
| `handshakes_aborted` | Inbound handshakes aborted to free an in-flight slot |
| `connect_timeouts` | Connection timeout count |
| `connect_errors` | Outbound connects that failed with an error rather than timing out |
| `pubkey_exchange_failures` | Connections dropped because the pre-handshake pubkey exchange failed |
| `tiebreaker_yields` | Outbound connections stood down by the cross-probe tie-breaker |
| `tiebreaker_drops` | Inbound connections stood down by the cross-probe tie-breaker |
| `pool_evictions` | Connection-pool entries evicted |
| `advertisements_sent` | BLE advertisements emitted |
| `scan_results` | BLE scan results observed |
| `duplicate_node_declines` | Connections declined because the peer was already linked on another link address |

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
