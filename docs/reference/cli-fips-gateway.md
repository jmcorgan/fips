# `fips-gateway`

Long-running service that bridges a LAN segment into the FIPS mesh.

## Synopsis

```text
fips-gateway [-c FILE] [-l LEVEL]
```

## Description

`fips-gateway` runs alongside `fips` on the same host, reads the same
`fips.yaml`, and exposes two complementary functions to the LAN it
fronts:

- **Outbound (LAN -> mesh).** Allocates a virtual IPv6 from a managed
  pool when a LAN client resolves `<npub>.fips`, installs nftables
  DNAT/SNAT/masquerade rules so the client's traffic is rewritten and
  carried into the mesh through the daemon's `fips0` adapter.
- **Inbound (mesh -> LAN).** Installs nftables DNAT and LAN-side
  masquerade rules so mesh-side traffic arriving on `fips0` for the
  configured listen ports is rewritten to a LAN `host:port`, per the
  `gateway.port_forwards[]` block.

The service runs alongside `fips`, not as a replacement for it:
the daemon must be running on the same host with the TUN adapter
and DNS resolver enabled. The gateway is read-only with respect to the
daemon's state, and connects to the daemon's resolver only — it is
not a peer. For the architecture, see
[../design/fips-gateway.md](../design/fips-gateway.md).

`fips-gateway` is **Linux-only**. The binary errors out and exits with
status `1` on any other platform, since the NAT pipeline is built on
nftables and proxy NDP. See
[Configuration](#configuration) for the platform notes that follow
from this.

## Options

| Flag | Argument | Default | Description |
| ---- | -------- | ------- | ----------- |
| `-c`, `--config` | `FILE` | *(default search paths)* | Use `FILE` as the configuration. Skips the default search paths. |
| `-l`, `--log-level` | `LEVEL` | `info` | Tracing level: `trace`, `debug`, `info`, `warn`, `error`. Overridden by `RUST_LOG` if set (see [Environment](#environment)). |
| `-V` | — | — | Print the short version. |
| `--version` | — | — | Print the long version (short version plus build target triple). |
| `-h`, `--help` | — | — | Print usage and exit. |

## Configuration

`fips-gateway` reads the same `fips.yaml` as `fips`; the gateway is
configured under the top-level `gateway:` block. The block must
include at minimum `enabled: true`, `pool`, and `lan_interface`. For
each field — pool, LAN interface, DNS listener, conntrack overrides,
and inbound `port_forwards[]` — see the
[Gateway section](configuration.md#gateway-gateway) of the
configuration reference.

The same default search paths apply as for `fips`
(see [`fips`](cli-fips.md#files)); `-c FILE` overrides the search.
The gateway must be able to read the same configuration file the
daemon is reading, or the two will disagree about pool, DNS port,
and LAN interface.

For deployment recipes, see
[../how-to/deploy-gateway.md](../how-to/deploy-gateway.md) (manual
Linux host) and
[../tutorials/deploy-fips-gateway.md](../tutorials/deploy-fips-gateway.md)
(OpenWrt walk-through).

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | Clean shutdown after `SIGINT` / `SIGTERM`. |
| `1` | Non-Linux platform, configuration load failure, missing or invalid `gateway:` block, NAT/network setup failure, or control-socket bind failure. The reason is printed to stderr or the log before exit. |

## Environment

| Variable | Description |
| -------- | ----------- |
| `RUST_LOG` | Tracing filter directive. Takes precedence over `--log-level`. Examples: `info`, `debug`, `fips=trace,fips::gateway=debug`. |

## Files

| Path | Purpose |
| ---- | ------- |
| `/etc/fips/fips.yaml` | Gateway configuration (top-level `gateway:` block). Same file the daemon reads. |
| `/run/fips/gateway.sock` | Gateway control socket. Hardcoded path; chowned to group `fips` (mode `0770`) at startup so members of that group can query without sudo. |
| `inet fips_gateway` (nftables) | NAT table the gateway installs and tears down. View with `nft list table inet fips_gateway`. |

The gateway also adds and removes a `local <pool-cidr> dev lo` route
in the local routing table so the kernel accepts pool addresses as
locally-owned.

## Control Socket

`fips-gateway` exposes a JSON line-protocol control socket separate
from the daemon's. The command set (`show_gateway`, `show_mappings`)
and JSON shapes are documented in the
[Gateway Command Catalog](control-socket.md#gateway-command-catalog).

There is no `fipsctl` subcommand for the gateway — query the socket
directly with `nc -U`, or watch the **Gateway** tab in
[`fipstop`](cli-fipstop.md), which polls the gateway socket
automatically.

## See also

- [`fips`](cli-fips.md) — the daemon. Required to be running on the
  same host.
- [`fipstop`](cli-fipstop.md) — the live-status TUI; its Gateway tab
  polls the gateway control socket.
- [configuration.md § Gateway](configuration.md#gateway-gateway) —
  full `gateway.*` block reference.
- [control-socket.md § Gateway Command Catalog](control-socket.md#gateway-command-catalog)
  — wire protocol for the gateway socket.
- [../design/fips-gateway.md](../design/fips-gateway.md) — design,
  NAT pipeline, virtual IP pool lifecycle.
- [../how-to/deploy-gateway.md](../how-to/deploy-gateway.md) — manual
  Linux deployment.
- [../how-to/troubleshoot-gateway.md](../how-to/troubleshoot-gateway.md)
  — diagnostic recipes.
- [../tutorials/deploy-fips-gateway.md](../tutorials/deploy-fips-gateway.md)
  — OpenWrt walk-through.
