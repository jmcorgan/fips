# `fips`

The FIPS mesh network daemon.

## Synopsis

```text
fips [-c FILE]
```

On Windows the same binary additionally accepts `--install-service`,
`--uninstall-service`, and (used internally by the service control
manager) `--service`.

## Description

`fips` is the FIPS daemon. It loads a YAML configuration, resolves an
identity, brings up the TUN adapter, listens on configured transports,
authenticates peers, maintains the spanning tree, and forwards mesh
traffic. There is one daemon per node.

The daemon stays in the foreground, logging to stderr, until it
receives `SIGINT` or `SIGTERM`. On Windows, the service variant is
controlled through the standard service control manager.

## Options

| Flag | Argument | Description |
| ---- | -------- | ----------- |
| `-c`, `--config` | `FILE` | Use `FILE` as the configuration. Skips the default search paths. |
| `-V` | — | Print the short version (e.g. `0.3.0-dev (rev abcdef1)`). |
| `--version` | — | Print the long version: short version plus build target triple. |
| `-h`, `--help` | — | Print usage and exit. |
| `--install-service` | — | (Windows only) Install `fips` as a Windows service. Requires Administrator. |
| `--uninstall-service` | — | (Windows only) Uninstall the Windows service. Requires Administrator. |
| `--service` | — | (Windows only, internal) Run as a Windows service. Invoked by the service control manager — not for direct use. |

There are no other CLI flags; all daemon behaviour is governed by the
YAML configuration. See [configuration.md](configuration.md).

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | Clean shutdown after `SIGINT` / `SIGTERM`. |
| `1` | Failed to load configuration, resolve identity, construct the node, or start the node. The reason is printed to stderr before exit. |

## Environment

| Variable | Description |
| -------- | ----------- |
| `RUST_LOG` | Tracing filter directive. Overrides `node.log_level` from the config. Examples: `info`, `debug`, `fips=trace,fips::node::handlers::mmp=debug`. |
| `XDG_RUNTIME_DIR` | Used to derive the default control-socket path when `/run/fips` does not exist. See [control-socket.md](control-socket.md). |
| `FIPS_CONFIG` | (Windows service mode only) Path to the configuration file when the daemon runs under the service control manager. |

The daemon also clamps the `nostr_relay_pool`, `nostr_sdk`, and `nostr`
log targets to `info` whenever the effective log level is below
`trace`, so that `RUST_LOG=debug` does not flood the journal with raw
relay frames. To see those frames, set the level to `trace`.

## Files

`fips` looks for `fips.yaml` in the following locations, lowest to
highest priority. All present files are merged in priority order; the
highest-priority value wins.

| Priority | Path | Purpose |
| -------- | ---- | ------- |
| 1 | `/etc/fips/fips.yaml` | System-wide defaults |
| 2 | `~/.config/fips/fips.yaml` | User preferences |
| 3 | `~/.fips.yaml` | Legacy user config |
| 4 | `./fips.yaml` | Deployment-specific overrides |

Adjacent to the highest-priority config file the daemon reads (or
writes, on first start) the identity files:

| File | Mode | Purpose |
| ---- | ---- | ------- |
| `fips.key` | `0600` | Bech32 nsec for the persistent identity (Unix only; Windows inherits parent ACLs). |
| `fips.pub` | `0644` | Bech32 npub corresponding to `fips.key`. |

When `node.identity.persistent` is `false` (the default), a fresh
keypair is written to these files on every start.

The control socket path is derived per
[control-socket.md](control-socket.md).

## See also

- [`fipsctl`](cli-fipsctl.md) — control-socket client.
- [`fipstop`](cli-fipstop.md) — live-status TUI.
- [configuration.md](configuration.md) — YAML reference.
- [control-socket.md](control-socket.md) — control-socket protocol.
