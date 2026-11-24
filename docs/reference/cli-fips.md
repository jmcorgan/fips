# `fips`

The FIPS mesh network daemon.

## Synopsis

```text
fips [-c FILE] [--log-file FILE]
```

On Windows the same binary additionally accepts `--install-service`,
`--uninstall-service`, and (used internally by the service control
manager) `--service`.

## Description

`fips` is the FIPS daemon. It loads a YAML configuration, resolves an
identity, brings up the TUN adapter, listens on configured transports,
authenticates peers, maintains the spanning tree, and forwards mesh
traffic. There is one daemon per node.

The daemon stays in the foreground, logging to stderr (or to the file
named by `--log-file` or `node.log_file`), until it
receives `SIGINT` or `SIGTERM`. On Windows, the service variant is
controlled through the standard service control manager.

## Options

| Flag | Argument | Description |
| ---- | -------- | ----------- |
| `-c`, `--config` | `FILE` | Use `FILE` as the configuration. Skips the default search paths. |
| `--log-file` | `FILE` | Log to `FILE` instead of stdout, rolled by size at `node.log_max_size_mb` and kept to `node.log_max_files` rolled files. Overrides `node.log_file`, and is opened before the configuration loads, so a configuration error is logged there too. The macOS package passes it from the launchd plist. See [configuration.md](configuration.md). |
| `-V` | — | Print the short version, `<version> (rev <git-hash>)`. The `rev` part is omitted when the build could not read a git revision, as in a package built from a git worktree. |
| `--version` | — | Print the long version: short version plus build target triple. |
| `-h`, `--help` | — | Print usage and exit. |
| `--install-service` | — | (Windows only) Install `fips` as a Windows service. Requires Administrator. |
| `--uninstall-service` | — | (Windows only) Uninstall the Windows service. Requires Administrator. |
| `--service` | — | (Windows only, internal) Run as a Windows service. Invoked by the service control manager — not for direct use. |

There are no other CLI flags; all other daemon behaviour is governed by
the YAML configuration. See [configuration.md](configuration.md).

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | Clean shutdown after `SIGINT` / `SIGTERM`. |
| `1` | Failed to load configuration, resolve identity, construct the node, or start the node. The reason is printed to stderr before exit. A configuration that configures nothing (no identity, transports, peers or gateway section) counts as a load failure; see [Files](#files). |

## Environment

| Variable | Description |
| -------- | ----------- |
| `RUST_LOG` | Tracing filter directive. Overrides `node.log_level` from the config. Examples: `info`, `debug`, `fips=trace,fips::node::handlers::mmp=debug`. |
| `XDG_RUNTIME_DIR` | Used to derive the default control-socket path when `/run/fips` does not exist and the daemon is not running as root. See [control-socket.md](control-socket.md). |
| `FIPS_CONFIG` | (Windows service mode only) Path to the configuration file when the daemon runs under the service control manager. |

The daemon also clamps the `nostr_sdk` and `nostr` log targets to
`info` whenever the effective log level is below `trace`, so that
`RUST_LOG=debug` does not flood the journal with raw relay frames. To
see those frames, set the level to `trace`.

## Files

`fips` looks for `fips.yaml` in the following locations, lowest to
highest priority. All present files are merged in priority order; the
highest-priority value wins.

| Priority | Path | Purpose |
| -------- | ---- | ------- |
| 1 | `/usr/local/etc/fips/fips.yaml` (macOS, FreeBSD), `C:\ProgramData\fips\fips.yaml` (Windows), `/etc/fips/fips.yaml` (other Unix) | System-wide defaults |
| 2 | `~/.config/fips/fips.yaml` (`%APPDATA%\fips\fips.yaml` on Windows) | User preferences |
| 3 | `~/.fips.yaml` | Legacy user config |
| 4 | `./fips.yaml` | Deployment-specific overrides |

On macOS and FreeBSD both system directories are probed: `/etc/fips`
first, then `/usr/local/etc/fips`, so the packaged file wins over a
leftover `/etc/fips` copy from an earlier install. Windows likewise
probes `\etc\fips` on the current drive, then `C:\ProgramData\fips`.
The `\etc\fips` probe is deprecated: any local user can create that
file, so the daemon warns when it loads a config from there, and from
v0.6.0 the search no longer looks there. Move the settings you need into
`C:\ProgramData\fips\fips.yaml`.

On Unix, when `fips` runs as root without `-c`, it logs a warning for
each config it read from priorities 2 to 4, since another account may be
able to write those files. The warning is logged at ERROR, so
`node.log_level` set in one of those files cannot hide it. Pass `-c` to
name the file to use.

If the file given with `-c`, or the files found on the search path taken
together, configure nothing (no `node.identity.nsec`,
`node.identity.persistent` off, no transports, no peers and no `gateway`
section), `fips` refuses to start and names the file or files, rather than
start an ephemeral node with no transports. This covers an empty or
comments-only file, and one that sets only other settings such as
`node.log_level`. A blank file beside one that configures the node is
accepted. With no config file found at all, `fips` starts on the built-in
defaults. See
[configuration.md](configuration.md#empty-configuration).

Adjacent to the highest-priority config file the daemon keeps the
identity files:

| File | Mode | Purpose |
| ---- | ---- | ------- |
| `fips.key` | `0600` | Bech32 nsec for the persistent identity, written only in persistent mode (Unix; on Windows the file takes its directory's ACL, which `install-service.ps1` restricts to SYSTEM and Administrators). |
| `fips.pub` | `0644` | Bech32 npub of the running identity, written on every start. In persistent mode it corresponds to `fips.key`. |

When `node.identity.persistent` is `false` (the default), a fresh
keypair is generated on every start and only `fips.pub` is written.
A `fips.key` found there is moved aside to `fips.key.unused` and a
warning is logged.

On Windows the service writes its log to `C:\ProgramData\fips\fips.log`,
rolled at 10 MiB with four old files kept; a foreground run logs to the
console.

On Windows, `install-service.ps1` restricts `C:\ProgramData\fips` to
SYSTEM and Administrators. Reading or editing files there,
`fipsctl keygen`, `fipsctl address` with no argument, and a foreground
run that relies on `C:\ProgramData\fips\fips.yaml` need an elevated
prompt; unelevated, a foreground run may skip that file without saying
so or fail with an access error. Run the installer before `fipsctl keygen`,
and again after moving files into the directory, since a moved file
keeps its old permissions.

The control socket path is derived per
[control-socket.md](control-socket.md).

## See also

- [`fipsctl`](cli-fipsctl.md) — control-socket client.
- [`fipstop`](cli-fipstop.md) — live-status TUI.
- [configuration.md](configuration.md) — YAML reference.
- [control-socket.md](control-socket.md) — control-socket protocol.
