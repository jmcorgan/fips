# `fipsctl`

Command-line client for the FIPS daemon's control socket.

## Synopsis

```text
fipsctl [-s SOCKET] <subcommand> [args...]
```

## Description

`fipsctl` connects to a running daemon over its control socket
(Unix domain socket on Linux/macOS, TCP loopback on Windows), sends
one JSON request, and pretty-prints the response. Exits with a
non-zero status if the socket cannot be reached, the daemon returns an
error, or the request times out.

`fipsctl keygen` is a special case: it does not contact the daemon and
operates purely on local files.

For the line-delimited JSON wire protocol, see
[control-socket.md](control-socket.md). For the YAML configuration
that defines the socket location, see
[configuration.md](configuration.md).

## Global Options

| Flag | Argument | Description |
| ---- | -------- | ----------- |
| `-s`, `--socket` | `PATH` | Override the control-socket path (Linux/macOS) or TCP port (Windows). |
| `-V`, `--version` | — | Print the short version. |
| `--version` | — | Print the long version. |
| `-h`, `--help` | — | Print usage and exit. Per-subcommand help via `fipsctl <subcommand> --help`. |

## Subcommands

### `show <what>`

Read-only queries against the daemon. Each subcommand maps 1:1 to a
control-socket query (see [control-socket.md](control-socket.md)) and
prints the response's `data` object as pretty JSON.

| Subcommand | Control-socket command | Returns |
| ---------- | ---------------------- | ------- |
| `show status` | `show_status` | Node-level status: identity, version, peer/link/session counts, TUN state, recent sparklines. |
| `show peers` | `show_peers` | Authenticated peer list with link IDs, transport addresses, MMP metrics, Noise/rekey state. |
| `show links` | `show_links` | Active links (one per FMP-authenticated peer): direction, state, byte counters. |
| `show tree` | `show_tree` | Spanning-tree state: root, my coordinates, parent, peer declarations. |
| `show sessions` | `show_sessions` | End-to-end FSP sessions: state, traffic counters, session-MMP metrics, path MTU. |
| `show bloom` | `show_bloom` | Bloom-filter state: own filter sequence, leaf dependents, per-peer filter summaries. |
| `show mmp` | `show_mmp` | MMP metrics summary: per-peer link-layer metrics and per-session session-layer metrics. |
| `show cache` | `show_cache` | Coordinate cache: TTL, fill ratio, per-destination coords and path MTU. |
| `show connections` | `show_connections` | Pending handshake connections: state, idle time, resend count. |
| `show transports` | `show_transports` | Transport instances: type, state, MTU, local address, per-transport stats. |
| `show routing` | `show_routing` | Routing summary: pending lookups, retry state, forwarding/discovery/error/congestion counters. |
| `show identity-cache` | `show_identity_cache` | Cached `(node_addr → npub)` entries with last-seen timestamps. |

### `acl <what>`

| Subcommand | Control-socket command | Returns |
| ---------- | ---------------------- | ------- |
| `acl show` | `show_acl` | Loaded peer-ACL state: allow/deny files, effective mode, default decision, entry counts. |

### `stats <what>`

Time-series metrics from the in-process history rings.

| Subcommand | Control-socket command | Description |
| ---------- | ---------------------- | ----------- |
| `stats list` | `show_stats_list` | Enumerate available metrics, their units, and the per-ring retention windows. |
| `stats metrics` | `show_metrics` | Dump current counter values for every protocol metric family (`forwarding`, `discovery`, `tree`, `bloom`, `congestion`, `errors`). |
| `stats peers` | `show_stats_peers` | List peers tracked in stats history (active or recently active). |
| `stats history <metric> [options]` | `show_stats_history` | Fetch a time-series window for one metric. |

`stats history` options:

| Flag | Argument | Default | Description |
| ---- | -------- | ------- | ----------- |
| `--peer` | `npub` or hostname | *(none)* | Required for per-peer metrics; resolves through `/etc/fips/hosts` if not an npub. |
| `--window` | `<N>s` / `<N>m` / `<N>h` | `10m` | Window duration. |
| `--granularity` | `1s` or `1m` | `1s` | Ring resolution. `1s` uses the fast ring; `1m` uses the slow ring. |
| `--plot` | — | off | Render a Unicode-block sparkline to stdout instead of JSON. |

### `keygen [options]`

Generate a new FIPS identity keypair locally. Does not contact the
daemon.

| Flag | Argument | Default | Description |
| ---- | -------- | ------- | ----------- |
| `-d`, `--dir` | `DIR` | `/usr/local/etc/fips` (macOS), `/etc/fips` (other Unix), `%APPDATA%\fips` (Windows) | Output directory for `fips.key` and `fips.pub`. Matches the directory the platform's packaging installs config into, which is where the daemon derives the key paths from. |
| `-f`, `--force` | — | off | Overwrite an existing `fips.key`. |
| `-s`, `--stdout` | — | off | Print `nsec` then `npub` to stdout instead of writing files. |

`fips.key` is written with mode `0600` and `fips.pub` with mode `0644`
on Unix. After running `keygen`, set `node.identity.persistent: true`
in `fips.yaml` or the daemon will overwrite the keys on next start.

### `connect <peer> <address> <transport>`

Tell the daemon to dial a peer over a specific transport.

| Argument | Description |
| -------- | ----------- |
| `peer` | npub (bech32) or hostname from `/etc/fips/hosts`. |
| `address` | Transport endpoint, e.g. `192.168.1.10:2121`, `[2001:db8::1]:2121`, or a Tor onion. FIPS-mesh ULAs (`fd00::/8`) are rejected for the IP-based transports (udp, tcp, ethernet). |
| `transport` | One of `udp`, `tcp`, `tor`, `nym`, `ethernet`. The named transport must be configured and running. |

### `disconnect <peer>`

Tell the daemon to drop a peer link.

| Argument | Description |
| -------- | ----------- |
| `peer` | npub (bech32) or hostname from `/etc/fips/hosts`. |

### `profile tick <on|off|status>`

> **Reading the output.** Step durations are wall clock measured across `await`
> points, not CPU time: a step that waits on I/O accrues that wait, and other
> tasks may run inside the span. That is the intended measure for head-of-line
> delay, and it means a large step is not necessarily an expensive one.
> `arm_starvation` is measured directly as the entry time minus the deadline
> the interval scheduled that tick for. It is not derived from
> `tick_entry_gap`, which carries no starvation signal on its own: under a
> steady delay every gap is exactly one tick period.

Start, stop and inspect a capture of the rx-loop tick body. **Present
only when both `fipsctl` and the daemon are built with
`--features profiling`**; the feature is off by default, so a stock
package does not carry this subcommand and a stock daemon reports
`profile_tick_*` as an unknown command.

| Subcommand | Control-socket command | Description |
| ---------- | ---------------------- | ----------- |
| `profile tick on` | `profile_tick_on` | Create the capture file and start recording. Fails if a capture is already running (naming the active file) or if the directory cannot be written. |
| `profile tick off` | `profile_tick_off` | Stop the capture. The writer is woken immediately, drains once more and is joined, so the command returns promptly. Succeeds, reporting nothing active, when no capture is running. |
| `profile tick status` | `profile_tick_status` | Report `idle`, `running`, `stopped_by_cap` or `stopped_by_error`, plus the active path, bytes written, flush interval and byte cap. |

`profile tick on` options:

| Flag | Argument | Default | Description |
| ---- | -------- | ------- | ----------- |
| `--dir` | directory path | `/var/log/fips` | Where to write the capture. Created if absent. Use it to profile a non-root `cargo run`, or on a platform whose log root differs. |

One file is written per capture, named `profile-<UTC timestamp>.tsv`.
It opens with a `#`-prefixed header block (node npub, build version,
platform, configured tick period, flush interval, byte cap, start
time), then a tab-separated column header, then one row per measured
step per flush interval:

```text
ts_unix  kind  domain  name  count  max  total  unit
```

`kind` is `step` for a timed span and `gauge` for a sampled scalar, so
a gauge value never lands under a duration column; `unit` names the
unit of `max` and `total` for that row. Every step present in the build
gets a row every interval, including zero-count rows. Gauges cover
ticks per interval, peer count, the wall gap between successive
tick-arm entries, and the arm-starvation delay, which is measured
against the deadline the tick was scheduled for rather than derived
from the gap.

A capture stops itself on reaching 32 MB, appending a `#` line saying
so; `profile tick status` then reports `stopped_by_cap` until the next
`on` or `off` clears it.

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | Daemon returned `{"status":"ok",...}`. |
| `1` | Argument parse failure, control-socket connection failure, daemon returned `{"status":"error",...}`, or local I/O failure (keygen). The error message is printed to stderr. |

## Environment

| Variable | Description |
| -------- | ----------- |
| `XDG_RUNTIME_DIR` | Used to derive the default control-socket path when `/run/fips` is absent. |

`fipsctl` does not consume `RUST_LOG`; logging is for the daemon.

## Files

| Path | Purpose |
| ---- | ------- |
| `/etc/fips/hosts` | Maps hostnames to npubs for the `connect`, `disconnect`, and `--peer` arguments. See [configuration.md](configuration.md). |
| Control socket (default) | Same resolution as the daemon: `/run/fips/control.sock` if present; then `/var/run/fips/control.sock` on macOS/FreeBSD if present; then `$XDG_RUNTIME_DIR/fips/control.sock`; finally `/tmp/fips-control.sock` (Unix). A privileged macOS daemon bootstraps the private `/var/run/fips` directory. Windows uses TCP `localhost:21210`. |

If you get `Permission denied` connecting to the socket on Linux,
add your user to the `fips` group (`sudo usermod -aG fips $USER`)
and log out and back in.

## See also

- [`fips`](cli-fips.md) — the daemon.
- [`fipstop`](cli-fipstop.md) — live-status TUI.
- [control-socket.md](control-socket.md) — wire protocol.
- [configuration.md](configuration.md) — YAML reference.
