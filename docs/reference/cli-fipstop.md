# `fipstop`

Live-status terminal UI for a running FIPS daemon.

## Synopsis

```text
fipstop [-s SOCKET] [--gateway-socket PATH] [-r SECONDS]
```

## Description

`fipstop` is a `ratatui`-based dashboard. It opens the daemon control
socket, polls a small set of `show_*` queries on a timer, and renders
the state in a tabbed full-screen UI. A separate poll runs against the
gateway control socket when the Gateway tab is active.

`fipstop` is read-only — it cannot mutate daemon state. Use
[`fipsctl`](cli-fipsctl.md) for `connect` / `disconnect` and friends.

## Options

| Flag | Argument | Default | Description |
| ---- | -------- | ------- | ----------- |
| `-s`, `--socket` | `PATH` | (auto) | Daemon control-socket path / port. Same default as `fipsctl`. |
| `--gateway-socket` | `PATH` | (auto) | `fips-gateway` control-socket path / port. Default: `/run/fips/gateway.sock` (Unix), TCP port `21211` (Windows). |
| `-r`, `--refresh` | `SECONDS` | `2` | Poll interval. |
| `-V`, `--version` | — | — | Print short version. |
| `--version` | — | — | Print long version. |
| `-h`, `--help` | — | — | Print usage and exit. |

## Tabs

Tabs cycle in this order. Each tab issues the listed control-socket
query on its first activation and on every refresh tick while active.

| Tab | Query | Shows |
| --- | ----- | ----- |
| **Node** | `show_status` | Identity, version, uptime, peer/link/session counts, sparklines for mesh size, tree depth, peer count, bytes, loss. |
| **Peers** | `show_peers` (+ `show_links`, `show_transports` cross-refs) | Authenticated peers in a table. Selecting a row and pressing Enter opens a detail view. |
| **Transports** | `show_transports` (+ `show_links`, `show_peers` cross-refs) | Tree of transport instances with per-link children when expanded. |
| **Sessions** | `show_sessions` | End-to-end FSP sessions. |
| **Tree** | `show_tree` | Spanning-tree state and per-peer coordinates. |
| **Filters** | `show_bloom` | Per-peer Bloom-filter state. |
| **Performance** | `show_mmp` | Link-layer and session-layer MMP metrics. |
| **Routing** | `show_routing` (+ `show_cache` cross-ref) | Forwarding/discovery counters, pending lookups, retry state. |
| **Graphs** | `show_stats_history` family + `show_stats_peers` | Stacked time-series plots. Three modes: node-level metrics, one metric across peers, all metrics for one peer. |
| **Gateway** | `show_gateway` and `show_mappings` against the gateway socket | Pool utilisation and per-mapping state when `fips-gateway` is running. Empty when the gateway socket is unreachable. |

The cycle order in the UI is: Node → Peers → Transports → Sessions →
Tree → Filters → Performance → Routing → Graphs → Gateway. The Links
and Cache tabs are not in the cycle but are fetched as cross-references
to populate Peers, Transports, and Routing detail views.

## Keybindings

### Global

| Key | Action |
| --- | ------ |
| `q`, `Ctrl-C` | Quit. |
| `Tab` | Next tab. |
| `Shift-Tab` | Previous tab. |
| `g` | Jump to the Graphs tab. |
| `Esc` | Close detail view (if open). |

### Table tabs (Peers, Sessions, Transports, Gateway)

| Key | Action |
| --- | ------ |
| `Up`, `Down` | Move row selection. |
| `Enter` | Open detail view for the selected row. |

### Transports tab (extra)

| Key | Action |
| --- | ------ |
| `Right`, `Space` | Expand the selected transport row to show its links. |
| `Left` | Collapse the selected transport row. |
| `e` | Expand all transports. |
| `c` | Collapse all transports. |

### Graphs tab (extra)

| Key | Action |
| --- | ------ |
| `Up`, `Down` | Scroll within the stacked plots. |
| `Right`, `Space` | Next time window. Cycles `1m / 1s` → `10m / 1s` → `1h / 1s` → `24h / 1m`. |
| `Left` | Previous time window. |
| `m` | Cycle view mode: `Node` (stacked node metrics) → `MetricByPeer` (one per-peer metric across all peers) → `PeerByMetric` (all per-peer metrics for one peer). |
| `n` | Next selector (next per-peer metric in MetricByPeer; next peer in PeerByMetric). |
| `Shift-N` | Previous selector. |

## Exit Codes

| Code | Meaning |
| ---- | ------- |
| `0` | Normal quit. |
| `1` | Failed to initialise the terminal. The reason is printed to stderr. |

A failure to reach the daemon socket is **not** fatal: the dashboard
displays "Disconnected" in the status bar and retries on every refresh
tick.

## Environment

| Variable | Description |
| -------- | ----------- |
| `XDG_RUNTIME_DIR` | Used to derive the default control-socket and gateway-socket paths when `/run/fips` is absent. |

## Files

Same control-socket resolution rules as
[`fipsctl`](cli-fipsctl.md#files). The gateway socket follows the same
pattern with `gateway.sock` in place of `control.sock`, falling back
to `/tmp/fips-gateway.sock` if neither system path nor
`XDG_RUNTIME_DIR` is available.

## See also

- [`fipsctl`](cli-fipsctl.md) — issue mutating commands.
- [`fips`](cli-fips.md) — the daemon.
- [control-socket.md](control-socket.md) — wire protocol fipstop polls.
