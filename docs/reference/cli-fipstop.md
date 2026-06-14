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

`fipstop` is almost entirely read-only: the only state-mutating action
it offers is disconnecting a peer (`Del` on a selected Peers row, with
a confirmation prompt — see [Keybindings](#keybindings)). For
`connect` and other mutating commands, use
[`fipsctl`](cli-fipsctl.md).

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
| **Node** | `show_status` (+ `show_listening_sockets`) | Identity, version, uptime, peer/link/session counts, sparklines for mesh size, tree depth, peer count, bytes, loss. The Traffic block on this tab is split: TUN counters on the left, the **Listening on fips0** panel on the right (see below). |
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

## Listening on fips0 panel (Node tab)

The right half of the Node tab's Traffic block lists local IPv6
listening sockets reachable from `fips0`, paired with the current
`inet fips` baseline filter classification for each (proto, port).
The panel exists to remind the operator which local services are
exposed to the mesh and which of those are admitted by the
default-deny firewall.

| Column | Meaning |
| ------ | ------- |
| **Proto** | `tcp` or `udp`. IPv4 listeners are not enumerated; `fips0` is IPv6-only. |
| **Port** | Listening port number. |
| **Process** | `comm(pid)` resolved by walking `/proc/<pid>/fd/`. A trailing `*` marks wildcard binds (`local_addr == ::`) — the bind is not fips0-specific, so the operator sees that the service is exposed across every interface, not just the mesh. |
| **State** | `OPEN` (default White) — the baseline filter has a canonical accept rule for this (proto, port). `filt` (DarkGray) — chain falls through to `counter drop`. `filt?` (DarkGray) — a rule references the port but uses matchers (saddr filter, jump, daddr) the panel cannot fully decompose; operator should `nft list table inet fips` to confirm. |

When `fips-firewall.service` is **not** active, the `inet fips`
table is absent. The panel renders every row in default White and
replaces the title with a yellow banner reading
"`Listening on fips0  fips-firewall.service inactive — all listeners exposed`".

The panel is read-only and unselectable. It refreshes on the same
poll tick as the rest of the Node tab. Sockets owned by other users
that the daemon could not resolve to a PID render as `?` in the
Process column; this only happens if the daemon itself is running
without root privileges (an unusual dev setup), since walking
`/proc/<pid>/fd/` for processes the daemon does not own requires
elevated capabilities.

The panel is Linux-only; on non-Linux daemons the query returns an
empty list and the panel hides.

## Keybindings

Press `?` at any time for an in-app help overlay. The overlay and the
status-bar hint footer both read from a single keybinding registry
keyed by `(tab, mode)`, so the always-visible hints describe exactly
the keys the current context accepts.

### Global

| Key | Action |
| --- | ------ |
| `q`, `Ctrl-C` | Quit. |
| `Tab` | Next tab. |
| `Shift-Tab` | Previous tab. |
| `g` | Jump to the Graphs tab. |
| `?` | Toggle the help overlay. |
| `Esc` | Close an open detail view; otherwise deselect the active table row. |

### Table tabs (Peers, Sessions, Transports, Gateway)

| Key | Action |
| --- | ------ |
| `Up`, `Down` | Move row selection. |
| `Enter` | Open detail view for the selected row. |
| `Esc` | Deselect the row (return to the tab's overview state). |

### Peers tab (extra)

| Key | Action |
| --- | ------ |
| `Del` | Disconnect the selected peer. Opens a `Y`/`N` confirmation modal first; this is the only state-mutating action in `fipstop`. |

### Transports tab (extra)

| Key | Action |
| --- | ------ |
| `Right`, `Space` | Expand the selected transport row to show its links. |
| `Left` | Collapse the selected transport row. |
| `e` | Expand all transports. |
| `c` | Collapse all transports. |

### Multi-pane scrolling tabs (Tree, Filters, Routing)

Each lays out stacked panes that scroll independently.

| Key | Action |
| --- | ------ |
| `f` | Move focus to the next pane. |
| `Up`, `Down` | Scroll the focused pane by one row. |
| `PageUp`, `PageDown` | Scroll the focused pane by ten rows. |
| `Home`, `End` | Jump to the top / bottom of the focused pane. |

### Performance tab (extra)

The Performance tab lays out two panes (Link MMP, Session MMP).

| Key | Action |
| --- | ------ |
| `f` | Move focus between the Link and Session MMP panes. |
| `Up`, `Down` | Scroll the focused pane. |
| `PageUp`, `PageDown` | Scroll the focused pane by ten rows. |
| `Home`, `End` | Jump to the top / bottom of the focused pane. |
| `s` | Cycle the sort column of the focused pane. |
| `Shift-S` | Toggle the sort direction of the focused pane. |

### Graphs tab (extra)

| Key | Action |
| --- | ------ |
| `Up`, `Down` | Scroll the stacked plots; in `MetricByPeer` mode, move the by-peer selection (and follow it when the by-peer detail is open). |
| `Right`, `Space` | Next time window. Cycles `1m / 1s` → `10m / 1s` → `1h / 1s` → `24h / 1m`. |
| `Left` | Previous time window. |
| `Enter` | In `MetricByPeer` mode, expand the selected peer summary into a full-pane plot. |
| `m` | Cycle view mode: `Node` (stacked node metrics) → `MetricByPeer` (one per-peer metric across all peers) → `PeerByMetric` (all per-peer metrics for one peer). |
| `n` | Next selector (next per-peer metric in MetricByPeer; next peer in PeerByMetric). |
| `Shift-N` | Previous selector. |
| `s` | Cycle the sort column of the by-peer summary list. |
| `Shift-S` | Toggle the sort direction of the by-peer summary list. |

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
