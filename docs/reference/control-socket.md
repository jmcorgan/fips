# Control Socket Protocol

The FIPS daemon and `fips-gateway` each expose a local control socket
that accepts line-delimited JSON requests and returns line-delimited
JSON responses. `fipsctl` and `fipstop` are clients of this protocol;
operators can also drive it directly with any tool that can speak
length-bounded JSON over a stream socket.

## Connection

### Linux / macOS

A Unix domain socket. The default path is resolved in this order:

1. `/run/fips/control.sock` (or `/run/fips/gateway.sock` for the
   gateway), if `/run/fips` exists. This is what the `fips.service`
   systemd unit creates.
2. `$XDG_RUNTIME_DIR/fips/control.sock` otherwise.
3. `/tmp/fips-control.sock` if neither of the above is available.

The daemon `chown`s the socket file and its parent directory to the
`fips` group at bind time and sets mode `0770`. Members of the `fips`
group can therefore connect without root. Add a user with
`sudo usermod -aG fips $USER` (re-login required).

The path can be overridden at the daemon side via
`node.control.socket_path` in the YAML config, and at the client side
via `fipsctl -s PATH` or `fipstop -s PATH`.

### Windows

A TCP listener bound to `127.0.0.1`. The daemon's port is `21210` by
default; the gateway's is `21211`. Only loopback connections are
accepted. Override via `node.control.socket_path` (which takes a port
number string on Windows).

Windows TCP does not provide filesystem-level ACLs — any local user
can connect. See the security note in
[configuration.md](configuration.md#control-socket-nodecontrol).

## Request Format

One JSON object per line, terminated by `\n`. Maximum request size is
4096 bytes; longer requests are dropped with `request too large`.

```json
{"command": "<name>", "params": {<object>}}
```

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `command` | string | yes | Command name. See [Daemon command catalog](#daemon-command-catalog) and [Gateway command catalog](#gateway-command-catalog). |
| `params` | object | only for commands that take parameters | Parameter object. Unknown fields are ignored; missing required fields produce an error response. |

Unknown top-level fields in the request are silently ignored.

## Response Format

One JSON object per line.

```json
{"status": "ok", "data": {<object>}}
{"status": "error", "message": "<reason>"}
```

| Field | Type | When present |
| ----- | ---- | ------------ |
| `status` | string | always; one of `"ok"` or `"error"`. |
| `data` | object | on `ok` responses. |
| `message` | string | on `error` responses. |

### I/O timeouts

The daemon enforces a 5-second timeout for both the request read and
the response write. If the connection idles longer than that, the
daemon closes it with no response.

### Common error messages

| Message | Cause |
| ------- | ----- |
| `empty request` | Connection closed before a newline was received. |
| `invalid request: <serde error>` | Malformed JSON or missing `command`. |
| `request too large` | Request exceeded 4096 bytes. |
| `read timeout` / `read error: ...` | Slow client or transport failure. |
| `unknown command: <name>` | Command not registered with this daemon. |
| `missing params for <name>` | Command requires `params` but none were provided. |
| `missing '<field>' parameter` | Required parameter missing. |
| `query timeout` | Internal handler did not respond within 5 seconds. |
| `node shutting down` | Daemon is exiting. |
| `gateway not yet initialized` | (Gateway socket only) snapshot has not been published yet. |

## Daemon Command Catalog

Read-only queries are dispatched in `src/control/queries.rs`;
mutating commands are dispatched in `src/control/commands.rs`. The
table below lists every command currently registered.

### Read-only queries

| Command | Params | `data` shape (top-level keys) |
| ------- | ------ | ----------------------------- |
| `show_status` | — | `version`, `npub`, `node_addr`, `ipv6_addr`, `state`, `is_leaf_only`, `peer_count`, `session_count`, `link_count`, `transport_count`, `connection_count`, `tun_state`, `tun_name`, `effective_ipv6_mtu`, `control_socket`, `pid`, `exe_path`, `uptime_secs`, `estimated_mesh_size`, `forwarding`, `sparklines`. |
| `show_acl` | — | `allow_file`, `deny_file`, `enforcement_active`, `effective_mode`, `default_decision`, `allow_all`, `deny_all`, `allow_file_entries`, `deny_file_entries`, `allow_entries`, `deny_entries`. |
| `show_peers` | — | `peers[]` — per-peer object: `node_addr`, `npub`, `display_name`, `ipv6_addr`, `connectivity`, `link_id`, `direction`, `transport_addr`, `transport_type`, `is_parent`, `is_child`, `tree_depth`, `stats`, `noise`, `current_k_bit`, `mmp`, plus optional `nostr_traversal`, `rekey_in_progress`, `rekey_draining`. |
| `show_links` | — | `links[]` — `link_id`, `transport_id`, `remote_addr`, `direction`, `state`, `created_at_ms`, `stats`. |
| `show_tree` | — | `my_node_addr`, `root`, `is_root`, `depth`, `my_coords[]`, `parent`, `parent_display_name`, `declaration_sequence`, `declaration_signed`, `peer_tree_count`, `peers[]`, `stats`. |
| `show_sessions` | — | `sessions[]` — `remote_addr`, `npub`, `display_name`, `state` (`established`, `initiating`, `awaiting_msg3`, `unknown`), `is_initiator`, `last_activity_ms`, `stats`, optional `mmp`, `current_k_bit`, `is_draining`. |
| `show_bloom` | — | `own_node_addr`, `is_leaf_only`, `sequence`, `leaf_dependent_count`, `leaf_dependents[]`, `peer_filters[]`, `stats`. |
| `show_mmp` | — | `peers[]` (link-layer per peer), `sessions[]` (session-layer per session). Each entry includes loss/RTT/ETX/goodput, smoothed values, trends. |
| `show_cache` | — | `count`, `max_entries`, `fill_ratio`, `default_ttl_ms`, `expired`, `avg_age_ms`, `entries[]` — per-destination coords, depth, age, last-used, optional `path_mtu`. |
| `show_connections` | — | `connections[]` — pending handshakes: `link_id`, `direction`, `handshake_state`, `started_at_ms`, `idle_ms`, `resend_count`, optional `expected_peer`. |
| `show_transports` | — | `transports[]` — `transport_id`, `type`, `state`, `mtu`, `name`, `local_addr`, optional `tor_mode`, `onion_address`, `tor_monitoring`, `stats`. |
| `show_routing` | — | `coord_cache_entries`, `identity_cache_entries`, `pending_lookups[]`, `pending_tun_destinations`, `pending_tun_packets`, `recent_requests`, `retries[]`, `forwarding`, `discovery`, `error_signals`, `congestion`. |
| `show_identity_cache` | — | `entries[]`, `count`, `max_entries`. Each entry: `node_addr`, `npub`, `display_name`, `ipv6_addr`, `last_seen_ms`, `age_ms`. |
| `show_stats_list` | — | `metrics[]` (each with `name`, `unit`, `scope`), `fast_ring_seconds`, `slow_ring_minutes`, `peer_retention_seconds`. |
| `show_stats_history` | `metric` (req), `peer` (req for per-peer metrics), `window` (`<N>s` / `<N>m` / `<N>h`, default `10m`), `granularity` (`1s` / `1m`, default `1s`) | A single `Series`: `metric`, `unit`, `granularity_seconds`, `values[]`. |
| `show_stats_all_history` | `peer` (optional npub), `window`, `granularity` | `granularity_seconds`, `window_seconds`, `peer`, `series[]` (one per metric). |
| `show_stats_peers` | — | `peers[]`, `count`. Each entry: `npub`, `node_addr`, `display_name`, `is_active`, `first_seen_secs_ago`, `last_contact_secs_ago`. |
| `show_stats_history_all_peers` | `metric` (req per-peer name), `window`, `granularity` | `metric`, `unit`, `granularity_seconds`, `window_seconds`, `peers[]` (each with `node_addr`, `display_name`, `is_active`, `values[]`). |

The schema of each query response is pinned by snapshot tests in
`src/control/snapshots/`; intentional schema changes regenerate those
fixtures.

### Mutating commands

| Command | Required params | Behaviour |
| ------- | --------------- | --------- |
| `connect` | `npub` (bech32), `address` (transport endpoint), `transport` (`udp`, `tcp`, `tor`, `ethernet`) | Asks the node to dial the peer over the named transport. Returns the API result on success or an error string on failure. |
| `disconnect` | `npub` (bech32) | Asks the node to drop the link to the named peer. |

Both commands run on the daemon's main task and may block briefly
while the node mutates its state.

## Gateway Command Catalog

`fips-gateway` exposes a separate control socket with its own command
set. Dispatch lives in `src/gateway/control.rs`.

| Command | Params | `data` shape |
| ------- | ------ | ------------ |
| `show_gateway` | — | `pool_total`, `pool_allocated`, `pool_active`, `pool_draining`, `pool_free`, `nat_mappings`, `dns_listen`, `uptime_secs`, `pool_cidr`, `lan_interface`, `dns_upstream`, `dns_ttl`, `pool_grace_period`. |
| `show_mappings` | — | `mappings[]` — `virtual_ip`, `mesh_addr`, `node_addr`, `dns_name`, `state` (`Allocated`, `Active`, `Draining`), `sessions`, `age_secs`, `last_ref_secs`. |

Until the first snapshot has been published (very early in startup),
both commands return `gateway not yet initialized`.

## Driving the Socket Directly

```sh
# Linux / macOS
echo '{"command":"show_status"}' | sudo nc -U /run/fips/control.sock

# Windows (PowerShell with a TCP-capable tool of your choice)
```

The newline at the end of the request is required: the daemon reads
one line per connection. The connection is closed after the single
response is written.

## See also

- [`fipsctl`](cli-fipsctl.md) — full-featured client.
- [`fipstop`](cli-fipstop.md) — read-only TUI.
- [configuration.md](configuration.md) — `node.control.*` keys.
