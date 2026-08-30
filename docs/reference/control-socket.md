# Control Socket Protocol

The FIPS daemon and `fips-gateway` each expose a local control socket
that accepts line-delimited JSON requests and returns line-delimited
JSON responses. `fipsctl` and `fipstop` are clients of this protocol;
operators can also drive it directly with any tool that can speak
length-bounded JSON over a stream socket.

## Connection

### Unix

A Unix domain socket. The default path is resolved in this order:

1. `/run/fips/control.sock` (or `/run/fips/gateway.sock` for the
   gateway), if `/run/fips` exists. This is what the `fips.service`
   systemd unit creates.
2. On macOS and FreeBSD, `/var/run/fips/control.sock` if its private
   directory exists. A privileged macOS daemon selects this path before the
   directory exists and creates it at bind time, so the packaged LaunchDaemon
   recreates its runtime state after every boot. The FreeBSD rc.d service
   creates the directory before starting FIPS.
3. `$XDG_RUNTIME_DIR/fips/control.sock` otherwise.
4. `/tmp/fips-control.sock` if none of the above is available.

The daemon sets the socket to group `fips`, mode `0770`. It sets a private
parent directory to group `fips`, mode `0750`, both when it creates that
directory and when a service manager pre-creates a canonical runtime directory
(`/run/fips`, `/var/run/fips`, or `$XDG_RUNTIME_DIR/fips`). Existing shared or
custom parents remain unchanged, so fallback locations such as `/tmp` retain
their system ownership and mode. Members of the `fips` group can connect
without root.

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
the response write. A request that does not arrive within the read
timeout is answered with a `read timeout` error response and the
connection is then closed; a response that cannot be written within the
write timeout is dropped and the connection closed with no response.

### Common error messages

| Message | Cause |
| ------- | ----- |
| `empty request` | Connection closed before a newline was received. |
| `invalid request: <serde error>` | Malformed JSON or missing `command`. |
| `read error: request too large` | Request exceeded 4096 bytes. |
| `read timeout` / `read error: ...` | Slow client or transport failure. |
| `unknown command: <name>` | Command not registered with this daemon. |
| `missing params for <name>` | Command requires `params` but none were provided. |
| `missing '<field>' parameter` | Required parameter missing. |
| `invalid peer npub: <e>` | `probe_start` could not decode the bech32 npub. |
| `cannot probe this node` | `probe_start` was given this daemon's own npub. |
| `unknown probe id: <n>` | `probe_poll` / `probe_cancel` named a job that does not exist, or one already collected by a previous poll. |
| `too many probes in flight` | The probe registry is at its concurrency cap. |
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
| `show_status` | — | `version`, `npub`, `node_addr`, `ipv6_addr`, `state`, `is_leaf_only`, `is_root` (bool — this node is the spanning-tree root), `root` (hex node-addr of the current tree root), `persistent` (bool — identity is persisted, i.e. `persistent` set or an `nsec` configured), `peer_count`, `session_count`, `link_count`, `transport_count`, `connection_count`, `transport_peer_counts` (object mapping transport-type name to its connected-peer count; configured transports appear with `0`), `tun_state`, `tun_name`, `effective_ipv6_mtu`, `control_socket`, `pid`, `exe_path`, `uptime_secs`, `estimated_mesh_size`, `forwarding`, `sparklines`. |
| `show_acl` | — | `allow_file`, `deny_file`, `enforcement_active`, `effective_mode`, `default_decision`, `allow_all`, `deny_all`, `allow_file_entries`, `deny_file_entries`, `allow_entries`, `deny_entries`. |
| `show_peers` | — | `peers[]` — per-peer object: `node_addr`, `npub`, `display_name`, `ipv6_addr`, `connectivity`, `link_id`, `direction`, `transport_addr`, `transport_type`, `is_parent`, `is_child`, `tree_depth`, `effective_depth` (`tree_depth + link_cost` — the metric `evaluate_parent` ranks on; `null` when the peer has no coords, or is unmeasured while another peer has an SRTT sample, per the cold-start gate), `stats`, `noise`, `current_k_bit`, `mmp`, plus optional `nostr_traversal`, `rekey_in_progress`, `rekey_draining`. |
| `show_links` | — | `links[]` — `link_id`, `transport_id`, `remote_addr`, `direction`, `state`, `created_at_ms`, `stats`. |
| `show_tree` | — | `my_node_addr`, `root`, `root_npub` (bech32 npub of the current tree root), `is_root`, `depth`, `my_coords[]`, `parent`, `parent_display_name`, `declaration_sequence`, `declaration_signed`, `peer_tree_count`, `peers[]`, `stats`. |
| `show_sessions` | — | `sessions[]` — `remote_addr`, `npub`, `display_name`, `state` (`established`, `initiating`, `awaiting_msg3`, `unknown`), `is_initiator`, `last_activity_ms`, `stats`, optional `mmp`, `current_k_bit`, `is_draining`. |
| `show_bloom` | — | `own_node_addr`, `is_leaf_only`, `sequence`, `leaf_dependent_count`, `leaf_dependents[]`, `peer_filters[]`, `uptree_fill_ratio` (fill ratio of the last filter actually sent to the tree parent), `uptree_estimated_count` (cardinality estimate of that uptree filter — this node's whole subtree under split-horizon, not the mesh; both are `null` for a root node or before the first announce), `stats`. |
| `show_mmp` | — | `peers[]` (link-layer per peer), `sessions[]` (session-layer per session). Each entry includes loss/RTT/ETX/goodput, smoothed values, trends. |
| `show_cache` | — | `count`, `max_entries`, `fill_ratio`, `default_ttl_ms`, `expired`, `avg_age_ms`, `entries[]` — per-destination coords, depth, age, last-used, optional `path_mtu`. |
| `show_connections` | — | `connections[]` — pending handshakes: `link_id`, `direction`, `handshake_state`, `started_at_ms`, `idle_ms`, `resend_count`, optional `expected_peer`. |
| `show_transports` | — | `transports[]` — `transport_id`, `type`, `state`, `mtu`, `name`, `local_addr`, optional `tor_mode`, `onion_address`, `tor_monitoring`, `stats`. |
| `show_routing` | — | `coord_cache_entries`, `identity_cache_entries`, `pending_lookups[]`, `pending_tun_destinations`, `pending_tun_packets`, `recent_requests`, `retries[]`, `forwarding`, `discovery` (request/response sub-counters; includes `req_deduplicated` — requests suppressed as recent duplicates — and `req_dedup_cache_full` — requests admitted because the dedup cache was full), `error_signals`, `congestion`. |
| `show_identity_cache` | — | `entries[]`, `count`, `max_entries`. Each entry: `node_addr`, `npub`, `display_name`, `ipv6_addr`, `last_seen_ms`, `age_ms`. |
| `show_native_flows` | — | `flows[]`, `listeners[]`, `stats` (the `native` counter family). Each flow: `flow_id`, `peer` (the peer's npub, which is its address; always present, because the flow carries the key its client named or its session authenticated), `peer_addr` (the 16-byte node address in hex — a truncated hash of the same key, kept because it is what `show_sessions` and `show_routing` key on), `local_port`, `remote_port`, `state` (`established` / `pending_accept`), `queued` (datagrams the node is holding for the flow), `age_ms` (time since the flow reached its current state: opened for a flow this node opened, accepted for one taken off a listener, announced for one still pending — accepting a pending flow restarts the clock). Each listener: `local_port`, `backlog`. |
| `show_listening_sockets` | — | `fips0_addr`, `firewall_active` (bool — `inet fips` table loaded), `sockets[]`. Each entry: `proto` (`tcp` / `udp`), `local_addr` (`::` or the node's fd00::/8 address), `port`, `pid` (nullable), `process` (nullable), `wildcard_bind` (bool — `local_addr == ::`), `filter` (`accept` / `drop` / `unknown` / `no_firewall`). Linux-only; returns an empty `sockets[]` on other platforms. |
| `show_stats_list` | — | `metrics[]` (each with `name`, `unit`, `scope`), `fast_ring_seconds`, `slow_ring_minutes`, `peer_retention_seconds`. |
| `show_metrics` | — | Flat snapshot of every counter family in the metrics registry: `forwarding`, `discovery`, `tree`, `bloom`, `congestion`, `errors`, `native`. Each value is that family's counter snapshot object. Counter-only — gauges/histograms that need the live node are excluded. Served off the main loop. Silent-rejection sites classify their reason as a typed `RejectReason` and increment the matching per-family counter exposed here — see [Rejection reasons](#rejection-reasons). |
| `show_stats_history` | `metric` (req), `peer` (req for per-peer metrics), `window` (`<N>s` / `<N>m` / `<N>h`, default `10m`), `granularity` (`1s` / `1m`, default `1s`) | A single `Series`: `metric`, `unit`, `granularity_seconds`, `values[]`. |
| `show_stats_all_history` | `peer` (optional npub), `window`, `granularity` | `granularity_seconds`, `window_seconds`, `peer`, `series[]` (one per metric). |
| `show_stats_peers` | — | `peers[]`, `count`. Each entry: `npub`, `node_addr`, `display_name`, `is_active`, `first_seen_secs_ago`, `last_contact_secs_ago`. |
| `show_stats_history_all_peers` | `metric` (req per-peer name), `window`, `granularity` | `metric`, `unit`, `granularity_seconds`, `window_seconds`, `peers[]` (each with `node_addr`, `display_name`, `is_active`, `values[]`). |

The schema of each query response is pinned by snapshot tests in
`src/control/snapshots/`; intentional schema changes regenerate those
fixtures.

### Rejection reasons

Silent-rejection paths across the node classify why a message was
dropped via a typed `RejectReason` rather than only logging it, so the
*what* of a rejection is visible in the counter snapshots above. The
top-level reason set has eight families, mirroring the protocol-layer /
subsystem split of the metrics:

- **Tree** — spanning-tree `TreeAnnounce` processing rejections.
- **Bloom** — bloom-filter `FilterAnnounce` processing rejections.
- **Discovery** — discovery request / response processing rejections.
- **Handshake** — Noise handshake state-machine rejections.
- **Session** — FSP session state-machine rejections.
- **Mmp** — MMP link-layer rejections.
- **Forwarding** — forwarding-path rejections (no-route, TTL, MTU).
- **Transport** — transport-layer rejections (admission caps, framing).

Each rejection increments the corresponding counter in its family's
stats, surfaced through `show_metrics` (the `tree`, `bloom`,
`discovery`, and `forwarding` families carry their own counters; the
`errors` family and the remaining subsystem counters carry the rest).
The full per-family variant list lives in `src/node/reject.rs`; it is
not reproduced here to avoid duplicating the source.

### Mutating commands

| Command | Required params | Behaviour |
| ------- | --------------- | --------- |
| `connect` | `npub` (bech32), `address` (transport endpoint), `transport` (`udp`, `tcp`, `tor`, `nym`, `ethernet`) | Asks the node to dial the peer over the named transport. The named transport must be configured and running. Returns the API result on success or an error string on failure. |
| `disconnect` | `npub` (bech32) | Asks the node to drop the link to the named peer. |
| `probe_start` | `npub` (bech32) | Admits a diagnostic probe job and returns immediately. `data`: `probe_id`, `npub`, `node_addr`, `display_name`, `budget_ms`. |
| `probe_poll` | `probe_id` (integer) | Reports a probe's progress. `data`: `state` (`running` / `done`) and `report`. A terminal job is removed on the poll that observes it, so the report is delivered once. |
| `probe_cancel` | `probe_id` (integer) | Runs the probe's terminal actions immediately, without the teardown grace tick. |

`connect` on a peer the node is **already connected to** neither tears the
live link down nor ignores the address: the address is tried as an alternate
path alongside the existing one, and the peer moves to it only if that
handshake authenticates. The response carries `refreshed` — `true` when such a
handshake was started, `false` when the peer is already on this exact path and
that path is fresh (a successful no-op). A `connect` that starts an ordinary
dial to a peer the node does not yet hold also reports `refreshed: false`.

`connect` is ephemeral either way: the peer is not written to the config file
and gets no auto-reconnect, so an attempt that fails leaves no residue.

`connect` and `disconnect` run on the daemon's main task and may block
briefly while the node mutates its state. The probe triplet does not:
each call returns in well under a millisecond, and the stages run on
the daemon's tick. That split exists because a probe needs a mesh
lookup, a Noise XK handshake and at least one remote MMP tick, which no
single control round-trip could survive inside the 5-second I/O
timeout.

A probe that runs and finds a problem is **not** an error response: the
status is `ok` and the failure is in the report's per-stage verdicts.
Error responses are reserved for malformed or inadmissible requests.

The report carries one block per stage — `bloom`, `discovery`, `path`,
`session`, `rtt` — plus `target`, `cleanup` and the overall verdict.
The two lookup stages are separate because they fail for unrelated
reasons: `bloom` says whether any peer's filter claimed the address and
a request therefore went out, and `discovery` says whether anything
answered. `discovery.attempts` is the request in flight, or the last
one tried, and `discovery.attempt_timeouts_secs` is this node's
configured ladder, published so a client can say how long each attempt
was given rather than guessing.

#### Profiler toggle (`--features profiling` builds only)

| Command | Params | Behaviour |
| ------- | ------ | --------- |
| `profile_tick_on` | `dir` (optional directory path; default `/var/log/fips`) | Creates the capture file, publishes its path, and starts the writer thread. `data`: `state`, `path`, `interval_secs`, `byte_cap`. Errors if a capture is already running (naming the active file) or the directory is unwritable. |
| `profile_tick_off` | — | Stops the capture, drains once more, joins the writer. `data`: `state`, `stopped`, `stopped_by_cap`, `stopped_by_error`, `path`, `bytes`. |
| `profile_tick_status` | — | `data`: `state` (`idle` / `running` / `stopped_by_cap` / `stopped_by_error`), `path`, `bytes`, `byte_cap`, `interval_secs`. |

Unlike `connect` and `disconnect`, these three are served in the
control accept task rather than on the daemon's main task. All of their
state is process statics and none of them needs `&mut Node`, so
routing them through the main loop would only make the toggle queue
behind the tick body it exists to measure. They are absent from a
default build, where the daemon answers them as unknown commands.

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
