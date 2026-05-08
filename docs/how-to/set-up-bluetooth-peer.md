# Set Up a Bluetooth (BLE) Peer Link

FIPS supports Bluetooth Low Energy as a transport for short-range
mesh extension — same room, same building, no IP infrastructure
between the two endpoints. The BLE transport runs as L2CAP
Connection-Oriented Channels on a configurable PSM and reports
per-link MTU back to the mesh layer for path-MTU computation.

For the design rationale and per-link MTU model, see
[../design/fips-transport-layer.md](../design/fips-transport-layer.md).
For all `transports.ble.*` configuration keys, see
[../reference/configuration.md](../reference/configuration.md).

> **Experimental.** The BLE transport works but is still maturing.
> Expect rougher edges than UDP or TCP — particularly around link
> stability under interference and MTU negotiation on older
> controllers. Treat it as you would any experimental transport in a
> production deployment.

## When to use

BLE is the right transport when:

- Two nodes are within roughly 10 metres line-of-sight (more with
  external antennas, less through walls).
- You want a self-contained mesh segment with no shared WiFi or
  Ethernet between the participants.
- You can work within practical L2CAP CoC throughput (1-2 Mbps in
  good conditions, often substantially less under interference or
  at range) and the higher latency variance compared to WiFi.

It is **not** the right transport for backbone links between rooms
where WiFi or Ethernet exists, for high-throughput data, or for any
deployment where range matters more than infrastructure-freedom.

## Platform support

The BLE transport is **Linux-only** in the current implementation.
The runtime depends on BlueZ via the `bluer` crate, which in turn
needs `glibc` (musl builds skip BLE; the build script gates the
crate accordingly).

| Platform | BLE transport |
| -------- | -------------- |
| Linux (glibc) | Supported. |
| Linux (musl, OpenWrt) | Disabled at build time. |
| macOS | Not supported. |
| Windows | Not supported. |

The Debian package `Recommends: bluez`; install it explicitly if you
opted out:

```sh
sudo apt install bluez
```

## Prerequisites

Both endpoints need:

1. A BLE-capable HCI adapter visible to BlueZ. Confirm with:

   ```sh
   sudo bluetoothctl show
   ```

   Note the controller name (typically `hci0`).

2. The `bluetoothd` service running and the adapter powered on:

   ```sh
   sudo systemctl enable --now bluetooth
   sudo bluetoothctl power on
   ```

3. Sufficient privileges for the FIPS daemon. There are two
   independent privilege concerns; the BLE-only deployment case
   (mesh router with `tun.enabled: false`) needs only the second.

   - **TUN adapter (always required when `tun.enabled: true`).**
     The daemon needs `CAP_NET_ADMIN` to create and configure the
     TUN device. The shipped systemd unit handles this by running
     as root; if you prefer to drop privileges, see
     [run-as-unprivileged-user.md](run-as-unprivileged-user.md).

   - **BLE access (required for this how-to).** BlueZ exposes
     L2CAP and D-Bus paths under either group membership or
     `CAP_NET_RAW`. Pick one:

     - Run the daemon as root. The shipped systemd unit takes
       this route.
     - Run as an unprivileged user that is a member of the
       `bluetooth` group. No additional capability is needed for
       the BLE side.
     - Run as an unprivileged user with no group membership, and
       grant the binary `CAP_NET_RAW`:

       ```sh
       sudo setcap cap_net_raw+ep $(which fips)
       ```

       This bypasses BlueZ's polkit/group check by holding
       `CAP_NET_RAW` directly. If you also need `CAP_NET_ADMIN`
       for TUN, combine them:

       ```sh
       sudo setcap cap_net_admin,cap_net_raw+ep $(which fips)
       ```

4. The same L2CAP PSM on both endpoints. The default is `0x0085`
   (133); override only if you need to coexist with another L2CAP
   service on that PSM.

## Configuration

Add a `ble` block under `transports` in `fips.yaml`. A minimum BLE-
active node looks like this:

```yaml
transports:
  ble:
    adapter: "hci0"
    advertise: true
    scan: true
    auto_connect: true
    accept_connections: true
```

Note: `auto_connect: true` is intentionally non-default (the default
is `false`). For a symmetric ground-up discovery flow where either
side may dial, both ends must opt in explicitly.

| Key | Purpose |
| --- | ------- |
| `adapter` | HCI controller name. Default: `hci0`. |
| `psm` | L2CAP PSM. Default: `0x0085` (must match on both ends). |
| `mtu` | Default L2CAP CoC MTU. Default: `2048`. The kernel may negotiate lower per link. |
| `max_connections` | Concurrent BLE connections. Default: `7` (Bluetooth controllers typically support up to ~7 simultaneous L2CAP CoCs). |
| `advertise` | Broadcast our BLE adverts so other FIPS nodes discover us. Default: `true`. |
| `scan` | Listen for other FIPS nodes' BLE adverts. Default: `true`. |
| `auto_connect` | Initiate a BLE connection to discovered FIPS adverts. Default: `false`. |
| `accept_connections` | Accept inbound L2CAP connections. Default: `true`. |
| `connect_timeout_ms` | Outbound L2CAP connect timeout. Default: `10000`. |
| `probe_cooldown_secs` | After probing a BD_ADDR (success or failure), wait this long before probing it again. Default: `30`. |

Two pairing patterns are common:

**Symmetric auto-discovery.** Both nodes advertise, scan, and
auto-connect. Whichever side completes the L2CAP connection first
wins; the other side aborts its in-flight attempt. This is the
"toss two devices in the same room" setup.

```yaml
# Both nodes
transports:
  ble:
    adapter: "hci0"
    advertise: true
    scan: true
    auto_connect: true
    accept_connections: true
```

**Asymmetric peripheral / central.** One node only listens
(peripheral), the other actively dials (central). Useful when one
endpoint is a dedicated bootstrap and the other is mobile.

```yaml
# Listener
transports:
  ble:
    adapter: "hci0"
    advertise: true
    scan: false
    auto_connect: false
    accept_connections: true
```

```yaml
# Dialer
transports:
  ble:
    adapter: "hci0"
    advertise: false
    scan: true
    auto_connect: true
    accept_connections: false
```

After editing, restart the daemon on each side:

```sh
sudo systemctl restart fips
```

## Verify

On each endpoint, confirm the transport came up:

```sh
fipsctl show transports
```

Look for an entry of type `ble` in the `state: Running` (or
equivalent) state. The `mtu` field reports the configured default;
per-link MTU is reported separately.

Confirm the link is established:

```sh
fipsctl show peers
```

The peer entry for the BLE-attached neighbour should report
`transport_type: "ble"` and a non-zero `last_seen_ms`.

BLE peering is auto-discovery only: there is no `fipsctl connect`
path for BLE (the command accepts `udp`, `tcp`, `tor`, and
`ethernet` only). Links come up via advert/scan; if you don't see
the peer here, the configuration above is the only knob.

To watch the link in real time, use `fipstop`'s **Peers** and
**Transports** tabs:

```sh
fipstop
```

The Performance tab reports the per-link MMP metrics — SRTT, loss
rate, ETX — which on BLE typically run an order of magnitude worse
than over UDP, with much higher jitter.

## Troubleshooting

### Transport never comes up

Check the BlueZ side first:

```sh
systemctl status bluetooth
sudo bluetoothctl show
```

If `bluetoothctl show` reports `Powered: no`, fix that before
debugging FIPS. The FIPS daemon will log a warning if it cannot
acquire the adapter.

If the FIPS log contains `bluer` D-Bus errors, the daemon usually
lacks permission. Run as root or grant `CAP_NET_ADMIN` and add the
fips user to the `bluetooth` group.

### Peers see each other but never connect

Verify `accept_connections` is true on at least one side and
`auto_connect` is true on at least one side. Two listen-only nodes
will discover each other but never establish an L2CAP connection.

Check `psm` matches on both ends. A mismatch presents as adverts
visible (in `fipstop` discovery counters) but every connect attempt
fails.

### Link comes up but throughput is poor

Practical L2CAP CoC throughput in good conditions reaches
1-2 Mbps, but interference, range, and controller capability all
push it lower. If throughput is well below that range, check the
negotiated ATT_MTU — a small ATT_MTU (default 23 bytes when
extended ATT MTU is not negotiated) caps per-PDU payload
regardless of radio conditions. The per-link MTU reported in
`fipsctl show transports` reveals what was negotiated.

If MTU is unexpectedly low, both endpoints must support and have
negotiated the BlueZ L2CAP `cocmode=2` extension. Older Bluetooth
controllers cap MTU regardless.

### Unstable links / repeated reconnects

Bluetooth in busy 2.4 GHz environments suffers from WiFi
interference. Switch the adapter to a less crowded channel (kernel
side, not configurable from FIPS) or add an external antenna. The
`probe_cooldown_secs` tunable backs off retry attempts; raise it if
the daemon log shows many short-lived probes.

### Permission errors on socket open

Most modern systemd installs do not allow non-root processes to
open raw L2CAP sockets without an explicit policy. Run the daemon
as root (the shipped systemd unit does this) or add a `polkit`
rule for the `bluetooth` group.

## See also

- [../design/fips-transport-layer.md](../design/fips-transport-layer.md)
  — per-transport MTU reporting and the BLE row of the supported-
  transports table.
- [../reference/configuration.md](../reference/configuration.md) —
  full `transports.ble.*` reference.
- [run-as-unprivileged-user.md](run-as-unprivileged-user.md) —
  adjacent privilege handling for the daemon process.
