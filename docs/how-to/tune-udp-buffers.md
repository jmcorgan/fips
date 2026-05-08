# Tune Host UDP Socket Buffers for FIPS

The FIPS UDP transport requests larger send and receive socket
buffers (default 2 MB each, doubled by the kernel to 4 MB actual)
than the Linux defaults provide. The kernel silently clamps the
request to `net.core.rmem_max` and `net.core.wmem_max` if those
sysctls are smaller than the requested size — which causes silent
packet drops under high throughput. For the design context (why FIPS
requests larger buffers and how `SO_RXQ_OVFL` feeds ECN congestion
detection), see
[../design/fips-transport-layer.md](../design/fips-transport-layer.md#socket-buffer-sizing).

This guide covers the host-side sysctl setup needed before deploying
a high-throughput FIPS node.

## Why this matters

The default Linux UDP receive buffer (`net.core.rmem_default`,
typically 212 KB) fills in roughly 2.5 ms at ~85 MB/s. Any stall in
the FIPS receive loop (decryption, routing, forwarding) causes the
kernel to drop incoming datagrams without notification — they don't
appear in `recv` errors, they don't trigger any application-visible
event. The drops show up only in `SO_RXQ_OVFL` on subsequent
packets, where FIPS surfaces them as congestion-detection events.

Setting `rmem_max` and `wmem_max` to at least the requested buffer
size prevents the kernel clamp and the silent drop loss it causes.

## Step 1: Check current limits

```sh
sysctl net.core.rmem_max net.core.wmem_max
```

Typical defaults on stock Linux distributions are 212992 bytes
(212 KB). FIPS requests 2 MB by default, which the kernel doubles
internally to 4 MB; for the request to succeed without clamping, both
sysctls must be at least 4194304 (4 MB).

## Step 2: Set the limits temporarily

```sh
sudo sysctl -w net.core.rmem_max=4194304
sudo sysctl -w net.core.wmem_max=4194304
```

Verify:

```sh
sysctl net.core.rmem_max net.core.wmem_max
```

These changes take effect immediately for new socket binds but do
not survive a reboot.

## Step 3: Make the limits persistent

Drop a file under `/etc/sysctl.d/`:

```sh
sudo tee /etc/sysctl.d/60-fips.conf <<'EOF'
# FIPS UDP transport requests 2 MB socket buffers, kernel doubles to 4 MB.
# Avoid silent receive-buffer drops under load.
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
EOF
```

Apply:

```sh
sudo sysctl --system
```

The drop-in is loaded automatically on every boot.

## Step 4: Restart FIPS and verify the actual buffer size

After raising the host limits, restart the FIPS daemon so the next
socket bind picks up the new ceiling:

```sh
sudo systemctl restart fips
```

The daemon logs the actual buffer sizes at startup:

```text
UDP transport started local_addr=0.0.0.0:2121 recv_buf=4194304 send_buf=4194304
```

If `recv_buf` or `send_buf` shows a smaller number than expected, the
host sysctl is still clamping. Recheck `sysctl net.core.rmem_max
net.core.wmem_max` and confirm the drop-in file is being loaded
(`sudo sysctl --system` prints the loaded files).

## Docker and other container hosts

Containers share the host kernel, so sysctls apply to the host, not
the container. If you run FIPS inside Docker, set
`net.core.rmem_max` / `net.core.wmem_max` on the **Docker host**, not
inside the container. Container privileges (cap_sys_admin) and
`--sysctl` flags do not let you raise these particular limits from
inside a container — they are global to the host network namespace.

For Kubernetes deployments, the host-level sysctl tuning is the same;
node-level configuration (DaemonSet with `privileged: true`, or a
node-init script) is the typical mechanism.

## Tuning higher

The 4 MB ceiling is a conservative starting point. For very high
throughput (multi-gigabit per second), raise both sysctls and the
corresponding `transports.udp.recv_buf_size` /
`transports.udp.send_buf_size` config values together. Setting a config value
larger than the host ceiling silently clamps to the ceiling, so both
must move in lockstep.

## See also

- [../design/fips-transport-layer.md](../design/fips-transport-layer.md)
  — UDP transport design, why FIPS requests larger buffers,
  `SO_RXQ_OVFL` and ECN integration
- [../reference/configuration.md](../reference/configuration.md) —
  `transports.udp.recv_buf_size` and `send_buf_size` defaults
