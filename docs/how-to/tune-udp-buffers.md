# Tune Host UDP Socket Buffers for FIPS

The FIPS UDP transport requests larger send and receive socket
buffers (default 2 MB each, doubled by the kernel to 4 MB actual)
than the Linux defaults provide, and so does the Ethernet transport's
packet socket. On Linux each socket first asks with `SO_RCVBUFFORCE`
and `SO_SNDBUFFORCE`, which a process holding `CAP_NET_ADMIN` is
granted whatever the host limits say. Without that capability it
falls back to plain `SO_RCVBUF` and `SO_SNDBUF`, which the kernel
clamps to `net.core.rmem_max` and `net.core.wmem_max`, and a clamped
buffer drops packets under high throughput. For the design context
(why FIPS requests larger buffers and how `SO_RXQ_OVFL` feeds ECN
congestion detection), see
[../design/fips-transport-layer.md](../design/fips-transport-layer.md#socket-buffer-sizing).

There are two remedies, and the daemon's clamp warning names both:
grant the process `CAP_NET_ADMIN`, or raise the sysctls. The
packaged service runs as root and already holds the capability, so
it gets the full buffers with no host tuning; so does a container
started with `--cap-add NET_ADMIN`, which FIPS needs for its TUN
device anyway. A node set up as an unprivileged user by
[run-as-unprivileged-user.md](run-as-unprivileged-user.md) holds the
capability too (the guide grants it with `setcap` and
`AmbientCapabilities=`), so it also needs no tuning. This guide
covers the sysctl setup for a node that runs without the capability:
a process running as an ordinary user with neither a file nor an
ambient capability, or a container started without
`--cap-add NET_ADMIN`, or started with `--user` and no ambient
capability.

## Why this matters

The default Linux UDP receive buffer (`net.core.rmem_default`,
typically 212 KB) fills in roughly 2.5 ms at ~85 MB/s. Any stall in
the FIPS receive loop (decryption, routing, forwarding) causes the
kernel to drop incoming datagrams without notification — they don't
appear in `recv` errors, they don't trigger any application-visible
event. The drops show up only in `SO_RXQ_OVFL` on subsequent
packets, where FIPS surfaces them as congestion-detection events.

A process with `CAP_NET_ADMIN` is not clamped. For one without it,
setting `rmem_max` and `wmem_max` to at least the requested buffer
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
host sysctl is still clamping, and the daemon also warns `UDP recv
buffer clamped by kernel (grant CAP_NET_ADMIN or increase
net.core.rmem_max)`, or the send or Ethernet equivalent. Recheck
`sysctl net.core.rmem_max net.core.wmem_max` and confirm the drop-in
file is being loaded (`sudo sysctl --system` prints the loaded files),
or grant the process `CAP_NET_ADMIN` instead.

## Docker and other container hosts

A container started with `--cap-add NET_ADMIN` (or `cap_add:
[NET_ADMIN]` in Compose), which FIPS needs for its TUN device, holds
`CAP_NET_ADMIN` and is granted the full buffers, so it needs no host
tuning. Under Docker's default, with no user-namespace remapping, a
2 MB `SO_RCVBUFFORCE` request from such a container is granted
4194304 bytes on a host whose `rmem_max` is 212992, and the same
request from a container without the capability is refused and
falls back to the clamped size.

A container without the capability is clamped by the host's limits.
Containers share the host kernel, so sysctls apply to the host, not
the container: set `net.core.rmem_max` / `net.core.wmem_max` on the
**Docker host**, not inside the container. `--sysctl` flags do not
let you raise these particular limits from inside a container; they
are global to the host.

For Kubernetes deployments, add `NET_ADMIN` to the container's
`securityContext.capabilities`, or tune the host as above through
node-level configuration (DaemonSet with `privileged: true`, or a
node-init script).

## Tuning higher

The 4 MB ceiling is a conservative starting point. For very high
throughput (multi-gigabit per second), raise both sysctls and the
corresponding `transports.udp.recv_buf_size` /
`transports.udp.send_buf_size` config values together. Without
`CAP_NET_ADMIN`, a config value larger than the host ceiling is
clamped to the ceiling (with a warning), so both must move in
lockstep; with the capability, the config value alone decides.

## See also

- [../design/fips-transport-layer.md](../design/fips-transport-layer.md)
  — UDP transport design, why FIPS requests larger buffers,
  `SO_RXQ_OVFL` and ECN integration
- [../reference/configuration.md](../reference/configuration.md) —
  `transports.udp.recv_buf_size` and `send_buf_size` defaults
