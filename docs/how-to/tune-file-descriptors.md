# Tune the File-Descriptor Limit for FIPS

A busy FIPS node opens many file descriptors, and the count grows with
the number of peers it serves. On most systemd distributions the daemon
inherits a soft `RLIMIT_NOFILE` of 1024, which a well-connected node can
exhaust — at which point peer admission, handshakes, and discovery start
failing with `EMFILE` ("Too many open files").

This guide explains the FD budget, shows how to raise the limit on
systemd and on OpenWrt, and how to verify the result.

## Why FIPS is FD-hungry

Unlike a service that multiplexes all traffic over one socket, the FIPS
data plane allocates descriptors **per peer**. The dominant term is:

```text
fds ≈ 3·P + fixed overhead (~30)
```

where `P` is the number of established UDP peers. Each such peer consumes
**3 file descriptors**:

- one `connect()`-ed UDP socket dedicated to that peer, plus
- a 2-FD self-pipe owned by that peer's receive-drain worker (used to
  wake and stop the worker cleanly).

The remaining consumers are bounded and do not scale with peer count:

- the TUN device (one descriptor, process-lifetime),
- the wildcard UDP listen socket(s) (one per bound UDP transport),
- TCP and Tor transport listeners and the Tor control socket,
- Nostr relay websockets (one per configured discovery relay),
- the control socket (one `UnixListener`, plus short-lived per-request
  client connections for `fipsctl` / `fipstop`),
- and base runtime descriptors (epoll, eventfd, logs).

Together these add a roughly flat overhead of about 30 descriptors. The
per-peer term is what drives the daemon toward the FD ceiling.

## The symptom

The systemd and distro default **soft** `RLIMIT_NOFILE` is **1024**.
With the `3·P` budget above, that ceiling is reached near **~320 peers**
(3 × 320 ≈ 960, plus the fixed overhead). Once the process is out of
descriptors, every syscall that allocates one — `socket()`, `accept()`,
`open()`, `pipe()` — fails with `EMFILE`, which surfaces as:

- failed peer admission (new peers cannot be accepted),
- failed handshakes (the daemon cannot open the per-peer socket), and
- dropped discovery (relay or probe sockets cannot be created).

These symptoms appear only under load, once the node has accumulated
enough peers to cross the ceiling, so they can be easy to misattribute.

## Raise the limit on systemd

Create a drop-in override for the service:

```sh
sudo systemctl edit fips.service
```

Add:

```ini
[Service]
LimitNOFILE=65535
```

A single `LimitNOFILE=` value sets **both** the soft and the hard limit,
so no separate soft/hard syntax is needed here.

Reload systemd and restart the daemon so the new limit takes effect:

```sh
sudo systemctl daemon-reload
sudo systemctl restart fips
```

`65535` (2¹⁶ − 1) is the conventional headroom value for network
daemons. With the `3·P` budget, it supports roughly **~21,800 peers**
before the FD ceiling binds — well beyond any plausible single-node FIPS
mesh degree. Past that point other limits (threads, memory, CPU) bind
first, so raising `LimitNOFILE` higher buys nothing.

## Raise the limit on OpenWrt

OpenWrt uses procd, not systemd, so `LimitNOFILE` does not apply.
Set the equivalent limit in the init script at `/etc/init.d/fips`,
inside the block that starts the service:

```sh
procd_set_param limits nofile="65535 65535"
```

The two values are the soft and hard limits respectively; setting them
equal mirrors the single-value systemd behaviour above.

Restart the service to apply:

```sh
/etc/init.d/fips restart
```

## Verify

Compare the live descriptor count against the established peer count:

```sh
ls /proc/$(pidof fips)/fd | wc -l
fipsctl show peers | wc -l
```

At steady state, expect a stable ratio of about **3 descriptors per
peer** plus the flat ~30-descriptor overhead. A ratio that holds steady
as peers come and go confirms healthy, bounded scaling.

If the descriptor count climbs steadily while the peer count stays flat,
that would indicate a descriptor leak rather than legitimate scaling —
the limit bump would only delay the wall. The current data plane has
been audited as leak-free (every per-peer descriptor has a guaranteed
close on every teardown path), so a climbing ratio at fixed peer count
would be a regression worth investigating.

## A note on deployment lines

The per-peer connected-UDP socket — the amplifier behind the
`3·P` term — is present on the master and next data planes. It is **not
yet present on the maintenance line**. On maintenance-only deployments
the 3-descriptor-per-peer term does not apply, and FD pressure comes
only from the fixed consumers listed above. Raising `LimitNOFILE` there
is still worthwhile as forward-looking headroom, and harmless where the
amplifier is absent.

## See also

- [tune-udp-buffers.md](tune-udp-buffers.md) — host sysctls so FIPS UDP
  sockets don't get clamped
- [run-as-unprivileged-user.md](run-as-unprivileged-user.md) — run the
  daemon under a dedicated service account
- [../reference/configuration.md](../reference/configuration.md) —
  transport and discovery configuration that influences the fixed FD
  overhead
