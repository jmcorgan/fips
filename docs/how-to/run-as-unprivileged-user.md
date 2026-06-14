# Run the FIPS Daemon as an Unprivileged User

By default, the FIPS daemon runs as `root` — the shipped Debian
systemd unit configures this, and no further setup is required.
The trade-off is that the daemon has full root authority,
including outside its actual network needs. Acceptable for
single-purpose hosts; less desirable for shared hosts.

This guide covers the alternative: drop privileges and run the
daemon under a dedicated unprivileged user account. The TUN
device that the FIPS IPv6 adapter creates requires
`CAP_NET_ADMIN` on Linux; the recipe below grants that privilege
via a file capability on the binary, plus everything else the
daemon needs to keep working without root: a service user
account, file permissions on the config directory, and a systemd
unit override to drop privileges.

For the design context (why the adapter needs a TUN, how the
adapter integrates with the kernel routing table), see
[../design/fips-ipv6-adapter.md](../design/fips-ipv6-adapter.md).

## Prerequisites

- FIPS package installed (the postinst already creates the `fips`
  system group used for control-socket access).
- `setcap` available (`apt install libcap2-bin` on Debian/Ubuntu;
  it is a standard utility on most distributions).
- Operator access to systemd unit overrides (`systemctl edit`).

## Step 1: Create a `fips` system user

The package creates a `fips` system *group* but no matching user.
Add a system user that belongs to the `fips` group:

```sh
sudo useradd --system --gid fips --no-create-home --shell /usr/sbin/nologin fips
```

The user has no home directory and no login shell — this account
exists only to run the daemon.

## Step 2: Grant `CAP_NET_ADMIN` to the binary

Apply the file capability so the daemon can create the TUN device
without root authority:

```sh
sudo setcap cap_net_admin+ep /usr/bin/fips
```

Verify:

```sh
getcap /usr/bin/fips
# /usr/bin/fips cap_net_admin=ep
```

The binary can now create TUN devices when run by any user.

**File-capability caveats:**

- The capability is attached to the binary file. **Re-applying
  the capability after every package upgrade is required**,
  because package upgrades replace the binary file and lose the
  cap. The systemd override in Step 4 includes an `ExecStartPre`
  line that automates this.
- File capabilities are stripped when the binary is copied across
  most filesystems and when it is downloaded via web tooling. If
  you build from source and install manually, remember to
  re-`setcap` after each rebuild.
- `LD_LIBRARY_PATH` and similar environment-driven loader
  controls are stripped at exec time when file capabilities are
  present; this is normally what you want, but development
  workflows that rely on custom library paths may be surprised.

## Step 3: Adjust config-file permissions

The shipped `/etc/fips/fips.yaml` is mode `0600` and owned by
`root:root`. The daemon needs to read it and, if persistent
identity is enabled, write `/etc/fips/fips.key` into the same
directory.

```sh
sudo chown -R fips:fips /etc/fips
sudo chmod 0640 /etc/fips/fips.yaml
```

If `node.identity.persistent: true` is set and `fips.key` does
not exist yet, leave `/etc/fips` itself writable by the `fips`
user so the daemon can create it on first start. After the key
file exists, you can tighten further:

```sh
sudo chmod 0600 /etc/fips/fips.key
```

## Step 4: Drop privileges in the systemd unit

Create an override:

```sh
sudo systemctl edit fips.service
```

Add:

```ini
[Service]
User=fips
Group=fips
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=no
ExecStartPre=/sbin/setcap cap_net_admin+ep /usr/bin/fips
```

`User=` / `Group=` set the service identity.
`AmbientCapabilities=` ensures the file capability granted in
Step 2 actually carries into the daemon's process tree.
`NoNewPrivileges=no` is required for file-capability execution
to work — systemd defaults this to `yes` for hardened units,
which would block the `setcap` from taking effect.
`ExecStartPre=` re-applies the capability before each start,
which makes the package-upgrade path self-heal.

The unit's `RuntimeDirectory=fips` directive already arranges
for `/run/fips/` to be created with the right ownership at
service start, now as `fips:fips 0750` instead of
`root:fips 0750`.

Reload and restart:

```sh
sudo systemctl daemon-reload
sudo systemctl restart fips
```

## Step 5: Verify

Confirm the daemon is running as `fips`:

```sh
ps -eo user,cmd | grep '[/]usr/bin/fips'
# fips     /usr/bin/fips --config /etc/fips/fips.yaml
```

Confirm the TUN device came up (the `setcap` worked):

```sh
ip link show fips0
# fips0: <POINTOPOINT,UP,...> mtu 1280 ...
```

Confirm the control socket is bound and accessible to the `fips`
group:

```sh
ls -la /run/fips/control.sock
# srwxrwx--- 1 fips fips ... /run/fips/control.sock
```

Add yourself to the `fips` group so you can use `fipsctl` /
`fipstop` without `sudo`:

```sh
sudo usermod -aG fips $USER
# log out and back in for the group change to take effect
```

Then:

```sh
fipsctl show status
```

## Caveats

- **`fips-firewall.service` still runs as root.** Loading nftables
  rules into the kernel requires root regardless. The firewall
  unit is intentionally separate from the daemon unit.
- **Bluetooth peers (`transports.ble.*`)** require additional
  privileges the `CAP_NET_ADMIN` setcap doesn't cover. If you use
  the BLE transport, you'll likely need to keep running as root
  or layer additional capability/D-Bus configuration; that path
  is not covered here.

## See also

- [persistent-identity.md](persistent-identity.md) — how the
  daemon manages `/etc/fips/fips.key`
- [../design/fips-ipv6-adapter.md](../design/fips-ipv6-adapter.md)
  — IPv6 adapter design, TUN interface architecture
- [../reference/security.md](../reference/security.md) —
  consolidated security surface
- [../reference/configuration.md](../reference/configuration.md)
  — `tun.*` configuration block
