# FIPS OpenWrt Package

This directory is an OpenWrt feed package that builds and installs FIPS on any
OpenWrt 22.03+ router via the standard `opkg` package system.

## Package contents

| Installed path | Purpose |
|---|---|
| `/usr/bin/fips` | Mesh daemon |
| `/usr/bin/fipsctl` | CLI control tool (`fipsctl show peers`, `fipsctl show links`, …) |
| `/usr/bin/fipstop` | Live TUI dashboard |
| `/usr/bin/fips-gateway` | Outbound LAN gateway service (not started by default) |
| `/usr/bin/fips-mesh-setup` | Opt-in helper — creates an open 802.11s mesh interface for router↔router backhaul |
| `/usr/bin/fips-ap-setup` | Opt-in helper — creates the open `!FIPS` access SSID for client devices |
| `/etc/init.d/fips` | procd service for the daemon (auto-start, crash respawn) |
| `/etc/init.d/fips-gateway` | procd service for the gateway (disabled by default) |
| `/etc/fips/fips.yaml` | Node configuration (edit before first start) |
| `/etc/fips/firewall.sh` | Firewall helper — accepts traffic on `fips0` |
| `/etc/sysctl.d/fips-bridge.conf` | `br_netfilter` settings for Ethernet transport |
| `/etc/sysctl.d/fips-gateway.conf` | `proxy_ndp` and IPv6 forwarding for the gateway |
| `/etc/hotplug.d/net/99-fips` | Applies firewall rules when `fips0` comes up |
| `/etc/uci-defaults/90-fips-setup` | First-boot kernel module, firewall and dnsmasq `.fips` forwarding setup |
| `/lib/upgrade/keep.d/fips` | Preserves `/etc/fips/` across `sysupgrade` |

## Requirements

### Build host

| Requirement | Notes |
|---|---|
| OpenWrt SDK 22.03+ | Older versions lack fw4 / nftables support |
| Rust host toolchain | Enable in `make menuconfig` → Advanced → Rust, or install rustup |
| Rust target for your router | Added automatically by the Makefile via `rustup target add` |

### Router

| Requirement | Notes |
|---|---|
| `kmod-tun` | Required for `fips0` TUN interface |
| `kmod-br-netfilter` | Required for Ethernet transport on bridge member ports |

Both kernel modules are listed as package dependencies (`DEPENDS`) and will be
installed automatically by `opkg`.

## Target architectures

The Makefile maps the OpenWrt `ARCH` variable to the correct Rust musl target:

| OpenWrt `ARCH` | Rust target |
|---|---|
| `aarch64` | `aarch64-unknown-linux-musl` |
| `x86_64` | `x86_64-unknown-linux-musl` |
| `mipsel` | `mipsel-unknown-linux-musl` |
| `mips` | `mips-unknown-linux-musl` |
| `arm` | `arm-unknown-linux-musleabihf` |

To add a missing architecture, add an `ifeq` block in `Makefile` mapping the
OpenWrt `ARCH` value to the Rust target triple.

## Building with the OpenWrt SDK

### 1. Obtain the SDK

Download the SDK for your router's target from
[downloads.openwrt.org](https://downloads.openwrt.org) and extract it.

### 2. Add this package

Copy or symlink this directory into the SDK's `package/` tree:

```bash
# From inside the SDK root:
ln -s /path/to/fips/packaging/openwrt-ipk package/fips
```

Or add the FIPS repository as a feed in `feeds.conf`:

```
src-git-full fips https://github.com/jmcorgan/fips.git
```

Then update and install feeds:

```bash
./scripts/feeds update fips
./scripts/feeds install -a -p fips
```

### 3. Build

```bash
make package/fips/compile V=s
```

The resulting `.ipk` is placed in `bin/packages/<arch>/`.

### 4. Pin the source version

For reproducible production builds, replace `PKG_SOURCE_VERSION:=master` in
`Makefile` with a specific commit SHA and set `PKG_MIRROR_HASH` to the correct
hash (or keep `skip` for development):

```makefile
PKG_SOURCE_VERSION:=bf117dfabc123...  # full 40-char SHA
PKG_MIRROR_HASH:=skip
```

## Installing on the router

```bash
scp bin/packages/<arch>/fips_0.1.0-1_<arch>.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 opkg install /tmp/fips_0.1.0-1_<arch>.ipk
```

## First-time configuration

Edit `/etc/fips/fips.yaml` on the router before starting the daemon:

```bash
ssh root@192.168.1.1
vi /etc/fips/fips.yaml
```

The default config enables:

- An ephemeral identity, generated on each start. Uncomment
  `node.identity.persistent: true` to keep one; the key is then saved next to
  the config, as `/etc/fips/fips.key`.
- TUN interface `fips0`
- DNS responder on `[::1]:5354`
- UDP transport on `[::]:2121`
- TCP transport on `0.0.0.0:8443`
- Ethernet transport, including the `wan`, `wwan` and `lan` entries

For Ethernet transport, edit the interface names in the `ethernet:` section to
match your router. **Always use physical port names
(`eth0`, `eth1`, or DSA port names like `wan`/`lan1`), never bridge names
(`br-lan`).** The shipped default WAN port is `eth0` (OpenWrt 24); on OpenWrt
25 (DSA) boards the WAN port is named `wan` — the `.apk` package ships that
default. Run `ip link show` to confirm the names on your board.

## Service management

```bash
/etc/init.d/fips start
/etc/init.d/fips stop
/etc/init.d/fips restart
/etc/init.d/fips enable    # start at boot (already enabled by opkg postinstall)
/etc/init.d/fips disable
```

### Outbound LAN gateway (optional)

The `fips-gateway` service is installed but disabled by default. It
turns the router into an outbound gateway that bridges LAN clients
onto the FIPS mesh. Enable only after configuring a `gateway:`
section in `/etc/fips/fips.yaml`:

```bash
/etc/init.d/fips-gateway enable
/etc/init.d/fips-gateway start
```

See `docs/tutorials/deploy-fips-gateway.md` in the source tree for
the full walkthrough.

## Inspection and logs

```bash
# Node-level status overview
fipsctl show status

# Peer table
fipsctl show peers

# Transport links
fipsctl show links

# Active end-to-end sessions
fipsctl show sessions

# Live TUI dashboard
fipstop

# Daemon logs (OpenWrt syslog)
logread | grep fips
```

See [`docs/reference/cli-fipsctl.md`](../../docs/reference/cli-fipsctl.md)
for the full subcommand list.

## Upgrading

Install the new `.ipk` with a plain `opkg install`:

```bash
opkg install /tmp/fips_<new-version>_<arch>.ipk
```

opkg runs this as an upgrade. The installed package's `prerm` stops `fips` and
`fips-gateway` without disabling them, and the new package's `postinst` starts
`fips` and starts `fips-gateway` again if it was enabled.

An upgrade from 0.5.1 or earlier is the exception. The `prerm` in those
packages disables `fips-gateway` and records nothing about whether it was
enabled, so the new `postinst` enables it again. If you had the gateway
disabled, disable it again after that first upgrade:

```bash
/etc/init.d/fips-gateway stop
/etc/init.d/fips-gateway disable
```

If opkg refuses because the new file's version sorts lower than the installed
one, as it can between development builds, add `--force-downgrade`. opkg then
takes the same upgrade path.

Do not use `--force-reinstall`. opkg runs it as a removal followed by a fresh
install, so `fips-gateway` ends up disabled. To turn it back on:

```bash
/etc/init.d/fips-gateway enable
/etc/init.d/fips-gateway start
```

On OpenWrt 25 and later, install and upgrade the `.apk` package with
`apk add --allow-untrusted` instead; see
[`../openwrt-apk/README.md`](../openwrt-apk/README.md).

The config in `/etc/fips/fips.yaml` and the identity key `/etc/fips/fips.key`
(when persistent identity is on) are preserved by `opkg` (the yaml is installed
as a conffile; the key is not a package file). Both survive `sysupgrade` via
`/lib/upgrade/keep.d/fips`.
