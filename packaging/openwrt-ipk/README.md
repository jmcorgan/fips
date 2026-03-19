# FIPS OpenWrt Package

This directory is an OpenWrt feed package that builds and installs FIPS on any
OpenWrt 22.03+ router via the standard `opkg` package system.

For ad-hoc deployment without the build system, see
[`deploy/native/`](../../deploy/native/README.md) instead.

## Package contents

| Installed path | Purpose |
|---|---|
| `/usr/bin/fips` | Mesh daemon |
| `/usr/bin/fipsctl` | CLI control tool (`fipsctl peers`, `fipsctl links`, …) |
| `/usr/bin/fipstop` | Live TUI dashboard |
| `/etc/init.d/fips` | procd service (auto-start, crash respawn) |
| `/etc/fips/fips.yaml` | Node configuration (edit before first start) |
| `/etc/fips/firewall.sh` | Firewall helper — accepts traffic on `fips0` |
| `/etc/dnsmasq.d/fips.conf` | Forwards `.fips` DNS queries to the daemon |
| `/etc/sysctl.d/fips-bridge.conf` | `br_netfilter` settings for Ethernet transport |
| `/etc/hotplug.d/net/99-fips` | Applies firewall rules when `fips0` comes up |
| `/etc/uci-defaults/90-fips-setup` | First-boot kernel module and firewall setup |
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
ln -s /path/to/fips/packaging/openwrt package/fips
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
- Persistent identity (key generated on first start, saved to `/etc/fips/fips.key`)
- TUN interface `fips0`
- DNS responder on `127.0.0.1:5354`
- UDP transport on `0.0.0.0:2121`

For Ethernet transport, uncomment the `ethernet:` section and set the correct
physical interface names for your router. **Always use physical port names
(`eth0`, `eth1`), never bridge names (`br-lan`).** See
[`deploy/native/README.md`](../../deploy/native/README.md) for details.

## Service management

```bash
/etc/init.d/fips start
/etc/init.d/fips stop
/etc/init.d/fips restart
/etc/init.d/fips enable    # start at boot (already enabled by opkg postinstall)
/etc/init.d/fips disable
```

## Inspection and logs

```bash
# Peer table
fipsctl peers

# Active sessions
fipsctl sessions

# Transport links
fipsctl links

# Live TUI dashboard
fipstop

# Daemon logs (OpenWrt syslog)
logread | grep fips
```

## Upgrading

Install the new `.ipk` over the existing one:

```bash
opkg install --force-reinstall fips_<new-version>_<arch>.ipk
```

The config in `/etc/fips/fips.yaml` and the identity key `/etc/fips/fips.key`
are preserved by `opkg` (the yaml is installed as a conffile; the key is not a
package file). Both survive `sysupgrade` via `/lib/upgrade/keep.d/fips`.
