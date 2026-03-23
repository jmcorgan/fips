# FIPS Packaging

This directory contains packaging for all supported target platforms.
All build outputs go to `dist/` at the project root.

## Quick Start

```sh
make deb        # Debian/Ubuntu .deb
make tarball    # systemd install tarball
make ipk        # OpenWrt .ipk  (OpenWrt 22.03+, opkg)
make apk        # OpenWrt .apk  (OpenWrt 25+, apk-tools)
make all        # deb + tarball (default)
```

## Directory Structure

```text
packaging/
  common/           Shared assets (default config, hosts file)
  debian/           Debian/Ubuntu .deb packaging via cargo-deb
  systemd/          Generic Linux systemd tarball packaging
  openwrt-ipk/      OpenWrt .ipk packaging (22.03+, opkg)
  openwrt-apk/      OpenWrt .apk packaging (25+, apk-tools)
```

## Formats

### Debian/Ubuntu (`.deb`)

Built with [cargo-deb](https://github.com/kornelski/cargo-deb). Installs
`fips`, `fipsctl`, and `fipstop` to `/usr/bin/`, places config at
`/etc/fips/fips.yaml` (preserved on upgrade), and enables the systemd
service.

```sh
# Build
make deb

# Install
sudo dpkg -i dist/fips_<version>_<arch>.deb

# Remove (preserves config and keys)
sudo dpkg -r fips

# Purge (removes config and identity keys)
sudo dpkg -P fips
```

### systemd Tarball

A self-contained tarball with binaries and an `install.sh` script for
any systemd-based Linux distribution.

```sh
# Build
make tarball

# Install (on target host)
tar -xzf dist/fips-<version>-linux-<arch>.tar.gz
sudo ./fips-<version>-linux-<arch>/install.sh
```

See [systemd/README.install.md](systemd/README.install.md) for full
installation and configuration instructions.

### OpenWrt (`.ipk`) — OpenWrt 22.03+

Cross-compiled with cargo-zigbuild and assembled as a standard `.ipk`
archive for routers running OpenWrt 22.03+ with the opkg package manager.
Supports aarch64, mipsel, mips, arm, and x86\_64 targets.

```sh
# Build (default: aarch64)
make ipk

# Build for a specific architecture
bash packaging/openwrt-ipk/build-ipk.sh --arch mipsel
```

See [openwrt-ipk/README.md](openwrt-ipk/README.md) for router-specific
installation instructions.

### OpenWrt (`.apk`) — OpenWrt 25+

Cross-compiled with cargo-zigbuild and assembled as an APK v2 archive for
routers running OpenWrt 25+ with the apk-tools package manager (which
replaced opkg in OpenWrt 25). Supports the same architectures as `.ipk`.

```sh
# Build (default: aarch64)
make apk

# Build for a specific architecture
bash packaging/openwrt-apk/build-apk.sh --arch x86_64

# Install on router
scp -O dist/fips_<version>_<arch>.apk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 apk add --allow-untrusted --no-network /tmp/fips_<version>_<arch>.apk
```

**macOS prerequisites:** `brew install llvm zig` and `cargo install cargo-zigbuild`.

## Shared Assets

`common/` contains assets used across packaging formats:

- `fips.yaml` — default configuration (ephemeral identity, UDP/TCP/TUN/DNS)
- `hosts` — static hostname-to-npub mappings for `.fips` DNS resolution
