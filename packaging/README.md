# FIPS Packaging

This directory contains packaging for all supported target platforms.
All build outputs go to `deploy/` at the project root.

## Quick Start

```sh
make deb        # Debian/Ubuntu .deb
make tarball    # systemd install tarball
make ipk        # OpenWrt .ipk
make all        # deb + tarball (default)
```

## Directory Structure

```text
packaging/
  common/         Shared assets (default config, hosts file)
  debian/         Debian/Ubuntu .deb packaging via cargo-deb
  systemd/        Generic Linux systemd tarball packaging
  openwrt/        OpenWrt .ipk packaging via cargo-zigbuild
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
sudo dpkg -i deploy/fips_<version>_<arch>.deb

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
tar -xzf deploy/fips-<version>-linux-<arch>.tar.gz
sudo ./fips-<version>-linux-<arch>/install.sh
```

See [systemd/README.install.md](systemd/README.install.md) for full
installation and configuration instructions.

### OpenWrt (`.ipk`)

Cross-compiled with cargo-zigbuild and assembled as a standard `.ipk`
archive. Supports aarch64, mipsel, mips, arm, and x86\_64 targets.

```sh
# Build (default: aarch64)
make ipk

# Build for a specific architecture
bash packaging/openwrt/build-ipk.sh --arch mipsel
```

See [openwrt/README.md](openwrt/README.md) for router-specific
installation instructions.

## Shared Assets

`common/` contains assets used across packaging formats:

- `fips.yaml` — default configuration (ephemeral identity, UDP/TCP/TUN/DNS)
- `hosts` — static hostname-to-npub mappings for `.fips` DNS resolution
