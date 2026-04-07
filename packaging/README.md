# FIPS Packaging

This directory contains packaging for all supported target platforms.
All build outputs go to `deploy/` at the project root.

## Quick Start

```sh
make deb        # Debian/Ubuntu .deb
make tarball    # systemd install tarball
make ipk        # OpenWrt .ipk
make aur        # Arch Linux AUR package (fips-git, local build + namcap)
make pkg        # macOS .pkg installer
make all        # deb + tarball (default)
```

## Directory Structure

```text
packaging/
  aur/            Arch Linux AUR packaging (PKGBUILD, supporting files)
  common/         Shared assets (default config, hosts file)
  debian/         Debian/Ubuntu .deb packaging via cargo-deb
  macos/          macOS .pkg installer via pkgbuild
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

### macOS (`.pkg`)

Built with `pkgbuild` (included with Xcode command-line tools). Installs
binaries to `/usr/local/bin/`, config to `/usr/local/etc/fips/`, sets up
the `/etc/resolver/fips` DNS resolver for `.fips` domains, and loads a
launchd daemon. The TUN device is named `utun<N>` (kernel-assigned)
rather than `fips0`.

```sh
# Build
make pkg

# Install
sudo installer -pkg deploy/fips-<version>-macos-<arch>.pkg -target /

# Remove
sudo packaging/macos/uninstall.sh
```

### Arch Linux (AUR)

Two AUR packages are maintained: `fips` (release, builds from tagged
tarball) and `fips-git` (development, builds from latest git master).

```sh
# Build and validate locally (git variant)
make aur

# Install from AUR
yay -S fips-git    # development build from master
yay -S fips        # release build from latest tag
```

See [aur/README.md](aur/README.md) for AUR publication instructions
and maintainer guide.

## Shared Assets

`common/` contains assets used across packaging formats:

- `fips.yaml` — default configuration (ephemeral identity, UDP/TCP/TUN/DNS)
- `hosts` — static hostname-to-npub mappings for `.fips` DNS resolution
