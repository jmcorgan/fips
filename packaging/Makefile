# FIPS Packaging Makefile
#
# Builds release packages for supported target platforms.
# All outputs are placed in deploy/ at the project root.
#
# Usage:
#   make deb        Build a Debian/Ubuntu .deb package in the pinned container
#   make deb-host   Build a .deb with the host toolchain (see below)
#   make tarball    Build a systemd install tarball
#   make ipk        Build an OpenWrt .ipk package (opkg, OpenWrt 24.x and earlier)
#   make apk        Build an OpenWrt .apk package (apk-tools, mandatory on OpenWrt 25+)
#   make aur        Build fips-git AUR package and validate with namcap
#   make pkg        Build a macOS .pkg installer
#   make freebsd    Build a FreeBSD .pkg package (on FreeBSD; use gmake)
#   make zip        Build a Windows .zip package
#   make all        Build deb and tarball (default)
#   make clean      Remove deploy/ directory

SHELL := /bin/bash
PACKAGING_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT  := $(abspath $(PACKAGING_DIR)/..)

.PHONY: all deb deb-host tarball ipk apk aur pkg freebsd zip clean

all: deb tarball

# `deb` builds in the pinned container so the package carries the declared glibc
# floor and can install on every supported distribution. It also checks that
# floor before it hands the package back.
deb:
	@bash $(PACKAGING_DIR)/debian/build-deb-container.sh

# `deb-host` builds with whatever toolchain and C library the host has. It is
# for iterating locally and NOT for anything anyone else installs: on a modern
# host it produces a package that installs cleanly and then cannot start on
# Debian 12 or Ubuntu 22.04, which is the defect that made the container build
# necessary. Nothing checks its floor, deliberately, so the check stays
# attached to the artifact that ships.
deb-host:
	@bash $(PACKAGING_DIR)/debian/build-deb.sh

tarball:
	@bash $(PACKAGING_DIR)/systemd/build-tarball.sh

ipk:
	@bash $(PACKAGING_DIR)/openwrt-ipk/build-ipk.sh

apk:
	@bash $(PACKAGING_DIR)/openwrt-apk/build-apk.sh

aur:
	@bash $(PACKAGING_DIR)/aur/build-aur.sh

pkg:
	@bash $(PACKAGING_DIR)/macos/build-pkg.sh

freebsd:
	@sh $(PACKAGING_DIR)/freebsd/build-pkg.sh

zip:
	@powershell -File $(PACKAGING_DIR)/windows/build-zip.ps1

clean:
	rm -rf $(PROJECT_ROOT)/deploy
