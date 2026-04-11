# FIPS Packaging Makefile
#
# Builds release packages for supported target platforms.
# All outputs are placed in deploy/ at the project root.
#
# Usage:
#   make deb        Build a Debian/Ubuntu .deb package
#   make tarball    Build a systemd install tarball
#   make ipk        Build an OpenWrt .ipk package
#   make aur        Build fips-git AUR package and validate with namcap
#   make pkg        Build a macOS .pkg installer
#   make zip        Build a Windows .zip package
#   make all        Build deb and tarball (default)
#   make clean      Remove deploy/ directory

SHELL := /bin/bash
PACKAGING_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT  := $(abspath $(PACKAGING_DIR)/..)

.PHONY: all deb tarball ipk aur pkg zip clean

all: deb tarball

deb:
	@bash $(PACKAGING_DIR)/debian/build-deb.sh

tarball:
	@bash $(PACKAGING_DIR)/systemd/build-tarball.sh

ipk:
	@bash $(PACKAGING_DIR)/openwrt-ipk/build-ipk.sh

aur:
	@bash $(PACKAGING_DIR)/aur/build-aur.sh

pkg:
	@bash $(PACKAGING_DIR)/macos/build-pkg.sh

zip:
	@powershell -File $(PACKAGING_DIR)/windows/build-zip.ps1

clean:
	rm -rf $(PROJECT_ROOT)/deploy
