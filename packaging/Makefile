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
#   make all        Build deb and tarball (default)
#   make clean      Remove deploy/ directory

SHELL := /bin/bash
PACKAGING_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT  := $(abspath $(PACKAGING_DIR)/..)

.PHONY: all deb tarball ipk aur clean

all: deb tarball

deb:
	@bash $(PACKAGING_DIR)/debian/build-deb.sh

tarball:
	@bash $(PACKAGING_DIR)/systemd/build-tarball.sh

ipk:
	@bash $(PACKAGING_DIR)/openwrt/build-ipk.sh

aur:
	@echo "Building fips-git AUR package..."
	cd $(PACKAGING_DIR)/aur && makepkg -sf -p PKGBUILD-git
	@echo "Running namcap validation..."
	namcap $(PACKAGING_DIR)/aur/PKGBUILD-git
	namcap $(PACKAGING_DIR)/aur/fips-git-*.pkg.tar.zst

clean:
	rm -rf $(PROJECT_ROOT)/deploy
