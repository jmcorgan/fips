# FIPS Packaging Makefile
#
# Builds release packages for supported target platforms.
# All outputs are placed in dist/ at the project root.
#
# Usage:
#   make deb        Build a Debian/Ubuntu .deb package
#   make tarball    Build a systemd install tarball
#   make ipk        Build an OpenWrt .ipk package (OpenWrt 22.03+, opkg)
#   make apk        Build an OpenWrt .apk package (OpenWrt 25+, apk-tools)
#   make all        Build deb and tarball (default)
#   make clean      Remove dist/ directory

SHELL := /bin/bash
PACKAGING_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT  := $(abspath $(PACKAGING_DIR)/..)

.PHONY: all deb tarball ipk apk clean

all: deb tarball

deb:
	@bash $(PACKAGING_DIR)/debian/build-deb.sh

tarball:
	@bash $(PACKAGING_DIR)/systemd/build-tarball.sh

ipk:
	@bash $(PACKAGING_DIR)/openwrt-ipk/build-ipk.sh

apk:
	@bash $(PACKAGING_DIR)/openwrt-apk/build-apk.sh

clean:
	rm -rf $(PROJECT_ROOT)/dist
