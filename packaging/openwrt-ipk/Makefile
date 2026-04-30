include $(TOPDIR)/rules.mk

PKG_NAME:=fips
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

# Pin to a specific commit for reproducible builds.
# Update PKG_SOURCE_VERSION and PKG_MIRROR_HASH when upgrading.
PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/jmcorgan/fips.git
PKG_SOURCE_VERSION:=master
PKG_MIRROR_HASH:=skip

PKG_MAINTAINER:=FIPS Network
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

# Rust host toolchain must be present in the build system.
# In the OpenWrt build system, enable via: make menuconfig → Advanced → Rust
PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

# ---------------------------------------------------------------------------
# Map OpenWrt ARCH to Rust target triple.
# All OpenWrt targets use musl libc.
# ---------------------------------------------------------------------------
ifeq ($(ARCH),aarch64)
  RUST_TARGET:=aarch64-unknown-linux-musl
else ifeq ($(ARCH),x86_64)
  RUST_TARGET:=x86_64-unknown-linux-musl
else ifeq ($(ARCH),mipsel)
  RUST_TARGET:=mipsel-unknown-linux-musl
else ifeq ($(ARCH),mips)
  RUST_TARGET:=mips-unknown-linux-musl
else ifeq ($(ARCH),arm)
  # OpenWrt ARM targets predominantly use hardfloat ABI.
  # Override RUST_TARGET in your build if your target uses softfloat.
  RUST_TARGET:=arm-unknown-linux-musleabihf
else
  $(error Unsupported architecture: $(ARCH). Add a RUST_TARGET mapping in packaging/openwrt/Makefile.)
endif

RUST_RELEASE_DIR:=$(PKG_BUILD_DIR)/target/$(RUST_TARGET)/release

define Package/fips
  SECTION:=net
  CATEGORY:=Network
  TITLE:=FIPS Mesh Network Daemon
  URL:=https://github.com/jmcorgan/fips
  DEPENDS:=+kmod-tun +kmod-br-netfilter +kmod-nft-nat \
	+kmod-nf-conntrack +ip-full
endef

define Package/fips/description
  FIPS is a distributed, decentralized mesh networking daemon. It routes
  traffic across nodes connected over UDP, TCP, or raw Ethernet (EtherType
  0x2121). Provides a TUN interface (fips0) with ULA IPv6 mesh addressing
  and a local DNS responder for .fips name resolution.

  Four binaries are installed:
    fips         — mesh daemon
    fipsctl      — CLI control and inspection tool
    fipstop      — live TUI dashboard (requires a terminal)
    fips-gateway — outbound LAN gateway (not started by default)
endef

# ---------------------------------------------------------------------------
# Build
#
# We write a temporary .cargo/config.toml to set the cross-linker without
# polluting the source tree. CARGO_HOME is scoped to the staging directory
# to avoid touching the developer's ~/.cargo during SDK builds.
# ---------------------------------------------------------------------------
define Build/Compile
	mkdir -p $(PKG_BUILD_DIR)/.cargo
	printf '[target.$(RUST_TARGET)]\nlinker = "$(TARGET_CC)"\n' \
		> $(PKG_BUILD_DIR)/.cargo/config.toml
	cd $(PKG_BUILD_DIR) && \
	CARGO_HOME=$(STAGING_DIR_HOST)/share/cargo \
	cargo build \
		--release \
		--target $(RUST_TARGET) \
		--bin fips \
		--bin fipsctl \
		--bin fipstop \
		--bin fips-gateway
endef

define Package/fips/install
	# Binaries
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(RUST_RELEASE_DIR)/fips    $(1)/usr/bin/fips
	$(INSTALL_BIN) $(RUST_RELEASE_DIR)/fipsctl $(1)/usr/bin/fipsctl
	$(INSTALL_BIN) $(RUST_RELEASE_DIR)/fipstop $(1)/usr/bin/fipstop
	$(INSTALL_BIN) $(RUST_RELEASE_DIR)/fips-gateway $(1)/usr/bin/fips-gateway

	# procd init script
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/files/etc/init.d/fips $(1)/etc/init.d/fips
	$(INSTALL_BIN) $(CURDIR)/files/etc/init.d/fips-gateway $(1)/etc/init.d/fips-gateway

	# Default config — installed as CONF so opkg will not overwrite it on upgrade
	$(INSTALL_DIR) $(1)/etc/fips
	$(INSTALL_CONF) $(CURDIR)/files/etc/fips/fips.yaml $(1)/etc/fips/fips.yaml

	# Firewall helper script (called by UCI include and hotplug)
	$(INSTALL_BIN) $(CURDIR)/files/etc/fips/firewall.sh $(1)/etc/fips/firewall.sh

	# dnsmasq drop-in: forward .fips queries to the FIPS DNS responder
	$(INSTALL_DIR) $(1)/etc/dnsmasq.d
	$(INSTALL_DATA) $(CURDIR)/files/etc/dnsmasq.d/fips.conf $(1)/etc/dnsmasq.d/fips.conf

	# sysctl: enable br_netfilter so AF_PACKET sees frames on bridge member ports
	$(INSTALL_DIR) $(1)/etc/sysctl.d
	$(INSTALL_DATA) $(CURDIR)/files/etc/sysctl.d/fips-bridge.conf $(1)/etc/sysctl.d/fips-bridge.conf
	$(INSTALL_DATA) $(CURDIR)/files/etc/sysctl.d/fips-gateway.conf $(1)/etc/sysctl.d/fips-gateway.conf

	# Hotplug: apply firewall rules when the FIPS TUN interface comes up
	$(INSTALL_DIR) $(1)/etc/hotplug.d/net
	$(INSTALL_BIN) $(CURDIR)/files/etc/hotplug.d/net/99-fips $(1)/etc/hotplug.d/net/99-fips

	# UCI defaults: one-time first-boot firewall and module setup
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(CURDIR)/files/etc/uci-defaults/90-fips-setup $(1)/etc/uci-defaults/90-fips-setup

	# sysupgrade: preserve /etc/fips/ (config + identity key) across firmware upgrades
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) $(CURDIR)/files/lib/upgrade/keep.d/fips $(1)/lib/upgrade/keep.d/fips
endef

$(eval $(call BuildPackage,fips))
