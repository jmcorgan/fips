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
else ifeq ($(DUMP),)
  # Not while OpenWrt scans package metadata (DUMP=1): the scan does not read
  # the target config, so ARCH is empty then, and stopping here would leave the
  # package out of the build entirely.
  $(error Unsupported architecture: $(ARCH). Add a RUST_TARGET mapping in packaging/openwrt-ipk/Makefile.)
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

	# 802.11s mesh backhaul setup helper
	$(INSTALL_BIN) $(CURDIR)/files/usr/bin/fips-mesh-setup $(1)/usr/bin/fips-mesh-setup

	# Open "FIPS" access SSID setup helper
	$(INSTALL_BIN) $(CURDIR)/files/usr/bin/fips-ap-setup $(1)/usr/bin/fips-ap-setup

	# procd init script
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/files/etc/init.d/fips $(1)/etc/init.d/fips
	$(INSTALL_BIN) $(CURDIR)/files/etc/init.d/fips-gateway $(1)/etc/init.d/fips-gateway

	# Default config, mode 0600. Package/fips/conffiles below is what keeps an
	# edited copy across an upgrade.
	$(INSTALL_DIR) $(1)/etc/fips
	$(INSTALL_CONF) $(CURDIR)/files/etc/fips/fips.yaml $(1)/etc/fips/fips.yaml

	# sysctl: turn off br_netfilter's call hooks (fips-bridge.conf). br_netfilter
	# does not make bridge member ports usable for the Ethernet transport; the
	# shipped config binds the LAN bridge instead. See fips-bridge.conf.
	$(INSTALL_DIR) $(1)/etc/sysctl.d
	$(INSTALL_DATA) $(CURDIR)/files/etc/sysctl.d/fips-bridge.conf $(1)/etc/sysctl.d/fips-bridge.conf
	$(INSTALL_DATA) $(CURDIR)/files/etc/sysctl.d/fips-gateway.conf $(1)/etc/sysctl.d/fips-gateway.conf

	# fw4 include: lets fips-gateway's port forwards through the fips zone.
	# One source, installed for the zone's input and forward chains.
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/chain-post/input_fips
	$(INSTALL_DATA) $(CURDIR)/files/usr/share/nftables.d/10-fips-port-forwards.nft $(1)/usr/share/nftables.d/chain-post/input_fips/10-fips-port-forwards.nft
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/chain-post/forward_fips
	$(INSTALL_DATA) $(CURDIR)/files/usr/share/nftables.d/10-fips-port-forwards.nft $(1)/usr/share/nftables.d/chain-post/forward_fips/10-fips-port-forwards.nft
	# fw4 include: refuses ICMPv6 from wan into the mesh, ahead of the stock
	# rule that accepts it into every zone.
	$(INSTALL_DIR) $(1)/usr/share/nftables.d/chain-pre/forward_wan
	$(INSTALL_DATA) $(CURDIR)/files/usr/share/nftables.d/10-fips-wan-icmpv6.nft $(1)/usr/share/nftables.d/chain-pre/forward_wan/10-fips-wan-icmpv6.nft

	# UCI defaults: one-time firewall zone and module setup
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(CURDIR)/files/etc/uci-defaults/90-fips-setup $(1)/etc/uci-defaults/90-fips-setup

	# sysupgrade: preserve /etc/fips/ (config + identity key) across firmware upgrades
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_DATA) $(CURDIR)/files/lib/upgrade/keep.d/fips $(1)/lib/upgrade/keep.d/fips
endef

# A user's edits to the config survive an upgrade.
define Package/fips/conffiles
/etc/fips/fips.yaml
endef

# Maintainer scripts, read from scripts/ so this package runs the same
# postinst and prerm bodies that build-ipk.sh and build-apk.sh install. OpenWrt
# wraps those two in its generated scripts, around default_postinst and
# default_prerm. The preinst is used only here: it keeps fips-gateway disabled
# and stopped through default_postinst's enable-and-start loop.
define Package/fips/preinst
$(file < $(CURDIR)/scripts/preinst)
endef

define Package/fips/postinst
$(file < $(CURDIR)/scripts/postinst)
endef

define Package/fips/prerm
$(file < $(CURDIR)/scripts/prerm)
endef

$(eval $(call BuildPackage,fips))
