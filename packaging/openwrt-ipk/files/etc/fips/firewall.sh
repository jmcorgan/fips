#!/bin/sh
# FIPS firewall rules — accept all traffic on the FIPS TUN interface.
#
# Called by:
#   - /etc/hotplug.d/net/99-fips  when fips0 comes up
#   - the UCI firewall include     on every firewall reload
#
# Supports both fw4 (nftables, OpenWrt 22.03+) and older iptables builds.

TUN="fips0"

if command -v nft >/dev/null 2>&1 && nft list table inet fw4 >/dev/null 2>&1; then
	for chain in input output forward; do
		case "$chain" in
			input|forward)  match="iifname \"$TUN\"" ;;
			output)         match="oifname \"$TUN\"" ;;
		esac
		nft list chain inet fw4 "$chain" 2>/dev/null | grep -q "$match" || \
			nft insert rule inet fw4 "$chain" $match accept comment "\"fips\""
	done
	# Also accept forwarded traffic leaving via fips0
	nft list chain inet fw4 forward 2>/dev/null | grep -q "oifname \"$TUN\"" || \
		nft insert rule inet fw4 forward oifname "$TUN" accept comment '"fips"'
fi

if command -v iptables >/dev/null 2>&1; then
	iptables -C INPUT  -i "$TUN" -j ACCEPT 2>/dev/null || \
		iptables -I INPUT  1 -i "$TUN" -j ACCEPT
	iptables -C OUTPUT -o "$TUN" -j ACCEPT 2>/dev/null || \
		iptables -I OUTPUT 1 -o "$TUN" -j ACCEPT
	iptables -C FORWARD -i "$TUN" -j ACCEPT 2>/dev/null || \
		iptables -I FORWARD 1 -i "$TUN" -j ACCEPT
fi
