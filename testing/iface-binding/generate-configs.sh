#!/bin/bash
# Generate fixtures for the dynamic interface binding integration test.
#
# Two FIPS nodes, each with two Ethernet transports and nothing else:
#
#   lab   ve-lab0      required  — does not exist when the daemon starts; the
#                                  harness creates the veth pair afterwards
#   dock  fips-dock0   optional  — never exists, on any host, ever
#
# Plus a third node whose single required interface exists *before* its daemon
# starts — the one ordering the other two cannot produce, and the one that
# `start_async`'s inline bind takes. See node-c in test.sh case (f).
#
# There is deliberately no UDP transport. A node whose only transports are
# interface-bound is the case that used to be unrecoverable: every transport
# skipped at start, nothing retried, and the node up and deaf.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Scoped by the per-run suffix because this directory is wiped and rewritten
# below: two runs sharing one output directory would delete each other's
# fixtures out from under running containers.
GENERATED_DIR="$SCRIPT_DIR/generated-configs${FIPS_CI_NAME_SUFFIX:-}"

# Deterministic test identities (mirrors the firewall/acl-allowlist style).
KEY_A="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
KEY_B="b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0"
KEY_C="c102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc0"

write_file() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    cat > "$path"
}

# Peers are found by beacon, not configured: a MAC address that does not exist
# until the harness creates the veth pair cannot be written into a config file
# ahead of time. Discovery over the late-bound interface is part of what the
# suite asserts.
write_node_config() {
    write_file "$GENERATED_DIR/$1/fips.yaml" <<EOF
node:
  identity:
    persistent: true

# No TUN and no DNS: this suite is about transport binding, and every extra
# child is another way for a failure to be misattributed.
tun:
  enabled: false

dns:
  enabled: false

transports:
  ethernet:
    lab:
      interface: "$LAB_IFACE"
      listen: true
      announce: true
      auto_connect: true
      accept_connections: true
      # Fast beacons so peering after a late bind is observed in seconds
      # rather than in the 30 s production default.
      beacon_interval_secs: 2
    dock:
      interface: "$DOCK_IFACE"
      # Absence is normal for this one, so it must never move node health.
      optional: true
      listen: true
      announce: true
      auto_connect: true
      accept_connections: true
      beacon_interval_secs: 2

peers: []
EOF
}

# node-c: one required interface, present at daemon start.
#
# The other two nodes can only ever reach `Present` through the binder loop,
# because their interface does not exist until the harness makes it. That left
# the inline bind in `start_async` — the ordinary case on a booted router —
# with no coverage at all, which is exactly where the churn guard went unseeded
# and the first detach stopped reaching node health.
write_boot_node_config() {
    write_file "$GENERATED_DIR/node-c/fips.yaml" <<EOF
node:
  identity:
    persistent: true

tun:
  enabled: false

dns:
  enabled: false

transports:
  ethernet:
    boot:
      interface: "$BOOT_IFACE"
      listen: true
      announce: true
      auto_connect: true
      accept_connections: true
      beacon_interval_secs: 2

peers: []
EOF
}

LAB_IFACE="${LAB_IFACE:-ve-lab0}"
DOCK_IFACE="${DOCK_IFACE:-fips-dock0}"
BOOT_IFACE="${BOOT_IFACE:-ve-boot0}"

echo "Generating interface-binding fixtures..."
rm -rf "$GENERATED_DIR"

write_node_config node-a
write_file "$GENERATED_DIR/node-a/fips.key" <<EOF
$KEY_A
EOF

write_node_config node-b
write_file "$GENERATED_DIR/node-b/fips.key" <<EOF
$KEY_B
EOF

write_boot_node_config
write_file "$GENERATED_DIR/node-c/fips.key" <<EOF
$KEY_C
EOF

echo "Interface-binding fixtures written to $GENERATED_DIR"
