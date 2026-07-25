#!/bin/bash
# Generate fixtures for the firewall integration test.
#
# Two FIPS nodes (a, b). node-b mounts the production fips.nft baseline
# plus a single drop-in (.nft) under /etc/fips/fips.d/ that allows TCP
# port 22 inbound — the test asserts this is honored. node-a is a
# probe-only node with no firewall.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Scoped by the per-run suffix because this directory is wiped and rewritten
# below: two runs sharing one output directory would delete each other's
# fixtures out from under running containers. Unset (a bare hand run, or the
# GitHub-hosted path) it collapses to the historical "generated-configs".
GENERATED_DIR="$SCRIPT_DIR/generated-configs${FIPS_CI_NAME_SUFFIX:-}"

# Deterministic test identities (mirrors the acl-allowlist style).
NPUB_A="npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
KEY_A="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

NPUB_B="npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le"
KEY_B="b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0"

write_file() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    cat > "$path"
}

write_hosts_file() {
    local node="$1"
    write_file "$GENERATED_DIR/$node/hosts" <<EOF
node-a $NPUB_A
node-b $NPUB_B
EOF
}

# Peers are addressed by the docker hostname the compose file assigns (host-a,
# host-b), not by IP. The network requests no subnet so that two concurrent
# runs cannot collide on one address range, which means neither node's address
# is knowable before `docker compose up`.
echo "Generating firewall fixtures..."
rm -rf "$GENERATED_DIR"

# ── node-a ────────────────────────────────────────────────────────────
write_file "$GENERATED_DIR/node-a/fips.yaml" <<EOF
node:
  identity:
    persistent: true

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "$NPUB_B"
    alias: "node-b"
    addresses:
      - transport: udp
        addr: "host-b:2121"
    connect_policy: auto_connect
EOF

write_file "$GENERATED_DIR/node-a/fips.key" <<EOF
$KEY_A
EOF

# ── node-b ────────────────────────────────────────────────────────────
write_file "$GENERATED_DIR/node-b/fips.yaml" <<EOF
node:
  identity:
    persistent: true

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "$NPUB_A"
    alias: "node-a"
    addresses:
      - transport: udp
        addr: "host-a:2121"
    connect_policy: auto_connect
EOF

write_file "$GENERATED_DIR/node-b/fips.key" <<EOF
$KEY_B
EOF

# ── node-b drop-in: allow inbound TCP/22 (Case d) ─────────────────────
# The simplest possible operator-supplied allowance, matching the
# fips.nft header example. The test asserts this rule unblocks an
# otherwise-DROP'd TCP/22 SYN.
write_file "$GENERATED_DIR/node-b/fips.d/services.nft" <<'EOF'
tcp dport 22 accept
EOF

write_hosts_file node-a
write_hosts_file node-b

echo "Firewall fixtures written to $GENERATED_DIR"
