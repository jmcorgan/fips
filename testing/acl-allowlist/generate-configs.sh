#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GENERATED_DIR="$SCRIPT_DIR/generated-configs"

write_file() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    cat > "$path"
}

write_hosts_file() {
    local node="$1"
    write_file "$GENERATED_DIR/$node/hosts" <<'EOF'
node-a npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m
node-b npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le
node-c npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6
node-d npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl
node-e npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6
node-f npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c
EOF
}

echo "Generating ACL allowlist fixtures..."
rm -rf "$GENERATED_DIR"

write_file "$GENERATED_DIR/node-a/fips.yaml" <<'EOF'
node:
  identity:
    persistent: true

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le"
    alias: "node-b"
    addresses:
      - transport: udp
        addr: "172.31.0.11:2121"
    connect_policy: auto_connect
  - npub: "npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6"
    alias: "node-c"
    addresses:
      - transport: udp
        addr: "172.31.0.12:2121"
    connect_policy: auto_connect
  - npub: "npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl"
    alias: "node-d"
    addresses:
      - transport: udp
        addr: "172.31.0.13:2121"
    connect_policy: auto_connect
  - npub: "npub1x5z9rwzzm26q9verutx4aajhf2zw2pyp34c6whhde2zduxqav40qgq36l6"
    alias: "node-e"
    addresses:
      - transport: udp
        addr: "172.31.0.14:2121"
    connect_policy: auto_connect
  - npub: "npub1ytrut7gjncn2zfnhn56c0zgftf0w6p99gf6fu8j73hzw5603zglqc9av6c"
    alias: "node-f"
    addresses:
      - transport: udp
        addr: "172.31.0.15:2121"
    connect_policy: auto_connect
EOF

write_file "$GENERATED_DIR/node-a/fips.key" <<'EOF'
0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
EOF

write_file "$GENERATED_DIR/node-a/peers.allow" <<'EOF'
node-a
node-b
node-e
node-f
EOF

write_file "$GENERATED_DIR/node-a/peers.deny" <<'EOF'
# Intentionally empty.
EOF

write_file "$GENERATED_DIR/node-b/fips.yaml" <<'EOF'
node:
  identity:
    persistent: true

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
    alias: "node-a"
    addresses:
      - transport: udp
        addr: "172.31.0.10:2121"
    connect_policy: auto_connect
  - npub: "npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6"
    alias: "node-c"
    addresses:
      - transport: udp
        addr: "172.31.0.12:2121"
    connect_policy: auto_connect
  - npub: "npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl"
    alias: "node-d"
    addresses:
      - transport: udp
        addr: "172.31.0.13:2121"
    connect_policy: auto_connect
EOF

write_file "$GENERATED_DIR/node-b/fips.key" <<'EOF'
b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0
EOF

write_file "$GENERATED_DIR/node-b/peers.allow" <<'EOF'
node-a
node-b
node-e
node-f
EOF

write_file "$GENERATED_DIR/node-b/peers.deny" <<'EOF'
# Intentionally empty.
EOF

write_file "$GENERATED_DIR/node-c/fips.yaml" <<'EOF'
node:
  identity:
    persistent: true

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
    alias: "node-a"
    addresses:
      - transport: udp
        addr: "172.31.0.10:2121"
    connect_policy: auto_connect
EOF

write_file "$GENERATED_DIR/node-c/fips.key" <<'EOF'
c102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc0
EOF

write_file "$GENERATED_DIR/node-c/peers.allow" <<'EOF'
node-a
node-b
node-c
node-d
node-e
node-f
EOF

write_file "$GENERATED_DIR/node-c/peers.deny" <<'EOF'
# Intentionally empty.
EOF

write_file "$GENERATED_DIR/node-d/fips.yaml" <<'EOF'
node:
  identity:
    persistent: true

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
    alias: "node-a"
    addresses:
      - transport: udp
        addr: "172.31.0.10:2121"
    connect_policy: auto_connect
EOF

write_file "$GENERATED_DIR/node-d/fips.key" <<'EOF'
d102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fd0
EOF

write_file "$GENERATED_DIR/node-d/peers.allow" <<'EOF'
node-a
node-b
node-c
node-d
node-e
node-f
EOF

write_file "$GENERATED_DIR/node-d/peers.deny" <<'EOF'
# Intentionally empty.
EOF

write_file "$GENERATED_DIR/node-e/fips.yaml" <<'EOF'
node:
  identity:
    persistent: true

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
    alias: "node-a"
    addresses:
      - transport: udp
        addr: "172.31.0.10:2121"
    connect_policy: auto_connect
EOF

write_file "$GENERATED_DIR/node-e/fips.key" <<'EOF'
nsec1egyrmekfw3u4l88v8zhrak9uht503s2kvn9v49tqgp6c5l2yuxgsv386l0
EOF

write_file "$GENERATED_DIR/node-f/fips.yaml" <<'EOF'
node:
  identity:
    persistent: true

tun:
  enabled: true
  name: fips0
  mtu: 1280

dns:
  enabled: true
  bind_addr: "127.0.0.1"

transports:
  udp:
    bind_addr: "0.0.0.0:2121"

peers:
  - npub: "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
    alias: "node-a"
    addresses:
      - transport: udp
        addr: "172.31.0.10:2121"
    connect_policy: auto_connect
EOF

write_file "$GENERATED_DIR/node-f/fips.key" <<'EOF'
nsec1afh3nysthqh47awpdewcw59wvvp499f8dvlyclmnv4gvpxdk56dsa6eqsn
EOF

write_hosts_file node-a
write_hosts_file node-b
write_hosts_file node-c
write_hosts_file node-d
write_hosts_file node-e
write_hosts_file node-f

echo "ACL allowlist fixtures written to $GENERATED_DIR"
