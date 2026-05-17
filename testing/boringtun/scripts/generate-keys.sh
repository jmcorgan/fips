#!/bin/bash
# Generate WG keypairs for alice and bob and write the
# generated/peers.env file the docker-compose.yml reads.
# Idempotent: skips if file already exists.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../generated"
ENV_FILE="$OUT_DIR/peers.env"

if [ -f "$ENV_FILE" ]; then
    echo "$ENV_FILE already exists; reusing keys"
    exit 0
fi

mkdir -p "$OUT_DIR"

# Use the built boringtun-test image to generate keys — host may
# not have wireguard-tools installed. The `pubkey` step needs `-i`
# so stdin is piped through; `genkey` doesn't need it but matching
# flags keeps the two calls symmetric.
GEN_CMD="docker run --rm --entrypoint wg boringtun-test:latest"
PUB_CMD="docker run --rm -i --entrypoint wg boringtun-test:latest"

ALICE_PRIV=$($GEN_CMD genkey)
ALICE_PUB=$(printf '%s' "$ALICE_PRIV" | $PUB_CMD pubkey)
BOB_PRIV=$($GEN_CMD genkey)
BOB_PUB=$(printf '%s' "$BOB_PRIV" | $PUB_CMD pubkey)

cat >"$ENV_FILE" <<EOF
ALICE_PRIV=$ALICE_PRIV
ALICE_PUB=$ALICE_PUB
BOB_PRIV=$BOB_PRIV
BOB_PUB=$BOB_PUB
ALICE_WG_IP=10.99.0.1/24
BOB_WG_IP=10.99.0.2/24
PEER_PORT=51820
EOF
chmod 600 "$ENV_FILE"
echo "wrote $ENV_FILE"
