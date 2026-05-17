#!/bin/bash
# End-to-end iperf3 bandwidth test between two boringtun containers.
# Output mirrors testing/static/scripts/iperf-test.sh so the FIPS
# numbers are directly comparable.
set -euo pipefail

DURATION="${DURATION:-10}"
PARALLEL="${PARALLEL:-1}"

echo "=== boringtun iperf3 throughput (single TCP stream, ${DURATION}s) ==="

# Run iperf3 server on alice (background), client on bob.
docker exec -d bt-alice iperf3 -s -1 -B 10.99.0.1 -p 5201
sleep 1

# wait for tun handshake to settle (boringtun + WG keepalive)
sleep 2

# Client: bob → alice over WG (10.99.0.1)
OUT=$(docker exec bt-bob iperf3 -c 10.99.0.1 -p 5201 -t "$DURATION" -P "$PARALLEL" -J)

# Pull SUM bps.
MBPS=$(echo "$OUT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(f\"{d['end']['sum_received']['bits_per_second'] / 1_000_000:.2f}\")")

echo "boringtun bob -> alice : ${MBPS} Mbits/sec"
