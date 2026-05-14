# BoringTun Throughput Baseline

This harness runs two userspace WireGuard peers with Cloudflare BoringTun and
measures single-stream TCP throughput with `iperf3`. It is intended as a simple
baseline for comparing FIPS tunnel throughput against another userspace tunnel.

```bash
docker build -t boringtun-test:latest testing/boringtun
testing/boringtun/scripts/generate-keys.sh
docker compose -f testing/boringtun/docker-compose.yml up -d
testing/boringtun/scripts/bench.sh
docker compose -f testing/boringtun/docker-compose.yml down
```

The generated WireGuard key material is written under
`testing/boringtun/generated/` and is ignored by git.
