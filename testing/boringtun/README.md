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

For FIPS-to-FIPS revision comparisons, use the static topology comparison
script:

```bash
testing/static/scripts/iperf-compare-refs.sh origin/master HEAD mesh
```

That script builds each ref into a separate `fips-test:*` image, runs the
same static `iperf3` topology against both images, and prints a bandwidth
summary for each path. Override `DURATION`, `PARALLEL`, `SETTLE_SECONDS`, or
`IPERF_TIMEOUT` in the environment when needed. Set `RUNS=3` or similar to
repeat each ref and print aggregate results.
