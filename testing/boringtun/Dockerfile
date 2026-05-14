# Minimal boringtun-cli image for throughput benchmarking against FIPS.
# Userspace WireGuard (boringtun) + wireguard-tools + iperf3 in one
# image. Run two containers on a docker bridge, configure a WG peer
# between them, then iperf3 client→server across the tunnel.

FROM rust:1-bookworm AS build
# 0.6.0 (crates.io HEAD) is from 2022 and turns in ~1.7 Mbps in
# this harness — clearly broken. Pull the boringtun-cli binary from
# the cloudflare HEAD instead; it gets the post-0.6 perf fixes and
# the multi-threaded recv loop.
RUN git clone --depth 1 https://github.com/cloudflare/boringtun /usr/src/boringtun \
    && cargo install --path /usr/src/boringtun/boringtun-cli

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iperf3 \
        iproute2 \
        wireguard-tools \
        iputils-ping \
        netcat-openbsd \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/cargo/bin/boringtun-cli /usr/local/bin/boringtun-cli
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
