FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping dnsutils && \
    rm -rf /var/lib/apt/lists/*

COPY fips /usr/local/bin/
RUN chmod +x /usr/local/bin/fips

ENTRYPOINT ["fips", "--config", "/etc/fips/fips.yaml"]
