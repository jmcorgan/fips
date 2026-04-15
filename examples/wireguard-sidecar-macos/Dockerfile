FROM fips-test:latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends vim wireguard-tools && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint-sidecar.sh /usr/local/bin/entrypoint-sidecar.sh
RUN chmod +x /usr/local/bin/entrypoint-sidecar.sh

ENTRYPOINT ["/usr/local/bin/entrypoint-sidecar.sh"]
