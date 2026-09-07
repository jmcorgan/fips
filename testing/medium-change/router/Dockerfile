FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping procps tcpdump && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
