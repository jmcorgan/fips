FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping dnsutils openssh-client openssh-server iperf3 \
        dnsmasq curl python3 rsync && \
    rm -rf /var/lib/apt/lists/*

# Setup SSH server with no authentication (test only!)
RUN mkdir -p /var/run/sshd && \
    ssh-keygen -A && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config && \
    passwd -d root

# dnsmasq: forward .fips to FIPS daemon, everything else to Docker DNS
RUN printf '%s\n' \
    'port=53' \
    'listen-address=127.0.0.1' \
    'bind-interfaces' \
    'server=/fips/127.0.0.1#5354' \
    'server=127.0.0.11' \
    'no-resolv' \
    >> /etc/dnsmasq.conf

COPY fips fipsctl /usr/local/bin/
RUN chmod +x /usr/local/bin/fips /usr/local/bin/fipsctl

# Static web page served via Python HTTP server
RUN printf 'Fuck IPs!\n' > /root/index.html

# Start dnsmasq, SSH server, iperf3, and HTTP server in background, then run FIPS
ENTRYPOINT ["/bin/bash", "-c", "dnsmasq && /usr/sbin/sshd && iperf3 -s -D && python3 -m http.server 8000 -d /root -b :: &>/dev/null & exec fips --config /etc/fips/fips.yaml"]
