# Unified test image for all FIPS integration test harnesses.
#
# Supports multiple modes via FIPS_TEST_MODE environment variable:
#   default        — static/basic: dnsmasq + sshd + iperf3 + http + fips
#   chaos          — above + ethernet interface wait loop + TCP ECN
#   sidecar        — config from env vars + iptables isolation + fips
#   tor-socks5     — dnsmasq + sshd + fips (tor daemon is separate container)
#   tor-directory  — dnsmasq + tor (directory mode) + wait for .onion + fips

FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping dnsutils \
        openssh-client openssh-server \
        dnsmasq iptables tor \
        iperf3 curl python3 \
        tcpdump netcat-openbsd rsync && \
    rm -rf /var/lib/apt/lists/*

# SSH server with no authentication (test only!)
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

COPY fips fipsctl fipstop /usr/local/bin/
RUN chmod +x /usr/local/bin/fips /usr/local/bin/fipsctl /usr/local/bin/fipstop

# Static web page for HTTP server (chaos/static modes)
RUN printf 'Fuck IPs!\n' > /root/index.html

COPY resolv.conf /etc/resolv.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
