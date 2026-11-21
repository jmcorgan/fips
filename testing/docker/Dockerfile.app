# Sidecar companion container: shares the FIPS container's network namespace.
# Provides basic networking tools for testing mesh connectivity.

# Pinned by digest, the same pin as DEBIAN13_SLIM in testing/base-images.env,
# which says why and how to move it.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iproute2 iputils-ping dnsutils iptables \
        openssh-client openssh-server python3 \
        tcpdump netcat-openbsd curl iperf3 && \
    rm -rf /var/lib/apt/lists/*

# SSH server, keys only, configured as in the main test image; nothing here
# starts it. Root has no usable password, keeps Debian's prohibit-password
# default, and password logins are off for every account.
RUN mkdir -p /var/run/sshd && \
    ssh-keygen -A && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config && \
    printf 'PasswordAuthentication no\n' > /etc/ssh/sshd_config.d/keys-only.conf

CMD ["sleep", "infinity"]
