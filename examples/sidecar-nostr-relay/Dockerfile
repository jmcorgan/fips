# ── Build stage: compile FIPS from source ──
FROM rust:1.94-slim-trixie AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY src ./src

RUN cargo build --release && \
    cp target/release/fips target/release/fipsctl target/release/fipstop /usr/local/bin/

# ── Runtime stage ──
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 iputils-ping dnsutils dnsmasq iptables \
        openssh-client openssh-server python3 \
        tcpdump netcat-openbsd curl iperf3 && \
    rm -rf /var/lib/apt/lists/*

# Install nak (Nostr Army Knife) — detect arch and download the correct binary.
# Asset naming: nak-<version>-linux-<arch>
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64)   NAK_ARCH="linux-amd64" ;; \
        arm64)   NAK_ARCH="linux-arm64" ;; \
        armhf)   NAK_ARCH="linux-arm" ;; \
        *)       echo "Unsupported arch: $ARCH" && exit 1 ;; \
    esac && \
    NAK_VERSION=$(curl -sSL --retry 3 \
        "https://api.github.com/repos/fiatjaf/nak/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/') && \
    echo "Installing nak ${NAK_VERSION} for ${NAK_ARCH}" && \
    curl -sSL --retry 3 \
        "https://github.com/fiatjaf/nak/releases/download/${NAK_VERSION}/nak-${NAK_VERSION}-${NAK_ARCH}" \
        -o /usr/local/bin/nak && \
    chmod +x /usr/local/bin/nak && \
    nak --version

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

COPY --from=builder /usr/local/bin/fips /usr/local/bin/fipsctl /usr/local/bin/fipstop /usr/local/bin/

COPY examples/sidecar-nostr-relay/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
