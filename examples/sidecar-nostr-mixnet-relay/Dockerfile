# Single-container FIPS-over-Nym-mixnet demo.
#
# Everything runs in ONE container: the FIPS daemon, the nym-socks5-client
# mixnet proxy, the strfry Nostr relay, nginx, and dnsmasq. The entrypoint
# starts them in strict order so the SOCKS5 proxy is up before FIPS dials
# its peer through the mixnet.
#
# Platform: the image builds NATIVE for the host. The FIPS daemon must NOT
# run under emulation — Rosetta mis-translates the amd64 ChaCha20-Poly1305
# assembly (ring/BoringSSL), silently failing AEAD on larger frames (bloom
# filter announces are the first casualty). fips is therefore always
# compiled for the native arch.
#
# nym-socks5-client is the official prebuilt amd64 binary (Nym ships no
# other arch). On amd64 hosts it runs natively; on arm64 (Apple Silicon)
# it runs via Docker Desktop's binfmt/Rosetta handler, with the x86-64
# loader + glibc copied in from an amd64 stage. The nym client tolerates
# emulation; fips does not.

# ── Build stage: compile FIPS from source ──
FROM rust:1.94-slim-trixie AS builder

# bluer (BLE) and rustables (nftables) are unconditional dependencies on
# glibc Linux: bluer needs the dbus headers, rustables runs bindgen
# (libclang) against the libnftnl headers.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config libdbus-1-dev libnftnl-dev libclang-dev clang && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY src ./src

RUN cargo build --release && \
    cp target/release/fips target/release/fipsctl target/release/fipstop /usr/local/bin/

# ── strfry stage: collect the binary and its musl runtime ──
# The official strfry image is alpine (musl) based; the runtime stage below
# is debian (glibc), so the musl dynamic loader and the exact set of shared
# libraries strfry links against must come along.
FROM ghcr.io/hoytech/strfry:latest AS strfry
RUN mkdir -p /strfry-libs && \
    ldd /app/strfry | awk '$3 ~ /^\// {print $3}' | xargs -I{} cp {} /strfry-libs/ && \
    cp /lib/ld-musl-*.so.1 /strfry-libs/

# ── nym stage: official prebuilt amd64 binary + its glibc runtime ──
# Pinned amd64-only stage regardless of host arch. Collects the x86-64
# dynamic loader and the binary's library closure so the binary can run
# inside the native (possibly arm64) runtime image via binfmt/Rosetta.
FROM --platform=linux/amd64 debian:trixie-slim AS nym
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
# Bumping the version = edit the tag in this URL.
RUN curl -sSL --retry 3 \
        "https://github.com/nymtech/nym/releases/download/nym-binaries-v2026.11-xynomizithra/nym-socks5-client" \
        -o /nym-socks5-client && \
    chmod +x /nym-socks5-client
RUN mkdir -p /nym-rt/lib64 /nym-rt/libs && \
    cp /lib64/ld-linux-x86-64.so.2 /nym-rt/lib64/ && \
    ldd /nym-socks5-client | awk '$3 ~ /^\// {print $3}' | xargs -I{} cp {} /nym-rt/libs/

# ── Runtime stage ──
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 iputils-ping dnsutils dnsmasq iptables \
        openssh-client openssh-server python3 \
        tcpdump netcat-openbsd curl jq iperf3 nginx && \
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

# nym-socks5-client: prebuilt amd64 binary plus its x86-64 loader/glibc.
# On amd64 these COPYs overwrite identical files; on arm64 they add the
# x86-64 runtime alongside the native one (paths don't collide). The
# version check doubles as a binfmt/Rosetta smoke test on arm64 hosts.
COPY --from=nym /nym-socks5-client /usr/local/bin/nym-socks5-client
COPY --from=nym /nym-rt/lib64/ /lib64/
COPY --from=nym /nym-rt/libs/ /lib/x86_64-linux-gnu/
RUN echo "Installed:" && /usr/local/bin/nym-socks5-client --version

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

# strfry: binary, musl loader, and its libraries in a private directory.
# /etc/ld-musl-<arch>.path tells the musl loader where to search, keeping
# the musl libraries invisible to the system glibc loader.
COPY --from=strfry /app/strfry /usr/local/bin/strfry
COPY --from=strfry /strfry-libs/ /opt/strfry-libs/
RUN mv /opt/strfry-libs/ld-musl-*.so.1 /lib/ && \
    echo "/opt/strfry-libs" > /etc/ld-musl-$(uname -m).path && \
    mkdir -p /usr/src/app/strfry-db && \
    strfry --version

# nginx: reverse proxy port 80 (IPv4 + IPv6) → strfry 127.0.0.1:7777
RUN printf 'server {\n\
    listen 80;\n\
    listen [::]:80;\n\
    location / {\n\
        proxy_pass http://127.0.0.1:7777;\n\
        proxy_http_version 1.1;\n\
        proxy_read_timeout 1d;\n\
        proxy_send_timeout 1d;\n\
        proxy_set_header Upgrade $http_upgrade;\n\
        proxy_set_header Connection "Upgrade";\n\
        proxy_set_header Host $host;\n\
    }\n\
}\n' > /etc/nginx/conf.d/nostr-relay.conf && \
    rm -f /etc/nginx/sites-enabled/default

COPY --from=builder /usr/local/bin/fips /usr/local/bin/fipsctl /usr/local/bin/fipstop /usr/local/bin/

COPY examples/sidecar-nostr-mixnet-relay/entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
