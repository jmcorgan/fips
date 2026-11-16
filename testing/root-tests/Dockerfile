# The image testing/ci-local.sh runs the root-only unit tests in under --tier
# (root_container), as uid 0 with no network. It holds only what
# testing/root-tests.sh needs besides the test binary, which is mounted in:
# bash and coreutils from the base, ip (iproute2), nft (nftables) and sysctl
# (procps). The binary links only glibc, so the base's glibc must be at least
# the build host's. Tagged fips-root-tests:trixie-1, the image the internal
# builder has run the root tests in since 2026-10-29; bump the tag with any
# change here.
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 nftables procps \
    && rm -rf /var/lib/apt/lists/*
