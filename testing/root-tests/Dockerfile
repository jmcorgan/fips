# The image testing/ci-local.sh runs the root-only unit tests in under --tier
# (root_container), as uid 0 with no network. It holds only what
# testing/root-tests.sh needs besides the test binary, which is mounted in:
# bash and coreutils from the base, ip (iproute2), nft (nftables) and sysctl
# (procps). The binary links only glibc, so the base's glibc must be at least
# the build host's. ci-local.sh tags it fips-root-tests:<the first 12 hex
# digits of this file's sha256>, so any change here builds a new image on a
# host that has the old one.
# Pinned by digest, the same pin as DEBIAN13_SLIM in testing/base-images.env,
# which says why and how to move it.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 nftables procps \
    && rm -rf /var/lib/apt/lists/*
