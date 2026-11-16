#!/bin/bash
# The apt proxy a CI host offers image builds, as docker build arguments.
#
# Source this file to get CI_BUILD_PROXY, an array to append to a `docker
# build` or `docker compose build` command line:
#   source "$SCRIPT_DIR/../lib/build-proxy.sh"
#   docker build "${CI_BUILD_PROXY[@]}" -t "$tag" "$context"
#
# FIPS_CI_APT_PROXY=http://<host>:<port>, set by the internal builder, becomes
# the http_proxy build argument, and nothing else: Docker predefines
# http_proxy as a build argument, so no Dockerfile declares it, RUN steps see
# it (apt fetches its plain-http mirrors through it), and it is not written
# into the image's configuration, so no container started from the image has
# it. It is never exported here and never passed to `docker run`: the test
# containers' own traffic, cargo and rustup are not to go through the proxy,
# which is why the builder sets this variable rather than the standard ones.
# With FIPS_CI_APT_PROXY unset or empty the array is empty and every build is
# unchanged. Only http_proxy is set, not https_proxy, so HTTPS fetches in a
# build (rustup, crates, Docker Hub) go direct.

# shellcheck disable=SC2034  # read by the scripts that source this file
CI_BUILD_PROXY=()
if [ -n "${FIPS_CI_APT_PROXY:-}" ]; then
    CI_BUILD_PROXY=(--build-arg "http_proxy=$FIPS_CI_APT_PROXY")
fi
