#!/bin/bash
# Mixed-version interop harness: the names and paths one run owns.
#
# Sourced by build-images.sh, generate-configs.sh, interop-test.sh and
# interop-stress.sh after each has set RUNS_BASE, so that every script
# derives the same names from the same settings. Two runs on one host that
# use different FIPS_INTEROP_NAME values (and different subnets) share no
# container, compose project, network, generated config or capture; runs
# that also share FIPS_INTEROP_IMAGE share its three images, read-only.
#
# Environment:
#   FIPS_INTEROP_NAME    Run name (default fips-interop): the container
#                        prefix <name>-<node>, the compose project, and the
#                        per-run directory. The default keeps the paths the
#                        harness has always used.
#   FIPS_INTEROP_IMAGE   Image repository (default: the run name): images
#                        are <image>:a, <image>:b, <image>:c. Set it to the
#                        repository one build-images.sh made to run several
#                        named runs from one build.
#   FIPS_INTEROP_SUBNET  First three octets of the mesh network's /24
#                        (default 172.30.0).
#
# Sets:
#   INTEROP_NAME, INTEROP_IMAGE, INTEROP_SUBNET
#   RUN_BASE     per-run root: RUNS_BASE for the default name, otherwise
#                RUNS_BASE/runs/<name>
#   BUILD_BASE   per-image build root: RUNS_BASE/.build for the default
#                image, otherwise RUNS_BASE/.build/images/<image>
#   GEN_DIR      RUN_BASE/generated-configs
#   REFS_ENV     BUILD_BASE/refs.env

INTEROP_DEFAULT_NAME="fips-interop"

# interop_names: validate the settings and set the names above. Exits the
# calling script on a malformed setting, so no run starts under a name or
# subnet that Docker would read differently. RUNS_BASE comes from the
# caller, and the variables set here are read by it (SC2153, SC2034).
# shellcheck disable=SC2034,SC2153
interop_names() {
    INTEROP_NAME="${FIPS_INTEROP_NAME:-$INTEROP_DEFAULT_NAME}"
    INTEROP_IMAGE="${FIPS_INTEROP_IMAGE:-$INTEROP_NAME}"
    INTEROP_SUBNET="${FIPS_INTEROP_SUBNET:-172.30.0}"
    # Compose project names allow lowercase letters, digits, '-' and '_'
    # and must start with a letter or digit; image repositories take the
    # same set here.
    if ! [[ "$INTEROP_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
        echo "ERROR: FIPS_INTEROP_NAME '$INTEROP_NAME' must match [a-z0-9][a-z0-9_-]*" >&2
        exit 2
    fi
    if ! [[ "$INTEROP_IMAGE" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
        echo "ERROR: FIPS_INTEROP_IMAGE '$INTEROP_IMAGE' must match [a-z0-9][a-z0-9_-]*" >&2
        exit 2
    fi
    interop_check_subnet FIPS_INTEROP_SUBNET "$INTEROP_SUBNET"
    if [ "$INTEROP_NAME" = "$INTEROP_DEFAULT_NAME" ]; then
        RUN_BASE="$RUNS_BASE"
    else
        RUN_BASE="$RUNS_BASE/runs/$INTEROP_NAME"
    fi
    if [ "$INTEROP_IMAGE" = "$INTEROP_DEFAULT_NAME" ]; then
        BUILD_BASE="$RUNS_BASE/.build"
    else
        BUILD_BASE="$RUNS_BASE/.build/images/$INTEROP_IMAGE"
    fi
    GEN_DIR="$RUN_BASE/generated-configs"
    REFS_ENV="$BUILD_BASE/refs.env"
}

# interop_check_subnet <setting> <prefix>: exit unless <prefix> is three
# dotted octets.
interop_check_subnet() {
    local setting="$1" prefix="$2" o
    if ! [[ "$prefix" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "ERROR: $setting '$prefix' must be three octets, e.g. 172.30.0" >&2
        exit 2
    fi
    for o in ${prefix//./ }; do
        if [ "$o" -gt 255 ]; then
            echo "ERROR: $setting '$prefix' has an octet above 255" >&2
            exit 2
        fi
    done
}

# interop_subnet_free <cidr>: return 0 when <cidr> overlaps no Docker
# network's subnet and no host IPv4 route other than the default route;
# otherwise print what it overlaps and return 1. Returns 2 when the
# networks or routes cannot be read, which the caller treats as not free.
interop_subnet_free() {
    local cidr="$1" ids taken
    ids="$(docker network ls -q)" || return 2
    taken="$(
        for id in $ids; do
            docker network inspect --format \
                '{{.Name}}{{range .IPAM.Config}} {{.Subnet}}{{end}}' "$id" || exit 2
        done
        ip -4 route show | awk '$1 != "default" { print "route " $1 }'
    )" || return 2
    TAKEN="$taken" python3 -c '
import ipaddress, os, sys

want = ipaddress.ip_network(sys.argv[1])
hits = []
for line in os.environ["TAKEN"].splitlines():
    name, *nets = line.split()
    for net in nets:
        try:
            have = ipaddress.ip_network(net, strict=False)
        except ValueError:
            continue
        if have.version == want.version and have.overlaps(want):
            hits.append(name + " " + net)
if hits:
    print(str(want) + " overlaps: " + "; ".join(hits))
    sys.exit(1)
' "$cidr"
}
