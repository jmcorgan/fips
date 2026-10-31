#!/bin/bash
# Shared helpers for building test images and starting test containers.
#
# Source this file to get dump_output(), run_quiet(), build_inline(),
# retry_build(), budget_allows_retry() and shared_tmpdir(), and the CI_LABELS
# array:
#   source "$SCRIPT_DIR/../lib/image-build.sh"
#   echo "$dockerfile" | run_quiet "docker build -t $tag" \
#       docker build -t "$tag" -f - "$REPO_ROOT"
#   retry_build "docker build $tag" docker build -t "$tag" "$context"
#   dir="$(shared_tmpdir --sweep "$REPO_ROOT/target" my-suite)" || exit 2
#   docker run -d "${CI_LABELS[@]}" --name "$name" "$image"
#
# A build or a container start that fails for a reason outside the project,
# such as a registry timeout, is indistinguishable from one the project caused
# unless its output survives. dump_output and run_quiet keep a command quiet
# when it succeeds and print everything it said when it fails.
#
# Image builds reach Docker Hub, ghcr.io and distribution mirrors, and every one
# of those has timed out or served a truncated file in CI for a few seconds at a
# time. retry_build runs a whole build again after such a failure, so the base
# image is resolved again and each RUN step that fetched packages runs again.

# The labels every container, network, volume and per-run image a suite
# creates must carry. The generic label marks the resource as CI's, and the
# run label names the run, because the generic one is shared by every run on
# the host: ci-local.sh's teardown reaps by the run label alone
# (ci-cleanup.sh --run-id), so a resource with only the generic label outlives
# a run that ended before the suite's own cleanup ran, and the builder's orphan
# sweep, which skips while any generic-labelled container is up, then stops
# for every later run as well. ci-local.sh exports FIPS_CI_RUN_ID; a hand run
# gets "manual". testing/check-ci-labels.py fails a docker command, or an
# array of its arguments, that carries the generic label without the run label,
# and a container, network or volume created under testing/ or packaging/
# without the run label at all.
#
# Not for an image every run shares under one fixed tag: a concurrent run's
# teardown would remove that tag from under this run. Label only what is
# this run's alone.
# shellcheck disable=SC2034  # read by the sourcing harness, not within this file
CI_LABELS=(
    --label com.corganlabs.fips-ci=1
    --label "com.corganlabs.fips-ci.run=${FIPS_CI_RUN_ID:-manual}"
)

# Emit a captured output file to stderr, delimited and labelled with the
# command it came from. Callers use this only on failure: a command that
# succeeds leaves no trace, so the suite stays quiet when it is green.
dump_output() {
    local label="$1" file="$2"
    {
        echo "  --- $label failed; captured output follows ---"
        if [ -s "$file" ]; then
            cat "$file"
        else
            echo "  (no output)"
        fi
        echo "  --- end captured output ---"
    } >&2
}

# Run a command with both streams captured. Discard the capture on success;
# on failure emit it, so the reason a build or a container start died is not
# thrown away. Stdin is inherited, so a caller may pipe into it.
run_quiet() {
    local label="$1"
    shift
    local out rc=0
    out=$(mktemp)
    "$@" >"$out" 2>&1 || rc=$?
    [ "$rc" -eq 0 ] || dump_output "$label" "$out"
    rm -f "$out"
    return "$rc"
}

# Build TAG from the Dockerfile text DOCKERFILE with context CONTEXT, output
# captured by run_quiet. The text is an argument rather than stdin, so that
# retry_build can run the build again: a pipe can be read only once. Any
# further arguments go to `docker build`, such as "${CI_LABELS[@]}".
build_inline() {
    local tag="$1" dockerfile="$2" context="$3"
    shift 3
    echo "$dockerfile" | run_quiet "docker build -t $tag" \
        docker build -t "$tag" "$@" -f - "$context"
}

# Run an image build, and run it again after a failure, up to three attempts
# with 10 s and then 20 s between them. Use it for builds only: a test or a
# container start that fails is a result, and running it again would hide it.
#
# Every message goes to stderr, because some callers promise that their stdout
# holds only their result. A first-attempt success prints nothing. A success
# after a failure says so, and on GitHub Actions also raises a warning on the
# run summary, so a recovered failure is still counted. Returns the last
# attempt's exit status.
#
# When FIPS_CI_DEADLINE is set (epoch seconds; testing/rpm-install/test.sh is
# the only harness that sets it), it is the end of the run's network budget:
# the first attempt always runs, and a retry that would start with under 30 s
# left is not started. Unset, nothing here changes.
retry_build() {
    local label="$1"
    shift
    local attempts=3 attempt=1 rc=0 wait
    while true; do
        rc=0
        if "$@"; then
            if [ "$attempt" -gt 1 ]; then
                echo "image-build: $label recovered on attempt $attempt of $attempts" >&2
                if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
                    echo "::warning::image-build: $label recovered on attempt $attempt of $attempts" >&2
                fi
            fi
            return 0
        else
            rc=$?
        fi
        if [ "$attempt" -ge "$attempts" ]; then
            echo "image-build: $label failed on all $attempts attempts (last exit $rc)" >&2
            return "$rc"
        fi
        wait=$((attempt * 10))
        if [ -n "${FIPS_CI_DEADLINE:-}" ] && ! budget_allows_retry "$label" "$wait"; then
            return "$rc"
        fi
        echo "image-build: $label failed on attempt $attempt of $attempts (exit $rc); retrying in ${wait}s" >&2
        sleep "$wait"
        attempt=$((attempt + 1))
    done
}

# Whether retry_build may start another attempt of LABEL after a pause of WAIT
# seconds, given FIPS_CI_DEADLINE, and why not when it may not. A deadline that
# is not an integer refuses the retry too: it can only be a broken hand-off,
# and retrying would run past whatever budget was meant.
budget_allows_retry() {
    local label="$1" wait="$2" left
    if ! [[ "$FIPS_CI_DEADLINE" =~ ^[0-9]+$ ]]; then
        echo "image-build: $label not retried: FIPS_CI_DEADLINE is not an integer ('$FIPS_CI_DEADLINE')" >&2
        return 1
    fi
    left=$((FIPS_CI_DEADLINE - $(date +%s)))
    if [ $((left - wait)) -lt 30 ]; then
        echo "image-build: $label not retried: the run's budget ends in ${left}s" >&2
        return 1
    fi
    return 0
}

# Create a temporary directory that can be a bind-mount source, and print its
# path: shared_tmpdir [--sweep] ROOT NAME makes ROOT/NAME.XXXXXX.
#
# Use this, never a bare `mktemp -d`, for any directory or file that becomes a
# `docker run -v` source; testing/check-mount-tmpdir.py enforces it. A
# directory that stays on this side of the boundary, such as a build context
# the docker CLI reads itself, does not need it.
#
# A bind-mount source is resolved by the Docker daemon in the host's mount
# namespace, never in the caller's. Under a service sandbox that gives the unit
# a private /tmp -- systemd's PrivateTmp=, which the CI worker on the builder
# sets -- a path from `mktemp -d` exists only in the caller's namespace. The
# daemon finds nothing at it and creates an empty directory instead, so a
# socket the container binds lands where the caller cannot see it, a file the
# container writes is never read back, and a file mount such as fips.yaml
# arrives as a directory, which the daemon reports as EISDIR. None of these
# says what happened. The suites failed all three ways on the builder while
# passing on GitHub, whose runner has no such sandbox.
#
# So ROOT must be a path that resolves the same in both namespaces: the
# worktree (its target/ is ignored), or a directory that is already a mount
# source, such as a packaging script's output directory. The helper does not
# check where ROOT is, because a caller's --output-dir may legitimately be
# under /tmp on a host without a private /tmp; the guard instead refuses a
# literal /tmp or $TMPDIR root.
#
# NAME is the directory's prefix and carries any leading dot. --sweep first
# removes ROOT/NAME.* directories older than two hours, for a persistent ROOT
# whose earlier runs may have been killed before their own cleanup ran. Two
# hours is far above any run and far below the interval at which leftovers
# would pile up. The swept trees can hold files a container wrote as root, so
# a stale directory that cannot be removed is left alone silently: the sweep
# never prints and never decides the exit status. Do not sweep inside a
# per-run ROOT that the caller's own trap removes; there it gains nothing and
# could remove a live sibling in a run longer than two hours.
#
# Returns 2 for a bad argument, 1 if ROOT or the directory cannot be created.
shared_tmpdir() {
    local sweep=0
    if [ "${1:-}" = "--sweep" ]; then
        sweep=1
        shift
    fi
    local root="${1:-}" name="${2:-}"
    if [ -z "$root" ] || [ -z "$name" ] || [[ "$name" == */* ]]; then
        echo "shared_tmpdir: usage: shared_tmpdir [--sweep] ROOT NAME (NAME without '/')" >&2
        return 2
    fi
    mkdir -p "$root" || return 1
    if [ "$sweep" -eq 1 ]; then
        find "$root" -maxdepth 1 -type d -name "$name.*" -mmin +120 -exec rm -rf {} + 2>/dev/null || :
    fi
    mktemp -d "$root/$name.XXXXXX" || return 1
}
