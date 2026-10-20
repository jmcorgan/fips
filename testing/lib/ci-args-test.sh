#!/bin/bash
# Tests for ci-local.sh's argument handling: an unknown option or an option
# missing its value is a usage error (exit 2, message on stderr), and --help
# still exits 0 with the usage on stdout. --rerun <suite> rejects an unknown
# suite name and the options it cannot be combined with, before any build.
#
# Every case invokes ci-local.sh with arguments that end during parsing, before
# the load sampler, traps, containers or any build, so the suite is hermetic and
# takes about a second. Should a parse fall through into a real run, cargo,
# docker and sudo are stand-ins that fail at once, and each invocation is
# bounded by a timeout, so the case fails without building or starting anything.
#
# Run:
#   ./ci-args-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CI_LOCAL="$SCRIPT_DIR/../ci-local.sh"

FAILURES=0
OUT_FILE="$(mktemp)"
ERR_FILE="$(mktemp)"
STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$OUT_FILE" "$ERR_FILE" "$STUB_DIR"' EXIT

for tool in cargo docker sudo; do
    printf '#!/bin/sh\necho "ci-args-test: %s called; the parse fell through into a run" >&2\nexit 97\n' \
        "$tool" >"$STUB_DIR/$tool"
    chmod +x "$STUB_DIR/$tool"
done

# Record a single assertion result.
check() {
    local name="$1"
    local ok="$2"      # 0 = pass, anything else = fail
    local detail="${3:-}"
    if [ "$ok" -eq 0 ]; then
        echo "PASS  $name${detail:+  ($detail)}"
    else
        echo "FAIL  $name${detail:+  ($detail)}"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# Run ci-local.sh with the given arguments; sets RC, OUT and ERR.
invoke() {
    RC=0
    PATH="$STUB_DIR:$PATH" timeout 30 bash "$CI_LOCAL" "$@" \
        >"$OUT_FILE" 2>"$ERR_FILE" || RC=$?
    OUT="$(cat "$OUT_FILE")"
    ERR="$(cat "$ERR_FILE")"
    return 0
}

# Assert exit status 2 and that stderr carries the expected text.
expect_usage_error() {
    local name="$1" text="$2"
    shift 2
    invoke "$@"
    check "$name: exits 2" "$([ "$RC" -eq 2 ] && echo 0 || echo 1)" "rc=$RC"
    check "$name: stderr names the problem" \
        "$(grep -qF -- "$text" <<<"$ERR" && echo 0 || echo 1)" "want '$text'"
    return 0
}

# Assert exit status 0 and the usage text on stdout.
expect_help() {
    local name="$1"
    shift
    invoke "$@"
    check "$name: exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)" "rc=$RC"
    check "$name: usage on stdout" \
        "$(grep -qF -- "Usage: ./ci-local.sh" <<<"$OUT" && echo 0 || echo 1)"
    return 0
}

expect_usage_error "unknown option" "Unknown option: --no-such-option" \
    --no-such-option
expect_help "--help" --help
expect_help "-h" -h
expect_usage_error "--only without a value" "--only needs a value" --only
expect_usage_error "--jobs without a value" "--jobs needs a value" --jobs
expect_usage_error "-j without a value" "-j needs a value" -j

expect_usage_error "--rerun without a value" "--rerun needs a value" --rerun
expect_usage_error "--rerun of an unknown suite" "Unknown suite: no-such-suite" \
    --rerun no-such-suite
for opt in --only --build-only --test-only --skip-integration --cross-check \
        --baremetal --slow-tests; do
    args=(--rerun firewall "$opt")
    [ "$opt" = --only ] && args+=(firewall)
    expect_usage_error "--rerun with $opt" \
        "--rerun cannot be combined with $opt" "${args[@]}"
done
# A known suite whose name is derived from its array (nat-, chaos-) passes the
# name check, so the conflict is what gets reported.
expect_usage_error "--rerun nat-cone is a known suite" \
    "--rerun cannot be combined with --build-only" --rerun nat-cone --build-only
expect_usage_error "--rerun chaos-tcp-mesh is a known suite" \
    "--rerun cannot be combined with --build-only" \
    --rerun chaos-tcp-mesh --build-only
# The builder asks for the bare-metal stage by environment, not by option.
FIPS_CI_BAREMETAL=1 expect_usage_error "--rerun with FIPS_CI_BAREMETAL=1" \
    "--rerun cannot be combined with --baremetal" --rerun firewall
FIPS_CI_SLOW_TESTS=1 expect_usage_error "--rerun with FIPS_CI_SLOW_TESTS=1" \
    "--rerun cannot be combined with --slow-tests" --rerun firewall
expect_help "--rerun with --help" --rerun firewall --help

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "All ci-local.sh argument cases passed"
    exit 0
fi
echo "$FAILURES ci-local.sh argument check(s) failed"
exit 1
