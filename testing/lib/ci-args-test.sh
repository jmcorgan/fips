#!/bin/bash
# Tests for ci-local.sh's argument handling: an unknown option or an option
# missing its value is a usage error (exit 2, message on stderr), and --help
# still exits 0 with the usage on stdout. --rerun <suite> rejects an unknown
# suite name and the options it cannot be combined with, before any build;
# --build-only rejects --root-tests and --explorers, whose stages it would
# skip; and --explorers= takes only core or root. --tier takes 1, 2 or 3 and
# refuses every option that changes what runs; --plan needs a tier and prints
# that tier's stages, and no tier a push starts (1 or 2) lists an explorer.
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

# The switches ci-local.sh reads from the environment change what a parse
# rejects first, and the internal builder exports both for its runs. Clear
# them so every case sees only what it sets itself.
unset FIPS_CI_BAREMETAL FIPS_CI_SLOW_TESTS FIPS_CI_ROOT_TESTS FIPS_CI_TIER

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
        --baremetal --slow-tests --root-tests --explorers; do
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
FIPS_CI_ROOT_TESTS=1 expect_usage_error "--rerun with FIPS_CI_ROOT_TESTS=1" \
    "--rerun cannot be combined with --root-tests" --rerun firewall
expect_help "--rerun with --help" --rerun firewall --help

expect_usage_error "--build-only with --root-tests" \
    "--root-tests cannot be combined with --build-only" --build-only --root-tests
expect_usage_error "--root-tests with --build-only" \
    "--root-tests cannot be combined with --build-only" --root-tests --build-only

expect_usage_error "--build-only with --explorers" \
    "--explorers cannot be combined with --build-only" --build-only --explorers
expect_usage_error "--explorers=root with --build-only" \
    "--explorers cannot be combined with --build-only" --explorers=root --build-only
expect_usage_error "--rerun with --explorers=core" \
    "--rerun cannot be combined with --explorers" --rerun firewall --explorers=core
expect_usage_error "--explorers= with an unknown half" \
    "--explorers takes core or root, not: both" --explorers=both
expect_usage_error "--explorers= with no half" \
    "--explorers takes core or root, not: nothing" --explorers=

expect_usage_error "--tier without a value" "--tier needs a value" --tier
expect_usage_error "--tier 4" "--tier takes 1, 2 or 3, not: 4" --tier 4
expect_usage_error "--tier 0" "--tier takes 1, 2 or 3, not: 0" --tier 0
expect_usage_error "--tier two" "--tier takes 1, 2 or 3, not: two" --tier two
FIPS_CI_TIER=9 expect_usage_error "FIPS_CI_TIER=9" "--tier takes 1, 2 or 3, not: 9"
expect_usage_error "--plan without --tier" "--plan needs --tier" --plan
for opt in --build-only --test-only --skip-integration --skip-chaos --baremetal \
        --slow-tests --explorers --explorers=core --cross-check --root-tests \
        --with-tor --only --rerun; do
    args=(--tier 2 "$opt")
    case "$opt" in --only|--rerun) args+=(firewall) ;; esac
    want="${opt%%=*}"
    expect_usage_error "--tier 2 with $opt" "--tier 2 cannot be combined with $want" "${args[@]}"
done
# The option order does not matter, and tier 3 refuses them too, but for Tor.
expect_usage_error "--slow-tests before --tier 3" \
    "--tier 3 cannot be combined with --slow-tests" --slow-tests --tier 3
expect_usage_error "--tier 1 with --with-tor" \
    "--tier 1 cannot be combined with --with-tor" --tier 1 --with-tor

# --plan for each tier: exit 0, nothing built (the stubs would exit 97), and
# the stages that tell the tiers apart.
expect_plan() {
    local name="$1" want="$2" refuse="$3"
    shift 3
    invoke "$@"
    check "$name: exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)" "rc=$RC"
    local missing=() present=() w
    for w in $want; do grep -qxF -- "$w" <<<"$OUT" || missing+=("$w"); done
    for w in $refuse; do grep -qxF -- "$w" <<<"$OUT" && present+=("$w"); done
    check "$name: lists $want" "${#missing[@]}" "missing: ${missing[*]:-none}"
    check "$name: does not list $refuse" "${#present[@]}" "present: ${present[*]:-none}"
    return 0
}
expect_plan "--tier 1 --plan" \
    "ci-parity core-baremetal cross-check-x86_64-apple-darwin unit-tests core-fence-tests known-defect release-test-compile root-tests" \
    "mutations musl-tests build-integration chaos-tcp-mesh core-explorers root-explorers" \
    --tier 1 --plan
expect_plan "--tier 2 --plan" \
    "root-tests mutations musl-tests build-integration chaos-tcp-mesh rpm-install" \
    "core-explorers root-explorers chaos-batch1-tcp-mesh chaos-maelstrom tor-socks5" \
    --tier 2 --plan
expect_plan "--tier 3 --plan" \
    "mutations musl-tests chaos-tcp-mesh core-explorers root-explorers chaos-batch3-tcp-mesh chaos-maelstrom chaos-maelstrom-sparse chaos-dead-grace-long" \
    "tor-socks5" \
    --tier 3 --plan
expect_plan "--tier 3 --with-tor --plan" "tor-socks5 tor-directory core-explorers" "" \
    --plan --with-tor --tier 3
FIPS_CI_TIER=1 expect_plan "FIPS_CI_TIER=1 --plan" "root-tests" "mutations core-explorers" --plan
# A tier overrides the builder's environment switches rather than refusing
# them, and says so.
FIPS_CI_SLOW_TESTS=1 FIPS_CI_ROOT_TESTS=1 expect_plan "--tier 1 under FIPS_CI_SLOW_TESTS=1" \
    "root-tests" "mutations" --tier 1 --plan
check "--tier 1 under FIPS_CI_SLOW_TESTS=1: says the switches are ignored" \
    "$(grep -qF -- "FIPS_CI_* switches in the environment are ignored" <<<"$ERR" && echo 0 || echo 1)"
check "--tier 1 --plan: core-fence-tests without slow-tests" \
    "$(invoke --tier 1 --plan; grep -qF -- "slow-tests feature" <<<"$OUT" && echo 1 || echo 0)"
check "--tier 2 --plan: core-fence-tests with slow-tests" \
    "$(invoke --tier 2 --plan; grep -qF -- "core-fence-tests runs with fips-core's slow-tests feature" <<<"$OUT" && echo 0 || echo 1)"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "All ci-local.sh argument cases passed"
    exit 0
fi
echo "$FAILURES ci-local.sh argument check(s) failed"
exit 1
