#!/bin/bash
# Tests for ci-local.sh's argument handling: an unknown option or an option
# missing its value is a usage error (exit 2, message on stderr), and --help
# still exits 0 with the usage on stdout. --rerun <suite> rejects an unknown
# suite name and the options it cannot be combined with, before any build;
# --build-only rejects --root-tests and --explorers, whose stages it would
# skip; and --explorers= takes only core or root. --tier takes 1, 2 or 3 and
# refuses every option that changes what runs; --plan needs a tier and prints
# that tier's stages, and no tier a push starts (1 or 2) lists an explorer.
# --part takes one of the three parts of tier 3 and needs that tier, and each
# part's plan lists exactly its own results.
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
    "mutations musl-tests build-integration chaos-tcp-mesh core-explorers root-explorers mutations-explorers build deb-build" \
    --tier 1 --plan
expect_plan "--tier 2 --plan" \
    "root-tests mutations musl-tests build-integration chaos-tcp-mesh rpm-install deb-build" \
    "core-explorers root-explorers mutations-explorers chaos-batch1-tcp-mesh chaos-maelstrom tor-socks5 build" \
    --tier 2 --plan
# The .deb is the release build at tier 2, so it comes first in the build
# stage, before the lints.
check "--tier 2 --plan: deb-build comes before fmt" \
    "$(invoke --tier 2 --plan; d=$(grep -nx deb-build <<<"$OUT" | cut -d: -f1); f=$(grep -nx fmt <<<"$OUT" | cut -d: -f1); [ -n "$d" ] && [ -n "$f" ] && [ "$d" -lt "$f" ] && echo 0 || echo 1)"
expect_plan "--tier 3 --plan" \
    "mutations musl-tests chaos-tcp-mesh core-explorers root-explorers mutations-explorers chaos-batch3-tcp-mesh chaos-maelstrom chaos-maelstrom-sparse chaos-dead-grace-long" \
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
# --part: one share of tier 3, so it needs that tier and a known name; the Tor
# suites go with the chaos part alone.
expect_usage_error "--part without a value" "--part needs a value" --tier 3 --part
expect_usage_error "--part with an unknown name" \
    "--part takes core-explorers, root-explorers or chaos, not: bogus" --tier 3 --part bogus
expect_usage_error "--part without a tier" "--part needs --tier 3" --part chaos
expect_usage_error "--part with --tier 2" "--part needs --tier 3" --tier 2 --part chaos
expect_usage_error "--part --plan without a tier" "--part needs --tier 3" --part chaos --plan
expect_usage_error "--part core-explorers with --with-tor" \
    "--with-tor combines only with --part chaos" --tier 3 --part core-explorers --with-tor
expect_usage_error "--part root-explorers with --with-tor" \
    "--with-tor combines only with --part chaos" --with-tor --part root-explorers --tier 3
expect_usage_error "--part with --slow-tests" \
    "--tier 3 cannot be combined with --slow-tests" --tier 3 --part chaos --slow-tests

# Each part's plan is exactly its own results. The chaos part's count comes
# from ci-local.sh's own arrays: each CI scenario NIGHTLY_CHAOS_RUNS times,
# the long scenarios, and the integration build.
expect_part_plan() {
    local name="$1" want="$2"
    shift 2
    invoke "$@"
    check "$name: exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)" "rc=$RC"
    local got
    got="$(grep -v '^#' <<<"$OUT" | tr '\n' ' ' | sed 's/ $//')"
    check "$name: lists exactly $want" "$([ "$got" = "$want" ] && echo 0 || echo 1)" "got: $got"
    return 0
}
expect_part_plan "--part core-explorers --plan" "core-explorers" \
    --tier 3 --part core-explorers --plan
expect_part_plan "--part root-explorers --plan" "root-explorers mutations-explorers" \
    --tier 3 --part root-explorers --plan
FIPS_CI_TIER=3 expect_part_plan "FIPS_CI_TIER=3 --part root-explorers --plan" \
    "root-explorers mutations-explorers" --part root-explorers --plan
n_chaos=$(invoke --list; grep -c '^    chaos-' <<<"$OUT")
n_runs=$(sed -n 's/^NIGHTLY_CHAOS_RUNS=\([0-9]*\)$/\1/p' "$CI_LOCAL")
n_long=$(sed -n '/^NIGHTLY_LONG=(/,/^)/p' "$CI_LOCAL" | grep -c '^    "')
want_chaos=$(( n_chaos * n_runs + n_long + 1 ))
invoke --tier 3 --part chaos -j 2 --plan
check "--part chaos -j 2 --plan: exits 0" "$([ "$RC" -eq 0 ] && echo 0 || echo 1)" "rc=$RC"
plan_lines="$(grep -v '^#' <<<"$OUT")"
check "--part chaos --plan: lists $want_chaos results ($n_chaos scenarios x $n_runs, $n_long long, the build)" \
    "$([ "$(grep -c . <<<"$plan_lines")" -eq "$want_chaos" ] && [ "$want_chaos" -gt 1 ] && echo 0 || echo 1)" \
    "got $(grep -c . <<<"$plan_lines")"
check "--part chaos --plan: starts with build-integration" \
    "$([ "$(head -n 1 <<<"$plan_lines")" = build-integration ] && echo 0 || echo 1)"
check "--part chaos --plan: lists the batch and the long scenarios" \
    "$(grep -qx chaos-batch1-tcp-mesh <<<"$plan_lines" && grep -qx chaos-dead-grace-long <<<"$plan_lines" && echo 0 || echo 1)"
check "--part chaos --plan: lists no Tor suite" \
    "$(grep -qx tor-socks5 <<<"$plan_lines" && echo 1 || echo 0)"
expect_plan "--part chaos --with-tor --plan" "tor-socks5 tor-directory chaos-maelstrom build-integration" \
    "core-explorers unit-tests ci-parity" --tier 3 --part chaos --with-tor --plan

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
