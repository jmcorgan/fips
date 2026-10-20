#!/bin/bash
# ── Known-defect lane ───────────────────────────────────────────────────────
# A test that asserts the correct behaviour and fails today is kept, ignored,
# as the record of a defect not yet fixed. Ignored, it runs nowhere, so the
# day the defect is fixed nothing notices and the test never starts gating.
# This lane runs every known-defect entry of testing/ignored-tests.txt and
# expects it to fail. A known-defect test that passes reds the lane: remove
# its ignore and its inventory line in the change that fixed it, so it gates
# from then on.
#
# It also lists the ignored tests of each library test binary and reds on
# one the inventory does not name by its full test path. That is the half of
# the inventory check testing/check-ignored-tests.py cannot do statically:
# the module path of a test depends on `#[path]` attributes, so only the
# build knows it. Tests the host does not compile (the macOS hardware tests
# on Linux) are not listed and are checked statically only.
#
# Each test runs its binary directly, under `timeout` with
# FIPS_KNOWN_DEFECT_TIMEOUT seconds (default 120), so a hang is killed with
# the process. A known-defect test that times out is counted as still
# failing, since a defect can be a hang.
#
# Exit 0 = every known-defect test still fails and every listed ignored test
# is inventoried. Exit 1 = one passed, ran nothing, or a listed ignored test
# is missing from the inventory; every problem is printed. Exit 2 = the lane
# could not run (build failed, binaries not found, inventory unreadable);
# never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INVENTORY="$SCRIPT_DIR/ignored-tests.txt"
LIMIT="${FIPS_KNOWN_DEFECT_TIMEOUT:-120}"

cd "$PROJECT_ROOT" || exit 2
[[ -r "$INVENTORY" ]] || { echo "known-defect-lane: cannot read $INVENTORY" >&2; exit 2; }

# The library test executable of each package, from cargo's own build report,
# found by library target name: `fips` is the fips-mesh package's library and
# `fips_core` the core's.
declare -A BIN
build_json=$(cargo test --workspace --lib --no-run --message-format=json) || {
    echo "known-defect-lane: building the library tests failed" >&2
    exit 2
}
while IFS=$'\t' read -r pkg exe; do
    BIN[$pkg]=$exe
done < <(python3 -c '
import json, sys
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("reason") == "compiler-artifact" and msg.get("executable") \
            and "lib" in msg["target"]["kind"]:
        pkg = {"fips": "fips-mesh", "fips_core": "fips-core"}.get(msg["target"]["name"])
        if pkg:
            print(pkg + "\t" + msg["executable"])
' <<<"$build_json")
for pkg in fips-mesh fips-core; do
    if [[ -z "${BIN[$pkg]:-}" || ! -x "${BIN[$pkg]}" ]]; then
        echo "known-defect-lane: no library test binary found for $pkg" >&2
        exit 2
    fi
done

problems=0
problem() {
    echo "known-defect-lane: $*"
    problems=$((problems + 1))
    return 0
}

# Every ignored test the host compiles must be inventoried under its path.
for pkg in fips-mesh fips-core; do
    listed=$("${BIN[$pkg]}" --list --ignored --format terse) || {
        echo "known-defect-lane: listing $pkg's ignored tests failed" >&2
        exit 2
    }
    while read -r name; do
        [[ -z "$name" ]] && continue
        if ! awk -v c="$pkg" -v t="$name" \
            '!/^[[:space:]]*#/ && $2 == c && $3 == t { found = 1 } END { exit !found }' \
            "$INVENTORY"; then
            problem "$pkg: ignored test $name is not in the inventory under that path"
        fi
    done < <(sed -n 's/: test$//p' <<<"$listed")
done

# Every known-defect test must still fail.
ran=0
while read -r pkg name; do
    ran=$((ran + 1))
    out=$(timeout -k 5 "$LIMIT" "${BIN[$pkg]}" --ignored --exact "$name" 2>&1)
    rc=$?
    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        echo "known-defect-lane: $name still fails (timed out after ${LIMIT}s)"
    elif grep -q '^test result: .* 1 failed;' <<<"$out"; then
        echo "known-defect-lane: $name still fails"
    elif grep -q '^test result: ok\. 1 passed;' <<<"$out"; then
        problem "$name now passes: remove its ignore and its inventory line"
    else
        problem "$name did not run as one test (rc $rc); check its path in the inventory"
    fi
done < <(awk '!/^[[:space:]]*#/ && $1 == "known-defect" { print $2, $3 }' "$INVENTORY")

if [[ $problems -gt 0 ]]; then
    echo "known-defect-lane: $problems problem(s)"
    exit 1
fi
echo "known-defect-lane: $ran known-defect test(s) still fail; every listed ignored test is inventoried"
exit 0
