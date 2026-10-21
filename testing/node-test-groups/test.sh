#!/bin/bash
# ── Fixture tests for check-node-test-groups.py ─────────────────────────────
# The check decides which node tests nextest runs one at a time. If it stopped
# seeing a socket module it would pass, the module would run beside the others
# and the first sign would be a dropped handshake on a loaded runner, months
# later and far from the cause. These fixtures pin its verdicts instead.
#
# base.fixture is a small tree that passes; each *.case beside it is a case.
# Both are one file holding a tree: after the header, each `=== <path>` line
# starts a file at that path. A case's files are written over a copy of the
# base tree. In the header, `#` lines describe the fixture, `expect exit N` is
# the status the check must return, and each `expect <text>` and
# `expect-absent <text>` is a string its output (run with --survey) must or
# must not contain, so a case that reds for the wrong reason fails here.
#
# Exit 0 = every case behaved. Exit 1 = a case did not.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECK="$SCRIPT_DIR/../check-node-test-groups.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILED=0
CASES=0
ok()  { echo "  ok   $*"; return 0; }
bad() { echo "  FAIL $*"; FAILED=$((FAILED + 1)); return 0; }

# materialize <fixture file> <directory>: writes the fixture's files under the
# directory, replacing any already there.
materialize() {
    awk -v dir="$2" '
        /^=== / {
            if (out != "") close(out)
            out = dir "/" substr($0, 5)
            parent = out
            sub(/\/[^\/]*$/, "", parent)
            system("mkdir -p \"" parent "\"")
            printf "" > out
            next
        }
        out != "" { print > out }
    ' "$1"
    return $?
}

# run_case <fixture file>: builds the base tree plus the case's files, runs
# the check on it, and compares the status and output with the case header.
run_case() {
    local file="$1" name tree want rc line text
    name="$(basename "$file")"
    name="${name%.*}"
    tree="$WORK/$name"
    CASES=$((CASES + 1))
    mkdir -p "$tree"
    if ! materialize "$SCRIPT_DIR/base.fixture" "$tree" || ! materialize "$file" "$tree"; then
        bad "$name: could not build its tree"
        return 0
    fi
    python3 "$CHECK" --root "$tree" --exemptions "$tree/exemptions.toml" --survey \
        > "$WORK/$name.out" 2>&1
    rc=$?
    want="$(sed -n 's/^expect exit \([0-9]*\)$/\1/p' "$file")"
    if [[ -z "$want" ]]; then
        bad "$name: no 'expect exit N' line"
        return 0
    fi
    if [[ "$want" != "$rc" ]]; then
        bad "$name: exit $rc, expected $want"
        sed 's/^/         /' "$WORK/$name.out"
        return 0
    fi
    while IFS= read -r line; do
        case "$line" in
            "expect exit "*) ;;
            "expect-absent "*)
                text="${line#expect-absent }"
                if grep -qF -- "$text" "$WORK/$name.out"; then
                    bad "$name: output contains '$text'"
                    sed 's/^/         /' "$WORK/$name.out"
                    return 0
                fi
                ;;
            "expect "*)
                text="${line#expect }"
                if ! grep -qF -- "$text" "$WORK/$name.out"; then
                    bad "$name: output lacks '$text'"
                    sed 's/^/         /' "$WORK/$name.out"
                    return 0
                fi
                ;;
        esac
    done < <(sed '/^=== /,$d' "$file")
    ok "$name: exit $rc"
    return 0
}

echo "check-node-test-groups fixtures"
run_case "$SCRIPT_DIR/base.fixture"
for file in "$SCRIPT_DIR"/*.case; do
    [[ -e "$file" ]] || continue
    run_case "$file"
done

# A runner that found no cases has proved nothing.
if [[ "$CASES" -lt 2 ]]; then
    echo "check-node-test-groups fixtures: only $CASES case(s) found in $SCRIPT_DIR"
    exit 1
fi
if [[ "$FAILED" -ne 0 ]]; then
    echo "check-node-test-groups fixtures: $FAILED of $CASES case(s) failed"
    exit 1
fi
echo "check-node-test-groups fixtures: all $CASES cases passed"
exit 0
