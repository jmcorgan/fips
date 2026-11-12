#!/bin/bash
# ── Fixture tests for check-nostr-machine.py ────────────────────────────────
# The check is all that holds the Nostr machine's fence: nothing builds the
# module without std. If it stopped seeing a std path or a back-import into the
# shell, the module would quietly grow a dependency on the host and the first
# sign would be an embedded build that cannot start. These fixtures pin its
# verdicts instead.
#
# base.fixture is a small tree laid out as src/nostr/machine/ that passes; each
# *.case beside it is a case. Both are one file holding a tree: after the
# header, each `=== <path>` line starts a file at that path. A case's files are
# written over a copy of the base tree. In the header, `#` lines describe the
# fixture, `expect exit N` is the status the check must return, and each
# `expect <text>` and `expect-absent <text>` is a string its output must or
# must not contain, so a case that reds for the wrong reason fails here.
#
# Exit 0 = every case behaved. Exit 1 = a case did not.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHECK="$SCRIPT_DIR/../check-nostr-machine.py"
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

# check_output <name> <fixture file>: compares the saved output with the
# fixture header's expect lines; returns 1 after reporting the first mismatch.
check_output() {
    local name="$1" file="$2" line text
    while IFS= read -r line; do
        case "$line" in
            "expect exit "*) ;;
            "expect-absent "*)
                text="${line#expect-absent }"
                if grep -qF -- "$text" "$WORK/$name.out"; then
                    bad "$name: output contains '$text'"
                    sed 's/^/         /' "$WORK/$name.out"
                    return 1
                fi
                ;;
            "expect "*)
                text="${line#expect }"
                if ! grep -qF -- "$text" "$WORK/$name.out"; then
                    bad "$name: output lacks '$text'"
                    sed 's/^/         /' "$WORK/$name.out"
                    return 1
                fi
                ;;
        esac
    done < <(sed '/^=== /,$d' "$file")
    return 0
}

# run_case <fixture file>: builds the base tree plus the case's files, runs
# the check on it, and compares the status and output with the case header.
run_case() {
    local file="$1" name tree want rc
    name="$(basename "$file")"
    name="${name%.*}"
    tree="$WORK/$name"
    CASES=$((CASES + 1))
    mkdir -p "$tree"
    if ! materialize "$SCRIPT_DIR/base.fixture" "$tree" || ! materialize "$file" "$tree"; then
        bad "$name: could not build its tree"
        return 0
    fi
    python3 "$CHECK" --root "$tree" > "$WORK/$name.out" 2>&1
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
    check_output "$name" "$file" && ok "$name: exit $rc"
    return 0
}

echo "check-nostr-machine fixtures"
run_case "$SCRIPT_DIR/base.fixture"
for file in "$SCRIPT_DIR"/*.case; do
    [[ -e "$file" ]] || continue
    run_case "$file"
done

# A tree with no Rust file is a check that could not look: exit 2, not a pass.
CASES=$((CASES + 1))
mkdir -p "$WORK/empty-root"
python3 "$CHECK" --root "$WORK/empty-root" > "$WORK/empty-root.out" 2>&1
rc=$?
if [[ "$rc" == 2 ]]; then ok "empty-root: exit 2"; else bad "empty-root: exit $rc, expected 2"; fi

# A runner that found no cases has proved nothing.
if [[ "$CASES" -lt 3 ]]; then
    echo "check-nostr-machine fixtures: only $CASES case(s) found in $SCRIPT_DIR"
    exit 1
fi
if [[ "$FAILED" -ne 0 ]]; then
    echo "check-nostr-machine fixtures: $FAILED of $CASES case(s) failed"
    exit 1
fi
echo "check-nostr-machine fixtures: all $CASES cases passed"
exit 0
