#!/bin/bash
# ── Single-test verdicts for the known-defect and mutation lanes ────────────
# Sourced by testing/known-defect-lane.sh and testing/mutations/run.sh. Both
# run one library test per process and need to know not only whether it
# failed but where: a known-defect test that fails in its setup has not shown
# its defect, and a mutation that breaks a test's setup has not shown that
# the test guards the behaviour the mutation broke.
#
# A test marks the assertions it means. The assertion that states the
# behaviour under test carries a message starting `defect:` (an aggregated
# list as `"defect: {bad:#?}"`); a setup check carries one starting
# `precondition:`. Anything else that fails the test (a bare unwrap(), a
# shared helper's plain expect, an arithmetic overflow, an unmarked assert)
# is `unmarked`, because nothing says it is the reason the test exists.
#
# Functions:
#   test_bins
#       Builds both library test executables once and sets the associative
#       array BIN, keyed fips-mesh and fips-core. Returns 2 when the build
#       fails or a binary is missing (message on stderr).
#   verdict <output> <rc> <test path>
#       Classifies the output and exit status of one test run in its own
#       process. Prints `<class>`, a tab, the panic location (file:line:col,
#       or empty), a tab, and the panic's first message line (or empty).
#       Classes:
#         passed        the summary reads `ok. 1 passed`
#         timeout       rc 124 or 137 (killed by `timeout`)
#         defect        one test failed, and its own thread's first message
#                       line starts with `defect:`
#         precondition  as defect, but the line starts with `precondition`
#         unmarked      one test failed, and its first message line has
#                       neither marker, or no panic of its own thread appears
#         norun         anything else (no such test, two tests, a crash)
#   lane_decision <class> [<location> <pin>]
#       What the known-defect lane makes of a known-defect entry's class:
#       `still-fails` (defect), `now-passes` (passed) or `problem`
#       (precondition, unmarked, timeout, norun, or anything unknown). A
#       timeout is a problem because the run was killed before it reached any
#       assertion, so it has not shown its defect. With a pin, a
#       `file:line` naming the entry's own defect assertion, `unmarked` at
#       that line is `still-fails` too. A pin is for an existing test that
#       cannot carry the `defect:` marker without editing a file the change
#       may not touch; an unmarked failure at any other line, or with no
#       location, is still a problem.
# ─────────────────────────────────────────────────────────────────────────────

# test_bins: build the two library test binaries and fill BIN.
test_bins() {
    local build_json pkg exe
    declare -gA BIN=()
    build_json=$(cargo test --workspace --lib --no-run --message-format=json) || {
        echo "test-verdict: building the library tests failed" >&2
        return 2
    }
    # The library test executable of each package, from cargo's own build
    # report, found by library target name: `fips` is the fips-mesh
    # package's library and `fips_core` the core's.
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
            echo "test-verdict: no library test binary found for $pkg" >&2
            return 2
        fi
    done
    return 0
}

# verdict <output> <rc> <test path>: classify one single-test run.
verdict() {
    local out="$1" rc="$2" name="$3" class loc="" msg="" found
    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        printf 'timeout\t\t\n'
        return 0
    fi
    if grep -q '^test result: ok\. 1 passed;' <<<"$out"; then
        printf 'passed\t\t\n'
        return 0
    fi
    if ! grep -q '^test result: FAILED\. 0 passed; 1 failed;' <<<"$out"; then
        printf 'norun\t\t\n'
        return 0
    fi
    # The test's own panic line, in either form libtest's panic hook prints:
    #   thread '<name>' panicked at <loc>:
    #   thread '<name>' (<id>) panicked at <loc>:
    # and the first message line after it.
    found=$(awk -v t="$name" '
        !hit {
            p1 = "thread \x27" t "\x27 panicked at "
            p2 = "thread \x27" t "\x27 ("
            rest = ""
            if (index($0, p1) == 1) {
                rest = substr($0, length(p1) + 1)
            } else if (index($0, p2) == 1) {
                tail = substr($0, length(p2) + 1)
                k = index(tail, ") panicked at ")
                if (k > 0 && substr(tail, 1, k - 1) ~ /^[0-9]+$/)
                    rest = substr(tail, k + length(") panicked at "))
            }
            if (rest != "" && rest ~ /:$/) {
                hit = 1
                loc = substr(rest, 1, length(rest) - 1)
                next
            }
        }
        hit == 1 { print loc "\t" $0; hit = 2; exit }
        END { if (hit == 1) print loc "\t" }
    ' <<<"$out")
    if [[ -z "$found" ]]; then
        printf 'unmarked\t\t\n'
        return 0
    fi
    loc="${found%%$'\t'*}"
    msg="${found#*$'\t'}"
    # assert_eq!/assert_ne! put their message after this prefix.
    if [[ "$msg" =~ ^assertion\ \`[^\`]*\`\ failed:\ (.*)$ ]]; then
        msg="${BASH_REMATCH[1]}"
    fi
    case "$msg" in
        defect:*) class=defect ;;
        precondition*) class=precondition ;;
        *) class=unmarked ;;
    esac
    printf '%s\t%s\t%s\n' "$class" "$loc" "$msg"
    return 0
}

# lane_decision <class> [<location> <pin>]: the known-defect lane's reading
# of a class, and of an unmarked failure at a pinned line.
lane_decision() {
    local class="$1" loc="${2:-}" pin="${3:-}"
    case "$class" in
        defect) echo still-fails ;;
        passed) echo now-passes ;;
        unmarked)
            # The location is file:line:col; the pin is file:line, so the
            # match is on the whole line number, never a prefix of it.
            if [[ -n "$pin" && -n "$loc" && "$loc" == "$pin":* ]]; then
                echo still-fails
            else
                echo problem
            fi
            ;;
        *) echo problem ;;
    esac
    return 0
}
