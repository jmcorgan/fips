#!/usr/bin/env bash
# Fixture tests for await-package-runs.sh, the gate that holds the AUR publish
# until every package workflow run for the release tag has succeeded.
#
# Each case writes GitHub API responses into a fixture directory and puts a
# stub `gh` first on PATH. The stub serves <workflow>.<call>.json for the Nth
# call about a workflow, falls back to <workflow>.json, and exits 1 when the
# fixture holds a file named `gh-fails`. It counts calls per workflow so a
# case can assert that the gate polled again rather than stopping early.
#
# Needs bash and jq. Exits nonzero if any case fails or if fewer cases ran
# than are defined.
#
# Usage: bash packaging/aur/test-await-package-runs.sh

set -euo pipefail
# No check pipes into grep -q or another reader that can stop early. Under
# pipefail, the reader exiting at its match kills a writer that still has
# output to write with SIGPIPE, and the pipeline fails although the text
# matched. bash's echo and printf write a multi-line string a line or two
# at a time, so one line of output after the match is enough to lose it.
# Checks match on a here-string, or on output captured first.

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GATE="${GATE:-$HERE/await-package-runs.sh}"
REPO_ROOT=$(cd "$HERE/../.." && pwd)

TAG=v9.9.9
SHA=0123456789abcdef0123456789abcdef01234567
WORKFLOWS=(package-freebsd.yml package-linux.yml package-macos.yml
           package-openwrt.yml package-windows.yml)

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# The stub gh. It answers `gh api <url>` only, which is all the gate uses.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = "api" ] || { echo "stub gh: unexpected args: $*" >&2; exit 2; }
[ -e "$STUB_FIXTURE/gh-fails" ] && { echo "stub gh: simulated API error" >&2; exit 1; }
wf=$(printf '%s\n' "$2" | sed -E 's|.*/actions/workflows/([^/]+)/runs.*|\1|')
count_file="$STUB_CALLS/$wf"
n=$(( $(cat "$count_file" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$count_file"
if [ -f "$STUB_FIXTURE/$wf.$n.json" ]; then
  cat "$STUB_FIXTURE/$wf.$n.json"
elif [ -f "$STUB_FIXTURE/$wf.json" ]; then
  cat "$STUB_FIXTURE/$wf.json"
else
  echo '{"total_count":0,"workflow_runs":[]}'
fi
STUB
chmod +x "$WORK/bin/gh"

# A workflow directory holding the five package workflows as empty files: the
# gate discovers the population by file name only.
mkdir -p "$WORK/workflows" "$WORK/empty-workflows"
for wf in "${WORKFLOWS[@]}"; do : > "$WORK/workflows/$wf"; done

# Print one run object in the shape of the v0.5.1 API response.
# Args: head_branch status conclusion created_at id
run() {
  local conclusion=null
  [ "$3" = null ] || conclusion="\"$3\""
  printf '{"id":%s,"name":"Package","head_branch":"%s","head_sha":"%s","event":"push","status":"%s","conclusion":%s,"created_at":"%s","updated_at":"%s","html_url":"https://github.com/example/fips/actions/runs/%s"}' \
    "$5" "$1" "$SHA" "$2" "$conclusion" "$4" "$4" "$5"
}

# Wrap run objects, given as arguments in the order the API returns them, in
# the list response envelope.
runs() {
  local IFS=,
  printf '{"total_count":%d,"workflow_runs":[%s]}\n' "$#" "$*"
}

# Write the healthy v0.5.1 shape for every workflow into a fixture: a tag run
# and a branch run of the same commit, newest first, both successful.
all_green() {
  local dir=$1 wf
  for wf in "${WORKFLOWS[@]}"; do
    runs "$(run "$TAG" completed success 2026-09-06T20:31:48Z 2)" \
         "$(run maint completed success 2026-09-06T20:31:10Z 1)" > "$dir/$wf.json"
  done
}

CASES_DEFINED=0
CASES_RAN=0
FAILED=0

# Run the gate against a fixture and check its exit status and, when a
# pattern is given, that its output states the expected reason (so a red
# caused by a crash in the gate does not pass as the intended red).
# Args: name fixture-dir expect(zero|nonzero) [pattern] [workflow-dir]
# Sets LAST_OUT to the gate's combined output.
check() {
  local name=$1 fixture=$2 expect=$3 pattern=${4:-} wfdir=${5:-$WORK/workflows} rc=0
  CASES_RAN=$((CASES_RAN + 1))
  rm -rf "$WORK/calls"; mkdir -p "$WORK/calls"
  LAST_OUT=$(PATH="$WORK/bin:$PATH" STUB_FIXTURE="$fixture" STUB_CALLS="$WORK/calls" \
    GITHUB_REPOSITORY=example/fips TAG="$TAG" SHA="$SHA" WORKFLOW_DIR="$wfdir" \
    AWAIT_POLLS=3 AWAIT_INTERVAL=0 bash "$GATE" 2>&1) || rc=$?
  if { [ "$expect" = zero ] && [ "$rc" -eq 0 ]; } ||
     { [ "$expect" = nonzero ] && [ "$rc" -ne 0 ]; }; then
    if [ -z "$pattern" ] || grep -qE -- "$pattern" <<<"$LAST_OUT"; then
      echo "PASS $name (exit $rc)"
      return 0
    fi
    echo "FAIL $name: exit $rc as expected, but output lacks /$pattern/"
  else
    echo "FAIL $name: expected $expect exit, got $rc"
  fi
  printf '%s\n' "$LAST_OUT" | sed 's/^/    /'
  FAILED=$((FAILED + 1))
  return 1
}

# Record an extra assertion's failure against the case that just ran.
fail() {
  echo "FAIL $1"
  FAILED=$((FAILED + 1))
}

# Make a fresh fixture directory for a case and print its path.
fixture() {
  local dir="$WORK/fx/$1"
  mkdir -p "$dir"
  echo "$dir"
}

# --- cases -------------------------------------------------------------------

# 1: every package workflow has a successful tag run.
CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 1); all_green "$fx"
check "1 all tag runs succeeded" "$fx" zero "has succeeded$" || true

# 2: one tag run failed; the gate must name that workflow.
CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 2); all_green "$fx"
runs "$(run "$TAG" completed failure 2026-09-06T20:31:48Z 2)" \
     "$(run maint completed success 2026-09-06T20:31:10Z 1)" > "$fx/package-macos.yml.json"
if check "2 one tag run failed" "$fx" nonzero "concluded 'failure'"; then
  grep -q 'package-macos.yml' <<<"$LAST_OUT" ||
    fail "2 one tag run failed: output does not name package-macos.yml"
fi

# 3: one tag run was cancelled.
CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 3); all_green "$fx"
runs "$(run "$TAG" completed cancelled 2026-09-06T20:31:48Z 2)" > "$fx/package-openwrt.yml.json"
check "3 one tag run cancelled" "$fx" nonzero "package-openwrt.yml: run for .* concluded 'cancelled'" || true

# 4: one workflow has only the branch run of the tag's commit (the v0.5.1
# shape a SHA-only filter would accept).
CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 4); all_green "$fx"
runs "$(run maint completed success 2026-09-06T20:31:10Z 1)" > "$fx/package-freebsd.yml.json"
check "4 only a branch run, no tag run" "$fx" nonzero "package-freebsd.yml: none$" || true

# 5: one tag run is in progress on the first poll and succeeds on the second.
CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 5); all_green "$fx"
runs "$(run "$TAG" in_progress null 2026-09-06T20:31:48Z 2)" > "$fx/package-freebsd.yml.1.json"
if check "5 in progress, then succeeded" "$fx" zero "has succeeded$"; then
  calls=$(cat "$WORK/calls/package-freebsd.yml" 2>/dev/null || echo 0)
  [ "$calls" -ge 2 ] ||
    fail "5 in progress, then succeeded: gate queried package-freebsd.yml $calls time(s), expected at least 2"
fi

# 6: one tag run stays in progress for the whole budget.
CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 6); all_green "$fx"
runs "$(run "$TAG" in_progress null 2026-09-06T20:31:48Z 2)" > "$fx/package-freebsd.yml.json"
check "6 in progress for the whole budget" "$fx" nonzero "package-freebsd.yml: in_progress " || true

# 7: no package workflows discovered.
CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 7); all_green "$fx"
check "7 empty workflow population" "$fx" nonzero "No package-\*\.yml workflows found" \
  "$WORK/empty-workflows" || true

# 8a-8d: the tag was re-pushed at the same commit, so two tag runs exist. The
# newest decides. The API lists newest first; 8b and 8c list oldest first so
# that "take the first match" and "take the newest" disagree.
CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 8a); all_green "$fx"
runs "$(run "$TAG" completed success 2026-09-06T21:00:00Z 3)" \
     "$(run "$TAG" completed failure 2026-09-06T20:31:48Z 2)" > "$fx/package-linux.yml.json"
check "8a older failure, newer success, newest first" "$fx" zero "has succeeded$" || true

CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 8b); all_green "$fx"
runs "$(run "$TAG" completed success 2026-09-06T20:31:48Z 2)" \
     "$(run "$TAG" completed failure 2026-09-06T21:00:00Z 3)" > "$fx/package-linux.yml.json"
check "8b older success, newer failure, oldest first" "$fx" nonzero \
  "package-linux.yml: run for .* concluded 'failure'" || true

CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 8c); all_green "$fx"
runs "$(run "$TAG" completed failure 2026-09-06T20:31:48Z 2)" \
     "$(run "$TAG" completed success 2026-09-06T21:00:00Z 3)" > "$fx/package-linux.yml.json"
check "8c older failure, newer success, oldest first" "$fx" zero "has succeeded$" || true

CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 8d); all_green "$fx"
runs "$(run "$TAG" completed failure 2026-09-06T21:00:00Z 3)" \
     "$(run "$TAG" completed success 2026-09-06T20:31:48Z 2)" > "$fx/package-linux.yml.json"
check "8d older success, newer failure, newest first" "$fx" nonzero \
  "package-linux.yml: run for .* concluded 'failure'" || true

# 9: every API call fails.
CASES_DEFINED=$((CASES_DEFINED + 1))
fx=$(fixture 9); all_green "$fx"; : > "$fx/gh-fails"
check "9 gh fails on every call" "$fx" nonzero "package-linux.yml: API error" || true

# 10: discovery against the repository's real workflow directory.
CASES_DEFINED=$((CASES_DEFINED + 1))
CASES_RAN=$((CASES_RAN + 1))
rc=0
found=$(DISCOVER_ONLY=1 WORKFLOW_DIR="$REPO_ROOT/.github/workflows" \
  GITHUB_REPOSITORY=example/fips TAG="$TAG" SHA="$SHA" bash "$GATE" 2>&1) || rc=$?
if [ "$rc" -eq 0 ] && [ -n "$found" ] &&
   grep -qx 'package-linux.yml' <<<"$found"; then
  echo "PASS 10 real workflow discovery: $(printf '%s\n' "$found" | tr '\n' ' ')"
else
  echo "FAIL 10 real workflow discovery: exit $rc, found: $found"
  FAILED=$((FAILED + 1))
fi

# -----------------------------------------------------------------------------

echo "cases defined: $CASES_DEFINED, ran: $CASES_RAN, failed: $FAILED"
if [ "$CASES_RAN" -ne "$CASES_DEFINED" ]; then
  echo "FAIL: not every defined case ran"
  exit 1
fi
[ "$FAILED" -eq 0 ]
