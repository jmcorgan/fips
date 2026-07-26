#!/bin/bash
# ── Test-image scoping guard ────────────────────────────────────────────────
# A local CI run builds fips-test:<run-id> and hands it to every suite through
# FIPS_TEST_IMAGE / FIPS_TEST_APP_IMAGE. It does NOT write fips-test:latest,
# deliberately: while a bridge back to that shared mutable name existed, a
# consumer that named it directly kept working while resolving whichever
# concurrent run wrote the tag last, and the verdict was then recorded against
# a commit whose binaries had not run. Nothing in the harness compares a
# running container's binary against the commit under test, so that failure is
# silent and leaves no artifact.
#
# The bridge is gone, so a consumer that names the shared tag now fails loudly
# at run time. This guard is the static half: it stops one being reintroduced,
# because the reintroduction is invisible on any host where a hand build has
# left an fips-test:latest lying around.
#
# What counts as a violation: a reference to the shared tag that is neither a
# comment, nor a documented default of the ${FIPS_TEST_IMAGE:-...} form, nor in
# a file on the allowlist below.
#
# Exit 0 = clean. Exit 1 = an unexpected reference. Exit 2 = the guard could
# not run; never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Files permitted to name the shared tag outright, each for a stated reason.
# Every one of these is a hand-run path: none is reachable from ci-local.sh
# with FIPS_TEST_IMAGE set.
#
#   scripts/build.sh              the developer build; :latest IS its product
#   sidecar/scripts/test-sidecar.sh  hand build, behind its --skip-build guard,
#                                 which ci-local always passes
#   static/scripts/iperf-compare-refs.sh  hand-run A/B against two refs
#   ci-cleanup.sh                 last-resort name for the image ip(8) runs in,
#                                 after the caller's and the run's have failed
#   check-image-scoping.sh        this guard, which has to name what it looks
#                                 for; it resolves no image
ALLOWED=(
    "scripts/build.sh"
    "sidecar/scripts/test-sidecar.sh"
    "static/scripts/iperf-compare-refs.sh"
    "ci-cleanup.sh"
    "check-image-scoping.sh"
)

if ! command -v git >/dev/null 2>&1; then
    echo "check-image-scoping: git not available, cannot sweep" >&2
    exit 2
fi
if [[ ! -d "$SCRIPT_DIR" ]]; then
    echo "check-image-scoping: $SCRIPT_DIR missing" >&2
    exit 2
fi

# Tracked files only, and no documentation: prose naming the tag is describing
# it, not resolving it.
mapfile -t files < <(git -C "$SCRIPT_DIR/.." ls-files -- testing/ | grep -vE '\.md$')
if [[ ${#files[@]} -eq 0 ]]; then
    echo "check-image-scoping: no tracked files under testing/, refusing to pass" >&2
    exit 2
fi

violations=0
for f in "${files[@]}"; do
    rel="${f#testing/}"
    skip=0
    for a in "${ALLOWED[@]}"; do
        [[ "$rel" == "$a" ]] && skip=1 && break
    done
    [[ $skip -eq 1 ]] && continue
    [[ -f "$SCRIPT_DIR/../$f" ]] || continue

    while IFS= read -r hit; do
        n="${hit%%:*}"
        text="${hit#*:}"
        # A comment line is describing the tag, not resolving it. Shell, python
        # and yaml all use #; nothing under testing/ uses // for comments.
        [[ "$text" =~ ^[[:space:]]*# ]] && continue
        # The documented indirection: the shared tag as a FALLBACK, which is
        # what a bare hand run is supposed to get.
        [[ "$text" == *'${FIPS_TEST_IMAGE:-fips-test:latest}'* ]] && continue
        [[ "$text" == *'${FIPS_TEST_APP_IMAGE:-fips-test-app:latest}'* ]] && continue
        [[ "$text" == *'os.environ.get("FIPS_TEST_IMAGE", "fips-test:latest")'* ]] && continue
        echo "FAIL $f:$n names the shared test image directly:"
        echo "     $text"
        violations=$((violations + 1))
    done < <(grep -n 'fips-test:latest\|fips-test-app:latest' "$SCRIPT_DIR/../$f" 2>/dev/null)
done

if [[ $violations -gt 0 ]]; then
    echo ""
    echo "check-image-scoping: $violations reference(s) to the shared mutable test image."
    echo "Read FIPS_TEST_IMAGE (default \${FIPS_TEST_IMAGE:-fips-test:latest}) instead."
    echo "A run that resolves the shared tag can execute a concurrent run's binaries"
    echo "and record the verdict against this commit."
    exit 1
fi

echo "check-image-scoping: no unscoped references to the shared test image"
exit 0
