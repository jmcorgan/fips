#!/bin/bash
# ── Test-image and build-context scoping guard ──────────────────────────────
# A local CI run builds fips-test:<run-id> from a build context of its own and
# hands both to every suite, through FIPS_TEST_IMAGE / FIPS_TEST_APP_IMAGE and
# FIPS_BUILD_CONTEXT. It does NOT write fips-test:latest and does not build from
# the shared testing/docker directory, deliberately.
#
# Both halves protect the same thing. While a bridge back to the shared mutable
# tag existed, a consumer that named it directly kept working while resolving
# whichever concurrent run wrote the tag last. The shared build context is that
# same failure one level down: testing/docker/ is a single directory in the
# working tree, so two runs racing on its CONTENTS produce a correctly
# per-run-tagged image built from the other run's binaries — scoping the tag
# alone does not close it. Either way the verdict is recorded against a commit
# whose binaries had not run, and nothing in the harness compares a running
# container's binary against the commit under test, so that failure is silent
# and leaves no artifact.
#
# The bridge is gone, so a consumer that names the shared tag now fails loudly
# at run time. This guard is the static half: it stops one being reintroduced,
# because the reintroduction is invisible on any host where a hand build has
# left an fips-test:latest and a populated testing/docker/ lying around.
#
# What counts as a violation:
#   * a reference to the shared image name, whether tagged :latest or left
#     untagged — docker resolves a bare `fips-test` to fips-test:latest, so
#     `image: fips-test` reintroduces the identical defect;
#   * a build context that names the shared testing/docker directory;
# unless it is a comment, the documented ${FIPS_TEST_IMAGE:-...} or
# ${FIPS_BUILD_CONTEXT:-...} fallback, or one of the individually justified
# references listed below.
#
# Exit 0 = clean. Exit 1 = an unexpected reference. Exit 2 = the guard could
# not run; never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# The shared image name: tagged :latest, or left untagged, which docker
# resolves to :latest. The run-scoped forms fips-test:${CI_RUN_ID} and the
# comparison harness's fips-test:compare-<ref> must NOT match, so the untagged
# half requires the name to end at a character that can continue neither a
# repository name nor a tag.
SHARED_IMAGE_RE="fips-test(-app)?:latest|fips-test(-app)?([^-:._[:alnum:]]|\$)"

# The shared build context: a path whose LAST component is the tracked
# testing/docker directory. A path that continues past it — ../docker/resolv.conf,
# "\$SCRIPT_DIR"/docker/* — names a file inside the directory rather than using
# the directory as a context, and is not what races. The per-run context is
# docker-<run-id>, so the terminator class also keeps that from matching.
SHARED_CONTEXT_RE="/docker([[:space:]\"'}]|\$)|^[[:space:]]*(build|context):[[:space:]]*[\"']?docker/?[\"']?[[:space:]]*\$"

# Individually justified references, as "<path under testing/>::<text the line
# must contain>". The exemption is scoped to the reference, not to the file: a
# NEW shared-tag or shared-context reference added anywhere in one of these
# files is still a violation.
#
# Two of these files ARE reached from ci-local.sh, which is why a
# whole-file exemption would not be honest here:
#   * sidecar/scripts/test-sidecar.sh is invoked with --skip-build, so the
#     build block holding its two references never executes under CI;
#   * ci-cleanup.sh is invoked to reap, and its references only pick the
#     throwaway image ip(8) runs in — it addresses no test container.
ALLOWED_REFS=(
    # The developer build. The shared directory is its context and the shared
    # tags are its product; that is the whole point of the script, and CI does
    # not run it.
    'scripts/build.sh::DOCKER_DIR="$TESTING_DIR/docker"'
    'scripts/build.sh::docker build -t fips-test:latest "$DOCKER_DIR"'
    'scripts/build.sh::docker build -t fips-test-app:latest -f "$DOCKER_DIR/Dockerfile.app"'
    'scripts/build.sh::echo "Done. Images: fips-test:latest, fips-test-app:latest"'

    # The hand-run sidecar build, behind its --skip-build guard. ci-local.sh
    # always passes that flag, so under CI these two lines do not run and the
    # image comes from FIPS_TEST_IMAGE like everywhere else.
    'sidecar/scripts/test-sidecar.sh::docker build -t fips-test:latest "$DOCKER_DIR"'
    'sidecar/scripts/test-sidecar.sh::docker build -t fips-test-app:latest -f "$DOCKER_DIR/Dockerfile.app"'

    # Hand-run A/B between two refs: it retags whatever the developer build
    # last produced, under a name of its own.
    'static/scripts/iperf-compare-refs.sh::docker tag fips-test:latest "$tag"'

    # The image ip(8) runs in during a reap, wanted only for its iproute2. The
    # repository-wide listing and the literal tag are the last two fallbacks,
    # after --veth-image and the run's own FIPS_TEST_IMAGE have both come back
    # empty; neither addresses a container under test.
    'ci-cleanup.sh::docker image ls --format'
    'ci-cleanup.sh::VETH_IMAGE="fips-test:latest"'

    # Per-ref interop images. This copies three files OUT of the shared
    # directory into a context of its own and builds from that, so it reads the
    # shared directory but never uses it as a context.
    'interop/build-images.sh::DOCKER_CTX_SRC="$REPO_ROOT/testing/docker"'
)

# This guard is the one file that must contain the patterns it looks for, so it
# is swept out of its own file list. The exemption is bounded rather than
# trusted: the guard must not be able to hide a real invocation behind it, so
# assert it runs no container command. That catches one written as its own
# statement, which is the shape a reintroduction here would take; it would not
# catch one buried inside a command substitution.
GUARD_REL="check-image-scoping.sh"

if ! command -v git >/dev/null 2>&1; then
    echo "check-image-scoping: git not available, cannot sweep" >&2
    exit 2
fi
if [[ ! -d "$SCRIPT_DIR" ]]; then
    echo "check-image-scoping: $SCRIPT_DIR missing" >&2
    exit 2
fi
if [[ ! -f "$SCRIPT_DIR/$GUARD_REL" ]]; then
    echo "check-image-scoping: cannot find itself at $SCRIPT_DIR/$GUARD_REL" >&2
    exit 2
fi

# Tracked files only, and no documentation: prose naming the tag or the
# directory is describing it, not resolving it.
if ! tracked="$(git -C "$SCRIPT_DIR/.." ls-files -- testing/)"; then
    echo "check-image-scoping: git ls-files failed, refusing to pass" >&2
    exit 2
fi
if [[ -z "$tracked" ]]; then
    echo "check-image-scoping: no tracked files under testing/, refusing to pass" >&2
    exit 2
fi
mapfile -t files < <(printf '%s\n' "$tracked" | grep -vE '\.md$')
if [[ ${#files[@]} -eq 0 ]]; then
    echo "check-image-scoping: no tracked non-doc files under testing/, refusing to pass" >&2
    exit 2
fi

violations=0

if grep -qE '^[[:space:]]*docker[[:space:]]' "$SCRIPT_DIR/$GUARD_REL"; then
    echo "FAIL testing/$GUARD_REL runs a docker command."
    echo "     It is exempt from its own sweep only because it resolves no image."
    violations=$((violations + 1))
fi

# True when this file:line is one of the justified references above.
allowed_ref() {
    local rel="$1" text="$2" entry path frag
    for entry in "${ALLOWED_REFS[@]}"; do
        path="${entry%%::*}"
        frag="${entry#*::}"
        [[ "$rel" == "$path" && "$text" == *"$frag"* ]] && return 0
    done
    return 1
}

for f in "${files[@]}"; do
    rel="${f#testing/}"
    [[ "$rel" == "$GUARD_REL" ]] && continue
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
        allowed_ref "$rel" "$text" && continue
        echo "FAIL $f:$n names the shared test image directly:"
        echo "     $text"
        violations=$((violations + 1))
    done < <(grep -nE "$SHARED_IMAGE_RE" "$SCRIPT_DIR/../$f" 2>/dev/null)

    while IFS= read -r hit; do
        n="${hit%%:*}"
        text="${hit#*:}"
        [[ "$text" =~ ^[[:space:]]*# ]] && continue
        # The same indirection for the context: the shared directory is allowed
        # only as the fallback a bare hand run gets. Compose resolves a relative
        # build.context against the compose FILE's directory, which is why the
        # harness exports an absolute path here.
        [[ "$text" == *'${FIPS_BUILD_CONTEXT:-'* ]] && continue
        allowed_ref "$rel" "$text" && continue
        echo "FAIL $f:$n builds from the shared testing/docker context:"
        echo "     $text"
        violations=$((violations + 1))
    done < <(grep -nE "$SHARED_CONTEXT_RE" "$SCRIPT_DIR/../$f" 2>/dev/null)
done

if [[ $violations -gt 0 ]]; then
    echo ""
    echo "check-image-scoping: $violations unscoped reference(s) to the shared test image"
    echo "or the shared build context."
    echo "Read FIPS_TEST_IMAGE (default \${FIPS_TEST_IMAGE:-fips-test:latest}) for the image"
    echo "and FIPS_BUILD_CONTEXT (default \${FIPS_BUILD_CONTEXT:-../docker}) for the context."
    echo "A run that resolves either shared name can execute a concurrent run's binaries"
    echo "and record the verdict against this commit."
    exit 1
fi

echo "check-image-scoping: no unscoped references to the shared test image or build context"
exit 0
