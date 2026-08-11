#!/bin/bash
# ── GitHub Action pinning guard ─────────────────────────────────────────────
# Every third-party action this repository invokes must be referenced by a
# 40-character commit SHA, with its human-readable tag in a trailing comment.
#
# A tag is a mutable pointer. Whoever controls an action's repository can move
# `v6` to different code at any time, and several of the jobs here are worth
# moving it for: aur-publish.yml and aur-publish-git.yml hand an action
# AUR_SSH_PRIVATE_KEY, and the OpenWrt release jobs run with HIVE_CI_NSEC in
# the environment. A SHA is content-addressed and cannot be repointed. The
# trailing comment is required rather than optional so the pin stays legible:
# a bare 40-hex string tells a reader nothing about which release it is, and a
# pin nobody can read is a pin nobody updates.
#
# What counts as a violation: any `uses:` reference that is not
#   * `owner/repo@<40 hex> # <tag>` — the required form, comment mandatory; or
#   * a local action, `./path` or `docker://...`; or
#   * one of the individually justified references listed below.
#
# WHAT THIS GUARD DOES NOT COVER, so a green run is not read as "the workflows
# fetch nothing unverified":
#   * the actions that the pinned actions themselves invoke. Pinning
#     KSXGitHub/github-actions-deploy-aur removes the retag vector; it does not
#     constrain what that action does with the SSH key it is given by design
#     (aur-publish.yml, aur-publish-git.yml).
#   * `pip3 install --quiet pyyaml` in ci.yml's ci-parity job, which holds
#     `checks: write`. Unpinned entirely, version and hash both.
#   * `cargo install cargo-zigbuild --version 0.19.8 --locked` in
#     package-openwrt.yml. Version-pinned, not hash-pinned.
#   * anything a workflow downloads at run time. The zig tarball and the nak
#     binary are SHA-256 checked in their own steps; nothing here enforces that.
#
# Exit 0 = clean. Exit 1 = an unpinned reference. Exit 2 = the guard could not
# run; never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR/.."

# The one accepted form for a third-party action. The comment is mandatory
# rather than optional: an optional comment would let the checker accept a pin
# it cannot describe, and a pin nobody can read is a pin nobody updates.
PINNED_RE='^[^@]+@[0-9a-f]{40} +#.*$'

# Individually justified unpinned references. Each entry is the exact ref text.
#
# Both of these actions read the tool they install from the ref name itself
# (`github.action_ref`), so replacing the ref with a SHA hands them a 40-hex
# string where a toolchain or tool name belongs and the step fails outright.
# They are not pinnable without also moving the selection into `with:`, which
# changes which toolchain resolves, and that is a separate decision from
# pinning. Note what stays exposed: both remain repointable by their upstream
# owners.
ALLOWED_REFS=(
    'dtolnay/rust-toolchain@nightly'
    'taiki-e/install-action@nextest'
)

if ! command -v git >/dev/null 2>&1; then
    echo "check-action-pins: git not available, cannot sweep" >&2
    exit 2
fi
if [[ ! -d "$REPO_ROOT/.github" ]]; then
    echo "check-action-pins: $REPO_ROOT/.github missing, refusing to pass" >&2
    exit 2
fi

# Tracked files only. Workflows plus any composite/local action definition:
# a future .yaml extension and a future .github/actions/ tree both have to be
# swept, or the guard silently narrows as the repository grows.
if ! tracked="$(git -C "$REPO_ROOT" ls-files -- '.github/workflows/*.yml' '.github/workflows/*.yaml' '.github/actions/*.yml' '.github/actions/*.yaml')"; then
    echo "check-action-pins: git ls-files failed, refusing to pass" >&2
    exit 2
fi
if [[ -z "$tracked" ]]; then
    echo "check-action-pins: no tracked workflow or action files, refusing to pass" >&2
    exit 2
fi
mapfile -t files < <(printf '%s\n' "$tracked")
if [[ ${#files[@]} -eq 0 ]]; then
    echo "check-action-pins: empty file list, refusing to pass" >&2
    exit 2
fi

# True when this ref is one of the justified references above.
allowed_ref() {
    local ref="$1" entry
    for entry in "${ALLOWED_REFS[@]}"; do
        [[ "$ref" == "$entry" ]] && return 0
    done
    return 1
}

violations=0
checked=0

for f in "${files[@]}"; do
    [[ -f "$REPO_ROOT/$f" ]] || continue

    while IFS= read -r hit; do
        n="${hit%%:*}"
        text="${hit#*:}"
        # A commented-out step is describing a reference, not resolving it.
        [[ "$text" =~ ^[[:space:]]*# ]] && continue

        # Everything after `uses:`, with surrounding whitespace and any quoting
        # removed. The trailing comment is part of the ref text on purpose:
        # the accepted form requires it.
        ref="${text#*uses:}"
        ref="${ref#"${ref%%[![:space:]]*}"}"
        ref="${ref%"${ref##*[![:space:]]}"}"

        checked=$((checked + 1))

        # A local action or a container image is not a mutable upstream tag.
        [[ "$ref" == ./* ]] && continue
        [[ "$ref" == docker://* ]] && continue
        [[ "$ref" =~ $PINNED_RE ]] && continue
        allowed_ref "$ref" && continue

        echo "$f:$n: $ref"
        violations=$((violations + 1))
    done < <(grep -nE '^[[:space:]]*(- )?uses:' "$REPO_ROOT/$f" 2>/dev/null)
done

if [[ $checked -eq 0 ]]; then
    echo "check-action-pins: no uses: references found at all, refusing to pass" >&2
    exit 2
fi

if [[ $violations -gt 0 ]]; then
    echo ""
    echo "check-action-pins: $violations action reference(s) are not pinned to a commit SHA."
    echo "Required form:  uses: owner/repo@<40-hex-commit-sha> # <tag>"
    echo "Resolve one with:"
    echo "  git ls-remote https://github.com/owner/repo 'refs/tags/<tag>^{}' refs/tags/<tag>"
    echo "and use the peeled (^{}) SHA when the tag is annotated."
    echo "A tag is a mutable pointer its owner can repoint; several of these jobs"
    echo "hold a signing key or an SSH deploy key while the action runs."
    exit 1
fi

echo "check-action-pins: all $checked action reference(s) pinned or justified"
exit 0
