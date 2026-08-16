#!/bin/bash
# ── Source comment reference guard ──────────────────────────────────────────
# Every reference a source comment makes must resolve for a reader who has
# only this repository.
#
# A comment that names a private planning artifact — by identifier, by file
# path, or in programme vocabulary that has no in-repo referent — is dead text
# to everyone outside the workspace that holds the artifact, and it publishes
# the existence and shape of that workspace to everyone else. A hand-run grep
# closes the population that exists on the day it runs; this closes it for
# every commit after.
#
# Three checks, each a `git grep` at HEAD rather than over the working tree,
# because the thing being gated is what is committed:
#
#   1. identifiers, repo-wide. A local item identifier anywhere in the tree.
#      Repo-wide because packaging/, testing/ and the workflow files are as
#      public as src/ — more so in the packaging case, which ships to users.
#   2. document paths, scoped to src/. A comment under src/ citing an *.md
#      path that does not exist in the tree at the checked commit. This is a
#      resolvability rule rather than a denylist, so it catches private
#      documents nobody has thought of. Scoped to src/ because resolving the
#      whole tree's relative documentation links against the repository root
#      is a different checker with its own population to triage first.
#   3. programme vocabulary, scoped to src/. Phase, rung, milestone and step
#      labels that name a plan a reader cannot open. The pattern is shared
#      verbatim with the sweep that produced today's clean tree, so the two
#      cannot drift apart.
#
# Known coverage gaps, recorded rather than discovered:
#   - a bare "milestone" in some other phrasing (the narrow alternatives keep
#     the Tor bootstrap loop in src/transport/tor/mod.rs out of check 3);
#   - the CATEGORY_D / CATEGORY_E code identifiers and test names, which
#     check 3's case-sensitive Category-[A-Z] deliberately does not match;
#   - programme vocabulary, or a document path, outside src/;
#   - a reference to a private artifact made in free prose with no marker at
#     all, at any scope: no check here matches it;
#   - a pathspec typo introduced after this file lands. git grep returns 1
#     with empty output for a pathspec that matches nothing, which is
#     indistinguishable from health. The non-empty-population assertion below
#     narrows that for the src/-scoped checks and closes nothing for check 1.
#
# Exit 0 = every reference resolves. Exit 1 = one or more do not; every hit is
# printed, not just the first. Exit 2 = the check could not look (not in a work
# tree, wrong directory, empty pathspec, or a git-level failure); never treated
# as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

# A pathspec is resolved against the current directory even when a rev is
# supplied, and a run from the wrong directory returns rc 1 with empty output
# on every check — the same shape as a clean tree. Assert the directory, then
# assert the post-condition rather than trusting the cd: `cd ""` succeeds and
# does not move, so a one-line form silently leaves the script where it began
# whenever the command substitution comes back empty.
ROOT=$(git rev-parse --show-toplevel 2>/dev/null) \
    || { echo "check-comment-refs: not inside a git work tree" >&2; exit 2; }
[[ -n "$ROOT" ]] \
    || { echo "check-comment-refs: empty work-tree root" >&2; exit 2; }
cd "$ROOT" || exit 2
[[ -z "$(git rev-parse --show-prefix)" ]] \
    || { echo "check-comment-refs: not at the work-tree root" >&2; exit 2; }

# The src/ pathspec must select something. wc -l is deliberate where the rest
# of this script preserves exit statuses: it always exits 0, so the decision is
# made on n and never on a status, and a failing git ls-tree yields n=0 and
# fires the assertion. This covers checks 2 and 3 only; check 1's pathspec is
# "." and stays non-empty from anywhere, so its wrong-directory case is covered
# by the --show-prefix assertion above and its mistyped-pathspec case by
# nothing.
n=$(git ls-tree -r --name-only HEAD -- src/ | wc -l)
(( n > 0 )) || { echo "check-comment-refs: pathspec src/ matched no files" >&2; exit 2; }

# Deliberately a superset of the sweep's own acceptance regex: the year group
# is optional, so the three-digit form is caught as well, and the separator is
# optional so underscores and spaces are caught alongside hyphens. Narrowing
# this is how a whole class goes unguarded while every break-check still
# passes.
ID_PAT='(TASK|ISSUE|IDEA|QUICK|RECUR)[-_ ]?(20[0-9]{2}[-_ ])?[0-9]{3,4}'

# Verbatim from the sweep's enumerating pattern. Do not edit one without the
# other. If check 3's scope is ever widened beyond src/, this text matches
# itself through six of its alternatives and the widening must add
# ':(exclude)testing/check-comment-refs.sh' — never an exclusion of testing/,
# which holds real check-1 hits a directory-wide exclusion would drop.
VOCAB_PAT='\b[RQ][0-9]\b|Category-[A-Z]|\bumbrella\b|refactor steps?|\bpre-scopes\b|R0 stub|read-isolation|cut over yet|Cutover begins|in Step [0-9]|(the|this) milestone|Milestone-'

MD_PAT='[A-Za-z0-9_./-]+\.md\b'

FAILED=0

# ── Check 1: local item identifiers, repo-wide ──────────────────────────────
# The capture preserves git grep's status instead of flattening it with
# `|| true`: a legitimate no-hit run exits 1, but so would a malformed
# pathspec magic, an unresolvable rev or a bad regex exit 128, and collapsing
# both into "clean" is the single likeliest way this script reports green
# while checking nothing. The hit decision is made on the output; the
# could-not-look decision is made on the status.
rc=0
out=$(git grep -nEI "$ID_PAT" HEAD -- .) || rc=$?
if (( rc > 1 )); then
    echo "check-comment-refs: check 1 grep failed (rc=$rc)" >&2
    exit 2
fi
if [[ -n "$out" ]]; then
    printf '%s\n' "$out" \
        | sed -E 's|^HEAD:([^:]*):([0-9]+):|\1:\2: names a local work item: |'
    FAILED=1
fi

# ── Check 2: document paths under src/ must resolve in-repo ─────────────────
rc=0
md_lines=$(git grep -nI '\.md' HEAD -- src/) || rc=$?
if (( rc > 1 )); then
    echo "check-comment-refs: check 2 grep failed (rc=$rc)" >&2
    exit 2
fi

# Drop any line carrying a URL before extracting a token from it. Keying the
# skip on the extracted token cannot work: ':' is outside the token character
# class, so the scheme is stripped first and what survives does not begin with
# "http". Inert on today's tree, and kept so a future URL citation does not red.
cited=$(printf '%s\n' "$md_lines" | grep -vE 'https?://')

declare -A CITES=()
while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    loc=${line#HEAD:}
    loc=$(printf '%s' "$loc" | sed -E 's|^([^:]*):([0-9]+):.*|\1:\2|')
    content=$(printf '%s' "$line" | sed -E 's|^HEAD:[^:]*:[0-9]+:||')
    while IFS= read -r tok; do
        [[ -n "$tok" ]] || continue
        CITES["$tok"]+="$loc "
    done < <(printf '%s\n' "$content" | grep -oE "$MD_PAT")
done <<< "$cited"

if (( ${#CITES[@]} > 0 )); then
    while IFS= read -r tok; do
        [[ -n "$tok" ]] || continue
        lrc=0
        lsout=$(git ls-tree HEAD -- "$tok" 2>/dev/null) || lrc=$?
        # A '../'-prefixed or absolute token makes git ls-tree exit 128 with
        # "is outside repository". That is neither a hit nor clean: the check
        # could not look, and reporting it as a hit would red a legitimate
        # citation while reporting it as clean would hide one.
        if (( lrc != 0 )); then
            echo "check-comment-refs: could not resolve '$tok' (git ls-tree rc=$lrc)" >&2
            exit 2
        fi
        if [[ -z "$lsout" ]]; then
            for loc in ${CITES["$tok"]}; do
                printf '%s: cites %s, which does not exist in this repository\n' \
                    "$loc" "$tok"
            done
            FAILED=1
        fi
    done < <(printf '%s\n' "${!CITES[@]}" | sort)
fi

# ── Check 3: programme vocabulary under src/ ────────────────────────────────
rc=0
out=$(git grep -nEI "$VOCAB_PAT" HEAD -- src/) || rc=$?
if (( rc > 1 )); then
    echo "check-comment-refs: check 3 grep failed (rc=$rc)" >&2
    exit 2
fi
if [[ -n "$out" ]]; then
    printf '%s\n' "$out" \
        | sed -E 's|^HEAD:([^:]*):([0-9]+):|\1:\2: names a plan this repository does not carry: |'
    FAILED=1
fi

if (( FAILED != 0 )); then
    echo "" >&2
    echo "check-comment-refs: a source comment references something a reader holding" >&2
    echo "only this repository cannot resolve. Rewrite the comment to say what the" >&2
    echo "code does, citing nothing outside the tree." >&2
    exit 1
fi

exit 0
