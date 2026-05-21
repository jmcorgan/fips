# PR Review Checklist

<!-- markdownlint-disable MD013 -->

This is the 13-criteria checklist the maintainer runs against every
incoming PR. The first pass on any submission is exactly this list,
so executing it yourself before opening — or after pushing a fresh
revision — saves a review round trip and surfaces problems faster.

The document is also written so you can hand it to a coding agent
(Claude Code, Copilot, Cursor, Aider, etc.) with "review my branch
against this checklist" and get a structured pass. The agent gets
better results than a free-form "review my PR" because every concern
the maintainer cares about is enumerated below.

## Step 1 — Should this even be reviewed?

Skip the review (and say so) if the PR is:

- closed, merged, or marked draft
- automated (bot author, dependabot, etc.) and trivially OK
- so small and obviously correct (typo fix, single-line doc tweak)
  that a thirteen-point pass is overkill — a one-paragraph informal
  review is better in that case

## Step 2 — Gather context

Read these *before* analyzing the diff so the review is grounded:

1. PR metadata. Title, body, author, head ref, base ref, head SHA,
   base SHA, mergeable status, CI rollup, commit list.

   ```bash
   gh pr view <num> --json title,body,author,headRefName,baseRefName,headRefOid,baseRefOid,mergeable,statusCheckRollup,commits
   ```

2. The diff.

   ```bash
   gh pr diff <num>
   ```

3. Base-branch freshness. How many commits have landed on the PR's
   base since the PR forked from it.
4. Project guidance. Read [CLAUDE.md](CLAUDE.md) at the repo root and
   any nested `CLAUDE.md` in directories the diff touches. These
   describe project-specific conventions and constraints not visible
   from the diff alone.
5. Related work on GitHub. Skim the [open issues](https://github.com/jmcorgan/fips/issues)
   and other [open PRs](https://github.com/jmcorgan/fips/pulls) for
   work that overlaps, duplicates, partially addresses, or is unblocked
   by this PR.
6. For "this looks wrong" observations later: `git blame` the modified
   lines and read recent commit history on the same files for context
   before flagging something as a problem. What looks like a bug at
   first glance is often a deliberate workaround documented in a prior
   commit message.

## Step 3 — The 13 criteria

The review must address all 13 criteria below at some point. They
group naturally into PR hygiene, diff content, and cross-cutting
concerns — but the report itself is *not* organized this way; see
Step 4.

### Group A — PR hygiene (structural review)

1. **PR body and issue cross-reference**. Does the body accurately
   describe the change (feature added or bug fixed) and match what
   the diff actually does? Is there an associated issue that
   should be referenced via `Closes #N` / `Fixes #N`?
2. **Commit hygiene and base freshness**. Is the PR a clean set of
   commits (or a single commit) representing appropriately chunked
   development items, or are there intermediate "WIP" / "fix typo" /
   "address review" commits that should have been squashed? Is the
   branch based off a recent `maint` / `master` / `next`, or has the
   base diverged far enough that rebase work is needed?
3. **Commit message quality**. Are the commit messages well-structured
   (subject + body where the change warrants), accurately referencing
   everything actually in each commit, and free of extraneous footers
   — particularly coding-assistant attribution (`Generated with
   Claude Code`, `Co-Authored-By: Claude`, similar from other AI
   tools)?

### Group B — Diff content

4. **Does it do what it says it does**. Walk each claimed behavior
   from the PR body against the actual diff lines.
5. **Coherent whole**. Are all parts of the diff in service of the
   stated goal, or are there drive-by formatting changes, unrelated
   touch-ups, or scope creep?
6. **Fits the codebase as a natural extension**. Does the new code
   use existing idioms, helpers, error types, and patterns, or does
   it introduce new ones where existing ones would have served?

### Group C — Cross-cutting concerns

7. **New dependency surface**. Any new crates, system deps,
   build-time requirements, or external-service dependencies?
8. **New test coverage**. Are the new code paths covered, are the
   tests scoped correctly (unit / integration / end-to-end), and
   are there obvious test gaps? Don't reflag anything CI already
   enforces (formatting, lint, type errors, unit-test pass/fail).
9. **Documentation impact**. Does this need a CHANGELOG entry,
   rustdoc updates, design-doc changes
   ([docs/design/](docs/design/)), README adjustments, or operator
   doc updates in [docs/](docs/)?
10. **Security vulnerabilities**. Any new attack surface,
    untrusted-input parsing, `unsafe` blocks, panic-on-untrusted
    paths, secret-handling concerns, or side-channel exposure?
11. **Rust and OSS best practices**. Idiomatic error handling, no
    silently-swallowed errors, no `unwrap` / `expect` on untrusted
    input, no `#[allow]` without justification, appropriate
    visibility (`pub` vs `pub(crate)` vs private), naming, and
    module shape.
12. **Overlap with existing work**. Cross-check open issues and
    other open PRs (and recently closed/merged ones) for related
    work that overlaps, duplicates, partially addresses, or is
    unblocked by this PR.
13. **Other concerns**. Anything not captured above — wire-format
    implications, branch-flow questions (`maint` vs `master` vs
    `next`; see [docs/branching.md](docs/branching.md)),
    deployment / packaging impact, contributor coordination needs,
    fragility notes for future maintainers.

## Step 4 — Compose the review

The review report is **not** a Q&A walk through the 13 criteria.
Write it as natural prose in a coherent, integrated narrative that
reads start-to-finish. All 13 criteria must be addressed at some
point in the body, but ordering, grouping, and emphasis follow the
actual shape of THIS PR — lead with what matters most for this PR,
not a fixed template.

A typical shape that often falls out naturally:

- **Opening paragraph**: what the PR does and the headline
  observations (subsumes criteria 1 and 4).
- **Substantive body**: diff analysis, design fit, cross-cutting
  concerns, surprises, fragilities, missing coverage,
  cross-PR/issue overlap, anything unusual. Don't reference
  criterion numbers in the prose.
- **Closing**: short summary and a proposed disposition — *land*,
  *land-with-followups* (list them), *request-changes* (with the
  blocking items called out), or *hold-for-thematic-batch*.

Short subheadings are fine where they aid scanning. Bullets are fine
for enumerable items (test names, file paths, follow-up actions).
Avoid bullets that just enumerate criterion responses.

## Step 5 — Filter aggressively

Quality over quantity. Do not flag:

- Pre-existing issues on lines the PR did not modify
- Issues that linter, type-checker, formatter, or CI would catch
- Pedantic style nitpicks a senior engineer would not call out
- Likely intentional changes related to the broader goal
- Things explicitly silenced by an `#[allow]` with justification
- Stylistic preferences not anchored in `CLAUDE.md` or the
  surrounding codebase's idioms

When in doubt about whether something is worth surfacing: would a
senior maintainer skim past it, or would they want it raised?
Skim-past items don't belong in the report.

For every issue you *do* surface, include a concrete fix suggestion
inline ("rename X to Y", "extract this into the existing helper at
`foo.rs:42`", "add a test exercising the `Err` branch") so the
author can act without a round-trip.

## Step 6 — Citation discipline

When the review references a specific code location, use full-SHA
GitHub permalinks so the link survives future history rewrites:

```text
https://github.com/jmcorgan/fips/blob/<full-40-char-sha>/<path>#L<start>-L<end>
```

For multi-line ranges include at least one line of context before
and after the line(s) being discussed. After `gh pr checkout <num>`,
use `git rev-parse HEAD` to grab the full SHA — never partial SHAs
in permalinks.

## Notes

- The review is one human's read of the PR. Confidence calibration
  matters: distinguish "this is a blocker" from "this is worth asking
  about" from "this is a fragility note for future maintainers." The
  closing disposition makes the action explicit.
- If a re-review is triggered after the author pushes new commits,
  lead with the delta from the prior review rather than re-walking
  the whole PR.
- This checklist exists to surface problems, not to assign blame.
  If you're running it as the author or via an agent, treat each
  finding as "would the maintainer ask about this?" — and either fix
  it before opening, or pre-empt it in the PR body so the maintainer
  doesn't have to ask.
