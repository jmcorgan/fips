# FIPS Branching and Merging Strategy

<!-- markdownlint-disable MD013 -->

This document explains how the three long-lived branches relate, when
to target each one, and how merges propagate fixes and features. For
the day-to-day "how do I send a PR" workflow, see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Branch Structure

Three long-lived branches track parallel development streams:

```text
next    ──●──●──●──●──●──────────────●──●──  (wire-format-breaking work)
           \                        /
master  ────●──●──●──●──●──●──────●──●──●──  (compatible features, latest release line)
               \              /
maint   ────────●──●──●──●──●──────────────  (bug fixes for the latest release)
```

### maint

- Reset to each minor release tag at release time
- Accepts only bug fixes for functionality that shipped in the
  latest release
- No new features, no API changes, no wire-format changes
- Patch releases tag from here (e.g., `v0.3.1`, `v0.3.2`)
- Periodically merged forward into `master` so fixes propagate

### master

- Compatible development for the next feature release
- Multiple feature releases may ship from master (`v0.4.0`, `v0.5.0`)
  before `next` promotes
- No wire-format breaking changes; no API breaks
- Receives merges from `maint` so released-line fixes flow forward
- Periodically merged forward into `next`

### next

- Accumulates work that breaks wire format, API, or compatibility
- Receives merges from `master` so it stays current with bug fixes
  and compatible feature work
- Cargo version on `next` is the expected release version with a
  `-dev` suffix, updated if `master` ships additional minor
  releases first
- Becomes the new `master` at the next breaking release; at the same
  point the old `master` becomes the new `maint`

## Versioning

While the project is in the `0.x` era, semver treats minor bumps as
potentially breaking. Both `master` and `next` bump the minor version;
the distinction between compatible and breaking is captured in the
changelog and in which branch the work landed on.

The `-dev` suffix in `Cargo.toml` indicates an unreleased development
state on the branch.

## Merge Direction

Fixes and features flow in **one direction only**: `maint → master → next`.
Never merge backward (`next` into `master`, or `master` into `maint`).

```text
maint ──→ master ──→ next
```

This guarantees:

- Bug fixes shipped in a release reach all subsequent branches
- Compatible features reach `next`
- Wire-format-breaking work stays isolated on `next` until release

If you submit a PR on `next` that should also be on master or maint
(rare, since the criteria for needing it on multiple branches are
usually mutually exclusive), the PR stays on its target; the
maintainer either backports as a separate commit on the upstream
branch or asks you to.

## Choosing a Branch for Your PR

Pick the branch that matches the scope of your change:

| Your change | Target branch | Why |
| --- | --- | --- |
| Bug fix in a feature that shipped in the latest release | `maint` | Fix forward-merges to `master` and `next` |
| Bug fix in code added on `master` since the last release (not in any released version) | `master` | The released v0.x.y line is unaffected, so `maint` does not need the change |
| Bug fix in code added on `next` (wire-format-breaking work) | `next` | The bug only exists where the breaking work exists |
| New feature that does not break wire format or API | `master` | Becomes part of the next compatible release |
| Wire-format breaking change, API break, or fundamental protocol shape change | `next` | Stays isolated until the next forklift release |
| Documentation, CI, or contributor-facing changes | `maint` if they apply to released material, else `master` | Forward-merges propagate naturally |

If you are not sure, ask in the related issue. The safest defaults
are `master` for new features and `maint` for bug fixes; the
maintainer will retarget the PR if needed.

## Release Workflow

### Bug fix release (from `maint`)

1. Fix on `maint`
2. Bump patch version, tag (e.g., `v0.3.1`)
3. Merge `maint` into `master`
4. Merge `master` into `next`

### Compatible feature release (from `master`)

1. Finalize features on `master`
2. Merge `maint` into `master` to pick up any pending fixes
3. Set version, tag (e.g., `v0.4.0`)
4. Reset `maint` to the new tag
5. Bump `master` to the next `-dev` version
6. Merge `master` into `next`

### Breaking release (from `next`)

1. Finalize features on `next`
2. Merge `master` into `next` to pick up pending fixes and features
3. Assign version as the next minor after `master`'s last release, tag
4. `master` becomes the new `maint`
5. `next` becomes the new `master`
6. Create a new `next` branch from `master`

## Practical Guidelines

- **Commit to the appropriate branch for the scope of the change.**
  Do not commit bug fixes to `master` when they apply to the latest
  release — put them on `maint` and let the forward-merge propagate.
- **Feature branches base off the long-lived branch they target.**
  Create with `git checkout -b my-feature maint` (or `master` or
  `next`), not `git checkout -b my-feature origin/maint`. The
  `origin/`-prefixed form auto-sets the new branch's upstream to
  the source ref, which can cause `git push` to land on the wrong
  ref under some configurations.
- **When in doubt about whether a change is compatible**, target
  `next`. The maintainer can advise on retargeting.
- **Resolve merge conflicts on the receiving branch**, preserving
  both the inherited fix and the new development.
- **PRs are merged via squash-merge.** One logical change per PR
  becomes one commit on the destination branch, making bisect
  clean across the integration suite.
