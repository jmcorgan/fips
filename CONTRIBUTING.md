# Contributing to FIPS

<!-- markdownlint-disable MD013 -->

FIPS is a mesh routing protocol for Nostr identities over arbitrary
transports. The architecture is layered, top to bottom:

- **IPv6 TUN compatibility layer** — presents the mesh as a local
  network interface (`fips0`) so unmodified applications can use it.
  Applications send IPv6 packets to `fd::/8` addresses derived from
  Nostr pubkeys; the daemon converts between IPv6 packets and FSP
  datagrams.
- **FSP** (FIPS Session Protocol) — end-to-end encrypted sessions
  between identities, with periodic rekey.
- **FMP** (FIPS Mesh Protocol) — peer management, spanning tree,
  bloom filters, routing and forwarding, and link encryption.
- **Transport** — the actual wire: UDP, TCP, Tor, Bluetooth LE,
  Ethernet, and so on. Each transport plugs into FMP via a trait.

Most non-trivial changes affect behavior visible across the mesh —
how nodes find each other, how packets route, how sessions rekey, how
peers recover from failure. A single-node `cargo test` run is
necessary but not sufficient for that class of change; the integration
harness in [testing/](testing/) is where regressions actually surface.
This document covers the workflow assuming that context. Protocol
depth lives in [docs/design/](docs/design/).

## Quick start

```bash
git clone https://github.com/jmcorgan/fips.git
cd fips
cargo build
cargo test
```

The pinned toolchain in [rust-toolchain.toml](rust-toolchain.toml) is
used for deterministic builds. On Debian/Ubuntu, BLE-capable builds
need `bluez`, `libdbus-1-dev`, and `pkg-config` installed; the default
build picks up BLE if those are present and skips it cleanly if not.

For multi-node integration runs, Docker is required. The harness
under [testing/](testing/) starts containerized topologies and
exercises real mesh behavior; see [testing/README.md](testing/README.md)
for the suite catalog.

For a guided first-run that joins the public test mesh, see
[docs/tutorials/join-the-test-mesh.md](docs/tutorials/join-the-test-mesh.md).
Pointing your local daemon at a `test-*` node is the cheapest way to
dogfood a change end-to-end before opening a PR.

## Choosing a branch to target

FIPS uses three long-lived branches, each a superset of the previous:

- **`maint`** — bug fixes for the latest released version.
- **`master`** — compatible work for the next feature release.
- **`next`** — wire-format-breaking and API-breaking work, staged for
  the next forklift release.

Pick the branch that matches the scope of your change:

| Your change | Target |
| --- | --- |
| Bug fix in a feature that shipped in the latest release | `maint` |
| Bug fix in code added on `master` since the last release | `master` |
| Bug fix in `next`-only code (wire-format-breaking work) | `next` |
| New feature, no wire-format or API break | `master` |
| Wire-format-breaking or API-breaking change | `next` |
| Documentation, CI, contributor-facing changes | `maint` if they apply to released material, else `master` |

When in doubt, ask in the issue. The maintainer can retarget if
needed. The full release workflow, version conventions, and
merge-direction rationale are in [docs/branching.md](docs/branching.md).

## Reporting bugs

Search [open issues](https://github.com/jmcorgan/fips/issues) before
filing a new one — duplicates are common in a young project.

When you open a bug report, please include:

- **FIPS version** (`fipsctl --version`)
- **Rust toolchain version** (`rustc --version`)
- **OS / distro** (Linux distro + kernel, or macOS / Windows version)
- **What you expected to happen** — your mental model of the
  behavior, ideally referencing the relevant docs or config field.
- **What actually happened** — the observed behavior, including the
  surprise.
- **Reproduction steps** — minimal and deterministic if you can.
  Multi-node bugs should include the topology and per-node config
  excerpts.
- **Evidence** — relevant log excerpts (`journalctl -u fips` or stdout
  with `RUST_LOG=info` or `debug`), `fipsctl show` output if relevant
  (`peers`, `links`, `status`), and any visible mesh state.

One issue per bug. Don't bundle unrelated symptoms even if you
suspect they share a root cause — the maintainer will link them if
they turn out to be related.

## Submitting pull requests

### Scope discipline

Every PR should make one logical change. The reviewer should be able
to read the whole diff and trace every line back to the PR's stated
purpose.

- No drive-by reformatting of unrelated files.
- No unrelated refactors folded into a bug fix or a feature PR.
- No "while I was in there" cleanups in files outside the change's
  natural footprint. Send them as separate PRs; they'll usually land
  faster on their own.
- Pre-existing lint warnings in files you didn't touch are not yours
  to fix in this PR.

### Required before opening any PR

Run these locally and confirm they all pass:

```bash
cargo fmt --check
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
```

`fmt` and `clippy -D warnings` are CI gates — PRs with formatting
drift or new clippy warnings will fail CI and be sent back.

Then run the integration suite that exercises your change:

```bash
./testing/ci-local.sh --only <suite>
```

See [testing/README.md](testing/README.md) for the available suites
and what each covers. Routing, discovery, rekey, NAT, gateway, and
transport changes all have specific suites; pick the narrowest one
that touches your code path.

**Recommended before opening**: the full local CI run.

```bash
./testing/ci-local.sh
```

This is the same matrix that runs on GitHub Actions. Catching a
regression locally is much cheaper than catching it in CI.

### Additional requirements for feature PRs

- **New CI coverage.** Features added without a test that exercises
  them won't be reviewed. Either extend an existing integration
  suite or add a new one under `testing/`. Coverage of just the
  happy path is fine for an initial PR; edge cases can land as
  follow-ups.
- **Documentation updated alongside the code.** Protocol changes
  update the relevant [docs/design/](docs/design/) page. Config
  changes update the operator-facing docs in [docs/](docs/) and the
  reference config. Behavior visible to operators updates
  [README.md](README.md) and any tutorial it touches.

### Additional requirements for bug-fix PRs

- **A regression test** where practical. If a regression test isn't
  tractable (some bugs only surface under timing or scale that's hard
  to encode), say so in the PR description with a one-paragraph
  explanation.
- **Commit message references the bug**: the symptom, the root cause
  in one sentence, and the fix shape.

### Merge mechanics

PRs are merged via **squash-merge**. One logical change per PR
becomes one commit on the destination branch, which keeps `git
bisect` useful across the integration suite. Your in-PR commit
history doesn't matter for the final landed history — the maintainer
rewrites the commit message at merge time.

## AI coding assistant policy

Use of AI coding assistants (Claude Code, Copilot, Cursor, Aider, and
similar) in preparing a contribution is welcome. These tools are
force multipliers and we have no objection in principle to their use
in writing code, tests, documentation, or PR descriptions.

What we require is that the contributor does a thorough manual review
and editorial pass over the output before submission. Concretely:

- Verify that the code does what it claims, not just that it
  compiles.
- Verify that any tests the agent wrote actually test something
  useful, not just that they pass.
- Verify that any documentation matches the behavior.
- Spot-check the diff for nothing-surprising: no unrelated files
  modified, no fabricated APIs, no references to symbols that don't
  exist, no version bumps you didn't intend, no churn outside the
  change's natural footprint.
- Be ready to discuss the design choices in the PR as if you wrote
  every line, because for the purposes of accountability you did.

The coding agent is a tool. The contributor is the author of record
and is accountable for whatever they submit. PRs are reviewed on
what they contain, not on who or what wrote them.

**Review effort scales with submission effort.** A submission that
shows signs of being unreviewed agent output — irrelevant edits
scattered across the tree, hallucinated function names, mismatched
test/behavior pairs, fabricated API references, ChatGPT-style summary
prose in comments — will receive an AI-coding-agent reply in turn,
without human review. If you want a human reviewer's attention, do
the editorial pass yourself first.

Repeated submissions of unreviewed AI output will result in the
contributor being asked to step back and may result in account
restrictions.

## Where the conversation happens

- **GitHub issues** — bugs, feature requests, design discussions
  that don't fit on a specific PR.
- **GitHub PRs** — design discussion specific to a change in
  flight. Comment threads on the diff are the right place to push
  back on a decision.
- **[fips.network](https://fips.network)** — community page, podcast,
  and the project's Nostr account. Broader project conversation and
  announcements happen here.

For implementation questions specific to your PR, ask in the PR
itself. For design or roadmap questions that don't have a clear PR
home yet, file a GitHub issue with the `design` label.

## Further reading

- [docs/design/README.md](docs/design/README.md) — protocol design tree.
- [docs/branching.md](docs/branching.md) — full release workflow and
  merge-direction rationale.
- [docs/getting-started.md](docs/getting-started.md) — operator
  walkthrough for a new node.
- [docs/tutorials/join-the-test-mesh.md](docs/tutorials/join-the-test-mesh.md)
  — how to dogfood your change against the public test mesh.
- [testing/README.md](testing/README.md) — integration suite catalog.
