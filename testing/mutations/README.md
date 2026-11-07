# testing/mutations

The mutation lane: patches that each put back the shape a real defect took
in the node, or make the smallest change that fixes a known defect, and a
script that shows the tests named for each patch react to it. A test that no
break turns red is not coverage; this directory is where the break is
written down and run.

## Files

- `run.sh`: applies each patch in turn to a clean tree, builds both library
  test binaries once per patch with `testing/lib/test-verdict.sh`'s
  `test_bins`, runs each named test as its own process under a timeout,
  classifies the run with that library's `verdict`, and reverts the patch.
  It prints each patch's wall time, each test's class and first message
  line, and the total. Exit 0 when every line held, 1 on a miss, 2 when it
  could not run. The header of the script states the rules.
- `manifest.txt`: one line per test, tab-separated:
  `<patch> <red|pass> <crate> <test path> [<anchor>]`.
- `*.patch`: one break each, a unified diff against the repository root,
  applied with `git apply`. Each names in its file name what it changes,
  never a planning label.

## What a line means

- `red`: the test must fail at its assertion of the behaviour the patch
  breaks. With no anchor that is its `defect:` assertion (class `defect`).
  With an anchor the class may also be `unmarked`, and the anchor must match
  the panic's first message line (as a substring) or its location (as
  `file:line`). Anchors serve two cases: an existing test that predates the
  marker, and a test with more than one `defect:` assertion (one of the
  behaviour, one from the audit), where the anchor picks the one the patch
  should reach.
- `pass`: the test must pass. A `pass` line under a fix shows a known-defect
  test's assertion can pass, so the lane would report its fix. A `pass` line
  under a break shows the break left another test, usually a twin, untouched.
- `precondition`, `timeout` and `norun` never hold: a test that broke in its
  setup or hung has not shown the patch's effect.

## Running it

`testing/mutations/run.sh` from any directory of a clean checkout. It is a
named gate at the finished tip of each settlement increment, not a stage of
local CI: patches are written against one tree, and a refactor of the code
they patch makes them stop applying, which reds the lane rather than
skipping. `FIPS_MUTATION_ONLY=<patch>` runs one patch.
`FIPS_MUTATION_TIMEOUT` sets the per-test limit (default 120 s).

## Rules for changing it

- A patch that stops applying is rewritten against the current tree in the
  change that moved the code, never deleted to make the lane pass.
- A fix probe (a `pass` patch that puts a missing fix in) is retired by the
  change that lands the fix, and replaced in that change by the inverse
  break, which takes the fix out again and is `red` for the tests the probe
  passed.
- A new test line needs the patch's red (or pass) shown in that change's
  record. Write a `red` anchor before the patch is first run, from the
  test's own assertion, so the run checks the anchor rather than supplying
  it.
- `run.sh` is linted by `testing/check-shellcheck.sh`.
