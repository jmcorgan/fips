# testing/mutations

The mutation lane: breaks that each put back the shape a real defect took
in the node, or make the smallest change that fixes a known defect, and a
script that shows the tests named for each break react to it. A test that
no break turns red is not coverage; this directory is where the break is
written down and run.

Every break is a switch: a variant of `Fault` in `core/src/faults.rs`,
one list for both crates, written in the code behind `node_fault!(Name)`;
in a normal or release build that condition is the literal `false`, so the
branch compiles away. A test process turns it on with
`FIPS_NODE_FAULTS=<Name>`. Because the breaks are in the code, they move
with it, and the whole lane runs against one build.

## Files

- `run.sh`: in order, a preflight over the sources and the manifest; the
  normal-build fence; one build of both library test binaries with `testing/lib/test-verdict.sh`'s
  `test_bins`; a self-check of its own decision on two planted switches;
  every named test once with no switch; then each switch's lines against
  that build. Each test runs as its own process under a timeout and is
  classified with that library's `verdict`. It prints each break's wall
  time, each test's class and first message line, and the total. Exit 0
  when every line held, 1 on a miss, 2 when it could not run. The header
  of the script states the rules.
- `manifest.txt`: one line per test, tab-separated:
  `<break> <red|pass> <crate> <test path> [<anchor>]`, where `<break>` is
  the switch's variant name.

## What a line means

- `red`: the test must fail at its assertion of the behaviour the break
  breaks. With no anchor that is its `defect:` assertion (class `defect`).
  With an anchor the class may also be `unmarked`, and the anchor must match
  the panic's first message line (as a substring) or its location (as
  `file:line`). Anchors serve two cases: an existing test that predates the
  marker, and a test with more than one `defect:` assertion (one of the
  behaviour, one from the audit), where the anchor picks the one the break
  should reach.
- `pass`: the test must pass. A `pass` line under a fix shows a known-defect
  test's assertion can pass, so the lane would report its fix. A `pass` line
  under a break shows the break left another test, usually a twin, untouched.
- `precondition`, `timeout` and `norun` never hold: a test that broke in its
  setup or hung has not shown the break's effect.
- Every named test must also pass with no switch, unless
  `testing/ignored-tests.txt` marks it known-defect.

## What the script checks of itself

- The preflight fails on a line that names no variant, and on a variant
  with no manifest line or no `node_fault!` site. The self-check's two
  switches are the exception, by name: `PlantedRed` and `PlantedGreen`
  take no manifest line, and `PlantedGreen` has no site by design; the
  preflight fails if either gains a line or `PlantedGreen` gains a site.
- The self-check runs `PlantedRed` on
  `node::tests::settle::lane::a_planted_switch_reds_at_its_defect_assertion`,
  which must be decided held, and `PlantedGreen` on
  `a_planted_test_that_passes`, which must be decided a miss, both through
  the same decision as a red manifest line. A wrong decision exits 1 before
  any manifest line runs, so a healthy run exits 0 and a planted miss never
  appears as a manifest miss.

- The fence builds the `fips` binary as a user would
  (`cargo build -p fips-mesh --bin fips`) and requires the name
  `FIPS_NODE_FAULTS` to appear in it 0 times, so a build that let
  `test-hooks` into a normal build, and the switches with it, is a miss. A
  failed build or a missing binary exits 2 and is never read as a count of
  0. `FIPS_MUTATION_FENCE_BIN=<path>` hands it a binary to read instead of
  building one, and a path that is not an executable exits 2. Local CI
  passes the `fips` from the `.deb` its build stage made (`deb-build`), a
  release `--locked` build with no dev-dependency features, which is what
  users install; a run with no package lets the lane build its own, as
  GitHub's `test-mutations` job does, since it starts before its package
  exists.

## Hosts with no BLE transport

The BLE tests exist only where `build.rs` sets `ble_available` (glibc
Linux, Android, macOS). When the `fips-mesh` test binary lists no test
under `transport::ble::` at all, the lines whose test is in `run.sh`'s
`BLE_ONLY` list, four module prefixes and one test gated on its own, are
skipped, and the script prints how many. The skip is keyed on the host,
not the line: where `transport::ble::` tests are listed, a BLE line whose
test does not resolve is a miss, so a renamed BLE test is never skipped
silently. A new BLE line whose test is behind `ble_available` and missing
from `BLE_ONLY` reds on a host without BLE, the loud direction.

## Lines whose test is a root explorer

The root crate's explorer walks (`node::tests::settle::explore::oracle::`
and `::parity::`) compile only with its `explorers` feature, which no
GitHub workflow and no tier 1 run turns on. Without
`FIPS_MUTATION_EXPLORERS=1` the lane
builds without that feature, and when the build lists no test of one of
those modules, its lines (`run.sh`'s `EXPLORER_ONLY`) are skipped and
counted. Each skipped line's test must still be defined as `fn <name>(` in
its module's file, so a misspelled or renamed name is a miss in every
build. The lane then prints the switches left with no line to run: as of
this change `MoveSkipsWorkerOffer` and `WorldSkipsWorkerWait`, which only
explorer lines show red, so neither the plain lane nor GitHub's mutation
job shows them. With `FIPS_MUTATION_EXPLORERS=1` the lane builds the root
crate's library tests with the feature and every line must resolve and
run.

`FIPS_MUTATION_EXPLORERS=only` builds with the feature and runs those lines
alone, 20 of them over 7 switches as of this change (the two other lines
naming the module are its world tests, which every build compiles): every
other line is skipped, and the normal-build fence is left out, since the
plain lane runs it on the same tree. A manifest in which no line's test is
in an `EXPLORER_ONLY` module fails with exit 1 before anything is built, so
a renamed module cannot turn the stage into a run of nothing. Local CI runs
this mode as its own stage, `mutations-explorers`, wherever the root
explorers run: `testing/ci-local.sh --explorers` and `--tier 2` and `3`,
the internal builder's trunk-tip, landing and nightly runs, and nowhere on
GitHub (operator, 2026-11-24). The plain lane (`mutations`) skips those
lines, so the two stages together run every line once.

Next builds no real-node explorer: its handshake is XX and the explorer is
written for master's IK, so the module is under `#[cfg(any())]`
(`src/node/tests/settle/explore/README.md`). Its manifest therefore has no
line whose test is a root explorer, the lane skips nothing, and no switch
is left without a line to run (`WorldSkipsWorkerWait` does not exist
here). `--explorers` and `--tier 3` run the core half alone and `--tier 2`
none (`ROOT_EXPLORER` in `testing/ci-local.sh`), so there is no
`mutations-explorers` stage on next. `FIPS_MUTATION_EXPLORERS=only`
run by hand here exits 1 before building, since no line is an explorer
walk.

## Running it

`testing/mutations/run.sh` from any directory of a checkout. It runs in
the unit-test stage of local CI (`testing/ci-local.sh`, recorded as
`mutations`, at tiers 2 and 3 and in a run with no tier) and GitHub CI's
`test-mutations` job; `testing/check-ci-parity.sh` holds the two to each
other. `FIPS_MUTATION_ONLY=<break>` runs one break.
`FIPS_MUTATION_TIMEOUT` sets the per-test limit (default 120 s).

## Rules for changing it

- A new break is a switch: a variant of `Fault`, with a doc comment
  stating the defect's shape, and the change behind one `node_fault!`
  condition at the site, never a patch. The variant goes in the `faults!`
  invocation one name per line, which is how `run.sh` reads the list.
- A switch moves with the code it sits in. A change that moves or rewrites
  the code under a switch keeps the switch's shape there, never deletes it
  to make the lane pass.
- A fix probe (a `pass` break that puts a missing fix in) is retired by the
  change that lands the fix, and replaced in that change by the inverse
  break, which takes the fix out again and is `red` for the tests the probe
  passed.
- A new test line needs the break's red (or pass) shown in that change's
  record. Write a `red` anchor before the break is first run, from the
  test's own assertion, so the run checks the anchor rather than supplying
  it.
- `run.sh` is linted by `testing/check-shellcheck.sh`.
