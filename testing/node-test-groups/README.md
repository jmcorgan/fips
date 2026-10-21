# testing/node-test-groups

Data and fixture tests for `testing/check-node-test-groups.py`, the guard that
keeps the node test groups in `.config/nextest.toml` in step with the source.

nextest runs each test in its own process, so it keeps tests apart with test
groups rather than locks. Two groups run their tests one at a time:

- `node-large` holds the tests that take `lock_large_network_test()`, the
  100-node tests.
- `node-synthetic` holds the test modules under `src/node/tests/` that open a
  real socket, directly or through a helper.

Every other node test runs in parallel. The guard recomputes both memberships
from the source and fails when a socket module or a lock holder is outside its
group, so a new socket test cannot land outside the group unnoticed. Its
docstring states what counts as a socket use, how calls are resolved, the two
filter shapes it accepts, and its exit codes (0 pass, 1 finding, 2 cannot
check).

## Files

- `exemptions.toml`: primitive uses that open no socket, one entry per
  function and primitive, each with its reason. The guard reads it from here
  by default. One file serves `maint`, `master` and `next`, so an entry naming
  a function a branch lacks is reported as a note, not a failure.
- `test.sh`: the fixture runner. It runs from local CI's guards
  (`run_node_test_groups` in `testing/ci-local.sh`) and from the ci-parity job
  in `.github/workflows/ci.yml`; the two are kept in step by hand.
- `base.fixture`: a small tree that must pass. It is one file holding several:
  after its header, each `=== <path>` line starts a file at that path. Its
  modules cover each way a test can reach a socket (directly, through an
  aliased import, two helpers away, through a `src/testutil.rs` type, through a
  `#[path]` module, through a `mod.rs` helper that opens a connected UDP
  socket, through the rx loop's shutdown variant) and each way text only looks
  like one (comments, strings, raw strings, a `Vec`'s `.drain(`).
- `*.case`: one case each, in the same format. The runner writes a case's files
  over a copy of the base tree. The header's `#` lines say what the case
  breaks; `expect exit N` is the status the guard must return, and each
  `expect <text>` or `expect-absent <text>` is a string its output must or must
  not contain, so a case that fails for the wrong reason fails the runner.

## Rules for changing it

- A new way for a test to reach a socket gets a primitive in the guard, a
  module in `base.fixture` that uses it, and a case that leaves that module out
  of the group.
- Each check the guard makes is shown to fire by a case. A change that removes
  a check, or makes one pass on input it cannot read, should turn a case red;
  if no case turns red, add one.
- The fixture trees are never compiled. They need only the text the guard
  reads, written as real code would be.
