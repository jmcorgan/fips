# core/src/tests

Unit tests for the files at the crate root. This directory is not a module
of its own: each file is attached from its source file with
`#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so it is a child
module of that file, sees its private items and keeps its test names.

- `faults.rs`: tests for `faults.rs` (`faults::tests::...`): the reading of
  `FIPS_NODE_FAULTS`, through the pure `parse` and `load` the process's set
  is built from, since a test in the shared binary cannot set the variable
  for the process. An unknown name panics; empty entries name nothing; every
  switch is found by its own name.

- `testutil.rs`: tests for `testutil.rs` (`testutil::tests::...`): the
  bounded runner the explorers use runs its most jobs at once and never
  more, returns their results in order, raises a job's panic once every
  job has run, and starts each job on a fresh thread. Under `slow-tests`,
  `explorer_only` finds the `slow-explorers` gate on a test, on a module
  and on a test in an inline module, refuses an ungated test, a
  misspelled name and a missing module, and, in a build without the
  explorers, holds for no test the binary compiles.

## Rules for this level

- A file here is named for the source file it tests, one directory up, and
  holds only that file's tests.
- Keep this list in step with the directory.
