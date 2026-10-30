# Config unit tests

Unit tests for the files in `src/config/`. Each file here is the test module
of the source file of the same name, declared from that file as
`#[cfg(test)] #[path = "tests/<file>.rs"] mod tests;`, so it is a child module
of its source file and can reach that file's private items.

- `floors.rs`: tests for `Config::apply_floors` (`src/config/floors.rs`). A
  bloom update debounce below 500 ms runs at 500, and a bloom acceptance cap
  outside `[0.20, 1.0)` (below 0.20, 1.0 or more, or NaN) runs at 0.20, each
  with one warning naming the key, the configured value and the value used.
  A debounce of 500 ms or more and a cap in `[0.20, 1.0)` are left alone with
  no warning.
