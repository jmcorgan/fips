# src/utils/tests

Unit tests for the modules in `src/utils/`, one file per module, each compiled
as a child module of the file it tests so it can reach that file's private
items.

- `sockbind.rs`: the `fips` group lookup that every Unix socket bind makes,
  run from many threads at once. On musl a lookup through libc's static
  buffers corrupts the heap under that load, so a regression there crashes the
  test binary.

`sockbind.rs` in the parent directory also keeps an older inline `tests`
module for its directory and permission policy; it has not been moved here.
