# Config unit tests

Unit tests for the files in `src/config/`. Each file here is a test module of
a source file one level up, declared from that file with
`#[cfg(test)] #[path = "tests/<file>.rs"]`, so it is a child module of its
source file and can reach that file's private items.

- `floors.rs`: tests for `Config::apply_floors` (`src/config/floors.rs`). A
  bloom update debounce below 500 ms runs at 500, and a bloom acceptance cap
  outside `[0.20, 1.0)` (below 0.20, 1.0 or more, or NaN) runs at 0.20, each
  with one warning naming the key, the configured value and the value used.
  An MMP one-way delay window (`node.mmp.owd_window_size`,
  `node.session_mmp.owd_window_size`) below 2 runs at 2 and one above 4096
  runs at 4096, with the same warning. A debounce of 500 ms or more, a cap in
  `[0.20, 1.0)` and a window from 2 to 4096 are left alone with no warning.
  An empty lookup retry ladder (`node.lookup.attempt_timeouts_secs`) runs as
  the default ladder, and a ladder over 255 entries runs its first 255, each
  with one warning; the default ladder and a 255-entry ladder are left alone.
  A second `apply_floors` call changes nothing and warns nothing.
- `native_flows.rs`: tests for the native API flow ceiling in
  `Config::validate`, declared from `mod.rs` as `mod native_flows`. A
  `node.native_api.max_flows` of 0 is refused at load, naming the key, and 1,
  the smallest working ceiling, is accepted.
