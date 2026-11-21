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
- `tor_auth.rs`: tests for `Config::validate_tor_auth`, called first in
  `Config::validate`, declared from `mod.rs` as `mod tor_auth`. A Tor
  `control_auth` password holding a line feed, or a carriage return in a
  named instance's password, is refused at load, naming the instance's key
  and not echoing the password. An ordinary password, quotes included, and
  both cookie forms are accepted.
- `socket_path.rs`: tests for the default Unix socket path (`resolve_for`),
  declared from `mod.rs` as `mod socket_path`. A root process takes
  `/run/fips/<name>`, or `/var/run/fips/<name>` under the macOS and FreeBSD
  policy when `/run/fips` is absent, even with a valid `XDG_RUNTIME_DIR` and
  no directory present, and never a `/tmp` path. A non-root process keeps the
  XDG and `/tmp` fallbacks. The older resolver tests stay in `mod.rs`'s inline
  `tests` module.
- `root_search.rs`: tests for the warning a root start gives for the user
  configs it read (`warn_for`), declared from `mod.rs` as `mod root_search`.
  A root process that took its config from the search warns once for each
  file it read outside the system config paths (the user config directory,
  `~/.fips.yaml`, `./fips.yaml`), naming the file and `--config`. It does
  not warn for the system config, when `--config` named the file, or when
  not running as root. Every search path after the system paths draws the
  warning. It is logged at ERROR, which no `node.log_level` value filters
  out, so a planted file cannot hide the warning about itself.
