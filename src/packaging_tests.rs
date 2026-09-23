//! Checks that the shipped packaging files agree with each other and with the
//! code that consumes them.
//!
//! Every file is read at run time from the source tree rather than with
//! `include_str!`, so a file that is missing is a named test failure instead of
//! a compile error. Lines are trimmed at the end before matching, so a CRLF
//! checkout reads the same as an LF one.

use std::collections::HashMap;
use std::path::Path;

/// Reads `rel`, a path relative to the crate root, panicking with the path on
/// failure.
fn repo_file(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Returns the lines of a TOML document after the line `header`, up to the
/// next line that starts (untrimmed) with `[`.
///
/// Array entries indented under a key begin with spaces, so they do not end
/// the section.
fn toml_section<'a>(text: &'a str, header: &str) -> Vec<&'a str> {
    let mut lines = text.lines().map(str::trim_end);
    assert!(
        lines.by_ref().any(|l| l == header),
        "no {header} section found"
    );
    lines.take_while(|l| !l.starts_with('[')).collect()
}

/// Returns the package names in a comma-separated `key = "..."` value of
/// `[package.metadata.deb]`, each cut at its first space or `(` so a version
/// constraint is dropped.
fn deb_list(cargo_toml: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key} = \"");
    let value = toml_section(cargo_toml, "[package.metadata.deb]")
        .into_iter()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no `{key} = \"...\"` line in [package.metadata.deb]"));
    let value = value
        .strip_suffix('"')
        .unwrap_or_else(|| panic!("[package.metadata.deb] {key} is not a one-line string"));
    value
        .split(',')
        .map(|item| {
            let item = item.trim();
            let end = item.find([' ', '(']).unwrap_or(item.len());
            item[..end].to_string()
        })
        .collect()
}

/// Returns the single-quoted items of the bash array `name=( ... )` in a
/// PKGBUILD.
///
/// The opening `name=(` must start a line, so `depends` does not match
/// `makedepends=(` or `optdepends=(`. The array may span lines; unquoted `#`
/// starts a comment that runs to the end of the line.
fn bash_array(pkgbuild: &str, name: &str) -> Vec<String> {
    let open = format!("{name}=(");
    let mut lines = pkgbuild.lines().map(str::trim_end);
    let first = lines
        .by_ref()
        .find_map(|l| l.strip_prefix(open.as_str()))
        .unwrap_or_else(|| panic!("no line starting `{open}`"));
    let mut items = Vec::new();
    let mut quoted: Option<String> = None;
    for line in std::iter::once(first).chain(lines) {
        for c in line.chars() {
            match quoted.as_mut() {
                Some(item) if c == '\'' => {
                    items.push(std::mem::take(item));
                    quoted = None;
                }
                Some(item) => item.push(c),
                None if c == '\'' => quoted = Some(String::new()),
                None if c == ')' => return items,
                None if c == '#' => break,
                None => {}
            }
        }
        if let Some(item) = quoted.as_mut() {
            item.push('\n');
        }
    }
    panic!("`{open}` is never closed");
}

/// Returns the variables a FreeBSD rc script sets: `name="value"` assignments
/// at column 0 and `: ${name:="value"}` defaults.
///
/// `${var}` references in a value are expanded from the variables set on
/// earlier lines; an unset variable expands to nothing, as in sh.
fn rc_vars(rc: &str) -> HashMap<String, String> {
    let mut vars = HashMap::new();
    for line in rc.lines().map(str::trim_end) {
        let assignment = line
            .strip_prefix(": ${")
            .and_then(|rest| rest.strip_suffix('}'))
            .and_then(|rest| rest.split_once(":="))
            .or_else(|| line.split_once('='));
        let Some((name, value)) = assignment else {
            continue;
        };
        let is_name = !name.is_empty()
            && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
            && !name.starts_with(|c: char| c.is_ascii_digit());
        let Some(value) = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .filter(|_| is_name)
        else {
            continue;
        };
        let expanded = expand_vars(value, &vars);
        vars.insert(name.to_string(), expanded);
    }
    vars
}

/// Expands each `${name}` in `value` from `vars`, an unset name giving the
/// empty string.
fn expand_vars(value: &str, vars: &HashMap<String, String>) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .unwrap_or_else(|| panic!("unclosed ${{ in {value:?}"));
        out.push_str(vars.get(&after[..end]).map_or("", String::as_str));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Returns the lines of a shell script with trailing-backslash continuations
/// joined into one line each.
fn logical_lines(sh: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = String::new();
    for line in sh.lines().map(str::trim_end) {
        match line.strip_suffix('\\') {
            Some(head) => {
                pending.push_str(head);
                pending.push(' ');
            }
            None => {
                pending.push_str(line);
                out.push(std::mem::take(&mut pending));
            }
        }
    }
    if !pending.is_empty() {
        out.push(pending);
    }
    out
}

/// Returns the feature names declared in the `[features]` table of a
/// Cargo.toml.
fn cargo_features(cargo_toml: &str) -> Vec<String> {
    toml_section(cargo_toml, "[features]")
        .into_iter()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(key, _)| key.trim().to_string()))
        .collect()
}

/// Returns the cargo feature names a config file's comments mention: on each
/// `#` comment line, the token before the word `feature` or `features` when
/// that token is wrapped in `'`, `"` or `` ` ``.
fn feature_mentions(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines().map(str::trim) {
        if !line.starts_with('#') {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        for pair in words.windows(2) {
            let word = pair[1].trim_end_matches(|c: char| c.is_ascii_punctuation());
            if word != "feature" && word != "features" {
                continue;
            }
            let quoted = ['\'', '"', '`'].iter().find_map(|q| {
                pair[0]
                    .strip_prefix(*q)
                    .and_then(|rest| rest.strip_suffix(*q))
            });
            if let Some(name) = quoted {
                found.push(name.to_string());
            }
        }
    }
    found
}

/// Whether a config line, commented out or not, starts a `ble:` block.
fn is_ble_key(line: &str) -> bool {
    line.trim()
        .trim_start_matches('#')
        .trim_start()
        .starts_with("ble:")
}

#[test]
fn deb_and_aur_packages_declare_nftables_for_the_firewall_units_nft() {
    let unit = repo_file("packaging/debian/fips-firewall.service");
    assert!(
        unit.lines()
            .map(str::trim_end)
            .any(|l| l.starts_with("ExecStart=") && l.contains("/usr/sbin/nft")),
        "fips-firewall.service no longer starts /usr/sbin/nft; revisit whether the \
         packages still need to declare nftables"
    );

    let mut undeclared = Vec::new();

    let cargo = repo_file("Cargo.toml");
    let depends = deb_list(&cargo, "depends");
    let recommends = deb_list(&cargo, "recommends");
    assert!(
        recommends.iter().any(|d| d == "bluez") && depends.iter().any(|d| d == "systemd"),
        "control: expected bluez in recommends and systemd in depends, \
         read depends {depends:?}, recommends {recommends:?}"
    );
    if !depends.iter().chain(&recommends).any(|d| d == "nftables") {
        undeclared.push(format!(
            "Cargo.toml [package.metadata.deb]: depends {depends:?}, recommends {recommends:?}"
        ));
    }

    for rel in ["packaging/aur/PKGBUILD", "packaging/aur/PKGBUILD-git"] {
        let text = repo_file(rel);
        let depends = bash_array(&text, "depends");
        let optdepends: Vec<String> = bash_array(&text, "optdepends")
            .iter()
            .map(|item| {
                item.split(':')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            })
            .collect();
        assert!(
            optdepends.iter().any(|d| d == "systemd-resolved")
                && depends.iter().any(|d| d == "glibc"),
            "{rel} control: expected systemd-resolved in optdepends and glibc in depends, \
             read depends {depends:?}, optdepends {optdepends:?}"
        );
        if !depends.iter().chain(&optdepends).any(|d| d == "nftables") {
            undeclared.push(format!(
                "{rel}: depends {depends:?}, optdepends {optdepends:?}"
            ));
        }
    }

    assert!(
        undeclared.is_empty(),
        "fips-firewall.service runs /usr/sbin/nft, but nftables is declared in neither \
         the required nor the optional dependencies of:\n  {}",
        undeclared.join("\n  ")
    );
}

#[test]
fn freebsd_newsyslog_entry_signals_the_daemon8_supervisor_started_with_sighup_reopen() {
    let rc = repo_file("packaging/freebsd/fips.rc");
    let vars = rc_vars(&rc);
    let args = vars
        .get("command_args")
        .unwrap_or_else(|| panic!("fips.rc sets no command_args"));
    let procname = vars
        .get("procname")
        .unwrap_or_else(|| panic!("fips.rc sets no procname"));
    let tokens: Vec<&str> = args.split_whitespace().collect();
    // daemon(8)'s own options are the tokens before the command it runs.
    let daemon_opts = tokens
        .iter()
        .position(|t| t == procname)
        .map(|i| &tokens[..i])
        .unwrap_or_else(|| panic!("fips.rc command_args does not run {procname}: {args}"));
    let operand = |flag: &str, what: &str| -> String {
        daemon_opts
            .iter()
            .position(|t| *t == flag)
            .and_then(|i| daemon_opts.get(i + 1))
            .map(|s| s.to_string())
            .unwrap_or_else(|| panic!("fips.rc starts daemon(8) without {flag} <{what}>: {args}"))
    };
    let child_pidfile = operand("-p", "child pidfile");
    let supervisor_pidfile = operand("-P", "supervisor pidfile");
    let logfile = operand("-o", "log file");
    assert!(
        daemon_opts.contains(&"-H"),
        "fips.rc starts daemon(8) without -H, so a SIGHUP from newsyslog does not \
         reopen {logfile} and the daemon keeps writing into the rotated file: {args}"
    );
    assert_ne!(
        child_pidfile, supervisor_pidfile,
        "fips.rc gives daemon(8) the same pidfile for -p and -P"
    );

    let rel = "packaging/freebsd/fips.newsyslog";
    let entry = repo_file(rel);
    let entries: Vec<&str> = entry
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim_start().is_empty() && !l.trim_start().starts_with('#'))
        .collect();
    let [line] = entries[..] else {
        panic!("{rel}: expected exactly one entry, found {entries:?}");
    };
    let mut fields = line.split_whitespace().peekable();
    let entry_logfile = fields.next().unwrap_or_default();
    fields.next_if(|f| f.contains(':'));
    let mode = fields.next().unwrap_or_default();
    let entry_pidfile = fields.find(|f| f.starts_with('/'));
    assert_eq!(
        entry_logfile, logfile,
        "{rel} rotates a different file from the one fips.rc passes to daemon(8) -o"
    );
    assert_eq!(
        mode, "600",
        "{rel} creates the rotated log with a mode other than daemon(8)'s 600"
    );
    assert_eq!(
        entry_pidfile,
        Some(supervisor_pidfile.as_str()),
        "{rel} must signal the daemon(8) supervisor (-P), the only process that \
         reopens the log on SIGHUP; the child pidfile (-p) is {child_pidfile}"
    );

    let build = repo_file("packaging/freebsd/build-pkg.sh");
    let installed = "/usr/local/etc/newsyslog.conf.d/fips.conf";
    assert!(
        logical_lines(&build)
            .iter()
            .any(|l| l.starts_with("install")
                && l.contains("fips.newsyslog")
                && l.contains(installed)),
        "build-pkg.sh does not install fips.newsyslog as {installed}"
    );
    let plist: Vec<&str> = build
        .lines()
        .map(str::trim_end)
        .skip_while(|l| *l != r#"cat > "${STAGE}/pkg-plist" <<'EOF'"#)
        .skip(1)
        .take_while(|l| *l != "EOF")
        .collect();
    assert!(
        plist.contains(&"etc/rc.d/fips"),
        "control: build-pkg.sh pkg-plist heredoc not found or lacks etc/rc.d/fips: {plist:?}"
    );
    assert!(
        plist.contains(&"etc/newsyslog.conf.d/fips.conf"),
        "build-pkg.sh pkg-plist does not list etc/newsyslog.conf.d/fips.conf: {plist:?}"
    );
}

const COMMON_CONFIG: &str = "packaging/common/fips.yaml";
const OPENWRT_CONFIG: &str = "packaging/openwrt-ipk/files/etc/fips/fips.yaml";

#[test]
fn shipped_configs_name_only_cargo_features_that_exist() {
    assert_eq!(
        feature_mentions(
            "  # Bluetooth Low Energy transport — requires BlueZ and the 'ble' feature."
        ),
        ["ble"],
        "control: the feature-mention scanner no longer finds a quoted feature name"
    );
    let features = cargo_features(&repo_file("Cargo.toml"));
    assert!(
        features.iter().any(|f| f == "profiling"),
        "control: expected the profiling feature in Cargo.toml [features], read {features:?}"
    );

    let mut unknown = Vec::new();
    for rel in [COMMON_CONFIG, OPENWRT_CONFIG] {
        for name in feature_mentions(&repo_file(rel)) {
            if !features.contains(&name) {
                unknown.push(format!("{rel}: '{name}'"));
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "shipped configs name cargo features that Cargo.toml does not define \
         (it defines {features:?}):\n  {}",
        unknown.join("\n  ")
    );
}

#[test]
fn openwrt_config_offers_no_ble_block_because_musl_builds_have_no_ble() {
    assert!(
        repo_file(COMMON_CONFIG).lines().any(is_ble_key),
        "control: expected the ble: example in {COMMON_CONFIG}"
    );
    let text = repo_file(OPENWRT_CONFIG);
    let found: Vec<(usize, &str)> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| is_ble_key(l))
        .map(|(i, l)| (i + 1, l.trim_end()))
        .collect();
    assert!(
        found.is_empty(),
        "{OPENWRT_CONFIG} offers a ble: block, but OpenWrt builds target musl, \
         where the BLE transport is not compiled: {found:?}"
    );
}
