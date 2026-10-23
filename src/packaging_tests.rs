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

/// Returns the logical lines of a shell script, trimmed at both ends, without
/// the lines that are comments.
fn code_lines(sh: &str) -> Vec<String> {
    logical_lines(sh)
        .into_iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.starts_with('#'))
        .collect()
}

/// Returns the code lines of the `case` branch `label)` in a shell script:
/// those after the line that trims to `label)`, up to the next line that trims
/// to `;;`.
fn case_branch(sh: &str, label: &str) -> Vec<String> {
    let open = format!("{label})");
    let lines = code_lines(sh);
    let start = 1 + lines
        .iter()
        .position(|l| *l == open)
        .unwrap_or_else(|| panic!("no `{open}` branch found"));
    let len = lines[start..]
        .iter()
        .position(|l| l == ";;")
        .unwrap_or_else(|| panic!("`{open}` branch is never closed with `;;`"));
    lines[start..start + len].to_vec()
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

/// Pins the DNS cleanup in `postrm remove` and `postrm purge` and in
/// `uninstall.sh` to the files `fips-dns-setup` writes, so a remove or purge
/// after a `fips-dns` that never ran its teardown does not leave the resolver
/// sending `.fips` to a dead responder.
///
/// This is a text test. Each path must appear on an `rm -f` line, but a
/// resolver command passes wherever it appears on a code line, including in a
/// message. What `postrm` actually does is covered by the deb-install remove
/// and purge checks. No suite runs `uninstall.sh`: its two resolved paths were
/// run once, by hand in a container, and its dnsmasq and NetworkManager paths
/// by nothing.
#[test]
fn dns_cleanup_in_postrm_remove_and_purge_and_uninstall_removes_every_file_fips_dns_setup_writes_and_restarts_its_resolver()
 {
    let setup = rc_vars(&repo_file("packaging/common/fips-dns-setup"));
    let teardown = rc_vars(&repo_file("packaging/common/fips-dns-teardown"));
    let paths: Vec<&str> = [
        "DNS_DELEGATE_FILE",
        "RESOLVED_DROPIN_FILE",
        "DNSMASQ_CONF",
        "NM_DNSMASQ_CONF",
    ]
    .into_iter()
    .map(|name| {
        let path = setup
            .get(name)
            .filter(|p| p.starts_with('/'))
            .unwrap_or_else(|| panic!("fips-dns-setup sets no absolute {name}"));
        assert_eq!(
            teardown.get(name),
            Some(path),
            "fips-dns-teardown's {name} is not the file fips-dns-setup writes"
        );
        path.as_str()
    })
    .collect();
    let commands = [
        "restart systemd-resolved",
        "try-restart dnsmasq",
        "nmcli general reload",
    ];

    let scripts = [
        (
            "packaging/debian/postrm remove|purge)",
            case_branch(&repo_file("packaging/debian/postrm"), "remove|purge"),
        ),
        (
            "packaging/systemd/uninstall.sh",
            code_lines(&repo_file("packaging/systemd/uninstall.sh")),
        ),
    ];
    let mut missing = Vec::new();
    for (script, lines) in &scripts {
        for path in &paths {
            if !lines
                .iter()
                .any(|l| l.contains("rm -f") && l.contains(path))
            {
                missing.push(format!("{script}: no `rm -f` of {path}"));
            }
        }
        for command in commands {
            if !lines.iter().any(|l| l.contains(command)) {
                missing.push(format!("{script}: never runs `{command}`"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "DNS cleanup does not match the files fips-dns-setup writes and the resolvers \
         fips-dns-teardown restarts:\n  {}",
        missing.join("\n  ")
    );
}

/// Returns the lines of a PowerShell script, trimmed, without blank lines and
/// without lines that are only a `#` comment.
fn ps_lines(ps1: &str) -> Vec<String> {
    ps1.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Asserts that line `i` of install-service.ps1's code lines is an `if` whose
/// body is `Write-Error` then `exit 1`, so the condition it tests stops the
/// install rather than only reporting it.
fn refuses_at(lines: &[String], i: usize, what: &str) {
    let cond = &lines[i];
    assert!(
        cond.starts_with("if (") && cond.ends_with('{'),
        "install-service.ps1: the {what} is not an if statement: {cond}"
    );
    let body = lines.get(i + 1..i + 3).unwrap_or_default();
    assert!(
        body.len() == 2 && body[0].starts_with("Write-Error ") && body[1] == "exit 1",
        "install-service.ps1: the {what} is not followed by Write-Error then exit 1: \
         {cond}\n  then: {body:?}"
    );
}

/// Returns the index of the line that closes the block opened on line
/// `start`, found by brace depth. Braces inside single- or double-quoted
/// strings are not counted.
fn block_end(lines: &[String], start: usize) -> usize {
    let mut depth = 0i64;
    for (i, line) in lines.iter().enumerate().skip(start) {
        let mut quote = None;
        for c in line.chars() {
            match (quote, c) {
                (None, '"' | '\'') => quote = Some(c),
                (Some(q), _) if c == q => quote = None,
                (None, '{') => depth += 1,
                (None, '}') => depth -= 1,
                _ => {}
            }
        }
        if depth <= 0 {
            assert!(
                i > start,
                "install-service.ps1: no block opens at code line {start}: {}",
                lines[start]
            );
            return i;
        }
    }
    panic!(
        "install-service.ps1: the block at code line {start} never closes: {}",
        lines[start]
    )
}

/// Guards the order in which install-service.ps1 secures `C:\ProgramData\fips`.
///
/// The directory inherits `C:\ProgramData`'s access, under which any local
/// user can read the files in it and create missing ones, and a user can
/// create the directory, or a junction in its place, before the installer
/// runs, or turn an empty one into a junction. So the installer must build
/// the restricted ACL and create a new directory with it in one step, refuse
/// a link and a directory owned by another account, take ownership, check the
/// directory and the entries inside for links and folders before replacing
/// the ACL (applying it propagates into them) and again after it, reset each
/// file, check once more, and only then name any path inside the directory.
#[test]
fn windows_installer_restricts_config_dir_before_any_path_inside_it() {
    let lines = ps_lines(&repo_file("packaging/windows/install-service.ps1"));
    let nth = |what: &str, n: usize, pred: &dyn Fn(&str) -> bool| -> usize {
        lines
            .iter()
            .enumerate()
            .filter(|(_, l)| pred(l))
            .nth(n)
            .map(|(i, _)| i)
            .unwrap_or_else(|| {
                panic!(
                    "install-service.ps1: no {} line {what}",
                    ["first", "second", "third"][n]
                )
            })
    };
    let is_check = |l: &str| l == "& $refuseEntries";
    let is_create = |l: &str| l.contains("CreateDirectory(") && l.contains("$ConfigDir");

    let order = [
        (
            "SetAccessRuleProtection",
            nth(
                "containing SetAccessRuleProtection($true, $false)",
                0,
                &|l| l.contains("SetAccessRuleProtection($true, $false)"),
            ),
        ),
        (
            "creation of $ConfigDir",
            nth("containing CreateDirectory( and $ConfigDir", 0, &is_create),
        ),
        (
            "ReparsePoint check on $ConfigDir",
            nth("containing ReparsePoint", 0, &|l| {
                l.contains("ReparsePoint")
            }),
        ),
        (
            "owner check",
            nth("containing GetOwner", 0, &|l| l.contains("GetOwner")),
        ),
        (
            "directory /setowner",
            nth("containing /setowner", 0, &|l| l.contains("/setowner")),
        ),
        (
            "$refuseEntries definition",
            nth("starting $refuseEntries =", 0, &|l| {
                l.starts_with("$refuseEntries =")
            }),
        ),
        (
            "check before the lock",
            nth("that is & $refuseEntries", 0, &is_check),
        ),
        (
            "Set-Acl of $ConfigDir",
            nth("containing Set-Acl and $ConfigDir", 0, &|l| {
                l.contains("Set-Acl") && l.contains("$ConfigDir")
            }),
        ),
        (
            "check after the lock",
            nth("that is & $refuseEntries", 1, &is_check),
        ),
        (
            "child /setowner",
            nth("containing /setowner", 1, &|l| l.contains("/setowner")),
        ),
        (
            "child /reset",
            nth("containing /reset", 0, &|l| l.contains("/reset")),
        ),
        (
            "check after the reset",
            nth("that is & $refuseEntries", 2, &is_check),
        ),
        (
            "first path inside $ConfigDir",
            nth("containing $ConfigDir\\", 0, &|l| {
                l.contains("$ConfigDir\\")
            }),
        ),
    ];
    for pair in order.windows(2) {
        let [(a, ia), (b, ib)] = pair else {
            unreachable!("windows(2) yields pairs")
        };
        assert!(
            ia < ib,
            "install-service.ps1: {a} (code line {ia}) must come before {b} (code line {ib})"
        );
    }

    let (protect, create) = (order[0].1, order[1].1);
    for needle in [
        "S-1-5-18",
        "S-1-5-32-544",
        "ContainerInherit",
        "ObjectInherit",
    ] {
        assert!(
            lines[protect..create].iter().any(|l| l.contains(needle)),
            "install-service.ps1: the ACL built between SetAccessRuleProtection and \
             the creation of $ConfigDir does not name {needle}"
        );
    }
    for l in lines.iter().filter(|l| l.contains("CreateDirectory")) {
        assert!(
            l.contains("$acl") && l.contains("$ConfigDir"),
            "install-service.ps1: $ConfigDir must be created with $acl in one step: {l}"
        );
    }
    if let Some(l) = lines
        .iter()
        .find(|l| l.contains("New-Item") && l.contains("$ConfigDir"))
    {
        panic!("install-service.ps1: New-Item creates $ConfigDir without its ACL: {l}");
    }
    let set_acl = &lines[order[7].1];
    assert!(
        set_acl.contains("-AclObject $acl"),
        "install-service.ps1: Set-Acl does not apply the ACL built for creation: {set_acl}"
    );

    let (def, first_check) = (order[5].1, order[6].1);
    let block = &lines[def..first_check];
    assert!(
        block
            .iter()
            .any(|l| l.contains("Get-Item -LiteralPath $ConfigDir") && l.contains("ReparsePoint")),
        "install-service.ps1: the $refuseEntries script block does not test whether \
         $ConfigDir itself has become a link"
    );
    assert!(
        block.iter().any(|l| l.contains("Get-ChildItem -LiteralPath $ConfigDir")
            && !l.contains("-Recurse")),
        "install-service.ps1: the $refuseEntries script block does not list $ConfigDir's entries"
    );
    for needle in ["ReparsePoint", "PSIsContainer"] {
        assert!(
            block
                .iter()
                .any(|l| l.contains("$item") && l.contains(needle)),
            "install-service.ps1: the $refuseEntries script block does not test {needle} \
             on each entry"
        );
    }

    let checks = lines.iter().filter(|l| is_check(l)).count();
    assert_eq!(
        checks, 3,
        "install-service.ps1: expected exactly three & $refuseEntries lines, found {checks}"
    );
    let setowners = lines.iter().filter(|l| l.contains("/setowner")).count();
    assert_eq!(
        setowners, 2,
        "install-service.ps1: expected exactly two /setowner lines, found {setowners}"
    );
    if let Some(l) = lines.iter().find(|l| l.contains("-Recurse")) {
        panic!("install-service.ps1: -Recurse is not allowed: {l}");
    }
}

/// Guards what install-service.ps1's ACL grants and who it makes owner, not
/// only the order of the steps.
///
/// The ACL must allow SYSTEM and Administrators full control and grant no one
/// else anything: granting Users read would expose the identity key and make
/// an unelevated `fipsctl address` work again. Both `/setowner` calls must
/// name Administrators. The PowerShell 7 `FileSystemAclExtensions` type must
/// be used only on Core, since Windows PowerShell 5.1's .NET Framework lacks
/// it.
#[test]
fn windows_installer_acl_allows_only_system_and_administrators_and_makes_administrators_owner() {
    let lines = ps_lines(&repo_file("packaging/windows/install-service.ps1"));

    let sid_loops: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with("foreach ($sid in "))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        sid_loops.len(),
        1,
        "install-service.ps1: expected one loop over the SIDs the ACL allows"
    );
    let sid_loop = sid_loops[0];
    assert_eq!(
        lines[sid_loop], r#"foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {"#,
        "install-service.ps1: the ACL must allow exactly SYSTEM and Administrators"
    );
    let body = &lines[sid_loop + 1..block_end(&lines, sid_loop)];
    for (what, want) in [
        (
            "the rule's account",
            "[System.Security.Principal.SecurityIdentifier]::new($sid),",
        ),
        (
            "the rule's rights",
            "[System.Security.AccessControl.FileSystemRights]::FullControl,",
        ),
        (
            "the rule's type",
            "[System.Security.AccessControl.AccessControlType]::Allow)",
        ),
        ("the rule's addition to $acl", "$acl.AddAccessRule($rule)"),
    ] {
        assert!(
            body.iter().any(|l| l == want),
            "install-service.ps1: the SID loop does not have {what} as {want}"
        );
    }
    for needle in [
        "FileSystemAccessRule",
        "FileSystemRights]::",
        "AccessControlType]::",
        "AccessRule(",
    ] {
        let uses = lines.iter().filter(|l| l.contains(needle)).count();
        let inside = body.iter().filter(|l| l.contains(needle)).count();
        assert!(
            uses == 1 && inside == 1,
            "install-service.ps1: expected {needle} exactly once, inside the SID loop; \
             found {uses}, {inside} inside"
        );
    }

    let setowners: Vec<&String> = lines.iter().filter(|l| l.contains("/setowner")).collect();
    assert!(
        !setowners.is_empty(),
        "install-service.ps1: no /setowner line"
    );
    for l in setowners {
        assert!(
            l.contains(r#"/setowner "*S-1-5-32-544" "#),
            "install-service.ps1: /setowner must make Administrators the owner: {l}"
        );
    }

    let editions: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("PSEdition"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        editions.len(),
        1,
        "install-service.ps1: expected one PSEdition test"
    );
    let at = editions[0];
    let want = [
        r#"if ($PSVersionTable.PSEdition -eq "Core") {"#,
        "[System.IO.FileSystemAclExtensions]::CreateDirectory($acl, $ConfigDir) | Out-Null",
        "} else {",
        "[System.IO.Directory]::CreateDirectory($ConfigDir, $acl) | Out-Null",
        "}",
    ];
    assert_eq!(
        lines.get(at..at + want.len()).unwrap_or_default(),
        want,
        "install-service.ps1: FileSystemAclExtensions must be used only when PSEdition is \
         Core, and Directory.CreateDirectory otherwise"
    );
}

/// Guards the conditions under which install-service.ps1 refuses its config
/// directory, not only their position.
///
/// Each refusal must be an `if` whose body is `Write-Error` then `exit 1`: an
/// owner outside SYSTEM, Administrators and the installing account; the
/// directory being a link, both at the start and inside every recheck; and an
/// entry that is a link or a folder, either of which is enough. A condition
/// that can never hold, or that needs both a link and a folder, would pass an
/// ordering check while refusing nothing.
#[test]
fn windows_installer_refusal_conditions_stop_the_install() {
    let lines = ps_lines(&repo_file("packaging/windows/install-service.ps1"));
    let find = |what: &str, pred: &dyn Fn(&str) -> bool| -> Vec<usize> {
        let found: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| pred(l))
            .map(|(i, _)| i)
            .collect();
        assert!(
            !found.is_empty(),
            "install-service.ps1: no line found for the {what}"
        );
        found
    };

    let trusted = find("list of trusted owners", &|l| {
        l.starts_with("$trustedOwners = @(")
    });
    assert_eq!(
        trusted.len(),
        1,
        "install-service.ps1: expected one list of trusted owners"
    );
    let owners: Vec<&str> = lines[trusted[0]]
        .strip_prefix("$trustedOwners = @(")
        .and_then(|l| l.strip_suffix(')'))
        .unwrap_or_else(|| {
            panic!(
                "install-service.ps1: the trusted owners are not one @( ) list: {}",
                lines[trusted[0]]
            )
        })
        .split(',')
        .map(str::trim)
        .collect();
    assert_eq!(
        owners,
        [
            "\"S-1-5-18\"",
            "\"S-1-5-32-544\"",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ],
        "install-service.ps1: the trusted owners must be exactly SYSTEM, Administrators \
         and the installing account"
    );
    for i in find("owner refusal", &|l| {
        l == "if ($trustedOwners -notcontains $ownerSid) {"
    }) {
        refuses_at(&lines, i, "owner refusal");
    }

    let dir_links = find("refusal of $ConfigDir as a link", &|l| {
        l.starts_with("if (") && l.contains("ReparsePoint") && !l.contains("$item")
    });
    assert_eq!(
        dir_links.len(),
        2,
        "install-service.ps1: expected the directory's link check once at the start and \
         once in $refuseEntries, found {}",
        dir_links.len()
    );
    for i in dir_links {
        refuses_at(&lines, i, "refusal of $ConfigDir as a link");
    }

    for i in find("refusal of a link or folder entry", &|l| {
        l.starts_with("if (") && l.contains("$item")
    }) {
        let cond = &lines[i];
        assert!(
            cond.contains("ReparsePoint")
                && cond.contains("PSIsContainer")
                && cond.contains(" -or ")
                && !cond.contains(" -and "),
            "install-service.ps1: an entry must be refused if it is a link or a folder, \
             either one: {cond}"
        );
        refuses_at(&lines, i, "refusal of a link or folder entry");
    }
}

/// Guards the recovery install-service.ps1 gives for a directory it refuses.
///
/// A user who created `C:\ProgramData\fips` holds full control of it through
/// an inherited entry for their own account. Taking ownership changes only the
/// owner, so the installer's owner check would then pass while that user could
/// still swap the directory for a junction. The recovery must be to delete the
/// directory, and the installer must not offer `takeown` as a way through.
#[test]
fn windows_installer_refusals_never_offer_takeown_as_the_recovery() {
    let lines = ps_lines(&repo_file("packaging/windows/install-service.ps1"));
    if let Some(l) = lines
        .iter()
        .find(|l| l.to_ascii_lowercase().contains("takeown"))
    {
        panic!("install-service.ps1: a refusal offers takeown as the recovery: {l}");
    }
    let owner_refusals = lines
        .iter()
        .filter(|l| l.contains("Write-Error") && l.contains("delete the directory"))
        .count();
    assert!(
        owner_refusals >= 2,
        "install-service.ps1: expected the owner refusals to say to delete the directory, \
         found {owner_refusals} such lines"
    );
}

/// Guards every icacls call in install-service.ps1: each acts on a link itself
/// rather than its target (`/L`), never walks a tree (`/T`), and has its exit
/// code checked on the next line, since `$ErrorActionPreference = "Stop"` does
/// not cover a native command's exit code in Windows PowerShell 5.1.
#[test]
fn windows_installer_icacls_calls_act_on_links_and_check_exit_codes() {
    let lines = ps_lines(&repo_file("packaging/windows/install-service.ps1"));
    let calls: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("& $icacls"))
        .map(|(i, _)| i)
        .collect();
    assert!(
        calls.len() >= 3,
        "install-service.ps1: expected at least three & $icacls calls, found {}",
        calls.len()
    );
    for i in calls {
        let call = &lines[i];
        let tokens: Vec<&str> = call.split_whitespace().collect();
        assert!(
            tokens.iter().any(|t| t.eq_ignore_ascii_case("/L")),
            "install-service.ps1: icacls call without /L follows a link: {call}"
        );
        assert!(
            !tokens.iter().any(|t| t.eq_ignore_ascii_case("/T")),
            "install-service.ps1: icacls call with /T walks the tree: {call}"
        );
        let next = lines.get(i + 1).map(String::as_str).unwrap_or_default();
        assert!(
            next.contains("$LASTEXITCODE"),
            "install-service.ps1: icacls call not followed by a $LASTEXITCODE check: \
             {call}\n  next line: {next}"
        );
    }
}

/// Guards the peer ACL files install-service.ps1 creates, and its refusal of
/// legacy ones.
///
/// Earlier releases read `peers.allow` and `peers.deny` from `\etc\fips` on
/// the system drive, where any local user can create files, and the service
/// still reads a file there when it is missing from `C:\ProgramData\fips`. So
/// for each of the two files the installer must stop when the legacy file
/// exists and the current one does not, which is exactly when the service
/// would enforce the legacy file, and otherwise create the current file empty
/// if it is missing, without truncating one that exists. Every refusal is
/// decided before any file is created, and all of it happens after the config
/// directory is secured and before the binaries are copied or the service is
/// registered, so a refusal leaves an existing install's binaries, config and
/// service as they were. Each check is bounded by its loop's closing brace,
/// since a statement moved out of its loop runs for the last file only.
#[test]
fn windows_installer_creates_empty_peer_acl_files_and_refuses_legacy_ones() {
    let lines = ps_lines(&repo_file("packaging/windows/install-service.ps1"));
    let all = |pred: &dyn Fn(&str) -> bool| -> Vec<usize> {
        lines
            .iter()
            .enumerate()
            .filter(|(_, l)| pred(l))
            .map(|(i, _)| i)
            .collect()
    };
    let first = |what: &str, pred: &dyn Fn(&str) -> bool| -> usize {
        all(pred)
            .first()
            .copied()
            .unwrap_or_else(|| panic!("install-service.ps1: no line {what}"))
    };

    let legacy_dir = first("assigning $legacyDir", &|l| l.starts_with("$legacyDir = "));
    assert_eq!(
        lines[legacy_dir], r#"$legacyDir = "$env:SystemDrive\etc\fips""#,
        "install-service.ps1: the legacy peer ACL directory is not \\etc\\fips on the \
         system drive"
    );

    let loop_line = r#"foreach ($name in @("peers.allow", "peers.deny")) {"#;
    let loops = all(&|l| {
        l.starts_with("foreach") && (l.contains("peers.allow") || l.contains("peers.deny"))
    });
    assert_eq!(
        loops.len(),
        2,
        "install-service.ps1: expected two loops over the peer ACL files, the refusal \
         and the creation, found {}",
        loops.len()
    );
    for &i in &loops {
        assert_eq!(
            lines[i], loop_line,
            "install-service.ps1: a peer ACL loop does not cover both files"
        );
    }
    let (refusal, creation) = (loops[0], loops[1]);
    let (refusal_end, creation_end) = (block_end(&lines, refusal), block_end(&lines, creation));
    let refusal_body = refusal + 1..refusal_end;
    let creation_body = creation + 1..creation_end;

    for text in [
        "$legacy = Join-Path $legacyDir $name",
        r#"$current = "$ConfigDir\$name""#,
    ] {
        assert!(
            lines[refusal_body.clone()].iter().any(|l| l == text),
            "install-service.ps1: the refusal loop has no line {text}"
        );
    }
    let check = refusal_body
        .clone()
        .find(|&i| lines[i].starts_with("if (") && lines[i].contains("$legacy"))
        .unwrap_or_else(|| {
            panic!("install-service.ps1: the refusal loop does not test the legacy file")
        });
    assert_eq!(
        lines[check],
        "if ((Test-Path -LiteralPath $legacy) -and -not (Test-Path -LiteralPath $current)) {",
        "install-service.ps1: the refusal must hold only when the legacy file exists and \
         the current one does not"
    );
    refuses_at(&lines, check, "refusal of a legacy peer ACL file");
    assert!(
        block_end(&lines, check) < refusal_end,
        "install-service.ps1: the refusal of a legacy peer ACL file does not close inside \
         the refusal loop"
    );

    let aclfile_line = r#"$aclFile = "$ConfigDir\$name""#;
    let guard_line = "if (-not (Test-Path -LiteralPath $aclFile)) {";
    let create = creation_body
        .clone()
        .find(|&i| lines[i].contains("New-Item") && lines[i].contains("-ItemType File"))
        .unwrap_or_else(|| panic!("install-service.ps1: the creation loop does not create a file"));
    let new_item = &lines[create];
    assert!(
        new_item.contains("$aclFile") && !new_item.to_ascii_lowercase().contains("-force"),
        "install-service.ps1: the peer ACL file must be created at $aclFile without -Force, \
         which would truncate an existing list: {new_item}"
    );
    assert!(
        lines[creation + 1..create]
            .iter()
            .any(|l| l == aclfile_line),
        "install-service.ps1: the creation loop does not set $aclFile to the file in $ConfigDir"
    );
    let guard = create - 1;
    assert!(
        lines[guard] == guard_line && block_end(&lines, guard) < creation_end,
        "install-service.ps1: the peer ACL file is not created only when it is missing"
    );
    for l in &lines[creation_body] {
        assert!(
            [aclfile_line, guard_line, new_item.as_str(), "}"].contains(&l.as_str())
                || l.starts_with("Write-Host "),
            "install-service.ps1: the creation loop does more than create a missing file: {l}"
        );
    }

    let is_check = |l: &str| l == "& $refuseEntries";
    let order = [
        ("check after the reset", all(&is_check).get(2).copied()),
        ("$legacyDir", Some(legacy_dir)),
        ("refusal loop", Some(refusal)),
        ("refusal of a legacy file", Some(check)),
        ("end of the refusal loop", Some(refusal_end)),
        ("creation loop", Some(creation)),
        ("creation of a peer ACL file", Some(create)),
        ("end of the creation loop", Some(creation_end)),
        (
            "binary copy",
            all(&|l| l.contains("$Binaries")).first().copied(),
        ),
        (
            "service registration",
            all(&|l| l.contains("--install-service")).first().copied(),
        ),
    ];
    for pair in order.windows(2) {
        let [(a, ia), (b, ib)] = pair else {
            unreachable!("windows(2) yields pairs")
        };
        let (ia, ib) = (
            ia.unwrap_or_else(|| panic!("install-service.ps1: no {a}")),
            ib.unwrap_or_else(|| panic!("install-service.ps1: no {b}")),
        );
        assert!(
            ia < ib,
            "install-service.ps1: {a} (code line {ia}) must come before {b} (code line {ib})"
        );
    }
}

/// Guards install-service.ps1's refusal of an identity key left in
/// `\etc\fips`.
///
/// A service that earlier releases ran from `\etc\fips` reads only
/// `C:\ProgramData\fips` once the installer sets `FIPS_CONFIG`, so a key left
/// in `\etc\fips` with none in the config directory means the node would
/// come up with a new identity. The installer must stop in exactly that case,
/// and must decide it before it creates any file in the config directory,
/// copies the binaries or registers the service, so a refusal leaves an
/// existing install as it was.
#[test]
fn windows_installer_refuses_a_legacy_identity_key_with_none_in_the_config_dir() {
    let lines = ps_lines(&repo_file("packaging/windows/install-service.ps1"));
    let first = |what: &str, pred: &dyn Fn(&str) -> bool| -> usize {
        lines
            .iter()
            .position(|l| pred(l))
            .unwrap_or_else(|| panic!("install-service.ps1: no line {what}"))
    };

    let dir = first("assigning $legacyDir", &|l| l.starts_with("$legacyDir = "));
    let key = first("assigning $legacyKey", &|l| l.starts_with("$legacyKey = "));
    assert_eq!(
        lines[key], r#"$legacyKey = Join-Path $legacyDir "fips.key""#,
        "install-service.ps1: the legacy key is not fips.key in $legacyDir"
    );
    let checks: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with("if (") && l.contains("$legacyKey"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        checks.len(),
        1,
        "install-service.ps1: expected one test of the legacy key, found {}",
        checks.len()
    );
    let check = checks[0];
    assert_eq!(
        lines[check],
        r#"if ((Test-Path -LiteralPath $legacyKey) -and -not (Test-Path -LiteralPath "$ConfigDir\fips.key")) {"#,
        "install-service.ps1: the refusal must hold only when the legacy key exists and \
         the config directory has none"
    );
    refuses_at(&lines, check, "refusal of a legacy identity key");

    let order = [
        ("$legacyDir", Some(dir)),
        ("$legacyKey", Some(key)),
        ("refusal of a legacy identity key", Some(check)),
        (
            "creation of a peer ACL file",
            lines
                .iter()
                .position(|l| l.contains("New-Item") && l.contains("-ItemType File")),
        ),
        (
            "binary copy",
            lines.iter().position(|l| l.contains("$Binaries")),
        ),
        (
            "default config copy",
            lines
                .iter()
                .position(|l| l.contains("Copy-Item") && l.contains("$ConfigDir\\fips.yaml")),
        ),
        (
            "service registration",
            lines.iter().position(|l| l.contains("--install-service")),
        ),
    ];
    for pair in order.windows(2) {
        let [(a, ia), (b, ib)] = pair else {
            unreachable!("windows(2) yields pairs")
        };
        let (ia, ib) = (
            ia.unwrap_or_else(|| panic!("install-service.ps1: no {a}")),
            ib.unwrap_or_else(|| panic!("install-service.ps1: no {b}")),
        );
        assert!(
            ia < ib,
            "install-service.ps1: {a} (code line {ia}) must come before {b} (code line {ib})"
        );
    }
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

/// `fips-dns-setup` is shared by the Debian package, the Arch packages, the
/// systemd tarball and, where it is packaged, the RPM, so the hint it prints
/// when it finds no DNS resolver must not tell the host to use one
/// distribution's package manager.
///
/// Every systemd-resolved backend in the script gates on the unit being active
/// (`is_active`), so the hint must say to start it (`enable --now`), not only to
/// install or enable it, and then to restart `fips-dns.service` so detection
/// runs again. `test_no_resolver` in `testing/dns-resolver/test.sh` asserts the
/// same on the script's real output.
#[test]
fn fips_dns_setup_no_resolver_hint_starts_resolved_and_names_no_package_manager_because_the_script_is_not_debian_only()
 {
    const SETUP: &str = "packaging/common/fips-dns-setup";
    const BANNED: [&str; 6] = [
        "apt install",
        "apt-get install",
        "dnf install",
        "yum install",
        "zypper install",
        "pacman -S",
    ];
    let lines = code_lines(&repo_file(SETUP));
    let mut problems = Vec::new();

    let hints: Vec<&String> = lines
        .iter()
        .filter(|l| l.starts_with("log \"  systemd-resolved:"))
        .collect();
    match hints.as_slice() {
        [hint] => {
            for needed in ["enable --now", "restart fips-dns.service"] {
                if !hint.contains(needed) {
                    problems.push(format!("hint lacks '{needed}': {hint}"));
                }
            }
        }
        _ => problems.push(format!(
            "expected one systemd-resolved hint line, found {}: {hints:?}",
            hints.len()
        )),
    }
    for line in &lines {
        for banned in BANNED {
            if line.contains(banned) {
                problems.push(format!("names a package manager ('{banned}'): {line}"));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "{SETUP}'s no-resolver hint is wrong:\n  {}",
        problems.join("\n  ")
    );
}

/// Returns the paths, relative to the crate root, of the files directly in
/// `rel`, sorted, panicking with the path on failure.
fn repo_dir_files(rel: &str) -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{rel}: {e}"))
        .map(|entry| entry.unwrap_or_else(|e| panic!("{rel}: {e}")))
        .filter(|entry| entry.path().is_file())
        .map(|entry| format!("{rel}/{}", entry.file_name().to_string_lossy()))
        .collect();
    files.sort();
    files
}

/// procd stops respawning a service for good once its retry count is used up,
/// and nothing starts it again, so a router whose daemon fails a few times in
/// a row would stay off the mesh. Every procd instance the OpenWrt package
/// declares must respawn without a limit: `respawn <threshold> <timeout> 0`.
#[test]
fn openwrt_services_respawn_without_a_retry_limit() {
    const DIR: &str = "packaging/openwrt-ipk/files/etc/init.d";
    const RESPAWNING: [&str; 2] = ["fips", "fips-gateway"];
    let inits = repo_dir_files(DIR);
    let mut problems = Vec::new();
    for name in RESPAWNING {
        if !inits.contains(&format!("{DIR}/{name}")) {
            problems.push(format!("control: {DIR}/{name} is missing"));
        }
    }
    for init in &inits {
        let script = repo_file(init);
        let respawns: Vec<&str> = script
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("procd_set_param respawn"))
            .collect();
        if respawns.is_empty() && RESPAWNING.iter().any(|n| init.ends_with(&format!("/{n}"))) {
            problems.push(format!("{init}: no procd_set_param respawn line"));
        }
        for line in respawns {
            let retry = line.split_whitespace().nth(4);
            if retry != Some("0") {
                problems.push(format!("{init}: retry limit is not 0: {line}"));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "OpenWrt services must respawn without giving up:\n  {}",
        problems.join("\n  ")
    );
}

/// Returns the value of every `key=` line in a systemd unit, in file order.
fn unit_values(unit: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key}=");
    unit.lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .map(|v| v.trim().to_string())
        .collect()
}

/// Guards the restart backoff of the units that systemd restarts on failure.
///
/// `Restart=on-failure` with a fixed `RestartSec=` and the default start limit
/// restarts a daemon whose start cannot succeed every few seconds for as long
/// as it is left. Each tarball and `.deb` unit that sets `Restart=` to anything
/// but `no` must also set `RestartSteps=` and `RestartMaxDelaySec=`, the two
/// copies of a unit must agree on both, and each NixOS service restarted on
/// failure must set both to the values of the unit of the same name.
#[test]
fn restarting_units_back_off_between_restarts() {
    const DIRS: [&str; 2] = ["packaging/systemd", "packaging/debian"];
    /// A unit copy's path with its `RestartSteps=` and `RestartMaxDelaySec=` values.
    type UnitCopy = (String, Vec<String>, Vec<String>);
    let mut backoff: HashMap<String, Vec<UnitCopy>> = HashMap::new();
    for dir in DIRS {
        for rel in repo_dir_files(dir) {
            let Some(name) = rel.rsplit('/').next().filter(|n| n.ends_with(".service")) else {
                continue;
            };
            let name = name.to_string();
            let unit = repo_file(&rel);
            let restart = unit_values(&unit, "Restart");
            if restart.is_empty() || restart == ["no"] {
                continue;
            }
            let steps = unit_values(&unit, "RestartSteps");
            let max = unit_values(&unit, "RestartMaxDelaySec");
            assert_eq!(
                steps.len(),
                1,
                "{rel}: Restart={restart:?} needs exactly one RestartSteps=, read {steps:?}"
            );
            assert_eq!(
                max.len(),
                1,
                "{rel}: Restart={restart:?} needs exactly one RestartMaxDelaySec=, read {max:?}"
            );
            backoff.entry(name).or_default().push((rel, steps, max));
        }
    }
    for name in ["fips.service", "fips-gateway.service"] {
        assert_eq!(
            backoff.get(name).map(Vec::len),
            Some(DIRS.len()),
            "control: {name} is no longer restarted on failure in each of {DIRS:?}"
        );
    }
    for copies in backoff.values() {
        let (first, rest) = copies.split_first().unwrap();
        for other in rest {
            assert_eq!(
                (&first.1, &first.2),
                (&other.1, &other.2),
                "{} and {} disagree on RestartSteps=/RestartMaxDelaySec=",
                first.0,
                other.0
            );
        }
    }

    let rel = "packaging/nixos/default.nix";
    let nix = repo_file(rel);
    let mut services: Vec<(String, Vec<&str>)> = Vec::new();
    for line in nix.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("systemd.services.") {
            let name = rest.split_whitespace().next().unwrap_or_default();
            services.push((format!("{name}.service"), Vec::new()));
        } else if let Some((_, body)) = services.last_mut() {
            body.push(line);
        }
    }
    let nix_value = |body: &[&str], key: &str| -> Vec<String> {
        let prefix = format!("{key} = ");
        body.iter()
            .filter_map(|l| l.strip_prefix(prefix.as_str()))
            .map(|v| v.trim_end_matches(';').trim().to_string())
            .collect()
    };
    let mut restarting = 0;
    for (name, body) in &services {
        if !body.contains(&"Restart = \"on-failure\";") {
            continue;
        }
        restarting += 1;
        let (unit, steps, max) = backoff
            .get(name)
            .and_then(|copies| copies.first())
            .unwrap_or_else(|| {
                panic!("{rel}: {name} restarts on failure but no unit of that name does")
            });
        assert_eq!(
            (
                &nix_value(body, "RestartSteps"),
                &nix_value(body, "RestartMaxDelaySec")
            ),
            (steps, max),
            "{rel}: {name} disagrees with {unit} on RestartSteps/RestartMaxDelaySec"
        );
    }
    assert!(
        restarting >= 2,
        "control: expected Restart = \"on-failure\" in both services of {rel}, found {restarting}"
    );
}

/// Returns the lines of an nftables file with each `#` comment cut off,
/// trimmed at both ends, without the lines left empty.
fn nft_code(nft: &str) -> Vec<String> {
    nft.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Returns the code lines inside `chain <name> {`, up to its closing `}`.
fn nft_chain(code: &[String], name: &str) -> Vec<String> {
    let open = format!("chain {name} {{");
    let start = 1 + code
        .iter()
        .position(|l| *l == open)
        .unwrap_or_else(|| panic!("no `{open}` outside a comment"));
    let len = code[start..]
        .iter()
        .position(|l| l == "}")
        .unwrap_or_else(|| panic!("`{open}` is never closed"));
    code[start..start + len].to_vec()
}

/// A gateway port forward is a DNAT in prerouting, so its traffic takes the
/// `forward` hook and never reaches the `inbound` chain or its drop-ins. The
/// packaged baseline must carry a `forward` chain scoped to the mesh interface
/// that includes the forward drop-ins after the conntrack accept and before
/// its own rule for port-forwarded connections, so a drop-in's `drop` is
/// reached by a new forwarded connection. The chain must hold nothing else: a
/// rule ahead of the include that accepts a forwarded connection would make
/// every drop-in dead, so the chain is compared line for line. The `inbound`
/// chain's include must stay a glob of `fips.d` itself, which cannot match the
/// `forward/` subdirectory's files.
#[test]
fn the_packaged_fips_nft_has_a_forward_chain_scoped_to_fips_if_that_includes_the_forward_dropins_before_its_port_forward_default()
 {
    const NFT: &str = "packaging/common/fips.nft";
    let code = nft_code(&repo_file(NFT));

    let inbound = nft_chain(&code, "inbound");
    let includes: Vec<&String> = inbound
        .iter()
        .filter(|l| l.starts_with("include "))
        .collect();
    assert_eq!(
        includes,
        [r#"include "/etc/fips/fips.d/*.nft""#],
        "{NFT}: the inbound chain must include only the fips.d drop-ins"
    );

    let forward = nft_chain(&code, "forward");
    let expected = [
        "type filter hook forward priority 0; policy accept;",
        "iifname != $fips_if return",
        "ct state established,related accept",
        r#"include "/etc/fips/fips.d/forward/*.nft""#,
    ];
    let defaults = [
        "ct status dnat counter accept",
        "ct status dnat counter drop",
    ];
    let (last, head) = forward
        .split_last()
        .unwrap_or_else(|| panic!("{NFT}: chain forward is empty"));
    assert!(
        head == expected && defaults.contains(&last.as_str()),
        "{NFT}: chain forward must hold exactly {expected:#?} and then one of {defaults:?}, \
         with nothing ahead of the drop-in include that could decide a forwarded \
         connection first: {forward:#?}"
    );
}
