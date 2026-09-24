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

/// Pins the DNS cleanup in `postrm purge` and `uninstall.sh` to the files
/// `fips-dns-setup` writes, so a purge after a `fips-dns` that never ran its
/// teardown does not leave the resolver sending `.fips` to a dead responder.
///
/// This is a text test. Each path must appear on an `rm -f` line, but a
/// resolver command passes wherever it appears on a code line, including in a
/// message. What `postrm` actually does is covered by the deb-install purge
/// check. No suite runs `uninstall.sh`: its two resolved paths were run once,
/// by hand in a container, and its dnsmasq and NetworkManager paths by nothing.
#[test]
fn dns_cleanup_in_postrm_purge_and_uninstall_removes_every_file_fips_dns_setup_writes_and_restarts_its_resolver()
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
        "reload dnsmasq",
        "nmcli general reload",
    ];

    let scripts = [
        (
            "packaging/debian/postrm purge)",
            case_branch(&repo_file("packaging/debian/postrm"), "purge"),
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
    let refuses_at = |i: usize, what: &str| {
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
    };
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
    for needle in [
        "\"S-1-5-18\"",
        "\"S-1-5-32-544\"",
        "WindowsIdentity]::GetCurrent().User.Value",
    ] {
        assert!(
            lines[trusted[0]].contains(needle),
            "install-service.ps1: the trusted owners do not include {needle}: {}",
            lines[trusted[0]]
        );
    }
    for i in find("owner refusal", &|l| {
        l == "if ($trustedOwners -notcontains $ownerSid) {"
    }) {
        refuses_at(i, "owner refusal");
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
        refuses_at(i, "refusal of $ConfigDir as a link");
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
        refuses_at(i, "refusal of a link or folder entry");
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
