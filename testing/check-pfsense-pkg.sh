#!/usr/bin/env bash
# ── pfSense package guard ───────────────────────────────────────────────────
# Validates a built pfSense .pkg and the scripts inside it.
#
# The pfSense package cannot be exercised the way the Docker suites exercise
# mesh behaviour: pfSense is not a container image, and Netgate publishes no
# base image to build one from. What IS checkable without a firewall — and is
# where this package's mistakes would actually live — is the handful of
# pfSense-specific decisions that separate it from the FreeBSD package, each of
# which fails silently on a real box if it regresses:
#
#   - the boot script must be named *.sh, or pfSense's rc.start_packages glob
#     never runs it and the daemon simply never starts, with no error anywhere;
#   - `start` must be idempotent, because that same glob is re-run on every
#     interface link change, IP change and gateway event;
#   - a recycled pid must not be mistaken for a running daemon, which would
#     make `start` a permanent no-op;
#   - the shipped config must carry the IPv4 loopback bind, because a config
#     that kept the ::1 default resolves nothing on a firewall with "Allow
#     IPv6" off and says nothing about why;
#   - fips.yaml must be 0600, because it may hold a node private key (nsec:).
#
# What this does NOT cover, stated so nobody reads a pass as more than it is:
# installing on pfSense, the config.xml edit in fips-unbound-custom.php (which
# needs pfSense's PHP and its config.inc), unbound actually answering .fips,
# and pf passing mesh traffic. Those are the manual steps in
# packaging/pfsense/README.md.
#
# Usage: testing/check-pfsense-pkg.sh [<package.pkg>]
#   With no argument, builds one from target/release via build-pkg.sh --no-build.
#   FreeBSD only: it needs pkg(8) to have produced the package.
#
# Exit 0 = every check passed. Exit 1 = at least one failed. Exit 2 = the check
# could not run; never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PFSENSE_DIR="$PROJECT_ROOT/packaging/pfsense"

failures=0
checks=0

pass() { checks=$((checks + 1)); printf '  PASS  %s\n' "$1"; }
fail() {
    checks=$((checks + 1))
    failures=$((failures + 1))
    printf '  FAIL  %s\n' "$1"
    [[ $# -gt 1 ]] && printf '        %s\n' "$2"
    return 0
}
bail() { printf 'check-pfsense-pkg: %s\n' "$1" >&2; exit 2; }
# A check that could not run here. Printed, not counted: a skipped check
# that reads as a pass would let a host without the tooling report a
# cleaner result than a host with it.
skip() { skipped=$((skipped + 1)); printf '  SKIP  %s\n' "$1"; }
skipped=0

# Probed by capability rather than by `uname -s`: what this needs is a
# working pkg(8) to have produced and to read the package, and that is
# also true on a host whose uname comes from a Linux compat layer.
command -v pkg >/dev/null 2>&1 && pkg config abi >/dev/null 2>&1 \
    || bail "needs pkg(8) — run this on the FreeBSD host that built the package"

PKG="${1:-}"
if [[ -z "$PKG" ]]; then
    "$PFSENSE_DIR/build-pkg.sh" --no-build >/dev/null \
        || bail "build-pkg.sh --no-build failed"
    PKG=$(ls -t "$PROJECT_ROOT"/deploy/fips-*-pfsense-*.pkg 2>/dev/null | head -1)
fi
[[ -n "$PKG" && -f "$PKG" ]] || bail "no package to check (pass one as \$1)"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/fips-pfsense-check.XXXXXX") || bail "mktemp failed"
trap 'rm -rf "$WORK"' EXIT

echo "==> checking $(basename "$PKG")"

MANIFEST="$WORK/manifest.json"
tar -xOf "$PKG" +MANIFEST > "$MANIFEST" 2>/dev/null \
    || bail "cannot read +MANIFEST from $PKG"
# Members are stored as absolute paths; bsdtar strips the leading "/" on
# extract, so the payload lands under $WORK/usr/local.
tar -xf "$PKG" -C "$WORK" 2>/dev/null || bail "cannot extract payload from $PKG"
PAYLOAD="$WORK/usr/local"

# ── 1. Contents ─────────────────────────────────────────────────────────────
echo "-- contents"

EXPECTED_PATHS="
bin/fips
bin/fipsctl
bin/fipstop
etc/fips/fips.conf.sample
etc/fips/fips.newsyslog
etc/fips/fips.yaml.sample
etc/fips/hosts.sample
etc/rc.d/fips.sh
libexec/fips/fips-dns-setup
libexec/fips/fips-dns-teardown
libexec/fips/fips-unbound-custom.php
"

for rel in $EXPECTED_PATHS; do
    if [[ -e "$PAYLOAD/$rel" ]]; then
        pass "ships $rel"
    else
        fail "missing $rel"
    fi
done

# The whole reason this package exists separately from the FreeBSD one.
if [[ -e "$PAYLOAD/etc/rc.d/fips" && ! -e "$PAYLOAD/etc/rc.d/fips.sh" ]]; then
    fail "boot script is rc.d/fips, not rc.d/fips.sh" \
         "pfSense's rc.start_packages globs *.sh; a suffixless script never runs."
else
    pass "boot script carries the .sh suffix pfSense globs for"
fi

for rel in etc/rc.d/fips.sh libexec/fips/fips-dns-setup libexec/fips/fips-dns-teardown; do
    if [[ -x "$PAYLOAD/$rel" ]]; then
        pass "$rel is executable"
    else
        fail "$rel is not executable"
    fi
done

# ── 2. Manifest ─────────────────────────────────────────────────────────────
echo "-- manifest"

perm_of() {
    grep -o "\"/usr/local/$1\":{[^}]*}" "$MANIFEST" \
        | grep -o '"perm":"[0-7]*"' | head -1 | cut -d'"' -f4
    return 0
}

# fips.yaml may hold a node private key (nsec:); every other platform's
# package installs it 0600 and so must this one.
yaml_perm=$(perm_of "etc/fips/fips.yaml.sample")
if [[ "$yaml_perm" == "0600" ]]; then
    pass "fips.yaml.sample is 0600"
else
    fail "fips.yaml.sample is ${yaml_perm:-unknown}, expected 0600" \
         "It may carry an nsec: private key."
fi

abi=$(grep -o '"abi":"[^"]*"' "$MANIFEST" | head -1 | cut -d'"' -f4)
if [[ "$abi" =~ ^FreeBSD:[0-9]+:[a-z0-9_]+$ ]]; then
    pass "manifest ABI is well-formed ($abi)"
else
    fail "manifest ABI is malformed: ${abi:-unset}"
fi
# The ABI string is the only thing pkg checks on the appliance, and it is
# just text in the manifest: a package labelled for one architecture and
# filled with binaries for another installs cleanly and then cannot exec.
# So compare the label against the binaries actually in the payload.
abi_arch="${abi##*:}"
file_out=$(file -b "$PAYLOAD/bin/fips" 2>/dev/null)
case "$abi_arch" in
    amd64)   want="x86-64" ;;
    aarch64) want="aarch64" ;;
    i386)    want="Intel 80386" ;;
    *)       want="" ;;
esac
if [[ -z "$want" ]]; then
    fail "unrecognised ABI architecture '${abi_arch}'" "$file_out"
elif [[ "$file_out" == *"$want"* ]]; then
    pass "binaries are ${abi_arch}, matching the manifest ABI"
else
    fail "manifest says ${abi_arch} but bin/fips is not ${want}" \
         "pkg trusts the label; the appliance would install this and fail to exec. file: ${file_out}"
fi


# Provenance annotations. These are the artifact's own record of which
# compiler built it and how it was linked; a package that lost them
# cannot answer "was this the pinned toolchain?" after the fact, which
# is the whole point of recording them.
ann_of() {
    grep -o "\"$1\":\"[^\"]*\"" "$MANIFEST" | head -1 | cut -d'"' -f4
    return 0
}

built_with=$(ann_of built_with)
linkage=$(ann_of linkage)
pin_honoured=$(ann_of pin_honoured)
toolchain_pin=$(ann_of toolchain_pin)

if [[ "$built_with" =~ ^rustc\ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
    pass "records the compiler that built it (${built_with})"
else
    fail "no usable 'built_with' annotation: '${built_with:-missing}'" \
         "pkg info -A could not say which rustc produced this package."
fi

case "$linkage" in
    static | dynamic) pass "records its linkage (${linkage})" ;;
    *) fail "no usable 'linkage' annotation: '${linkage:-missing}'" ;;
esac

# The annotation must describe the artifact, not the intent. A package
# claiming static while carrying a dynamic binary would put back exactly
# the base-drift exposure that static linking exists to remove.
if [[ "$linkage" == "static" ]]; then
    if [[ "$file_out" == *"statically linked"* ]]; then
        pass "linkage annotation matches the binary (statically linked)"
    else
        fail "annotated static, but bin/fips is not statically linked" \
             "file: ${file_out}"
    fi
    if grep -q '"shlibs_required"' "$MANIFEST"; then
        fail "annotated static, but the manifest still declares shared libraries" \
             "A static package should depend on no shlibs at all."
    else
        pass "static package declares no shared-library dependencies"
    fi
elif [[ "$linkage" == "dynamic" ]]; then
    if [[ "$file_out" == *"dynamically linked"* ]]; then
        pass "linkage annotation matches the binary (dynamically linked)"
    else
        fail "annotated dynamic, but bin/fips is not dynamically linked" "file: ${file_out}"
    fi
fi

# Not a failure: an aarch64 package cannot honour the pin, because
# rustup ships no toolchain for that platform. It is reported loudly
# because such a package is build-it-yourself and must not be published
# as a release artifact.
case "$pin_honoured" in
    yes) pass "built with the pinned toolchain (${toolchain_pin})" ;;
    no)  pass "NOT built with the pinned toolchain (${toolchain_pin}; used ${built_with}) — do not publish this as a release artifact" ;;
    *)   fail "no usable 'pin_honoured' annotation: '${pin_honoured:-missing}'" ;;
esac

# The FreeBSD major is not asserted against a fixed number: CE 2.8 is 15,
# CE 2.9 and Plus 26.x are 16, and all are legitimate outputs. It only has
# to be present and numeric — the operator matches it to the target.
abi_major=$(printf '%s' "$abi" | awk -F: '{print $2}')
if [[ "$abi_major" =~ ^[0-9]+$ ]]; then
    pass "ABI FreeBSD major is ${abi_major} — match this to the target's base"
else
    fail "ABI has no numeric FreeBSD major: ${abi}"
fi
if grep -q 'pw groupadd fips' "$MANIFEST"; then
    pass "post-install creates the fips control-socket group"
else
    fail "post-install does not create the fips group"
fi
# The manifest's file list always names the teardown script, so grep the
# pre-deinstall script body itself, not the whole manifest.
pre_deinstall=$(grep -o '"pre-deinstall":"[^"]*\(\\"[^"]*\)*"' "$MANIFEST" | head -1)
post_install=$(grep -o '"post-install":"[^"]*\(\\"[^"]*\)*"' "$MANIFEST" | head -1)
if [[ "$pre_deinstall" == *"libexec/fips/fips-dns-teardown"* ]]; then
    pass "pre-deinstall invokes fips-dns-teardown"
else
    fail "pre-deinstall never calls fips-dns-teardown" \
         "config.xml would keep forwarding fips. to a dead port after removal."
fi
if [[ "$post_install" == *"install -m 0600"*"fips.yaml.sample"*"fips.yaml"* ]]; then
    pass "post-install seeds fips.yaml at 0600"
else
    fail "post-install does not seed fips.yaml with install -m 0600" \
         "It may carry an nsec: private key."
fi

# ── 3. Shipped configuration ────────────────────────────────────────────────
echo "-- configuration"

CFG="$PAYLOAD/etc/fips/fips.yaml.sample"
if grep -Fqx '  bind_addr: "127.0.0.1"' "$CFG"; then
    pass "dns.bind_addr is IPv4 loopback"
else
    fail "dns.bind_addr is not 127.0.0.1" \
         "unbound gets do-ip6: no unless 'Allow IPv6' is set, and cannot reach [::1]."
fi
if grep -Eq '^[[:space:]]+bind_addr:[[:space:]]*"::1"' "$CFG"; then
    fail "config still carries an active ::1 bind"
else
    pass "config carries no active ::1 bind"
fi
# The splice must keep the rest of the common config, not just the dns block.
for key in "^node:" "^tun:" "^transports:" "^peers:"; do
    if grep -q "$key" "$CFG"; then
        pass "config retains ${key#^}"
    else
        fail "config lost ${key#^} — the dns: splice ate too much"
    fi
done

# ── 4. Boot script behaviour ────────────────────────────────────────────────
# Two kinds of case. The negative ones prove a stale or foreign pid is not
# mistaken for the daemon. The positive one proves the script can see a
# daemon it started — which no negative case can: a pid check that never
# succeeds passes every negative case. That defect shipped once, so the
# positive case comes first and the rewrites it depends on are asserted.
# Exercised against the copy inside the package, with its pidfile and knobs
# file redirected into the work dir so nothing here touches a running daemon.
echo "-- boot script"

RC="$WORK/fips-under-test.sh"
# The stub daemon is a copy of sleep named fips: the script identifies the
# daemon by comm, and comm is the basename it was exec'd as.
mkdir -p "$WORK/run"; : > "$WORK/cfg.yaml"; cp /bin/sleep "$WORK/fips"
sed -e "s|^pidfile=.*|pidfile=\"$WORK/test.pid\"|" \
    -e "s|^supervisor_pidfile=.*|supervisor_pidfile=\"$WORK/test-daemon.pid\"|" \
    -e "s|^daemon_err=.*|daemon_err=\"$WORK/run/daemon.err\"|" \
    -e "s|^fips_conf=.*|fips_conf=\"$WORK/fips.conf\"|" \
    -e "s|^procname=.*|procname=\"$WORK/fips\"|" \
    -e "s|^runtime_dir=.*|runtime_dir=\"$WORK/run\"|" \
    -e "s|fips_config:=/usr/local/etc/fips/fips.yaml|fips_config:=$WORK/cfg.yaml|" \
    -e "s|fips_logfile:=/var/log/fips.log|fips_logfile:=$WORK/fips.log|" \
    -e "s|^    if pw groupshow fips|    if false \&\& pw groupshow fips|" \
    -e "s|--config \"\$fips_config\" \${fips_flags}|300|" \
    "$PAYLOAD/etc/rc.d/fips.sh" > "$RC"
chmod +x "$RC"

# Every one of those rewrites must have landed, or the cases below run
# against the wrong paths and the wrong binary and prove nothing.
for want in "pidfile=\"$WORK/test.pid\"" "procname=\"$WORK/fips\"" "runtime_dir=\"$WORK/run\"" \
            "fips_config:=$WORK/cfg.yaml" "fips_logfile:=$WORK/fips.log"; do
    if grep -Fq "$want" "$RC"; then
        pass "harness rewrite in place: ${want%%=*}"
    else
        fail "harness rewrite missing: $want" "the lifecycle cases below would test the wrong thing."
    fi
done

# Redirect the script's output to a file, not through $(...): start and
# restart background daemon(8), whose child inherits the caller's stdout,
# so a command-substitution capture would block until that child exits —
# the same pipe-inheritance trap the boot script itself avoids. The
# daemon writes to the file; the capture only reads cat's output.
rc() {
    : > "$WORK/rc.out"
    # --foreground matters. Without it, FreeBSD's timeout(1) makes itself a
    # reaper for everything the script spawns (procctl PROC_REAP_ACQUIRE):
    # after the script exits it keeps waiting until every descendant has
    # exited too, and at the time limit it kills them all (PROC_REAP_KILL).
    # daemon(8) never exits, so `start` would sit for the full 30 seconds
    # and then the daemon it started would be killed — "started", no
    # daemon. With --foreground timeout only signals its direct child, and
    # the detached daemon is left alone. No process group is involved.
    # (Found by running this checker as root in a FreeBSD VM.)
    timeout --foreground 30 sh "$RC" "$@" > "$WORK/rc.out" 2>&1 </dev/null
    rc_status=$?
    cat "$WORK/rc.out"
    return $rc_status
}

out=$(rc start); sleep 1
if [[ "$out" == *"started"* ]] && [[ -s "$WORK/test.pid" ]]; then
    pass "start launches the daemon via daemon(8)"
else
    fail "start did not launch the daemon" "$out"
fi
# daemon(8) writes the pid with no trailing newline; read must cope with
# that, which is exactly what the shipped-once defect did not. Require the
# pidfile to exist first: tail on a missing file prints nothing, which
# would otherwise pass this vacuously.
if [[ ! -s "$WORK/test.pid" ]]; then
    fail "no pidfile to check for a trailing newline (start did not write one)"
elif [[ "$(tail -c1 "$WORK/test.pid" | od -An -c | tr -d ' ')" != '\n' ]]; then
    pass "pidfile has no trailing newline (the case read must handle)"
else
    fail "pidfile ends in a newline — this harness no longer exercises the read-at-EOF case"
fi
live=$(cat "$WORK/test.pid")
out=$(rc status)
if [[ "$out" == *"running as pid $live"* ]]; then
    pass "status sees the daemon it started (pid $live)"
else
    fail "status cannot see a running daemon" "$out"
fi
out=$(rc start)
if [[ "$out" == *"already running as pid $live"* ]] && kill -0 "$live" 2>/dev/null; then
    pass "re-entrant start is a no-op (pfSense re-runs start on WAN IP changes)"
else
    fail "re-entrant start disturbed a running daemon" "$out"
fi
out=$(rc restart); sleep 1
newpid=$(cat "$WORK/test.pid" 2>/dev/null)
if [[ "$out" == *"stopped"* ]] && [[ "$out" == *"started"* ]] && [[ -n "$newpid" ]] && [[ "$newpid" != "$live" ]] \
   && ! kill -0 "$live" 2>/dev/null && kill -0 "$newpid" 2>/dev/null; then
    pass "restart stops the old daemon and starts a new one ($live -> $newpid)"
else
    fail "restart did not replace the daemon" "$out"
fi
out=$(rc stop); sleep 1
if [[ "$out" == *"stopped"* ]] && ! kill -0 "$newpid" 2>/dev/null; then
    pass "stop terminates the daemon"
else
    fail "stop left the daemon running" "$out"
fi
if rc status >/dev/null 2>&1; then fail "status exits 0 after stop"; else pass "status exits non-zero after stop"; fi
pkill -f "$WORK/fips" 2>/dev/null || true

# A live process whose comm is not "fips": stands in for a recycled pid.
sleep 120 &
decoy_pid=$!

status_says() {
    sh "$RC" status 2>&1 | tail -1
    return 0
}

printf '%s\n' "$$" > "$WORK/test.pid"
# $$ is this shell, comm "bash" — a pid that exists but is not the daemon.
if [[ "$(status_says)" == *"not running"* ]]; then
    pass "a live pid whose comm is not fips reads as not running"
else
    fail "a recycled pid was mistaken for a running daemon" \
         "start would then be a permanent no-op."
fi

printf '%s\n' "$decoy_pid" > "$WORK/test.pid"
if [[ "$(status_says)" == *"not running"* ]]; then
    pass "a live non-fips child reads as not running"
else
    fail "a live non-fips process was mistaken for the daemon"
fi

printf 'junk\n' > "$WORK/test.pid"
if [[ "$(status_says)" == *"not running"* ]]; then
    pass "a non-numeric pidfile reads as not running"
else
    fail "a non-numeric pidfile was accepted"
fi

printf '999999\n' > "$WORK/test.pid"
if [[ "$(status_says)" == *"not running"* ]]; then
    pass "a pid that does not exist reads as not running"
else
    fail "a dead pid was reported as running"
fi

rm -f "$WORK/test.pid"
if [[ "$(status_says)" == *"not running"* ]]; then
    pass "a missing pidfile reads as not running"
else
    fail "a missing pidfile was not handled"
fi

kill "$decoy_pid" 2>/dev/null
wait "$decoy_pid" 2>/dev/null

# status must exit non-zero when not running: the package's pre-deinstall
# tests it to decide whether to restart the daemon after an upgrade.
sh "$RC" status >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
    pass "status exits non-zero when not running"
else
    fail "status exits 0 when not running" \
         "pre-deinstall would mark a stopped daemon for restart on upgrade."
fi

# The opt-out has to be silent as well as inert: pfSense re-runs this on every
# interface event, and a chatty no-op floods /tmp/bootup_messages.
printf 'fips_enable="NO"\n' > "$WORK/fips.conf"
out=$(sh "$RC" start 2>&1)
rc=$?
if [[ $rc -eq 0 && -z "$out" ]]; then
    pass "fips_enable=NO start is silent and exits 0"
else
    fail "fips_enable=NO start printed '${out}' and exited ${rc}"
fi
rm -f "$WORK/fips.conf"

sh "$RC" not-a-verb >/dev/null 2>&1
if [[ $? -eq 64 ]]; then
    pass "an unknown verb exits 64 (EX_USAGE)"
else
    fail "an unknown verb did not exit 64"
fi

# ── 5. DNS helper ───────────────────────────────────────────────────────────
echo "-- dns helper"

# On anything that is not pfSense it must refuse rather than half-configure a
# resolver it does not understand. This host is FreeBSD, so /etc/inc/config.inc
# is absent and the refusal path is the one that runs.
if [[ -f /etc/inc/config.inc ]]; then
    skip "non-pfSense refusal check (this host is pfSense)"
else
    out=$("$PAYLOAD/libexec/fips/fips-dns-setup" 2>&1)
    rc=$?
    if [[ $rc -ne 0 && "$out" == *"not a pfSense system"* ]]; then
        pass "fips-dns-setup refuses on a non-pfSense host"
    else
        fail "fips-dns-setup did not refuse on a non-pfSense host (rc=${rc})" "$out"
    fi
fi

# The reader must take dns.bind_addr, not a transport's bind_addr — a plain
# grep would hand back the UDP transport's 0.0.0.0:2121 and point unbound there.
READER="$WORK/reader.sh"
sed -n '/^yaml_dns_field()/,/^}/p' "$PAYLOAD/libexec/fips/fips-dns-setup" > "$READER"
{
    echo 'echo "$(yaml_dns_field bind_addr) $(yaml_dns_field port)"'
} >> "$READER"
got=$(FIPS_CONFIG="$CFG" sh -c ". '$READER'")
if [[ "$got" == "127.0.0.1 5354" ]]; then
    pass "dns field reader is scoped to the dns: block ($got)"
else
    fail "dns field reader returned '${got}', expected '127.0.0.1 5354'"
fi
# In the shipped config dns: precedes transports:, so a first-match grep
# would also pass. Put a transport's bind_addr FIRST and make sure the
# reader still finds the dns: one.
cat > "$WORK/transports-first.yaml" <<'EOF'
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    port: 1
dns:
  enabled: true
  bind_addr: "127.0.0.1"
  port: 5354
EOF
got=$(FIPS_CONFIG="$WORK/transports-first.yaml" sh -c ". '$READER'")
if [[ "$got" == "127.0.0.1 5354" ]]; then
    pass "dns field reader ignores a transports: block that comes first"
else
    fail "dns field reader picked up the transport's bind_addr: '${got}'" \
         "unbound would be pointed at the UDP transport."
fi

# ── 6. PHP helper ───────────────────────────────────────────────────────────
echo "-- php helper"
HELPER="$PAYLOAD/libexec/fips/fips-unbound-custom.php"
if ! command -v php >/dev/null 2>&1; then
    skip "php -l and the fips_strip_block unit test (no php on this host)"
else
    if php -l "$HELPER" >/dev/null 2>&1; then
        pass "fips-unbound-custom.php parses (php -l)"
    else
        fail "fips-unbound-custom.php does not parse" "$(php -l "$HELPER" 2>&1 | head -3)"
    fi
    # fips_strip_block has no side effects; under FIPS_UNBOUND_HELPER_TEST the
    # file defines its functions and returns before touching config.xml.
    if php -r '
        putenv("FIPS_UNBOUND_HELPER_TEST=1"); require $argv[1];
        $bad = 0;
        foreach (["", "opt: 1\n", "opt: 1", "a\n\n\nb\n", "\n"] as $t) {
            $hb = $mf = false;
            $r = fips_strip_block(fips_add_block($t, "server:\n  x: y"), $hb, $mf);
            if ($r !== $t || !$hb || $mf) { $bad++; }
        }
        $hb = $mf = false; fips_strip_block("x\n" . FIPS_BEGIN . "\nzzz\n", $hb, $mf); if (!$mf) { $bad++; }
        $hb = $mf = false; $r = fips_strip_block("keep\n", $hb, $mf); if ($r !== "keep\n" || $hb) { $bad++; }
        // Operator text on its own line below the block must survive on its
        // own line, not be spliced onto the line before BEGIN.
        $above = "# my local tweaks";
        $below = fips_add_block($above, "server:\n  x: y") . "private-domain: \"lan\"";
        $hb = $mf = false; $r = fips_strip_block($below, $hb, $mf);
        if ($r !== $above . "\nprivate-domain: \"lan\"" || !$hb || $mf) { $bad++; }
        exit($bad ? 1 : 0);' "$HELPER" >/dev/null 2>&1; then
        pass "fips_strip_block: add then remove is byte-identical; partial block flagged"
    else
        fail "fips_strip_block does not round-trip the operator text" \
             "the README promises the surrounding text is left byte for byte."
    fi
fi

# ── Result ──────────────────────────────────────────────────────────────────
echo
if [[ $failures -eq 0 ]]; then
    echo "==> pfSense package checks PASSED (${checks} checks, ${skipped} skipped)"
    exit 0
fi
echo "==> pfSense package checks FAILED (${failures} of ${checks})" >&2
exit 1
