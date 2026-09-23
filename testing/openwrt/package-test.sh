#!/bin/bash
# ── OpenWrt package contents, checked on the host ───────────────────────────
# Runs the real packaging/openwrt-apk/build-apk.sh against placeholder
# binaries and a stub `apk` that records what `apk mkpkg` was asked to
# package. No docker, no apk-tools and no FIPS build are needed.
#
# What it checks is which maintainer scripts the .apk registers and what each
# one does with apk's upgrade arguments and environment (apk-tools v3 passes
# "<new-version> <old-version>" and a PATH-only environment to pre-upgrade and
# post-upgrade), and which files the .apk and the .ipk install. The .ipk is
# built for real by build-ipk.sh, which needs only tar. Whether a real
# `apk mkpkg` accepts the result is left to the GitHub packaging workflow,
# which builds with the real tool.
#
# Usage: package-test.sh [--keep <dir>]
#   --keep <dir>  copy the captured apk scripts into <dir> as post-install,
#                 pre-upgrade, post-upgrade and pre-deinstall, so
#                 scenarios.sh can run them under ash.
#
# Exit 0 = every check passed. Exit 1 = at least one failed. Exit 2 = the
# harness could not run; never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCRIPTS_SRC="$PROJECT_ROOT/packaging/openwrt-ipk/scripts"

KEEP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep)
            [[ $# -ge 2 ]] || { echo "package-test: --keep needs a directory" >&2; exit 2; }
            KEEP="$2"
            shift 2
            ;;
        *) echo "package-test: unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [[ -n "$KEEP" && ! -d "$KEEP" ]]; then
    echo "package-test: --keep needs an existing directory" >&2
    exit 2
fi

# The version is unique to this run so the cleanup below removes only what
# this run's builders wrote into dist/.
PKG_VERSION="pkgtest.$$"
TMP="$(mktemp -d)" || { echo "package-test: mktemp failed" >&2; exit 2; }

trap 'rm -rf "$TMP"; rm -f "$PROJECT_ROOT/dist/fips_${PKG_VERSION}_"*' EXIT

harness_fail() {
    echo "package-test: $*" >&2
    exit 2
}

FAILURES=0
CASES=0

ok() {
    CASES=$((CASES + 1))
    echo "  ok   $*"
    return 0
}

bad() {
    CASES=$((CASES + 1))
    FAILURES=$((FAILURES + 1))
    echo "  FAIL $*"
    return 0
}

# ── Build the .apk against a stub apk ───────────────────────────────────────

BINS="$TMP/bins"
CAPTURE="$TMP/capture"
mkdir -p "$BINS" "$CAPTURE" || harness_fail "cannot create $TMP subdirectories"
for bin in fips fipsctl fipstop fips-gateway; do
    printf 'x' > "$BINS/$bin" || harness_fail "cannot write placeholder $bin"
done

# The stub knows only the arguments build-apk.sh passes today. Anything else
# exits 64, so a new mkpkg argument fails the build rather than going unseen.
cat > "$TMP/apk" <<STUB
#!/bin/bash
set -euo pipefail
cap='$CAPTURE'
[ "\${1-}" = mkpkg ] || { echo "stub apk: only mkpkg is supported, got '\${1-}'" >&2; exit 64; }
shift
files=""
out=""
while [ \$# -gt 0 ]; do
    [ \$# -ge 2 ] || { echo "stub apk: \$1 has no value" >&2; exit 64; }
    case "\$1" in
        --info) ;;
        --script)
            phase="\${2%%:*}"
            cp "\${2#*:}" "\$cap/script.\$phase"
            echo "\$phase" >> "\$cap/phases"
            ;;
        --files) files="\$2" ;;
        --output) out="\$2" ;;
        *) echo "stub apk: unknown argument \$1" >&2; exit 64 ;;
    esac
    shift 2
done
[ -n "\$files" ] && [ -n "\$out" ] || { echo "stub apk: --files and --output are required" >&2; exit 64; }
(cd "\$files" && find . -mindepth 1 | LC_ALL=C sort) > "\$cap/payload"
: > "\$out"
: > "\$cap/called"
STUB
chmod 0755 "$TMP/apk" || harness_fail "cannot make the stub apk executable"

echo "OpenWrt package checks"
echo "==> build-apk.sh with a stub apk"
if ! PKG_VERSION="$PKG_VERSION" APK_VERSION=0.0.0-r0 APK_BIN="$TMP/apk" \
    bash "$PROJECT_ROOT/packaging/openwrt-apk/build-apk.sh" --arch x86_64 --bin-dir "$BINS" \
    > "$TMP/build-apk.log" 2>&1; then
    cat "$TMP/build-apk.log" >&2
    harness_fail "build-apk.sh failed, so nothing was checked"
fi
[[ -f "$CAPTURE/called" ]] || harness_fail "build-apk.sh exited 0 but never ran apk mkpkg"
[[ -f "$CAPTURE/phases" ]] || harness_fail "apk mkpkg ran but no script phase was recorded"

# ── A1. The .apk registers exactly the four lifecycle scripts ───────────────
# apk runs only post-install on a fresh install, only pre-upgrade and
# post-upgrade on an upgrade, and only pre-deinstall on a removal.
WANT_PHASES="post-install post-upgrade pre-deinstall pre-upgrade"
got_phases="$(LC_ALL=C sort "$CAPTURE/phases" | tr '\n' ' ')"
got_phases="${got_phases% }"
if [[ "$got_phases" == "$WANT_PHASES" ]]; then
    ok "A1 the .apk registers $WANT_PHASES"
else
    missing=""
    for phase in $WANT_PHASES; do
        grep -qxF "$phase" "$CAPTURE/phases" || missing="$missing $phase"
    done
    bad "A1 registered phases are '$got_phases', want '$WANT_PHASES'; missing:${missing:- none}"
fi

# ── A2. Every registered script starts with a working #! line ───────────────
# apk execs the script directly, so the kernel reads line 1.
for phase in $WANT_PHASES; do
    script="$CAPTURE/script.$phase"
    if [[ ! -f "$script" ]]; then
        bad "A2 $phase is not registered, so it has no #! line"
    elif [[ "$(head -n 1 "$script")" == "#!/bin/sh" ]]; then
        ok "A2 $phase starts with #!/bin/sh"
    else
        bad "A2 $phase starts with '$(head -n 1 "$script")', not #!/bin/sh"
    fi
done

# ── A3. Install and removal ship the shared bodies unchanged ────────────────
for pair in post-install:postinst pre-deinstall:prerm; do
    phase="${pair%%:*}"
    src="$SCRIPTS_SRC/${pair#*:}"
    if cmp -s "$CAPTURE/script.$phase" "$src"; then
        ok "A3 $phase is the shipped ${pair#*:}, byte for byte"
    else
        bad "A3 $phase differs from the shipped ${pair#*:}"
    fi
done

# ── A4 and A5. The upgrade pair wraps the shared bodies ─────────────────────
# A4 reads the structure: the script ends with the body after its #! line, and
# at least one header line sits between the two. A5 runs the header with apk's
# upgrade argv and environment, so what is judged is what the shell does with
# it, not how it reads.
for pair in pre-upgrade:prerm post-upgrade:postinst; do
    phase="${pair%%:*}"
    src="$SCRIPTS_SRC/${pair#*:}"
    script="$CAPTURE/script.$phase"
    if [[ ! -f "$script" ]]; then
        bad "A4 $phase is not registered"
        bad "A5 $phase is not registered, so its header cannot run"
        continue
    fi

    tail -n +2 "$src" > "$TMP/body" || harness_fail "cannot read $src"
    body_lines=$(wc -l < "$TMP/body")
    script_lines=$(wc -l < "$script")
    header_lines=$((script_lines - body_lines))
    if [[ $header_lines -lt 2 ]]; then
        bad "A4 $phase has $header_lines header line(s) before the ${pair#*:} body, want at least 2"
    elif ! tail -n "$body_lines" "$script" | cmp -s - "$TMP/body"; then
        bad "A4 $phase does not end with the ${pair#*:} body"
    else
        ok "A4 $phase is a $header_lines-line header and the ${pair#*:} body"
    fi

    if [[ $header_lines -lt 1 ]]; then
        bad "A5 $phase has no header to run"
        continue
    fi
    probe="$TMP/probe.$phase"
    {
        head -n "$header_lines" "$script"
        # shellcheck disable=SC2016
        printf '%s\n' 'printf '\''%s|%s|%s\n'\'' "${1-}" "${2-}" "${PKG_UPGRADE-}"'
    } > "$probe"
    chmod 0755 "$probe" || harness_fail "cannot make the $phase probe executable"
    got="$(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin "$probe" 0.6.0-r1 0.5.2-r1)"
    rc=$?
    if [[ $rc -eq 126 || $rc -eq 127 ]]; then
        harness_fail "the $phase probe could not be executed (exit $rc)"
    fi
    IFS='|' read -r f1 f2 f3 <<< "$got"
    case "$phase" in
        pre-upgrade)
            if [[ $rc -eq 0 && "$f1|$f2" == "upgrade|0.6.0-r1" ]]; then
                ok "A5 pre-upgrade hands the body 'upgrade 0.6.0-r1'"
            else
                bad "A5 pre-upgrade hands the body '$f1 $f2' (exit $rc), want 'upgrade 0.6.0-r1'"
            fi
            ;;
        post-upgrade)
            if [[ $rc -eq 0 && "$f3" == "1" ]]; then
                ok "A5 post-upgrade runs the body with PKG_UPGRADE=1"
            else
                bad "A5 post-upgrade runs the body with PKG_UPGRADE='$f3' (exit $rc), want 1"
            fi
            ;;
    esac
done

# ── Build the .ipk ──────────────────────────────────────────────────────────

echo "==> build-ipk.sh"
if ! PKG_VERSION="$PKG_VERSION" \
    bash "$PROJECT_ROOT/packaging/openwrt-ipk/build-ipk.sh" --arch x86_64 --bin-dir "$BINS" \
    > "$TMP/build-ipk.log" 2>&1; then
    cat "$TMP/build-ipk.log" >&2
    harness_fail "build-ipk.sh failed, so the .ipk was not checked"
fi
IPK="$PROJECT_ROOT/dist/fips_${PKG_VERSION}_x86_64.ipk"
[[ -f "$IPK" ]] || harness_fail "build-ipk.sh exited 0 but wrote no $IPK"
tar -xzf "$IPK" -O ./data.tar.gz | tar -tzf - > "$TMP/ipk-data" \
    || harness_fail "cannot list data.tar.gz in $IPK"
tar -xzf "$IPK" -O ./control.tar.gz | tar -tzf - > "$TMP/ipk-control" \
    || harness_fail "cannot list control.tar.gz in $IPK"

# ── P1 and P2. Neither package ships the dnsmasq drop-in ────────────────────
# OpenWrt's dnsmasq builds its config from UCI and reads no directory under
# /etc, so .fips forwarding comes from the UCI entry 90-fips-setup adds. The
# match is on the directory prefix: tar lists the directory with a trailing
# slash and the stub's find without one.
for pair in "P1:apk:$CAPTURE/payload" "P2:ipk:$TMP/ipk-data"; do
    id="${pair%%:*}"
    rest="${pair#*:}"
    kind="${rest%%:*}"
    listing="${rest#*:}"
    hits="$(grep -F './etc/dnsmasq.d' "$listing" | tr '\n' ' ')"
    if [[ -z "$hits" ]]; then
        ok "$id the .$kind installs nothing under /etc/dnsmasq.d"
    else
        bad "$id the .$kind still installs: $hits"
    fi
done

# ── P3. Positive control for P1 and P2 ──────────────────────────────────────
# An empty or unreadable listing would pass P1 and P2, so each listing must
# show files that are known to ship.
for pair in "apk:$CAPTURE/payload" "ipk:$TMP/ipk-data"; do
    kind="${pair%%:*}"
    listing="${pair#*:}"
    for path in ./etc/init.d/fips-gateway ./etc/uci-defaults/90-fips-setup; do
        if grep -qxF "$path" "$listing"; then
            ok "P3 the .$kind payload lists $path"
        else
            bad "P3 the .$kind payload does not list $path, so P1/P2 saw no real listing"
        fi
    done
done
for path in ./postinst ./prerm; do
    if grep -qxF "$path" "$TMP/ipk-control"; then
        ok "P3 the .ipk control archive lists $path"
    else
        bad "P3 the .ipk control archive does not list $path"
    fi
done

# ── P4. No source still names the drop-in ───────────────────────────────────
# This is the only check on the SDK feed Makefile, which nothing here builds.
# grep exits 1 when nothing matches and 2 when it could not read a path; only
# the first is a pass.
(cd "$PROJECT_ROOT" && grep -rlF 'dnsmasq.d/fips.conf' \
    packaging/openwrt-ipk packaging/openwrt-apk .github/workflows/package-openwrt.yml) \
    > "$TMP/refs"
rc=$?
[[ $rc -le 1 ]] || harness_fail "the drop-in reference search failed (grep exit $rc)"
refs="$(tr '\n' ' ' < "$TMP/refs")"
if [[ -z "$refs" ]]; then
    ok "P4 no OpenWrt packaging file names the dnsmasq drop-in"
else
    bad "P4 the dnsmasq drop-in is still named in: $refs"
fi
if [[ -e "$PROJECT_ROOT/packaging/openwrt-ipk/files/etc/dnsmasq.d/fips.conf" ]]; then
    bad "P4 packaging/openwrt-ipk/files/etc/dnsmasq.d/fips.conf still exists"
else
    ok "P4 the drop-in source file is gone"
fi

# ── Hand the scripts to the ash scenarios ───────────────────────────────────
if [[ -n "$KEEP" ]]; then
    for phase in $WANT_PHASES; do
        [[ -f "$CAPTURE/script.$phase" ]] || continue
        install -m 0755 "$CAPTURE/script.$phase" "$KEEP/$phase" \
            || harness_fail "cannot copy $phase into $KEEP"
    done
fi

echo ""
if [[ $FAILURES -eq 0 ]]; then
    echo "package-test: all $CASES checks passed"
    exit 0
fi
echo "package-test: $FAILURES of $CASES checks failed"
exit 1
