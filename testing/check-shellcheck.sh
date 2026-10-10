#!/bin/bash
# ── OpenWrt shell-script lint guard ─────────────────────────────────────────
# Runs shellcheck over the shell scripts the OpenWrt packages ship, and over
# .github/scripts/install-nak.sh, which the OpenWrt Package workflow runs to
# fetch its publishing tool.
#
# This is the one copy of that lint. The OpenWrt Package workflow calls it
# after building each .ipk, and ci.yml and ci-local.sh call it too, because
# that workflow runs only on trunk pushes, tags and pull requests: without the
# other two, a finding in a script edited on a topic branch first shows up
# after the branch has reached a trunk.
#
# What is checked, and how:
#   * Every script under packaging/openwrt-ipk/files/ and the maintainer
#     scripts under packaging/openwrt-ipk/scripts/, as POSIX sh. Both the .ipk
#     and the .apk package take their payload and maintainer scripts from these
#     two directories (build-apk.sh wraps the maintainer scripts with one
#     header line, which is not linted separately); the SDK feed Makefile ships
#     preinst as well. On a router they run under busybox ash.
#   * install-nak.sh as bash, with no exclusions. It is a CI script, not a
#     shipped one, and the sh exclusion set below misfires on bash.
#
# The sh exclusions, with reason:
#   SC1008  the init scripts' `#!/bin/sh /etc/rc.common` shebang, an
#           interpreter line the linter does not recognise.
#   SC2317  rc.common's start_service/stop_service/reload_service hooks,
#           which nothing in the file itself calls.
#   SC2034  the init scripts' USE_PROCD, START, STOP, EXTRA_COMMANDS and
#           EXTRA_HELP, which rc.common reads rather than the script.
#   SC3043  `local`, which POSIX leaves undefined and ash supports.
#
# Every sh-family script in those two directories must be on the list below. A
# new one that is not fails the guard, so a script added to the package is not
# silently left unlinted.
#
# Exit 0 = clean. Exit 1 = a finding, a listed script missing, or a shipped
# script not on the list. Exit 2 = the guard could not run (shellcheck or git
# missing, or shellcheck could not process a file); never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT" || { echo "check-shellcheck: cannot cd to $PROJECT_ROOT" >&2; exit 2; }

IPK=packaging/openwrt-ipk
SH_EXCLUDE=SC1008,SC2317,SC2034,SC3043

SH_TARGETS=(
    "$IPK/files/etc/init.d/fips"
    "$IPK/files/etc/init.d/fips-gateway"
    "$IPK/files/etc/uci-defaults/90-fips-setup"
    "$IPK/files/usr/bin/fips-mesh-setup"
    "$IPK/files/usr/bin/fips-ap-setup"
    "$IPK/scripts/preinst"
    "$IPK/scripts/postinst"
    "$IPK/scripts/prerm"
)
BASH_TARGETS=(
    ".github/scripts/install-nak.sh"
)

if ! command -v shellcheck >/dev/null 2>&1; then
    echo "check-shellcheck: shellcheck not found; cannot lint the shell scripts" >&2
    echo "check-shellcheck: install it with 'apt-get install shellcheck'" >&2
    exit 2
fi
if ! command -v git >/dev/null 2>&1; then
    echo "check-shellcheck: git not found; cannot list the shipped scripts" >&2
    exit 2
fi

shellcheck --version | sed -n 's/^version: /check-shellcheck: shellcheck /p'

findings=0
broken=0

# ── Completeness: every shipped sh-family script is on the list ─────────────
shipped=$(git ls-files -- "$IPK/files" "$IPK/scripts") || {
    echo "check-shellcheck: git ls-files failed, refusing to pass" >&2
    exit 2
}
if [[ -z "$shipped" ]]; then
    echo "check-shellcheck: git ls-files found nothing under $IPK, refusing to pass" >&2
    exit 2
fi
while IFS= read -r f; do
    # A tracked file deleted from the working tree: if listed, the lint below
    # reports it missing; if not, there is nothing to ship.
    [[ -f "$f" ]] || continue
    head -n 1 "$f" | grep -qE '^#![[:space:]]*[^[:space:]]*/(env[[:space:]]+)?(ba|a|da)?sh([[:space:]]|$)' || continue
    listed=0
    for t in "${SH_TARGETS[@]}"; do
        [[ "$t" == "$f" ]] && { listed=1; break; }
    done
    if [[ $listed -eq 0 ]]; then
        echo "FAIL: $f is a shipped shell script missing from SH_TARGETS in $0"
        findings=1
    fi
done <<< "$shipped"

# ── Lint ─────────────────────────────────────────────────────────────────────
lint() {
    # lint <file> <shellcheck args...>: one file; sets findings or broken.
    local f="$1" rc=0
    shift
    if [[ ! -f "$f" ]]; then
        echo "FAIL: missing $f"
        findings=1
        return 0
    fi
    echo "==> shellcheck $* $f"
    shellcheck "$@" "$f" || rc=$?
    case $rc in
        0) echo "    PASS" ;;
        1) echo "    FAIL"; findings=1 ;;
        *) echo "    shellcheck exited $rc: could not check $f"; broken=1 ;;
    esac
    return 0
}

for f in "${SH_TARGETS[@]}"; do
    lint "$f" --shell=sh --exclude="$SH_EXCLUDE"
done
for f in "${BASH_TARGETS[@]}"; do
    lint "$f" --shell=bash
done

total=$(( ${#SH_TARGETS[@]} + ${#BASH_TARGETS[@]} ))
if [[ $broken -ne 0 ]]; then
    echo "shellcheck could not check every script; refusing to pass"
    exit 2
fi
if [[ $findings -ne 0 ]]; then
    echo "shellcheck FAILED"
    exit 1
fi
echo "shellcheck PASS ($total scripts: ${#SH_TARGETS[@]} as sh, ${#BASH_TARGETS[@]} as bash)"
exit 0
