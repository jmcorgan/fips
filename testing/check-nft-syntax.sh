#!/bin/bash
# ── nftables ruleset syntax check ───────────────────────────────────────────
# Runs `nft -c -f` on the fips0 baseline ruleset, which ships in every Linux
# package, so a ruleset nft would refuse at install time fails local CI first.
#
# Usage: check-nft-syntax.sh [ruleset]
#   The ruleset defaults to packaging/common/fips.nft.
#
# `nft -c` needs root even though it changes nothing: it reads the kernel's
# ruleset cache, and as an ordinary user that fails with "cache initialization
# failed: Operation not permitted". The check takes root one of two ways,
# without ever prompting:
#   1. unshare -rn: root in a private user and network namespace, which needs
#      no sudo. Hosts that block unprivileged user namespaces refuse it (Ubuntu
#      24.04 sets kernel.apparmor_restrict_unprivileged_userns = 1).
#   2. sudo -n: passwordless sudo. It fails at once where sudo wants a
#      password, rather than waiting on a prompt nobody answers.
#
# Each way is first tried on a small ruleset known to be valid, written to a
# temporary file. A way is used only if that probe passes, so a failure on the
# real file is nft refusing the ruleset or a file it includes, not the
# environment refusing to run nft. fips.nft includes the host's
# /etc/fips/fips.d/*.nft, so a broken drop-in there fails the check too.
#
# nft is looked up on PATH, then in /usr/sbin and /sbin, which a non-root
# login PATH on Debian leaves out. It is named by its full path, so sudo runs
# that nft rather than the first one on its secure_path.
#
# GitHub's CI job runs `sudo nft -c` directly, since sudo is passwordless on
# its runners; this script is ci-local.sh's nft-syntax stage.
#
# Exit 0 = nft accepts the ruleset. Exit 1 = nft refuses it or a file it
# includes, with nft's own message. Exit 2 = the check could not run (nft missing, the ruleset
# unreadable, or no way to run nft as root); never treated as a pass.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ $# -gt 1 ]; then
    echo "usage: check-nft-syntax.sh [ruleset]" >&2
    exit 2
fi
RULESET="${1:-$PROJECT_ROOT/packaging/common/fips.nft}"

cant() {
    echo "check-nft-syntax: $*" >&2
    exit 2
}

[ -r "$RULESET" ] || cant "cannot read $RULESET"

# find_nft: prints the path of the nft to run, or returns 1 if there is none.
find_nft() {
    local p
    command -v nft && return 0
    for p in /usr/sbin/nft /sbin/nft; do
        if [ -x "$p" ]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

NFT="$(find_nft)" || {
    echo "check-nft-syntax: nft is not installed; cannot check $RULESET" >&2
    if [ -r "$SCRIPT_DIR/lib/tool-hint.sh" ]; then
        # shellcheck source=/dev/null
        . "$SCRIPT_DIR/lib/tool-hint.sh"
        hint="$(tool_hint nft)" && echo "check-nft-syntax: $hint" >&2
    fi
    exit 2
}

WORK="$(mktemp -d)" || cant "mktemp failed"
trap 'rm -rf "$WORK"' EXIT

PROBE="$WORK/probe.nft"
cat > "$PROBE" <<'NFT'
table inet fips_probe {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "lo" accept
    }
}
NFT

# as_root <way> <file>: runs nft -c on the file as root the given way, with
# its output in $WORK/out. Returns nft's status, or 127 when the way's own
# tool is not installed.
as_root() {
    local way="$1" file="$2"
    case "$way" in
        unshare)
            command -v unshare >/dev/null 2>&1 || { echo "unshare is not installed" > "$WORK/out"; return 127; }
            unshare -rn "$NFT" -c -f "$file" > "$WORK/out" 2>&1
            ;;
        sudo)
            command -v sudo >/dev/null 2>&1 || { echo "sudo is not installed" > "$WORK/out"; return 127; }
            # The output file is this user's own, so the redirect stays
            # outside sudo on purpose.
            { sudo -n "$NFT" -c -f "$file"; } > "$WORK/out" 2>&1
            ;;
    esac
}

WAY=""
for way in unshare sudo; do
    if as_root "$way" "$PROBE"; then
        WAY="$way"
        break
    fi
    { echo "  $way:"; sed 's/^/    | /' "$WORK/out"; } >> "$WORK/refused"
done

if [ -z "$WAY" ]; then
    echo "check-nft-syntax: cannot run: needs unprivileged user namespaces or passwordless sudo" >&2
    echo "check-nft-syntax: nft -c on a known-good ruleset failed every way it was run as root:" >&2
    cat "$WORK/refused" >&2
    exit 2
fi

if as_root "$WAY" "$RULESET"; then
    echo "check-nft-syntax: nft accepts $RULESET (as root through $WAY)"
    exit 0
fi
echo "check-nft-syntax: nft refuses $RULESET (as root through $WAY):" >&2
cat "$WORK/out" >&2
exit 1
