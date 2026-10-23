#!/bin/bash
# Tests for tun_name() in packaging/common/fips-dns-setup, which reads the
# TUN interface name the daemon will create from the top-level `tun:` block of
# its config and falls back to the daemon's default, fips0.
#
# The script is sourced in a subshell, with FIPS_CONFIG pointing at a fixture,
# and only tun_name is called. Sourcing must not run the script's main path,
# which waits for the interface and configures the host's resolver. As a guard
# against a script whose main path does run, every command that path could use
# to touch the host (ip, systemctl, resolvectl, nmcli, and sleep, so a wait
# ends at once) is replaced by a stub on PATH that only reports it was called.
# No containers, no root; about a second.
#
# Run:
#   ./tun-name-test.sh
# Exits 0 only if every case passes; non-zero if any case fails.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETUP="$REPO_ROOT/packaging/common/fips-dns-setup"
SHIPPED_YAML="$REPO_ROOT/packaging/common/fips.yaml"

FAILURES=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin"
for cmd in ip systemctl resolvectl nmcli; do
    printf '#!/bin/sh\necho "STUB-CALLED: %s $*" >&2\nexit 1\n' "$cmd" >"$WORK/bin/$cmd"
    chmod +x "$WORK/bin/$cmd"
done
printf '#!/bin/sh\nexit 0\n' >"$WORK/bin/sleep"
chmod +x "$WORK/bin/sleep"

# Print what tun_name returns for the config at $1, or a line starting with
# "ERROR:" saying why it could not be called. $0 inside the subshell is "_", so
# the script's main guard sees it is being sourced.
lookup() {
    local config="$1" out rc=0
    # shellcheck disable=SC2016  # expanded by the subshell, not here
    out=$(PATH="$WORK/bin:$PATH" FIPS_CONFIG="$config" timeout 10 bash -c '
        source "$1" >"$2/source.out" 2>&1 || exit 3
        declare -F tun_name >/dev/null || exit 4
        tun_name
    ' _ "$SETUP" "$WORK" 2>&1) || rc=$?
    case "$rc" in
        0) printf '%s\n' "$out" ;;
        4) echo "ERROR: fips-dns-setup defines no tun_name function" ;;
        124) echo "ERROR: sourcing fips-dns-setup did not return within 10s" ;;
        *) echo "ERROR: sourcing fips-dns-setup exited $rc, so it ran its main path: $(tr '\n' ' ' <"$WORK/source.out")" ;;
    esac
    return 0
}

# expect <case name> <wanted name> <config path>
expect() {
    local name="$1" want="$2" config="$3" got
    got=$(lookup "$config")
    if [ "$got" = "$want" ]; then
        echo "PASS  $name  (got $got)"
    else
        echo "FAIL  $name  (want '$want', got '$got')"
        FAILURES=$((FAILURES + 1))
    fi
    return 0
}

# fixture <file name> <yaml text>: writes a config fixture and prints its path.
fixture() {
    printf '%s\n' "$2" >"$WORK/$1"
    echo "$WORK/$1"
    return 0
}

expect "shipped_config_gives_fips0" fips0 "$SHIPPED_YAML"

expect "plain_name_under_tun_is_read" mesh0 "$(fixture plain.yaml 'tun:
  enabled: true
  name: mesh0
  mtu: 1280')"

expect "double_quoted_name_is_unquoted" mesh0 "$(fixture dq.yaml 'tun:
  name: "mesh0"')"

expect "single_quoted_name_with_trailing_comment_is_unquoted" mesh0 "$(fixture sq.yaml "tun:
  name: 'mesh0'  # renamed for the lab")"

expect "commented_tun_line_and_four_space_indent_are_read" mesh1 "$(fixture indent.yaml 'tun:   # the TUN device
    enabled: true
    name: mesh1')"

expect "name_under_another_top_level_block_is_ignored" fips0 "$(fixture other.yaml 'node:
  name: notatun
tun:
  enabled: true
dns:
  name: alsonot')"

expect "name_nested_below_tun_is_not_the_tun_name" mesh2 "$(fixture nested.yaml 'tun:
  extra:
    name: deeper
  name: mesh2')"

expect "name_after_the_tun_block_ends_is_ignored" fips0 "$(fixture after.yaml 'tun:
  enabled: true
# a comment between blocks
peers:
  - name: peer0')"

expect "commented_out_name_is_ignored" fips0 "$(fixture commented.yaml 'tun:
  # name: mesh9
  enabled: true')"

expect "config_without_tun_block_gives_fips0" fips0 "$(fixture notun.yaml 'node:
  identity:
    persistent: true')"

expect "missing_config_gives_fips0" fips0 "$WORK/does-not-exist.yaml"

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "tun-name: all cases passed"
    exit 0
fi
echo "tun-name: $FAILURES case(s) failed"
exit 1
