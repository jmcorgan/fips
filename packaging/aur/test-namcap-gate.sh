#!/usr/bin/env bash
# Tests for namcap-gate.sh, the check that fails the AUR build job on namcap
# error-level findings.
#
# Default mode runs the gate against canned namcap output. A stub `namcap`
# first on PATH records its arguments, prints <fixture>/<basename>.out for the
# file it is given (nothing if absent), and exits with <basename>.rc (0 if
# absent). It exits 2 on an argument shape namcap does not accept. The canned
# output is copied verbatim from namcap 3.6.0-3 runs on the real fips package
# and on toy packages. These cases prove the parsing: which lines fail the
# gate, and that an unreadable input cannot pass as a clean one.
#
# --live builds three toy packages with makepkg and runs the gate on each with
# the real namcap: one declared correctly, one missing a library dependency,
# one missing a script interpreter's package. It proves that the installed
# namcap still reports those as error-level findings, which canned output
# cannot. It needs makepkg, gcc, namcap and the dbus and nftables packages,
# and refuses to run as root, because makepkg does.
#
# GATE=<path> runs the cases against another script in place of the gate.
# Exits nonzero if any case fails or if fewer cases ran than are defined.
#
# Usage: bash packaging/aur/test-namcap-gate.sh [--live]

set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GATE="${GATE:-$HERE/namcap-gate.sh}"

case "${1:-}" in
  '') MODE=canned ;;
  --live) MODE=live ;;
  *) echo "usage: test-namcap-gate.sh [--live]" >&2; exit 2 ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

CASES_DEFINED=0
CASES_RAN=0
FAILED=0
STUBDIR=""

# Run the gate on the given files and check its exit status and that its
# output states the expected reason, so a red caused by a crash in the gate
# does not pass as the intended red. The stub namcap is first on PATH in
# canned mode only. Sets LAST_OUT to the gate's combined output.
# Args: name fixture-dir expect(zero|nonzero) pattern [file...]
check() {
  local name=$1 fixture=$2 expect=$3 pattern=$4 rc=0
  shift 4
  CASES_RAN=$((CASES_RAN + 1))
  : > "$WORK/calls"
  LAST_OUT=$(PATH="$STUBDIR$PATH" STUB_FIXTURE="$fixture" STUB_CALLS="$WORK/calls" \
    bash "$GATE" "$@" 2>&1) || rc=$?
  if { [ "$expect" = zero ] && [ "$rc" -eq 0 ]; } ||
     { [ "$expect" = nonzero ] && [ "$rc" -ne 0 ]; }; then
    # Matched on a here-string, not a pipe from printf: under pipefail,
    # grep -q exiting at its match can kill the writer with SIGPIPE and turn
    # the match into a miss once the output is over 4 KB (two cases are).
    if grep -qE -- "$pattern" <<<"$LAST_OUT"; then
      echo "PASS $name (exit $rc)"
      return 0
    fi
    echo "FAIL $name: exit $rc as expected, but output lacks /$pattern/"
  else
    echo "FAIL $name: expected $expect exit, got $rc"
  fi
  printf '%s\n' "$LAST_OUT" | sed 's/^/    /'
  FAILED=$((FAILED + 1))
  return 1
}

# Record an extra assertion's failure against the case that just ran.
fail() {
  echo "FAIL $1"
  FAILED=$((FAILED + 1))
}

# Count the stub namcap's invocations in the case that just ran.
calls() {
  grep -c '' "$WORK/calls" || true
}

# Make a fresh fixture directory for a case and print its path.
fixture() {
  local dir="$WORK/fx/$1"
  mkdir -p "$dir/files"
  echo "$dir"
}

# Create the file the gate is given, in the fixture's files directory, and
# print its path. The content is irrelevant: the stub serves the output.
placeholder() {
  : > "$1/files/$2"
  echo "$1/files/$2"
}

# --- canned namcap output ----------------------------------------------------

# The real fips 0.5.1 package built from maint, as declared.
REAL_DECLARED=$(cat <<'EOF'
fips W: file-not-world-readable etc/fips/fips.yaml
fips I: script-link-detected nft in ['etc/fips/fips.nft']
fips I: script-link-detected bash in ['usr/lib/fips/fips-dns-setup', 'usr/lib/fips/fips-dns-teardown']
fips I: libdepends-missing-provides ld-linux-x86-64.so=2-64 glibc (['usr/bin/fipsctl', 'usr/bin/fips', 'usr/bin/fipstop', 'usr/bin/fips-gateway'])
fips I: libdepends-missing-provides libc.so=6-64 glibc (['usr/bin/fipsctl', 'usr/bin/fips', 'usr/bin/fipstop', 'usr/bin/fips-gateway'])
fips I: libdepends-missing-provides libm.so=6-64 glibc (['usr/bin/fips', 'usr/bin/fipstop', 'usr/bin/fips-gateway'])
fips I: link-level-dependence dbus in ['usr/lib/libdbus-1.so.3']
fips I: link-level-dependence glibc in ['usr/lib/ld-linux-x86-64.so.2', 'usr/lib/libc.so.6', 'usr/lib/libm.so.6']
fips I: link-level-dependence libgcc in ['usr/lib/libgcc_s.so.1']
fips I: libdepends-detected-not-included libdbus-1.so=3-64 dbus (['usr/bin/fips'])
fips I: libdepends-detected-not-included libgcc_s.so=1-64 libgcc (['usr/bin/fipsctl', 'usr/bin/fips', 'usr/bin/fipstop', 'usr/bin/fips-gateway'])
fips I: libdepends-by-namcap-sight depends=(glibc libdbus-1.so=3-64 libgcc_s.so=1-64)
fips I: libprovides-by-namcap-sight provides=()
fips W: unused-sodepend /usr/lib64/ld-linux-x86-64.so.2 usr/bin/fips
fips W: unused-sodepend /usr/lib64/ld-linux-x86-64.so.2 usr/bin/fips-gateway
fips W: unused-sodepend /usr/lib64/ld-linux-x86-64.so.2 usr/bin/fipsctl
fips W: unused-sodepend /usr/lib64/ld-linux-x86-64.so.2 usr/bin/fipstop
fips W: dependency-detected-but-optional nftables (programs-needed ['nft'] ['etc/fips/fips.nft'])
fips W: dependency-implicitly-satisfied libgcc (libraries-needed ['usr/lib/libgcc_s.so.1'] ['usr/bin/fipsctl', 'usr/bin/fips', 'usr/bin/fipstop', 'usr/bin/fips-gateway'])
fips W: dependency-implicitly-satisfied bash (programs-needed ['bash'] ['usr/lib/fips/fips-dns-setup', 'usr/lib/fips/fips-dns-teardown'])
fips W: dependency-not-needed gcc-libs
fips I: dependency-detected-satisfied glibc (libraries-needed ['usr/lib/ld-linux-x86-64.so.2', 'usr/lib/libc.so.6', 'usr/lib/libm.so.6'] ['usr/bin/fipsctl', 'usr/bin/fips-gateway', 'usr/bin/fipstop', 'usr/bin/fips'])
fips I: dependency-detected-satisfied dbus (libraries-needed ['usr/lib/libdbus-1.so.3'] ['usr/bin/fips'])
fips I: depends-by-namcap-sight depends=(nftables libgcc glibc dbus bash)
EOF
)

# The same package rebuilt with dbus dropped from depends.
REAL_NODBUS=$(cat <<'EOF'
fips W: file-not-world-readable etc/fips/fips.yaml
fips I: script-link-detected nft in ['etc/fips/fips.nft']
fips I: script-link-detected bash in ['usr/lib/fips/fips-dns-teardown', 'usr/lib/fips/fips-dns-setup']
fips I: libdepends-missing-provides ld-linux-x86-64.so=2-64 glibc (['usr/bin/fips-gateway', 'usr/bin/fipsctl', 'usr/bin/fips', 'usr/bin/fipstop'])
fips I: libdepends-missing-provides libc.so=6-64 glibc (['usr/bin/fips-gateway', 'usr/bin/fipsctl', 'usr/bin/fips', 'usr/bin/fipstop'])
fips I: libdepends-missing-provides libm.so=6-64 glibc (['usr/bin/fips-gateway', 'usr/bin/fips', 'usr/bin/fipstop'])
fips I: link-level-dependence dbus in ['usr/lib/libdbus-1.so.3']
fips I: link-level-dependence glibc in ['usr/lib/libc.so.6', 'usr/lib/ld-linux-x86-64.so.2', 'usr/lib/libm.so.6']
fips I: link-level-dependence libgcc in ['usr/lib/libgcc_s.so.1']
fips I: libdepends-detected-not-included libdbus-1.so=3-64 dbus (['usr/bin/fips'])
fips I: libdepends-detected-not-included libgcc_s.so=1-64 libgcc (['usr/bin/fips-gateway', 'usr/bin/fipsctl', 'usr/bin/fips', 'usr/bin/fipstop'])
fips I: libdepends-by-namcap-sight depends=(glibc libdbus-1.so=3-64 libgcc_s.so=1-64)
fips I: libprovides-by-namcap-sight provides=()
fips W: unused-sodepend /usr/lib64/ld-linux-x86-64.so.2 usr/bin/fips
fips W: unused-sodepend /usr/lib64/ld-linux-x86-64.so.2 usr/bin/fips-gateway
fips W: unused-sodepend /usr/lib64/ld-linux-x86-64.so.2 usr/bin/fipsctl
fips W: unused-sodepend /usr/lib64/ld-linux-x86-64.so.2 usr/bin/fipstop
fips E: dependency-detected-not-included dbus (libraries-needed ['usr/lib/libdbus-1.so.3'] ['usr/bin/fips'])
fips E: dependency-detected-not-included bash (programs-needed ['bash'] ['usr/lib/fips/fips-dns-teardown', 'usr/lib/fips/fips-dns-setup'])
fips W: dependency-implicitly-satisfied libgcc (libraries-needed ['usr/lib/libgcc_s.so.1'] ['usr/bin/fips-gateway', 'usr/bin/fipsctl', 'usr/bin/fips', 'usr/bin/fipstop'])
fips W: dependency-detected-but-optional nftables (programs-needed ['nft'] ['etc/fips/fips.nft'])
fips W: dependency-not-needed gcc-libs
fips I: dependency-detected-satisfied glibc (libraries-needed ['usr/lib/libc.so.6', 'usr/lib/ld-linux-x86-64.so.2', 'usr/lib/libm.so.6'] ['usr/bin/fipsctl', 'usr/bin/fipstop', 'usr/bin/fips-gateway', 'usr/bin/fips'])
fips I: depends-by-namcap-sight depends=(dbus glibc libgcc nftables bash)
EOF
)

# A toy package with nftables in neither depends nor optdepends and an nft
# script under etc/.
TOY_NONFT=$(cat <<'EOF'
fips W: elffile-without-relro usr/bin/fips
fips I: script-link-detected nft in ['etc/fips/fips.nft']
fips I: libdepends-missing-provides libc.so=6-64 glibc (['usr/bin/fips'])
fips I: link-level-dependence dbus in ['usr/lib/libdbus-1.so.3']
fips I: link-level-dependence glibc in ['usr/lib/libc.so.6']
fips I: libdepends-detected-not-included libdbus-1.so=3-64 dbus (['usr/bin/fips'])
fips I: libdepends-by-namcap-sight depends=(glibc libdbus-1.so=3-64)
fips I: libprovides-by-namcap-sight provides=()
fips E: dependency-detected-not-included nftables (programs-needed ['nft'] ['etc/fips/fips.nft'])
fips I: dependency-detected-satisfied glibc (libraries-needed ['usr/lib/libc.so.6'] ['usr/bin/fips'])
fips I: dependency-detected-satisfied dbus (libraries-needed ['usr/lib/libdbus-1.so.3'] ['usr/bin/fips'])
fips I: depends-by-namcap-sight depends=(glibc nftables dbus)
EOF
)

# Warning-level findings only, with the dependency-analysis line.
WARN_ONLY=$(cat <<'EOF'
fips W: dependency-detected-but-optional nftables (programs-needed ['nft'] ['etc/fips/fips.nft'])
fips I: depends-by-namcap-sight depends=(dbus glibc nftables)
EOF
)

# A PKGBUILD without url or maintainer.
PKGBUILD_BAD=$(cat <<'EOF'
PKGBUILD (fips) W: missing-maintainer
PKGBUILD (fips) E: missing-url
PKGBUILD (fips) W: pkgname-in-description
EOF
)

# The maint release PKGBUILD.
PKGBUILD_CLEAN=$(cat <<'EOF'
PKGBUILD (fips) I: missing-contributor
EOF
)

# namcap given a file that does not exist; it exits 0.
UNREADABLE=$(cat <<'EOF'
Error: Problem reading nosuch.pkg.tar.zst
usage: python3 -m namcap [-h] [-L] [-i] [-m] [-t TAGS] [-e RULELIST |
                         -r RULELIST] [-v]
                         [packages ...]
Error: nosuch.pkg.tar.zst not package or PKGBUILD
EOF
)

# --- canned cases ------------------------------------------------------------

# Run the cases against canned namcap output through the stub.
canned() {
  local fx f a b

  mkdir -p "$WORK/bin"
  cat > "$WORK/bin/namcap" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$STUB_CALLS"
file=""
for a in "$@"; do
  case "$a" in
    -i|-m) ;;
    -*) echo "stub namcap: unexpected option: $a" >&2; exit 2 ;;
    *)
      [ -z "$file" ] || { echo "stub namcap: more than one file: $*" >&2; exit 2; }
      file=$a
      ;;
  esac
done
[ -n "$file" ] || { echo "stub namcap: no file given" >&2; exit 2; }
b=$(basename -- "$file")
if [ -f "$STUB_FIXTURE/$b.out" ]; then cat "$STUB_FIXTURE/$b.out"; fi
exit "$(cat "$STUB_FIXTURE/$b.rc" 2>/dev/null || echo 0)"
STUB
  chmod +x "$WORK/bin/namcap"
  STUBDIR="$WORK/bin:"

  local pkg=fips-0.5.1-1-x86_64.pkg.tar.zst

  # C1: the real package as declared has warnings only, and the gate asks
  # namcap for informational lines and tag names.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C1); f=$(placeholder "$fx" "$pkg")
  printf '%s\n' "$REAL_DECLARED" > "$fx/$pkg.out"
  if check "C1 real package as declared passes" "$fx" zero '^namcap gate: passed' "$f"; then
    grep -q -- "^-i -m $f\$" "$WORK/calls" ||
      fail "C1 real package as declared passes: namcap not called with -i -m: $(cat "$WORK/calls")"
  fi

  # C2: the real package with dbus dropped from depends.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C2); f=$(placeholder "$fx" "$pkg")
  printf '%s\n' "$REAL_NODBUS" > "$fx/$pkg.out"
  check "C2 real package missing dbus fails" "$fx" nonzero \
    '^::error title=namcap::fips E: dependency-detected-not-included dbus ' "$f" || true

  # C3: a script interpreter's package declared nowhere.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C3); f=$(placeholder "$fx" "$pkg")
  printf '%s\n' "$TOY_NONFT" > "$fx/$pkg.out"
  check "C3 undeclared script dependency fails" "$fx" nonzero \
    '^::error title=namcap::fips E: dependency-detected-not-included nftables ' "$f" || true

  # C4: warnings are advisory.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C4); f=$(placeholder "$fx" "$pkg")
  printf '%s\n' "$WARN_ONLY" > "$fx/$pkg.out"
  check "C4 warnings only pass" "$fx" zero '^namcap gate: passed' "$f" || true

  # C5: an error-level finding on a PKGBUILD.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C5); f=$(placeholder "$fx" PKGBUILD)
  printf '%s\n' "$PKGBUILD_BAD" > "$fx/PKGBUILD.out"
  check "C5 PKGBUILD error fails" "$fx" nonzero \
    '^::error title=namcap::PKGBUILD \(fips\) E: missing-url' "$f" || true

  # C6: a clean PKGBUILD needs no dependency-analysis line.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C6); f=$(placeholder "$fx" PKGBUILD)
  printf '%s\n' "$PKGBUILD_CLEAN" > "$fx/PKGBUILD.out"
  check "C6 clean PKGBUILD passes" "$fx" zero '^namcap gate: passed' "$f" || true

  # C7: namcap could not read its input, printed an error and usage, and
  # exited 0.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C7); f=$(placeholder "$fx" "$pkg")
  printf '%s\n' "$UNREADABLE" > "$fx/$pkg.out"
  check "C7 unreadable input fails" "$fx" nonzero \
    ': unrecognised namcap output: Error: Problem reading' "$f" || true

  # C8: a package for which namcap printed nothing.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C8); f=$(placeholder "$fx" "$pkg")
  check "C8 empty output for a package fails" "$fx" nonzero \
    ': no dependency analysis in namcap output$' "$f" || true

  # C9: namcap exits nonzero on otherwise clean output.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C9); f=$(placeholder "$fx" "$pkg")
  printf '%s\n' "$REAL_DECLARED" > "$fx/$pkg.out"
  echo 1 > "$fx/$pkg.rc"
  check "C9 namcap nonzero exit fails" "$fx" nonzero ': namcap exited 1$' "$f" || true

  # C10: the named file does not exist, as when a glob matched nothing.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C10)
  if check "C10 missing file fails" "$fx" nonzero ': not found$' "$fx/files/*.pkg.tar.*"; then
    [ "$(calls)" -eq 0 ] ||
      fail "C10 missing file fails: namcap was called $(calls) time(s), expected 0"
  fi

  # C11: no files at all.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C11)
  check "C11 no arguments fails" "$fx" nonzero '^usage: ' || true

  # C12: two packages, the error only in the second.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C12)
  a=$(placeholder "$fx" a-1-1-x86_64.pkg.tar.zst); b=$(placeholder "$fx" b-1-1-x86_64.pkg.tar.zst)
  printf '%s\n' "$REAL_DECLARED" > "$fx/a-1-1-x86_64.pkg.tar.zst.out"
  printf '%s\n' "$REAL_NODBUS" > "$fx/b-1-1-x86_64.pkg.tar.zst.out"
  if check "C12 error in the second of two packages fails" "$fx" nonzero \
      "^namcap gate: $b: 2 error-level finding" "$a" "$b"; then
    [ "$(calls)" -eq 2 ] ||
      fail "C12 error in the second of two packages fails: namcap called $(calls) time(s), expected 2"
  fi

  # C13: two packages, the error only in the first; the clean second must not
  # overwrite the verdict.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C13)
  a=$(placeholder "$fx" a-1-1-x86_64.pkg.tar.zst); b=$(placeholder "$fx" b-1-1-x86_64.pkg.tar.zst)
  printf '%s\n' "$REAL_NODBUS" > "$fx/a-1-1-x86_64.pkg.tar.zst.out"
  printf '%s\n' "$REAL_DECLARED" > "$fx/b-1-1-x86_64.pkg.tar.zst.out"
  if check "C13 error in the first of two packages fails" "$fx" nonzero \
      "^namcap gate: $a: 2 error-level finding" "$a" "$b"; then
    [ "$(calls)" -eq 2 ] ||
      fail "C13 error in the first of two packages fails: namcap called $(calls) time(s), expected 2"
  fi

  # C14: " E: " inside a warning's text is not an error-level finding.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C14); f=$(placeholder "$fx" "$pkg")
  { printf '%s\n' "$REAL_DECLARED"; echo "fips W: some-tag text ' E: ' inside"; } > "$fx/$pkg.out"
  check "C14 E: inside a warning's text passes" "$fx" zero '^namcap gate: passed' "$f" || true

  # C15: a file that is neither a PKGBUILD nor a package.
  CASES_DEFINED=$((CASES_DEFINED + 1))
  fx=$(fixture C15); f=$(placeholder "$fx" fips.tar.gz)
  if check "C15 unknown file shape fails" "$fx" nonzero ': not a PKGBUILD or package$' "$f"; then
    [ "$(calls)" -eq 0 ] ||
      fail "C15 unknown file shape fails: namcap was called $(calls) time(s), expected 0"
  fi
}

# --- live cases --------------------------------------------------------------

# Write a toy package's PKGBUILD and sources into a directory, build it with
# makepkg, and print the built package's path. The binary links libdbus; the
# nft script under etc/ needs nftables' interpreter.
# Args: dir depends optdepends
toypkg() {
  local dir=$1 pkgs
  mkdir -p "$dir"
  cat > "$dir/probe.c" <<'EOF'
/* Calls one libdbus symbol so the binary carries NEEDED libdbus-1.so.3. */
extern void *dbus_message_new(int message_type);
int main(void) { return dbus_message_new(1) == 0; }
EOF
  printf '#!/usr/sbin/nft -f\nflush ruleset\n' > "$dir/probe.nft"
  cat > "$dir/PKGBUILD" <<EOF
# Maintainer: namcap gate test <test@example.invalid>
pkgname=namcap-probe
pkgver=1
pkgrel=1
pkgdesc="Toy package for the namcap gate test"
url="https://example.invalid"
license=('MIT')
arch=('x86_64')
depends=($2)
optdepends=($3)
options=('!debug')
source=("probe.c" "probe.nft")
b2sums=('SKIP' 'SKIP')
build() { gcc -O2 -o namcap-probe probe.c -Wl,--no-as-needed -ldbus-1; }
package() {
  install -Dm0755 namcap-probe "\$pkgdir/usr/bin/namcap-probe"
  install -Dm0644 /dev/null "\$pkgdir/usr/share/licenses/namcap-probe/LICENSE"
  install -Dm0644 probe.nft "\$pkgdir/etc/namcap-probe/probe.nft"
}
EOF
  (cd "$dir" && makepkg -f -d --noconfirm) > "$dir/makepkg.log" 2>&1 || return 1
  pkgs=("$dir"/*.pkg.tar.*)
  [ -f "${pkgs[0]}" ] || return 1
  echo "${pkgs[0]}"
}

# Build one toy package and run the gate on it with the real namcap. A build
# failure fails the case and prints the build log; it is never a skip.
# Args: name expect pattern depends optdepends
livecase() {
  local name=$1 expect=$2 pattern=$3 dir pkg
  dir="$WORK/live/${name%% *}"
  CASES_DEFINED=$((CASES_DEFINED + 1))
  if ! pkg=$(toypkg "$dir" "$4" "$5"); then
    CASES_RAN=$((CASES_RAN + 1))
    fail "$name: toy package did not build"
    sed 's/^/    /' "$dir/makepkg.log" 2>/dev/null || true
    return 0
  fi
  check "$name" "$dir" "$expect" "$pattern" "$pkg" || true
}

# Run the cases that build toy packages and lint them with the real namcap.
live() {
  local missing
  if [ "$(id -u)" -eq 0 ]; then
    echo "test-namcap-gate.sh --live: run as a non-root user; makepkg refuses root" >&2
    exit 2
  fi
  if ! missing=$(pacman -Q dbus nftables 2>&1); then
    echo "FAIL live cases need dbus and nftables installed, as namcap looks up"
    echo "     script and library owners in the local package database:"
    printf '%s\n' "$missing" | sed 's/^/    /'
    exit 1
  fi

  livecase "L1 correctly declared toy package passes" zero '^namcap gate: passed' \
    "'dbus' 'glibc'" "'nftables: ruleset'"
  livecase "L2 toy package missing dbus fails" nonzero \
    '^::error title=namcap::namcap-probe E: dependency-detected-not-included dbus ' \
    "'glibc'" "'nftables: ruleset'"
  livecase "L3 toy package missing nftables fails" nonzero \
    '^::error title=namcap::namcap-probe E: dependency-detected-not-included nftables ' \
    "'dbus' 'glibc'" ""
}

# -----------------------------------------------------------------------------

if [ "$MODE" = live ]; then live; else canned; fi

echo "cases defined: $CASES_DEFINED, ran: $CASES_RAN, failed: $FAILED"
if [ "$CASES_RAN" -ne "$CASES_DEFINED" ]; then
  echo "FAIL: not every defined case ran"
  exit 1
fi
[ "$FAILED" -eq 0 ]
