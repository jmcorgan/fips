# shellcheck shell=bash
# ── Package hints for the tools local CI guards need ────────────────────────
# Sourced, not run. A guard that finds a tool missing exits 2 rather than
# passing, and calls tool_hint to say which package provides the tool, so a
# contributor off Debian is told what to install rather than left to guess.
# One table keeps the hints the same in every guard.
#
# The guards source this only inside their missing-tool branch, and only when
# the file is readable: glibc-floor/test.sh runs a copy of check-glibc-floor.sh
# with no lib/ beside it, and that copy must still run.
#
# Usage: tool_hint <tool>
#   Prints one line naming the package on Debian and Ubuntu, Fedora and Arch.
#   <tool> is a command name, or "yaml" for the python3 module. Returns 1,
#   printing nothing, for a tool the table does not know.
# ─────────────────────────────────────────────────────────────────────────────

tool_hint() {
    local deb fedora arch what="$1"
    case "$1" in
        dpkg|dpkg-deb) deb=dpkg;         fedora=dpkg;           arch=dpkg ;;
        readelf)       deb=binutils;     fedora=binutils;       arch=binutils ;;
        tar)           deb=tar;          fedora=tar;            arch=tar ;;
        python3)       deb=python3;      fedora=python3;        arch=python ;;
        yaml)          deb=python3-yaml; fedora=python3-pyyaml; arch=python-yaml
                       what="the python3 yaml module" ;;
        nft)           deb=nftables;     fedora=nftables;       arch=nftables ;;
        *) return 1 ;;
    esac
    echo "install $what with: apt install $deb (Debian, Ubuntu), dnf install $fedora (Fedora), pacman -S $arch (Arch)"
    return 0
}
