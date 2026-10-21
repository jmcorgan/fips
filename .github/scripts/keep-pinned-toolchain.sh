#!/bin/bash
# ── Remove every Rust toolchain but the pinned one ──────────────────────────
# rust-cache puts a hash of every installed toolchain's `rustc -vV` in its cache
# key. GitHub's runner images ship their own stable Rust, which moves with each
# image release, so while it stays installed the key changes whenever GitHub
# rolls a new image, and during a rollout runs alternate between two keys and
# miss each other's entries (rustc 1.99.0 on image 20261012, 1.99.1 on
# 20261018). Removing it leaves only rust-toolchain.toml's channel in the hash.
#
# The channel is read from a line exactly `channel = "<version>"`; any other
# spelling fails closed with "no channel".
#
# Called from .github/workflows/ci.yml between the toolchain install and the
# cache step of every job that uses rust-cache.
#
# Exit 0 = `rustup toolchain list --quiet`, the list rust-cache hashes, names
# only the pinned channel. Non-zero = the pin could not be read, the pinned
# toolchain is missing, or another toolchain is still installed afterwards.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

pinned=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
if [[ -z $pinned ]]; then
    echo "keep-pinned-toolchain: no channel in rust-toolchain.toml" >&2
    exit 1
fi

# Names only, without the Windows carriage return; rustup exits 0 when asked
# to uninstall a name it does not have, so a mangled name would otherwise
# leave its toolchain in place unnoticed.
toolchains() {
    local list
    list=$(rustup toolchain list --quiet)
    printf '%s\n' "${list//$'\r'/}"
}

list=$(toolchains)
kept=""
while read -r name; do
    if [[ $name == "$pinned"-* ]]; then
        kept=${kept:-$name}
    fi
done <<<"$list"
if [[ -z $kept ]]; then
    echo "keep-pinned-toolchain: toolchain $pinned is not installed" >&2
    exit 1
fi

# The image's stable is usually the default; repoint it first so nothing is
# left defaulting to a removed toolchain.
rustup default "$kept"
while read -r name; do
    if [[ -n $name && $name != "$pinned"-* ]]; then
        rustup toolchain uninstall "$name"
    fi
done <<<"$list"

left=$(toolchains)
while read -r name; do
    if [[ $name != "$pinned"-* ]]; then
        echo "keep-pinned-toolchain: still installed: '$name'" >&2
        exit 1
    fi
done <<<"$left"
printf '%s\n' "$left"
