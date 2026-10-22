#!/bin/bash
# Run a dnf command inside an RPM-family container with a wall-clock bound on
# each attempt, and report how long each attempt took and which mirrors it
# fetched from.
#
# Usage: dnf-bounded.sh --bound SECONDS [--attempts N] [--record FILE] -- DNF-ARGS...
#
#   --bound     seconds one attempt may run before it is killed (required)
#   --attempts  attempts before giving up, default 1; 5 s, then 10 s, ... between
#   --record    also append the per-attempt report to FILE
#
# Exit status: 0 once an attempt succeeds, otherwise the last attempt's status
# (124 when the bound ended it).
#
# Why: a fresh container downloads the whole repository metadata (about 80 MB
# for AlmaLinux 9) from whichever mirror the mirror list hands it. On GitHub
# that silent download has taken from seconds to nearly ten minutes, and once
# ran until the job's own limit with nothing to say which mirror or step held
# it. dnf's own limits do not help there: its default minrate trips only below
# 1 kB/s. So each attempt carries a wall-clock bound, a mirror slower than
# 50 kB/s for 20 s is abandoned for the next one, and the report names the
# mirrors and the transfer rates, so a slow job's log says where the time went.
#
# Runs inside the container, so it needs only bash, coreutils and dnf. It
# handles both dnf 4 (EL9, which takes -v) and dnf5 (Fedora, which does not and
# logs to a different file).

set -uo pipefail

bound=""
attempts=1
record=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bound) bound="${2:?missing value for --bound}"; shift 2 ;;
        --attempts) attempts="${2:?missing value for --attempts}"; shift 2 ;;
        --record) record="${2:?missing value for --record}"; shift 2 ;;
        --) shift; break ;;
        *) echo "dnf-bounded: unknown option $1" >&2; exit 2 ;;
    esac
done
if ! [[ "$bound" =~ ^[1-9][0-9]*$ && "$attempts" =~ ^[1-9][0-9]*$ ]] || [ $# -eq 0 ]; then
    echo "dnf-bounded: usage: dnf-bounded.sh --bound SECONDS [--attempts N] [--record FILE] -- DNF-ARGS..." >&2
    exit 2
fi

# dnf5 rejects -v; its progress lines and librepo's URLs come without it. The
# version is read whole before it is matched: `dnf --version | grep -q` lets
# grep exit at the first line, dnf then dies of SIGPIPE, and under pipefail the
# test fails on dnf5 some of the time.
verbose=(-v)
librepo_log=/var/log/dnf.librepo.log
version=$(dnf --version 2>/dev/null)
if [[ "$version" == dnf5* ]]; then
    verbose=()
    librepo_log=/var/log/dnf5.log
fi

out=/var/tmp/dnf-bounded.out
# Print to stderr, and to the record file when one was asked for.
report() {
    echo "$*" >&2
    if [ -n "$record" ]; then
        echo "$*" >>"$record"
    fi
    return 0
}

attempt=1
while true; do
    seen=0
    [ -f "$librepo_log" ] && seen=$(wc -l <"$librepo_log")
    start=$SECONDS
    rc=0
    timeout -k 10 "$bound" dnf "${verbose[@]}" \
        --setopt=timeout=20 --setopt=minrate=50k "$@" >"$out" 2>&1 || rc=$?
    took=$((SECONDS - start))

    urls=""
    [ -f "$librepo_log" ] && urls=$(tail -n +"$((seen + 1))" "$librepo_log" \
        | grep -oE 'Downloading: [a-z]+://[^ ]+' | sed 's/^Downloading: //')
    mirrors=$(grep -oE '^[a-z]+://[^/]+' <<<"$urls" | sort | uniq -c \
        | awk '{ printf "%s%s (%s)", sep, $2, $1; sep = ", " }')

    outcome="exit $rc"
    [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] && outcome="killed at the ${bound}s bound"
    report "dnf-bounded: $(date -u +%FT%TZ) attempt $attempt of $attempts, dnf $1: $outcome after ${took}s; mirrors: ${mirrors:-none}"
    # The transfer lines, rate and size, from both dnf versions: one per
    # repository's metadata and the packages' total, not one per package.
    while IFS= read -r line; do
        report "dnf-bounded:   $line"
    done < <(grep -E '[0-9.]+ +[kKMG]i?B/s +\|' "$out" \
        | awk '!/^[[:space:]]*[([] *[0-9]+\/[0-9]+[])]/ || / Total /' \
        | sed 's/[[:space:]]\+$//')

    if [ "$rc" -eq 0 ]; then
        rm -f "$out"
        exit 0
    fi
    if [ -n "$urls" ]; then
        report "dnf-bounded:   last fetch started: $(tail -n 1 <<<"$urls")"
    fi
    echo "dnf-bounded:   --- last lines of dnf's output ---" >&2
    tail -n 20 "$out" >&2
    if [ "$attempt" -ge "$attempts" ]; then
        rm -f "$out"
        exit "$rc"
    fi
    sleep $((attempt * 5))
    attempt=$((attempt + 1))
done
