#!/bin/bash
# Run a dnf command inside an RPM-family container with a wall-clock bound on
# each attempt, and report how long each attempt took and which mirrors it
# fetched from.
#
# Usage: dnf-bounded.sh --bound SECONDS [--attempts N] [--record FILE]
#                       [--deadline EPOCH|@FILE] [--label TEXT] -- DNF-ARGS...
#
#   --bound     seconds one attempt may run before it is killed (required)
#   --attempts  attempts before giving up, default 1; 5 s, then 10 s, ... between
#   --record    also append the per-attempt report to FILE
#   --deadline  the caller's network budget ends at EPOCH (seconds since 1970),
#               or at the epoch read from FILE: no attempt runs past it
#   --label     what the budget messages call this call, default "dnf <command>"
#
# Exit status: 0 once an attempt succeeds, otherwise the last attempt's status
# (124 when the bound ended it). 124 also when the deadline ended an attempt or
# left no time for the next, and 2 for a usage error, which includes a
# --deadline @FILE that is missing, empty or not an integer.
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
# The per-attempt bound alone cannot keep a job inside its limit: a job runs
# several such calls, each slow but under its bound, and their sum can still
# pass the limit. --deadline is the job-wide answer. Each attempt is bounded by
# the smaller of --bound and the time left; a first attempt starts whenever
# any time is left, so a short no-network step after a slow one still runs,
# and a retry does not start with under 30 s left, because it would only be
# killed again. A deadline that cannot be read is an error rather than no
# deadline, so a broken hand-off fails loudly instead of running unbounded.
#
# Runs inside the container, so it needs only bash, coreutils and dnf. It
# handles both dnf 4 (EL9, which takes -v) and dnf5 (Fedora, which does not and
# logs to a different file). DNF_BOUNDED_LOG overrides the librepo log it reads
# the mirrors from, for testing/rpm-install/budget-test.sh.

set -uo pipefail

bound=""
attempts=1
record=""
deadline=""
label=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bound) bound="${2:?missing value for --bound}"; shift 2 ;;
        --attempts) attempts="${2:?missing value for --attempts}"; shift 2 ;;
        --record) record="${2:?missing value for --record}"; shift 2 ;;
        --deadline) deadline="${2:?missing value for --deadline}"; shift 2 ;;
        --label) label="${2:?missing value for --label}"; shift 2 ;;
        --) shift; break ;;
        *) echo "dnf-bounded: unknown option $1" >&2; exit 2 ;;
    esac
done
if ! [[ "$bound" =~ ^[1-9][0-9]*$ && "$attempts" =~ ^[1-9][0-9]*$ ]] || [ $# -eq 0 ]; then
    echo "dnf-bounded: usage: dnf-bounded.sh --bound SECONDS [--attempts N] [--record FILE]" >&2
    echo "                    [--deadline EPOCH|@FILE] [--label TEXT] -- DNF-ARGS..." >&2
    exit 2
fi
: "${label:=dnf $1}"

# The deadline is read once, before dnf runs. A secret file arrives empty when
# the build was not handed a value, and that must not read as "no deadline".
if [[ "$deadline" == @* ]]; then
    file="${deadline#@}"
    why=""
    if [ ! -e "$file" ]; then
        why="missing"
    else
        deadline=$(tr -d '[:space:]' <"$file")
        if [ -z "$deadline" ]; then
            why="empty"
        elif ! [[ "$deadline" =~ ^[0-9]+$ ]]; then
            why="not an integer"
        fi
    fi
    if [ -n "$why" ]; then
        echo "dnf-bounded: --deadline @FILE: $file is $why" >&2
        exit 2
    fi
elif [ -n "$deadline" ] && ! [[ "$deadline" =~ ^[0-9]+$ ]]; then
    echo "dnf-bounded: --deadline: '$deadline' is not an integer" >&2
    exit 2
fi

# dnf5 rejects -v; its progress lines and librepo's URLs come without it. The
# version is read whole before it is matched: `dnf --version | grep -q` lets
# grep exit at the first line, dnf then dies of SIGPIPE, and under pipefail the
# test fails on dnf5 some of the time.
verbose=(-v)
librepo_log=${DNF_BOUNDED_LOG:-/var/log/dnf.librepo.log}
version=$(dnf --version 2>/dev/null)
if [[ "$version" == dnf5* ]]; then
    verbose=()
    librepo_log=${DNF_BOUNDED_LOG:-/var/log/dnf5.log}
fi

out=$(mktemp) || exit 1
trap 'rm -f "$out"' EXIT
# Print to stderr, and to the record file when one was asked for.
report() {
    echo "$*" >&2
    if [ -n "$record" ]; then
        echo "$*" >>"$record"
    fi
    return 0
}

# The mirrors a list of URLs reached, with a count of requests each.
mirror_list() {
    grep -oE '^[a-z]+://[^/]+' <<<"$1" | sort | uniq -c \
        | awk '{ printf "%s%s (%s)", sep, $2, $1; sep = ", " }'
}

# Seconds left before the deadline; meaningful only when one was given.
time_left() {
    echo $((deadline - $(date +%s)))
}

# The loop stops because the budget is spent: say so, with every mirror any
# attempt reached, and exit as an attempt its own bound ended does.
budget_spent() {
    local after="$1" tried
    tried=$(mirror_list "$all_urls")
    report "dnf-bounded: $label: the run's network budget is spent after attempt $after of $attempts; mirrors tried: ${tried:-none}"
    exit 124
}

attempt=1
all_urls=""
while true; do
    limit=$bound
    clamped=0
    if [ -n "$deadline" ]; then
        left=$(time_left)
        if [ "$attempt" -eq 1 ] && [ "$left" -le 0 ]; then
            report "dnf-bounded: $label: the run's network budget was spent before attempt 1 of $attempts"
            exit 124
        fi
        if [ "$attempt" -gt 1 ] && [ "$left" -lt 30 ]; then
            budget_spent $((attempt - 1))
        fi
        # timeout treats 0 as no bound at all, which the checks above rule
        # out: left is at least 1 here.
        if [ "$left" -lt "$bound" ]; then
            limit=$left
            clamped=1
        fi
    fi
    seen=0
    [ -f "$librepo_log" ] && seen=$(wc -l <"$librepo_log")
    start=$SECONDS
    rc=0
    timeout -k 10 "$limit" dnf "${verbose[@]}" \
        --setopt=timeout=20 --setopt=minrate=50k "$@" >"$out" 2>&1 || rc=$?
    took=$((SECONDS - start))

    urls=""
    [ -f "$librepo_log" ] && urls=$(tail -n +"$((seen + 1))" "$librepo_log" \
        | grep -oE 'Downloading: [a-z]+://[^ ]+' | sed 's/^Downloading: //')
    [ -n "$urls" ] && all_urls+="$urls"$'\n'
    mirrors=$(mirror_list "$urls")

    outcome="exit $rc"
    killed=0
    [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ] && killed=1
    if [ "$killed" -eq 1 ]; then
        if [ "$clamped" -eq 1 ]; then
            outcome="killed at the run's budget (deadline $(date -u -d "@$deadline" +%FT%TZ))"
        else
            outcome="killed at the ${bound}s bound"
        fi
    fi
    report "dnf-bounded: $(date -u +%FT%TZ) attempt $attempt of $attempts, dnf $1: $outcome after ${took}s; mirrors: ${mirrors:-none}"
    # The transfer lines, rate and size, from both dnf versions: one per
    # repository's metadata and the packages' total, not one per package.
    while IFS= read -r line; do
        report "dnf-bounded:   $line"
    done < <(grep -E '[0-9.]+ +[kKMG]i?B/s +\|' "$out" \
        | awk '!/^[[:space:]]*[([] *[0-9]+\/[0-9]+[])]/ || / Total /' \
        | sed 's/[[:space:]]\+$//')

    if [ "$rc" -eq 0 ]; then
        exit 0
    fi
    if [ -n "$urls" ]; then
        report "dnf-bounded:   last fetch started: $(tail -n 1 <<<"$urls")"
    fi
    echo "dnf-bounded:   --- last lines of dnf's output ---" >&2
    tail -n 20 "$out" >&2
    if [ "$killed" -eq 1 ] && [ "$clamped" -eq 1 ]; then
        budget_spent "$attempt"
    fi
    if [ "$attempt" -ge "$attempts" ]; then
        exit "$rc"
    fi
    pause=$((attempt * 5))
    if [ -n "$deadline" ] && [ $(($(time_left) - pause)) -lt 30 ]; then
        budget_spent "$attempt"
    fi
    sleep "$pause"
    attempt=$((attempt + 1))
done
