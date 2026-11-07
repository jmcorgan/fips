#!/bin/bash
# Interop harness: the log and capture readers the driver's checks use,
# and the multipath mode's checks with their planted-input controls.
#
# Sourced by interop-test.sh. It can also be run on its own to show the
# multipath checks failing on planted input without bringing up a mesh:
#
#   bash testing/interop/checks.sh --controls <image> <work-dir>
#
# <image> is any interop image (it supplies tcpdump and a shell for the
# planted logs and captures); <work-dir> is a scratch directory. The run
# names its containers <FIPS_INTEROP_NAME>-ctl-<k> and removes them.
#
# The readers keep one rule: a log or capture that could not be read is
# "not established", never a count of 0. count_log_pattern and
# matching_lines print `unreadable:<container>` and return 1 for a node
# whose `docker logs` failed. Every check sets V (PASS, FAIL or NE, for
# not established) and VD (a one-line detail) and records nothing itself,
# so the controls can call the same functions the run does and compare
# the verdict with the one expected.
#
# The patterns stay literal at every call site, as the first argument of
# count_log_pattern, matching_lines or counted_lines, so
# testing/check-log-strings.py checks each against the daemon source.

# ── Log readers ──────────────────────────────────────────────────────

# count_log_pattern <pattern> [node...]: the number of log lines matching
# the extended regex <pattern> across the nodes given (every node in
# NODES when none is). A node whose logs cannot be read makes the whole
# count unusable rather than contributing 0: it prints
# `unreadable:<container>` and returns 1. The previous form ended each
# read `| grep -cE … || true`, so a failed `docker logs` yielded 0 for
# that node and an expect-zero assertion read a clean result from a node
# that was never consulted. Same defect and same fix as rekey-test.sh.
count_log_pattern() {
    local pattern="$1" total=0 n logs count
    shift
    local nodes=("$@")
    [ "${#nodes[@]}" -gt 0 ] || nodes=("${NODES[@]}")
    for n in "${nodes[@]}"; do
        if ! logs=$(docker logs "${CONTAINER[$n]:-}" 2>&1); then
            echo "unreadable:${CONTAINER[$n]:-$n}"
            return 1
        fi
        count=$(grep -cE "$pattern" <<<"$logs" || true)
        total=$((total + count))
    done
    echo "$total"
    return 0
}

# matching_lines <pattern> [node...]: the matching log lines themselves,
# with the same unreadable contract as count_log_pattern.
matching_lines() {
    local pattern="$1" n logs
    shift
    local nodes=("$@")
    [ "${#nodes[@]}" -gt 0 ] || nodes=("${NODES[@]}")
    for n in "${nodes[@]}"; do
        if ! logs=$(docker logs "${CONTAINER[$n]:-}" 2>&1); then
            echo "unreadable:${CONTAINER[$n]:-$n}"
            return 1
        fi
        grep -E "$pattern" <<<"$logs" || true
    done
    return 0
}

# line_count <text>: the number of lines in <text>, 0 for empty text.
line_count() {
    if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l; fi
}

# counted_lines <pattern> [node...]: read the matching lines, then the
# count, then the lines again, and set CL_LINES (the second read) and
# CL_N (its line count). Returns 0 when the count lies between the two
# line reads, the only outcome a log that only grows allows; otherwise
# sets CL_WHY and returns 1, which the caller reports as not established.
# This is what keeps a split by a runtime value (an address, a type) tied
# to a count of the same lines.
counted_lines() {
    local pattern="$1" first count n1
    shift
    CL_LINES=""
    CL_N=0
    CL_WHY=""
    if ! first="$(matching_lines "$pattern" "$@")"; then
        CL_WHY="logs $first"
        return 1
    fi
    if ! count="$(count_log_pattern "$pattern" "$@")"; then
        CL_WHY="logs $count"
        return 1
    fi
    if ! CL_LINES="$(matching_lines "$pattern" "$@")"; then
        CL_WHY="logs $CL_LINES"
        CL_LINES=""
        return 1
    fi
    n1="$(line_count "$first")"
    CL_N="$(line_count "$CL_LINES")"
    if [ "$count" -lt "$n1" ] || [ "$count" -gt "$CL_N" ]; then
        CL_WHY="count $count outside the line reads $n1 and $CL_N"
        return 1
    fi
    return 0
}

# grep_count <fixed-string> <text>: lines of <text> containing the string.
grep_count() {
    if [ -z "$2" ]; then echo 0; return; fi
    grep -cF -- "$1" <<<"$2" || true
}

# ── Verdicts ─────────────────────────────────────────────────────────

V=""
VD=""
verdict() { V="$1"; VD="$2"; }

# is_count <value>: whether <value> is a non-negative integer.
is_count() { [[ "$1" =~ ^[0-9]+$ ]]; }

# chk_range <count-or-unreadable> <lo> <hi>: PASS when the count is in
# [lo, hi]; NE when it is not a number (an unreadable log).
chk_range() {
    local c="$1" lo="$2" hi="$3"
    if ! is_count "$c"; then
        verdict NE "not established: $c"
    elif [ "$c" -ge "$lo" ] && [ "$c" -le "$hi" ]; then
        verdict PASS "$c (bound $lo to $hi)"
    else
        verdict FAIL "$c (bound $lo to $hi)"
    fi
}

# chk_gated <gate> <gate-why> <count> <lo> <hi>: chk_range, but NE unless
# <gate> is 1. A zero read from a log line is evidence only once the line
# has been seen in this run's log at that node.
chk_gated() {
    local gate="$1" why="$2"
    shift 2
    if [ "$gate" != "1" ]; then
        verdict NE "not established: $why"
        return
    fi
    chk_range "$@"
}

# ── The capability-probe bound (draft Section 5.2, Appendix A) ───────

CAPABILITY_PROBE_BUDGET=3
CAPABILITY_PROBE_SPAN=30
CAPABILITY_PROBE_INTERVAL_MAX=600

# capability_bound <elapsed_s>: the most capability probes the draft
# allows in the first <elapsed_s> seconds of a link: a first round of
# CAPABILITY_PROBE_BUDGET at once, then further probes no closer than an
# interval that starts at CAPABILITY_PROBE_SPAN after the first round and
# doubles after each, up to CAPABILITY_PROBE_INTERVAL_MAX. A probe falling
# exactly at <elapsed_s> counts.
capability_bound() {
    local elapsed="$1" t=0 gap="$CAPABILITY_PROBE_SPAN" n="$CAPABILITY_PROBE_BUDGET"
    while [ $((t + gap)) -le "$elapsed" ]; do
        t=$((t + gap))
        n=$((n + 1))
        gap=$((gap * 2))
        [ "$gap" -le "$CAPABILITY_PROBE_INTERVAL_MAX" ] || gap="$CAPABILITY_PROBE_INTERVAL_MAX"
    done
    echo "$n"
}

# ── Line checks ──────────────────────────────────────────────────────

# chk_sends <lines> <addr> <len>: every `Path message sent` line is a
# capability probe (msg_type=82) to <addr> of <len> bytes. Gated by the
# caller on the line being live.
chk_sends() {
    local lines="$1" addr="$2" len="$3" total probes good
    total="$(line_count "$lines")"
    probes="$(grep_count " msg_type=82 " "$lines")"
    good="$(grep -F -- " remote_addr=$addr " <<<"$lines" | grep -F -- " msg_type=82 " \
        | grep -cE -- " len=$len( |$)" || true)"
    if [ "$total" -eq 0 ]; then
        verdict NE "not established: no send line"
    elif [ "$good" -eq "$total" ]; then
        verdict PASS "$total of $total sends are msg_type=82 to $addr with len=$len"
    else
        verdict FAIL "$good of $total sends are msg_type=82 to $addr with len=$len ($probes are msg_type=82)"
    fi
}

# chk_absent <lines> <fixed-string> <what>: no line carries the string.
chk_absent() {
    local lines="$1" s="$2" what="$3" c
    c="$(grep_count "$s" "$lines")"
    if [ "$c" -eq 0 ]; then
        verdict PASS "0 $what"
    else
        verdict FAIL "$c $what"
    fi
}

# ── Python helpers: captures, timestamps, JSON ───────────────────────

# One program, several subcommands; kept here so the checks and their
# controls are one file. Every reader exits 0 and prints `NE <why>` when
# it could not read its input, which the shell side turns into V=NE.
MP_PY="$(cat <<'PYEOF'
import datetime
import json
import re
import subprocess
import sys

CTL_PORT = "40999"


def ts(line):
    """Epoch seconds of a tracing log line's leading RFC 3339 stamp."""
    m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?)Z", line)
    if not m:
        return None
    t = datetime.datetime.fromisoformat(m.group(1)).replace(tzinfo=datetime.timezone.utc)
    return t.timestamp()


def read(path, filt):
    """tcpdump's lines for <path> under filter <filt>, or None and why.

    A read that exits non-zero or reports a truncated file, anywhere, is
    not a count: a record cut short by a kill is the frame nearest it."""
    try:
        size = len(open(path, "rb").read(24))
    except OSError as e:
        return None, f"cannot open {path}: {e}"
    if size < 24:
        return None, f"{path}: shorter than a pcap header ({size} bytes)"
    opts = [x for x in filt if x == "-e"]
    filt = [x for x in filt if x != "-e"]
    for attempt in (1, 2):
        p = subprocess.run(["tcpdump", "-n", "-tt"] + opts + ["-r", path] + filt,
                           capture_output=True, text=True)
        if p.returncode == 0 and "truncated" not in p.stderr:
            return [l for l in p.stdout.splitlines() if l.strip()], None
        if attempt == 1:
            subprocess.run(["sleep", "1"])
    err = " ".join(p.stderr.split())
    return None, f"{path}: tcpdump exit {p.returncode}: {err}"


def endpoint(s):
    """(host, port) of a tcpdump endpoint `a.b.c.d.port` or `v6.port`."""
    s = s.rstrip(":,")
    host, _, port = s.rpartition(".")
    return host, port


def pcap(args):
    """Classify a capture:
    `pcap <file> <from> <to> <arp-from> <arp-for> <ctl-times> [<macs>]`.

    Counts, over packets with from <= t < to (`-` for open), every UDP
    datagram other than a control (source and destination port 40999)
    sent from one of <macs> (comma-separated source MACs; `-` or absent
    for any) as a frame, by port, and one from any other MAC as foreign,
    reported only: the host's own side of a Docker bridge carries what
    the host multicasts, which neither node sent. Also counts the
    controls, and ARP requests `who-has <arp-for> tell <arp-from>` (when
    given) outside [c - 1, c + 5] of a control send time c as frames,
    inside as control ARPs. `arp_before` is the number of such ARP
    requests in the 5 s before the last control datagram seen."""
    path, lo, hi, arp_from, arp_for, ctl = args[:6]
    macs = set(m.lower() for m in (args[6] if len(args) > 6 else "-").split(",") if m and m != "-")
    lo = float(lo) if lo != "-" else float("-inf")
    hi = float(hi) if hi != "-" else float("inf")
    ctl = [float(c) for c in ctl.split(",") if c and c != "-"]
    udp, why = read(path, ["udp"])
    if udp is None:
        print("NE " + why)
        return
    # The same packets again with their link headers, in the same order,
    # for the source MAC of each.
    udp_e, why = read(path, ["-e", "udp"])
    if udp_e is None:
        print("NE " + why)
        return
    src_mac = [l.split()[1].lower() if len(l.split()) > 1 else "?" for l in udp_e]
    arp, why = read(path, ["arp"])
    if arp is None:
        print("NE " + why)
        return
    rest, why = read(path, ["not", "udp", "and", "not", "arp"])
    if rest is None:
        print("NE " + why)
        return
    frames, ports, ctl_seen, foreign, fports = 0, {}, [], 0, {}
    for idx, l in enumerate(udp):
        f = l.split()
        t = float(f[0])
        if not (lo <= t < hi):
            continue
        try:
            i = f.index(">")
            _, sport = endpoint(f[i - 1])
            _, dport = endpoint(f[i + 1])
        except (ValueError, IndexError):
            sport = dport = "?"
        mac = src_mac[idx] if idx < len(src_mac) else "?"
        if sport == CTL_PORT and dport == CTL_PORT:
            ctl_seen.append(t)
        elif macs and mac not in macs:
            foreign += 1
            key = f"{mac}:{sport}>{dport}"
            fports[key] = fports.get(key, 0) + 1
        else:
            frames += 1
            key = f"{sport}>{dport}"
            ports[key] = ports.get(key, 0) + 1
    arp_bad = arp_ctl = 0
    arp_times = []
    for l in arp:
        t = float(l.split()[0])
        if not (lo <= t < hi):
            continue
        if arp_for == "-" or f"Request who-has {arp_for} tell {arp_from}," not in l:
            continue
        arp_times.append(t)
        if any(c - 1 <= t <= c + 5 for c in ctl):
            arp_ctl += 1
        else:
            arp_bad += 1
    arp_before = 0
    if ctl_seen:
        last = max(ctl_seen)
        arp_before = sum(1 for t in arp_times if last - 5 <= t <= last)
    kinds = {}
    for l in rest:
        f = l.split()
        if not (lo <= float(f[0]) < hi):
            continue
        k = f[1] if len(f) > 1 else "?"
        m = re.search(r" > \S+: (\S+)", l)
        if k in ("IP", "IP6") and m:
            k = f"{k}/{m.group(1).rstrip(',')}"
        kinds[k] = kinds.get(k, 0) + 1
    print(f"OK frames={frames} ctl={len(ctl_seen)} arp_bad={arp_bad} "
          f"arp_ctl={arp_ctl} arp_before={arp_before} "
          f"ports={','.join(f'{k}:{v}' for k, v in sorted(ports.items())) or '-'} "
          f"foreign={foreign}{'[' + ','.join(f'{k}:{v}' for k, v in sorted(fports.items())) + ']' if fports else ''} "
          f"other={','.join(f'{k}:{v}' for k, v in sorted(kinds.items())) or '-'}")


def gaps(args):
    """`gaps <tolerance>` with send lines on stdin: check the gap before
    each probe past the first round against its floor (30 s, doubling,
    capped at 600 s). Prints PASS/FAIL, the gaps and the largest."""
    tol = float(args[0])
    span, budget, cap = 30.0, 3, 600.0
    t = [ts(l) for l in sys.stdin.read().splitlines() if l.strip()]
    if any(x is None for x in t):
        print("NE a send line has no timestamp")
        return
    bad, out, floor = [], [], span
    for i in range(1, len(t)):
        g = t[i] - t[i - 1]
        if i >= budget:
            out.append(f"{g:.1f}>={floor:.0f}")
            if g < floor - tol:
                bad.append(f"probe {i + 1}: {g:.1f}s < {floor:.0f}s")
            floor = min(floor * 2, cap)
        else:
            out.append(f"{g:.1f}")
    largest = max((t[i] - t[i - 1] for i in range(1, len(t))), default=0.0)
    verdict = "FAIL" if bad else "PASS"
    print(f"{verdict} {len(t)} sends; gaps {' '.join(out) or '-'}; largest {largest:.1f}s"
          + (f"; below floor: {'; '.join(bad)}" if bad else ""))


def since(args):
    """`since <epoch>` with log lines on stdin: those stamped at or after."""
    lo = float(args[0])
    for l in sys.stdin.read().splitlines():
        x = ts(l)
        if x is not None and x >= lo:
            print(l)


def stamps(args):
    """`stamps` with log lines on stdin: each line's epoch stamp."""
    for l in sys.stdin.read().splitlines():
        x = ts(l)
        if x is not None:
            print(f"{x:.6f}")


def wire(args):
    """`wire <pcap>... -- <src> <dst> <size>` with send lines on stdin:
    each send has its own UDP datagram src:2121 > dst:2121 of <size>
    bytes within 0.5 s."""
    i = args.index("--")
    files, (src, dst, size) = args[:i], args[i + 1:]
    sends = [ts(l) for l in sys.stdin.read().splitlines() if l.strip()]
    if not sends or any(x is None for x in sends):
        print("NE no send line, or one without a timestamp")
        return
    seen, sizes = [], {}
    for f in files:
        lines, why = read(f, ["udp", "and", "src", "host", src, "and", "dst", "host", dst,
                              "and", "src", "port", "2121", "and", "dst", "port", "2121"])
        if lines is None:
            print("NE " + why)
            return
        for l in lines:
            m = re.search(r"UDP, length (\d+)", l)
            if not m:
                continue
            sizes[m.group(1)] = sizes.get(m.group(1), 0) + 1
            if m.group(1) == size:
                seen.append(float(l.split()[0]))
    seen.sort()
    used, missing = set(), 0
    for s in sends:
        hit = next((j for j, x in enumerate(seen) if j not in used and abs(x - s) <= 0.5), None)
        if hit is None:
            missing += 1
        else:
            used.add(hit)
    tally = ",".join(f"{k}:{v}" for k, v in sorted(sizes.items(), key=lambda kv: int(kv[0])))
    verdict = "PASS" if missing == 0 else "FAIL"
    print(f"{verdict} {len(sends) - missing} of {len(sends)} sends matched a {size}-byte datagram; "
          f"{len(seen)} datagrams of that size in all; sizes src>dst {tally or '-'}")


def paths(args):
    """`paths <addr>` with `path show` JSON on stdin."""
    addr = args[0]
    try:
        j = json.load(sys.stdin)
    except ValueError as e:
        print(f"NE path show is not JSON: {e}")
        return
    p = j.get("paths")
    if not isinstance(p, list):
        print("NE path show has no paths list")
        return
    desc = ";".join(f"{x.get('transport')}/{x.get('addr')}" for x in p)
    ok = (len(p) == 1 and p[0].get("addr") == addr and j.get("capable") is False
          and j.get("enabled") is True)
    print(f"{'PASS' if ok else 'FAIL'} {len(p)} path(s) [{desc}] capable={j.get('capable')} "
          f"enabled={j.get('enabled')}")


def mmp(args):
    """`mmp <display-name>` with `show mmp` JSON on stdin: the peer's
    link_layer.smoothed_loss, present and 0."""
    name = args[0]
    try:
        j = json.load(sys.stdin)
    except ValueError as e:
        print(f"NE show mmp is not JSON: {e}")
        return
    peers = [p for p in j.get("peers", []) if p.get("display_name") == name]
    if len(peers) != 1:
        print(f"NE {len(peers)} show mmp entries for {name}")
        return
    ll = peers[0].get("link_layer", {})
    lr = ll.get("loss_rate")
    if "smoothed_loss" not in ll:
        print(f"NE smoothed_loss absent (no ReceiverReport interval yet); loss_rate={lr}")
        return
    sl = ll["smoothed_loss"]
    print(f"{'PASS' if sl == 0 else 'FAIL'} smoothed_loss={sl} loss_rate={lr}")


def connect(args):
    """`connect` with the connect reply on stdin: refreshed false and the
    detail of a live peer not dialled."""
    try:
        j = json.load(sys.stdin)
    except ValueError as e:
        print(f"FAIL reply is not JSON: {e}")
        return
    d = j.get("data", j) if isinstance(j, dict) else {}
    ok = d.get("refreshed") is False and d.get("detail") == "peer live, not dialled"
    print(f"{'PASS' if ok else 'FAIL'} refreshed={d.get('refreshed')} detail={d.get('detail')!r}")


def transports(args):
    """`transports <name> <port>` with `show transports` JSON on stdin:
    the transport is up on that port. (A UDP transport reports no
    interface here; the driver reads the socket's device with `ss`.)"""
    name, port = args
    try:
        j = json.load(sys.stdin)
    except ValueError as e:
        print(f"NE show transports is not JSON: {e}")
        return
    t = [x for x in j.get("transports", []) if x.get("name") == name]
    if len(t) != 1:
        print(f"FAIL {len(t)} transports named {name}")
        return
    t = t[0]
    addr = str(t.get("local_addr"))
    ok = t.get("state") == "up" and addr.endswith(f":{port}")
    print(f"{'PASS' if ok else 'FAIL'} {name} state={t.get('state')} local_addr={addr}")


{"pcap": pcap, "gaps": gaps, "since": since, "stamps": stamps, "wire": wire,
 "paths": paths, "mmp": mmp, "connect": connect,
 "transports": transports}[sys.argv[1]](sys.argv[2:])
PYEOF
)"

# mp_py <subcommand> <args...>: run one helper, stdin passed through.
mp_py() { python3 -c "$MP_PY" "$@"; }

# py_verdict <helper output>: V and VD from a helper's first word.
py_verdict() {
    local out="$1"
    case "$out" in
        PASS*) verdict PASS "${out#PASS }" ;;
        FAIL*) verdict FAIL "${out#FAIL }" ;;
        NE*)   verdict NE "not established: ${out#NE }" ;;
        *)     verdict NE "not established: helper said '${out:-nothing}'" ;;
    esac
}

# chk_gaps <lines>: the floors between capability probes, from the send
# lines' timestamps (0.5 s tolerance).
chk_gaps() {
    if [ -z "$1" ]; then
        verdict NE "not established: no send line"
        return
    fi
    py_verdict "$(mp_py gaps 0.5 <<<"$1")"
}

# chk_paths <json> <addr>: `path show` lists one path, at <addr>, with
# the peer not capable and multipath enabled.
chk_paths() { py_verdict "$(mp_py paths "$2" <<<"$1")"; }

# chk_loss <json> <name>: smoothed_loss present and 0 for peer <name>.
chk_loss() { py_verdict "$(mp_py mmp "$2" <<<"$1")"; }

# ── Capture checks ───────────────────────────────────────────────────

# pcap_read <file> <from> <to> <arp-from> <arp-for> <ctl-times> [<macs>]: return
# 0 when the capture was read, and set PC_FRAMES, PC_CTL, PC_ARPBAD, PC_ARPBEFORE and
# PC_DESC from the classifier above. `-` leaves a bound or the ARP rule
# off.
pcap_read() {
    local out
    out="$(mp_py pcap "$@" 2>&1)"
    PC_DESC="$out"
    PC_FRAMES=""
    PC_CTL=""
    PC_ARPBAD=""
    PC_ARPBEFORE=""
    case "$out" in
        OK*) ;;
        *) return 1 ;;
    esac
    PC_FRAMES="$(sed -n 's/.* frames=\([0-9]*\) .*/\1/p' <<<"$out")"
    PC_CTL="$(sed -n 's/.* ctl=\([0-9]*\) .*/\1/p' <<<"$out")"
    PC_ARPBAD="$(sed -n 's/.* arp_bad=\([0-9]*\) .*/\1/p' <<<"$out")"
    PC_ARPBEFORE="$(sed -n 's/.* arp_before=\([0-9]*\) .*/\1/p' <<<"$out")"
    return 0
}

# chk_quiet <file> <from> <to> <arp-from> <arp-for> <ctl-times> [<macs>]:
# no FIPS frame (any UDP datagram but a control sent from one of <macs>,
# and an ARP request from <arp-from> for <arp-for> outside a control
# window) in the capture.
chk_quiet() {
    if ! pcap_read "$@"; then
        verdict NE "not established: $PC_DESC"
        return
    fi
    if [ "$PC_FRAMES" -eq 0 ] && [ "$PC_ARPBAD" -eq 0 ]; then
        verdict PASS "${PC_DESC#OK }"
    else
        verdict FAIL "${PC_DESC#OK }"
    fi
}

# chk_control <before-ctl> <file> <ctl-times> [need-arp <arp-from> <arp-for>]:
# the capture holds exactly one more control datagram than <before-ctl>,
# and with need-arp an ARP request for <arp-for> in the 5 s before it.
chk_control() {
    local before="$1" file="$2" ctl="$3" need="${4:-}" from="${5:--}" for="${6:--}"
    if ! pcap_read "$file" - - "$from" "$for" "$ctl"; then
        verdict NE "not established: $PC_DESC"
        return
    fi
    if ! is_count "$before"; then
        verdict NE "not established: no count before the control ($before)"
    elif [ "$PC_CTL" -ne $((before + 1)) ]; then
        verdict FAIL "controls $before -> $PC_CTL (expected +1)"
    elif [ "$need" = "need-arp" ] && [ "$PC_ARPBEFORE" -lt 1 ]; then
        verdict FAIL "control seen but no ARP request for $for before it"
    else
        verdict PASS "controls $before -> $PC_CTL${need:+, ARP requests before it: $PC_ARPBEFORE}"
    fi
}

# ── Controls (planted input) ─────────────────────────────────────────

CTL_RESULTS=()
CTL_BAD=0

# expect <name> <expected verdict>: compare the last check's verdict with
# the one a correct check gives on this planted input.
expect() {
    local name="$1" want="$2" mark="ok"
    if [ "$V" != "$want" ]; then
        mark="WRONG"
        CTL_BAD=$((CTL_BAD + 1))
    fi
    CTL_RESULTS+=("$mark")
    printf '    %-5s %-62s expected %-4s got %-4s %s\n' "$mark" "$name" "$want" "${V:-none}" "$VD"
    # A check that did not run must not leave the next control a verdict.
    V=""
    VD=""
}

# plant_log <key> <lines...>: a container whose log is exactly <lines>,
# registered as node <key> in CONTAINER.
plant_log() {
    local key="$1" ctr
    shift
    ctr="$CTL_PREFIX-$key"
    printf '%s\n' "$@" > "$CTL_DIR/$key.log"
    docker rm -f "$ctr" >/dev/null 2>&1 || true
    if ! docker run "${CI_LABELS[@]}" --name "$ctr" -v "$CTL_DIR:/planted:ro" --entrypoint cat \
        "$CTL_IMAGE" "/planted/$key.log" >/dev/null 2>&1; then
        echo "    could not start the control container $ctr" >&2
        return 1
    fi
    CONTAINER[$key]="$ctr"
    CTL_CONTAINERS+=("$ctr")
}

# Planted lines in the formats the two daemons write: v0.5.3's discard
# line (message, then the field; no peer), and the new node's send and
# dial lines in the field order of their debug! calls, "Path message
# sent" in Node::run_outputs (src/node/handlers/path.rs) and "Connection
# initiated" in Node::prepare_outbound_msg1 (src/node/lifecycle/mod.rs).
planted_discard() {
    printf '2026-11-05T14:00:%02d.000000Z DEBUG fips::node::dataplane::dispatch: Unknown link message type msg_type=%s' "$1" "$2"
}
planted_send() {
    # planted_send <second> <addr> <type> <len>
    printf '2026-11-05T14:%s DEBUG fips::node::handlers::path: Path message sent peer=c1 transport_id=1 remote_addr=%s msg_type=%s len=%s' "$1" "$2" "$3" "$4"
}
planted_dial() {
    printf '2026-11-05T14:00:%02d.000000Z DEBUG fips::node::lifecycle: Connection initiated peer=c1 transport_id=1 remote_addr=%s link_id=1 our_index=1' "$1" "$2"
}

# plant_pcap <name> <script>: run <script> in a container from the
# control image with the work directory at /w, for planted captures.
plant_pcap() {
    docker run --rm "${CI_LABELS[@]}" -v "$CTL_DIR:/w" --entrypoint sh "$CTL_IMAGE" -c "$2" >/dev/null 2>&1
}

# mp_controls <image> <dir>: run every multipath check on planted input
# and compare each verdict with the one expected. Returns 0 when every
# control gave its expected verdict.
mp_controls() {
    CTL_IMAGE="$1"
    CTL_DIR="$2"
    CTL_PREFIX="${INTEROP_NAME:-${FIPS_INTEROP_NAME:-fips-interop}}-ctl"
    CTL_CONTAINERS=()
    CTL_RESULTS=()
    CTL_BAD=0
    mkdir -p "$CTL_DIR"
    local n1="172.30.0.11:2121" n2="172.30.1.11:2121" k lines c b i
    local -a six seven twelve thirteen four five
    for ((i = 0; i < 13; i++)); do
        thirteen+=("$(planted_discard "$i" 82)")
    done
    six=("${thirteen[@]:0:6}")
    seven=("${thirteen[@]:0:7}")
    twelve=("${thirteen[@]:0:12}")
    four=("${thirteen[@]:0:4}")
    five=("${thirteen[@]:0:5}")

    plant_log c0 "2026-11-05T14:00:00.000000Z  INFO fips: FIPS 0.5.3 starting" || return 1
    plant_log c6 "${six[@]}" || return 1
    plant_log c7 "${seven[@]}" || return 1
    plant_log c12 "${twelve[@]}" || return 1
    plant_log c13 "${thirteen[@]}" || return 1
    plant_log c4 "${four[@]}" || return 1
    plant_log c5 "${five[@]}" || return 1
    plant_log c83 "${six[@]}" "$(planted_discard 30 83)" || return 1
    plant_log c99 "${six[@]}" "$(planted_discard 30 99)" || return 1
    plant_log c1z "$(planted_discard 1 82)" || return 1
    plant_log aempty "2026-11-05T14:00:00.000000Z  INFO fips: FIPS 0.6.0-dev starting" || return 1
    plant_log agood "$(planted_send 00:00.000000Z "$n1" 82 27)" \
        "$(planted_send 00:10.000000Z "$n1" 82 27)" "$(planted_send 00:20.000000Z "$n1" 82 27)" \
        "$(planted_send 00:50.000000Z "$n1" 82 27)" "$(planted_send 01:50.000000Z "$n1" 82 27)" \
        "$(planted_send 03:50.000000Z "$n1" 82 27)" || return 1
    plant_log alen "$(planted_send 00:00.000000Z "$n1" 82 28)" || return 1
    plant_log anet2 "$(planted_send 00:00.000000Z "$n1" 82 27)" \
        "$(planted_send 00:01.000000Z "$n2" 82 27)" || return 1
    plant_log agap "$(planted_send 00:00.000000Z "$n1" 82 27)" \
        "$(planted_send 00:10.000000Z "$n1" 82 27)" "$(planted_send 00:20.000000Z "$n1" 82 27)" \
        "$(planted_send 00:49.000000Z "$n1" 82 27)" || return 1
    plant_log dial1 "$(planted_dial 1 "$n1")" || return 1
    plant_log dial2 "$(planted_dial 1 "$n1")" "$(planted_dial 2 "$n2")" || return 1
    plant_log rmonly "2026-11-05T14:00:01.000000Z DEBUG fips::node::handlers::mmp: Removing peer: link dead timeout peer=c1 timeout_secs=30" || return 1
    plant_log err1 "2026-11-05T14:00:01.000000Z ERROR fips::node: something failed" || return 1
    plant_log move1 "2026-11-05T14:00:40.000000Z DEBUG fips::node::handlers::handshake: Cross-connection: swapped to outbound session (our outbound wins) peer=c1" || return 1
    plant_log move2 "2026-11-05T14:00:40.000000Z DEBUG fips::node::handlers::handshake: Second dial answered: swapped to its session (the answer supersedes our earlier dial's) peer=c1" || return 1

    echo "  -- discard count (c1) --"
    b="$(capability_bound 310)"
    chk_range "$(count_log_pattern 'Unknown link message type.*msg_type=82' c0)" 1 "$b"; expect "0 discard lines, at least one" FAIL
    chk_range "$(count_log_pattern 'Unknown link message type.*msg_type=82' c7)" 1 "$b"; expect "7 discard lines against capability_bound 310 = $b" FAIL
    chk_range "$(count_log_pattern 'Unknown link message type.*msg_type=82' c6)" 1 "$b"; expect "6 discard lines against capability_bound 310 = $b" PASS
    b="$(capability_bound 3610)"
    chk_range "$(count_log_pattern 'Unknown link message type.*msg_type=82' c13)" 1 "$b"; expect "13 discard lines against capability_bound 3610 = $b" FAIL
    chk_range "$(count_log_pattern 'Unknown link message type.*msg_type=82' c12)" 1 "$b"; expect "12 discard lines against capability_bound 3610 = $b" PASS
    b="$(capability_bound 60)"
    chk_range "$(count_log_pattern 'Unknown link message type.*msg_type=82' c5)" 0 "$b"; expect "5 discard lines against capability_bound 60 = $b" FAIL
    chk_range "$(count_log_pattern 'Unknown link message type.*msg_type=82' c4)" 0 "$b"; expect "4 discard lines against capability_bound 60 = $b" PASS
    chk_gated 1 - "$(count_log_pattern 'Unknown link message type.*msg_type=8[34]' c83)" 0 0; expect "one msg_type=83 line, PathAck/PathClose zero" FAIL
    chk_gated 1 - "$(count_log_pattern 'Unknown link message type.*msg_type=8[34]' c6)" 0 0; expect "probes only, PathAck/PathClose zero" PASS
    c="$(count_log_pattern 'Unknown link message type' c99)"
    k="$(count_log_pattern 'Unknown link message type.*msg_type=82' c99)"
    if is_count "$c" && is_count "$k"; then chk_range "$((c - k))" 0 0; else verdict NE "$c $k"; fi
    expect "a msg_type=99 discard beside 6 probes, only probes" FAIL
    CONTAINER[gone]="$CTL_PREFIX-no-such-container"
    chk_range "$(count_log_pattern 'Unknown link message type.*msg_type=82' gone)" 1 6; expect "container that does not exist" NE

    echo "  -- zeros and the verdict order --"
    chk_gated 1 - "$(count_log_pattern 'Unknown link message type.*msg_type=82' c1z)" 0 0; expect "M1 zero, one planted msg_type=82 line" FAIL
    chk_gated 1 - "$(count_log_pattern 'Unknown link message type.*msg_type=82' c1z)" 0 0; expect "request relink zero, one planted msg_type=82 line" FAIL
    mp_gates c0 aempty "$n1"
    chk_gated "$C1_LIVE" "$C1_WHY" "$(count_log_pattern 'Unknown link message type.*msg_type=82' c0)" 0 0; expect "M1 zero with 0 discard lines in the run" NE
    mp_gates c6 aempty "$n1"
    chk_gated "$A1_LIVE" "$A1_WHY" 0 0 0; expect "send-side zero, c1=6 and a1=0" NE
    if counted_lines 'Path message sent' aempty; then
        if [ "$A1_LIVE" = 1 ]; then chk_sends "$CL_LINES" "$n1" 27; else verdict NE "$A1_WHY"; fi
    else verdict NE "$CL_WHY"; fi
    expect "send-line check, empty a1 log" NE
    if [ "$A1_LIVE" = 1 ]; then chk_gaps ""; else verdict NE "$A1_WHY"; fi
    expect "floor check, empty a1 log" NE
    mp_gates c0 aempty "$n1"
    chk_gated "$A1_LIVE" "$A1_WHY" 0 0 0; expect "send-side zero, c1=0 and a1=0" NE
    mp_gates c6 agood "$n1"
    chk_gated "$A1_LIVE" "$A1_WHY" 0 0 0; expect "send-side zero, c1=6 and a1=6" PASS
    mp_gates c7 agood "$n1"
    chk_gated "$A1_LIVE" "$A1_WHY" 0 0 0; expect "send-side zero, c1=7 and a1=6" NE

    echo "  -- send lines, gaps and the log witness --"
    counted_lines 'Path message sent' agood && chk_sends "$CL_LINES" "$n1" 27; expect "six good send lines" PASS
    counted_lines 'Path message sent' alen && chk_sends "$CL_LINES" "$n1" 27; expect "a send line with len=28" FAIL
    counted_lines 'Path message sent' anet2 && chk_sends "$CL_LINES" "$n1" 27; expect "a send line to the second network" FAIL
    counted_lines 'Path message sent' anet2 && chk_absent "$CL_LINES" " remote_addr=${n2%:*}:" "sends on the second network"; expect "W: Path message sent on the second network" FAIL
    counted_lines 'Path message sent' agood && chk_absent "$CL_LINES" " remote_addr=${n2%:*}:" "sends on the second network"; expect "W: Path message sent, first network only" PASS
    counted_lines 'Connection initiated' dial2 && chk_absent "$CL_LINES" " remote_addr=${n2%:*}:" "dials on the second network"; expect "W: Connection initiated on the second network" FAIL
    counted_lines 'Connection initiated' dial1 && chk_absent "$CL_LINES" " remote_addr=${n2%:*}:" "dials on the second network"; expect "W: Connection initiated, first network only" PASS
    dial_gate aempty "${n1%:*}"
    chk_gated "$DIAL_LIVE" "$DIAL_WHY" 0 0 0; expect "W: dial zero with no first-network dial line" NE
    if counted_lines 'Path message sent' gone; then verdict PASS "read"; else verdict NE "$CL_WHY"; fi
    expect "lines from a container that does not exist" NE
    counted_lines 'Path message sent' agap && chk_gaps "$CL_LINES"; expect "a 29 s gap after the third probe" FAIL
    counted_lines 'Path message sent' agood && chk_gaps "$CL_LINES"; expect "the earliest schedule (0, 10, 20, 50, 110, 230 s)" PASS

    echo "  -- re-dial, removal, window deltas, session moves --"
    c="$(count_log_pattern 'Removing peer: link dead timeout' rmonly)"; chk_range "$c" 1 1; expect "removal line present" PASS
    c="$(count_log_pattern 'Removing peer: link dead timeout' aempty)"; chk_range "$c" 1 1; expect "no removal line" FAIL
    c="$(count_log_pattern 'Connection initiated' rmonly)"; chk_range "$c" 1 9999; expect "removal and no Connection initiated (re-dial)" FAIL
    c="$(count_log_pattern 'Connection initiated' c0)"; chk_range "$c" 1 9999; expect "config relink, no Connection initiated at c1" FAIL
    c="$(count_log_pattern 'ERROR' err1)"; chk_range "$c" 0 0; expect "Phase 8 pattern delta, one ERROR line" FAIL
    mp_moves move1 "$(mp_py stamps <<<"2026-11-05T14:00:30.000000Z x")"
    chk_gated "$MOVE_OK" "$MOVE_WHY" 0 0 0; expect "a session move after link-up (configured run)" NE
    mp_moves move2 "$(mp_py stamps <<<"2026-11-05T14:00:30.000000Z x")"
    chk_gated "$MOVE_OK" "$MOVE_WHY" 0 0 0; expect "a swap to a second dial's session after link-up" NE
    mp_moves aempty "$(mp_py stamps <<<"2026-11-05T14:00:30.000000Z x")"
    chk_gated "$MOVE_OK" "$MOVE_WHY" 0 0 0; expect "no session move" PASS
    sampler_read "$CTL_DIR/no-such-sample"; chk_range "$SAMPLE_C1" 1 6; expect "the 310 s sampler wrote nothing" NE
    printf 'c1=garbled\n' > "$CTL_DIR/bad-sample"
    sampler_read "$CTL_DIR/bad-sample"; chk_range "$SAMPLE_C1" 1 6; expect "the 310 s sampler wrote garbage" NE

    echo "  -- path show and the loss check --"
    chk_paths '{"enabled":true,"capable":false,"paths":[{"transport":"main","addr":"'"$n1"'"},{"transport":"mp2","addr":"'"$n2"'"}]}' "$n1"; expect "path show, two paths" FAIL
    chk_paths '{"enabled":true,"capable":true,"paths":[{"transport":"main","addr":"'"$n1"'"}]}' "$n1"; expect "path show, capable: true" FAIL
    chk_paths '{"enabled":true,"capable":false,"paths":[{"transport":"main","addr":"'"$n1"'"}]}' "$n1"; expect "path show, one path, not capable" PASS
    chk_loss '{"peers":[{"display_name":"c1","link_layer":{"loss_rate":0.0,"smoothed_loss":0.01}}]}' c1; expect "smoothed_loss 0.01" FAIL
    chk_loss '{"peers":[{"display_name":"c1","link_layer":{"loss_rate":0.0}}]}' c1; expect "smoothed_loss absent, loss_rate 0" NE
    chk_loss '{"peers":[{"display_name":"c1","link_layer":{"loss_rate":0.0,"smoothed_loss":0.0}}]}' c1; expect "smoothed_loss 0" PASS

    echo "  -- capture reader --"
    # Captures on the control container's loopback: a datagram to a FIPS
    # port, one to another port, and a marked control. The script runs in
    # the container, so nothing in it expands here.
    # shellcheck disable=SC2016
    plant_pcap caps '
        cap() { tcpdump -U --immediate-mode -n -Z root -i lo -w /w/$1.pcap 2>/w/$1.err & P=$!
                i=0; until grep -q "listening on" /w/$1.err; do i=$((i+1)); [ $i -lt 50 ] || exit 1; sleep 0.1; done
                sleep 0.3
                python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"127.0.0.1\", $2)); s.sendto(b\"fips-multipath-control\", (\"127.0.0.1\", $3))"
                sleep 0.3; kill $P; wait $P; }
        cap fips 2121 2121; cap other 5353 5353; cap ctl 40999 40999
        : > /w/empty.pcap
        head -c 12 /w/fips.pcap > /w/cuthdr.pcap
        s=$(stat -c %s /w/fips.pcap); head -c $((s - 5)) /w/fips.pcap > /w/cutrec.pcap
        chmod a+r /w/*.pcap'
    chk_quiet "$CTL_DIR/fips.pcap" - - - - -; expect "one datagram to port 2121" FAIL
    chk_quiet "$CTL_DIR/other.pcap" - - - - -; expect "one datagram to port 5353 (any UDP counts)" FAIL
    chk_quiet "$CTL_DIR/ctl.pcap" - - - - -; expect "a control datagram only: 0 frames" PASS
    chk_quiet "$CTL_DIR/other.pcap" - - - - - 00:00:00:00:00:00; expect "port 5353 from a node's MAC" FAIL
    chk_quiet "$CTL_DIR/other.pcap" - - - - - 02:00:00:00:00:01; expect "port 5353 from another MAC (the host's bridge)" PASS
    chk_control 0 "$CTL_DIR/ctl.pcap" -; expect "a control datagram only: control +1" PASS
    chk_control 1 "$CTL_DIR/ctl.pcap" -; expect "control count not advanced" FAIL
    chk_control 0 "$CTL_DIR/ctl.pcap" - need-arp 127.0.0.1 127.0.0.2; expect "control with no ARP before it (C1's ARP rule)" FAIL
    chk_quiet "$CTL_DIR/empty.pcap" - - - - -; expect "a 0-byte capture" NE
    chk_quiet "$CTL_DIR/cuthdr.pcap" - - - - -; expect "a capture cut inside its header" NE
    chk_quiet "$CTL_DIR/cutrec.pcap" - - - - -; expect "a capture cut inside its last record" NE
    chk_quiet "$CTL_DIR/no-such.pcap" - - - - -; expect "a capture that does not exist" NE

    for k in "${CTL_CONTAINERS[@]}"; do
        docker rm -f "$k" >/dev/null 2>&1 || true
    done
    # The planted captures were written as root; hand them back.
    docker run --rm "${CI_LABELS[@]}" -v "$CTL_DIR:/w" --entrypoint chown "$CTL_IMAGE" \
        -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 \
        || echo "    WARN could not hand $CTL_DIR back to $(id -u):$(id -g)"
    local left
    left="$(docker ps -a --filter "name=^$CTL_PREFIX-" --format '{{.Names}}')"
    [ -z "$left" ] || echo "    WARN control containers left: $left"
    echo "  controls: $(( ${#CTL_RESULTS[@]} - CTL_BAD )) of ${#CTL_RESULTS[@]} gave the expected verdict"
    [ "$CTL_BAD" -eq 0 ]
}

# ── Gates ────────────────────────────────────────────────────────────

# mp_gates <c1-node> <a1-node> <addr>: C1_LIVE when the old node's
# discard line is seen at least once (so a zero of it means something),
# A1_LIVE when the new node's msg_type=82 send lines to <addr> number at
# least one and at least the old node's discards: every discard at the
# old node was sent by the new node, so fewer sends than discards means
# the send line is not being logged in full. Counts are read old node
# first, so a probe sent between the reads can only raise the new node's.
mp_gates() {
    local cn="$1" an="$2" addr="$3" c sends
    C1_LIVE=0
    A1_LIVE=0
    C1_WHY=""
    A1_WHY=""
    c="$(count_log_pattern 'Unknown link message type.*msg_type=82' "$cn")"
    if ! is_count "$c"; then
        C1_WHY="old node's log $c"
    elif [ "$c" -lt 1 ]; then
        C1_WHY="no discard line at the old node in this run"
    else
        C1_LIVE=1
    fi
    if ! counted_lines 'Path message sent' "$an"; then
        A1_WHY="new node's send lines: $CL_WHY"
        return
    fi
    sends="$(probe_sends "$CL_LINES" "$addr")"
    send_gate "$c" "$sends" "$addr"
}

# probe_sends <lines> <addr>: how many of the send lines are capability
# probes (msg_type=82) to <addr>.
probe_sends() {
    grep -F -- " remote_addr=$2 " <<<"$1" | grep -cF -- " msg_type=82 " || true
}

# send_gate <discards> <sends> <addr>: A1_LIVE from two counts taken
# old node first (see mp_gates).
send_gate() {
    local c="$1" sends="$2" addr="$3"
    A1_LIVE=0
    A1_WHY=""
    if ! is_count "$c"; then
        A1_WHY="old node's log $c"
    elif ! is_count "$sends"; then
        A1_WHY="new node's log $sends"
    elif [ "$sends" -lt 1 ] || [ "$sends" -lt "$c" ]; then
        A1_WHY="new node logged $sends probe sends to $addr against $c discards at the old node"
    else
        A1_LIVE=1
    fi
}

# dial_gate <node> <first-network-host>: DIAL_LIVE when the node logged
# at least one `Connection initiated` to the first network, so its zero
# on the second network is of a live line.
dial_gate() {
    local n="$1" host="$2" c
    DIAL_LIVE=0
    DIAL_WHY=""
    if ! counted_lines 'Connection initiated' "$n"; then
        DIAL_WHY="dial lines: $CL_WHY"
        return
    fi
    c="$(grep_count " remote_addr=$host:" "$CL_LINES")"
    if [ "$c" -lt 1 ]; then
        DIAL_WHY="no first-network Connection initiated line at $n"
    else
        DIAL_LIVE=1
    fi
}

# mp_moves <node> <link-up-epoch>: MOVE_OK unless the node logged a
# cross-connection resolution, a swap to the session its own second dial
# was answered on, or a promotion more than 2 s after the link came up.
# Each renews the path machine (draft 5.2 counts the bound from the last
# move onto another session), so a bound counted from the first link-up
# no longer applies.
mp_moves() {
    local n="$1" up="$2" late
    MOVE_OK=0
    MOVE_WHY=""
    if ! counted_lines 'Cross-connection|Second dial answered|Peer promoted to active' "$n"; then
        MOVE_WHY="move lines: $CL_WHY"
        return
    fi
    late="$(mp_py since "$(awk -v u="$up" 'BEGIN{printf "%.6f", u + 2}')" <<<"$CL_LINES")"
    if [ -n "$late" ]; then
        MOVE_WHY="session move or promotion after link-up: $(head -1 <<<"$late" | cut -c1-120)"
    else
        MOVE_OK=1
    fi
}

# sampler_read <file>: SAMPLE_C1 and SAMPLE_A1 from the background
# sampler's file (`c1=<n>` and `a1=<n>` lines), or `missing`/`garbled`
# when it died or wrote nothing usable.
sampler_read() {
    local f="$1"
    SAMPLE_C1="missing"
    SAMPLE_A1="missing"
    [ -s "$f" ] || return 1
    SAMPLE_C1="$(sed -n 's/^c1=//p' "$f")"
    SAMPLE_A1="$(sed -n 's/^a1=//p' "$f")"
    is_count "$SAMPLE_C1" || SAMPLE_C1="garbled:${SAMPLE_C1:-none}"
    is_count "$SAMPLE_A1" || SAMPLE_A1="garbled:${SAMPLE_A1:-none}"
    return 0
}

# ── Stand-alone controls ─────────────────────────────────────────────

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    if [ "${1:-}" != "--controls" ] || [ "$#" -ne 3 ]; then
        echo "Usage: $0 --controls <image> <work-dir>" >&2
        exit 2
    fi
    # The driver sources this for a run. Unset, CI_LABELS expands to
    # nothing rather than failing, and the containers go unlabelled.
    # shellcheck source=../lib/image-build.sh
    source "$(dirname "$0")/../lib/image-build.sh"
    declare -A CONTAINER=()
    NODES=()
    echo "Multipath checks on planted input (image $2)"
    if mp_controls "$2" "$3"; then
        echo "PASS: every control gave its expected verdict"
        exit 0
    fi
    echo "FAIL: $CTL_BAD control(s) gave the wrong verdict"
    exit 1
fi
