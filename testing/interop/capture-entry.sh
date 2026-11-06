#!/bin/sh
# Interop harness, multipath mode: start this container's packet captures,
# then the image's own entrypoint.
#
# The compose file the generator writes for the multipath mode
# (generate-configs.sh, FIPS_INTEROP_MULTIPATH) makes this the entrypoint
# of every slot `a` and slot `c` container, mounted read-only. It changes
# neither the daemon's binary nor its configuration. It exists so that a
# capture covers the daemon's whole life, startup dials included: the
# image's entrypoint starts `fips` as soon as the container starts, so a
# capture the driver started afterwards would miss them.
#
# For each interface in FIPS_CAPTURE_IFACES it waits for the interface to
# be up, then starts one tcpdump writing to
# /captures/<node>-<iface>-<start>.pcap, where <start> is this start's
# epoch second (with a .N suffix if that name is taken), so each start of
# the container opens new files and a killed start's files are kept. Each
# tcpdump runs with -U and --immediate-mode, so every packet is on disk as
# it is taken and a SIGKILL loses none: with -U alone, libpcap's
# TPACKET_V3 ring hands packets over in blocks, and a kill 50 ms after a
# datagram lost it in 10 of 10 trials. -Z root keeps tcpdump from dropping
# to its own user before it opens the file on the bind mount.
#
# It prints `capture-entry: captures running <ifaces> <start>` once every
# tcpdump has printed `listening on`, and only then execs the entrypoint,
# so the line precedes every daemon line in `docker logs`. An interface
# not up within 30 s, or a tcpdump not listening within 10 s, fails the
# container with a `capture-entry: FATAL` line: a missing capture is a
# failed start, not a silent gap.
#
# Environment:
#   FIPS_CAPTURE_NODE           node id, the file-name prefix (required)
#   FIPS_CAPTURE_IFACES         space-separated interfaces (required)
#   FIPS_CAPTURE_SNAPLEN_<if>   optional snap length for interface <if>

set -eu

DIR=/captures
ENTRYPOINT=/usr/local/bin/entrypoint.sh

fatal() {
    echo "capture-entry: FATAL $*"
    exit 1
}

NODE="${FIPS_CAPTURE_NODE:-}"
IFACES="${FIPS_CAPTURE_IFACES:-}"
[ -n "$NODE" ] || fatal "FIPS_CAPTURE_NODE is not set"
[ -n "$IFACES" ] || fatal "FIPS_CAPTURE_IFACES is not set"
[ -d "$DIR" ] || fatal "$DIR is not mounted"

for ifc in $IFACES; do
    case "$ifc" in
        *[!a-z0-9]*) fatal "interface name '$ifc' is not [a-z0-9]+" ;;
    esac
    i=0
    # Up means `ip link show dev <if> up` lists it, as the image's own
    # entrypoint waits for interfaces.
    until [ -n "$(ip link show dev "$ifc" up 2>/dev/null)" ]; do
        i=$((i + 1))
        [ "$i" -le 300 ] || fatal "interface $ifc not up within 30 s"
        sleep 0.1
    done
    echo "capture-entry: interface $ifc up"
done

start="$(date +%s)"
tag="$start"
n=0
while ls "$DIR/$NODE-"*"-$tag.pcap" >/dev/null 2>&1; do
    n=$((n + 1))
    tag="$start.$n"
done

for ifc in $IFACES; do
    file="$DIR/$NODE-$ifc-$tag.pcap"
    err="$DIR/$NODE-$ifc-$tag.err"
    snap="$(eval "printf '%s' \"\${FIPS_CAPTURE_SNAPLEN_$ifc:-}\"")"
    if [ -n "$snap" ]; then
        tcpdump -U --immediate-mode -n -Z root -s "$snap" -i "$ifc" -w "$file" 2>"$err" &
    else
        tcpdump -U --immediate-mode -n -Z root -i "$ifc" -w "$file" 2>"$err" &
    fi
    pid=$!
    i=0
    until grep -q "listening on" "$err" 2>/dev/null; do
        kill -0 "$pid" 2>/dev/null || fatal "tcpdump on $ifc exited: $(cat "$err" 2>/dev/null)"
        i=$((i + 1))
        [ "$i" -le 100 ] || fatal "tcpdump on $ifc not listening within 10 s"
        sleep 0.1
    done
    echo "capture-entry: capture $ifc file $(basename "$file") pid $pid"
done

echo "capture-entry: captures running $IFACES $tag"
exec "$ENTRYPOINT" "$@"
