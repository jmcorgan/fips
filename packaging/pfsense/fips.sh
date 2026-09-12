#!/bin/sh
# fips.sh - start/stop the FIPS mesh daemon on pfSense.
#
# pfSense does not drive rc.d(8) the way stock FreeBSD does. At the end
# of boot, rc.start_packages globs /usr/local/etc/rc.d/*.sh and runs
# each match as `<script> start`, backgrounded, with output appended to
# /tmp/bootup_messages. The same glob runs again whenever WAN gets a
# new address (rc.newwanip -> "service reload packages" -> rc.start_packages),
# so `start` here must be idempotent: a re-run must neither fork a second
# daemon nor disturb the one running. A link flap on a static-address
# interface does not reach rc.newwanip; an address change does. Either
# way the daemon handles medium changes itself (src/node/netmon/), so
# there is nothing to restart when an interface moves.
#
# Two consequences shape this script:
#
#   - The `.sh` suffix is what makes pfSense run it at all. The stock
#     FreeBSD package installs `/usr/local/etc/rc.d/fips` with no
#     suffix, which pfSense would never start.
#   - Plain sh rather than rc.subr. rc.subr would also work here — it
#     reads rc.conf.d/<name> as well as /etc/rc.conf, and a script may
#     default its own rcvar to YES — so this is a choice, not a need.
#     What pfSense actually imposes is the `.sh` name and that `start`
#     be re-run while the daemon is up: at boot, and again whenever WAN
#     gets a new address (rc.newwanip -> "service reload packages" ->
#     /etc/rc.start_packages). A re-run must leave a healthy daemon
#     alone and exit 0 quietly; keeping that in plain sh makes exactly
#     what happens on a re-run visible in this file. The enable knob
#     lives in fips.conf beside the daemon's own configuration.
#
# Usage: fips.sh start|stop|restart|status|onestart
#   onestart starts regardless of fips_enable (mirrors rc.subr's one*).
#
# See packaging/pfsense/README.md for installation and caveats.

set -u

fips_conf="/usr/local/etc/fips/fips.conf"
# shellcheck source=/dev/null
[ -r "$fips_conf" ] && . "$fips_conf"

: "${fips_enable:=YES}"
: "${fips_config:=/usr/local/etc/fips/fips.yaml}"
: "${fips_logfile:=/var/log/fips.log}"
: "${fips_flags:=}"

procname="/usr/local/bin/fips"
daemon_title="fips"
newsyslog_src="/usr/local/etc/fips/fips.newsyslog"
runtime_dir="/var/run/fips"
pidfile="${runtime_dir}/fips.pid"
# daemon(8) supervises the child; keeping its pid separately means stop
# can reap the supervisor too instead of leaving it parented to init.
supervisor_pidfile="${runtime_dir}/daemon.pid"
daemon_err="${runtime_dir}/daemon.err"

log() {
    echo "fips: $*"
    # Also to syslog: at boot and on package reloads stdout lands in
    # /tmp/bootup_messages, which nobody watches; operators read the
    # system log.
    logger -t fips -p daemon.notice -- "$*" 2>/dev/null || :
}

is_enabled() {
    case "$fips_enable" in
        [Yy][Ee][Ss] | [Tt][Rr][Uu][Ee] | [Oo][Nn] | 1) return 0 ;;
    esac
    return 1
}

# Echoes the running daemon's pid and returns 0, or returns 1.
#
# Existence and identity are both settled by ps: a bare kill -0 would
# fail with EPERM for a caller who does not own the daemon, and would
# not catch a stale pidfile whose number has been recycled by an
# unrelated process — which would make `start` a silent no-op forever.
#
# The read is deliberately NOT guarded with `|| return 1`. daemon(8)
# writes the pid with no trailing newline, so read reaches EOF and
# returns non-zero having nonetheless read the value. Guarding it made
# this function report "not running" for a perfectly healthy daemon,
# which in turn made status always wrong, stop find nothing to stop,
# restart never come back up, and every start orphan another supervisor.
running_pid() {
    [ -r "$pidfile" ] || return 1
    _pid=""
    read -r _pid < "$pidfile" 2>/dev/null || :
    case "${_pid:-}" in
        '' | *[!0-9]*) return 1 ;;
    esac
    [ "$(ps -p "$_pid" -o comm= 2>/dev/null)" = "fips" ] || return 1
    echo "$_pid"
    return 0
}

# The daemon resolves its control socket to /var/run/fips when the
# directory exists, so it must be there before the daemon starts.
# root:fips 0750 lets members of the fips group run fipsctl and fipstop
# without root; the group is created by the package post-install. Fall
# back to 0755 where the group is absent (e.g. a source install).
prepare_runtime_dir() {
    # Log rotation. pfSense writes /etc/newsyslog.conf itself, with an
    # include of /var/etc/newsyslog.conf.d/*, and on a box with RAM disks
    # /var/etc is rebuilt at every boot — so a rotation entry installed
    # there by pkg would be gone after a reboot. Re-copy it here instead:
    # start runs after pfSense has set up /var/etc, and the copy is cheap.
    if [ -d /var/etc/newsyslog.conf.d ] && [ -r "$newsyslog_src" ]; then
        install -m 0644 "$newsyslog_src" /var/etc/newsyslog.conf.d/fips.conf 2>/dev/null || :
    fi
    if pw groupshow fips >/dev/null 2>&1; then
        install -d -m 0750 -o root -g fips "$runtime_dir"
    else
        install -d -m 0755 "$runtime_dir"
    fi
    return 0
}

# Launch daemon(8), leaving its diagnostics in $daemon_err for the caller.
#
# stderr goes to a file rather than through a command substitution: the
# supervisor daemon(8) leaves behind inherits the pipe and never closes
# it, so `out=$(daemon ...)` blocks until the daemon exits — which is to
# say for ever, and on pfSense that would hang rc.start_packages at boot.
# shellcheck disable=SC2086  # fips_flags is deliberately unquoted:
# it carries zero or more separate arguments from fips.conf, and
# quoting it would pass the lot as one argument.
start_daemon() {
    : > "$daemon_err" 2>/dev/null || :
    # -H: close and reopen the -o log file on SIGHUP, which is how the
    # newsyslog.conf.d entry signals a rotation (its pid_file is the
    # supervisor's -P file). Without it the daemon writes into the rotated,
    # eventually-unlinked inode.
    /usr/sbin/daemon -H -p "$pidfile" -P "$supervisor_pidfile" -t "$daemon_title" \
        -o "$fips_logfile" \
        "$procname" --config "$fips_config" ${fips_flags} 2>>"$daemon_err"
}

# Whatever daemon(8) last complained about, as one line.
daemon_error() {
    [ -r "$daemon_err" ] && tr '\n' ' ' < "$daemon_err" | sed 's/  */ /g; s/ $//'
    return 0
}
do_start() {
    if pid=$(running_pid); then
        log "already running as pid ${pid}"
        return 0
    fi
    if [ ! -x "$procname" ]; then
        log "ERROR: ${procname} is missing or not executable"
        return 1
    fi
    if [ ! -r "$fips_config" ]; then
        log "ERROR: config ${fips_config} is missing or unreadable"
        return 1
    fi
    prepare_runtime_dir

    if start_daemon; then
        log "started (log: ${fips_logfile})"
        return 0
    fi

    # daemon(8) refused. The case worth recovering from is an orphaned
    # supervisor holding the pidfile lock, left behind by a child that
    # died during startup — running_pid() has already established that no
    # daemon of ours is alive, so nothing that matters owns that lock.
    #
    # daemon(8) names the offending pid ("process already running, pid:
    # N"), so kill exactly that, after confirming it is a daemon(8).
    # Earlier versions swept by process title instead, which was worse
    # than the problem twice over: done before every start it killed the
    # supervisor that had just been started (pfSense re-enters start on
    # every interface event, and daemon(8) forwards the signal to its
    # child, so the daemon shut down cleanly seconds after starting with
    # nothing in the log to say why); and done after any failure it could
    # kill an unrelated daemon(8) that merely shared the title.
    case "$(daemon_error)" in
        *"already running"*) ;;
        *)
            log "ERROR: daemon(8) failed to start ${procname}"
            [ -n "$(daemon_error)" ] && log "ERROR: $(daemon_error)"
            return 1
            ;;
    esac
    # daemon(8) names the pid it read from the pidfile. For a locked file
    # that holds no pid — the orphan case — pidfile_read yields -1, so
    # "pid: -1" is what it prints, and parsing that leads nowhere. Ask the
    # kernel instead: the supervisor keeps the pidfile open to hold the
    # lock, and fstat(1) names the process and its command.
    stale="$(fstat "$pidfile" 2>/dev/null | awk 'NR > 1 && $2 == "daemon" { print $3; exit }')"
    if [ -z "$stale" ]; then
        log "ERROR: daemon(8) says the pidfile is locked, but no daemon(8) holds ${pidfile}"
        log "ERROR: $(daemon_error)"
        holder="$(fstat "$pidfile" 2>/dev/null | awk 'NR > 1 { print $2 " (pid " $3 ")"; exit }')"
        [ -n "$holder" ] && log "ERROR: it is held by ${holder}; not touching it"
        return 1
    fi

    log "clearing an orphaned supervisor (pid ${stale}) and retrying"
    kill -TERM "$stale" 2>/dev/null
    i=0
    while [ "$i" -lt 5 ] && kill -0 "$stale" 2>/dev/null; do
        sleep 1
        i=$((i + 1))
    done
    rm -f "$supervisor_pidfile" "$pidfile"

    if start_daemon; then
        log "started after clearing an orphaned supervisor (log: ${fips_logfile})"
        return 0
    fi
    log "ERROR: daemon(8) failed to start ${procname}"
    [ -n "$(daemon_error)" ] && log "ERROR: $(daemon_error)"
    return 1
}
do_stop() {
    pid=$(running_pid) || {
        log "not running"
        # Nothing is running, but daemon(8) may be: clear it either way.
        stop_supervisor
        rm -f "$pidfile"
        return 0
    }
    kill -TERM "$pid" 2>/dev/null
    i=0
    while [ "$i" -lt 15 ]; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
        i=$((i + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        log "WARNING: pid ${pid} did not exit within 15s; sending SIGKILL"
        kill -KILL "$pid" 2>/dev/null
        sleep 1
    fi
    stop_supervisor
    rm -f "$pidfile"
    log "stopped"
    return 0
}

# daemon(8) exits once its child does, so this is normally a no-op. It
# matters in two cases that are not no-ops at all.
#
# After a SIGKILL the supervisor can outlive the child. And when the
# child dies during startup, daemon(8) can be left holding a pidfile it
# created and locked but never wrote a pid into — an *empty* file. A
# `read` from an empty file returns non-zero, so guarding the read with
# `|| return` skips both the kill and the cleanup, which leaves an
# orphaned supervisor holding the lock. Every later start then fails with
# daemon(8)'s "process already running", naming a pid that is not the
# daemon and cannot be stopped through this script. On pfSense, where
# start is re-run on every interface event, that is permanent.
#
# So: never early-return. Recovering an orphan the pidfile cannot name is
# do_start's job, from the pid daemon(8) itself reports.
stop_supervisor() {
    if [ -r "$supervisor_pidfile" ]; then
        _sup=""
        read -r _sup < "$supervisor_pidfile" 2>/dev/null || :
        case "${_sup:-}" in
            '' | *[!0-9]*) ;;
            *) kill -TERM "$_sup" 2>/dev/null ;;
        esac
    fi
    rm -f "$supervisor_pidfile"
    return 0
}

case "${1:-}" in
    start)
        if ! is_enabled; then
            # Boot and every interface event land here; stay quiet about
            # a deliberate opt-out rather than filling bootup_messages.
            exit 0
        fi
        do_start
        ;;
    onestart)
        do_start
        ;;
    stop | onestop)
        do_stop
        ;;
    restart | onerestart)
        do_stop
        do_start
        ;;
    status | onestatus)
        if pid=$(running_pid); then
            log "running as pid ${pid}"
            exit 0
        fi
        log "not running"
        exit 1
        ;;
    *)
        echo "usage: $0 start|stop|restart|status|onestart" >&2
        exit 64
        ;;
esac
