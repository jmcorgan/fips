#!/bin/bash
# A detached container start that survives a transient refusal by the daemon.
#
# Source image-build.sh first, for CI_LABELS, then this file:
#   source "$SCRIPT_DIR/../lib/image-build.sh"
#   source "$SCRIPT_DIR/../lib/docker-run.sh"
#   run_container "$name" -v "$dir:/run/fips" "$image" --config /etc/fips.yaml
#
# The Docker daemon has refused a container create under side load with an
# error that has nothing to do with the image or the project:
#   Error response from daemon: failed to create task for container:
#   Unavailable: error reading from server: EOF
# A suite that ignores the status of `docker run -d` then waits for a container
# that was never made, and reports the timeout as the project failing to start.
# CI must hold up under side load rather than be serialised to avoid it, so
# run_container retries the start, as relay_lab_start in relay-verdict.sh
# retries a relay that faulted in its start window, and when every attempt
# fails it says the failure was Docker's, in a line a reader can find.
#
# The run labels are passed here, not by the caller: testing/check-ci-labels.py
# reads only the line holding the docker command, and a helper that takes its
# labels from "$@" fails its rule 3.

# run_container <name> <docker run arguments...>
#
# Runs `docker run -d --name <name>` with CI_LABELS and the arguments, its
# stdout (the container id) discarded. On a non-zero exit it removes whatever
# the attempt left under that name and tries again, up to three attempts, 2 s
# apart. Every attempt's stderr goes to stderr. Returns 0 once a start
# succeeds; returns 125 after the last failure, having printed
#   INFRASTRUCTURE: docker run for <name> failed: <docker's last error>
# Returns 2, with nothing run, when CI_LABELS is not set.
run_container() {
    local name="$1"
    shift
    if [ -z "${CI_LABELS+x}" ] || [ "${#CI_LABELS[@]}" -eq 0 ]; then
        echo "run_container: CI_LABELS is not set; source testing/lib/image-build.sh first" >&2
        return 2
    fi
    local attempts=3 attempt=1 err rc
    err="$(mktemp)"
    while true; do
        rc=0
        docker run -d --name "$name" "${CI_LABELS[@]}" "$@" >/dev/null 2>"$err" || rc=$?
        if [ "$rc" -eq 0 ]; then
            if [ "$attempt" -gt 1 ]; then
                echo "run_container: $name started on attempt $attempt of $attempts" >&2
            fi
            rm -f "$err"
            return 0
        fi
        cat "$err" >&2
        docker rm -f "$name" >/dev/null 2>&1
        if [ "$attempt" -ge "$attempts" ]; then
            echo "INFRASTRUCTURE: docker run for $name failed: $(tr '\n' ' ' <"$err")" >&2
            rm -f "$err"
            return 125
        fi
        echo "run_container: docker run for $name failed on attempt $attempt of $attempts (exit $rc); retrying in 2s" >&2
        sleep 2
        attempt=$((attempt + 1))
    done
}
