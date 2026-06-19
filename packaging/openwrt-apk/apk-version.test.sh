#!/bin/sh
# Case-table test for apk-version.sh. Run: sh apk-version.test.sh
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SUT="$HERE/apk-version.sh"

fail=0
check() {
    # check <expected> <args...>
    expected="$1"; shift
    actual="$(sh "$SUT" "$@")"
    if [ "$actual" = "$expected" ]; then
        printf '  PASS  %-22s -> %s\n' "$*" "$actual"
    else
        printf '  FAIL  %-22s -> %s (expected %s)\n' "$*" "$actual" "$expected"
        fail=1
    fi
}

echo "== apk-version.sh =="

# Plain release tags.
check "1.2.3-r0"        tag v1.2.3
check "0.4.0-r0"        tag v0.4.0
check "10.20.30-r0"     tag v10.20.30

# Pre-release tags: hyphen separator becomes apk's '_' marker.
check "1.2.3_rc1-r0"    tag v1.2.3-rc1
check "1.2.3_alpha1-r0" tag v1.2.3-alpha1
check "1.2.3_beta2-r0"  tag v1.2.3-beta2
check "1.2.3_pre1-r0"   tag v1.2.3-pre1

# Unknown pre-release token is dropped (apk cannot represent it).
check "1.2.3-r0"        tag v1.2.3-weird9

# Dev builds: monotonic commit height as a _git component.
check "0.0.0_git1234-r0" dev 1234
check "0.0.0_git0-r0"    dev 0

if [ "$fail" -ne 0 ]; then
    echo "FAILED"
    exit 1
fi
echo "OK"
