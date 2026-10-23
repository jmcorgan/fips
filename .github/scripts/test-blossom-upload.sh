#!/bin/bash
# ── Test blossom-upload.sh against a stub Blossom server ────────────────────
# blossom.primal.net answers HTTP 415 to every OpenWrt .apk upload while it
# accepts the .ipk uploads made by the same step. nak sends a Content-Type taken
# from the file's extension through the host's MIME table, which maps .apk to
# Android's package type. This reproduces the client half of that with no third
# party: a stub server on 127.0.0.1 records each upload's Content-Type, answers
# 415 to application/vnd.android.package-archive, and otherwise accepts the
# upload with a blob descriptor carrying the body's SHA-256.
#
# Cases:
#   host_mime_table_maps_apk_to_the_android_type: a precondition. nak itself,
#     given a .apk, must send the Android type, or this host cannot exercise
#     the defect and the test fails saying so.
#   apk_upload_through_the_helper_succeeds_with_a_type_the_server_accepts: the
#     helper exits 0 on a .apk file and records the file's own SHA-256 as the
#     uploaded hash.
#   refused_upload_warns_and_writes_a_summary_line: with a server that refuses
#     every upload, the helper exits 1, prints a ::warning:: annotation and
#     adds a line to $GITHUB_STEP_SUMMARY.
# It also prints, as DATA, the type the stub saw for a .ipk upload made by nak
# directly.
#
# Needs nak, jq and python3 on PATH, and generates a throwaway key. Run by the
# OpenWrt Package workflow's build-apk job. Exit 0 only if every case passes.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$SCRIPT_DIR/blossom-upload.sh"
ANDROID_TYPE="application/vnd.android.package-archive"

for tool in nak jq python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "test-blossom-upload: $tool not found; cannot run" >&2
    exit 2
  fi
done

WORK=$(mktemp -d)
STUB_PIDS=()
# shellcheck disable=SC2317  # called by the EXIT trap
cleanup() {
  local pid
  for pid in "${STUB_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

FAILURES=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILURES=$((FAILURES + 1)); }

cat >"$WORK/stub.py" <<'PY'
"""Stub Blossom server: records each PUT /upload's Content-Type, one per line,
in the log file; answers 415 to the refused type (or to everything in
refuse-all mode) and otherwise 200 with a blob descriptor. Prints its port."""
import hashlib, http.server, json, sys

log_path, mode, refused = sys.argv[1], sys.argv[2], sys.argv[3]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self._reply(200)

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        ctype = self.headers.get("Content-Type") or "(none)"
        with open(log_path, "a") as f:
            f.write(ctype + "\n")
        if self.path != "/upload":
            self._reply(404)
        elif mode == "refuse-all" or ctype == refused:
            self._reply(415)
        else:
            digest = hashlib.sha256(body).hexdigest()
            host = self.headers.get("Host")
            self._reply(200, json.dumps({
                "url": f"http://{host}/{digest}",
                "sha256": digest,
                "size": len(body),
                "type": ctype,
                "uploaded": 0,
            }).encode())

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
print(server.server_address[1], flush=True)
server.serve_forever()
PY

# start_stub <mode> <log>: starts a stub and prints its URL.
start_stub() {
  local mode="$1" log="$2" port="" _i
  : >"$log"
  python3 "$WORK/stub.py" "$log" "$mode" "$ANDROID_TYPE" >"$log.port" 2>"$log.err" &
  STUB_PIDS+=("$!")
  for _i in $(seq 1 50); do
    port=$(head -n 1 "$log.port" 2>/dev/null)
    [ -n "$port" ] && break
    sleep 0.1
  done
  if [ -z "$port" ]; then
    echo "test-blossom-upload: the stub server did not start: $(cat "$log.err")" >&2
    exit 2
  fi
  echo "http://127.0.0.1:$port"
  return 0
}

NSEC=$(nak key generate </dev/null)
if [ -z "$NSEC" ]; then
  echo "test-blossom-upload: nak key generate produced no key" >&2
  exit 2
fi
export NSEC

head -c 4096 /dev/urandom >"$WORK/fips_0.0.0-r1_x86_64.apk"
cp "$WORK/fips_0.0.0-r1_x86_64.apk" "$WORK/fips_0.0.0-r1_x86_64.ipk"
APK="$WORK/fips_0.0.0-r1_x86_64.apk"
WANT_HASH=$(sha256sum "$APK" | cut -d' ' -f1)

SERVER=$(start_stub refuse-android "$WORK/types.log")

# Precondition: nak on this host sends the Android type for a .apk.
nak blossom upload --server "$SERVER" --sec "$NSEC" "$APK" </dev/null >/dev/null 2>&1 || true
seen=$(head -n 1 "$WORK/types.log")
if [ "$seen" = "$ANDROID_TYPE" ]; then
  pass "host_mime_table_maps_apk_to_the_android_type  (nak sent $seen)"
else
  fail "host_mime_table_maps_apk_to_the_android_type  (nak sent '${seen:-nothing}'; this host cannot exercise the defect)"
fi

# DATA: what nak sends for a .ipk, the type the real server accepts.
: >"$WORK/types.log"
nak blossom upload --server "$SERVER" --sec "$NSEC" "$WORK/fips_0.0.0-r1_x86_64.ipk" </dev/null >/dev/null 2>&1 || true
echo "DATA  nak sends Content-Type '$(head -n 1 "$WORK/types.log")' for a .ipk"

# The helper on a .apk.
: >"$WORK/types.log"
rc=0
GITHUB_OUTPUT="$WORK/output" GITHUB_STEP_SUMMARY="$WORK/summary" BLOSSOM_RETRY_DELAY=0 \
  bash "$HELPER" "$SERVER" "$APK" >"$WORK/helper.out" 2>&1 || rc=$?
got_hash=$(sed -n 's/^hash=//p' "$WORK/output" 2>/dev/null | tail -n 1)
types=$(tr '\n' ' ' <"$WORK/types.log")
if [ "$rc" -eq 0 ] && [ "$got_hash" = "$WANT_HASH" ]; then
  pass "apk_upload_through_the_helper_succeeds_with_a_type_the_server_accepts  (sent: $types)"
else
  fail "apk_upload_through_the_helper_succeeds_with_a_type_the_server_accepts  (exit $rc, hash '${got_hash}' want '$WANT_HASH', sent: $types)"
  sed 's/^/      /' "$WORK/helper.out"
fi

# A server that refuses everything: exit 1, a warning annotation and a
# summary line.
REFUSING=$(start_stub refuse-all "$WORK/refused.log")
rm -f "$WORK/output" "$WORK/summary"
rc=0
GITHUB_OUTPUT="$WORK/output" GITHUB_STEP_SUMMARY="$WORK/summary" BLOSSOM_RETRY_DELAY=0 \
  bash "$HELPER" "$REFUSING" "$APK" >"$WORK/helper.out" 2>&1 || rc=$?
attempts=$(wc -l <"$WORK/refused.log")
if [ "$rc" -eq 1 ] && [ "$attempts" -eq 3 ] &&
  grep -q '^::warning::.*Blossom' "$WORK/helper.out" &&
  grep -qF "$(basename "$APK")" "$WORK/summary" 2>/dev/null &&
  ! grep -q '^hash=' "$WORK/output" 2>/dev/null; then
  pass "refused_upload_warns_and_writes_a_summary_line  ($attempts attempts)"
else
  fail "refused_upload_warns_and_writes_a_summary_line  (exit $rc want 1, $attempts attempts want 3, warning and summary line required, no hash output)"
  sed 's/^/      /' "$WORK/helper.out"
  echo "      summary: $(cat "$WORK/summary" 2>/dev/null)"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "test-blossom-upload: all cases passed"
  exit 0
fi
echo "test-blossom-upload: $FAILURES case(s) failed"
exit 1
