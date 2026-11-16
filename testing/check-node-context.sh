#!/bin/bash
# Guard: the effectively-immutable state lives solely in NodeContext. The Node
# struct in src/node/mod.rs must not re-declare a bundled field
# (config/identity/startup_epoch/started_at/is_leaf_only/node_profile/max_*):
# a shadow field would silently reopen dual-store divergence between the
# struct and the context. It checks the struct *declaration*, so it is
# wrap-insensitive. Run by testing/ci-local.sh's build stage, recorded as
# node-context-guard, and by GitHub CI's ci-parity job.
#
# The declaration is captured before it is matched: under pipefail, grep -q
# exiting at its match killed awk with SIGPIPE before its last write, so the
# guard never fired. An empty capture means the struct was not found and the
# guard would check nothing, so that fails too.
#
# Usage: testing/check-node-context.sh [<file>]   (default src/node/mod.rs)
# Exit 0 = clean; 1 = a bundled field is re-declared, or no struct was found.
set -uo pipefail

file="${1:-$(cd "$(dirname "$0")/.." && pwd)/src/node/mod.rs}"
node_decl=$(awk '/^pub struct Node \{/,/^\}/' "$file") || node_decl=""
if [[ -z "$node_decl" ]]; then
    echo "check-node-context: no 'pub struct Node' declaration found in $file, so the single-store guard checked nothing" >&2
    exit 1
fi
if grep -qE '^[[:space:]]+(config|identity|startup_epoch|started_at|is_leaf_only|node_profile|max_connections|max_peers|max_links):' \
    <<<"$node_decl"; then
    echo "check-node-context: the Node struct re-declares a bundled immutable field; it must live solely in NodeContext" >&2
    exit 1
fi
echo "check-node-context: the Node struct declares no NodeContext field"
exit 0
