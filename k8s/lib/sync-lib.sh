#!/usr/bin/env bash
#
# Copies k8s/lib/sedai-latency-lib.sh into every script that embeds it (each script
# must stay a single downloadable file). Replaces the existing BEGIN..END block, or a
# "# @@LATENCY-LIB@@" placeholder line. Run after editing the lib; run-tests.sh fails
# when a copy drifts.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="$HERE/sedai-latency-lib.sh"
for f in "$HERE/../webhook-connectivity/sedai-webhook-connectivity.sh" "$HERE/../diagnostics/sedai-diagnostics.sh"; do
    [ -f "$f" ] || continue
    awk -v lib="$LIB" '
        function dump(   l) { while ((getline l < lib) > 0) print l; close(lib) }
        /^# @@LATENCY-LIB@@$/                 { dump(); next }
        /^# ==== BEGIN sedai-latency-lib/      { dump(); skip = 1; next }
        skip && /^# ==== END sedai-latency-lib ====/ { skip = 0; next }
        !skip' "$f" > "$f.tmp"
    cat "$f.tmp" > "$f" && rm -f "$f.tmp"
    echo "synced: $f"
done
