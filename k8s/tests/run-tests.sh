#!/usr/bin/env bash
#
# Offline tests for the sedai-utils k8s scripts. No cluster needed.
# Usage: bash k8s/tests/run-tests.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
K8S="$(cd "$HERE/.." && pwd)"
LIB="$K8S/lib/sedai-latency-lib.sh"
FAILED=0

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILED=1; }

# 1. Latency lib unit self-test.
lib_out="$(bash -c ". '$LIB'; lat_self_test" 2>&1)"
if printf '%s\n' "$lib_out" | grep -q 'latency lib self-test PASSED'; then
    pass "latency lib self-test"
else
    fail "latency lib self-test"; printf '%s\n' "$lib_out" | sed 's/^/      /'
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAKE="$HERE/fake-kubectl"
export FAKE_FIXTURES="$HERE/fixtures"

# lib_block FILE: the embedded latency-lib block, markers included.
lib_block() { sed -n '/^# ==== BEGIN sedai-latency-lib/,/^# ==== END sedai-latency-lib ====/p' "$1"; }

# expect FILE LABEL REGEX: FILE must contain a line matching REGEX.
expect() {
    if grep -qE -- "$3" "$1"; then pass "$2"; else fail "$2 (no match for: $3)"; fi
}
# reject FILE LABEL FIXED: FILE must not contain FIXED.
reject() {
    if grep -qF -- "$3" "$1"; then fail "$2 (found: $3)"; else pass "$2"; fi
}

# run_script NAME SCRIPT MODE APIMETRICS OUT [args...]: run SCRIPT against the fake kubectl.
run_script() {
    local name="$1" script="$2" mode="$3" apim="$4" out="$5"; shift 5
    local rc=0
    PATH="$FAKE:$PATH" FAKE_KUBECTL_MODE="$mode" FAKE_APIMETRICS="$apim" FAKE_STATE="$TMP/state-$name" \
        bash "$script" "$@" >"$TMP/$name.console" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then pass "$name: exits 0"; else fail "$name: exit code $rc"; sed 's/^/      /' "$TMP/$name.console" | tail -20; fi
    case "$out" in *.ran) : ;; *) [ -s "$out" ] || fail "$name: no output written to $out" ;; esac
}

CONN="$K8S/webhook-connectivity/sedai-webhook-connectivity.sh"

# 2. Connectivity script: self-test and embedded lib in sync with the canonical copy.
if bash "$CONN" --self-test 2>&1 | grep -q 'latency lib self-test PASSED'; then pass "connectivity --self-test"; else fail "connectivity --self-test"; fi
if diff <(lib_block "$LIB") <(lib_block "$CONN") >/dev/null; then pass "connectivity lib block in sync"; else fail "connectivity lib block differs from k8s/lib/sedai-latency-lib.sh"; fi

# 3. Connectivity script, healthy data: window classification end to end.
out="$TMP/conn-ok.txt"
run_script conn-ok "$CONN" ok ok "$out" -n sedai --window 1 --no-port-forward -o "$out"
for h in '^SIGNALS' '^VERDICT' '13\. Admission latency' '14\. Admission latency' '15\. Slow admissions' '^Not collected'; do expect "$out" "conn-ok: has $h" "$h"; done
expect "$out" "conn-ok: pod and spark merged row" 'pod\+spark'
expect "$out" "conn-ok: pod row dropping, slow in controller" 'pod\+spark.*DROPPING SLOW-IN-CONTROLLER'
expect "$out" "conn-ok: workload row OK" 'workload .*OK'
expect "$out" "conn-ok: window over-timeout count" '20/100'
expect "$out" "conn-ok: dominant stage" 'dominant stage.*owner_resolve'
expect "$out" "conn-ok: health 15-minute block" 'last 15 retired minutes'
expect "$out" "conn-ok: 24h history" '1h ago'
expect "$out" "conn-ok: slow admission owners" 'Deployment/api'
expect "$out" "conn-ok: historical fail-open line" 'DROPPED-HISTORICALLY'
reject "$out" "conn-ok: fixture secret redacted" 'fixtureHunter2'
reject "$out" "conn-ok: no 198.18 claim for a 10.x endpoint" '198.18.0.0/15)'

# 4. API-server /metrics forbidden: controller view and verdict still render.
out="$TMP/conn-forbidden.txt"
run_script conn-forbidden "$CONN" ok forbidden "$out" -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-forbidden: reason recorded" 'unavailable: forbidden'
expect "$out" "conn-forbidden: verdict present" '^VERDICT'
expect "$out" "conn-forbidden: controller view still shown" 'dominant stage'

# 5. Every kubectl call fails: still exits 0 and renders every section.
out="$TMP/conn-fail.txt"
run_script conn-fail "$CONN" fail ok "$out" -n sedai --window 1 --no-port-forward -o "$out"
for h in '^SIGNALS' '^VERDICT' '13\. Admission latency' '14\. Admission latency' '15\. Slow admissions' '^Not collected'; do expect "$out" "conn-fail: has $h" "$h"; done
expect "$out" "conn-fail: says the API server itself is unreachable" 'kubectl cannot reach the API server'
reject "$out" "conn-fail: no hostNetwork advice when nothing was measured" 'isHostAddress'

# 6. Old controller (v2.0.5): API-server view still classifies; controller parts say why they are missing.
out="$TMP/conn-old.txt"
FAKE_CTRL_OLD=1 run_script conn-old "$CONN" ok ok "$out" -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-old: API-server classification kept" 'pod\+spark.*DROPPING'
expect "$out" "conn-old: breakdown unavailable reason" 'controller-side breakdown unavailable'
expect "$out" "conn-old: predates latency metrics" 'v2\.0\.5 predates'
expect "$out" "conn-old: slow admissions predates" 'predates slow-admission tracking'

# 7. HA control plane: reading 2 from another API-server instance -> no window, never DROPPING.
out="$TMP/conn-ha.txt"
FAKE_API_HA=1 run_script conn-ha "$CONN" ok ok "$out" -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-ha: reason recorded" 'different API-server instances'
reject "$out" "conn-ha: no DROPPING verdict without a window" 'DROPPING'
expect "$out" "conn-ha: historical evidence still shown" 'DROPPED-HISTORICALLY'
reject "$out" "conn-ha: no OK all-clear without the API-server window" 'workload: OK —'
expect "$out" "conn-ha: workload row is INSUFFICIENT-WINDOW" 'workload: INSUFFICIENT-WINDOW'

# 7b. No fail-open counter (Kubernetes < 1.24): never claim "no dropped mutations".
out="$TMP/conn-nofo.txt"
FAKE_NO_FAILOPEN=1 run_script conn-nofo "$CONN" ok ok "$out" -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-nofo: says fail-open was not measured" 'workload: OK .*fail-open not measured'
reject "$out" "conn-nofo: no 'no dropped mutations' claim" 'no dropped mutations'

DIAG="$K8S/diagnostics/sedai-diagnostics.sh"

# 8. Diagnostics: self-test covers sanitizer and lib; embedded lib in sync.
dst="$(bash "$DIAG" --self-test 2>&1)"
if printf '%s' "$dst" | grep -q 'Sanitizer self-test PASSED' && printf '%s' "$dst" | grep -q 'latency lib self-test PASSED'; then
    pass "diagnostics --self-test"; else fail "diagnostics --self-test"; printf '%s\n' "$dst" | tail -5 | sed 's/^/      /'; fi
if diff <(lib_block "$LIB") <(lib_block "$DIAG") >/dev/null; then pass "diagnostics lib block in sync"; else fail "diagnostics lib block differs from k8s/lib/sedai-latency-lib.sh"; fi

# run_diag NAME MODE: run the bundle against the fake kubectl and unpack it into $TMP/NAME.
run_diag() {
    local name="$1" mode="$2" tgz
    mkdir -p "$TMP/$name"
    run_script "$name" "$DIAG" "$mode" ok "$TMP/$name/.ran" -n sedai --window 1 --no-exec -o "$TMP/$name"
    tgz="$(ls "$TMP/$name"/sedai-diagnostics-*.tar.gz 2>/dev/null | head -1)"
    if [ -n "$tgz" ]; then pass "$name: bundle written"; tar -xzf "$tgz" -C "$TMP/$name"; else fail "$name: no bundle"; fi
    BUNDLE="$(ls -d "$TMP/$name"/sedai-diagnostics-sedai-*/ 2>/dev/null | head -1)"
    BUNDLE="${BUNDLE%/}"
}

# 9. Diagnostics, healthy data.
run_diag diag-ok ok
S="$BUNDLE/summary.txt"
expect "$S" "diag-ok: per-row latency check FAILs on the dropping row" '^FAIL +admission latency vs timeout \(pod\+spark\)'
expect "$S" "diag-ok: workload row PASS" '^PASS +admission latency vs timeout \(workload\)'
expect "$S" "diag-ok: controller metrics reachable" '^PASS +controller metrics reachable'
expect "$S" "diag-ok: controller latency metrics present" '^PASS +controller latency metrics present'
expect "$S" "diag-ok: instrumentation reported" '^INFO +instrumentation enabled'
expect "$S" "diag-ok: controller version reported" '^INFO +controller version .*v2\.2\.0'
expect "$S" "diag-ok: probe TLS noise separated" '^INFO +spec-controller probe TLS noise .*3'
expect "$S" "diag-ok: Postgres signature counted" '^WARN +spec-controller log failure signatures +1 matching'
expect "$S" "diag-ok: no SQLite PVC check on Postgres" 'spec-controller DB PVC bound'
reject "$S" "diag-ok: SQLite PVC check skipped" 'spec-controller PVC bound'
expect "$S" "diag-ok: Not collected section" '^Not collected'
expect "$BUNDLE/spec-controller/latency/latency-summary.txt" "diag-ok: latency summary" 'DROPPING SLOW-IN-CONTROLLER'
expect "$BUNDLE/spec-controller/wisb-wiri/controller-metrics.txt" "diag-ok: controller metrics captured" '^sedai_pi_admission_stage_duration_seconds_bucket'
if grep -rqF 'fixtureHunter2' "$BUNDLE"; then fail "diag-ok: fixture secret leaked into bundle"; else pass "diag-ok: fixture secret redacted"; fi

# 9b. Diagnostics on an HA control plane: never PASS a row whose dropped mutations were not measured.
FAKE_API_HA=1 run_diag diag-ha ok
reject "$BUNDLE/summary.txt" "diag-ha: no PASS latency row without the API-server window" 'PASS  admission latency'

# 9c. Controller pod Pending: still collected, and reported as not Running.
FAKE_CTRL_PENDING=1 run_diag diag-pending ok
expect "$BUNDLE/summary.txt" "diag-pending: pod found but not Running" '^WARN +spec-controller pod found .*Pending'
if [ -s "$BUNDLE/spec-controller/pod-describe.txt" ]; then pass "diag-pending: pod describe collected"; else fail "diag-pending: pod describe not collected"; fi

# 10. Diagnostics, every kubectl call fails: still produces a bundle with a Not collected list.
run_diag diag-fail fail
expect "$BUNDLE/summary.txt" "diag-fail: Not collected section" '^Not collected'

# 12. --context is reported as the context actually used.
out="$TMP/conn-ctx.txt"
run_script conn-ctx "$CONN" ok ok "$out" --context ctx-explicit -n sedai --window 0 --no-port-forward -o "$out"
expect "$out" "conn-ctx: report names the --context used" '^context   : ctx-explicit$'

# 13. No controller pod: say so, not "use hostNetwork".
out="$TMP/conn-noctrl.txt"
FAKE_NO_CTRL=1 run_script conn-noctrl "$CONN" ok ok "$out" -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-noctrl: verdict names the missing pod" 'NO CONTROLLER POD'
reject "$out" "conn-noctrl: no hostNetwork advice" 'isHostAddress'

# 14. Access preflight, GKE-style /healthz, podCIDR, konnectivity logs, NEXT STEPS.
out="$TMP/conn-gaps.txt"
FAKE_HEALTHZ_404=1 FAKE_KONN=1 FAKE_PODCIDRS="10.0.1.0/24 10.0.0.0/29" run_script conn-gaps "$CONN" ok ok "$out" -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-gaps: access gaps listed" '^kubectl access gaps +get services/proxy -n sedai, .*get /metrics'
expect "$out" "conn-gaps: NotFound /healthz still reachable" '^kubectl -> API server \(/healthz\) +reachable \(/healthz answered NotFound'
reject "$out" "conn-gaps: not misread as NO-APISERVER" 'kubectl cannot reach the API server'
expect "$out" "conn-gaps: endpoint inside a node podCIDR" 'inside a node podCIDR\? +yes'
expect "$out" "conn-gaps: konnectivity hit counted (whole-IP match, autoscaler skipped)" 'konnectivity agent log \(1h\) +1 line\(s\) mention the controller IP .* 1 agent\(s\); 1 look like errors'
reject "$out" "conn-gaps: 10.0.0.50 is not 10.0.0.5" 'dialing 10.0.0.50'
expect "$out" "conn-gaps: forbidden agent recorded" 'konnectivity agent logs \(1 of 2 agents\)'
expect "$out" "conn-gaps: NEXT STEPS re-run with access" '^1\. Re-run this script with a context that has'
expect "$out" "conn-gaps: TLS section rendered" '17\. Webhook TLS'
reject "$out" "conn-gaps: no network steps when drops are explained by a slow controller" 'failed calling webhook'

out="$TMP/conn-podcidr-no.txt"
FAKE_PODCIDRS="10.0.0.8/29" run_script conn-podcidr-no "$CONN" ok ok "$out" -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-podcidr-no: /29 boundary excludes .5" 'inside a node podCIDR\? +no'

out="$TMP/conn-access.txt"
FAKE_ACCESS=yes run_script conn-access "$CONN" ok ok "$out" -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-access: no gaps" '^kubectl access gaps +none$'

# 15. Unexplained (lifetime-only) drops: NEXT STEPS asks for the API-server error and the network checks.
out="$TMP/conn-next.txt"
FAKE_API_HA=1 FAKE_WL_FAILOPEN=300 run_script conn-next "$CONN" ok ok "$out" --context gke_proj-1_us-east1_clu-a -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-next: GKE log query names the cluster" "gcloud logging read .*cluster_name=\"clu-a\".*--project proj-1"
expect "$out" "conn-next: manual TLS check offered" 'Check the webhook TLS by hand'
reject "$out" "conn-next: no network steps when the proxy reached the controller" 'sedai-webhook-probe'

out="$TMP/conn-dial.txt"
FAKE_PROXY_DIAL=1 FAKE_API_HA=1 FAKE_WL_FAILOPEN=300 run_script conn-dial "$CONN" ok ok "$out" --context gke_proj-1_us-east1_clu-a -n sedai --window 1 --no-port-forward -o "$out"
expect "$out" "conn-dial: proxy DIAL-FAILED" 'API server -> service \(health proxy\) +DIAL-FAILED'
expect "$out" "conn-dial: pod-network probe avoids the controller node" '"values":\["node-a"\]'
expect "$out" "conn-dial: GKE firewall check" 'gcloud compute firewall-rules list --project proj-1'
reject "$out" "conn-next: no TLS PROBLEM without caBundles to compare" 'TLS: PROBLEM'

# 16. Webhook TLS checks against generated certificates (no key material is committed).
if command -v openssl >/dev/null 2>&1; then
    CERTS="$TMP/certs"; mkdir -p "$CERTS"
    # mkca NAME / mkleaf NAME CA SAN DAYS
    mkca() { openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CERTS/$1.key" -out "$CERTS/$1.crt" -days 3650 -subj "/CN=$1" >/dev/null 2>&1; }
    mkleaf() {
        printf 'subjectAltName=DNS:%s\n' "$3" > "$CERTS/$1.ext"
        openssl req -newkey rsa:2048 -nodes -keyout "$CERTS/$1.key" -out "$CERTS/$1.csr" -subj "/CN=$1" >/dev/null 2>&1
        openssl x509 -req -in "$CERTS/$1.csr" -CA "$CERTS/$2.crt" -CAkey "$CERTS/$2.key" -CAcreateserial \
            -out "$CERTS/$1.crt" -days "$4" -extfile "$CERTS/$1.ext" >/dev/null 2>&1
    }
    SAN=sedai-kube-spec-controller-svc.sedai.svc
    mkca ca1; mkca ca2
    mkleaf leaf1 ca1 "$SAN" 400; mkleaf leaf1b ca1 "$SAN" 400; mkleaf leafbad ca1 wrong.sedai.svc 400; mkleaf leafsoon ca1 "$SAN" 10
    # tlsdir NAME SECRET-CA SECRET-LEAF BUNDLE-CA SERVED-LEAF
    tlsdir() {
        local d="$TMP/tls-$1"; mkdir -p "$d"
        base64 < "$CERTS/$2.crt" | tr -d '\n' > "$d/ca.b64"
        base64 < "$CERTS/$3.crt" | tr -d '\n' > "$d/tls.b64"
        base64 < "$CERTS/$4.crt" | tr -d '\n' > "$d/bundle.b64"
        cp "$CERTS/$5.crt" "$d/served.crt"; cp "$CERTS/$5.key" "$d/served.key"
        echo "$d"
    }
    tls_run() { local name="$1"; shift; out="$TMP/$name.txt"; run_script "$name" "$CONN" ok ok "$out" -n sedai --window 1 -o "$out" "$@"; }

    FAKE_TLS_DIR="$(tlsdir ok ca1 leaf1 ca1 leaf1)" FAKE_PF=1 FAKE_PF_TLS=1 tls_run tls-ok
    expect "$out" "tls-ok: TLS OK" '^webhook TLS \(caBundle/Secret/served\) +OK$'
    for c in 'caBundle <-> Secret ca.crt' 'Secret tls.crt signed by ca.crt' 'served cert <-> caBundle' 'SAN covers the Service name' 'certificate expiry' "pod serves the Secret's cert"; do
        expect "$out" "tls-ok: $c OK" "^$c +OK"
    done
    expect "$out" "tls-ok: fingerprints, no PEM" 'served cert +sha256 [0-9A-F:]{20}'
    reject "$out" "tls-ok: no PEM body in the report" 'BEGIN CERTIFICATE'
    if [ -e "$TMP/state-tls-ok/read-tls-key" ]; then fail "tls-ok: script read tls.key"; else pass "tls-ok: tls.key never read"; fi

    FAKE_TLS_DIR="$(tlsdir mismatch ca1 leaf1 ca2 leaf1)" tls_run tls-mismatch --no-port-forward
    expect "$out" "tls-mismatch: caBundle mismatch" '^caBundle <-> Secret ca.crt +MISMATCH'
    expect "$out" "tls-mismatch: SIGNALS PROBLEM" '^webhook TLS \(caBundle/Secret/served\) +PROBLEM'
    expect "$out" "tls-mismatch: TLS verdict line" '^TLS: PROBLEM'
    expect "$out" "tls-mismatch: NEXT STEPS fix" 'Fix the webhook TLS mismatch'

    FAKE_TLS_DIR="$(tlsdir served ca1 leaf1 ca1 leaf1b)" FAKE_PF=1 FAKE_PF_TLS=1 tls_run tls-served-stale
    expect "$out" "tls-served-stale: served cert still trusted" '^served cert <-> caBundle +OK'
    expect "$out" "tls-served-stale: pod serves an old cert" "^pod serves the Secret's cert +STALE +the pod serves a different"

    FAKE_TLS_DIR="$(tlsdir heur ca1 leaf1 ca1 leaf1)" FAKE_SECRET_TIME=2026-11-02T00:00:00Z tls_run tls-heuristic --no-port-forward
    expect "$out" "tls-heuristic: Secret written after pod start" "^pod serves the Secret's cert +STALE +heuristic"

    FAKE_TLS_DIR="$(tlsdir san ca1 leafbad ca1 leafbad)" tls_run tls-san --no-port-forward
    expect "$out" "tls-san: wrong SAN" '^SAN covers the Service name +MISSING'

    FAKE_TLS_DIR="$(tlsdir soon ca1 leafsoon ca1 leafsoon)" tls_run tls-soon --no-port-forward
    expect "$out" "tls-soon: expiring warns" '^certificate expiry +EXPIRING'
    reject "$out" "tls-soon: expiring is not a PROBLEM" 'TLS: PROBLEM'
else
    echo "SKIP  webhook TLS tests (openssl not installed)"
fi

# interrupt_run NAME SECONDS ENV...: start the connectivity script, send TERM after SECONDS,
# and require it to exit within 5s with no fake port-forward left running.
interrupt_run() {
    local name="$1" after="$2" pid i; shift 2
    env PATH="$FAKE:$PATH" FAKE_STATE="$TMP/state-$name" "$@" \
        bash "$CONN" -n sedai --window 30 -o "$TMP/$name.txt" >"$TMP/$name.console" 2>&1 &
    pid=$!
    sleep "$after"; kill -TERM "$pid" 2>/dev/null
    i=0; while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 10 ]; do sleep 0.5; i=$((i + 1)); done
    if kill -0 "$pid" 2>/dev/null; then fail "$name: still running 5s after TERM"; kill -KILL "$pid" 2>/dev/null
    else pass "$name: exits promptly on TERM"; fi
    wait "$pid" 2>/dev/null
    if pgrep -f "$FAKE/kubectl.* port-forward" >/dev/null 2>&1; then
        fail "$name: port-forward left running"; pkill -f "$FAKE/kubectl.* port-forward" 2>/dev/null
    else pass "$name: no port-forward left running"; fi
}

# 11. Interrupted during the window wait, and during a port-forward metrics fetch.
interrupt_run int-window 3
interrupt_run int-portforward 3 FAKE_PF=1 FAKE_PF_NOPROXY=1

echo
if [ "$FAILED" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "SOME TESTS FAILED"; fi
exit "$FAILED"
