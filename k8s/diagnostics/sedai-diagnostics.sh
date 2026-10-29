#!/usr/bin/env bash
#
# sedai-diagnostics.sh — read-only diagnostics bundle for the Sedai Smart Agent
# and the Sedai Kube Spec Controller.
#
# Collects logs, health, configuration, restart history, connectivity and TLS
# state for both components into a sanitized tar.gz that can be sent to Sedai
# support. The script NEVER modifies the cluster: it only uses kubectl
# get/describe/logs/events/auth and (optionally) kubectl exec with read-only
# commands (wget/nslookup) inside the already-running Sedai pods.
#
# Sensitive material is excluded or redacted:
#   - Secret values are never collected (only secret names/types).
#   - The TLS private key is never read; only public certificates are analyzed.
#   - Env vars / YAML / logs / helm values pass through a redaction filter
#     (access keys, encryption keys, tokens, passwords, bearer headers, AWS keys).
#
# Admission latency: per Sedai webhook, dropped mutations (API-server fail-open)
# and calls over the webhook timeout from two metric readings --window seconds
# apart, next to the controller's own stage timings (spec-controller/latency/).
# A step that fails is listed under "Not collected" in summary.txt; the run
# never aborts on it.
#
# Usage:
#   ./sedai-diagnostics.sh [-n <namespace>] [--context <kube-context>]
#                          [--since <duration>] [--tail <lines>] [--window <seconds>]
#                          [--no-exec] [-o <output-dir>] [--self-test]
#
# Requirements: bash, kubectl (required); openssl, helm, jq (optional, used
# when present for deeper analysis).

set -uo pipefail

NAMESPACE="sedai"
KCONTEXT=""
LOG_SINCE="72h"
LOG_TAIL="20000"
DO_EXEC="true"
OUT_DIR="$(pwd)"
SELF_TEST="false"
WINDOW="60"

AGENT_LABEL="app.kubernetes.io/name=sedai-smart-agent"
CONTROLLER_LABEL="app=sedai-kube-spec-controller"
# Namespaces opted into Spark optimization carry this label; the spec-controller
# webhook's namespaceSelector keys off it, so which namespaces have it decides
# where SparkApplication mutation actually fires.
SPARK_OPT_LABEL="sedai-spark-optimization-enabled=true"
# SparkApplication custom resource managed by the Spark operator.
SPARKAPP_KIND="sparkapplications.sparkoperator.k8s.io"
CONTROLLER_SVC="sedai-kube-spec-controller-svc"
CONTROLLER_PORT="8443"
CONTROLLER_HEALTH_PATH="/sedai/health"
# Names the shared latency lib expects.
CONTROLLER_DEPLOY="sedai-kube-spec-controller"
HEALTH_PATH="$CONTROLLER_HEALTH_PATH"
PF_METRICS_PORT="18090"
DUR_METRIC="apiserver_admission_webhook_admission_duration_seconds"
STAGE_METRIC="sedai_pi_admission_stage_duration_seconds"
DB_NAME="sedai-kube-spec-controller-db"
TLS_SECRET="sedai-kube-spec-controller-tls"
# 127.0.0.1 rather than localhost: the agent binds IPv4 only and busybox wget
# reports an obscure "Invalid argument" when localhost resolves to ::1 first.
AGENT_SELF_HEALTH_URL="http://127.0.0.1:8080/agent/health"

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        --context)      KCONTEXT="$2"; shift 2 ;;
        --since)        LOG_SINCE="$2"; shift 2 ;;
        --tail)         LOG_TAIL="$2"; shift 2 ;;
        --no-exec)      DO_EXEC="false"; shift ;;
        --window)       WINDOW="${2:-}"; shift 2 ;;
        -o|--output)    OUT_DIR="$2"; shift 2 ;;
        --self-test)    SELF_TEST="true"; shift ;;
        -h|--help)      usage ;;
        *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
    esac
done
case "$WINDOW" in ''|*[!0-9]*) echo "WARNING: --window must be whole seconds; using 60" >&2; WINDOW=60 ;; esac

CTX_FLAG=""; [ -n "$KCONTEXT" ] && CTX_FLAG="--context=$KCONTEXT"
# Every call is bounded: short for queries, longer for logs and the API-server
# /metrics; exec/port-forward stream and are bounded by their own timeouts.
KUBECTL="kubectl --request-timeout=10s${CTX_FLAG:+ $CTX_FLAG}"
KUBECTL_LONG="kubectl --request-timeout=120s${CTX_FLAG:+ $CTX_FLAG}"
KUBECTL_METRICS="kubectl --request-timeout=60s${CTX_FLAG:+ $CTX_FLAG}"
KUBECTL_PF="kubectl${CTX_FLAG:+ $CTX_FLAG}"
HAVE_CURL="false"; command -v curl >/dev/null 2>&1 && HAVE_CURL="true"
DO_PF="$DO_EXEC"

HAVE_OPENSSL="false"; command -v openssl >/dev/null 2>&1 && HAVE_OPENSSL="true"
HAVE_HELM="false";    command -v helm    >/dev/null 2>&1 && HAVE_HELM="true"
HAVE_JQ="false";      command -v jq      >/dev/null 2>&1 && HAVE_JQ="true"

# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------
# Redacts:
#  1. PEM private key blocks (any "-----BEGIN ... PRIVATE KEY-----" section).
#  2. The "value:" line following an env-var name that looks sensitive
#     (ACCESSKEY, ENCRYPTIONKEY, TOKEN, PASSWORD, SECRET, CREDENTIAL, APIKEY).
#  3. Inline "key: value" / "key=value" pairs whose key looks sensitive
#     (covers helm values, logs, properties).
#  4. Authorization/Bearer headers, AWS access key IDs, basic-auth in URLs.
sanitize() {
    awk '
        BEGIN { IGNORECASE = 1; inkey = 0; pending = 0 }
        /-----BEGIN [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE)-----/ { inkey = 1; print "[REDACTED PEM BLOCK]"; next }
        inkey && /-----END [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE)-----/ { inkey = 0; next }
        inkey { next }
        pending && /^[[:space:]]*(value|"value")[":]? *[:=]/ {
            sub(/(value|"value")[":]? *[:=].*/, "value: \"[REDACTED]\"")
            print; pending = 0; next
        }
        /name["'\'']?[[:space:]]*[:=][[:space:]]*["'\'']?[A-Za-z0-9_.-]*(ACCESS[-_]?KEY|ENCRYPTION[-_]?KEY|API[-_]?KEY|TOKEN|PASSWORD|PASSWD|SECRET|CREDENTIAL)/ {
            print; pending = 1; next
        }
        { pending = 0; print }
    ' | sed -E \
        -e 's/((accessKey|access[-_]key|serverAccessKey|encryptionKey|encryption[-_]key|apiKey|api[-_]key|password|passwd|secret[-_]?key|client[-_]?secret|credential[s]?|[A-Za-z]*[-_]?token|user[-_]?name)["'"'"']?[[:space:]]*[:=][[:space:]]*)("[^"]*"|'"'"'[^'"'"']*'"'"'|[^[:space:],}"]+)/\1"[REDACTED]"/Ig' \
        -e 's/(Authorization[[:space:]]*[:=][[:space:]]*)[^[:space:]].*/\1[REDACTED]/Ig' \
        -e 's/([Bb]earer )[A-Za-z0-9._~+\/=-]{8,}/\1[REDACTED]/g' \
        -e 's/(caBundle\\?["'"'"']?[[:space:]]*[:=][[:space:]]*\\?"?)[A-Za-z0-9+\/=]{16,}/\1[REDACTED-CERT-DATA]/g' \
        -e 's/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+/[REDACTED-JWT]/g' \
        -e 's/(AKIA|ASIA)[0-9A-Z]{16}/[REDACTED-AWS-KEY-ID]/g' \
        -e 's#(https?://)[^/@[:space:]]+@#\1[REDACTED]@#g'
}

# ==== BEGIN sedai-latency-lib (keep byte-identical in both scripts; source: k8s/lib/sedai-latency-lib.sh) ====
# Shared admission-latency analysis for the sedai-utils k8s scripts: Prometheus
# text parsing, histogram deltas, slow-call counts, classification, and a small
# JSON flattener (no jq dependency). Every function prints to stdout, returns 0,
# and prints nothing (or "none") on unusable input — callers never abort on it.
# All arithmetic runs in awk: metric values may be printed like 1.234567e+06.

# shellcheck disable=SC2034  # constants are read by the scripts that embed this block
LAT_MIN_CALLS=20                  # calls in the window before a current-state verdict
LAT_MIN_SLOW=3                    # over-timeout calls before SLOW
LAT_IN_RATIO=0.5                  # controller over-T fraction >= this x API server's => in controller
LAT_HIST_WARN_FRAC=0.01           # historical over-timeout fraction that warrants a WARN
# shellcheck disable=SC2034  # read by the diagnostics bundle only
LAT_HIST_FAILOPEN_WARN_FRAC=0.001 # historical fail-open fraction that warrants a WARN
LAT_HAPI_RETRIES=3                # re-reads when the API-server instance changed between readings

# Shared awk helpers: label parsing, selector matching, number formatting.
_LAT_AWK_COMMON='
function lat_num(v) { return (v == int(v)) ? sprintf("%.0f", v) : sprintf("%.6f", v) }
function lat_isnum(v) { return (v ~ /^[-+]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][-+]?[0-9]+)?$/) }
# Splits a sample line into name, labels (L[]) and value; returns 0 when unparsable.
function lat_parse(line,   i, c, k, v, ob, cb, rest) {
    delete L; S_NAME = ""; S_VAL = ""
    if (line ~ /^#/ || line ~ /^[ \t]*$/) return 0
    ob = index(line, "{")
    if (ob == 0) {
        split(line, parts, /[ \t]+/); S_NAME = parts[1]; S_VAL = parts[2]
        return lat_isnum(S_VAL)
    }
    S_NAME = substr(line, 1, ob - 1)
    rest = substr(line, ob + 1); i = 1
    while (i <= length(rest)) {
        c = substr(rest, i, 1)
        if (c == "}") { i++; break }
        if (c == "," || c == " ") { i++; continue }
        k = ""
        while (i <= length(rest) && substr(rest, i, 1) != "=") { k = k substr(rest, i, 1); i++ }
        i += 2; v = ""
        while (i <= length(rest)) {
            c = substr(rest, i, 1)
            if (c == "\\") { v = v substr(rest, i + 1, 1); i += 2; continue }
            if (c == "\"") { i++; break }
            v = v c; i++
        }
        L[k] = v
    }
    rest = substr(rest, i); sub(/^[ \t]+/, "", rest); split(rest, parts, /[ \t]+/); S_VAL = parts[1]
    return lat_isnum(S_VAL)
}
function lat_match(sel,   n, i, kv, eq) {
    n = split(sel, kv, / +/)
    for (i = 1; i <= n; i++) {
        if (kv[i] == "") continue
        eq = index(kv[i], "=")
        if (eq == 0 || !(substr(kv[i], 1, eq - 1) in L) || L[substr(kv[i], 1, eq - 1)] != substr(kv[i], eq + 1)) return 0
    }
    return 1
}
# Parses a lat_hist line into HB[bound]=count (keys numeric strings), HN bound count, HC total.
function lat_hparse(line,   n, f, i, eq, k) {
    delete HB; delete HK; HN = 0; HC = ""
    n = split(line, f, / +/)
    for (i = 1; i <= n; i++) {
        eq = index(f[i], "="); if (eq == 0) continue
        k = substr(f[i], 1, eq - 1)
        if (!lat_isnum(substr(f[i], eq + 1))) continue
        if (k == "count") { HC = substr(f[i], eq + 1) + 0; continue }
        if (!lat_isnum(k)) continue
        HB[k] = substr(f[i], eq + 1) + 0; HK[++HN] = k
    }
    return HC != ""
}
'

# lat_hist FILE METRIC SELECTOR -> "count=<n> <le>=<cum> ..." (finite bounds, ascending)
lat_hist() {
    [ -r "${1:-}" ] || return 0
    awk -v m="$2" -v sel="${3:-}" "$_LAT_AWK_COMMON"'
        {
            if (!lat_parse($0)) next
            if (S_NAME != m "_bucket" && S_NAME != m "_count") next
            if (!lat_match(sel)) next
            if (S_NAME == m "_count") { cnt += S_VAL; seen = 1; next }
            if (!("le" in L) || L["le"] == "+Inf" || !lat_isnum(L["le"])) next
            k = sprintf("%.10g", L["le"] + 0)
            if (!(k in B)) { nb++; K[nb] = k }
            B[k] += S_VAL
        }
        END {
            if (!seen) exit
            for (i = 2; i <= nb; i++) { x = K[i]; j = i - 1; while (j >= 1 && K[j] + 0 > x + 0) { K[j + 1] = K[j]; j-- } K[j + 1] = x }
            out = "count=" lat_num(cnt)
            for (i = 1; i <= nb; i++) out = out " " K[i] "=" lat_num(B[K[i]])
            print out
        }' "$1" 2>/dev/null
    return 0
}

# lat_counter FILE METRIC SELECTOR -> summed sample value; empty when no sample matches
lat_counter() {
    [ -r "${1:-}" ] || return 0
    awk -v m="$2" -v sel="${3:-}" "$_LAT_AWK_COMMON"'
        lat_parse($0) && S_NAME == m && lat_match(sel) { sum += S_VAL; seen = 1 }
        END { if (seen) print lat_num(sum) }' "$1" 2>/dev/null
    return 0
}

# lat_hist_delta H1 H2 -> H2-H1 per field; "reset" if anything decreased or bounds differ
lat_hist_delta() {
    [ -n "${1:-}" ] && [ -n "${2:-}" ] || return 0
    awk -v a="$1" -v b="$2" "$_LAT_AWK_COMMON"'
        BEGIN {
            if (!lat_hparse(a)) exit
            ac = HC; an = HN; for (i = 1; i <= HN; i++) { AK[i] = HK[i]; AB[HK[i]] = HB[HK[i]] }
            if (!lat_hparse(b)) exit
            if (an != HN || HC < ac) { print "reset"; exit }
            out = "count=" lat_num(HC - ac)
            for (i = 1; i <= HN; i++) {
                k = HK[i]
                if (!(k in AB) || HB[k] < AB[k]) { print "reset"; exit }
                out = out " " k "=" lat_num(HB[k] - AB[k])
            }
            print out
        }' 2>/dev/null
    return 0
}

# lat_num_delta A B -> B-A; "reset" when negative; empty unless both are numbers
lat_num_delta() {
    awk -v a="${1:-}" -v b="${2:-}" "$_LAT_AWK_COMMON"'
        BEGIN {
            if (!lat_isnum(a) || !lat_isnum(b)) exit
            if (b + 0 < a + 0) { print "reset"; exit }
            print lat_num(b - a)
        }' 2>/dev/null
    return 0
}

# lat_over HIST T -> "exact <over> <count>" | "range <lo> <hi> <count>" | "none"
lat_over() {
    awk -v h="${1:-}" -v t="${2:-}" "$_LAT_AWK_COMMON"'
        BEGIN {
            if (!lat_hparse(h) || !lat_isnum(t)) { print "none"; exit }
            t += 0; below = ""; above = ""
            for (i = 1; i <= HN; i++) {
                k = HK[i] + 0
                if (k == t) { printf "exact %s %s\n", lat_num(HC - HB[HK[i]]), lat_num(HC); exit }
                if (k < t && (below == "" || k > below + 0)) { below = HK[i] }
                if (k > t && (above == "" || k < above + 0)) { above = HK[i] }
            }
            lo = (above == "") ? 0 : HC - HB[above]
            hi = (below == "") ? HC : HC - HB[below]
            printf "range %s %s %s\n", lat_num(lo), lat_num(hi), lat_num(HC)
        }' 2>/dev/null
    return 0
}

# lat_classify API_COUNT API_OVER_LO API_OVER_HI FAILOPEN_D CTRL_COUNT CTRL_OVER [API_OVER_SHARED]
#   -> "CLASS [CAUSE]". All inputs are window deltas; empty CTRL_* = controller view unavailable.
# CTRL_OVER and API_OVER_SHARED count calls over a bound both histograms share (see
# lat_shared_bound); without API_OVER_SHARED the API-server fraction uses API_OVER_LO.
lat_classify() {
    awk -v ac="${1:-}" -v lo="${2:-}" -v hi="${3:-}" -v fo="${4:-}" -v cc="${5:-}" -v co="${6:-}" -v as="${7:-}" \
        -v minc="$LAT_MIN_CALLS" -v mins="$LAT_MIN_SLOW" -v ratio="$LAT_IN_RATIO" "$_LAT_AWK_COMMON"'
        function cause(   af, cf) {
            if (!lat_isnum(cc) || cc + 0 <= 0 || !lat_isnum(co)) return "CONTROLLER-VIEW-UNAVAILABLE"
            af = (ac + 0 > 0) ? (lat_isnum(as) ? as : lo) / ac : 0; cf = co / cc
            return (af > 0 && cf >= ratio * af) ? "SLOW-IN-CONTROLLER" : "SLOW-OUTSIDE-CONTROLLER"
        }
        BEGIN {
            if (!lat_isnum(ac)) { print "UNKNOWN"; exit }
            ac += 0; lo = lat_isnum(lo) ? lo + 0 : 0; hi = lat_isnum(hi) ? hi + 0 : lo; fo = lat_isnum(fo) ? fo + 0 : 0
            if (fo > 0) {
                # Failed calls that returned before the timeout never reached a slow controller.
                # lo/hi bracket the over-timeout count when the timeout is not a bucket bound.
                if (hi < fo / 2) print "DROPPING NEVER-REACHED-CONTROLLER"
                else if (lo >= fo / 2) print "DROPPING " cause()
                else print "DROPPING CAUSE-INDETERMINATE"
                exit
            }
            if (ac == 0) { print "NO-TRAFFIC"; exit }
            if (ac < minc) { print "INSUFFICIENT-WINDOW"; exit }
            if (lo >= mins) { print "SLOW " cause(); exit }
            if (hi >= mins) { print "POSSIBLY-SLOW"; exit }
            print "OK"
        }' 2>/dev/null
    return 0
}

# lat_shared_bound HIST_A HIST_B T -> the largest bucket bound <= T present in both; empty if none
lat_shared_bound() {
    awk -v a="${1:-}" -v b="${2:-}" -v t="${3:-}" "$_LAT_AWK_COMMON"'
        BEGIN {
            if (!lat_hparse(a) || !lat_isnum(t)) exit
            for (i = 1; i <= HN; i++) A[HK[i] + 0] = HK[i]
            if (!lat_hparse(b)) exit
            best = ""
            for (i = 1; i <= HN; i++) { k = HK[i] + 0; if (k <= t + 0 && (k in A) && (best == "" || k > best + 0)) best = HK[i] }
            if (best != "") print best
        }' 2>/dev/null
    return 0
}

# lat_hist_classify FAILOPEN REQUESTS OVER COUNT (lifetime) -> zero or more evidence lines
lat_hist_classify() {
    awk -v fo="${1:-}" -v rq="${2:-}" -v ov="${3:-}" -v ct="${4:-}" -v warn="$LAT_HIST_WARN_FRAC" "$_LAT_AWK_COMMON"'
        BEGIN {
            if (lat_isnum(fo) && fo + 0 > 0)
                printf "DROPPED-HISTORICALLY %s %.6f\n", lat_num(fo + 0), (lat_isnum(rq) && rq + 0 > 0) ? fo / rq : 0
            if (lat_isnum(ov) && lat_isnum(ct) && ct + 0 > 0 && ov / ct >= warn)
                printf "HISTORICALLY-SLOW %.6f\n", ov / ct
        }' 2>/dev/null
    return 0
}

# json_flat (stdin JSON) -> "<path>\t<value>" per scalar, e.g. ".a.b[0].c<TAB>v"
json_flat() {
    awk '
        { s = s $0 "\n" }
        END { n = length(s); p = 1; jval("") }
        function ws() { while (p <= n && index(" \t\r\n", substr(s, p, 1)) > 0) p++ }
        function jstr(   out, c, c2) {
            p++; out = ""
            while (p <= n) {
                c = substr(s, p, 1)
                if (c == "\\") {
                    c2 = substr(s, p + 1, 1)
                    if (c2 == "n" || c2 == "t" || c2 == "r") out = out " "
                    else if (c2 == "u") { out = out "?"; p += 4 }
                    else out = out c2
                    p += 2; continue
                }
                if (c == "\"") { p++; return out }
                out = out c; p++
            }
            return out
        }
        function jval(path,   c, tok) {
            ws(); if (p > n) return
            c = substr(s, p, 1)
            if (c == "{") { jobj(path); return }
            if (c == "[") { jarr(path); return }
            if (c == "\"") { print path "\t" jstr(); return }
            tok = ""
            while (p <= n && index(",}] \t\r\n", substr(s, p, 1)) == 0) { tok = tok substr(s, p, 1); p++ }
            if (tok == "") { p = n + 1; return }
            print path "\t" tok
        }
        function jobj(path,   k, c) {
            p++; ws()
            if (substr(s, p, 1) == "}") { p++; return }
            while (p <= n) {
                ws(); if (substr(s, p, 1) != "\"") { p = n + 1; return }
                k = jstr(); ws()
                if (substr(s, p, 1) != ":") { p = n + 1; return }
                p++; jval(path "." k); ws()
                c = substr(s, p, 1)
                if (c == ",") { p++; continue }
                if (c == "}") { p++; return }
                p = n + 1; return
            }
        }
        function jarr(path,   i, c) {
            p++; ws()
            if (substr(s, p, 1) == "]") { p++; return }
            i = 0
            while (p <= n) {
                jval(path "[" i "]"); i++; ws()
                c = substr(s, p, 1)
                if (c == ",") { p++; continue }
                if (c == "]") { p++; return }
                p = n + 1; return
            }
        }' 2>/dev/null
    return 0
}

# json_get FLAT PATH -> value at the exact path (FLAT is json_flat output)
json_get() {
    printf '%s\n' "${1:-}" | awk -v p="${2:-}" '
        { t = index($0, "\t"); if (t > 0 && substr($0, 1, t - 1) == p) { print substr($0, t + 1); exit } }' 2>/dev/null
    return 0
}

# json_index_of FLAT ARRAY_PATH KEY VALUE -> index of the first element whose KEY equals VALUE
json_index_of() {
    printf '%s\n' "${1:-}" | awk -v a="${2:-}" -v k="${3:-}" -v v="${4:-}" '
        {
            t = index($0, "\t"); if (t == 0) next
            path = substr($0, 1, t - 1)
            if (substr(path, 1, length(a) + 1) != a "[") next
            rest = substr(path, length(a) + 2); rb = index(rest, "]"); if (rb == 0) next
            if (substr(rest, rb + 1) != "." k || substr($0, t + 1) != v) next
            print substr(rest, 1, rb - 1); exit
        }' 2>/dev/null
    return 0
}

# json_array_has FLAT ARRAY_PATH VALUE -> "yes" when a scalar element equals VALUE, else "no"
json_array_has() {
    printf '%s\n' "${1:-}" | awk -v a="${2:-}" -v v="${3:-}" '
        BEGIN { r = "no" }
        {
            t = index($0, "\t"); if (t == 0) next
            path = substr($0, 1, t - 1)
            if (substr(path, 1, length(a) + 1) != a "[") next
            rest = substr(path, length(a) + 2)
            if (rest ~ /^[0-9]+\]$/ && substr($0, t + 1) == v) { r = "yes"; exit }
        }
        END { print r }' 2>/dev/null
    return 0
}

_lat_fail=0
_lat_eq() {
    if [ "$2" = "$3" ]; then :; else
        echo "FAIL: $1"; echo "  expected: [$2]"; echo "  actual:   [$3]"; _lat_fail=1
    fi
}

lat_self_test() {
    _lat_fail=0
    local d api ctrl h1 flat
    d="$(mktemp -d 2>/dev/null || echo /tmp/sedai-lat-$$)"; mkdir -p "$d"
    api="$d/api.txt"; ctrl="$d/ctrl.txt"
    cat > "$api" <<'FIXTURE'
# HELP apiserver_admission_webhook_admission_duration_seconds fixture
# TYPE apiserver_admission_webhook_admission_duration_seconds histogram
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="admit",le="0.005"} 10
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="admit",le="0.025"} 20
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="admit",le="0.1"} 30
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="admit",le="0.5"} 40
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="admit",le="1"} 50
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="admit",le="2.5"} 60
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="admit",le="10"} 70
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="admit",le="25"} 70
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="admit",le="+Inf"} 70
apiserver_admission_webhook_admission_duration_seconds_sum{name="a",operation="CREATE",rejected="false",type="admit"} 99.5
apiserver_admission_webhook_admission_duration_seconds_count{name="a",operation="CREATE",rejected="false",type="admit"} 70
apiserver_admission_webhook_admission_duration_seconds_bucket{le="0.005",type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_bucket{le="0.025",type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_bucket{le="0.1",type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_bucket{le="0.5",type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_bucket{le="1",type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_bucket{le="2.5",type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_bucket{le="10",type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_bucket{le="25",type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_bucket{le="+Inf",type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_count{type="admit",rejected="true",operation="CREATE",name="a"} 5
apiserver_admission_webhook_admission_duration_seconds_bucket{name="a",operation="CREATE",rejected="false",type="validate",le="1"} 999
apiserver_admission_webhook_admission_duration_seconds_count{name="a",operation="CREATE",rejected="false",type="validate"} 999
apiserver_admission_webhook_admission_duration_seconds_bucket{name="big",operation="UPDATE",rejected="false",type="admit",le="1"} 1000
apiserver_admission_webhook_admission_duration_seconds_bucket{name="big",operation="UPDATE",rejected="false",type="admit",le="+Inf"} 1.2e+03
apiserver_admission_webhook_admission_duration_seconds_count{name="big",operation="UPDATE",rejected="false",type="admit"} 1.2e+03
apiserver_admission_webhook_fail_open_count{name="a",type="admit"} 4
apiserver_admission_webhook_fail_open_count{name="b",type="admit"} 2
process_start_time_seconds 1.76e+09
FIXTURE
    printf 'sedai_pi_admission_stage_duration_seconds_bucket{managed="true",served_by="db",stage="total",webhook="pod",le="1"} 8\nsedai_pi_admission_stage_duration_seconds_bucket{managed="true",served_by="db",stage="total",webhook="pod",le="+Inf"} 10\nsedai_pi_admission_stage_duration_seconds_count{managed="true",served_by="db",stage="total",webhook="pod"} 10\nsedai_pi_admission_stage_duration_seconds_bucket{managed="false",served_by="none",stage="total",webhook="pod",le="1"} 30\nsedai_pi_admission_stage_duration_seconds_bucket{managed="false",served_by="none",stage="total",webhook="pod",le="+Inf"} 30\nsedai_pi_admission_stage_duration_seconds_count{managed="false",served_by="none",stage="total",webhook="pod"} 30\nsedai_pi_db_connection_wait_seconds_total 1.5\n' > "$ctrl"

    # Histogram aggregation: sums matching series, honours every selector label,
    # sorts bounds numerically, ignores label order, parses exponent notation.
    _lat_eq "lat_hist sums name=a type=admit" \
        "count=75 0.005=15 0.025=25 0.1=35 0.5=45 1=55 2.5=65 10=75 25=75" \
        "$(lat_hist "$api" apiserver_admission_webhook_admission_duration_seconds 'name=a type=admit')"
    _lat_eq "lat_hist exponent values" "count=1200 1=1000" \
        "$(lat_hist "$api" apiserver_admission_webhook_admission_duration_seconds 'name=big type=admit')"
    _lat_eq "lat_hist no match" "" \
        "$(lat_hist "$api" apiserver_admission_webhook_admission_duration_seconds 'name=nope')"
    _lat_eq "lat_hist controller stage total" "count=40 1=38" \
        "$(lat_hist "$ctrl" sedai_pi_admission_stage_duration_seconds 'webhook=pod stage=total')"
    _lat_eq "lat_hist controller managed only" "count=10 1=8" \
        "$(lat_hist "$ctrl" sedai_pi_admission_stage_duration_seconds 'webhook=pod stage=total managed=true')"

    # Counters.
    _lat_eq "lat_counter name=a" "4" "$(lat_counter "$api" apiserver_admission_webhook_fail_open_count 'name=a')"
    _lat_eq "lat_counter all" "6" "$(lat_counter "$api" apiserver_admission_webhook_fail_open_count '')"
    _lat_eq "lat_counter exponent" "1760000000" "$(lat_counter "$api" process_start_time_seconds '')"
    _lat_eq "lat_counter fractional" "1.500000" "$(lat_counter "$ctrl" sedai_pi_db_connection_wait_seconds_total '')"
    _lat_eq "lat_counter missing" "" "$(lat_counter "$api" no_such_metric '')"

    # Slow counts over a threshold.
    h1="count=75 0.005=15 0.025=25 0.1=35 0.5=45 1=55 2.5=65 10=75 25=75"
    _lat_eq "lat_over exact at bound" "exact 20 75" "$(lat_over "$h1" 1)"
    _lat_eq "lat_over range between bounds" "range 0 10 75" "$(lat_over "$h1" 5)"
    _lat_eq "lat_over above all bounds" "range 0 0 75" "$(lat_over "$h1" 30)"
    _lat_eq "lat_over below all bounds" "range 60 75 75" "$(lat_over "$h1" 0.001)"
    _lat_eq "lat_over empty" "none" "$(lat_over "" 1)"

    # Window deltas.
    _lat_eq "lat_hist_delta subtracts" "count=20 1=15 2.5=17" \
        "$(lat_hist_delta 'count=10 1=5 2.5=8' 'count=30 1=20 2.5=25')"
    _lat_eq "lat_hist_delta reset on decrease" "reset" \
        "$(lat_hist_delta 'count=30 1=20' 'count=10 1=5')"
    _lat_eq "lat_hist_delta reset on bound mismatch" "reset" \
        "$(lat_hist_delta 'count=10 1=5' 'count=30 2.5=25')"
    _lat_eq "lat_hist_delta empty input" "" "$(lat_hist_delta '' 'count=30 1=20')"
    _lat_eq "lat_num_delta" "6" "$(lat_num_delta 4 10)"
    _lat_eq "lat_num_delta reset" "reset" "$(lat_num_delta 10 4)"
    _lat_eq "lat_num_delta empty" "" "$(lat_num_delta '' 4)"

    # Current-state classification (window deltas only).
    _lat_eq "classify unknown"           "UNKNOWN"                          "$(lat_classify '' '' '' '' '' '')"
    _lat_eq "classify never reached"     "DROPPING NEVER-REACHED-CONTROLLER" "$(lat_classify 100 0 0 4 '' '')"
    _lat_eq "classify dropping slow-in"  "DROPPING SLOW-IN-CONTROLLER"       "$(lat_classify 100 10 10 4 100 9)"
    _lat_eq "classify slow in"           "SLOW SLOW-IN-CONTROLLER"           "$(lat_classify 100 10 10 0 100 9)"
    _lat_eq "classify slow outside"      "SLOW SLOW-OUTSIDE-CONTROLLER"      "$(lat_classify 100 10 10 0 100 0)"
    _lat_eq "classify slow no ctrl"      "SLOW CONTROLLER-VIEW-UNAVAILABLE"  "$(lat_classify 100 10 10 0 '' '')"
    _lat_eq "classify slow ctrl zero"    "SLOW CONTROLLER-VIEW-UNAVAILABLE"  "$(lat_classify 100 10 10 0 0 0)"
    _lat_eq "classify possibly slow"     "POSSIBLY-SLOW"                     "$(lat_classify 100 0 5 0 '' '')"
    _lat_eq "classify insufficient"      "INSUFFICIENT-WINDOW"               "$(lat_classify 10 5 5 0 '' '')"
    _lat_eq "classify no traffic"        "NO-TRAFFIC"                        "$(lat_classify 0 0 0 0 '' '')"
    _lat_eq "classify ok"                "OK"                                "$(lat_classify 100 1 1 0 100 0)"
    _lat_eq "classify garbage"           "UNKNOWN"                           "$(lat_classify abc x y z '' '')"
    # Timeouts that are not a bucket bound (T=5, T=30): lo is 0 by construction, so the
    # never-reached rule must use hi, and an undecidable split says so.
    _lat_eq "classify T=5 indeterminate cause" "DROPPING CAUSE-INDETERMINATE"       "$(lat_classify 100 0 20 10 100 15)"
    _lat_eq "classify fast failures (hi)"      "DROPPING NEVER-REACHED-CONTROLLER"  "$(lat_classify 100 0 2 10 '' '')"
    # In/outside compares fractions at a bound both histograms share (7th arg = API over that bound).
    _lat_eq "classify shared-bound outside"    "SLOW SLOW-OUTSIDE-CONTROLLER"       "$(lat_classify 100 10 10 0 100 9 30)"
    _lat_eq "classify shared-bound inside"     "SLOW SLOW-IN-CONTROLLER"            "$(lat_classify 100 10 10 0 100 9 12)"
    _lat_eq "shared bound T=5"  "2.5" "$(lat_shared_bound 'count=10 1=5 2.5=6 10=9 25=10' 'count=10 1=5 2.5=6 5=8' 5)"
    _lat_eq "shared bound T=30" "2.5" "$(lat_shared_bound 'count=10 1=5 2.5=6 10=9 25=10' 'count=10 1=5 2.5=6 5=8' 30)"
    _lat_eq "shared bound T=1"  "1"   "$(lat_shared_bound 'count=10 1=5 2.5=6 10=9 25=10' 'count=10 1=5 2.5=6 5=8' 1)"
    _lat_eq "shared bound none" ""    "$(lat_shared_bound 'count=10 1=5' 'count=10 2.5=6' 0.5)"
    # pf_stop forgets the PID, so cleanup never signals a recycled PID.
    sleep 30 & local _p=$!
    PF_PIDS=" 1 $_p"; pf_stop "$_p"
    _lat_eq "pf_stop forgets the pid" " 1" "$PF_PIDS"
    PF_PIDS=""

    # Historical (lifetime) evidence never yields DROPPING/SLOW.
    _lat_eq "hist dropped" "DROPPED-HISTORICALLY 5 0.000050" "$(lat_hist_classify 5 100000 0 100000)"
    _lat_eq "hist slow" "HISTORICALLY-SLOW 0.020000" "$(lat_hist_classify 0 100000 2000 100000)"
    _lat_eq "hist both" "DROPPED-HISTORICALLY 5 0.000050
HISTORICALLY-SLOW 0.020000" "$(lat_hist_classify 5 100000 2000 100000)"
    _lat_eq "hist quiet" "" "$(lat_hist_classify 0 100000 10 100000)"
    _lat_eq "hist empty" "" "$(lat_hist_classify '' '' '' '')"

    # JSON flattening.
    flat="$(printf '%s' '{"status":"OK","version":"v2.2.0","capabilities":["A","ADMISSION_LATENCY_QUERY"],"admissionLatency":{"enabled":true,"windowMinutes":15,"endpoints":[{"endpoint":"/mutate/workload","count":3},{"endpoint":"/mutate/pod","count":120,"over1s":7,"windows":12}]},"db":{"driver":"pgx","note":"a \"q\" b","nothing":null}}' | json_flat)"
    _lat_eq "json_get string" "/mutate/pod" "$(json_get "$flat" '.admissionLatency.endpoints[1].endpoint')"
    _lat_eq "json_get number" "7" "$(json_get "$flat" '.admissionLatency.endpoints[1].over1s')"
    _lat_eq "json_get bool" "true" "$(json_get "$flat" '.admissionLatency.enabled')"
    _lat_eq "json_get escaped" 'a "q" b' "$(json_get "$flat" '.db.note')"
    _lat_eq "json_get null" "null" "$(json_get "$flat" '.db.nothing')"
    _lat_eq "json_get missing" "" "$(json_get "$flat" '.nope')"
    _lat_eq "json_index_of" "1" "$(json_index_of "$flat" '.admissionLatency.endpoints' endpoint /mutate/pod)"
    _lat_eq "json_index_of missing" "" "$(json_index_of "$flat" '.admissionLatency.endpoints' endpoint /mutate/x)"
    _lat_eq "json_array_has yes" "yes" "$(json_array_has "$flat" '.capabilities' ADMISSION_LATENCY_QUERY)"
    _lat_eq "json_array_has no" "no" "$(json_array_has "$flat" '.capabilities' NOPE)"

    # Garbage in: nothing aborts, nothing is invented.
    printf 'garbage {{{ not metrics\n\x01\x02 le="1"} x\n' > "$d/garbage"
    _lat_eq "garbage lat_hist" "" "$(lat_hist "$d/garbage" apiserver_admission_webhook_admission_duration_seconds '')"
    _lat_eq "missing file lat_hist" "" "$(lat_hist "$d/does-not-exist" x '')"
    _lat_eq "garbage json_flat survives" "ok" "$(printf 'not json {"a":' | json_flat >/dev/null 2>&1; echo ok)"
    _lat_eq "garbage lat_over" "none" "$(lat_over 'nonsense' 1)"

    rm -rf "$d"
    if [ "$_lat_fail" -eq 0 ]; then echo "latency lib self-test PASSED"; else echo "latency lib self-test FAILED"; fi
    return "$_lat_fail"
}

# ---------------------------------------------------------------------------
# Collection and reporting, shared by both scripts. Callers define these first:
#   NAMESPACE CONTROLLER_LABEL CONTROLLER_DEPLOY CONTROLLER_SVC CONTROLLER_PORT HEALTH_PATH
#   PF_METRICS_PORT DUR_METRIC STAGE_METRIC WINDOW DO_PF HAVE_CURL WORK
#   KUBECTL (bounded) KUBECTL_METRICS (long bound) KUBECTL_PF (unbounded, port-forward)
#   PF_PIDS (killed by the caller's EXIT trap), log(), note_missing()
# ---------------------------------------------------------------------------
# err_reason <kubectl output> -> short human reason for "unavailable: ..."
err_reason() {
    local lc
    lc="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$lc" in
        "")                                                       echo "empty response" ;;
        *forbidden*)                                              echo "forbidden (RBAC)" ;;
        *client.timeout*|*"deadline exceeded"*|*"timed out"*|*timeout*) echo "timed out" ;;
        *"no endpoints available"*|*"error trying to reach service"*) echo "controller not reachable through the API server" ;;
        *"connection refused"*|*"unable to connect"*|*"no route to host"*) echo "API server not reachable" ;;
        *"could not find the requested resource"*|*notfound*|*"not found"*) echo "not found (404 — endpoint absent in this version)" ;;
        *) printf '%s' "$1" | tr '\n' ' ' | cut -c1-110 ;;
    esac
}

# proxy_get <path> — GET on the controller's HTTPS service through the API-server proxy
proxy_get() {
    $KUBECTL get --raw "/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy$1"
}

# pf_start <target> <local-port> <remote-port> — background localhost port-forward; sets PF_PID
pf_start() {
    $KUBECTL_PF -n "$NAMESPACE" port-forward "$1" "$2:$3" >"$WORK/pf-$2.log" 2>&1 &
    PF_PID=$!; PF_PIDS="$PF_PIDS $PF_PID"
}
# pf_forget <pid> — drop a finished child from PF_PIDS so cleanup never signals a recycled PID
pf_forget() {
    local p keep=""
    for p in $PF_PIDS; do [ "$p" = "$1" ] || keep="$keep $p"; done
    PF_PIDS="$keep"
}
pf_stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; pf_forget "$1"; }

CAN_PF=""
can_portforward() {
    if [ -z "$CAN_PF" ]; then
        CAN_PF="no"
        if [ "$DO_PF" = "true" ] && [ "$HAVE_CURL" = "true" ] \
           && [ "$($KUBECTL auth can-i create pods/portforward -n "$NAMESPACE" 2>/dev/null)" = "yes" ]; then
            CAN_PF="yes"
        fi
    fi
    [ "$CAN_PF" = "yes" ]
}

# fmt_over <lat_over output> -> "20/100 (20.0%)", a labelled range, or n/a
fmt_over() {
    printf '%s\n' "${1:-none}" | awk '
        $1 == "exact" { printf "%s/%s (%s)\n", $2, $3, ($3 > 0) ? sprintf("%.1f%%", 100 * $2 / $3) : "-"; next }
        $1 == "range" { printf "%s-%s/%s (range: timeout is not a bucket bound)\n", $2, $3, $4; next }
        { print "n/a" }'
}
# over_lo / over_hi / over_count <lat_over output>
over_lo()    { printf '%s\n' "${1:-}" | awk '$1 == "exact" || $1 == "range" { print $2 }'; }
over_hi()    { printf '%s\n' "${1:-}" | awk '$1 == "exact" { print $2 } $1 == "range" { print $3 }'; }
over_count() { printf '%s\n' "${1:-}" | awk '$1 == "exact" { print $3 } $1 == "range" { print $4 }'; }
# hist_count <lat_hist line>
hist_count() { printf '%s\n' "${1:-}" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^count=/) { sub(/^count=/, "", $i); print $i } }'; }
# fmt_age <seconds> -> "3d4h" / "5h12m" / "42m"
fmt_age() {
    awk -v s="${1:-}" 'BEGIN { if (s !~ /^[0-9.]+$/) { print "?"; exit } s = int(s)
        if (s >= 86400) printf "%dd%dh\n", s / 86400, (s % 86400) / 3600
        else if (s >= 3600) printf "%dh%dm\n", s / 3600, (s % 3600) / 60
        else printf "%dm\n", s / 60 }'
}
# codes_by <file> <selector> -> "200=96 500=4" for apiserver_admission_webhook_request_total
codes_by() {
    local f="$1" sel="$2" c v out=""
    [ -r "$f" ] || return 0
    for c in $(awk -F'code="' 'index($0, "apiserver_admission_webhook_request_total{") == 1 && NF > 1 { split($2, a, "\""); print a[1] }' "$f" | sort -u); do
        v="$(lat_counter "$f" apiserver_admission_webhook_request_total "$sel code=$c")"
        [ -n "$v" ] && out="$out $c=$v"
    done
    printf '%s\n' "${out# }"
}
# fmt_hist <lat_hist_classify output> -> readable historical-evidence lines
fmt_hist() {
    printf '%s\n' "${1:-}" | awk '
        $1 == "DROPPED-HISTORICALLY" { printf "historical: DROPPED-HISTORICALLY — %s mutation(s) dropped since API-server start (%.2f%% of requests)\n", $2, 100 * $3 }
        $1 == "HISTORICALLY-SLOW"    { printf "historical: HISTORICALLY-SLOW — %.2f%% of calls over the timeout since API-server start\n", 100 * $2 }'
}

# list_webhooks <kind> -> "config|name|ns|svc|port|path|timeout|policy" per webhook entry
list_webhooks() {
    local raw
    raw="$($KUBECTL get "$1" -o jsonpath='{range .items[*]}{"#"}{.metadata.name}{"\n"}{range .webhooks[*]}{.name}{"|"}{.clientConfig.service.namespace}{"|"}{.clientConfig.service.name}{"|"}{.clientConfig.service.port}{"|"}{.clientConfig.service.path}{"|"}{.timeoutSeconds}{"|"}{.failurePolicy}{"\n"}{end}{end}' 2>&1)" \
        || { note_missing "$1" "$(err_reason "$raw")"; return 0; }
    printf '%s\n' "$raw" | awk '/^#/ { cfg = substr($0, 2); next } NF { print cfg "|" $0 }'
}

# discover_controller — controller pods, Service, Deployment settings, Sedai webhooks and the
# analysis rows ($WORK/rows: "id|webhook name|operation|controller webhook label|timeout|endpoints").
# The pod and kubeflow-spark webhooks share one name, so the API server merges their series.
# shellcheck disable=SC2034  # sets globals; each script reads a different subset
discover_controller() {
    CTRL_PODS=""; CTRL_POD=""; POD_IP=""; CTRL_ANY_POD=""; CTRL_ANY_PHASE=""
    pods_raw="$($KUBECTL -n "$NAMESPACE" get pods -l "$CONTROLLER_LABEL" -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{.status.phase}{"|"}{.status.podIP}{"\n"}{end}' 2>&1)" && pods_rc=0 || pods_rc=$?
    if [ "$pods_rc" -eq 0 ]; then
        CTRL_PODS="$(printf '%s\n' "$pods_raw" | awk -F'|' '$2 == "Running" { printf "%s ", $1 }')"
        CTRL_PODS="${CTRL_PODS% }"
        CTRL_POD="${CTRL_PODS%% *}"
        # Any-phase pod: a Pending/Failed controller still needs its describe and logs collected.
        CTRL_ANY_POD="$(printf '%s\n' "$pods_raw" | awk -F'|' 'NF >= 2 { print $1; exit }')"
        CTRL_ANY_PHASE="$(printf '%s\n' "$pods_raw" | awk -F'|' 'NF >= 2 { print $2; exit }')"
        POD_IP="$(printf '%s\n' "$pods_raw" | awk -F'|' -v p="$CTRL_POD" '$1 == p { print $3; exit }')"
    fi
    if [ -z "$CTRL_POD" ]; then
        if [ "$pods_rc" -eq 0 ]; then note_missing "controller pod" "no Running pod matching $CONTROLLER_LABEL in $NAMESPACE"
        else note_missing "controller pod" "$(err_reason "$pods_raw")"; fi
    fi
    CTRL_POD_COUNT="$(printf '%s\n' "$CTRL_PODS" | wc -w | tr -d ' ')"

    ENDPOINT_IP="$($KUBECTL -n "$NAMESPACE" get endpoints "$CONTROLLER_SVC" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)"
    svc_raw="$($KUBECTL -n "$NAMESPACE" get svc "$CONTROLLER_SVC" -o jsonpath='{.spec.clusterIP}|{.spec.ports[0].port}' 2>/dev/null || true)"
    CLUSTER_IP="${svc_raw%%|*}"; SVC_PORT="${svc_raw#*|}"; [ "$SVC_PORT" = "$svc_raw" ] && SVC_PORT=""

    dep_raw="$($KUBECTL -n "$NAMESPACE" get deploy "$CONTROLLER_DEPLOY" -o jsonpath='{.spec.template.spec.hostNetwork}|{.spec.template.spec.dnsPolicy}|{.spec.template.spec.containers[0].resources.limits.cpu}' 2>/dev/null)" || dep_raw=""
    HOSTNET="$(printf '%s' "$dep_raw" | cut -d'|' -f1)"; [ -z "$HOSTNET" ] && HOSTNET="false"
    [ -z "$dep_raw" ] && HOSTNET="?"
    CPU_LIMIT="$(printf '%s' "$dep_raw" | cut -d'|' -f3)"
    dep_env="$($KUBECTL -n "$NAMESPACE" get deploy "$CONTROLLER_DEPLOY" -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null || true)"
    HTTP_PORT="$(printf '%s\n' "$dep_env" | awk -F= '$1 == "SEDAI_KUBE_SPEC_CONTROLLER_HTTP_PORT" { print $2; exit }')"
    case "$HTTP_PORT" in ''|*[!0-9]*) HTTP_PORT=8080 ;; esac

    list_webhooks mutatingwebhookconfigurations   > "$WORK/wh.mutating"
    list_webhooks validatingwebhookconfigurations > "$WORK/wh.validating"
    # Webhooks served by this controller (mutating, service-based, in this namespace).
    awk -F'|' -v s="$CONTROLLER_SVC" -v n="$NAMESPACE" '$4 == s && $3 == n' "$WORK/wh.mutating" > "$WORK/wh.ctrl"

    local wh_port
    wh_port="$(awk -F'|' 'NF { print $5; exit }' "$WORK/wh.ctrl")"
    if [ -n "$wh_port" ]; then CONTROLLER_PORT="$wh_port"; elif [ -n "$SVC_PORT" ]; then CONTROLLER_PORT="$SVC_PORT"; fi
    WHPATH="$(awk -F'|' '$6 == "/mutate/pod" { print $6; exit }' "$WORK/wh.ctrl")"
    [ -z "$WHPATH" ] && WHPATH="$(awk -F'|' 'NF { print $6; exit }' "$WORK/wh.ctrl")"
    WHPOLICY="$(awk -F'|' -v p="$WHPATH" '$6 == p { print $8; exit }' "$WORK/wh.ctrl")"
    [ -s "$WORK/wh.ctrl" ] || note_missing "Sedai webhooks" "no mutating webhook targets $NAMESPACE/$CONTROLLER_SVC"

    # Analysis rows: "id|webhook name|operation filter|controller webhook label|timeout|endpoints".
    # The pod and kubeflow-spark webhooks share one name, so the API server merges their series.
    awk -F'|' '
        { to = ($7 == "") ? 10 : $7 }
        $6 == "/mutate/pod"            { pn = $2; pt = to; next }
        $6 == "/mutate/kubeflow-spark" { sn = $2; st = to; next }
        $6 == "/mutate/workload"       { wn = $2; wt = to; next }
        NF                             { o[++no] = $6 "|" $2 "|||" to "|" $6 }
        END {
            if (pn != "" && sn == pn) {
                print "pod+spark|" pn "||pod|" pt "|/mutate/pod /mutate/kubeflow-spark"
                print "spark-update|" sn "|UPDATE||" st "|/mutate/kubeflow-spark"
            } else {
                if (pn != "") print "pod|" pn "||pod|" pt "|/mutate/pod"
                if (sn != "") print "spark|" sn "|||" st "|/mutate/kubeflow-spark"
            }
            if (wn != "") print "workload|" wn "||workload|" wt "|/mutate/workload"
            for (i = 1; i <= no; i++) print o[i]
        }' "$WORK/wh.ctrl" > "$WORK/rows"
    HOSTNET_FIX=""
    [ "$HOSTNET" = "false" ] && HOSTNET_FIX=" Fix: run the controller on the host network (Helm value sedaiPodInterceptor.isHostAddress=true -> hostNetwork: true)."
}

# fetch_api_metrics <out> — admission-webhook series + process start time only
fetch_api_metrics() {
    if $KUBECTL_METRICS get --raw /metrics > "$WORK/api.raw" 2> "$WORK/api.err"; then
        grep -E '^(apiserver_admission_webhook_|process_start_time_seconds)' "$WORK/api.raw" > "$1"
        rm -f "$WORK/api.raw"
        if ! grep -q '^apiserver_admission_webhook_' "$1"; then
            API_ERR="API-server /metrics has no admission-webhook series"; return 1
        fi
        grep -q '^apiserver_admission_webhook_fail_open_count' "$1" \
            || note_missing "API-server fail-open counter" "absent (Kubernetes < 1.24)"
        return 0
    fi
    API_ERR="$(err_reason "$(cat "$WORK/api.err")")"
    case "$API_ERR" in "timed out") API_ERR="timed out (API-server /metrics too large/slow)" ;; esac
    rm -f "$WORK/api.raw" "$1"; return 1
}

# ctrl_metrics_fetch <out> — every Running controller pod's /metrics, concatenated
# (series then sum across replicas). Pod proxy first, then a port-forward.
ctrl_metrics_fetch() {
    local out="$1" pod got=0 m i=0 w why
    : > "$out"
    [ -n "$CTRL_PODS" ] || { CTRL_ERR="no Running controller pod"; return 1; }
    for pod in $CTRL_PODS; do
        m=""; why=""
        if [ "$CTRL_METHOD" != "port-forward" ]; then
            if $KUBECTL get --raw "/api/v1/namespaces/${NAMESPACE}/pods/http:${pod}:${HTTP_PORT}/proxy/metrics" > "$WORK/cm.tmp" 2> "$WORK/cm.err" \
               && grep -q '^[a-z_]' "$WORK/cm.tmp"; then
                m="pod-proxy"
            else
                why="pod proxy: $(err_reason "$(cat "$WORK/cm.err")")"
            fi
        fi
        if [ -z "$m" ] && [ "$CTRL_METHOD" != "pod-proxy" ]; then
            if can_portforward; then
                i=$((i + 1)); pf_start "pod/$pod" "$((PF_METRICS_PORT + i))" "$HTTP_PORT"
                w=0
                while [ "$w" -lt 10 ]; do
                    sleep 1; w=$((w + 1))
                    if curl -s --max-time 5 "http://127.0.0.1:$((PF_METRICS_PORT + i))/metrics" > "$WORK/cm.tmp" 2>/dev/null \
                       && grep -q '^[a-z_]' "$WORK/cm.tmp"; then m="port-forward"; break; fi
                done
                pf_stop "$PF_PID"
                [ -z "$m" ] && why="$why; port-forward: no /metrics answer within 10s"
            else
                why="$why; port-forward: not attempted (disabled, no curl, or no pods/portforward RBAC)"
            fi
        fi
        if [ -n "$m" ]; then cat "$WORK/cm.tmp" >> "$out"; got=1; CTRL_METHOD="$m"; else CTRL_ERR="${why#; }"; fi
    done
    [ "$got" -eq 1 ]
}

# collect_reading <n>
collect_reading() {
    local n="$1" hout hrc
    fetch_api_metrics "$WORK/api.$n" || true
    ctrl_metrics_fetch "$WORK/ctrl.$n" || rm -f "$WORK/ctrl.$n"
    hout="$(proxy_get "$HEALTH_PATH" 2>&1)" && hrc=0 || hrc=$?
    if [ "$n" -eq 1 ]; then PROXY_HEALTH="$hout"; PROXY_HEALTH_RC="$hrc"; fi
    if [ "$hrc" -eq 0 ]; then printf '%s' "$hout" | json_flat > "$WORK/health.$n"; else HEALTH_ERR="$(err_reason "$hout")"; fi
    eval "READ_T$n=$(date +%s)"
}

# take_first_reading — reading 1 alone, so a caller can do other work during the window
take_first_reading() {
    API_ERR=""; CTRL_ERR=""; CTRL_METHOD=""; HEALTH_ERR=""
    PROXY_HEALTH=""; PROXY_HEALTH_RC=1
    READ_T1=0; READ_T2=0
    log "Reading 1: API-server metrics, controller metrics, controller health..."
    collect_reading 1
}

# take_readings — reading 1 (unless take_first_reading ran), wait out --window, reading 2; validates both windows
# (API-server instance fingerprint with retries, controller restart) and sets the
# lifetime files (API_L, CTRL_L, HEALTH_L), HFLAT, CTRL_VERSION, HAS_STAGE and uptimes.
take_readings() {
    local rem
    [ "${READ_T1:-0}" -gt 0 ] || take_first_reading
    LAST=1; WIN_API="no"; WIN_CTRL="no"; API_WIN_REASON="--window 0 (lifetime only)"; CTRL_WIN_REASON="$API_WIN_REASON"
    if [ "$WINDOW" -gt 0 ]; then
        rem=$((WINDOW - ($(date +%s) - READ_T1)))
        if [ "$rem" -gt 0 ]; then
            log "Waiting ${rem}s for the second reading (Ctrl-C is safe)..."
            # Backgrounded so a trapped INT/TERM interrupts the wait instead of queueing behind sleep.
            local sp
            sleep "$rem" & sp=$!; PF_PIDS="$PF_PIDS $sp"
            wait "$sp"; pf_forget "$sp"
        fi
        log "Reading 2..."
        collect_reading 2
        LAST=2
        API_WIN_REASON=""; CTRL_WIN_REASON=""
        if [ -s "$WORK/api.1" ] && [ -s "$WORK/api.2" ]; then
            local fp1 tries
            fp1="$(lat_counter "$WORK/api.1" process_start_time_seconds '')"
            tries=0
            while [ "$(lat_counter "$WORK/api.2" process_start_time_seconds '')" != "$fp1" ] && [ "$tries" -lt "$LAT_HAPI_RETRIES" ]; do
                tries=$((tries + 1)); fetch_api_metrics "$WORK/api.2" || break
            done
            if [ "$(lat_counter "$WORK/api.2" process_start_time_seconds '')" = "$fp1" ]; then WIN_API="yes"
            else API_WIN_REASON="readings came from different API-server instances (HA control plane) or it restarted"; fi
        else
            API_WIN_REASON="API-server metrics unavailable${API_ERR:+: $API_ERR}"
        fi
        if [ -s "$WORK/ctrl.1" ] && [ -s "$WORK/ctrl.2" ]; then
            if [ "$(lat_counter "$WORK/ctrl.1" process_start_time_seconds '')" = "$(lat_counter "$WORK/ctrl.2" process_start_time_seconds '')" ]; then WIN_CTRL="yes"
            else CTRL_WIN_REASON="controller restarted during the window"; fi
        else
            CTRL_WIN_REASON="controller metrics unavailable${CTRL_ERR:+: $CTRL_ERR}"
        fi
    fi
    ELAPSED=$((READ_T2 - READ_T1)); [ "$ELAPSED" -le 0 ] && ELAPSED=1
    [ "$WIN_API" = "yes" ] || note_missing "API-server window" "${API_WIN_REASON:-unavailable}"
    [ "$WIN_CTRL" = "yes" ] || note_missing "controller window" "${CTRL_WIN_REASON:-unavailable}"
    [ -s "$WORK/api.$LAST" ] || [ -s "$WORK/api.1" ] || note_missing "API-server /metrics" "${API_ERR:-unavailable}"
    [ -s "$WORK/ctrl.1" ] || note_missing "controller /metrics" "${CTRL_ERR:-unavailable}"
    [ -s "$WORK/health.1" ] || note_missing "controller /sedai/health" "${HEALTH_ERR:-unavailable}"
    API_L="$WORK/api.$LAST"; [ -s "$API_L" ] || API_L="$WORK/api.1"
    CTRL_L="$WORK/ctrl.$LAST"; [ -s "$CTRL_L" ] || CTRL_L="$WORK/ctrl.1"
    HEALTH_L="$WORK/health.$LAST"; [ -s "$HEALTH_L" ] || HEALTH_L="$WORK/health.1"
    HFLAT=""; [ -s "$HEALTH_L" ] && HFLAT="$(cat "$HEALTH_L")"
    CTRL_VERSION="$(json_get "$HFLAT" '.version')"
    HAS_STAGE="no"; [ -s "$CTRL_L" ] && grep -q "^${STAGE_METRIC}_count" "$CTRL_L" && HAS_STAGE="yes"
    [ -s "$CTRL_L" ] && [ "$HAS_STAGE" = "no" ] && note_missing "controller latency metrics" "controller ${CTRL_VERSION:-version ?} predates them (need v2.0.6+ on 2.0, or v2.2.0+)"
    NOW=$(date +%s)
    API_UP="$(lat_counter "$API_L" process_start_time_seconds '')"; API_AGE="?"; [ -n "$API_UP" ] && API_AGE="$(fmt_age "$(awk -v n="$NOW" -v s="$API_UP" 'BEGIN { print n - s }')")"
    CTRL_UP="$(lat_counter "$CTRL_L" process_start_time_seconds '')"; CTRL_AGE="?"
    [ -n "$CTRL_UP" ] && CTRL_AGE="$(fmt_age "$(awk -v n="$NOW" -v s="$CTRL_UP" -v c="${CTRL_POD_COUNT:-1}" 'BEGIN { if (c < 1) c = 1; print n - s / c }')")"
}

# classify_proxy <output> <rc> -> REACHABLE | TIMEOUT | TLS-ERROR | DIAL-FAILED | NO-SERVICE | RBAC-DENIED | UNKNOWN
classify_proxy() {
    local lc
    lc="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$lc" in *forbidden*) echo "RBAC-DENIED"; return ;; esac
    case "$lc" in *client.timeout*|*"context deadline exceeded"*|*"request canceled"*|*"unable to return a response in the time allotted"*) echo "TIMEOUT"; return ;; esac
    case "$lc" in *x509*|*"tls:"*|*"certificate"*) echo "TLS-ERROR"; return ;; esac
    case "$lc" in *"error trying to reach service"*|*"address is not allowed"*|*"no endpoints available"*|*"connection refused"*|*"no route to host"*|*"i/o timeout"*|*serviceunavailable*|*"timed out"*) echo "DIAL-FAILED"; return ;; esac
    case "$lc" in *"services \""*"not found"*) echo "NO-SERVICE"; return ;; esac
    if [ "${2:-1}" -eq 0 ]; then echo "REACHABLE"; return; fi
    case "$lc" in *"error from server (methodnotallowed)"*|*"error from server (notfound)"*|*"error from server (badrequest)"*|*"method not allowed"*) echo "REACHABLE"; return ;; esac
    echo "UNKNOWN"
}

# analyze_row <id> <webhook name> <operation> <controller label> <timeout> — appends the row's
# API-server view ($WORK/s13), controller view ($WORK/s14), SIGNALS line ($WORK/sig),
# verdict line ($WORK/vl) and "id|class" ($WORK/classes).
analyze_row() {
    local id="$1" name="$2" op="$3" ctrl="$4" to="$5"
    local sel fsel a1 a2 aw al ao al_o fo1 fo2 fow fol c1 c2 cw cl co cl_o class basis hist ctrl_note line s best bestn n
    sel="name=$name type=admit"; [ -n "$op" ] && sel="$sel operation=$op"
    fsel="name=$name type=admit"

    a1="$(lat_hist "$WORK/api.1" "$DUR_METRIC" "$sel")"
    al="$(lat_hist "$API_L" "$DUR_METRIC" "$sel")"
    aw=""; [ "$WIN_API" = "yes" ] && { a2="$(lat_hist "$WORK/api.2" "$DUR_METRIC" "$sel")"; aw="$(lat_hist_delta "$a1" "$a2")"; }
    [ "$aw" = "reset" ] && aw=""
    ao="$(lat_over "$aw" "$to")"; al_o="$(lat_over "$al" "$to")"
    fo1=""; fo2=""; fow=""; fol=""
    if [ -z "$op" ]; then
        fo1="$(lat_counter "$WORK/api.1" apiserver_admission_webhook_fail_open_count "$fsel")"
        fol="$(lat_counter "$API_L" apiserver_admission_webhook_fail_open_count "$fsel")"
        [ "$WIN_API" = "yes" ] && { fo2="$(lat_counter "$WORK/api.2" apiserver_admission_webhook_fail_open_count "$fsel")"; fow="$(lat_num_delta "$fo1" "$fo2")"; }
        [ "$fow" = "reset" ] && fow=""
        [ -z "$fol" ] && [ -n "$al" ] && fol="0"
    fi

    c1=""; c2=""; cw=""; cl=""
    if [ -n "$ctrl" ] && [ "$HAS_STAGE" = "yes" ]; then
        c1="$(lat_hist "$WORK/ctrl.1" "$STAGE_METRIC" "webhook=$ctrl stage=total")"
        cl="$(lat_hist "$CTRL_L" "$STAGE_METRIC" "webhook=$ctrl stage=total")"
        [ "$WIN_CTRL" = "yes" ] && { c2="$(lat_hist "$WORK/ctrl.2" "$STAGE_METRIC" "webhook=$ctrl stage=total")"; cw="$(lat_hist_delta "$c1" "$c2")"; }
        [ "$cw" = "reset" ] && cw=""
    fi
    co="$(lat_over "$cw" "$to")"; cl_o="$(lat_over "$cl" "$to")"

    # Current-state class: window deltas only.
    if [ -n "$aw" ]; then
        # Inside vs outside compares the two sides at a bucket bound both share (<= timeout).
        local tb as cs
        tb="$(lat_shared_bound "$aw" "$cw" "$to")"; as=""; cs="$(over_lo "$co")"
        if [ -n "$tb" ]; then as="$(over_lo "$(lat_over "$aw" "$tb")")"; cs="$(over_lo "$(lat_over "$cw" "$tb")")"; fi
        class="$(lat_classify "$(hist_count "$aw")" "$(over_lo "$ao")" "$(over_hi "$ao")" "$fow" "$(over_count "$co")" "$cs" "$as")"
        basis="window ${ELAPSED}s"
    elif [ -n "$cw" ]; then
        # The controller alone cannot see dropped or never-delivered calls: only a slow
        # controller is a finding here, never an all-clear.
        class="$(lat_classify "$(hist_count "$cw")" "$(over_lo "$co")" "$(over_hi "$co")" "" "" "")"
        case "$class" in SLOW*) class="SLOW SLOW-IN-CONTROLLER" ;; *) class="INSUFFICIENT-WINDOW" ;; esac
        basis="controller window only (API-server view: ${API_WIN_REASON:-unavailable})"
    elif [ -n "$al" ] || [ -n "$cl" ]; then
        class="INSUFFICIENT-WINDOW"; basis="no window: ${API_WIN_REASON:-unavailable}"
    else
        class="UNKNOWN"; basis="no latency data: ${API_ERR:-API-server metrics unavailable}"
    fi
    hist="$(lat_hist_classify "$fol" "$(lat_counter "$API_L" apiserver_admission_webhook_request_total "$fsel")" "$(over_hi "$al_o")" "$(over_count "$al_o")")"

    # Section 13 — API-server view.
    {
        echo "--- $id (webhook $name${op:+, operation=$op}, timeout ${to}s) ---"
        if [ -z "$al" ]; then
            echo "unavailable: ${API_ERR:-no series for this webhook}"
        else
            if [ -z "$op" ]; then
                echo "fail-open (dropped mutations): window ${fow:-n/a} | lifetime ${fol:-n/a} (this API-server instance, up ${API_AGE}; ~1/n of traffic on HA control planes)"
            else
                echo "fail-open: shared with the merged pod+spark row (the counter has no operation label)"
            fi
            echo "calls over timeout (${to}s): window $(fmt_over "$ao") | lifetime $(fmt_over "$al_o")"
            echo "responses by code: lifetime $(codes_by "$API_L" "$sel")"
            [ -n "$hist" ] && fmt_hist "$hist"
        fi
        echo
    } >> "$WORK/s13"

    # Section 14 — controller view for this row.
    {
        echo "--- $id (controller webhook label: ${ctrl:-none}) ---"
        if [ -z "$ctrl" ]; then
            echo "no controller stage timing for this webhook (kubeflow-spark/legacy are not recorded); see the handler view below"
        elif [ "$HAS_STAGE" != "yes" ]; then
            echo "controller-side breakdown unavailable: ${CTRL_ERR:-controller ${CTRL_VERSION:-?} predates latency metrics}"
        else
            ctrl_note=""; [ "$ctrl" = "workload" ] && ctrl_note=" (timed subset: excludes HPA writes, DELETE, dry-run)"
            [ "$id" = "pod+spark" ] && ctrl_note=" (timed subset: pod only; spark is not stage-timed)"
            echo "total over timeout (${to}s)${ctrl_note}: window $(fmt_over "$co") | lifetime $(fmt_over "$cl_o")"
            best=""; bestn=-1; line=""
            for s in owner_resolve layer_read stale_write; do
                local h1 h2 hw
                h1="$(lat_hist "$WORK/ctrl.1" "$STAGE_METRIC" "webhook=$ctrl stage=$s")"
                h2="$(lat_hist "$CTRL_L" "$STAGE_METRIC" "webhook=$ctrl stage=$s")"
                [ -z "$h2" ] && continue
                if [ "$WIN_CTRL" = "yes" ]; then hw="$(lat_hist_delta "$h1" "$h2")"; else hw="$h2"; fi
                case "$hw" in ""|reset) continue ;; esac
                n="$(over_lo "$(lat_over "$hw" 0.25)")"
                line="$line  $s $(fmt_over "$(lat_over "$hw" 0.25)")"
                if [ -n "$n" ] && awk -v a="$n" -v b="$bestn" 'BEGIN { exit !(a > b) }'; then best="$s"; bestn="$n"; fi
            done
            echo "stages, calls over 0.25s ($([ "$WIN_CTRL" = "yes" ] && echo window || echo lifetime)):${line:- n/a}"
            if [ -n "$best" ] && awk -v a="$bestn" 'BEGIN { exit !(a > 0) }'; then
                case "$best" in
                    owner_resolve) echo "dominant stage: owner_resolve (Kube API owner lookups)" ;;
                    layer_read)    echo "dominant stage: layer_read (DB / cache read of the stored config)" ;;
                    *)             echo "dominant stage: $best" ;;
                esac
            else
                echo "dominant stage: none (no stage over 0.25s)"
            fi
            local m1 m2 mw
            m1="$(lat_hist "$WORK/ctrl.1" "$STAGE_METRIC" "webhook=$ctrl stage=total managed=true")"
            m2="$(lat_hist "$CTRL_L" "$STAGE_METRIC" "webhook=$ctrl stage=total managed=true")"
            if [ "$WIN_CTRL" = "yes" ]; then mw="$(lat_hist_delta "$m1" "$m2")"; else mw="$m2"; fi
            [ -n "$mw" ] && [ "$mw" != "reset" ] && echo "managed (Sedai-optimised) workloads only, over timeout: $(fmt_over "$(lat_over "$mw" "$to")")"
        fi
        echo
    } >> "$WORK/s14"

    printf '%s|%s|%s|%s|%s|%s\n' "$id" "$class" "$to" "$(fmt_over "$ao")" "${fow:-n/a}" "$(fmt_hist "$hist" | sed 's/^historical: //' | tr '\n' ';')" >> "$WORK/classes"
    printf '%-42s %s\n' "row $id (timeout ${to}s)" "$class | over-timeout $(fmt_over "$ao") | fail-open window ${fow:-n/a} | basis: $basis" >> "$WORK/sig"

    case "$class" in
        "DROPPING NEVER-REACHED-CONTROLLER")
            echo "$id: DROPPING — ${fow} mutation(s) dropped in the window, and the failed calls returned before the ${to}s timeout: they never reached the controller (intermittent unreachability).${HOSTNET_FIX}" ;;
        "DROPPING CAUSE-INDETERMINATE")
            echo "$id: DROPPING — ${fow} mutation(s) dropped in the window. The ${to}s timeout falls between histogram buckets, so it cannot be told whether they timed out ($(fmt_over "$ao") over ${to}s) or never reached the controller. Check section 14 and the reachability verdict." ;;
        DROPPING*SLOW-IN-CONTROLLER|SLOW*SLOW-IN-CONTROLLER)
            echo "$id: ${class%% *}$([ -n "$fow" ] && [ "$fow" != "0" ] && printf ' (%s mutation(s) dropped in the window)' "$fow") — the controller itself is slow: $(fmt_over "$co") of its timed calls exceed ${to}s. See the dominant stage in section 14. Fix the controller-side cost; raising timeoutSeconds (max 30) only buys headroom." ;;
        DROPPING*SLOW-OUTSIDE-CONTROLLER|SLOW*SLOW-OUTSIDE-CONTROLLER)
            echo "$id: ${class%% *}$([ -n "$fow" ] && [ "$fow" != "0" ] && printf ' (%s mutation(s) dropped in the window)' "$fow") — the API server sees $(fmt_over "$ao") calls over ${to}s, but the controller's timed path is fast: the time is spent outside it (network/TLS/API server, or an untimed path: decode, HPA writes, workload DELETE)." ;;
        DROPPING*|SLOW*)
            echo "$id: $class — the API server sees $(fmt_over "$ao") calls over ${to}s; controller-side breakdown unavailable (${CTRL_ERR:-${CTRL_WIN_REASON:-see section 14}})." ;;
        POSSIBLY-SLOW)
            echo "$id: POSSIBLY-SLOW — between $(over_lo "$ao") and $(over_hi "$ao") calls may exceed ${to}s (the timeout is not a histogram bucket bound)." ;;
        OK)
            if [ -n "$fow" ]; then echo "$id: OK — no dropped mutations and no calls over ${to}s in the window."
            elif [ -n "$op" ]; then echo "$id: OK — no calls over ${to}s in the window (fail-open not measured for this row: shared with the merged pod+spark row)."
            else echo "$id: OK — no calls over ${to}s in the window (fail-open not measured: the API server exposes no fail-open counter, Kubernetes < 1.24)."; fi ;;
        NO-TRAFFIC)  echo "$id: NO-TRAFFIC — no admissions in the window." ;;
        INSUFFICIENT-WINDOW)
            echo "$id: INSUFFICIENT-WINDOW — too few calls in the window (or none: $basis).$( [ -n "$hist" ] && printf ' Historical evidence: %s' "$(fmt_hist "$hist" | sed 's/^historical: //' | tr '\n' ';')")" ;;
        *)           echo "$id: $class — $basis" ;;
    esac >> "$WORK/vl"
}

# analyze_rows — analyse every row in $WORK/rows
analyze_rows() {
    : > "$WORK/s13"; : > "$WORK/s14"; : > "$WORK/sig"; : > "$WORK/vl"; : > "$WORK/classes"
    while IFS="|" read -r r_id r_name r_op r_ctrl r_to _; do
        [ -n "$r_id" ] || continue
        log "Analysing webhook row $r_id..."
        analyze_row "$r_id" "$r_name" "$r_op" "$r_ctrl" "$r_to"
    done < "$WORK/rows"
    [ -s "$WORK/rows" ] || echo "no Sedai webhook rows to analyse (no mutating webhook targets $NAMESPACE/$CONTROLLER_SVC)" >> "$WORK/vl"
}

# render_api_view — section body: API-server view per webhook row
render_api_view() {
    echo "Window = reading 2 minus reading 1 (${WINDOW}s apart); lifetime = the last reading."
    echo "fail-open counts calls the API server gave up on (timeout or dial error) and admitted"
    echo "UNPATCHED because failurePolicy=Ignore — the direct count of dropped mutations."
    [ "$WIN_API" = "yes" ] || echo "window: unavailable: ${API_WIN_REASON:-?}"
    [ -n "$API_ERR" ] && [ ! -s "$WORK/api.1" ] && echo "API-server /metrics unavailable: ${API_ERR}"
    echo
    cat "$WORK/s13"
    rej="$(lat_counter "$API_L" apiserver_admission_webhook_rejection_count '')"
    echo "rejections (informational; for Ignore webhooks only deliberate denials, e.g. the HPA-DELETE guard): ${rej:-n/a}"
}

# render_ctrl_view — section body: controller stage, backends, handler summary, 24h history
render_ctrl_view() {
    echo "controller metrics: ${CTRL_METHOD:-unavailable: ${CTRL_ERR:-?}}  (pods: ${CTRL_PODS:-none}; HTTP metrics port ${HTTP_PORT})"
    [ "${CTRL_POD_COUNT:-0}" -gt 1 ] && echo "WARNING: ${CTRL_POD_COUNT} controller replicas (single-replica by design); series are summed"
    echo "controller version: ${CTRL_VERSION:-?}   up ${CTRL_AGE}   window: $([ "$WIN_CTRL" = "yes" ] && echo "${ELAPSED}s" || echo "unavailable: ${CTRL_WIN_REASON:-?}")"
    echo "Stage timing is measured inside admit: it excludes dry-run, HTTP decode/encode and, for"
    echo "workload, DELETE and all HPA writes — its count is a subset of the API server's."
    echo
    cat "$WORK/s14"
    if [ -s "$CTRL_L" ]; then
        echo "--- backends (source=\"admission\" only; background writers excluded) ---"
        for spec in "DB queries|sedai_pi_db_query_duration_seconds" "Kube API calls|sedai_pi_kube_api_request_duration_seconds"; do
            lbl="${spec%%|*}"; met="${spec#*|}"
            b1="$(lat_hist "$WORK/ctrl.1" "$met" 'source=admission')"; b2="$(lat_hist "$CTRL_L" "$met" 'source=admission')"
            if [ "$WIN_CTRL" = "yes" ]; then bw="$(lat_hist_delta "$b1" "$b2")"; bl="window"; else bw="$b2"; bl="lifetime"; fi
            case "$bw" in ""|reset) echo "$lbl: n/a" ;; *) echo "$lbl ($bl): over 0.25s $(fmt_over "$(lat_over "$bw" 0.25)"), over 1s $(fmt_over "$(lat_over "$bw" 1)")" ;; esac
        done
        w1="$(lat_counter "$WORK/ctrl.1" sedai_pi_db_connection_wait_seconds_total '')"; w2="$(lat_counter "$CTRL_L" sedai_pi_db_connection_wait_seconds_total '')"
        n1="$(lat_counter "$WORK/ctrl.1" sedai_pi_db_connection_waits_total '')"; n2="$(lat_counter "$CTRL_L" sedai_pi_db_connection_waits_total '')"
        if [ "$WIN_CTRL" = "yes" ]; then
            echo "DB pool waits (window): $(lat_num_delta "$n1" "$n2") waits, $(lat_num_delta "$w1" "$w2")s blocked"
            cpu="$(lat_num_delta "$(lat_counter "$WORK/ctrl.1" process_cpu_seconds_total '')" "$(lat_counter "$CTRL_L" process_cpu_seconds_total '')")"
            echo "CPU (window): $(awk -v c="$cpu" -v e="$ELAPSED" 'BEGIN { if (c ~ /^[0-9.]+$/) printf "%.2f cores", c / e; else print "n/a" }') used vs limit ${CPU_LIMIT:-none}"
        else
            echo "DB pool waits (lifetime): ${n2:-n/a} waits, ${w2:-n/a}s blocked"
        fi
        if [ -n "$CTRL_POD" ]; then
            rs="$($KUBECTL -n "$NAMESPACE" get pod "$CTRL_POD" -o jsonpath='{range .status.containerStatuses[*]}{.name}{"|"}{.restartCount}{"|"}{.lastState.terminated.reason}{"\n"}{end}' 2>/dev/null || true)"
            printf '%s\n' "$rs" | awk -F'|' 'NF { printf "container %s: restarts=%s last-termination=%s\n", $1, $2, ($3 == "" ? "-" : $3) }'
        fi
        echo
    fi
    echo "--- controller handler view (/sedai/health admissionLatency; v2.2.0+) ---"
    if [ -z "$HFLAT" ]; then
        echo "unavailable: ${HEALTH_ERR:-health not reachable}"
    elif [ -z "$(json_get "$HFLAT" '.admissionLatency.enabled')" ]; then
        echo "unavailable: controller ${CTRL_VERSION:-?} predates the handler latency summary (v2.2.0+)"
    elif [ "$(json_get "$HFLAT" '.admissionLatency.enabled')" != "true" ]; then
        echo "unavailable: admission_latency.enabled=false"
    else
        for ep in $(printf '%s\n' "$HFLAT" | awk -F'\t' '$1 ~ /^\.admissionLatency\.endpoints\[[0-9]+\]\.endpoint$/ { print $2 }'); do
            i="$(json_index_of "$HFLAT" '.admissionLatency.endpoints' endpoint "$ep")"
            g() { json_get "$HFLAT" ".admissionLatency.endpoints[$i].$1"; }
            echo "$ep (handler, last $(g windows) retired minutes): $(g count) calls, >=1s $(g over1s), >=5s $(g over5s), worst p99 $(awk -v u="$(g worstP99Us)" 'BEGIN { printf "%.0fms", u / 1000 }'), max $(awk -v u="$(g maxUs)" 'BEGIN { printf "%.0fms", u / 1000 }')"
        done
    fi
    echo
    echo "--- 24h history (/sedai/admission-latency, hourly; v2.2.0+) ---"
    if [ -z "$HFLAT" ]; then
        echo "unavailable: ${HEALTH_ERR:-controller health not reachable} (capabilities unknown)"
    elif [ "$(json_array_has "$HFLAT" '.capabilities' ADMISSION_LATENCY_QUERY)" != "yes" ]; then
        echo "unavailable: controller ${CTRL_VERSION:-?} does not advertise ADMISSION_LATENCY_QUERY"
    else
        now_ms=$(( $(date +%s) * 1000 ))
        for ep in $(cut -d'|' -f6 "$WORK/rows" | tr ' ' '\n' | sort -u); do
            hout="$(proxy_get "/sedai/admission-latency?from=$((now_ms - 86400000))&to=${now_ms}&step=3600&endpoint=${ep}" 2>&1)" \
                || { echo "$ep: unavailable: $(err_reason "$hout")"; continue; }
            printf '%s' "$hout" | json_flat | awk -F'\t' -v ep="$ep" '
                $1 == ".result.toMillis" { to = $2 }
                match($1, /^\.result\.series\[[0-9]+\]/) {
                    si = substr($1, 16, RLENGTH - 16); rest = substr($1, RLENGTH + 1)
                    if (rest == ".endpoint") E[si] = $2
                    if (match(rest, /^\.points\[[0-9]+\]\./)) {
                        pi = substr(rest, 9, RLENGTH - 10); f = substr(rest, RLENGTH + 1)
                        V[si, pi, f] = $2; if (!((si, pi) in P)) { P[si, pi] = 1; np[si]++ ; PL[si, np[si]] = pi }
                    }
                }
                END {
                    for (s in E) if (E[s] == ep) for (j = 1; j <= np[s]; j++) {
                        p = PL[s, j]; t = V[s, p, "tMillis"]
                        if (!(t in C)) { nt++; T[nt] = t }
                        C[t] += V[s, p, "count"]; O1[t] += V[s, p, "over1s"]; O5[t] += V[s, p, "over5s"]
                        if (V[s, p, "p99Us"] + 0 > MX[t] + 0) MX[t] = V[s, p, "p99Us"]
                    }
                    if (nt == 0) { print ep ": no admissions recorded in the last 24h"; exit }
                    for (i = 2; i <= nt; i++) { x = T[i]; k = i - 1; while (k >= 1 && T[k] + 0 > x + 0) { T[k + 1] = T[k]; k-- } T[k + 1] = x }
                    print ep ":"
                    printf "  %-8s %8s %8s %8s %10s\n", "HOUR", "CALLS", ">=1s", ">=5s", "P99"
                    for (i = 1; i <= nt; i++) { t = T[i]
                        printf "  %-8s %8d %8d %8d %8.0fms\n", sprintf("%dh ago", (to - t) / 3600000), C[t], O1[t], O5[t], MX[t] / 1000 }
                }'
        done
    fi
}

# render_slow_admissions — section body: instrumentation setting and the slow-admission buffer
render_slow_admissions() {
    sout="$(proxy_get /sedai/settings 2>&1)" && srcd=0 || srcd=$?
    if [ "$srcd" -eq 0 ]; then
        sflat="$(printf '%s' "$sout" | json_flat)"
        si="$(json_index_of "$sflat" '' key instrumentation.enabled)"
        INSTR="${si:+$(json_get "$sflat" "[$si].value")}"
        echo "instrumentation.enabled = ${INSTR:-?}"
    else
        INSTR=""; echo "settings: unavailable: $(err_reason "$sout")"
    fi
    aout="$(proxy_get /sedai/instrumentation/slow-admissions 2>&1)" && arc=0 || arc=$?
    if [ "$arc" -ne 0 ]; then
        case "$(err_reason "$aout")" in
            not\ found*) echo "unavailable: controller ${CTRL_VERSION:-?} predates slow-admission tracking (v2.0.6+ on 2.0, or v2.2.0+)" ;;
            *)           echo "unavailable: $(err_reason "$aout")" ;;
        esac
    else
        aflat="$(printf '%s' "$aout" | json_flat)"
        if [ "$(json_get "$aflat" '.enabled')" != "true" ]; then
            echo "instrumentation.enabled=false — enable it (PUT /sedai/settings {\"instrumentation.enabled\": true}) and re-run to see which pods/owners are slow."
        else
            echo "admissions slower than $(json_get "$aflat" '.thresholdMs')ms, newest first (controller keeps the last 100):"
            printf '%s\n' "$aflat" | awk -F'\t' '
                match($1, /^\.entries\[[0-9]+\]\./) { i = substr($1, 10, RLENGTH - 11) + 0; f = substr($1, RLENGTH + 1); V[i, f] = $2; if (i + 1 > n) n = i + 1 }
                END {
                    printf "  %-20s %-9s %-40s %-32s %9s %5s %4s %s\n", "TIME", "WEBHOOK", "NAMESPACE/POD", "OWNER", "MS", "KUBE", "DB", "SERVED_BY"
                    for (i = 0; i < n && i < 20; i++) {
                        pod = (V[i, "name"] != "") ? V[i, "name"] : V[i, "generateName"] "*"
                        printf "  %-20s %-9s %-40s %-32s %9.1f %5s %4s %s\n", V[i, "time"], V[i, "webhook"], V[i, "namespace"] "/" pod, V[i, "ownerKind"] "/" V[i, "ownerName"], V[i, "durationMs"], V[i, "kubeCalls"], V[i, "dbCalls"], V[i, "servedBy"]
                    }
                    for (i = 0; i < n; i++) { o = V[i, "namespace"] " " V[i, "ownerKind"] "/" V[i, "ownerName"]; if (!(o in C)) { no++; O[no] = o } C[o]++; M[o] += V[i, "durationMs"] }
                    for (i = 2; i <= no; i++) { x = O[i]; k = i - 1; while (k >= 1 && M[O[k]] < M[x]) { O[k + 1] = O[k]; k-- } O[k + 1] = x }
                    print ""; print "top owners by total slow time:"
                    for (i = 1; i <= no && i <= 5; i++) printf "  %-50s %3d admissions %10.1f ms total\n", O[i], C[O[i]], M[O[i]]
                    if (n == 0) print "  (none buffered)"
                }'
        fi
    fi
}
# ==== END sedai-latency-lib ====

self_test() {
    echo "Running sanitizer self-test..."
    local fixture out fail=0
    fixture='- name: SERVER_ACCESSKEY
  value: "abc123supersecret"
- name: AGENT_ENCRYPTIONKEY
  value: zzz999
- name: AGENT_TENANT
  value: "acme"
serverAccessKey: raw-helm-value-123
sedaiApiToken: fixtureApiTokenValue999
bare JWT eyJhbGciOiJIUzI1NiIsInR5cCJ9.eyJmYWtlUGF5bG9hZCI6MX0.ZmFrZXNpZ25hdHVyZQ in log line
caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURWZpeHR1cmUwMTIzNDU2Nzg5
username: "fixtureLokiUser0123456789"
password=hunter2
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig
aws_key AKIAIOSFODNN7EXAMPLE used
url https://user:pass@host/path
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7
-----END RSA PRIVATE KEY-----
after-key line'
    out="$(printf '%s\n' "$fixture" | sanitize)"
    for leaked in "abc123supersecret" "zzz999" "raw-helm-value-123" "fixtureApiTokenValue999" "eyJmYWtlUGF5bG9hZCI6MX0" "fixtureLokiUser0123456789" "hunter2" "eyJhbGciOiJIUzI1NiJ9" "AKIAIOSFODNN7EXAMPLE" "user:pass@" "MIIEpAIBAAKCAQEA7" "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURWZpeHR1cmUw"; do
        if printf '%s' "$out" | grep -qF "$leaked"; then
            echo "FAIL: sanitizer leaked: $leaked"; fail=1
        fi
    done
    for kept in 'value: "acme"' "after-key line" "AGENT_TENANT"; do
        if ! printf '%s' "$out" | grep -qF "$kept"; then
            echo "FAIL: sanitizer over-redacted, missing: $kept"; fail=1
        fi
    done
    if [ "$fail" -eq 0 ]; then echo "Sanitizer self-test PASSED"; else echo "Sanitizer self-test FAILED"; fi
    lat_self_test || fail=1
    exit "$fail"
}
[ "$SELF_TEST" = "true" ] && self_test

# ---------------------------------------------------------------------------
# Bundle setup and helpers
# ---------------------------------------------------------------------------
TS="$(date -u +%Y%m%d-%H%M%SZ)"
BUNDLE_NAME="sedai-diagnostics-${NAMESPACE}-${TS}"
WORK="$(mktemp -d)"
ROOT="$WORK/$BUNDLE_NAME"
mkdir -p "$ROOT"/{cluster,smart-agent,spec-controller,tls,connectivity,events,checks}
SUMMARY="$ROOT/summary.txt"
ERRLOG="$ROOT/collection-errors.log"
MISSING="$WORK/missing"; : > "$MISSING"
PF_PIDS=""
cleanup() {
    local p
    for p in $PF_PIDS; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
note_missing() { printf '%s: %s\n' "$1" "$2" >> "$MISSING"; }

log()  { echo "[$(date -u +%H:%M:%S)] $*"; }

# run <output-file> <description> <command...>
# Captures command + sanitized stdout/stderr into the bundle; never aborts.
run() {
    local out="$1" desc="$2"; shift 2
    {
        echo "### $desc"
        echo "### command: $*"
        echo "### collected-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo
    } >> "$out"
    if "$@" 2>&1 | sanitize >> "$out"; then :; else
        echo "### exit-code: non-zero" >> "$out"
        echo "$desc: command failed: $*" >> "$ERRLOG"
    fi
    echo >> "$out"
}

# check <PASS|WARN|FAIL|INFO> <name> <detail>
declare -a CHECKS=()
check() {
    CHECKS+=("$(printf '%-5s %-55s %s' "$1" "$2" "$3")")
}

log "Sedai diagnostics starting (namespace=$NAMESPACE context=${KCONTEXT:-current}, read-only)"

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if ! command -v kubectl >/dev/null 2>&1; then
    echo "ERROR: kubectl is required"; exit 1
fi
ns_out="$($KUBECTL get namespace "$NAMESPACE" -o name 2>&1)" || {
    echo "WARNING: cannot access namespace '$NAMESPACE' ($(err_reason "$ns_out")); collecting what is reachable"
    note_missing "namespace $NAMESPACE" "$(err_reason "$ns_out") — in-namespace collection may be empty"
}

run "$ROOT/cluster/versions.txt" "kubectl client/server version" $KUBECTL version
run "$ROOT/cluster/rbac-access.txt" "RBAC self-check (get pods)" $KUBECTL auth can-i get pods -n "$NAMESPACE"
run "$ROOT/cluster/rbac-access.txt" "RBAC self-check (get pod logs)" $KUBECTL auth can-i get pods --subresource=log -n "$NAMESPACE"
run "$ROOT/cluster/rbac-access.txt" "RBAC self-check (exec)" $KUBECTL auth can-i create pods/exec -n "$NAMESPACE"
run "$ROOT/cluster/rbac-access.txt" "RBAC self-check (webhooks)" $KUBECTL auth can-i get mutatingwebhookconfigurations
run "$ROOT/cluster/nodes.txt" "Node summary" $KUBECTL get nodes -o wide
run "$ROOT/cluster/namespace-overview.txt" "Workloads in $NAMESPACE" $KUBECTL get deploy,sts,ds,rs,pods -n "$NAMESPACE" -o wide
run "$ROOT/cluster/namespace-overview.txt" "Services/endpoints in $NAMESPACE" $KUBECTL get svc,endpoints -n "$NAMESPACE" -o wide
run "$ROOT/cluster/namespace-overview.txt" "PVCs in $NAMESPACE" $KUBECTL get pvc -n "$NAMESPACE"
run "$ROOT/cluster/namespace-overview.txt" "ConfigMap names in $NAMESPACE" $KUBECTL get configmaps -n "$NAMESPACE"
# Names and types only — secret data is never collected.
run "$ROOT/cluster/namespace-overview.txt" "Secret NAMES/types only in $NAMESPACE" $KUBECTL get secrets -n "$NAMESPACE"

# Every namespace in the cluster with its Spark-optimization status: "active" only
# when it carries the label $SPARK_OPT_LABEL (the spec-controller webhook's
# namespaceSelector — where SparkApplications get mutated), "inactive" otherwise.
# Sorted by status (active first). Two label-agnostic name queries drive this
# (simple .metadata.name jsonpath); the active set is just the label-selected
# subset — this avoids fragile jsonpath access to a dashed label key.
SPARK_NS_FILE="$ROOT/cluster/spark-optimization-namespaces.txt"
all_ns_out="$($KUBECTL get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>&1)"
all_ns_rc=$?
active_ns="$($KUBECTL get namespaces -l "$SPARK_OPT_LABEL" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -v '^[[:space:]]*$' || true)"
if [ "$all_ns_rc" -eq 0 ]; then
    {
        echo "### All namespaces with Spark-optimization status"
        echo "### collected-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "### status=active only when the namespace is labeled $SPARK_OPT_LABEL; sorted by status (active first)."
        echo
        printf '%-9s %s\n' STATUS NAMESPACE
        printf '%s\n' "$all_ns_out" | grep -v '^[[:space:]]*$' | while IFS= read -r ns; do
            nsstatus="inactive"
            printf '%s\n' "$active_ns" | grep -qxF "$ns" && nsstatus="active"
            printf '%-9s %s\n' "$nsstatus" "$ns"
        done | sort
    } | sanitize > "$SPARK_NS_FILE"
    total_ns="$(printf '%s\n' "$all_ns_out" | grep -cve '^[[:space:]]*$')"
    active_count="$(printf '%s\n' "$active_ns" | grep -cve '^[[:space:]]*$')"
    if [ "${active_count:-0}" -gt 0 ]; then
        check PASS "Spark-optimization namespaces" "$active_count of $total_ns namespaces active (labeled $SPARK_OPT_LABEL): $(echo $active_ns | tr '\n' ' ')"
    else
        check INFO "Spark-optimization namespaces" "0 of $total_ns namespaces active (Spark optimization not opted in on any namespace)"
    fi
elif echo "$all_ns_out" | grep -qi 'forbidden'; then
    check INFO "Spark-optimization namespaces" "skipped (RBAC denies cluster-wide list namespaces)"
else
    check WARN "Spark-optimization namespaces" "could not list namespaces: $(echo "$all_ns_out" | head -c 160)"
fi

# Live SparkApplications managed by the Spark operator (cluster-wide). Anything
# kubectl still returns has NOT been garbage-collected — i.e. it is available and
# its post-termination TTL has not elapsed. Only non-sensitive metadata/status
# fields are extracted; the SparkApplication .spec is deliberately never dumped
# (its args, env, image and file paths can carry credentials).
SPARKAPP_FILE="$ROOT/cluster/spark-applications.txt"

# to_epoch <rfc3339> -> unix seconds (GNU date, then BSD date); empty on failure.
to_epoch() {
    local ts="$1"
    [ -z "$ts" ] && return 0
    date -u -d "$ts" +%s 2>/dev/null || date -u -jf '%Y-%m-%dT%H:%M:%SZ' "$ts" +%s 2>/dev/null || true
}
# fmt_dur <seconds> -> "1h02m03s"; "?" when unknown/negative.
fmt_dur() {
    local s="$1"
    { [ -z "$s" ] || ! [ "$s" -ge 0 ] 2>/dev/null; } && { echo "?"; return; }
    printf '%dh%02dm%02ds' $((s / 3600)) $(((s % 3600) / 60)) $((s % 60))
}

# Fields are pipe-delimited, not tab-delimited: tab is IFS-whitespace, so `read`
# would collapse empty fields (e.g. an unset terminationTime) and shift every
# later column. A pipe never appears in these values (DNS names, RFC3339 times,
# integers), and is preserved as a distinct empty field by `read`/awk.
sa_rows="$($KUBECTL get "$SPARKAPP_KIND" --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{"|"}{.metadata.name}{"|"}{.status.applicationState.state}{"|"}{.status.submissionAttempts}{"|"}{.status.executionAttempts}{"|"}{.status.sparkApplicationId}{"|"}{.metadata.creationTimestamp}{"|"}{.status.lastSubmissionAttemptTime}{"|"}{.status.terminationTime}{"|"}{.spec.timeToLiveSeconds}{"|"}{.status.driverInfo.podName}{"\n"}{end}' 2>&1)"
sa_rc=$?
if [ "$sa_rc" -ne 0 ] && echo "$sa_rows" | grep -qiE "server doesn't have a resource type|could not find the requested resource|the server could not find"; then
    check INFO "Spark operator SparkApplications" "Spark operator CRD not installed (no $SPARKAPP_KIND resource)"
elif [ "$sa_rc" -ne 0 ] && echo "$sa_rows" | grep -qi 'forbidden'; then
    check INFO "Spark operator SparkApplications" "skipped (RBAC denies cluster-wide list $SPARKAPP_KIND)"
elif [ "$sa_rc" -ne 0 ]; then
    check WARN "Spark operator SparkApplications" "could not list: $(echo "$sa_rows" | head -c 160)"
else
    now="$(date -u +%s)"
    {
        echo "### Live SparkApplications managed by the Spark operator (cluster-wide)"
        echo "### collected-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "### Every row still exists in the cluster: available, TTL not yet elapsed, not garbage-collected."
        echo "### The SparkApplication .spec is intentionally omitted (may contain credentials); only status/metadata shown."
        echo "### DURATION = (terminationTime or now) - (start of run: lastSubmissionAttemptTime, else creationTimestamp)."
        echo "### SUB = submissionAttempts, EXEC = executionAttempts (times the operator ran/retried this app to completion)."
        echo
        printf '%-18s %-40s %-14s %-4s %-5s %-11s %-21s %-21s %-8s %-30s\n' \
            NAMESPACE NAME STATE SUB EXEC DURATION STARTED TERMINATED TTL_SEC DRIVER_POD
        printf '%s\n' "$sa_rows" | grep -v '^[[:space:]]*$' | while IFS='|' read -r ns name state attempts execs _ created submitted terminated ttl driver; do
            start="$submitted"; [ -z "$start" ] && start="$created"
            s_ep="$(to_epoch "$start")"
            if [ -n "$terminated" ]; then e_ep="$(to_epoch "$terminated")"; else e_ep="$now"; fi
            dur="?"
            [ -n "$s_ep" ] && [ -n "$e_ep" ] && dur="$(fmt_dur $((e_ep - s_ep)))"
            printf '%-18s %-40s %-14s %-4s %-5s %-11s %-21s %-21s %-8s %-30s\n' \
                "$ns" "$name" "${state:-UNKNOWN}" "${attempts:--}" "${execs:--}" "$dur" \
                "${start:--}" "${terminated:--RUNNING-}" "${ttl:--}" "${driver:--}"
        done
    } | sanitize > "$SPARKAPP_FILE"

    sa_count="$(printf '%s\n' "$sa_rows" | grep -cve '^[[:space:]]*$')"
    if [ "${sa_count:-0}" -eq 0 ]; then
        check INFO "Spark operator SparkApplications" "operator present but no live SparkApplications in the cluster"
    else
        sa_states="$(printf '%s\n' "$sa_rows" | awk -F'|' 'NF{c[$3==""?"UNKNOWN":$3]++} END{for(s in c) printf "%s=%d ", s, c[s]}')"
        check PASS "Spark operator SparkApplications" "$sa_count live: ${sa_states:-n/a}(see cluster/spark-applications.txt)"
    fi

    # Timestamped Spark lifecycle events (SparkApplicationSubmitted / SparkDriverRunning
    # / SparkApplicationCompleted / SparkApplicationFailed, ...): the best signal for
    # WHEN and HOW OFTEN apps actually ran — including runs already garbage-collected —
    # but bounded by the cluster's event retention (default ~1h). The COUNT column
    # shows how many times the same event repeated.
    # Absolute RFC3339 timestamps (not kubectl's relative "LAST SEEN" age, which is
    # meaningless once the bundle is read later). eventTime is included because
    # events from the newer events.k8s.io API leave firstTimestamp/lastTimestamp null.
    SPARK_EVENTS_FILE="$ROOT/cluster/spark-application-events.txt"
    run "$SPARK_EVENTS_FILE" "SparkApplication lifecycle events (cluster-wide, oldest->newest; absolute timestamps; bounded by event TTL)" \
        $KUBECTL get events --all-namespaces --field-selector involvedObject.kind=SparkApplication --sort-by=.lastTimestamp \
        -o custom-columns=FIRST_SEEN:.firstTimestamp,LAST_SEEN:.lastTimestamp,EVENT_TIME:.eventTime,COUNT:.count,TYPE:.type,REASON:.reason,NAMESPACE:.involvedObject.namespace,OBJECT:.involvedObject.name,MESSAGE:.message
    sa_evt_count="$($KUBECTL get events --all-namespaces --field-selector involvedObject.kind=SparkApplication -o jsonpath='{range .items[*]}{.reason}{"\n"}{end}' 2>/dev/null | grep -cve '^[[:space:]]*$')"
    if [ "${sa_evt_count:-0}" -gt 0 ]; then
        # Per-reason tally so submitted/completed/failed counts are visible at a glance.
        sa_evt_reasons="$($KUBECTL get events --all-namespaces --field-selector involvedObject.kind=SparkApplication -o jsonpath='{range .items[*]}{.reason}{"\n"}{end}' 2>/dev/null | grep -v '^[[:space:]]*$' | sort | uniq -c | awk '{printf "%s=%s ", $2, $1}')"
        check PASS "SparkApplication lifecycle events" "$sa_evt_count in retention window: ${sa_evt_reasons}(see cluster/spark-application-events.txt)"
    else
        check INFO "SparkApplication lifecycle events" "none in the event-retention window (events expire, default ~1h)"
    fi
fi

if [ "$HAVE_HELM" = "true" ]; then
    HELM="helm"; [ -n "$KCONTEXT" ] && HELM="helm --kube-context=$KCONTEXT"
    run "$ROOT/cluster/helm.txt" "Helm releases" $HELM list -n "$NAMESPACE"
    # Find the release by CHART name (column contains sedai-smart-agent-<ver>),
    # so customers with a custom release name are still covered.
    REL="$($HELM list -n "$NAMESPACE" 2>/dev/null | awk '/sedai-smart-agent-[0-9]/ {print $1; exit}' || true)"
    if [ -n "$REL" ]; then
        run "$ROOT/cluster/helm.txt" "Helm history ($REL)" $HELM history "$REL" -n "$NAMESPACE"
        run "$ROOT/cluster/helm.txt" "Helm user values ($REL, sanitized)" $HELM get values "$REL" -n "$NAMESPACE"
    fi
else
    echo "helm not found on this machine; skipped helm release info" >> "$ERRLOG"
fi

# ---------------------------------------------------------------------------
# Component discovery
# ---------------------------------------------------------------------------
AGENT_POD="$($KUBECTL get pods -n "$NAMESPACE" -l "$AGENT_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
# Controller pods, Service, Deployment settings and Sedai webhook rows (shared lib).
discover_controller
# Reading 1 now; reading 2 near the end, so the --window overlaps the collection.
take_first_reading
# Resolve the agent Deployment through the pod's owning ReplicaSet: several
# chart resources share the app.kubernetes.io/name label, so a label query on
# deployments is ambiguous, but the pod-level selector labels are unique.
AGENT_DEPLOY=""
if [ -n "$AGENT_POD" ]; then
    agent_rs="$($KUBECTL get pod "$AGENT_POD" -n "$NAMESPACE" -o jsonpath='{.metadata.ownerReferences[?(@.kind=="ReplicaSet")].name}' 2>/dev/null || true)"
    [ -n "$agent_rs" ] && AGENT_DEPLOY="$($KUBECTL get rs "$agent_rs" -n "$NAMESPACE" -o jsonpath='{.metadata.ownerReferences[?(@.kind=="Deployment")].name}' 2>/dev/null || true)"
fi
[ -z "$AGENT_DEPLOY" ] && AGENT_DEPLOY="$($KUBECTL get deploy -n "$NAMESPACE" -o name 2>/dev/null | sed 's#deployment.apps/##' | grep -m1 '^sedai-smart-agent' | grep -v spec-controller || true)"
CTRL_DEPLOY="sedai-kube-spec-controller"

if [ -n "$AGENT_POD" ]; then
    check PASS "smart-agent pod found" "$AGENT_POD"
else
    check FAIL "smart-agent pod found" "no pod matching $AGENT_LABEL in $NAMESPACE"
fi
if [ -n "$CTRL_POD" ]; then
    check PASS "spec-controller pod found" "$CTRL_POD"
elif [ -n "${CTRL_ANY_POD:-}" ]; then
    check WARN "spec-controller pod found" "$CTRL_ANY_POD (phase ${CTRL_ANY_PHASE:-?}, not Running)"
else
    check FAIL "spec-controller pod found" "no pod matching $CONTROLLER_LABEL in $NAMESPACE"
fi
log "smart-agent pod: ${AGENT_POD:-NOT FOUND}; spec-controller pod: ${CTRL_POD:-NOT FOUND}"

# collect_component <dir> <deploy> <pod> <label>
collect_component() {
    local dir="$1" deploy="$2" pod="$3" label="$4"
    [ -n "$deploy" ] && {
        run "$dir/deployment.yaml.txt" "Deployment YAML (env sanitized)" $KUBECTL get deploy "$deploy" -n "$NAMESPACE" -o yaml
        run "$dir/deployment-describe.txt" "Deployment describe" $KUBECTL describe deploy "$deploy" -n "$NAMESPACE"
    }
    [ -n "$pod" ] || return 0
    run "$dir/pod.yaml.txt" "Pod YAML (env sanitized)" $KUBECTL get pod "$pod" -n "$NAMESPACE" -o yaml
    run "$dir/pod-describe.txt" "Pod describe" $KUBECTL describe pod "$pod" -n "$NAMESPACE"
    run "$dir/restarts.txt" "Container restart state" $KUBECTL get pod "$pod" -n "$NAMESPACE" \
        -o jsonpath='{range .status.containerStatuses[*]}container={.name} restarts={.restartCount} ready={.ready} state={.state} lastState={.lastState}{"\n"}{end}'
    run "$dir/logs-current.log" "Current logs (last ${LOG_TAIL} lines / ${LOG_SINCE})" \
        $KUBECTL_LONG logs "$pod" -n "$NAMESPACE" --all-containers=true --since="$LOG_SINCE" --tail="$LOG_TAIL" --timestamps=true
    local restarts
    restarts="$($KUBECTL get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo 0)"
    if [ "${restarts:-0}" -gt 0 ] 2>/dev/null; then
        run "$dir/logs-previous.log" "Previous-container logs (pod restarted ${restarts}x)" \
            $KUBECTL_LONG logs "$pod" -n "$NAMESPACE" --previous --tail="$LOG_TAIL" --timestamps=true
    fi
    # Historical restarts across replicas (ReplicaSets keep no logs, but events do)
    run "$dir/pods-by-label.txt" "All pods for label $label (incl. terminating/evicted)" \
        $KUBECTL get pods -n "$NAMESPACE" -l "$label" -o wide
}

log "Collecting smart-agent state and logs..."
collect_component "$ROOT/smart-agent" "$AGENT_DEPLOY" "$AGENT_POD" "$AGENT_LABEL"
log "Collecting spec-controller state and logs..."
collect_component "$ROOT/spec-controller" "$CTRL_DEPLOY" "${CTRL_POD:-${CTRL_ANY_POD:-}}" "$CONTROLLER_LABEL"

# Spec-controller supporting objects
run "$ROOT/spec-controller/service.txt" "Controller service" $KUBECTL get svc "$CONTROLLER_SVC" -n "$NAMESPACE" -o yaml
run "$ROOT/spec-controller/endpoints.txt" "Controller endpoints" $KUBECTL get endpoints "$CONTROLLER_SVC" -n "$NAMESPACE" -o yaml
# Store: Postgres StatefulSet (current chart) or SQLite on a PVC (older installs).
DB_DRIVER="$(json_get "$(cat "$WORK/health.1" 2>/dev/null)" '.db.driver')"
[ -z "$DB_DRIVER" ] && DB_DRIVER="$(printf '%s\n' "${dep_env:-}" | awk -F= '$1 == "SEDAI_KUBE_SPEC_CONTROLLER_DB_DRIVER_NAME" { print $2; exit }')"
case "$DB_DRIVER" in
    pgx|postgres*) STORE="postgres" ;;
    "")            if [ -n "${dep_env:-}" ]; then STORE="sqlite"; else STORE="unknown"; fi ;;
    *)             STORE="sqlite" ;;
esac
if [ "$STORE" = "postgres" ]; then
    DBDIR="$ROOT/spec-controller/db"; mkdir -p "$DBDIR"
    DB_POD="$($KUBECTL get pods -n "$NAMESPACE" -l "app=$DB_NAME" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    run "$DBDIR/statefulset.yaml.txt" "DB StatefulSet (env sanitized; the DB secret is never read)" $KUBECTL get statefulset "$DB_NAME" -n "$NAMESPACE" -o yaml
    run "$DBDIR/pvc.txt" "DB PVC" $KUBECTL get pvc "$DB_NAME-pvc" -n "$NAMESPACE" -o yaml
    if [ -n "$DB_POD" ]; then
        run "$DBDIR/pod-describe.txt" "DB pod describe" $KUBECTL describe pod "$DB_POD" -n "$NAMESPACE"
        run "$DBDIR/logs.log" "DB logs (last 2000 lines / ${LOG_SINCE})" $KUBECTL_LONG logs "$DB_POD" -n "$NAMESPACE" --since="$LOG_SINCE" --tail=2000 --timestamps=true
    else
        note_missing "spec-controller DB pod" "no pod labelled app=$DB_NAME in $NAMESPACE"
    fi
elif [ "$STORE" = "sqlite" ]; then
    run "$ROOT/spec-controller/pvc.txt" "Controller PVC (SQLite store)" $KUBECTL get pvc sedai-kube-spec-controller-pvc -n "$NAMESPACE" -o yaml
else
    note_missing "spec-controller store" "driver unknown (health and deployment unreadable)"
fi
run "$ROOT/spec-controller/configmap.txt" "Controller app config" $KUBECTL get configmap sedai-kube-spec-controller-config -n "$NAMESPACE" -o yaml
run "$ROOT/spec-controller/webhooks.txt" "Sedai mutating webhook configurations" \
    sh -c "$KUBECTL get mutatingwebhookconfigurations -o name | grep sedai | xargs -r $KUBECTL get -o yaml"

# Readiness checks
for c in "smart-agent:$AGENT_DEPLOY" "spec-controller:$CTRL_DEPLOY"; do
    name="${c%%:*}"; dep="${c#*:}"
    [ -z "$dep" ] && continue
    ready="$($KUBECTL get deploy "$dep" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}/{.status.replicas}' 2>/dev/null || echo '?')"
    if [ "${ready%%/*}" = "${ready##*/}" ] && [ "${ready%%/*}" != "" ] && [ "${ready%%/*}" != "0" ]; then
        check PASS "$name deployment ready" "$ready replicas ready"
    else
        check FAIL "$name deployment ready" "readyReplicas=$ready"
    fi
done

# Restart summary checks
for c in "smart-agent:$AGENT_POD" "spec-controller:${CTRL_POD:-${CTRL_ANY_POD:-}}"; do
    name="${c%%:*}"; pod="${c#*:}"
    [ -z "$pod" ] && continue
    rc="$($KUBECTL get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo '?')"
    if [ "$rc" = "0" ]; then
        check PASS "$name container restarts" "0 restarts"
    else
        reason="$($KUBECTL get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason} at {.status.containerStatuses[0].lastState.terminated.finishedAt}' 2>/dev/null || true)"
        check WARN "$name container restarts" "restartCount=$rc lastTermination=${reason:-unknown}"
    fi
done

# Store health: Postgres pod/PVC, or the SQLite PVC on older installs.
if [ "$STORE" = "postgres" ]; then
    if [ -n "$DB_POD" ]; then
        db_ready="$($KUBECTL get pod "$DB_POD" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || true)"
        [ "$db_ready" = "true" ] && check PASS "spec-controller DB pod ready" "$DB_POD" \
                                 || check FAIL "spec-controller DB pod ready" "$DB_POD ready=${db_ready:-?}"
        db_rc="$($KUBECTL get pod "$DB_POD" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || true)"
        if [ "${db_rc:-0}" = "0" ]; then check PASS "spec-controller DB restarts" "0 restarts"
        else check WARN "spec-controller DB restarts" "restartCount=$db_rc lastTermination=$($KUBECTL get pod "$DB_POD" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}' 2>/dev/null || echo '?')"; fi
    else
        check FAIL "spec-controller DB pod ready" "no pod labelled app=$DB_NAME"
    fi
    pvc_phase="$($KUBECTL get pvc "$DB_NAME-pvc" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo 'NotFound')"
    [ "$pvc_phase" = "Bound" ] && check PASS "spec-controller DB PVC bound" "phase=Bound" \
                               || check FAIL "spec-controller DB PVC bound" "$DB_NAME-pvc phase=${pvc_phase:-NotFound}"
elif [ "$STORE" = "sqlite" ]; then
    pvc_phase="$($KUBECTL get pvc sedai-kube-spec-controller-pvc -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo 'NotFound')"
    [ "$pvc_phase" = "Bound" ] && check PASS "spec-controller PVC bound" "phase=Bound (SQLite store)" \
                               || check FAIL "spec-controller PVC bound" "phase=${pvc_phase:-NotFound} (SQLite store)"
else
    check INFO "spec-controller store" "driver unknown; store checks skipped"
fi

# Service endpoints populated?
ep="$($KUBECTL get endpoints "$CONTROLLER_SVC" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)"
[ -n "$ep" ] && check PASS "spec-controller service has endpoints" "$ep" \
             || check FAIL "spec-controller service has endpoints" "no ready endpoints behind $CONTROLLER_SVC"

# ---------------------------------------------------------------------------
# Agent -> controller configuration cross-check
# ---------------------------------------------------------------------------
EXPECTED_URL="https://${CONTROLLER_SVC}.${NAMESPACE}.svc:${CONTROLLER_PORT}"
if [ -n "$AGENT_DEPLOY" ]; then
    agent_env="$($KUBECTL get deploy "$AGENT_DEPLOY" -n "$NAMESPACE" -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' 2>/dev/null || true)"
    baseurl="$(printf '%s\n' "$agent_env" | grep '^KUBESPECCONTROLLER_BASEURL=' | cut -d= -f2- || true)"
    enabled="$(printf '%s\n' "$agent_env" | grep '^SEDAI_KUBE_SPEC_CONTROLLER_ENABLED=' | cut -d= -f2- || true)"
    {   echo "expected baseUrl : $EXPECTED_URL"
        echo "actual baseUrl   : ${baseurl:-<unset>}"
        echo "controller flag  : SEDAI_KUBE_SPEC_CONTROLLER_ENABLED=${enabled:-<unset>}"
        printf '%s\n' "$agent_env" | grep -E '^(SEDAI_KUBE_SPEC|KUBESPEC|DISABLE_SSL)' || true
    } | sanitize >> "$ROOT/connectivity/agent-config-crosscheck.txt"
    # Env delivered via envFrom (secret/configmap) is intentionally not read;
    # in that case the vars look unset here even though the agent has them.
    has_envfrom="$($KUBECTL get deploy "$AGENT_DEPLOY" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.containers[0].envFrom}' 2>/dev/null || true)"
    if [ "$baseurl" = "$EXPECTED_URL" ]; then
        check PASS "agent spec-controller baseUrl" "$baseurl"
    elif [ -z "$baseurl" ] && [ -n "$has_envfrom" ]; then
        check INFO "agent spec-controller baseUrl" "delivered via envFrom (secret not inspected); expected $EXPECTED_URL"
    else
        check WARN "agent spec-controller baseUrl" "expected $EXPECTED_URL got ${baseurl:-<unset>}"
    fi
    if [ "$enabled" = "true" ]; then
        check PASS "agent spec-controller integration enabled" "SEDAI_KUBE_SPEC_CONTROLLER_ENABLED=true"
    elif [ -z "$enabled" ] && [ -n "$has_envfrom" ]; then
        check INFO "agent spec-controller integration enabled" "delivered via envFrom (secret not inspected)"
    else
        check WARN "agent spec-controller integration enabled" "SEDAI_KUBE_SPEC_CONTROLLER_ENABLED=${enabled:-<unset>}"
    fi
fi

# ---------------------------------------------------------------------------
# TLS analysis (public certs only — the private key is never read)
# ---------------------------------------------------------------------------
log "Analyzing TLS configuration..."
TLSDIR="$ROOT/tls"
# Certificates are extracted OUTSIDE the bundle root ($BUNDLE_NAME is the only
# directory packaged), analyzed, and discarded — only the textual analysis in
# tls-summary.txt ships. No certificate or key material enters the bundle.
CERT_SCRATCH="$WORK/cert-scratch"
mkdir -p "$CERT_SCRATCH"
secret_keys="$($KUBECTL get secret "$TLS_SECRET" -n "$NAMESPACE" -o jsonpath='{.data}' 2>/dev/null | tr ',{}' '\n' | sed -E 's/"([^"]+)":.*/\1/' | grep -v '^$' || true)"
if [ -z "$secret_keys" ]; then
    check FAIL "TLS secret present" "$TLS_SECRET not found/readable in $NAMESPACE"
else
    echo "secret $TLS_SECRET keys present: $(echo $secret_keys | tr '\n' ' ')" > "$TLSDIR/tls-summary.txt"
    check PASS "TLS secret present" "$TLS_SECRET (keys: $(echo $secret_keys | tr '\n' ' '))"
    b64dec="base64 -d"; echo test | base64 -d >/dev/null 2>&1 || b64dec="base64 -D"
    $KUBECTL get secret "$TLS_SECRET" -n "$NAMESPACE" -o jsonpath='{.data.ca\.crt}'  | $b64dec > "$CERT_SCRATCH/ca.crt"  2>/dev/null
    $KUBECTL get secret "$TLS_SECRET" -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' | $b64dec > "$CERT_SCRATCH/tls.crt" 2>/dev/null

    if [ "$HAVE_OPENSSL" = "true" ] && [ -s "$CERT_SCRATCH/tls.crt" ]; then
        # -text + grep instead of "-ext subjectAltName": LibreSSL (macOS) has no -ext
        san_lines="$(openssl x509 -in "$CERT_SCRATCH/tls.crt" -noout -text 2>/dev/null | grep -A3 'Subject Alternative Name' || true)"
        {   echo "=== ca.crt (certificate itself not included in bundle) ==="
            openssl x509 -in "$CERT_SCRATCH/ca.crt" -noout -subject -issuer -dates -fingerprint -sha256 2>&1
            echo; echo "=== tls.crt (certificate itself not included in bundle) ==="
            openssl x509 -in "$CERT_SCRATCH/tls.crt" -noout -subject -issuer -dates -fingerprint -sha256 2>&1
            echo "$san_lines"
            echo; echo "=== chain verification (tls.crt signed by ca.crt) ==="
            openssl verify -CAfile "$CERT_SCRATCH/ca.crt" "$CERT_SCRATCH/tls.crt" 2>&1
        } >> "$TLSDIR/tls-summary.txt"

        if openssl verify -CAfile "$CERT_SCRATCH/ca.crt" "$CERT_SCRATCH/tls.crt" >/dev/null 2>&1; then
            check PASS "server cert chains to CA" "openssl verify OK"
        else
            check FAIL "server cert chains to CA" "tls.crt does NOT verify against ca.crt in $TLS_SECRET"
        fi
        expected_san="${CONTROLLER_SVC}.${NAMESPACE}.svc"
        if echo "$san_lines" | grep -q "$expected_san"; then
            check PASS "server cert SAN covers service DNS" "$expected_san"
        else
            check FAIL "server cert SAN covers service DNS" "SAN does not include $expected_san (agent/webhook TLS will fail)"
        fi
        if openssl x509 -in "$CERT_SCRATCH/tls.crt" -noout -checkend $((30*24*3600)) >/dev/null 2>&1; then
            check PASS "server cert validity" "valid for >30 days"
        elif openssl x509 -in "$CERT_SCRATCH/tls.crt" -noout -checkend 0 >/dev/null 2>&1; then
            check WARN "server cert validity" "expires within 30 days"
        else
            check FAIL "server cert validity" "certificate is EXPIRED"
        fi
    else
        echo "openssl unavailable or cert unreadable; skipped x509 analysis" >> "$TLSDIR/tls-summary.txt"
        check INFO "TLS certificate analysis" "skipped (openssl not available)"
    fi

    # Webhook caBundle must match the CA the controller serves with.
    ca_b64="$($KUBECTL get secret "$TLS_SECRET" -n "$NAMESPACE" -o jsonpath='{.data.ca\.crt}' 2>/dev/null || true)"
    {   echo; echo "=== webhook caBundle vs secret ca.crt ==="
    } >> "$TLSDIR/tls-summary.txt"
    # Every webhook entry carries its own caBundle; all entries in this namespace must match.
    for wh in $($KUBECTL get mutatingwebhookconfigurations -o name 2>/dev/null | grep sedai | sed 's#.*/##'); do
        bundles="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath='{range .webhooks[*]}{.name}{"|"}{.clientConfig.service.namespace}{"|"}{.clientConfig.caBundle}{"\n"}{end}' 2>/dev/null || true)"
        n_in=0; bad=""
        while IFS='|' read -r e_name e_ns e_bundle; do
            [ -n "$e_name" ] || continue
            if [ "$e_ns" != "$NAMESPACE" ]; then
                echo "$wh / $e_name -> targets namespace '$e_ns' (not $NAMESPACE), skipped" >> "$TLSDIR/tls-summary.txt"; continue
            fi
            n_in=$((n_in + 1))
            if [ "$e_bundle" = "$ca_b64" ]; then echo "$wh / $e_name -> caBundle MATCHES secret ca.crt" >> "$TLSDIR/tls-summary.txt"
            else echo "$wh / $e_name -> caBundle DIFFERS from secret ca.crt" >> "$TLSDIR/tls-summary.txt"; bad="$bad $e_name"; fi
        done <<EOF
$bundles
EOF
        [ "$n_in" -eq 0 ] && continue
        if [ -z "$bad" ]; then check PASS "webhook caBundle matches CA ($wh)" "all $n_in entries identical to $TLS_SECRET ca.crt"
        else check FAIL "webhook caBundle matches CA ($wh)" "caBundle != $TLS_SECRET ca.crt for:$bad (webhook TLS trust broken)"; fi
    done

    # Does the agent mount the same secret?
    if [ -n "$AGENT_DEPLOY" ]; then
        mounts_tls="$($KUBECTL get deploy "$AGENT_DEPLOY" -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.volumes[?(@.secret.secretName=="'"$TLS_SECRET"'")].name}' 2>/dev/null || true)"
        if [ -n "$mounts_tls" ]; then
            check PASS "agent mounts controller TLS secret" "volume '$mounts_tls' from $TLS_SECRET"
        else
            check FAIL "agent mounts controller TLS secret" "$TLS_SECRET not mounted by $AGENT_DEPLOY (agent cannot trust controller CA)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Webhook registration + API-server -> controller TLS serving
# ---------------------------------------------------------------------------
# The webhook client is the API server itself: at pod admission it dials the
# controller service over HTTPS and validates the served cert against the
# webhook's caBundle. We verify each registration points at the right service,
# that the registered path answers over TLS (via the API-server service proxy),
# and that the certificate the controller is ACTUALLY serving right now matches
# the secret (via a localhost-only port-forward + openssl; catches a rotated
# secret with a stale pod still serving the old cert).
log "Checking webhook registration and served TLS certificate..."
WHREG="$ROOT/spec-controller/webhook-registration.txt"

for wh in $($KUBECTL get mutatingwebhookconfigurations -o name 2>/dev/null | grep sedai | sed 's#.*/##'); do
    wh_count="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath='{.webhooks[*].name}' 2>/dev/null | wc -w | tr -d ' ')"
    i=0
    while [ "$i" -lt "${wh_count:-0}" ]; do
        wh_ns="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath="{.webhooks[$i].clientConfig.service.namespace}" 2>/dev/null || true)"
        wh_svc="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath="{.webhooks[$i].clientConfig.service.name}" 2>/dev/null || true)"
        wh_port="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath="{.webhooks[$i].clientConfig.service.port}" 2>/dev/null || true)"
        wh_path="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath="{.webhooks[$i].clientConfig.service.path}" 2>/dev/null || true)"
        wh_policy="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath="{.webhooks[$i].failurePolicy}" 2>/dev/null || true)"
        wh_timeout="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath="{.webhooks[$i].timeoutSeconds}" 2>/dev/null || true)"
        wh_rules="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath="{.webhooks[$i].rules[*].resources}" 2>/dev/null || true)"
        wh_nssel="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath="{.webhooks[$i].namespaceSelector}" 2>/dev/null || true)"
        i=$((i + 1))
        [ "$wh_ns" = "$NAMESPACE" ] || continue
        {
            echo "=== $wh (webhook #$((i-1))) ==="
            echo "service ref      : ${wh_svc}.${wh_ns}:${wh_port}${wh_path}"
            echo "rules            : ${wh_rules:-<none>}"
            echo "failurePolicy    : ${wh_policy}"
            echo "timeoutSeconds   : ${wh_timeout}"
            echo "namespaceSelector: ${wh_nssel:-<none>}"
            echo
        } >> "$WHREG"

        if [ "$wh_svc" = "$CONTROLLER_SVC" ] && [ "$wh_port" = "$CONTROLLER_PORT" ]; then
            check PASS "webhook service ref ($wh)" "${wh_svc}:${wh_port}${wh_path}"
        else
            check FAIL "webhook service ref ($wh)" "points at ${wh_svc:-<none>}:${wh_port:-<none>}, expected ${CONTROLLER_SVC}:${CONTROLLER_PORT}"
        fi
        [ "$wh_policy" = "Ignore" ] && \
            check INFO "webhook failurePolicy ($wh)" "Ignore — webhook errors admit pods unpatched and stay invisible; check controller logs"

        # Registered path served over TLS? GET via the API-server proxy: the
        # handlers are POST-only, so MethodNotAllowed/404/400 still proves the
        # TLS handshake and routing to the path work. The exact command is
        # recorded so an operator can re-run this probe by hand (proxy syntax is
        # scheme:name:port — "https:svc:8443", one colon, no "//").
        path_raw="/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy${wh_path}"
        echo "path probe command: $KUBECTL get --raw \"${path_raw}\"" >> "$WHREG"
        path_out="$($KUBECTL get --raw "$path_raw" 2>&1)" && path_rc=0 || path_rc=$?
        path_class="$(classify_proxy "$path_out" "$path_rc")"
        echo "path probe (${wh_path}): rc=$path_rc class=$path_class $(echo "$path_out" | head -c 160)" >> "$WHREG"
        # A dial failure here is the API server failing to reach the backend Pod; the
        # admission call uses the same egress and fails the same way.
        case "$path_class" in
            REACHABLE)   check PASS "webhook path served over TLS ($wh)" "${wh_path} answers via API-server proxy" ;;
            RBAC-DENIED) check INFO "webhook path served over TLS ($wh)" "skipped (RBAC denies services/proxy)" ;;
            DIAL-FAILED|TIMEOUT|TLS-ERROR|NO-SERVICE)
                         check FAIL "webhook path served over TLS ($wh)" "$path_class: $(echo "$path_out" | head -c 160)" ;;
            *)           check WARN "webhook path served over TLS ($wh)" "unexpected: $(echo "$path_out" | head -c 160)" ;;
        esac
        echo >> "$WHREG"
    done
done
[ -f "$WHREG" ] || check WARN "webhook registration" "no sedai mutating webhooks target namespace $NAMESPACE"

# Live served-certificate check: does the running controller serve the cert
# from the secret? (kubectl port-forward is a localhost-only read tunnel.)
if [ "$HAVE_OPENSSL" = "true" ] && [ -s "$CERT_SCRATCH/tls.crt" ] && [ "$DO_EXEC" = "true" ] \
   && [ "$($KUBECTL auth can-i create pods/portforward -n "$NAMESPACE" 2>/dev/null)" = "yes" ]; then
    pf_port=18443
    served_ok="no"
    $KUBECTL_PF port-forward -n "$NAMESPACE" "svc/$CONTROLLER_SVC" "${pf_port}:${CONTROLLER_PORT}" >/dev/null 2>&1 &
    pf_pid=$!; PF_PIDS="$PF_PIDS $pf_pid"
    waited=0
    while [ "$waited" -lt 10 ]; do
        sleep 1; waited=$((waited + 1))
        if echo | openssl s_client -connect "127.0.0.1:${pf_port}" -servername "${CONTROLLER_SVC}.${NAMESPACE}.svc" 2>/dev/null \
             | openssl x509 -outform PEM > "$CERT_SCRATCH/served.crt" 2>/dev/null && [ -s "$CERT_SCRATCH/served.crt" ]; then
            served_ok="yes"; break
        fi
    done
    kill "$pf_pid" 2>/dev/null; wait "$pf_pid" 2>/dev/null
    if [ "$served_ok" = "yes" ]; then
        fp_served="$(openssl x509 -in "$CERT_SCRATCH/served.crt" -noout -fingerprint -sha256 2>/dev/null)"
        fp_secret="$(openssl x509 -in "$CERT_SCRATCH/tls.crt" -noout -fingerprint -sha256 2>/dev/null)"
        {
            echo "=== live served certificate (via port-forward) ==="
            echo "served : $fp_served"
            echo "secret : $fp_secret"
        } >> "$TLSDIR/tls-summary.txt"
        if [ -n "$fp_served" ] && [ "$fp_served" = "$fp_secret" ]; then
            check PASS "controller serves the secret's certificate" "live fingerprint matches $TLS_SECRET tls.crt"
        else
            check FAIL "controller serves the secret's certificate" "live cert differs from $TLS_SECRET tls.crt (stale pod after secret rotation?)"
        fi
        if openssl verify -CAfile "$CERT_SCRATCH/ca.crt" "$CERT_SCRATCH/served.crt" >/dev/null 2>&1; then
            check PASS "API-server->webhook TLS trust" "live served cert verifies against the CA in $TLS_SECRET (webhook caBundle source)"
        else
            check FAIL "API-server->webhook TLS trust" "live served cert does NOT verify against the CA — admission requests will fail TLS"
        fi
        rm -f "$CERT_SCRATCH/served.crt"
    else
        check WARN "controller serves the secret's certificate" "could not capture live cert via port-forward within 10s"
    fi
else
    check INFO "controller serves the secret's certificate" "skipped (needs openssl, secret certs, exec allowed, and pods/portforward RBAC)"
fi

# Evidence the webhook is actually being invoked (informational)
if [ -s "$ROOT/spec-controller/logs-current.log" ]; then
    adm_count="$(grep -ciE 'mutate|admission' "$ROOT/spec-controller/logs-current.log" 2>/dev/null)" || true
    echo "admission-related log lines in collected window: ${adm_count:-0}" >> "$WHREG"
    check INFO "webhook admission activity in controller logs" "${adm_count:-0} admission-related lines in collected window"
fi

# ---------------------------------------------------------------------------
# Spec-controller WISB/WIRI inventory (read-only diagnostics APIs)
# ---------------------------------------------------------------------------
# The controller exposes read-only GET diagnostics endpoints; we call them
# through the API-server service proxy so no exec is needed. NOTE:
# /sedai/spark/admission-events is deliberately NOT called — reading it drains
# the event queue the smart agent consumes.
log "Querying spec-controller WISB/WIRI diagnostics APIs..."
WISBDIR="$ROOT/spec-controller/wisb-wiri"
mkdir -p "$WISBDIR"


# json_field <field> <json> — first integer/string value of "field" (jq when available)
json_field() {
    if [ "$HAVE_JQ" = "true" ]; then
        printf '%s' "$2" | jq -r ".. | objects | select(has(\"$1\")) | .\"$1\"" 2>/dev/null | head -1
    else
        printf '%s' "$2" | sed -nE 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"?([^,}"]*)"?.*/\1/p' | head -1
    fi
}

sum_out="$(proxy_get /sedai/pod/diagnostics/summary 2>&1)" && sum_rc=0 || sum_rc=$?
printf '%s\n' "$sum_out" | sanitize > "$WISBDIR/diagnostics-summary.json"
if [ "$sum_rc" -eq 0 ]; then
    total_wisbs="$(json_field totalWisbs "$sum_out")"
    stale_wisbs="$(json_field staleWisbs "$sum_out")"
    temp_wisbs="$(json_field temporaryWisbs "$sum_out")"
    val_wisbs="$(json_field validatedWisbs "$sum_out")"
    check PASS "WISB diagnostics summary" "total=${total_wisbs:-?} stale=${stale_wisbs:-?} temporary=${temp_wisbs:-?} validated=${val_wisbs:-?}"
elif echo "$sum_out" | grep -qi 'forbidden'; then
    check INFO "WISB diagnostics summary" "skipped (RBAC denies services/proxy)"
elif echo "$sum_out" | grep -qiE 'the server could not find|404'; then
    check INFO "WISB diagnostics summary" "endpoint not available (older controller version)"
else
    check FAIL "WISB diagnostics summary" "$(echo "$sum_out" | head -c 160)"
fi

list_out="$(proxy_get '/sedai/pod/resourceconfigs/list?pageSize=500' 2>&1)" && list_rc=0 || list_rc=$?
printf '%s\n' "$list_out" | sanitize > "$WISBDIR/podspec-wisb-list-page1.json"
if [ "$list_rc" -eq 0 ]; then
    total_items="$(json_field totalItems "$list_out")"
    total_pages="$(json_field totalPages "$list_out")"
    check PASS "WISB/WIRI config list" "${total_items:-?} configs (page 1 of ${total_pages:-?} captured, pageSize=500)"
    # Fetch up to 2 more pages; log what is left out rather than truncating silently.
    if [ "${total_pages:-1}" -gt 1 ] 2>/dev/null; then
        p=2
        while [ "$p" -le "$total_pages" ] && [ "$p" -le 3 ]; do
            proxy_get "/sedai/pod/resourceconfigs/list?pageSize=500&page=$p" 2>&1 | sanitize > "$WISBDIR/podspec-wisb-list-page$p.json"
            p=$((p + 1))
        done
        [ "${total_pages:-1}" -gt 3 ] && echo "NOTE: only pages 1-3 of $total_pages captured (pageSize=500)" >> "$WISBDIR/podspec-wisb-list-page1.json"
    fi
    # One full WISB+WIRI example: latest configs for the first listed resource.
    sample_id="$(json_field sedaiResourceId "$list_out")"
    if [ -n "$sample_id" ] && [ "$sample_id" != "null" ]; then
        proxy_get "/sedai/pod/resourceconfigs/latest?resourceId=${sample_id}" 2>&1 | sanitize > "$WISBDIR/sample-latest-config.json"
        check INFO "sample latest WISB/WIRI config" "captured for resourceId=$sample_id"
    fi
elif echo "$list_out" | grep -qiE 'forbidden'; then
    check INFO "WISB/WIRI config list" "skipped (RBAC denies services/proxy)"
elif echo "$list_out" | grep -qiE 'the server could not find|404'; then
    check INFO "WISB/WIRI config list" "endpoint not available (older controller version)"
else
    check FAIL "WISB/WIRI config list" "$(echo "$list_out" | head -c 160)"
fi


# ---------------------------------------------------------------------------
# Connectivity probes (read-only execs into existing pods; skipped by --no-exec)
# ---------------------------------------------------------------------------
CONN="$ROOT/connectivity"
SVC_FQDN="${CONTROLLER_SVC}.${NAMESPACE}.svc"
HEALTH_URL="https://${SVC_FQDN}:${CONTROLLER_PORT}${CONTROLLER_HEALTH_PATH}"

# From outside the cluster via the API-server service proxy (no exec needed).
log "Probing controller health via API-server proxy..."
# Reuses reading 1: /sedai/health counts every DB table, so it is fetched once per reading.
proxy_out="$PROXY_HEALTH"
proxy_rc="$PROXY_HEALTH_RC"
{ echo "### controller health via kubectl API-server proxy"; echo "$proxy_out"; } | sanitize > "$CONN/controller-health-apiserver-proxy.txt"
if [ $proxy_rc -eq 0 ]; then
    check PASS "controller health (apiserver proxy)" "$(echo "$proxy_out" | head -c 120)"
elif echo "$proxy_out" | grep -qi 'forbidden'; then
    check INFO "controller health (apiserver proxy)" "skipped (RBAC denies services/proxy)"
else
    check FAIL "controller health (apiserver proxy)" "$(echo "$proxy_out" | head -c 160)"
fi

# Skip exec probes gracefully when the operator's RBAC does not allow exec.
if [ "$DO_EXEC" = "true" ]; then
    can_exec="$($KUBECTL auth can-i create pods/exec -n "$NAMESPACE" 2>/dev/null || echo no)"
    if [ "$can_exec" != "yes" ]; then
        DO_EXEC="rbac-denied"
    fi
fi

if [ "$DO_EXEC" = "true" ] && [ -n "$AGENT_POD" ]; then
    log "Probing agent -> controller connectivity from inside the agent pod..."
    # Informational only: busybox nslookup ignores resolv.conf search domains, so
    # NXDOMAIN here does not mean the agent's libc cannot resolve the name.
    run "$CONN/agent-dns.txt" "DNS lookup (informational; busybox nslookup ignores search domains)" \
        $KUBECTL_PF exec "$AGENT_POD" -n "$NAMESPACE" -- nslookup "${SVC_FQDN}.cluster.local"

    # Reachability + controller health (TLS cert NOT verified — pure reachability).
    # This uses the same libc resolver path as the agent JVM, so it doubles as
    # the authoritative DNS check.
    health_out="$($KUBECTL_PF exec "$AGENT_POD" -n "$NAMESPACE" -- wget -q -O- -T 10 --no-check-certificate "$HEALTH_URL" 2>&1)"
    health_rc=$?
    { echo "### agent-pod wget (reachability, cert check disabled): $HEALTH_URL"; echo "$health_out"; } | sanitize > "$CONN/agent-to-controller-health.txt"
    if [ $health_rc -eq 0 ]; then
        check PASS "agent DNS resolves controller service" "$SVC_FQDN (resolved during health probe)"
        check PASS "agent -> controller HTTPS reachability" "health endpoint answered: $(echo "$health_out" | head -c 120)"
    elif echo "$health_out" | grep -qiE 'bad address|unable to resolve|Name does not resolve'; then
        check FAIL "agent DNS resolves controller service" "$SVC_FQDN: $(echo "$health_out" | head -c 160)"
        check FAIL "agent -> controller HTTPS reachability" "blocked by DNS failure"
    else
        check PASS "agent DNS resolves controller service" "$SVC_FQDN (failure was past DNS stage)"
        check FAIL "agent -> controller HTTPS reachability" "wget failed (rc=$health_rc): $(echo "$health_out" | head -c 160)"
    fi

    # Full TLS verification using the CA the agent actually mounts (GNU wget only)
    if $KUBECTL_PF exec "$AGENT_POD" -n "$NAMESPACE" -- wget --version 2>/dev/null | grep -qi 'GNU Wget'; then
        vtls_out="$($KUBECTL_PF exec "$AGENT_POD" -n "$NAMESPACE" -- wget -q -O- -T 10 --ca-certificate=/tls/ca.crt "$HEALTH_URL" 2>&1)"
        vtls_rc=$?
        { echo "### agent-pod wget with CA verification (--ca-certificate=/tls/ca.crt): $HEALTH_URL"; echo "$vtls_out"; } | sanitize > "$CONN/agent-to-controller-health-tls-verified.txt"
        if [ $vtls_rc -eq 0 ]; then
            check PASS "agent -> controller TLS verification" "handshake verified against mounted /tls/ca.crt"
        else
            check FAIL "agent -> controller TLS verification" "TLS verify vs /tls/ca.crt failed (rc=$vtls_rc): $(echo "$vtls_out" | head -c 160)"
        fi
    else
        check INFO "agent -> controller TLS verification" "skipped (agent wget is busybox; no --ca-certificate support)"
    fi

    # Agent's own health endpoint
    self_out="$($KUBECTL_PF exec "$AGENT_POD" -n "$NAMESPACE" -- wget -q -O- -T 10 "$AGENT_SELF_HEALTH_URL" 2>&1)"
    self_rc=$?
    { echo "### agent self health: $AGENT_SELF_HEALTH_URL"; echo "$self_out"; } | sanitize > "$CONN/agent-self-health.txt"
    if [ $self_rc -eq 0 ]; then
        check PASS "agent self health endpoint" "$(echo "$self_out" | head -c 120)"
    else
        check WARN "agent self health endpoint" "wget failed (rc=$self_rc): $(echo "$self_out" | head -c 160)"
    fi
elif [ "$DO_EXEC" = "true" ]; then
    check INFO "in-pod connectivity probes" "skipped (agent pod not found)"
elif [ "$DO_EXEC" = "rbac-denied" ]; then
    check INFO "in-pod connectivity probes" "skipped (RBAC denies pods/exec)"
else
    check INFO "in-pod connectivity probes" "skipped (--no-exec)"
fi

# ---------------------------------------------------------------------------
# Log forwarder (scheduler/compactor sidecars shipping logs to Sedai Loki)
# ---------------------------------------------------------------------------
# The log-forwarder sidecar streams the main container's logs from the Kube API
# (pod SA needs "get pods/log") and POSTs them with basic auth to
# https://$LOKI_HOST:$LOKI_PORT/loki/api/v1/push (secret sedai-smart-scheduler-
# loki-secret). Only LOKI_HOST/LOKI_PORT (the endpoint) are ever read from that
# secret — the username/password are only referenced in-pod, never collected.
log "Checking log-forwarder setup..."
LOGFWD="$ROOT/log-forwarder"
mkdir -p "$LOGFWD"
LOKI_SECRET="sedai-smart-scheduler-loki-secret"
LOKI_PUSH_PATH="/loki/api/v1/push"

FWD_PODS="$($KUBECTL get pods -n "$NAMESPACE" -o jsonpath='{range .items[*]}{.metadata.name}{"="}{range .spec.containers[*]}{.name}{","}{end}{"\n"}{end}' 2>/dev/null | awk -F= '$2 ~ /(^|,)log-forwarder(,|$)/ {print $1}' || true)"

if [ -z "$FWD_PODS" ]; then
    check INFO "log forwarder deployed" "no log-forwarder sidecars in $NAMESPACE (smart-scheduler or logForwarder disabled)"
    echo "no pods with a log-forwarder container found in $NAMESPACE" > "$LOGFWD/not-deployed.txt"
else
    check PASS "log forwarder deployed" "sidecars in: $(echo $FWD_PODS | tr '\n' ' ')"

    # --- Loki secret: key NAMES + endpoint host/port only ---
    LOKI_HOST_VAL=""; LOKI_PORT_VAL=""
    loki_keys="$($KUBECTL get secret "$LOKI_SECRET" -n "$NAMESPACE" -o jsonpath='{.data}' 2>/dev/null | tr ',{}' '\n' | sed -E 's/"([^"]+)":.*/\1/' | grep -v '^$' || true)"
    if [ -z "$loki_keys" ]; then
        check FAIL "loki secret present" "$LOKI_SECRET missing/unreadable (sidecars cannot start without it)"
    else
        missing=""
        for k in LOKI_HOST LOKI_PORT LOKI_USERNAME LOKI_PASSWORD; do
            echo "$loki_keys" | grep -qx "$k" || missing="$missing $k"
        done
        if [ -z "$missing" ]; then
            check PASS "loki secret present" "$LOKI_SECRET has all expected keys"
        else
            check FAIL "loki secret present" "$LOKI_SECRET missing keys:$missing"
        fi
        b64dec="base64 -d"; echo test | base64 -d >/dev/null 2>&1 || b64dec="base64 -D"
        LOKI_HOST_VAL="$($KUBECTL get secret "$LOKI_SECRET" -n "$NAMESPACE" -o jsonpath='{.data.LOKI_HOST}' 2>/dev/null | $b64dec || true)"
        LOKI_PORT_VAL="$($KUBECTL get secret "$LOKI_SECRET" -n "$NAMESPACE" -o jsonpath='{.data.LOKI_PORT}' 2>/dev/null | $b64dec || true)"
        echo "loki endpoint: https://${LOKI_HOST_VAL:-<unset>}:${LOKI_PORT_VAL:-<unset>}$LOKI_PUSH_PATH" > "$LOGFWD/loki-endpoint.txt"
        echo "secret keys present: $(echo $loki_keys | tr '\n' ' ') (credential values not collected)" >> "$LOGFWD/loki-endpoint.txt"
    fi

    FIRST_FWD_POD="$(echo "$FWD_PODS" | head -1)"

    # --- forwarder script configmap (as mounted by the pod) ---
    fwd_cm="$($KUBECTL get pod "$FIRST_FWD_POD" -n "$NAMESPACE" -o jsonpath='{.spec.volumes[?(@.name=="log-forwarder-script")].configMap.name}' 2>/dev/null || true)"
    [ -n "$fwd_cm" ] && run "$LOGFWD/forward-logs-configmap.txt" "Log-forwarder script configmap" \
        $KUBECTL get configmap "$fwd_cm" -n "$NAMESPACE" -o yaml

    # --- RBAC: can the pod's SA stream pod logs? (read-only SubjectAccessReview) ---
    fwd_sa="$($KUBECTL get pod "$FIRST_FWD_POD" -n "$NAMESPACE" -o jsonpath='{.spec.serviceAccountName}' 2>/dev/null || true)"
    if [ -n "$fwd_sa" ]; then
        can_logs="$($KUBECTL auth can-i get pods --subresource=log -n "$NAMESPACE" --as="system:serviceaccount:${NAMESPACE}:${fwd_sa}" 2>/dev/null || echo error)"
        if [ "$can_logs" = "yes" ]; then
            check PASS "log-forwarder RBAC (get pods/log)" "SA $fwd_sa may stream pod logs"
        else
            check FAIL "log-forwarder RBAC (get pods/log)" "SA $fwd_sa cannot get pods/log ($can_logs) — forwarder has nothing to ship"
        fi
    fi

    # --- per-pod sidecar state + logs + push-failure count ---
    for pod in $FWD_PODS; do
        run "$LOGFWD/${pod}-sidecar-status.txt" "log-forwarder container status in $pod" $KUBECTL get pod "$pod" -n "$NAMESPACE" \
            -o jsonpath='{range .status.containerStatuses[?(@.name=="log-forwarder")]}restarts={.restartCount} ready={.ready} state={.state} lastState={.lastState}{"\n"}{end}'
        run "$LOGFWD/${pod}-sidecar.log" "log-forwarder sidecar logs ($pod)" \
            $KUBECTL_LONG logs "$pod" -n "$NAMESPACE" -c log-forwarder --since="$LOG_SINCE" --tail=2000 --timestamps=true
        fwd_ready="$($KUBECTL get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[?(@.name=="log-forwarder")].ready}' 2>/dev/null || true)"
        fwd_restarts="$($KUBECTL get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[?(@.name=="log-forwarder")].restartCount}' 2>/dev/null || echo '?')"
        if [ "$fwd_ready" = "true" ] && [ "$fwd_restarts" = "0" ]; then
            check PASS "log-forwarder sidecar healthy ($pod)" "ready, 0 restarts"
        elif [ "$fwd_ready" = "true" ]; then
            check WARN "log-forwarder sidecar healthy ($pod)" "ready but restartCount=$fwd_restarts"
        else
            check FAIL "log-forwarder sidecar healthy ($pod)" "ready=$fwd_ready restarts=$fwd_restarts"
        fi
        push_fails="$(grep -c 'Loki push failed' "$LOGFWD/${pod}-sidecar.log" 2>/dev/null)" || true
        if [ "${push_fails:-0}" -gt 0 ] 2>/dev/null; then
            check WARN "loki push failures in sidecar logs ($pod)" "$push_fails 'Loki push failed' lines in window"
        else
            check PASS "loki push failures in sidecar logs ($pod)" "none in collected window"
        fi
    done

    # --- Loki endpoint reachability ---
    # From this machine (informational: workstation egress differs from cluster egress)
    if [ -n "$LOKI_HOST_VAL" ] && command -v curl >/dev/null 2>&1; then
        local_code="$(curl -sS -o /dev/null -w '%{http_code}' -m 10 -X POST "https://${LOKI_HOST_VAL}:${LOKI_PORT_VAL:-443}${LOKI_PUSH_PATH}" 2>&1 | tail -c 3)"
        echo "local unauthenticated POST -> HTTP ${local_code}" >> "$LOGFWD/loki-endpoint.txt"
        check INFO "loki endpoint from this machine" "unauthenticated POST -> HTTP ${local_code} (401 = reachable, auth enforced)"
    fi

    # From inside the sidecar (authoritative: same network path and creds the forwarder uses)
    if [ "$DO_EXEC" = "true" ]; then
        # Reachability without credentials: any HTTP status proves DNS+TLS+egress work
        unauth_code="$($KUBECTL_PF exec "$FIRST_FWD_POD" -n "$NAMESPACE" -c log-forwarder -- \
            sh -c 'curl -sS -o /dev/null -w "%{http_code}" -m 10 -X POST "https://${LOKI_HOST}:${LOKI_PORT}'"$LOKI_PUSH_PATH"'"' 2>&1 | tail -c 3)"
        echo "in-pod unauthenticated POST -> HTTP ${unauth_code}" >> "$LOGFWD/loki-endpoint.txt"
        case "$unauth_code" in
            [0-9][0-9][0-9])
                if [ "$unauth_code" = "000" ]; then
                    check FAIL "loki endpoint reachable from cluster" "connection failed (egress/DNS/TLS blocked from $FIRST_FWD_POD)"
                else
                    check PASS "loki endpoint reachable from cluster" "endpoint answered HTTP $unauth_code from $FIRST_FWD_POD"
                fi ;;
            *) check FAIL "loki endpoint reachable from cluster" "probe failed: $unauth_code" ;;
        esac

        # End-to-end authenticated test push: one clearly-labeled synthetic log
        # line into Sedai's Loki. Credentials expand inside the pod only.
        push_code="$($KUBECTL_PF exec "$FIRST_FWD_POD" -n "$NAMESPACE" -c log-forwarder -- \
            sh -c 'TS="$(date +%s)000000000"; curl -sS -o /dev/null -w "%{http_code}" -m 10 -X POST -H "Content-Type: application/json" -u "${LOKI_USERNAME}:${LOKI_PASSWORD}" --data-binary "{\"streams\":[{\"stream\":{\"container_name\":\"sedai-diagnostics-probe\",\"tenant\":\"${AGENT_TENANT}\",\"account_id\":\"${AGENT_ACCOUNTID}\"},\"values\":[[\"${TS}\",\"sedai-diagnostics connectivity probe\"]]}]}" "https://${LOKI_HOST}:${LOKI_PORT}'"$LOKI_PUSH_PATH"'"' 2>&1 | tail -c 3)"
        echo "in-pod authenticated test push -> HTTP ${push_code}" >> "$LOGFWD/loki-endpoint.txt"
        case "$push_code" in
            2[0-9][0-9]) check PASS "loki authenticated test push" "HTTP $push_code — end-to-end log path works (stream: sedai-diagnostics-probe)" ;;
            401|403)     check FAIL "loki authenticated test push" "HTTP $push_code — Loki credentials rejected" ;;
            000)         check FAIL "loki authenticated test push" "connection failed" ;;
            *)           check WARN "loki authenticated test push" "unexpected HTTP $push_code" ;;
        esac
    else
        check INFO "loki endpoint reachable from cluster" "skipped (exec probes disabled: $DO_EXEC)"
    fi
fi

# ---------------------------------------------------------------------------
# Admission latency (shared lib): second reading, per-webhook classification
# ---------------------------------------------------------------------------
log "Admission latency: second reading and per-webhook analysis..."
take_readings
analyze_rows
LATDIR="$ROOT/spec-controller/latency"; mkdir -p "$LATDIR"
{
    for n in 1 2; do [ -s "$WORK/ctrl.$n" ] && { echo "### controller /metrics reading $n (via $CTRL_METHOD)"; cat "$WORK/ctrl.$n"; echo; }; done
    [ -s "$WORK/ctrl.1" ] || echo "controller /metrics unavailable: ${CTRL_ERR:-?}"
} | sanitize > "$WISBDIR/controller-metrics.txt"
{
    for n in 1 2; do
        [ -s "$WORK/api.$n" ] || continue
        echo "### API-server admission-webhook series for Sedai webhooks, reading $n"
        cut -d'|' -f2 "$WORK/rows" | sort -u | while IFS= read -r whn; do grep -F "name=\"$whn\"" "$WORK/api.$n"; done
        grep '^process_start_time_seconds' "$WORK/api.$n"; echo
    done
    [ -s "$WORK/api.1" ] || echo "API-server /metrics unavailable: ${API_ERR:-?}"
} | sanitize > "$LATDIR/apiserver-admission-metrics.txt"
{
    echo "Per-webhook admission latency (window ${WINDOW}s; see the connectivity script README for the classes)"
    echo
    cat "$WORK/sig"; echo; cat "$WORK/vl"; echo
    echo "=== API-server view ==="; render_api_view; echo
    echo "=== Controller view ==="; render_ctrl_view; echo
    echo "=== Slow admissions ==="; render_slow_admissions
} | sanitize > "$LATDIR/latency-summary.txt"
proxy_get /sedai/instrumentation/slow-admissions 2>&1 | sanitize > "$LATDIR/slow-admissions.json"
proxy_get /sedai/settings 2>&1 | sanitize > "$LATDIR/settings.json"
if [ "$(json_array_has "$HFLAT" '.capabilities' ADMISSION_LATENCY_QUERY)" = "yes" ]; then
    now_ms=$(( $(date +%s) * 1000 ))
    for ep in $(cut -d'|' -f6 "$WORK/rows" | tr ' ' '\n' | sort -u); do
        echo "### $ep"; proxy_get "/sedai/admission-latency?from=$((now_ms - 86400000))&to=${now_ms}&step=3600&endpoint=${ep}" 2>&1; echo
    done | sanitize > "$LATDIR/admission-latency-history.json"
fi

if [ -s "$WORK/ctrl.1" ]; then check PASS "controller metrics reachable" "via $CTRL_METHOD (HTTP port $HTTP_PORT)"
else check INFO "controller metrics reachable" "unavailable: ${CTRL_ERR:-?}"; fi
if [ "$HAS_STAGE" = "yes" ]; then check PASS "controller latency metrics present" "stage histograms found"
elif [ -s "$WORK/ctrl.1" ]; then check INFO "controller latency metrics present" "controller ${CTRL_VERSION:-?} predates them (need v2.0.6+ on 2.0, or v2.2.0+)"
else check INFO "controller latency metrics present" "unknown (controller /metrics unavailable)"; fi
check INFO "controller version" "${CTRL_VERSION:-unknown}"
case "$(json_get "$HFLAT" '.db.migrationDirty')" in
    true)  check FAIL "spec-controller DB migration clean" "migration $(json_get "$HFLAT" '.db.migrationVersion') is marked dirty" ;;
    false) check PASS "spec-controller DB migration clean" "migration $(json_get "$HFLAT" '.db.migrationVersion')" ;;
esac
sflat="$(json_flat < "$LATDIR/settings.json")"
si="$(json_index_of "$sflat" '' key instrumentation.enabled)"
instr="${si:+$(json_get "$sflat" "[$si].value")}"
check INFO "instrumentation enabled" "${instr:-unknown (settings unavailable or controller predates them)}"
[ "${CTRL_POD_COUNT:-0}" -gt 1 ] && check WARN "multiple controller replicas" "$CTRL_POD_COUNT Running (single-replica by design); latency series summed"
fo_warn_pct="$(awk -v f="$LAT_HIST_FAILOPEN_WARN_FRAC" 'BEGIN { print 100 * f }')"
while IFS='|' read -r c_id c_class c_to c_over c_fow c_hist; do
    [ -n "$c_id" ] || continue
    detail="$c_class | over ${c_to}s: $c_over | fail-open in window: $c_fow${c_hist:+ | historical: $c_hist}"
    hist_warn="no"
    case "$c_hist" in *HISTORICALLY-SLOW*) hist_warn="yes" ;; esac
    if printf '%s' "$c_hist" | awk -v t="$fo_warn_pct" 'match($0, /\(([0-9.]+)% of requests\)/) { v = substr($0, RSTART + 1, RLENGTH - 15); if (v + 0 >= t) found = 1 } END { exit !found }'; then hist_warn="yes"; fi
    case "$c_class" in
        DROPPING*|SLOW*) check FAIL "admission latency vs timeout ($c_id)" "$detail" ;;
        POSSIBLY-SLOW)   check WARN "admission latency vs timeout ($c_id)" "$detail" ;;
        OK)              if [ "$hist_warn" = "yes" ]; then check WARN "admission latency vs timeout ($c_id)" "$detail"; else check PASS "admission latency vs timeout ($c_id)" "$detail"; fi ;;
        *)               if [ "$hist_warn" = "yes" ]; then check WARN "admission latency vs timeout ($c_id)" "$detail"; else check INFO "admission latency vs timeout ($c_id)" "$detail"; fi ;;
    esac
done < "$WORK/classes"

# ---------------------------------------------------------------------------
# Events + log signature analysis
# ---------------------------------------------------------------------------
log "Collecting events and scanning logs for known failure signatures..."
run "$ROOT/events/namespace-events.txt" "Events in $NAMESPACE (by time)" \
    $KUBECTL get events -n "$NAMESPACE" --sort-by=.lastTimestamp
run "$ROOT/events/warning-events.txt" "Warning events in $NAMESPACE" \
    $KUBECTL get events -n "$NAMESPACE" --field-selector type=Warning --sort-by=.lastTimestamp

# Error signatures drive the WARN check; the broad spec-controller terms only
# feed an informational extract (they match routine INFO logging too).
AGENT_ERR_SIGS='SSLHandshakeException|PKIX path|certificate_unknown|unable to find valid certification|Connection refused|UnknownHostException|SocketTimeoutException|ConnectTimeoutException|ResourceAccessException|NoHttpResponseException|handshake_failure'
AGENT_TOPIC_SIGS='Spec Controller|spec.controller|SpecController|kubespeccontroller'
CTRL_ERR_SIGS='TLS handshake error|x509|bad certificate|panic|fatal|SIGSEGV|bind: address already in use|connection reset'
case "$STORE" in
    postgres) CTRL_ERR_SIGS="$CTRL_ERR_SIGS|too many clients|deadlock detected|pq: |pgconn|context deadline exceeded" ;;
    sqlite)   CTRL_ERR_SIGS="$CTRL_ERR_SIGS|database is locked|no such table" ;;
esac
# A plain-HTTP liveness/readiness probe against the HTTPS port logs a TLS handshake
# error every few minutes; it is noise, not a webhook failure.
PROBE_NOISE='client sent an HTTP request to an HTTPS server'

# analyze_logs <logfile> <error-sigs> <topic-sigs|-> <outfile> <label>
analyze_logs() {
    local src="$1" errsigs="$2" topicsigs="$3" out="$4" label="$5"
    [ -s "$src" ] || { echo "no logs collected for $label" > "$out"; return; }
    {
        echo "### Failure-signature scan of $label logs (window: $LOG_SINCE, tail: $LOG_TAIL)"
        echo
        echo "--- error-signature match counts ---"
        echo "$errsigs" | tr '|' '\n' | while read -r sig; do
            [ -z "$sig" ] && continue
            n="$(grep -ciE "$sig" "$src" 2>/dev/null)" || true
            [ "${n:-0}" != "0" ] && printf '%8s  %s\n' "$n" "$sig"
        done
        echo
        echo "--- last 100 error-signature lines ---"
        grep -iE "$errsigs" "$src" | tail -100
        if [ "$topicsigs" != "-" ]; then
            echo
            echo "--- last 200 spec-controller-related lines (informational) ---"
            grep -iE "$topicsigs" "$src" | tail -200
            echo
            echo "--- spec-controller-related ERROR/WARN lines ---"
            grep -iE "$topicsigs" "$src" | grep -E ' (ERROR|WARN) ' | tail -100
        fi
    } > "$out"
    local total
    total="$(grep -ciE "$errsigs" "$src" 2>/dev/null)" || true
    if [ "${total:-0}" -gt 0 ] 2>/dev/null; then
        check WARN "$label log failure signatures" "$total matching lines (see checks/${out##*/})"
    else
        check PASS "$label log failure signatures" "none found in collected window"
    fi
}

analyze_logs "$ROOT/smart-agent/logs-current.log" "$AGENT_ERR_SIGS" "$AGENT_TOPIC_SIGS" "$ROOT/checks/agent-log-signature-scan.txt" "smart-agent"
ctrl_log_src="$ROOT/spec-controller/logs-current.log"
if [ -s "$ctrl_log_src" ]; then
    noise_n="$(grep -c -- "$PROBE_NOISE" "$ctrl_log_src" 2>/dev/null)" || true
    grep -v -- "$PROBE_NOISE" "$ctrl_log_src" > "$WORK/ctrl-logs-signal.log"
    ctrl_log_src="$WORK/ctrl-logs-signal.log"
    [ "${noise_n:-0}" -gt 0 ] && check INFO "spec-controller probe TLS noise" "$noise_n plain-HTTP probe handshake errors (a probe hitting the HTTPS port; not a webhook failure)"
fi
analyze_logs "$ctrl_log_src" "$CTRL_ERR_SIGS" "-" "$ROOT/checks/controller-log-signature-scan.txt" "spec-controller"

# ---------------------------------------------------------------------------
# Consolidated per-component health (one-file answers)
# ---------------------------------------------------------------------------
# Roll the health signals — otherwise spread across connectivity/, the component
# dir, and the check table — into a single file per component. This duplicates
# data already in the bundle for convenience; summary.txt stays the authority.
log "Assembling consolidated per-component health files..."

# embed_file <path> [fallback]: print a collected file, or a note if it is absent.
embed_file() { if [ -s "$1" ]; then cat "$1"; else echo "${2:-(not collected)}"; fi; }
# emit_checks <name-regex>: the CHECK lines whose NAME (anchored after the status)
# matches, so a keyword in a detail column cannot pull in an unrelated component.
emit_checks() {
    local out
    out="$(printf '%s\n' ${CHECKS[@]+"${CHECKS[@]}"} | grep -E "^[A-Z]+ +($1)" 2>/dev/null || true)"
    [ -n "$out" ] && printf '%s\n' "$out" || echo "(no matching checks recorded)"
}

# --- Smart agent ---
{
    echo "=== Sedai Smart Agent — consolidated health ==="
    echo "generated : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "namespace : $NAMESPACE"
    echo "pod       : ${AGENT_POD:-NOT FOUND}"
    echo "deployment: ${AGENT_DEPLOY:-<unresolved>}"
    echo
    echo "--- Readiness & restarts ---"
    [ -n "$AGENT_DEPLOY" ] && echo "deployment readyReplicas : $($KUBECTL get deploy "$AGENT_DEPLOY" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}/{.status.replicas}' 2>/dev/null || echo '?')"
    [ -n "$AGENT_POD" ] && $KUBECTL get pod "$AGENT_POD" -n "$NAMESPACE" -o jsonpath='{range .status.containerStatuses[*]}container={.name} restarts={.restartCount} ready={.ready} state={.state}{"\n"}{end}' 2>/dev/null
    echo
    echo "--- Self-health endpoint ($AGENT_SELF_HEALTH_URL, in-pod) ---"
    embed_file "$CONN/agent-self-health.txt" "(agent self-health not collected — needs pods/exec)"
    echo
    echo "--- Agent -> controller reachability & TLS ---"
    embed_file "$CONN/agent-to-controller-health.txt" "(reachability probe not collected)"
    embed_file "$CONN/agent-to-controller-health-tls-verified.txt" ""
    echo
    echo "--- Agent -> controller configuration ---"
    embed_file "$CONN/agent-config-crosscheck.txt" "(config cross-check not collected)"
    echo
    echo "--- Related check verdicts (authority: summary.txt) ---"
    emit_checks 'smart-agent|agent '
} | sanitize > "$ROOT/smart-agent/health.txt"

# --- Spec controller ---
{
    echo "=== Sedai Kube Spec Controller — consolidated health ==="
    echo "generated : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "namespace : $NAMESPACE"
    echo "pod       : ${CTRL_POD:-NOT FOUND}"
    echo "deployment: ${CTRL_DEPLOY}"
    echo
    echo "--- Readiness & restarts ---"
    echo "deployment readyReplicas : $($KUBECTL get deploy "$CTRL_DEPLOY" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}/{.status.replicas}' 2>/dev/null || echo '?')"
    [ -n "$CTRL_POD" ] && $KUBECTL get pod "$CTRL_POD" -n "$NAMESPACE" -o jsonpath='{range .status.containerStatuses[*]}container={.name} restarts={.restartCount} ready={.ready} state={.state}{"\n"}{end}' 2>/dev/null
    echo
    echo "--- Supporting resources ---"
    echo "PVC sedai-kube-spec-controller-pvc : phase=$($KUBECTL get pvc sedai-kube-spec-controller-pvc -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo NotFound)"
    echo "service $CONTROLLER_SVC endpoints  : $($KUBECTL get endpoints "$CONTROLLER_SVC" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || echo none)"
    echo
    echo "--- Health endpoint ($CONTROLLER_HEALTH_PATH via API-server proxy) ---"
    embed_file "$CONN/controller-health-apiserver-proxy.txt" "(controller health probe not collected)"
    echo
    echo "--- Store ($STORE) ---"
    hf="$HFLAT"
    if [ -n "$hf" ] && [ -n "$(json_get "$hf" '.db.driver')" ]; then
        echo "driver=$(json_get "$hf" '.db.driver') migrationVersion=$(json_get "$hf" '.db.migrationVersion') migrationDirty=$(json_get "$hf" '.db.migrationDirty')"
        printf '%s\n' "$hf" | awk -F'\t' 'index($1, ".db.tableRows.") == 1 { printf "rows %-40s %s\n", substr($1, 15), $2 }'
    else
        echo "(health DB stats unavailable)"
    fi
    echo
    echo "--- WISB/WIRI diagnostics summary ---"
    embed_file "$WISBDIR/diagnostics-summary.json" "(WISB diagnostics summary not collected)"
    echo
    echo "--- Related check verdicts (authority: summary.txt) ---"
    emit_checks 'spec-controller|controller health|controller serves|controller metrics|controller latency|controller version|instrumentation|admission latency|multiple controller|API-server->webhook|server cert|webhook|WISB|TLS secret present'
} | sanitize > "$ROOT/spec-controller/health.txt"

# ---------------------------------------------------------------------------
# Summary, final leak sweep, and packaging
# ---------------------------------------------------------------------------
{
    echo "Sedai Smart Agent / Kube Spec Controller diagnostics"
    echo "===================================================="
    echo "generated : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "namespace : $NAMESPACE"
    echo "context   : ${KCONTEXT:-<current kubeconfig context>}"
    echo "log window: since=$LOG_SINCE tail=$LOG_TAIL   exec probes: $DO_EXEC"
    echo "tools     : openssl=$HAVE_OPENSSL helm=$HAVE_HELM jq=$HAVE_JQ"
    echo
    echo "CHECK RESULTS"
    echo "-------------"
    for line in ${CHECKS[@]+"${CHECKS[@]}"}; do echo "$line"; done
    echo
    echo "Not collected"
    echo "-------------"
    if [ -s "$MISSING" ]; then sort -u "$MISSING" | sed 's/^/- /'; else echo "(nothing — every source answered)"; fi
    echo
    echo "BUNDLE CONTENTS"
    echo "---------------"
    (cd "$WORK" && find "$BUNDLE_NAME" -type f | sort)
    echo
    echo "Note: this bundle contains no secret values, no private keys, and no"
    echo "certificate files — tls/tls-summary.txt holds textual analysis only."
} > "$SUMMARY"

# Final safety sweep: refuse to package if any PEM material (keys OR
# certificates) survived collection.
if grep -rlE -- '-----BEGIN [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE)-----' "$ROOT" >/dev/null 2>&1; then
    echo "ERROR: key/certificate material detected in bundle; aborting packaging." >&2
    echo "Offending files:" >&2
    grep -rlE -- '-----BEGIN [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE)-----' "$ROOT" >&2
    exit 2
fi

mkdir -p "$OUT_DIR"
TARBALL="$OUT_DIR/$BUNDLE_NAME.tar.gz"
tar -czf "$TARBALL" -C "$WORK" "$BUNDLE_NAME"
rm -rf "$WORK"

echo
echo "==================== CHECK SUMMARY ===================="
tar -xzOf "$TARBALL" "$BUNDLE_NAME/summary.txt" | sed -n '/CHECK RESULTS/,/BUNDLE CONTENTS/p' | sed '$d'
echo "======================================================="
echo
echo "Diagnostics bundle written to: $TARBALL"
echo "Review summary.txt inside the bundle, then send the tar.gz to Sedai support."
