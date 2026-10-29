#!/usr/bin/env bash
#
# sedai-webhook-connectivity.sh — focused, READ-ONLY probe of whether the
# Kubernetes API server can reach the Sedai Kube Spec Controller's mutating
# webhooks, and whether they answer within their timeout. Produces ONE text
# file to send to Sedai support.
#
# Every Sedai webhook is failurePolicy: Ignore, so two failures are silent:
#   * UNREACHABLE — the API server cannot dial the controller Pod (e.g. a pod
#     network in 198.18.0.0/15 the control plane cannot route to);
#   * TOO SLOW    — the controller answers slower than the webhook's
#     timeoutSeconds, so the API server gives up and admits unpatched.
# The report measures both: an API-server-proxy probe vs a port-forward control
# for reachability, and — per webhook — dropped mutations (fail-open) and calls
# over the timeout from the API server's metrics next to the controller's own
# stage timings, sampled twice --window seconds apart.
#
# READ ONLY: only `kubectl get`/`--raw`, localhost-only `port-forward`, and `curl`
# to that local tunnel. It never mutates the cluster. Steps that fail are listed
# under "Not collected" and the run continues. Output is redacted.
#
# Usage:
#   ./sedai-webhook-connectivity.sh [-n <namespace>] [--context <kube-context>]
#                                   [--window <seconds>] [--no-port-forward]
#                                   [-o <output-file>] [--self-test]
#
#   --window <s>   seconds between the two metric readings (default 60; 0 = lifetime only)
#   --self-test    run the offline analysis self-test; no cluster access
#
# Requirements: bash, kubectl (required); curl (used for the port-forward
# probes — skipped if absent).

set -uo pipefail

NAMESPACE="sedai"
KCONTEXT=""
DO_PF="true"
OUT=""
WINDOW="60"
SELF_TEST="false"

CONTROLLER_LABEL="app=sedai-kube-spec-controller"
CONTROLLER_DEPLOY="sedai-kube-spec-controller"
CONTROLLER_SVC="sedai-kube-spec-controller-svc"
CONTROLLER_PORT="8443"          # fallback only; the webhook/Service port wins
HEALTH_PATH="/sedai/health"
PF_LOCAL_PORT="18443"
PF_METRICS_PORT="18080"
DUR_METRIC="apiserver_admission_webhook_admission_duration_seconds"
STAGE_METRIC="sedai_pi_admission_stage_duration_seconds"

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--namespace)     NAMESPACE="${2:-}"; shift 2 ;;
        --context)          KCONTEXT="${2:-}"; shift 2 ;;
        --no-port-forward)  DO_PF="false"; shift ;;
        --window)           WINDOW="${2:-}"; shift 2 ;;
        -o|--output)        OUT="${2:-}"; shift 2 ;;
        --self-test)        SELF_TEST="true"; shift ;;
        -h|--help)          usage ;;
        *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
    esac
done
case "$WINDOW" in ''|*[!0-9]*) echo "WARNING: --window must be whole seconds; using 60" >&2; WINDOW=60 ;; esac

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

if [ "$SELF_TEST" = "true" ]; then lat_self_test; exit $?; fi

command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl is required"; exit 1; }
CTX_FLAG=""; [ -n "$KCONTEXT" ] && CTX_FLAG="--context=$KCONTEXT"
# Every call is bounded; the API-server /metrics fetch can be tens of MB, port-forwards stream.
KUBECTL="kubectl --request-timeout=10s${CTX_FLAG:+ $CTX_FLAG}"
KUBECTL_METRICS="kubectl --request-timeout=60s${CTX_FLAG:+ $CTX_FLAG}"
KUBECTL_PF="kubectl${CTX_FLAG:+ $CTX_FLAG}"
HAVE_CURL="false"; command -v curl >/dev/null 2>&1 && HAVE_CURL="true"

TS="$(date -u +%Y%m%d-%H%M%SZ)"
[ -z "$OUT" ] && OUT="$(pwd)/sedai-webhook-connectivity-${NAMESPACE}-${TS}.txt"
: > "$OUT" 2>/dev/null || { echo "ERROR: cannot write output file: $OUT"; exit 1; }

WORK="$(mktemp -d)"; BODY="$WORK/body.txt"; MISSING="$WORK/missing"; : > "$BODY"; : > "$MISSING"
PF_PIDS=""
cleanup() {
    local p
    for p in $PF_PIDS; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
log() { echo "[$(date -u +%H:%M:%S)] $*" >&2; }
note_missing() { printf '%s: %s\n' "$1" "$2" >> "$MISSING"; }

# ---------------------------------------------------------------------------
# Redaction — nothing sensitive should reach the shared file.
# ---------------------------------------------------------------------------
sanitize() {
    sed -E \
        -e 's/((accessKey|access[-_]key|secret[-_]?key|client[-_]?secret|password|passwd|[A-Za-z]*[-_]?token|credential[s]?|api[-_]?key)["'"'"']?[[:space:]]*[:=][[:space:]]*)("[^"]*"|'"'"'[^'"'"']*'"'"'|[^[:space:],}"]+)/\1"[REDACTED]"/Ig' \
        -e 's/(Authorization[[:space:]]*:[[:space:]]*)[^[:space:]].*/\1[REDACTED]/Ig' \
        -e 's/([Bb]earer )[A-Za-z0-9._~+\/=-]{8,}/\1[REDACTED]/g' \
        -e 's/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+/[REDACTED-JWT]/g' \
        -e 's/(AKIA|ASIA)[0-9A-Z]{16}/[REDACTED-AWS-KEY-ID]/g' \
        -e 's#(https?://)[^/@[:space:]]+@#\1[REDACTED]@#g'
}

# section <title>
section() { { echo; echo "==================== $* ===================="; } >> "$BODY"; }
# runsh <description> <shell-command-string> — record command + sanitized output
runsh() {
    local desc="$1" cmd="$2"
    { echo "### $desc"; echo "### \$ $cmd"; } >> "$BODY"
    sh -c "$cmd" 2>&1 | sanitize >> "$BODY"
    echo >> "$BODY"
}
# emit — append stdin to the body, sanitized
emit() { sanitize >> "$BODY"; }


log "Sedai webhook-connectivity probe starting (namespace=$NAMESPACE, window=${WINDOW}s, read-only)"

# ---------------------------------------------------------------------------
# Discovery (every step guarded; failures are recorded, never fatal)
# ---------------------------------------------------------------------------
# `config current-context` ignores --context, so the flag wins when given.
CTX="$KCONTEXT"; [ -z "$CTX" ] && CTX="$($KUBECTL config current-context 2>/dev/null || true)"
APISERVER="$($KUBECTL config view --minify -o jsonpath='{.clusters[*].cluster.server}' 2>/dev/null || true)"
HEALTHZ="$($KUBECTL get --raw /healthz 2>&1 || true)"

ns_out="$($KUBECTL get namespace "$NAMESPACE" -o name 2>&1)" || note_missing "namespace $NAMESPACE" "$(err_reason "$ns_out") — in-namespace checks may be empty"

discover_controller

# ---------------------------------------------------------------------------
# Readings: API-server /metrics, controller /metrics, /sedai/health
# ---------------------------------------------------------------------------
take_readings

log "Control probe: port-forward to svc/${CONTROLLER_SVC} + curl (bypasses the pod-network dial)..."
PF_RESULT="skipped"
if [ "$DO_PF" != "true" ]; then
    PF_RESULT="skipped (--no-port-forward)"
elif [ "$HAVE_CURL" != "true" ]; then
    PF_RESULT="skipped (curl not installed)"
elif ! can_portforward; then
    PF_RESULT="skipped (RBAC denies pods/portforward)"
else
    pf_start "svc/$CONTROLLER_SVC" "$PF_LOCAL_PORT" "$CONTROLLER_PORT"
    waited=0
    while [ "$waited" -lt 10 ]; do
        sleep 1; waited=$((waited + 1))
        out="$(curl -sk --max-time 5 "https://127.0.0.1:${PF_LOCAL_PORT}${HEALTH_PATH}" 2>&1)"
        if [ -n "$out" ]; then PF_RESULT="$out"; break; fi
    done
    pf_stop "$PF_PID"
fi

# ---------------------------------------------------------------------------
# Reachability classification (drives the first verdict line)
# ---------------------------------------------------------------------------

PROXY_WH=""; PROXY_WH_RC="n/a"; PWH_URL=""; PWH_CLASS="n/a"
if [ -n "$WHPATH" ]; then
    PWH_URL="/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy${WHPATH}"
    PROXY_WH="$($KUBECTL get --raw "$PWH_URL" 2>&1)" && PROXY_WH_RC=0 || PROXY_WH_RC=$?
    PWH_CLASS="$(classify_proxy "$PROXY_WH" "$PROXY_WH_RC")"
fi
PHEALTH_URL="/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy${HEALTH_PATH}"
PHEALTH_CLASS="$(classify_proxy "$PROXY_HEALTH" "$PROXY_HEALTH_RC")"

PF_OK="no"
echo "$PF_RESULT" | grep -qiE 'WAITING_FOR_CONFIGS|patchedResources|"status"' && PF_OK="yes"
CH_STATUS="$(printf '%s\n%s\n' "$PF_RESULT" "$PROXY_HEALTH" | sed -nE 's/.*"status"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -1)"
[ -z "$CH_STATUS" ] && CH_STATUS="? (health endpoint not reachable)"

IN_19818="no"
echo " $ENDPOINT_IP $POD_IP " | grep -qE ' 198\.(18|19)\.' && IN_19818="yes"
RANGE_NOTE=""; [ "$IN_19818" = "yes" ] && RANGE_NOTE=" (endpoint IP is in reserved 198.18.0.0/15)"

# Any answer from the server (even Forbidden) proves the API server is reachable.
APISERVER_OK="yes"
case "$HEALTHZ" in ok|*"Error from server"*) ;; *) APISERVER_OK="no" ;; esac
if [ "$APISERVER_OK" != "yes" ]; then
    PHEALTH_CLASS="NO-APISERVER"
elif [ -z "$CTRL_POD" ] && [ "$PHEALTH_CLASS" != "REACHABLE" ]; then
    PHEALTH_CLASS="NO-CONTROLLER"
fi
case "$PHEALTH_CLASS" in
    NO-CONTROLLER) VERDICT="NO CONTROLLER POD — no Running pod matches $CONTROLLER_LABEL in $NAMESPACE, so the Sedai webhooks have no backend and every admission call fails open (nothing is mutated). Check the controller Deployment (replicas, image pull, scheduling, crash loop) first." ;;
    NO-APISERVER) VERDICT="kubectl cannot reach the API server (/healthz: $(err_reason "$HEALTHZ")) — nothing about the webhooks could be measured. Fix the kubeconfig/context or network access and re-run." ;;
    REACHABLE)   VERDICT="API server CAN reach the controller service." ;;
    DIAL-FAILED)
        if [ "$PF_OK" = "yes" ]; then
            VERDICT="UNREACHABLE (CONFIRMED) — the API server cannot reach the controller (dial failed) while the controller is healthy via port-forward. Mutating webhook calls fail the same way and, with failurePolicy=${WHPOLICY:-?}, are silently dropped. Fix the API-server -> controller pod-network path${RANGE_NOTE}.${HOSTNET_FIX}"
        else
            VERDICT="UNREACHABLE — the API server cannot reach the controller, and the port-forward control did not return healthy JSON. Check controller/pod health first, then the network path.${HOSTNET_FIX}"
        fi ;;
    TIMEOUT)     VERDICT="The API server reached the controller service but /sedai/health did not answer within 10s — the controller is overloaded or its DB is slow. See the latency lines." ;;
    TLS-ERROR)   VERDICT="TLS error between the API server and the controller — check the webhook caBundle and the controller certificate (the diagnostics bundle checks both)." ;;
    NO-SERVICE)  VERDICT="Service ${NAMESPACE}/${CONTROLLER_SVC} does not exist — the webhooks point at nothing." ;;
    RBAC-DENIED) VERDICT="Reachability inconclusive — this account cannot use services/proxy (RBAC). Port-forward control healthy: ${PF_OK}." ;;
    *)           VERDICT="Reachability inconclusive — see the REPRODUCER and CONTROL sections." ;;
esac

# ---------------------------------------------------------------------------
# Per-webhook latency analysis
# ---------------------------------------------------------------------------
analyze_rows

# ---------------------------------------------------------------------------
# Detailed sections (all read-only, all sanitized)
# ---------------------------------------------------------------------------
K="$KUBECTL"

section "0. Context & API-server reachability (/healthz must be: ok)"
if [ -n "$KCONTEXT" ]; then runsh "context (from --context)" "echo '$KCONTEXT'"; else runsh "current context" "$K config current-context"; fi
runsh "api server url"       "$K config view --minify -o jsonpath='{.clusters[*].cluster.server}{\"\\n\"}'"
runsh "/healthz"             "$K get --raw /healthz"

section "1. Controller pod / endpoint / service / deployment net settings"
runsh "controller pod"        "$K -n $NAMESPACE get pod -l $CONTROLLER_LABEL -o wide"
runsh "controller endpoints"  "$K -n $NAMESPACE get endpoints $CONTROLLER_SVC -o wide"
runsh "controller service"    "$K -n $NAMESPACE get svc $CONTROLLER_SVC -o wide"
runsh "controller deploy net settings (hostNetwork / dnsPolicy)" "$K -n $NAMESPACE get deploy $CONTROLLER_DEPLOY -o jsonpath='hostNetwork={.spec.template.spec.hostNetwork} dnsPolicy={.spec.template.spec.dnsPolicy}{\"\\n\"}' 2>/dev/null || echo '(deployment not found)'"

section "2. Node IPs (the network a port-forward uses)"
runsh "nodes" "$K get nodes -o wide"

section "3. Sample of pod IPs cluster-wide (what range are pods normally on?)"
runsh "running pod IPs (first 40)" "$K get pods -A -o wide --field-selector status.phase=Running -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,IP:.status.podIP,NODE:.spec.nodeName | head -40"

section "4. Per-node podCIDR (may be blank with Calico/Cilium/VPC-CNI)"
runsh "node podCIDRs" "$K get nodes -o jsonpath='{range .items[*]}{.metadata.name}{\"\\t\"}{.spec.podCIDR}{\"\\t\"}{.spec.podCIDRs}{\"\\n\"}{end}'"

section "5. CNI / IPAM configuration (explains why the controller pod got its IP range)"
runsh "cilium-config (CIDR/IPAM keys)"                    "$K -n kube-system get configmap cilium-config -o yaml 2>/dev/null | grep -iE 'cluster-pool|cluster-cidr|ipam|native-routing|ipv4-(range|cidr)|cidr' || echo '(no cilium-config)'"
runsh "calico IP pools"                                   "$K get ippools.crd.projectcalico.org -o custom-columns=NAME:.metadata.name,CIDR:.spec.cidr,IPIP:.spec.ipipMode,VXLAN:.spec.vxlanMode 2>/dev/null || echo '(no calico ippools)'"
runsh "AWS VPC CNI ENIConfigs"                            "$K get eniconfigs.crd.k8s.amazonaws.com -o custom-columns=NAME:.metadata.name,SUBNET:.spec.subnet 2>/dev/null || echo '(no eniconfigs)'"
runsh "kube-controller-manager CIDRs (self-managed only)" "$K -n kube-system get pod -l component=kube-controller-manager -o jsonpath='{range .items[0].spec.containers[0].command[*]}{@}{\"\\n\"}{end}' 2>/dev/null | grep -iE 'cluster-cidr|service-cluster-ip-range|node-cidr-mask' || echo '(not visible)'"

section "6. REPRODUCER: API server -> service (the path admission webhooks use)"
{
    echo "### health via API-server proxy (reading 1)"
    echo "### \$ $K get --raw \"$PHEALTH_URL\""
    printf '%s\n' "$PROXY_HEALTH" | cut -c1-600
    echo "### classification: $PHEALTH_CLASS"
    echo
    echo "### webhook path via API-server proxy (discovered path: ${WHPATH:-<none found>})"
    if [ -n "$WHPATH" ]; then
        echo "### \$ $K get --raw \"$PWH_URL\""
        printf '%s\n' "$PROXY_WH"
        echo "### classification: $PWH_CLASS"
    else
        echo "(no mutating webhook found whose clientConfig.service.name = $CONTROLLER_SVC)"
    fi
} | emit
echo >> "$BODY"

section "7. CONTROL: port-forward + curl (bypasses the pod-network dial)"
{
    echo "### \$ $K -n $NAMESPACE port-forward svc/$CONTROLLER_SVC ${PF_LOCAL_PORT}:${CONTROLLER_PORT}  +  curl -sk https://127.0.0.1:${PF_LOCAL_PORT}${HEALTH_PATH}"
    printf 'result: %s\n' "$PF_RESULT" | cut -c1-600
    echo "### healthy JSON returned: $PF_OK"
} | emit
echo >> "$BODY"

section "8. Sedai mutating webhook configuration"
{
    printf '%-58s %-52s %-24s %-8s %s\n' "CONFIG" "WEBHOOK" "PATH" "TIMEOUT" "POLICY"
    awk -F'|' 'tolower($1) ~ /sedai/ { printf "%-58s %-52s %-24s %-8s %s\n", $1, $2, ($6 == "" ? "(url)" : $6), $7, $8 }' "$WORK/wh.mutating"
} | emit

section "9. Sedai admission webhook(s) — LIVE reachability probe (webhook path)"
{
    echo "Every Sedai admission webhook (config name contains 'sedai') that targets a Service"
    echo "is probed with one GET of its own path via the API-server proxy — the network path a"
    echo "real admission call takes. The handlers are POST-only, so 404/405 = routes OK."
    echo "Other vendors' webhooks are intentionally NOT probed."
    echo
    printf '%-12s %-40s %s\n' "WEBHOOKPATH" "SERVICE (ns/name:port)" "WEBHOOK (config / name : path)"
    found=0
    for kind in mutating validating; do
        while IFS='|' read -r cfg whn ns svc port path _ _; do
            case "$(printf '%s' "$cfg" | tr '[:upper:]' '[:lower:]')" in *sedai*) ;; *) continue ;; esac
            found=1
            if [ -z "$svc" ]; then printf '%-12s %-40s %s\n' "URL-BASED" "-" "$cfg / $whn"; continue; fi
            log "  probing webhook $cfg / ${whn:-?} -> ${ns}/${svc}:${port:-443}${path:-/}"
            pout="$($KUBECTL get --raw "/api/v1/namespaces/${ns}/services/https:${svc}:${port:-443}/proxy${path:-/}" 2>&1)" && prc=0 || prc=$?
            printf '%-12s %-40s %s\n' "$(classify_proxy "$pout" "$prc")" "${ns}/${svc}:${port:-443}" "$cfg / $whn : ${path:-/}"
        done < "$WORK/wh.$kind"
    done
    [ "$found" -eq 0 ] && echo "(no admission webhook with 'sedai' in its config name found)"
} | emit
echo >> "$BODY"

section "10. NetworkPolicy affecting the Sedai namespace"
runsh "NetworkPolicies in $NAMESPACE"       "$K -n $NAMESPACE get networkpolicy -o wide 2>/dev/null || echo '(none / not supported)'"
runsh "CiliumNetworkPolicies in $NAMESPACE" "$K -n $NAMESPACE get cnp,ccnp 2>/dev/null || echo '(none / not cilium)'"

section "12. (OPTIONAL) Konnectivity / egress proxy present?"
runsh "konnectivity pods" "$K -n kube-system get pods 2>/dev/null | grep -i konnectivity || echo '(none found)'"

section "13. Admission latency — API-server view (per Sedai webhook)"
render_api_view | emit

section "14. Admission latency — controller view"
render_ctrl_view | emit

section "15. Slow admissions (which pods/owners are slow; needs instrumentation.enabled)"
render_slow_admissions | emit

# ---------------------------------------------------------------------------
# Assemble the final single file: header + SIGNALS + VERDICT + body + Not collected
# ---------------------------------------------------------------------------
{
    echo "Sedai Kube Spec Controller — webhook connectivity report"
    echo "========================================================"
    echo "generated : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "namespace : $NAMESPACE"
    echo "context   : ${CTX:-<current kubeconfig context>}"
    echo "apiserver : ${APISERVER:-<unknown>}"
    echo "window    : ${WINDOW}s (API server: $([ "$WIN_API" = "yes" ] && echo ok || echo "unavailable — ${API_WIN_REASON:-?}"); controller: $([ "$WIN_CTRL" = "yes" ] && echo ok || echo "unavailable — ${CTRL_WIN_REASON:-?}"))"
    echo
    echo "SIGNALS"
    echo "-------"
    printf '%-42s %s\n' "kubectl -> API server (/healthz)"        "$(echo "$HEALTHZ" | head -c 60)"
    printf '%-42s %s\n' "controller pod(s)"                       "${CTRL_PODS:-NOT FOUND}"
    printf '%-42s %s\n' "controller version / uptime"             "${CTRL_VERSION:-?} / ${CTRL_AGE}"
    printf '%-42s %s\n' "controller pod IP"                       "${POD_IP:-?}"
    printf '%-42s %s\n' "controller endpoint IP (svc backend)"    "${ENDPOINT_IP:-?}"
    printf '%-42s %s\n' "  in reserved 198.18.0.0/15?"            "$IN_19818"
    printf '%-42s %s\n' "controller hostNetwork"                  "$HOSTNET"
    printf '%-42s %s\n' "service ClusterIP / HTTPS port"          "${CLUSTER_IP:-?} / ${CONTROLLER_PORT}"
    printf '%-42s %s\n' "webhook path / failurePolicy"            "${WHPATH:-<none found>} / ${WHPOLICY:-?}"
    printf '%-42s %s\n' "API server -> service (health proxy)"    "$PHEALTH_CLASS"
    printf '%-42s %s\n' "API server -> service (webhook path)"    "$PWH_CLASS"
    printf '%-42s %s\n' "port-forward + curl (control, healthy?)" "$PF_OK"
    printf '%-42s %s\n' "controller health status"                "$CH_STATUS"
    printf '%-42s %s\n' "controller metrics via"                  "${CTRL_METHOD:-unavailable}"
    printf '%-42s %s\n' "API-server instance uptime"              "$API_AGE"
    cat "$WORK/sig"
    echo
    echo "VERDICT"
    echo "-------"
    echo "$VERDICT" | fold -s -w 78
    fold -s -w 78 "$WORK/vl"
    echo
    echo "(Full command output below. This file is read-only-collected and redacted;"
    echo " please send the whole file to Sedai support.)"
} | sanitize > "$OUT"
cat "$BODY" >> "$OUT"
{
    echo
    echo "Not collected"
    echo "-------------"
    if [ -s "$MISSING" ]; then sort -u "$MISSING" | sed 's/^/- /'; else echo "(nothing — every source answered)"; fi
} | sanitize >> "$OUT"

echo
echo "----------------------------------------------------------------"
# Show SIGNALS only on the console; the VERDICT lives in the file (below).
sed -n '/^SIGNALS$/,/^VERDICT$/p' "$OUT" | sed '$d'
echo "----------------------------------------------------------------"
echo
echo "Report written to: $OUT"
echo "(the VERDICT and full command output are inside that file)"
echo "Send that single file to Sedai support."
