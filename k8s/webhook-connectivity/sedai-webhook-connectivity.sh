#!/usr/bin/env bash
#
# sedai-webhook-connectivity.sh — focused, READ-ONLY probe of whether the
# Kubernetes API server can actually reach the Sedai Kube Spec Controller's
# mutating webhook. Produces ONE text file to send to Sedai support.
#
# It answers a single question: when a SparkApplication (or pod) is admitted,
# can the API server call the spec-controller webhook? A common failure is the
# controller Pod landing on a pod network the API server cannot route to (e.g.
# a 198.18.0.0/15 range), so the admission call fails and — because the webhook
# is failurePolicy: Ignore — is silently dropped. The controller then looks
# perfectly healthy (a port-forward works) yet never mutates anything.
#
# The report deliberately captures BOTH sides of that contrast:
#   * API-server -> service, via the API-server proxy   (the path webhooks use)
#   * localhost -> service, via kubectl port-forward     (bypasses that path)
# If the first fails while the second succeeds, the controller is fine and the
# API server simply cannot reach its pod network.
#
# READ ONLY: only `kubectl get`/`--raw`, a localhost-only `port-forward`, and a
# `curl` to that local tunnel. It never mutates the cluster. Output is passed
# through a redaction filter (tokens/passwords/keys/JWTs/AWS keys/basic-auth).
#
# Usage:
#   ./sedai-webhook-connectivity.sh [-n <namespace>] [--context <kube-context>]
#                                   [--no-port-forward] [-o <output-file>]
#
# Requirements: bash, kubectl (required); curl (used only for the port-forward
# control test — that one section is skipped if curl is absent).

set -uo pipefail

NAMESPACE="sedai"
KCONTEXT=""
DO_PF="true"
OUT=""

CONTROLLER_LABEL="app=sedai-kube-spec-controller"
CONTROLLER_DEPLOY="sedai-kube-spec-controller"
CONTROLLER_SVC="sedai-kube-spec-controller-svc"
CONTROLLER_PORT="8443"
HEALTH_PATH="/sedai/health"
PF_LOCAL_PORT="18443"
REQ_TIMEOUT="--request-timeout=10s"   # bound every API-server-proxy probe

usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--namespace)     NAMESPACE="$2"; shift 2 ;;
        --context)          KCONTEXT="$2"; shift 2 ;;
        --no-port-forward)  DO_PF="false"; shift ;;
        -o|--output)        OUT="$2"; shift 2 ;;
        -h|--help)          usage ;;
        *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
    esac
done

command -v kubectl >/dev/null 2>&1 || { echo "ERROR: kubectl is required"; exit 1; }
KUBECTL="kubectl"
[ -n "$KCONTEXT" ] && KUBECTL="kubectl --context=$KCONTEXT"
HAVE_CURL="false"; command -v curl >/dev/null 2>&1 && HAVE_CURL="true"

TS="$(date -u +%Y%m%d-%H%M%SZ)"
[ -z "$OUT" ] && OUT="$(pwd)/sedai-webhook-connectivity-${NAMESPACE}-${TS}.txt"
: > "$OUT" 2>/dev/null || { echo "ERROR: cannot write output file: $OUT"; exit 1; }

WORK="$(mktemp -d)"; BODY="$WORK/body.txt"; : > "$BODY"
trap 'rm -rf "$WORK"' EXIT
log() { echo "[$(date -u +%H:%M:%S)] $*" >&2; }

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

log "Sedai webhook-connectivity probe starting (namespace=$NAMESPACE, read-only)"

# ---------------------------------------------------------------------------
# Discovery (values reused in the SIGNALS summary)
# ---------------------------------------------------------------------------
CTX="$($KUBECTL config current-context 2>/dev/null || true)"
APISERVER="$($KUBECTL config view --minify -o jsonpath='{.clusters[*].cluster.server}' 2>/dev/null || true)"
HEALTHZ="$($KUBECTL get --raw /healthz 2>&1 || true)"

CTRL_POD="$($KUBECTL get pods -n "$NAMESPACE" -l "$CONTROLLER_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
POD_IP="";  [ -n "$CTRL_POD" ] && POD_IP="$($KUBECTL get pod "$CTRL_POD" -n "$NAMESPACE" -o jsonpath='{.status.podIP}' 2>/dev/null || true)"
ENDPOINT_IP="$($KUBECTL get endpoints "$CONTROLLER_SVC" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)"
CLUSTER_IP="$($KUBECTL get svc "$CONTROLLER_SVC" -n "$NAMESPACE" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"

# Webhook path + failurePolicy for the webhook whose service is the controller.
WHPATH="$($KUBECTL get mutatingwebhookconfigurations -o jsonpath='{range .items[*].webhooks[*]}{.clientConfig.service.name}{" "}{.clientConfig.service.path}{"\n"}{end}' 2>/dev/null | awk -v s="$CONTROLLER_SVC" '$1==s{print $2; exit}' || true)"
WHPOLICY="$($KUBECTL get mutatingwebhookconfigurations -o jsonpath='{range .items[*].webhooks[*]}{.clientConfig.service.name}{" "}{.failurePolicy}{"\n"}{end}' 2>/dev/null | awk -v s="$CONTROLLER_SVC" '$1==s{print $2; exit}' || true)"

# ---------------------------------------------------------------------------
# The two probes that matter (captured once, reused in body + summary)
# ---------------------------------------------------------------------------
log "Probing API server -> service ${CONTROLLER_SVC} (the path admission webhooks use)..."
PHEALTH_URL="/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy${HEALTH_PATH}"
PROXY_HEALTH="$($KUBECTL get --raw "$PHEALTH_URL" $REQ_TIMEOUT 2>&1)" && PROXY_HEALTH_RC=0 || PROXY_HEALTH_RC=$?

PROXY_WH=""; PROXY_WH_RC="n/a"; PWH_URL=""
if [ -n "$WHPATH" ]; then
    PWH_URL="/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy${WHPATH}"
    PROXY_WH="$($KUBECTL get --raw "$PWH_URL" $REQ_TIMEOUT 2>&1)" && PROXY_WH_RC=0 || PROXY_WH_RC=$?
fi

log "Control probe: port-forward to svc/${CONTROLLER_SVC} + curl (bypasses the pod-network dial)..."
PF_RESULT="skipped"
if [ "$DO_PF" != "true" ]; then
    PF_RESULT="skipped (--no-port-forward)"
elif [ "$HAVE_CURL" != "true" ]; then
    PF_RESULT="skipped (curl not installed)"
elif [ "$($KUBECTL auth can-i create pods/portforward -n "$NAMESPACE" 2>/dev/null || echo no)" != "yes" ]; then
    PF_RESULT="skipped (RBAC denies pods/portforward)"
else
    $KUBECTL port-forward -n "$NAMESPACE" "svc/$CONTROLLER_SVC" "${PF_LOCAL_PORT}:${CONTROLLER_PORT}" >"$WORK/pf.log" 2>&1 &
    PF_PID=$!
    waited=0
    while [ "$waited" -lt 10 ]; do
        sleep 1; waited=$((waited + 1))
        out="$(curl -sk --max-time 5 "https://127.0.0.1:${PF_LOCAL_PORT}${HEALTH_PATH}" 2>&1)"
        if [ -n "$out" ]; then PF_RESULT="$out"; break; fi
    done
    kill "$PF_PID" 2>/dev/null; wait "$PF_PID" 2>/dev/null
fi

# ---------------------------------------------------------------------------
# Classify (drives the one-line verdict)
# ---------------------------------------------------------------------------
# classify_proxy <output> <rc> -> REACHABLE | DIAL-FAILED | RBAC-DENIED | UNKNOWN
classify_proxy() {
    local out="$1" rc="$2"
    if [ "$rc" -eq 0 ] || echo "$out" | grep -qiE 'MethodNotAllowed|method not allowed|the server could not find|WAITING_FOR_CONFIGS|patchedResources|"status"|404|405|400'; then
        echo "REACHABLE"
    elif echo "$out" | grep -qi 'forbidden'; then
        echo "RBAC-DENIED"
    elif echo "$out" | grep -qiE 'error trying to reach service|address is not allowed|no endpoints available|connection refused|timed out|timeout|ServiceUnavailable|x509|tls'; then
        echo "DIAL-FAILED"
    else
        echo "UNKNOWN"
    fi
}

# probe_sedai_webhooks: for every SEDAI admission webhook (the webhook-config name
# contains "sedai") that targets a Service, send two GETs through the API-server
# proxy — the same network path a real admission call takes:
#   HEALTH      = GET $HEALTH_PATH on the service (side-effect-free reachability)
#   WEBHOOKPATH = GET the webhook's own registered path (POST-only handler; a
#                 404/405 still proves the path routes)
# DIAL-FAILED on either means the API server cannot reach that backend. Only
# Sedai-named webhooks are probed; other vendors' webhooks are never touched.
probe_sedai_webhooks() {
    local kind cfg n i whn ns svc port path url hout hrc hclass pout prc pclass found=0
    {
        printf '%-11s %-11s %-40s %s\n' "HEALTH" "WEBHOOKPATH" "SERVICE (ns/name:port)" "WEBHOOK (config / name : path)"
        for kind in mutatingwebhookconfigurations validatingwebhookconfigurations; do
            for cfg in $($KUBECTL get "$kind" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\n' | grep -i sedai); do
                n="$($KUBECTL get "$kind" "$cfg" -o jsonpath='{.webhooks[*].name}' 2>/dev/null | wc -w | tr -d ' ')"
                i=0
                while [ "$i" -lt "${n:-0}" ]; do
                    whn="$($KUBECTL get "$kind" "$cfg" -o jsonpath="{.webhooks[$i].name}" 2>/dev/null)"
                    ns="$($KUBECTL get "$kind" "$cfg" -o jsonpath="{.webhooks[$i].clientConfig.service.namespace}" 2>/dev/null)"
                    svc="$($KUBECTL get "$kind" "$cfg" -o jsonpath="{.webhooks[$i].clientConfig.service.name}" 2>/dev/null)"
                    port="$($KUBECTL get "$kind" "$cfg" -o jsonpath="{.webhooks[$i].clientConfig.service.port}" 2>/dev/null)"
                    path="$($KUBECTL get "$kind" "$cfg" -o jsonpath="{.webhooks[$i].clientConfig.service.path}" 2>/dev/null)"
                    url="$($KUBECTL get "$kind" "$cfg" -o jsonpath="{.webhooks[$i].clientConfig.url}" 2>/dev/null)"
                    i=$((i + 1))
                    found=1
                    if [ -z "$svc" ]; then
                        log "  webhook $cfg / ${whn:-?} -> URL-based (not probed)"
                        printf '%-11s %-11s %-40s %s\n' "URL-BASED" "URL-BASED" "${url:-<none>}" "$cfg / $whn"
                        continue
                    fi
                    log "  probing webhook $cfg / ${whn:-?} -> ${ns}/${svc}:${port:-443} (health + path)"
                    hout="$($KUBECTL get --raw "/api/v1/namespaces/${ns}/services/https:${svc}:${port:-443}/proxy${HEALTH_PATH}" $REQ_TIMEOUT 2>&1)" && hrc=0 || hrc=$?
                    hclass="$(classify_proxy "$hout" "$hrc")"
                    pout="$($KUBECTL get --raw "/api/v1/namespaces/${ns}/services/https:${svc}:${port:-443}/proxy${path:-/}" $REQ_TIMEOUT 2>&1)" && prc=0 || prc=$?
                    pclass="$(classify_proxy "$pout" "$prc")"
                    printf '%-11s %-11s %-40s %s\n' "$hclass" "$pclass" "${ns}/${svc}:${port:-443}" "$cfg / $whn : ${path:-/}"
                done
            done
        done
        [ "$found" -eq 0 ] && echo "(no admission webhook with 'sedai' in its name found)"
    } | sanitize >> "$BODY"
    echo >> "$BODY"
}

PHEALTH_CLASS="$(classify_proxy "$PROXY_HEALTH" "$PROXY_HEALTH_RC")"
PWH_CLASS="n/a"; [ -n "$WHPATH" ] && PWH_CLASS="$(classify_proxy "$PROXY_WH" "$PROXY_WH_RC")"

PF_OK="no"
echo "$PF_RESULT" | grep -qiE 'WAITING_FOR_CONFIGS|patchedResources|"status"' && PF_OK="yes"

# Controller health status (the "status" field from /sedai/health, via whichever
# probe reached it — port-forward first, then the API-server proxy).
CH_STATUS="$(printf '%s\n%s\n' "$PF_RESULT" "$PROXY_HEALTH" | sed -nE 's/.*"status"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -1)"
[ -z "$CH_STATUS" ] && CH_STATUS="? (health endpoint not reachable)"

IN_19818="no"
echo " $ENDPOINT_IP $POD_IP " | grep -qE ' 198\.(18|19)\.' && IN_19818="yes"

if [ "$PHEALTH_CLASS" = "REACHABLE" ]; then
    VERDICT="API server CAN reach the controller service — webhook connectivity is NOT the problem. Look elsewhere (WISBs pushed? agent healthy? namespace labeled?)."
elif [ "$PHEALTH_CLASS" = "DIAL-FAILED" ] && [ "$PF_OK" = "yes" ]; then
    VERDICT="CONFIRMED — the API server cannot reach the controller (dial failed) while the controller is healthy via port-forward. The mutating webhook call fails the same way and, with failurePolicy=${WHPOLICY:-?}, is silently dropped. Fix the API-server -> controller pod-network path${IN_19818:+ (endpoint IP is in reserved 198.18.0.0/15)}."
elif [ "$PHEALTH_CLASS" = "DIAL-FAILED" ] && [ "$PF_OK" != "yes" ]; then
    VERDICT="API server cannot reach the controller AND port-forward did not return healthy JSON — investigate controller/pod health first, then the network path."
elif [ "$PHEALTH_CLASS" = "RBAC-DENIED" ]; then
    VERDICT="Inconclusive — this account cannot use services/proxy (RBAC). Re-run with a context that can, or rely on the port-forward result: control=${PF_OK}."
else
    VERDICT="Inconclusive — see the REPRODUCER and CONTROL sections below and send this file to Sedai support."
fi

# ---------------------------------------------------------------------------
# Detailed sections (all read-only, all sanitized)
# ---------------------------------------------------------------------------
K="$KUBECTL"

section "0. Context & API-server reachability (/healthz must be: ok)"
runsh "current context"      "$K config current-context"
runsh "api server url"       "$K config view --minify -o jsonpath='{.clusters[*].cluster.server}{\"\\n\"}'"
runsh "/healthz"             "$K get --raw /healthz"

section "1. Controller pod / endpoint / service / deployment net settings"
runsh "controller pod"        "$K -n $NAMESPACE get pod -l $CONTROLLER_LABEL -o wide"
runsh "controller endpoints"  "$K -n $NAMESPACE get endpoints $CONTROLLER_SVC -o wide"
runsh "controller service"    "$K -n $NAMESPACE get svc $CONTROLLER_SVC -o wide"
runsh "controller deploy net settings (hostNetwork expected false; dnsPolicy)" "$K -n $NAMESPACE get deploy $CONTROLLER_DEPLOY -o jsonpath='hostNetwork={.spec.template.spec.hostNetwork} dnsPolicy={.spec.template.spec.dnsPolicy}{\"\\n\"}' 2>/dev/null || echo '(deployment not found)'"

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
    echo "### health via API-server proxy"
    echo "### \$ $K get --raw \"$PHEALTH_URL\" $REQ_TIMEOUT"
    printf '%s\n' "$PROXY_HEALTH"
    echo "### classification: $PHEALTH_CLASS"
    echo
    echo "### webhook path via API-server proxy (discovered path: ${WHPATH:-<none found>})"
    if [ -n "$WHPATH" ]; then
        echo "### \$ $K get --raw \"$PWH_URL\" $REQ_TIMEOUT"
        printf '%s\n' "$PROXY_WH"
        echo "### classification: $PWH_CLASS"
    else
        echo "(no mutating webhook found whose clientConfig.service.name = $CONTROLLER_SVC)"
    fi
} | sanitize >> "$BODY"
echo >> "$BODY"

section "7. CONTROL: port-forward + curl (bypasses the pod-network dial)"
{
    echo "### \$ $K -n $NAMESPACE port-forward svc/$CONTROLLER_SVC ${PF_LOCAL_PORT}:${CONTROLLER_PORT}  +  curl -sk https://127.0.0.1:${PF_LOCAL_PORT}${HEALTH_PATH}"
    printf 'result: %s\n' "$PF_RESULT"
    echo "### healthy JSON returned: $PF_OK"
} | sanitize >> "$BODY"
echo >> "$BODY"

section "8. Sedai mutating webhook configuration"
runsh "sedai webhook(s)" "$K get mutatingwebhookconfigurations -o custom-columns=NAME:.metadata.name,WEBHOOK:'.webhooks[*].name',SVC:'.webhooks[*].clientConfig.service.name',PATH:'.webhooks[*].clientConfig.service.path',POLICY:'.webhooks[*].failurePolicy',TIMEOUT:'.webhooks[*].timeoutSeconds' | grep -iE 'NAME|sedai' || true"

section "9. Sedai admission webhook(s) — LIVE reachability probe (health + webhook path)"
{
    echo "Every Sedai admission webhook (webhook-config name contains 'sedai') that targets"
    echo "a Service is probed via the API-server proxy — the same network path a real"
    echo "admission call takes. Two safe GETs per webhook:"
    echo "  HEALTH      = GET ${HEALTH_PATH} on the service (side-effect-free reachability)"
    echo "  WEBHOOKPATH = GET the webhook's own path (POST-only handler; a 404/405 = routes OK)"
    echo "DIAL-FAILED means the API server cannot reach that backend. Other vendors'"
    echo "webhooks are intentionally NOT probed."
    echo
} >> "$BODY"
log "Probing Sedai webhook(s) reachability via API-server proxy..."
probe_sedai_webhooks

section "10. NetworkPolicy affecting the Sedai namespace"
runsh "NetworkPolicies in $NAMESPACE"       "$K -n $NAMESPACE get networkpolicy -o wide 2>/dev/null || echo '(none / not supported)'"
runsh "CiliumNetworkPolicies in $NAMESPACE" "$K -n $NAMESPACE get cnp,ccnp 2>/dev/null || echo '(none / not cilium)'"

section "11. (OPTIONAL) apiserver admission fail-open / request counters"
runsh "fail-open counters (may be RBAC-denied or blocked on managed clusters)" "$K get --raw /metrics 2>/dev/null | grep 'apiserver_admission_webhook_fail_open_count' | head -30 || echo '(unavailable)'"
runsh "request totals for sedai/spark webhooks" "$K get --raw /metrics 2>/dev/null | grep 'apiserver_admission_webhook_request_total' | grep -iE 'spark|sedai' | head -30 || echo '(unavailable)'"

section "12. (OPTIONAL) Konnectivity / egress proxy present?"
runsh "konnectivity pods" "$K -n kube-system get pods 2>/dev/null | grep -i konnectivity || echo '(none found)'"

# ---------------------------------------------------------------------------
# Assemble the final single file: header + SIGNALS + VERDICT + body
# ---------------------------------------------------------------------------
{
    echo "Sedai Kube Spec Controller — webhook connectivity report"
    echo "========================================================"
    echo "generated : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "namespace : $NAMESPACE"
    echo "context   : ${CTX:-<current kubeconfig context>}"
    echo "apiserver : ${APISERVER:-<unknown>}"
    echo
    echo "SIGNALS"
    echo "-------"
    printf '%-42s %s\n' "kubectl -> API server (/healthz)"        "$(echo "$HEALTHZ" | head -c 60)"
    printf '%-42s %s\n' "controller pod"                          "${CTRL_POD:-NOT FOUND}"
    printf '%-42s %s\n' "controller pod IP"                       "${POD_IP:-?}"
    printf '%-42s %s\n' "controller endpoint IP (svc backend)"    "${ENDPOINT_IP:-?}"
    printf '%-42s %s\n' "  in reserved 198.18.0.0/15?"            "$IN_19818"
    printf '%-42s %s\n' "service ClusterIP"                       "${CLUSTER_IP:-?}"
    printf '%-42s %s\n' "webhook path"                            "${WHPATH:-<none found>}"
    printf '%-42s %s\n' "webhook failurePolicy"                   "${WHPOLICY:-?}"
    printf '%-42s %s\n' "API server -> service (health proxy)"    "$PHEALTH_CLASS"
    printf '%-42s %s\n' "API server -> service (webhook path)"    "$PWH_CLASS"
    printf '%-42s %s\n' "port-forward + curl (control, healthy?)" "$PF_OK"
    printf '%-42s %s\n' "controller health status"                "$CH_STATUS"
    echo
    echo "VERDICT"
    echo "-------"
    echo "$VERDICT" | fold -s -w 78
    echo
    echo "(Full command output below. This file is read-only-collected and redacted;"
    echo " please send the whole file to Sedai support.)"
} | sanitize > "$OUT"
cat "$BODY" >> "$OUT"

echo
echo "----------------------------------------------------------------"
# Show SIGNALS only on the console; the VERDICT lives in the file (below).
sed -n '/^SIGNALS$/,/^VERDICT$/p' "$OUT" | sed '$d'
echo "----------------------------------------------------------------"
echo
echo "Report written to: $OUT"
echo "(the VERDICT and full command output are inside that file)"
echo "Send that single file to Sedai support."
