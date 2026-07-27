#!/usr/bin/env bash
#
# sedai-restart.sh — ordered restart of the Sedai Kube Spec Controller and the
# Sedai Smart Agent, with health verification and a report bundle.
#
# Sequence:
#   1. Record pre-restart state (pods, restart counts, health) of both components.
#   2. Restart the spec controller by scaling it to 0, waiting for the pod to
#      terminate, then scaling back up. (Scale-down/up rather than a rollout:
#      the controller's SQLite PVC is ReadWriteOnce, so a rolling restart can
#      leave the new pod Pending while the volume is still attached to the old.)
#   3. Poll the controller's /sedai/health endpoint until it answers (or timeout).
#   4. Rollout-restart the smart agent, wait for the rollout, poll agent health.
#   5. Collect the fresh logs of both new pods and write a restart summary,
#      packaged as a sanitized tar.gz (same redaction rules as sedai-diagnostics.sh).
#
# The ONLY mutating commands issued are the two "kubectl scale" calls for the
# controller and one "kubectl rollout restart" for the agent. Everything else
# is read-only (get/describe/logs/rollout status/exec wget).
# A confirmation prompt guards the restarts; use --yes for non-interactive runs
# and --dry-run to see what would happen without changing anything.
#
# Usage:
#   ./sedai-restart.sh [-n <namespace>] [--context <kube-context>]
#                      [--rollout-timeout <seconds>] [--health-timeout <seconds>]
#                      [--yes] [--dry-run] [-o <output-dir>]
#
# Requirements: bash, kubectl.

set -uo pipefail

NAMESPACE="sedai"
KCONTEXT=""
ROLLOUT_TIMEOUT="180"
HEALTH_TIMEOUT="120"
ASSUME_YES="false"
DRY_RUN="false"
OUT_DIR="$(pwd)"

CONTROLLER_DEPLOY="sedai-kube-spec-controller"
CONTROLLER_SVC="sedai-kube-spec-controller-svc"
CONTROLLER_PORT="8443"
CONTROLLER_HEALTH_PATH="/sedai/health"
AGENT_LABEL="app.kubernetes.io/name=sedai-smart-agent"
AGENT_SELF_HEALTH_URL="http://127.0.0.1:8080/agent/health"
HEALTH_POLL_INTERVAL="5"
LOG_TAIL="5000"

usage() {
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--namespace)      NAMESPACE="$2"; shift 2 ;;
        --context)           KCONTEXT="$2"; shift 2 ;;
        --rollout-timeout)   ROLLOUT_TIMEOUT="$2"; shift 2 ;;
        --health-timeout)    HEALTH_TIMEOUT="$2"; shift 2 ;;
        --yes|-y)            ASSUME_YES="true"; shift ;;
        --dry-run)           DRY_RUN="true"; shift ;;
        -o|--output)         OUT_DIR="$2"; shift 2 ;;
        -h|--help)           usage ;;
        *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
    esac
done

KUBECTL="kubectl"
[ -n "$KCONTEXT" ] && KUBECTL="kubectl --context=$KCONTEXT"

# Same redaction filter as sedai-diagnostics.sh (kept in sync manually).
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

now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# ---------------------------------------------------------------------------
# Preflight and discovery (read-only)
# ---------------------------------------------------------------------------
if ! command -v kubectl >/dev/null 2>&1; then
    echo "ERROR: kubectl is required"; exit 1
fi
if ! $KUBECTL get namespace "$NAMESPACE" >/dev/null 2>&1; then
    echo "ERROR: cannot access namespace '$NAMESPACE' (check kubeconfig/context/RBAC)"; exit 1
fi

if ! $KUBECTL get deploy "$CONTROLLER_DEPLOY" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "ERROR: deployment $CONTROLLER_DEPLOY not found in $NAMESPACE"; exit 1
fi

AGENT_POD="$($KUBECTL get pods -n "$NAMESPACE" -l "$AGENT_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
AGENT_DEPLOY=""
if [ -n "$AGENT_POD" ]; then
    agent_rs="$($KUBECTL get pod "$AGENT_POD" -n "$NAMESPACE" -o jsonpath='{.metadata.ownerReferences[?(@.kind=="ReplicaSet")].name}' 2>/dev/null || true)"
    [ -n "$agent_rs" ] && AGENT_DEPLOY="$($KUBECTL get rs "$agent_rs" -n "$NAMESPACE" -o jsonpath='{.metadata.ownerReferences[?(@.kind=="Deployment")].name}' 2>/dev/null || true)"
fi
[ -z "$AGENT_DEPLOY" ] && AGENT_DEPLOY="$($KUBECTL get deploy -n "$NAMESPACE" -o name 2>/dev/null | sed 's#deployment.apps/##' | grep -m1 '^sedai-smart-agent' | grep -v spec-controller || true)"
if [ -z "$AGENT_DEPLOY" ]; then
    echo "ERROR: smart-agent deployment not found in $NAMESPACE"; exit 1
fi

can_exec="$($KUBECTL auth can-i create pods/exec -n "$NAMESPACE" 2>/dev/null || echo no)"

controller_health() {
    $KUBECTL get --raw "/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy${CONTROLLER_HEALTH_PATH}" 2>&1
}

agent_health() {
    local pod="$1"
    [ "$can_exec" = "yes" ] || { echo "exec not permitted; relying on pod readiness"; return 0; }
    $KUBECTL exec "$pod" -n "$NAMESPACE" -- wget -q -O- -T 10 "$AGENT_SELF_HEALTH_URL" 2>&1
}

pod_of() {
    local selector="$1"
    $KUBECTL get pods -n "$NAMESPACE" -l "$selector" --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

CTRL_POD_BEFORE="$(pod_of app=sedai-kube-spec-controller)"
AGENT_POD_BEFORE="$(pod_of "$AGENT_LABEL")"

echo
echo "Planned restart in namespace '$NAMESPACE' (context: ${KCONTEXT:-current}):"
echo "  1. deployment/$CONTROLLER_DEPLOY   (current pod: ${CTRL_POD_BEFORE:-none running})"
echo "     scale to 0, wait for termination, scale back up, wait for controller health"
echo "  2. deployment/$AGENT_DEPLOY   (current pod: ${AGENT_POD_BEFORE:-none running})"
echo "     rollout restart, then wait for rollout + agent health"
echo

if [ "$DRY_RUN" = "true" ]; then
    echo "--dry-run: no changes made. Pre-restart health follows."
    echo "controller health: $(controller_health | head -c 200 | sanitize)"
    [ -n "$AGENT_POD_BEFORE" ] && echo "agent health     : $(agent_health "$AGENT_POD_BEFORE" | head -c 200 | sanitize)"
    exit 0
fi

if [ "$ASSUME_YES" != "true" ]; then
    printf "Proceed with the restarts above? [y/N] "
    read -r reply
    case "$reply" in y|Y|yes|YES) ;; *) echo "Aborted; nothing was changed."; exit 1 ;; esac
fi

# ---------------------------------------------------------------------------
# Report setup
# ---------------------------------------------------------------------------
TS="$(date -u +%Y%m%d-%H%M%SZ)"
BUNDLE_NAME="sedai-restart-${NAMESPACE}-${TS}"
WORK="$(mktemp -d)"
ROOT="$WORK/$BUNDLE_NAME"
mkdir -p "$ROOT"
SUMMARY="$ROOT/summary.txt"

declare -a TIMELINE=()
mark() { TIMELINE+=("$(now_utc)  $*"); log "$*"; }

# wait_for_health <label> <health-fn> <arg>
# Polls until the health command output looks like a JSON status or "UP",
# or HEALTH_TIMEOUT elapses. Returns 0 on healthy.
wait_for_health() {
    local label="$1" fn="$2" arg="${3:-}" waited=0 out=""
    while [ "$waited" -le "$HEALTH_TIMEOUT" ]; do
        out="$($fn "$arg" 2>&1 || true)"
        if echo "$out" | grep -qE '"status"|UP|OK'; then
            mark "$label healthy after ${waited}s: $(echo "$out" | head -c 160)"
            return 0
        fi
        sleep "$HEALTH_POLL_INTERVAL"
        waited=$((waited + HEALTH_POLL_INTERVAL))
    done
    mark "$label NOT healthy after ${HEALTH_TIMEOUT}s; last response: $(echo "$out" | head -c 200)"
    return 1
}

# scale_restart <deployment> <pod-selector> <label>
# Scale to 0, wait for the pods to terminate, scale back to the original
# replica count, wait for readiness. Used for the spec controller because its
# RWO PVC blocks a rolling restart's surge pod from starting. If the scale-down
# times out, we still scale back up so the deployment is never left at 0.
scale_restart() {
    local deploy="$1" selector="$2" label="$3" start end orig waited=0
    orig="$($KUBECTL get deploy "$deploy" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null)"
    orig="${orig:-1}"; [ "$orig" = "0" ] && orig=1
    start=$(date +%s)
    mark "scaling deployment/$deploy to 0 (was $orig)"
    if ! $KUBECTL scale "deployment/$deploy" -n "$NAMESPACE" --replicas=0 >> "$ROOT/${label}-rollout.txt" 2>&1; then
        mark "FAILED to scale $deploy down"
        return 1
    fi
    while [ "$waited" -le "$ROLLOUT_TIMEOUT" ]; do
        [ -z "$($KUBECTL get pods -n "$NAMESPACE" -l "$selector" -o name 2>/dev/null)" ] && break
        sleep 3; waited=$((waited + 3))
    done
    if [ "$waited" -gt "$ROLLOUT_TIMEOUT" ]; then
        mark "pods of $deploy did NOT terminate within ${ROLLOUT_TIMEOUT}s; scaling back up anyway"
        $KUBECTL scale "deployment/$deploy" -n "$NAMESPACE" --replicas="$orig" >> "$ROOT/${label}-rollout.txt" 2>&1
        return 1
    fi
    mark "scale-down of $deploy complete after ${waited}s; scaling back up to $orig"
    if ! $KUBECTL scale "deployment/$deploy" -n "$NAMESPACE" --replicas="$orig" >> "$ROOT/${label}-rollout.txt" 2>&1; then
        mark "FAILED to scale $deploy back up to $orig — deployment may be at 0 replicas"
        return 1
    fi
    if $KUBECTL rollout status "deployment/$deploy" -n "$NAMESPACE" --timeout="${ROLLOUT_TIMEOUT}s" >> "$ROOT/${label}-rollout.txt" 2>&1; then
        end=$(date +%s)
        mark "scale-down/up restart of $deploy complete in $((end - start))s"
        return 0
    fi
    mark "$deploy did NOT become ready within ${ROLLOUT_TIMEOUT}s after scale-up"
    return 1
}

# restart_and_wait <deployment> <label>
restart_and_wait() {
    local deploy="$1" label="$2" start end
    start=$(date +%s)
    mark "restarting deployment/$deploy"
    if ! $KUBECTL rollout restart "deployment/$deploy" -n "$NAMESPACE" >> "$ROOT/${label}-rollout.txt" 2>&1; then
        mark "FAILED to trigger restart of $deploy"
        return 1
    fi
    if $KUBECTL rollout status "deployment/$deploy" -n "$NAMESPACE" --timeout="${ROLLOUT_TIMEOUT}s" >> "$ROOT/${label}-rollout.txt" 2>&1; then
        end=$(date +%s)
        mark "rollout of $deploy complete in $((end - start))s"
        return 0
    fi
    end=$(date +%s)
    mark "rollout of $deploy DID NOT complete within ${ROLLOUT_TIMEOUT}s"
    return 1
}

overall="SUCCESS"

# ---------------------------------------------------------------------------
# Pre-restart state
# ---------------------------------------------------------------------------
mark "pre-restart controller pod: ${CTRL_POD_BEFORE:-none}; agent pod: ${AGENT_POD_BEFORE:-none}"
{
    echo "### pre-restart controller health ($(now_utc))"
    controller_health
    echo
    echo "### pre-restart agent health ($(now_utc))"
    [ -n "$AGENT_POD_BEFORE" ] && agent_health "$AGENT_POD_BEFORE"
} 2>&1 | sanitize > "$ROOT/health-before.txt"

# ---------------------------------------------------------------------------
# Step 1+2: spec controller restart (scale 0 -> up), then health
# ---------------------------------------------------------------------------
if scale_restart "$CONTROLLER_DEPLOY" "app=sedai-kube-spec-controller" "spec-controller"; then
    wait_for_health "spec-controller" controller_health || overall="DEGRADED"
else
    overall="FAILED"
fi
CTRL_POD_AFTER="$(pod_of app=sedai-kube-spec-controller)"

# ---------------------------------------------------------------------------
# Step 3: smart agent restart, then health
# ---------------------------------------------------------------------------
AGENT_POD_AFTER=""
if [ "$overall" != "FAILED" ]; then
    if restart_and_wait "$AGENT_DEPLOY" "smart-agent"; then
        AGENT_POD_AFTER="$(pod_of "$AGENT_LABEL")"
        wait_for_health "smart-agent" agent_health "$AGENT_POD_AFTER" || overall="DEGRADED"
    else
        overall="FAILED"
    fi
else
    mark "skipping agent restart because the controller restart failed"
fi
[ -z "$AGENT_POD_AFTER" ] && AGENT_POD_AFTER="$(pod_of "$AGENT_LABEL")"

# ---------------------------------------------------------------------------
# Post-restart health + fresh logs
# ---------------------------------------------------------------------------
sleep 5
{
    echo "### post-restart controller health ($(now_utc))"
    controller_health
    echo
    echo "### post-restart agent health ($(now_utc))"
    [ -n "$AGENT_POD_AFTER" ] && agent_health "$AGENT_POD_AFTER"
} 2>&1 | sanitize > "$ROOT/health-after.txt"

for spec in "spec-controller:app=sedai-kube-spec-controller" "smart-agent:$AGENT_LABEL"; do
    label="${spec%%:*}"; sel="${spec#*:}"
    pod="$(pod_of "$sel")"
    [ -z "$pod" ] && { echo "no running pod for $label" > "$ROOT/${label}-logs.log"; continue; }
    {
        echo "### logs of $pod since restart (tail $LOG_TAIL)"
        $KUBECTL logs "$pod" -n "$NAMESPACE" --all-containers=true --tail="$LOG_TAIL" --timestamps=true
    } 2>&1 | sanitize > "$ROOT/${label}-logs.log"
    errs="$(grep -ciE 'ERROR|Exception|panic|fatal' "$ROOT/${label}-logs.log" 2>/dev/null)" || true
    mark "$label post-restart logs: $(wc -l < "$ROOT/${label}-logs.log" | tr -d ' ') lines, ${errs:-0} error-like lines"
done

# ---------------------------------------------------------------------------
# Summary + packaging
# ---------------------------------------------------------------------------
{
    echo "Sedai ordered restart report"
    echo "============================"
    echo "generated : $(now_utc)"
    echo "namespace : $NAMESPACE"
    echo "context   : ${KCONTEXT:-<current kubeconfig context>}"
    echo "result    : $overall"
    echo
    echo "PODS"
    echo "----"
    echo "spec-controller: ${CTRL_POD_BEFORE:-none} -> ${CTRL_POD_AFTER:-none}"
    echo "smart-agent    : ${AGENT_POD_BEFORE:-none} -> ${AGENT_POD_AFTER:-none}"
    echo
    echo "TIMELINE"
    echo "--------"
    for line in ${TIMELINE[@]+"${TIMELINE[@]}"}; do echo "$line"; done
    echo
    echo "HEALTH BEFORE"
    echo "-------------"
    cat "$ROOT/health-before.txt"
    echo
    echo "HEALTH AFTER"
    echo "------------"
    cat "$ROOT/health-after.txt"
    echo
    echo "FILES"
    echo "-----"
    (cd "$WORK" && find "$BUNDLE_NAME" -type f | sort)
} > "$SUMMARY"

mkdir -p "$OUT_DIR"
TARBALL="$OUT_DIR/$BUNDLE_NAME.tar.gz"
tar -czf "$TARBALL" -C "$WORK" "$BUNDLE_NAME"
rm -rf "$WORK"

echo
echo "==================== RESTART SUMMARY ===================="
tar -xzOf "$TARBALL" "$BUNDLE_NAME/summary.txt" | sed -n '1,/HEALTH BEFORE/p' | sed '$d'
echo "========================================================="
echo
echo "Result: $overall"
echo "Full report (health before/after + fresh logs): $TARBALL"
[ "$overall" = "SUCCESS" ] || exit 1
