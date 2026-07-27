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
# Usage:
#   ./sedai-diagnostics.sh [-n <namespace>] [--context <kube-context>]
#                          [--since <duration>] [--tail <lines>]
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

AGENT_LABEL="app.kubernetes.io/name=sedai-smart-agent"
CONTROLLER_LABEL="app=sedai-kube-spec-controller"
CONTROLLER_SVC="sedai-kube-spec-controller-svc"
CONTROLLER_PORT="8443"
CONTROLLER_HEALTH_PATH="/sedai/health"
TLS_SECRET="sedai-kube-spec-controller-tls"
# 127.0.0.1 rather than localhost: the agent binds IPv4 only and busybox wget
# reports an obscure "Invalid argument" when localhost resolves to ::1 first.
AGENT_SELF_HEALTH_URL="http://127.0.0.1:8080/agent/health"

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--namespace) NAMESPACE="$2"; shift 2 ;;
        --context)      KCONTEXT="$2"; shift 2 ;;
        --since)        LOG_SINCE="$2"; shift 2 ;;
        --tail)         LOG_TAIL="$2"; shift 2 ;;
        --no-exec)      DO_EXEC="false"; shift ;;
        -o|--output)    OUT_DIR="$2"; shift 2 ;;
        --self-test)    SELF_TEST="true"; shift ;;
        -h|--help)      usage ;;
        *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
    esac
done

KUBECTL="kubectl"
[ -n "$KCONTEXT" ] && KUBECTL="kubectl --context=$KCONTEXT"

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

self_test() {
    echo "Running sanitizer self-test..."
    local fixture expected out fail=0
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
if ! $KUBECTL get namespace "$NAMESPACE" >/dev/null 2>&1; then
    echo "ERROR: cannot access namespace '$NAMESPACE' (check kubeconfig/context/RBAC)"; exit 1
fi

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
CTRL_POD="$($KUBECTL get pods -n "$NAMESPACE" -l "$CONTROLLER_LABEL" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
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
        $KUBECTL logs "$pod" -n "$NAMESPACE" --all-containers=true --since="$LOG_SINCE" --tail="$LOG_TAIL" --timestamps=true
    local restarts
    restarts="$($KUBECTL get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo 0)"
    if [ "${restarts:-0}" -gt 0 ] 2>/dev/null; then
        run "$dir/logs-previous.log" "Previous-container logs (pod restarted ${restarts}x)" \
            $KUBECTL logs "$pod" -n "$NAMESPACE" --previous --tail="$LOG_TAIL" --timestamps=true
    fi
    # Historical restarts across replicas (ReplicaSets keep no logs, but events do)
    run "$dir/pods-by-label.txt" "All pods for label $label (incl. terminating/evicted)" \
        $KUBECTL get pods -n "$NAMESPACE" -l "$label" -o wide
}

log "Collecting smart-agent state and logs..."
collect_component "$ROOT/smart-agent" "$AGENT_DEPLOY" "$AGENT_POD" "$AGENT_LABEL"
log "Collecting spec-controller state and logs..."
collect_component "$ROOT/spec-controller" "$CTRL_DEPLOY" "$CTRL_POD" "$CONTROLLER_LABEL"

# Spec-controller supporting objects
run "$ROOT/spec-controller/service.txt" "Controller service" $KUBECTL get svc "$CONTROLLER_SVC" -n "$NAMESPACE" -o yaml
run "$ROOT/spec-controller/endpoints.txt" "Controller endpoints" $KUBECTL get endpoints "$CONTROLLER_SVC" -n "$NAMESPACE" -o yaml
run "$ROOT/spec-controller/pvc.txt" "Controller PVC" $KUBECTL get pvc sedai-kube-spec-controller-pvc -n "$NAMESPACE" -o yaml
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
for c in "smart-agent:$AGENT_POD" "spec-controller:$CTRL_POD"; do
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

# PVC bound?
pvc_phase="$($KUBECTL get pvc sedai-kube-spec-controller-pvc -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo 'NotFound')"
[ "$pvc_phase" = "Bound" ] && check PASS "spec-controller PVC bound" "phase=Bound" \
                           || check FAIL "spec-controller PVC bound" "phase=$pvc_phase"

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
    for wh in $($KUBECTL get mutatingwebhookconfigurations -o name 2>/dev/null | grep sedai | sed 's#.*/##'); do
        wh_ns="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath='{.webhooks[0].clientConfig.service.namespace}' 2>/dev/null || true)"
        wh_bundle="$($KUBECTL get mutatingwebhookconfiguration "$wh" -o jsonpath='{.webhooks[0].clientConfig.caBundle}' 2>/dev/null || true)"
        if [ "$wh_ns" != "$NAMESPACE" ]; then
            echo "$wh -> targets namespace '$wh_ns' (not $NAMESPACE), skipped" >> "$TLSDIR/tls-summary.txt"
            continue
        fi
        if [ "$wh_bundle" = "$ca_b64" ]; then
            echo "$wh -> caBundle MATCHES secret ca.crt" >> "$TLSDIR/tls-summary.txt"
            check PASS "webhook caBundle matches CA ($wh)" "identical to $TLS_SECRET ca.crt"
        else
            echo "$wh -> caBundle DIFFERS from secret ca.crt" >> "$TLSDIR/tls-summary.txt"
            check FAIL "webhook caBundle matches CA ($wh)" "caBundle != $TLS_SECRET ca.crt (webhook TLS trust broken)"
        fi
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
        # TLS handshake and routing to the path work.
        path_out="$($KUBECTL get --raw "/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy${wh_path}" 2>&1)" && path_rc=0 || path_rc=$?
        echo "path probe (${wh_path}): rc=$path_rc $(echo "$path_out" | head -c 160)" >> "$WHREG"
        if [ "$path_rc" -eq 0 ] || echo "$path_out" | grep -qiE 'MethodNotAllowed|method not allowed|the server could not find|404|400'; then
            check PASS "webhook path served over TLS ($wh)" "${wh_path} answers via API-server proxy"
        elif echo "$path_out" | grep -qi 'forbidden'; then
            check INFO "webhook path served over TLS ($wh)" "skipped (RBAC denies services/proxy)"
        elif echo "$path_out" | grep -qiE 'no endpoints available|connection refused|timed out|timeout|TLS|x509'; then
            check FAIL "webhook path served over TLS ($wh)" "$(echo "$path_out" | head -c 160)"
        else
            check WARN "webhook path served over TLS ($wh)" "unexpected: $(echo "$path_out" | head -c 160)"
        fi
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
    $KUBECTL port-forward -n "$NAMESPACE" "svc/$CONTROLLER_SVC" "${pf_port}:${CONTROLLER_PORT}" >/dev/null 2>&1 &
    pf_pid=$!
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

proxy_get() {
    $KUBECTL get --raw "/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy$1" 2>&1
}

# json_field <field> <json> — first integer/string value of "field" (jq when available)
json_field() {
    if [ "$HAVE_JQ" = "true" ]; then
        printf '%s' "$2" | jq -r ".. | objects | select(has(\"$1\")) | .\"$1\"" 2>/dev/null | head -1
    else
        printf '%s' "$2" | sed -nE 's/.*"'"$1"'"[[:space:]]*:[[:space:]]*"?([^,}"]*)"?.*/\1/p' | head -1
    fi
}

sum_out="$(proxy_get /sedai/pod/diagnostics/summary)" && sum_rc=0 || sum_rc=$?
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

list_out="$(proxy_get '/sedai/pod/resourceconfigs/list?pageSize=500')" && list_rc=0 || list_rc=$?
printf '%s\n' "$list_out" | sanitize > "$WISBDIR/podspec-wisb-list-page1.json"
if [ "$list_rc" -eq 0 ]; then
    total_items="$(json_field totalItems "$list_out")"
    total_pages="$(json_field totalPages "$list_out")"
    check PASS "WISB/WIRI config list" "${total_items:-?} configs (page 1 of ${total_pages:-?} captured, pageSize=500)"
    # Fetch up to 2 more pages; log what is left out rather than truncating silently.
    if [ "${total_pages:-1}" -gt 1 ] 2>/dev/null; then
        p=2
        while [ "$p" -le "$total_pages" ] && [ "$p" -le 3 ]; do
            proxy_get "/sedai/pod/resourceconfigs/list?pageSize=500&page=$p" | sanitize > "$WISBDIR/podspec-wisb-list-page$p.json"
            p=$((p + 1))
        done
        [ "${total_pages:-1}" -gt 3 ] && echo "NOTE: only pages 1-3 of $total_pages captured (pageSize=500)" >> "$WISBDIR/podspec-wisb-list-page1.json"
    fi
    # One full WISB+WIRI example: latest configs for the first listed resource.
    sample_id="$(json_field sedaiResourceId "$list_out")"
    if [ -n "$sample_id" ] && [ "$sample_id" != "null" ]; then
        proxy_get "/sedai/pod/resourceconfigs/latest?resourceId=${sample_id}" | sanitize > "$WISBDIR/sample-latest-config.json"
        check INFO "sample latest WISB/WIRI config" "captured for resourceId=$sample_id"
    fi
elif echo "$list_out" | grep -qiE 'forbidden'; then
    check INFO "WISB/WIRI config list" "skipped (RBAC denies services/proxy)"
elif echo "$list_out" | grep -qiE 'the server could not find|404'; then
    check INFO "WISB/WIRI config list" "endpoint not available (older controller version)"
else
    check FAIL "WISB/WIRI config list" "$(echo "$list_out" | head -c 160)"
fi

# Controller Prometheus metrics (request/mutation counters) — informational.
proxy_get /metrics | sanitize > "$WISBDIR/controller-metrics.txt" 2>/dev/null || \
    echo "metrics endpoint not readable" > "$WISBDIR/controller-metrics.txt"

# ---------------------------------------------------------------------------
# Connectivity probes (read-only execs into existing pods; skipped by --no-exec)
# ---------------------------------------------------------------------------
CONN="$ROOT/connectivity"
SVC_FQDN="${CONTROLLER_SVC}.${NAMESPACE}.svc"
HEALTH_URL="https://${SVC_FQDN}:${CONTROLLER_PORT}${CONTROLLER_HEALTH_PATH}"

# From outside the cluster via the API-server service proxy (no exec needed).
log "Probing controller health via API-server proxy..."
proxy_out="$($KUBECTL get --raw "/api/v1/namespaces/${NAMESPACE}/services/https:${CONTROLLER_SVC}:${CONTROLLER_PORT}/proxy${CONTROLLER_HEALTH_PATH}" 2>&1)"
proxy_rc=$?
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
        $KUBECTL exec "$AGENT_POD" -n "$NAMESPACE" -- nslookup "${SVC_FQDN}.cluster.local"

    # Reachability + controller health (TLS cert NOT verified — pure reachability).
    # This uses the same libc resolver path as the agent JVM, so it doubles as
    # the authoritative DNS check.
    health_out="$($KUBECTL exec "$AGENT_POD" -n "$NAMESPACE" -- wget -q -O- -T 10 --no-check-certificate "$HEALTH_URL" 2>&1)"
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
    if $KUBECTL exec "$AGENT_POD" -n "$NAMESPACE" -- wget --version 2>/dev/null | grep -qi 'GNU Wget'; then
        vtls_out="$($KUBECTL exec "$AGENT_POD" -n "$NAMESPACE" -- wget -q -O- -T 10 --ca-certificate=/tls/ca.crt "$HEALTH_URL" 2>&1)"
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
    self_out="$($KUBECTL exec "$AGENT_POD" -n "$NAMESPACE" -- wget -q -O- -T 10 "$AGENT_SELF_HEALTH_URL" 2>&1)"
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
            $KUBECTL logs "$pod" -n "$NAMESPACE" -c log-forwarder --since="$LOG_SINCE" --tail=2000 --timestamps=true
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
        unauth_code="$($KUBECTL exec "$FIRST_FWD_POD" -n "$NAMESPACE" -c log-forwarder -- \
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
        push_code="$($KUBECTL exec "$FIRST_FWD_POD" -n "$NAMESPACE" -c log-forwarder -- \
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
CTRL_ERR_SIGS='TLS handshake error|x509|bad certificate|panic|fatal|SIGSEGV|database is locked|no such table|bind: address already in use|connection reset'

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
analyze_logs "$ROOT/spec-controller/logs-current.log" "$CTRL_ERR_SIGS" "-" "$ROOT/checks/controller-log-signature-scan.txt" "spec-controller"

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
grep -E '^(PASS|WARN|FAIL|INFO)' "$TARBALL" >/dev/null 2>&1 || true
tar -xzOf "$TARBALL" "$BUNDLE_NAME/summary.txt" | sed -n '/CHECK RESULTS/,/BUNDLE CONTENTS/p' | sed '$d'
echo "======================================================="
echo
echo "Diagnostics bundle written to: $TARBALL"
echo "Review summary.txt inside the bundle, then send the tar.gz to Sedai support."
