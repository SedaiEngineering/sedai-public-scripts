# sedai-diagnostics.sh — diagnostics bundle collector

Collects a sanitized, **read-only** diagnostics bundle for the Sedai components installed in a Kubernetes cluster (Smart Agent, Kube Spec Controller, and the log forwarder): logs, health checks, configuration, restart history, connectivity tests, and TLS state, packaged into a single archive with a `summary.txt` listing a PASS/WARN/FAIL result for each automated check. The bundle can be shared with Sedai support.

## Usage

```bash
./sedai-diagnostics.sh                        # defaults: namespace "sedai", current kube context
./sedai-diagnostics.sh -n <namespace>         # Sedai installed in a different namespace
./sedai-diagnostics.sh --context <context>    # explicit kubeconfig context
./sedai-diagnostics.sh --since 24h --tail 5000
./sedai-diagnostics.sh --window 120           # longer admission-latency sampling window (default 60s; 0 = lifetime only)
./sedai-diagnostics.sh --no-exec              # skip probes that use kubectl exec / port-forward
./sedai-diagnostics.sh --self-test            # verify the redaction filter offline; no cluster access
```

Output: `sedai-diagnostics-<namespace>-<timestamp>.tar.gz` in the current directory (`-o <dir>` to change). A typical run takes one to two minutes; the latency window overlaps the collection, so it adds little.

A step that fails (RBAC, an older controller version, a timeout) never stops the run: the bundle is still written, and `summary.txt` ends with a **Not collected** list naming each skipped item and why.

## What it collects

| Bundle path | Contents |
|---|---|
| `summary.txt` | PASS/WARN/FAIL/INFO results of the automated checks, the **Not collected** list, and a bundle manifest |
| `cluster/` | kubectl/node versions, workload/service/PVC overview, RBAC self-check, Helm release history and sanitized values (secret **names** only, never values), the cluster-wide namespace list with each namespace's Spark-optimization status (`active` only when labeled `sedai-spark-optimization-enabled=true`, else `inactive`; sorted by status), the live Spark-operator SparkApplications inventory (name, namespace, state, submission/execution attempt counts, run duration, start/termination times, TTL — status/metadata only, never the spec), and the timestamped SparkApplication lifecycle events (submitted/running/completed/failed, with repeat counts — bounded by the cluster's event retention) |
| `smart-agent/`, `spec-controller/` | deployment/pod YAML (env redacted), describes, restart state, current logs (and previous-container logs after restarts), plus a consolidated `health.txt` per component — readiness, restarts, the component's health-endpoint payload, agent→controller reachability/config (agent) or PVC/endpoints/WISB summary (controller), and that component's check verdicts |
| `spec-controller/` extras | service, endpoints, PVC, configmap, mutating webhook configurations, per-webhook registration details with a TLS probe of each registered path |
| `spec-controller/wisb-wiri/` | output of the controller's read-only diagnostics APIs: aggregated configuration counts, the configuration inventory, one sampled full configuration, and the controller's Prometheus metrics (both readings) |
| `spec-controller/latency/` | admission latency per Sedai webhook (see below): `latency-summary.txt` (classification, API-server view, controller view, slow admissions), the API-server admission-webhook series for the Sedai webhooks, `slow-admissions.json`, `settings.json`, and `admission-latency-history.json` (controller v2.2.0+) |
| `spec-controller/db/` | for the Postgres store: StatefulSet YAML, PVC, DB pod describe and logs (the DB secret is never read) |
| `tls/` | textual x509 analysis only (subjects, SANs, expiry, fingerprints, chain verification, webhook CA comparison, live served-certificate check) — no certificate files are included |
| `connectivity/` | component health probes via the Kubernetes API-server proxy and from inside the Sedai pods (DNS, HTTPS reachability, self-health) |
| `log-forwarder/` | log-forwarder sidecar state and logs, RBAC verification, and log-endpoint reachability probes including one authenticated test push of a single synthetic log line |
| `events/`, `checks/` | namespace events and log scans for known failure signatures |

## Admission latency

Every Sedai webhook is `failurePolicy: Ignore`, so a controller that answers slower than the webhook's `timeoutSeconds`, or that the API server cannot reach, drops mutations silently. The bundle takes one metric reading at the start and one at least `--window` seconds later. For each Sedai webhook, `summary.txt` then gets an `admission latency vs timeout (<webhook>)` check:

- **FAIL** for `DROPPING` (mutations dropped in the window) or `SLOW` (at least 3 calls over the timeout). The detail says whether the time is spent inside the controller (and which stage) or outside it.
- **WARN** for `POSSIBLY-SLOW`, or when historical counts since the API server started are high.
- **PASS** for `OK`.
- **INFO** for no traffic, too few calls in the window, or missing data.

The analysis is the same as in [`webhook-connectivity/`](../webhook-connectivity/), whose README explains the classes. Related checks: `controller metrics reachable`, `controller latency metrics present`, `controller version`, `instrumentation enabled` and `multiple controller replicas`.

What you get depends on the controller version:

| Controller version | Stage timings, slow admissions, settings | Handler summary + 24h history |
|---|---|---|
| v2.2.0 and later | yes | yes |
| v2.0.6+ on the 2.0 line | yes | no |
| v2.1.0, v2.0.5 and earlier | no | no |

The API-server side works on any version (fail-open counts need Kubernetes 1.24+).

**Store checks:** for the Postgres store (current chart), the checks are `spec-controller DB pod ready`, `DB restarts`, `DB PVC bound` and `DB migration clean`. Older SQLite installs keep the `spec-controller PVC bound` check. In the controller log scan, TLS handshake errors from a plain-HTTP probe hitting the HTTPS port are reported separately as INFO noise, not as failures.

## Safety

- **Read-only against the cluster**: only `kubectl get/describe/logs/events/auth`, plus (unless `--no-exec`) `kubectl exec` running read-only commands (`wget`, `nslookup`) inside the already-running Sedai pods and a brief localhost-only `kubectl port-forward` used to read the TLS certificate the controller serves. Nothing is created, modified, or deleted in the cluster.
- **No secrets in the bundle**: Kubernetes Secret values are never read (names/types only, with one non-credential exception: the log endpoint's hostname and port). No private keys and no certificate files are collected. Every file passes through a redaction filter (access keys, encryption keys, tokens, usernames, passwords, authorization headers, cloud credentials, JWTs, certificate data), and packaging aborts if key or certificate material is somehow detected. `--self-test` exercises the redaction filter without touching any cluster.
- **One outbound test**: when the log forwarder is deployed, a single clearly-labeled synthetic log line is sent to the configured Sedai log endpoint to verify the log path end to end.

The bundle contains only plain-text files and can be reviewed before sharing.

## Requirements

`bash` (3.2+) and `kubectl` (required); `openssl`, `helm`, `jq`, `curl` (optional — used for deeper analysis when present, skipped gracefully otherwise). For the latency analysis the account also needs `pods/proxy` (controller metrics; `pods/portforward` is the fallback) and `get` on the API server's `/metrics` nonResourceURL.
