# sedai-diagnostics.sh — diagnostics bundle collector

Collects a sanitized, **read-only** diagnostics bundle for the Sedai components installed in a Kubernetes cluster (Smart Agent, Kube Spec Controller, and the log forwarder): logs, health checks, configuration, restart history, connectivity tests, and TLS state, packaged into a single archive with a `summary.txt` listing a PASS/WARN/FAIL result for each automated check. The bundle can be shared with Sedai support.

## Usage

```bash
./sedai-diagnostics.sh                        # defaults: namespace "sedai", current kube context
./sedai-diagnostics.sh -n <namespace>         # Sedai installed in a different namespace
./sedai-diagnostics.sh --context <context>    # explicit kubeconfig context
./sedai-diagnostics.sh --since 24h --tail 5000
./sedai-diagnostics.sh --no-exec              # skip probes that use kubectl exec / port-forward
./sedai-diagnostics.sh --self-test            # verify the redaction filter offline; no cluster access
```

Output: `sedai-diagnostics-<namespace>-<timestamp>.tar.gz` in the current directory (`-o <dir>` to change). A typical run takes one to two minutes.

## What it collects

| Bundle path | Contents |
|---|---|
| `summary.txt` | PASS/WARN/FAIL/INFO results of the automated checks, plus a bundle manifest |
| `cluster/` | kubectl/node versions, workload/service/PVC overview, RBAC self-check, Helm release history and sanitized values (secret **names** only, never values) |
| `smart-agent/`, `spec-controller/` | deployment/pod YAML (env redacted), describes, restart state, current logs (and previous-container logs after restarts) |
| `spec-controller/` extras | service, endpoints, PVC, configmap, mutating webhook configurations, per-webhook registration details with a TLS probe of each registered path |
| `spec-controller/wisb-wiri/` | output of the controller's read-only diagnostics APIs: aggregated configuration counts, the configuration inventory, one sampled full configuration, and Prometheus metrics |
| `tls/` | textual x509 analysis only (subjects, SANs, expiry, fingerprints, chain verification, webhook CA comparison, live served-certificate check) — no certificate files are included |
| `connectivity/` | component health probes via the Kubernetes API-server proxy and from inside the Sedai pods (DNS, HTTPS reachability, self-health) |
| `log-forwarder/` | log-forwarder sidecar state and logs, RBAC verification, and log-endpoint reachability probes including one authenticated test push of a single synthetic log line |
| `events/`, `checks/` | namespace events and log scans for known failure signatures |

## Safety

- **Read-only against the cluster**: only `kubectl get/describe/logs/events/auth`, plus (unless `--no-exec`) `kubectl exec` running read-only commands (`wget`, `nslookup`) inside the already-running Sedai pods and a brief localhost-only `kubectl port-forward` used to read the TLS certificate the controller serves. Nothing is created, modified, or deleted in the cluster.
- **No secrets in the bundle**: Kubernetes Secret values are never read (names/types only, with one non-credential exception: the log endpoint's hostname and port). No private keys and no certificate files are collected. Every file passes through a redaction filter (access keys, encryption keys, tokens, usernames, passwords, authorization headers, cloud credentials, JWTs, certificate data), and packaging aborts if key or certificate material is somehow detected. `--self-test` exercises the redaction filter without touching any cluster.
- **One outbound test**: when the log forwarder is deployed, a single clearly-labeled synthetic log line is sent to the configured Sedai log endpoint to verify the log path end to end.

The bundle contains only plain-text files and can be reviewed before sharing.

## Requirements

`bash` and `kubectl` (required); `openssl`, `helm`, `jq` (optional — used for deeper analysis when present, skipped gracefully otherwise).
