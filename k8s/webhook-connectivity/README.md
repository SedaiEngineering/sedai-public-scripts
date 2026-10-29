# Spec Controller webhook connectivity and latency check

`sedai-webhook-connectivity.sh` is a focused, **read-only** probe that answers two questions about the Sedai Kube Spec Controller's mutating webhooks:

> 1. Can the Kubernetes API server reach the webhooks at all?
> 2. Do the webhooks answer within their `timeoutSeconds`?

Use it when Spark or pod optimization is enabled and correctly labeled, the controller looks healthy, and yet **nothing is being mutated**. Every Sedai webhook is `failurePolicy: Ignore`, so both failures are silent: the API server gives up on the call and admits the object unpatched.

It produces a **single text file** to send to Sedai support.

## Why this is separate from the diagnostics bundle

The full [`diagnostics/`](../diagnostics/) collector gathers everything, and it now includes the same latency analysis. This script is the small, fast companion for these two failure modes: the customer runs one command and returns one file. It does not replace the diagnostics bundle.

## What it does

### Reachability

The script captures **both sides of the decisive contrast**:

1. **API server → service**, via the API-server proxy (`kubectl get --raw .../services/https:svc:8443/proxy...`). This is the same network path an admission webhook call takes.
2. **localhost → service**, via `kubectl port-forward` + `curl`. This reaches the controller through the node's kubelet and **bypasses** the API-server-to-pod dial.

If (1) fails to dial while (2) returns healthy JSON, the controller is fine and the API server cannot route to the controller's pod network. That is often a Pod IP in the reserved `198.18.0.0/15` range, or a CNI/egress path the control plane can't reach. The verdict then recommends running the controller on the host network (Helm value `sedaiPodInterceptor.isHostAddress=true`).

Probe results are classified as follows:

| Class | Meaning |
|---|---|
| `REACHABLE` | Reached the controller. A 404 or 405 on a webhook path counts, because the handlers are POST-only. |
| `DIAL-FAILED` | The API server could not connect to the pod. |
| `TIMEOUT` | The API server connected, but the controller did not answer in time. |
| `TLS-ERROR` | Certificate or caBundle problem. |
| `NO-SERVICE` | The Service is missing. |
| `RBAC-DENIED` | This account cannot use `services/proxy`. |

### Latency: is any webhook too slow?

The script reads metrics twice, `--window` seconds apart (default 60). From the two readings it reports, per Sedai webhook:

- **Dropped mutations** (`apiserver_admission_webhook_fail_open_count`): calls the API server gave up on and admitted unpatched.
- **Calls over the webhook's timeout**, as the API server measured them.
- **The controller's own timing** of the same calls, with the slowest stage named: `owner_resolve` (Kube API owner lookups) or `layer_read` (DB/cache read). It also shows DB pool waits, CPU against the pod's limit, and restarts/OOM.
- **The controller's handler summary** for the last 15 minutes, and a **24-hour hourly history** (controller v2.2.0+).
- **The last slow admissions**, with pod and owner names, when the controller setting `instrumentation.enabled` is on.

The pod and Spark webhooks share one name, so the API server reports them as one row, `pod+spark`. Spark updates appear on their own line.

Each webhook row gets one class, computed **only from the window**:

| Class | Meaning |
|---|---|
| `DROPPING NEVER-REACHED-CONTROLLER` | Mutations were dropped, and the failed calls returned before the timeout, so they never reached the controller. This is intermittent unreachability. |
| `DROPPING` / `SLOW` + `SLOW-IN-CONTROLLER` | The controller itself is slow. Fix the slow stage; raising `timeoutSeconds` (max 30) only buys headroom. |
| `DROPPING` / `SLOW` + `SLOW-OUTSIDE-CONTROLLER` | The API server sees slow calls, but the controller's timed path is fast. The time is spent in the network, TLS or the API server, or in a path the controller doesn't time (decode, HPA writes, workload DELETE). |
| `POSSIBLY-SLOW` | The timeout falls between histogram buckets, so only a range can be given. |
| `OK`, `NO-TRAFFIC` | Self-explanatory. |
| `INSUFFICIENT-WINDOW` | Fewer than 20 calls, or no window at all (see below). |

Counts since the API server or controller started are reported separately as **historical** evidence (`DROPPED-HISTORICALLY`, `HISTORICALLY-SLOW`). They never produce a current-state verdict: every controller restart drops a few calls.

On managed control planes with several API-server instances (EKS, regional GKE, AKS), the two readings can land on different instances. The script detects this from each instance's start time and retries. If it can't get a matching pair, it reports no API-server window and says why.

### What you get per controller version

| Controller version | Stage timings, slow admissions, settings | Handler summary + 24h history |
|---|---|---|
| v2.2.0 and later | yes | yes |
| v2.0.6+ on the 2.0 line | yes | no |
| v2.1.0, v2.0.5 and earlier | no | no |

The API-server view works on every version: it needs Kubernetes 1.24+ for the fail-open counter. Whatever a cluster can't provide is listed under **Not collected** at the end of the report, with the reason. The run never stops because one source failed.

### Root-cause context

The report also records:

- `/healthz` (confirms you're talking to a real API server, not a Lens/Freelens proxy).
- Controller pod, endpoint, ClusterIP, and the Deployment's `hostNetwork`/`dnsPolicy`.
- Node IPs, a sample of cluster-wide pod IPs, and per-node `podCIDR`.
- **CNI / IPAM config:** `cilium-config`, Calico IP pools, AWS VPC-CNI ENIConfigs, kube-controller-manager CIDRs.
- A live probe of every *Sedai* admission webhook's own path. Other vendors' webhooks are never touched.
- `NetworkPolicy` / `CiliumNetworkPolicy` in the Sedai namespace, and whether Konnectivity is in use.

What it still **cannot** see, because it lives on the control plane or cloud fabric: the API server's `egress-selector` config, apiserver "failing open" logs, and VPC routes / security groups.

## Usage

```bash
./sedai-webhook-connectivity.sh [-n <namespace>] [--context <kube-context>] \
                                [--window <seconds>] [--no-port-forward] \
                                [-o <output-file>] [--self-test]
```

- `-n, --namespace`   namespace where Sedai is installed (default `sedai`)
- `--context`         kube-context to target (default: current)
- `--window`          seconds between the two metric readings (default 60; `0` = lifetime numbers only)
- `--no-port-forward` skip the port-forward probes (e.g. no `pods/portforward` RBAC)
- `-o, --output`      output file path (default `./sedai-webhook-connectivity-<ns>-<ts>.txt`)
- `--self-test`       run the offline analysis self-test; no cluster access

A default run takes about 75 seconds, most of it the window. Ctrl-C is safe at any point. Then send the single generated file to Sedai support.

## Requirements

- `bash` (3.2+) and `kubectl` with access to the Sedai namespace. For the full report the account also needs:
  - `services/proxy` (controller health and webhook probes);
  - `pods/proxy` (controller metrics);
  - `pods/portforward` (control probe, and the controller-metrics fallback);
  - `get` on the API server's `/metrics` nonResourceURL (dropped-mutation and latency counts).
- `curl`, only for the port-forward probes; they are skipped if `curl` is absent.
- On **Windows/PowerShell** the backgrounded port-forward won't work. Run with `--no-port-forward`, and do the port-forward + `curl` manually in two terminals.

## Safety

- **Read-only.** Only `kubectl get`/`--raw`, localhost-only `port-forward`, and `curl` to that local tunnel. It never mutates the cluster or any controller setting.
- **Bounded.** Every `kubectl` call has a timeout (60s for the API server's `/metrics`, which can be large), and every `curl` has `--max-time`. Port-forwards are cleaned up on exit or interrupt.
- **Redacted.** All output passes through a filter that strips tokens, passwords, keys, JWTs, AWS access-key IDs and basic-auth in URLs. IPs, webhook configs and metric counters are kept. The slow-admissions list includes namespace, pod and owner names, the same kind of data as the pod listings. Controller settings are tuning knobs with no secrets.
