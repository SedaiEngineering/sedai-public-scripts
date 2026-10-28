# Spec Controller webhook connectivity check

`sedai-webhook-connectivity.sh` is a focused, **read-only** probe that answers one question:

> Can the Kubernetes API server actually reach the Sedai Kube Spec Controller's mutating webhook?

Use it when Spark (or pod) optimization is enabled and correctly labeled, the controller looks healthy, yet **nothing is being mutated** — the classic symptom of the API server being unable to call the webhook while `failurePolicy: Ignore` silently drops the failed admission call.

It produces a **single text file** to send to Sedai support.

## Why this is separate from the diagnostics bundle

The full [`diagnostics/`](../diagnostics/) collector gathers everything. This script is a small, fast, single-purpose companion for one specific failure mode, designed so a customer can run one command and return one file. It does not replace the diagnostics bundle.

## What it does

It captures **both sides of the decisive contrast**:

1. **API server → service**, via the API-server proxy (`kubectl get --raw .../services/https:svc:8443/proxy...`) — the same network path an admission webhook call takes.
2. **localhost → service**, via `kubectl port-forward` + `curl` — which reaches the controller through the node's kubelet and **bypasses** the API-server-to-pod dial.

If (1) fails with `Address is not allowed` / `error trying to reach service` while (2) returns healthy JSON, the controller is fine and the API server simply cannot route to the controller's pod network (often a Pod IP in the reserved `198.18.0.0/15` range, or a CNI/egress path the control plane can't reach). The report leads with a one-line **VERDICT** stating exactly that.

It also records enough to start **root-causing** the fix, not just confirming the fault:

- `/healthz` (confirms you're talking to a real API server, not a Lens/Freelens proxy).
- Controller pod / endpoint / ClusterIP, and the Deployment's `hostNetwork`/`dnsPolicy`.
- Node IPs, a sample of cluster-wide pod IPs, and per-node `podCIDR` (to spot an anomalous range).
- **CNI / IPAM config** — `cilium-config`, Calico IP pools, AWS VPC-CNI ENIConfigs, kube-controller-manager CIDRs — i.e. *why* the pod landed on its IP range.
- The Sedai webhook's `failurePolicy`/path, plus a **live reachability probe of every *Sedai* admission webhook** (webhook-config name contains `sedai`) — two safe GETs per webhook: a **HEALTH** probe (`/sedai/health` on the service, side-effect-free) and a **WEBHOOKPATH** probe (the webhook's own path). Other vendors' webhooks are intentionally not touched. The fault is isolated to the network path by the §6 (API-server proxy) vs §7 (port-forward) contrast; probing all Sedai webhooks additionally catches cases like a stage install working while prod does not.
- `NetworkPolicy` / `CiliumNetworkPolicy` in the Sedai namespace.
- Where available: the API server's `apiserver_admission_webhook_fail_open_count` metric (the direct count of silently-dropped webhook calls) and whether Konnectivity is in use.

Every API-server-proxy probe is bounded with `--request-timeout=10s` so the run can't hang.

What it still **cannot** see (needs the customer's cloud/platform team): the API server's `egress-selector` config, apiserver "failing open" logs, and VPC routes / security groups — those live on the control plane / cloud fabric, out of reach of any in-cluster script.

## Usage

```bash
./sedai-webhook-connectivity.sh [-n <namespace>] [--context <kube-context>] \
                                [--no-port-forward] [-o <output-file>]
```

- `-n, --namespace`   namespace where Sedai is installed (default `sedai`)
- `--context`         kube-context to target (default: current)
- `--no-port-forward` skip the port-forward control test (e.g. no `pods/portforward` RBAC)
- `-o, --output`      output file path (default `./sedai-webhook-connectivity-<ns>-<ts>.txt`)

Then send the single generated file to Sedai support.

## Requirements

- `bash` and `kubectl` with access to the Sedai namespace (and, ideally, permission to use `services/proxy` and `pods/portforward`).
- `curl` — only for the port-forward control test; that one section is skipped if `curl` is absent.
- On **Windows/PowerShell** the backgrounded port-forward won't work; run `--no-port-forward` and do the port-forward + `curl` manually in two terminals.

## Safety

- **Read-only.** Only `kubectl get`/`--raw`, a localhost-only `port-forward`, and `curl` to that local tunnel. It never mutates the cluster.
- **Redacted.** All output passes through a filter that strips tokens, passwords, keys, JWTs, AWS access-key IDs, and basic-auth in URLs. IPs, webhook configs, and metric counters (non-sensitive) are kept.
- Optional sections (`/metrics`, Konnectivity) degrade gracefully when RBAC-denied or blocked on managed clusters.
