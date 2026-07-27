# Kubernetes tools

Scripts for operating the Sedai components installed in a Kubernetes cluster — the Smart Agent, the Kube Spec Controller, and the log forwarder.

All tools here need `bash` and `kubectl` with access to the namespace where Sedai is installed (default `sedai`; every script accepts `-n <namespace>` and `--context <kube-context>`).

## Tools

| Directory | Script | What it does | Changes the cluster? |
|---|---|---|---|
| [diagnostics/](diagnostics/) | `sedai-diagnostics.sh` | Collects a sanitized, read-only diagnostics bundle (logs, health, connectivity, TLS state) to share with Sedai support | No — read-only |
| [restart/](restart/) | `sedai-restart.sh` | Ordered restart of the Kube Spec Controller and Smart Agent with health verification and a restart report bundle | Yes — two scale calls and one rollout restart, behind a confirmation prompt |

See each directory's README for full usage, output details, and safety notes.
