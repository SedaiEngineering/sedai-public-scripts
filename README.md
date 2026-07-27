# sedai-utils

Utility scripts and tools for [Sedai](https://www.sedai.io) platform deployments.

Each tool lives in its own directory with a README covering usage, requirements, and behavior. Scripts are self-contained single files unless noted, and are designed to be safe to run in production environments: read-only wherever possible, with any state-changing action documented explicitly in the tool's README.

## Tools

### Kubernetes ([k8s/](k8s/))

- **[k8s/diagnostics/](k8s/diagnostics/)** — `sedai-diagnostics.sh`: collects a sanitized, read-only diagnostics bundle (logs, health, connectivity, TLS state) for the Sedai Kubernetes components, ready to share with Sedai support.
- **[k8s/restart/](k8s/restart/)** — `sedai-restart.sh`: ordered restart of the Sedai Kube Spec Controller and Smart Agent with health verification between steps and a restart report bundle.

## General requirements

- `bash` and `kubectl` with access to the namespace where the Sedai components are installed.
- Individual tools may use `openssl`, `helm`, or `jq` for deeper checks when available; they degrade gracefully when these are absent.

## Support

For questions about any of these tools, or to share a generated bundle, contact Sedai support through your usual support channel.
