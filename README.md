# sedai-utils

Utility scripts and tools for [Sedai](https://www.sedai.io) platform deployments.

Each tool lives in its own directory with a README covering usage, requirements, and behavior. Scripts are self-contained single files unless noted, and are designed to be safe to run in production environments: read-only wherever possible, with any state-changing action documented explicitly in the tool's README.

## Tools

- **[k8s/](k8s/)** — tools for the Sedai components installed in Kubernetes clusters (diagnostics bundle collector, ordered component restart).

Each platform directory has its own README listing the tools it contains; each tool directory documents usage, requirements, and safety notes.

## Support

For questions about any of these tools, or to share a generated bundle, contact Sedai support through your usual support channel.
