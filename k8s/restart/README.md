# sedai-restart.sh — ordered component restart

Restarts the Sedai Kube Spec Controller and the Sedai Smart Agent in the correct order with health verification between steps, and writes a report bundle (`sedai-restart-<namespace>-<timestamp>.tar.gz`) containing the restart timeline, health before/after, and the fresh logs of both new pods.

## Sequence

1. Record pre-restart state (pods, restart counts, health of both components).
2. Restart the controller by scaling to 0, waiting for the pod to terminate, and scaling back up — its data volume is ReadWriteOnce, which a rolling restart cannot handle cleanly. If the scale-down fails, the original replica count is restored so the deployment is never left at 0.
3. Poll the controller's health endpoint until it answers (or a timeout).
4. Only then rollout-restart the agent, wait for the rollout, and poll the agent's health endpoint. If the controller restart failed, the agent restart is skipped.
5. Collect the fresh logs of both new pods and package the report.

## Usage

```bash
./sedai-restart.sh                     # interactive confirmation before any change
./sedai-restart.sh -n <namespace> --context <context>
./sedai-restart.sh --dry-run           # show the plan and current health; change nothing
./sedai-restart.sh --yes               # non-interactive
./sedai-restart.sh --rollout-timeout 300 --health-timeout 180
```

## Safety

This tool **does** change cluster state: two `kubectl scale` calls for the controller and one `kubectl rollout restart` for the agent, guarded by an interactive confirmation prompt (or `--yes`). Everything else it does is read-only, `--dry-run` previews the plan without changing anything, and the report bundle passes through the same redaction filter as the diagnostics collector (no secret values, keys, or certificates).

## Requirements

`bash` and `kubectl`.
