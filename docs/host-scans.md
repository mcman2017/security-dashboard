# Host OS scanners

The plugin's **Security Scans → Host OS** page surfaces two optional scanners that audit the
*nodes* rather than the workloads. Both are disabled by default in the Helm chart and run in
their own namespace (`hostScanners.namespace`, default `trivy-system` — the namespace the
plugin's Host OS page reads pod logs from).

Enable them via chart values:

```yaml
hostScanners:
  namespace: trivy-system
  createNamespace: true      # labels it PSS privileged
  trivyRootfs:
    enabled: true
  lynis:
    enabled: true
    image: ghcr.io/you/lynis:3.1.6   # you must provide this — see below
    schedule: "0 3 * * *"
    # nodeSelector: { kubernetes.io/hostname: my-node }   # pin to one node
```

## trivy rootfs (DaemonSet, per node)

Runs `trivy rootfs --severity HIGH,CRITICAL` against the host filesystem (mounted read-only
at `/host`) in a daily loop, one pod per node. Kernel/runtime state and container snapshot
directories are skipped so image contents aren't double-scanned; add cluster-specific paths
with `hostScanners.trivyRootfs.extraSkipDirs` (e.g. a non-default containerd root).

The pod runs as root with a read-only host mount, but is *not* privileged.

## Lynis audit (CronJob, daily)

Runs a [Lynis](https://cisofy.com/lynis/) system audit and prints the report to the pod log.
Privileged + hostPID (Lynis inspects host processes and the mounted root filesystem).

There is no official upstream Lynis container image, so you provide one:

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache lynis
```

```bash
docker build -t ghcr.io/you/lynis:3.1.6 . && docker push ghcr.io/you/lynis:3.1.6
```

Trigger a run manually without waiting for the schedule:

```bash
kubectl create job --from=cronjob/lynis-host-audit lynis-manual -n trivy-system
```
