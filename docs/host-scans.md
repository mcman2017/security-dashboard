# Host OS scanners

The plugin's **Security Scans → Host OS** page surfaces two scanners that audit the
*nodes* rather than the workloads:

- **Lynis host audit** — a first-class scanner orchestrated by the backend: one Job per
  cluster node, results parsed into findings (severities, per-node hardening index, history)
  like the Trivy scans.
- **trivy rootfs** — an optional DaemonSet whose per-node logs are shown raw on the page.

Both are disabled by default in the Helm chart.

## Lynis host audit (backend-orchestrated, per node)

Launching a Lynis scan — from the Host OS page's button, `POST /api/scans`
`{"scanner": "lynis"}`, or the daily schedule — makes the backend create one Job per
cluster node (control-plane nodes included; the pod pins with `nodeName` and tolerates
all taints). Each Job runs a [Lynis](https://cisofy.com/lynis/) system audit against the
host filesystem, mounted read-only at `/rootfs` (`--forensics --rootdir /rootfs/`), writes
`report.dat` to the shared scan-results PVC, and the backend parses it into findings:
warnings → MEDIUM, suggestions → LOW, plus one INFO finding per node carrying the
hardening index. The raw `report.dat` for every node stays viewable on the scan's detail
page.

Enable via chart values:

```yaml
lynis:
  enabled: true
  image: ghcr.io/you/lynis:3.1.6   # you must provide this — see below
  schedule:
    enabled: true        # daily scheduled scan (a CronJob POSTs the launch)
    cron: "30 3 * * *"
    timeZone: ""         # optional, needs Kubernetes >= 1.27
```

The audit Jobs run **privileged with hostPID** in the release namespace (Lynis inspects
host processes, kernel parameters, and the mounted root filesystem), so the namespace must
allow it:

```bash
kubectl label namespace security-dashboard \
  pod-security.kubernetes.io/enforce=privileged --overwrite
```

There is no official upstream Lynis container image, so you provide one:

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache lynis
```

Build it **multi-arch** if your nodes mix CPU architectures — a single-arch image fails
with `exec format error` on the other nodes:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/you/lynis:3.1.6 --push .
```

The scan-results PVC is shared by up to one writer per node during a Lynis scan, so its
access mode must be `ReadWriteMany` on multi-node clusters (the chart default).

## trivy rootfs (DaemonSet, per node)

Runs `trivy rootfs --severity HIGH,CRITICAL` against the host filesystem (mounted read-only
at `/host`) in a daily loop, one pod per node, in its own namespace
(`hostScanners.namespace`, default `trivy-system` — the namespace the plugin's Host OS page
reads pod logs from). Kernel/runtime state and container snapshot directories are skipped so
image contents aren't double-scanned; add cluster-specific paths with
`hostScanners.trivyRootfs.extraSkipDirs` (e.g. a non-default containerd root).

The pod runs as root with a read-only host mount, but is *not* privileged.

Enable via chart values:

```yaml
hostScanners:
  namespace: trivy-system
  createNamespace: true      # labels it PSS privileged
  trivyRootfs:
    enabled: true
```
