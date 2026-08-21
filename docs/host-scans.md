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
all taints). Each Job copies the [Lynis](https://cisofy.com/lynis/) script tree onto the
node and runs the system audit **chroot'ed into the host root** (bind-mounted at
`/host`), so OS detection, package inventory, and service checks genuinely audit the
node — Lynis's `--rootdir` flag alone only redirects some file checks while still
inventorying the container. The Job writes `report.dat` to the shared scan-results PVC,
and the backend parses it into findings:
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

There is no official upstream Lynis container image, so you provide one. The scan Job
expects the portable Lynis source tree at `/opt/lynis` (it copies that tree into the
host chroot), so build from the upstream tag rather than a distro package:

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash coreutils procps file lsof net-tools ca-certificates git && \
    git clone --depth 1 --branch 3.1.6 \
        https://github.com/CISOfy/lynis.git /opt/lynis && \
    rm -rf /opt/lynis/.git && \
    ln -s /opt/lynis/lynis /usr/local/bin/lynis && \
    apt-get purge -y git && apt-get autoremove -y && apt-get clean && \
    rm -rf /var/lib/apt/lists/*
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
