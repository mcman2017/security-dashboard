# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/mcman2017/security-dashboard/security/advisories/new).
Do not open a public issue for security reports. You should get a response within a week.

## Threat model

This project deliberately holds more privilege than a typical dashboard plugin — it exists to
scan the whole cluster. Here is exactly what each identity can do, and which parts are opt-in.

### The plugin (runs in the viewer's browser)

Uses **the viewer's own Headlamp credentials** for everything: reading Trivy Operator CRDs,
reading host-scanner pod logs, and reaching the backend through the Kubernetes apiserver
**service proxy** (`services/proxy` in the `security-dashboard` namespace). The plugin has no
credentials of its own. Anyone whose identity is allowed `services/proxy` on that service can
launch scans and delete scan history — scope that permission accordingly.

### The backend ServiceAccount (`security-dashboard-backend`)

**Namespaced Role only** — create/watch/delete Jobs and read pod logs/events inside its own
namespace. It has no cluster-wide access.

### The scanner ServiceAccount (`trivy-scanner`)

Bound to a **read-only ClusterRole** (`get`/`list` on workloads, RBAC, network policies,
etc.) so `trivy k8s` can enumerate what to scan. Its token exists only for the lifetime of a
scan Job.

- **Secrets read is opt-in** (`rbac.scanSecrets`, default `false`). When enabled, Trivy can
  flag credentials embedded in Secret YAMLs — at the cost of the scanner being able to read
  every Secret in the cluster. When disabled, Trivy logs "forbidden" warnings and skips those
  checks.

### Scan modes (`scan.mode`)

- **`registry` (default):** scan Jobs pull image layers from registries. No hostPath, no
  node access; the namespace can enforce Pod Security Standards **baseline**.
- **`node-cache` (opt-in):** scan Jobs mount the node's **containerd socket** (hostPath) and
  read already-pulled image layers from the runtime cache. This means a compromise of the
  trivy container has node-wide image-read access, and the namespace must allow PSS
  **privileged**. Use it for air-gapped clusters, private single-arch registries, or to avoid
  registry rate limits — and understand the trade-off.

### Optional host scanners (`hostScanners.*`, default off)

The per-node `trivy rootfs` DaemonSet mounts the host filesystem read-only; the Lynis CronJob
runs privileged with hostPID. Both are off by default and exist for host-OS audit coverage.

### Suppressions

Suppressed findings are **rebucketed, never dropped** — the raw finding and its original
severity remain inspectable, and the parser fails open (a malformed allowlist suppresses
nothing).

### Roadmap note

Planned automated-remediation features will require **write** RBAC. They will ship in a
separate, opt-in ClusterRole (default off) with a dry-run mode.
