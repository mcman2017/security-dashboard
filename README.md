# Security Dashboard for Headlamp

A security-scanning dashboard for [Headlamp](https://headlamp.dev), the CNCF Kubernetes UI.
It adds a **Security Scans** section to Headlamp with on-demand cluster scanning, historical
results, severity roll-ups, and a documented risk-acceptance (suppressions) workflow.

Two parts, one repo:

| Part | What it is |
|------|-----------|
| **Headlamp plugin** (this repo's root, `src/`) | Adds the Security Scans sidebar: Overview, Vulnerabilities, Configuration, RBAC, Compliance, Exposed Secrets, Host OS, and Suppressions pages. |
| **Scan backend** (`backend/`, installed via the [Helm chart](charts/security-dashboard)) | FastAPI service that launches [Trivy](https://trivy.dev) scans as Kubernetes Jobs — CIS Benchmark, NSA/CISA hardening, or a full cluster vulnerability scan — parses and stores the findings, and serves them to the plugin. |

## How it compares

Existing Headlamp security plugins ([headlamp-trivy](https://artifacthub.io/packages/headlamp/headlamp-trivy/headlamp_trivy),
[kubescape-plugin](https://artifacthub.io/packages/headlamp/kubescape-plugin/headlamp_kubescape)) are
viewers for reports that an operator (Trivy Operator / Kubescape operator) already produced.
This project also renders Trivy Operator CRD reports, but its core feature is different:

- **Launch scans on demand** from the UI — CIS 1.23, NSA 1.0, or full CVE — no Trivy Operator required for that path.
- **Scan history with roll-ups** — completed scans aggregate into severity totals; click a severity card to drill into exactly those findings; delete old scans from the UI.
- **Suppressions with justifications** — an auditable allowlist that rebuckets accepted-risk findings to SUPPRESSED (never dropped) and shows the written justification inline.
- **Host OS coverage** — optional per-node `trivy rootfs` and Lynis audit scanners surfaced in the UI.
- **Roadmap: automated remediation** of critical/high findings (opt-in, dry-run first).

## Architecture

```
Headlamp (any install: desktop or in-cluster)
  └─ Security Dashboard plugin
       ├─ Trivy Operator CRDs ──────────── read via the viewer's own credentials
       └─ Kubernetes apiserver service proxy
            └─ security-dashboard-api (FastAPI, Helm chart)
                 ├─ SQLite (PVC): scans + findings
                 └─ Trivy scan Jobs (created on demand)
                      └─ results → shared PVC → parsed + stored
```

The plugin talks to the backend **through the Kubernetes apiserver service proxy** — no extra
ingress, no CORS, and every request is authenticated with whatever identity Headlamp uses for
the cluster. That identity needs `services/proxy` access in the `security-dashboard` namespace.

## Install

### 1. Backend (Helm)

```bash
helm install security-dashboard oci://ghcr.io/mcman2017/charts/security-dashboard \
  -n security-dashboard --create-namespace
kubectl label namespace security-dashboard pod-security.kubernetes.io/enforce=baseline
```

Key values (see [values.yaml](charts/security-dashboard/values.yaml) for all):

| Value | Default | Meaning |
|-------|---------|---------|
| `scan.mode` | `registry` | `registry`: Trivy pulls image layers from registries (unprivileged, PSS baseline). `node-cache`: mounts the node's containerd socket to read already-pulled layers — for air-gapped clusters, private single-arch registries, or registry rate limits; requires PSS `privileged` on the namespace. |
| `rbac.scanSecrets` | `false` | Grant the scanner cluster-wide **read** on Secrets so Trivy can flag embedded credentials. |
| `persistence.*.storageClassName` | `""` | Storage classes for the data / trivy-cache / scan-results PVCs. **`scanResults` needs ReadWriteMany** (CephFS, EFS, NFS, Longhorn RWX, …) unless you run single-node. |
| `suppressions.enabled` | `false` | Mount your own suppression allowlist (see [docs/suppressions.md](docs/suppressions.md)). |
| `hostScanners.*` | disabled | Optional per-node `trivy rootfs` DaemonSet + Lynis CronJob (see [docs/host-scans.md](docs/host-scans.md)). |

### 2. Plugin

**Headlamp desktop:** install "Security Dashboard" from the in-app Plugin Catalog (ArtifactHub).

**In-cluster Headlamp (Helm):** point the headlamp chart's plugin manager at the release tarball:

```yaml
# values for the headlamp/headlamp chart
config:
  pluginsManager:
    enabled: true
    plugins:
      - name: headlamp-security-dashboard
        source: https://github.com/mcman2017/security-dashboard/releases/download/v0.5.0/headlamp-security-dashboard-0.5.0.tar.gz
```

**Air-gapped / initContainer:** the repo's root `Dockerfile` builds
`ghcr.io/mcman2017/headlamp-security-dashboard`, an image whose `/plugins/` directory you copy
into Headlamp's plugins volume with an initContainer.

### 3. Use it

Open Headlamp → **Security Scans → Overview** → launch a CIS, NSA, or Full Vulnerability scan.
The Vulnerabilities / Configuration / RBAC / Compliance / Exposed Secrets pages additionally
render [Trivy Operator](https://github.com/aquasecurity/trivy-operator) CRD reports if the
operator is installed.

## Development

```bash
# Plugin: hot-reloading dev server (needs a running Headlamp)
npm ci && npm start

# Backend: mock mode — full API with sample data, no cluster needed
cd backend && pip install -e '.[dev]'
SEC_DASHBOARD_MOCK=1 uvicorn sec_dashboard.main:app --reload
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details and [SECURITY.md](SECURITY.md) for the
threat model and how to report vulnerabilities.

## License

[Apache-2.0](LICENSE)
