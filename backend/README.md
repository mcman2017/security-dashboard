# security-dashboard backend

FastAPI service that powers the on-demand scanning features of the Security Dashboard
Headlamp plugin. It creates Trivy scan Jobs in its own namespace, watches them, reads the
JSON results from a shared PVC, normalizes the findings into SQLite, and serves them under
`/api`.

Runs in two modes:

- **mock** (`SEC_DASHBOARD_MOCK=1`): returns hand-written sample scanner data. No cluster
  connection — used for frontend development and CI.
- **live** (default): connects to the Kubernetes API (in-cluster SA, or your kubeconfig when
  run on a workstation), creates scan Jobs, ingests their results.

## Layout

```
src/sec_dashboard/
  main.py          FastAPI app + lifespan
  config.py        Settings (SEC_DASHBOARD_* env vars)
  db.py            SQLAlchemy async engine + models
  storage.py       Scan/finding persistence
  severity.py      Cross-scanner severity normalization
  mock_data.py     Sample scanner outputs for mock mode
  scans/
    base.py        Scan abstract base + result schema
    manager.py     Scan orchestrator (Job lifecycle, reconciliation)
    k8s.py         kubernetes-asyncio wrapper (Job/pod/event verbs)
    trivy.py       Trivy Job manifests (cis / nsa / vuln variants, scan modes)
    suppressions.py  Accepted-risk allowlist matching
    parsers/trivy.py Trivy JSON → normalized findings
  routes/
    health.py      /api/health
    scans.py       /api/scans, /api/scans/{id}, /api/findings/by-severity/{sev}
```

## Configuration

All settings are env vars prefixed `SEC_DASHBOARD_` (see `config.py`). The most important:

| Env var | Default | Meaning |
|---------|---------|---------|
| `SEC_DASHBOARD_SCAN_MODE` | `registry` | `registry` or `node-cache` (containerd socket hostPath) |
| `SEC_DASHBOARD_TRIVY_IMAGE` | `aquasec/trivy:0.59.0` | Image for scan Jobs |
| `SEC_DASHBOARD_NAMESPACE` | `security-dashboard` | Namespace for scan Jobs |
| `SEC_DASHBOARD_SUPPRESSIONS_PATH` | `/data/suppressions.yaml` | Accepted-risk allowlist |
| `SEC_DASHBOARD_MOCK` | `0` | Mock mode |

## Dev

```bash
pip install -e '.[dev]'
SEC_DASHBOARD_MOCK=1 uvicorn sec_dashboard.main:app --reload   # http://localhost:8000/api/scans
pytest
ruff check src tests
```
