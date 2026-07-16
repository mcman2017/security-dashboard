# Contributing

Thanks for your interest! Issues and PRs are welcome.

## Dev setup

### Plugin (TypeScript, Headlamp plugin SDK)

```bash
npm ci
npm start          # hot-reloading dev server; needs a running Headlamp
npm run lint       # eslint
npm run tsc        # type check
npm run build      # production bundle → dist/main.js
npm run package    # release tarball
```

Point Headlamp (desktop: Settings → Plugins, or `headlamp --plugins-dir`) at the dev server
per the [Headlamp plugin docs](https://headlamp.dev/docs/latest/development/plugins/).

### Backend (Python 3.12, FastAPI)

The backend has a **mock mode** that serves the full API with realistic sample data — you can
develop every plugin page without a cluster:

```bash
cd backend
pip install -e '.[dev]'
SEC_DASHBOARD_MOCK=1 uvicorn sec_dashboard.main:app --reload
# → http://localhost:8000/api/scans
```

Tests and lint:

```bash
pytest
ruff check src tests
```

Live mode against a real cluster works from a workstation too — it falls back to your
kubeconfig when not running in-cluster.

### Helm chart

```bash
helm lint charts/security-dashboard
helm template test charts/security-dashboard -n security-dashboard
```

## Guidelines

- Keep the plugin free of credentials and cluster-specific values — everything
  environment-specific belongs in Helm values or backend settings.
- Suppression-list changes: only entries that are true on effectively **every** cluster
  (built-in Kubernetes objects, upstream chart defaults) belong in the shipped default;
  anything else is user configuration.
- Security-sensitive changes (RBAC, scan Job spec, hostPath usage) should update
  [SECURITY.md](SECURITY.md) in the same PR.
- Before a release PR: `npm run lint && npm run tsc && npm run build && pytest` must pass.
