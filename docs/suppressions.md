# Suppressions — the accepted-risk allowlist

Every real cluster has findings that are *true but accepted*: built-in Kubernetes roles that
must read Secrets, CNI daemonsets that must run privileged, an operator whose entire purpose
is the thing being flagged. The suppression allowlist lets you record those decisions —
with a written justification — instead of tuning them out mentally on every scan.

## How it behaves

- A suppressed finding is **rebucketed to severity `SUPPRESSED`, never dropped**. The raw
  finding, its original severity, and your justification remain visible in the UI
  (Security Scans → Suppressions, and the `suppressed` bucket of each scan).
- Matching is by the triple `(avd_id, target_kind, target_name)`; `target_name_pattern`
  glob-matches dynamically named resources (e.g. `kube-apiserver-*`).
- The parser **fails open**: if the file is missing or malformed, nothing is suppressed —
  a suppression bug shows you too many findings, never too few.

## File format

```yaml
suppressions:
  - avd_id: AVD-KSV-0041          # the Trivy/AVD rule id
    target_kind: ClusterRole
    target_name: my-operator      # or: target_name_pattern: "my-jobs-*"
    reason: app-by-design         # built-in-k8s | vendor-helm | app-by-design
    justification: >-
      Why this is accepted, in enough detail that a future audit
      understands the decision without asking you.
```

## Shipped default vs your own list

The repo ships a **minimal** default (`src/data/suppressions.yaml`): entries that are true on
effectively every kubeadm-based cluster (built-in roles, control-plane static pods) plus
chart-default cert-manager / ingress-nginx roles. Everything specific to *your* cluster is
intentionally left unsuppressed for you to review.

To use your own list, set it in the Helm chart — it is mounted via ConfigMap and read by the
backend at ingest time:

```yaml
# values for the security-dashboard chart
suppressions:
  enabled: true
  content: |
    suppressions:
      - avd_id: AVD-KSV-0041
        target_kind: ClusterRole
        target_name: my-secrets-operator
        reason: app-by-design
        justification: >-
          This operator IS a secret manager; secret CRUD is its purpose.
          Token is short-lived and namespace-bound.
```

Suggested hygiene (what we practice): date each review of the list, re-review on a fixed
cadence, and when you *remove* an entry, pair it with the RBAC/PodSpec tightening that made
it unnecessary.
