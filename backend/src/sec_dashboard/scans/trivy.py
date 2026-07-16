"""Trivy scanner spec — Job manifest construction for the three variants.

Variants:
  - cis:  CIS Kubernetes Benchmark compliance scan (k8s-cis-1.23)
  - nsa:  NSA/CISA Kubernetes hardening (k8s-nsa-1.0)
  - vuln: Full cluster vulnerability scan (image + node CVEs)

2026-05-24: Trivy used to use the shipper-via-container-log transport
(scanner writes to emptyDir, shipper sidecar gzip+base64s the file and
echos with sentinels, api decodes from `kubectl logs`). That breaks
once the result exceeds kubelet's containerLogMaxSize (default 10MB):
the BEGIN sentinel rotates out of the visible log window before the
api reads it, decode fails, scan is marked failed despite Trivy having
succeeded.

The fix: a shared RWX PVC (settings.scan_results_pvc), mounted in both
this Job and the api Deployment. The scanner writes its JSON result
directly to /scan-results/<scan-id>.json; the api reads it as a file.
No log-rotation ceiling, no decode step, and the file path makes it
trivial to retain the raw output for replay.

Image-layer access is controlled by settings.scan_mode:
  registry   (default) — Trivy pulls layers from the image registries.
                         No hostPath, no root beyond the trivy image's own
                         default; the namespace can enforce PSS baseline.
  node-cache           — mounts the node's containerd socket (hostPath) so
                         Trivy reads the already-pulled layers from the local
                         runtime cache. For air-gapped clusters, private
                         single-arch registries (remote-manifest platform
                         negotiation fails there), or registry rate limits.
                         Requires PSS privileged on the namespace.
"""

from __future__ import annotations

from ..config import settings

SCAN_RESULTS_MOUNT = "/scan-results"


# Trivy 0.59 dropped the `cluster` positional from `trivy k8s` — it's now just
# `trivy k8s` (defaults to the in-cluster context when run in a Pod with an
# SA token mounted). Passing `cluster` would be interpreted as a kubectl
# context name → "context cluster does not exist" fatal.
# `--disable-node-collector` skips Trivy's optional node-collector DaemonSet.
# Tradeoff: we drop node-OS misconfig coverage from Trivy. That coverage is
# already provided by kube-bench (node CIS config) + Lynis (host OS audit),
# so the net coverage of the dashboard is unchanged. Without this flag,
# Trivy tries to `create namespace trivy-temp` + `create daemonset` cluster-wide,
# which would require a much broader trivy-scanner ClusterRole.
VARIANTS: dict[str, list[str]] = {
    "cis": [
        "k8s",
        "--compliance", "k8s-cis-1.23",
        "--format", "json",
        "--quiet",
        "--timeout", "30m",
        "--scanners", "misconfig",
        "--report", "all",
        "--disable-node-collector",
    ],
    "nsa": [
        "k8s",
        "--compliance", "k8s-nsa-1.0",
        "--format", "json",
        "--quiet",
        "--timeout", "30m",
        "--report", "all",
        "--disable-node-collector",
    ],
    "vuln": [
        "k8s",
        "--scanners", "vuln",
        "--format", "json",
        "--quiet",
        "--timeout", "60m",
        "--report", "all",
        "--parallel", "3",
        "--disable-node-collector",
    ],
}


def _scanner_command(variant: str, scan_id: str) -> list[str]:
    args = VARIANTS[variant]
    quoted = " ".join(["trivy", *args])
    # Atomic write: trivy → tmp file → rename. A mid-scan crash (OOM,
    # segfault, network blip) leaves a `.tmp` behind, never a partial
    # `.json` — the api can trust that any `.json` it finds is the
    # complete output.
    return [
        "sh", "-c",
        f"set -e; "
        f"{quoted} > {SCAN_RESULTS_MOUNT}/{scan_id}.json.tmp && "
        f"mv {SCAN_RESULTS_MOUNT}/{scan_id}.json.tmp {SCAN_RESULTS_MOUNT}/{scan_id}.json",
    ]


def build_job(scan_id: str, variant: str) -> dict:
    if variant not in VARIANTS:
        raise ValueError(f"unknown trivy variant {variant!r}; choose one of {sorted(VARIANTS)}")

    name = f"trivy-{variant}-{scan_id[:8]}"
    short_labels = {
        "security-dashboard/scan-id": scan_id,
        "security-dashboard/scanner": "trivy",
        "security-dashboard/variant": variant,
    }

    env: list[dict] = []
    if settings.trivy_platform:
        # Fallback hint only: `trivy k8s` per-image scans ignore TRIVY_PLATFORM
        # (and --platform; only `trivy image` honors them), but remote fetches
        # that fall back to the `remote` image source do respect it.
        env.append({"name": "TRIVY_PLATFORM", "value": settings.trivy_platform})

    volume_mounts = [
        {"name": "trivy-cache", "mountPath": "/root/.cache/trivy"},
        # Shared RWX PVC — scanner writes here, api reads here. See module
        # docstring for the rationale.
        {"name": "scan-results", "mountPath": SCAN_RESULTS_MOUNT},
    ]
    volumes = [
        {
            "name": "trivy-cache",
            "persistentVolumeClaim": {"claimName": settings.trivy_cache_pvc},
        },
        {
            "name": "scan-results",
            "persistentVolumeClaim": {"claimName": settings.scan_results_pvc},
        },
    ]

    if settings.scan_mode == "node-cache":
        # Containerd socket — let Trivy read images from the local container
        # runtime cache (the images kubelet actually pulled) instead of
        # negotiating remote manifests. Trade-off: the scan pod can read every
        # container's image bytes on the host node, so RCE in the trivy
        # container would have node-wide image-read access. Mitigated by: the
        # scanner only runs on-demand (no persistent pod) and the SA is
        # read-only. Requires PSS privileged on the namespace.
        volume_mounts.append(
            {"name": "containerd-sock", "mountPath": settings.containerd_socket_path}
        )
        # hostPath socket — type:Socket asserts the path is a unix socket; if
        # containerd isn't running on the node the pod fails to start (loud
        # failure, not silent skip).
        volumes.append(
            {
                "name": "containerd-sock",
                "hostPath": {"path": settings.containerd_socket_path, "type": "Socket"},
            }
        )

    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": settings.namespace,
            "labels": short_labels,
        },
        "spec": {
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": 86_400,  # 24h — long enough for reconciliation
            "activeDeadlineSeconds": 4_500,      # 75 min cap (vuln scan is the longest)
            "template": {
                "metadata": {"labels": short_labels},
                "spec": {
                    "restartPolicy": "Never",
                    "serviceAccountName": settings.scanner_service_account,
                    "automountServiceAccountToken": True,
                    "containers": [
                        {
                            "name": "scanner",
                            "image": settings.trivy_image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": _scanner_command(variant, scan_id),
                            "env": env,
                            "volumeMounts": volume_mounts,
                            "resources": {
                                "requests": {"cpu": "500m", "memory": "1Gi"},
                                "limits": {"memory": "4Gi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                                "runAsNonRoot": False,  # trivy image runs as root by default
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                        },
                    ],
                    "volumes": volumes,
                },
            },
        },
    }
