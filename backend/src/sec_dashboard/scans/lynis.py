"""Lynis host-OS audit — one privileged Job per cluster node.

The manager fans out `build_job()` across every node returned by
`k8s.list_nodes()`, pinning each Job with `nodeName` (bypasses the scheduler;
`tolerations: operator=Exists` is still required for kubelet admission on
tainted control-plane nodes).

The host filesystem is bind-mounted read-only at /rootfs and audited via
`--forensics --rootdir /rootfs/` — without `--rootdir`, Lynis audits the
scanner *container's* filesystem, which is exactly the bug this module
replaces (the old standalone CronJob did that, and additionally rendered its
"report" with `lynis show report`, which prints only the report file path).

Results transport reuses the Trivy pattern: the Job writes report.dat to the
shared RWX scan-results PVC (per-scan directory, per-node file, atomic
tmp+rename) and the api reads it as a file. hostPID/hostNetwork/privileged
are required for Lynis's process/network/kernel inspection.
"""

from __future__ import annotations

import re

from ..config import settings
from .trivy import SCAN_RESULTS_MOUNT


def result_rel_path(scan_id: str, node_name: str) -> str:
    """PVC-relative path a node's report lands at: <scan-id>/<node>.dat."""
    return f"{scan_id}/{node_name}.dat"


def _sanitize(node_name: str) -> str:
    """Node name → DNS-1123-safe Job-name fragment."""
    return re.sub(r"[^a-z0-9-]", "-", node_name.lower()).strip("-")


def _scanner_command(scan_id: str, node_name: str) -> list[str]:
    dest = f"{SCAN_RESULTS_MOUNT}/{result_rel_path(scan_id, node_name)}"
    # No `set -e` around the audit: lynis exits non-zero when it finds
    # warnings, which is a *successful* scan. Success = report.dat exists.
    # No --quiet: the human-readable section output stays in the Job log,
    # which the manager captures as the scanner log for the raw-log view.
    audit = (
        "lynis audit system --quick --no-colors --forensics --rootdir /rootfs/ "
        "--report-file /tmp/report.dat --log-file /tmp/lynis.log "
        "--auditor security-dashboard"
    )
    return [
        "sh", "-c",
        f"{audit}; "
        f'[ -s /tmp/report.dat ] || {{ echo "no report produced"; tail -50 /tmp/lynis.log; exit 1; }}; '
        f"mkdir -p {SCAN_RESULTS_MOUNT}/{scan_id} && "
        # Lynis writes report.dat 0640 root:root; the api reads the PVC as
        # uid 1000, so widen before publishing.
        f"cp /tmp/report.dat {dest}.tmp && chmod 644 {dest}.tmp && mv {dest}.tmp {dest}",
    ]


def build_job(scan_id: str, node_name: str, is_control_plane: bool) -> dict:
    name = f"lynis-{_sanitize(node_name)[:24]}-{scan_id[:8]}"
    labels = {
        "security-dashboard/scan-id": scan_id,
        "security-dashboard/scanner": "lynis",
        "security-dashboard/job-target": node_name,
        "security-dashboard/job-role": "cp" if is_control_plane else "node",
    }
    pull_secrets = [
        {"name": s.strip()}
        for s in settings.lynis_image_pull_secrets.split(",")
        if s.strip()
    ]
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": settings.namespace,
            "labels": labels,
        },
        "spec": {
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": 86_400,
            "activeDeadlineSeconds": settings.lynis_job_deadline_s,
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "restartPolicy": "Never",
                    # Lynis makes no K8s API calls — default SA, no token.
                    "automountServiceAccountToken": False,
                    **({"imagePullSecrets": pull_secrets} if pull_secrets else {}),
                    "nodeName": node_name,
                    "hostPID": True,
                    "hostNetwork": True,
                    "tolerations": [{"operator": "Exists"}],
                    "containers": [
                        {
                            "name": "scanner",
                            "image": settings.lynis_image,
                            "imagePullPolicy": "IfNotPresent",
                            "command": _scanner_command(scan_id, node_name),
                            "volumeMounts": [
                                {"name": "rootfs", "mountPath": "/rootfs", "readOnly": True},
                                {"name": "scan-results", "mountPath": SCAN_RESULTS_MOUNT},
                                {"name": "tmp", "mountPath": "/tmp"},
                            ],
                            "resources": {
                                "requests": {"cpu": "100m", "memory": "128Mi"},
                                "limits": {"memory": "512Mi"},
                            },
                            # privileged + hostPID are what make this a *host*
                            # audit rather than a container audit; the namespace
                            # must enforce PSS privileged (see chart NOTES).
                            "securityContext": {"privileged": True},
                        },
                    ],
                    "volumes": [
                        {"name": "rootfs", "hostPath": {"path": "/", "type": "Directory"}},
                        {
                            "name": "scan-results",
                            "persistentVolumeClaim": {"claimName": settings.scan_results_pvc},
                        },
                        {"name": "tmp", "emptyDir": {}},
                    ],
                },
            },
        },
    }
