"""Lynis host-OS audit — one privileged Job per cluster node.

The manager fans out `build_job()` across every node returned by
`k8s.list_nodes()`, pinning each Job with `nodeName` (bypasses the scheduler;
`tolerations: operator=Exists` is still required for kubelet admission on
tainted control-plane nodes).

To audit the HOST rather than the scanner container, the job copies the
Lynis source tree (a portable shell-script suite the image must ship at
LYNIS_DIR) into a temp dir on the host and runs it *chroot'ed into the host
root* (bind-mounted read-write at /host). Lynis's `--rootdir`/`--forensics`
flags are not enough — they only prefix some file checks, while OS
detection, package inventory, and service checks still hit the container
filesystem, which is a subtler variant of the bug this module replaces (the
old standalone CronJob audited the container outright, and additionally
rendered its "report" with `lynis show report`, which prints only the
report file path). The chroot needs the host mount writable for the
report/log/temp files; everything lands in one per-scan temp dir that a
trap removes on exit.

PLGN-3814 (journalctl --verify) is skipped via a profile: verifying months
of journal files takes tens of minutes and hangs the audit well past any
reasonable deadline.

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


# Where the scanner image ships the portable Lynis source tree (the docs
# Dockerfile git-clones the upstream tag here). The job copies this tree onto
# the host and runs it inside the chroot.
LYNIS_DIR = "/opt/lynis"

# Host-root bind mount inside the scanner container.
HOST_MOUNT = "/host"


def _scanner_command(scan_id: str, node_name: str) -> list[str]:
    dest = f"{SCAN_RESULTS_MOUNT}/{result_rel_path(scan_id, node_name)}"
    # Per-scan working dir as seen from INSIDE the chroot (i.e. a host path);
    # prefix with HOST_MOUNT for the container's view of the same dir.
    work = f"/tmp/lynis-audit-{scan_id[:8]}"
    # No `set -e` around the audit: lynis exits non-zero when it finds
    # warnings, which is a *successful* scan. Success = report.dat exists.
    # No --quiet: the human-readable section output stays in the Job log,
    # which the manager captures as the scanner log for the raw-log view.
    audit = (
        f"cd {work}/lynis && TMPDIR={work} ./lynis audit system --quick --no-colors "
        f"--profile ./custom.prf --report-file {work}/report.dat "
        f"--log-file {work}/lynis.log --auditor security-dashboard"
    )
    return [
        "sh", "-c",
        f"trap 'rm -rf {HOST_MOUNT}{work}' EXIT; "
        f"rm -rf {HOST_MOUNT}{work} && mkdir -p {HOST_MOUNT}{work} && "
        f"cp -a {LYNIS_DIR} {HOST_MOUNT}{work}/lynis && "
        # PLGN-3814 = journalctl --verify; see module docstring.
        f"printf 'skip-test=PLGN-3814\\n' > {HOST_MOUNT}{work}/lynis/custom.prf; "
        f'chroot {HOST_MOUNT} /bin/sh -c "{audit}"; '
        f'[ -s {HOST_MOUNT}{work}/report.dat ] || {{ echo "no report produced"; tail -50 {HOST_MOUNT}{work}/lynis.log; exit 1; }}; '
        f"mkdir -p {SCAN_RESULTS_MOUNT}/{scan_id} && "
        # Lynis writes report.dat 0640 root:root; the api reads the PVC as
        # uid 1000, so widen before publishing.
        f"cp {HOST_MOUNT}{work}/report.dat {dest}.tmp && chmod 644 {dest}.tmp && mv {dest}.tmp {dest}",
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
                                # Read-write: the chroot'ed audit writes its
                                # report/log/temp files into a per-scan dir
                                # under the host's /tmp (removed on exit).
                                {"name": "host-root", "mountPath": HOST_MOUNT},
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
                        {"name": "host-root", "hostPath": {"path": "/", "type": "Directory"}},
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
