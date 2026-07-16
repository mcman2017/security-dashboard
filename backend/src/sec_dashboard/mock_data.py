"""Hand-written sample scan outputs for frontend development without a cluster.

These mirror the shape of real Trivy/Kubescape/kube-bench/Lynis outputs.
Severity-bucketed to exercise every UI severity branch.
"""

from datetime import datetime, timedelta
from uuid import uuid4

from .severity import Severity


def _scan(scanner: str, variant: str | None, status: str, findings: list[dict]) -> dict:
    started = datetime.utcnow() - timedelta(minutes=12)
    finished = started + timedelta(minutes=3, seconds=41) if status == "completed" else None
    counts = {s.label: 0 for s in Severity}
    for f in findings:
        counts[Severity(f["severity_normalized"]).label] += 1
    return {
        "id": str(uuid4()),
        "scanner": scanner,
        "variant": variant,
        "status": status,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat() if finished else None,
        "summary_counts": counts,
        "findings": findings,
        "error": None,
    }


_TRIVY_FINDINGS = [
    {
        "severity_normalized": Severity.CRITICAL.value,
        "severity_original": "CRITICAL",
        "scanner_id": "CVE-2025-1974",
        "resource_ns": "ingress-nginx",
        "resource_kind": "Deployment",
        "resource_name": "ingress-nginx-controller",
        "image": "registry.k8s.io/ingress-nginx/controller:v1.10.1",
        "title": "IngressNightmare — unauthenticated remote code execution",
        "description": "ingress-nginx v1.10.1 admission webhook accepts crafted AdmissionReview, allowing config injection and code execution in the controller pod. Controller SA reads all TLS secrets cluster-wide.",
        "control_id": None,
        "evidence": {"cvss": 9.8, "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
        "ecosystem_bucket": True,
    },
    {
        "severity_normalized": Severity.HIGH.value,
        "severity_original": "HIGH",
        "scanner_id": "CVE-2024-12798",
        "resource_ns": "web",
        "resource_kind": "Deployment",
        "resource_name": "web-frontend",
        "image": "docker.io/library/nginx:1.25.1",
        "title": "logback-classic JNDI injection",
        "description": "Library shipped in nginx-extras image; reachable via PaaS exporter sidecar.",
        "control_id": None,
        "evidence": {"cvss": 7.4},
        "ecosystem_bucket": False,
    },
    {
        "severity_normalized": Severity.MEDIUM.value,
        "severity_original": "MEDIUM",
        "scanner_id": "CVE-2024-7264",
        "resource_ns": "container-registry",
        "resource_kind": "StatefulSet",
        "resource_name": "registry",
        "image": "registry:2.8.3",
        "title": "curl OOB read in ASN.1 decoder",
        "description": "Used by registry's auth proxy. Exploitable only with crafted certificate chains.",
        "control_id": None,
        "evidence": {"cvss": 5.9},
        "ecosystem_bucket": True,
    },
    {
        "severity_normalized": Severity.LOW.value,
        "severity_original": "LOW",
        "scanner_id": "CVE-2024-0001",
        "resource_ns": "default",
        "resource_kind": "Deployment",
        "resource_name": "demo",
        "image": "library/debian:12.5",
        "title": "Information disclosure in /proc",
        "description": "Local-only; cluster has no untrusted tenants.",
        "control_id": None,
        "evidence": {"cvss": 2.1},
        "ecosystem_bucket": False,
    },
]


_KUBESCAPE_FINDINGS = [
    {
        "severity_normalized": Severity.HIGH.value,
        "severity_original": "High",
        "scanner_id": "C-0001",
        "resource_ns": "kubernetes-dashboard",
        "resource_kind": "Deployment",
        "resource_name": "kubernetes-dashboard",
        "image": None,
        "title": "Workloads with secret-token volume",
        "description": "Pod auto-mounts SA token; tighten with automountServiceAccountToken: false.",
        "control_id": "C-0001",
        "evidence": {"score": 7.2, "framework": "NSA"},
        "ecosystem_bucket": True,
    },
    {
        "severity_normalized": Severity.MEDIUM.value,
        "severity_original": "Medium",
        "scanner_id": "C-0017",
        "resource_ns": "my-app",
        "resource_kind": "Deployment",
        "resource_name": "sample-app",
        "image": None,
        "title": "Workload mounts host paths",
        "description": "sample-app mounts a host home directory as a volume.",
        "control_id": "C-0017",
        "evidence": {"score": 5.5, "framework": "MITRE"},
        "ecosystem_bucket": False,
    },
]


_KUBEBENCH_FINDINGS = [
    {
        "severity_normalized": Severity.HIGH.value,
        "severity_original": "FAIL",
        "scanner_id": "1.2.31",
        "resource_ns": None,
        "resource_kind": "Node",
        "resource_name": "cp-1",
        "image": None,
        "title": "Ensure that the --encryption-provider-config argument is set",
        "description": "Profile: master. apiserver started without --encryption-provider-config; etcd Secrets are base64 only.",
        "control_id": "1.2.31",
        "evidence": {"profile": "master", "status": "FAIL"},
        "ecosystem_bucket": True,
    },
    {
        "severity_normalized": Severity.MEDIUM.value,
        "severity_original": "WARN",
        "scanner_id": "4.2.6",
        "resource_ns": None,
        "resource_kind": "Node",
        "resource_name": "worker-1",
        "image": None,
        "title": "Ensure that the --protect-kernel-defaults argument is set to true",
        "description": "Profile: node. Kubelet default; project policy required.",
        "control_id": "4.2.6",
        "evidence": {"profile": "node", "status": "WARN"},
        "ecosystem_bucket": True,
    },
]


_LYNIS_FINDINGS = [
    {
        "severity_normalized": Severity.HIGH.value,
        "severity_original": "warning",
        "scanner_id": "AUTH-9286",
        "resource_ns": None,
        "resource_kind": "Host",
        "resource_name": "node-1",
        "image": None,
        "title": "No password set for single user mode",
        "description": "Lynis IMPACT=high. Allows bypass of root password at boot via init=/bin/sh.",
        "control_id": "AUTH-9286",
        "evidence": {"impact": "high"},
        "ecosystem_bucket": False,
    },
    {
        "severity_normalized": Severity.LOW.value,
        "severity_original": "suggestion",
        "scanner_id": "BOOT-5184",
        "resource_ns": None,
        "resource_kind": "Host",
        "resource_name": "node-1",
        "image": None,
        "title": "Set a password on GRUB bootloader",
        "description": "Useful in shared-physical-access environments; less relevant for a server in a locked rack.",
        "control_id": "BOOT-5184",
        "evidence": {},
        "ecosystem_bucket": False,
    },
]


def mock_scans() -> list[dict]:
    return [
        _scan("trivy", "cis", "completed", _TRIVY_FINDINGS),
        _scan("trivy", "vuln", "running", []),
        _scan("kubescape", None, "completed", _KUBESCAPE_FINDINGS),
        _scan("kube-bench", None, "completed", _KUBEBENCH_FINDINGS),
        _scan("lynis", None, "completed", _LYNIS_FINDINGS),
        _scan("trivy", "nsa", "failed", []),
    ]


def mock_raw_output(scanner: str) -> str:
    """Multi-KB pretend stdout for the Raw Output panel."""
    if scanner == "trivy":
        return (
            '{\n  "Results": [\n    {\n      "Target": "ingress-nginx/Deployment/ingress-nginx-controller",\n'
            '      "Class": "config",\n      "Type": "kubernetes",\n      "Vulnerabilities": [\n        {\n'
            '          "VulnerabilityID": "CVE-2025-1974",\n          "Severity": "CRITICAL",\n'
            '          "Title": "IngressNightmare — unauthenticated RCE",\n          "Description": "..."\n'
            "        }\n      ]\n    }\n  ]\n}\n"
        )
    if scanner == "lynis":
        return (
            "# Lynis report — node-1\n"
            "hardening_index=66\n"
            "warning[]=AUTH-9286|No password set for single user mode|-|-\n"
            "suggestion[]=BOOT-5184|Set a password on GRUB bootloader|-|-\n"
        )
    return f"# Mock raw output for {scanner}\nfindings: see /scans/<id>\n"
