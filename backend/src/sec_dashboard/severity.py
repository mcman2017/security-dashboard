"""Cross-scanner severity normalization.

The user requires every result ranked CRITICAL > HIGH > MEDIUM > LOW > INFO,
even though each tool has its own scale. Mapping rules are documented in the
plan §3 / severity normalization table.
"""

from enum import IntEnum


class Severity(IntEnum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    # SUPPRESSED is a rebucket target for findings on the allowlist (see
    # scans/suppressions.py). The raw finding is preserved — only its
    # severity_normalized changes — so the dashboard can render an
    # "accepted risk" panel without dropping data.
    SUPPRESSED = 0

    @property
    def label(self) -> str:
        return self.name


SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.SUPPRESSED,
]


def from_trivy(s: str) -> Severity:
    s = (s or "").upper()
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "UNKNOWN": Severity.INFO,
    }.get(s, Severity.INFO)


def from_kube_bench(status: str, profile: str) -> Severity:
    """kube-bench has no severity field; weight by profile + status."""
    status = (status or "").upper()
    profile = (profile or "").lower()
    if status == "FAIL":
        if profile in {"master", "controlplane", "etcd"}:
            return Severity.HIGH
        return Severity.MEDIUM
    if status == "WARN":
        return Severity.MEDIUM
    if status == "INFO":
        return Severity.INFO
    return Severity.INFO


def from_kubescape(severity_label: str, score: float | None = None) -> Severity:
    s = (severity_label or "").lower()
    if s == "critical":
        return Severity.CRITICAL
    if s == "high":
        return Severity.HIGH
    if s == "medium":
        return Severity.MEDIUM
    if s == "low":
        return Severity.LOW
    if score is not None:
        if score >= 9:
            return Severity.CRITICAL
        if score >= 7:
            return Severity.HIGH
        if score >= 4:
            return Severity.MEDIUM
        return Severity.LOW
    return Severity.INFO


def from_lynis(kind: str, impact: str | None = None) -> Severity:
    """Lynis warnings may carry IMPACT=high|medium|low; suggestions → LOW."""
    kind = (kind or "").lower()
    impact = (impact or "").lower()
    if kind == "warning":
        if impact == "high":
            return Severity.HIGH
        if impact == "low":
            return Severity.LOW
        return Severity.MEDIUM
    if kind == "suggestion":
        return Severity.LOW
    return Severity.INFO
