"""Trivy JSON output → flat finding dicts.

Handles both report shapes:
  - **Resource scan** (vuln/misconfig/secret): top-level key `Resources`,
    each resource carries `Results[*].{Vulnerabilities|Misconfigurations|Secrets}`.
  - **Compliance scan** (cis/nsa --compliance ...): top-level keys `ID` +
    `Results`, where each control's nested `Results[*].Misconfigurations`
    holds the actual findings.

Severity is normalized via `severity.from_trivy`. Ecosystem bucketing
uses the namespace/image rules from plan §3.
"""

from __future__ import annotations

import re

from ...severity import Severity, from_trivy
from ..suppressions import is_suppressed

ECOSYSTEM_NAMESPACES = {
    "kube-system", "kube-public", "kube-node-lease",
    "ingress-nginx", "cert-manager", "metallb-system",
    "kube-flannel", "rook-ceph", "rook-ceph-system",
    "registry", "container-registry", "kubernetes-dashboard",
    "security-dashboard", "trivy-system",
}

ECOSYSTEM_IMAGE_PATTERNS = [
    re.compile(r"^registry\.k8s\.io/ingress-nginx/"),
    re.compile(r"^quay\.io/jetstack/cert-manager-"),
    re.compile(r"^quay\.io/metallb/"),
    re.compile(r"docker\.io/flannel/"),
    re.compile(r"rook/ceph"),
    re.compile(r"^registry\.k8s\.io/(kube-apiserver|kube-controller-manager|kube-scheduler|kube-proxy|etcd|coredns)"),
]


def is_ecosystem(ns: str | None, image: str | None) -> bool:
    if ns and ns in ECOSYSTEM_NAMESPACES:
        return True
    if image:
        for pat in ECOSYSTEM_IMAGE_PATTERNS:
            if pat.search(image):
                return True
    return False


def _finding(
    *,
    severity_normalized: Severity,
    severity_original: str,
    scanner_id: str | None,
    resource_ns: str | None,
    resource_kind: str | None,
    resource_name: str | None,
    image: str | None,
    title: str,
    description: str | None,
    control_id: str | None,
    evidence: dict | None,
) -> dict:
    # Apply the suppression allowlist late, after the parser has resolved
    # severity and evidence. The AVD id appears in different fields depending
    # on the Trivy report shape:
    #   compliance-shape misconfigs → evidence["avd_id"]
    #   resource-shape misconfigs   → control_id (the parser puts AVDID there)
    # Try both; the allowlist only has AVD-KSV-* keys so a CIS control id
    # like "5.1.2" naturally misses and is a no-op.
    ev = dict(evidence) if evidence else {}
    avd = ev.get("avd_id") or control_id
    suppressed, reason, justification = is_suppressed(
        avd_id=avd, target_kind=resource_kind, target_name=resource_name,
    )
    if suppressed:
        severity_normalized = Severity.SUPPRESSED
        ev["suppression_reason"] = reason
        ev["suppression_justification"] = justification

    return {
        "severity_normalized": int(severity_normalized),
        "severity_original": severity_original,
        "scanner_id": scanner_id,
        "resource_ns": resource_ns,
        "resource_kind": resource_kind,
        "resource_name": resource_name,
        "image": image,
        "title": title,
        "description": description,
        "control_id": control_id,
        "evidence": ev,
        "ecosystem_bucket": is_ecosystem(resource_ns, image),
    }


def _parse_resource_findings(resources: list[dict]) -> list[dict]:
    out: list[dict] = []
    for r in resources:
        ns = r.get("Namespace")
        kind = r.get("Kind")
        name = r.get("Name")
        for result in r.get("Results", []) or []:
            target = result.get("Target", "")
            image = result.get("Target") if result.get("Class") == "container_image" else None
            # vulnerabilities
            for v in result.get("Vulnerabilities", []) or []:
                sev_orig = v.get("Severity", "UNKNOWN")
                out.append(_finding(
                    severity_normalized=from_trivy(sev_orig),
                    severity_original=sev_orig,
                    scanner_id=v.get("VulnerabilityID"),
                    resource_ns=ns,
                    resource_kind=kind,
                    resource_name=name,
                    image=image,
                    title=v.get("Title") or v.get("VulnerabilityID") or "vulnerability",
                    description=v.get("Description"),
                    control_id=None,
                    evidence={
                        "pkg": v.get("PkgName"),
                        "installed": v.get("InstalledVersion"),
                        "fixed": v.get("FixedVersion"),
                        "cvss": v.get("CVSS"),
                        "primary_url": v.get("PrimaryURL"),
                        "references": (v.get("References") or [])[:10],
                        "target": target,
                    },
                ))
            # misconfigurations (from --scanners misconfig)
            for m in result.get("Misconfigurations", []) or []:
                sev_orig = m.get("Severity", "UNKNOWN")
                out.append(_finding(
                    severity_normalized=from_trivy(sev_orig),
                    severity_original=sev_orig,
                    scanner_id=m.get("ID") or m.get("AVDID"),
                    resource_ns=ns,
                    resource_kind=kind,
                    resource_name=name,
                    image=image,
                    title=m.get("Title") or m.get("ID") or "misconfiguration",
                    description=m.get("Description") or m.get("Message"),
                    control_id=m.get("AVDID"),
                    evidence={
                        "type": m.get("Type"),
                        "message": m.get("Message"),
                        "resolution": m.get("Resolution"),
                        "references": m.get("References"),
                        "target": target,
                    },
                ))
            # secrets
            for s in result.get("Secrets", []) or []:
                sev_orig = s.get("Severity", "UNKNOWN")
                out.append(_finding(
                    severity_normalized=from_trivy(sev_orig),
                    severity_original=sev_orig,
                    scanner_id=s.get("RuleID"),
                    resource_ns=ns,
                    resource_kind=kind,
                    resource_name=name,
                    image=image,
                    title=s.get("Title") or "secret detected",
                    description=s.get("Category"),
                    control_id=None,
                    evidence={"match": s.get("Match"), "target": target},
                ))
    return out


def _parse_compliance_findings(report: dict) -> list[dict]:
    """trivy --compliance produces a different shape — controls at the top.

    A control with `Results: null` and no `DefaultStatus` is INCONCLUSIVE —
    Trivy couldn't evaluate it (typically because it requires reading the
    host filesystem, which an in-cluster scanner can't do). We skip those
    so the dashboard only surfaces actionable findings.

    A control with `DefaultStatus: "FAIL"` and no Results is a baseline
    fail-by-default; we emit ONE cluster-level finding for it.
    Controls with nested `Results[].Misconfigurations[]` emit per-resource
    findings carrying the misconfig's full evidence (Status, Resolution,
    PrimaryURL, AVDID, etc.).
    """
    out: list[dict] = []
    compliance_id = report.get("ID", "")
    for ctrl in report.get("Results", []) or []:
        control_id = ctrl.get("ID", "")
        sev_orig = ctrl.get("Severity", "MEDIUM")
        default_status = ctrl.get("DefaultStatus")
        nested = ctrl.get("Results", []) or []

        if not nested:
            # No per-resource detail — emit only if Trivy explicitly says
            # "default fail"; otherwise treat as inconclusive (skip).
            if (default_status or "").upper() in {"FAIL", "WARN"}:
                out.append(_finding(
                    severity_normalized=from_trivy(sev_orig),
                    severity_original=sev_orig,
                    scanner_id=control_id,
                    resource_ns=None,
                    resource_kind="Cluster",
                    resource_name=None,
                    image=None,
                    title=ctrl.get("Name") or control_id,
                    description=ctrl.get("Description"),
                    control_id=control_id,
                    evidence={
                        "compliance": compliance_id,
                        "default_status": default_status,
                        "note": "control marked default-fail; no per-resource data",
                    },
                ))
            # else: inconclusive, drop silently
            continue

        for sub in nested:
            # `sub` carries Target (e.g. "Pod/kube-apiserver-node-1"); the
            # Namespace/Kind/Name fields are populated for resource-class
            # results but null for "config" results — fall back to Target.
            sub_target = sub.get("Target") or ""
            sub_ns = sub.get("Namespace")
            sub_kind = sub.get("Kind")
            sub_name = sub.get("Name")
            if not sub_kind and "/" in sub_target:
                # "Pod/kube-apiserver-node-1" → kind=Pod, name=kube-apiserver-node-1
                parts = sub_target.split("/", 1)
                sub_kind = parts[0]
                sub_name = parts[1]

            for m in sub.get("Misconfigurations", []) or []:
                # Trivy compliance reports have TWO severities per row:
                #   ctrl.Severity   = how the CIS framework grades the control
                #   m.Severity      = how Trivy grades this specific misconfig
                # The per-misconfig severity is authoritative for the actual
                # impact of THIS finding; the control severity is preserved
                # in evidence so the framework view is still visible.
                misconfig_sev = m.get("Severity") or sev_orig
                out.append(_finding(
                    severity_normalized=from_trivy(misconfig_sev),
                    severity_original=misconfig_sev,
                    scanner_id=control_id,
                    resource_ns=sub_ns,
                    resource_kind=sub_kind,
                    resource_name=sub_name,
                    image=None,
                    title=ctrl.get("Name") or control_id,
                    description=m.get("Message") or m.get("Description") or ctrl.get("Description"),
                    control_id=control_id,
                    evidence={
                        "compliance": compliance_id,
                        "control_severity": sev_orig,
                        "target": sub_target,
                        # Trivy's `Status: "FAIL"` means the cluster FAILED the
                        # check (the misconfig is present) — NOT that the scan
                        # failed to run. Renaming to be unambiguous.
                        "check_result": m.get("Status"),
                        "severity": m.get("Severity"),
                        "avd_id": m.get("AVDID"),
                        "rule_id": m.get("ID"),
                        "message": m.get("Message"),
                        "resolution": m.get("Resolution"),
                        "primary_url": m.get("PrimaryURL"),
                        "references": m.get("References"),
                    },
                ))
    return out


def parse_trivy(report: dict) -> list[dict]:
    """Dispatch by report shape. Resource shape wins if both keys present."""
    if isinstance(report.get("Resources"), list):
        return _parse_resource_findings(report["Resources"])
    if isinstance(report.get("Results"), list) and "ID" in report:
        return _parse_compliance_findings(report)
    # Plain vuln scan (single image) — same shape as one entry in Resources
    if isinstance(report.get("Results"), list):
        return _parse_resource_findings([{"Namespace": None, "Kind": None, "Name": None, "Results": report["Results"]}])
    return []
