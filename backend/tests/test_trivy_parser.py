import json
import os
import tempfile

import pytest

from sec_dashboard.scans import suppressions as _suppressions
from sec_dashboard.scans.parsers.trivy import (
    ECOSYSTEM_NAMESPACES,
    is_ecosystem,
    parse_trivy,
)
from sec_dashboard.severity import Severity


# ---------- ecosystem bucket helper ----------

def test_ecosystem_by_namespace():
    for ns in ECOSYSTEM_NAMESPACES:
        assert is_ecosystem(ns, None) is True
    assert is_ecosystem("default", None) is False
    assert is_ecosystem("my-app", None) is False


def test_ecosystem_by_image_pattern():
    assert is_ecosystem(None, "registry.k8s.io/ingress-nginx/controller:v1.10.1") is True
    assert is_ecosystem(None, "quay.io/jetstack/cert-manager-controller:v1.13.3") is True
    assert is_ecosystem(None, "rook/ceph:v1.13.1") is True
    assert is_ecosystem(None, "registry.k8s.io/kube-apiserver:v1.33.3") is True
    assert is_ecosystem(None, "docker.io/library/nginx:1.25.1") is False


# ---------- resource-shape (vuln + misconfig scan) ----------

RESOURCE_REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": "kubernetes-cluster",
    "ClusterName": "test",
    "Resources": [
        {
            "Namespace": "ingress-nginx",
            "Kind": "Deployment",
            "Name": "ingress-nginx-controller",
            "Results": [
                {
                    "Target": "registry.k8s.io/ingress-nginx/controller:v1.10.1",
                    "Class": "container_image",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2025-1974",
                            "PkgName": "nginx",
                            "InstalledVersion": "1.21.6",
                            "FixedVersion": "1.27.1",
                            "Severity": "CRITICAL",
                            "Title": "ingress-nginx unauthenticated RCE",
                            "Description": "IngressNightmare",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2025-1974",
                            "CVSS": {"nvd": {"V3Score": 9.8}},
                        }
                    ],
                },
                {
                    "Target": "ingress-nginx/Deployment/ingress-nginx-controller",
                    "Class": "config",
                    "Type": "kubernetes",
                    "Misconfigurations": [
                        {
                            "Type": "Kubernetes Security Check",
                            "ID": "KSV001",
                            "AVDID": "AVD-KSV-0001",
                            "Title": "Process can elevate its own privileges",
                            "Description": "Allow privilege escalation",
                            "Message": "Container should set allowPrivilegeEscalation=false",
                            "Severity": "MEDIUM",
                            "References": ["https://avd.aquasec.com/misconfig/ksv001"],
                        }
                    ],
                },
            ],
        },
        {
            "Namespace": "default",
            "Kind": "Pod",
            "Name": "test-pod",
            "Results": [
                {
                    "Target": "test-pod",
                    "Class": "secret",
                    "Type": "kubernetes",
                    "Secrets": [
                        {
                            "RuleID": "aws-access-key-id",
                            "Category": "AWS",
                            "Severity": "HIGH",
                            "Title": "AWS Access Key ID detected",
                            "Match": "AKIA*****",
                        }
                    ],
                }
            ],
        },
    ],
}


def test_resource_shape_counts_and_severity():
    findings = parse_trivy(RESOURCE_REPORT)
    assert len(findings) == 3

    by_sev = {f["severity_normalized"]: 0 for f in findings}
    for f in findings:
        by_sev[f["severity_normalized"]] += 1
    assert by_sev[Severity.CRITICAL] == 1
    assert by_sev[Severity.HIGH] == 1
    assert by_sev[Severity.MEDIUM] == 1


def test_resource_shape_ecosystem_tagging():
    findings = parse_trivy(RESOURCE_REPORT)
    # CVE in ingress-nginx → ecosystem; misconfig in ingress-nginx → ecosystem;
    # secret in default → not ecosystem
    eco = [f["ecosystem_bucket"] for f in findings]
    assert eco.count(True) == 2
    assert eco.count(False) == 1


def test_resource_shape_cve_evidence():
    findings = parse_trivy(RESOURCE_REPORT)
    cve = next(f for f in findings if f["scanner_id"] == "CVE-2025-1974")
    assert cve["severity_normalized"] == Severity.CRITICAL
    assert cve["resource_ns"] == "ingress-nginx"
    assert cve["evidence"]["pkg"] == "nginx"
    assert cve["evidence"]["fixed"] == "1.27.1"
    assert "primary_url" in cve["evidence"]


def test_resource_shape_misconfig_evidence():
    findings = parse_trivy(RESOURCE_REPORT)
    misc = next(f for f in findings if f["scanner_id"] == "KSV001")
    assert misc["control_id"] == "AVD-KSV-0001"
    assert misc["severity_normalized"] == Severity.MEDIUM


# ---------- compliance shape ----------

COMPLIANCE_REPORT = {
    "ID": "k8s-cis-1.23",
    "Title": "CIS Kubernetes Benchmarks",
    "RelatedResources": [],
    "Results": [
        {
            "ID": "1.2.6",
            "Name": "Ensure that the --kubelet-certificate-authority argument is set",
            "Description": "...",
            "Severity": "LOW",
            "Results": [
                {
                    "Target": "Pod/kube-apiserver-cp-1",
                    "Namespace": "kube-system",
                    "Kind": "Pod",
                    "Name": "kube-apiserver-cp-1",
                    "Misconfigurations": [
                        {
                            "Type": "Kubernetes",
                            "ID": "KCV0046",
                            "AVDID": "AVD-KCV-0046",
                            "Status": "FAIL",
                            "Severity": "LOW",
                            "Message": "kubelet-certificate-authority is not set",
                            "Resolution": "Set the --kubelet-certificate-authority argument",
                            "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-kcv-0046",
                            "References": ["https://cisecurity.org/..."],
                        }
                    ],
                }
            ],
        },
        {
            # control with DefaultStatus=FAIL but no per-resource data —
            # should emit one cluster-level finding.
            "ID": "5.2.5",
            "Name": "Minimize allowPrivilegeEscalation",
            "Description": "...",
            "Severity": "HIGH",
            "DefaultStatus": "FAIL",
            "Results": None,
        },
        {
            # inconclusive control: null Results + no DefaultStatus.
            # Should be SKIPPED — Trivy couldn't evaluate it in-cluster
            # (e.g., host filesystem check the scanner can't reach).
            "ID": "1.1.1",
            "Name": "Ensure API server pod spec file perms are 600 or more restrictive",
            "Description": "...",
            "Severity": "HIGH",
            "Results": None,
        },
    ],
}


def test_compliance_shape():
    findings = parse_trivy(COMPLIANCE_REPORT)
    # 1.2.6 (per-resource) + 5.2.5 (default-fail) — 1.1.1 is inconclusive, skipped.
    assert len(findings) == 2
    ids = sorted(f["control_id"] for f in findings)
    assert ids == ["1.2.6", "5.2.5"]


def test_compliance_inconclusive_controls_skipped():
    """Controls with Results=null + no DefaultStatus are NOT findings."""
    findings = parse_trivy(COMPLIANCE_REPORT)
    assert all(f["control_id"] != "1.1.1" for f in findings)


def test_compliance_default_fail_emits_cluster_finding():
    findings = parse_trivy(COMPLIANCE_REPORT)
    high = next(f for f in findings if f["control_id"] == "5.2.5")
    assert high["severity_normalized"] == Severity.HIGH
    assert high["resource_kind"] == "Cluster"
    assert high["evidence"]["default_status"] == "FAIL"
    assert "note" in high["evidence"]


def test_compliance_per_resource_finding_has_rich_evidence():
    """For controls with per-resource detail, evidence carries the
    misconfig's status/resolution/PrimaryURL/AVDID — not just generic
    compliance metadata."""
    findings = parse_trivy(COMPLIANCE_REPORT)
    f = next(f for f in findings if f["control_id"] == "1.2.6")
    assert f["resource_ns"] == "kube-system"
    assert f["resource_kind"] == "Pod"
    assert f["resource_name"] == "kube-apiserver-cp-1"
    assert f["ecosystem_bucket"] is True
    ev = f["evidence"]
    assert ev["check_result"] == "FAIL"
    assert ev["avd_id"] == "AVD-KCV-0046"
    assert ev["resolution"].startswith("Set the --kubelet")
    assert ev["primary_url"].endswith("/avd-kcv-0046")
    assert ev["target"] == "Pod/kube-apiserver-cp-1"


def test_compliance_uses_misconfig_severity_not_control_severity():
    """When a misconfig has its own Severity, that wins — and the
    control's framework-severity is preserved in evidence."""
    # Control 1.2.6 has Severity=LOW; its misconfig also LOW → matches.
    # Build a synthetic case where they differ to prove misconfig wins:
    rpt = {
        "ID": "k8s-cis-1.23",
        "Results": [
            {
                "ID": "X.Y", "Name": "...", "Severity": "HIGH",
                "Results": [
                    {
                        "Target": "Pod/foo",
                        "Misconfigurations": [
                            {"Severity": "LOW", "Status": "FAIL", "Message": "m",
                             "AVDID": "AVD-X-1", "ID": "X1"}
                        ],
                    }
                ],
            }
        ],
    }
    findings = parse_trivy(rpt)
    assert len(findings) == 1
    f = findings[0]
    assert f["severity_normalized"] == Severity.LOW       # misconfig wins
    assert f["severity_original"] == "LOW"
    assert f["evidence"]["severity"] == "LOW"
    assert f["evidence"]["control_severity"] == "HIGH"    # framework view preserved


def test_compliance_per_resource_kind_fallback_from_target():
    """If sub.Kind is null, parse from sub.Target (e.g. 'Pod/foo')."""
    rpt = {
        "ID": "k8s-cis-1.23",
        "Results": [
            {
                "ID": "X.Y", "Name": "...", "Severity": "MEDIUM",
                "Results": [
                    {
                        "Target": "Node/cp-1",
                        "Misconfigurations": [{"ID": "K", "AVDID": "AVD-K", "Status": "FAIL", "Severity": "MEDIUM", "Message": "m"}],
                    }
                ],
            }
        ],
    }
    findings = parse_trivy(rpt)
    assert len(findings) == 1
    assert findings[0]["resource_kind"] == "Node"
    assert findings[0]["resource_name"] == "cp-1"


# ---------- empty / edge cases ----------

def test_empty_report():
    assert parse_trivy({}) == []
    assert parse_trivy({"Resources": []}) == []
    assert parse_trivy({"ID": "x", "Results": []}) == []


def test_plain_results_shape_treated_as_resource():
    """trivy image scan output has top-level `Results` with no `ID` or `Resources`."""
    report = {
        "Results": [
            {
                "Target": "nginx:1.25",
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-X", "Severity": "LOW", "Title": "T"},
                ],
            }
        ]
    }
    findings = parse_trivy(report)
    assert len(findings) == 1
    assert findings[0]["scanner_id"] == "CVE-X"


def test_real_report_roundtrip_json():
    """Sanity: parser doesn't choke on json.loads/dumps of itself."""
    findings = parse_trivy(RESOURCE_REPORT)
    json.dumps(findings)  # must be JSON-serializable


# ---------- suppression allowlist ----------


@pytest.fixture
def with_suppressions_file():
    """Yields a function that takes YAML text and writes it to a temp file
    + points $SEC_DASHBOARD_SUPPRESSIONS_PATH at it. Cleans up after."""
    tmps: list[str] = []
    saved = os.environ.get("SEC_DASHBOARD_SUPPRESSIONS_PATH")

    def install(yaml_text: str) -> None:
        f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        f.write(yaml_text)
        f.close()
        tmps.append(f.name)
        os.environ["SEC_DASHBOARD_SUPPRESSIONS_PATH"] = f.name
        _suppressions.reload_for_testing()

    yield install

    if saved is None:
        os.environ.pop("SEC_DASHBOARD_SUPPRESSIONS_PATH", None)
    else:
        os.environ["SEC_DASHBOARD_SUPPRESSIONS_PATH"] = saved
    for p in tmps:
        try:
            os.unlink(p)
        except OSError:
            pass
    _suppressions.reload_for_testing()


COMPLIANCE_RBAC_REPORT = {
    "ID": "k8s-cis-1.23",
    "Results": [
        {
            "ID": "5.1.2", "Name": "Minimize access to secrets", "Severity": "HIGH",
            "Results": [
                {
                    "Target": "ClusterRole/admin",
                    "Kind": "ClusterRole",
                    "Name": "admin",
                    "Misconfigurations": [
                        {"Severity": "CRITICAL", "Status": "FAIL",
                         "Message": "shouldn't have access to secrets",
                         "AVDID": "AVD-KSV-0041", "ID": "KSV041"}
                    ],
                },
                {
                    "Target": "ClusterRole/my-app-role",
                    "Kind": "ClusterRole",
                    "Name": "my-app-role",
                    "Misconfigurations": [
                        {"Severity": "CRITICAL", "Status": "FAIL",
                         "Message": "shouldn't have access to secrets",
                         "AVDID": "AVD-KSV-0041", "ID": "KSV041"}
                    ],
                },
            ],
        }
    ],
}


def test_suppression_built_in_admin_role(with_suppressions_file):
    """A ClusterRole on the allowlist gets rebucketed to SUPPRESSED."""
    with_suppressions_file("""
suppressions:
  - avd_id: AVD-KSV-0041
    target_kind: ClusterRole
    target_name: admin
    reason: built-in-k8s
    justification: "Built-in admin role; namespace admins need this."
""")
    findings = parse_trivy(COMPLIANCE_RBAC_REPORT)
    by_name = {f["resource_name"]: f for f in findings}
    admin = by_name["admin"]
    assert admin["severity_normalized"] == int(Severity.SUPPRESSED)
    assert admin["evidence"]["suppression_reason"] == "built-in-k8s"
    assert "namespace admins" in admin["evidence"]["suppression_justification"]


def test_suppression_unknown_role_passes_through(with_suppressions_file):
    """A ClusterRole NOT on the allowlist keeps its original severity."""
    with_suppressions_file("""
suppressions:
  - avd_id: AVD-KSV-0041
    target_kind: ClusterRole
    target_name: admin
    reason: built-in-k8s
    justification: "..."
""")
    findings = parse_trivy(COMPLIANCE_RBAC_REPORT)
    by_name = {f["resource_name"]: f for f in findings}
    unknown = by_name["my-app-role"]
    assert unknown["severity_normalized"] == int(Severity.CRITICAL)
    assert "suppression_reason" not in unknown["evidence"]


def test_suppression_fail_open_if_yaml_missing(monkeypatch):
    """If the allowlist file doesn't exist, every finding passes through."""
    monkeypatch.setenv("SEC_DASHBOARD_SUPPRESSIONS_PATH", "/nonexistent/path/suppressions.yaml")
    _suppressions.reload_for_testing()
    try:
        findings = parse_trivy(COMPLIANCE_RBAC_REPORT)
        for f in findings:
            assert f["severity_normalized"] == int(Severity.CRITICAL)
    finally:
        _suppressions.reload_for_testing()


def test_suppression_glob_pattern_matches(with_suppressions_file):
    """target_name_pattern entries use fnmatch — useful for kubeadm static
    pods (kube-apiserver-<node>) and rook-ceph osd-prepare Jobs whose
    names change on every reconciliation."""
    rpt = {
        "ID": "k8s-cis-1.23",
        "Results": [
            {
                "ID": "5.2.5", "Name": "hostNetwork", "Severity": "HIGH",
                "Results": [
                    {
                        "Target": "Pod/kube-apiserver-cp-1",
                        "Kind": "Pod", "Name": "kube-apiserver-cp-1",
                        "Misconfigurations": [
                            {"Severity": "HIGH", "Status": "FAIL", "Message": "hostNetwork",
                             "AVDID": "AVD-KSV-0009", "ID": "KSV009"}
                        ],
                    },
                    {
                        "Target": "Pod/kube-apiserver-cp-99",
                        "Kind": "Pod", "Name": "kube-apiserver-cp-99",  # new node, future-proof
                        "Misconfigurations": [
                            {"Severity": "HIGH", "Status": "FAIL", "Message": "hostNetwork",
                             "AVDID": "AVD-KSV-0009", "ID": "KSV009"}
                        ],
                    },
                    {
                        "Target": "Pod/totally-unrelated-app",
                        "Kind": "Pod", "Name": "totally-unrelated-app",
                        "Misconfigurations": [
                            {"Severity": "HIGH", "Status": "FAIL", "Message": "hostNetwork",
                             "AVDID": "AVD-KSV-0009", "ID": "KSV009"}
                        ],
                    },
                ],
            }
        ],
    }
    with_suppressions_file("""
suppressions:
  - avd_id: AVD-KSV-0009
    target_kind: Pod
    target_name_pattern: "kube-apiserver-*"
    reason: built-in-k8s
    justification: "Kubeadm static apiserver pod; needs hostNetwork to bind 6443."
""")
    findings = parse_trivy(rpt)
    by = {f["resource_name"]: f for f in findings}
    assert by["kube-apiserver-cp-1"]["severity_normalized"] == int(Severity.SUPPRESSED)
    assert by["kube-apiserver-cp-99"]["severity_normalized"] == int(Severity.SUPPRESSED)
    assert by["totally-unrelated-app"]["severity_normalized"] == int(Severity.HIGH)
    assert by["kube-apiserver-cp-1"]["evidence"]["suppression_reason"] == "built-in-k8s"


def test_suppression_exact_wins_over_pattern(with_suppressions_file):
    """If both exact + pattern match, exact wins (its reason/justification
    is used). Exact is faster and explicit."""
    with_suppressions_file("""
suppressions:
  - avd_id: AVD-KSV-0009
    target_kind: Pod
    target_name: kube-apiserver-cp-1
    reason: built-in-k8s
    justification: "exact-match reason"
  - avd_id: AVD-KSV-0009
    target_kind: Pod
    target_name_pattern: "kube-apiserver-*"
    reason: vendor-helm
    justification: "pattern-match reason — should NOT win for cp-1"
""")
    rpt = {
        "ID": "k8s-cis-1.23",
        "Results": [
            {
                "ID": "5.2.5", "Name": "hostNetwork", "Severity": "HIGH",
                "Results": [{"Target": "Pod/kube-apiserver-cp-1", "Kind": "Pod",
                            "Name": "kube-apiserver-cp-1",
                            "Misconfigurations": [{"Severity": "HIGH", "Status": "FAIL",
                                                    "Message": "m", "AVDID": "AVD-KSV-0009",
                                                    "ID": "KSV009"}]}],
            }
        ],
    }
    f = parse_trivy(rpt)[0]
    assert f["severity_normalized"] == int(Severity.SUPPRESSED)
    assert f["evidence"]["suppression_reason"] == "built-in-k8s"
    assert "exact-match" in f["evidence"]["suppression_justification"]


def test_suppression_only_matches_avd_not_cis_control_id(with_suppressions_file):
    """The allowlist must NOT match a CIS control id like '5.1.2' even though
    it's also present in control_id-style fields. AVD ids are the canonical
    suppression key."""
    with_suppressions_file("""
suppressions:
  - avd_id: "5.1.2"
    target_kind: ClusterRole
    target_name: admin
    reason: built-in-k8s
    justification: "wrong key shape"
""")
    findings = parse_trivy(COMPLIANCE_RBAC_REPORT)
    by_name = {f["resource_name"]: f for f in findings}
    admin = by_name["admin"]
    # control_id is "5.1.2" in compliance shape, but evidence.avd_id is
    # "AVD-KSV-0041" — and the lookup prefers evidence.avd_id, so the entry
    # keyed on "5.1.2" must NOT match.
    assert admin["severity_normalized"] == int(Severity.CRITICAL)
