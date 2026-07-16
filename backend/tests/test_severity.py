from sec_dashboard.severity import (
    Severity,
    from_kube_bench,
    from_kubescape,
    from_lynis,
    from_trivy,
)


def test_trivy_direct_map():
    assert from_trivy("CRITICAL") == Severity.CRITICAL
    assert from_trivy("HIGH") == Severity.HIGH
    assert from_trivy("MEDIUM") == Severity.MEDIUM
    assert from_trivy("LOW") == Severity.LOW
    assert from_trivy("UNKNOWN") == Severity.INFO
    assert from_trivy("") == Severity.INFO
    assert from_trivy("nonsense") == Severity.INFO


def test_kube_bench_profile_weighting():
    # FAIL on control-plane profiles → HIGH
    for prof in ("master", "controlplane", "etcd"):
        assert from_kube_bench("FAIL", prof) == Severity.HIGH
    # FAIL on node/policies → MEDIUM
    assert from_kube_bench("FAIL", "node") == Severity.MEDIUM
    assert from_kube_bench("FAIL", "policies") == Severity.MEDIUM
    # WARN regardless of profile → MEDIUM
    assert from_kube_bench("WARN", "master") == Severity.MEDIUM
    # INFO → INFO
    assert from_kube_bench("INFO", "node") == Severity.INFO


def test_kubescape_label_and_score():
    assert from_kubescape("Critical") == Severity.CRITICAL
    assert from_kubescape("High") == Severity.HIGH
    assert from_kubescape("Medium") == Severity.MEDIUM
    assert from_kubescape("Low") == Severity.LOW
    # Score fallback when label missing
    assert from_kubescape("", score=9.5) == Severity.CRITICAL
    assert from_kubescape("", score=7.4) == Severity.HIGH
    assert from_kubescape("", score=4.5) == Severity.MEDIUM
    assert from_kubescape("", score=1.0) == Severity.LOW


def test_lynis_warning_and_suggestion():
    assert from_lynis("warning", "high") == Severity.HIGH
    assert from_lynis("warning", "medium") == Severity.MEDIUM
    assert from_lynis("warning", "low") == Severity.LOW
    assert from_lynis("warning", None) == Severity.MEDIUM  # default impact
    assert from_lynis("suggestion") == Severity.LOW


def test_severity_label():
    assert Severity.CRITICAL.label == "CRITICAL"
    assert Severity.INFO.label == "INFO"
