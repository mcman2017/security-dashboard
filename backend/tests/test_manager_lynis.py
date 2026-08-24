import asyncio

import pytest

from sec_dashboard.config import settings
from sec_dashboard.reparse import _parse_bundle
from sec_dashboard.scans.manager import _build_jobs_for, _parse_for, _pvc_result_path


class _StubK8s:
    async def list_nodes(self):
        return [
            {"name": "cp-1", "is_control_plane": True, "labels": {}, "taints": []},
            {"name": "worker-1", "is_control_plane": False, "labels": {}, "taints": []},
            {"name": "worker-2", "is_control_plane": False, "labels": {}, "taints": []},
        ]


def test_build_jobs_fans_out_per_node():
    settings.lynis_image = "example/lynis:test"
    jobs = asyncio.run(_build_jobs_for("scan-1", "lynis", None, _StubK8s()))
    assert len(jobs) == 3
    targets = [j["metadata"]["labels"]["security-dashboard/job-target"] for j in jobs]
    assert targets == ["cp-1", "worker-1", "worker-2"]
    roles = [j["metadata"]["labels"]["security-dashboard/job-role"] for j in jobs]
    assert roles == ["cp", "node", "node"]


def test_build_jobs_rejects_variant():
    settings.lynis_image = "example/lynis:test"
    with pytest.raises(ValueError, match="no variants"):
        asyncio.run(_build_jobs_for("scan-1", "lynis", "cis", _StubK8s()))


def test_build_jobs_requires_image():
    settings.lynis_image = ""
    with pytest.raises(ValueError, match="lynis image not configured"):
        asyncio.run(_build_jobs_for("scan-1", "lynis", None, _StubK8s()))


def test_pvc_result_path_per_scanner():
    assert _pvc_result_path("trivy", "id1", None) == "/scan-results/id1.json"
    assert _pvc_result_path("lynis", "id1", "worker-1") == "/scan-results/id1/worker-1.dat"
    with pytest.raises(ValueError, match="target node"):
        _pvc_result_path("lynis", "id1", None)


def test_parse_for_lynis_attributes_node():
    raw = b"hardening_index=80\nwarning[]=AUTH-1|msg|-|-\n"
    findings = _parse_for("lynis", raw, target_node="worker-2")
    assert all(f["resource_name"] == "worker-2" for f in findings)
    assert any(f["scanner_id"] == "AUTH-1" for f in findings)


def test_reparse_bundle_splits_nodes():
    bundle = (
        "# ===== node: cp-1 =====\n"
        "hardening_index=60\n"
        "warning[]=A-1|first|-|-\n"
        "\n\n"
        "# ===== node: worker-1 =====\n"
        "hardening_index=70\n"
        "suggestion[]=B-2|second|-|-\n"
    )
    findings = _parse_bundle("lynis", bundle.encode())
    by_node = {}
    for f in findings:
        by_node.setdefault(f["resource_name"], []).append(f)
    assert set(by_node) == {"cp-1", "worker-1"}
    assert any(f["scanner_id"] == "A-1" for f in by_node["cp-1"])
    assert any(f["scanner_id"] == "B-2" for f in by_node["worker-1"])
    # hardening index stays per-node
    hi_cp = next(f for f in by_node["cp-1"] if f["scanner_id"] == "LYNIS-HARDENING-INDEX")
    assert "60" in hi_cp["title"]
