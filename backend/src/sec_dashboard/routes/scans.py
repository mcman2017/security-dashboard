from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..scans.base import ScannerName
from ..scans.manager import manager

router = APIRouter()


@router.get("/scanners")
async def list_scanners() -> dict:
    return {
        "scanners": [
            {
                "name": "trivy",
                "label": "Trivy",
                "variants": [
                    {"id": "cis", "label": "CIS k8s-cis-1.23", "description": "CIS Benchmark compliance scan"},
                    {"id": "nsa", "label": "NSA k8s-nsa-1.0", "description": "NSA/CISA Kubernetes hardening"},
                    {"id": "vuln", "label": "Full vulnerability scan", "description": "CVE scan across all cluster images"},
                ],
            },
        ]
    }


@router.get("/scans")
async def list_scans() -> dict:
    scans = await manager.list_scans()
    return {"scans": [{k: v for k, v in s.items() if k != "findings"} for s in scans]}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    scan = await manager.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail=f"scan {scan_id} not found")
    return scan


@router.get("/scans/{scan_id}/raw")
async def get_scan_raw(scan_id: str) -> dict:
    raw = await manager.get_raw(scan_id)
    if raw is None:
        raise HTTPException(status_code=404, detail=f"scan {scan_id} not found")
    return raw


class LaunchRequest(BaseModel):
    scanner: ScannerName
    variant: str | None = None


@router.post("/scans")
async def launch_scan(req: LaunchRequest) -> dict:
    try:
        return await manager.launch(req.scanner, req.variant)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    deleted = await manager.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"scan {scan_id} not found")
    return {"id": scan_id, "deleted": True}


_SEVERITY_LABEL_TO_INT = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "SUPPRESSED": 0,
}


@router.get("/findings/by-severity/{severity}")
async def findings_by_severity(severity: str) -> dict:
    """Aggregate every completed scan's findings of one severity into a
    single response. Used by the Home stat-card click-through view."""
    label = severity.upper()
    if label not in _SEVERITY_LABEL_TO_INT:
        raise HTTPException(
            status_code=400,
            detail=f"unknown severity {severity!r}; expected one of {sorted(_SEVERITY_LABEL_TO_INT)}",
        )
    findings = await manager.findings_by_severity(_SEVERITY_LABEL_TO_INT[label])
    return {"severity": label, "total": len(findings), "findings": findings}
