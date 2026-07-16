"""Scanner abstractions.

In M1 these are stubs — the real Job-creation / log-shipping logic lands
in M2 (Trivy) and M3 (the others). The shapes here are what `manager.py`
will call.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ScannerName(StrEnum):
    TRIVY = "trivy"


@dataclass
class ScanResult:
    raw_json: dict | str
    findings: list[dict] = field(default_factory=list)
    error: str | None = None
    raw_log: str = ""

    @property
    def summary_counts(self) -> dict[str, int]:
        out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            from ..severity import Severity

            out[Severity(f["severity_normalized"]).label] += 1
        return out


class ScannerSpec:
    """Per-scanner spec — image, command, mounts, RBAC. Filled out in M2/M3."""

    name: ScannerName
    variant: str | None = None

    def job_manifest(self, scan_id: str, image: str, shipper_image: str) -> dict[str, Any]:
        raise NotImplementedError

    def parse_output(self, raw_json: dict | str) -> list[dict]:
        raise NotImplementedError
