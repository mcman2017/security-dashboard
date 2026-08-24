"""Lynis report.dat → flat finding dicts.

The .dat format is line-based key=value with arrays denoted by `key[]=value`:
  hardening_index=66
  warning[]=AUTH-9286|No password set for single user mode|-|-
  suggestion[]=BOOT-5184|Set a password on GRUB bootloader|-|-

Each warning[]/suggestion[] line carries pipe-separated fields:
  TEST_ID | MESSAGE | TEST_DETAILS | EXTRA

IMPACT is NOT in report.dat — Lynis defines IMPACT in each test's plugin file,
not in the output — so warnings default to MEDIUM and suggestions to LOW
(see severity.from_lynis).
"""

from __future__ import annotations

from ...severity import Severity, from_lynis

HARDENING_INDEX_ID = "LYNIS-HARDENING-INDEX"


def _parse_dat(text: str) -> tuple[list[dict], dict[str, str]]:
    """Returns (rows, single_values) where rows are the warning[]/suggestion[]
    entries and single_values is the rest of report.dat as a flat dict."""
    rows: list[dict] = []
    singles: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, eq, value = line.partition("=")
        if not eq:
            continue
        key = key.strip()
        value = value.strip()
        if key.endswith("[]"):
            kind = key[:-2]
            fields = value.split("|")
            test_id = fields[0] if len(fields) > 0 else ""
            message = fields[1] if len(fields) > 1 else ""
            detail = fields[2] if len(fields) > 2 else ""
            extra = fields[3] if len(fields) > 3 else ""
            rows.append({
                "kind": kind,
                "test_id": test_id,
                "message": message,
                "detail": detail if detail not in ("-", "") else None,
                "extra": extra if extra not in ("-", "") else None,
            })
        else:
            singles[key] = value
    return rows, singles


def parse_lynis(text: str, *, target_node: str | None = None) -> list[dict]:
    rows, singles = _parse_dat(text)
    hardening_index = singles.get("hardening_index")
    findings: list[dict] = []
    for r in rows:
        kind = r["kind"]
        if kind not in {"warning", "suggestion"}:
            continue
        sev = from_lynis(kind, None)  # IMPACT not in .dat; default mapping applies
        findings.append({
            "severity_normalized": int(sev),
            "severity_original": kind,
            "scanner_id": r["test_id"],
            "resource_ns": None,
            "resource_kind": "Host",
            "resource_name": target_node,
            "image": None,
            "title": r["message"] or r["test_id"] or "lynis finding",
            "description": r["detail"] or r["extra"],
            "control_id": r["test_id"],
            "evidence": {
                "kind": kind,
                "detail": r["detail"],
                "extra": r["extra"],
                "hardening_index": hardening_index,
            },
            "ecosystem_bucket": False,
        })
    # Surface the node's hardening index as its own INFO finding so the score
    # is visible in the dashboard instead of buried inside evidence blobs.
    if hardening_index is not None:
        findings.append({
            "severity_normalized": int(Severity.INFO),
            "severity_original": "index",
            "scanner_id": HARDENING_INDEX_ID,
            "resource_ns": None,
            "resource_kind": "Host",
            "resource_name": target_node,
            "image": None,
            "title": f"Lynis hardening index: {hardening_index}",
            "description": (
                "Lynis's overall hardening score for this host (0-100; higher "
                "is better). Warnings and suggestions in this scan list the "
                "individual improvements."
            ),
            "control_id": HARDENING_INDEX_ID,
            "evidence": {
                "hardening_index": hardening_index,
                "lynis_version": singles.get("lynis_version"),
                "os_fullname": singles.get("os_fullname"),
                "kernel_version": singles.get("os_kernel_version_full") or singles.get("os_kernel_version"),
            },
            "ecosystem_bucket": False,
        })
    return findings
