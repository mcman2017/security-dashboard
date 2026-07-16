"""One-shot: re-parse every completed scan's stored raw JSON with the
CURRENT parser, replacing the persisted findings + summary_counts in SQLite.

Use when a parser bug is fixed and you want existing scans to reflect the
new logic without re-running the scan. The raw .json.gz files on the PVC
are the source of truth — we never need re-execute Trivy/Kubescape/Lynis.

Invoke from inside the api container:

    kubectl -n sec-dashboard exec deploy/sec-dashboard -c api -- \
        python3 -m sec_dashboard.reparse [scan_id_prefix...]

With no args, re-parses every completed scan. With one or more args, only
re-parses scans whose id starts with that prefix.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import sqlite3
import sys

from sqlalchemy import select

from .config import settings
from .db import Scan, get_sessionmaker, init_db
from .scans.manager import _summary_counts
from .scans.parsers import parse_trivy


def _parse_one(scanner: str, raw_bytes: bytes, target_node: str | None) -> list[dict]:
    if scanner == "trivy":
        return parse_trivy(json.loads(raw_bytes))
    raise ValueError(f"unknown scanner {scanner}")


def _parse_bundle(scanner: str, raw_bytes: bytes) -> list[dict]:
    """Trivy scans are single-job, so the stored raw is always a single JSON
    report. Kept as a thin wrapper for parity with the live ingestion path."""
    return _parse_one(scanner, raw_bytes, target_node=None)


async def reparse(prefixes: list[str]) -> None:
    await init_db()
    sm = get_sessionmaker()
    async with sm() as sess:
        q = select(Scan).where(Scan.status == "completed").order_by(Scan.started_at.desc())
        scans = (await sess.execute(q)).scalars().all()

    for s in scans:
        if prefixes and not any(s.id.startswith(p) for p in prefixes):
            continue
        if not s.raw_json_path or not os.path.exists(s.raw_json_path):
            print(f"  {s.id[:8]} {s.scanner}/{s.variant or '-'}: no raw file (skipping)")
            continue

        with gzip.open(s.raw_json_path, "rb") as f:
            raw_bytes = f.read()

        try:
            findings = _parse_bundle(s.scanner, raw_bytes)
        except Exception as e:  # noqa: BLE001
            print(f"  {s.id[:8]} {s.scanner}/{s.variant or '-'}: parse failed: {e}")
            continue

        counts = _summary_counts(findings)
        # Bypass SQLAlchemy for the bulk insert. The async + aiosqlite +
        # autoincrement RETURNING combo reliably trips `disk I/O error`
        # on the network-attached (Ceph/NFS-class) PVC; a direct sqlite3 connection with
        # executemany() handles the same workload fine. We keep using
        # SQLAlchemy for the Scan summary update because that's a single
        # row and benefits from the model.
        _bulk_replace_findings(s.id, findings)
        async with sm() as sess:
            row = (await sess.execute(select(Scan).where(Scan.id == s.id))).scalar_one()
            row.summary_counts = counts
            await sess.commit()
        print(f"  {s.id[:8]} {s.scanner}/{s.variant or '-'}: re-parsed → {len(findings)} findings, counts={counts}")


def _bulk_replace_findings(scan_id: str, findings: list[dict]) -> None:
    """Delete existing findings for scan_id and insert the new list using a
    raw sqlite3 connection. Used by reparse + by the live ingestion path."""
    conn = sqlite3.connect(settings.sqlite_path, timeout=30.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("delete from findings where scan_id = ?", (scan_id,))
        rows = [
            (
                scan_id,
                f["severity_normalized"],
                f["severity_original"],
                f.get("scanner_id"),
                f.get("resource_ns"),
                f.get("resource_kind"),
                f.get("resource_name"),
                f.get("image"),
                f["title"],
                f.get("description"),
                f.get("control_id"),
                json.dumps(f.get("evidence")) if f.get("evidence") is not None else None,
                bool(f.get("ecosystem_bucket", False)),
            )
            for f in findings
        ]
        conn.executemany(
            "insert into findings ("
            "scan_id, severity_normalized, severity_original, scanner_id, "
            "resource_ns, resource_kind, resource_name, image, title, "
            "description, control_id, evidence, ecosystem_bucket"
            ") values (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def main() -> None:
    prefixes = sys.argv[1:]
    if prefixes:
        print(f"re-parsing scans matching: {prefixes}")
    else:
        print("re-parsing ALL completed scans")
    print(f"data_dir: {settings.data_dir}")
    asyncio.run(reparse(prefixes))


if __name__ == "__main__":
    main()
