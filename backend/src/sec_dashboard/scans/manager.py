"""Scan orchestrator — live mode (M3: multi-Job support).

A scan may map to one OR many K8s Jobs (kube-bench creates one per node).
The orchestrator tracks Jobs by the shared `security-dashboard/scan-id` label.

Lifecycle:
  1. `launch()` — generates scan-id, builds the list of Job manifests for the
     requested scanner, persists Scan(status=pending), creates each Job,
     flips to `running`, spawns a background poller.
  2. `_poll_to_completion()` — every 5s, lists Jobs labeled with the scan-id.
     When ALL Jobs are terminal, dispatches `_capture_completion`.
  3. `_capture_completion()` — for each succeeded Job: reads shipper log
     → base64+gunzip → bytes → parse with the scanner's parser → aggregate.
     For each failed Job: captures stderr + pod events into the error message.
     Persists aggregated findings, writes raw outputs, deletes Jobs.

In mock mode (SEC_DASHBOARD_MOCK=1) the manager bypasses K8s entirely.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select

from ..config import settings
from ..severity import Severity
from ..db import Event, Finding, Scan, get_sessionmaker
from ..mock_data import mock_raw_output, mock_scans
from .. import storage
from .base import ScannerName
from .k8s import K8sClient, get_k8s
from . import trivy as trivy_spec
from .parsers import parse_trivy

log = logging.getLogger(__name__)

POLL_INTERVAL_S = 5


def _scan_to_dict(s: Scan, *, include_findings: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": s.id,
        "scanner": s.scanner,
        "variant": s.variant,
        "status": s.status,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "error": s.error,
        "summary_counts": s.summary_counts or {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "SUPPRESSED": 0},
        "job_name": s.job_name,
    }
    if include_findings:
        out["findings"] = [_finding_to_dict(f) for f in s.findings]
    return out


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "severity_normalized": f.severity_normalized,
        "severity_original": f.severity_original,
        "scanner_id": f.scanner_id,
        "resource_ns": f.resource_ns,
        "resource_kind": f.resource_kind,
        "resource_name": f.resource_name,
        "image": f.image,
        "title": f.title,
        "description": f.description,
        "control_id": f.control_id,
        "evidence": f.evidence,
        "ecosystem_bucket": f.ecosystem_bucket,
    }


# Mount path shared with the Trivy Job; see trivy.SCAN_RESULTS_MOUNT.
# Kept as a private constant here so the manager and the Job spec agree on
# the path without importing across module boundaries unnecessarily.
_SCAN_RESULTS_DIR = "/scan-results"


def _read_pvc_result(scan_id: str) -> bytes:
    """Read the scan-result JSON for `scan_id` off the shared RWX PVC.

    Trivy writes /scan-results/<scan-id>.json atomically (tmp + rename) on
    successful completion. If the file is missing the scan must have failed
    before producing output — caller surfaces that as an error.
    """
    path = f"{_SCAN_RESULTS_DIR}/{scan_id}.json"
    with open(path, "rb") as f:
        return f.read()


def _cleanup_pvc_result(scan_id: str) -> None:
    """Delete the scan-result JSON from the PVC after ingestion. Best-effort;
    a leftover file won't break future scans (each gets its own id) but does
    consume PVC space."""
    import os
    for suffix in (".json", ".json.tmp"):
        path = f"{_SCAN_RESULTS_DIR}/{scan_id}{suffix}"
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            log.warning("scan %s: cleanup of %s failed: %s", scan_id, path, e)


# Trivy ≥0.61 doesn't abort `trivy k8s` when one image can't be fetched — it
# logs one ERROR per image and keeps scanning. This typically hits single-arch
# private-registry images that aren't in the scan node's containerd store:
# `trivy k8s` has no --platform flag and asks registries for linux/amd64
# regardless of the node's arch (upstream limitation, verified through 0.72).
# The escaped \" is how the image name appears inside trivy's err="..." lines.
_UNSCANNABLE_IMAGE_RE = re.compile(r'unable to find the specified image \\*"([^"\\]+)')


def _unscannable_image_findings(scanner_log: str) -> list[dict]:
    """One INFO finding per image Trivy skipped, so coverage gaps are visible
    in the dashboard instead of buried in the scanner log."""
    images = sorted({m.group(1) for m in _UNSCANNABLE_IMAGE_RE.finditer(scanner_log or "")})
    return [
        {
            "severity_normalized": int(Severity.INFO),
            "severity_original": "SKIPPED",
            "scanner_id": None,
            "resource_ns": None,
            "resource_kind": "Image",
            "resource_name": image,
            "image": image,
            "title": "Image could not be scanned",
            "description": (
                "Trivy could not fetch this image from any source, so it has no "
                "vulnerability coverage in this scan. Typical cause: a single-arch "
                "private-registry image that is not present in the scan node's "
                "container runtime cache (`trivy k8s` requests linux/amd64 from "
                "registries regardless of node architecture)."
            ),
            "control_id": None,
            "evidence": {"reason": "image unavailable to scanner"},
            "ecosystem_bucket": False,
        }
        for image in images
    ]


def _summary_counts(findings: list[dict]) -> dict[str, int]:
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "SUPPRESSED": 0}
    label_map = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "INFO", 0: "SUPPRESSED"}
    for f in findings:
        out[label_map[f["severity_normalized"]]] += 1
    return out


async def _build_jobs_for(scan_id: str, scanner: str, variant: str | None, k8s: K8sClient) -> list[dict]:
    # Trivy-only build. `k8s` is retained in the signature for callers/tests.
    if scanner == "trivy":
        if variant not in trivy_spec.VARIANTS:
            raise ValueError(f"unknown trivy variant {variant!r}; choose one of {sorted(trivy_spec.VARIANTS)}")
        return [trivy_spec.build_job(scan_id, variant)]
    raise ValueError(f"unknown scanner {scanner}")


def _parse_for(scanner: str, raw_bytes: bytes, *, target_node: str | None) -> list[dict]:
    # Trivy-only parse. `target_node` is retained for signature compatibility.
    if scanner == "trivy":
        return parse_trivy(json.loads(raw_bytes))
    raise ValueError(f"no parser for {scanner}")


class ScanManager:
    """Owner of in-flight scan tasks. One instance per process."""

    def __init__(self) -> None:
        self._mock_cache: dict[str, dict] | None = None
        self._tasks: dict[str, asyncio.Task] = {}

    # ---------- mock-mode shortcut ----------

    def _mock_index(self) -> dict[str, dict]:
        if self._mock_cache is None:
            self._mock_cache = {s["id"]: s for s in mock_scans()}
        return self._mock_cache

    # ---------- public API ----------

    async def list_scans(self) -> list[dict]:
        if settings.mock:
            return list(self._mock_index().values())
        sm = get_sessionmaker()
        async with sm() as sess:
            res = await sess.execute(select(Scan).order_by(Scan.started_at.desc()).limit(200))
            return [_scan_to_dict(s) for s in res.scalars().all()]

    async def get_scan(self, scan_id: str) -> dict | None:
        if settings.mock:
            return self._mock_index().get(scan_id)
        sm = get_sessionmaker()
        async with sm() as sess:
            res = await sess.execute(select(Scan).where(Scan.id == scan_id))
            s = res.scalar_one_or_none()
            if s is None:
                return None
            await sess.refresh(s, ["findings"])
            return _scan_to_dict(s, include_findings=True)

    async def findings_by_severity(self, severity_int: int) -> list[dict]:
        """All findings of one severity across every completed scan, each
        annotated with its owning scan's metadata so the UI can label the row.

        Implementation note: we split into two queries (scans first, then
        findings) and join in Python rather than using SQL JOIN. The JOIN
        version reliably ran into `sqlite3.OperationalError: disk I/O error`
        on the network-attached (Ceph/NFS-class) PVC for the larger buckets (HIGH/MEDIUM/LOW
        > ~1500 rows), even after enabling WAL + busy_timeout. The direct
        sqlite3 driver handled the same rows fine, so the cause is
        SQLAlchemy/aiosqlite materializing the wide JOIN result set rather
        than the disk itself. Two narrow queries avoid the hot spot.
        """
        if settings.mock:
            out: list[dict] = []
            for scan in self._mock_index().values():
                if scan.get("status") != "completed":
                    continue
                for f in scan.get("findings", []) or []:
                    if f.get("severity_normalized") == severity_int:
                        out.append({
                            **f,
                            "scan": {
                                "id": scan["id"],
                                "scanner": scan["scanner"],
                                "variant": scan.get("variant"),
                                "started_at": scan.get("started_at"),
                            },
                        })
            return out
        sm = get_sessionmaker()
        async with sm() as sess:
            scans_res = await sess.execute(
                select(Scan.id, Scan.scanner, Scan.variant, Scan.started_at)
                .where(Scan.status == "completed")
                .order_by(Scan.started_at.desc())
            )
            scans_meta: dict[str, dict] = {}
            for sid, scanner, variant, started_at in scans_res.all():
                scans_meta[sid] = {
                    "id": sid,
                    "scanner": scanner,
                    "variant": variant,
                    "started_at": started_at.isoformat() if started_at else None,
                }
            if not scans_meta:
                return []
            scan_ids = list(scans_meta.keys())
            findings_res = await sess.execute(
                select(Finding)
                .where(Finding.severity_normalized == severity_int)
                .where(Finding.scan_id.in_(scan_ids))
                .order_by(Finding.id)
            )
            out2: list[dict] = []
            for f in findings_res.scalars().all():
                d = _finding_to_dict(f)
                d["scan"] = scans_meta.get(f.scan_id, {"id": f.scan_id})
                out2.append(d)
            # Sort by scan's started_at desc, then finding.id
            def _sort_key(d: dict) -> tuple[str, int]:
                return (
                    "" if d["scan"].get("started_at") is None else d["scan"]["started_at"],
                    0,
                )
            out2.sort(key=_sort_key, reverse=True)
            return out2

    async def get_raw(self, scan_id: str) -> dict | None:
        if settings.mock:
            scan = self._mock_index().get(scan_id)
            if not scan:
                return None
            return {"scan_id": scan_id, "scanner": scan["scanner"], "raw": mock_raw_output(scan["scanner"])}
        raw = storage.read_raw_json(scan_id)
        sm = get_sessionmaker()
        async with sm() as sess:
            res = await sess.execute(select(Scan).where(Scan.id == scan_id))
            s = res.scalar_one_or_none()
            if s is None:
                return None
            text = ""
            if raw:
                try:
                    parsed = json.loads(raw)
                    text = json.dumps(parsed, indent=2)
                except json.JSONDecodeError:
                    text = raw.decode("utf-8", errors="replace")
            return {"scan_id": scan_id, "scanner": s.scanner, "raw": text}

    async def launch(self, scanner: ScannerName, variant: str | None) -> dict:
        if settings.mock:
            return self._mock_launch(scanner, variant)

        scan_id = str(uuid4())
        k8s = await get_k8s()

        try:
            manifests = await _build_jobs_for(scan_id, scanner.value, variant, k8s)
        except (ValueError, RuntimeError):
            raise
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"job-manifest build failed: {e}") from e

        primary_name = manifests[0]["metadata"]["name"]

        sm = get_sessionmaker()
        async with sm() as sess:
            sess.add(Scan(
                id=scan_id,
                scanner=scanner.value,
                variant=variant,
                status="pending",
                job_name=primary_name if len(manifests) == 1 else f"{primary_name} (+{len(manifests)-1} more)",
            ))
            await sess.commit()

        created: list[str] = []
        for m in manifests:
            try:
                name = await k8s.create_job(m)
                created.append(name)
                log.info("scan %s: created job %s", scan_id, name)
            except Exception as e:  # noqa: BLE001
                # Roll back any partially-created jobs
                for n in created:
                    await k8s.delete_job(n)
                await self._mark_failed(scan_id, f"job creation failed: {e}")
                raise

        sm = get_sessionmaker()
        async with sm() as sess:
            res = await sess.execute(select(Scan).where(Scan.id == scan_id))
            s = res.scalar_one()
            s.status = "running"
            await sess.commit()

        self._tasks[scan_id] = asyncio.create_task(
            self._poll_to_completion(scan_id),
            name=f"scan-poll-{scan_id}",
        )
        return await self.get_scan(scan_id) or {"id": scan_id, "status": "running"}

    def _mock_launch(self, scanner: ScannerName, variant: str | None) -> dict:
        new_id = str(uuid4())
        scan = {
            "id": new_id,
            "scanner": scanner.value,
            "variant": variant,
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "finished_at": None,
            "summary_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "SUPPRESSED": 0},
            "findings": [],
            "error": None,
        }
        self._mock_index()[new_id] = scan
        return scan

    # ---------- internal polling ----------

    async def _poll_to_completion(self, scan_id: str) -> None:
        try:
            k8s = await get_k8s()
            while True:
                await asyncio.sleep(POLL_INTERVAL_S)
                jobs = await k8s.list_scan_jobs(scan_id)
                if not jobs:
                    await self._mark_failed(scan_id, "all jobs disappeared before completion")
                    return
                active = [j for j in jobs if j["active"] > 0]
                if active:
                    continue
                await self._capture_completion(scan_id, jobs, k8s)
                return
        except asyncio.CancelledError:
            log.info("scan %s: poller cancelled (process shutdown)", scan_id)
            raise
        except Exception as e:  # noqa: BLE001
            log.exception("scan %s: poller crashed", scan_id)
            await self._mark_failed(scan_id, f"poller crashed: {e}")
        finally:
            self._tasks.pop(scan_id, None)

    async def _capture_completion(self, scan_id: str, jobs: list[dict], k8s: K8sClient) -> None:
        sm = get_sessionmaker()
        async with sm() as sess:
            s = (await sess.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            scanner_name = s.scanner

        all_findings: list[dict] = []
        raw_outputs: dict[str, bytes] = {}
        scanner_logs: dict[str, str] = {}
        errors: list[str] = []

        for j in jobs:
            name = j["name"]
            if j["succeeded"] > 0:
                pod = await k8s.find_pod(name)
                if pod is None:
                    errors.append(f"{name}: succeeded but pod missing (logs lost)")
                    continue
                # Capture scanner log either way — it carries any stderr
                # diagnostics from Trivy/Kubescape/etc. that we want to surface
                # in the UI's raw-log page even on a successful scan.
                scanner_log = await k8s.read_container_log(pod, "scanner")
                scanner_logs[name] = scanner_log
                # Trivy writes its result file to the shared RWX PVC
                # (security-dashboard-scan-results). Read it as a file — no
                # kubelet log-rotation ceiling on large vuln output.
                try:
                    raw_bytes = await asyncio.to_thread(_read_pvc_result, scan_id)
                except FileNotFoundError:
                    errors.append(
                        f"{name}: succeeded but no result file at "
                        f"{_SCAN_RESULTS_DIR}/{scan_id}.json — trivy crashed "
                        f"after the .tmp rename. Scanner log tail: " +
                        ("\n".join(scanner_log.splitlines()[-10:]) if scanner_log else "(empty)")
                    )
                    continue
                except Exception as e:  # noqa: BLE001
                    errors.append(f"{name}: result load failed: {e}")
                    continue
                raw_outputs[name] = raw_bytes
                try:
                    findings = _parse_for(scanner_name, raw_bytes, target_node=j.get("target"))
                except Exception as e:  # noqa: BLE001
                    errors.append(f"{name}: parse failed: {e}")
                    continue
                all_findings.extend(findings)
                all_findings.extend(_unscannable_image_findings(scanner_log))
            elif j["failed"] > 0:
                pod = await k8s.find_pod(name)
                scanner_log = ""
                msg = "failed"
                if pod is not None:
                    scanner_log = await k8s.read_container_log(pod, "scanner")
                    scanner_logs[name] = scanner_log
                    # Scanner stderr/stdout tail is the actionable bit — surface
                    # it directly in the error message so the UI's ErrorPanel
                    # shows the real cause without needing a /raw/ trip.
                    if scanner_log:
                        tail = "\n".join(scanner_log.splitlines()[-10:])
                        msg += f" — scanner log tail:\n{tail}"
                    events = await k8s.list_pod_events(pod)
                    # Filter to error-ish events only — startup-noise events
                    # otherwise dominate and bury the real cause.
                    err_events = [e for e in events if e["type"] != "Normal"]
                    if err_events:
                        msg += " — events: " + "; ".join(
                            f"[{e['type']}/{e['reason']}] {e['message']}" for e in err_events[-3:]
                        )
                errors.append(f"{name}: {msg}")
            else:
                errors.append(f"{name}: terminal but neither succeeded nor failed")

        # Persist raw outputs to PVC files (bundled for multi-job scans).
        raw_json_path: str | None = None
        if len(raw_outputs) == 1:
            only = next(iter(raw_outputs.values()))
            raw_json_path = storage.write_raw_json(scan_id, only)
        elif raw_outputs:
            bundle = {n: rb.decode("utf-8", errors="replace") for n, rb in raw_outputs.items()}
            raw_json_path = storage.write_raw_json(scan_id, json.dumps(bundle, indent=2).encode())

        raw_log_path: str | None = None
        if scanner_logs:
            combined = "\n\n---\n\n".join(
                f"=== {n} ===\n{lg}" for n, lg in sorted(scanner_logs.items())
            )
            raw_log_path = storage.write_raw_log(scan_id, combined)

        counts = _summary_counts(all_findings)

        # Status decision:
        #   * any findings or any clean success → completed (errors recorded as warnings)
        #   * zero outputs collected → failed
        if raw_outputs:
            status = "completed"
        else:
            status = "failed"
        error_text = "; ".join(errors) if errors else None

        sm = get_sessionmaker()
        async with sm() as sess:
            s = (await sess.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
            s.status = status
            s.error = error_text
            s.finished_at = datetime.utcnow()
            s.summary_counts = counts
            s.raw_json_path = raw_json_path
            s.raw_log_path = raw_log_path
            sess.add(Event(
                scan_id=scan_id,
                kind="error" if status == "failed" else ("warn" if errors else "info"),
                message=(error_text or f"completed with {sum(counts.values())} findings"),
            ))
            await sess.commit()
        # Bulk insert findings via raw sqlite3. SQLAlchemy ORM bulk inserts
        # trip `disk I/O error` on aiosqlite on network-attached PVCs for >500 rows
        # (autoincrement RETURNING + async pool interaction). The raw sqlite3
        # path handles the same workload reliably.
        from ..reparse import _bulk_replace_findings
        await asyncio.to_thread(_bulk_replace_findings, scan_id, all_findings)

        # Trivy writes its raw result to the shared RWX PVC; we already
        # persisted a copy via storage.write_raw_json above (in raw_outputs).
        # Drop the PVC copy so it doesn't accumulate.
        if scanner_name == "trivy":
            await asyncio.to_thread(_cleanup_pvc_result, scan_id)

        for j in jobs:
            await k8s.delete_job(j["name"])

        log.info(
            "scan %s: %s — %d findings, %d errors",
            scan_id, status, sum(counts.values()), len(errors),
        )

    async def _mark_failed(
        self,
        scan_id: str,
        error: str,
        *,
        raw_log: str | None = None,
        raw_json: bytes | None = None,
    ) -> None:
        sm = get_sessionmaker()
        async with sm() as sess:
            res = await sess.execute(select(Scan).where(Scan.id == scan_id))
            s = res.scalar_one_or_none()
            if s is None:
                return
            s.status = "failed"
            s.error = error
            s.finished_at = datetime.utcnow()
            if raw_log is not None:
                s.raw_log_path = storage.write_raw_log(scan_id, raw_log)
            if raw_json is not None:
                s.raw_json_path = storage.write_raw_json(scan_id, raw_json)
            sess.add(Event(scan_id=scan_id, kind="error", message=error))
            await sess.commit()
        log.warning("scan %s: failed — %s", scan_id, error)

    async def delete_scan(self, scan_id: str) -> bool:
        """Remove a scan everywhere: SQLite (cascades to findings + events),
        PVC raw files, and any still-live K8s Jobs/Pods that share the label.
        Returns True if the scan existed and was removed."""
        if settings.mock:
            return self._mock_index().pop(scan_id, None) is not None

        # If a poller is in flight, cancel it before yanking its DB row.
        t = self._tasks.pop(scan_id, None)
        if t is not None:
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

        sm = get_sessionmaker()
        async with sm() as sess:
            res = await sess.execute(select(Scan).where(Scan.id == scan_id))
            scan = res.scalar_one_or_none()
            if scan is None:
                return False
            await sess.delete(scan)   # cascade=all,delete-orphan removes findings + events
            await sess.commit()

        # Best-effort cleanup of PVC artefacts + any leftover Job.
        for p in (storage.raw_json_path(scan_id), storage.raw_log_path(scan_id)):
            try:
                if p.exists():
                    p.unlink()
            except OSError as e:  # noqa: BLE001
                log.warning("delete_scan %s: failed to remove %s: %s", scan_id, p, e)

        try:
            k8s = await get_k8s()
            jobs = await k8s.list_scan_jobs(scan_id)
            for j in jobs:
                await k8s.delete_job(j["name"])
        except Exception as e:  # noqa: BLE001
            # K8s unreachable shouldn't block the user-visible delete; the
            # next reconcile() will clean up any leftover Jobs anyway.
            log.warning("delete_scan %s: cluster cleanup deferred: %s", scan_id, e)

        log.info("scan %s: deleted", scan_id)
        return True

    async def shutdown(self) -> None:
        for t in list(self._tasks.values()):
            t.cancel()
        for t in list(self._tasks.values()):
            try:
                await t
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    # ---------- startup reconciliation ----------

    async def reconcile(self) -> None:
        """Recover in-flight scans after a process restart.

        Three cases per `security-dashboard/scan-id` label group:
          1. Jobs exist but no Scan row     → orphan; delete the Jobs.
          2. Jobs exist for a terminal Scan → stale; delete the Jobs.
          3. Jobs exist for a pending/running Scan → re-attach a poller.

        Then sweep SQLite for scans in pending/running with no matching Jobs
        (process crashed mid-creation OR after Job deletion but before commit) —
        mark them failed so the UI doesn't show a perpetual "running" spinner.
        """
        if settings.mock:
            return
        try:
            k8s = await get_k8s()
            jobs = await k8s.list_scan_jobs()
        except Exception as e:  # noqa: BLE001
            log.warning("reconcile: k8s unreachable, skipping (%s)", e)
            return

        by_scan: dict[str, list[dict]] = {}
        for j in jobs:
            sid = j.get("scan_id")
            if not sid:
                continue
            by_scan.setdefault(sid, []).append(j)

        sm = get_sessionmaker()

        live_scan_ids: set[str] = set()
        for scan_id, scan_jobs in by_scan.items():
            async with sm() as sess:
                res = await sess.execute(select(Scan).where(Scan.id == scan_id))
                scan = res.scalar_one_or_none()

            if scan is None:
                # orphan jobs — clean up
                log.info("reconcile: scan %s has %d orphan job(s); deleting",
                         scan_id, len(scan_jobs))
                for j in scan_jobs:
                    await k8s.delete_job(j["name"])
                continue

            if scan.status in ("completed", "failed"):
                # Stale jobs from a prior run — clean up
                log.info("reconcile: scan %s already terminal (%s); deleting %d stale job(s)",
                         scan_id, scan.status, len(scan_jobs))
                for j in scan_jobs:
                    await k8s.delete_job(j["name"])
                continue

            # Scan is pending/running with live Jobs — re-attach the poller
            log.info("reconcile: re-attaching poller for scan %s (%d job(s) live)",
                     scan_id, len(scan_jobs))
            live_scan_ids.add(scan_id)
            self._tasks[scan_id] = asyncio.create_task(
                self._poll_to_completion(scan_id),
                name=f"scan-poll-{scan_id}",
            )

        # Zombie sweep: SQLite says pending/running but no Jobs exist for them
        async with sm() as sess:
            res = await sess.execute(
                select(Scan).where(Scan.status.in_(["pending", "running"]))
            )
            for s in res.scalars().all():
                if s.id in live_scan_ids:
                    continue
                log.warning("reconcile: zombie scan %s (status=%s, no jobs); marking failed",
                            s.id, s.status)
                s.status = "failed"
                s.error = "backend restarted; scan jobs were not found on resume"
                s.finished_at = datetime.utcnow()
                sess.add(Event(
                    scan_id=s.id,
                    kind="error",
                    message="reconcile: jobs not found after restart — marked failed",
                ))
            await sess.commit()


manager = ScanManager()
