"""Filesystem persistence for raw scan outputs.

SQLite holds parsed findings + scan metadata. The verbatim scanner output
(potentially many MB of JSON) lives as files on the PVC so the UI can
serve "Download raw JSON" without bloating the DB.
"""

from pathlib import Path

import gzip

from .config import settings


def ensure_dirs() -> None:
    Path(settings.data_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.raw_dir).mkdir(parents=True, exist_ok=True)


def raw_json_path(scan_id: str) -> Path:
    return Path(settings.raw_dir) / f"{scan_id}.json.gz"


def raw_log_path(scan_id: str) -> Path:
    return Path(settings.raw_dir) / f"{scan_id}.log.gz"


def write_raw_json(scan_id: str, content: bytes) -> str:
    ensure_dirs()
    p = raw_json_path(scan_id)
    with gzip.open(p, "wb") as f:
        f.write(content)
    return str(p)


def write_raw_log(scan_id: str, content: str) -> str:
    ensure_dirs()
    p = raw_log_path(scan_id)
    with gzip.open(p, "wt", encoding="utf-8") as f:
        f.write(content)
    return str(p)


def read_raw_json(scan_id: str) -> bytes | None:
    p = raw_json_path(scan_id)
    if not p.exists():
        return None
    with gzip.open(p, "rb") as f:
        return f.read()


def read_raw_log(scan_id: str) -> str | None:
    p = raw_log_path(scan_id)
    if not p.exists():
        return None
    with gzip.open(p, "rt", encoding="utf-8") as f:
        return f.read()
