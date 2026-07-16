"""Finding suppression — allowlist of accepted-risk (avd_id, target_kind, target_name) triples.

When a Trivy or Kubescape parser produces a finding whose triple is on the
list, the parser rebuckets the finding's severity to SUPPRESSED instead of
its original severity (CRITICAL / HIGH / etc.). The finding is **kept** —
only its severity_normalized field changes — and the evidence is enriched
with `suppression_reason` + `suppression_justification` so the dashboard
can render the per-row acceptance rationale inline.

The allowlist file lives at `$SEC_DASHBOARD_SUPPRESSIONS_PATH` (defaults
to `/data/suppressions.yaml`, mounted via ConfigMap in K8s). If the file
is missing or malformed, `is_suppressed()` returns `False` for every
query — fail-open. The rationale: a silent suppression bug would hide
real findings; better to show CRITICAL=40 again until the operator
notices.

The file format is YAML (see docs/suppressions.md):

    suppressions:
      - avd_id: AVD-KSV-0041
        target_kind: ClusterRole
        target_name: admin
        reason: built-in-k8s
        justification: "..."

Lookup is O(1) via an in-memory dict keyed by (avd_id, target_kind, target_name).
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_PATH = "/data/suppressions.yaml"


@dataclass(frozen=True)
class _PatternEntry:
    """Glob-pattern entry — matched at lookup time, in YAML order, after exact
    misses. Two reasons we need this:
      1. Kubeadm static pods are named `<component>-<nodename>`; suppressing
         each instance per node is tedious and breaks on rename.
      2. Rook-Ceph OSD-prepare Jobs get fresh names on every provisioning;
         exact matches go stale immediately.
    Patterns use fnmatch syntax (`*`, `?`, `[abc]`) — not full regex."""
    avd_id: str
    target_kind: str
    target_name_pattern: str
    reason: str
    justification: str


def _path() -> Path:
    return Path(os.environ.get("SEC_DASHBOARD_SUPPRESSIONS_PATH", _DEFAULT_PATH))


@lru_cache(maxsize=1)
def _load() -> tuple[dict[tuple[str, str, str], tuple[str, str]], list[_PatternEntry]]:
    """Returns (exact_lookup, pattern_list). Patterns evaluated only when
    exact lookup misses. Both share the same `reason` + `justification` shape."""
    p = _path()
    if not p.exists():
        logger.info("suppressions: file not found at %s; fail-open (no suppressions)", p)
        return ({}, [])
    try:
        data = yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        logger.warning("suppressions: failed to parse %s: %s; fail-open", p, e)
        return ({}, [])
    if not isinstance(data, dict):
        logger.warning("suppressions: %s root is not a mapping; fail-open", p)
        return ({}, [])

    exact: dict[tuple[str, str, str], tuple[str, str]] = {}
    patterns: list[_PatternEntry] = []
    entries = data.get("suppressions") or []
    if not isinstance(entries, list):
        logger.warning("suppressions: 'suppressions' key is not a list; fail-open")
        return ({}, [])

    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            logger.warning("suppressions: entry %d is not a mapping; skipping", i)
            continue
        avd = e.get("avd_id")
        kind = e.get("target_kind")
        if not (avd and kind):
            logger.warning("suppressions: entry %d missing avd_id/target_kind; skipping", i)
            continue
        reason = e.get("reason") or "unspecified"
        justification = (e.get("justification") or "").strip()
        name = e.get("target_name")
        pattern = e.get("target_name_pattern")
        if pattern:
            patterns.append(_PatternEntry(avd, kind, pattern, reason, justification))
        elif name:
            exact[(avd, kind, name)] = (reason, justification)
        else:
            logger.warning(
                "suppressions: entry %d needs target_name or target_name_pattern; skipping", i
            )
            continue

    logger.info(
        "suppressions: loaded %d exact + %d pattern entries from %s",
        len(exact),
        len(patterns),
        p,
    )
    return (exact, patterns)


def reload_for_testing() -> None:
    """Tests should call this after monkeypatching the env var."""
    _load.cache_clear()


def is_suppressed(
    *,
    avd_id: str | None,
    target_kind: str | None,
    target_name: str | None,
) -> tuple[bool, str | None, str | None]:
    """Return (suppressed, reason, justification). All None if no match.

    Lookup order: exact (O(1)) first, then patterns in YAML order. Patterns
    are O(N) but N is small (~30) and only run on the exact miss path."""
    if not (avd_id and target_kind and target_name):
        return (False, None, None)
    exact, patterns = _load()
    match = exact.get((avd_id, target_kind, target_name))
    if match:
        return (True, match[0], match[1])
    for p in patterns:
        if p.avd_id != avd_id or p.target_kind != target_kind:
            continue
        if fnmatch.fnmatchcase(target_name, p.target_name_pattern):
            return (True, p.reason, p.justification)
    return (False, None, None)


# Kubescape uses C-* control IDs but flags the same underlying ClusterRoles
# as Trivy's KSV041/KSV044/KSV046. Map the Kubescape control IDs to their
# Trivy equivalents so a single allowlist covers both scanners.
#
# Cross-references verified against Kubescape v3.0.27 control catalog:
#   C-0035: Cluster-admin binding              <-> KSV044/KSV046 (wildcard)
#   C-0036: Validate admission controller     (not RBAC; skip)
#   C-0053: Access container service account  <-> KSV041 (secret-read via SA)
#   C-0066: Secret/etcd encryption           (not role-level; skip)
#
# Conservative mapping — only the controls that genuinely fire on the same
# ClusterRoles. Extend as new Kubescape versions ship new control IDs.
KUBESCAPE_TO_TRIVY_AVD = {
    "C-0035": "AVD-KSV-0046",   # cluster-admin bindings (wildcard manage all)
    "C-0044": "AVD-KSV-0046",   # container hostPort / wildcard
    "C-0053": "AVD-KSV-0041",   # access to secrets via ClusterRole
    "C-0270": "AVD-KSV-0041",   # secret-management ClusterRole (post-v3 control id)
    "C-0271": "AVD-KSV-0046",   # wildcard ClusterRole (post-v3 control id)
}


def kubescape_avd_equivalent(control_id: str | None) -> str | None:
    if not control_id:
        return None
    return KUBESCAPE_TO_TRIVY_AVD.get(control_id)
