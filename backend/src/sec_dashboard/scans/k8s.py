"""Thin wrapper around kubernetes-asyncio for scan-job lifecycle.

Loads in-cluster config when deployed; falls back to ~/.kube/config when
running on a workstation. Exposes only the verbs the orchestrator needs.
"""

from __future__ import annotations

import asyncio
import logging

from kubernetes_asyncio import client, config
from kubernetes_asyncio.client.exceptions import ApiException

from ..config import settings

log = logging.getLogger(__name__)


SHIPPER_BEGIN = "__SEC_DASHBOARD_BEGIN__"
SHIPPER_END = "__SEC_DASHBOARD_END__"


class K8sClient:
    def __init__(self) -> None:
        self._api: client.ApiClient | None = None

    async def init(self) -> None:
        try:
            config.load_incluster_config()
            log.info("k8s: loaded in-cluster config")
        except config.ConfigException:
            await config.load_kube_config()
            log.info("k8s: loaded kubeconfig from disk")
        self._api = client.ApiClient()

    async def close(self) -> None:
        if self._api is not None:
            await self._api.close()
            self._api = None

    @property
    def api(self) -> client.ApiClient:
        if self._api is None:
            raise RuntimeError("K8sClient not initialized — call init() first")
        return self._api

    async def create_job(self, manifest: dict) -> str:
        batch = client.BatchV1Api(self.api)
        ns = manifest["metadata"]["namespace"]
        try:
            j = await batch.create_namespaced_job(namespace=ns, body=manifest)
            return j.metadata.name
        except ApiException as e:
            raise RuntimeError(f"create_job failed: {e.status} {e.reason} {e.body}") from e

    async def get_job(self, name: str) -> dict | None:
        batch = client.BatchV1Api(self.api)
        try:
            j = await batch.read_namespaced_job(name=name, namespace=settings.namespace)
        except ApiException as e:
            if e.status == 404:
                return None
            raise
        s = j.status
        return {
            "name": name,
            "active": s.active or 0,
            "succeeded": s.succeeded or 0,
            "failed": s.failed or 0,
            "conditions": [
                {"type": c.type, "status": c.status, "reason": c.reason, "message": c.message}
                for c in (s.conditions or [])
            ],
        }

    async def delete_job(self, name: str) -> None:
        batch = client.BatchV1Api(self.api)
        try:
            await batch.delete_namespaced_job(
                name=name,
                namespace=settings.namespace,
                propagation_policy="Background",
            )
        except ApiException as e:
            if e.status != 404:
                log.warning("delete_job %s: %s %s", name, e.status, e.reason)

    async def find_pod(self, job_name: str) -> str | None:
        core = client.CoreV1Api(self.api)
        pods = await core.list_namespaced_pod(
            namespace=settings.namespace,
            label_selector=f"job-name={job_name}",
        )
        if not pods.items:
            return None
        return pods.items[0].metadata.name

    async def read_container_log(self, pod: str, container: str) -> str:
        core = client.CoreV1Api(self.api)
        try:
            return await core.read_namespaced_pod_log(
                name=pod,
                namespace=settings.namespace,
                container=container,
            )
        except ApiException as e:
            if e.status == 404:
                return ""
            raise

    async def list_pod_events(self, pod: str) -> list[dict]:
        core = client.CoreV1Api(self.api)
        try:
            evs = await core.list_namespaced_event(
                namespace=settings.namespace,
                field_selector=f"involvedObject.name={pod}",
            )
            return [
                {"type": e.type, "reason": e.reason, "message": e.message, "ts": str(e.last_timestamp)}
                for e in evs.items
            ]
        except ApiException:
            return []

    async def list_scan_jobs(self, scan_id: str | None = None) -> list[dict]:
        """All jobs in our namespace labeled by us. Used by polling + reconciliation."""
        batch = client.BatchV1Api(self.api)
        selector = "security-dashboard/scan-id"
        if scan_id is not None:
            selector = f"security-dashboard/scan-id={scan_id}"
        jobs = await batch.list_namespaced_job(
            namespace=settings.namespace,
            label_selector=selector,
        )
        out = []
        for j in jobs.items:
            s = j.status
            labels = j.metadata.labels or {}
            out.append({
                "name": j.metadata.name,
                "scan_id": labels.get("security-dashboard/scan-id"),
                "scanner": labels.get("security-dashboard/scanner"),
                "variant": labels.get("security-dashboard/variant"),
                "target": labels.get("security-dashboard/job-target"),
                "role": labels.get("security-dashboard/job-role"),
                "active": s.active or 0,
                "succeeded": s.succeeded or 0,
                "failed": s.failed or 0,
            })
        return out

    async def list_nodes(self) -> list[dict]:
        """Nodes + control-plane detection for kube-bench Job placement."""
        core = client.CoreV1Api(self.api)
        nodes = await core.list_node()
        out = []
        for n in nodes.items:
            labels = n.metadata.labels or {}
            taints = [
                {"key": t.key, "value": t.value, "effect": t.effect}
                for t in (n.spec.taints or [])
            ]
            out.append({
                "name": n.metadata.name,
                "is_control_plane": "node-role.kubernetes.io/control-plane" in labels,
                "labels": labels,
                "taints": taints,
            })
        return out


_client: K8sClient | None = None
_init_lock = asyncio.Lock()


async def get_k8s() -> K8sClient:
    global _client
    async with _init_lock:
        if _client is None:
            _client = K8sClient()
            await _client.init()
    return _client


async def shutdown_k8s() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None


def extract_shipper_payload(log_text: str) -> str:
    """Pull the base64'd gzipped result out of the shipper container log."""
    begin = log_text.find(SHIPPER_BEGIN)
    end = log_text.find(SHIPPER_END)
    if begin < 0 or end < 0 or end <= begin:
        raise ValueError(
            "shipper log missing sentinels — scan likely failed before producing output; "
            f"log was: {log_text[:500]!r}"
        )
    body = log_text[begin + len(SHIPPER_BEGIN) : end]
    return "".join(body.split())  # strip whitespace / newlines
