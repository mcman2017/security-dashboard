from pathlib import Path
from typing import Literal

from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SEC_DASHBOARD_", env_file=".env", extra="ignore")

    mock: bool = False
    data_dir: str = "/data"
    namespace: str = "security-dashboard"

    # How the Trivy scan Jobs read image layers:
    #   registry   — pull from the image registries directly. No hostPath, no
    #                extra node access; the namespace can enforce PSS baseline.
    #   node-cache — mount the node's containerd socket (hostPath) and read
    #                the already-pulled layers from the runtime cache. Needed
    #                for air-gapped clusters, private single-arch registries,
    #                or to avoid registry rate limits — requires PSS privileged.
    scan_mode: Literal["registry", "node-cache"] = "registry"
    containerd_socket_path: str = "/run/containerd/containerd.sock"
    # Optional TRIVY_PLATFORM value (e.g. "linux/arm64"). Only a fallback hint:
    # `trivy k8s` per-image scans ignore it, but `trivy image`-style remote
    # fetches honor it. Empty = unset.
    trivy_platform: str = ""

    # Names of the K8s objects the scan Jobs reference — must match the
    # ServiceAccount / PVCs the Helm chart (or your manifests) created.
    scanner_service_account: str = "trivy-scanner"
    scan_results_pvc: str = "security-dashboard-scan-results"
    trivy_cache_pvc: str = "security-dashboard-trivy-cache"

    @computed_field  # type: ignore[misc]
    @property
    def sqlite_path(self) -> str:
        return str(Path(self.data_dir) / "sqlite.db")

    @computed_field  # type: ignore[misc]
    @property
    def raw_dir(self) -> str:
        return str(Path(self.data_dir) / "raw")

    trivy_image: str = "aquasec/trivy:0.59.0"

    # The plugin reaches this backend through Headlamp's in-cluster apiserver
    # service-proxy (same origin as Headlamp), so CORS is not exercised in
    # production. Kept permissive only for local dev against the Vite server.
    cors_origins: list[str] = ["http://localhost:5173"]


settings = Settings()
