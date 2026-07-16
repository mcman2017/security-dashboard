# syntax=docker/dockerfile:1.7
# Multi-arch (linux/amd64 + linux/arm64) — built via docker buildx in CI.

FROM python:3.12-slim-bookworm AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN pip install --no-cache-dir uv==0.5.* \
 && uv venv /venv
COPY pyproject.toml ./
COPY src ./src
RUN uv pip install --python /venv/bin/python --no-cache .


FROM python:3.12-slim-bookworm AS runtime
ENV PATH="/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SEC_DASHBOARD_DATA_DIR=/data

# Non-root runtime user with a stable uid/gid for fsGroup in the PVC manifest.
RUN groupadd -g 1000 sec && useradd -u 1000 -g 1000 -d /app -M -s /usr/sbin/nologin sec \
 && mkdir -p /data /app && chown -R 1000:1000 /data /app

WORKDIR /app
COPY --from=builder /venv /venv

USER 1000
EXPOSE 8000

# Plain stdlib healthcheck — no curl in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3); sys.exit(0 if r.status==200 else 1)" || exit 1

CMD ["uvicorn", "sec_dashboard.main:app", "--host", "0.0.0.0", "--port", "8000"]
