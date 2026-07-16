import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import storage
from .config import settings
from .db import init_db
from .routes import health, scans
from .scans.k8s import shutdown_k8s
from .scans.manager import manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    storage.ensure_dirs()
    await init_db()
    await manager.reconcile()
    yield
    await manager.shutdown()
    await shutdown_k8s()


app = FastAPI(
    title="security-dashboard-backend",
    description="On-demand Trivy (CIS / NSA / Full-Vuln) scanning backend for the Headlamp security-dashboard plugin.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api")
app.include_router(scans.router, prefix="/api")
