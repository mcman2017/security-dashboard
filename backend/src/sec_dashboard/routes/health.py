from fastapi import APIRouter

from .. import __version__
from ..config import settings

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "mode": "mock" if settings.mock else "live",
        "namespace": settings.namespace,
    }
