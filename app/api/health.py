"""Health check endpoint."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/api/health")
async def health_check() -> dict[str, str]:
    """Return service health status."""
    return {"status": "healthy"}
