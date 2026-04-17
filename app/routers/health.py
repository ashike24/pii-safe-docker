"""app/routers/health.py — /health endpoint for Docker healthcheck"""

from fastapi import APIRouter, Response
from sqlalchemy import text
from app.db.session import AsyncSessionLocal
from app.cache.redis import redis_ping

router = APIRouter()


@router.get("/health", summary="Service health check")
async def health(response: Response):
    checks = {
        "api": "ok",
        "postgres": "unknown",
        "redis": "unknown",
    }

    # Postgres check
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:
        checks["postgres"] = f"error: {exc}"

    # Redis check
    checks["redis"] = "ok" if await redis_ping() else "error"

    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    if overall != "ok":
        response.status_code = 503

    return {"status": overall, "checks": checks}
