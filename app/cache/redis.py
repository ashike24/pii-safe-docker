"""app/cache/redis.py — Redis client for session token map caching"""

import json
import redis.asyncio as aioredis
from typing import Optional

from app.core.config import settings

_redis: Optional[aioredis.Redis] = None


async def init_redis() -> None:
    global _redis
    _redis = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )


async def close_redis() -> None:
    if _redis:
        await _redis.aclose()


def get_redis() -> aioredis.Redis:
    if _redis is None:
        raise RuntimeError("Redis not initialised — call init_redis() first")
    return _redis


async def store_token_map(session_id: str, token_map: dict) -> None:
    """Persist a session's token map in Redis with TTL."""
    await get_redis().setex(
        f"token_map:{session_id}",
        settings.redis_token_ttl,
        json.dumps(token_map),
    )


async def load_token_map(session_id: str) -> Optional[dict]:
    """Retrieve a session's token map from Redis."""
    raw = await get_redis().get(f"token_map:{session_id}")
    return json.loads(raw) if raw else None


async def delete_token_map(session_id: str) -> None:
    await get_redis().delete(f"token_map:{session_id}")


async def redis_ping() -> bool:
    try:
        return await get_redis().ping()
    except Exception:
        return False
