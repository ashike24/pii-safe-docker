"""
app/main.py
============
PII-Safe FastAPI middleware service entrypoint.
Wires up routers, lifespan (DB + Redis init), and middleware.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import setup_logging
from app.db.session import init_db
from app.cache.redis import init_redis, close_redis
from app.routers import health, sanitize, audit

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    await init_db()
    await init_redis()
    yield
    await close_redis()


app = FastAPI(
    title="PII-Safe",
    description=(
        "Middleware and MCP-compatible privacy plugin that automatically "
        "detects, redacts, or pseudonymises PII before it reaches an LLM."
    ),
    version="1.0.0",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, tags=["Health"])
app.include_router(sanitize.router, prefix="/api/v1", tags=["Sanitize"])
app.include_router(audit.router, prefix="/api/v1", tags=["Audit"])
