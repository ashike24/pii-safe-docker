# =============================================================================
# Dockerfile — PII-Safe FastAPI Middleware
# Multi-stage: development (hot-reload) + production (gunicorn)
# =============================================================================

# ── Base ──────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS base

WORKDIR /app

# System deps: curl for healthcheck, libpq for asyncpg
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Development ───────────────────────────────────────────────────────────────
FROM base AS development

# Dev extras: pytest, httpx for testing
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ── Production ────────────────────────────────────────────────────────────────
FROM base AS production

# Non-root user for security
RUN addgroup --system piisafe && adduser --system --ingroup piisafe piisafe

COPY --chown=piisafe:piisafe . .
USER piisafe

EXPOSE 8000

# gunicorn with uvicorn workers — tune WEB_CONCURRENCY via env
CMD ["sh", "-c", \
     "gunicorn app.main:app \
      -k uvicorn.workers.UvicornWorker \
      --workers ${WEB_CONCURRENCY:-2} \
      --bind 0.0.0.0:8000 \
      --timeout 60 \
      --access-logfile - \
      --error-logfile -"]
