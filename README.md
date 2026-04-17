# PII-Safe Docker — Full Service Stack

**Fixes:** [c2siorg/PII-Safe Issue #7](https://github.com/c2siorg/PII-Safe/issues/7)

Production deployment of [PII-Safe](https://github.com/c2siorg/PII-Safe) as a single `docker-compose up` — containerising the FastAPI middleware service, PostgreSQL for audit logging, and Redis for session token map caching.

---

## Services

| Service    | Image                  | Purpose                                      |
|------------|------------------------|----------------------------------------------|
| `api`      | Python 3.12 (custom)   | FastAPI PII middleware — redact/pseudonymise |
| `postgres` | `postgres:16-alpine`   | Audit log persistence                        |
| `redis`    | `redis:7-alpine`       | Session token map caching + TTL              |
| `nginx`    | `nginx:1.25-alpine`    | Reverse proxy with rate limiting             |

---

## Quick Start

```bash
# 1. Clone this repo
git clone https://github.com/YOUR_USERNAME/pii-safe-docker.git
cd pii-safe-docker

# 2. Set up environment
cp .env.example .env
# Edit .env — change the passwords before running in production

# 3. Start everything
docker-compose up --build

# API is now live at http://localhost:8000
# Docs at http://localhost:8000/docs (debug mode only)
```

**Tear down:**
```bash
docker-compose down -v   # -v removes volumes (wipes data)
```

---

## API Endpoints

### `POST /api/v1/sanitize/input`
Redact or pseudonymise PII before sending to an LLM.

```bash
curl -X POST http://localhost:8000/api/v1/sanitize/input \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Send report to alice@example.com, SSN 123-45-6789.",
    "session_id": "my-session-001",
    "strategy": "pseudonymise"
  }'
```

```json
{
  "session_id": "my-session-001",
  "sanitized_text": "Send report to EMAIL_01, SSN SSN_01.",
  "entities_found": 2
}
```

### `POST /api/v1/sanitize/output`
Check the LLM's response for PII leaks (output guardrails).

```bash
curl -X POST http://localhost:8000/api/v1/sanitize/output \
  -H "Content-Type: application/json" \
  -d '{
    "text": "The user is alice@example.com — confirmed.",
    "session_id": "my-session-001"
  }'
```

```json
{
  "session_id": "my-session-001",
  "sanitized_text": "The user is EMAIL_01 — confirmed.",
  "was_modified": true,
  "security_alert": false,
  "interception_count": 1
}
```

### `GET /api/v1/audit`
Query the audit log (filter by `session_id`, `reason`, `limit`).

### `DELETE /api/v1/sessions/{session_id}`
Purge a session's token map from Redis.

### `GET /health`
Health check used by Docker. Returns status of API, Postgres, and Redis.

---

## Development Mode

Hot-reload, no nginx:

```bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

---

## Running Tests

No Docker needed — tests use in-memory mocks:

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

**22 tests, all passing** across: health checks, input sanitisation, output guardrails, session management, audit log.

---

## File Structure

```
.
├── docker-compose.yml          # Production stack
├── docker-compose.dev.yml      # Dev override (hot reload, no nginx)
├── Dockerfile                  # Multi-stage: dev + production
├── .env.example                # All environment variables documented
├── requirements.txt
├── requirements-dev.txt
├── nginx/
│   └── nginx.conf              # Reverse proxy + rate limiting
├── scripts/
│   └── init_db.sql             # Postgres init (runs on first start)
├── app/
│   ├── main.py                 # FastAPI app entrypoint
│   ├── core/
│   │   ├── config.py           # Typed settings (pydantic-settings)
│   │   └── logging.py
│   ├── db/
│   │   └── session.py          # SQLAlchemy async engine + AuditLog model
│   ├── cache/
│   │   └── redis.py            # Redis client + token map helpers
│   └── routers/
│       ├── health.py           # /health — checks API + Postgres + Redis
│       ├── sanitize.py         # /sanitize/input, /sanitize/output
│       └── audit.py            # /audit
└── tests/
    └── test_api.py             # 22 integration tests
```

---

## Environment Variables

See [`.env.example`](.env.example) for the full list with descriptions. Key ones:

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | *(required)* | Postgres password |
| `REDIS_PASSWORD` | *(required)* | Redis password |
| `SECRET_KEY` | *(required)* | API secret key |
| `PII_DEFAULT_STRATEGY` | `pseudonymise` | `redact` or `pseudonymise` |
| `ENABLE_OUTPUT_GUARDRAILS` | `true` | Toggle output-side PII checking |
| `ENABLE_HONEY_TOKENS` | `true` | Toggle honey-token injection |
| `REDIS_TOKEN_TTL` | `3600` | Session TTL in seconds |

---

## License

Apache 2.0 — consistent with the parent [PII-Safe](https://github.com/c2siorg/PII-Safe) project.
