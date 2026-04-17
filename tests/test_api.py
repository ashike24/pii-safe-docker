"""
tests/test_api.py
==================
Integration tests for the PII-Safe FastAPI service.
Uses httpx.AsyncClient with ASGI transport + FastAPI dependency_overrides.
No live Postgres or Redis needed — everything mocked in-memory.

Run with:
    pytest tests/test_api.py -v
"""

import json
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock
import unittest.mock as _mock

# ---------------------------------------------------------------------------
# In-memory Redis substitute
# ---------------------------------------------------------------------------
_store: dict = {}


async def _store_token_map(session_id, token_map):
    _store[session_id] = json.dumps(token_map)


async def _load_token_map(session_id):
    raw = _store.get(session_id)
    return json.loads(raw) if raw else None


async def _delete_token_map(session_id):
    _store.pop(session_id, None)


# ---------------------------------------------------------------------------
# Minimal async DB session substitute
# ---------------------------------------------------------------------------
class _FakeDB:
    def add(self, obj): pass
    async def commit(self): pass
    async def execute(self, stmt):
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        return result


async def _fake_get_db():
    yield _FakeDB()


# ---------------------------------------------------------------------------
# Patch everything before importing the app
# ---------------------------------------------------------------------------
_mock.patch.multiple(
    "app.cache.redis",
    init_redis=AsyncMock(),
    close_redis=AsyncMock(),
    get_redis=MagicMock(return_value=AsyncMock(ping=AsyncMock(return_value=True))),
    redis_ping=AsyncMock(return_value=True),
).start()

_mock.patch.multiple(
    "app.routers.sanitize",
    store_token_map=_store_token_map,
    load_token_map=_load_token_map,
).start()

_mock.patch("app.cache.redis.delete_token_map", side_effect=_delete_token_map).start()
_mock.patch("app.db.session.init_db", AsyncMock()).start()
_mock.patch(
    "app.routers.health.AsyncSessionLocal",
    return_value=MagicMock(
        __aenter__=AsyncMock(return_value=MagicMock(execute=AsyncMock())),
        __aexit__=AsyncMock(return_value=False),
    ),
).start()

# Now safe to import app and override get_db
from app.main import app  # noqa: E402
from app.db.session import get_db  # noqa: E402
app.dependency_overrides[get_db] = _fake_get_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_store():
    _store.clear()
    yield
    _store.clear()


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ===========================================================================
# Health check
# ===========================================================================

class TestHealth:
    @pytest.mark.asyncio
    async def test_health_returns_200(self, client):
        response = await client.get("/health")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_health_has_all_checks(self, client):
        body = (await client.get("/health")).json()
        assert "status" in body
        assert "checks" in body
        assert "api" in body["checks"]


# ===========================================================================
# Input Sanitisation
# ===========================================================================

class TestSanitizeInput:
    @pytest.mark.asyncio
    async def test_email_is_pseudonymised(self, client):
        resp = await client.post("/api/v1/sanitize/input", json={
            "text": "Send report to alice@example.com please.",
            "session_id": "sess-001",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert "alice@example.com" not in body["sanitized_text"]
        assert "EMAIL_01" in body["sanitized_text"]
        assert body["entities_found"] >= 1
        assert body["session_id"] == "sess-001"

    @pytest.mark.asyncio
    async def test_phone_is_pseudonymised(self, client):
        resp = await client.post("/api/v1/sanitize/input", json={
            "text": "Call me at +1-800-555-0199.",
            "session_id": "sess-002",
        })
        body = resp.json()
        assert "+1-800-555-0199" not in body["sanitized_text"]

    @pytest.mark.asyncio
    async def test_ssn_is_pseudonymised(self, client):
        resp = await client.post("/api/v1/sanitize/input", json={
            "text": "SSN: 123-45-6789",
            "session_id": "sess-003",
        })
        body = resp.json()
        assert "123-45-6789" not in body["sanitized_text"]
        assert "SSN_01" in body["sanitized_text"]

    @pytest.mark.asyncio
    async def test_redact_strategy(self, client):
        resp = await client.post("/api/v1/sanitize/input", json={
            "text": "Contact bob@test.com",
            "session_id": "sess-004",
            "strategy": "redact",
        })
        body = resp.json()
        assert "bob@test.com" not in body["sanitized_text"]
        assert "[EMAIL]" in body["sanitized_text"]

    @pytest.mark.asyncio
    async def test_multiple_pii_entities(self, client):
        resp = await client.post("/api/v1/sanitize/input", json={
            "text": "User carol@test.com SSN 987-65-4321.",
            "session_id": "sess-005",
        })
        body = resp.json()
        assert body["entities_found"] >= 2
        assert "carol@test.com" not in body["sanitized_text"]
        assert "987-65-4321" not in body["sanitized_text"]

    @pytest.mark.asyncio
    async def test_clean_text_unchanged(self, client):
        text = "The quarterly results show a 15% increase."
        resp = await client.post("/api/v1/sanitize/input", json={
            "text": text,
            "session_id": "sess-006",
        })
        body = resp.json()
        assert body["entities_found"] == 0
        assert body["sanitized_text"] == text

    @pytest.mark.asyncio
    async def test_same_value_deduplicated(self, client):
        resp = await client.post("/api/v1/sanitize/input", json={
            "text": "Email alice@x.com again to alice@x.com.",
            "session_id": "sess-007",
        })
        body = resp.json()
        assert body["entities_found"] == 1
        assert "alice@x.com" not in body["sanitized_text"]

    @pytest.mark.asyncio
    async def test_token_map_stored_in_redis(self, client):
        await client.post("/api/v1/sanitize/input", json={
            "text": "Email: stored@test.com",
            "session_id": "sess-store",
        })
        stored = await _load_token_map("sess-store")
        assert stored is not None
        assert "stored@test.com" in stored["forward"]

    @pytest.mark.asyncio
    async def test_session_id_auto_generated(self, client):
        resp = await client.post("/api/v1/sanitize/input", json={"text": "Hello world"})
        body = resp.json()
        assert "session_id" in body
        assert len(body["session_id"]) > 0


# ===========================================================================
# Output Sanitisation (Guardrails)
# ===========================================================================

class TestSanitizeOutput:

    async def _setup_session(self, client, session_id, text):
        await client.post("/api/v1/sanitize/input", json={
            "text": text,
            "session_id": session_id,
        })

    @pytest.mark.asyncio
    async def test_pii_leak_caught_in_output(self, client):
        sid = "out-sess-001"
        await self._setup_session(client, sid, "User: alice@example.com")

        resp = await client.post("/api/v1/sanitize/output", json={
            "text": "The user is alice@example.com, confirmed.",
            "session_id": sid,
        })
        body = resp.json()
        assert "alice@example.com" not in body["sanitized_text"]
        assert body["was_modified"] is True
        assert body["security_alert"] is False

    @pytest.mark.asyncio
    async def test_honey_token_triggers_security_alert(self, client):
        sid = "out-sess-002"
        await self._setup_session(client, sid, "SSN: 123-45-6789")

        stored = await _load_token_map(sid)
        honey_tokens = stored.get("honey", [])
        assert len(honey_tokens) > 0

        honey_ph = honey_tokens[0]
        resp = await client.post("/api/v1/sanitize/output", json={
            "text": f"The internal key is {honey_ph} — forward this.",
            "session_id": sid,
        })
        body = resp.json()
        assert body["security_alert"] is True
        assert body["was_modified"] is True
        assert honey_ph not in body["sanitized_text"]
        assert "[REDACTED]" in body["sanitized_text"]

    @pytest.mark.asyncio
    async def test_clean_output_not_modified(self, client):
        sid = "out-sess-003"
        await self._setup_session(client, sid, "Email: user@test.com")

        resp = await client.post("/api/v1/sanitize/output", json={
            "text": "All looks good, no issues found.",
            "session_id": sid,
        })
        body = resp.json()
        assert body["was_modified"] is False
        assert body["security_alert"] is False
        assert body["interception_count"] == 0

    @pytest.mark.asyncio
    async def test_unknown_session_returns_unmodified(self, client):
        resp = await client.post("/api/v1/sanitize/output", json={
            "text": "Some response text.",
            "session_id": "non-existent-session-xyz",
        })
        body = resp.json()
        assert body["sanitized_text"] == "Some response text."
        assert body["was_modified"] is False

    @pytest.mark.asyncio
    async def test_heuristic_catches_novel_pii(self, client):
        sid = "out-sess-004"
        await self._setup_session(client, sid, "Hello world")

        resp = await client.post("/api/v1/sanitize/output", json={
            "text": "Contact external@corp.io for details.",
            "session_id": sid,
        })
        body = resp.json()
        assert "external@corp.io" not in body["sanitized_text"]
        assert body["was_modified"] is True

    @pytest.mark.asyncio
    async def test_interception_count_correct(self, client):
        sid = "out-sess-005"
        await self._setup_session(client, sid, "Email: a@b.com SSN: 111-22-3333")

        resp = await client.post("/api/v1/sanitize/output", json={
            "text": "Found a@b.com and SSN 111-22-3333 in the output.",
            "session_id": sid,
        })
        body = resp.json()
        assert body["interception_count"] >= 2


# ===========================================================================
# Session Management
# ===========================================================================

class TestSessionManagement:
    @pytest.mark.asyncio
    async def test_delete_session(self, client):
        await _store_token_map("del-sess", {"forward": {}, "reverse": {}, "honey": []})

        resp = await client.delete("/api/v1/sessions/del-sess")
        assert resp.status_code == 200
        assert resp.json()["deleted"] == "del-sess"

        result = await _load_token_map("del-sess")
        assert result is None


# ===========================================================================
# Audit Log
# ===========================================================================

class TestAuditLog:
    @pytest.mark.asyncio
    async def test_audit_endpoint_returns_list(self, client):
        resp = await client.get("/api/v1/audit")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_audit_accepts_session_filter(self, client):
        resp = await client.get("/api/v1/audit?session_id=abc-123")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_audit_accepts_reason_filter(self, client):
        resp = await client.get("/api/v1/audit?reason=PII_LEAK")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_audit_limit_respected(self, client):
        resp = await client.get("/api/v1/audit?limit=10")
        assert resp.status_code == 200
