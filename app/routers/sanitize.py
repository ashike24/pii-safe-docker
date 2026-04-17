"""
app/routers/sanitize.py
========================
Core API endpoints for PII detection, redaction, and pseudonymisation.

POST /api/v1/sanitize/input   — sanitise text before sending to LLM
POST /api/v1/sanitize/output  — sanitise LLM response (output guardrails)
DELETE /api/v1/sessions/{id}  — purge a session's token map from Redis
"""

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.cache.redis import store_token_map, load_token_map
from app.core.config import settings
from app.db.session import get_db, AuditLog

router = APIRouter()

# ---------------------------------------------------------------------------
# Regex-based PII patterns (production deployments swap this for Presidio)
# ---------------------------------------------------------------------------
_PATTERNS = {
    "EMAIL":       re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "SSN":         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "PHONE":       re.compile(r"(?<!\d)(?:\+?\d[\d\-\s().]{7,}\d)(?!\d)"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "IP_ADDR":     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SanitizeInputRequest(BaseModel):
    text: str = Field(..., description="Raw text that may contain PII")
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    strategy: Literal["redact", "pseudonymise"] = Field(
        default_factory=lambda: settings.pii_default_strategy
    )

class SanitizeInputResponse(BaseModel):
    session_id: str
    sanitized_text: str
    entities_found: int


class SanitizeOutputRequest(BaseModel):
    text: str = Field(..., description="Raw LLM response to check for PII leaks")
    session_id: str = Field(..., description="Session ID from the input sanitization step")

class SanitizeOutputResponse(BaseModel):
    session_id: str
    sanitized_text: str
    was_modified: bool
    security_alert: bool
    interception_count: int


# ---------------------------------------------------------------------------
# Input sanitisation
# ---------------------------------------------------------------------------

@router.post("/sanitize/input", response_model=SanitizeInputResponse)
async def sanitize_input(
    req: SanitizeInputRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Detect and redact/pseudonymise PII in the input text.
    Stores the token map in Redis for the session.
    """
    token_map: dict = {"forward": {}, "reverse": {}, "honey": []}
    counters: dict = {}
    text = req.text
    entities_found = 0

    for entity_type, pattern in _PATTERNS.items():
        if entity_type not in settings.entity_types:
            continue
        for match in pattern.finditer(text):
            real_value = match.group(0)
            if real_value in token_map["forward"]:
                continue

            entities_found += 1
            if req.strategy == "pseudonymise":
                idx = counters.get(entity_type, 0) + 1
                counters[entity_type] = idx
                placeholder = f"{entity_type}_{idx:02d}"
            else:
                placeholder = f"[{entity_type}]"

            token_map["forward"][real_value] = placeholder
            token_map["reverse"][placeholder] = real_value

            # Inject honey-token alongside every real token
            if settings.enable_honey_tokens:
                honey_ph = f"HONEY_{entity_type}_{entities_found:02d}"
                token_map["honey"].append(honey_ph)

    # Replace in text
    for real_value, placeholder in sorted(
        token_map["forward"].items(), key=lambda x: len(x[0]), reverse=True
    ):
        text = text.replace(real_value, placeholder)

    # Persist token map in Redis
    await store_token_map(req.session_id, token_map)

    return SanitizeInputResponse(
        session_id=req.session_id,
        sanitized_text=text,
        entities_found=entities_found,
    )


# ---------------------------------------------------------------------------
# Output sanitisation (guardrails — Issue #16)
# ---------------------------------------------------------------------------

@router.post("/sanitize/output", response_model=SanitizeOutputResponse)
async def sanitize_output(
    req: SanitizeOutputRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Post-process an LLM response.
    Checks for PII leaks using the session's stored token map.
    """
    if not settings.enable_output_guardrails:
        return SanitizeOutputResponse(
            session_id=req.session_id,
            sanitized_text=req.text,
            was_modified=False,
            security_alert=False,
            interception_count=0,
        )

    token_map = await load_token_map(req.session_id)
    if not token_map:
        return SanitizeOutputResponse(
            session_id=req.session_id,
            sanitized_text=req.text,
            was_modified=False,
            security_alert=False,
            interception_count=0,
        )

    text = req.text
    security_alert = False
    interceptions = []

    # 1. Honey-token scan
    for honey_ph in token_map.get("honey", []):
        if honey_ph in text:
            security_alert = True
            text = text.replace(honey_ph, "[REDACTED]")
            interceptions.append(("HONEY_TOKEN_FIRED", honey_ph))
            # Persist to DB
            db.add(AuditLog(
                session_id=req.session_id,
                reason="HONEY_TOKEN_FIRED",
                action="FLAGGED",
                token_type=honey_ph.split("_")[1] if "_" in honey_ph else "UNKNOWN",
                value_hash=hashlib.sha256(honey_ph.encode()).hexdigest(),
                placeholder="[REDACTED]",
                context_snippet=_snippet(req.text, honey_ph),
            ))

    # 2. Mapping check
    for real_value, placeholder in sorted(
        token_map["forward"].items(), key=lambda x: len(x[0]), reverse=True
    ):
        if real_value in text:
            text = text.replace(real_value, placeholder)
            interceptions.append(("PII_LEAK", real_value))
            db.add(AuditLog(
                session_id=req.session_id,
                reason="PII_LEAK",
                action="REPLACED",
                token_type=placeholder.rsplit("_", 1)[0],
                value_hash=hashlib.sha256(real_value.encode()).hexdigest(),
                placeholder=placeholder,
                context_snippet=_snippet(req.text, real_value),
            ))

    # 3. Heuristic scan
    for entity_type, pattern in _PATTERNS.items():
        for match in pattern.finditer(text):
            matched = match.group(0)
            if matched not in token_map["forward"]:
                replacement = f"[{entity_type}_DETECTED]"
                text = text.replace(matched, replacement, 1)
                interceptions.append(("PATTERN_MATCH", matched))
                db.add(AuditLog(
                    session_id=req.session_id,
                    reason="PATTERN_MATCH",
                    action="REDACTED",
                    token_type=entity_type,
                    value_hash=hashlib.sha256(matched.encode()).hexdigest(),
                    placeholder=replacement,
                    context_snippet=_snippet(req.text, matched),
                ))

    await db.commit()

    return SanitizeOutputResponse(
        session_id=req.session_id,
        sanitized_text=text,
        was_modified=text != req.text,
        security_alert=security_alert,
        interception_count=len(interceptions),
    )


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

@router.delete("/sessions/{session_id}", summary="Purge session token map")
async def delete_session(session_id: str):
    from app.cache.redis import delete_token_map
    await delete_token_map(session_id)
    return {"deleted": session_id}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snippet(text: str, value: str, window: int = 40) -> str:
    idx = text.find(value)
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end   = min(len(text), idx + len(value) + window)
    return text[start:end].replace(value, f"<{value[:4]}…>")
