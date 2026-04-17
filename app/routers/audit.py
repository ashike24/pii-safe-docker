"""app/routers/audit.py — query the audit log stored in PostgreSQL"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

from app.db.session import get_db, AuditLog

router = APIRouter()


class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    session_id: str
    reason: str
    action: str
    token_type: str
    value_hash: str
    placeholder: str
    context_snippet: str

    model_config = {"from_attributes": True}


@router.get("/audit", response_model=List[AuditEntry], summary="Query audit log")
async def get_audit_log(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    reason:     Optional[str] = Query(None, description="Filter by reason (PII_LEAK, HONEY_TOKEN_FIRED, PATTERN_MATCH)"),
    limit:      int           = Query(100, le=1000),
    db: AsyncSession          = Depends(get_db),
):
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    if session_id:
        stmt = stmt.where(AuditLog.session_id == session_id)
    if reason:
        stmt = stmt.where(AuditLog.reason == reason)

    result = await db.execute(stmt)
    return result.scalars().all()
