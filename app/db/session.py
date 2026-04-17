"""app/db/session.py — SQLAlchemy async engine + audit log model"""

from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, DateTime, Text
import uuid

from app.core.config import settings

engine = create_async_engine(settings.database_url, echo=settings.debug)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class AuditLog(Base):
    """Persists every PII interception event."""
    __tablename__ = "audit_logs"

    id:            Mapped[str]      = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp:     Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    session_id:    Mapped[str]      = mapped_column(String(128), index=True)
    reason:        Mapped[str]      = mapped_column(String(64))
    action:        Mapped[str]      = mapped_column(String(64))
    token_type:    Mapped[str]      = mapped_column(String(64))
    value_hash:    Mapped[str]      = mapped_column(String(64))   # SHA-256 only — never raw PII
    placeholder:   Mapped[str]      = mapped_column(String(128))
    context_snippet: Mapped[str]   = mapped_column(Text, default="")


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
