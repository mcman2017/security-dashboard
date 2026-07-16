from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, Boolean, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .config import settings


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scanner: Mapped[str] = mapped_column(String(32), index=True)
    variant: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(16), index=True)  # pending|running|completed|failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_json_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    raw_log_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    summary_counts: Mapped[dict] = mapped_column(JSON, default=dict)
    job_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    events: Mapped[list["Event"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    severity_normalized: Mapped[int] = mapped_column(Integer, index=True)  # Severity enum value
    severity_original: Mapped[str] = mapped_column(String(32))
    scanner_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)  # CVE id, control id, etc.
    resource_ns: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    resource_kind: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    resource_name: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    image: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    control_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ecosystem_bucket: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    kind: Mapped[str] = mapped_column(String(32))  # info|warn|error
    message: Mapped[str] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="events")


_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _engine_url() -> str:
    if settings.mock:
        # in-memory for mock mode keeps each restart clean
        return "sqlite+aiosqlite:///:memory:"
    return f"sqlite+aiosqlite:///{settings.sqlite_path}"


def _apply_sqlite_pragmas(dbapi_conn, _connection_record):  # type: ignore[no-untyped-def]
    """SQLite pragmas to keep us alive on network-attached (Ceph/NFS-class) PVC under contention.

    - journal_mode=WAL: readers no longer block on writers (and vice versa).
      Without this, a long-running parser INSERT can starve a list query and
      we hit `disk I/O error` once the rook-ceph-osd write path backs up.
    - busy_timeout: wait up to 30s for a busy lock before giving up. The PVC's
      tail latency under contention can spike to seconds; this absorbs it.
    - synchronous=NORMAL: durability for WAL, less fsync pressure than FULL.
    - foreign_keys=ON: matches the schema (CASCADE in ForeignKey).

    Applied at every new connection (engine pools connections) so brand-new
    cursors inherit the settings.
    """
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA busy_timeout=30000;")
    cur.execute("PRAGMA synchronous=NORMAL;")
    cur.execute("PRAGMA foreign_keys=ON;")
    cur.close()


async def init_db() -> None:
    global _engine, _sessionmaker
    _engine = create_async_engine(_engine_url(), echo=False, future=True)
    # Listen on the SYNC engine inside the async engine so the pragma hook
    # fires on every new SQLite connection the pool opens.
    event.listen(_engine.sync_engine, "connect", _apply_sqlite_pragmas)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False, class_=AsyncSession)
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        raise RuntimeError("DB not initialized — call init_db() first")
    return _sessionmaker
