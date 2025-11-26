"""
qsms.database.db_config

Centralized database configuration for QSMS.

Features
- Uses DATABASE_URL env var when present; defaults to local SQLite file.
- Safe defaults (pool_pre_ping, expire_on_commit=False).
- SQLite-specific pragmas (WAL, foreign_keys=ON) are enabled automatically.
- Simple session helpers: get_engine(), get_session(), and session_scope().
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Example override (PowerShell):
#   $env:DATABASE_URL = "postgresql+psycopg://user:pass@localhost:5432/qsms"
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///qsms.sqlite3")

# Enable SQL echo logs (for debugging) by setting QSMS_DB_ECHO=1
ECHO_SQL: bool = os.getenv("QSMS_DB_ECHO", "0").strip() in {"1", "true", "True"}

# Engine & Session factory (lazily initialized)
_engine: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker] = None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def _is_sqlite(url: str) -> bool:
    # Cheap check that works for "sqlite:///file.db" and "sqlite:///:memory:"
    return url.lower().startswith("sqlite")


def get_engine() -> Engine:
    """
    Return a module-wide SQLAlchemy Engine (singleton).
    Creates it on first call based on DATABASE_URL.
    """
    global _engine, _SessionLocal
    if _engine is not None:
        return _engine

    connect_args = {}
    if _is_sqlite(DATABASE_URL):
        # Needed to allow access across threads (tests, background tasks)
        connect_args = {"check_same_thread": False}

    _engine = create_engine(
        DATABASE_URL,
        echo=ECHO_SQL,
        pool_pre_ping=True,
        future=True,
        connect_args=connect_args,
    )

    # Apply pragmatic SQLite settings for robustness & performance
    if _is_sqlite(DATABASE_URL):
        @event.listens_for(_engine, "connect")
        def _sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[no-redef]
            cur = dbapi_connection.cursor()
            # Foreign key enforcement (off by default in SQLite)
            cur.execute("PRAGMA foreign_keys=ON")
            # WAL mode improves concurrency (ok for file-backed DBs)
            cur.execute("PRAGMA journal_mode=WAL")
            # Reasonable compromise between durability & performance
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

    # Build the session factory bound to this engine
    _SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
        bind=_engine,
        future=True,
    )

    return _engine


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def get_session() -> Session:
    """
    Return a new Session. Caller is responsible for closing it,
    or prefer using session_scope() which handles commit/rollback.
    """
    global _SessionLocal
    if _SessionLocal is None:
        get_engine()  # initializes _SessionLocal
    assert _SessionLocal is not None
    return _SessionLocal()


@contextmanager
def session_scope() -> Iterator[Session]:
    """
    Context manager for a transactional session.

    Example:
        from qsms.database.db_config import session_scope
        with session_scope() as s:
            s.add(obj)
            # commit happens automatically; rollback on exception
    """
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# CLI helper (optional)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    eng = get_engine()
    print(f"[+] Connected engine: {eng}")
    if _is_sqlite(DATABASE_URL):
        print("[i] SQLite pragmas enabled: foreign_keys=ON, WAL, synchronous=NORMAL")
